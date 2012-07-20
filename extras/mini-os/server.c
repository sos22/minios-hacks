/*
 * server.c -- nsd(8) network input/output
 *
 * Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#ifndef SHUT_WR
#define SHUT_WR 1
#endif

#include "axfr.h"
#include "namedb.h"
#include "netio.h"
#include "xfrd.h"
#include "xfrd-tcp.h"
#include "difffile.h"
#include "nsec3.h"
#include "ipc.h"

/*
 * Data for the UDP handlers.
 */
struct udp_handler_data
{
	struct nsd        *nsd;
	struct nsd_socket *socket;
	query_type        *query;
};

/*
 * Data for the TCP accept handlers.  Most data is simply passed along
 * to the TCP connection handler.
 */
struct tcp_accept_handler_data {
	struct nsd         *nsd;
	struct nsd_socket  *socket;
	size_t              tcp_accept_handler_count;
	netio_handler_type *tcp_accept_handlers;
};

int slowaccept;
struct timespec slowaccept_timeout;

/*
 * Data for the TCP connection handlers.
 *
 * The TCP handlers use non-blocking I/O.  This is necessary to avoid
 * blocking the entire server on a slow TCP connection, but does make
 * reading from and writing to the socket more complicated.
 *
 * Basically, whenever a read/write would block (indicated by the
 * EAGAIN errno variable) we remember the position we were reading
 * from/writing to and return from the TCP reading/writing event
 * handler.  When the socket becomes readable/writable again we
 * continue from the same position.
 */
struct tcp_handler_data
{
	/*
	 * The region used to allocate all TCP connection related
	 * data, including this structure.  This region is destroyed
	 * when the connection is closed.
	 */
	region_type     *region;

	/*
	 * The global nsd structure.
	 */
	struct nsd      *nsd;

	/*
	 * The current query data for this TCP connection.
	 */
	query_type      *query;

	/*
	 * These fields are used to enable the TCP accept handlers
	 * when the number of TCP connection drops below the maximum
	 * number of TCP connections.
	 */
	size_t              tcp_accept_handler_count;
	netio_handler_type *tcp_accept_handlers;

	/*
	 * The query_state is used to remember if we are performing an
	 * AXFR, if we're done processing, or if we should discard the
	 * query and connection.
	 */
	query_state_type query_state;

	/*
	 * The bytes_transmitted field is used to remember the number
	 * of bytes transmitted when receiving or sending a DNS
	 * packet.  The count includes the two additional bytes used
	 * to specify the packet length on a TCP connection.
	 */
	size_t           bytes_transmitted;

	/*
	 * The number of queries handled by this specific TCP connection.
	 */
	int					query_count;
};

/*
 * Handle incoming queries on the UDP server sockets.
 */
static void handle_udp(netio_type *netio,
		       netio_handler_type *handler,
		       netio_event_types_type event_types);

/*
 * Handle incoming connections on the TCP sockets.  These handlers
 * usually wait for the NETIO_EVENT_READ event (indicating an incoming
 * connection) but are disabled when the number of current TCP
 * connections is equal to the maximum number of TCP connections.
 * Disabling is done by changing the handler to wait for the
 * NETIO_EVENT_NONE type.  This is done using the function
 * configure_tcp_accept_handlers.
 */
static void handle_tcp_accept(netio_type *netio,
			      netio_handler_type *handler,
			      netio_event_types_type event_types);

/*
 * Handle incoming queries on a TCP connection.  The TCP connections
 * are configured to be non-blocking and the handler may be called
 * multiple times before a complete query is received.
 */
static void handle_tcp_reading(netio_type *netio,
			       netio_handler_type *handler,
			       netio_event_types_type event_types);

/*
 * Handle outgoing responses on a TCP connection.  The TCP connections
 * are configured to be non-blocking and the handler may be called
 * multiple times before a complete response is sent.
 */
static void handle_tcp_writing(netio_type *netio,
			       netio_handler_type *handler,
			       netio_event_types_type event_types);


/* set childrens flags to send NSD_STATS to them */
#ifdef BIND8_STATS
static void set_children_stats(struct nsd* nsd);
#endif /* BIND8_STATS */

/*
 * Change the event types the HANDLERS are interested in to
 * EVENT_TYPES.
 */
static void configure_handler_event_types(size_t count,
					  netio_handler_type *handlers,
					  netio_event_types_type event_types);

static uint16_t *compressed_dname_offsets = 0;
static uint32_t compression_table_capacity = 0;
static uint32_t compression_table_size = 0;

#ifdef BIND8_STATS
static void set_bind8_alarm(struct nsd* nsd)
{
	/* resync so that the next alarm is on the next whole minute */
	if(nsd->st.period > 0) /* % by 0 gives divbyzero error */
		alarm(nsd->st.period - (time(NULL) % nsd->st.period));
}
#endif

static void
cleanup_dname_compression_tables(void *ptr)
{
	free(ptr);
	compressed_dname_offsets = NULL;
	compression_table_capacity = 0;
}

static void
initialize_dname_compression_tables(struct nsd *nsd)
{
	size_t needed = domain_table_count(nsd->db->domains) + 1;
	needed += EXTRA_DOMAIN_NUMBERS;
	if(compression_table_capacity < needed) {
		if(compressed_dname_offsets) {
			region_remove_cleanup(nsd->db->region,
				cleanup_dname_compression_tables,
				compressed_dname_offsets);
			free(compressed_dname_offsets);
		}
		compressed_dname_offsets = (uint16_t *) xalloc(
			needed * sizeof(uint16_t));
		region_add_cleanup(nsd->db->region, cleanup_dname_compression_tables,
			compressed_dname_offsets);
		compression_table_capacity = needed;
		compression_table_size=domain_table_count(nsd->db->domains)+1;
	}
	memset(compressed_dname_offsets, 0, needed * sizeof(uint16_t));
	compressed_dname_offsets[0] = QHEADERSZ; /* The original query name */
}

/*
 * Initialize the server, create and bind the sockets.
 *
 */
int
server_init(struct nsd *nsd)
{
	size_t i;
#if defined(SO_REUSEADDR) || (defined(INET6) && (defined(IPV6_V6ONLY) || defined(IPV6_USE_MIN_MTU) || defined(IPV6_MTU)))
	int on = 1;
#endif

	/* UDP */

	/* Make a socket... */
	for (i = 0; i < nsd->ifs; i++) {
	  if ((nsd->udp[i].s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
#if defined(INET6)
			if (nsd->udp[i].addr->ai_family == AF_INET6 &&
				errno == EAFNOSUPPORT && nsd->grab_ip6_optional) {
				log_msg(LOG_WARNING, "fallback to UDP4, no IPv6: not supported");
				continue;
			}
#endif /* INET6 */
			log_msg(LOG_ERR, "can't create a socket: %s", strerror(errno));
			return -1;
		}

#if defined(INET6)
		if (nsd->udp[i].addr->ai_family == AF_INET6) {
# if defined(IPV6_V6ONLY)
			if (setsockopt(nsd->udp[i].s,
				       IPPROTO_IPV6, IPV6_V6ONLY,
				       &on, sizeof(on)) < 0)
			{
				log_msg(LOG_ERR, "setsockopt(..., IPV6_V6ONLY, ...) failed: %s",
					strerror(errno));
				return -1;
			}
# endif
# if defined(IPV6_USE_MIN_MTU)
			/*
			 * There is no fragmentation of IPv6 datagrams
			 * during forwarding in the network. Therefore
			 * we do not send UDP datagrams larger than
			 * the minimum IPv6 MTU of 1280 octets. The
			 * EDNS0 message length can be larger if the
			 * network stack supports IPV6_USE_MIN_MTU.
			 */
			if (setsockopt(nsd->udp[i].s,
				       IPPROTO_IPV6, IPV6_USE_MIN_MTU,
				       &on, sizeof(on)) < 0)
			{
				log_msg(LOG_ERR, "setsockopt(..., IPV6_USE_MIN_MTU, ...) failed: %s",
					strerror(errno));
				return -1;
			}
# elif defined(IPV6_MTU)
			/*
			 * On Linux, PMTUD is disabled by default for datagrams
			 * so set the MTU equal to the MIN MTU to get the same.
			 */
			on = IPV6_MIN_MTU;
			if (setsockopt(nsd->udp[i].s, IPPROTO_IPV6, IPV6_MTU, 
				&on, sizeof(on)) < 0)
			{
				log_msg(LOG_ERR, "setsockopt(..., IPV6_MTU, ...) failed: %s",
					strerror(errno));
				return -1;
			}
			on = 1;
# endif
		}
#endif
#if defined(AF_INET)
		if (1) {
#  if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
			int action = IP_PMTUDISC_DONT;
			if (setsockopt(nsd->udp[i].s, IPPROTO_IP, 
				IP_MTU_DISCOVER, &action, sizeof(action)) < 0)
			{
				log_msg(LOG_ERR, "setsockopt(..., IP_MTU_DISCOVER, IP_PMTUDISC_DONT...) failed: %s",
					strerror(errno));
				return -1;
			}
#  elif defined(IP_DONTFRAG)
			int off = 0;
			if (setsockopt(nsd->udp[i].s, IPPROTO_IP, IP_DONTFRAG,
				&off, sizeof(off)) < 0)
			{
				log_msg(LOG_ERR, "setsockopt(..., IP_DONTFRAG, ...) failed: %s",
					strerror(errno));
				return -1;
			}
#  endif
		}
#endif
		/* set it nonblocking */
		/* otherwise, on OSes with thundering herd problems, the
		   UDP recv could block NSD after select returns readable. */
		if (fcntl(nsd->udp[i].s, F_SETFL, O_NONBLOCK) == -1) {
			log_msg(LOG_ERR, "cannot fcntl udp: %s", strerror(errno));
		}

		/* Bind it... */
		{
			struct sockaddr_in addr;
			memset(&addr, 0, sizeof(addr));
			addr.sin_port = htons(53);
			if (bind(nsd->udp[i].s, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
				log_msg(LOG_ERR, "can't bind udp socket: %s", strerror(errno));
				return -1;
			}
		}
	}

	/* TCP */

	/* Make a socket... */
	for (i = 0; i < nsd->ifs; i++) {
		if ((nsd->tcp[i].s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
#if defined(INET6)
			if (nsd->tcp[i].addr->ai_family == AF_INET6 &&
				errno == EAFNOSUPPORT && nsd->grab_ip6_optional) {
				log_msg(LOG_WARNING, "fallback to TCP4, no IPv6: not supported");
				continue;
			}
#endif /* INET6 */
			log_msg(LOG_ERR, "can't create a socket: %s", strerror(errno));
			return -1;
		}

#ifdef	SO_REUSEADDR
		if (setsockopt(nsd->tcp[i].s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
			log_msg(LOG_ERR, "setsockopt(..., SO_REUSEADDR, ...) failed: %s", strerror(errno));
		}
#endif /* SO_REUSEADDR */

#if defined(INET6) && defined(IPV6_V6ONLY)
		if (nsd->tcp[i].addr->ai_family == AF_INET6 &&
		    setsockopt(nsd->tcp[i].s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0)
		{
			log_msg(LOG_ERR, "setsockopt(..., IPV6_V6ONLY, ...) failed: %s", strerror(errno));
			return -1;
		}
#endif
		/* set it nonblocking */
		/* (StevensUNP p463), if tcp listening socket is blocking, then
		   it may block in accept, even if select() says readable. */
		if (fcntl(nsd->tcp[i].s, F_SETFL, O_NONBLOCK) == -1) {
			log_msg(LOG_ERR, "cannot fcntl tcp: %s", strerror(errno));
		}

		/* Bind it... */
		{
			struct sockaddr_in addr;
			memset(&addr, 0, sizeof(addr));
			addr.sin_port = htons(53);
			if (bind(nsd->tcp[i].s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
				log_msg(LOG_ERR, "can't bind tcp socket: %s", strerror(errno));
				return -1;
			}
		}

		/* Listen to it... */
		if (listen(nsd->tcp[i].s, TCP_BACKLOG) == -1) {
			log_msg(LOG_ERR, "can't listen: %s", strerror(errno));
			return -1;
		}
	}

	return 0;
}

/*
 * Prepare the server for take off.
 *
 */
int
server_prepare(struct nsd *nsd)
{
	/* Open the database... */
	if ((nsd->db = namedb_open(nsd->dbfile, nsd->options, nsd->child_count)) == NULL) {
		log_msg(LOG_ERR, "unable to open the database %s: %s",
			nsd->dbfile, strerror(errno));
		return -1;
	}

	/* Read diff file */
	if(!diff_read_file(nsd->db, nsd->options, NULL, nsd->child_count)) {
		log_msg(LOG_ERR, "The diff file contains errors. Will continue "
						 "without it");
	}

#ifdef NSEC3
	prehash(nsd->db, 0);
#endif

	compression_table_capacity = 0;
	initialize_dname_compression_tables(nsd);

#ifdef	BIND8_STATS
	/* Initialize times... */
	time(&nsd->st.boot);
	set_bind8_alarm(nsd);
#endif /* BIND8_STATS */

	return 0;
}

static void
close_all_sockets(struct nsd_socket sockets[], size_t n)
{
	size_t i;

	/* Close all the sockets... */
	for (i = 0; i < n; ++i) {
		if (sockets[i].s != -1) {
			close(sockets[i].s);
			sockets[i].s = -1;
		}
	}
}

/*
 * Close the sockets, shutdown the server and exit.
 * Does not return.
 *
 */
static void
server_shutdown(struct nsd *nsd)
{
	size_t i;

	close_all_sockets(nsd->udp, nsd->ifs);
	close_all_sockets(nsd->tcp, nsd->ifs);
	/* CHILD: close command channel to parent */
	if(nsd->this_child && nsd->this_child->parent_fd != -1)
	{
		close(nsd->this_child->parent_fd);
		nsd->this_child->parent_fd = -1;
	}
	/* SERVER: close command channels to children */
	if(!nsd->this_child)
	{
		for(i=0; i < nsd->child_count; ++i)
			if(nsd->children[i].child_fd != -1)
			{
				close(nsd->children[i].child_fd);
				nsd->children[i].child_fd = -1;
			}
	}

	log_finalize();
	tsig_finalize();

	nsd_options_destroy(nsd->options);
	region_destroy(nsd->region);

	exit(0);
}

/*
 * Get the mode depending on the signal hints that have been received.
 * Multiple signal hints can be received and will be handled in turn.
 */
static sig_atomic_t
server_signal_mode(struct nsd *nsd)
{
	if(nsd->signal_hint_quit) {
		nsd->signal_hint_quit = 0;
		return NSD_QUIT;
	}
	else if(nsd->signal_hint_shutdown) {
		nsd->signal_hint_shutdown = 0;
		return NSD_SHUTDOWN;
	}
	else if(nsd->signal_hint_child) {
		nsd->signal_hint_child = 0;
		return NSD_REAP_CHILDREN;
	}
	else if(nsd->signal_hint_reload) {
		nsd->signal_hint_reload = 0;
		return NSD_RELOAD;
	}
	else if(nsd->signal_hint_stats) {
		nsd->signal_hint_stats = 0;
#ifdef BIND8_STATS
		set_bind8_alarm(nsd);
#endif
		return NSD_STATS;
	}
	else if(nsd->signal_hint_statsusr) {
		nsd->signal_hint_statsusr = 0;
		return NSD_STATS;
	}
	return NSD_RUN;
}

/*
 * The main server simply waits for signals and child processes to
 * terminate.  Child processes are restarted as necessary.
 */
void
server_main(struct nsd *nsd)
{
	region_type *server_region = region_create(xalloc, free);
	netio_handler_type xfrd_listener;

	/* Ensure we are the main process */
	assert(nsd->server_kind == NSD_SERVER_MAIN);

	xfrd_listener.user_data = (struct ipc_handler_conn_data*)region_alloc(
		server_region, sizeof(struct ipc_handler_conn_data));
	xfrd_listener.fd = -1;
	((struct ipc_handler_conn_data*)xfrd_listener.user_data)->nsd = nsd;
	((struct ipc_handler_conn_data*)xfrd_listener.user_data)->conn =
		xfrd_tcp_create(server_region);

				nsd->pid = 0;
				nsd->child_count = 0;
				nsd->server_kind = NSD_SERVER_UDP;
				nsd->this_child = &nsd->children[0];
				/* remove signal flags inherited from parent
				   the parent will handle them. */
				nsd->signal_hint_reload = 0;
				nsd->signal_hint_child = 0;
				nsd->signal_hint_quit = 0;
				nsd->signal_hint_shutdown = 0;
				nsd->signal_hint_stats = 0;
				nsd->signal_hint_statsusr = 0;
				close(nsd->this_child->child_fd);
				nsd->this_child->child_fd = -1;
				server_child(nsd);
				abort();
}

static query_state_type
server_process_query(struct nsd *nsd, struct query *query)
{
	return query_process(query, nsd);
}


/*
 * Serve DNS requests.
 */
void
server_child(struct nsd *nsd)
{
	size_t i;
	region_type *server_region = region_create(xalloc, free);
	netio_type *netio = netio_create(server_region);
	netio_handler_type *tcp_accept_handlers;
	query_type *udp_query;
	sig_atomic_t mode;

	assert(nsd->server_kind != NSD_SERVER_MAIN);
	DEBUG(DEBUG_IPC, 2, (LOG_INFO, "child process started"));

	if (!(nsd->server_kind & NSD_SERVER_TCP)) {
		close_all_sockets(nsd->tcp, nsd->ifs);
	}
	if (!(nsd->server_kind & NSD_SERVER_UDP)) {
		close_all_sockets(nsd->udp, nsd->ifs);
	}

	if (nsd->this_child && nsd->this_child->parent_fd != -1) {
		netio_handler_type *handler;

		handler = (netio_handler_type *) region_alloc(
			server_region, sizeof(netio_handler_type));
		handler->fd = nsd->this_child->parent_fd;
		handler->timeout = NULL;
		handler->user_data = (struct ipc_handler_conn_data*)region_alloc(
			server_region, sizeof(struct ipc_handler_conn_data));
		((struct ipc_handler_conn_data*)handler->user_data)->nsd = nsd;
		((struct ipc_handler_conn_data*)handler->user_data)->conn =
			xfrd_tcp_create(server_region);
		handler->event_types = NETIO_EVENT_READ;
		handler->event_handler = child_handle_parent_command;
		netio_add_handler(netio, handler);
	}

	if (nsd->server_kind & NSD_SERVER_UDP) {
		udp_query = query_create(server_region,
			compressed_dname_offsets, compression_table_size);

		for (i = 0; i < nsd->ifs; ++i) {
			struct udp_handler_data *data;
			netio_handler_type *handler;

			data = (struct udp_handler_data *) region_alloc(
				server_region,
				sizeof(struct udp_handler_data));
			data->query = udp_query;
			data->nsd = nsd;
			data->socket = &nsd->udp[i];

			handler = (netio_handler_type *) region_alloc(
				server_region, sizeof(netio_handler_type));
			handler->fd = nsd->udp[i].s;
			handler->timeout = NULL;
			handler->user_data = data;
			handler->event_types = NETIO_EVENT_READ;
			handler->event_handler = handle_udp;
			netio_add_handler(netio, handler);
		}
	}

	/*
	 * Keep track of all the TCP accept handlers so we can enable
	 * and disable them based on the current number of active TCP
	 * connections.
	 */
	tcp_accept_handlers = (netio_handler_type *) region_alloc(
		server_region, nsd->ifs * sizeof(netio_handler_type));
	if (nsd->server_kind & NSD_SERVER_TCP) {
		for (i = 0; i < nsd->ifs; ++i) {
			struct tcp_accept_handler_data *data;
			netio_handler_type *handler;

			data = (struct tcp_accept_handler_data *) region_alloc(
				server_region,
				sizeof(struct tcp_accept_handler_data));
			data->nsd = nsd;
			data->socket = &nsd->tcp[i];
			data->tcp_accept_handler_count = nsd->ifs;
			data->tcp_accept_handlers = tcp_accept_handlers;

			handler = &tcp_accept_handlers[i];
			handler->fd = nsd->tcp[i].s;
			handler->timeout = NULL;
			handler->user_data = data;
			handler->event_types = NETIO_EVENT_READ | NETIO_EVENT_ACCEPT;
			handler->event_handler = handle_tcp_accept;
			netio_add_handler(netio, handler);
		}
	}

	/* The main loop... */
	while ((mode = nsd->mode) != NSD_QUIT) {
		if(mode == NSD_RUN) nsd->mode = mode = server_signal_mode(nsd);

		/* Do we need to do the statistics... */
		if (mode == NSD_STATS) {
#ifdef BIND8_STATS
			/* Dump the statistics */
			bind8_stats(nsd);
#else /* !BIND8_STATS */
			log_msg(LOG_NOTICE, "Statistics support not enabled at compile time.");
#endif /* BIND8_STATS */

			nsd->mode = NSD_RUN;
		}
		else if (mode == NSD_REAP_CHILDREN) {
			/* got signal, notify parent. parent reaps terminated children. */
			if (nsd->this_child->parent_fd != -1) {
				sig_atomic_t parent_notify = NSD_REAP_CHILDREN;
				if (write(nsd->this_child->parent_fd,
				    &parent_notify,
				    sizeof(parent_notify)) == -1)
				{
					log_msg(LOG_ERR, "problems sending command from %d to parent: %s",
						(int) nsd->this_child->pid, strerror(errno));
				}
			} else /* no parent, so reap 'em */
				while (waitpid(0, NULL, WNOHANG) > 0) ;
			nsd->mode = NSD_RUN;
		}
		else if(mode == NSD_RUN) {
			/* Wait for a query... */
			if (netio_dispatch(netio, NULL, NULL) == -1) {
				if (errno != EINTR) {
					log_msg(LOG_ERR, "netio_dispatch failed: %s", strerror(errno));
					break;
				}
			}
		} else if(mode == NSD_QUIT) {
			/* ignore here, quit */
		} else {
			log_msg(LOG_ERR, "mode bad value %d, back to service.",
				mode);
			nsd->mode = NSD_RUN;
		}
	}

#ifdef	BIND8_STATS
	bind8_stats(nsd);
#endif /* BIND8_STATS */

	namedb_fd_close(nsd->db);
	region_destroy(server_region);
	server_shutdown(nsd);
}


static void
handle_udp(netio_type *ATTR_UNUSED(netio),
	   netio_handler_type *handler,
	   netio_event_types_type event_types)
{
	struct udp_handler_data *data
		= (struct udp_handler_data *) handler->user_data;
	int received, sent;
	struct query *q = data->query;

	if (!(event_types & NETIO_EVENT_READ)) {
		return;
	}

	/* Account... */
#ifdef BIND8_STATS
	if (data->socket->addr->ai_family == AF_INET) {
		STATUP(data->nsd, qudp);
	} else if (data->socket->addr->ai_family == AF_INET6) {
		STATUP(data->nsd, qudp6);
	}
#endif

	/* Initialize the query... */
	query_reset(q, UDP_MAX_MESSAGE_LEN, 0);

	received = recvfrom(handler->fd,
			    buffer_begin(q->packet),
			    buffer_remaining(q->packet),
			    0,
			    (struct sockaddr *)&q->addr,
			    &q->addrlen);
	if (received == -1) {
		if (errno != EAGAIN && errno != EINTR) {
			log_msg(LOG_ERR, "recvfrom failed: %s", strerror(errno));
			STATUP(data->nsd, rxerr);
			/* No zone statup */
		}
	} else {
		buffer_skip(q->packet, received);
		buffer_flip(q->packet);

		/* Process and answer the query... */
		if (server_process_query(data->nsd, q) != QUERY_DISCARDED) {
#ifdef BIND8_STATS
			if (RCODE(q->packet) == RCODE_OK && !AA(q->packet)) {
				STATUP(data->nsd, nona);
				ZTATUP(q->zone, nona);
			}

# ifdef USE_ZONE_STATS
			if (data->socket->addr->ai_family == AF_INET) {
				ZTATUP(q->zone, qudp);
			} else if (data->socket->addr->ai_family == AF_INET6) {
				ZTATUP(q->zone, qudp6);
			}
# endif
#endif

			/* Add EDNS0 and TSIG info if necessary.  */
			query_add_optional(q, data->nsd);

			buffer_flip(q->packet);

			sent = sendto(handler->fd,
				      buffer_begin(q->packet),
				      buffer_remaining(q->packet),
				      0,
				      (struct sockaddr *) &q->addr,
				      q->addrlen);
			if (sent == -1) {
				log_msg(LOG_ERR, "sendto failed: %s", strerror(errno));
				STATUP(data->nsd, txerr);
				ZTATUP(q->zone, txerr);
			} else if ((size_t) sent != buffer_remaining(q->packet)) {
				log_msg(LOG_ERR, "sent %d in place of %d bytes", sent, (int) buffer_remaining(q->packet));
#ifdef BIND8_STATS
			} else {
				/* Account the rcode & TC... */
				STATUP2(data->nsd, rcode, RCODE(q->packet));
				ZTATUP2(q->zone, rcode, RCODE(q->packet));
				if (TC(q->packet)) {
					STATUP(data->nsd, truncated);
					ZTATUP(q->zone, truncated);
				}
#endif /* BIND8_STATS */
			}
#ifdef BIND8_STATS
		} else {
			STATUP(data->nsd, dropped);
# ifdef USE_ZONE_STATS
			if (q->zone) {
				ZTATUP(q->zone, dropped);
			}
# endif
#endif
		}
	}
}


static void
cleanup_tcp_handler(netio_type *netio, netio_handler_type *handler)
{
	struct tcp_handler_data *data
		= (struct tcp_handler_data *) handler->user_data;
	netio_remove_handler(netio, handler);
	close(handler->fd);
	slowaccept = 0;

	/*
	 * Enable the TCP accept handlers when the current number of
	 * TCP connections is about to drop below the maximum number
	 * of TCP connections.
	 */
	if (data->nsd->current_tcp_count == data->nsd->maximum_tcp_count) {
		configure_handler_event_types(data->tcp_accept_handler_count,
					      data->tcp_accept_handlers,
					      NETIO_EVENT_READ);
	}
	--data->nsd->current_tcp_count;
	assert(data->nsd->current_tcp_count >= 0);

	region_destroy(data->region);
}

static void
handle_tcp_reading(netio_type *netio,
		   netio_handler_type *handler,
		   netio_event_types_type event_types)
{
	struct tcp_handler_data *data
		= (struct tcp_handler_data *) handler->user_data;
	ssize_t received;

	if (event_types & NETIO_EVENT_TIMEOUT) {
		/* Connection timed out.  */
		cleanup_tcp_handler(netio, handler);
		return;
	}

	if (data->nsd->tcp_query_count > 0 &&
		data->query_count >= data->nsd->tcp_query_count) {
		/* No more queries allowed on this tcp connection.  */
		cleanup_tcp_handler(netio, handler);
		return;
	}

	assert(event_types & NETIO_EVENT_READ);

	if (data->bytes_transmitted == 0) {
		query_reset(data->query, TCP_MAX_MESSAGE_LEN, 1);
	}

	/*
	 * Check if we received the leading packet length bytes yet.
	 */
	if (data->bytes_transmitted < sizeof(uint16_t)) {
		received = read(handler->fd,
				(char *) &data->query->tcplen
				+ data->bytes_transmitted,
				sizeof(uint16_t) - data->bytes_transmitted);
		if (received == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				/*
				 * Read would block, wait until more
				 * data is available.
				 */
				return;
			} else {
#ifdef ECONNRESET
				if (verbosity >= 2 || errno != ECONNRESET)
#endif /* ECONNRESET */
				log_msg(LOG_ERR, "failed reading from tcp: %s", strerror(errno));
				cleanup_tcp_handler(netio, handler);
				return;
			}
		} else if (received == 0) {
			/* EOF */
			cleanup_tcp_handler(netio, handler);
			return;
		}

		data->bytes_transmitted += received;
		if (data->bytes_transmitted < sizeof(uint16_t)) {
			/*
			 * Not done with the tcplen yet, wait for more
			 * data to become available.
			 */
			return;
		}

		assert(data->bytes_transmitted == sizeof(uint16_t));

		data->query->tcplen = ntohs(data->query->tcplen);

		/*
		 * Minimum query size is:
		 *
		 *     Size of the header (12)
		 *   + Root domain name   (1)
		 *   + Query class        (2)
		 *   + Query type         (2)
		 */
		if (data->query->tcplen < QHEADERSZ + 1 + sizeof(uint16_t) + sizeof(uint16_t)) {
			VERBOSITY(2, (LOG_WARNING, "packet too small, dropping tcp connection"));
			cleanup_tcp_handler(netio, handler);
			return;
		}

		if (data->query->tcplen > data->query->maxlen) {
			VERBOSITY(2, (LOG_WARNING, "insufficient tcp buffer, dropping connection"));
			cleanup_tcp_handler(netio, handler);
			return;
		}

		buffer_set_limit(data->query->packet, data->query->tcplen);
	}

	assert(buffer_remaining(data->query->packet) > 0);

	/* Read the (remaining) query data.  */
	received = read(handler->fd,
			buffer_current(data->query->packet),
			buffer_remaining(data->query->packet));
	if (received == -1) {
		if (errno == EAGAIN || errno == EINTR) {
			/*
			 * Read would block, wait until more data is
			 * available.
			 */
			return;
		} else {
#ifdef ECONNRESET
			if (verbosity >= 2 || errno != ECONNRESET)
#endif /* ECONNRESET */
			log_msg(LOG_ERR, "failed reading from tcp: %s", strerror(errno));
			cleanup_tcp_handler(netio, handler);
			return;
		}
	} else if (received == 0) {
		/* EOF */
		cleanup_tcp_handler(netio, handler);
		return;
	}

	data->bytes_transmitted += received;
	buffer_skip(data->query->packet, received);
	if (buffer_remaining(data->query->packet) > 0) {
		/*
		 * Message not yet complete, wait for more data to
		 * become available.
		 */
		return;
	}

	assert(buffer_position(data->query->packet) == data->query->tcplen);

	/* Account... */
#ifdef BIND8_STATS
# ifndef INET6
	STATUP(data->nsd, ctcp);
# else
	if (data->query->addr.ss_family == AF_INET) {
		STATUP(data->nsd, ctcp);
	} else if (data->query->addr.ss_family == AF_INET6) {
		STATUP(data->nsd, ctcp6);
	}
# endif
#endif /* BIND8_STATS */

	/* We have a complete query, process it.  */

	/* tcp-query-count: handle query counter ++ */
	data->query_count++;

	buffer_flip(data->query->packet);
	data->query_state = server_process_query(data->nsd, data->query);
	if (data->query_state == QUERY_DISCARDED) {
		/* Drop the packet and the entire connection... */
		STATUP(data->nsd, dropped);
#if defined(BIND8_STATS) && defined(USE_ZONE_STATS)
		if (data->query->zone) {
			ZTATUP(data->query->zone, dropped);
		}
#endif
		cleanup_tcp_handler(netio, handler);
		return;
	}

#ifdef BIND8_STATS
	if (RCODE(data->query->packet) == RCODE_OK
	    && !AA(data->query->packet))
	{
		STATUP(data->nsd, nona);
		ZTATUP(data->query->zone, nona);
	}

# ifdef USE_ZONE_STATS
#  ifndef INET6
	ZTATUP(data->query->zone, ctcp);
#  else
	if (data->query->addr.ss_family == AF_INET) {
		ZTATUP(data->query->zone, ctcp);
	} else if (data->query->addr.ss_family == AF_INET6) {
		ZTATUP(data->query->zone, ctcp6);
	}
#  endif
# endif /* USE_ZONE_STATS */

#endif /* BIND8_STATS */

	query_add_optional(data->query, data->nsd);

	/* Switch to the tcp write handler.  */
	buffer_flip(data->query->packet);
	data->query->tcplen = buffer_remaining(data->query->packet);
	data->bytes_transmitted = 0;

	handler->timeout->tv_sec = data->nsd->tcp_timeout;
	handler->timeout->tv_nsec = 0L;
	timespec_add(handler->timeout, netio_current_time(netio));

	handler->event_types = NETIO_EVENT_WRITE | NETIO_EVENT_TIMEOUT;
	handler->event_handler = handle_tcp_writing;
}

static void
handle_tcp_writing(netio_type *netio,
		   netio_handler_type *handler,
		   netio_event_types_type event_types)
{
	struct tcp_handler_data *data
		= (struct tcp_handler_data *) handler->user_data;
	ssize_t sent;
	struct query *q = data->query;

	if (event_types & NETIO_EVENT_TIMEOUT) {
		/* Connection timed out.  */
		cleanup_tcp_handler(netio, handler);
		return;
	}

	assert(event_types & NETIO_EVENT_WRITE);

	if (data->bytes_transmitted < sizeof(q->tcplen)) {
		/* Writing the response packet length.  */
		uint16_t n_tcplen = htons(q->tcplen);
		sent = write(handler->fd,
			     (const char *) &n_tcplen + data->bytes_transmitted,
			     sizeof(n_tcplen) - data->bytes_transmitted);
		if (sent == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				/*
				 * Write would block, wait until
				 * socket becomes writable again.
				 */
				return;
			} else {
#ifdef ECONNRESET
				if(verbosity >= 2 || errno != ECONNRESET)
#endif /* ECONNRESET */
#ifdef EPIPE
					if(verbosity >= 2 || errno != EPIPE)
#endif /* EPIPE 'broken pipe' */
				log_msg(LOG_ERR, "failed writing to tcp: %s", strerror(errno));
				cleanup_tcp_handler(netio, handler);
				return;
			}
		}

		data->bytes_transmitted += sent;
		if (data->bytes_transmitted < sizeof(q->tcplen)) {
			/*
			 * Writing not complete, wait until socket
			 * becomes writable again.
			 */
			return;
		}

		assert(data->bytes_transmitted == sizeof(q->tcplen));
	}

	assert(data->bytes_transmitted < q->tcplen + sizeof(q->tcplen));

	sent = write(handler->fd,
		     buffer_current(q->packet),
		     buffer_remaining(q->packet));
	if (sent == -1) {
		if (errno == EAGAIN || errno == EINTR) {
			/*
			 * Write would block, wait until
			 * socket becomes writable again.
			 */
			return;
		} else {
#ifdef ECONNRESET
			if(verbosity >= 2 || errno != ECONNRESET)
#endif /* ECONNRESET */
#ifdef EPIPE
					if(verbosity >= 2 || errno != EPIPE)
#endif /* EPIPE 'broken pipe' */
			log_msg(LOG_ERR, "failed writing to tcp: %s", strerror(errno));
			cleanup_tcp_handler(netio, handler);
			return;
		}
	}

	buffer_skip(q->packet, sent);
	data->bytes_transmitted += sent;
	if (data->bytes_transmitted < q->tcplen + sizeof(q->tcplen)) {
		/*
		 * Still more data to write when socket becomes
		 * writable again.
		 */
		return;
	}

	assert(data->bytes_transmitted == q->tcplen + sizeof(q->tcplen));

	if (data->query_state == QUERY_IN_AXFR) {
		/* Continue processing AXFR and writing back results.  */
		buffer_clear(q->packet);
		data->query_state = query_axfr(data->nsd, q);
		if (data->query_state != QUERY_PROCESSED) {
			query_add_optional(data->query, data->nsd);

			/* Reset data. */
			buffer_flip(q->packet);
			q->tcplen = buffer_remaining(q->packet);
			data->bytes_transmitted = 0;
			/* Reset timeout.  */
			handler->timeout->tv_sec = data->nsd->tcp_timeout;
			handler->timeout->tv_nsec = 0;
			timespec_add(handler->timeout, netio_current_time(netio));

			/*
			 * Write data if/when the socket is writable
			 * again.
			 */
			return;
		}
	}

	/*
	 * Done sending, wait for the next request to arrive on the
	 * TCP socket by installing the TCP read handler.
	 */
	if (data->nsd->tcp_query_count > 0 &&
		data->query_count >= data->nsd->tcp_query_count) {

		(void) shutdown(handler->fd, SHUT_WR);
	}

	data->bytes_transmitted = 0;

	handler->timeout->tv_sec = data->nsd->tcp_timeout;
	handler->timeout->tv_nsec = 0;
	timespec_add(handler->timeout, netio_current_time(netio));

	handler->event_types = NETIO_EVENT_READ | NETIO_EVENT_TIMEOUT;
	handler->event_handler = handle_tcp_reading;
}


/*
 * Handle an incoming TCP connection.  The connection is accepted and
 * a new TCP reader event handler is added to NETIO.  The TCP handler
 * is responsible for cleanup when the connection is closed.
 */
static void
handle_tcp_accept(netio_type *netio,
		  netio_handler_type *handler,
		  netio_event_types_type event_types)
{
	struct tcp_accept_handler_data *data
		= (struct tcp_accept_handler_data *) handler->user_data;
	int s;
	struct tcp_handler_data *tcp_data;
	region_type *tcp_region;
	netio_handler_type *tcp_handler;
#ifdef INET6
	struct sockaddr_storage addr;
#else
	struct sockaddr_in addr;
#endif
	socklen_t addrlen;

	if (!(event_types & NETIO_EVENT_READ)) {
		return;
	}

	if (data->nsd->current_tcp_count >= data->nsd->maximum_tcp_count) {
		return;
	}

	/* Accept it... */
	addrlen = sizeof(addr);
	s = accept(handler->fd, (struct sockaddr *) &addr, &addrlen);
	if (s == -1) {
		/**
		 * EMFILE and ENFILE is a signal that the limit of open
		 * file descriptors has been reached. Pause accept().
		 * EINTR is a signal interrupt. The others are various OS ways
		 * of saying that the client has closed the connection.
		 */
		if (errno == EMFILE || errno == ENFILE) {
			if (!slowaccept) {
				slowaccept_timeout.tv_sec = NETIO_SLOW_ACCEPT_TIMEOUT;
				slowaccept_timeout.tv_nsec = 0L;
				timespec_add(&slowaccept_timeout, netio_current_time(netio));
				slowaccept = 1;
				/* We don't want to spam the logs here */
			}
		} else if (errno != EINTR
			&& errno != EWOULDBLOCK
#ifdef ECONNABORTED
			&& errno != ECONNABORTED
#endif /* ECONNABORTED */
#ifdef EPROTO
			&& errno != EPROTO
#endif /* EPROTO */
			) {
			log_msg(LOG_ERR, "accept failed: %s", strerror(errno));
		}
		return;
	}

	if (fcntl(s, F_SETFL, O_NONBLOCK) == -1) {
		log_msg(LOG_ERR, "fcntl failed: %s", strerror(errno));
		close(s);
		return;
	}

	/*
	 * This region is deallocated when the TCP connection is
	 * closed by the TCP handler.
	 */
	tcp_region = region_create(xalloc, free);
	tcp_data = (struct tcp_handler_data *) region_alloc(
		tcp_region, sizeof(struct tcp_handler_data));
	tcp_data->region = tcp_region;
	tcp_data->query = query_create(tcp_region, compressed_dname_offsets,
		compression_table_size);
	tcp_data->nsd = data->nsd;
	tcp_data->query_count = 0;

	tcp_data->tcp_accept_handler_count = data->tcp_accept_handler_count;
	tcp_data->tcp_accept_handlers = data->tcp_accept_handlers;

	tcp_data->query_state = QUERY_PROCESSED;
	tcp_data->bytes_transmitted = 0;
	memcpy(&tcp_data->query->addr, &addr, addrlen);
	tcp_data->query->addrlen = addrlen;

	tcp_handler = (netio_handler_type *) region_alloc(
		tcp_region, sizeof(netio_handler_type));
	tcp_handler->fd = s;
	tcp_handler->timeout = (struct timespec *) region_alloc(
		tcp_region, sizeof(struct timespec));
	tcp_handler->timeout->tv_sec = data->nsd->tcp_timeout;
	tcp_handler->timeout->tv_nsec = 0L;
	timespec_add(tcp_handler->timeout, netio_current_time(netio));

	tcp_handler->user_data = tcp_data;
	tcp_handler->event_types = NETIO_EVENT_READ | NETIO_EVENT_TIMEOUT;
	tcp_handler->event_handler = handle_tcp_reading;

	netio_add_handler(netio, tcp_handler);

	/*
	 * Keep track of the total number of TCP handlers installed so
	 * we can stop accepting connections when the maximum number
	 * of simultaneous TCP connections is reached.
	 */
	++data->nsd->current_tcp_count;
	if (data->nsd->current_tcp_count == data->nsd->maximum_tcp_count) {
		configure_handler_event_types(data->tcp_accept_handler_count,
					      data->tcp_accept_handlers,
					      NETIO_EVENT_NONE);
	}
}

#ifdef BIND8_STATS
static void
set_children_stats(struct nsd* nsd)
{
	size_t i;
	assert(nsd->server_kind == NSD_SERVER_MAIN && nsd->this_child == 0);
	DEBUG(DEBUG_IPC, 1, (LOG_INFO, "parent set stats to send to children"));
	for (i = 0; i < nsd->child_count; ++i) {
		nsd->children[i].need_to_send_STATS = 1;
		nsd->children[i].handler->event_types |= NETIO_EVENT_WRITE;
	}
}
#endif /* BIND8_STATS */

static void
configure_handler_event_types(size_t count,
			      netio_handler_type *handlers,
			      netio_event_types_type event_types)
{
	size_t i;

	assert(handlers);

	for (i = 0; i < count; ++i) {
		handlers[i].event_types = event_types;
	}
}
