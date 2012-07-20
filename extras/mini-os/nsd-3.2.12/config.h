/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define this to enable BIND8 like NSTATS & XSTATS. */
#define BIND8_STATS /**/

/* NSD default chroot directory */
/* #undef CHROOTDIR */

/* Pathname to the NSD configuration file */
#define CONFIGFILE "/etc/nsd/nsd.conf"

/* Define this if on macOSX10.4-darwin8 and setreuid and setregid do not work
   */
/* #undef DARWIN_BROKEN_SETREUID */

/* Pathname to the NSD database */
#define DBFILE "/var/db/nsd/nsd.db"

/* Pathname to the NSD diff transfer journal file. */
#define DIFFFILE "/var/db/nsd/ixfr.db"

/* Define to the default maximum message length with EDNS. */
#define EDNS_MAX_MESSAGE_LEN 4096

/* Define to the default facility for syslog. */
#define FACILITY LOG_DAEMON

/* Define this to enable NSEC3 full prehashing. */
#define FULL_PREHASH /**/

/* Define to 1 if you have the `alarm' function. */
#define HAVE_ALARM 1

/* Define to 1 if you have the `arc4random' function. */
/* #undef HAVE_ARC4RANDOM */

/* Define to 1 if you have the `arc4random_uniform' function. */
/* #undef HAVE_ARC4RANDOM_UNIFORM */

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Whether the C compiler accepts the "format" attribute */
#define HAVE_ATTR_FORMAT 1

/* Whether the C compiler accepts the "unused" attribute */
#define HAVE_ATTR_UNUSED 1

/* Define to 1 if you have the `b64_ntop' function. */
/* #undef HAVE_B64_NTOP */

/* Define to 1 if you have the `b64_pton' function. */
/* #undef HAVE_B64_PTON */

/* Define to 1 if you have the `basename' function. */
#define HAVE_BASENAME 1

/* Define to 1 if your system has a working `chown' function. */
#define HAVE_CHOWN 1

/* Define to 1 if you have the `chroot' function. */
#define HAVE_CHROOT 1

/* if time.h provides ctime_r prototype */
#define HAVE_CTIME_R_PROTO 1

/* Define to 1 if you have the `dup2' function. */
#define HAVE_DUP2 1

/* Define to 1 if you have the `endpwent' function. */
#define HAVE_ENDPWENT 1

/* Define to 1 if you have the `EVP_sha1' function. */
/* #undef HAVE_EVP_SHA1 */

/* Define to 1 if you have the `EVP_sha256' function. */
/* #undef HAVE_EVP_SHA256 */

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* Define to 1 if you have the `freeaddrinfo' function. */
#define HAVE_FREEADDRINFO 1

/* Define to 1 if fseeko (and presumably ftello) exists and is declared. */
#define HAVE_FSEEKO 1

/* Define to 1 if you have the `gai_strerror' function. */
#define HAVE_GAI_STRERROR 1

/* Define to 1 if you have the `getaddrinfo' function. */
#define HAVE_GETADDRINFO 1

/* Define to 1 if you have the `gethostname' function. */
#define HAVE_GETHOSTNAME 1

/* Define to 1 if you have the `getnameinfo' function. */
#define HAVE_GETNAMEINFO 1

/* Define to 1 if you have the `getpwnam' function. */
#define HAVE_GETPWNAM 1

/* Define to 1 if you have the <grp.h> header file. */
#define HAVE_GRP_H 1

/* Define to 1 if you have the `inet_aton' function. */
#define HAVE_INET_ATON 1

/* Define to 1 if you have the `inet_ntop' function. */
#define HAVE_INET_NTOP 1

/* Define to 1 if you have the `inet_pton' function. */
#define HAVE_INET_PTON 1

/* Define to 1 if you have the `initgroups' function. */
#define HAVE_INITGROUPS 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `crypto' library (-lcrypto). */
/* #undef HAVE_LIBCRYPTO */

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if your system has a GNU libc compatible `malloc' function, and
   to 0 otherwise. */
#define HAVE_MALLOC 1

/* Define to 1 if you have the `memcpy' function. */
#define HAVE_MEMCPY 1

/* Define to 1 if you have the `memmove' function. */
#define HAVE_MEMMOVE 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have the `mmap' function. */
/* #undef HAVE_MMAP */

/* Define to 1 if you have the `munmap' function. */
/* #undef HAVE_MUNMAP */

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the `pselect' function. */
#define HAVE_PSELECT 1

/* if sys/select.h provides pselect prototype */
#define HAVE_PSELECT_PROTO 1

/* Define to 1 if you have the `setregid' function. */
#define HAVE_SETREGID 1

/* Define to 1 if you have the `setresgid' function. */
#define HAVE_SETRESGID 1

/* Define to 1 if you have the `setresuid' function. */
#define HAVE_SETRESUID 1

/* Define to 1 if you have the `setreuid' function. */
#define HAVE_SETREUID 1

/* Define to 1 if you have the `setusercontext' function. */
/* #undef HAVE_SETUSERCONTEXT */

/* Define to 1 if you have the `sigaction' function. */
#define HAVE_SIGACTION 1

/* Define to 1 if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* Define to 1 if you have the `sigprocmask' function. */
#define HAVE_SIGPROCMASK 1

/* Define to 1 if you have the `snprintf' function. */
#define HAVE_SNPRINTF 1

/* Define to 1 if you have the `socket' function. */
#define HAVE_SOCKET 1

/* Define if you have the SSL libraries installed. */
/* #undef HAVE_SSL */

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strcasecmp' function. */
#define HAVE_STRCASECMP 1

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
/* #undef HAVE_STRLCAT */

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the `strncasecmp' function. */
#define HAVE_STRNCASECMP 1

/* Define to 1 if you have the `strptime' function. */
#define HAVE_STRPTIME 1

/* Define to 1 if you have the `strtol' function. */
#define HAVE_STRTOL 1

/* If time.h has a struct timespec (for pselect). */
#define HAVE_STRUCT_TIMESPEC 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/bitypes.h> header file. */
#define HAVE_SYS_BITYPES_H 1

/* Define to 1 if you have the <sys/mman.h> header file. */
/* #undef HAVE_SYS_MMAN_H */

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have <sys/wait.h> that is POSIX.1 compatible. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <tcpd.h> header file. */
#define HAVE_TCPD_H 1

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define this if you have double va_list definitions. */
/* #undef HAVE_VA_LIST_DOUBLE_DEF */

/* Define to 1 if you have the `vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the <vfork.h> header file. */
/* #undef HAVE_VFORK_H */

/* Define to 1 if `fork' works. */
#define HAVE_WORKING_FORK 1

/* Define to 1 if `vfork' works. */
#define HAVE_WORKING_VFORK 1

/* Define to the default nsd identity. */
#define IDENTITY "unidentified server"

/* Define this to enable IPv6 support. */
#define INET6 /**/

/* Define to the maximum message length to pass to syslog. */
#define MAXSYSLOGMSGLEN 512

/* Define to the maximum ip-addresses to serve. */
#define MAX_INTERFACES 8

/* Define if memcmp() does not compare unsigned bytes */
/* #undef MEMCMP_IS_BROKEN */

/* Define this to enable response minimalization to reduce truncation. */
#define MINIMAL_RESPONSES /**/

/* Undefine this to enable internal runtime checks. */
#define NDEBUG /**/

/* Define this to enable NSEC3 support. */
#define NSEC3 /**/

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "nsd-bugs@nlnetlabs.nl"

/* Define to the full name of this package. */
#define PACKAGE_NAME "NSD"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "NSD 3.2.12"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "nsd"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "3.2.12"

/* Pathname to the NSD pidfile */
#define PIDFILE "/var/run/nsd.pid"

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Define this to configure as a root server. */
/* #undef ROOT_SERVER */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* strptime is available from time.h with some defines. */
#define STRPTIME_NEEDS_DEFINES 1

/* use default strptime. */
#define STRPTIME_WORKS 1

/* Define to the backlog to be used with listen. */
#define TCP_BACKLOG 5

/* Define to the default maximum message length. */
#define TCP_MAX_MESSAGE_LEN 65535

/* Define to the default tcp port. */
#define TCP_PORT "53"

/* Define to the default tcp timeout. */
#define TCP_TIMEOUT 120

/* Define to the default maximum udp message length. */
#define UDP_MAX_MESSAGE_LEN 512

/* Define to the default udp port. */
#define UDP_PORT "53"

/* the user name to drop privileges to */
#define USER "nsd"

/* Define this to enable mmap instead of malloc. Experimental. */
/* #undef USE_MMAP_ALLOC */

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif


/* Define this to enable zone statistics. */
/* #undef USE_ZONE_STATS */

/* Define to the NSD version to answer version.server query. */
#define VERSION PACKAGE_STRING

/* Pathname to the NSD xfrd zone timer state file. */
#define XFRDFILE "/var/db/nsd/xfrd.state"

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
#define YYTEXT_POINTER 1

/* NSD default location for zone files. Empty string or NULL to disable. */
#define ZONESDIR "/etc/nsd"

/* Pathname to the NSD statistics file */
#define ZONESTATSFILE "/var/log/nsd.stats"

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define to 1 to make fseeko visible on some hosts (e.g. glibc 2.2). */
/* #undef _LARGEFILE_SOURCE */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define to 1 if on MINIX. */
/* #undef _MINIX */

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
/* #undef _POSIX_1_SOURCE */

/* Define to 1 if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* in_addr_t */
/* #undef in_addr_t */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define "int16_t" to "short" if "int16_t" is missing */
/* #undef int16_t */

/* Define "int32_t" to "int" if "int32_t" is missing */
/* #undef int32_t */

/* Define "int64_t" to "long long" if "int64_t" is missing */
/* #undef int64_t */

/* Define "int8_t" to "char" if "int8_t" is missing */
/* #undef int8_t */

/* Define to rpl_malloc if the replacement function should be used. */
/* #undef malloc */

/* Define to `long int' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* Define "sig_atomic_t" to "int" if "sig_atomic_t" is missing */
/* #undef sig_atomic_t */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define "socklen_t" to "int" if "socklen_t" is missing */
/* #undef socklen_t */

/* Fallback member name for socket family in struct sockaddr_storage */
/* #undef ss_family */

/* Define "ssize_t" to "int" if "ssize_t" is missing */
/* #undef ssize_t */

/* Define "suseconds_t" to "time_t" if "suseconds_t" is missing */
/* #undef suseconds_t */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef uid_t */

/* Define "uint16_t" to "unsigned short" if "uint16_t" is missing */
/* #undef uint16_t */

/* Define "uint32_t" to "unsigned int" if "uint32_t" is missing */
/* #undef uint32_t */

/* Define "uint64_t" to "unsigned long long" if "uint64_t" is missing */
/* #undef uint64_t */

/* Define "uint8_t" to "unsigned char" if "uint8_t" is missing */
/* #undef uint8_t */

/* Define "uintptr_t" to "void*" if "uintptr_t" is missing */
/* #undef uintptr_t */

/* Define as `fork' if `vfork' does not work. */
/* #undef vfork */


/* define before includes as it specifies what standard to use. */
#if (defined(HAVE_PSELECT) && !defined (HAVE_PSELECT_PROTO)) \
	|| !defined (HAVE_CTIME_R_PROTO) \
	|| defined (STRPTIME_NEEDS_DEFINES)
#  ifndef _XOPEN_SOURCE
#    define _XOPEN_SOURCE 600
#  endif
#  ifndef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200112
#  endif
#  ifndef _BSD_SOURCE
#    define _BSD_SOURCE 1
#  endif
#  ifndef __EXTENSIONS__
#    define __EXTENSIONS__ 1
#  endif 
#  ifndef _STDC_C99
#    define _STDC_C99 1
#  endif
#  ifndef _ALL_SOURCE
#    define _ALL_SOURCE 1
#  endif
#endif



#ifdef HAVE_VA_LIST_DOUBLE_DEF
/* workaround double va_list definition on some platforms */
#  ifndef _VA_LIST_DEFINED
#    define _VA_LIST_DEFINED
#  endif
#endif



#include <sys/types.h>
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

/* For Tru64 */
#ifdef HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif



#ifdef HAVE_ATTR_FORMAT
#define ATTR_FORMAT(archetype, string_index, first_to_check) \
    __attribute__ ((format (archetype, string_index, first_to_check)))
#else /* !HAVE_ATTR_FORMAT */
#define ATTR_FORMAT(archetype, string_index, first_to_check) /* empty */
#endif /* !HAVE_ATTR_FORMAT */
#if defined(__cplusplus)
#define ATTR_UNUSED(x)
#elif defined(HAVE_ATTR_UNUSED)
#define ATTR_UNUSED(x)  x __attribute__((unused))
#else /* !HAVE_ATTR_UNUSED */
#define ATTR_UNUSED(x)  x
#endif /* !HAVE_ATTR_UNUSED */



#ifndef IPV6_MIN_MTU
#define IPV6_MIN_MTU 1280
#endif /* IPV6_MIN_MTU */

#ifndef AF_INET6
#define AF_INET6	28
#endif /* AF_INET6 */



/* maximum nesting of included files */
#define MAXINCLUDES 10



#ifndef B64_PTON
int b64_ntop(uint8_t const *src, size_t srclength,
	     char *target, size_t targsize);
#endif /* !B64_PTON */
#ifndef B64_NTOP
int b64_pton(char const *src, uint8_t *target, size_t targsize);
#endif /* !B64_NTOP */
#ifndef HAVE_FSEEKO
#define fseeko fseek
#define ftello ftell
#endif /* HAVE_FSEEKO */
#ifndef HAVE_SNPRINTF
#include <stdarg.h>
int snprintf (char *str, size_t count, const char *fmt, ...);
int vsnprintf (char *str, size_t count, const char *fmt, va_list arg);
#endif /* HAVE_SNPRINTF */
#ifndef HAVE_INET_PTON
int inet_pton(int af, const char* src, void* dst);
#endif /* HAVE_INET_PTON */
#ifndef HAVE_INET_NTOP
const char *inet_ntop(int af, const void *src, char *dst, size_t size);
#endif
#ifndef HAVE_INET_ATON
int inet_aton(const char *cp, struct in_addr *addr);
#endif
#ifndef HAVE_MEMMOVE
void *memmove(void *dest, const void *src, size_t n);
#endif
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif
#ifndef HAVE_GETADDRINFO
#include "compat/fake-rfc2553.h"
#endif
#ifndef HAVE_STRPTIME
#define HAVE_STRPTIME 1
char *strptime(const char *s, const char *format, struct tm *tm); 
#endif
#ifndef STRPTIME_WORKS
#define STRPTIME_WORKS 1
#define strptime(a,b,c) nsd_strptime((a),(b),(c))
#endif



#ifdef MEMCMP_IS_BROKEN
#include "compat/memcmp.h"
#define memcmp memcmp_nsd
int memcmp(const void *x, const void *y, size_t n);
#endif





/* provide timespec def if not available */
#ifndef CONFIG_DEFINES
#define CONFIG_DEFINES
#ifndef HAVE_STRUCT_TIMESPEC
#ifndef __timespec_defined
#define __timespec_defined 1
	struct timespec {
		long    tv_sec;         /* seconds */
		long    tv_nsec;        /* nanoseconds */
	};
#endif /* !__timespec_defined */
#endif /* !HAVE_STRUCT_TIMESPEC */
#endif /* !CONFIG_DEFINES */

