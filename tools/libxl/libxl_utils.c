/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Stefano Stabellini <stefano.stabellini@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_osdeps.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <xs.h>
#include <xenctrl.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "libxl_utils.h"
#include "libxl_internal.h"

struct schedid_name {
    char *name;
    int id;
};

static struct schedid_name schedid_name[] = {
    { "credit", XEN_SCHEDULER_CREDIT },
    { "sedf", XEN_SCHEDULER_SEDF },
    { "credit2", XEN_SCHEDULER_CREDIT2 },
    { NULL, -1 }
};

const char *libxl_basename(const char *name)
{
    const char *filename;
    if (name == NULL)
        return strdup(".");
    if (name[0] == '\0')
        return strdup(".");

    filename = strrchr(name, '/');
    if (filename)
        return strdup(filename+1);
    return strdup(name);
}

unsigned long libxl_get_required_shadow_memory(unsigned long maxmem_kb, unsigned int smp_cpus)
{
    /* 256 pages (1MB) per vcpu,
       plus 1 page per MiB of RAM for the P2M map,
       plus 1 page per MiB of RAM to shadow the resident processes.
       This is higher than the minimum that Xen would allocate if no value
       were given (but the Xen minimum is for safety, not performance).
     */
    return 4 * (256 * smp_cpus + 2 * (maxmem_kb / 1024));
}

char *libxl_domid_to_name(libxl_ctx *ctx, uint32_t domid)
{
    unsigned int len;
    char path[strlen("/local/domain") + 12];
    char *s;

    snprintf(path, sizeof(path), "/local/domain/%d/name", domid);
    s = xs_read(ctx->xsh, XBT_NULL, path, &len);
    return s;
}

char *libxl__domid_to_name(libxl__gc *gc, uint32_t domid)
{
    char *s = libxl_domid_to_name(libxl__gc_owner(gc), domid);
    if ( s )
        libxl__ptr_add(gc, s);
    return s;
}

int libxl_name_to_domid(libxl_ctx *ctx, const char *name,
                        uint32_t *domid)
{
    int i, nb_domains;
    char *domname;
    libxl_dominfo *dominfo;
    int ret = ERROR_INVAL;

    dominfo = libxl_list_domain(ctx, &nb_domains);
    if (!dominfo)
        return ERROR_NOMEM;

    for (i = 0; i < nb_domains; i++) {
        domname = libxl_domid_to_name(ctx, dominfo[i].domid);
        if (!domname)
            continue;
        if (strcmp(domname, name) == 0) {
            *domid = dominfo[i].domid;
            ret = 0;
            free(domname);
            break;
        }
        free(domname);
    }
    free(dominfo);
    return ret;
}

char *libxl_cpupoolid_to_name(libxl_ctx *ctx, uint32_t poolid)
{
    unsigned int len;
    char path[strlen("/local/pool") + 12];
    char *s;

    snprintf(path, sizeof(path), "/local/pool/%d/name", poolid);
    s = xs_read(ctx->xsh, XBT_NULL, path, &len);
    if (!s && (poolid == 0))
        return strdup("Pool-0");
    return s;
}

char *libxl__cpupoolid_to_name(libxl__gc *gc, uint32_t poolid)
{
    char *s = libxl_cpupoolid_to_name(libxl__gc_owner(gc), poolid);
    if ( s )
        libxl__ptr_add(gc, s);
    return s;
}

int libxl_name_to_cpupoolid(libxl_ctx *ctx, const char *name,
                        uint32_t *poolid)
{
    int i, nb_pools;
    char *poolname;
    libxl_cpupoolinfo *poolinfo;
    int ret = ERROR_INVAL;

    poolinfo = libxl_list_cpupool(ctx, &nb_pools);
    if (!poolinfo)
        return ERROR_NOMEM;

    for (i = 0; i < nb_pools; i++) {
        if (ret && ((poolname = libxl_cpupoolid_to_name(ctx,
            poolinfo[i].poolid)) != NULL)) {
            if (strcmp(poolname, name) == 0) {
                *poolid = poolinfo[i].poolid;
                ret = 0;
            }
            free(poolname);
        }
        libxl_cpupoolinfo_destroy(poolinfo + i);
    }
    free(poolinfo);
    return ret;
}

int libxl_name_to_schedid(libxl_ctx *ctx, const char *name)
{
    int i;

    for (i = 0; schedid_name[i].name != NULL; i++)
        if (strcmp(name, schedid_name[i].name) == 0)
            return schedid_name[i].id;

    return ERROR_INVAL;
}

char *libxl_schedid_to_name(libxl_ctx *ctx, int schedid)
{
    int i;

    for (i = 0; schedid_name[i].name != NULL; i++)
        if (schedid_name[i].id == schedid)
            return schedid_name[i].name;

    return "unknown";
}

int libxl_get_stubdom_id(libxl_ctx *ctx, int guest_domid)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    char * stubdom_id_s;
    int ret;

    stubdom_id_s = libxl__xs_read(&gc, XBT_NULL,
                                 libxl__sprintf(&gc, "%s/image/device-model-domid",
                                               libxl__xs_get_dompath(&gc, guest_domid)));
    if (stubdom_id_s)
        ret = atoi(stubdom_id_s);
    else
        ret = 0;
    libxl__free_all(&gc);
    return ret;
}

int libxl_is_stubdom(libxl_ctx *ctx, uint32_t domid, uint32_t *target_domid)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    char *target, *endptr;
    uint32_t value;
    int ret = 0;

    target = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/target", libxl__xs_get_dompath(&gc, domid)));
    if (!target)
        goto out;
    value = strtol(target, &endptr, 10);
    if (*endptr != '\0')
        goto out;
    if (target_domid)
        *target_domid = value;
    ret = 1;
out:
    libxl__free_all(&gc);
    return ret;
}

static int logrename(libxl_ctx *ctx, const char *old, const char *new) {
    int r;

    r = rename(old, new);
    if (r) {
        if (errno == ENOENT) return 0; /* ok */

        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "failed to rotate logfile - could not"
                     " rename %s to %s", old, new);
        return ERROR_FAIL;
    }
    return 0;
}

int libxl_create_logfile(libxl_ctx *ctx, char *name, char **full_name)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    struct stat stat_buf;
    char *logfile, *logfile_new;
    int i, rc;

    logfile = libxl__sprintf(&gc, "/var/log/xen/%s.log", name);
    if (stat(logfile, &stat_buf) == 0) {
        /* file exists, rotate */
        logfile = libxl__sprintf(&gc, "/var/log/xen/%s.log.10", name);
        unlink(logfile);
        for (i = 9; i > 0; i--) {
            logfile = libxl__sprintf(&gc, "/var/log/xen/%s.log.%d", name, i);
            logfile_new = libxl__sprintf(&gc, "/var/log/xen/%s.log.%d", name, i + 1);
            rc = logrename(ctx, logfile, logfile_new);
            if (rc)
                goto out;
        }
        logfile = libxl__sprintf(&gc, "/var/log/xen/%s.log", name);
        logfile_new = libxl__sprintf(&gc, "/var/log/xen/%s.log.1", name);

        rc = logrename(ctx, logfile, logfile_new);
        if (rc)
            goto out;
    } else {
        if (errno != ENOENT)
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_WARNING, "problem checking existence of"
                         " logfile %s, which might have needed to be rotated",
                         name);
    }
    *full_name = strdup(logfile);
    rc = 0;
out:
    libxl__free_all(&gc);
    return rc;
}

int libxl_string_to_backend(libxl_ctx *ctx, char *s, libxl_disk_backend *backend)
{
    char *p;
    int rc = 0;

    if (!strcmp(s, "phy")) {
        *backend = DISK_BACKEND_PHY;
    } else if (!strcmp(s, "file")) {
        *backend = DISK_BACKEND_TAP;
    } else if (!strcmp(s, "tap")) {
        p = strchr(s, ':');
        if (!p) {
            rc = ERROR_INVAL;
            goto out;
        }
        p++;
        if (!strcmp(p, "vhd")) {
            *backend = DISK_BACKEND_TAP;
        } else if (!strcmp(p, "qcow")) {
            *backend = DISK_BACKEND_QDISK;
        } else if (!strcmp(p, "qcow2")) {
            *backend = DISK_BACKEND_QDISK;
        }
    }
out:
    return rc;
}

int libxl_read_file_contents(libxl_ctx *ctx, const char *filename,
                             void **data_r, int *datalen_r) {
    FILE *f = 0;
    uint8_t *data = 0;
    int datalen = 0;
    int e;
    struct stat stab;
    ssize_t rs;
    
    f = fopen(filename, "r");
    if (!f) {
        if (errno == ENOENT) return ENOENT;
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "failed to open %s", filename);
        goto xe;
    }

    if (fstat(fileno(f), &stab)) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "failed to fstat %s", filename);
        goto xe;
    }

    if (!S_ISREG(stab.st_mode)) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "%s is not a plain file", filename);
        errno = ENOTTY;
        goto xe;
    }

    if (stab.st_size > INT_MAX) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "file %s is far too large", filename);
        errno = EFBIG;
        goto xe;
    }

    datalen = stab.st_size;

    if (stab.st_size && data_r) {
        data = malloc(datalen);
        if (!data) goto xe;

        rs = fread(data, 1, datalen, f);
        if (rs != datalen) {
            if (ferror(f))
                LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "failed to read %s", filename);
            else if (feof(f))
                LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "%s changed size while we"
                       " were reading it", filename);
            else
                abort();
            goto xe;
        }
    }

    if (fclose(f)) {
        f = 0;
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "failed to close %s", filename);
        goto xe;
    }

    if (data_r) *data_r = data;
    if (datalen_r) *datalen_r = datalen;

    return 0;

 xe:
    e = errno;
    assert(e != ENOENT);
    if (f) fclose(f);
    if (data) free(data);
    return e;
}

#define READ_WRITE_EXACTLY(rw, zero_is_eof, constdata)                    \
                                                                          \
  int libxl_##rw##_exactly(libxl_ctx *ctx, int fd,                 \
                           constdata void *data, ssize_t sz,              \
                           const char *filename, const char *what) {      \
      ssize_t got;                                                        \
                                                                          \
      while (sz > 0) {                                                    \
          got = rw(fd, data, sz);                                         \
          if (got == -1) {                                                \
              if (errno == EINTR) continue;                               \
              if (!ctx) return errno;                                     \
              LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "failed to " #rw " %s%s%s", \
                           what?what:"", what?" from ":"", filename);     \
              return errno;                                               \
          }                                                               \
          if (got == 0) {                                                 \
              if (!ctx) return EPROTO;                                    \
              LIBXL__LOG(ctx, LIBXL__LOG_ERROR,                                   \
                     zero_is_eof                                          \
                     ? "file/stream truncated reading %s%s%s"             \
                     : "file/stream write returned 0! writing %s%s%s",    \
                     what?what:"", what?" from ":"", filename);           \
              return EPROTO;                                              \
          }                                                               \
          sz -= got;                                                      \
          data = (char*)data + got;                                       \
      }                                                                   \
      return 0;                                                           \
  }

READ_WRITE_EXACTLY(read, 1, /* */)
READ_WRITE_EXACTLY(write, 0, const)


int libxl_ctx_postfork(libxl_ctx *ctx) {
    if (ctx->xsh) xs_daemon_destroy_postfork(ctx->xsh);
    ctx->xsh = xs_daemon_open();
    if (!ctx->xsh) return ERROR_FAIL;
    return 0;
}

pid_t libxl_fork(libxl_ctx *ctx)
{
    pid_t pid;

    pid = fork();
    if (pid == -1) {
        LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "fork failed");
        return -1;
    }

    if (!pid) {
        if (ctx->xsh) xs_daemon_destroy_postfork(ctx->xsh);
        ctx->xsh = 0;
        /* This ensures that anyone who forks but doesn't exec,
         * and doesn't reinitialise the libxl_ctx, is OK.
         * It also means they can safely call libxl_ctx_free. */
    }

    return pid;
}

int libxl_pipe(libxl_ctx *ctx, int pipes[2])
{
    if (pipe(pipes) < 0) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Failed to create a pipe");
        return -1;
    }
    return 0;
}

int libxl_mac_to_device_nic(libxl_ctx *ctx, uint32_t domid,
                            const char *mac, libxl_device_nic *nic)
{
    libxl_nicinfo *nics;
    unsigned int nb, i;
    int found;
    uint8_t mac_n[6];
    uint8_t *a, *b;
    const char *tok;
    char *endptr;

    nics = libxl_list_nics(ctx, domid, &nb);
    if (!nics)
        return ERROR_FAIL;

    for (i = 0, tok = mac; *tok && (i < 6); ++i, tok += 3) {
        mac_n[i] = strtol(tok, &endptr, 16);
        if (endptr != (tok + 2))
            return ERROR_INVAL;
    }
    memset(nic, 0, sizeof (libxl_device_nic));
    found = 0;
    for (i = 0; i < nb; ++i) {
        for (i = 0, a = nics[i].mac, b = mac_n;
             (b < mac_n + 6) && (*a == *b); ++a, ++b)
            ;
        if ((b >= mac_n + 6) && (*a == *b)) {
            nic->backend_domid = nics[i].backend_id;
            nic->domid = nics[i].frontend_id;
            nic->devid = nics[i].devid;
            memcpy(nic->mac, nics[i].mac, sizeof (nic->mac));
            nic->script = strdup(nics[i].script);
            found = 1;
            break;
        }
    }

    for (i=0; i<nb; i++)
        libxl_nicinfo_destroy(&nics[i]);
    free(nics);
    return found;
}

int libxl_devid_to_device_nic(libxl_ctx *ctx, uint32_t domid,
                              const char *devid, libxl_device_nic *nic)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    char *tok, *val;
    char *dompath, *nic_path_fe, *nic_path_be;
    unsigned int i;
    int rc = ERROR_FAIL;

    memset(nic, 0, sizeof (libxl_device_nic));
    dompath = libxl__xs_get_dompath(&gc, domid);
    if (!dompath) {
        goto out;
    }
    nic_path_fe = libxl__sprintf(&gc, "%s/device/vif/%s", dompath, devid);
    nic_path_be = libxl__xs_read(&gc, XBT_NULL,
                                libxl__sprintf(&gc, "%s/backend", nic_path_fe));
    val = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/backend-id", nic_path_fe));
    if ( NULL == val ) {
        goto out;
    }
    nic->backend_domid = strtoul(val, NULL, 10);
    nic->devid = strtoul(devid, NULL, 10);

    val = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/mac", nic_path_fe));
    for (i = 0, tok = strtok(val, ":"); tok && (i < 6);
         ++i, tok = strtok(NULL, ":")) {
        nic->mac[i] = strtoul(tok, NULL, 16);
    }
    nic->script = xs_read(ctx->xsh, XBT_NULL, libxl__sprintf(&gc, "%s/script", nic_path_be), NULL);
    rc = 0;
out:
    libxl__free_all(&gc);
    return rc;
}

int libxl_devid_to_device_disk(libxl_ctx *ctx, uint32_t domid,
                               const char *devid, libxl_device_disk *disk)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    char *val;
    char *dompath, *diskpath, *be_path;
    unsigned int devid_n;
    int rc = ERROR_INVAL;

    devid_n = libxl__device_disk_dev_number(devid);
    if (devid_n < 0) {
        goto out;
    }
    rc = ERROR_FAIL;
    dompath = libxl__xs_get_dompath(&gc, domid);
    diskpath = libxl__sprintf(&gc, "%s/device/vbd/%d", dompath, devid_n);
    if (!diskpath) {
        goto out;
    }

    val = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/backend-id", diskpath));
    if (!val)
        goto out;
    disk->backend_domid = strtoul(val, NULL, 10);
    disk->domid = domid;
    be_path = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/backend", diskpath));
    disk->pdev_path = xs_read(ctx->xsh, XBT_NULL, libxl__sprintf(&gc, "%s/params", be_path), NULL);
    val = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/type", be_path));
    libxl_string_to_backend(ctx, val, &(disk->backend));
    disk->vdev = xs_read(ctx->xsh, XBT_NULL, libxl__sprintf(&gc, "%s/dev", be_path), NULL);
    val = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/removable", be_path));
    disk->unpluggable = !strcmp(val, "1");
    val = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/mode", be_path));
    disk->readwrite = !!strcmp(val, "w");
    val = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/device-type", diskpath));
    disk->is_cdrom = !strcmp(val, "cdrom");
    rc = 0;

out:
    libxl__free_all(&gc);
    return rc;
}

int libxl_devid_to_device_net2(libxl_ctx *ctx, uint32_t domid,
                               const char *devid, libxl_device_net2 *net2)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    char *tok, *endptr, *val;
    char *dompath, *net2path, *be_path;
    unsigned int devid_n, i;
    int rc = ERROR_INVAL;

    devid_n = strtoul(devid, &endptr, 10);
    if (devid == endptr) {
        goto out;
    }
    rc = ERROR_FAIL;
    dompath = libxl__xs_get_dompath(&gc, domid);
    net2path = libxl__sprintf(&gc, "%s/device/vif2/%s", dompath, devid);
    if (!net2path) {
        goto out;
    }
    memset(net2, 0, sizeof (libxl_device_net2));
    be_path = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/backend", net2path));

    net2->devid = devid_n;
    val = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/mac", net2path));
    for (i = 0, tok = strtok(val, ":"); tok && (i < 6);
         ++i, tok = strtok(NULL, ":")) {
        net2->front_mac[i] = strtoul(tok, NULL, 16);
    }
    val = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/remote-mac", net2path));
    for (i = 0, tok = strtok(val, ":"); tok && (i < 6);
         ++i, tok = strtok(NULL, ":")) {
        net2->back_mac[i] = strtoul(tok, NULL, 16);
    }
    val = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/backend-id", net2path));
    net2->backend_domid = strtoul(val, NULL, 10);

    net2->domid = domid;
    val = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/remote-trusted", be_path));
    net2->trusted = strtoul(val, NULL, 10);
    val = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/local-trusted", be_path));
    net2->back_trusted = strtoul(val, NULL, 10);
    val = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/filter-mac", be_path));
    net2->filter_mac = strtoul(val, NULL, 10);
    val = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/filter-mac", net2path));
    net2->front_filter_mac = strtoul(val, NULL, 10);
    val = libxl__xs_read(&gc, XBT_NULL, libxl__sprintf(&gc, "%s/max-bypasses", be_path));
    net2->max_bypasses = strtoul(val, NULL, 10);
    rc = 0;

out:
    libxl__free_all(&gc);
    return rc;
}

int libxl_strtomac(const char *mac_s, uint8_t *mac)
{
    const char *end = mac_s + 17;
    char val, *endptr;

    for (; mac_s < end; mac_s += 3, ++mac) {
        val = strtoul(mac_s, &endptr, 16);
        if (endptr != (mac_s + 2)) {
            return ERROR_INVAL;
        }
        *mac = val;
    }
    return 0;
}

#define QEMU_VERSION_STR  "QEMU emulator version "


int libxl_check_device_model_version(libxl_ctx *ctx, char *path)
{
    libxl__gc gc = LIBXL_INIT_GC(ctx);
    pid_t pid = -1;
    int pipefd[2];
    char buf[100];
    ssize_t i, count = 0;
    int status;
    char *abs_path = NULL;
    int rc = -1;

    abs_path = libxl__abs_path(&gc, path, libxl_private_bindir_path());

    if (pipe(pipefd))
        goto out;

    pid = fork();
    if (pid == -1) {
        goto out;
    }

    if (!pid) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) == -1)
            exit(1);
        execlp(abs_path, abs_path, "-h", NULL);

        close(pipefd[1]);
        exit(127);
    }

    close(pipefd[1]);

    /* attempt to get the first line of `qemu -h` */
    while ((i = read(pipefd[0], buf + count, 99 - count)) > 0) {
        if (i + count > 90)
            break;
        for (int j = 0; j <  i; j++) {
            if (buf[j + count] == '\n')
                break;
        }
        count += i;
    }
    count += i;
    close(pipefd[0]);
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        goto out;
    }

    /* Check if we have the forked qemu-xen. */
    /* QEMU-DM emulator version 0.10.2, ... */
    if (strncmp("QEMU-DM ", buf, 7) == 0) {
        rc = 0;
        goto out;
    }

    /* Check if the version is above 12.0 */
    /* The first line is : QEMU emulator version 0.12.50, ... */
    if (strncmp(QEMU_VERSION_STR, buf, strlen(QEMU_VERSION_STR)) == 0) {
        int major, minor;
        char *endptr = NULL;
        char *v = buf + strlen(QEMU_VERSION_STR);

        major = strtol(v, &endptr, 10);
        if (major == 0 && endptr && *endptr == '.') {
            v = endptr + 1;
            minor = strtol(v, &endptr, 10);
            if (minor >= 12) {
                rc = 1;
                goto out;
            }
        }
    }
    rc = 0;
out:
    libxl__free_all(&gc);
    return rc;
}

int libxl_cpumap_alloc(libxl_ctx *ctx, libxl_cpumap *cpumap)
{
    int max_cpus;
    int sz;

    max_cpus = libxl_get_max_cpus(ctx);
    if (max_cpus == 0)
        return ERROR_FAIL;

    sz = (max_cpus + 7) / 8;
    cpumap->map = calloc(sz, sizeof(*cpumap->map));
    if (!cpumap->map)
        return ERROR_NOMEM;
    cpumap->size = sz;
    return 0;
}

void libxl_cpumap_destroy(libxl_cpumap *map)
{
    free(map->map);
}

int libxl_cpumap_test(libxl_cpumap *cpumap, int cpu)
{
    if (cpu >= cpumap->size * 8)
        return 0;
    return (cpumap->map[cpu / 8] & (1 << (cpu & 7))) ? 1 : 0;
}

void libxl_cpumap_set(libxl_cpumap *cpumap, int cpu)
{
    if (cpu >= cpumap->size * 8)
        return;
    cpumap->map[cpu / 8] |= 1 << (cpu & 7);
}

void libxl_cpumap_reset(libxl_cpumap *cpumap, int cpu)
{
    if (cpu >= cpumap->size * 8)
        return;
    cpumap->map[cpu / 8] &= ~(1 << (cpu & 7));
}

int libxl_cpuarray_alloc(libxl_ctx *ctx, libxl_cpuarray *cpuarray)
{
    int max_cpus;
    int i;

    max_cpus = libxl_get_max_cpus(ctx);
    if (max_cpus == 0)
        return ERROR_FAIL;

    cpuarray->array = calloc(max_cpus, sizeof(*cpuarray->array));
    if (!cpuarray->array)
        return ERROR_NOMEM;
    cpuarray->entries = max_cpus;
    for (i = 0; i < max_cpus; i++)
        cpuarray->array[i] = LIBXL_CPUARRAY_INVALID_ENTRY;

    return 0;
}

void libxl_cpuarray_destroy(libxl_cpuarray *array)
{
    free(array->array);
}

int libxl_get_max_cpus(libxl_ctx *ctx)
{
    return xc_get_max_cpus(ctx->xch);
}
