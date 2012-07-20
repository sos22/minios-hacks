/******************************************************************************
 * xc_acm.c
 *
 * Copyright (C) 2005, 2006 IBM Corporation, R Sailer
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "xc_private.h"

int xc_acm_op(xc_interface *xch, int cmd, void *arg, unsigned long arg_size)
{
    int ret;
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(struct xen_acmctl, acmctl);

    acmctl = xc_hypercall_buffer_alloc(xch, acmctl, sizeof(*acmctl));
    if ( acmctl == NULL )
    {
        PERROR("Could not allocate memory for ACM OP hypercall");
        return -EFAULT;
    }

    switch (cmd) {
        case ACMOP_setpolicy: {
            struct acm_setpolicy *setpolicy = (struct acm_setpolicy *)arg;
            memcpy(&acmctl->u.setpolicy,
                   setpolicy,
                   sizeof(struct acm_setpolicy));
        }
        break;

        case ACMOP_getpolicy: {
            struct acm_getpolicy *getpolicy = (struct acm_getpolicy *)arg;
            memcpy(&acmctl->u.getpolicy,
                   getpolicy,
                   sizeof(struct acm_getpolicy));
        }
        break;

        case ACMOP_dumpstats: {
            struct acm_dumpstats *dumpstats = (struct acm_dumpstats *)arg;
            memcpy(&acmctl->u.dumpstats,
                   dumpstats,
                   sizeof(struct acm_dumpstats));
        }
        break;

        case ACMOP_getssid: {
            struct acm_getssid *getssid = (struct acm_getssid *)arg;
            memcpy(&acmctl->u.getssid,
                   getssid,
                   sizeof(struct acm_getssid));
        }
        break;

        case ACMOP_getdecision: {
            struct acm_getdecision *getdecision = (struct acm_getdecision *)arg;
            memcpy(&acmctl->u.getdecision,
                   getdecision,
                   sizeof(struct acm_getdecision));
        }
        break;

        case ACMOP_chgpolicy: {
            struct acm_change_policy *change_policy = (struct acm_change_policy *)arg;
            memcpy(&acmctl->u.change_policy,
                   change_policy,
                   sizeof(struct acm_change_policy));
        }
        break;

        case ACMOP_relabeldoms: {
            struct acm_relabel_doms *relabel_doms = (struct acm_relabel_doms *)arg;
            memcpy(&acmctl->u.relabel_doms,
                   relabel_doms,
                   sizeof(struct acm_relabel_doms));
        }
        break;
    }

    acmctl->cmd = cmd;
    acmctl->interface_version = ACM_INTERFACE_VERSION;

    hypercall.op = __HYPERVISOR_xsm_op;
    hypercall.arg[0] = HYPERCALL_BUFFER_AS_ARG(acmctl);
    if ( (ret = do_xen_hypercall(xch, &hypercall)) < 0)
    {
        if ( errno == EACCES )
            DPRINTF("acmctl operation failed -- need to"
                    " rebuild the user-space tool set?\n");
    }

    switch (cmd) {
        case ACMOP_getdecision: {
            struct acm_getdecision *getdecision = (struct acm_getdecision *)arg;
            memcpy(getdecision,
                   &acmctl->u.getdecision,
                   sizeof(struct acm_getdecision));
            break;
        }
    }

    xc_hypercall_buffer_free(xch, acmctl);

    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
