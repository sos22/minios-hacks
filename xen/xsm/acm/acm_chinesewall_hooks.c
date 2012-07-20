/****************************************************************
 * acm_chinesewall_hooks.c
 * 
 * Copyright (C) 2005 IBM Corporation
 *
 * Author:
 * Reiner Sailer <sailer@watson.ibm.com>
 *
 * Contributions:
 * Stefan Berger <stefanb@watson.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * sHype Chinese Wall Policy for Xen
 *    This code implements the hooks that are called
 *    throughout Xen operations and decides authorization
 *    based on domain types and Chinese Wall conflict type 
 *    sets. The CHWALL policy decides if a new domain can be started
 *    based on the types of running domains and the type of the
 *    new domain to be started. If the new domain's type is in
 *    conflict with types of running domains, then this new domain
 *    is not allowed to be created. A domain can have multiple types,
 *    in which case all types of a new domain must be conflict-free
 *    with all types of already running domains.
 *
 * indent -i4 -kr -nut
 *
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/delay.h>
#include <xen/sched.h>
#include <public/xsm/acm.h>
#include <asm/atomic.h>
#include <xsm/acm/acm_core.h>
#include <xsm/acm/acm_hooks.h>
#include <xsm/acm/acm_endian.h>

ssidref_t dom0_chwall_ssidref = 0x0001;

/* local cache structures for chinese wall policy */
struct chwall_binary_policy chwall_bin_pol;

/*
 * Initializing chinese wall policy (will be filled by policy partition
 * using setpolicy command)
 */
int acm_init_chwall_policy(void)
{
    /* minimal startup policy; policy write-locked already */
    chwall_bin_pol.max_types = 1;
    chwall_bin_pol.max_ssidrefs = 1 + dom0_chwall_ssidref;
    chwall_bin_pol.max_conflictsets = 1;
    chwall_bin_pol.ssidrefs =
        (domaintype_t *) xmalloc_array(domaintype_t,
                                       chwall_bin_pol.max_ssidrefs *
                                       chwall_bin_pol.max_types);
    chwall_bin_pol.conflict_sets =
        (domaintype_t *) xmalloc_array(domaintype_t,
                                       chwall_bin_pol.max_conflictsets *
                                       chwall_bin_pol.max_types);
    chwall_bin_pol.running_types =
        (domaintype_t *) xmalloc_array(domaintype_t,
                                       chwall_bin_pol.max_types);
    chwall_bin_pol.conflict_aggregate_set =
        (domaintype_t *) xmalloc_array(domaintype_t,
                                       chwall_bin_pol.max_types);

    if ( (chwall_bin_pol.conflict_sets == NULL)
        || (chwall_bin_pol.running_types == NULL)
        || (chwall_bin_pol.ssidrefs == NULL)
        || (chwall_bin_pol.conflict_aggregate_set == NULL) )
        return ACM_INIT_SSID_ERROR;

    /* initialize state */
    memset((void *) chwall_bin_pol.ssidrefs, 0,
           chwall_bin_pol.max_ssidrefs * chwall_bin_pol.max_types *
           sizeof(domaintype_t));
    memset((void *) chwall_bin_pol.conflict_sets, 0,
           chwall_bin_pol.max_conflictsets * chwall_bin_pol.max_types *
           sizeof(domaintype_t));
    memset((void *) chwall_bin_pol.running_types, 0,
           chwall_bin_pol.max_types * sizeof(domaintype_t));
    memset((void *) chwall_bin_pol.conflict_aggregate_set, 0,
           chwall_bin_pol.max_types * sizeof(domaintype_t));
    return ACM_OK;
}


static int chwall_init_domain_ssid(void **chwall_ssid, ssidref_t ssidref)
{
    struct chwall_ssid *chwall_ssidp = xmalloc(struct chwall_ssid);
    traceprintk("%s.\n", __func__);

    if ( chwall_ssidp == NULL )
        return ACM_INIT_SSID_ERROR;

    chwall_ssidp->chwall_ssidref =
        GET_SSIDREF(ACM_CHINESE_WALL_POLICY, ssidref);

    if ( chwall_ssidp->chwall_ssidref >= chwall_bin_pol.max_ssidrefs )
    {
        printkd("%s: ERROR chwall_ssidref(%x) undefined (>max) or unset "
                "(0).\n",
                __func__, chwall_ssidp->chwall_ssidref);
        xfree(chwall_ssidp);
        return ACM_INIT_SSID_ERROR;
    }
    (*chwall_ssid) = chwall_ssidp;
    printkd("%s: determined chwall_ssidref to %x.\n",
            __func__, chwall_ssidp->chwall_ssidref);
    return ACM_OK;
}


static void chwall_free_domain_ssid(void *chwall_ssid)
{
    xfree(chwall_ssid);
    return;
}


/* dump chinese wall cache; policy read-locked already */
static int chwall_dump_policy(u8 * buf, u32 buf_size)
{
    struct acm_chwall_policy_buffer *chwall_buf =
        (struct acm_chwall_policy_buffer *) buf;
    int ret = 0;

    if ( buf_size < sizeof(struct acm_chwall_policy_buffer) )
        return -EINVAL;

    chwall_buf->chwall_max_types = cpu_to_be32(chwall_bin_pol.max_types);
    chwall_buf->chwall_max_ssidrefs = cpu_to_be32(chwall_bin_pol.max_ssidrefs);
    chwall_buf->policy_code = cpu_to_be32(ACM_CHINESE_WALL_POLICY);
    chwall_buf->chwall_ssid_offset =
        cpu_to_be32(sizeof(struct acm_chwall_policy_buffer));
    chwall_buf->chwall_max_conflictsets =
        cpu_to_be32(chwall_bin_pol.max_conflictsets);
    chwall_buf->chwall_conflict_sets_offset =
        cpu_to_be32(be32_to_cpu(chwall_buf->chwall_ssid_offset) +
              sizeof(domaintype_t) * chwall_bin_pol.max_ssidrefs *
              chwall_bin_pol.max_types);
    chwall_buf->chwall_running_types_offset =
        cpu_to_be32(be32_to_cpu(chwall_buf->chwall_conflict_sets_offset) +
              sizeof(domaintype_t) * chwall_bin_pol.max_conflictsets *
              chwall_bin_pol.max_types);
    chwall_buf->chwall_conflict_aggregate_offset =
        cpu_to_be32(be32_to_cpu(chwall_buf->chwall_running_types_offset) +
              sizeof(domaintype_t) * chwall_bin_pol.max_types);

    ret = be32_to_cpu(chwall_buf->chwall_conflict_aggregate_offset) +
        sizeof(domaintype_t) * chwall_bin_pol.max_types;

    ret = (ret + 7) & ~7;

    if ( buf_size < ret )
        return -EINVAL;

    /* now copy buffers over */
    arrcpy16((u16 *) (buf + be32_to_cpu(chwall_buf->chwall_ssid_offset)),
             chwall_bin_pol.ssidrefs,
             chwall_bin_pol.max_ssidrefs * chwall_bin_pol.max_types);

    arrcpy16((u16 *) (buf +
                      be32_to_cpu(chwall_buf->chwall_conflict_sets_offset)),
             chwall_bin_pol.conflict_sets,
             chwall_bin_pol.max_conflictsets * chwall_bin_pol.max_types);

    arrcpy16((u16 *) (buf +
                      be32_to_cpu(chwall_buf->chwall_running_types_offset)),
             chwall_bin_pol.running_types, chwall_bin_pol.max_types);

    arrcpy16((u16 *) (buf +
                      be32_to_cpu(chwall_buf->chwall_conflict_aggregate_offset)),
             chwall_bin_pol.conflict_aggregate_set,
             chwall_bin_pol.max_types);
    return ret;
}

/*
 * Adapt security state (running_types and conflict_aggregate_set) to all
 * running domains; chwall_init_state is called when a policy is changed
 * to bring the security information into a consistent state and to detect
 * violations (return != 0) from a security point of view, we simulate
 * that all running domains are re-started
 */
static int
chwall_init_state(struct acm_chwall_policy_buffer *chwall_buf,
                  domaintype_t * ssidrefs,
                  domaintype_t * conflict_sets,
                  domaintype_t * running_types,
                  domaintype_t * conflict_aggregate_set,
                  struct acm_sized_buffer *errors /* may be NULL */)
{
    int violation = 0, i, j;
    struct chwall_ssid *chwall_ssid;
    ssidref_t chwall_ssidref;
    struct acm_ssid_domain *rawssid;

    read_lock(&ssid_list_rwlock);

    /* go through all domains and adjust policy as if this domain was
     * started now
     */
    for_each_acmssid( rawssid )
    {
        chwall_ssid =
            GET_SSIDP(ACM_CHINESE_WALL_POLICY, rawssid);
        chwall_ssidref = chwall_ssid->chwall_ssidref;
        traceprintk("%s: validating policy for domain %x (chwall-REF=%x).\n",
                    __func__, d->domain_id, chwall_ssidref);
        /* a) adjust types ref-count for running domains */
        for ( i = 0; i < chwall_buf->chwall_max_types; i++ )
            running_types[i] +=
                ssidrefs[chwall_ssidref * chwall_buf->chwall_max_types + i];

        /* b) check for conflict */
        for ( i = 0; i < chwall_buf->chwall_max_types; i++ )
            if ( conflict_aggregate_set[i] &&
                 ssidrefs[chwall_ssidref * chwall_buf->chwall_max_types + i] )
            {
                printk("%s: CHINESE WALL CONFLICT in type %02x.\n",
                       __func__, i);
                violation = 1;

                acm_array_append_tuple(errors, ACM_CHWALL_CONFLICT, i);

                goto out;
            }

        /* set violation and break out of the loop */
        /* c) adapt conflict aggregate set for this domain
         *    (notice conflicts)
         */
        for ( i = 0; i < chwall_buf->chwall_max_conflictsets; i++ )
        {
            int common = 0;
            /* check if conflict_set_i and ssidref have common types */
            for ( j = 0; j < chwall_buf->chwall_max_types; j++ )
                if ( conflict_sets[i * chwall_buf->chwall_max_types + j] &&
                     ssidrefs[chwall_ssidref *
                              chwall_buf->chwall_max_types + j] )
                {
                    common = 1;
                    break;
                }

            if ( common == 0 )
                continue;       /* try next conflict set */

            /* now add types of the conflict set to conflict_aggregate_set
             * (except types in chwall_ssidref)
             */
            for ( j = 0; j < chwall_buf->chwall_max_types; j++ )
                if ( conflict_sets[i * chwall_buf->chwall_max_types + j] &&
                     !ssidrefs[chwall_ssidref *
                               chwall_buf->chwall_max_types + j] )
                    conflict_aggregate_set[j]++;
        }
    }
 out:
    read_unlock(&ssid_list_rwlock);
    return violation;
    /* returning "violation != 0" means that the currently running set of
     * domains would not be possible if the new policy had been enforced
     * before starting them; for chinese wall, this means that the new
     * policy includes at least one conflict set of which more than one
     * type is currently running
     */
}


int
do_chwall_init_state_curr(struct acm_sized_buffer *errors)
{
    struct acm_chwall_policy_buffer chwall_buf =
    {
         /* only these two are important */
         .chwall_max_types        = chwall_bin_pol.max_types,
         .chwall_max_conflictsets = chwall_bin_pol.max_conflictsets,
    };
    /* reset running_types and aggregate set for recalculation */
    memset(chwall_bin_pol.running_types,
           0x0,
           sizeof(domaintype_t) * chwall_bin_pol.max_types);
    memset(chwall_bin_pol.conflict_aggregate_set,
           0x0,
           sizeof(domaintype_t) * chwall_bin_pol.max_types);
    return chwall_init_state(&chwall_buf,
                             chwall_bin_pol.ssidrefs,
                             chwall_bin_pol.conflict_sets,
                             chwall_bin_pol.running_types,
                             chwall_bin_pol.conflict_aggregate_set,
                             errors);
}

/*
 * Attempt to set the policy. This function must be called in test_only
 * mode first to only perform checks. A second call then does the
 * actual changes.
 */
static int _chwall_update_policy(u8 *buf, u32 buf_size, int test_only,
                                 struct acm_sized_buffer *errors)
{
    int rc = -EFAULT;
    /* policy write-locked already */
    struct acm_chwall_policy_buffer *chwall_buf =
        (struct acm_chwall_policy_buffer *) buf;
    void *ssids = NULL, *conflict_sets = NULL, *running_types = NULL,
         *conflict_aggregate_set = NULL;

    /* 1. allocate new buffers */
    ssids =
        xmalloc_array(domaintype_t,
                      chwall_buf->chwall_max_types *
                      chwall_buf->chwall_max_ssidrefs);
    conflict_sets =
        xmalloc_array(domaintype_t,
                      chwall_buf->chwall_max_conflictsets *
                      chwall_buf->chwall_max_types);
    running_types =
        xmalloc_array(domaintype_t, chwall_buf->chwall_max_types);
    conflict_aggregate_set =
        xmalloc_array(domaintype_t, chwall_buf->chwall_max_types);

    if ( (ssids == NULL) || (conflict_sets == NULL) ||
         (running_types == NULL) || (conflict_aggregate_set == NULL) )
        goto error_free;

    /* 2. set new policy */
    if ( chwall_buf->chwall_ssid_offset + sizeof(domaintype_t) *
         chwall_buf->chwall_max_types * chwall_buf->chwall_max_ssidrefs >
         buf_size )
        goto error_free;

    arrcpy(ssids, buf + chwall_buf->chwall_ssid_offset,
           sizeof(domaintype_t),
           chwall_buf->chwall_max_types * chwall_buf->chwall_max_ssidrefs);

    if ( chwall_buf->chwall_conflict_sets_offset + sizeof(domaintype_t) *
         chwall_buf->chwall_max_types *
         chwall_buf->chwall_max_conflictsets > buf_size )
        goto error_free;

    arrcpy(conflict_sets, buf + chwall_buf->chwall_conflict_sets_offset,
           sizeof(domaintype_t),
           chwall_buf->chwall_max_types *
           chwall_buf->chwall_max_conflictsets);

    /* we also use new state buffers since max_types can change */
    memset(running_types, 0,
           sizeof(domaintype_t) * chwall_buf->chwall_max_types);
    memset(conflict_aggregate_set, 0,
           sizeof(domaintype_t) * chwall_buf->chwall_max_types);

    /* 3. now re-calculate the state for the new policy based on
     *    running domains; this can fail if new policy is conflicting
     *    with running domains
     */
    if ( chwall_init_state(chwall_buf, ssids,
                           conflict_sets, running_types,
                           conflict_aggregate_set,
                           errors))
    {
        printk("%s: New policy conflicts with running domains. Policy load aborted.\n",
               __func__);
        goto error_free;        /* new policy conflicts with running domains */
    }

    /* if this was only a test run, exit with ACM_OK */
    if ( test_only )
    {
        rc = ACM_OK;
        goto error_free;
    }

    /* 4. free old policy buffers, replace with new ones */
    chwall_bin_pol.max_types = chwall_buf->chwall_max_types;
    chwall_bin_pol.max_ssidrefs = chwall_buf->chwall_max_ssidrefs;
    chwall_bin_pol.max_conflictsets = chwall_buf->chwall_max_conflictsets;
    xfree(chwall_bin_pol.ssidrefs);
    xfree(chwall_bin_pol.conflict_aggregate_set);
    xfree(chwall_bin_pol.running_types);
    xfree(chwall_bin_pol.conflict_sets);
    chwall_bin_pol.ssidrefs = ssids;
    chwall_bin_pol.conflict_aggregate_set = conflict_aggregate_set;
    chwall_bin_pol.running_types = running_types;
    chwall_bin_pol.conflict_sets = conflict_sets;

    return ACM_OK;

 error_free:
    if ( !test_only )
        printk("%s: ERROR setting policy.\n", __func__);

    xfree(ssids);
    xfree(conflict_sets);
    xfree(running_types);
    xfree(conflict_aggregate_set);
    return rc;
}

/*
 * This function MUST be called before the chwall_ste_policy function!
 */
static int chwall_test_policy(u8 *buf, u32 buf_size, int is_bootpolicy,
                              struct acm_sized_buffer *errors)
{
    struct acm_chwall_policy_buffer *chwall_buf =
        (struct acm_chwall_policy_buffer *) buf;

    if ( buf_size < sizeof(struct acm_chwall_policy_buffer) )
        return -EINVAL;

    /* rewrite the policy due to endianess */
    chwall_buf->policy_code = be32_to_cpu(chwall_buf->policy_code);
    chwall_buf->policy_version = be32_to_cpu(chwall_buf->policy_version);
    chwall_buf->chwall_max_types =
        be32_to_cpu(chwall_buf->chwall_max_types);
    chwall_buf->chwall_max_ssidrefs =
        be32_to_cpu(chwall_buf->chwall_max_ssidrefs);
    chwall_buf->chwall_max_conflictsets =
        be32_to_cpu(chwall_buf->chwall_max_conflictsets);
    chwall_buf->chwall_ssid_offset =
        be32_to_cpu(chwall_buf->chwall_ssid_offset);
    chwall_buf->chwall_conflict_sets_offset =
        be32_to_cpu(chwall_buf->chwall_conflict_sets_offset);
    chwall_buf->chwall_running_types_offset =
        be32_to_cpu(chwall_buf->chwall_running_types_offset);
    chwall_buf->chwall_conflict_aggregate_offset =
        be32_to_cpu(chwall_buf->chwall_conflict_aggregate_offset);

    /* policy type and version checks */
    if ( (chwall_buf->policy_code != ACM_CHINESE_WALL_POLICY) ||
         (chwall_buf->policy_version != ACM_CHWALL_VERSION) )
        return -EINVAL;

    /* during boot dom0_chwall_ssidref is set */
    if ( is_bootpolicy &&
         (dom0_chwall_ssidref >= chwall_buf->chwall_max_ssidrefs) )
        return -EINVAL;

    return _chwall_update_policy(buf, buf_size, 1, errors);
}

static int chwall_set_policy(u8 *buf, u32 buf_size)
{
    return _chwall_update_policy(buf, buf_size, 0, NULL);
}

static int chwall_dump_stats(u8 * buf, u16 len)
{
    /* no stats for Chinese Wall Policy */
    return 0;
}

static int chwall_dump_ssid_types(ssidref_t ssidref, u8 * buf, u16 len)
{
    int i;

    /* fill in buffer */
    if ( chwall_bin_pol.max_types > len )
        return -EFAULT;

    if ( ssidref >= chwall_bin_pol.max_ssidrefs )
        return -EFAULT;

    /* read types for chwall ssidref */
    for ( i = 0; i < chwall_bin_pol.max_types; i++ )
    {
        if ( chwall_bin_pol.
             ssidrefs[ssidref * chwall_bin_pol.max_types + i] )
            buf[i] = 1;
        else
            buf[i] = 0;
    }
    return chwall_bin_pol.max_types;
}

/***************************
 * Authorization functions
 ***************************/

/* -------- DOMAIN OPERATION HOOKS -----------*/

static int _chwall_pre_domain_create(void *subject_ssid, ssidref_t ssidref)
{
    ssidref_t chwall_ssidref;
    int i, j;

    chwall_ssidref = GET_SSIDREF(ACM_CHINESE_WALL_POLICY, ssidref);

    if ( chwall_ssidref >= chwall_bin_pol.max_ssidrefs )
    {
        printk("%s: ERROR chwall_ssidref > max(%x).\n",
               __func__, chwall_bin_pol.max_ssidrefs - 1);
        return ACM_ACCESS_DENIED;
    }

    /* A: chinese wall check for conflicts */
    for ( i = 0; i < chwall_bin_pol.max_types; i++ )
        if ( chwall_bin_pol.conflict_aggregate_set[i] &&
             chwall_bin_pol.ssidrefs[chwall_ssidref *
                                     chwall_bin_pol.max_types + i] )
        {
            printk("%s: CHINESE WALL CONFLICT in type %02x.\n", __func__, i);
            return ACM_ACCESS_DENIED;
        }

    /* B: chinese wall conflict set adjustment (so that other
     *    other domains simultaneously created are evaluated against
     *    this new set)
     */
    for ( i = 0; i < chwall_bin_pol.max_conflictsets; i++ )
    {
        int common = 0;
        /* check if conflict_set_i and ssidref have common types */
        for ( j = 0; j < chwall_bin_pol.max_types; j++ )
            if ( chwall_bin_pol.
                 conflict_sets[i * chwall_bin_pol.max_types + j]
                 && chwall_bin_pol.ssidrefs[chwall_ssidref *
                                            chwall_bin_pol.max_types + j] )
            {
                common = 1;
                break;
            }
        if ( common == 0 )
            continue;           /* try next conflict set */
        /* now add types of the conflict set to conflict_aggregate_set (except types in chwall_ssidref) */
        for ( j = 0; j < chwall_bin_pol.max_types; j++ )
            if ( chwall_bin_pol.
                 conflict_sets[i * chwall_bin_pol.max_types + j]
                 && !chwall_bin_pol.ssidrefs[chwall_ssidref *
                                             chwall_bin_pol.max_types + j])
                 chwall_bin_pol.conflict_aggregate_set[j]++;
    }
    return ACM_ACCESS_PERMITTED;
}


static void _chwall_post_domain_create(domid_t domid, ssidref_t ssidref)
{
    int i;
    ssidref_t chwall_ssidref;

    chwall_ssidref = GET_SSIDREF(ACM_CHINESE_WALL_POLICY, ssidref);
    /* adjust types ref-count for running domains */
    for ( i = 0; i < chwall_bin_pol.max_types; i++ )
        chwall_bin_pol.running_types[i] +=
            chwall_bin_pol.ssidrefs[chwall_ssidref *
                                   chwall_bin_pol.max_types + i];
}


/*
 * To be called when creating a domain. If this call is unsuccessful,
 * no state changes have occurred (adjustments of counters etc.). If it
 * was successful, state was changed and can be undone using
 * chwall_domain_destroy.
 */
static int chwall_domain_create(void *subject_ssid, ssidref_t ssidref,
                                domid_t domid)
{
    int rc;
    read_lock(&acm_bin_pol_rwlock);

    rc = _chwall_pre_domain_create(subject_ssid, ssidref);
    if ( rc == ACM_ACCESS_PERMITTED )
        _chwall_post_domain_create(domid, ssidref);

    read_unlock(&acm_bin_pol_rwlock);
    return rc;
}

/*
 * This function undoes everything a successful call to
 * chwall_domain_create has done.
 */
static void chwall_domain_destroy(void *object_ssid, struct domain *d)
{
    int i, j;
    struct chwall_ssid *chwall_ssidp = GET_SSIDP(ACM_CHINESE_WALL_POLICY,
                                                 (struct acm_ssid_domain *)
                                                 object_ssid);
    ssidref_t chwall_ssidref = chwall_ssidp->chwall_ssidref;

    read_lock(&acm_bin_pol_rwlock);

    /* adjust running types set */
    for ( i = 0; i < chwall_bin_pol.max_types; i++ )
        chwall_bin_pol.running_types[i] -=
            chwall_bin_pol.ssidrefs[chwall_ssidref *
                                   chwall_bin_pol.max_types + i];

    /* roll-back: re-adjust conflicting types aggregate */
    for ( i = 0; i < chwall_bin_pol.max_conflictsets; i++ )
    {
        int common = 0;
        /* check if conflict_set_i and ssidref have common types */
        for ( j = 0; j < chwall_bin_pol.max_types; j++ )
            if ( chwall_bin_pol.conflict_sets[i * chwall_bin_pol.max_types + j]
                 && chwall_bin_pol.ssidrefs[chwall_ssidref *
                                            chwall_bin_pol.max_types + j])
            {
                common = 1;
                break;
            }
        if ( common == 0 )
        {
            /* try next conflict set, this one does not include
               any type of chwall_ssidref */
            continue;
        }

        /* now add types of the conflict set to conflict_aggregate_set
           (except types in chwall_ssidref) */
        for ( j = 0; j < chwall_bin_pol.max_types; j++ )
            if ( chwall_bin_pol.
                 conflict_sets[i * chwall_bin_pol.max_types + j]
                 && !chwall_bin_pol.ssidrefs[chwall_ssidref *
                                             chwall_bin_pol.max_types + j])
                chwall_bin_pol.conflict_aggregate_set[j]--;
    }

    read_unlock(&acm_bin_pol_rwlock);

    return;
}


static int chwall_is_default_policy(void)
{
    static const domaintype_t def_policy[2] = { 0x0, 0x0 };
    return ( ( chwall_bin_pol.max_types    == 1 ) &&
             ( chwall_bin_pol.max_ssidrefs == 2 ) &&
             ( memcmp(chwall_bin_pol.ssidrefs,
                      def_policy,
                      sizeof(def_policy)) == 0 ) );
}


static int chwall_is_in_conflictset(ssidref_t ssidref1)
{
    /* is ssidref1 in conflict with any running domains ? */
    int rc = 0;
    int i, j;
    ssidref_t ssid_chwall;

    read_lock(&acm_bin_pol_rwlock);

    ssid_chwall = GET_SSIDREF(ACM_CHINESE_WALL_POLICY, ssidref1);

    if ( ssid_chwall >= 0 && ssid_chwall < chwall_bin_pol.max_ssidrefs ) {
        for ( i = 0; i < chwall_bin_pol.max_conflictsets && rc == 0; i++ ) {
            for ( j = 0; j < chwall_bin_pol.max_types; j++ ) {
                if ( chwall_bin_pol.conflict_aggregate_set
                                 [i * chwall_bin_pol.max_types + j] &&
                     chwall_bin_pol.ssidrefs
                                 [ssid_chwall * chwall_bin_pol.max_types + j])
                {
                    rc = 1;
                    break;
                }
            }
        }
    } else {
        rc = 1;
    }

    read_unlock(&acm_bin_pol_rwlock);

    return rc;
}


struct acm_operations acm_chinesewall_ops = {
    /* policy management services */
    .init_domain_ssid = chwall_init_domain_ssid,
    .free_domain_ssid = chwall_free_domain_ssid,
    .dump_binary_policy = chwall_dump_policy,
    .test_binary_policy = chwall_test_policy,
    .set_binary_policy = chwall_set_policy,
    .dump_statistics = chwall_dump_stats,
    .dump_ssid_types = chwall_dump_ssid_types,
    /* domain management control hooks */
    .domain_create = chwall_domain_create,
    .domain_destroy = chwall_domain_destroy,
    /* event channel control hooks */
    .pre_eventchannel_unbound = NULL,
    .fail_eventchannel_unbound = NULL,
    .pre_eventchannel_interdomain = NULL,
    .fail_eventchannel_interdomain = NULL,
    /* grant table control hooks */
    .pre_grant_map_ref = NULL,
    .fail_grant_map_ref = NULL,
    .pre_grant_setup = NULL,
    .fail_grant_setup = NULL,
    /* generic domain-requested decision hooks */
    .sharing = NULL,
    .authorization = NULL,
    .conflictset = chwall_is_in_conflictset,

    .is_default_policy = chwall_is_default_policy,
};

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
