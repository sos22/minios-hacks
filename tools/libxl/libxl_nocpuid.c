/*
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

#include "libxl.h"

void libxl_cpuid_destroy(libxl_cpuid_policy_list *p_cpuid_list)
{
}

int libxl_cpuid_parse_config(libxl_cpuid_policy_list *cpuid, const char* str)
{
    return 0;
}

int libxl_cpuid_parse_config_xend(libxl_cpuid_policy_list *cpuid,
                                  const char* str)
{
    return 0;
}

void libxl_cpuid_apply_policy(libxl_ctx *ctx, uint32_t domid)
{
}

void libxl_cpuid_set(libxl_ctx *ctx, uint32_t domid,
		     libxl_cpuid_policy_list cpuid)
{
}
