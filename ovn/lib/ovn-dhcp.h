/*
 * Copyright (c) 2016 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OVN_DHCP_H
#define OVN_DHCP_H 1

#include "hmap.h"
#include "hash.h"

enum dhcp_opt_type {
    DHCP_OPT_TYPE_BOOL,
    DHCP_OPT_TYPE_UINT8,
    DHCP_OPT_TYPE_UINT16,
    DHCP_OPT_TYPE_UINT32,
    DHCP_OPT_TYPE_IP4,
    DHCP_OPT_TYPE_STATIC_ROUTES,
    DHCP_OPT_TYPE_STR
};

struct dhcp_opts_map {
    struct hmap_node hmap_node;
    char *name;
    size_t code;
    size_t type;
};

#define DHCP_OPTION(NAME, CODE, TYPE) \
    {.name = NAME, .code = CODE, .type = TYPE}

#define OFFERIP              DHCP_OPTION("offerip", 0, DHCP_OPT_TYPE_IP4)
#define DHCP_OPT_NETMASK     DHCP_OPTION("netmask", 1, DHCP_OPT_TYPE_IP4)
#define DHCP_OPT_ROUTER      DHCP_OPTION("router", 3, DHCP_OPT_TYPE_IP4)
#define DHCP_OPT_DNS_SERVER  DHCP_OPTION("dns_server", 6, DHCP_OPT_TYPE_IP4)
#define DHCP_OPT_LOG_SERVER  DHCP_OPTION("log_server", 7, DHCP_OPT_TYPE_IP4)
#define DHCP_OPT_LPR_SERVER  DHCP_OPTION("lpr_server", 9, DHCP_OPT_TYPE_IP4)
#define DHCP_OPT_SWAP_SERVER DHCP_OPTION("swap_server", 16, DHCP_OPT_TYPE_IP4)

#define DHCP_OPT_POLICY_FILTER \
    DHCP_OPTION("policy_filter", 21, DHCP_OPT_TYPE_IP4)

#define DHCP_OPT_ROUTER_SOLICITATION \
    DHCP_OPTION("router_solicitation", 32, DHCP_OPT_TYPE_IP4)

#define DHCP_OPT_NIS_SERVER  DHCP_OPTION("nis_server", 41, DHCP_OPT_TYPE_IP4)
#define DHCP_OPT_NTP_SERVER  DHCP_OPTION("ntp_server", 42, DHCP_OPT_TYPE_IP4)
#define DHCP_OPT_SERVER_ID   DHCP_OPTION("server_id", 54, DHCP_OPT_TYPE_IP4)
#define DHCP_OPT_TFTP_SERVER DHCP_OPTION("tftp_server", 66, DHCP_OPT_TYPE_IP4)

#define DHCP_OPT_CLASSLESS_STATIC_ROUTE \
    DHCP_OPTION("classless_static_route", 121, DHCP_OPT_TYPE_STATIC_ROUTES)

#define DHCP_OPT_IP_FORWARD_ENABLE \
    DHCP_OPTION("ip_forward_enable", 19, DHCP_OPT_TYPE_BOOL)
#define DHCP_OPT_ROUTER_DISCOVERY \
    DHCP_OPTION("router_discovery", 31, DHCP_OPT_TYPE_BOOL)
#define DHCP_OPT_ETHERNET_ENCAP \
    DHCP_OPTION("ethernet_encap", 36, DHCP_OPT_TYPE_BOOL)

#define DHCP_OPT_DEFAULT_TTL \
    DHCP_OPTION("default_ttl", 23, DHCP_OPT_TYPE_UINT8)

#define DHCP_OPT_TCP_TTL  DHCP_OPTION("tcp_ttl", 37, DHCP_OPT_TYPE_UINT8)
#define DHCP_OPT_MTU      DHCP_OPTION("mtu", 26, DHCP_OPT_TYPE_UINT16)
#define DHCP_OPT_LEASE_TIME \
    DHCP_OPTION("lease_time", 51, DHCP_OPT_TYPE_UINT32)




static inline uint32_t
dhcp_opt_hash(char *opt_name)
{
    return hash_string(opt_name, 0);
}

static inline struct dhcp_opts_map *
dhcp_opts_find(const struct hmap *dhcp_opts, char *opt_name)
{
    struct dhcp_opts_map *dhcp_opt;
    HMAP_FOR_EACH_WITH_HASH (dhcp_opt, hmap_node, dhcp_opt_hash(opt_name),
                             dhcp_opts) {
        if (!strcmp(dhcp_opt->name, opt_name)) {
            return dhcp_opt;
        }
    }

    return NULL;
}

static inline void
dhcp_opt_add(struct hmap *dhcp_opts, char *opt_name, size_t code, size_t type)
{
    struct dhcp_opts_map *dhcp_opt = xzalloc(sizeof *dhcp_opt);
    dhcp_opt->name = xstrdup(opt_name);
    dhcp_opt->code = code;
    dhcp_opt->type = type;
    hmap_insert(dhcp_opts, &dhcp_opt->hmap_node, dhcp_opt_hash(opt_name));
}

static inline void
dhcp_opts_destroy(struct hmap *dhcp_opts)
{
    struct dhcp_opts_map *dhcp_opt;
    HMAP_FOR_EACH_POP(dhcp_opt, hmap_node, dhcp_opts) {
        free(dhcp_opt->name);
        free(dhcp_opt);
    }
    hmap_destroy(dhcp_opts);
}

#endif /* OVN_DHCP_H */
