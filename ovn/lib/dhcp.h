/*
 * Copyright (c) 2016.
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
    struct dhcp_opts_map *dhcp_opt, *next;
    HMAP_FOR_EACH_SAFE(dhcp_opt, next, hmap_node, dhcp_opts) {
        hmap_remove(dhcp_opts, &dhcp_opt->hmap_node);
        free(dhcp_opt->name);
        free(dhcp_opt);
    }
    hmap_destroy(dhcp_opts);
}

#endif /* OVN_DHCP_H */
