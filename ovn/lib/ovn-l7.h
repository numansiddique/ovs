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

#ifndef OVN_L4_H
#define OVN_L4_H 1

#include "openvswitch/hmap.h"
#include "hash.h"
#include "smap.h"

struct ofpbuf;

struct ovn_l4_fields_map {
    struct hmap_node hmap_node;
    char *name;
    char *type;
    size_t code;
};

#define OVN_L4_FIELD(NAME, CODE, TYPE) \
    {.name = NAME, .code = CODE, .type = TYPE}

#define DNS_QUERY   OVN_L4_FIELD("dns.query", 1, "str")

static inline uint32_t
l4_field_hash(char *l4_field_name)
{
    return hash_string(l4_field_name, 0);
}

static inline struct ovn_l4_fields_map *
ovn_l4_field_find(const struct hmap *ovn_l4_fields, char *field_name)
{
    struct ovn_l4_fields_map *l4_field;
    HMAP_FOR_EACH_WITH_HASH (l4_field, hmap_node, l4_field_hash(field_name),
                             ovn_l4_fields) {
        if (!strcmp(l4_field->name, field_name)) {
            return l4_field;
        }
    }

    return NULL;
}

static inline void
ovn_l4_field_add(struct hmap *ovn_l4_fields, char *field_name, size_t code,
                 char *type)
{
    struct ovn_l4_fields_map *l4_field = xzalloc(sizeof *l4_field);
    l4_field->name = xstrdup(field_name);
    l4_field->code = code;
    l4_field->type = xstrdup(type);
    hmap_insert(ovn_l4_fields, &l4_field->hmap_node,
                l4_field_hash(field_name));
}

static inline void
ovn_l4_fields_destroy(struct hmap *ovn_l4_fields)
{
    struct ovn_l4_fields_map *l4_field;
    HMAP_FOR_EACH_POP(l4_field, hmap_node, ovn_l4_fields) {
        free(l4_field->name);
        free(l4_field->type);
        free(l4_field);
    }
    hmap_destroy(ovn_l4_fields);
}

struct ovn_l4_dp_flows {
    struct hmap_node hmap_node;
    uint64_t datapath_key;
    struct smap match_actions;
};

void ovn_init_l4_fields(struct hmap *ovn_l4_fields);
void ovn_init_l4_flows(void);
void ovn_destroy_l4_flows(void);
struct ovn_l4_dp_flows *ovn_l4_dp_flows_find(uint64_t datapath_key);

bool ovn_parse_l4_matches_and_store(const char *s, struct hmap *ovn_l4_fields,
                                    struct ofpbuf *actions,
                                    uint64_t logical_datapath_key);


#define DNS_HEADER_LEN 12
OVS_PACKED(
struct dns_header {
    ovs_be16 id;
    uint8_t lo_flag; /* QR (1), OPCODE (4), AA (1), TC (1) and RD (1) */
    uint8_t hi_flag; /* RA (1), Z (3) and RCODE (4) */
    ovs_be16 qdcount; /* Num of entries in the question section. */
    ovs_be16 ancount; /* Num of resource records in the answer section. */
    ovs_be16 nscount; /* Num of name server records in the authority record section. */
    ovs_be16 arcount; /* Num of resource records in the additional records section. */
});

BUILD_ASSERT_DECL(DNS_HEADER_LEN == sizeof(struct dns_header));

#endif /* OVN_L4_H */
