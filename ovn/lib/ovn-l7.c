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

#include <config.h>
#include "ovn/expr.h"
#include "ovn/lex.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"

#include "ovn-l7.h"
#include "packets.h"

VLOG_DEFINE_THIS_MODULE(ovn_l7);

static struct hmap l7_dp_flows = HMAP_INITIALIZER(&l7_dp_flows);

void
ovn_init_l4_fields(struct hmap *ovn_l4_fields)
{
    hmap_init(ovn_l4_fields);
    ovn_l4_field_add(ovn_l4_fields, "dns.query", 1, "str");
}

void
ovn_init_l4_flows(void)
{
    hmap_init(&l7_dp_flows);

}

struct ovn_l4_dp_flows *
ovn_l4_dp_flows_find(uint64_t datapath_key)
{
    struct ovn_l4_dp_flows *l4_dp_flow;
    HMAP_FOR_EACH_WITH_HASH (l4_dp_flow, hmap_node, hash_uint64(datapath_key),
                             &l7_dp_flows) {
        if (l4_dp_flow->datapath_key == datapath_key) {
            return l4_dp_flow;
        }
    }

    return NULL;
}

static inline struct ovn_l4_dp_flows *
ovn_l4_dp_flows_get(uint64_t datapath_key)
{
    struct ovn_l4_dp_flows *l4_dp_flow = ovn_l4_dp_flows_find(datapath_key);
    if (!l4_dp_flow) {
        l4_dp_flow = xzalloc(sizeof *l4_dp_flow);
        l4_dp_flow->datapath_key = datapath_key;
        smap_init(&l4_dp_flow->match_actions);

        hmap_insert(&l7_dp_flows, &l4_dp_flow->hmap_node,
                    hash_uint64(datapath_key));
    }

    return l4_dp_flow;
}

/*
static inline void
ovn_l4_dp_flows_delete(uint64_t datapath_key)
{
    struct ovn_l4_dp_flows *l4_dp_flow = ovn_l4_dp_flows_find(datapath_key);
    if (l4_dp_flow) {
        hmap_remove(&l4_dp_flows, l4_dp_flow->hmap_node);
        smap_destroy(&l4_dp_flow->match_actions);
        free(l4_dp_flow);
    }
}*/

void
ovn_destroy_l4_flows(void)
{
    struct ovn_l4_dp_flows *l7_dp_flow;
    HMAP_FOR_EACH_POP(l7_dp_flow, hmap_node, &l7_dp_flows) {
        smap_destroy(&l7_dp_flow->match_actions);
        free(l7_dp_flow);
    }

    hmap_destroy(&l7_dp_flows);
    hmap_init(&l7_dp_flows);
}

bool
ovn_parse_l4_matches_and_store(const char *s, struct hmap *ovn_l4_fields,
                               struct ofpbuf *actions, uint64_t datapath_key)
{
    struct lexer lexer;
    bool retval = false;

    lexer_init(&lexer, s);
    lexer_get(&lexer);

    if (lexer.token.type != LEX_T_ID) {
        goto exit;
    }

    const struct ovn_l4_fields_map *l4_field =
        ovn_l4_field_find(ovn_l4_fields, lexer.token.s);

    if (!l4_field) {
        goto exit;
    }

    lexer_get(&lexer);
    if (lexer.token.type != LEX_T_EQ) {
        goto exit;
    }

    lexer_get(&lexer);
    struct expr_constant_set value;
    if (!expr_constant_set_parse(&lexer, &value)) {
        goto exit;
    }

    if (!strcmp(l4_field->type, "str") && value.type != EXPR_C_STRING) {
        goto exit;
    }


    ovs_be32 *ip = ofpbuf_try_pull(actions, sizeof *ip);
    if (!ip) {
        goto exit;
    }

    char *str_ip = xasprintf(IP_FMT, IP_ARGS(*ip));
    struct ovn_l4_dp_flows *l4_dp_flows = ovn_l4_dp_flows_get(datapath_key);
    smap_replace(&l4_dp_flows->match_actions, value.values[0].string, str_ip);
    free(str_ip);

    retval = true;
exit:
    lexer_destroy(&lexer);
    return retval;
}
