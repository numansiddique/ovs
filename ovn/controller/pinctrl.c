
/* Copyright (c) 2015 Red Hat, Inc.
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
#include "dirs.h"
#include "dp-packet.h"
#include "pinctrl.h"
#include "ofp-msgs.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "rconn.h"
#include "openvswitch/vlog.h"
#include "socket-util.h"
#include "vswitch-idl.h"
#include "ovn-dhcp.h"

VLOG_DEFINE_THIS_MODULE(pinctrl);

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

/* OpenFlow connection to the switch. */
static struct rconn *swconn;

/* Last seen sequence number for 'swconn'.  When this differs from
 * rconn_get_connection_seqno(rconn), 'swconn' has reconnected. */
static unsigned int conn_seq_no;

void
pinctrl_init(void)
{
    swconn = rconn_create(5, 0, DSCP_DEFAULT, 0xF);
    conn_seq_no = 0;
}

static ovs_be32
queue_msg(struct ofpbuf *msg)
{
    const struct ofp_header *oh = msg->data;
    ovs_be32 xid = oh->xid;

    rconn_send(swconn, msg, NULL);
    return xid;
}

static void
get_switch_config(struct rconn *swconn)
{
    struct ofpbuf *request;

    request = ofpraw_alloc(OFPRAW_OFPT_GET_CONFIG_REQUEST,
                           rconn_get_version(swconn), 0);
    queue_msg(request);
}

static void
set_switch_config(struct rconn *swconn, const struct ofp_switch_config *config)
{
    struct ofpbuf *request;

    request =
        ofpraw_alloc(OFPRAW_OFPT_SET_CONFIG, rconn_get_version(swconn), 0);
    ofpbuf_put(request, config, sizeof *config);

    queue_msg(request);
}

static enum ofputil_protocol
pinctrl_ofp_proto(void)
{
    enum ofp_version version;

    version = rconn_get_version(swconn);
    return ofputil_protocol_from_ofp_version(version);
}

static inline bool
is_dhcp_packet(struct flow *flow)
{
    if (flow->dl_type == htons(ETH_TYPE_IP) &&
        flow->nw_proto == IPPROTO_UDP &&
        flow->nw_src == INADDR_ANY &&
        flow->nw_dst == INADDR_BROADCAST &&
        flow->tp_src == htons(DHCP_CLIENT_PORT) &&
        flow->tp_dst == htons(DHCP_SERVER_PORT)) {
        return true;
    }
    return false;
}

static void
process_packet_in(struct controller_ctx *ctx OVS_UNUSED,
                  const struct ofp_header *msg)
{
    struct ofputil_packet_in pin;
    struct ofpbuf *buf = NULL;

    if (ofputil_decode_packet_in(&pin, msg) != 0) {
        return;
    }

    if (pin.reason != OFPR_ACTION) {
        return;
    }

    struct flow flow;
    struct dp_packet packet;
    dp_packet_use_const(&packet, pin.packet, pin.packet_len);
    flow_extract(&packet, &flow);

    if (is_dhcp_packet(&flow)) {
        ovn_dhcp_process_packet(ctx, &pin, pinctrl_ofp_proto(),
                                &flow, &packet, &buf);
        if (buf) {
            rconn_send(swconn, buf, NULL);
        }
    }

}

static void
pinctrl_recv(struct controller_ctx *ctx, const struct ofp_header *oh,
             enum ofptype type)
{
    if (type == OFPTYPE_ECHO_REQUEST) {
        queue_msg(make_echo_reply(oh));
    } else if (type == OFPTYPE_GET_CONFIG_REPLY) {
        struct ofpbuf rq_buf;
        struct ofpbuf *spif;
        struct ofpbuf *scid;
        struct ofp_switch_config *config_, config;

        ofpbuf_use_const(&rq_buf, oh, ntohs(oh->length));
        config_ = ofpbuf_pull(&rq_buf, sizeof *config_);
        config = *config_;
        config.miss_send_len = htons(UINT16_MAX);
        set_switch_config(swconn, &config);

        spif = ofputil_make_set_packet_in_format(rconn_get_version(swconn),
                                                 NXPIF_NXM);
        queue_msg(spif);

        scid = ofputil_make_set_controller_id(rconn_get_version(swconn),
                                              OVN_PACKET_IN_CONTROLLER_ID);
        queue_msg(scid);
    } else if (type == OFPTYPE_PACKET_IN) {
        process_packet_in(ctx, oh);
    } else if (type != OFPTYPE_ECHO_REPLY && type != OFPTYPE_BARRIER_REPLY) {
        if (VLOG_IS_DBG_ENABLED()) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);

            char *s = ofp_to_string(oh, ntohs(oh->length), 2);

            VLOG_DBG_RL(&rl, "OpenFlow packet ignored: %s", s);
            free(s);
        }
    }
}

void
pinctrl_run(struct controller_ctx *ctx, const struct ovsrec_bridge *br_int)
{
    if (br_int) {
        char *target;

        target = xasprintf("unix:%s/%s.mgmt", ovs_rundir(), br_int->name);
        if (strcmp(target, rconn_get_target(swconn))) {
            VLOG_INFO("%s: connecting to switch", target);
            rconn_connect(swconn, target, target);
        }
        free(target);
    } else {
        rconn_disconnect(swconn);
    }

    rconn_run(swconn);

    if (!rconn_is_connected(swconn)) {
        return;
    }

    if (conn_seq_no != rconn_get_connection_seqno(swconn)) {
        get_switch_config(swconn);
        conn_seq_no = rconn_get_connection_seqno(swconn);
    }

    struct ofpbuf *msg = rconn_recv(swconn);

    if (!msg) {
        return;
    }

    const struct ofp_header *oh = msg->data;
    enum ofptype type;

    ofptype_decode(&type, oh);
    pinctrl_recv(ctx, oh, type);
    ofpbuf_delete(msg);
}

void
pinctrl_wait(void)
{
    rconn_run_wait(swconn);
    rconn_recv_wait(swconn);
}

void
pinctrl_destroy(void)
{
    rconn_destroy(swconn);
}
