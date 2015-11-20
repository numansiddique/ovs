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
#include "command-line.h"
#include "flow.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "classifier.h"
#include "dhcp.h"
#include "ofpbuf.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "openflow/openflow.h"
#include "ovstest.h"
#include "dp-packet.h"
#include "pcap-file.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"
#include "lib/packets.h"


#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

#define DHCP_MAGIC_COOKIE (uint32_t)0x63825363
#define DHCP_OPT_MSG_TYPE    ((uint8_t)53)

/* Verify the dhcp option type */
struct dhcp_option_header {
    uint8_t option;
    uint8_t len;
};

#define OPTION_PAYLOAD(opt) ((char *)opt + sizeof(struct dhcp_option_header))

static void
test_ovn_dhcp_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    int retval = 1;
    FILE *pcap;
    bool verify_response = true;

    if (argc == 2) {
        verify_response = false;
    }
    else if (argc < 6) {
        printf("Usage : test_ovn_dhcp_main pcap-file expected ip"
               " expected-netmask expected-gw-ip dhcp-reply-type\n");
        exit(1);
    }


    set_program_name(argv[0]);

    pcap = fopen(argv[1], "rb");
    if (!pcap) {
        ovs_fatal(errno, "failed to open %s", argv[1]);
    }

    retval = ovs_pcap_read_header(pcap);
    if (retval) {
        ovs_fatal(retval > 0 ? retval : 0, "reading pcap header failed");
    }

    struct dp_packet *packet;
    retval = ovs_pcap_read(pcap, &packet, NULL);
    if (retval == EOF) {
        ovs_fatal(0, "unexpected end of file reading pcap file : [%s]\n",
                  argv[1]);
    } else if (retval) {
        ovs_fatal(retval, "error reading pcap file");
    }

    struct flow flow;
    flow_extract(packet, &flow);

    if (verify_response) {
        if (flow.tp_src != htons(DHCP_SERVER_PORT) &&
            flow.tp_dst != htons(DHCP_CLIENT_PORT)) {
            printf("Error. Not a dhcp response packet \n");
            exit(1);
        }
    }
    else {
        if (flow.dl_type == htons(ETH_TYPE_IP) && \
            flow.nw_proto == IPPROTO_UDP && \
            flow.nw_src == INADDR_ANY && \
            flow.nw_dst == INADDR_BROADCAST && \
            flow.tp_src == htons(DHCP_CLIENT_PORT) && \
            flow.tp_dst == htons(DHCP_SERVER_PORT)) {
                exit(0);
        }
        else {
            printf("Error.. Not a dhcp discover/request packet \n");
            exit(1);
        }
    }
    /* verify if the dst ip is as expected */
    ovs_be32 expected_offer_ip;
    if (!ovs_scan(argv[2], IP_SCAN_FMT, IP_SCAN_ARGS(&expected_offer_ip))) {
        ovs_fatal(1, "invalid expected offer ip");
    }

    ovs_be32 expected_netmask;
    if (!ovs_scan(argv[3], IP_SCAN_FMT, IP_SCAN_ARGS(&expected_netmask))) {
        ovs_fatal(1, "invalid expected netmask");
    }

    ovs_be32 expected_gw_ip;
    if (!ovs_scan(argv[4], IP_SCAN_FMT, IP_SCAN_ARGS(&expected_gw_ip))) {
        ovs_fatal(1, "invalid expected gw ip");
    }

    if (flow.nw_dst != expected_offer_ip) {
        printf("Error. Offered ip : "IP_FMT " : Expected ip : %s\n",
        IP_ARGS(flow.nw_dst), argv[2]);
        exit(1);
    }

    /* verify the dhcp reply type */
    struct dhcp_header const *dhcp_data = dp_packet_get_udp_payload(packet);
    if (dhcp_data->op != (uint8_t)2) {
        printf("Invalid dhcp op reply code : %d\n", dhcp_data->op);
        exit(1);
    }

    if(dhcp_data->yiaddr != expected_offer_ip) {
        printf("Error. Offered yiaddr : "IP_FMT " : Expected ip : %s\n",
        IP_ARGS(dhcp_data->yiaddr), argv[2]);
        exit(1);
    }

    /* Verify the dhcp option cookie */
    char const *footer = (char *)dhcp_data + sizeof(*dhcp_data);
    uint32_t cookie = *(uint32_t *)footer;
    if (cookie != htonl(DHCP_MAGIC_COOKIE)) {
        printf("Error. Invalid dhcp magic cookie\n");
        exit(1);
    }

    footer += sizeof(uint32_t);
    struct dhcp_option_header const *opt;
    uint8_t dhcp_msg_type = 0;
    ovs_be32 netmask = 0;
    ovs_be32 gw_ip = 0xffffffff;

    size_t dhcp_data_size = dp_packet_l4_size(packet);
    for (opt = (struct dhcp_option_header *)footer;
         footer < (char *)dhcp_data + dhcp_data_size;
         footer += (sizeof(*opt) + opt->len)) {
        opt = (struct dhcp_option_header *)footer;
        switch(opt->option) {
        case 53: /* DHCP OPT MESSAGE TYPE */
            dhcp_msg_type = *(uint8_t *)OPTION_PAYLOAD(opt);
            break;
        case 1: /* DHCP OPT NETMASK */
            netmask = *(ovs_be32 *)OPTION_PAYLOAD(opt);
            break;
        case 3: /* DHCP OPT ROUTER */
            gw_ip = *(ovs_be32 *)OPTION_PAYLOAD(opt);
            break;
        }
    }

    uint8_t expected_msg_type = (uint8_t)atoi(argv[5]);
    if (expected_msg_type == 1) {
        expected_msg_type = 2;
    }
    else {
        expected_msg_type = 5;
    }


    if (dhcp_msg_type != expected_msg_type) {
        printf("Error. dhcp message type = [%d] : "
               "Expected dhcp message type = [%d]\n",
        dhcp_msg_type, expected_msg_type);
        exit(1);
    }

    if (netmask != expected_netmask) {
        printf("Error. Offered netmask : "IP_FMT " : Expected netmask : %s\n",
               IP_ARGS(netmask), argv[3]);
        exit(1);
    }
    if (gw_ip != expected_gw_ip) {
        printf("Error. Offered gateway ip : "IP_FMT " : Expected gateway ip : %s\n",
               IP_ARGS(gw_ip), argv[4]);
        exit(1);
    }

    exit(0);
}

OVSTEST_REGISTER("test-ovn-dhcp", test_ovn_dhcp_main);
