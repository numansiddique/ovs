/* Copyright (c) 2016 Red Hat, Inc.
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

#include <assert.h>
#include <config.h>
#include "command-line.h"
#include "dp-packet.h"
#include <errno.h>
#include "flow.h"
#include "lib/dhcp.h"
#include "lib/packets.h"
#include "lib/util.h"
#include "openvswitch/ofp-actions.h"
#include "ovstest.h"
#include "ovn/lib/actions.h"
#include "ovn/lib/ovn-dhcp.h"
#include "pcap-file.h"
#include <stdlib.h>
#include <stdio.h>


static void
test_ovn_dhcp_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    if (argc != 7) {
        printf("Usage: %s pcap-file offer-ip server-ip"
                " server-mac dhcp-type userdata\n", argv[0]);
        exit(1);
    }

    int retval = 1;
    FILE *pcap;

    set_program_name(argv[0]);

    pcap = fopen(argv[1], "rb");
    if (!pcap) {
        ovs_fatal(errno, "failed to open %s", argv[1]);
    }

    retval = ovs_pcap_read_header(pcap);
    if (retval) {
        ovs_fatal(retval > 0 ? retval : 0, "reading pcap header failed");
    }

    /* verify if the offer-ip is in proper format */
    ovs_be32 expected_offer_ip;
    if (!ovs_scan(argv[2], IP_SCAN_FMT, IP_SCAN_ARGS(&expected_offer_ip))) {
        ovs_fatal(1, "invalid expected offer ip");
    }

    /* verify if the server-ip is in proper format */
    ovs_be32 server_ip;
    if (!ovs_scan(argv[3], IP_SCAN_FMT, IP_SCAN_ARGS(&server_ip))) {
        ovs_fatal(1, "invalid expected server ip");
    }

    struct eth_addr server_mac;
    if (!eth_addr_from_string(argv[4], &server_mac)) {
        ovs_fatal(1, "invalid expected server mac");
    }

    /*
     * In the testing its been observed that, the pcap file is
     * receiving 2 packets.
     *
     * 1. The resumed dhcp response packet from the ovn-controller
     * 2. The dhcp response packet without the 'pause' with all the other
     *    actions applied.
     */

    int num_pcap_reads = 0;
    int exit_code = 1;
    struct dp_packet *packet = NULL;
    do {
        num_pcap_reads++;
        retval = ovs_pcap_read(pcap, &packet, NULL);
        if (retval == EOF) {
            ovs_fatal(0, "unexpected end of file reading pcap file : [%s]\n",
                      argv[1]);
        } else if (retval) {
            ovs_fatal(retval, "error reading pcap file");
        }

        struct flow flow;
        flow_extract(packet, &flow);

        struct dhcp_header const *dhcp_data = dp_packet_get_udp_payload(packet);
        if (dhcp_data->op != (uint8_t)2) {
            if (num_pcap_reads == 1) {
                /* This is the incomplete dhcp reply packet without the
                 * 'pause'. Read the next packet */
                dp_packet_delete(packet);
                continue;
            }
            printf("Invalid dhcp op reply code : %d\n", dhcp_data->op);
            break;
        }

        if (flow.tp_src != htons(DHCP_SERVER_PORT) &&
            flow.tp_dst != htons(DHCP_CLIENT_PORT)) {
            printf("Error. Not a dhcp response packet \n");
            break;
        }

        if (flow.nw_dst != expected_offer_ip) {
            printf("Error. Offered ip : "IP_FMT " : Expected ip : %s\n",
            IP_ARGS(flow.nw_dst), argv[2]);
            break;
        }

        if(dhcp_data->yiaddr != expected_offer_ip) {
            printf("Error. Offered yiaddr : "IP_FMT " : Expected ip : %s\n",
            IP_ARGS(dhcp_data->yiaddr), argv[2]);
            break;
        }

        /* Verify the dhcp option cookie */
        char const *footer = (char *)dhcp_data + sizeof(*dhcp_data);
        uint32_t cookie = *(uint32_t *)footer;
        if (cookie != htonl(DHCP_MAGIC_COOKIE)) {
            printf("Error. Invalid dhcp magic cookie\n");
            break;
        }

        /* Validate userdata. It should be ASCII hex */
        uint64_t dhcp_opts_stub[1024 / 8];
        struct ofpbuf dhcp_opts = OFPBUF_STUB_INITIALIZER(dhcp_opts_stub);
        if (atoi(argv[5]) == 1) {
            /* DHCP reply type should be OFFER (02) */
            ofpbuf_put_hex(&dhcp_opts, "350102", NULL);
        } else {
            /* DHCP reply type should be ACK (05) */
            ofpbuf_put_hex(&dhcp_opts, "350105", NULL);
        }

        if (ofpbuf_put_hex(&dhcp_opts, argv[6], NULL)[0] != '\0') {
            printf("Error. Invalid userdata\n");
            break;
        }

        /* 4 bytes padding, 1 byte FF and 4 bytes padding */
        ofpbuf_put_hex(&dhcp_opts, "00000000FF00000000", NULL);

        footer += sizeof(uint32_t);

        size_t dhcp_opts_size = (const char *)dp_packet_tail(packet) - (
            const char *)footer;
        if (dhcp_opts_size != dhcp_opts.size) {
            printf("Error. dhcp options size mismatch\n");
            break;
        }

        if (memcmp(footer, dhcp_opts.data, dhcp_opts.size)) {
            printf("Error. Invalid dhcp options present\n");
            break;
        }

        exit_code = 0;
        break;
    }while(num_pcap_reads < 2);

    fclose(pcap);
    if (packet) {
        dp_packet_delete(packet);
    }
    exit(exit_code);
}

static void
test_dhcp_offer_action(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    if (argc != 3) {
        printf("Usage: %s dhcp-options expected-dhcp-opt-codes", argv[0]);
        exit(1);
    }

    struct hmap dhcp_opts = HMAP_INITIALIZER(&dhcp_opts);

    dhcp_opt_add(&dhcp_opts, "offerip", 0, DHCP_OPT_TYPE_IP4);
    dhcp_opt_add(&dhcp_opts, "netmask", 1, DHCP_OPT_TYPE_IP4);
    dhcp_opt_add(&dhcp_opts, "router",  3, DHCP_OPT_TYPE_IP4);
    dhcp_opt_add(&dhcp_opts, "dns_server", 6, DHCP_OPT_TYPE_IP4);
    dhcp_opt_add(&dhcp_opts, "log_server", 7, DHCP_OPT_TYPE_IP4);
    dhcp_opt_add(&dhcp_opts, "lpr_server",  9, DHCP_OPT_TYPE_IP4);
    dhcp_opt_add(&dhcp_opts, "swap_server", 16, DHCP_OPT_TYPE_IP4);
    dhcp_opt_add(&dhcp_opts, "policy_filter", 21, DHCP_OPT_TYPE_IP4);
    dhcp_opt_add(&dhcp_opts, "router_solicitation",  32, DHCP_OPT_TYPE_IP4);
    dhcp_opt_add(&dhcp_opts, "nis_server", 41, DHCP_OPT_TYPE_IP4);
    dhcp_opt_add(&dhcp_opts, "ntp_server", 42, DHCP_OPT_TYPE_IP4);
    dhcp_opt_add(&dhcp_opts, "server_id",  54, DHCP_OPT_TYPE_IP4);
    dhcp_opt_add(&dhcp_opts, "tftp_server", 66, DHCP_OPT_TYPE_IP4);
    dhcp_opt_add(&dhcp_opts, "classless_static_route", 121,
                 DHCP_OPT_TYPE_STATIC_ROUTES);
    dhcp_opt_add(&dhcp_opts, "ip_forward_enable",  19, DHCP_OPT_TYPE_BOOL);
    dhcp_opt_add(&dhcp_opts, "router_discovery", 31, DHCP_OPT_TYPE_BOOL);
    dhcp_opt_add(&dhcp_opts, "ethernet_encap", 36, DHCP_OPT_TYPE_BOOL);
    dhcp_opt_add(&dhcp_opts, "default_ttl",  23, DHCP_OPT_TYPE_UINT8);
    dhcp_opt_add(&dhcp_opts, "tcp_ttl", 37, DHCP_OPT_TYPE_UINT8);
    dhcp_opt_add(&dhcp_opts, "mtu", 26, DHCP_OPT_TYPE_UINT16);
    dhcp_opt_add(&dhcp_opts, "lease_time",  51, DHCP_OPT_TYPE_UINT32);

    struct action_params ap = {
        .dhcp_opts = &dhcp_opts,
    };


    char *actions = xasprintf("dhcp_offer(%s);", argv[1]);
    uint64_t ofpacts_stub[128 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(
        ofpacts_stub);
    struct expr *prereqs;
    char *error;

    error = actions_parse_string(actions, &ap, &ofpacts, &prereqs);
    dhcp_opts_destroy(&dhcp_opts);
    free(actions);
    if (error) {
        printf("actions_parse_string failed with error - %s\n", error);
        free(error);
        exit(1);
    }

    if (ofpacts.size < (sizeof(struct ofpact_controller) +
        sizeof(struct action_header))) {
        ovs_fatal(1, "Error. dhcp_offer parse action failed : "
                  " ofpact_controller not configured");
    }

    struct ofpact_controller *oc = ofpbuf_pull(&ofpacts, sizeof *oc);
    if (!oc->pause) {
        ovs_fatal(1, "Error. dhcp_offer parse action failed : pause flag "
                  " not set in ofpact_controller");
    }
    struct action_header *ah = ofpbuf_pull(&ofpacts, sizeof *ah);
    if (ah->opcode != htonl(ACTION_OPCODE_DHCP_OFFER)) {
        ovs_fatal(1, "Error. dhcp_offer parse action failed : dhcp_offer "
                  "action header flag not set");
    }

    uint64_t expected_dhcp_opts_stub[128 / 8];
    struct ofpbuf expected_dhcp_opts = OFPBUF_STUB_INITIALIZER(
        expected_dhcp_opts_stub);
    if (ofpbuf_put_hex(&expected_dhcp_opts, argv[2], NULL)[0] != '\0') {
        ovs_fatal(1, "Error. Invalid expected dhcp opts");
    }

    if (oc->userdata_len  != (expected_dhcp_opts.size + sizeof *ah)) {
        ovs_fatal(1, "Error. dhcp_offer parse action failed : userdata length"
                  " mismatch. Expected - %lu : Actual - %u",
                  expected_dhcp_opts.size + sizeof *ah, oc->userdata_len);
    }

    if (memcmp(ofpacts.data, expected_dhcp_opts.data, expected_dhcp_opts.size)) {
        ovs_fatal(1, "Error. dhcp_offer parse action failed : dhcp opts are"
                  " not as expected");
    }

    exit(0);
}

OVSTEST_REGISTER("test-ovn-dhcp", test_ovn_dhcp_main);
OVSTEST_REGISTER("test-ovn-dhcp-offer-action", test_dhcp_offer_action);
