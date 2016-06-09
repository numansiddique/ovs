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
#include "ovstest.h"
#include "pcap-file.h"


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

    struct dp_packet *packet = NULL;
    retval = ovs_pcap_read(pcap, &packet, NULL);
    if (retval == EOF) {
        ovs_fatal(0, "unexpected end of file reading pcap file : [%s]\n",
                  argv[1]);
    } else if (retval) {
        ovs_fatal(retval, "error reading pcap file");
    }

    int exit_code = 1;
    struct flow flow;
    flow_extract(packet, &flow);

    struct dhcp_header const *dhcp_data = dp_packet_get_udp_payload(packet);
    if (dhcp_data->op != (uint8_t)2) {
        printf("Invalid dhcp op reply code : %d\n", dhcp_data->op);
        goto exit;
    }

    if (flow.tp_src != htons(DHCP_SERVER_PORT) &&
        flow.tp_dst != htons(DHCP_CLIENT_PORT)) {
        printf("Error. Not a dhcp response packet \n");
        goto exit;
    }

    if (flow.nw_dst != expected_offer_ip) {
        printf("Error. Offered ip : "IP_FMT " : Expected ip : %s\n",
        IP_ARGS(flow.nw_dst), argv[2]);
        goto exit;
    }

    if(dhcp_data->yiaddr != expected_offer_ip) {
        printf("Error. Offered yiaddr : "IP_FMT " : Expected ip : %s\n",
        IP_ARGS(dhcp_data->yiaddr), argv[2]);
        goto exit;
    }

    /* Verify the dhcp option cookie */
    uint8_t const *footer = (uint8_t *)dhcp_data + sizeof(*dhcp_data);
    ovs_be32 dhcp_cookie = htonl(DHCP_MAGIC_COOKIE);
    if (memcmp(footer, &dhcp_cookie, sizeof(ovs_be32))) {
        printf("Error. Invalid dhcp magic cookie\n");
        goto exit;
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
        goto exit;
    }

    /* 4 bytes padding, 1 byte FF and 4 bytes padding */
    ofpbuf_put_hex(&dhcp_opts, "00000000FF00000000", NULL);

    footer += sizeof(uint32_t);

    size_t dhcp_opts_size = (const char *)dp_packet_tail(packet) - (
        const char *)footer;
    if (dhcp_opts_size != dhcp_opts.size) {
        printf("Error. dhcp options size mismatch\n");
        goto exit;
    }

    if (memcmp(footer, dhcp_opts.data, dhcp_opts.size)) {
        printf("Error. Invalid dhcp options present\n");
        goto exit;
    }

    exit_code = 0;

exit:
    fclose(pcap);
    if (packet) {
        dp_packet_delete(packet);
    }
    exit(exit_code);
}

OVSTEST_REGISTER("test-ovn-dhcp", test_ovn_dhcp_main);
