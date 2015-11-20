
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

#ifndef OVN_DHCP_H
#define OVN_DHCP_H

#include "ofp-util.h"

struct controller_ctx;
struct ofpbuf;
struct flow;
struct dp_packet;

bool ovn_dhcp_process_packet(struct controller_ctx * ctx,
                             struct ofputil_packet_in * pin,
                             enum ofputil_protocol ofp_proto,
                             struct flow *flow,
                             struct dp_packet *packet,
                             struct ofpbuf **ret_buf);

#endif
