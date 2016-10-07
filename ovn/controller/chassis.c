/* Copyright (c) 2015, 2016 Nicira, Inc.
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
#include <unistd.h>

#include "chassis.h"

#include "lib/smap.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn-controller.h"
#include "lib/util.h"

VLOG_DEFINE_THIS_MODULE(chassis);

#ifndef HOST_NAME_MAX
/* For windows. */
#define HOST_NAME_MAX 255
#endif /* HOST_NAME_MAX */

void
chassis_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_external_ids);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_iface_types);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_datapath_type);
}

static const char *
get_bridge_mappings(const struct smap *ext_ids)
{
    return smap_get_def(ext_ids, "ovn-bridge-mappings", "");
}

/* Returns this chassis's Chassis record */
const struct sbrec_chassis *
chassis_run(struct controller_ctx *ctx, const char *chassis_id,
            const struct ovsrec_bridge *br_int)
{
    const struct ovsrec_open_vswitch *cfg;

    cfg = ovsrec_open_vswitch_first(ctx->ovs_idl);
    if (!cfg) {
        VLOG_INFO("No Open_vSwitch row defined.");
        return NULL;
    }

    const struct sbrec_chassis *chassis_rec
        = get_chassis(ctx->ovnsb_idl, chassis_id);

    if (!chassis_rec) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "No chassis row defined for chassis '%s'.",
                     chassis_id);
        return NULL;
    }

    uint32_t cur_tunnels = 0;
    for (int i = 0; i < chassis_rec->n_encaps; i++) {
        cur_tunnels |= get_tunnel_type(chassis_rec->encaps[i]->type);
    }

    if (!cur_tunnels) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "Invalid or no encap params for chassis '%s'.",
                     chassis_id);
        return NULL;
    }

    if (!chassis_rec->hostname[0]) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "No hostname defined for chassis '%s'.",
                     chassis_id);
        return NULL;
    }

    const struct sbrec_chassis *cr;
    SBREC_CHASSIS_FOR_EACH(cr, ctx->ovnsb_idl) {
        if (strcmp(chassis_rec->name, cr->name) &&
            !strcmp(chassis_rec->hostname, cr->hostname)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "hostname defined for this chassis '%s' is "
                         "same as other chassis '%s'", chassis_id, cr->name);
            return NULL;
        }
    }

    const char *bridge_mappings = get_bridge_mappings(&cfg->external_ids);
    const char *datapath_type =
        br_int && br_int->datapath_type ? br_int->datapath_type : "";

    const char *chassis_bridge_mappings
        = get_bridge_mappings(&chassis_rec->external_ids);
    const char *chassis_datapath_type
        = smap_get_def(&chassis_rec->external_ids, "datapath-type", "");

    if (strcmp(bridge_mappings, chassis_bridge_mappings)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "bridge_mappings configuration mismatch. Defined -,"
                  " %s, Expected - %s", chassis_bridge_mappings,
                  bridge_mappings);
    }

    if (strcmp(datapath_type, chassis_datapath_type)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "datapath_type configuration mismatch. Defined - %s,"
                  " Expected - %s", chassis_datapath_type, datapath_type);
    }

    return chassis_rec;
}

/* Returns true if the database is all cleaned up, false if more work is
 * required. */
bool
chassis_cleanup(struct controller_ctx *ctx, const char *chassis_id)
{
    if (!chassis_id) {
        return true;
    }

    /* Delete Chassis row. */
    const struct sbrec_chassis *chassis_rec
        = get_chassis(ctx->ovnsb_idl, chassis_id);
    if (!chassis_rec) {
        return true;
    }
    if (ctx->ovnsb_idl_txn) {
        ovsdb_idl_txn_add_comment(ctx->ovnsb_idl_txn,
                                  "ovn-controller: unregistering chassis '%s'",
                                  chassis_id);
        sbrec_chassis_delete(chassis_rec);
    }
    return false;
}
