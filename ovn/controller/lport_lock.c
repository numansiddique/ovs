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

#include <config.h>
#include "lport_lock.h"
#include "sset.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(lport_lock);

static struct sset locked_lports = SSET_INITIALIZER(&locked_lports);

static char *
construct_valid_lock_name(const char *s) {
    char *l_name = xzalloc(strlen(s) + 2);
    strcpy(l_name, "L_");
    for(int i = 0; i < strlen(s); i++) {
        if (s[i] == '-') {
            l_name[i + 2] = '_';
        } else {
            l_name[i + 2] = s[i];
        }
    }

    return l_name;
}

void
lport_lock_init(void)
{

}

void
lport_lock_run(struct ovsdb_idl *sb_idl, const char *chassis_id,
               struct sset *chassis_lports)
{
    struct sset lports_to_lock = SSET_INITIALIZER(&lports_to_lock);
    const struct sbrec_port_binding *sb;

    SBREC_PORT_BINDING_FOR_EACH(sb, sb_idl) {
        if (sb->type[0]) {
            continue;
        }

        if (sb->chassis && !strcmp(sb->chassis->name, chassis_id)
            && sset_contains(chassis_lports, sb->logical_port)) {
            sset_add(&lports_to_lock, sb->logical_port);
            if (!sset_contains(&locked_lports, sb->logical_port)) {
                char *l_name = construct_valid_lock_name(sb->logical_port);
                if (!ovsdb_idl_has_lock(sb_idl, l_name)) {
                    ovsdb_idl_steal_lock(sb_idl, l_name);
                }
                free(l_name);
                sset_add(&locked_lports, sb->logical_port);
            }
        }
    }

    const char *lport, *next;
    SSET_FOR_EACH_SAFE (lport, next, &locked_lports) {
        if (!sset_contains(&lports_to_lock, lport)) {
            sset_delete(&locked_lports, SSET_NODE_FROM_NAME(lport));
            char *l_name = construct_valid_lock_name(lport);
            ovsdb_idl_remove_lock(sb_idl, l_name);
            free(l_name);
        }
    }

    sset_destroy(&lports_to_lock);
}

bool
lport_lock_cleanup(void)
{
    sset_destroy(&locked_lports);
    return true;
}
