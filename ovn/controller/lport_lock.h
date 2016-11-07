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

#ifndef OVN_LPORT_LOCK_H
#define OVN_LPORT_LOCK_H 1

#include "ovsdb-idl.h"

struct sset;
void lport_lock_init(void);
void lport_lock_run(struct ovsdb_idl *, const char *chassis_id,
                    struct sset *chassis_lports);
bool lport_lock_cleanup(void);

#endif /* OVN_LPORT_LOCK_H */
