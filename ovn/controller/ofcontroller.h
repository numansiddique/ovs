
#ifndef OFCONTROLLER_H
#define OFCONTROLLER_H 1

#include <stdint.h>

/* Interface for OVN main loop. */
void ofcontroller_init(char const*);
void ofcontroller_run(struct controller_ctx *ctx, const struct ovsrec_bridge *br_int);
void ofcontroller_wait(void);
void ofcontroller_destroy(void);

/*
* Add flows to forward the packets to the controller.
*/
void ofcontroller_add_flows(const struct sbrec_port_binding *binding,
                            struct hmap *flow_table);
#endif
