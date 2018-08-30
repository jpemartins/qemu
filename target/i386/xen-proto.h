/*
 * Definitions for Xen guest/hypervisor interaction - x86-specific part
 *
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef TARGET_I386_XEN_PROTO_H
#define TARGET_I386_XEN_PROTO_H

typedef struct XenCallbackVector {
    int via;
    int vector;
    int virq;
} XenCallbackVector;

typedef struct XenEvtChn {
  int notify_vcpu_id;
  int port;
  int virq;
#define XEN_EVTCHN_TYPE_VIRQ 0
#define XEN_EVTCHN_TYPE_IPI  1
  int type;
#define XEN_EVTCHN_STATE_FREE  0
#define XEN_EVTCHN_STATE_INUSE 1
  int state;
} XenEvtChn;

typedef struct XenState {
    struct shared_info *shared_info;
    union {
        struct XenCallbackVector cb;
    };
    int port;
    QemuMutex port_lock;
} XenState;

typedef struct XenCPUState {
   struct vcpu_info *info;
   /* per cpu vector */
   struct XenCallbackVector cb;
#define NR_VIRQS 24
   struct XenEvtChn *virq_to_evtchn[NR_VIRQS];
} XenCPUState;

#endif

