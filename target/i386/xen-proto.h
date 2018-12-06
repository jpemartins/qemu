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

#include "hw/xen/xen-bus.h"
#include "hw/xen/xen-legacy-backend.h"

typedef struct XenGrantTable {
    unsigned int version;
    unsigned int nr_frames;

#define GNTTAB_MAX_FRAMES 64
    unsigned int max_nr_frames;
    union {
        void **frames;
        struct grant_entry_v1 **frames_v1;
    };
} XenGrantTable;

typedef struct XenCallbackVector {
    int via;
    int vector;
    int virq;
} XenCallbackVector;

typedef struct XenEvtChn {
  int notify_vcpu_id;
  int remote_dom;
  int remote_port;
  int port;
  int virq;
#define XEN_EVTCHN_TYPE_VIRQ      0
#define XEN_EVTCHN_TYPE_IPI       1
#define XEN_EVTCHN_TYPE_INTERDOM  2
#define XEN_EVTCHN_TYPE_UNBOUND   3
  int type;
#define XEN_EVTCHN_STATE_FREE     0
#define XEN_EVTCHN_STATE_INUSE    1
#define XEN_EVTCHN_STATE_UNBOUND  2
  int state;

  bool is_legacy;
  union {
      XenLegacyDeviceHandler *legacy_handler;
      XenEventHandler handler;
  } callback;
  union {
      struct XenLegacyDevice *dev;
      void *opaque;
  } callback_arg;
} XenEvtChn;

typedef struct XenState {
    struct shared_info *shared_info;
    union {
        struct XenCallbackVector cb;
    };
    int domid;
    int port;
    QemuMutex port_lock;
    Notifier exit;
    struct xs_handle *xenstore;
    MemoryRegion mr;
    int xenstore_pfn;
    int xenstore_port;
    struct XenGrantTable gnttab;
} XenState;

typedef struct XenCPUState {
   struct vcpu_info *info;
   /* per cpu vector */
   struct XenCallbackVector cb;
#define NR_VIRQS 24
   struct XenEvtChn *virq_to_evtchn[NR_VIRQS];
   struct QEMUTimer *oneshot_timer;
   struct QEMUTimer *periodic_timer;
   unsigned long period_ns;
} XenCPUState;

#endif

