/*
 * Event channels implementation on Xen HVM guests in KVM
 *
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef TARGET_I386_XEN_EVTCHN_H
#define TARGET_I386_XEN_EVTCHN_H

#include "cpu.h"
#include "sysemu/kvm.h"
#include "qemu/event_notifier.h"

int kvm_xen_evtchn_init(XenState *xen_state);

int kvm_xen_evtchn_bind_ipi(X86CPU *cpu, void *arg);
int kvm_xen_evtchn_bind_virq(X86CPU *cpu, void *arg);
int kvm_xen_evtchn_bind_interdomain(X86CPU *cpu, void *arg);
int kvm_xen_evtchn_close(X86CPU *cpu, void *arg);
int kvm_xen_evtchn_unmask(X86CPU *cpu, void *arg);
int kvm_xen_evtchn_status(X86CPU *cpu, void *arg);
int kvm_xen_evtchn_send(X86CPU *cpu, void *arg);
int kvm_xen_evtchn_vcpu_init(X86CPU *cpu, struct vcpu_info *info);

void evtchn_2l_set_pending(X86CPU *cpu, XenEvtChn *evtchn);

#endif
