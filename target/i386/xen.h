/*
 * Xen HVM emulation support in KVM
 *
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef TARGET_I386_XEN_H
#define TARGET_I386_XEN_H

#include "cpu.h"
#include "sysemu/kvm.h"
#include "qemu/event_notifier.h"

#define XEN_CPUID_SIGNATURE        0x40000000
#define XEN_CPUID_VENDOR           0x40000001
#define XEN_CPUID_HVM_MSR          0x40000002
#define XEN_CPUID_TIME             0x40000003
#define XEN_CPUID_HVM              0x40000004

int kvm_xen_set_hypercall_page(CPUState *env);
int kvm_xen_handle_exit(X86CPU *cpu, struct kvm_xen_exit *exit);

#endif
