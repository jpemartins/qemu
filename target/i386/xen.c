/*
 * Xen HVM emulation support in KVM
 *
 * Copyright (c) 2019 Oracle and/or its affiliates. All rights reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "linux/kvm.h"
#include "cpu.h"
#include "xen.h"

static void arch_init_hypercall_page(CPUState *cs, void *addr)
{
    CPUX86State *env = cs->env_ptr;
    char *p;
    int i;

    for (i = 0; i < (TARGET_PAGE_SIZE / 32); i++) {
        p = (char *)(addr + (i * 32));
        *(uint8_t  *)(p + 0) = 0xb8; /* mov imm32, %eax */
        *(uint32_t *)(p + 1) = i;
        *(uint8_t  *)(p + 5) = 0x0f; /* vmcall */
        *(uint8_t  *)(p + 6) = 0x01;

        if (env->cpuid_vendor1 == CPUID_VENDOR_INTEL_1 &&
            env->cpuid_vendor2 == CPUID_VENDOR_INTEL_2 &&
            env->cpuid_vendor3 == CPUID_VENDOR_INTEL_3)
            *(uint8_t  *)(p + 7) = 0xc1;
        else
            *(uint8_t  *)(p + 7) = 0xd9;

        *(uint8_t  *)(p + 8) = 0xc3; /* ret */
    }
}

int kvm_xen_set_hypercall_page(CPUState *env)
{
    struct kvm_xen_hvm_config cfg;
    void *page;

    page = g_malloc(TARGET_PAGE_SIZE);
    if (!page) {
        return -ENOMEM;
    }

    memset(page, 0xCC, TARGET_PAGE_SIZE);

    arch_init_hypercall_page(env, page);

    cfg.msr = XEN_CPUID_SIGNATURE;
    cfg.flags = 0;
    cfg.blob_addr_32 = (uint64_t) page;
    cfg.blob_size_32 = 1;
    cfg.blob_addr_64 = (uint64_t) page;
    cfg.blob_size_64 = 1;

    return kvm_vm_ioctl(env->kvm_state, KVM_XEN_HVM_CONFIG, &cfg);
}
