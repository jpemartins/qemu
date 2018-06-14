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
#include "qemu/log.h"
#include "linux/kvm.h"
#include "exec/address-spaces.h"
#include "standard-headers/xen/version.h"
#include "cpu.h"
#include "xen.h"

#include "trace.h"

#define PAGE_OFFSET    0xffffffff80000000UL

/*
 * Unhandled hypercalls error:
 *
 * -1 crash and dump registers
 *  0 no abort and guest handles -ENOSYS (default)
 */
#ifndef HCALL_ERR
#define HCALL_ERR      0
#endif

static void *gpa_to_hva(uint64_t gpa)
{
    MemoryRegionSection mrs;

    mrs = memory_region_find(get_system_memory(), gpa, 1);
    return !mrs.mr ? NULL : qemu_map_ram_ptr(mrs.mr->ram_block,
                                             mrs.offset_within_region);
}

static void *gva_to_hva(CPUState *cs, uint64_t gva)
{
    struct kvm_translation t = { .linear_address = gva };
    int err;

    err = kvm_vcpu_ioctl(cs, KVM_TRANSLATE, &t);
    if (err || !t.valid) {
        return NULL;
    }

    return gpa_to_hva(t.physical_address);
}

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

static int kvm_xen_hcall_xen_version(struct kvm_xen_exit *exit, X86CPU *cpu,
                                     int cmd, uint64_t arg)
{
    int err = 0;

    switch (cmd) {
    case XENVER_get_features: {
            struct xen_feature_info *fi;

            fi = gva_to_hva(CPU(cpu), arg);
            if (!fi) {
                err = -EFAULT;
                break;
            }

            if (fi->submap_idx != 0) {
                err = -EINVAL;
                break;
            }

            /*
             * There's only HVM guests and we only expose what
             * we intend to support. These are left in the open
             * whether we should or not support them:
             *
             *   XENFEAT_memory_op_vnode_supported
             *   XENFEAT_writable_page_tables
             */
            fi->submap = (1U << XENFEAT_auto_translated_physmap);
            break;
         }
    }

    exit->u.hcall.result = err;
    return err ? HCALL_ERR : 0;
}

static int __kvm_xen_handle_exit(X86CPU *cpu, struct kvm_xen_exit *exit)
{
    uint16_t code = exit->u.hcall.input;

    switch (code) {
    case __HYPERVISOR_xen_version:
        return kvm_xen_hcall_xen_version(exit, cpu, exit->u.hcall.params[0],
                                         exit->u.hcall.params[1]);
    default:
        exit->u.hcall.result = -ENOSYS;
        return HCALL_ERR;
    }
}

int kvm_xen_handle_exit(X86CPU *cpu, struct kvm_xen_exit *exit)
{
    int ret = HCALL_ERR;

    switch (exit->type) {
    case KVM_EXIT_XEN_HCALL: {
        ret = __kvm_xen_handle_exit(cpu, exit);
        trace_kvm_xen_hypercall(CPU(cpu)->cpu_index, exit->u.hcall.input,
                           exit->u.hcall.params[0], exit->u.hcall.params[1],
                           exit->u.hcall.params[2], exit->u.hcall.result);
        return ret;
    }
    default:
        return ret;
    }
}
