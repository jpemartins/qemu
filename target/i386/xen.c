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
#include "cpu.h"
#include "xen.h"
#include "trace.h"
#include "sysemu/sysemu.h"

#include "standard-headers/xen/version.h"
#include "standard-headers/xen/memory.h"
#include "standard-headers/xen/hvm/hvm_op.h"
#include "standard-headers/xen/vcpu.h"

#define PAGE_OFFSET    0xffffffff80000000UL
#define PAGE_SHIFT     12

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

static uint64_t gva_to_gpa(CPUState *cs, uint64_t gva)
{
    struct kvm_translation t = { .linear_address = gva };
    int err;

    err = kvm_vcpu_ioctl(cs, KVM_TRANSLATE, &t);
    if (err || !t.valid) {
        return 0;
    }

    return t.physical_address;
}

static void *gva_to_hva(CPUState *cs, uint64_t gva)
{
    return gpa_to_hva(gva_to_gpa(cs, gva));
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

static int xen_set_shared_info(CPUState *cs, struct shared_info *shi,
                               uint64_t gfn)
{
    struct kvm_xen_hvm_attr xhsi;
    XenState *xen = cs->xen_state;
    KVMState *s = cs->kvm_state;
    XenCPUState *xcpu;
    CPUState *cpu;
    int i, err;

    xhsi.type = KVM_XEN_ATTR_TYPE_SHARED_INFO;
    xhsi.u.shared_info.gfn = gfn;
    err = kvm_vm_ioctl(s, KVM_XEN_HVM_SET_ATTR, &xhsi);
    trace_kvm_xen_set_shared_info(gfn);
    xen->shared_info = shi;

    for (i = 0; i < smp_cpus; i++) {
        cpu = qemu_get_cpu(i);

        xcpu = &X86_CPU(cpu)->env.xen_vcpu;
        xcpu->info = &shi->vcpu_info[cpu->cpu_index];
    }

    return err;
}

static int kvm_xen_hcall_memory_op(struct kvm_xen_exit *exit,
                                   int cmd, uint64_t arg, X86CPU *cpu)
{
    CPUState *cs = CPU(cpu);
    int err = 0;

    switch (cmd) {
    case XENMEM_add_to_physmap: {
            struct xen_add_to_physmap *xatp;
            struct shared_info *shi;

            xatp = gva_to_hva(cs, arg);
            if (!xatp) {
                err = -EFAULT;
                break;
            }

            switch (xatp->space) {
            case XENMAPSPACE_shared_info:
                break;
            default:
                err = -ENOSYS;
                break;
            }

            shi = gpa_to_hva(xatp->gpfn << PAGE_SHIFT);
            if (!shi) {
                err = -EFAULT;
                break;
            }

            err = xen_set_shared_info(cs, shi, xatp->gpfn);
            break;
         }
    }

    exit->u.hcall.result = err;
    return err ? HCALL_ERR : 0;
}

static int kvm_xen_hcall_hvm_op(struct kvm_xen_exit *exit,
                                int cmd, uint64_t arg)
{
    switch (cmd) {
    case HVMOP_pagetable_dying: {
            exit->u.hcall.result = -ENOSYS;
            return 0;
        }
    }

    exit->u.hcall.result = -ENOSYS;
    return HCALL_ERR;
}

static int xen_set_vcpu_attr(CPUState *cs, uint16_t type, uint64_t gpa)
{
    struct kvm_xen_hvm_attr xhsi;
    KVMState *s = cs->kvm_state;

    xhsi.type = type;
    xhsi.u.vcpu_attr.vcpu = cs->cpu_index;
    xhsi.u.vcpu_attr.gpa = gpa;

    trace_kvm_xen_set_vcpu_attr(cs->cpu_index, type, gpa);

    return kvm_vm_ioctl(s, KVM_XEN_HVM_SET_ATTR, &xhsi);
}

static int vcpuop_register_vcpu_info(CPUState *cs, CPUState *target,
                                     uint64_t arg)
{
    XenCPUState *xt = &X86_CPU(target)->env.xen_vcpu;
    struct vcpu_register_vcpu_info *rvi;
    uint64_t gpa;
    void *hva;

    rvi = gva_to_hva(cs, arg);
    if (!rvi) {
        return -EFAULT;
    }

    gpa = ((rvi->mfn << PAGE_SHIFT) + rvi->offset);
    hva = gpa_to_hva(gpa);
    if (!hva) {
        return -EFAULT;
    }

    xt->info = hva;
    return xen_set_vcpu_attr(target, KVM_XEN_ATTR_TYPE_VCPU_INFO, gpa);
}

static int vcpuop_register_vcpu_time_info(CPUState *cs, CPUState *target,
                                          uint64_t arg)
{
    struct vcpu_register_time_memory_area *tma;
    uint64_t gpa;
    void *hva;

    tma = gva_to_hva(cs, arg);
    if (!tma) {
        return -EFAULT;
    }

    hva = gva_to_hva(cs, tma->addr.p);
    if (!hva || !tma->addr.p) {
        return -EFAULT;
    }

    gpa = gva_to_gpa(cs, tma->addr.p);
    return xen_set_vcpu_attr(target, KVM_XEN_ATTR_TYPE_VCPU_TIME_INFO, gpa);
}

static int vcpuop_register_runstate_info(CPUState *cs, CPUState *target,
                                         uint64_t arg)
{
    struct vcpu_register_runstate_memory_area *rma;
    uint64_t gpa;
    void *hva;

    rma = gva_to_hva(cs, arg);
    if (!rma) {
        return -EFAULT;
    }

    hva = gva_to_hva(cs, rma->addr.p);
    if (!hva || !rma->addr.p) {
        return -EFAULT;
    }

    gpa = gva_to_gpa(cs, rma->addr.p);
    return xen_set_vcpu_attr(target, KVM_XEN_ATTR_TYPE_VCPU_RUNSTATE, gpa);
}

static int kvm_xen_hcall_vcpu_op(struct kvm_xen_exit *exit, X86CPU *cpu,
                                 int cmd, int vcpu_id, uint64_t arg)
{
    CPUState *dest = qemu_get_cpu(vcpu_id);
    CPUState *cs = CPU(cpu);
    int err = -ENOSYS;

    switch (cmd) {
    case VCPUOP_register_runstate_memory_area: {
            err = vcpuop_register_runstate_info(cs, dest, arg);
            break;
        }
    case VCPUOP_register_vcpu_time_memory_area: {
            err = vcpuop_register_vcpu_time_info(cs, dest, arg);
            break;
        }
    case VCPUOP_register_vcpu_info: {
            err = vcpuop_register_vcpu_info(cs, dest, arg);
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
    case __HYPERVISOR_vcpu_op:
        return kvm_xen_hcall_vcpu_op(exit, cpu,
                                     exit->u.hcall.params[0],
                                     exit->u.hcall.params[1],
                                     exit->u.hcall.params[2]);
    case __HYPERVISOR_hvm_op:
        return kvm_xen_hcall_hvm_op(exit, exit->u.hcall.params[0],
                                    exit->u.hcall.params[1]);
    case __HYPERVISOR_memory_op:
        return kvm_xen_hcall_memory_op(exit, exit->u.hcall.params[0],
                                       exit->u.hcall.params[1], cpu);
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
