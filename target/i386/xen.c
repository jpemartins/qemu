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
#include "qemu/error-report.h"
#include "qemu/cutils.h"
#include "linux/kvm.h"
#include "exec/address-spaces.h"
#include "cpu.h"
#include "xen.h"
#include "trace.h"
#include "xen_evtchn.h"
#include "sysemu/sysemu.h"
#include "monitor/monitor.h"
#include "qapi/qmp/qdict.h"
#include "qapi/error.h"
#include "qom/cpu.h"
#include "hw/xen/xen.h"


#define __XEN_INTERFACE_VERSION__ 0x00040400

#include "standard-headers/xen/version.h"
#include "standard-headers/xen/memory.h"
#include "standard-headers/xen/hvm/hvm_op.h"
#include "standard-headers/xen/hvm/params.h"
#include "standard-headers/xen/vcpu.h"
#include "standard-headers/xen/sched.h"
#include "standard-headers/xen/event_channel.h"
#include "standard-headers/xen/grant_table.h"

#include <xenstore.h>

#define PAGE_OFFSET    0xffffffff80000000UL
#define PAGE_SHIFT     12

/* Import from libxencontrol */
#define X86_HVM_END_SPECIAL_REGION  0xff000U
#define X86_HVM_NR_SPECIAL_PAGES    8i

#define SPECIALPAGE_XENSTORE 0
#define SPECIALPAGE_CONSOLE  1

#define xen_special_pfn(x) \
     (X86_HVM_END_SPECIAL_REGION - X86_HVM_NR_SPECIAL_PAGES + (x))

/*
 * Unhandled hypercalls error:
 *
 * -1 crash and dump registers
 *  0 no abort and guest handles -ENOSYS (default)
 */
#ifndef HCALL_ERR
#define HCALL_ERR      0
#endif

static QemuMutex xen_global_mutex;
static int xs_domid;

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

static uint64_t kvm_get_current_ns(CPUState *cs)
{
    struct kvm_clock_data data;
    int ret;

    ret = kvm_vm_ioctl(cs->kvm_state, KVM_GET_CLOCK, &data);
    if (ret < 0) {
        fprintf(stderr, "KVM_GET_CLOCK failed: %s\n", strerror(ret));
                abort();
    }

    return data.clock;
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

static void kvm_xen_exit(Notifier *n, void *data)
{
    XenState *xen = container_of(n, XenState, exit);
    struct xs_handle *xsh = xen->xenstore;

    if (xsh) {
        xs_release_domain(xsh, xen->domid);
        xs_rm(xsh, XBT_NULL, xs_get_domain_path(xsh, xen->domid));
        xs_close(xsh);
    }
}

void kvm_xen_init(XenState *xen)
{
    kvm_xen_set_domid(kvm_state, xen);

    qemu_mutex_init(&xen_global_mutex);
    qemu_mutex_init(&xen->port_lock);

    xen->exit.notify = kvm_xen_exit;
    qemu_add_exit_notifier(&xen->exit);

    kvm_xen_evtchn_init(xen);
}

int kvm_xen_set_domid(KVMState *kvm_state, XenState *xen)
{
    struct kvm_xen_hvm_attr xhd;
    int r;

    if (xen->domid != 0) {
        return -EEXIST;
    }

    /* Domid 0 means invalid */
    xen->domid = 0;

    xhd.type = KVM_XEN_ATTR_TYPE_DOMID;
    if (!xen_domid)
        xhd.u.dom.domid = -1;
    else
        xhd.u.dom.domid = xen_domid;
    r = kvm_vm_ioctl(kvm_state, KVM_XEN_HVM_SET_ATTR, &xhd);
    if (r) {
        return -EFAULT;
    }

    r = kvm_vm_ioctl(kvm_state, KVM_XEN_HVM_GET_ATTR, &xhd);
    if (r || !xhd.u.dom.domid) {
        return -EFAULT;
    }

    xen->domid = xhd.u.dom.domid;
    trace_kvm_xen_set_domid(xen->domid);
    xen_domid = xen->domid;
    return r;
}

void kvm_xen_run_on_cpu(CPUState *cpu, run_on_cpu_func func, void *data)
{
    do_run_on_cpu(cpu, func, RUN_ON_CPU_HOST_PTR(data), &xen_global_mutex);
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
            fi->submap = (1U << XENFEAT_auto_translated_physmap) |
                         (1U << XENFEAT_hvm_callback_vector);

            if (cpu->xen_pvclock) {
                fi->submap |= (1U << XENFEAT_hvm_safe_pvclock);
            }

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

static int xen_set_gnttab_frame(CPUState *cs, void *frame,
                                uint32_t idx, uint64_t gfn)
{
    struct kvm_xen_hvm_attr xhgt;
    XenState *xen = cs->xen_state;
    int err;

    if (idx < xen->gnttab.nr_frames &&
        idx >= xen->gnttab.max_nr_frames) {
        return -EINVAL;
    }

    xhgt.type = KVM_XEN_ATTR_TYPE_GNTTAB;
    xhgt.u.gnttab.flags = KVM_XEN_GNTTAB_F_GROW;
    xhgt.u.gnttab.grow.idx = idx;
    xhgt.u.gnttab.grow.gfn = gfn;
    err = kvm_vm_ioctl(cs->kvm_state, KVM_XEN_HVM_SET_ATTR, &xhgt);
    if (!err) {
        if (!idx) {
            g_free(xen->gnttab.frames[idx]);
        }
        xen->gnttab.frames[idx] = frame;
        xen->gnttab.nr_frames++;
    }
    return err;
}

static int kvm_xen_hcall_memory_op(struct kvm_xen_exit *exit,
                                   int cmd, uint64_t arg, X86CPU *cpu)
{
    CPUState *cs = CPU(cpu);
    int err = -ENOSYS;

    switch (cmd) {
    case XENMEM_add_to_physmap: {
            struct xen_add_to_physmap *xatp;
            void *hva;

            xatp = gva_to_hva(cs, arg);
            if (!xatp) {
                err = -EFAULT;
                break;
            }

            hva = gpa_to_hva(xatp->gpfn << PAGE_SHIFT);
            if (!hva) {
                err = -EFAULT;
                break;
            }

            switch (xatp->space) {
            case XENMAPSPACE_shared_info: {
                err = xen_set_shared_info(cs, hva, xatp->gpfn);
                break;
            }
            case XENMAPSPACE_grant_table: {
                err = xen_set_gnttab_frame(cs, hva, xatp->idx, xatp->gpfn);
                break;
            }
            default:
                break;
            }

            trace_kvm_xen_add_to_physmap(xatp->space, xatp->idx, xatp->gpfn);
            break;
         }
    }

    exit->u.hcall.result = err;
    return err ? HCALL_ERR : 0;
}

static void xen_vcpu_set_callback(CPUState *cs, run_on_cpu_data data)
{
    XenCallbackVector *cb = data.host_ptr;
    KVMState *kvm = cs->kvm_state;
    X86CPU *cpu = X86_CPU(cs);
    XenCPUState *xcpu = &cpu->env.xen_vcpu;
    int vcpu = cs->cpu_index;
    int err;

    err = kvm_irqchip_add_xen_evtchn_route(kvm, cb->via, vcpu, cb->vector);
    if (err < 0) {
        return;
    }

    xcpu->cb.via = cb->via;
    xcpu->cb.vector = cb->vector;
    xcpu->cb.virq = err;

    cb->virq = xcpu->cb.virq;

    trace_kvm_xen_set_callback(cs->cpu_index, cb->virq, cb->vector, cb->via);

    g_free(cb);
}

static int xen_add_evtchn_route(CPUState *cs, int vector, int via)
{
    CPUState *cpu;
    int i;

    for (i = 0; i < smp_cpus; i++) {
        XenCallbackVector *data;

        cpu = qemu_get_cpu(i);
        if (!cpu) {
            return -1;
        }

        data = g_malloc(sizeof(*data));
        if (!data) {
            return -1;
        }

        cpu = qemu_get_cpu(i);
        data->virq = -1;
        data->vector = vector;
        data->via = via;

        kvm_xen_run_on_cpu(cpu, xen_vcpu_set_callback, data);
    }

    return 0;
}

static int handle_set_param(struct kvm_xen_exit *exit, X86CPU *cpu,
                            uint64_t arg)
{
    CPUState *cs = CPU(cpu);
    struct xen_hvm_param *hp;
    int err = 0, via, vector;

    hp = gva_to_hva(cs, arg);
    if (!hp) {
        err = -EFAULT;
        goto out;
    }

    if (hp->domid != DOMID_SELF) {
        err = -EINVAL;
        goto out;
    }

#define CALLBACK_VIA_TYPE_SHIFT       56
#define CALLBACK_VIA_TYPE_GSI         0x0
#define CALLBACK_VIA_TYPE_PCI_INTX    0x1
#define CALLBACK_VIA_TYPE_VECTOR      0x2
#define CALLBACK_VIA_TYPE_EVTCHN      0x3
    switch (hp->index) {
    case HVM_PARAM_CALLBACK_IRQ:
        via = hp->value >> CALLBACK_VIA_TYPE_SHIFT;
        if (via == CALLBACK_VIA_TYPE_GSI ||
            via == CALLBACK_VIA_TYPE_PCI_INTX) {
            err = -ENOSYS;
            goto out;
        } else if (via == CALLBACK_VIA_TYPE_VECTOR) {
            vector = hp->value & ((1ULL << CALLBACK_VIA_TYPE_SHIFT) - 1);
            err = xen_add_evtchn_route(cs, vector, via);
        }
        break;
    default:
        err = -ENOSYS;
        goto out;
    }


out:
    exit->u.hcall.result = err;
    return err ? HCALL_ERR : 0;
}

static int kvm_xen_hcall_evtchn_upcall_vector(struct kvm_xen_exit *exit,
                                              X86CPU *cpu, uint64_t arg)
{
    KVMState *kvm = CPU(cpu)->kvm_state;
    XenCPUState *xcpu = &cpu->env.xen_vcpu;
    struct xen_hvm_evtchn_upcall_vector *up;
    int err = 0, vector, vcpu, via;

    up = gva_to_hva(CPU(cpu), arg);
    if (!up) {
        err = -EFAULT;
        goto out;
    }

    via = CALLBACK_VIA_TYPE_EVTCHN;
    vcpu = up->vcpu;
    vector = up->vector;
    if (vector < 0x10) {
        err = -EINVAL;
        goto out;
    }

    err = kvm_irqchip_add_xen_evtchn_route(kvm, via, vcpu, vector);
    if (err < 0) {
        goto out;
    }

    xcpu->cb.via = via;
    xcpu->cb.vector = vector;
    xcpu->cb.virq = err;

out:
    return err;
}

static int handle_get_param(struct kvm_xen_exit *exit, X86CPU *cpu,
                            uint64_t arg)
{
    CPUState *cs = CPU(cpu);
    XenState *xen = cs->xen_state;
    struct xen_hvm_param *hp;
    int err;

    hp = gva_to_hva(cs, arg);
    if (!hp) {
        err = -EFAULT;
        goto out;
    }

    if (hp->domid != DOMID_SELF) {
        err = -EINVAL;
        goto out;
    }

    err = 0;
    switch (hp->index) {
    case HVM_PARAM_STORE_PFN:
        if (X86_CPU(cs)->xen_xenbus) {
            hp->value = xen->xenstore_pfn;
        } else {
            err = -ENOSYS;
        }
        break;
    case HVM_PARAM_STORE_EVTCHN:
        if (X86_CPU(cs)->xen_xenbus) {
            hp->value = xen->xenstore_port;
        } else {
            err = -ENOSYS;
        }
        break;
    default:
        err = -ENOSYS;
        break;
    }
out:
    return err;
}

static int kvm_xen_hcall_hvm_op(struct kvm_xen_exit *exit, X86CPU *cpu,
                                int cmd, uint64_t arg)
{
    int ret = -ENOSYS;
    switch (cmd) {
    case HVMOP_pagetable_dying: {
            exit->u.hcall.result = -ENOSYS;
            return 0;
        }
    case HVMOP_set_param: {
            ret = handle_set_param(exit, cpu, arg);
            break;
        }
    case HVMOP_get_param: {
            ret = handle_get_param(exit, cpu, arg);
            break;
        }
    }

    exit->u.hcall.result = ret;
    return ret ? HCALL_ERR : 0;
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

static void xen_vcpu_timer_event(void *opaque)
{
    CPUState *cpu = opaque;
    XenCPUState *xcpu = &X86_CPU(cpu)->env.xen_vcpu;
    struct XenEvtChn *evtchn = xcpu->virq_to_evtchn[VIRQ_TIMER];

    if (likely(evtchn)) {
        evtchn_2l_set_pending(X86_CPU(cpu), evtchn);
    }
}

static void xen_vcpu_periodic_timer_event(void *opaque)
{
    CPUState *cpu = opaque;
    XenCPUState *xcpu = &X86_CPU(cpu)->env.xen_vcpu;
    struct XenEvtChn *evtchn = xcpu->virq_to_evtchn[VIRQ_TIMER];
    unsigned long now;

    if (likely(evtchn)) {
        evtchn_2l_set_pending(X86_CPU(cpu), evtchn);
    }

    now = kvm_get_current_ns(cpu);
    timer_mod_ns(xcpu->periodic_timer, now + xcpu->period_ns);
}

static int xen_vcpu_timer_init(CPUState *cpu)
{
    XenCPUState *xcpu = &X86_CPU(cpu)->env.xen_vcpu;
    QEMUTimer *timer;

    if (xcpu->oneshot_timer) {
        return 0;
    }

    timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, xen_vcpu_timer_event, cpu);
    if (!timer) {
        return -ENOMEM;
    }

    xcpu->oneshot_timer = timer;
    return 0;
}

static int vcpuop_set_singleshot_timer(CPUState *cs, CPUState *target,
                                       uint64_t arg)
{
    XenCPUState *xt = &X86_CPU(target)->env.xen_vcpu;
    struct vcpu_set_singleshot_timer *sst;
    long now, qemu_now, interval;

    if (xen_vcpu_timer_init(target)) {
        return -EFAULT;
    }

    sst = gva_to_hva(cs, arg);
    if (!sst) {
        return -EFAULT;
    }

    now = kvm_get_current_ns(cs);
    qemu_now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    interval = sst->timeout_abs_ns - now;

    if ((sst->flags & VCPU_SSHOTTMR_future) &&
        sst->timeout_abs_ns < now) {
        return -ETIME;
    }

    timer_mod_ns(xt->oneshot_timer, qemu_now + interval);

    return 0;
}

static void vcpuop_stop_singleshot_timer(CPUState *cs, CPUState *target,
                                         uint64_t arg)
{
    XenCPUState *xt = &X86_CPU(target)->env.xen_vcpu;

    if (likely(xt->oneshot_timer)) {
        timer_del(xt->oneshot_timer);
    }
}

static int vcpuop_set_periodic_timer(CPUState *cs, CPUState *target,
                                     uint64_t arg)
{
    XenCPUState *xt = &X86_CPU(target)->env.xen_vcpu;
    struct vcpu_set_periodic_timer *spt;
    unsigned long now;

    if (!xt->periodic_timer) {
        QEMUTimer *timer;

        timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                             xen_vcpu_periodic_timer_event, target);
        if (!timer) {
            return -EFAULT;
        }
        xt->periodic_timer = timer;
    }

    spt = gva_to_hva(cs, arg);
    if (!spt) {
        return -EFAULT;
    }

    if (spt->period_ns) {
        return -EFAULT;
    }

    timer_del(xt->periodic_timer);
    xt->period_ns = spt->period_ns;

    now = kvm_get_current_ns(cs);
    timer_mod_ns(xt->periodic_timer, now + xt->period_ns);

    return 0;
}

static void vcpuop_stop_periodic_timer(CPUState *cs, CPUState *target,
                                       uint64_t arg)
{
    XenCPUState *xt = &X86_CPU(target)->env.xen_vcpu;

    if (unlikely(xt->periodic_timer))
        timer_del(xt->periodic_timer);
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
    case VCPUOP_set_singleshot_timer: {
            err = vcpuop_set_singleshot_timer(cs, dest, arg);
            break;
        }
    case VCPUOP_stop_singleshot_timer: {
            vcpuop_stop_singleshot_timer(cs, dest, arg);
            err = 0;
            break;
        }
    case VCPUOP_set_periodic_timer: {
            err = vcpuop_set_periodic_timer(cs, dest, arg);
            break;
        }
    case VCPUOP_stop_periodic_timer: {
            vcpuop_stop_periodic_timer(cs, dest, arg);
            err = 0;
            break;
        }
    }

    exit->u.hcall.result = err;
    return err ? HCALL_ERR : 0;
}

static int kvm_xen_hcall_evtchn_op_compat(struct kvm_xen_exit *exit,
                                          X86CPU *cpu, uint64_t arg)
{
    struct evtchn_op *op = gva_to_hva(CPU(cpu), arg);
    int err = -ENOSYS;

    if (!op) {
        goto err;
    }

    switch (op->cmd) {
    default:
        exit->u.hcall.result = err;
        return 0;
    }
err:
    exit->u.hcall.result = err;
    return err ? HCALL_ERR : 0;
}

static int kvm_xen_hcall_evtchn_op(struct kvm_xen_exit *exit, X86CPU *cpu,
                                   int cmd, uint64_t arg)
{
    int err = -ENOSYS;
    void *eop;

    eop = gva_to_hva(CPU(cpu), arg);
    if (!eop) {
        err = -EFAULT;
        goto err;
    }

    switch (cmd) {
    case EVTCHNOP_bind_interdomain:
        err = kvm_xen_evtchn_bind_interdomain(cpu, eop);
        break;
    case EVTCHNOP_bind_ipi:
        err = kvm_xen_evtchn_bind_ipi(cpu, eop);
        break;
    case EVTCHNOP_bind_virq:
        err = kvm_xen_evtchn_bind_virq(cpu, eop);
        break;
    case EVTCHNOP_alloc_unbound:
        err = kvm_xen_evtchn_alloc_unbound(cpu, eop);
        break;
    case EVTCHNOP_bind_vcpu:
        err = kvm_xen_evtchn_bind_vcpu(cpu, eop);
        break;
    case EVTCHNOP_close:
        err = kvm_xen_evtchn_close(cpu, eop);
        break;
    case EVTCHNOP_unmask:
        err = kvm_xen_evtchn_unmask(cpu, eop);
        break;
    case EVTCHNOP_status:
        err = kvm_xen_evtchn_status(cpu, eop);
        break;
    case EVTCHNOP_send:
        err = kvm_xen_evtchn_send(cpu, eop);
        break;
    /* FIFO ABI only */
    case EVTCHNOP_init_control:
    case EVTCHNOP_expand_array:
    case EVTCHNOP_set_priority:
    default:
        err = -ENOSYS;
        break;
    }

err:
    exit->u.hcall.result = err;
    return 0;
}

static int schedop_shutdown(CPUState *cs, uint64_t arg)
{
    struct sched_shutdown *shutdown;

    shutdown = gva_to_hva(cs, arg);
    if (!shutdown) {
        return -EFAULT;
    }

    if (shutdown->reason == SHUTDOWN_crash) {
        cpu_dump_state(cs, stderr, fprintf, CPU_DUMP_CODE);
        qemu_system_guest_panicked(NULL);
    } else if (shutdown->reason == SHUTDOWN_reboot) {
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
    } else if (shutdown->reason == SHUTDOWN_poweroff) {
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
    }

    return 0;
}

static int kvm_xen_hcall_sched_op(struct kvm_xen_exit *exit, X86CPU *cpu,
                                  int cmd, uint64_t arg)
{
    CPUState *cs = CPU(cpu);
    int err = -ENOSYS;

    switch (cmd) {
    case SCHEDOP_shutdown: {
          err = schedop_shutdown(cs, arg);
          break;
       }
    }

    exit->u.hcall.result = err;
    return err ? HCALL_ERR : 0;
}

static int kvm_xen_hcall_set_timer_op(struct kvm_xen_exit *exit, X86CPU *cpu,
                                      uint64_t timeout)
{
    XenCPUState *xcpu = &cpu->env.xen_vcpu;
    long qemu_now, now, offset = 0;
    int err = -ENOSYS;

    if (xen_vcpu_timer_init(CPU(cpu))) {
            goto error;
    }

    qemu_now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    now = kvm_get_current_ns(CPU(cpu));
    offset = timeout - now;

    err = 0;
    if (timeout == 0) {
        timer_del(xcpu->oneshot_timer);
    } else if (unlikely(timeout < now) || ((uint32_t) (offset >> 50) != 0)) {
        offset = (50 * SCALE_MS);
        timer_mod_ns(xcpu->oneshot_timer, qemu_now + offset);
    } else {
        xcpu->oneshot_timer->opaque = CPU(cpu);
        timer_mod_ns(xcpu->oneshot_timer, qemu_now + offset);
    }

error:
    exit->u.hcall.result = err;
    return err ? HCALL_ERR : 0;
}

static int kvm_xen_set_gnttab(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    XenState *xen = cs->xen_state;
    unsigned int max = cpu->xen_gnttab_max_frames;
    XenGrantTable *gnttab = &xen->gnttab;
    struct kvm_xen_hvm_attr xhsi;
    struct kvm_xen_gnttab *xhgt = &xhsi.u.gnttab;
    void *addr, *initial;
    int err;

    if (gnttab->max_nr_frames > 0) {
        return 0;
    }

    addr = g_malloc(sizeof(addr) * max);
    if (!addr) {
        return -ENOMEM;
    }

    initial = qemu_memalign(TARGET_PAGE_SIZE, TARGET_PAGE_SIZE);
    if (!initial) {
        g_free(addr);
        return -ENOMEM;
    }

    xhsi.type = KVM_XEN_ATTR_TYPE_GNTTAB;
    xhgt->flags = KVM_XEN_GNTTAB_F_INIT;
    xhgt->init.max_frames = max;
    xhgt->init.max_maptrack_frames = max;
    xhgt->init.initial_frame = (__u64) initial;

    err = kvm_vm_ioctl(cs->kvm_state, KVM_XEN_HVM_SET_ATTR, &xhsi);
    if (err) {
        g_free(addr);
        qemu_vfree(initial);
        return -EFAULT;
    }

    gnttab->nr_frames = 0;
    gnttab->max_nr_frames = cpu->xen_gnttab_max_frames;
    gnttab->frames = addr;
    gnttab->frames[0] = initial;
    return 0;
}

static int kvm_xen_hcall_gnttab_op(struct kvm_xen_exit *exit, X86CPU *cpu,
                                   int cmd, uint64_t arg, int count)
{
    CPUState *cs = CPU(cpu);
    XenState *xen = cs->xen_state;
    int err = -ENOSYS;

    switch (cmd) {
    case GNTTABOP_set_version: {
        struct gnttab_set_version *gsv;

        gsv = gva_to_hva(cs, arg);
        if (!gsv) {
            err = -EFAULT;
            break;
        }

        if (!gsv->version ||
            gsv->version > cpu->xen_gnttab_max_version) {
            err = -ENOTSUP;
            break;
        }

        err = 0;
        break;
    }
    case GNTTABOP_query_size: {
        struct gnttab_query_size *gqs;

        gqs = gva_to_hva(cs, arg);
        if (!gqs) {
            err = -EFAULT;
            break;
        }

        if (gqs->dom != DOMID_SELF) {
            err = 0;
            gqs->status = GNTST_permission_denied;
            break;
        }

        gqs->nr_frames = xen->gnttab.nr_frames;
        gqs->max_nr_frames = xen->gnttab.max_nr_frames;
        gqs->status = GNTST_okay;
        err = 0;
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
    case __HYPERVISOR_set_timer_op:
        return kvm_xen_hcall_set_timer_op(exit, cpu,
                                          exit->u.hcall.params[0]);
    case HVMOP_set_evtchn_upcall_vector:
        return kvm_xen_hcall_evtchn_upcall_vector(exit, cpu,
                                                  exit->u.hcall.params[0]);
    case __HYPERVISOR_grant_table_op:
        return kvm_xen_hcall_gnttab_op(exit, cpu, exit->u.hcall.params[0],
                                       exit->u.hcall.params[1],
                                       exit->u.hcall.params[2]);
    case __HYPERVISOR_sched_op_compat:
    case __HYPERVISOR_sched_op:
        return kvm_xen_hcall_sched_op(exit, cpu, exit->u.hcall.params[0],
                                      exit->u.hcall.params[1]);
    case __HYPERVISOR_event_channel_op_compat:
        return kvm_xen_hcall_evtchn_op_compat(exit, cpu,
                                              exit->u.hcall.params[0]);
    case __HYPERVISOR_event_channel_op:
        return kvm_xen_hcall_evtchn_op(exit, cpu, exit->u.hcall.params[0],
                                       exit->u.hcall.params[1]);
    case __HYPERVISOR_vcpu_op:
        return kvm_xen_hcall_vcpu_op(exit, cpu,
                                     exit->u.hcall.params[0],
                                     exit->u.hcall.params[1],
                                     exit->u.hcall.params[2]);
    case __HYPERVISOR_hvm_op:
        return kvm_xen_hcall_hvm_op(exit, cpu, exit->u.hcall.params[0],
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

static int kvm_xen_connect_xenstore(CPUState *cs)
{
    XenState *xen = cs->xen_state;
    struct xs_handle *xsh;
    unsigned int len = 0;
    char *str;
    long int res;

    if (!X86_CPU(cs)->xen_xenbus) {
        return -EINVAL;
    }

    xsh = xs_open(XS_OPEN_SOCKETONLY);
    if (!xsh) {
        error_report("Cannot connect to xenstore");
        return -ENOENT;
    }

    str = xs_read(xsh, XBT_NULL, "/tool/xenstored/domid", &len);
    if (str) {
        if (qemu_strtol(str, NULL, 10, &res) < 0) {
            error_report("Failed to parse xenstored domid");
            return -EINVAL;
        }
        free(str);
        if (res < 0) {
            error_report("Invalid xenstored domid");
            return -EINVAL;
        }
        xs_domid = res;
    }

    xen->xenstore = xsh;
    return 0;
}

static void kvm_xen_seed_xenbus(CPUState *cs)
{
    struct xs_permissions frontend_perms[2];
    XenState *xen = cs->xen_state;
    struct xs_handle *xsh = xen->xenstore;
    char *parent = xs_get_domain_path(xsh, xen->domid);
    xs_transaction_t t;
    char *path = NULL;
    char *value = NULL;
    int len;

retry_transaction:
    t = xs_transaction_start(xsh);

    xs_mkdir(xsh, t, parent);

    frontend_perms[0].id = xen->domid;
    frontend_perms[0].perms = XS_PERM_NONE;
    frontend_perms[1].id = xs_domid;
    frontend_perms[1].perms = XS_PERM_READ;
    xs_set_permissions(xsh, t, parent, frontend_perms, 2);

    if (asprintf(&path, "%s/domid", parent) > 0 &&
        (len = asprintf(&value, "%d", xen->domid)) > 0) {
        xs_write(xsh, t, path, value, len);
        free(value);
        value = NULL;
        free(path);
        path = NULL;
    }

    if (asprintf(&path, "%s/store/port", parent) > 0 &&
        (len = asprintf(&value, "%d", xen->xenstore_port)) > 0) {
        xs_write(xsh, t, path, value, len);
        free(value);
        value = NULL;
        free(path);
        path = NULL;
    }
    if (asprintf(&path, "%s/store/ring-ref", parent) &&
        (len = asprintf(&value, "%d", xen->xenstore_pfn)) > 0) {
        xs_write(xsh, t, path, value, len);
        free(value);
        value = NULL;
    }

    if (!xs_transaction_end(xsh, t, 0)) {
        if (errno == EAGAIN) {
            goto retry_transaction;
        }
    }
}

static void kvm_xen_set_xenbus(CPUState *cs)
{
    unsigned long pfn;
    XenState *xen = cs->xen_state;
    XenGrantTable *gnttab = &xen->gnttab;
    struct evtchn_alloc_unbound alloc = {
        .dom = DOMID_SELF, .remote_dom = xs_domid,
    };

    if (kvm_xen_evtchn_alloc_unbound(X86_CPU(cs), &alloc)) {
        error_report("failed to set xenstored port");
        return;
    }

    pfn = xen_special_pfn(SPECIALPAGE_XENSTORE);
    memory_region_init_ram_shared(&xen->mr, NULL, "xenbus",
                                  TARGET_PAGE_SIZE, &error_fatal);
    memory_region_add_subregion(get_system_memory(), pfn << PAGE_SHIFT,
                                &xen->mr);
    memset(memory_region_get_ram_ptr(&xen->mr), 0, TARGET_PAGE_SIZE);

    xen->xenstore_pfn = pfn;
    xen->xenstore_port = alloc.port;

    gnttab->frames_v1[0][GNTTAB_RESERVED_XENSTORE].flags = GTF_permit_access;
    gnttab->frames_v1[0][GNTTAB_RESERVED_XENSTORE].domid = xs_domid;
    gnttab->frames_v1[0][GNTTAB_RESERVED_XENSTORE].frame = xen->xenstore_pfn;
}

static int kvm_xen_introduce_domain(CPUState *cs)
{
    XenState *xen = cs->xen_state;

    if (!xen->xenstore) {
        return -EFAULT;
    }

    if (xs_introduce_domain(xen->xenstore, xen->domid,
                            xen->xenstore_pfn, xen->xenstore_port)) {
        return 0;
    }

    return -EFAULT;
}

int kvm_xen_vcpu_init(CPUState *cs)
{
    if (cs->cpu_index != 0) {
        return 0;
    }

    if (!kvm_check_extension(cs->kvm_state, KVM_CAP_XEN_HVM) ||
        !kvm_check_extension(cs->kvm_state, KVM_CAP_XEN_HVM_GUEST)) {
        return -ENOTSUP;
    }

    kvm_xen_set_hypercall_page(cs);

    if (kvm_xen_set_gnttab(cs) < 0) {
        error_report("vcpu%d: failed to allocate grant table", cs->cpu_index);
        return -EFAULT;
    }

    if (!kvm_xen_connect_xenstore(cs)) {
        kvm_xen_set_xenbus(cs);
        kvm_xen_seed_xenbus(cs);
    } else if (!X86_CPU(cs)->xen_xenbus) {
        return 0;
    } else {
        return -ENOENT;
    }

    if (kvm_xen_introduce_domain(cs) < 0) {
        error_report("vcpu%d: failed to introduce domain", cs->cpu_index);
        return -EFAULT;
    }

    return 0;
}

int kvm_xen_vcpu_inject_upcall(X86CPU *cpu)
{
    XenCPUState *xcpu = &cpu->env.xen_vcpu;
    CPUState *cs = CPU(cpu);

    return kvm_set_irq(cs->kvm_state, xcpu->cb.virq, 0);
}

void hmp_xen_inject_callback(Monitor *mon, const QDict *qdict)
{
    int injected = 0, idx = qdict_get_try_int(qdict, "vcpu", -1);
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        if (idx == -1 || cpu->cpu_index == idx) {
            kvm_xen_vcpu_inject_upcall(X86_CPU(cpu));
            injected++;
        }
    }

    if (!injected) {
        monitor_printf(mon, "failed to inject events to vcpu %d\n", idx);
    }
}
