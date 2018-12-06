/*
 * Event channels implementation on Xen HVM guests in KVM.
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
#include "sysemu/sysemu.h"
#include "sysemu/cpus.h"
#include "cpu.h"
#include "monitor/monitor.h"
#include "qapi/qmp/qdict.h"
#include "qom/cpu.h"
#include "xen_evtchn.h"
#include "xen.h"
#include "trace.h"

#ifndef __XEN_INTERFACE_VERSION__
#define __XEN_INTERFACE_VERSION__ 0x00040400
#endif

#include "standard-headers/xen/xen.h"
#include "standard-headers/xen/event_channel.h"
#include "standard-headers/asm-x86/atomic_bitops.h"

/*
 * 2 Level ABI supports up to:
 *   - 4096 event channels on 64-bit
 *   - 1024 event channels on 32-bit
 */
#define EVTCHN_2L_MAX_ABI      4096
#define EVTCHN_2L_PER_GROUP    (sizeof(xen_ulong_t) * 8)

#ifndef EVTCHN_MAX_ABI
/* Maximum amount of event channels in 2-Level ABI */
#define EVTCHN_MAX_ABI         EVTCHN_2L_MAX_ABI
#define EVTCHN_PER_GROUP       EVTCHN_2L_PER_GROUP
#endif

#define EVTCHN_MAX_GROUPS      (EVTCHN_MAX_ABI / EVTCHN_PER_GROUP)

#define groupid_from_port(p)   (p / EVTCHN_PER_GROUP)
#define group_from_port(p)     (evtchns[groupid_from_port(p)])
#define bucket_from_port(p)    (p % EVTCHN_PER_GROUP)

static struct XenEvtChn *evtchns[EVTCHN_MAX_GROUPS];

static int alloc_group(XenState *xen_state, int port)
{
    struct XenEvtChn *group;
    int i, g, p;

    if ((port / EVTCHN_PER_GROUP) >= EVTCHN_MAX_GROUPS) {
        return -ENOSPC;
    }

    if (group_from_port(port) != NULL) {
        return 0;
    }

    qemu_mutex_lock(&xen_state->port_lock);
    group = g_malloc0(sizeof(XenEvtChn) * EVTCHN_PER_GROUP);
    if (!group) {
        return -ENOMEM;
    }

    g = port / EVTCHN_PER_GROUP;
    p = g * EVTCHN_PER_GROUP;
    for (i = 0; i < EVTCHN_PER_GROUP; i++) {
        group[i].port = p + i;
    }

    evtchns[g] = group;
    qemu_mutex_unlock(&xen_state->port_lock);

    return 0;
}

static XenEvtChn *alloc_evtchn(XenState *xen_state)
{
    struct XenEvtChn *event = NULL;
    int i, j;

    /* Find next free port */
    for (i = 0; i < EVTCHN_MAX_GROUPS; i++) {
        for (j = 0; j < EVTCHN_PER_GROUP; j++) {
            struct XenEvtChn *e;

            /* Port 0 is not valid */
            if (!(i + j) || !evtchns[i]) {
                continue;
            }

            e = &evtchns[i][j];
            if (e->state == XEN_EVTCHN_STATE_FREE) {
                event = e;
                goto out;
            }
        }
    }

    /* Find next group to be created */
    for (i = 0; i < EVTCHN_MAX_GROUPS; i++) {
        if (!evtchns[i]) {
            break;
        }
    }

    /* New group hence first port to be allocated */
    j = i * EVTCHN_PER_GROUP;
    if (!alloc_group(xen_state, j)) {
        event = group_from_port(j);
    }

 out:
    if (event) {
        event->state = XEN_EVTCHN_STATE_INUSE;
    }

    return event;
}

int kvm_xen_evtchn_init(XenState *xen_state)
{
    return alloc_group(xen_state, 1);
}

static struct XenEvtChn *evtchn_from_port(int port)
{
    if (port <= 0 || !group_from_port(port)) {
        return NULL;
    }

    return &group_from_port(port)[bucket_from_port(port)];
}

#define BITS_PER_EVTCHN_WORD (sizeof(xen_ulong_t) * 8)

static void evtchn_2l_vcpu_set_pending(X86CPU *cpu)
{
    struct vcpu_info *vcpu_info = cpu->env.xen_vcpu.info;
    unsigned long *upcall_pending;
    int pending;

    upcall_pending = (unsigned long *) &vcpu_info->evtchn_upcall_pending;
    pending = test_and_set_bit_atomic(0, upcall_pending);
    if (pending) {
        return;
    }

    kvm_xen_vcpu_inject_upcall(cpu);
}

void evtchn_2l_set_pending(X86CPU *cpu, XenEvtChn *evtchn)
{
    struct shared_info *shared_info = CPU(cpu)->xen_state->shared_info;
    struct vcpu_info *vcpu_info = cpu->env.xen_vcpu.info;
    int port = evtchn->port;
    unsigned long *pending;

    pending = (unsigned long *) shared_info->evtchn_pending;
    if (test_and_set_bit_atomic(port, pending)) {
        return;
    }

    if (!test_bit(port, (unsigned long *) shared_info->evtchn_mask) &&
        !test_and_set_bit_atomic(port / BITS_PER_EVTCHN_WORD,
                          (unsigned long *) &vcpu_info->evtchn_pending_sel))
        evtchn_2l_vcpu_set_pending(cpu);
}

static void evtchn_2l_clear_pending(X86CPU *cpu, XenEvtChn *evtchn)
{
    struct shared_info *shared_info = CPU(cpu)->xen_state->shared_info;
    int port = evtchn->port;

    clear_bit_atomic(port, (unsigned long *) shared_info->evtchn_pending);
}

static bool evtchn_2l_is_pending(X86CPU *cpu, XenEvtChn *evtchn)
{
    struct shared_info *shared_info = CPU(cpu)->xen_state->shared_info;
    int port = evtchn->port;

    return !!test_bit(port, (unsigned long *) shared_info->evtchn_pending);
}

static bool evtchn_2l_is_masked(X86CPU *cpu, XenEvtChn *evtchn)
{
    struct shared_info *shared_info = CPU(cpu)->xen_state->shared_info;
    int port = evtchn->port;

    return !!test_bit(port, (unsigned long *) shared_info->evtchn_mask);
}

static int evtchn_2l_state(X86CPU *cpu, XenEvtChn *evtchn)
{
    struct vcpu_info *vcpu_info = cpu->env.xen_vcpu.info;
    int port = evtchn->port;

    return !!test_bit(port / BITS_PER_EVTCHN_WORD,
                      (unsigned long *) &vcpu_info->evtchn_pending_sel);
}

static void evtchn_2l_unmask(X86CPU *cpu, XenEvtChn *evtchn)
{
    struct shared_info *shared_info = CPU(cpu)->xen_state->shared_info;
    struct vcpu_info *vcpu_info = cpu->env.xen_vcpu.info;
    unsigned long *masked = (unsigned long *) shared_info->evtchn_mask;
    int port = evtchn->port;

    if (test_and_clear_bit_atomic(port, masked) &&
        test_bit(port, (unsigned long *) shared_info->evtchn_pending) &&
        !test_and_set_bit_atomic(port / BITS_PER_EVTCHN_WORD,
                          (unsigned long *) &vcpu_info->evtchn_pending_sel))
        evtchn_2l_vcpu_set_pending(cpu);
}

static void xen_vcpu_set_evtchn(CPUState *cpu, run_on_cpu_data data)
{
    XenCPUState *xen_vcpu = &X86_CPU(cpu)->env.xen_vcpu;
    struct XenEvtChn *evtchn = data.host_ptr;

    xen_vcpu->virq_to_evtchn[evtchn->virq] = evtchn;
}

static int __kvm_set_xen_event(KVMState *s, XenEvtChn *e,
                               EventNotifier *n, unsigned int flags)
{
    struct kvm_xen_eventfd xenevfd = {
        .port = e->port,
        .vcpu = e->notify_vcpu_id,
        .type = e->type,
        .fd = n ? event_notifier_get_fd(n) : -1,
        .flags = flags,
    };
    struct kvm_xen_hvm_attr xha;
    int r;

    if (!kvm_check_extension(s, KVM_CAP_XEN_HVM_EVTCHN)) {
        return -ENOSYS;
    }

    if (e->type == XEN_EVTCHN_TYPE_VIRQ) {
        xenevfd.virq.type = e->virq;
    } else if (e->type == XEN_EVTCHN_TYPE_INTERDOM) {
        xenevfd.remote.domid = e->remote_dom;
        xenevfd.remote.port = e->remote_port;
    }

    xha.type = KVM_XEN_ATTR_TYPE_EVTCHN;
    xha.u.evtchn = xenevfd;
    r =  kvm_vm_ioctl(s, KVM_XEN_HVM_SET_ATTR, &xha);
    trace_kvm_xen_evtchn_set(flags, xenevfd.port, xenevfd.type);
    return r;
}

static int kvm_set_xen_event(KVMState *s, XenEvtChn *e, EventNotifier *n)
{
    return __kvm_set_xen_event(s, e, n, 0);
}

static int kvm_clear_xen_event(KVMState *s, XenEvtChn *e)
{
    return __kvm_set_xen_event(s, e, NULL, KVM_XEN_EVENTFD_DEASSIGN);
}

int kvm_xen_evtchn_bind_ipi(X86CPU *cpu, void *arg)
{
    struct evtchn_bind_ipi *out = arg;
    struct evtchn_bind_ipi bind_ipi;
    struct XenEvtChn *evtchn;
    CPUState *dest;

    memcpy(&bind_ipi, arg, sizeof(bind_ipi));

    dest = qemu_get_cpu(bind_ipi.vcpu);
    if (!dest) {
        return -EINVAL;
    }

    evtchn = alloc_evtchn(CPU(cpu)->xen_state);
    if (!evtchn) {
        return -ENOMEM;
    }

    evtchn->type = XEN_EVTCHN_TYPE_IPI;
    evtchn->notify_vcpu_id = bind_ipi.vcpu;

    kvm_set_xen_event(dest->kvm_state, evtchn, NULL);

    out->port = evtchn->port;

    return 0;
}

int kvm_xen_evtchn_bind_interdomain(X86CPU *cpu, void *arg)
{
    struct evtchn_bind_interdomain *out = arg;
    struct evtchn_bind_interdomain bind_dom;
    struct XenEvtChn *evtchn;
    int default_vcpu = 0;
    CPUState *dest;
    int r;

    memcpy(&bind_dom, arg, sizeof(bind_dom));

    dest = qemu_get_cpu(default_vcpu);
    if (!dest) {
        return -EINVAL;
    }

    evtchn = alloc_evtchn(CPU(cpu)->xen_state);
    if (!evtchn) {
        return -ENOMEM;
    }

    if (bind_dom.remote_dom == DOMID_SELF) {
        bind_dom.remote_dom = dest->xen_state->domid;
    }

    evtchn->type = XEN_EVTCHN_TYPE_INTERDOM;
    evtchn->notify_vcpu_id = 0;
    evtchn->remote_dom = bind_dom.remote_dom;
    evtchn->remote_port = bind_dom.remote_port;

    r = kvm_set_xen_event(dest->kvm_state, evtchn, NULL);
    if (r) {
        evtchn->state = XEN_EVTCHN_STATE_FREE;
        return -EINVAL;
    }

    out->local_port = evtchn->port;

    return 0;
}

int kvm_xen_evtchn_bind_virq(X86CPU *cpu, void *arg)
{
    XenCPUState *destxcpu;
    struct evtchn_bind_virq *out = arg;
    struct evtchn_bind_virq bind_virq;
    struct XenEvtChn *evtchn;
    CPUState *dest;

    memcpy(&bind_virq, arg, sizeof(bind_virq));

    dest = qemu_get_cpu(bind_virq.vcpu);
    if (!dest || bind_virq.virq >= NR_VIRQS) {
        return -EINVAL;
    }

    destxcpu = &X86_CPU(dest)->env.xen_vcpu;
    if (destxcpu->virq_to_evtchn[bind_virq.virq]) {
        return -EEXIST;
    }

    evtchn = alloc_evtchn(CPU(cpu)->xen_state);
    if (!evtchn) {
        return -ENOMEM;
    }

    evtchn->type = XEN_EVTCHN_TYPE_VIRQ;
    evtchn->virq = bind_virq.virq;
    evtchn->notify_vcpu_id = bind_virq.vcpu;

    kvm_xen_run_on_cpu(dest, xen_vcpu_set_evtchn, evtchn);

    /* We want to offload timers where possible */
    if (evtchn->virq == VIRQ_TIMER) {
        kvm_set_xen_event(dest->kvm_state, evtchn, NULL);
    }

    out->port = evtchn->port;

    return 0;
}

int kvm_xen_evtchn_close(X86CPU *cpu, void *arg)
{
    struct evtchn_close close;
    struct XenEvtChn *evtchn;

    memcpy(&close, arg, sizeof(close));

    evtchn = evtchn_from_port(close.port);
    if (!evtchn) {
        return -EINVAL;
    }

    evtchn_2l_clear_pending(cpu, evtchn);
    kvm_clear_xen_event(CPU(cpu)->kvm_state, evtchn);

    evtchn->state = XEN_EVTCHN_STATE_FREE;
    evtchn->notify_vcpu_id = 0;

    return 0;
}

int kvm_xen_evtchn_unmask(X86CPU *cpu, void *arg)
{
    struct evtchn_unmask unmask;
    struct XenEvtChn *evtchn;

    memcpy(&unmask, arg, sizeof(unmask));

    evtchn = evtchn_from_port(unmask.port);
    if (!evtchn) {
        return -EINVAL;
    }

    evtchn_2l_unmask(cpu, evtchn);

    return 0;
}

int kvm_xen_evtchn_status(X86CPU *cpu, void *arg)
{
    struct evtchn_status status;
    struct XenEvtChn *evtchn;
    int type = -1;

    memcpy(&status, arg, sizeof(status));

    evtchn = evtchn_from_port(status.port);
    if (!evtchn) {
        return -EINVAL;
    }

    if (evtchn->state == XEN_EVTCHN_STATE_INUSE) {
        type = evtchn->type;
    }

    status.status = EVTCHNSTAT_closed;
    status.vcpu = evtchn->notify_vcpu_id;

    switch (type) {
    case XEN_EVTCHN_TYPE_IPI:
        status.status = EVTCHNSTAT_ipi;
        break;
    case XEN_EVTCHN_TYPE_VIRQ:
        status.status = EVTCHNSTAT_virq;
        status.u.virq = evtchn->virq;
        break;
    default:
        break;
    }

    memcpy(arg, &status, sizeof(status));

    return 0;
}

int kvm_xen_evtchn_send(X86CPU *cpu, void *arg)
{
    struct evtchn_send send;
    struct XenEvtChn *evtchn;
    CPUState *dest;

    memcpy(&send, arg, sizeof(send));

    evtchn = evtchn_from_port(send.port);
    if (!evtchn) {
        return -ENOENT;
    }

    dest = qemu_get_cpu(evtchn->notify_vcpu_id);
    if (!dest) {
        return -EINVAL;
    }

    evtchn_2l_set_pending(X86_CPU(dest), evtchn);

    trace_kvm_xen_evtchn_send(CPU(cpu)->cpu_index, evtchn->notify_vcpu_id,
                              send.port);
    return 0;
}

int kvm_xen_evtchn_vcpu_init(X86CPU *cpu, struct vcpu_info *vcpu)
{
    int i;

    vcpu->evtchn_upcall_pending = 1;
    for (i = 0; i < BITS_PER_EVTCHN_WORD; i++) {
        set_bit(i, &vcpu->evtchn_pending_sel);
    }
    kvm_xen_vcpu_inject_upcall(cpu);

    return 0;
}

void hmp_xen_event_list(Monitor *mon, const QDict *qdict)
{
    struct XenEvtChn *evtchn;
    X86CPU *x86_cpu;
    CPUState *cpu;
    int i, j;

    for (i = 0; i < EVTCHN_MAX_GROUPS; i++) {
        for (j = 0; j < EVTCHN_PER_GROUP; j++) {
            if (!evtchns[i]) {
                continue;
            }

            evtchn = &evtchns[i][j];
            cpu = qemu_get_cpu(evtchn->notify_vcpu_id);
            x86_cpu = X86_CPU(cpu);

            if (!evtchn) {
                continue;
            }
            if (!evtchn->state) {
                continue;
            }

            monitor_printf(mon, "port %4u [%c/%c/%d] vcpu %d type %d ",
                           evtchn->port,
                           evtchn_2l_is_pending(x86_cpu, evtchn) ? 'p' : ' ',
                           evtchn_2l_is_masked(x86_cpu, evtchn) ? 'm' : ' ',
                           evtchn_2l_state(x86_cpu, evtchn),
                           evtchn->notify_vcpu_id, evtchn->type);

            if (evtchn->type == XEN_EVTCHN_TYPE_VIRQ) {
                monitor_printf(mon, "virq %d ", evtchn->virq);
            }

            monitor_printf(mon, "\n");
        }
    }
}

void hmp_xen_event_inject(Monitor *mon, const QDict *qdict)
{
    int port = qdict_get_int(qdict, "port");
    struct XenEvtChn *evtchn;
    CPUState *cpu;

    evtchn = evtchn_from_port(port);
    if (!evtchn) {
        return;
    }

    cpu = qemu_get_cpu(evtchn->notify_vcpu_id);
    evtchn_2l_set_pending(X86_CPU(cpu), evtchn);
    monitor_printf(mon, "evtchn_set_pending(port:%d,qcpu:%d,vcpu:%d)\n",
                   port, cpu->cpu_index, evtchn->notify_vcpu_id);
}

