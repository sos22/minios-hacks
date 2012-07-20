/*
 * hvm.h: Hardware virtual machine assist interface definitions.
 *
 * Leendert van Doorn, leendert@watson.ibm.com
 * Copyright (c) 2005, International Business Machines Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#ifndef __ASM_X86_HVM_HVM_H__
#define __ASM_X86_HVM_HVM_H__

#include <asm/current.h>
#include <asm/x86_emulate.h>
#include <asm/hvm/asid.h>
#include <public/domctl.h>
#include <public/hvm/save.h>

/* Interrupt acknowledgement sources. */
enum hvm_intsrc {
    hvm_intsrc_none,
    hvm_intsrc_pic,
    hvm_intsrc_lapic,
    hvm_intsrc_nmi,
    hvm_intsrc_mce,
    hvm_intsrc_vector
};
struct hvm_intack {
    uint8_t source; /* enum hvm_intsrc */
    uint8_t vector;
};
#define hvm_intack(src, vec)   ((struct hvm_intack) { hvm_intsrc_##src, vec })
#define hvm_intack_none        hvm_intack(none, 0)
#define hvm_intack_pic(vec)    hvm_intack(pic, vec)
#define hvm_intack_lapic(vec)  hvm_intack(lapic, vec)
#define hvm_intack_nmi         hvm_intack(nmi, 2)
#define hvm_intack_mce         hvm_intack(mce, 18)
#define hvm_intack_vector(vec) hvm_intack(vector, vec)
enum hvm_intblk {
    hvm_intblk_none,      /* not blocked (deliverable) */
    hvm_intblk_shadow,    /* MOV-SS or STI shadow */
    hvm_intblk_rflags_ie, /* RFLAGS.IE == 0 */
    hvm_intblk_tpr,       /* LAPIC TPR too high */
    hvm_intblk_nmi_iret   /* NMI blocked until IRET */
};

/* These happen to be the same as the VMX interrupt shadow definitions. */
#define HVM_INTR_SHADOW_STI    0x00000001
#define HVM_INTR_SHADOW_MOV_SS 0x00000002
#define HVM_INTR_SHADOW_SMI    0x00000004
#define HVM_INTR_SHADOW_NMI    0x00000008

/*
 * HAP super page capabilities:
 * bit0: if 2MB super page is allowed?
 * bit1: if 1GB super page is allowed?
 */
#define HVM_HAP_SUPERPAGE_2MB   0x00000001
#define HVM_HAP_SUPERPAGE_1GB   0x00000002

/*
 * The hardware virtual machine (HVM) interface abstracts away from the
 * x86/x86_64 CPU virtualization assist specifics. Currently this interface
 * supports Intel's VT-x and AMD's SVM extensions.
 */
struct hvm_function_table {
    char *name;

    /* Support Hardware-Assisted Paging? */
    int hap_supported;

    /* Indicate HAP capabilities. */
    int hap_capabilities;


    /*
     * Initialise/destroy HVM domain/vcpu resources
     */
    int  (*domain_initialise)(struct domain *d);
    void (*domain_destroy)(struct domain *d);
    int  (*vcpu_initialise)(struct vcpu *v);
    void (*vcpu_destroy)(struct vcpu *v);

    /* save and load hvm guest cpu context for save/restore */
    void (*save_cpu_ctxt)(struct vcpu *v, struct hvm_hw_cpu *ctxt);
    int (*load_cpu_ctxt)(struct vcpu *v, struct hvm_hw_cpu *ctxt);

    /* Examine specifics of the guest state. */
    unsigned int (*get_interrupt_shadow)(struct vcpu *v);
    void (*set_interrupt_shadow)(struct vcpu *v, unsigned int intr_shadow);
    int (*guest_x86_mode)(struct vcpu *v);
    void (*get_segment_register)(struct vcpu *v, enum x86_segment seg,
                                 struct segment_register *reg);
    void (*set_segment_register)(struct vcpu *v, enum x86_segment seg,
                                 struct segment_register *reg);

    /* 
     * Re-set the value of CR3 that Xen runs on when handling VM exits.
     */
    void (*update_host_cr3)(struct vcpu *v);

    /*
     * Called to inform HVM layer that a guest CRn or EFER has changed.
     */
    void (*update_guest_cr)(struct vcpu *v, unsigned int cr);
    void (*update_guest_efer)(struct vcpu *v);

    void (*set_tsc_offset)(struct vcpu *v, u64 offset);

    void (*inject_exception)(unsigned int trapnr, int errcode,
                             unsigned long cr2);

    void (*init_hypercall_page)(struct domain *d, void *hypercall_page);

    int  (*event_pending)(struct vcpu *v);
    int  (*do_pmu_interrupt)(struct cpu_user_regs *regs);

    int  (*cpu_up_prepare)(unsigned int cpu);
    void (*cpu_dead)(unsigned int cpu);

    int  (*cpu_up)(void);
    void (*cpu_down)(void);

    /* Instruction intercepts: non-void return values are X86EMUL codes. */
    void (*cpuid_intercept)(
        unsigned int *eax, unsigned int *ebx,
        unsigned int *ecx, unsigned int *edx);
    void (*wbinvd_intercept)(void);
    void (*fpu_dirty_intercept)(void);
    int (*msr_read_intercept)(unsigned int msr, uint64_t *msr_content);
    int (*msr_write_intercept)(unsigned int msr, uint64_t msr_content);
    void (*invlpg_intercept)(unsigned long vaddr);
    void (*set_uc_mode)(struct vcpu *v);
    void (*set_info_guest)(struct vcpu *v);
    void (*set_rdtsc_exiting)(struct vcpu *v, bool_t);
};

extern struct hvm_function_table hvm_funcs;
extern bool_t hvm_enabled;
extern bool_t cpu_has_lmsl;

int hvm_domain_initialise(struct domain *d);
void hvm_domain_relinquish_resources(struct domain *d);
void hvm_domain_destroy(struct domain *d);

int hvm_vcpu_initialise(struct vcpu *v);
void hvm_vcpu_destroy(struct vcpu *v);
void hvm_vcpu_down(struct vcpu *v);
int hvm_vcpu_cacheattr_init(struct vcpu *v);
void hvm_vcpu_cacheattr_destroy(struct vcpu *v);
void hvm_vcpu_reset_state(struct vcpu *v, uint16_t cs, uint16_t ip);

bool_t hvm_send_assist_req(struct vcpu *v);

void hvm_set_guest_tsc(struct vcpu *v, u64 guest_tsc);
u64 hvm_get_guest_tsc(struct vcpu *v);

void hvm_init_guest_time(struct domain *d);
void hvm_set_guest_time(struct vcpu *v, u64 guest_time);
u64 hvm_get_guest_time(struct vcpu *v);

int hvm_girq_dest_2_vcpu_id(struct domain *d, uint8_t dest, uint8_t dest_mode);

#define hvm_paging_enabled(v) \
    (!!((v)->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PG))
#define hvm_wp_enabled(v) \
    (!!((v)->arch.hvm_vcpu.guest_cr[0] & X86_CR0_WP))
#define hvm_pae_enabled(v) \
    (hvm_paging_enabled(v) && ((v)->arch.hvm_vcpu.guest_cr[4] & X86_CR4_PAE))
#define hvm_smep_enabled(v) \
    (hvm_paging_enabled(v) && ((v)->arch.hvm_vcpu.guest_cr[4] & X86_CR4_SMEP))
#define hvm_nx_enabled(v) \
    (!!((v)->arch.hvm_vcpu.guest_efer & EFER_NX))

#define hvm_hap_has_1gb(d) \
    (hvm_funcs.hap_capabilities & HVM_HAP_SUPERPAGE_1GB)
#define hvm_hap_has_2mb(d) \
    (hvm_funcs.hap_capabilities & HVM_HAP_SUPERPAGE_2MB)

#ifdef __x86_64__
#define hvm_long_mode_enabled(v) \
    ((v)->arch.hvm_vcpu.guest_efer & EFER_LMA)
#else
#define hvm_long_mode_enabled(v) (v,0)
#endif

enum hvm_intblk
hvm_interrupt_blocked(struct vcpu *v, struct hvm_intack intack);

static inline int
hvm_guest_x86_mode(struct vcpu *v)
{
    ASSERT(v == current);
    return hvm_funcs.guest_x86_mode(v);
}

static inline void
hvm_update_host_cr3(struct vcpu *v)
{
    hvm_funcs.update_host_cr3(v);
}

static inline void hvm_update_guest_cr(struct vcpu *v, unsigned int cr)
{
    hvm_funcs.update_guest_cr(v, cr);
}

static inline void hvm_update_guest_efer(struct vcpu *v)
{
    hvm_funcs.update_guest_efer(v);
}

/*
 * Called to ensure than all guest-specific mappings in a tagged TLB are 
 * flushed; does *not* flush Xen's TLB entries, and on processors without a 
 * tagged TLB it will be a noop.
 */
static inline void hvm_flush_guest_tlbs(void)
{
    if ( hvm_enabled )
        hvm_asid_flush_core();
}

void hvm_hypercall_page_initialise(struct domain *d,
                                   void *hypercall_page);

static inline void
hvm_get_segment_register(struct vcpu *v, enum x86_segment seg,
                         struct segment_register *reg)
{
    hvm_funcs.get_segment_register(v, seg, reg);
}

static inline void
hvm_set_segment_register(struct vcpu *v, enum x86_segment seg,
                         struct segment_register *reg)
{
    hvm_funcs.set_segment_register(v, seg, reg);
}

#define is_viridian_domain(_d)                                             \
 (is_hvm_domain(_d) && ((_d)->arch.hvm_domain.params[HVM_PARAM_VIRIDIAN]))

void hvm_cpuid(unsigned int input, unsigned int *eax, unsigned int *ebx,
                                   unsigned int *ecx, unsigned int *edx);
void hvm_migrate_timers(struct vcpu *v);
void hvm_do_resume(struct vcpu *v);
void hvm_migrate_pirqs(struct vcpu *v);

static inline void
hvm_inject_exception(unsigned int trapnr, int errcode, unsigned long cr2)
{
    hvm_funcs.inject_exception(trapnr, errcode, cr2);
}

static inline int hvm_event_pending(struct vcpu *v)
{
    return hvm_funcs.event_pending(v);
}

static inline int hvm_do_pmu_interrupt(struct cpu_user_regs *regs)
{
    return hvm_funcs.do_pmu_interrupt(regs);
}

/* These reserved bits in lower 32 remain 0 after any load of CR0 */
#define HVM_CR0_GUEST_RESERVED_BITS             \
    (~((unsigned long)                          \
       (X86_CR0_PE | X86_CR0_MP | X86_CR0_EM |  \
        X86_CR0_TS | X86_CR0_ET | X86_CR0_NE |  \
        X86_CR0_WP | X86_CR0_AM | X86_CR0_NW |  \
        X86_CR0_CD | X86_CR0_PG)))

/* These bits in CR4 are owned by the host. */
#define HVM_CR4_HOST_MASK (mmu_cr4_features & \
    (X86_CR4_VMXE | X86_CR4_PAE | X86_CR4_MCE))

/* These bits in CR4 cannot be set by the guest. */
#define HVM_CR4_GUEST_RESERVED_BITS(_v)                 \
    (~((unsigned long)                                  \
       (X86_CR4_VME | X86_CR4_PVI | X86_CR4_TSD |       \
        X86_CR4_DE  | X86_CR4_PSE | X86_CR4_PAE |       \
        X86_CR4_MCE | X86_CR4_PGE | X86_CR4_PCE |       \
        X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT |           \
        (cpu_has_smep ? X86_CR4_SMEP : 0) |             \
        (cpu_has_fsgsbase ? X86_CR4_FSGSBASE : 0) |     \
        (xsave_enabled(_v) ? X86_CR4_OSXSAVE : 0))))

/* These exceptions must always be intercepted. */
#define HVM_TRAP_MASK ((1U << TRAP_machine_check) | (1U << TRAP_invalid_op))

/*
 * x86 event types. This enumeration is valid for:
 *  Intel VMX: {VM_ENTRY,VM_EXIT,IDT_VECTORING}_INTR_INFO[10:8]
 *  AMD SVM: eventinj[10:8] and exitintinfo[10:8] (types 0-4 only)
 */
#define X86_EVENTTYPE_EXT_INTR              0    /* external interrupt */
#define X86_EVENTTYPE_NMI                   2    /* NMI                */
#define X86_EVENTTYPE_HW_EXCEPTION          3    /* hardware exception */
#define X86_EVENTTYPE_SW_INTERRUPT          4    /* software interrupt */
#define X86_EVENTTYPE_SW_EXCEPTION          6    /* software exception */

int hvm_event_needs_reinjection(uint8_t type, uint8_t vector);

uint8_t hvm_combine_hw_exceptions(uint8_t vec1, uint8_t vec2);

void hvm_set_rdtsc_exiting(struct domain *d, bool_t enable);

static inline int hvm_cpu_up(void)
{
    return (hvm_funcs.cpu_up ? hvm_funcs.cpu_up() : 0);
}

static inline void hvm_cpu_down(void)
{
    if ( hvm_funcs.cpu_down )
        hvm_funcs.cpu_down();
}

enum hvm_task_switch_reason { TSW_jmp, TSW_iret, TSW_call_or_int };
void hvm_task_switch(
    uint16_t tss_sel, enum hvm_task_switch_reason taskswitch_reason,
    int32_t errcode);

enum hvm_access_type {
    hvm_access_insn_fetch,
    hvm_access_none,
    hvm_access_read,
    hvm_access_write
};
int hvm_virtual_to_linear_addr(
    enum x86_segment seg,
    struct segment_register *reg,
    unsigned long offset,
    unsigned int bytes,
    enum hvm_access_type access_type,
    unsigned int addr_size,
    unsigned long *linear_addr);

void *hvm_map_guest_frame_rw(unsigned long gfn);
void *hvm_map_guest_frame_ro(unsigned long gfn);
void hvm_unmap_guest_frame(void *p);

static inline void hvm_set_info_guest(struct vcpu *v)
{
    if ( hvm_funcs.set_info_guest )
        return hvm_funcs.set_info_guest(v);
}

int hvm_debug_op(struct vcpu *v, int32_t op);

bool_t hvm_hap_nested_page_fault(unsigned long gpa,
                                 bool_t gla_valid, unsigned long gla,
                                 bool_t access_valid, 
                                 bool_t access_r,
                                 bool_t access_w,
                                 bool_t access_x);

#define hvm_msr_tsc_aux(v) ({                                               \
    struct domain *__d = (v)->domain;                                       \
    (__d->arch.tsc_mode == TSC_MODE_PVRDTSCP)                               \
        ? (u32)__d->arch.incarnation : (u32)(v)->arch.hvm_vcpu.msr_tsc_aux; \
})

int hvm_x2apic_msr_read(struct vcpu *v, unsigned int msr, uint64_t *msr_content);
int hvm_x2apic_msr_write(struct vcpu *v, unsigned int msr, uint64_t msr_content);

#ifdef __x86_64__
/* Called for current VCPU on crX changes by guest */
void hvm_memory_event_cr0(unsigned long value, unsigned long old);
void hvm_memory_event_cr3(unsigned long value, unsigned long old);
void hvm_memory_event_cr4(unsigned long value, unsigned long old);

/* Called for current VCPU on int3: returns -1 if no listener */
int hvm_memory_event_int3(unsigned long gla);

/* Called for current VCPU on single step: returns -1 if no listener */
int hvm_memory_event_single_step(unsigned long gla);

#else
static inline void hvm_memory_event_cr0(unsigned long value, unsigned long old)
{ }
static inline void hvm_memory_event_cr3(unsigned long value, unsigned long old)
{ }
static inline void hvm_memory_event_cr4(unsigned long value, unsigned long old)
{ }
static inline int hvm_memory_event_int3(unsigned long gla)
{ return 0; }
static inline int hvm_memory_event_single_step(unsigned long gla)
{ return 0; }
#endif

#endif /* __ASM_X86_HVM_HVM_H__ */
