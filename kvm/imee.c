#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/interrupt.h>

#include <asm/desc.h>
#include <asm/apic.h>
#include "imee.h"
// #include <linux/imee.h>
/* Jiaqi */
#include <linux/file.h>
#include <asm/vmx.h>
#include <linux/fdtable.h>
/* /Jiaqi */

LIST_HEAD (introspection_contexts);

DECLARE_PER_CPU(unsigned long, old_rsp);

intro_ctx_t* current_target;
EXPORT_SYMBOL_GPL (current_target);

int imee_scan_mode = SCAN_ALL;
EXPORT_SYMBOL_GPL (imee_scan_mode);

volatile int exit_flg;
EXPORT_SYMBOL_GPL (exit_flg);

volatile struct kvm_vcpu* imee_vcpu;
EXPORT_SYMBOL_GPL (imee_vcpu);

spinlock_t sync_lock;
EXPORT_SYMBOL_GPL(sync_lock);

spinlock_t flag_r_lock;
EXPORT_SYMBOL_GPL(flag_r_lock);
spinlock_t flag_w_lock;
EXPORT_SYMBOL_GPL(flag_w_lock);

// volatile unsigned char go_flg;
// EXPORT_SYMBOL_GPL(go_flg);

volatile int imee_pid;
EXPORT_SYMBOL_GPL (imee_pid);

volatile unsigned long last_cr3;
EXPORT_SYMBOL_GPL(last_cr3);
volatile unsigned long onsite_cr3;
EXPORT_SYMBOL_GPL(onsite_cr3);

// // volatile u32 last_rip;
// volatile unsigned long last_rip;
// EXPORT_SYMBOL_GPL(last_rip);
// 
// // volatile u32 last_rsp;
// volatile unsigned long last_rsp;
// EXPORT_SYMBOL_GPL(last_rsp);

// volatile u32 switched_cr3;
volatile unsigned long switched_cr3;
EXPORT_SYMBOL_GPL(switched_cr3);

struct desc_ptr imee_idt, imee_gdt;
EXPORT_SYMBOL_GPL(imee_idt);
EXPORT_SYMBOL_GPL(imee_gdt);

struct kvm_segment imee_tr;
EXPORT_SYMBOL_GPL(imee_tr);

// volatile int demand_switch;
// EXPORT_SYMBOL_GPL(demand_switch);

int imee_up;
EXPORT_SYMBOL_GPL(imee_up);

// u32* temp;
// int trial_run;
// EXPORT_SYMBOL_GPL(trial_run);

// int enable_notifier;

// volatile int do_switch;
// EXPORT_SYMBOL_GPL(do_switch);

#define NBASE 4
void* p_bases[NBASE];
void* p_base;
int p_base_idx;
int p_idx;
#define PAGE_ORDER 10

/* Jiaqi, second EPT */
// void* s_p_bases[NBASE];
// void* s_p_base;
// int s_p_base_idx;
// int s_p_idx;
/* /Jiaqi */

// ulong code_hpa, data_hpa;
// EXPORT_SYMBOL_GPL(code_hpa);
// EXPORT_SYMBOL_GPL(data_hpa);
// ulong code_entry;
// EXPORT_SYMBOL_GPL(code_entry);

// ulong fake_cr3_pd_hpa;
// ulong fake_cr3_pt_hpa_exec;
// ulong fake_cr3_pt_hpa_data;

struct arg_blk imee_arg;
EXPORT_SYMBOL_GPL (imee_arg);

// struct shar_arg* ei_shar_arg;
// EXPORT_SYMBOL_GPL (ei_shar_arg);

/* Jiaqi */
struct sig_record sig_array[64];
EXPORT_SYMBOL_GPL (sig_array);

int vmc_idx;//indicator to change EXCEPTION_BITMAP
EXPORT_SYMBOL_GPL(vmc_idx);
unsigned long ana_new_round_rip, ana_new_round_rsp;
EXPORT_SYMBOL_GPL(ana_new_round_rip);
EXPORT_SYMBOL_GPL(ana_new_round_rsp);
/* The following structures are maintained to make the EPT redirection on target
 * pages more efficient */
// struct gva_hpa_pair {
//     unsigned long gva;
//     unsigned long hpa;
// };
struct gva_hpa_pair gva_hpa_pool[max_pf_pool];
EXPORT_SYMBOL_GPL (gva_hpa_pool);
struct gva_hpa_pair int3_gva_hpa_pool[max_int3_pool];
EXPORT_SYMBOL_GPL (int3_gva_hpa_pool);

int crt_pfpool_idx;//the Number of used gva_hpa pairs. 
EXPORT_SYMBOL_GPL(crt_pfpool_idx);

int crt_search_idx;//It is likely an index of 
EXPORT_SYMBOL_GPL(crt_search_idx);
int pre_search_idx;//add this to handle cross page hook
EXPORT_SYMBOL_GPL(pre_search_idx);
int int3_pool_idx;//add this to handle cross page hook
EXPORT_SYMBOL_GPL(int3_pool_idx);

/* / */

unsigned long analyzer_cr3;
EXPORT_SYMBOL_GPL (analyzer_cr3);

unsigned long host_syscall_entry;
EXPORT_SYMBOL_GPL (host_syscall_entry);

unsigned long guest_syscall_entry;
EXPORT_SYMBOL_GPL (guest_syscall_entry);

unsigned long host_pf_entry;
EXPORT_SYMBOL_GPL (host_pf_entry);

int kernel_idx;//defined in walk_gpt_new as 468, adjust if the borrowed kernel entry changes
int user_idx;//defined as 255 currently
EXPORT_SYMBOL_GPL(kernel_idx);

unsigned long UK_OFFSET;
EXPORT_SYMBOL_GPL (UK_OFFSET);

unsigned long eptp_list;
// EXPORT_SYMBOL_GPL (eptp_list);

void* ana_tss_tmp;//since we need 3 continuous physical pages, cannot get through get_ept_page();

struct kvm_segment imee_gs;
/* Jiaqi */
struct region 
{
    u32 start;
    u32 end;
    int type;
};

// 64bit guest, 64bit host
// #define GPA_MASK (0xFFFUL | (1UL << 63))
// 32bit guest, 64bit host
#define GPA_MASK (0xFFFUL)
#define GPAE_MASK 0x3fffff000
// 32bit guest, 32bit host
// #define GPA_MASK (0xFFFU)
// 32bit PAE guest...
// ...
#define NO_CONFLICT_GPA_MASK 0xC00000000UL
// 64bit
#define HPA_MASK (0xFFFUL | (1UL << 63))
// 32bit
// #define HPA_MASK (0xFFFU)
// 32bit PAE
// #define HPA_MASK (0xFFFULL | (1ULL << 63))

// 64bit
#define EPT_MASK (0xFFFUL | (1UL << 63))
// 32bit
// #define EPT_MASK (0xFFFULL | (1ULL << 63))

#define HPAE_MASK 0x7FFFFFF000UL //mask PT entry to become a valid pa
// EXPORT_SYMBOL_GPL (HPAE_MASK);

// static __attribute__((always_inline)) unsigned long long rdtsc(void)
// {
//     unsigned long long x;
//     __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
//     return x;
// }

// unsigned long long t0, t1;
// unsigned long long total_cycle;
// unsigned long long setup_cycle;

// unsigned long long imee_t;
// EXPORT_SYMBOL_GPL(imee_t);

// unsigned long long t[100];
// int cycle_idx = 0;

// unsigned long long* ts_buffer1;
// EXPORT_SYMBOL_GPL(ts_buffer1);
// volatile int ts_buffer_idx1;
// EXPORT_SYMBOL_GPL(ts_buffer_idx1);
// volatile int ts_buffer_idx1_limit;
// EXPORT_SYMBOL_GPL(ts_buffer_idx1_limit);

// unsigned long update_gfn;
// EXPORT_SYMBOL_GPL(update_gfn);
// unsigned long update_spte;
// EXPORT_SYMBOL_GPL(update_spte);
// unsigned long update_level;
// EXPORT_SYMBOL_GPL(update_level);

spinlock_t sync_lock1;
EXPORT_SYMBOL_GPL(sync_lock1);

// int __tmp_counter1;
// int __tmp_counter2;
// int __tmp_counter4;
// int __tmp_counter5;
// 
// int __tmp_counter3;
// EXPORT_SYMBOL_GPL(__tmp_counter3);
// int __tmp_counter;
// EXPORT_SYMBOL_GPL(__tmp_counter);

// /* Jiaqi, syn s_EPT */
// int complete_s_ept (unsigned long gfn, unsigned long hpa_pt)
// {
//     struct kvm_mmu_page* cur;
//     int pml4_ind;
//     int pdpt_ind;
//     int pd_ind;
//     u64 *root, *pdpt, *pd;
// 
//     list_for_each_entry (cur, &current_target->s_non_leaf_page, link)
//     {
//         if (cur->role.level == 4)
//             root = cur->spt;
//     }
//     if (!root)
//     {
//         ERR ("get root of s-ept fail. \n");
//         return -5;
//     }
//     
//     pml4_ind = (gfn >> 27) & 0x1FF;
//     pdpt_ind = (gfn >> 18) & 0x1FF;
//     pd_ind = (gfn >> 9) & 0x1FF;
// 
//     if (root[pml4_ind] == 0)
//     {
//         pdpt = (u64*) alloc_non_leaf_page (&current_target->s_non_leaf_page, 3);
//         root[pml4_ind] = __pa (pdpt) | 0x7;
//         // DBG ("added root[pml4_ind]: %llX\n", root[pml4_ind]);
//     }
//     else
//     {
//         // pdpt = __va (root[pml4_ind] & ~EPT_MASK);
//         pdpt = __va (root[pml4_ind] & ~0xFFF);
//         // DBG ("found pdpt: %llX\n", pdpt);
//     }
// 
//     if (pdpt[pdpt_ind] == 0)
//     {
//         pd = (u64*) alloc_non_leaf_page (&current_target->s_non_leaf_page, 2);
//         pdpt[pdpt_ind] = __pa (pd) | 0x7;
//         // DBG ("added pdpt[pdpt_ind]: %llX\n", pdpt[pdpt_ind]);
//     }
//     else
//     {
//         // pd = __va (pdpt[pdpt_ind] & ~EPT_MASK);
//         pd = __va (pdpt[pdpt_ind] & ~0xFFF);
//         // DBG ("found pd: %llX\n", pd);
//     }
// 
//     if (pd[pd_ind] == 0)
//     {
//         pd[pd_ind] = hpa_pt | 0x7;
//     }
//     return 1;
// }
// 
// //gfn: gfn of the modified entry, not the gfn of the leaf_ept_page
// //new_spte: update the spte as new_spte
// int syn_s_ept (unsigned long gfn, unsigned long new_spte)
// {
//     struct kvm_mmu_page* sp;
//     unsigned long pt_idx = (gfn) & 0x1ff;
//     unsigned long pt_gfn = gfn & ~0x1ff;
//     unsigned long* s_ept_spt;
//     unsigned long spte;
//     hlist_for_each_entry(sp, &imee_vcpu->kvm->arch.mmu_page_hash[gfn &((1 << KVM_MMU_HASH_SHIFT) - 1)], hash_link)
//     {
//         if (sp->gfn == pt_gfn && sp->spt)
//         {
//             s_ept_spt = sp->spt + pt_idx;
//             // spte = *s_ept_spt;
//             *s_ept_spt = new_spte;
//             // printk ("sp gfn: %lx. spt: %p, %lx.\n", sp->gfn, spt, *spt);
//             return 1;
//         }
//     }
//     if (!s_ept_spt)
//     {
//         void* new_leaf_ept;
//         unsigned long hpa_pt;
//         new_leaf_ept = (void*) get_ept_page ();
//         sp = kmalloc (sizeof (struct kvm_mmu_page), GFP_KERNEL);
//         sp->spt = new_leaf_ept;
//         sp->role.level = 1;
//         sp->gfn = pt_gfn;
//         INIT_LIST_HEAD (&sp->link);
//         list_add (&sp->link, &current_target->s_leaf_page);
//         hlist_add_head(&sp->hash_link, &imee_vcpu->kvm->arch.mmu_page_hash[(sp->gfn & ((1 << KVM_MMU_HASH_SHIFT) - 1))]);
//         s_ept_spt = sp->spt + pt_idx;
//         *s_ept_spt = new_spte;
//         hpa_pt = __pa(new_leaf_ept);
//         return complete_s_ept(gfn, hpa_pt);
//     }
// }

// ringBuffer_typedef(struct update_epte, intBuffer);
// EXPORT_SYMBOL_GPL(intBuffer);
// Declare vars.
intBuffer myBuffer;
intBuffer* myBuffer_ptr;
EXPORT_SYMBOL_GPL(myBuffer_ptr);

void bufferDestroy(intBuffer* BUF)
{
    kfree(BUF->elems);
    return;
}

int nextStartIndex(intBuffer* BUF)
{
    return ((BUF->start + 1) % (BUF->size + 1));
}
EXPORT_SYMBOL_GPL(nextStartIndex);

int nextEndIndex(intBuffer* BUF) 
{
    return ((BUF->end + 1) % (BUF->size + 1));
}
EXPORT_SYMBOL_GPL(nextEndIndex);

int isBufferEmpty(intBuffer* BUF)
{
    return (BUF->end == BUF->start);
}
// int isBufferEmpty(intBuffer* BUF)
// {
//     if (BUF->end == BUF->start)
//         return 1;
//     else
//         return 0;
// }
EXPORT_SYMBOL_GPL(isBufferEmpty);

int isBufferFull(intBuffer* BUF)
{
    return (nextEndIndex(BUF) == BUF->start);
}
EXPORT_SYMBOL_GPL(isBufferFull);

void bufferWrite(intBuffer* BUF, struct update_epte ELEM) 
{
    BUF->elems[BUF->end] = ELEM;
    // printk ("in bufferWrite, gfn: %lx, \n", ELEM.gfn);
    BUF->end = (BUF->end + 1) % (BUF->size + 1); 
    if (isBufferEmpty(BUF)) { 
        BUF->start = nextStartIndex(BUF); 
    }
    return;
}
EXPORT_SYMBOL_GPL(bufferWrite);

// struct update_epte bufferRead(intBuffer* BUF, struct update_epte ELEM) 
struct update_epte bufferRead(intBuffer* BUF) 
{
    struct update_epte ELEM;
    ELEM = BUF->elems[BUF->start]; 
    // printk ("in bufferRead, gfn: %lx, spte: %lx, level: %d. \n", ELEM.gfn, ELEM.spte, ELEM.level);
    BUF->start = nextStartIndex(BUF);
    return ELEM;
}
EXPORT_SYMBOL_GPL(bufferRead);

// runs on the IMEE core
void imee_trace_cr3 (void)
{
    // if (update_level == 1)
    // {
    //     spin_lock (&current_target->target_vcpu->kvm->mmu_lock);
    //     spin_lock (&sync_lock1); 
    //     unsigned long gfn = update_gfn;
    //     unsigned long new_spte = update_spte;
    //     int ret = syn_s_ept (gfn, new_spte);
    //     update_gfn = 0;
    //     update_spte = 0;
    //     spin_unlock (&sync_lock1); 
    //     spin_unlock (&current_target->target_vcpu->kvm->mmu_lock);
    //     kvm_mmu_flush_tlb(imee_vcpu);
    //     // return ret;
    // }
    // else
    // {
    //     ERR ("not leaf EPT updated, level: %lx, gfn: %lx, spte: %lx. \n", update_level, update_gfn, update_spte);
    //     // return -5;
    // }
    // // syn_s_ept ();
    apic->write (APIC_EOI, 0);
    // if (imee_up) do_switch = 1;
    // __tmp_counter1 ++;
    return;
}
 
asmlinkage void imee_int_handler (void);
asm ("  .text");
asm ("  .type   imee_int_handler, @function");
asm ("imee_int_handler: \n");
asm ("cli \n");
asm ("pushq %rax \n");
asm ("pushq %rbx \n");
asm ("pushq %rcx \n");
asm ("pushq %rdx \n");
asm ("pushq %rsi \n");
asm ("pushq %rdi \n");
asm ("pushq %rbp \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r10 \n");
asm ("pushq %r11 \n");
asm ("pushq %r12 \n");
asm ("pushq %r13 \n");
asm ("pushq %r14 \n");
asm ("pushq %r15 \n");
asm ("callq imee_trace_cr3 \n");
asm ("popq %r15 \n");
asm ("popq %r14 \n");
asm ("popq %r13 \n");
asm ("popq %r12 \n");
asm ("popq %r11 \n");
asm ("popq %r10 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %rbp \n");
asm ("popq %rdi \n");
asm ("popq %rsi \n");
asm ("popq %rdx \n");
asm ("popq %rcx \n");
asm ("popq %rbx \n");
asm ("popq %rax \n");
asm ("sti \n");
asm ("iretq");

/* Jiaqi */
void imee_write_eoi_64 (void)
{
    unsigned long this_cr3 = 0;

    apic->write (APIC_EOI, 0);
   
    if (vmc_idx == 0)
    {
        kvm_x86_ops->read_cr3_64 ((u64*) (&this_cr3));
        if(!last_cr3)
        {
            kvm_x86_ops->get_seg_sec (current_target->target_vcpu, &imee_tr, VCPU_SREG_TR);
            kvm_x86_ops->get_idt (current_target->target_vcpu, &imee_idt);
            kvm_x86_ops->get_gdt (current_target->target_vcpu, &imee_gdt);
            /* Jiaqi */
            kvm_x86_ops->get_seg_sec (current_target->target_vcpu, &imee_gs, VCPU_SREG_GS);
            /* Jiaqi */
        }
        last_cr3 = this_cr3;
    }
    exit_flg ++;
    smp_wmb ();
    return;
}
/*  /Jiaqi*/


asmlinkage void imee_guest_int (void);
asm ("  .text");
asm ("  .type   imee_guest_int, @function");
asm ("imee_guest_int: \n");
asm ("cli \n");
asm ("pushq %rax \n");
asm ("pushq %rbx \n");
asm ("pushq %rcx \n");
asm ("pushq %rdx \n");
asm ("pushq %rsi \n");
asm ("pushq %rdi \n");
asm ("pushq %rbp \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r10 \n");
asm ("pushq %r11 \n");
asm ("pushq %r12 \n");
asm ("pushq %r13 \n");
asm ("pushq %r14 \n");
asm ("pushq %r15 \n");
/* Jiaqi, 64 bit guest instead */
// asm ("call imee_write_eoi \n");
asm ("call imee_write_eoi_64 \n");
/*  /Jiaqi */
asm ("popq %r15 \n");
asm ("popq %r14 \n");
asm ("popq %r13 \n");
asm ("popq %r12 \n");
asm ("popq %r11 \n");
asm ("popq %r10 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %rbp \n");
asm ("popq %rdi \n");
asm ("popq %rsi \n");
asm ("popq %rdx \n");
asm ("popq %rcx \n");
asm ("popq %rbx \n");
asm ("popq %rax \n");
asm ("sti \n");
asm ("iretq");

struct kvm_vcpu* pick_cpu (struct kvm* target_kvm)
{
    // TODO: randomly pick a cpu?
    return target_kvm->vcpus[0];
}
EXPORT_SYMBOL_GPL(pick_cpu);

// #define T_CODE 1
// #define T_DATA 2
// #define T_NORM 3
#define PAGESIZE 0x1000
#define PTE_P_BIT           0x1
#define PTE_RW_BIT          0x2
/* Jiaqi */
#define PTE_NX_BIT 0x8000000000000000
/* Jiaqi */
#define PDE_PG_BIT          (0x1 << 7)

// static pte_t* get_pte (struct task_struct *tsk, unsigned long addr)
// {
//     pgd_t* pgd;
//     pud_t* pud;
//     pmd_t* pmd;
//     pte_t* pte;
// 
//     struct mm_struct* mm = tsk->mm;
// 
//     pgd = pgd_offset (mm, addr);
//     if (pgd_none (*pgd) || pgd_bad (*pgd)) return 0;
// 
//     pud = pud_offset (pgd,addr);
//     if (pud_none (*pud) || pud_bad (*pud)) return 0;
// 
//     pmd = pmd_offset (pud, addr);
//     if (pmd_none (*pmd) || pmd_bad (*pmd)) return 0;
// 
//     pte = pte_offset_map (pmd, addr);
//     if (pte_none(*pte))
//     {
//         pte_unmap (pte);
//         return 0;
//     }
// 
//     return pte;
// }

// // takes a guest physical address and return a pointer to that page
// ulong get_ptr_guest_page (struct task_struct* target_proc, struct kvm* target_kvm, gpa_t gpa)
// {
//     struct kvm_arch *arch = &target_kvm->arch;
//     struct kvm_mmu_page *page;
// 
//     list_for_each_entry(page, &arch->active_mmu_pages, link)
//     {
//         if (page->gfn == ((gpa >> 12) & ~0x1FFUL) && page->role.level == 1)
//         {
//             u64* p = page->spt;
//             int idx = (gpa >> 12) & 0x1FFUL;
//             ulong r = (ulong) (p[idx] & ~EPT_MASK);
//             DBG ("r: 0x%lx gpa: 0x%lx\n", r, gpa);
//             return r;
//         }
//     }
//     // DBG ("mapping not found for gpa: %lX\n", gpa);
//     return 0;
// }
// EXPORT_SYMBOL_GPL(get_ptr_guest_page);

// TODO: assuming 32bit guest, change it to be more generic
// static struct pt_mapping* get_guest_pte (struct task_struct* target_proc, struct kvm* target_kvm, u32 cr3, gva_t gva)
// {
//     int idx[4] = {
//         (gva >> 22) & 0x3FF,
//         (gva >> 12) & 0x3FF
//     };
//     int page_level = 2;
// 
//     struct pt_mapping* pm = 0; 
// 
//     int lv = 0;
//     u32 next, next_addr;
//     next = cr3;
//     next_addr = cr3 & ~0xFFFU;
// 
//     // DBG ("gva: %lX\n", gva);
// 
//     for ( ; lv < page_level; lv++)
//     {
//         ulong hpa = get_ptr_guest_page (target_proc, target_kvm, next_addr);
//         if (hpa)
//         {
//             ulong pfn = hpa >> 12;
//             struct page* pg = pfn_to_page (pfn);
//             u32* pp = (u32*) kmap_atomic (pg);
//             // DBG ("ptr to guest page: %p\n", p);
//             next = pp[idx[lv]];
//             DBG ("lv: %d next: %lX\n", lv, next);
//             kunmap_atomic (pp);
// 
//             if (!next || !(next & PTE_P_BIT)) 
//                 break;
// 
//             if (next && (next & PDE_PG_BIT) && (next && PTE_P_BIT)) // this is a huge page
//             {
//                 pm = kmalloc (sizeof (struct pt_mapping), GFP_KERNEL);
//                 pm->lv = page_level - lv;
//                 pm->e = next;
//                 return pm;
//             }
//             next_addr = next & ~GPA_MASK;
//             // DBG ("lv: %d, next_addr: %lX\n", lv, next_addr);
//         }
//         else
//         {
//             break;
//         }
//     }
//     
//     if (lv == page_level)
//     {
//         pm = kmalloc (sizeof (struct pt_mapping), GFP_KERNEL);
//         pm->lv = page_level - lv + 1;
//         pm->e = next;
//         return pm;
//     }
//     else
//     {
//         return 0;
//     }
// }

u64* get_epte (intro_ctx_t* ctx, gpa_t gpa)
{
    struct kvm_mmu_page* cur;
    int idx;
    gpa_t needle = (gpa >> 12);
    idx = (gpa >> 12) & 0x1FFUL;
    list_for_each_entry (cur, &ctx->leaf_page, link)
    {
        if (cur->gfn == (needle & ~0x1FFUL))
        {
            // DBG ("Found epte: %lX\n", cur->spt[idx]);
            return &cur->spt[idx];
        }
    }

    // DBG ("epte not found: %lX\n", gpa);
    return 0;
}
EXPORT_SYMBOL_GPL(get_epte);

void* alloc_non_leaf_page (struct list_head* non_leaf_page, int lv);
void* alloc_leaf_page (struct list_head* leaf_page, gpa_t gpa);

u64* map_epte (intro_ctx_t* ctx, gpa_t gpa, ulong new_hpa, ulong perm)
{
    u64* r;
    u64* root;
    int page_level;
    int i;
    
    int idx[4] = {
        (gpa >> 39) & 0x1FF,
        (gpa >> 30) & 0x1FF,
        (gpa >> 21) & 0x1FF,
        (gpa >> 12) & 0x1FF
    };
    u64* table;
    u64 entry;

    r = 0;
    root = __va (ctx->eptptr);
    page_level = 4;
    i = 0;
    table = root;
    
    for ( ; i < page_level; i ++)
    {
        DBG ("lv: %d table: %p\n", i, table);
        entry = table[idx[i]];
        if (!entry)
        {
            u64* tbl;
            if (i < page_level - 2)
            {
                DBG ("allocating new non-leaf page for gpa: 0x%lx\n", (unsigned long)gpa);
                tbl = (u64*) alloc_non_leaf_page (&ctx->non_leaf_page, page_level - i);
            }
            else if (i < page_level - 1) // i == page_level - 2
            {
                DBG ("allocating new leaf page for gpa: 0x%lx\n", (unsigned long)gpa);
                tbl = (u64*) alloc_leaf_page (&ctx->leaf_page, gpa);
            }
            else // i == page_level - 1
            {
                // we are at leaf now
                // set the PTE, at last!
                u64 e;
                e = (new_hpa & ~EPT_MASK) | (perm & 0xFFFU) | 0x270; // 0x270: hard-coded memory type and stuff
                DBG ("new EPTE: %llX\n", e);
                table[idx[i]] = e;
                r = &table[idx[i]];
                break;
            }
            table[idx[i]] = __pa (tbl) | 0x7;
            table = tbl;
        }
        else
        {
            if (i < page_level - 1)
            {
                table = __va (entry & ~EPT_MASK);
            }
            else
            {
                table[idx[i]] = (new_hpa & ~EPT_MASK) | (perm & 0xFFFU);
                r = &table[idx[i]];
                break;
            }
        }
    }

    return r;
}


/* Jiaqi */

// takes a guest physical address and return hpa of that page
// unsigned long get_ptr_guest_page_64 (struct task_struct* target_proc, struct kvm* target_kvm, gpa_t gpa)
// unsigned long get_ptr_guest_page_64 (struct kvm* target_kvm, gpa_t gpa)
unsigned long get_ptr_guest_page_64 (struct kvm* target_kvm, unsigned long gpa)
{
    struct kvm_arch *arch = &target_kvm->arch;
    struct kvm_mmu_page *page;

    // DBG ("gpa in get_ptr_guest_page_64: %lx. %lx. \n", gpa, (gpa >> 12) & ~0x1FF);
    // DBG("size of gpt_t: %d. \n", sizeof(gpa_t));

    list_for_each_entry(page, &arch->active_mmu_pages, link)
    {
        if (page->gfn == ((gpa >> 12) & ~0x1FFUL) && page->role.level == 1)
        {
            u64* p;
            int idx;
            unsigned long r;
            
            p = page->spt;
            idx = (gpa >> 12) & 0x1FFUL;
            r = (ulong) (p[idx] & ~EPT_MASK);
            // DBG ("hpa: 0x%lx ,ept entry: %lx, gpa: 0x%lx\n", r, p[idx], (unsigned long)gpa);
            return r;
        }
    }
    // DBG ("mapping not found for gpa: %lX\n", gpa);
    return 0;
}
EXPORT_SYMBOL_GPL(get_ptr_guest_page_64);

// static unsigned long get_user_esp (void)
// {
//     struct thread_info* thread_info;
//     unsigned long thread_info_addr;
//     unsigned long* stack_ptr;
//     thread_info = task_thread_info (current);
//     thread_info_addr = thread_info;
//     DBG ("thread_info_addr: %lx\n", thread_info_addr);
//     stack_ptr = thread_info_addr + 0x2000;
//     stack_ptr -= 2;
//     unsigned long user_esp;
//     user_esp = *stack_ptr;
//     DBG ("user_esp_addr: %p, user_esp: %lx\n", stack_ptr, *stack_ptr);
//     unsigned long hyp_stack;
//     asm volatile ("movq %%rsp, %0;\n\t"
//             :"=m"(hyp_stack)::);
//     DBG ("hyp_stack: %lx\n", hyp_stack);
//     return user_esp;
// }

static void adjust_imee_vcpu_new (struct kvm_vcpu *vcpu, ulong rip, ulong data)
{
    vcpu->arch.regs[VCPU_REGS_RIP] = rip;
    __set_bit (VCPU_REGS_RIP, (unsigned long*)&vcpu->arch.regs_dirty); // VCPU_REGS_RIP bit
    vcpu->arch.regs[VCPU_REGS_RSP] = data;
    return;
}

//TODO: fix the non-meaningful return value to filter out the GPA overlap 
static int adjust_ept_entry (intro_ctx_t* ctx, unsigned long gpa, ulong eptptr, unsigned long new_pa, int indicator)
{
    
    // ulong eptptr = imee_vcpu->arch.mmu.root_hpa;
    // DBG ("old gpa of PT: %llx\n", gpa);
    // DBG ("update for gpa: %lx\n", gpa);
    u64* pml4_ptr;
    u64 *pdpt_ptr, *pd_ptr, *pt_ptr;
    int pml4_idx, pdpt_idx, pd_idx, pt_idx;
    
    pml4_idx = (gpa >> 39) & 0x1FF;
    pdpt_idx = (gpa >> 30) & 0x1FF;
    pd_idx = (gpa >> 21) & 0x1FF;
    pt_idx = (gpa >> 12) & 0x1FF;
    
    pml4_ptr = __va (eptptr);
    // DBG ("pml4 page pointer: %p\n", pml4_ptr);
    // DBG ("pml entry: %lx\n", pml4_ptr[pml4_idx]);
    /* Just for testing */
    if (gpa == last_cr3)
    {
        printk ("gpa conflict with last cr3!!!!!!!!!!!!\n");
    }
    /* / */

    if (pml4_ptr[pml4_idx] == 0)
    {
        // DBG ("pml4 PTE is not mapped.\n");
        pdpt_ptr = (u64*) alloc_non_leaf_page (&ctx->non_leaf_page, 3);
        // pml4_ptr[pml4_idx] = (__pa (pdpt_ptr) & 0x3FFFFF000UL) | 0x7; 
        pml4_ptr[pml4_idx] = (__pa (pdpt_ptr) & HPAE_MASK) | 0x7; 
    }
    else 
    {
        // pdpt_ptr = __va (pml4_ptr[pml4_idx] & 0x3fffff000UL);
        pdpt_ptr = __va (pml4_ptr[pml4_idx] & HPAE_MASK);
        // DBG ("pdpt page pointer: %p\n", pdpt_ptr);
        // DBG ("pdpt entry: %lx\n", pdpt_ptr[pdpt_idx]);
        pml4_ptr[pml4_idx] |= 0x7;
    }

    if (pdpt_ptr[pdpt_idx] == 0)
    {
        // DBG ("pdpt entry is not mapped.\n");
        pd_ptr = (u64*) alloc_non_leaf_page (&ctx->non_leaf_page, 2);
        // pdpt_ptr[pdpt_idx] = (__pa (pd_ptr) & 0x3FFFFF000UL) | 0x7;
        pdpt_ptr[pdpt_idx] = (__pa (pd_ptr) & HPAE_MASK) | 0x7;

    }
    else
    {
        // pd_ptr = __va(pdpt_ptr[pdpt_idx] & 0x3fffff000UL);
        pd_ptr = __va(pdpt_ptr[pdpt_idx] & HPAE_MASK);
        // DBG ("pd page pointer: %p\n", pd_ptr);
        if (pdpt_ptr[pdpt_idx] & 0x80)
        {
            printk ("large page in pd. \n");
        }
        // DBG ("pd entry: %lx\n", pd_ptr[pd_idx]);
        pdpt_ptr[pdpt_idx] |= 0x7;
    }

    if (pd_ptr[pd_idx] == 0)
    {
        // DBG ("pd entry is not mapped.\n");
        pt_ptr = (u64*) alloc_leaf_page (&ctx->leaf_page, gpa);
        // pd_ptr[pd_idx] = (__pa (pt_ptr) & 0x3FFFFF000UL) | 0x7;
        pd_ptr[pd_idx] = (__pa (pt_ptr) & HPAE_MASK) | 0x7;
    }
    else
    {
        // pt_ptr = __va(pd_ptr[pd_idx] & 0x3FFFFF000UL);
        pt_ptr = __va(pd_ptr[pd_idx] & HPAE_MASK);
        // DBG ("pt page pointer: %p\n", pt_ptr);
        if (pd_ptr[pd_idx] & 0x80)
        {
            printk ("large page in pd. \n");
        }
        // DBG ("pt entry: %lx\n", pt_ptr[pt_idx]);
        pd_ptr[pd_idx] |= 0x7;
    }
    // if (pt_ptr[pt_idx] == 0)
    // if (pt_ptr[pt_idx] != 0)
    if ((pt_ptr[pt_idx] != 0) && (pt_ptr[pt_idx] != 3))
    {
        if ((pt_ptr[pt_idx] & HPAE_MASK) != new_pa)
        {
            // printk ("pt entry is filled >>>>>>>>>>>>>>, gpa: %lx, pt_ptr[pt_idx]: 0x%lx, new_pa: 0x%lx\n", gpa, (unsigned long) pt_ptr[pt_idx], new_pa);
            if (indicator == 1)
            {
                return -1;
            }
        }
    }
    
    // pt_ptr[pt_idx] = (new_pa & 0x3FFFFF000UL) | 0x7;
    // pt_ptr[pt_idx] = (new_pa & 0x3FFFFF000UL) | 0xf77;
    pt_ptr[pt_idx] = (new_pa & HPAE_MASK) | 0xf77;
    // DBG ("updated EPT entry: %lx, for gpa: %lx\n", pt_ptr[pt_idx], gpa);
    // return 0;
    return 1;
}
EXPORT_SYMBOL_GPL(adjust_ept_entry);

static int fix_ept_mapping (intro_ctx_t* ctx, struct kvm_vcpu* vcpu, unsigned long gpa, int index)
{
    unsigned long eptptr;
    unsigned long* pml4_ptr;
    unsigned long* imee_pdpt_ptr;
    unsigned long* imee_pd_ptr;
    unsigned long* imee_pt_ptr;
    unsigned long imee_pdpt_hpa;
    unsigned long imee_pd_hpa;
    unsigned long imee_pt_hpa;
    unsigned long imee_page_hpa;
    
    int i, j, k;

    int ret;
    
    eptptr = vcpu->arch.mmu.root_hpa;
    // DBG ("ept pointer in fix_ept_mapping: %lx\n", eptptr);
    pml4_ptr = (unsigned long*) current->mm->pgd;
    imee_pdpt_hpa = pml4_ptr[index] & HPAE_MASK;
    imee_pdpt_ptr = __va(imee_pdpt_hpa);
    // DBG ("Start to adjust EPT mapping for PT. pml4_ptr in kvm: %p\n", pml4_ptr);
    adjust_ept_entry (ctx, gpa, eptptr, imee_pdpt_hpa, 0);
    DBG ("FINISH update for pdpt page, original gpa from target: %lx, new hpa from imee: %lx\n", gpa, imee_pdpt_hpa);
    
    i = 0;
    for (; i < 512; i ++)
    {
        if (imee_pdpt_ptr[i] != 0)
        {
            if ((imee_pdpt_ptr[i] & 0x80 ))
            {
                printk (KERN_ERR "PDPT entry for 1GB page in host PT: %lx .\n", imee_pdpt_ptr[i]);
            }

            imee_pd_hpa = imee_pdpt_ptr[i] & HPAE_MASK;
            DBG ("i: %d, imee_pd_hpa: %lx\n", i, imee_pdpt_ptr[i]);
            adjust_ept_entry (ctx, imee_pd_hpa, eptptr, imee_pd_hpa, 0);// what if confliction
            imee_pd_ptr = __va(imee_pd_hpa);
            // DBG ("pd_ptr: %p\n", imee_pd_ptr);
            j = 0;
            for (; j < 512; j ++)
            {
                if (imee_pd_ptr[j] != 0)
                {
                    if ((imee_pdpt_ptr[i] & 0x80 ))
                    {
                        printk (KERN_ERR "PD entry for 2MB page in host PT: %lx .\n", imee_pd_ptr[j]);
                    }

                    imee_pt_hpa = imee_pd_ptr[j] & HPAE_MASK;
                    DBG ("j: %d, imee_pt_hpa: %lx\n", j, imee_pd_ptr[j]);
                    adjust_ept_entry (ctx, imee_pt_hpa, eptptr, imee_pt_hpa, 0);
                    imee_pt_ptr = __va(imee_pt_hpa);
                    // DBG ("pt_ptr: %p\n", imee_pt_ptr);
                    k = 0;
                    for (; k < 512; k ++)
                    {
                        if (imee_pt_ptr[k] != 0)
                        {
                            // imee_page_hpa = imee_pt_ptr[k] & 0x3fffff000UL;
                            imee_page_hpa = imee_pt_ptr[k] & HPAE_MASK;
                            // DBG ("k: %d, imee_page_hpa: %lx\n", k, imee_pt_ptr[k]);
                            // ret = adjust_ept_entry (ctx, imee_page_hpa, eptptr, imee_page_hpa, 1);
                            ret = adjust_ept_entry (ctx, imee_page_hpa, eptptr, imee_page_hpa, 0);

                            // /* deal with gpa confliction */
                            // while (ret == -1) 
                            // {
                            //     // unsigned long re_va = __get_free_page(GFP_USER);
                            //     void* re_va = get_ept_page();
                            //     unsigned long re_pa = virt_to_phys(re_va);
                            //     unsigned long attr_bits = imee_pt_ptr[k] & 0x8000000000000fffUL;
                            //     // DBG ("reget a page due to gpa confliction, new gpa: %lx. \n", re_pa);
                            //     imee_pt_ptr[k] = (re_pa & HPAE_MASK) | attr_bits;
                            //     imee_page_hpa = imee_pt_ptr[k];
                            //     DBG ("reget a page due to gpa confliction, new gpa: %lx. entry: %lx. \n", re_pa, imee_page_hpa);
                            //     // ret = adjust_ept_entry (ctx, imee_page_hpa, eptptr, imee_page_hpa, 1);
                            //     ret = adjust_ept_entry (ctx, imee_page_hpa, eptptr, imee_page_hpa, 0);
                            // }
                            /* / */
                        }
                    }
                }
            }
        }
    }
    DBG ("FINISH EPT UPDATE===============\n");
    return 0;
}
/* This function does not take care of large page, so be careful */
unsigned long trans_hva_to_hpa (unsigned long hva)
{
    unsigned long* pml4_ptr;
    unsigned long* pdpt_ptr;
    unsigned long* pd_ptr;
    unsigned long* pt_ptr;

    int pml4_idx;
    int pdpt_idx;
    int pd_idx;
    int pt_idx;

    // unsigned long pdpt_pa;
    // unsigned long pd_pa;
    // unsigned long pt_pa;
    unsigned long pa;

    pml4_idx = (hva >> 39) & 0x1FF; 
    pdpt_idx = (hva >> 30) & 0x1FF; 
    pd_idx = (hva >> 21) & 0x1FF; 
    pt_idx = (hva >> 12) & 0x1FF; 

    pml4_ptr = (unsigned long*) current->mm->pgd;

    // DBG ("this is to get pa of shared memory page. \n");

    if (pml4_ptr[pml4_idx] == 0)
    {
        printk ("pml4 entry is invalid \n");
        return 0;
    }
    else
    {
        pdpt_ptr = __va(pml4_ptr[pml4_idx] & 0x7ffffff000);
        if (pdpt_ptr[pdpt_idx] == 0)
        {
            printk ("pdpt entry is invalid \n");
            return 0;
        }
        else 
        {
            pd_ptr = __va(pdpt_ptr[pdpt_idx] & 0x7ffffff000);
            if (pd_ptr[pd_idx] == 0)
            {
                printk ("pd entry is invalid \n");
                return 0;
            }
            else 
            {
                pt_ptr = __va(pd_ptr[pd_idx] & 0x7ffffff000);
                if (pt_ptr[pt_idx] == 0)
                {
                    printk ("pt entry is invalid \n");
                    return 0;
                }
                else
                {
                    pa = pt_ptr[pt_idx] &0x7ffffff000;
                    // imee_arg_ptr->shar_pa = pa;
                    return pa;
                }
            }
        }
    }

}

/* Jiaqi, the following two functions are for testing whether ept is adjusted
 * correctly */
unsigned long trans_gpa_into_hpa (unsigned long gpa, unsigned long eptptr)
{
    int pml4_idx, pdpt_idx, pd_idx, pt_idx;
    unsigned long *pml4_ptr, *pdpt_ptr, *pd_ptr, *pt_ptr;

    pml4_idx = (gpa >> 39) & 0x1ff;
    pdpt_idx = (gpa >> 30) & 0x1ff;
    pd_idx = (gpa >> 21) & 0x1ff;
    pt_idx = (gpa >> 12) & 0x1ff;
    pml4_ptr = __va (eptptr & HPAE_MASK);
    if (pml4_ptr[pml4_idx] == 0)
    {
        printk ("PML4 ENTRY IS EMPTY.\n");
        return 0;
    }
    else
    {
        // printk ("pml4 entry: %lx. \n", pml4_ptr[pml4_idx]);
        pdpt_ptr = __va(pml4_ptr[pml4_idx] & HPAE_MASK);
    }
    
    if (pdpt_ptr[pdpt_idx] == 0)
    {
        printk ("Pdpt ENTRY IS EMPTY.\n");
        return 0;
    }
    else
    {
        // printk ("pdpt entry: %lx. \n", pdpt_ptr[pdpt_idx]);
        pd_ptr = __va(pdpt_ptr[pdpt_idx] & HPAE_MASK);
    }
    
    if (pd_ptr[pd_idx] == 0)
    {
        printk ("pd ENTRY IS EMPTY.\n");
        return 0;
    }
    else
    {
        // printk ("pd entry: %lx. \n", pd_ptr[pd_idx]);
        pt_ptr = __va(pd_ptr[pd_idx] & HPAE_MASK);
    }
    
    if (pt_ptr[pt_idx] == 0)
    {
        printk ("pt ENTRY IS EMPTY.\n");
        return 0;
    }
    else
    {
        DBG ("pt entry: %lx.  for gpa: %lx. \n", pt_ptr[pt_idx], gpa);
        return pt_ptr[pt_idx];
    }
}
EXPORT_SYMBOL_GPL(trans_gpa_into_hpa);
/* / */

/* upfate the ept entry for a gpa from gust VM */
// int update_ept_entry_for_gpa (struct kvm* target_kvm, unsigned long gpa, unsigned long new_hpa)
// {
//     struct kvm_arch *arch = &target_kvm->arch;
//     struct kvm_mmu_page *page;
// 
//     list_for_each_entry(page, &arch->active_mmu_pages, link)
//     {
//         if (page->gfn == ((gpa >> 12) & ~0x1FFUL) && page->role.level == 1)
//         {
//             u64* p;
//             int idx;
//             unsigned long r;
//             
//             p = page->spt;
//             idx = (gpa >> 12) & 0x1FFUL;
//             // r = (ulong) (p[idx] & ~EPT_MASK);
//             // DBG ("hpa: 0x%lx ,ept entry: %lx, gpa: 0x%lx\n", r, p[idx], (unsigned long)gpa);
//             p[idx] = (new_hpa & HPAE_MASK) | 0xf77;
//             
//             return 1;
//         }
//     }
//     // DBG ("mapping not found for gpa: %lX\n", gpa);
//     return 0;
// }

/* translate gva into hpa */
unsigned long trans_gva_into_hpa (unsigned long gva, unsigned long eptptr, unsigned long g_cr3)
{
    int pml4_idx, pdpt_idx, pd_idx, pt_idx;
    unsigned long *pml4_ptr, *pdpt_ptr, *pd_ptr, *pt_ptr;

    // int page_idx;
    // void* page_ptr;

    unsigned long pfn;
    struct page *pg;
    unsigned long* pp;

    unsigned long gpa;
    unsigned long hpa;

    pml4_idx = (gva >> 39) & 0x1ff;
    pdpt_idx = (gva >> 30) & 0x1ff;
    pd_idx = (gva >> 21) & 0x1ff;
    pt_idx = (gva >> 12) & 0x1ff;

    gpa = g_cr3;
    hpa = trans_gpa_into_hpa (gpa, eptptr);
    if (hpa == 0)
    {
        printk ("in transalting for guest cr3. \n");
        return 0;
    }
    pfn = hpa >> 12;
    pg = pfn_to_page (pfn);
    pp = (unsigned long*) kmap_atomic (pg);
    pml4_ptr = pp;

    gpa = pml4_ptr[pml4_idx];
    if (gpa == 0)
    {
        printk ("GPA in pml4 entry is zero. \n");
        return 0;
    }
    // DBG ("guest pml4 entry: %lx\n", gpa);
    hpa = trans_gpa_into_hpa (gpa, eptptr);
    // DBG ("hpa of pdpt page: %lx\n", hpa);
    if (hpa == 0)
    {
        printk ("in transalting for guest pdpt. \n");
        return 0;
    }
    pfn = hpa >> 12;
    pg = pfn_to_page (pfn);
    pp = (unsigned long*) kmap_atomic (pg);
    pdpt_ptr = pp;
    kunmap_atomic (pml4_ptr);

    gpa = pdpt_ptr[pdpt_idx];
    if (gpa == 0)
    {
        printk ("GPA in pdpt entry is zero. \n");
        return 0;
    }
    DBG ("guest pdpt entry: %lx\n", gpa);
    hpa = trans_gpa_into_hpa (gpa, eptptr);
    if (hpa == 0)
    {
        printk ("in transalting for guest pd. \n");
        return 0;
    }
    pfn = hpa >> 12;
    pg = pfn_to_page (pfn);
    pp = (unsigned long*) kmap_atomic (pg);
    pd_ptr = pp;
    kunmap_atomic (pdpt_ptr);

    gpa = pd_ptr[pd_idx];
    if (gpa == 0)
    {
        printk ("GPA in pd entry is zero. \n");
        return 0;
    }
    DBG ("guest pd entry: %lx\n", gpa);

    if ((gpa>>7) & 1)
    {
        gpa += (pt_idx*0x1000);
        hpa = trans_gpa_into_hpa(gpa, eptptr);
        kunmap_atomic (pd_ptr);
        return hpa;
    }

    hpa = trans_gpa_into_hpa (gpa, eptptr);
    if (hpa == 0)
    {
        printk ("in transalting for guest pt. \n");
        return 0;
    }
    pfn = hpa >> 12;
    pg = pfn_to_page (pfn);
    pp = (unsigned long*) kmap_atomic (pg);
    pt_ptr = pp;
    kunmap_atomic (pd_ptr);
    
    gpa = pt_ptr[pt_idx];
    if (gpa == 0)
    {
        printk ("GPA in pt entry is zero. \n");
        return 0;
    }
    DBG ("guest pt entry: %lx\n", gpa);
    hpa = trans_gpa_into_hpa (gpa, eptptr);
    if (hpa == 0)
    {
        printk ("in transalting for guest page. \n");
        return 0;
    }
    
    kunmap_atomic (pt_ptr);
    return hpa;
    
    // pfn = hpa >> 12;
    // pg = pfn_to_page (pfn);
    // pp = (unsigned long*) kmap_atomic (pg);
    // page_ptr = pp;
    // 
    // unsigned long temp;
    // page_idx = gva & 0xfff;
    // page_ptr += page_idx;
    // temp = *((unsigned long*) page_ptr);

    // kunmap_atomic (page_ptr);

    // return temp;
}
/* Jiaqi */
EXPORT_SYMBOL_GPL(trans_gva_into_hpa);

static int walk_gpt_new (intro_ctx_t* ctx, struct kvm_vcpu* vcpu, struct arg_blk* args)
{
    struct task_struct* target_proc;
    struct kvm* target_kvm;
    unsigned long orig_root_hpa;
    unsigned long new_root_hpa;
    unsigned long pfn;
    struct page* pg;
    unsigned long* pp;//pp points to the original guest root PT 
    unsigned long new_pdpt_gpa;
    unsigned long* sec_pml4;
    int ret;
    
    unsigned long dota_esp;
    unsigned long dota_eip;

    target_proc = ctx->task;
    target_kvm = ctx->kvm;
    orig_root_hpa = get_ptr_guest_page_64 (target_kvm, last_cr3);
    
    if (!orig_root_hpa)
    {
        ERR ("cannot get host physical address of guest pml4 table. \n");
        return -1;
    }
    
    pfn = orig_root_hpa >> 12;
    pg = pfn_to_page (pfn);
    pp = (unsigned long*) kmap_atomic (pg);

    /* Let's check whether it is a valid root PT since 510th entry should always
     * exist */
    if (!(pp[510] & PTE_P_BIT))
    {
        ERR ("The %dth entry is not usable!!!: %lx\n", kernel_idx, pp[510]);
        kunmap_atomic (pp);
        return -1;
    }
    
    /* allocate a new page as guest pml4 page , TODO: we should use a new cr3 for this root PT page */
    sec_pml4 = (void*) imee_arg.root_pt_addr;
    memcpy ((void*)sec_pml4, (void*) pp, 0x1000);
    new_root_hpa = trans_hva_to_hpa(sec_pml4);
    DBG ("onsite root PT page va: %p. pa: %lx. \n", sec_pml4, new_root_hpa);
    
    if (!new_root_hpa)
    {
        ERR ("get pa of new pml4 failed. \n");
        kunmap_atomic (pp);
        return -1;
    }
    
    kernel_idx = 509;
    user_idx = 255;
    if (kernel_idx <= 255)
    {
        UK_OFFSET = ((unsigned long)(kernel_idx - user_idx))*(((unsigned long)1)<<39);
    }
    else
    {
        UK_OFFSET = ((unsigned long)(kernel_idx - user_idx))*(((unsigned long)1)<<39)+0xffff000000000000;
    }
    DBG ("kernel_idx, : %d, user_idx: %d, UK_OFFSET: %lx\n", kernel_idx, user_idx, UK_OFFSET);
    
    // adjust_ept_entry (ctx, last_cr3, ctx->eptptr, new_root_hpa, 0);
    adjust_ept_entry (ctx, onsite_cr3, ctx->eptptr, new_root_hpa, 0);
    /* duplicate 510th entry to kernel_idx entry and |0xc00000007 to
    * guarantee no gpa confliction */
    // sec_pml4[kernel_idx] = sec_pml4[510] | 0xC0000007;
    sec_pml4[kernel_idx] = sec_pml4[510] | NO_CONFLICT_GPA_MASK | 0x7;
    new_pdpt_gpa = sec_pml4[kernel_idx];
    // DBG ("va for entry: %lx. \n", &sec_pml4[kernel_idx]);
    // DBG ("onsite pdpt page, original gpa: %lx, new gpa: %lx. \n", pp[kernel_idx], new_pdpt_gpa);

    /* adjust ept mapping to activate the address space of app in
     * Fuse mode */
    ret = fix_ept_mapping (ctx, vcpu, new_pdpt_gpa, user_idx);
    
    kunmap_atomic (pp);
    
    dota_eip = args->rip + UK_OFFSET;
    dota_esp = args->rsp + UK_OFFSET;

    // /* to test the correctness of EPT mapping */
    // DBG("translate shar_arg into: %lx. \n", trans_gva_into_hpa (0xfffffef020903000, ctx->eptptr, last_cr3));
    // DBG ("trans 0x4025f0 into : %lx. \n", trans_gva_into_hpa(0x4025f0, ctx->eptptr, last_cr3));
    
    adjust_imee_vcpu_new (vcpu, dota_eip, dota_esp);
    DBG ("dota_eip: %lx, dota_esp: %lx\n", dota_eip, dota_esp);
    return ret;
}

/* Jiaqi */
/*
static ulong make_gpa (struct pt_mapping* pm, u32 gva)
{
    switch (pm->lv)
    {
        case 1:
            return pm->e & ~(0xFFFU);
        case 2:
            return (pm->e & (0xFFC00000U)) | (gva & 0x3FF000);
        default:
            ERR ("paging structure level at %d not implemented", pm->lv);
            return 0;
    }

}
*/

static void* do_alloc_ept_frames (void* base)
{
    base = (void*) __get_free_pages (GFP_KERNEL, PAGE_ORDER);
    return base;
}

void init_ept_frames (void)
{
    if (!p_base)
    {
        p_idx = 0;
        p_base_idx = 0;
        p_base = do_alloc_ept_frames (p_bases[p_base_idx]);
    }
}
EXPORT_SYMBOL_GPL(init_ept_frames);

static void release_ept_frames (void)
{
    int i = 0;
    for (; i <= p_base_idx; i ++)
    {
        free_pages ((ulong) p_bases[i], PAGE_ORDER);
        p_bases[i] = 0;
    }

    p_base_idx = 0;
    p_base = 0;
    p_idx = 0;
}

// static ulong* get_ept_page (void)
ulong* get_ept_page (void)
{
    if (p_base)
    {
        p_idx ++;
        if (p_idx < (1 << PAGE_ORDER))
        {
            int i;
            ulong* p;
            p = (ulong*) (((ulong) p_base) + p_idx * PAGE_SIZE);
            for (i = 0; i < PAGE_SIZE / sizeof (ulong); i ++)
            {
                p[i] = 0;
            }
            return p;
        }
        else
        {
            p_base_idx ++;
            if (p_base_idx < NBASE)
            {
                p_base = do_alloc_ept_frames (p_bases[p_base_idx]);
                p_idx = 0;
                return (ulong*) p_base;
            }
            else
            {
                printk (KERN_ERR "EPT frames have been used up, p_base_idx: %d p_idx: %d\n", p_base_idx, p_idx);
                return 0;
            }
        }
    }
    else
    {
        printk (KERN_ERR "EPT frames have not been allocated.");
        return 0;
    }
}
EXPORT_SYMBOL_GPL(get_ept_page);

void* alloc_non_leaf_page (struct list_head* non_leaf_page, int lv)
{
    struct kvm_mmu_page* temp_page;
    void* page;
    
    temp_page = kmalloc (sizeof (struct kvm_mmu_page), GFP_KERNEL);
    INIT_LIST_HEAD(&temp_page->link);
    page = get_ept_page();
    
    temp_page->spt = page;
    temp_page->role.level = lv;
    list_add (&temp_page->link, non_leaf_page);
    return page;
}
EXPORT_SYMBOL_GPL(alloc_non_leaf_page);

void* alloc_leaf_page (struct list_head* leaf_page, gpa_t gpa)
{
    struct kvm_mmu_page* temp_page;
    void* page;
    
    temp_page = kmalloc (sizeof (struct kvm_mmu_page), GFP_KERNEL);
    INIT_LIST_HEAD(&temp_page->link);
    page = get_ept_page();
    
    temp_page->spt = page;
    temp_page->role.level = 1;
    temp_page->gfn = (gpa >> 12) & ~0x1FFUL; 
    list_add (&temp_page->link, leaf_page);
    return page;
}

/* Jiaqi. second EPT */
// static void* do_alloc_s_ept_frames (void* s_base)
// {
//     DBG ("inside do_alloc_s_ept_frame\n");
//     s_base = (void*) __get_free_pages (GFP_KERNEL, PAGE_ORDER);
//     return s_base;
// }
// 
// void init_s_ept_frames (void)
// {
//     if (!s_p_base)
//     {
//         DBG ("s_p_base: %lx\n", s_p_base);
//         s_p_idx = 0;
//         s_p_base_idx = 0;
//         s_p_base = do_alloc_s_ept_frames (s_p_bases[s_p_base_idx]);
//         DBG ("s_p_base: %lx\n", s_p_base);
//     }
// }
// EXPORT_SYMBOL_GPL(init_s_ept_frames);
// 
// static void release_s_ept_frames (void)
// {
//     int i = 0;
//     for (; i <= s_p_base_idx; i ++)
//     {
//         free_pages ((ulong) s_p_bases[i], PAGE_ORDER);
//         s_p_bases[i] = 0;
//     }
// 
//     s_p_base_idx = 0;
//     s_p_base = 0;
//     s_p_idx = 0;
// }
// 
// static ulong* get_s_ept_page (void)
// {
//     int i;
//     if (s_p_base)
//     {
//         s_p_idx ++;
//         if (s_p_idx < (1 << PAGE_ORDER))
//         {
//             ulong* p = (ulong*) (((ulong) s_p_base) + s_p_idx * PAGE_SIZE);
//             for (i = 0; i < PAGE_SIZE / sizeof (ulong); i ++)
//             {
//                 p[i] = 0;
//             }
//             return p;
//         }
//         else
//         {
//             s_p_base_idx ++;
//             if (s_p_base_idx < NBASE)
//             {
//                 s_p_base = do_alloc_s_ept_frames (s_p_bases[s_p_base_idx]);
//                 s_p_idx = 0;
//                 return (ulong*) s_p_base;
//             }
//             else
//             {
//                 printk (KERN_ERR "EPT frames have been used up, s_p_base_idx: %d s_p_idx: %d\n", s_p_base_idx, s_p_idx);
//                 return 0;
//             }
//         }
//     }
//     else
//     {
//         printk (KERN_ERR "EPT frames have not been allocated.");
//         return 0;
//     }
// }

// void* alloc_s_non_leaf_page (struct list_head* s_non_leaf_page, int lv)
// {
//     struct kvm_mmu_page* temp_page;
//     void* page;
//     temp_page = kmalloc (sizeof (struct kvm_mmu_page), GFP_KERNEL);
//     INIT_LIST_HEAD(&temp_page->link);
//     page = get_s_ept_page();
//     temp_page->spt = page;
//     temp_page->role.level = lv;
//     list_add (&temp_page->link, s_non_leaf_page);
//     return page;
// }

// void* alloc_s_leaf_page (struct list_head* s_leaf_page, gpa_t gpa)
// {
//     struct kvm_mmu_page* temp_page = kmalloc (sizeof (struct kvm_mmu_page), GFP_KERNEL);
//     INIT_LIST_HEAD(&temp_page->link);
//     void* page = get_s_ept_page();
//     temp_page->spt = page;
//     temp_page->role.level = 1;
//     temp_page->gfn = (gpa >> 12) & ~0x1FFUL; 
//     list_add (&temp_page->link, s_leaf_page);
//     return page;
// }

u64 make_imee_s_ept (struct list_head* s_leaf_page, struct list_head* s_non_leaf_page)
{
    struct kvm_mmu_page* root_page;
    struct kvm_mmu_page* cur;
    
    u64* root;

    int pml4_ind;
    int pdpt_ind;
    int pd_ind;

    root_page = kmalloc (sizeof (struct kvm_mmu_page), GFP_KERNEL);
    root_page->spt = (u64*) get_ept_page ();
    root_page->role.level = 4;
    INIT_LIST_HEAD (&root_page->link);
    list_add (&root_page->link, s_non_leaf_page);

    root = root_page->spt;
    
    list_for_each_entry (cur, s_leaf_page, link)
    {
        u64 *pdpt, *pd;
        // DBG ("building higher level pages for GFN: %llX\n", cur->gfn);
        pml4_ind = ((cur->gfn) >> 27) & 0x1FF;
        pdpt_ind = ((cur->gfn) >> 18) & 0x1FF;
        pd_ind = ((cur->gfn) >> 9) & 0x1FF;
        // DBG ("pml4_ind: %X\n", pml4_ind);
        // DBG ("pdpt_ind: %X\n", pdpt_ind);
        // DBG ("pd_ind: %X\n", pd_ind);

        if (root[pml4_ind] == 0)
        {
            pdpt = (u64*) alloc_non_leaf_page (s_non_leaf_page, 3);
            root[pml4_ind] = __pa (pdpt) | 0x7;
            // DBG ("added root[pml4_ind]: %llX\n", root[pml4_ind]);
        }
        else
        {
            pdpt = __va (root[pml4_ind] & ~EPT_MASK);
            // DBG ("found pdpt: %llX\n", pdpt);
        }

        if (pdpt[pdpt_ind] == 0)
        {
            pd = (u64*) alloc_non_leaf_page (s_non_leaf_page, 2);
            pdpt[pdpt_ind] = __pa (pd) | 0x7;
            // DBG ("added pdpt[pdpt_ind]: %llX\n", pdpt[pdpt_ind]);
        }
        else
        {
            pd = __va (pdpt[pdpt_ind] & ~EPT_MASK);
            // DBG ("found pd: %llX\n", pd);
        }

        if (pd[pd_ind] == 0)
        {
            pd[pd_ind] = __pa (cur->spt) | 0x7;
        }
    }

    // list_for_each_entry (cur, s_non_leaf_page, link)
    // {
    //     DBG ("new non-leaf page at: %p\n", cur->spt);
    // }

    return (u64) __pa (root);
}
// EXPORT_SYMBOL_GPL(make_imee_s_ept);

// static int adjust_ept_entry_s (intro_ctx_t* ctx, unsigned long gpa, ulong eptptr, unsigned long new_pa)
int adjust_ept_entry_s (intro_ctx_t* ctx, unsigned long gpa, ulong eptptr, unsigned long new_pa)
{
    
    // ulong eptptr = imee_vcpu->arch.mmu.root_hpa;
    // DBG ("old gpa of PT: %llx\n", gpa);
    // DBG ("update for gpa: %lx\n", gpa);
    u64* pml4_ptr;
    u64 *pdpt_ptr, *pd_ptr, *pt_ptr;
    int pml4_idx, pdpt_idx, pd_idx, pt_idx;
    
    pml4_ptr = __va (eptptr);
    pml4_idx = (gpa >> 39) & 0x1FF;
    pdpt_idx = (gpa >> 30) & 0x1FF;
    pd_idx = (gpa >> 21) & 0x1FF;
    pt_idx = (gpa >> 12) & 0x1FF;
    
    // DBG ("pml4 page pointer: %p\n", pml4_ptr);
    // DBG ("pml entry: %lx\n", pml4_ptr[pml4_idx]);
    /* Just for testing */
    // if (gpa == last_cr3)
    if (gpa == onsite_cr3)
    {
        printk ("gpa conflict with onsite cr3!!!!!!!!!!!!\n");
    }
    /* / */

    if (pml4_ptr[pml4_idx] == 0)
    {
        // DBG ("pml4 PTE is not mapped.\n");
        pdpt_ptr = (u64*) alloc_non_leaf_page (&ctx->s_non_leaf_page, 3);
        // pml4_ptr[pml4_idx] = (__pa (pdpt_ptr) & 0x3FFFFF000UL) | 0x7; 
        pml4_ptr[pml4_idx] = (__pa (pdpt_ptr) & HPAE_MASK) | 0x7; 
    }
    else 
    {
        // pdpt_ptr = __va (pml4_ptr[pml4_idx] & 0x3fffff000UL);
        pdpt_ptr = __va (pml4_ptr[pml4_idx] & HPAE_MASK);
        // DBG ("pdpt page pointer: %p\n", pdpt_ptr);
        // DBG ("pdpt entry: %lx\n", pdpt_ptr[pdpt_idx]);
        pml4_ptr[pml4_idx] |= 0x7;
    }

    if (pdpt_ptr[pdpt_idx] == 0)
    {
        // DBG ("pdpt entry is not mapped.\n");
        pd_ptr = (u64*) alloc_non_leaf_page (&ctx->s_non_leaf_page, 2);
        // pdpt_ptr[pdpt_idx] = (__pa (pd_ptr) & 0x3FFFFF000UL) | 0x7;
        pdpt_ptr[pdpt_idx] = (__pa (pd_ptr) & HPAE_MASK) | 0x7;

    }
    else
    {
        // pd_ptr = __va(pdpt_ptr[pdpt_idx] & 0x3fffff000UL);
        pd_ptr = __va(pdpt_ptr[pdpt_idx] & HPAE_MASK);
        // DBG ("pd page pointer: %p\n", pd_ptr);
        if (pdpt_ptr[pdpt_idx] & 0x80)
        {
            printk ("large page in pdpt. \n");
        }
        // DBG ("pd entry: %lx\n", pd_ptr[pd_idx]);
        pdpt_ptr[pdpt_idx] |= 0x7;
    }

    if (pd_ptr[pd_idx] == 0)
    {
        // DBG ("pd entry is not mapped.\n");
        pt_ptr = (u64*) alloc_leaf_page (&ctx->s_leaf_page, gpa);
        // pd_ptr[pd_idx] = (__pa (pt_ptr) & 0x3FFFFF000UL) | 0x7;
        pd_ptr[pd_idx] = (__pa (pt_ptr) & HPAE_MASK) | 0x7;
    }
    else
    {
        // pt_ptr = __va(pd_ptr[pd_idx] & 0x3FFFFF000UL);
        pt_ptr = __va(pd_ptr[pd_idx] & HPAE_MASK);
        // DBG ("pt page pointer: %p\n", pt_ptr);
        if (pd_ptr[pd_idx] & 0x80)
        {
            printk ("large page in pd. \n");
        }
        // DBG ("pt entry: %lx\n", pt_ptr[pt_idx]);
        pd_ptr[pd_idx] |= 0x7;
    }
    // if (pt_ptr[pt_idx] == 0)
    if (pt_ptr[pt_idx] != 0)
    {
        // // if ((pt_ptr[pt_idx] & 0x3fffff000) != new_pa)
        // if ((pt_ptr[pt_idx] & HPAE_MASK) != new_pa)
        // {
            // printk ("in second EPT, pt entry is filled >>>>>>>>>>>>>>, gpa:%lx. pt_ptr[pt_idx]: 0x%lx, new_pa: 0x%lx\n", gpa, (unsigned long) pt_ptr[pt_idx], new_pa);
        // }
    }
    
    // pt_ptr[pt_idx] = (new_pa & 0x3FFFFF000UL) | 0x7;
    // pt_ptr[pt_idx] = (new_pa & 0x3FFFFF000UL) | 0xf77;
    pt_ptr[pt_idx] = (new_pa & HPAE_MASK) | 0xf77;
    // DBG ("updated EPT entry: %lx, for gpa: %lx\n", pt_ptr[pt_idx], gpa);
    return 0;
}
EXPORT_SYMBOL_GPL(adjust_ept_entry_s);

// static int fix_ept_mapping_s (intro_ctx_t* ctx, unsigned long* sec_pml4, unsigned long gpa, int index)
static int fix_ept_mapping_s (intro_ctx_t* ctx)
{
    unsigned long eptptr;
    
    unsigned long *lib_pml4_ptr, *lib_pdpt_ptr, *lib_pd_ptr, *lib_pt_ptr;
    unsigned long lib_pdpt_hpa, lib_pd_hpa, lib_pt_hpa;
    unsigned long pml4e, pdpte, pde, code_pte, data_pte, idt_pte, gdt_pte, tss_pte, tss1_pte;
    int pdpt_idx, pd_idx, pt_idx_code, pt_idx_data;
    int pt_idx_idt, pt_idx_gdt, pt_idx_tss, pt_idx_tss1;

    unsigned long *sec_pml4;
    void *new_pdpt, *new_pd, *new_pt;
    
    unsigned long* tmp_pp;
    unsigned long new_gpa;
   
    unsigned long root_pt_pa;
    
    eptptr = current_target->s_eptptr;
    DBG ("second ept pointer in fix_ept_mapping: %lx\n", eptptr);
    pdpt_idx = (imee_arg.exit_gate_addr >> 30) & 0x1FF;
    pd_idx = (imee_arg.exit_gate_addr >> 21) & 0x1FF;
    pt_idx_code = (imee_arg.exit_gate_addr >> 12) & 0x1FF;
    pt_idx_idt = (imee_arg.t_idt_va >> 12) & 0x1FF;
    pt_idx_gdt = (imee_arg.t_gdt_va >> 12) & 0x1FF;
    pt_idx_tss = (imee_arg.t_tss_va >> 12) & 0x1FF;
    pt_idx_tss1 = ((imee_arg.t_tss_va+0x1000) >> 12) & 0x1FF;
    pt_idx_data = (imee_arg.stack_addr >> 12) & 0x1FF;
   
    sec_pml4 = (unsigned long*) imee_arg.root_pt_addr;
    /* we already checked root_pt_pa and pml4 in the first EPT setup stage */
    root_pt_pa = trans_hva_to_hpa((unsigned long)sec_pml4);
    pml4e = sec_pml4[kernel_idx];
   
    /* get the pa of lib's code and data page, the new gpa of pdpt, pd, pt can
     * be arbitrary one, |0xc00000000 is enough */
    lib_pml4_ptr = (unsigned long*) current->mm->pgd;
    lib_pdpt_hpa = lib_pml4_ptr[user_idx] & HPAE_MASK;
    lib_pdpt_ptr = __va(lib_pdpt_hpa);
    pdpte = lib_pdpt_ptr[pdpt_idx];
    if ((!(pdpte & _PAGE_PRESENT)) || (pdpte & _PAGE_PSE))
    {
        printk ("pdpt entry not present or large: %lx. \n", pdpte);
        return -1;
    }
    
    lib_pd_hpa = pdpte & HPAE_MASK;
    lib_pd_ptr = __va(lib_pd_hpa);
    pde = lib_pd_ptr[pd_idx];
    if ((!(pde & _PAGE_PRESENT)) || (pde & _PAGE_PSE))
    {
        printk ("pd entry not present or large: %lx. \n", pde);
        return -1;
    }

    lib_pt_hpa = pde & HPAE_MASK;
    lib_pt_ptr = __va(lib_pt_hpa);
    code_pte = lib_pt_ptr[pt_idx_code];
    idt_pte = lib_pt_ptr[pt_idx_idt];
    gdt_pte = lib_pt_ptr[pt_idx_gdt];
    tss_pte = lib_pt_ptr[pt_idx_tss];
    tss1_pte = lib_pt_ptr[pt_idx_tss1];
    data_pte = lib_pt_ptr[pt_idx_data];
    DBG ("tss_pte: %lx, tss1_pte: %lx, tss2_pte: %lx. \n", tss_pte, tss1_pte, data_pte);
    
    if ((!(code_pte & _PAGE_PRESENT)) || (!(data_pte & _PAGE_PRESENT)))
    {
        printk ("pte not present, code_pte: %lx, data_pte: %lx. \n", code_pte, data_pte);
        return -1;
    }

    // adjust_ept_entry_s (ctx, last_cr3, eptptr, root_pt_pa);
    adjust_ept_entry_s (ctx, onsite_cr3, eptptr, root_pt_pa);
    // since two EPTs share the same guest PML4, the pml4 entry is already adjusted in the setup stage of first EPT
    new_gpa = pml4e; 
    new_pdpt = get_ept_page();
    adjust_ept_entry_s (ctx, new_gpa, eptptr, __pa(new_pdpt));
    DBG ("FINISH update for pdpt page, new created gpa: %lx, new hpa: %lx\n", new_gpa, __pa(new_pdpt));

    /* modify the pdpt entry on which points to a new onsite pd page */
    tmp_pp = (unsigned long*)new_pdpt;
    new_gpa = pdpte | NO_CONFLICT_GPA_MASK;
    tmp_pp[pdpt_idx] = new_gpa;
    new_pd = (void*) get_ept_page();
    adjust_ept_entry_s (ctx, new_gpa, eptptr, __pa(new_pd));
    DBG ("FINISH update for pd page, new created gpa: %lx, new hpa: %lx\n", new_gpa, __pa(new_pd));
        
    /* modify the pd entry on which points to a new onsite pt page */
    tmp_pp = (unsigned long*)new_pd;
    new_gpa = pde | NO_CONFLICT_GPA_MASK;
    tmp_pp[pd_idx] = new_gpa;
    new_pt = get_ept_page();
    adjust_ept_entry_s (ctx, new_gpa, eptptr, __pa(new_pt));
    DBG ("FINISH update for pt page, new created gpa: %lx, new hpa: %lx\n", new_gpa, __pa(new_pt));

    /* modify the two PT entries on which point to the lib's code and data page */
    tmp_pp = (unsigned long*)new_pt;
    new_gpa = code_pte | NO_CONFLICT_GPA_MASK;
    tmp_pp[pt_idx_code] = new_gpa;
    adjust_ept_entry_s (ctx, new_gpa, eptptr, code_pte);
    DBG ("FINISH update for code pt entry, new created gpa: %lx, original gpa: %lx\n", new_gpa, code_pte);
    
    new_gpa = data_pte | NO_CONFLICT_GPA_MASK;
    tmp_pp[pt_idx_data] = new_gpa;
    adjust_ept_entry_s (ctx, new_gpa, eptptr, data_pte);
    DBG ("FINISH update for data pt entry, new created gpa: %lx, original gpa: %lx\n", new_gpa, data_pte);
    new_gpa = idt_pte | NO_CONFLICT_GPA_MASK;
    tmp_pp[pt_idx_idt] = new_gpa;
    adjust_ept_entry_s (ctx, new_gpa, eptptr, idt_pte);
    DBG ("FINISH update for idt pt entry, new created gpa: %lx, original gpa: %lx\n", new_gpa, idt_pte);
    new_gpa = gdt_pte | NO_CONFLICT_GPA_MASK;
    tmp_pp[pt_idx_gdt] = new_gpa;
    adjust_ept_entry_s (ctx, new_gpa, eptptr, gdt_pte);
    DBG ("FINISH update for gdt pt entry, new created gpa: %lx, original gpa: %lx\n", new_gpa, gdt_pte);
    new_gpa = tss_pte | NO_CONFLICT_GPA_MASK;
    tmp_pp[pt_idx_tss] = new_gpa;
    adjust_ept_entry_s (ctx, new_gpa, eptptr, tss_pte);
    DBG ("FINISH update for tss pt entry, new created gpa: %lx, original gpa: %lx\n", new_gpa, tss_pte);
    new_gpa = tss1_pte | NO_CONFLICT_GPA_MASK;
    tmp_pp[pt_idx_tss1] = new_gpa;
    adjust_ept_entry_s (ctx, new_gpa, eptptr, tss1_pte);
    DBG ("FINISH update for tss1 pt entry, new created gpa: %lx, original gpa: %lx\n", new_gpa, tss1_pte);
    return 0;
}
// /* setup mappings on EPT2 for page tables and des_table and debug_handler and so on */
// int complete_s_ept(intro_ctx_t* ctx)
// {
//     unsigned long hpa;
//     int r;
//     
//     void* sec_pml4;
//    
//     sec_pml4 = imee_arg.des_addr;
//     hpa = trans_hva_to_hpa(sec_pml4);
//     if (hpa)
//     {
//         DBG ("last cr3 in here: %lx. \n", last_cr3);
//         adjust_ept_entry_s (ctx, last_cr3, ctx->s_eptptr, hpa);
// 
//         /* adjust ept mapping to activate the address space of app in
//          * Fuse mode */
//         r = fix_ept_mapping_s (ctx, sec_pml4);
//         return r;
//     } 
//     
//     // kunmap_atomic (pp);
// 
//     return -1;
// }

void copy_s_leaf_ept (struct list_head* s_leaf_page, struct kvm_arch* arch)
{
    struct kvm_mmu_page *page;

    void* newpage;
    struct kvm_mmu_page* new_ept_page;
    u64 *pte;

    int i = 0;
    // int j = 0;

    list_for_each_entry (page, &arch->active_mmu_pages, link)
    {
        // DBG ("level: %d gfn: %lx. \n", page->role.level, page->gfn);
        if (page->role.level == 1)
        {
            // j ++;
            newpage = (void*) get_ept_page ();
            new_ept_page = kmalloc (sizeof (struct kvm_mmu_page), GFP_KERNEL);

            new_ept_page->spt = newpage;
            new_ept_page->role.level = 1;
            new_ept_page->gfn = page->gfn;
            INIT_LIST_HEAD (&new_ept_page->link);
            list_add (&new_ept_page->link, s_leaf_page);
            /* Jiaqi */
            /* TODO, fix onsite's active_mmu_pages? */
            new_ept_page->spt = newpage;
            // list_add(&new_ept_page->link, &arch->active_mmu_pages);
            // hlist_add_head(&new_ept_page->hash_link, &vcpu->kvm->arch.mmu_page_hash[kvm_page_table_hashfn(new_ept_page->gfn)]);
            // struct hlist_head* temp_hlist_head = &imee_vcpu->kvm->arch.mmu_page_hash[(new_ept_page->gfn & ((1 << KVM_MMU_HASH_SHIFT) - 1))];
            // INIT_HLIST_HEAD (temp_hlist_head);
            hlist_add_head(&new_ept_page->hash_link, &imee_vcpu->kvm->arch.mmu_page_hash[(new_ept_page->gfn & ((1 << KVM_MMU_HASH_SHIFT) - 1))]);
            // DBG ("hlist head for copy: %p. gfn: %lx.idx: %lx. \n", &imee_vcpu->kvm->arch.mmu_page_hash[(new_ept_page->gfn & ((1 << KVM_MMU_HASH_SHIFT) - 1))], new_ept_page->gfn, (new_ept_page->gfn & ((1 << KVM_MMU_HASH_SHIFT) - 1)));
            // hlist_add_head(&new_ept_page->hash_link, temp_hlist_head);
            /* / */
            pte = (u64*) newpage;
            i = 0;
            for (; i < 512; i ++)
            {
                // pte[i] = page->spt[i] & ~0x4;//bit 0: read; bit 1: write; bit 2: execute
                // /* to make all page r+w+x in ept */
                // pte[i] = page->spt[i] | 0x7;
                // /* to make all page r+w in ept */
                // pte[i] = page->spt[i] | 0x3;
                /* to make all page w in ept */
                pte[i] = page->spt[i] | 0x2;
            }
        }
        /* Jiaqi. to report large page in EPT */
        else if (page->role.level == 2 || page->role.level == 3)
        {
            i = 0;
            for (; i < 512; i ++)
            {
                // if (page->spt[i] & 0x80)
                if (page->spt[i] & _PAGE_PSE)
                    ERR ("large page detected while setup second EPT, page level: %x, epte: 0x%lx\n", page->role.level, (unsigned long) page->spt[i]);
            }
        }
    }
    // DBG ("number of leaf pages: %d\n", j);
}
// EXPORT_SYMBOL_GPL(copy_s_leaf_ept);
/* /Jiaqi */

u64 make_imee_ept (struct list_head* leaf_page, struct list_head* non_leaf_page)
{
    u64* root;
    struct kvm_mmu_page* root_page;
    struct kvm_mmu_page* cur;
    
    root_page = kmalloc (sizeof (struct kvm_mmu_page), GFP_KERNEL);
    root_page->spt = (u64*) get_ept_page ();
    root_page->role.level = 4;
    INIT_LIST_HEAD (&root_page->link);
    list_add (&root_page->link, non_leaf_page);

    root = root_page->spt;
    list_for_each_entry (cur, leaf_page, link)
    {
        u64 *pdpt, *pd;
        // DBG ("building higher level pages for GFN: %llX\n", cur->gfn);
        int pml4_ind, pdpt_ind, pd_ind;
        
        pml4_ind = ((cur->gfn) >> 27) & 0x1FF;
        pdpt_ind = ((cur->gfn) >> 18) & 0x1FF;
        pd_ind = ((cur->gfn) >> 9) & 0x1FF;
        // DBG ("pml4_ind: %X\n", pml4_ind);
        // DBG ("pdpt_ind: %X\n", pdpt_ind);
        // DBG ("pd_ind: %X\n", pd_ind);

        if (root[pml4_ind] == 0)
        {
            pdpt = (u64*) alloc_non_leaf_page (non_leaf_page, 3);
            root[pml4_ind] = __pa (pdpt) | 0x7;
            // DBG ("added root[pml4_ind]: %llX\n", root[pml4_ind]);
        }
        else
        {
            pdpt = __va (root[pml4_ind] & ~EPT_MASK);
            // DBG ("found pdpt: %llX\n", pdpt);
        }

        if (pdpt[pdpt_ind] == 0)
        {
            pd = (u64*) alloc_non_leaf_page (non_leaf_page, 2);
            pdpt[pdpt_ind] = __pa (pd) | 0x7;
            // DBG ("added pdpt[pdpt_ind]: %llX\n", pdpt[pdpt_ind]);
        }
        else
        {
            pd = __va (pdpt[pdpt_ind] & ~EPT_MASK);
            // DBG ("found pd: %llX\n", pd);
        }

        if (pd[pd_ind] == 0)
        {
            pd[pd_ind] = __pa (cur->spt) | 0x7;
        }
    }

    list_for_each_entry (cur, non_leaf_page, link)
    {
        DBG ("new non-leaf page at: %p\n", cur->spt);
    }

    return (u64) __pa (root);
}
// EXPORT_SYMBOL_GPL(make_imee_ept);

static void cr0_wp_off (void)
{
    u64 cr0;
    asm ("movq %%cr0, %0;":"=r"(cr0)::);
    // printk ("%llX\n", cr0);
    cr0 &= ~0x10000;
    // printk ("%llX\n", cr0);
    asm ("movq %0, %%cr0;"::"r"(cr0):);

}

static void cr0_wp_on (void)
{
    u64 cr0;
    asm ("movq %%cr0, %0;":"=r"(cr0)::);
    // printk ("%llX\n", cr0);
    cr0 |= 0x10000;
    // printk ("%llX\n", cr0);
    asm ("movq %0, %%cr0;"::"r"(cr0):);

}

static void install_int_handlers (void)
{
    unsigned char idtr[10];
    u64* idt;
    gate_desc s;
    
    // unsigned long high_offset, mid_offset, low_offset;

    asm ("sidt %0":"=m"(idtr)::);

    idt = (u64*)(*(u64*)(idtr + 2));
    DBG ("idt: %p\n", idt);

    cr0_wp_off ();
    pack_gate(&s, GATE_INTERRUPT, (unsigned long) imee_int_handler, 0, 0, __KERNEL_CS);

    idt[0x55 * 2] = * ((u64*) (&s));
    idt[0x55 * 2 + 1] = 0x00000000FFFFFFFFULL;

    pack_gate(&s, GATE_INTERRUPT, (unsigned long) imee_guest_int, 0, 0, __KERNEL_CS);

    idt[0x56 * 2] = * ((u64*) (&s));
    idt[0x56 * 2 + 1] = 0x00000000FFFFFFFFULL;

    cr0_wp_on ();

    // /* Jiaqi, to get the host_pf_entry */
    // high_offset = idt[29] & 0xffffffff;
    // mid_offset = idt[28] & 0xffff000000000000;
    // low_offset = idt[28] & 0xffff;
    // host_pf_entry = (high_offset << 32) | (mid_offset >> 32) | low_offset;
    // DBG ("host_pf_entry: %lx. \n", host_pf_entry);
    // /* / */

    DBG ("imee_int_handler: %p\n", imee_int_handler);
}

// remove_int_handlers by Jiaqi
static void remove_int_handlers (void)
{
    unsigned char idtr[10];
    u64* idt;
    // gate_desc s;
    asm ("sidt %0":"=m"(idtr)::);
    idt = (u64*)(*(u64*)(idtr + 2));
    // DBG ("idt: %p\n", idt);
    cr0_wp_off ();
    idt[0x55 * 2] = 0x0;
    idt[0x55 * 2 + 1] = 0x0;
    idt[0x56 * 2] = 0x0;
    idt[0x56 * 2 + 1] = 0x0;
    cr0_wp_on ();
    DBG ("remove int handlers done\n");
}

int get_next_ctx (intro_ctx_t** next)
{
    intro_ctx_t* cur = 0;

    list_for_each_entry (cur, &introspection_contexts, node)
    {
        if (cur->visited == 0)
        {
            cur->visited ++;
            *next = cur;

            current_target = cur;

            DBG ("picked VM: target_vm_pid: %d process: %s\n", 
                    cur->task->pid, cur->task->comm);

            return 0;
        }
    }

    return -1;
}
EXPORT_SYMBOL_GPL(get_next_ctx);

static void free_ept (struct list_head* leaf_page, struct list_head* non_leaf_page)
{
    struct kvm_mmu_page *cur, *n;

    list_for_each_entry_safe (cur, n, leaf_page, link)
    {
        // DBG ("releasing leaf page: %llX lv: %d\n", cur->gfn, cur->role.level);
        // if (cur->gfn == ((last_cr3 >> 12) & ~0x1FF))
        // {
        //     int i;
        //     for (i = 0; i < 512; i++)
        //     {
        //         // u64* p = cur->spt;
        //         // if (p[i])
        //         //     DBG ("\t i:%d -> %llX\n", i, p[i]);
        //     }
        // }

        list_del (&cur->link);
        // free_page (cur->spt);
        kfree (cur);
    }

    list_for_each_entry_safe (cur, n, non_leaf_page, link)
    {
        // DBG ("releasing non-leaf page: %llX lv: %d\n", cur->gfn, cur->role.level);
        int i;
        for (i = 0; i < 512; i++)
        {
            // u64* p = cur->spt;
            // if (p[i])
            //     DBG ("\t i:%d -> %llX\n", i, p[i]);
        }

        list_del (&cur->link);
        // free_page (cur->spt);
        kfree (cur);
    }
    
}

void copy_leaf_ept (struct list_head* leaf_page, struct kvm_arch* arch)
{
    struct kvm_mmu_page *page;
    int i;

    list_for_each_entry(page, &arch->active_mmu_pages, link)
    {
        // DBG ("level: %d gfn: %lX\n", page->role.level, page->gfn);
        // copy all leaf page
        if (page->role.level == 1)
        {
            void *newpage;
            struct kvm_mmu_page* new_pt_page;
            u64 *pte;
            
            newpage = (void*) get_ept_page ();
            
            new_pt_page = kmalloc (sizeof (struct kvm_mmu_page), GFP_KERNEL);
            new_pt_page->spt = newpage;
            new_pt_page->role.level = 1;
            new_pt_page->gfn = page->gfn;
            INIT_LIST_HEAD (&new_pt_page->link);
            list_add (&new_pt_page->link, leaf_page);
            
            pte = (u64*) newpage;
           
            i = 0;
            for (; i < 512; i ++)
            {
                pte[i] = page->spt[i] & ~0x4;//not eXecutable
                pte[i] |= 0x3;//r+w
                // pte[i] = page->spt[i] | 0x3;
            }
        }
        /* Jiaqi. to report large page in EPT */
        else if (page->role.level == 2 || page->role.level == 3)
        {
            i = 0;
            for (; i < 512; i ++)
            {
                if (page->spt[i] & 0x80)
                    ERR ("larget ept page detected while copying first EPT. page level: %x, epte: 0x%lx\n", page->role.level, (unsigned long) page->spt[i]);
            }
        }
    }
}
// EXPORT_SYMBOL_GPL(copy_leaf_ept);

void setup_imee_vcpu_sregs (struct kvm_vcpu* guest_vcpu, struct kvm_vcpu* vcpu)
{
    struct kvm_sregs *imee_sregs;
    // unsigned long fs_base, fs_h, fs_l;
    
    imee_sregs = kmalloc (sizeof (struct kvm_sregs), GFP_KERNEL);
    kvm_arch_vcpu_ioctl_get_sregs (guest_vcpu, imee_sregs);
    // kvm_arch_vcpu_ioctl_set_sregs (vcpu, imee_sregs);
    
    // DBG ("guest_vcpu: %p imee_vcpu: %p\n", guest_vcpu, vcpu);

    // init CS register
    imee_sregs->cs.selector = 0x10;
    imee_sregs->cs.base = 0x0;
    imee_sregs->cs.limit = 0xFFFFF;
    imee_sregs->cs.type = 0xB;
    imee_sregs->cs.s = 1;
    imee_sregs->cs.dpl = 0;
    imee_sregs->cs.present = 1;
    imee_sregs->cs.avl = 0;
    imee_sregs->cs.l = 1;
    imee_sregs->cs.db = 0;
    imee_sregs->cs.g = 1;

    // DS register
    imee_sregs->ds.selector = 0x18;
    imee_sregs->ds.base = 0x0;
    imee_sregs->ds.limit = 0xFFFFF;
    imee_sregs->ds.type = 0x3;
    imee_sregs->ds.s = 1;
    imee_sregs->ds.dpl = 3;
    imee_sregs->ds.present = 1;
    imee_sregs->ds.avl = 0;
    imee_sregs->ds.l = 0;
    imee_sregs->ds.db = 1;
    imee_sregs->ds.g = 1;

    // SS register
    imee_sregs->ss.selector = 0x18;
    imee_sregs->ss.base = 0x0;
    imee_sregs->ss.limit = 0xFFFFF;
    imee_sregs->ss.type = 0x3;
    imee_sregs->ss.s = 1;
    imee_sregs->ss.dpl = 0;
    imee_sregs->ss.present = 1;
    imee_sregs->ss.avl = 0;
    imee_sregs->ss.l = 0;
    imee_sregs->ss.db = 1;
    imee_sregs->ss.g = 1;

    // GS register
    imee_sregs->gs.selector = 0x18;
    // imee_sregs->gs.base = 0x0;
    imee_sregs->gs.base = imee_gs.base;
    imee_sregs->gs.limit = 0xFFFFF;
    imee_sregs->gs.type = 0x3;
    imee_sregs->gs.s = 1;
    imee_sregs->gs.dpl = 0;
    imee_sregs->gs.present = 1;
    imee_sregs->gs.avl = 0;
    imee_sregs->gs.l = 0;
    imee_sregs->gs.db = 1;
    imee_sregs->gs.g = 1;

    // FS register
    // asm volatile("movl $0xc0000100, %%ecx; \n\t"
    //         "rdmsr; \n\t"
    //         "movl %%edx, %0; \n\t"
    //         "movl %%eax, %1; \n\t"
    //         :"=m"(fs_h), "=m"(fs_l)::"%eax", "%ecx", "%edx");
    // fs_base = (fs_h << 32) | (fs_l & 0xffffffff);
    // DBG ("fs_base: %lx, fs_h: %lx, fs_l: %lx\n", fs_base, fs_h, fs_l);
    // imee_sregs->fs.selector = 0x68;
    imee_sregs->fs.selector = 0x0;
    imee_sregs->fs.base = 0x0;
    // imee_sregs->fs.base = 0x7ffff7ffc700;
    // imee_sregs->fs.base = fs_base;
    imee_sregs->fs.limit = 0xFFFFF;
    imee_sregs->fs.type = 0x3;
    imee_sregs->fs.s = 1;
    imee_sregs->fs.dpl = 0;
    imee_sregs->fs.present = 1;
    imee_sregs->fs.avl = 0;
    imee_sregs->fs.l = 0;
    imee_sregs->fs.db = 1;
    imee_sregs->fs.g = 1;

    // DBG ("CS selector: %X base: %llX limit: %X\n", imee_sregs->cs.selector, imee_sregs->cs.base, imee_sregs->cs.limit);
    // DBG ("DS selector: %X base: %llX limit: %X\n", imee_sregs->ds.selector, imee_sregs->ds.base, imee_sregs->ds.limit);
    // DBG ("SS selector: %X base: %llX limit: %X\n", imee_sregs->ss.selector, imee_sregs->ss.base, imee_sregs->ss.limit);
    // DBG ("ES selector: %X base: %llX limit: %X\n", imee_sregs->es.selector, imee_sregs->es.base, imee_sregs->es.limit);
    // DBG ("FS selector: %X base: %llX limit: %X\n", imee_sregs->fs.selector, imee_sregs->fs.base, imee_sregs->fs.limit);
    // DBG ("GS selector: %X base: %llX limit: %X\n", imee_sregs->gs.selector, imee_sregs->gs.base, imee_sregs->gs.limit);
    // DBG ("IDT base: %llX limit: %X\n", imee_sregs->idt.base, imee_sregs->idt.limit);
    // DBG ("GDT base: %llX limit: %X\n", imee_sregs->gdt.base, imee_sregs->gdt.limit);
    // DBG ("TR  base: %llX limit: %X sel: %X\n", imee_sregs->tr.base, imee_sregs->tr.limit, imee_sregs->tr.selector);
    // DBG ("CR0:%llX CR2: %llX, CR3: %llX, CR4: %llX\n", imee_sregs->cr0, imee_sregs->cr2, imee_sregs->cr3, imee_sregs->cr4);
    // DBG ("CR8:%llX EFER: %X\n", imee_sregs->cr8, imee_sregs->efer);

    kvm_x86_ops->set_segment (vcpu, &imee_sregs->cs, VCPU_SREG_CS);
    kvm_x86_ops->set_segment (vcpu, &imee_sregs->ds, VCPU_SREG_DS);
    kvm_x86_ops->set_segment (vcpu, &imee_sregs->ss, VCPU_SREG_SS);
    kvm_x86_ops->set_segment (vcpu, &imee_sregs->ds, VCPU_SREG_ES);
    kvm_x86_ops->set_segment (vcpu, &imee_sregs->fs, VCPU_SREG_FS);
    kvm_x86_ops->set_segment (vcpu, &imee_sregs->gs, VCPU_SREG_GS);
    kvm_x86_ops->set_segment (vcpu, &imee_sregs->ldt, VCPU_SREG_LDTR);

    // kvm_x86_ops->set_rflags (vcpu, 0x2 | 0x100);
    kvm_x86_ops->set_rflags (vcpu, 0x2);

    // imee_sregs->cr3 = last_cr3; 
    // DBG ("last_cr3: 0x%lx, overwrite imee cr3 as: 0x%lx\n", last_cr3, (unsigned long)imee_sregs->cr3);
    // vcpu->arch.cr3 = last_cr3;
    vcpu->arch.cr3 = onsite_cr3;
	
    // vcpu->arch.cr2 = imee_sregs->cr2;
	kvm_x86_ops->set_cr0(vcpu, (imee_sregs->cr0 | 0x2 ) & ~(0x4 | 0x8)); // set MP, clear TS and EM
	// kvm_x86_ops->set_cr0(vcpu, (imee_sregs->cr0 | 0x2 ) & ~(0x4)); // set MP, clear TS and EM
	// kvm_x86_ops->set_cr0(vcpu, (imee_sregs->cr0 | 0x2 ) & ~(0x4)); // set MP, clear EM
    /* Jiaqi */
	// kvm_x86_ops->set_cr4(vcpu, imee_sregs->cr4 | 0x80 | 0x600 | 0x20); // set PGE bit, and OSFXSR, OSXMMEXCPT bits for SSE, set PAE bit
	// kvm_x86_ops->set_cr4(vcpu, (imee_sregs->cr4 | 0x80 | 0x600 | 0x20) & 0xffefffff); // set PGE bit, and OSFXSR, OSXMMEXCPT bits for SSE, set PAE bit
	kvm_x86_ops->set_cr4(vcpu, (imee_sregs->cr4 | 0x80 | 0x600 | 0x20 | 0x10000) & 0xffefffff); // set PGE bit, and OSFXSR, OSXMMEXCPT bits for SSE, set PAE bit, set enable the instructions RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE
	// kvm_x86_ops->set_cr4(vcpu, (imee_sregs->cr4 | 0x80 | 0x600 | 0x20 | 0x10000) & 0xffefdfff); // set PGE bit, and OSFXSR, OSXMMEXCPT bits for SSE, set PAE bit, set enable the instructions RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE, clear VMXE bit
    /* Jiaqi, set_cr3 is provided by kvm, it would overwrite eptp based on this
     * cr3*/
    // kvm_x86_ops->write_cr3_64(imee_sregs->cr3);//this line is added by Jiaqi to set up cr3 for the fused address space
    kvm_x86_ops->write_cr3_64(onsite_cr3);//this line is added by Jiaqi to set up cr3 for the fused address space
    /* Jiaqi */	
	// kvm_x86_ops->set_efer(vcpu, imee_sregs->efer);
    // kvm_x86_ops->set_efer(vcpu, imee_sregs->efer | 0xd00); // set LME bit and NXE bit
    kvm_x86_ops->set_efer(vcpu, 0xd01);
    /* Jiaqi */
    // kvm_x86_ops->write_eptp (vcpu);
    /* Jiaqi */
    
    kfree (imee_sregs);
   
}

static void init_global_vars (struct kvm_vcpu* vcpu)
{
    // __tmp_counter = 0;
    // __tmp_counter1 = 0;
    // __tmp_counter2 = 0;
    // __tmp_counter3 = 0;
    // __tmp_counter5 = 0;

    // total_cycle = 0;
    // cycle_idx = 0;
    // imee_t = 0;

    // // ts_buffer1 = (unsigned long long*) __get_free_pages (GFP_KERNEL, PAGE_ORDER);
    // ts_buffer_idx1 = 0;
    // ts_buffer_idx1_limit = (1 << PAGE_ORDER) * 0x1000 / sizeof (unsigned long long);

    imee_pid = current->pid;
    imee_vcpu = vcpu;
    exit_flg = 0;
    imee_up = 0;
}

intro_ctx_t* kvm_to_ctx (struct kvm* target)
{

    intro_ctx_t* cur;
    list_for_each_entry (cur, &introspection_contexts, node)
    {
        if (cur->kvm == target)
            return cur;
    }

    return NULL;
}
EXPORT_SYMBOL_GPL(kvm_to_ctx);

static void create_introspection_context (struct kvm* target, struct kvm_vcpu *vcpu)
{
    intro_ctx_t* ctx;
    struct kvm_arch *arch;
    
    /* return if this VM is myself */
    if (target->mm->owner == current)
    {
        return;
    }

    if (kvm_to_ctx (target))
    {
        // already created
        return;
    }

    ctx = (intro_ctx_t*) kmalloc (sizeof (intro_ctx_t), GFP_KERNEL);
    ctx->task = target->mm->owner;
    DBG ("pid: %d, process: %s, cpu: %d\n", 
            ctx->task->pid, ctx->task->comm, task_cpu (ctx->task));
    ctx->visited = 0;

    list_add (&ctx->node, &introspection_contexts);
    INIT_LIST_HEAD(&ctx->leaf_page);
    INIT_LIST_HEAD(&ctx->non_leaf_page);

    ctx->kvm = target;
    ctx->target_vcpu = pick_cpu ((struct kvm*) target);
    /* just for testing */
    // DBG ("target vcpu_id: %d\n", ctx->target_vcpu->vcpu_id);
    // DBG ("hpa for targt vm: 0x%lx\n", (unsigned long) ctx->target_vcpu->arch.mmu.root_hpa);
    /* / */
    
    /* copy leaf EPTs */
    arch = (struct kvm_arch*) &target->arch;

    spin_lock (&ctx->target_vcpu->kvm->mmu_lock);
    copy_leaf_ept (&ctx->leaf_page, arch);
    
    ctx->eptptr = make_imee_ept (&ctx->leaf_page, &ctx->non_leaf_page);
    
    if (imee_arg.instrum_flag == 1)
    {
        int i = 0;
        struct kvm_mmu_page* cur;
        // init_s_ept_frames ();
        INIT_LIST_HEAD(&ctx->s_leaf_page);
        INIT_LIST_HEAD(&ctx->s_non_leaf_page);
        // /* init hlist head for mmu_page_hash */
        for (i = 0; i < (1 << KVM_MMU_HASH_SHIFT) ; i ++)
        {
            INIT_HLIST_HEAD (&imee_vcpu->kvm->arch.mmu_page_hash[i]);
            // DBG ("hlist head: %p. \n", &imee_vcpu->kvm->arch.mmu_page_hash[i]);
        }
        // /* / */
        // INIT_HLIST_HEAD(&ctx->s_mmu_page_hash);
        copy_s_leaf_ept (&ctx->s_leaf_page, arch);
        ctx->s_eptptr = make_imee_s_ept (&ctx->s_leaf_page, &ctx->s_non_leaf_page);
        // DBG ("after copy second leaf ept pages. \n");
        /* debugging */ 
        list_for_each_entry (cur, &ctx->s_non_leaf_page, link)
        {
            DBG ("new non-leaf page at: %p, level: %x.\n", cur->spt, cur->role.level);
        }
        list_for_each_entry (cur, &ctx->s_leaf_page, link)
        {
            // DBG ("new leaf page at: %p\n", cur->spt);
        }
        // // /* checking */
        // unsigned long gfn = 0x3d800;
        // // hlist_for_each_entry (cur, &imee_vcpu->kvm->arch.mmu_page_hash[gfn & ((1 << KVM_MMU_HASH_SHIFT) - 1)], hash_link)
        // // {
        // //     // if (cur->gfn == gfn)
        // //     // {
        // //         printk ("sp gfn: %lx. spt:%p. \n", cur->gfn, cur->spt);
        // //     // }
        // // }
        // cur = hlist_entry_safe(imee_vcpu->kvm->arch.mmu_page_hash[gfn & ((1 << KVM_MMU_HASH_SHIFT) - 1)].first, typeof(*cur), hash_link);
        // if (cur)
        // {
        //     DBG ("cur gfn: %lx.:%p. \n", cur->gfn, cur->spt);
        // }
    }
    imee_up = 1;
    /* init ring buffer for update_epte */
    // bufferInit(myBuffer, 2000, struct update_epte);
    bufferInit(myBuffer, 3000, struct update_epte);

    // We must have the pointer. All of the macros deal with the pointer. (except
    // for init.
    myBuffer_ptr = &myBuffer;
    DBG ("is buffer empty: %d. is buffer full: %d. \n", isBufferEmpty(myBuffer_ptr), isBufferFull(myBuffer_ptr));
    // DBG ("start: %d. end: %d. \n", nextStartIndex(myBuffer_ptr), nextEndIndex(myBuffer_ptr));
    /* / */
    
    spin_unlock (&ctx->target_vcpu->kvm->mmu_lock);
}

static void free_contexts (void)
{
    intro_ctx_t* cur, *bck;
    list_for_each_entry_safe (cur, bck, &introspection_contexts, node)
    {
        free_ept (&cur->leaf_page, &cur->non_leaf_page);
        list_del (&cur->node);
        kfree (cur);
    }
}

int init_imee_vcpu (intro_ctx_t* next, struct kvm_vcpu* vcpu)
{
    /* Jiaqi set up vmcs field */
    u32 vm_entry_control, vm_exit_control;
    // vm_entry_control = kvm_x86_ops->read_vm_entry_controls();
    // DBG ("Read vm entry controls: %lx\n", vm_entry_control);
    vm_entry_control = 0xd3ff;
    kvm_x86_ops->write_vm_entry_controls (vm_entry_control); 
    // vm_entry_control = kvm_x86_ops->read_vm_entry_controls();
    // DBG ("updated vm entry controls as: %lx\n", vm_entry_control);
    vm_exit_control = kvm_x86_ops->read_vm_exit_controls();
    // DBG ("Read vm exit control: %lx\n", vm_exit_control);
    vm_exit_control |= (u32)(0x100000);
    kvm_x86_ops->write_vm_exit_controls (vm_exit_control); 
    vm_exit_control = kvm_x86_ops->read_vm_exit_controls();
    /* / */

    DBG ("current->pid: %d parent->pid: %d imee_pid: %d\n", current->pid, current->parent->pid, imee_pid);

    /* setup rest of vCPU */
    setup_imee_vcpu_sregs (next->target_vcpu, vcpu);
    
    return 0;
}

void reset_general_regs (struct kvm_vcpu* vcpu)
{
    vcpu->arch.regs[VCPU_REGS_RAX] = 0;
    vcpu->arch.regs[VCPU_REGS_RBX] = 0;
    vcpu->arch.regs[VCPU_REGS_RCX] = 0;
    vcpu->arch.regs[VCPU_REGS_RDX] = 0;
    vcpu->arch.regs[VCPU_REGS_RSP] = 0;
    vcpu->arch.regs[VCPU_REGS_RBP] = 0;
    vcpu->arch.regs[VCPU_REGS_RSI] = 0;
    vcpu->arch.regs[VCPU_REGS_RDI] = 0;
    /* Jiaqi */
    vcpu->arch.regs[VCPU_REGS_R8] = 0;
    vcpu->arch.regs[VCPU_REGS_R9] = 0;
    vcpu->arch.regs[VCPU_REGS_R10] = 0;
    vcpu->arch.regs[VCPU_REGS_R11] = 0;
    vcpu->arch.regs[VCPU_REGS_R12] = 0;
    vcpu->arch.regs[VCPU_REGS_R13] = 0;
    vcpu->arch.regs[VCPU_REGS_R14] = 0;
    vcpu->arch.regs[VCPU_REGS_R15] = 0;
    /* /Jiaqi*/

    vcpu->arch.regs_dirty = 0xFFFFFFFFU;
    vcpu->arch.regs_avail = 0xFFFFFFFFU;
}

void switch_intro_ctx (intro_ctx_t* next, struct kvm_vcpu* vcpu)
{
    vcpu->arch.mmu.root_hpa = next->eptptr;
    kvm_x86_ops->write_eptp (vcpu, next->eptptr);
}
EXPORT_SYMBOL_GPL(switch_intro_ctx);

long kvm_imee_get_guest_context (struct kvm_vcpu *vcpu, void* argp)
{
    struct kvm* cur;
    
    DBG ("================start==================\n");
    // t0 = rdtsc ();

    init_global_vars (vcpu);

    // install the handlers to IDT
    install_int_handlers ();

    /* allocate page frames for EPT from the kernel */
    init_ept_frames();

    // struct arg_blk* args = &imee_arg;
    copy_from_user (&imee_arg, argp, sizeof (struct arg_blk));
    /* Jiaqi */
    // DBG ("initialize imee_arg, addr of imee_arg in get_guest_context: %p, size: %lx\n", &imee_arg, sizeof(struct arg_blk));
    /* Jiaqi */

    /* init contexts */
    spin_lock (&kvm_lock);
    list_for_each_entry (cur, &vm_list, vm_list)
    {
        create_introspection_context (cur, vcpu);
    }
    spin_unlock (&kvm_lock);

    // t1 = rdtsc ();
    // setup_cycle = t1 - t0;

    return 0; 
}
/* Jiaqi */
EXPORT_SYMBOL_GPL(kvm_imee_get_guest_context);
/*  /Jiaqi */

/* given a gva, return the gpte */
struct pt_mapping* get_gpte_from_gva (struct kvm* target_kvm, unsigned long gva, unsigned long g_cr3)
{
    int idx[4] = {
        (gva >> 39) & 0x1FF,
        (gva >> 30) & 0x1FF,
        (gva >> 21) & 0x1FF,
        (gva >> 12) & 0x1FF
    };
    int page_level = 4;

    struct pt_mapping* pm = 0; 

    int lv = 0;
    unsigned long next, next_addr;
    next = g_cr3;
    next_addr = g_cr3 & ~0xFFFUL;

    // DBG ("gva: %lX\n", gva);

    for ( ; lv < page_level; lv++)
    {
        ulong hpa = get_ptr_guest_page_64 (target_kvm, next_addr);
        if (hpa)
        {
            ulong pfn = hpa >> 12;
            struct page* pg = pfn_to_page (pfn);
            unsigned long* pp = (unsigned long*) kmap_atomic (pg);
            // DBG ("ptr to guest page: %p\n", p);
            next = pp[idx[lv]];
            // DBG ("lv: %d next: %lX\n", lv, next);
            kunmap_atomic (pp);

            if (!next || !(next & PTE_P_BIT)) 
                break;

            if (next && (next & PDE_PG_BIT) && (next & PTE_P_BIT) && (lv < page_level - 1)) // this is a huge page
            {
                pm = kmalloc (sizeof (struct pt_mapping), GFP_KERNEL);
                // pm->hpa = hpa;
                // pm->lv = page_level - lv;
                pm->lv = lv;
                pm->e = next;
                return pm;
            }
            
            if (lv == page_level -1)
            {
                pm = kmalloc (sizeof (struct pt_mapping), GFP_KERNEL);
                // pm->lv = page_level - lv + 1;
                // pm->hpa = hpa;
                pm->lv = lv;
                pm->e = next;
                return pm;
            }
           
            // next_addr = next & ~GPA_MASK;
            next_addr = next & GPAE_MASK;
            // DBG ("lv: %d, next_addr: %lX\n", lv, next_addr);
        }
        else
        {
            break;
        }
    }
    
    return 0;
}

/*Jiaqi, export the following function to get the hpa based on gva */
struct gpa_hpa get_hpa_from_gva (struct kvm* target_kvm, unsigned long gva, unsigned long g_cr3)
{
    // struct kvm* target_kvm = current_target->kvm;
    struct pt_mapping* pm = get_gpte_from_gva (target_kvm, gva, g_cr3);
    unsigned long gpa;
    struct gpa_hpa temp;
    ulong hpa;

    if (pm && (pm->lv == 3))
    {
        gpa = pm->e & ~0xFFFU;
    }
    else if (pm && (pm->lv == 2))
    {
        gpa = pm->e + (gva & 0x1ff000); 
    }
    else if (pm && (pm->lv == 1))
    {
        gpa = pm->e + (gva & 0x3ffff000); 
    }
    else
    {
        printk ("get_gpte_from_gva failed !!!!. \n");
        // return NULL;
        return temp;
    }
    // DBG ("gpa: %lx, gva: %lx. \n", gpa, gva);
    /* transfers the gpte entry into a gpa */
    gpa &= GPAE_MASK;
    hpa = get_ptr_guest_page_64 (target_kvm, gpa);
    DBG ("hpa: %lx. gpa: %lx, gva: %lx. \n", hpa, gpa, gva);
    // DBG ("hpa: %lx. \n", hpa);
    /* debugging */
    // if (!hpa && gpa)
    // {
    //     hpa = trans_gpa_into_hpa (gpa, current_target->target_vcpu->arch.mmu.root_hpa);
    //     DBG ("hpa: %lx. \n", hpa);
    // }

    temp.gpa = gpa;
    temp.hpa = hpa;
    return temp;
}
EXPORT_SYMBOL_GPL(get_hpa_from_gva);

/*Jiaqi, export the following function to get the gpa based on gva */
unsigned long get_gpa_from_gva (struct kvm* target_kvm, unsigned long gva, unsigned long g_cr3)
{
    // struct kvm* target_kvm = current_target->kvm;
    struct pt_mapping* pm = get_gpte_from_gva (target_kvm, gva, g_cr3);
    unsigned long gpa;

    if (pm && (pm->lv == 3))
    {
        gpa = pm->e & ~0xFFFU;
    }
    else if (pm && (pm->lv == 2))
    {
        gpa = pm->e + (gva & 0x1ff000); 
    }
    else if (pm && (pm->lv == 1))
    {
        gpa = pm->e + (gva & 0x3ffff000); 
    }
    else
    {
        printk ("get_gpte_from_gva failed !!!!. \n");
        return 0;
    }
    DBG ("gpa: %lx, gva: %lx. \n", gpa, gva);
    return gpa;
}
EXPORT_SYMBOL_GPL(get_gpa_from_gva);

/* / */

int copy_guest_page (struct kvm* target_kvm, unsigned long g_cr3, unsigned long gva, unsigned char new_ins[0xd], unsigned long new_ins_size)
{
    struct pt_mapping* pm = get_gpte_from_gva (target_kvm, gva, g_cr3);
    unsigned long old_ins_offset;
    unsigned long gpa;
    ulong hpa;
    old_ins_offset = gva & 0xfff;
    // unsigned long new_ins_size;
    // exit gate
    // new_ins_size = 0xc;
    DBG ("new_ins: %p, new_ins_size: %lx. \n", new_ins, new_ins_size);

    if (pm && (pm->lv == 3))
    {
        gpa = pm->e & ~0xFFFU;
    }
    else if (pm && (pm->lv == 2))
    {
        gpa = pm->e + (gva & 0x1ff000); 
    }
    else if (pm && (pm->lv == 1))
    {
        gpa = pm->e + (gva & 0x3ffff000); 
    }
    else
    {
        printk ("get_gpte_from_gva failed !!!!. \n");
        return -1;
    }
    DBG ("gpa: %lx, gva: %lx. \n", gpa, gva);
    hpa = get_ptr_guest_page_64 (target_kvm, gpa);
    DBG ("hpa: %lx. \n", hpa);
    // next_addr = g_cr3 & ~0xFFFU;
    if (hpa)
    {
        ulong pfn = (hpa)  >> 12;
        struct page* pg = pfn_to_page (pfn);
        void* pp = kmap_atomic (pg);
        // void* new_page = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        void* new_page = (void*) get_ept_page();
        unsigned long eptptr = current_target->s_eptptr;
        
        memcpy (new_page, pp, 0x1000);
        // memcpy (new_page + old_ins_offset, new_ins, new_ins_size);
        memcpy (new_page + old_ins_offset, new_ins, new_ins_size);
        DBG ("old_ins_offset: %lx, new_ins: %lx. \n", old_ins_offset, *((unsigned long*) (new_page+old_ins_offset)));

        adjust_ept_entry_s (current_target, gpa, eptptr, virt_to_phys(new_page));

        kunmap_atomic (pp);
        return 1;
    }
    else
    {
        DBG ("cannot get a hpa for gva: %lx. \n", gva);
        return -1;
    }
}

/* enfoece write protection for gpa on s-EPT */
int prot_root_PT(unsigned long gpa, int permission)
{   
    // unsigned long root_pt_hpa;
    // target_proc = ctx->task;
    // target_kvm = ctx->kvm;
    // orig_root_hpa = get_ptr_guest_page_64 (target_kvm, last_cr3);
    int pml4_idx, pdpt_idx, pd_idx, pt_idx;
    unsigned long *pml4_ptr, *pdpt_ptr, *pd_ptr, *pt_ptr;
    unsigned long eptptr = current_target->s_eptptr;
    // unsigned long gpa = last_cr3;
    pml4_idx = (gpa >> 39) & 0x1ff;
    pdpt_idx = (gpa >> 30) & 0x1ff;
    pd_idx = (gpa >> 21) & 0x1ff;
    pt_idx = (gpa >> 12) & 0x1ff;
    pml4_ptr = __va (eptptr & HPAE_MASK);
    if (pml4_ptr[pml4_idx] == 0)
    {
        printk ("PML4 ENTRY IS EMPTY.\n");
        return 0;
    }
    else
    {
        // printk ("pml4 entry: %lx. \n", pml4_ptr[pml4_idx]);
        pdpt_ptr = __va(pml4_ptr[pml4_idx] & HPAE_MASK);
    }
    
    if (pdpt_ptr[pdpt_idx] == 0)
    {
        printk ("Pdpt ENTRY IS EMPTY.\n");
        return 0;
    }
    else
    {
        // printk ("pdpt entry: %lx. \n", pdpt_ptr[pdpt_idx]);
        pd_ptr = __va(pdpt_ptr[pdpt_idx] & HPAE_MASK);
    }
    
    if (pd_ptr[pd_idx] == 0)
    {
        printk ("pd ENTRY IS EMPTY.\n");
        return 0;
    }
    else
    {
        // printk ("pd entry: %lx. \n", pd_ptr[pd_idx]);
        pt_ptr = __va(pd_ptr[pd_idx] & HPAE_MASK);
    }
    
    if (pt_ptr[pt_idx] == 0)
    {
        printk ("pt ENTRY IS EMPTY.\n");
        return 0;
    }
    else
    {
        DBG ("last cr3 pt entry: %lx.  for gpa: %lx. \n", pt_ptr[pt_idx], gpa);
        if (permission == 0x1)
        {
            pt_ptr[pt_idx] &= ~0x2;
            DBG ("after write protection for last cr3, pt entry: %lx. \n", pt_ptr[pt_idx]);
        }
        else if (permission == 0x3)
        {
            pt_ptr[pt_idx] |= 0x2;
            DBG ("give RW permission for last cr3, pt entry: %lx. \n", pt_ptr[pt_idx]);
        }
        else
        {
            printk ("error permission request for guest root PT:%d. \n", permission);
        }
        return 1;
    }
}
EXPORT_SYMBOL_GPL(prot_root_PT);

int sec_ept (struct kvm_vcpu *vcpu)
{
    int ret;

    // ret = complete_s_ept (current_target);
    ret = fix_ept_mapping_s (current_target);
    if (prot_root_PT(last_cr3, 0x1) == 0)
    {
        printk ("when enforce write protect on last cr3, entry not found. \n");
        return -5;
    }
    // if (!ret)
    // {
    //     DBG ("complete_s_ept: %d. \n", ret);
    //     return ret;
    // }

    /* complete ept redirection is this is no privilege switch version */
    if (imee_arg.pl_switch == 1)
    {
        struct kvm* target_kvm = current_target->kvm;
        unsigned long gva, new_ins_size;
        // unsigned char new_ins[new_ins_size];
        unsigned char new_ins[0xd];
        unsigned long g_cr3 = current_target->cr3;
        DBG ("guest cr3: %lx. \n", g_cr3);
        gva = 0xffffffff8108fd4b;
        new_ins_size = 0xd;
        // new_ins[0] = 0x0f; //0x7ff020900338 is the addr of exit gate
        // new_ins[1] = 0x01; //0x7ff020900338 is the addr of exit gate
        // new_ins[2] = 0xc1; //0x7ff020900338 is the addr of exit gate
        
        new_ins[0] = 0x50;
        new_ins[1] = 0x48;
        new_ins[2] = 0xb8;
        new_ins[3] = 0x33;
        new_ins[4] = 0x06;
        new_ins[5] = 0x90;
        new_ins[6] = 0x20;
        new_ins[7] = 0xf0;
        new_ins[8] = 0x7f;
        new_ins[0] = 0x00;
        new_ins[10] = 0x00;
        new_ins[11] = 0xff;
        new_ins[12] = 0xe0;

        ret = copy_guest_page (target_kvm, g_cr3, gva, new_ins, new_ins_size);
        if (ret < 0)
        {
            DBG ("ret from copy_guest_page: %d. \n", ret);
            return ret;
        }
        
        gva = 0xffffffff817f6f36;
        new_ins_size = 0xd;
        new_ins[0] = 0x50;
        new_ins[1] = 0x48;
        new_ins[2] = 0xb8;
        new_ins[3] = 0x79;
        new_ins[4] = 0x06;
        new_ins[5] = 0x90;
        new_ins[6] = 0x20;
        new_ins[7] = 0xf0;
        new_ins[8] = 0x7f;
        new_ins[9] = 0x00;
        new_ins[10] = 0x00;
        new_ins[11] = 0xff;
        new_ins[12] = 0xe0;
        
        ret = copy_guest_page (target_kvm, g_cr3, gva, new_ins, new_ins_size);
        if (ret < 0)
        {
            DBG ("ret from copy_guest_page: %d. \n", ret);
            return ret;
        }
    }
    /* / */

    if (ret == 0)
    {
        // eptp_list = __get_free_page(GFP_KERNEL | __GFP_ZERO);
        eptp_list = get_ept_page();
        DBG ("eptp_list: 0x%lx\n", eptp_list);
        DBG ("pa of ept_list: 0x%lx\n", (unsigned long) virt_to_phys((void*)eptp_list));
        kvm_x86_ops->write_vmfunc_control ();
        kvm_x86_ops->write_eptp_list(eptp_list);
        kvm_x86_ops->write_secondary_exec_control(0x2000);
        
        kvm_x86_ops->write_primary_exec_control(0xfff7fffff);//TODO
    }
    return ret;
}

// void set_vpid (struct kvm_vcpu* vcpu)
// {
//     kvm_x86_ops->write_secondary_exec_control(0x20);
// 
// }

/* analyzer IDT, GDT, TSS 's GVA are the same as the one used by target */
/* analyzer IDT, GDT, TSS 's GPA | 0xC00000000 are the same as the one used by target, the GPA in t-EPT are adjusted later */
/* analyzer IDT, GDT, TSS 's HPA are totally different from the one used by target, the HPA in a-EPT are adjusted here */
/* install #PF in a-EPT, which uses IST[7]; #int3 in t-EPT, which uses IST[7] */
/* analyzer use new physical copies of those des_tables, target use original
 * copies allocated as data pages */
/* TODO: is it an issue that the GPA, HPA are not contiguous for the 3 pages of
 * TSS_STRUCT? performace issue? */
static int copy_des_table (void)
{
    void* ana_tss;
    // unsigned long exit_gate_offset = 0x297;//the call gate in the GDT used by target thread
    // unsigned long pf_handler_offset = 0x2da;//for analyser's usage
    // unsigned long int3_hand_offset = 0x2d8;//for target's usage
    // unsigned long t_pf_offset = 0x360;//to trap target's #PF
    unsigned long exit_gate_offset = 0x2c1;//the call gate in the GDT used by target thread
    unsigned long pf_handler_offset = 0x2da;//for analyser's usage
    unsigned long int3_hand_offset = 0x2f4;//for target's usage
    unsigned long t_pf_offset = 0x319;//to trap target's #PF
    gate_desc s;
    tss_desc tss;

    unsigned long guest_idt, guest_gdt, guest_tss, guest_tss_page_off;
    struct gpa_hpa temp;
   
    ulong pfn;
    struct page* pg;
    void* pp;
    void* new_page;
    unsigned long eptptr;
    
    struct shar_arg* ei_shar_arg = (struct shar_arg*) imee_arg.shar_va;
    
    /* initialize ana_idt */
    guest_idt = imee_idt.address;
    new_page = get_ept_page();//new IDT page
    imee_idt.address = imee_arg.t_idt_va + UK_OFFSET;
    temp = get_hpa_from_gva (current_target->kvm, guest_idt, last_cr3);
    if (!(temp.gpa && temp.hpa))
    {
        printk ("get gpa and hpa of idt table fail. \n");
        printk ("IDT gva: %lx. gpa: %lx, hpa: %lx. \n", guest_idt, temp.gpa, temp.hpa);
        return -5;
    }
    printk ("IDT gva: %lx. gpa: %lx, hpa: %lx. \n", guest_idt, temp.gpa, temp.hpa);
    pfn = (temp.hpa)  >> 12;
    pg = pfn_to_page (pfn);
    pp = kmap_atomic (pg);
   
    unsigned long temp_entry, low, mid;
    unsigned long* idt_ptr;
    idt_ptr = (unsigned long*) pp;
    temp_entry = idt_ptr[0xe*2];
    low = temp_entry & 0xffff;
    mid = (temp_entry >> 48) & 0xffff;
    temp_entry = low | (mid << 16);
    ei_shar_arg->pf_entry = temp_entry | 0xffffffff00000000;
    temp_entry = idt_ptr[0x3*2];
    low = temp_entry & 0xffff;
    mid = (temp_entry >> 48) & 0xffff;
    temp_entry = low | (mid << 16);
    ei_shar_arg->int3_entry = temp_entry | 0xffffffff00000000;
    
    memcpy (new_page, pp, 0x1000);
    pack_gate(&s, GATE_INTERRUPT, pf_handler_offset + imee_arg.pf_addr + UK_OFFSET, 0, 7, __KERNEL_CS);
    memcpy (new_page + 0x2*8*0xe, &s, 0x10);
    eptptr = current_target->eptptr;
    adjust_ept_entry (current_target, imee_arg.t_idt_pa, eptptr, virt_to_phys(new_page), 0);
    /* setup idt in second ept */
    memcpy ((void*)imee_arg.t_idt_va, pp, 0x1000);
    // pack_gate(&s, GATE_INTERRUPT, int3_hand_offset + imee_arg.exit_gate_addr + UK_OFFSET, 0, 7, __KERNEL_CS);
    pack_gate(&s, GATE_INTERRUPT, int3_hand_offset + imee_arg.exit_gate_addr + UK_OFFSET, 3, 7, __KERNEL_CS);
    // memcpy (new_page + 0x2*8*0x3, &s, 0x10);
    memcpy ((void*)(imee_arg.t_idt_va + 0x2*8*0x3), &s, 0x10);
    pack_gate(&s, GATE_INTERRUPT, t_pf_offset + imee_arg.exit_gate_addr + UK_OFFSET, 3, 0, __KERNEL_CS);
    DBG ("orig #PF entry in IDT: %lx. \n", *((unsigned long*)(imee_arg.t_idt_va+0x2*8*0xe)));
    DBG ("orig #PF entry in IDT: %lx. \n", *((unsigned long*)(imee_arg.t_idt_va+0x8+0x2*8*0xe)));
    // memcpy (new_page + 0x2*8*0x3, &s, 0x10);
    memcpy ((void*)(imee_arg.t_idt_va + 0x2*8*0xe), &s, 0x10);
    kunmap_atomic (pp);

    /* initialize tss */
    guest_tss = imee_tr.base & ~0xfffUL;
    guest_tss_page_off = imee_tr.base & 0xfffUL;
    ei_shar_arg->tss_pg_off = guest_tss_page_off;
    ei_shar_arg->g_syscall_entry = guest_syscall_entry;
    
    imee_tr.base = imee_arg.t_tss_va + UK_OFFSET + guest_tss_page_off;
    ana_tss_tmp = (void*) __get_free_pages(GFP_USER| __GFP_ZERO, 2);
    temp = get_hpa_from_gva (current_target->kvm, guest_tss, last_cr3);
    if (!(temp.gpa && temp.hpa))
    {
        printk ("get gpa and hpa of tss table fail. \n");
        return -5;
    }
    DBG ("TSS gva: %lx. gpa: %lx, hpa: %lx. \n", guest_tss, temp.gpa, temp.hpa);
    /* a-tss-0 */
    pfn = (temp.hpa)  >> 12;
    pg = pfn_to_page (pfn);
    pp = kmap_atomic (pg);
    // memcpy (ana_tss_tmp, pp + guest_tss_page_off, 0x1000 - guest_tss_page_off);
    memcpy (ana_tss_tmp, pp, 0x1000);
    adjust_ept_entry (current_target, imee_arg.t_tss_pa, eptptr, virt_to_phys(ana_tss_tmp), 0);
    //redirect the a-EPT to allow the analyser to read/modify the target's TSS_struct
    adjust_ept_entry (current_target, imee_arg.ana_t_tss_pa, eptptr, imee_arg.t_tss_pa, 0);
    //redirect the a-EPT to allow the analyser to read/modify the target's GDT
    adjust_ept_entry (current_target, imee_arg.ana_t_gdt_pa, eptptr, imee_arg.t_gdt_pa, 0);
    /* t-tss-0 */
    memcpy ((void*)imee_arg.t_tss_va, pp, 0x1000);
    kunmap_atomic (pp);
    
    /* a-tss-1 */
    guest_tss += 0x1000;
    temp = get_hpa_from_gva (current_target->kvm, guest_tss, last_cr3);
    
    // if (!(temp.gpa && temp.hpa))
    // {
    //     printk ("get gpa and hpa of tss1 table fail. \n");
    //     return -5;
    // }
    // DBG ("TSS1 gva: %lx. gpa: %lx, hpa: %lx. \n", guest_tss, temp.gpa, temp.hpa);
    // pfn = (temp.hpa + 0x1000)  >> 12;
    // pg = pfn_to_page (pfn);
    // pp = kmap_atomic (pg);
    // memcpy ((void*)(ana_tss_tmp+0x1000), pp, 0x1000);
    // adjust_ept_entry (current_target, imee_arg.t_tss1_pa, eptptr, virt_to_phys(ana_tss_tmp+0x1000), 0);
    // /* t-tss-1 */
    // memcpy ((void*)(imee_arg.t_tss_va+0x1000), pp, 0x1000);
    // kunmap_atomic (pp);
    
    /* since the host swaps tss-1 and tss-2 out after the guest VM powers on for
     * a while, and we know the values in the I/O bitmap are all 0xff, so ... */
    if (!temp.gpa)
    {
        printk ("get gpa of tss1 table fail. \n");
        return -5;
    }
    DBG ("TSS1 gva: %lx. gpa: %lx, hpa: %lx. \n", guest_tss, temp.gpa, temp.hpa);
    memset ((void*)(ana_tss_tmp+0x1000), 0xff, 0x1000);
    adjust_ept_entry (current_target, imee_arg.t_tss1_pa, eptptr, virt_to_phys(ana_tss_tmp+0x1000), 0);
    /* t-tss-1 */
    memset ((void*)(imee_arg.t_tss_va+0x1000), 0xff, 0x1000);
   
    /* a-tss-2 */
    guest_tss += 0x1000;
    temp = get_hpa_from_gva (current_target->kvm, guest_tss, last_cr3);
    // if (!(temp.gpa && temp.hpa))
    // {
    //     printk ("get gpa and hpa of tss2 table fail. \n");
    //     return -5;
    // }
    // DBG ("TSS2 gva: %lx. gpa: %lx, hpa: %lx. \n", guest_tss, temp.gpa, temp.hpa);
    // 
    // pfn = (temp.hpa + 0x2000)  >> 12;
    // pg = pfn_to_page (pfn);
    // pp = kmap_atomic (pg);
    // memcpy ((void*)(ana_tss_tmp+0x2000), pp, 0x1000);
    // adjust_ept_entry (current_target, imee_arg.t_tss2_pa, eptptr, virt_to_phys(ana_tss_tmp+0x2000), 0);
    // /* t-tss-2 */
    // memcpy ((void*)(imee_arg.t_tss_va+0x2000), pp, 0x1000);
    // kunmap_atomic (pp);
    
    /* since the host swaps tss-1 and tss-2 out after the guest VM powers on for
     * a while, and we know the values in the I/O bitmap are all 0xff, so ... */
    if (!temp.gpa)
    {
        printk ("get gpa of tss2 table fail. \n");
        return -5;
    }
    DBG ("TSS2 gva: %lx. gpa: %lx, hpa: %lx. \n", guest_tss, temp.gpa, temp.hpa);
    /* the analyser and target should share the same writeable data page */
    // memset ((void*)(ana_tss_tmp+0x2000), 0xff, 0x500);
    // adjust_ept_entry (current_target, imee_arg.t_tss2_pa, eptptr, virt_to_phys(ana_tss_tmp+0x2000), 0);
    /* t-tss-2 */
    memset ((void*)(imee_arg.t_tss_va+0x2000), 0xff, 0x500);
   
    /* setup #PF's IST[7] for analyser */
    ana_tss = ana_tss_tmp + guest_tss_page_off;
    ana_tss += offsetof(struct x86_hw_tss, ist[6]);//TODO: don't know why but offsetof api returns the offset between the beginning of struct and the end of ist[6];
    *((unsigned long*) ana_tss) = imee_arg.pf_stack + 0x1000 + UK_OFFSET;
    DBG ("ana_tss: %p, content: %lx. \n", ana_tss, *((unsigned long*) ana_tss));

    /* setup #BP's IST[7] for target */
    ana_tss = (void*) imee_arg.t_tss_va + guest_tss_page_off;
    ana_tss += offsetof(struct x86_hw_tss, ist[6]);
    *((unsigned long*) ana_tss) = imee_arg.stack_addr + 0x1000 + UK_OFFSET - 0x100;
    DBG ("ana_tss: %p, content: %lx. \n", ana_tss, *((unsigned long*) ana_tss));
    
    /* initialize gdt */
    guest_gdt = imee_gdt.address;
    new_page = get_ept_page();//new GDT page
    imee_gdt.address = imee_arg.t_gdt_va + UK_OFFSET;
    temp = get_hpa_from_gva (current_target->kvm, guest_gdt, last_cr3);
    if (!(temp.gpa && temp.hpa))
    {
        printk ("get gpa and hpa of idt table fail. \n");
        return -5;
    }
    DBG ("GDT gva: %lx. gpa: %lx, hpa: %lx. \n", guest_gdt, temp.gpa, temp.hpa);
    pfn = (temp.hpa)  >> 12;
    pg = pfn_to_page (pfn);
    pp = kmap_atomic (pg);
    memcpy (new_page, pp, 0x1000);
    eptptr = current_target->eptptr;
    adjust_ept_entry (current_target, imee_arg.t_gdt_pa, eptptr, virt_to_phys(new_page), 0);
    set_tssldt_descriptor(&tss, imee_tr.base, DESC_TSS, 0x22c0);
    unsigned long* tss_tmp = &tss;
    DBG ("onsite_tss_va: %lx, tss_gate: %lx. :%lx. \n", imee_arg.t_tss_va + UK_OFFSET + guest_tss_page_off, *tss_tmp, *(tss_tmp + 0x1));
    memcpy ((void*)(new_page + GDT_ENTRY_TSS*0x8), &tss, 0x10);
    /* setup gdt in second ept */
    memcpy ((void*)imee_arg.t_gdt_va, pp, 0x1000);
    memcpy ((void*)(imee_arg.t_gdt_va + GDT_ENTRY_TSS*0x8), &tss, 0x10);
    
    /* setup a call_gate on GDT of s-EPT */
    imee_gdt.size = 8191*8;//enlarge the size of GDT to be the maximum
    // the definition of pack_gate
    // pack_gate(gate_desc *gate, unsigned type, unsigned long func, unsigned dpl, unsigned ist, unsigned seg)
    // the call gate for user space, since pack_gate api hard coded seg as
    // __KERNEL_CS
	unsigned long func = exit_gate_offset + imee_arg.exit_gate_addr + UK_OFFSET;
    s.offset_low	= PTR_LOW(func);
	s.segment		= __USER_CS;
	s.ist		= 0;
	s.p			= 1;
	s.dpl		= 3;
	s.zero0		= 0;
	s.zero1		= 0;
	s.type		= GATE_CALL;
	s.offset_middle	= PTR_MIDDLE(func);
	s.offset_high	= PTR_HIGH(func);
    // // the call gate for kernel space
    // pack_gate(&s, GATE_CALL, exit_gate_offset + imee_arg.exit_gate_addr + UK_OFFSET, 0, 0, __KERNEL_CS);
    tss_tmp = imee_arg.t_gdt_va;
    int i = 0;
    i = 32;
    memcpy (&tss_tmp[i], &s, 0x10);//the call gate is installed for the libc code, possible selector: 0x0103/0x0100
    printk ("index: %d, gate_addr: %p, %lx, %lx. \n", i, &tss_tmp[i], tss_tmp[i], tss_tmp[i+1]);
    // i = 125;
    // memcpy (&tss_tmp[i], &s, 0x10);//the call gate is for user program code, the possible selector: 0x03eb/0x03e80 
    i = 56;
    memcpy (&tss_tmp[i], &s, 0x10);//the call gate is installed for user program code, possible selector: 0x01c3/0x01c0/0x01c1/0x01c2
    printk ("index: %d, gate_addr: %p, %lx, %lx. \n", i, &tss_tmp[i], tss_tmp[i], tss_tmp[i+1]);
    i = 18;
    memcpy (&tss_tmp[i], &s, 0x10);//the call gate is installed for user program code, possible selector: 0x0090/0x0093/0x0091/0x0092
    printk ("index: %d, gate_addr: %p, %lx, %lx. \n", i, &tss_tmp[i], tss_tmp[i], tss_tmp[i+1]);
    i = 409;
    memcpy (&tss_tmp[i], &s, 0x10);//the call gate is installed for superpi user program code, possible selector: 0x0cc8/0x0cc9/0x0cca/0x0ccb
    printk ("index: %d, gate_addr: %p, %lx, %lx. \n", i, &tss_tmp[i], tss_tmp[i], tss_tmp[i+1]);
    i = 417;
    memcpy (&tss_tmp[i], &s, 0x10);//the call gate is installed for superpi user program code, possible selector: 0x0cc8/0x0cc9/0x0cca/0x0ccb
    printk ("index: %d, gate_addr: %p, %lx, %lx. \n", i, &tss_tmp[i], tss_tmp[i], tss_tmp[i+1]);
    i = 163;
    memcpy (&tss_tmp[i], &s, 0x10);//the call gate is installed for superpi user program code with printf, possible selector: 0x0518/0x0519/0x051a/0x051b
    printk ("index: %d, gate_addr: %p, %lx, %lx. \n", i, &tss_tmp[i], tss_tmp[i], tss_tmp[i+1]);
    i = 60;
    memcpy (&tss_tmp[i], &s, 0x10);//the call gate is installed for upx packed uname user program code, possible selector: 0x01e0/0x01e1/0x01e2/0x01e3
    printk ("index: %d, gate_addr: %p, %lx, %lx. \n", i, &tss_tmp[i], tss_tmp[i], tss_tmp[i+1]);
    i = 480;
    pack_gate(&s, GATE_CALL, exit_gate_offset + imee_arg.exit_gate_addr + UK_OFFSET, 3, 0, __KERNEL_CS);
    memcpy (&tss_tmp[i], &s, 0x10);//the call gate is installed for kernel space code, the possible selector: 0x0f00/0x0f03 
    printk ("index: %d, gate_addr: %p, %lx, %lx. \n", i, &tss_tmp[i], tss_tmp[i], tss_tmp[i+1]);
    // i = 24;
    // memcpy (&tss_tmp[i], &s, 0x10);//the call gate is installed in 10th entry. 0x50/0x53
    // printk ("index: %d, gate_addr: %p, %lx, %lx. \n", i, &tss_tmp[i], tss_tmp[i], tss_tmp[i+1]);
    // i = 32;
    // memcpy (&tss_tmp[i], &s, 0x10);//the call gate is installed in 10th entry. 0x50/0x53
    // printk ("index: %d, gate_addr: %p, %lx, %lx. \n", i, &tss_tmp[i], tss_tmp[i], tss_tmp[i+1]);
    // memcpy (&tss_tmp[32], &s, 0x10);//the call gate is installed in 32th entry
    // printk ("gate_addr: %p, %lx, %lx. \n", &tss_tmp[32], tss_tmp[32], tss_tmp[33]);
    // memcpy (&tss_tmp[12], &s, 0x10);//the call gate is installed in 24th entry, 0xc0/0xc3
    // printk ("gate_addr: %p, %lx, %lx. \n", &tss_tmp[12], tss_tmp[12], tss_tmp[13]);
    // memcpy (&tss_tmp[16], &s, 0x10);//the call gate is installed in 24th entry, 0xc0/0xc3
    // printk ("gate_addr: %p, %lx, %lx. \n", &tss_tmp[16], tss_tmp[16], tss_tmp[16]);
    // memcpy (&tss_tmp[24], &s, 0x10);//the call gate is installed in 24th entry, 0xc0/0xc3
    // printk ("gate_addr: %p, %lx, %lx. \n", &tss_tmp[24], tss_tmp[24], tss_tmp[25]);
    // pack_gate(&s, GATE_CALL, exit_gate_offset + imee_arg.exit_gate_addr + UK_OFFSET, 3, 0, __KERNEL_CS);
    // memcpy (imee_arg.t_gdt_va + 32*8, &s, 0x10);//the call gate is installed in 32th entry
    // tss_tmp = imee_arg.t_gdt_va + 32*8;
    // DBG ("call_gate addr on s-EPT: %p, content: %lx. \n", tss_tmp, *tss_tmp);
    // tss_tmp ++;
    // DBG ("second part call_gate addr on s-EPT: %p, content: %lx. \n", tss_tmp, *tss_tmp);
    /* / */
    
    kunmap_atomic (pp);
   
    return 0;
}

void check_bitmaps (void)
{
    unsigned long pfn;
    struct page *pg;
    void* pp;
    int i;
    unsigned long temp_content;
    unsigned long msr_bitmap_pa, io_a_pa, io_b_pa;
    
    kvm_x86_ops->get_bitmap_pa (&msr_bitmap_pa, &io_a_pa, &io_b_pa);

    if (msr_bitmap_pa)
    {
        DBG ("msr_bitmap_pa: %lx. \n", msr_bitmap_pa);
        pfn = (msr_bitmap_pa) >> 12;
        pg = pfn_to_page (pfn);
        pp = (void*) kmap_atomic (pg);
        for (i = 0; i < 512; i ++)
        {
            temp_content = ((unsigned long*)pp)[i];
            if (temp_content != 0xffffffffffffffff)
            {
                // memset (pp, 0x0, 4096);
                DBG ("in msr bitmap, i : %d, content: %lx. \n", i, temp_content);
            }
        }
        kunmap_atomic (pp);
    }

    /* check the state of the IO_BITMAP_A & IO_BITMAP_B */
    if (io_a_pa)
    {
        DBG ("io_bitmap_a_pa: %lx. \n", io_a_pa);
        pfn = (io_a_pa) >> 12;
        pg = pfn_to_page (pfn);
        pp = (void*) kmap_atomic (pg);
        for (i = 0; i < 512; i ++)
        {
            temp_content = ((unsigned long*)pp)[i];
            if (temp_content != 0xffffffffffffffff)
            {
                // memset (pp, 0x0, 4096);
                DBG ("in io bitmap A, i : %d, content: %lx. \n", i, temp_content);
            }
        }
        kunmap_atomic (pp);
    }

    if (io_b_pa)
    {
        DBG ("io_bitmap_b_pa: %lx. \n", io_b_pa);
        pfn = (io_b_pa) >> 12;
        pg = pfn_to_page (pfn);
        pp = (void*) kmap_atomic (pg);
        for (i = 0; i < 512; i ++)
        {
            temp_content = ((unsigned long*)pp)[i];
            if (temp_content != 0xffffffffffffffff)
            {
                // memset (pp, 0x0, 4096);
                DBG ("in io bitmap B, i : %d, content: %lx. \n", i, temp_content);
            }
        }
        kunmap_atomic (pp);
    }

    return;
}

int start_guest_intercept (struct kvm_vcpu *vcpu)
{
    intro_ctx_t* next;
    int r;
    int cpu;
    int j;
    int ret;
    
    // cycle_idx = 0;
    r = 0;
    /* Jiaqi */
    vmc_idx = 0;
    imee_pid = current->pid;
    // DBG ("update imee_pid as analysis pid: %d\n", imee_pid);
    if (imee_vcpu == vcpu)
    {
        // DBG ("this is imee_vcpu\n");
    }
    // return -1;
    /* Jiaqi */
    
    // last_cr3 = 0;//TODO: recover if this is not in expand vma experiment

    // spin_lock (&sync_lock);
    // if (ACCESS_ONCE (go_flg) == 2)
    // {
    //     printk ("WARNING: last scan ended without resetting CR3 scanning, skipping now.\n");
    // }
    // else if (ACCESS_ONCE (go_flg) == 1)
    // {
    //     ACCESS_ONCE (go_flg) = 0;
    // }
    // else if (ACCESS_ONCE (go_flg) == 3)
    // {
    //     ACCESS_ONCE (go_flg) = 2;
    // }
    // spin_unlock (&sync_lock);

    next = 0;
    if (get_next_ctx (&next) == -1)
    {
        printk ("no target vm detected. \n");
        return -1;
    }
    
    // return -1;
    switch_intro_ctx (next, vcpu);
    reset_general_regs (vcpu);
    // return -1;
    exit_flg = 1;
    smp_mb ();

    cpu = next->target_vcpu->cpu;
    DBG ("Firing IPI to cpu: %d\n", cpu);
    apic->send_IPI_mask (cpumask_of (cpu), 0x56);
    
    smp_mb ();
    j = 0;
    while (ACCESS_ONCE(exit_flg) == 1)
    {
        j ++;
        if (j > 10000000) 
        {
            ERR ("Waited for too long for exit_flg, last_cr3: %lX\n", last_cr3);
            return -1;
        }
    }
    // /* Jiaqi for test */
    exit_flg = 1;
    // DBG("last_rsp: %lx, last_rip: %lx\n", last_rsp, last_rip);
    // remove_int_handlers ();
  
    // use hardcoded cr3 instead of intercepted cr3
    if (imee_arg.hard_cr3 != 0)
    {
        last_cr3 = imee_arg.hard_cr3;
        // onsite_cr3 = imee_arg.hard_cr3 | NO_CONFLICT_GPA_MASK;
    }
    onsite_cr3 = last_cr3 | NO_CONFLICT_GPA_MASK;
    DBG("intercept guest CR3 done! last_cr3: %lx, onsite_cr3: %lx, current cpu: %d\n", last_cr3, onsite_cr3, smp_processor_id());

    // next->cr3 = last_cr3;
    next->cr3 = onsite_cr3;

    init_imee_vcpu (next, vcpu);
    
    // imee_up = 1;
    // host_syscall_entry = 0xffffffff817142b0;
    host_syscall_entry = kallsyms_lookup_name("system_call");
    host_pf_entry = kallsyms_lookup_name("page_fault");
    // guest_syscall_entry = 0xffffffff817f6ed0;
    if (guest_syscall_entry == 0)
    {  
        printk ("guest syscall entry did not setup successfully. \n");
        return -1;
    }

    DBG ("host_pf_entry: %lx. host_syscall_entry: %lx. \n", host_pf_entry, host_syscall_entry);
        

    ret = walk_gpt_new (next, vcpu, &imee_arg);

    /* Jiaqi */
    if (ret == 0)
    {
        if (imee_arg.instrum_flag == 1)
        {
            ret = copy_des_table();
            if (ret < 0)
            {
                printk ("setup desc tables fail.\n");
                return ret;
            }
            
            /* setup eptp_list page and ept_switching in vmfunc */
            ret = sec_ept (vcpu);
            if (ret < 0)
            {
                printk ("sec_ept fail.\n");
                return ret;
            }

        }

        kvm_x86_ops->set_segment (vcpu, &imee_tr, VCPU_SREG_TR);
        kvm_x86_ops->set_idt (vcpu, &imee_idt);
        kvm_x86_ops->set_gdt (vcpu, &imee_gdt);
        DBG ("IMEE_IDT.base: %lx, imee_idt.size: 0x%x\n", imee_idt.address, imee_idt.size); 
        DBG ("IMEE_GDT.base: %lx, imee_gdt.size: 0x%x\n", imee_gdt.address, imee_gdt.size); 
        DBG ("IMEE_tr.base: %lx, imee_tr.size: 0x%x\n", (unsigned long) imee_tr.base, imee_tr.limit); 
        imee_arg.syscall_flag = 1;

        // check_bitmaps();
        /* Jiaqi */
    }

    // return -1;
    return ret;
}
EXPORT_SYMBOL_GPL(start_guest_intercept);

int adjust_dota_context (struct kvm_vcpu *vcpu)
{
    int r;
    unsigned long ret_rax;
    unsigned long rip;
    unsigned long rflags;
    // copy_from_user (&imee_arg, argp, sizeof (struct arg_blk));
    ret_rax = imee_arg.ret_rax;
    // rip = kvm_register_read(vcpu, VCPU_REGS_RIP);
    rip = imee_arg.rcx;
    // rip += 0x2;
    // printk ("adjust dota mode rip as: %lx, rax as: %lx\n", rip, ret_rax);
    rflags = imee_arg.r11;
    rflags &= 0xffffefff;
    /* now return to syscall stub to recover 6 arguments */
    vcpu->arch.regs[VCPU_REGS_RIP] = rip;
    __set_bit (VCPU_REGS_RIP, (unsigned long*)&vcpu->arch.regs_dirty); // VCPU_REGS_RIP bit
    vcpu->arch.regs[VCPU_REGS_RAX] = ret_rax;
    kvm_x86_ops->set_rflags (vcpu, rflags);
    /* set fs for dota mode */
    if (imee_arg.rax == 0x9e)
    {
        if (imee_arg.ret_rax == 0)
        {
            struct kvm_sregs *imee_sregs = kmalloc (sizeof (struct kvm_sregs), GFP_KERNEL);
            DBG ("set fs as : %lx\n", imee_arg.rsi);
            // asm volatile("movl $0xc0000100, %%ecx; \n\t"
            //         "rdmsr; \n\t"
            //         "movl %%edx, %0; \n\t"
            //         "movl %%eax, %1; \n\t"
            //         :"=m"(fs_h), "=m"(fs_l)::"%eax", "%ecx", "%edx");
            // fs_base = (fs_h << 32) | (fs_l & 0xffffffff);
            // DBG ("fs_base: %lx, fs_h: %lx, fs_l: %lx\n", fs_base, fs_h, fs_l);
            // imee_sregs->fs.selector = 0x68;
            imee_sregs->fs.selector = 0x0;
            // imee_sregs->fs.base = 0x0;
            // imee_sregs->fs.base = 0x7ffff7ffc700;
            // imee_sregs->fs.base = imee_arg.rsi + 0xffff6a8000000000;
            imee_sregs->fs.base = imee_arg.rsi + UK_OFFSET;
            imee_sregs->fs.limit = 0xFFFFF;
            imee_sregs->fs.type = 0x3;
            imee_sregs->fs.s = 1;
            imee_sregs->fs.dpl = 0;
            imee_sregs->fs.present = 1;
            imee_sregs->fs.avl = 0;
            imee_sregs->fs.l = 0;
            imee_sregs->fs.db = 1;
            imee_sregs->fs.g = 1;
            kvm_x86_ops->set_segment (vcpu, &imee_sregs->fs, VCPU_SREG_FS);
            kfree (imee_sregs);
        }
        else
        {
            printk (KERN_ERR "set fs failed\n");
        }
    }
    r = 0;
    return r;
}
// EXPORT_SYMBOL_GPL(adjust_dota_context);
int vcpu_entry (void)
{
    int r;
    // struct files_struct *files = current->real_parent->files;
    struct files_struct *files = current->files;
    struct file *filp;
    struct kvm_vcpu *vcpu;

    r = 0;
    
    imee_pid = current->pid;
    // printk ("update imee_pid as : %d in vcpu_entry\n", imee_pid);
    // printk ("in vcpu_entry, address of imee_arg: %p, vcpufd: %d, sstub_entry: %lx\n",&imee_arg, imee_arg.vcpu_fd, imee_arg.sstub_entry);
    // printk ("vcpufd in vcpu_entry: %d\n", imee_arg->vcpu_fd);
    rcu_read_lock ();
    filp = fcheck_files (files, imee_arg.vcpu_fd);
    rcu_read_unlock ();

    // unsigned long fir_cr3;
    asm volatile("movq %%cr3, %%rax; \n\t"
            "movq %%rax, %0; \n\t"
            :"=m"(analyzer_cr3)::"%rax");
    DBG ("---------------------- analyzer_cr3 after fcheck: %lx\n", analyzer_cr3);
    // DBG ("just before enter dota mode, cpuid : %d, comm: %s\n", smp_processor_id(), current->comm);
    // analyzer_cr3 = fir_cr3;
    /* / */
    // filp = fget(imee_arg->vcpu_fd);
    if (filp)
    {
        vcpu = filp->private_data;
        if (vcpu)
        {
            struct kvm_fpu *fpu = NULL;
            struct kvm_sregs *kvm_sregs = NULL;
            // r = vcpu_load (vcpu);
            // printk ("return from vcpu_load, r=%d\n", r);
            // if (r)
            //     return r;
            vcpu_load (vcpu); //since vcpu_load does not return anything
            // printk ("return from vcpu_load, r=%d\n", r);
            
            r = start_guest_intercept (vcpu);
            /* new added to overwrite host cr3 in vmcs */
            kvm_x86_ops->write_host_cr3 (analyzer_cr3);//TODO: to confirm that this is the right place to overwrite host cr3 in vmcs
            /* */
            // unsigned long fir_cr3;
            // asm volatile("movq %%cr3, %%rax; \n\t"
            //         "movq %%rax, %0; \n\t"
            //         :"=m"(fir_cr3)::"%rax");
            // printk ("---------------------- cr3 after intercept guest: %lx\n", fir_cr3);
            // printk("just before enter dota mode, cpuid : %d, comm: %s\n", smp_processor_id(), current->comm);
            // unsigned long parent_cr3;
            // parent_cr3 = __pa(current->real_parent->mm->pgd);
            // printk ("parent_cr3: %lx\n", parent_cr3);
            /* / */
            if (r >= 0)
            {
                printk ("try to enter dota mode for the first time\n");
                r = kvm_arch_vcpu_ioctl_run(vcpu, vcpu->run);
            }
            vcpu_put (vcpu);
            kfree(fpu);
            kfree(kvm_sregs);
            return r;
        }
        else
        {
            printk (KERN_ERR "transfer vcpu failed\n");

        }
    }
    else
    {
        printk (KERN_ERR "fget failed\n");
    }
    return r;
}
EXPORT_SYMBOL_GPL (vcpu_entry);

// int vcpu_reentry (int fd)
int vcpu_reentry (void)
{
    int r;
    struct files_struct *files = current->real_parent->files;
    struct file *filp;
    struct kvm_vcpu *vcpu;
    
    r = 0;
    // DBG ("in vcpu_entry, address of imee_arg: %p, vcpufd: %d, sstub_entry: %lx\n",&imee_arg, imee_arg.vcpu_fd, imee_arg.sstub_entry);
    // DBG ("vcpufd in vcpu_entry: %d\n", imee_arg.vcpu_fd);
    rcu_read_lock ();
    filp = fcheck_files (files, imee_arg.vcpu_fd);
    rcu_read_unlock ();
    // filp = fget(imee_arg->vcpu_fd);
    if (filp)
    {
        vcpu = filp->private_data;
        if (vcpu)
        {
            struct kvm_fpu *fpu = NULL;
            struct kvm_sregs *kvm_sregs = NULL;
            // r = vcpu_load (vcpu);
            // printk ("in vcpu_reentry, return from vcpu_load, r=%d\n", r);
            // if (r)
            //     return r;
            vcpu_load (vcpu);//since vcpu_load does not return anything
            
            r = adjust_dota_context (vcpu);
            
            if (r >= 0)
            {
                // printk ("enter dota mode again\n");
                r = kvm_arch_vcpu_ioctl_run(vcpu, vcpu->run);
            }

            // /* debuging */
            // if (r == 0)
            // {
            //     unsigned long temp_exit_reason;
            //     unsigned long field;
            //     field = 0x4402;
            //     asm volatile (__ex_clear(ASM_VMX_VMREAD_RDX_RAX, "%0")
            //             // :"=a"(value) : "d"(field):"cc");
            //             :"=a"(temp_exit_reason) : "d"(field):"cc");
            //     printk ("exit_reason: %lx. \n", temp_exit_reason);
            //     
            //     field = 0x681e;
            //     asm volatile (__ex_clear(ASM_VMX_VMREAD_RDX_RAX, "%0")
            //             // :"=a"(value) : "d"(field):"cc");
            //             :"=a"(temp_exit_reason) : "d"(field):"cc");
            //     printk ("guest_rip: %lx. \n", temp_exit_reason);
            // }
            // /* / */

            vcpu_put (vcpu);
            kfree(fpu);
            kfree(kvm_sregs);
            return r;
        }
        else
        {
            printk ("transfer vcpu failed\n");

        }
    }
    else
    {
        printk ("fget failed\n");
    }
    return r;
}
EXPORT_SYMBOL_GPL (vcpu_reentry);

int kvm_imee_stop (struct kvm_vcpu* vcpu)
{
    current_target = 0;

    DBG ("releasing IMEE. cpuid:%d\n", smp_processor_id());

    free_contexts ();

    release_ept_frames ();

    /* Jiaqi, free ept_list page */
    // if (eptp_list != 0)
    // {
    //     free_pages (eptp_list, 0);
    //     // __free_pages(eptp_list, 0);
    // }
    if (ana_tss_tmp != 0)
    {
        free_pages ((unsigned long)ana_tss_tmp, 2);
    }
    /* /Jiaqi */

    ACCESS_ONCE(exit_flg) = 0;

    remove_int_handlers ();

    // smp_mb ();
    spin_lock (&sync_lock);
    // if (ACCESS_ONCE (go_flg) == 2)
    // {
    //     ACCESS_ONCE(go_flg) = 3;
    // }

    ACCESS_ONCE(imee_pid) = 0;
    ACCESS_ONCE(imee_vcpu) = 0;
    spin_unlock (&sync_lock);

    smp_mb ();

    vcpu->arch.mmu.root_hpa = INVALID_PAGE;
    // enable_notifier = 0;
    last_cr3 = 0;
    onsite_cr3 = 0;
    /* Jiaqi */
    // guest_syscall_entry = 0;
    
    vmc_idx = 0;
    crt_pfpool_idx = 0;
    crt_search_idx = 0;
    pre_search_idx = 0;
    int3_pool_idx = 0;
    imee_up = 0;
    // /* unmap ei_arg */
    // if (shar_mem_ei)
    // {
    //     __kunmap_atomic (shar_mem_ei);
    // }
    // shar_mem_ei = 0;
    /* / */
    memset (&gva_hpa_pool, 0x0, sizeof(gva_hpa_pool));

    if (myBuffer_ptr)
    {
        bufferDestroy(myBuffer_ptr);
    }
    /* /Jiaqi */

    // printk ("__tmp_counter: %d\n", __tmp_counter);
    // printk ("__tmp_counter3: %d\n", __tmp_counter3);
    // DBG ("__tmp_counter4: %d\n", __tmp_counter4);
    // DBG ("__tmp_counter5: %d\n", __tmp_counter5);
    // printk ("__tmp_counter2: %d\n", __tmp_counter2);
    DBG ("last_cr3: %lX\n", last_cr3);
    // DBG ("go_flg: %d\n", go_flg);
    // printk ("total_cycle: %lld\n", total_cycle);
    // printk ("setup_cycle: %lld\n", setup_cycle);

    // printk ("imee_t: %lld\n", imee_t);
    // printk ("__tmp_counter1: %d\n", __tmp_counter1);

    // if (ts_buffer1)
    // {
    //     int i;
    //     for (i = 0; i < ts_buffer_idx1; i += 2)
    //     {
    //         printk ("%lld %lld\n", ts_buffer1[i], ts_buffer1[i + 1]);
    //     }
    //     free_pages ((ulong) ts_buffer1, PAGE_ORDER);
    //     ts_buffer1 = 0;
    // }

    // imee_up = 0;

    printk ("=================end===================\n");
    return 0;
}
