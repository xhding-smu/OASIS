#ifndef IMEE
#define IMEE
#include <linux/list.h>
/* Jiaqi */
// #include <linux/kvm_types.h>
/* /Jiaqi */
#define DBG(fmt, ...) \
    do {printk ("%s(): " fmt, __func__, ##__VA_ARGS__); } while (0)

/*
#define DBG(fmt, ...) 
*/
// #define DBG(fmt, ...) 

#define ERR(fmt, ...) \
    do {printk ("%s(): " fmt, __func__, ##__VA_ARGS__); } while (0)

struct arg_blk
{
    int instrum_flag;
    int pl_switch;
    unsigned long exit_gate_addr;
    unsigned long t_idt_va;
    unsigned long t_gdt_va;
    unsigned long t_tss_va;//2 tss pages
    unsigned long t_idt_pa;
    unsigned long t_gdt_pa;
    unsigned long t_tss_pa;
    unsigned long t_tss1_pa;
    unsigned long t_tss2_pa;
    unsigned long stack_addr;//0x2c0 from tss + int 3 stack + data
    unsigned long root_pt_addr;
    unsigned long shar_va;
    unsigned long shar_pa;
    unsigned long ana_t_tss_va;
    unsigned long ana_t_tss_pa;
    unsigned long ana_t_gdt_va;
    unsigned long ana_t_gdt_pa;
    unsigned long pf_addr;
    unsigned long pf_stack;
    unsigned long vcpu_fd;
    unsigned long syscall_flag;
    unsigned long rip;
    unsigned long rsp;
    unsigned long rax;
    unsigned long rdi;
    unsigned long rsi;
    unsigned long rdx;
    unsigned long r10;
    unsigned long r8;
    unsigned long r9;
    unsigned long r11;
    unsigned long rcx;
    unsigned long ret_rax;
    unsigned long sstub_entry;
    unsigned long hard_cr3;
};
/* Jiaqi */
// extern struct arg_blk* imee_arg;
extern struct arg_blk imee_arg;

struct shar_arg
{
    volatile unsigned long flag;
    unsigned long rdi;
    unsigned long rsi;
    unsigned long rdx;
    unsigned long rcx;
    unsigned long r8;
    unsigned long r9;
    unsigned long r11;
    unsigned long r10;
    unsigned long rax;
    unsigned long eflags;
    unsigned long rip;
    unsigned long rsp;
    unsigned long rbx;
    unsigned long rbp;
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;
    // unsigned long long xmm0;
    // unsigned long long xmm1;
    // unsigned long long xmm2;
    // unsigned long long xmm3;
    // unsigned long long xmm4;
    // unsigned long long xmm5;
    // unsigned long long xmm6;
    // unsigned long long xmm7;
    unsigned long cr0;
    unsigned long cr2;
    unsigned long cr4;
    unsigned long efer;
    unsigned long gs_base;
    unsigned long msr_kernel_gs_base;
    unsigned long fs_base;
    unsigned long apic_base_addr;
    unsigned long apic_access_addr;
    unsigned long io_bitmap_a_addr;
    unsigned long io_bitmap_b_addr;
    unsigned long msr_bitmap_addr;
    unsigned long tsc_offset;
    unsigned long exit_reason;
    unsigned long exit_qualification;
    unsigned long inst_len;
    unsigned long event_flag;
    unsigned long entry_intr_info;
    unsigned long user_flag;
    unsigned long gdtr;
    unsigned long idtr;
    unsigned long tss_base;
    unsigned long tss_pg_off;
    unsigned long g_syscall_entry;
    unsigned long pf_entry;
    unsigned long int3_entry;
    volatile unsigned long guest_timeout_flag;
    volatile unsigned long exit_wrong_flag;
    volatile unsigned long cross_page_flag;
};
// extern struct shar_arg* ei_shar_arg;

// extern int dota_vcpu_id;
extern unsigned long analyzer_cr3;
extern unsigned long host_syscall_entry;
extern unsigned long host_pf_entry;
extern int kernel_idx;
extern unsigned long guest_syscall_entry;
extern int vmc_idx;
extern unsigned long ana_new_round_rip, ana_new_round_rsp;
extern int imee_up;

struct update_epte {
    unsigned long gfn;
    unsigned long spte;
    int level;
};
#ifndef _ringbuffer_h
#define _ringbuffer_h

#define ringBuffer_typedef(T, NAME) \
  typedef struct { \
    int size; \
    int start; \
    int end; \
    T* elems; \
  } NAME

#define bufferInit(BUF, S, T) \
  BUF.size = S; \
  BUF.start = 0; \
  BUF.end = 0; \
  BUF.elems = (T*)kcalloc(BUF.size, sizeof(T), GFP_KERNEL)

  // BUF.elems = (T*)kmalloc(BUF.size, sizeof(T))

ringBuffer_typedef(struct update_epte, intBuffer);

#endif

extern intBuffer* myBuffer_ptr;
int isBufferFull(intBuffer* BUF);
int isBufferEmpty(intBuffer* BUF);
int nextStartIndex(intBuffer* BUF);
int nextEndIndex(intBuffer* BUF); 
void bufferWrite(intBuffer* BUF, struct update_epte ELEM);
struct update_epte bufferRead(intBuffer* BUF);
/* The following structures are maintained to make the EPT redirection on target
 * pages more efficient */
// #define max_int3_pool 2
#define max_int3_pool 8
// #define max_pf_pool 200
// #define redirected_low_va 0xfffffefff7f06000
// #define redirected_high_va 0xfffffefff7fcd000
#define max_pf_pool 400
#define redirected_low_va 0xfffffefff7e3e000
#define redirected_high_va 0xfffffefff7fcd000
struct gva_hpa_pair {
    unsigned long a_gva;
    unsigned long hpa;
    unsigned long t_gva;
    unsigned long t_gpa;
    unsigned long a_epte;
    unsigned long t_epte;
    unsigned long *spt;
    // int int3_flg;
};
// struct int3_gva_hpa {
//     unsigned long a_gva;
//     unsigned long hpa;
//     unsigned long t_gva;
//     unsigned long t_gpa;
//     unsigned long a_epte;
//     unsigned long t_epte;
//     unsigned long *spt;
//     // int int3_flg;
// };
extern struct gva_hpa_pair gva_hpa_pool[max_pf_pool];
extern struct gva_hpa_pair int3_gva_hpa_pool[max_int3_pool];
extern int crt_pfpool_idx;
extern int crt_search_idx;
extern int pre_search_idx;
extern int int3_pool_idx;
/* / */

struct sig_record{
    void* sig_handler;
    // int index;
    // int flag;
};
// struct sig_record sig_array[64];
// EXPORT_SYMBOL_GPL (sig_array);
extern struct sig_record sig_array[64];

struct gpa_hpa{
    unsigned long gpa;
    unsigned long hpa;
};
/* /Jiaqi */
struct pt_mapping
{
    int lv;  // the level which the entry exits
    ulong e; // the paging structure entry
};

typedef struct introspection_context
{
    struct kvm* kvm;
    struct kvm_vcpu* target_vcpu;
    struct task_struct* task;

    ulong eptptr;
    /* Jiaqi */
    ulong s_eptptr;
    struct list_head s_leaf_page;
    struct list_head s_non_leaf_page;
    u64 cr3;
    /*  /Jiaqi*/

    ulong visited;

    struct list_head leaf_page; // leaf pages of EPT
    struct list_head non_leaf_page; // non-leaf pages of EPT

    struct list_head node; // linked to global list

    u64* code_ept_pte_p;
    u64 code_ept_pte;
    u64* data_ept_pte_p;
    u64 data_ept_pte;

} intro_ctx_t;

extern intro_ctx_t* current_target;

/* Jiaqi */
// struct gpa_hpa* get_hpa_from_gva (struct kvm* target_kvm, unsigned long gva, unsigned long guest_cr3);
struct gpa_hpa get_hpa_from_gva (struct kvm* target_kvm, unsigned long gva, unsigned long g_cr3);
unsigned long get_gpa_from_gva (struct kvm* target_kvm, unsigned long gva, unsigned long g_cr3);
// int prot_root_PT (unsigned long gpa, int permission);
int adjust_ept_entry_s (intro_ctx_t* ctx, unsigned long gpa, ulong eptptr, unsigned long new_pa);
ulong* get_ept_page (void);
void* alloc_non_leaf_page (struct list_head* non_leaf_page, int lv);
/* /Jiaqi */

#define PD_GPA (0xF0000000U)
#define PT_GPA_EXEC (0xF0001000U)
#define PT_GPA_DATA (0xF0002000U)
#define CODE_GPA (0xF0003000U)
#define DATA_GPA (0xF0004000U)


#define SCAN_ALL 1
#define SCAN_ONE 2
extern int imee_scan_mode;

extern volatile struct kvm_vcpu* imee_vcpu;
// extern int enable_notifier;
extern volatile int imee_pid;
extern spinlock_t sync_lock;
extern spinlock_t flag_r_lock;
extern spinlock_t flag_w_lock;
// extern volatile unsigned char go_flg;
// extern ulong code_hpa, data_hpa;
extern volatile unsigned long last_cr3;
extern volatile unsigned long onsite_cr3;
// extern volatile unsigned long last_rip, last_rsp;

volatile extern int exit_flg;
// extern int __tmp_counter;
// extern int __tmp_counter3;
volatile extern unsigned long switched_cr3;
// volatile extern int do_switch;
// extern unsigned long long imee_t;
// extern unsigned long long* ts_buffer1;
// extern volatile int ts_buffer_idx1;
// extern volatile int ts_buffer_idx1_limit;
extern spinlock_t sync_lock1;
// extern unsigned long update_gfn;
// extern unsigned long update_spte;
// extern unsigned long update_level;

// ulong get_ptr_guest_page (struct task_struct* target_proc, struct kvm* target_kvm, gpa_t gpa);
// u64* get_epte (intro_ctx_t* ctx, gpa_t gpa);
int remap_gpa (intro_ctx_t* ctx, ulong gpa);

// void copy_leaf_ept (struct list_head* leaf_page, struct kvm_arch* arch);
intro_ctx_t* kvm_to_ctx (struct kvm* target);
void switch_intro_ctx (intro_ctx_t* next, struct kvm_vcpu* vcpu);
// u64 make_imee_ept (struct list_head* leaf_page, struct list_head* non_leaf_page);
// extern added by Jiaqi
// extern int start_guest_intercept (struct kvm_vcpu *vcpu);
int start_guest_intercept (struct kvm_vcpu *vcpu);
// extern int start_guest_intercept (struct kvm_vcpu *vcpu, void* argp);
// extern int adjust_dota_context (struct kvm_vcpu *vcpu, void* argp);
int vcpu_entry(void);
int vcpu_reentry(void);
int adjust_dota_context (struct kvm_vcpu *vcpu);
struct kvm_vcpu* pick_cpu (struct kvm* target_kvm);

extern struct desc_ptr imee_idt, imee_gdt;
extern struct kvm_segment imee_tr;
// extern ulong code_entry;
// extern int trial_run;

extern intro_ctx_t* cur_ctx;

int kvm_imee_stop (struct kvm_vcpu* vcpu);
long kvm_imee_get_guest_context (struct kvm_vcpu *vcpu, void* argp);
// long kvm_imee_get_guest_context (struct kvm_vcpu *vcpu);
unsigned long trans_gva_into_hpa (unsigned long gva, unsigned long eptptr, unsigned long g_cr3);
unsigned long trans_gpa_into_hpa (unsigned long gpa, unsigned long eptptr);
unsigned long get_ptr_guest_page_64 (struct kvm* target_kvm, unsigned long gpa);

// extern unsigned long eptp_list;
extern unsigned long UK_OFFSET;
// extern void* shar_mem_ei;//ei_shar_arg between analyser and guest's hyp
#define user_start 0x7ff000000000UL
#define user_end 0x7ffff8000000UL
// #define user_end 0x7fffffffffffUL
// the address of onsite wrapper
#define onsite_wrapper_addr 0x7ff020300000UL
// the address of dummy_sighandler
#define dummy_handler_addr 0x7ff020600000UL
// the address of sigflag in dummy_sighandler
#define user_sigflag_addr 0x7ff020804000UL

// #define sstub_addr 0x7ff020900000UL

/* to install special descriptor table and stack and debug handler */
#define debug_handler_addr 0x7ff020900000UL//1 code page 
// #define root_pt_page 0x7ff020906000UL
// #define shar_addr 0x7ff020907000UL
// #define ana_t_tss_va 0x7ff020908000UL
// #define data_page_num 0x8000 //first half: 1 IDT page + 1 GDT page + 2 TSS page + 1 writable data page // second half: 1 page for root PT + 1 page for shar_mem; The second half is not mapped in t-EPT
#define data_page_num 0x9000 //first half: 1 IDT page + 1 GDT page + 2 TSS page + 1 writable data page // second half: 1 page for root PT + 1 page for shar_mem; The second half is not mapped in t-EPT
#define pf_handler_addr 0x7ff02090d000UL
/* / */

#endif
