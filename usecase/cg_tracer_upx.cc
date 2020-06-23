/*
   Copyright (C) 2015 Alin Mindroc
   (mindroc dot alin at gmail dot com)

   This is a sample program that shows how to use InstructionAPI in order to
   6  print the assembly code and functions in a provided binary.


   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   11  License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.
   */
#include <iostream>
#include "CodeObject.h"
#include "InstructionDecoder.h"
using namespace std;
using namespace Dyninst;
using namespace ParseAPI;

using namespace InstructionAPI;

/* Jiaqi */
#include <CodeSource.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
// #include "Symtab.h"
#include "Instruction.h"
#include "Register.h"
/* /Jiaqi */

#define DBG(fmt, ...) \

// #define DBG(fmt, ...) \
//     do {printf ("%s(): " fmt, __func__, ##__VA_ARGS__); } while (0)

/* Jiaqi */
// bool decodeInsns = false;
bool decodeInsns = true;
bool rand_exp = false;

FILE *out;

/* MyCodeRegion */
// class PARSER_EXPORT MyCodeRegion : public CodeRegion {
class MyCodeRegion : public CodeRegion {
    private:
        std::map<Address, Address> knowData;
    public:
        MyCodeRegion (Address add1, Address add2);
        ~MyCodeRegion();

        /* InstructionSource implementation */
        bool isValidAddress(const Address) const;
        void* getPtrToInstruction(const Address) const;
        void* getPtrToData(const Address) const;
        unsigned int getAddressWidth() const;
        bool isCode(const Address) const;
        bool isData(const Address) const;
        bool isReadOnly(const Address) const;

        Address offset() const;
        Address length() const;
        Architecture getArch() const;

        /** interval **/
        Address low() const { return offset(); }
        Address high() const { return offset() + length(); }
};

MyCodeRegion::~MyCodeRegion()
{

}

MyCodeRegion::MyCodeRegion(Address add1, Address add2)
{
    knowData[add1] = add2;//only one pair in this CodeRegion map
}

bool MyCodeRegion::isValidAddress(const Address addr) const
{
    // return true;
    return contains(addr);
}

void* MyCodeRegion::getPtrToInstruction(const Address addr) const
{
    if (isValidAddress(addr))
    {
        return (void*)addr;
    }
    return NULL;
}

void* MyCodeRegion::getPtrToData(const Address addr) const
{
    if (isValidAddress(addr))
    {
        return (void*)addr;
    }
    return NULL;
}

unsigned int MyCodeRegion::getAddressWidth() const
{
    // DBG ("in MyCodeRegion, getAddressWidth \n");
    // return 0x8;
    return 0x10;
    // return length();
}

bool MyCodeRegion::isCode(const Address addr) const
{
    return true;
}

bool MyCodeRegion::isData(const Address addr) const
{
    return false;
}

bool MyCodeRegion::isReadOnly(const Address addr) const
{
    return true;
}

Address MyCodeRegion::offset() const
{
    // printf ("in MyCodeRegion, offset \n");
    return knowData.begin()->first;
}

Address MyCodeRegion::length() const
{
    // printf ("in MyCodeRegion, length \n");
    return knowData.begin()->second - knowData.begin()->first ;
}

Architecture MyCodeRegion::getArch() const
{
    Architecture arch = Arch_x86_64;
    return arch;//TODO: 
}


/* MyCodeSource */

class PARSER_EXPORT MyCodeSource: public CodeSource {
    private:
        // void init_regions(Address add1, Address add2);
        void init_regions(Address adds, Address adde);
        void init_hints();

        mutable CodeRegion* _lookup_cache;
    public:
        // MyCodeSource(Address add1, Address add2);
        MyCodeSource(Address adds, Address adde);
        ~MyCodeSource();
        
        /* InstructionSource implementation */
        bool isValidAddress(const Address) const;
        void* getPtrToInstruction(const Address) const;
        void* getPtrToData(const Address) const;
        unsigned int getAddressWidth() const;
        bool isCode(const Address) const;
        bool isData(const Address) const;
        bool isReadOnly(const Address) const;

        Address offset() const;
        Address length() const;
        Architecture getArch() const;

        //newly added by Jiaqi
        void MyaddRegion (CodeRegion *cr)
        {
            addRegion(cr);
            // printf ("add a new code region \n");
            return;
        }

    private:
        CodeRegion* lookup_region(const Address addr) const;
};

void MyCodeSource::init_regions(Address adds, Address adde)
{
    MyCodeRegion *cr;
    // Address adds, adde;

    // adds = ;
    // adde = ;
    cr = new MyCodeRegion(adds, adde);
    MyaddRegion(cr);
}


void MyCodeSource::init_hints()//intialize the std::vector<Hint> _hints;
{
    // _hints.push_back(hint);
    return;
}

MyCodeSource::~MyCodeSource()
{

}

MyCodeSource::MyCodeSource(Address adds, Address adde)
{
    init_regions(adds, adde);
    // printf ("mycodesource initiated \n");
    init_hints();
}

inline CodeRegion* MyCodeSource::lookup_region(const Address addr) const
{
    CodeRegion *ret = NULL;
    if (_lookup_cache && _lookup_cache->contains(addr))
        ret = _lookup_cache;
    else {
        set<CodeRegion *> stab;
        int rcnt = findRegions(addr, stab);

        assert(rcnt <=1 || regionsOverlap());

        if (rcnt) {
            ret = *stab.begin();
            _lookup_cache = ret;
        }
    }
    // ret = _regions[0];
    return ret;
}

bool MyCodeSource::isValidAddress(const Address addr) const
{
    CodeRegion *cr = lookup_region(addr);
    if (cr)
    {
        return cr->isValidAddress(addr);
    }
    else
    {
        return false;
    }
}

void* MyCodeSource::getPtrToInstruction(const Address addr) const
{
    CodeRegion *cr = lookup_region(addr);
    if (cr)
    {
        return cr->getPtrToInstruction(addr);
    }
    else
    {
        return NULL;
    }
}

void* MyCodeSource::getPtrToData(const Address addr) const
{
    return NULL;
}

unsigned int MyCodeSource::getAddressWidth() const
{
    DBG ("in MyCodeSource, getAddressWidth \n");
    // return 0x8;
    return 0x10;
    // return _regions[0]->offset();
}

bool MyCodeSource::isCode(const Address addr) const
{
    return true;
}

bool MyCodeSource::isData(const Address addr) const
{
    return false;
}

bool MyCodeSource::isReadOnly(const Address addr) const
{
    return true;
}

Address MyCodeSource::offset() const
{
    DBG ("in MyCodeSource, offset \n");
    return _regions[0]->offset();
}

Address MyCodeSource::length() const
{
    DBG("in MyCodeSource, length \n");
    return _regions[0]->length();
}

Architecture MyCodeSource::getArch() const
{
    Architecture arch = Arch_x86_64;
    return arch;//TODO: 
}

// static __attribute__ ((noinline)) unsigned long long rdtsc(void)
// {
//     unsigned long long x;
//     asm volatile (".byte 0x0f, 0x31" : "=A"(x));
//     // asm volatile ("int $3;\n\t");
//     return x;
// }
static __attribute__ ((noinline)) unsigned long long rdtsc(void)
{
    unsigned hi, lo;
    asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    // asm volatile ("int $3;\n\t");
    return ((unsigned long long) lo | ((unsigned long long) hi << 32));
}

struct args_blk {
    unsigned long flag; //1: ready to receive request; 2: finish request; 0: new request;
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
    unsigned long syscall_entry;
    unsigned long guest_timeout_flag;
    unsigned long exit_wrong_flag;
    unsigned long cross_page_flag;
};

volatile struct args_blk* shar_args;

/* the following two structs is set for load and store convinience */
struct target_context {
    unsigned long eflags;
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;
    unsigned long rbp;
    unsigned long rbx;
    unsigned long r11;
    unsigned long r9;
    unsigned long r8;
    unsigned long r10;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
};
volatile struct target_context* target_ctx;

//the int 3 stack and dynamic probe share the same region to temporaly store
//target's rax & rcx
struct board_context {
    unsigned long selfw_exit_handler;
    unsigned long pf_exit_handler;
    unsigned long int3_exit_handler;
    unsigned long user_handler;
    // unsigned long reserved1;
    // unsigned long reserved2;
    unsigned long rcx;
    unsigned long rax;
    unsigned long rsp;
    unsigned long rip;
};
volatile struct board_context* board_ctx;

void cr0_wp_off (void)
{
    unsigned long cr0;
    asm ("movq %%cr0, %0;":"=r"(cr0)::);
    cr0 &= ~0x10000;
    asm ("movq %0, %%cr0;"::"r"(cr0):);
    return;
}

void cr0_wp_on (void)
{
    unsigned long cr0;
    asm ("movq %%cr0, %0;":"=r"(cr0)::);
    cr0 |= 0x10000;
    asm ("movq %0, %%cr0;"::"r"(cr0):);
    return;
}

// #define max_idx 200
// #define max_redirect_idx 135
// #define max_redirect_idx 200
#define max_redirect_idx 400
// #define ins_length 17
// #define ins_length 20
#define prob_length 7
#define prob_length_mask 0xf//adjust the mask according to the ins_length, if it is less than 16, set mask as 0xf; if larger than 16, set mask as 0xff; so on so forth
#define uk_border 0x800000000000
#define page_mask 0xfffUL
// #define syscallEntry 0xffffffff817f6ed0 
// #define syscallEntry 0xffffffff817f6ef0 
#define syscallEntry 0xffffffff817f6eef 
#define max_int3 10
#define len_int3_probe 13

MyCodeSource *sts;
CodeObject *co;
CodeRegion *cr;
Instruction::Ptr instr;
InstructionDecoder* decoder;
volatile InsnCategory crtCate;
volatile Address crtAddr;
// volatile int crt_ins_length;

volatile Address target_cr2;
volatile Address lasttransAddr;
volatile Address pf_handler_addr;//the address of target's PF handler
volatile Address iret_to_rip;//the rip that triggers the PF
// Address target1, target2;
Address lastAddr, initAddr;

Address redirected_pages[max_redirect_idx];
Address new_pages[max_redirect_idx];
Address offsets[max_redirect_idx];

unsigned long exit_gate_va;
unsigned long idt_va;
unsigned long gdt_va;
unsigned long tss_va;
unsigned long data_page;
unsigned long root_pt_va;
unsigned long shar_mem;
unsigned long ana_t_tss;
unsigned long ana_t_gdt;
unsigned long ana_stack;
unsigned long f_trampoline;
unsigned long pf_exit;//the resume rip in ana if there is a pf
unsigned long cg_exit;//the exit gate addr for dynamic call gate based probe
unsigned long ana_fs_base;
unsigned long target_fs_base;
unsigned long pf_stack;
unsigned long* gdt_base;
unsigned long addr_tss_base;
unsigned long breakpoint1;
unsigned long breakpoint2;
unsigned long breakpoint3;
unsigned long breakpoint4;
int debug_flag;

int crt_max_redir_idx;//the current max number of redirected pages
int crt_redir_idx; //indicate the idx of the current in use redirected page

char saved_instr[prob_length];
char d_prob_instr[prob_length];
unsigned long cg_sel_addr_u;
unsigned long cg_sel_addr_u_1;
unsigned long cg_sel_addr_lib;
unsigned long cg_sel_addr_k;
unsigned long cg_sel_u;
unsigned long cg_sel_lib;
unsigned long cg_sel_k;
char per_hook[0x1];
unsigned long orig_addr_int3[max_int3];
char orig_instr_int3[max_int3];
int int3_array_idx;
unsigned long int3_stack;
unsigned long addr_indt_call, addr_sys_ioctl, addr_drv_ioctl, addr_drv;
unsigned long int3_o_addr;

unsigned long search_cg_addr;

int bb_count;
int loop_idx;
int dyn_pro_idx;

// int syscall_idx;
int pg_trans_count;
int pf_count;
int syscall_count;
int selfw_count;

// int temp_direct_count;
// int call_count, jmp_count, ret_count;
// int temp_indirect_count;

unsigned long long t0, t1;
unsigned long long tt, tt0, tt1;
unsigned long long ttt, ttt0, ttt1;

// #define max_u_bb 1000 
// #define max_k_bb 1000
// struct bb_info u_bb_recording[max_u_bb];
// struct bb_info k_bb_recording[max_k_bb];
#define k_u 2
// #define max_bb 1106
// #define max_bb 1606
// #define max_bb 1906
// #define max_bb 3206
#define max_bb 5206
/* structure to maintain the store information of a basic block */
struct bb_info {
    Address entry_addr;
    Address exit_addr;
    Address target1;
    Address target2;
    InsnCategory category;//the instruction category of the exit instruction
    entryID operation_id;
    // int exit_ins_length;//the length of the instruction at the exit_addr
    bool resolved;
    bool aft;
    bool readmem;
    // Instruction exit_instr;
    // Expression exit_expre;
};
struct bb_info bb_recording[k_u][max_bb];
int k_u_indicator;//1: user; 0: kernel
int crt_bb_idx;
int crt_max_u_idx, crt_max_k_idx;

/* initialize page_pool */
typedef struct pool
{
    void* init;
    void* next;
    void* end;
} POOL;

POOL* page_pool;

void init_w_page (void);
void new_round (void);
void switch_to_ring0 (void);
void restore_user_privilege (void);

void pool_create (size_t size)
{
    void* temp = valloc(size);
    page_pool->init = temp;
    page_pool->next = temp;
    page_pool->end = temp + size;
    
    memset (temp, 0x0, size);
    
    printf ("redirected page start from :%p. ends : %p. \n", temp, page_pool->end);
    return;
}

void pool_destroy (POOL *p)
{
    free(p);
}

size_t pool_available (POOL* p)
{
    return (unsigned long)p->end - (unsigned long)p->next;
}

void* pool_alloc (POOL* p, size_t size)
{
    if (pool_available(p) < size)
    {
        return NULL;
    }
    void* mem = (void*) p->next;
    p->next += size;
    return mem;
}
/* / */

void hypercall (void* ker_addr)
{
    // ttt0 = rdtsc ();
    
    if (crt_max_redir_idx == max_redirect_idx)
    {
        printf ("new_pages used up. \n");
        asm volatile ("movq $0x999999, %%rax; \n\t"
                "vmcall; \n\t"
                :::"%rax");
    }

    // /* vmcall to set PF bit in exception_bitmap */
    // asm volatile ("movq $0xaaaaa, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");
    // /* / */

    // void* new_va = valloc (0x1000);
    void* new_va = pool_alloc (page_pool, 0x1000);
    // printf ("new_va: %lx. ker_addr: %lx. \n", new_va, ker_addr);

    memcpy (new_va, ker_addr, 0x1000);

    // if ((((unsigned long) new_va) & 0xfff) != 0)
    // {
    //     printf ("non-align va: %lx. \n", new_va);
    // }

    /* issue a hypercall to request ept redirection for new page */
    asm volatile ("movq $0xabcd, %%rbx; \n\t"
            "movq %0, %%rax; \n\t"
            "movq %1, %%rcx; \n\t"
            "lea 0x2(%%rip), %%rdx; \n\t"
            "jmpq *%%rax; \n\t"
            ::"m"(ker_addr), "m"(new_va):"%rax","%rbx","%rcx");
    /* / */

    redirected_pages[crt_max_redir_idx] = (Address) ker_addr;
    new_pages[crt_max_redir_idx] = (Address) new_va;
    if (((unsigned long)ker_addr) < uk_border)
    {
        offsets[crt_max_redir_idx] = (((Address)new_va - (Address)ker_addr));
    }
    else
    {
        offsets[crt_max_redir_idx] = ((Address)ker_addr) - ((Address)new_va);
    }
    
    /* update the crt_redir_idx */
    crt_redir_idx = crt_max_redir_idx;
    
    crt_max_redir_idx ++;
    
    // ttt1 = rdtsc();
    // ttt += ttt1 - ttt0;
    // /* vmcall to clear PF bit in exception_bitmap */
    // asm volatile ("movq $0xbbbbb, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");
    // /* / */
    
    // printf ("new_va: %lx. t_ker_addr: %lx. crt_idx: %d, crt_max_redir_idx: %d. \n", new_va, ker_addr, crt_redir_idx, crt_max_redir_idx);
    // printf ("new_va: %lx. ker_addr: %lx, crt_idx: %d. \n", new_va, ker_addr, crt_idx);

    return;
}

// only when transfer to another page, ana needs to search index
int search_crt_redir_idx (Address tempAddr)
{
    int i;
    // int temp_idx = crt_redir_idx;

    for (i = 0; i < crt_max_redir_idx; i ++)
    {
        if (tempAddr == redirected_pages[i])
        {
            /* update the crt_redir_idx */
            crt_redir_idx = i;
            // printf ("update crt_idx as: %d. tempAddr: %lx. \n", crt_redir_idx, tempAddr);
            // if (temp_idx != crt_redir_idx)
            // {
            unsigned long ker_addr = tempAddr;
            unsigned long new_va = new_pages[i];

            /* issue a hypercall to request ept redirection for new page */
            asm volatile ("movq $0xabcd, %%rbx; \n\t"
                    "movq %0, %%rax; \n\t"
                    "movq %1, %%rcx; \n\t"
                    "lea 0x2(%%rip), %%rdx; \n\t"
                    "jmpq *%%rax; \n\t"
                    ::"m"(ker_addr), "m"(new_va):"%rax","%rbx","%rcx");
            memcpy ((void*)new_va, (void*)ker_addr, 0x1000);
            /* / */
            // }
            return 1;
        }
    }
    // return crt_max_idx;
    return 0;
}

int cross_flag;//indicate whether it is a cross page hook in last hook
int cross_hook_idx;//record the cross_page_idx besides the crt_idx
int cross_hook_n_idx;
int cross_hook_length;//record the instruction length in cross_page_idx page

void install_cg (int idx, int ring)
{
    unsigned long* temp_gdt;
    unsigned long call_gate_entry;
    unsigned long call_gate_addr;

    // idx = idx >> 3;
    call_gate_addr = cg_exit;
    // temp_gdt = (unsigned long*) shar_args->gdtr;
    temp_gdt = (unsigned long*) ana_t_gdt;
    // // if (!temp_gdt[idx] && !temp_gdt[idx+1])
    // if ((idx != 32) && (idx != 480))
    // {
        // call_gate_entry = (call_gate_addr & 0xffff) | (0x10 << 16) | ((unsigned long) (0xec00) << 32) | (((call_gate_addr >> 16) & 0xffff) << 48);
        call_gate_entry = (call_gate_addr & 0xffff) | (ring << 16) | ((unsigned long) (0xec00) << 32) | (((call_gate_addr >> 16) & 0xffff) << 48);
        temp_gdt[idx] = call_gate_entry;
        call_gate_entry = (call_gate_addr >> 32) & 0xffffffff;
        temp_gdt[idx + 1] = call_gate_entry;
        printf ("idx: %d, gdt entry: %lx, %lx, \n", idx, temp_gdt[idx], temp_gdt[idx+1]);
    // }
    // else
    // {
    //     printf ("the entry is filled, find another one. \n");
    //     asm volatile ("movq $0x9843211, %%rax; \n\t"
    //             "vmcall; \n\t"
    //             :::"%rax");
    // }
    // asm volatile ("clflush (%0)" :: "r"(&(temp_gdt[12])));
    return; 
}

/* search cg in crtAddr page */
unsigned long search_cg ()
{
    unsigned long cg;
    // unsigned long search_cg_addr = crtAddr & ~0xfff;
    // int i = 0;
    unsigned long page_bound;
    page_bound = (crtAddr & ~0xfff) + 0x1000 - 2;
    printf ("crtAddr: %lx, search_cg_addr: %lx, page_bound: %lx. \n", crtAddr, search_cg_addr, page_bound);
    // for (i = 8; i < 4092; i ++)
    for (search_cg_addr; search_cg_addr < page_bound; search_cg_addr += 2)
    {
        cg = *((unsigned long*) search_cg_addr);
        cg &= 0xffff;
        if (cg >= 0x50 && cg <= 0xff3 && !(cg>>2 & 0x1))
        {
            printf ("usable cg found, search_addr: %lx, %lx. \n", search_cg_addr, cg);
            // cg_sel_addr_u = search_addr - 0x8;

            break;
        }
        // search_addr += 0x4;
    }
    // if (i == 4092)
    if (search_cg_addr >= (page_bound))
    {
        printf ("no call gate found in current RIP page. \n");
        asm volatile ("movq $0x9843211, %%rax; \n\t"
                "vmcall; \n\t"
                :::"%rax");
    }
    return cg;
}

/* update d_prob_instr based on crtAddr */
void update_d_probe(void)
{
    /* update d_prob_instr based on the offset between c_rip and call_gate_sel_addr */
    char cr[4];
    int off;
    
    unsigned long tmp = crtAddr >> 31;
    unsigned long tmp_cg;
    unsigned long* tmp_ptr;
    unsigned long tmp_sel;
    if (tmp == (cg_sel_addr_u >> 31))
    {
        // printf ("crtAddr: %lx. \n", crtAddr);
        // asm volatile ("movq $0x9843211, %%rax; \n\t"
        //         "vmcall; \n\t"
        //         :::"%rax");
        
        off = (int) cg_sel_addr_u - ((int) crtAddr + (int) prob_length);
        tmp_ptr = (unsigned long*)(cg_sel_addr_u+0x8);
        tmp_sel = *tmp_ptr;
        tmp_sel &= 0xffff;
        tmp_sel = tmp_sel >> 2;
        // if (*tmp_ptr != 0x01c38348dc14ff41)
        /* for upx packed uname */
        // if (*tmp_ptr != 0x01e083c231e8d3f0)
        if (tmp_sel != cg_sel_u)
        {
            printf ("prob_u does not match. \n");
            // /* debug */
            search_cg_addr = crtAddr & ~0xfff;
            int idx;
            while (true)
            {
                idx = search_cg();
                idx = idx >> 2;
                if ((idx != cg_sel_lib) && (idx != cg_sel_k))
                    break;
            }
            cg_sel_addr_u = search_cg_addr - 0x8;
            // cg_sel_addr_u = search_cg_addr - 0xa;
            cg_sel_u = idx;
            idx = idx >> 1;
            install_cg (idx, 0x33);
            off = (int) cg_sel_addr_u - ((int) crtAddr + (int) prob_length);
            printf ("crtAddr: %lx. in updating cg for u as : %lx. \n", crtAddr, cg_sel_addr_u);
            // tmp_ptr = (unsigned long*) crtAddr;
            // int i = 0;
            // for (i = 0; i < 8; i ++)
            // {
            //     printf ("addr: %p, content: %lx. \n", &tmp_ptr[i], tmp_ptr[i]);
            // }
            // /* / */
            // asm volatile ("movq $0x9843211, %%rax; \n\t"
            //         "vmcall; \n\t"
            //         :::"%rax");
        }
        tmp_cg = cg_sel_addr_u;
    }
    else if (tmp == (cg_sel_addr_lib >> 31))
    {
        off = (int) cg_sel_addr_lib - ((int) crtAddr + (int) prob_length);
        // tmp_ptr = (unsigned long*)(cg_sel_addr_lib+0x2);
        // if (*tmp_ptr != 0x01039d1c8d48e839)
        // {
        //     printf ("prob_lib does not match. \n");
        //     asm volatile ("movq $0x9843211, %%rax; \n\t"
        //             "vmcall; \n\t"
        //             :::"%rax");
        // }
        tmp_ptr = (unsigned long*)(cg_sel_addr_lib+0x8);
        tmp_sel = *tmp_ptr;
        tmp_sel &= 0xffff;
        tmp_sel = tmp_sel >> 2;
        // if (*tmp_ptr != 0x01c38348dc14ff41)
        /* for upx packed uname */
        // if (*tmp_ptr != 0x01e083c231e8d3f0)
        if (tmp_sel != cg_sel_lib)
        {
            printf ("prob_lib does not match. \n");
            // /* debug */
            search_cg_addr = crtAddr & ~0xfff;
            int idx;
            while (true)
            {
                idx = search_cg();
                idx = idx >> 2;
                if ((idx != cg_sel_u) && (idx != cg_sel_k))
                    break;
            }
            cg_sel_addr_lib = search_cg_addr - 0x8;
            // cg_sel_addr_lib = search_cg_addr - 0xa;
            cg_sel_lib = idx;
            idx = idx >> 1;
            install_cg (idx, 0x33);
            off = (int) cg_sel_addr_lib - ((int) crtAddr + (int) prob_length);
            printf ("crtAddr: %lx. in updating cg for lib. as: %lx. \n", crtAddr, cg_sel_addr_lib);
            // tmp_ptr = (unsigned long*) crtAddr;
            // int i = 0;
            // for (i = 0; i < 8; i ++)
            // {
            //     printf ("addr: %p, content: %lx. \n", &tmp_ptr[i], tmp_ptr[i]);
            // }
            // /* / */
            // asm volatile ("movq $0x9843211, %%rax; \n\t"
            //         "vmcall; \n\t"
            //         :::"%rax");
        }
        tmp_cg = cg_sel_addr_lib;
    }
    else if (tmp == (cg_sel_addr_k >> 31))
    {
        off = (int) cg_sel_addr_k - ((int) crtAddr + (int) prob_length);
        tmp_ptr = (unsigned long*)(cg_sel_addr_k+0x2);
        if (*tmp_ptr != 0x0f00000273e9ff83)
        {
            printf ("prob_k does not match. \n");
            asm volatile ("movq $0x9843211, %%rax; \n\t"
                    "vmcall; \n\t"
                    :::"%rax");
        }
        tmp_cg = cg_sel_addr_k;
    }
    else
    {
        printf ("crtAddr out of scope, crtAddr: %lx. bb_count: %d. \n", crtAddr, bb_count);
        asm volatile ("movq $0x9843211, %%rax; \n\t"
                "vmcall; \n\t"
                :::"%rax");
    }
    
    tmp = crtAddr + prob_length;
    if (tmp >= tmp_cg && tmp <= (tmp_cg+0xa))
    {
        printf ("cg overlap found, crtAddr: %lx, cg_addr: %lx. \n", crtAddr, tmp_cg);
        asm volatile ("movq $0x9843211, %%rax; \n\t"
                "vmcall; \n\t"
                :::"%rax");
        if (tmp_cg == cg_sel_addr_u)
        {
            tmp_ptr = (unsigned long*)(cg_sel_addr_u_1+0x2);
            /* for uname, ls, pwd */
            if (*tmp_ptr != 0x0090838948ef2383)
            /* for superpi without printf */
            // // if (*tmp_ptr != 0x0cc8258d4c5441d5)
            // if (*tmp_ptr != 0x0d08258d4c5441d5)
            /* for superpi with printf */
            // if (*tmp_ptr != 0x0518258d4c5441d5)
            {
                printf ("prob_u_1 does not match. \n");
                asm volatile ("movq $0x9843211, %%rax; \n\t"
                        "vmcall; \n\t"
                        :::"%rax");
            }
            
            off = (int) cg_sel_addr_u_1 - ((int) crtAddr + (int) prob_length);
        }
        else
        {
            asm volatile ("movq $0x9843211, %%rax; \n\t"
                    "vmcall; \n\t"
                    :::"%rax");
        }
    }

    
    cr[0] = off & 0xff;
    cr[1] = (off >> 8) & 0xff;
    cr[2] = (off >> 16) & 0xff;
    cr[3] = (off >> 24) & 0xff;
    memcpy (&d_prob_instr[3], &cr[0], 0x4);
    // printf ("off: 0x%lx. crtAddr: 0x%lx. ins_length: %d. \n", off, crtAddr, ins_length);
    // printf ("off: 0x%lx. crtAddr: 0x%lx. \n", off, crtAddr);
    // int i = 0;
    // for (i = 0; i < 7; i ++)
    // {
    //     printf ("i: %d, : %x. \n", i, d_prob_instr[i]);
    // }
    return;
}

/* check if it is a cross page hook */
void handle_cross_page (Address tempAddr)
{
    /* save instruction first */
    memcpy (saved_instr, (void*)crtAddr, prob_length);//backup the bytes in the new hooked place
   
    cross_hook_length = prob_length_mask + 1 - (crtAddr & prob_length_mask);
    // cross_hook_length = 0x10 - (crtAddr & 0xf);
     
    update_d_probe();

    if (((unsigned long) crtAddr) < uk_border)
    {
        memcpy ((void*)(crtAddr+offsets[crt_redir_idx]), d_prob_instr, cross_hook_length);//install the new hook
    }
    else
    {
        memcpy ((void*)(crtAddr-offsets[crt_redir_idx]), d_prob_instr, cross_hook_length);//install the new hook

    }
    // printf ("local va: %lx. ker_add: %lx. crt_idx: %d.\n", crtAddr-offsets[crt_idx], crtAddr, crt_idx);
    // printf ("local va: %lx.\n", *((unsigned long*)0x7ff0002e0ff5));
    // printf ("local va: %lx.\n", *((unsigned long*)0x7ff0002e0ff8));
    
    cross_flag = 1;
    shar_args->cross_page_flag = 1;
    
    cross_hook_idx = crt_redir_idx;
    
    int ret = search_crt_redir_idx (tempAddr + 0x1000);
    if (!ret)
    {
        hypercall((void*)(tempAddr+0x1000));
    }

    /* to test */
    cross_hook_n_idx = crt_redir_idx;
    crt_redir_idx = cross_hook_idx;
 
    memcpy ((void*)(new_pages[cross_hook_n_idx]), d_prob_instr+cross_hook_length, prob_length - cross_hook_length);//install the new hook

    // asm volatile("mfence; \n\t");

    // printf ("new_page; %lx. content: %lx. \n", new_pages[cross_hook_n_idx], *((unsigned long*)new_pages[cross_hook_n_idx]));
    
    // printf ("local va: %lx. ker_add: %lx. cross_hook_n_idx: %d.\n", new_pages[cross_hook_n_idx], crtAddr, cross_hook_n_idx);
    
    // printf ("installed hook : %lx. : %lx. \n", *((unsigned long*)crtAddr), *((unsigned long*)(crtAddr+0x8)));
    
    // printf ("installed hook : %lx. : %lx. \n", *((unsigned long*)0xffffffff81218ff5), *((unsigned long*)0xffffffff81219000));
    
    // printf("cross_hook_length: %d, cross_hook_idx: %d,  cross_hook_n_idx: %d. \n", cross_hook_length, cross_hook_idx,  cross_hook_n_idx); 
   
    // asm volatile ("vmcall; \n\t");
    return;
}


/* check if last hook is a cross page hook */
void restore_cross_hook ()
{
    if (crtAddr < uk_border)
    {
        memcpy ((void*)(crtAddr + offsets[cross_hook_idx]), saved_instr, cross_hook_length);
    }
    else
    {
        memcpy ((void*)(crtAddr - offsets[cross_hook_idx]), saved_instr, cross_hook_length);
    }
    memcpy ((void*)(new_pages[cross_hook_n_idx]), saved_instr + cross_hook_length, prob_length - cross_hook_length);
    
    cross_flag = 0;
    shar_args->cross_page_flag = 0;

    /* to save cross page instruction */
    if (((crtAddr+instr->size()) & ~ 0xfff) != (crtAddr & ~0xfff))
    {
        crt_redir_idx = cross_hook_n_idx;
        
        /* $0x1 tells hyp to restall t-data-page for pre_search_idx */
        asm volatile ("mov $0xabcdef, %%rax; \n\t"
                "movq $0x1, %%rbx; \n\t"
                "vmcall; \n\t"
                :::"%rax","%rbx");
    }
    else
    {
        /* $0x0 tells hyp to restall t-data-page for crt_search_idx */
        asm volatile ("mov $0xabcdef, %%rax; \n\t"
                "movq $0x0, %%rbx; \n\t"
                "vmcall; \n\t"
                :::"%rax","%rbx");

    }

    return;
}

void hook_for_trans_ins (Address tempAddr)
{
    // Address tmpAddr = tempAddr & ~0xfff;
    // update crt_redir_idx when install hook in a different page.
    // /* debug */
    // if (crtAddr == 0xffffffff817f300f)
    // {
    //     printf ("crt_redir_idx: %d, new_va: %lx. offset: %lx. u_k_indicator: %d. \n", crt_redir_idx, new_pages[crt_redir_idx], offsets[crt_redir_idx], k_u_indicator);
    // }
    /* / */
    if (tempAddr != redirected_pages[crt_redir_idx])
    {
        int ret = search_crt_redir_idx (tempAddr);
        if (!ret)
        {
            // printf ("issue hyp call. \n");
            hypercall ((void*) tempAddr);
        
        }
        pg_trans_count ++;
    }
    // printf ("crtAddr: %lx. \n", crtAddr);
    
    if (((crtAddr + prob_length) & ~0xfff) != tempAddr)
    {
        handle_cross_page (tempAddr);
        // printf ("cross page hook found. crtAddr: %lx. bb_count: %d. \n", crtAddr, bb_count);
        // asm volatile ("movq $0x9843211, %%rax; \n\t"
        //         "vmcall; \n\t"
        //         :::"%rax");
    }
    else
    {
        /* the fifth step is to backup the bytes in the new hooked place, and
         * then install the new hook */
        memcpy (saved_instr, (void*)crtAddr, prob_length);//backup the bytes in the new hooked place
        update_d_probe();
        if (crtAddr < uk_border)
        {
            memcpy ((void*)(crtAddr+offsets[crt_redir_idx]), d_prob_instr, prob_length);//install the new hook
        }
        else
        {
            memcpy ((void*)(crtAddr-offsets[crt_redir_idx]), d_prob_instr, prob_length);//install the new hook
            // printf ("prob:%lx, orig: %lx. \n", *((unsigned long*) crtAddr), *((unsigned long*)(crtAddr-offsets[crt_redir_idx])));
        }
    }
   
    // /* debug */
    // if (crtAddr == 0xffffffff817f300f)
    // {
    //     printf ("bb_count: %d, crt_redir_idx: %d, new_va: %lx. offset: %lx. u_k_indicator: %d. \n", bb_count, crt_redir_idx, new_pages[crt_redir_idx], offsets[crt_redir_idx], k_u_indicator);
    // }
    // /* / */
    /* for testing */
    // if (crtAddr == 0xffffffff812190b0)
    // {
    //     printf ("check hook: %lx. \n", *((unsigned long*)crtAddr));
    // }
    return;
}

// void hook_for_seq_ins (Address tempAddr)
// {
//     printf ("crtAddr: %lx. \n", crtAddr);
//     
//     if (((crtAddr + ins_length) & ~0xfff) != tempAddr)
//     {
//         handle_cross_page (tempAddr);
//         // printf ("cross page hook found. \n");
//         // asm volatile ("vmcall; \n\t");
//     }
//     else
//     {
//         /* the fifth step is to backup the bytes in the new hooked place, and
//          * then install the new hook */
//         memcpy (saved_instr, (void*)crtAddr, ins_length);//backup the bytes in the new hooked place
//         if (crtAddr < uk_border)
//         {
//             memcpy ((void*)(crtAddr+offsets[crt_idx]), new_instr, ins_length);//install the new hook
//         }
//         else
//         {
//             memcpy ((void*)(crtAddr-offsets[crt_idx]), new_instr, ins_length);//install the new hook
//         }
//     }
//     
//     /* for testing */
//     // if (crtAddr == 0xffffffff812190b0)
//     // {
//     //     printf ("check hook: %lx. \n", *((unsigned long*)crtAddr));
//     // }
//     return;
// }

// Expression::Ptr bind_value_for_exp (Expression::Ptr target)
void bind_value_for_exp (Expression::Ptr target)
{
    // std::set<RegisterAST::Ptr> regsRead;
    // // (*(operands.begin())).getReadSet(regsRead);
    // instr->getReadSet(regsRead);

    std::vector<Operand> operands;
    instr->getOperands (operands);
    Address tempTarget;
    for (auto iter = operands.begin(); iter != operands.end(); iter++)
    {
        // cout << (*iter).format(Arch_x86_64, 0) << endl;
        std::set<RegisterAST::Ptr> regsRead;
        (*iter).getReadSet(regsRead);
        for (auto iter = regsRead.begin(); iter != regsRead.end(); iter++)
        {
            // printf ("id: %lx. \n", ((*iter)->getID()));
            switch ((*iter)->getID())
            {
                // signed int GPR = 0x00010000
                RegisterAST* rast;
                case Arch_x86_64+0x10000 : //rax
                    rast = new RegisterAST(x86_64::rax);
                    tempTarget = board_ctx->rax;
                    target->bind(rast, Result(s64, tempTarget));
                    break;
                case Arch_x86_64+0x10001 : //rcx
                    rast = new RegisterAST(x86_64::rcx);
                    tempTarget = board_ctx->rcx;
                    target->bind(rast, Result(s64, tempTarget));
                    break;
                case Arch_x86_64+0x10002 : //rdx
                    rast = new RegisterAST(x86_64::rdx);
                    tempTarget = target_ctx->rdx;
                    target->bind(rast, Result(s64, tempTarget));
                    break;
                case Arch_x86_64+0x10003 : //rbx
                    rast = new RegisterAST(x86_64::rbx);
                    tempTarget = target_ctx->rbx;
                    target->bind(rast, Result(s64, tempTarget));
                    break;
                case Arch_x86_64+0x10004 : //rsp
                    rast = new RegisterAST(x86_64::rsp);
                    tempTarget = board_ctx->rsp;
                    target->bind(rast, Result(s64, tempTarget));
                    break;
                case Arch_x86_64+0x10005 : //rbp
                    rast = new RegisterAST(x86_64::rbp);
                    tempTarget = target_ctx->rbp;
                    target->bind(rast, Result(s64, tempTarget));
                    break;
                case Arch_x86_64+0x10006 : //rsi
                    rast = new RegisterAST(x86_64::rsi);
                    tempTarget = target_ctx->rsi;
                    target->bind(rast, Result(s64, tempTarget));
                    break;
                case Arch_x86_64+0x10007 : //rdi
                    rast = new RegisterAST(x86_64::rdi);
                    tempTarget = target_ctx->rdi;
                    target->bind(rast, Result(s64, tempTarget));
                    break;
                case Arch_x86_64+0x10008 : //r8
                    rast = new RegisterAST(x86_64::r8);
                    tempTarget = target_ctx->r8;
                    target->bind(rast, Result(s64, tempTarget));
                    break;
                case Arch_x86_64+0x10009 : //r9
                    rast = new RegisterAST(x86_64::r9);
                    tempTarget = target_ctx->r9;
                    target->bind(rast, Result(s64, tempTarget));
                    break;
                case Arch_x86_64+0x1000a : //r10
                    rast = new RegisterAST(x86_64::r10);
                    tempTarget = target_ctx->r10;
                    target->bind(rast, Result(s64, tempTarget));
                    break;
                case Arch_x86_64+0x1000b : //r11
                    rast = new RegisterAST(x86_64::r11);
                    tempTarget = target_ctx->r11;
                    target->bind(rast, Result(s64, tempTarget));
                    break;
                case Arch_x86_64+0x1000c : //r12
                    rast = new RegisterAST(x86_64::r12);
                    tempTarget = target_ctx->r12;
                    target->bind(rast, Result(s64, tempTarget));
                    break;
                case Arch_x86_64+0x1000d : //r13
                    rast = new RegisterAST(x86_64::r13);
                    tempTarget = target_ctx->r13;
                    target->bind(rast, Result(s64, tempTarget));
                    break;
                case Arch_x86_64+0x1000e : //r14
                    rast = new RegisterAST(x86_64::r14);
                    tempTarget = target_ctx->r14;
                    target->bind(rast, Result(s64, tempTarget));
                    break;
                case Arch_x86_64+0x1000f : //r15
                    rast = new RegisterAST(x86_64::r15);
                    tempTarget = target_ctx->r15;
                    target->bind(rast, Result(s64, tempTarget));
                    break;

                // case Arch_x86_64+0x10010 : //rip
                case Arch_x86_64+0x00010 : //rip
                    rast = new RegisterAST(x86_64::rip);
                    // crtAddr = board_ctx->rip;
                    // crtAddr = crtAddr + instr->size(); 
                    // target->bind(rast, Result(s64, crtAddr));
                    tempTarget = crtAddr;
                    // printf ("tempTarget: %lx. \n", tempTarget);
                    tempTarget += instr->size();
                    // printf ("instruction length: %lx. tempTarget: %lx. \n", instr->size(), tempTarget);
                    target->bind(rast, Result(s64, tempTarget));
                    // printf ("rip. \n");
                    break;

                default:
                    asm volatile ("vmcall; \n\t");
            }
        }
    }
    return;
}

bool if_condition_fail (entryID opera_id)
{
    int ret;
    unsigned long eflags;
    eflags = target_ctx->eflags;
    bool cf, pf, zf, sf, of;
    cf = eflags & 0x1;
    pf = (eflags >> 2) & 0x1;
    zf = (eflags >> 6) & 0x1;
    sf = (eflags >> 7) & 0x1;
    of = (eflags >> 11) & 0x1;

    ret = 0;
   
    /* the index operation is in dyninst/common/h/entryIDs.h */
    // switch (instr->getOperation().getID())
    switch (opera_id)
    {
        case e_jnbe:
        // if (cf && zf)
            if (cf || zf)
                ret = 1;
                break;
        case e_jb: 
            if (!cf)
                ret = 1;
                break;
        case e_jnb: 
            if (cf)
                ret = 1;
                break;
        case e_jnb_jae_j: 
            if (cf)
                ret = 1;
                break;
        case e_jb_jnaej_j:
            if (!cf)
                ret = 1;
                break;
        case e_jbe:
            if ((!cf) && (!zf))
                ret = 1;
                break;
        case e_jz:
            if (!zf)
                ret = 1;
                break;
        case e_jnz:
            if (zf)
                ret = 1;
                break;

        case e_jnp:
            if (pf)
                ret = 1;
                break;
        case e_jp: 
            if (!pf)
                ret = 1;
                break;
        case e_jcxz_jec:
            int ecx;
            ecx = (int) (board_ctx->rcx & 0xffffffff);
            // printf ("jcx instruction. crtAddr: %lx. ecx: %lx rcx: %lx . \n", crtAddr, ecx, board_ctx->rcx);
            // asm volatile ("vmcall; \n\t");
            if (ecx)
                ret = 1;
                break;
    /* singed conditional jumps */
        case e_jnle:
        // if (zf && (sf ^ of))
            if (zf || (sf ^ of))
                ret = 1;
                break;
        case e_jnl:
            if ((sf ^ of))
                ret = 1;
                break;
        case e_jl:
            if (!(sf ^ of))
                ret = 1;
                break;
        case e_jle:
        // if (!((sf ^ of) && zf))
            if (!((sf ^ of) || zf))
                ret = 1;
                break;
        case e_jno:
            if (of)
                ret = 1;
                break;
        case e_jns:
            if (sf)
                ret = 1;
                break;
        case e_jo:
            if (!of)
                ret = 1;
                break;
        case e_js: 
            if (!sf)
                ret = 1;
                break;
        default :
            printf ("////conditional jump. curAddr: %lx \n", crtAddr);
            asm volatile ("vmcall; \n\t");
    }

    return ret;
}

// volatile void switch_to_ring0 (void)
void switch_to_ring0 (void)
{
    void* mem = malloc (10);
    asm volatile ("movq %%rsp, %%rdx; \n\t"
            "movq %0, %%rdi; \n\t"
            "movq $0xffff, %%rsi; \n\t"
            "movq %%rsi, (%%rdi); \n\t"
            "movq $0x63, 0x8(%%rdi); \n\t"
            "REX.W lcall *(%%rdi); \n\t"
            "movq %%rdx, %%rsp; \n\t"
            ::"m"(mem):"%rdi","%rsi", "%rdx");
    return;
}

void restore_user_privilege (void)
{
    asm volatile (
            "movq %%rsp, %%rdi; \n\t"
            "pushq $0x2b; \n\t"
            "pushq %%rdi; \n\t"
            "pushfq; \n\t"
            "lea 0x5(%%rip), %%rdi; \n\t"
            "pushq $0x33; \n\t"
            "pushq %%rdi; \n\t"
            "iretq; \n\t"
            :::"%rdi");
    return;
}


/* return the number of bp */
int find_n_exit (void)
{
    // tt0 = rdtsc ();
    /* insert hook into the exit point of next basic block */
    while (true)
    {
        //decode current instruction
        instr = decoder->decode((unsigned char *)cr->getPtrToInstruction(crtAddr));
        crtCate = instr->getCategory();
        // crt_ins_length = instr->size();
        
        entryID tempinsID = instr->getOperation().getID();
            
        // cout << "\"" << crtAddr << instr->format() << endl;
        // printf ("crtAddr: %lx, instr: %s. \n", crtAddr, instr->format().c_str());
        
        /* the third step is to get the next crtAddr */
        if (crtCate == c_ReturnInsn || crtCate == c_CallInsn || crtCate == c_BranchInsn)
        {
            hook_for_trans_ins (crtAddr & ~0xfff);//determine whether it is a cross page hook or not
            // if (crtCate == c_CallInsn)
            // {
            //     call_count ++;
            // }
            // else if (crtCate == c_BranchInsn)
            // {
            //     jmp_count ++;
            // }
            // else
            // {
            //     ret_count ++;
            // }
            break;
        }
        else if (crtCate == c_SyscallInsn)
        {
            // // asm volatile ("movq $0x9843211, %%rax; \n\t"
            // //         "vmcall; \n\t"
            // //         :::"%rax");
            hook_for_trans_ins (crtAddr & ~0xfff);//determine whether it is a cross page hook or not
            // printf ("syscall instruction detected. \n");
            break;
        }

        // else if (instr->getOperation().getID() == e_sysret)
        else if (tempinsID == e_sysret)
        {
            // cout << "\"" << instr->format() << endl;
            // printf ("sysret instruction. \n");
            hook_for_trans_ins (crtAddr & ~0xfff);//determine whether it is a cross page hook or not

            /* record the e_sysret operation id here */
            bb_recording[k_u_indicator][crt_bb_idx].operation_id = e_sysret;
            // printf ("sysret instruction detected. crtAddr: %lx. \n", crtAddr);
            // asm volatile ("movq $0x9843211, %%rax; \n\t"
            //         "vmcall; \n\t"
            //         :::"%rax");
            break;
        }
        
        // else if (instr->getOperation().getID() == e_iret)
        else if (tempinsID == e_iret)
        {
            // cout << "\"" << instr->format() << endl;
            // printf ("iret instruction. \n");
            // unsigned long* temp_ptr = (unsigned long*) board_ctx->rsp; 
            // printf ("target rsp: %p, :%lx. crtAddr: %lx. \n", temp_ptr, *temp_ptr, crtAddr);
            hook_for_trans_ins (crtAddr & ~0xfff);//determine whether it is a cross page hook or not
            bb_recording[k_u_indicator][crt_bb_idx].operation_id = e_iret;
            // printf ("iret instruction detected. crtAddr: %lx. \n", crtAddr);
            // asm volatile ("movq $0x9843211, %%rax; \n\t"
            //         "vmcall; \n\t"
            //         :::"%rax");
            break;
        }
        // else if (tempinsID == e_wrmsr)
        // {
        //     hook_for_trans_ins (crtAddr & ~0xfff);//determine whether it is a cross page hook or not
        //     printf ("wrmsr instruction detected.crtAddr: %lx, rcx: %lx. rax: %lx. \n", crtAddr, board_ctx->rcx, board_ctx->rax);
        //     break;
        //     // asm volatile ("movq $0x9843211, %%rax; \n\t"
        //     //         "vmcall; \n\t"
        //     //         :::"%rax");

        // }
        // else if (tempinsID == e_rdmsr)
        // {
        //     hook_for_trans_ins (crtAddr & ~0xfff);//determine whether it is a cross page hook or not
        //     printf ("rdmsr instruction detected. crtAddr:%lx, rcx: %lx. \n", crtAddr, board_ctx->rcx);
        //     break;
        //     // asm volatile ("movq $0x9843211, %%rax; \n\t"
        //     //         "vmcall; \n\t"
        //     //         :::"%rax");

        // }
        // else if (tempinsID == e_invlpg)
        // {
        //     hook_for_trans_ins (crtAddr & ~0xfff);//determine whether it is a cross page hook or not
        //     printf ("swap instruction detected. crtAddr: %lx. \n", crtAddr);
        //     break;
        //     // asm volatile ("movq $0x9843211, %%rax; \n\t"
        //     //         "vmcall; \n\t"
        //     //         :::"%rax");

        // }
        // else if (tempinsID == e_wait)
        // {
        //     hook_for_trans_ins (crtAddr & ~0xfff);//determine whether it is a cross page hook or not
        //     printf ("wait instruction detected. crtAddr: %lx. \n", crtAddr);
        //     break;

        // }
        // else if (tempinsID == e_rdtsc)
        // {
        //     hook_for_trans_ins (crtAddr & ~0xfff);//determine whether it is a cross page hook or not
        //     printf ("rdtsc instruction detected. crtAddr: %lx. \n", crtAddr);
        //     break;
        //     // asm volatile ("movq $0x9843211, %%rax; \n\t"
        //     //         "vmcall; \n\t"
        //     //         :::"%rax");

        // }
        else
        {
            //go to the address of the next instruction
            crtAddr += instr->size();
            // crtAddr += crt_ins_length;
            
        }
    }

    // tt1 = rdtsc ();
    // tt += tt1 - tt0;
    // // lasttransAddr = crtAddr;
    return 1;
}

/* find the entry of next basic block, and skip the control transfer instruction
 * by resuming from the entry of next basic block */
int calculate_trans_target ()
{
    /* get the entry of next basis block based on last control transfer
     * instruction */
    if (crtCate == c_CallInsn)
    {
        // cout << "\"" << instr->format() << endl;
        Expression::Ptr target = instr->getControlFlowTarget();
        if (target)
        {
            RegisterAST* rast = new RegisterAST(MachRegister::getPC(Arch_x86_64));
            target->bind(rast, Result(s64, crtAddr));
            Result res = target->eval();
            Address tempTarget;
            if (res.defined) //direct call
            {
                tempTarget = res.convert<Address>();
                bb_recording[k_u_indicator][crt_bb_idx].target1 = tempTarget;
                // temp_direct_count ++;
                // printf ("call, target1: %lx. target2: %lx. rsp: %lx. \n", bb_recording[k_u_indicator][crt_bb_idx].target1, bb_recording[k_u_indicator][crt_bb_idx].target2, board_ctx->rsp);
            }
            else // indirect call 
            {
                bind_value_for_exp(target);
                res = target->eval();
                if (!(res.defined))//get target address from memory
                {
                    std::vector<Expression::Ptr> temp_exp;
                    target->getChildren(temp_exp);

                    target = *(temp_exp.begin());
                    res = target->eval();
                    
                    tempTarget = res.convert<Address>();
                    tempTarget = *((unsigned long*) tempTarget);
                    bb_recording[k_u_indicator][crt_bb_idx].readmem = 1;
                }
                else
                {
                    tempTarget = res.convert<Address>();
                }
            }
        
            bb_recording[k_u_indicator][crt_bb_idx].resolved = 1;
            bb_recording[k_u_indicator][crt_bb_idx].target2 = crtAddr + instr->size();//this addr should be pushed on stack
            /* skip the call instruction */
            board_ctx->rip = tempTarget;
            board_ctx->rsp -= 0x8;
            *((unsigned long*) (board_ctx->rsp)) = crtAddr + instr->size();
        
            crtAddr = tempTarget;

            // printf ("temp_target in call instruction: %lx. new rsp: %lx. ret address: %lx. \n", tempTarget, board_ctx->rsp, *((unsigned long*)(board_ctx->rsp)));
            return 1;
        }
    }

    else if (crtCate == c_BranchInsn)
    {
        // cout << "\"" << instr->format() << endl;
        Expression::Ptr target = instr->getControlFlowTarget();
        if (target)
        {
            RegisterAST* rast = new RegisterAST(MachRegister::getPC(Arch_x86_64));
            target->bind(rast, Result(s64, crtAddr));
            Result res = target->eval();
            Address tempTarget;
            if (res.defined)//direct jmp
            {
                tempTarget = res.convert<Address>();
                bb_recording[k_u_indicator][crt_bb_idx].target1 = tempTarget;
                // temp_direct_count ++;
            }
            else//indirect jmp
            {
                bind_value_for_exp(target);
                res = target->eval();
                if (!(res.defined))//get target address from memory
                {
                    std::vector<Expression::Ptr> temp_exp;
                    target->getChildren(temp_exp);

                    target = *(temp_exp.begin());
                    res = target->eval();
                    
                    tempTarget = res.convert<Address>();
                    tempTarget = *((unsigned long*) tempTarget);
                    bb_recording[k_u_indicator][crt_bb_idx].readmem = 1;
                }
                else
                {
                    tempTarget = res.convert<Address>();
                }
            }
           
            /* handle the second possible destination if it is conditional jump */
            if (instr->allowsFallThrough())
            {
                // asm volatile ("vmcall; \n\t");
                bb_recording[k_u_indicator][crt_bb_idx].aft = 1;
                bb_recording[k_u_indicator][crt_bb_idx].target2 = crtAddr + instr->size();
                entryID temp_operation_id = instr->getOperation().getID();
                bb_recording[k_u_indicator][crt_bb_idx].operation_id = temp_operation_id;
                int ret = if_condition_fail(temp_operation_id);
                if (ret)//if condition fail, change tempTarget to next instruction
                {
                    tempTarget = crtAddr + instr->size();
                }
            }

            bb_recording[k_u_indicator][crt_bb_idx].resolved = 1;
            /* skip the jmp instruction */
            board_ctx->rip = tempTarget;
            crtAddr = tempTarget;
            // printf ("temp_target in jmp instruction: %lx. rdx: %lx, rax: %lx. crtAddr: %lx, :%lx. \n", tempTarget, target_ctx->rdx, board_ctx->rax, crtAddr, *((unsigned long*) (crtAddr)));
            return 1;
        }
    }

    return 0;
}

void ins_perst_hook (unsigned long addr)
{
    int backup_crt_redir_idx;
    backup_crt_redir_idx = crt_redir_idx;
    
    unsigned long t_addr = addr & ~0xfff;
    // int ret = search_crt_redir_idx (tempAddr);
    // if (!ret)
    // {
        // hypercall ((void*) tempAddr);
        /* the page which installed int3 should not be traced. a new api to
        request EPT redirection */
        if (crt_max_redir_idx == max_redirect_idx)
        {
            printf ("new_pages used up. \n");
            asm volatile ("movq $0x999999, %%rax; \n\t"
                    "vmcall; \n\t"
                    :::"%rax");
        }

        void* new_va = pool_alloc (page_pool, 0x1000);
        // printf ("new_va: %lx. ker_addr: %lx. \n", new_va, ker_addr);

        memcpy (new_va, (void*)t_addr, 0x1000);

        /* issue a hypercall to request ept redirection for new page */
        asm volatile ("movq $0xdcba, %%rbx; \n\t"
                "movq %0, %%rax; \n\t"
                "movq %1, %%rcx; \n\t"
                "lea 0x2(%%rip), %%rdx; \n\t"
                "jmpq *%%rax; \n\t"
                ::"m"(t_addr), "m"(new_va):"%rax","%rbx","%rcx");
        /* / */

        redirected_pages[crt_max_redir_idx] = (Address) t_addr;
        new_pages[crt_max_redir_idx] = (Address) new_va;
        if (((unsigned long)t_addr) < uk_border)
        {
            offsets[crt_max_redir_idx] = (((Address)new_va - (Address)t_addr));
        }
        else
        {
            offsets[crt_max_redir_idx] = ((Address)t_addr) - ((Address)new_va);
        }
        
        /* update the crt_redir_idx */
        crt_redir_idx = crt_max_redir_idx;
        
        crt_max_redir_idx ++;
        /* / */ 
    // }
    
    memcpy (&orig_instr_int3[int3_array_idx], (void*)addr, 0x1);//backup the bytes in the persistent int3 place
    if (addr < uk_border)
    {
        memcpy ((void*)(addr+offsets[crt_redir_idx]), per_hook, 0x1);//install the new hook
    }
    else
    {
        memcpy ((void*)(addr-offsets[crt_redir_idx]), per_hook, 0x1);//install the new hook
    }

    int3_array_idx ++; 
    if (int3_array_idx >= max_int3)
    {
        printf ("int3 array used up, int3_array_idx: %d. \n", int3_array_idx);
        asm volatile ("movq $0x999999, %%rax; \n\t"
                "vmcall; \n\t"
                :::"%rax");
    }
    
    crt_redir_idx = backup_crt_redir_idx;//restore the crt_redir_idx for tracing
    return;
}

/* since we replace the IDT, so we can install a new int 3 handler in the new
 * onsite's IDT, no need to redorect int 3 handler through EPT redirection */
// void ins_int3_handler (unsigned long addr)
// {
//     int backup_crt_redir_idx;
//     backup_crt_redir_idx = crt_redir_idx;
//    
//     unsigned long tempAddr = addr & ~0xfff;
//     int ret = search_crt_redir_idx (tempAddr);
//     if (!ret)
//     {
//         hypercall ((void*) tempAddr);
//     
//     }
//     
//     memcpy (&orig_int3_handler, (void*)addr, len_int3_probe);//backup the bytes in the int3 handler
//     // if (addr < uk_border)
//     // {
//     //     memcpy ((void*)(addr+offsets[crt_redir_idx]), int3_handler_probe, len_int3_probe);//install the new hook
//     // }
//     // else
//     // {
//         memcpy ((void*)(addr-offsets[crt_redir_idx]), int3_handler_probe, len_int3_probe);//install the new hook
//     // }
// 
//     // int3_array_idx ++; 
//     // if (int3_array_idx >= max_int3)
//     // {
//     //     printf ("int3 array used up, int3_array_idx: %d. \n", int3_array_idx);
//     //     asm volatile ("movq $0x999999, %%rax; \n\t"
//     //             "vmcall; \n\t"
//     //             :::"%rax");
//     // }
//     
//     crt_redir_idx = backup_crt_redir_idx;//restore the crt_redir_idx for tracing
//     return;
// }
void swap_fs (unsigned long base)
{
    asm volatile ("movq %0, %%rax; \n\t"
            "wrfsbase %%rax; \n\t"
            ::"m"(base):"%rax");
    return;
}

unsigned long read_fs (void)
{
    unsigned long base;
    asm volatile (
            "rdfsbase %%rax; \n\t"
            "movq %%rax, %0; \n\t"
            ::"m"(base):"%rax");
    return base;
}

void swap_gs (unsigned long base)
{
    asm volatile ("movq %0, %%rax; \n\t"
            "wrgsbase %%rax; \n\t"
            ::"m"(base):"%rax");
    return;
}

unsigned long read_gs (void)
{
    unsigned long base;
    asm volatile (
            "rdgsbase %%rax; \n\t"
            "movq %%rax, %0; \n\t"
            ::"m"(base):"%rax");
    return base;
}
unsigned long rdmsr (unsigned long idx)
{
    unsigned long value;
    unsigned long high, low;
    asm volatile ("mov %2, %%ecx; \n\t"
            "rdmsr; \n\t"
            "mov %%edx, %0; \n\t"
            "mov %%eax, %1; \n\t"
            :"=m"(high), "=m"(low):"m"(idx):"%eax","%edx","%ecx");
    value = ((high << 32) & 0xffffffff00000000) | (low & 0xffffffff);
    return value;
}
void wrmsr (unsigned long idx, unsigned long value)
{
    unsigned long high, low;
    high = (value >> 32) & 0xffffffff;
    low = value & 0xffffffff;
    asm volatile ("mov %2, %%ecx; \n\t"
            "mov %0, %%edx; \n\t"
            "mov %1, %%eax; \n\t"
            "wrmsr; \n\t"
            ::"m"(high), "m"(low), "m"(idx):"%eax","%edx","%ecx");
    return;
}
unsigned long rd_cr0 (void)
{
    unsigned long cr0;
    asm volatile ("mov %%cr0, %%rax; \n\t"
            "mov %%rax, %0; \n\t"
            :"=m"(cr0)::"%rax");
    return cr0;
}
unsigned long rd_cr2 (void)
{
    unsigned long cr2;
    asm volatile ("mov %%cr2, %%rax; \n\t"
            "mov %%rax, %0; \n\t"
            :"=m"(cr2)::"%rax");
    return cr2;
}
unsigned long rd_cr4 (void)
{
    unsigned long cr4;
    asm volatile ("mov %%cr4, %%rax; \n\t"
            "mov %%rax, %0; \n\t"
            :"=m"(cr4)::"%rax");
    return cr4;
}
void wr_cr0 (unsigned long cr0)
{
    asm volatile (
            "mov %0, %%rax; \n\t"
            "mov %%rax, %%cr0; \n\t"
            ::"m"(cr0):"%rax");
    return;
}
void wr_cr2 (unsigned long cr2)
{
    asm volatile (
            "mov %0, %%rax; \n\t"
            "mov %%rax, %%cr2; \n\t"
            ::"m"(cr2):"%rax");
    return;
}
void wr_cr4 (unsigned long cr4)
{
    asm volatile (
            "mov %0, %%rax; \n\t"
            "mov %%rax, %%cr4; \n\t"
            ::"m"(cr4):"%rax");
    return;
}

void func(void)
{
    asm volatile ("" : );
    return;
}

void find_n_exit_pf (void)
{
    unsigned long privilege;
    asm volatile ("mov %%cs, %%rax; \n\t"
            "andq $0x3, %%rax; \n\t"
            "movq %%rax, %0; \n\t"
            :"=m"(privilege)::"%rax");
    
    // printf ("init crtAddr in pf: %lx. privilege: %d. \n", crtAddr, privilege);
    unsigned long temp_addr;
    // temp_addr = 0xfffffef020905ff8;
    temp_addr = pf_stack + 0xff0;
    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "movq %0, %%rdx; \n\t"
    //         "movq -0x10(%%rdx), %%rdi; \n\t"
    //         "movq -0x20(%%rdx), %%rdx; \n\t"
    //         // "movq %%cr2, %%rsi; \n\t"
    //         "vmcall; \n\t"
    //         ::"m"(temp_addr):"%rax");
    // printf ("resume from rip: %lx. rsp: %lx. eflags: %lx. err_rip: %lx. err_code: %lx. cr2: %lx. lasttransAddr: %lx. bb_count: %d. \n", board_ctx->rip, *((unsigned long*)(temp_addr - 0x8)), *((unsigned long*) (temp_addr - 0x10)), *((unsigned long*) (temp_addr - 0x20)),*((unsigned long*)(temp_addr - 0x28)), *((unsigned long*)(temp_addr - 0x38)), lasttransAddr, bb_count);
    //// printf ("resume from rip: %lx. ss: %lx. rsp: %lx. eflags: %lx. cs: %lx. err_rip: %lx. err_code: %lx. rax: %lx. cr2: %lx. rdx: %lx. privilege: %d. lasttransAddr: %lx. bb_count: %d. \n", board_ctx->rip, *((unsigned long*)(temp_addr)), *((unsigned long*)(temp_addr - 0x8)), *((unsigned long*) (temp_addr - 0x10)), *((unsigned long*)(temp_addr - 0x18)), *((unsigned long*) (temp_addr - 0x20)),*((unsigned long*)(temp_addr - 0x28)), *((unsigned long*) (temp_addr - 0x30)), *((unsigned long*)(temp_addr - 0x38)), *((unsigned long*) (temp_addr - 0x40)), privilege, lasttransAddr, bb_count);
    unsigned long temp_cr2;
    temp_cr2 = *((unsigned long*) (temp_addr - 0x38));
    // printf ("temp_cr2: %lx. \n", temp_cr2);
    if (temp_cr2 == 0)
    {
        asm volatile ("movq $0x9843211, %%rax; \n\t"
                "vmcall; \n\t"
                :::"%rax");
    }
    // printf ("temp_cr2: %lx. \n", temp_cr2);
   
    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");
    
    // crtAddr = pf_handler_addr;
    // 
    // if ((crtAddr > uk_border) && (privilege == 3))
    // {
    //     switch_to_ring0 ();
    //     shar_args->user_flag = 0;
    // }

    /* there is problem if the trans instruction is a call instead of a jmp */
    if (crtCate == c_BranchInsn)
    {
         board_ctx->rip = lasttransAddr;
    }
    else if (crtCate == c_CallInsn)
    {
        board_ctx->rip = lasttransAddr;
        board_ctx->rsp += 0x8;
    }
    // else 
    // {
    //     printf ("not jump before pf. temp_cr2: %lx. lasttransins: %lx. \n", temp_cr2, lasttransAddr);
    //     // printf ("resume from rip: %lx. rsp: %lx. eflags: %lx. err_rip: %lx. err_code: %lx. cr2: %lx. lasttransAddr: %lx. bb_count: %d. \n", board_ctx->rip, *((unsigned long*)(temp_addr - 0x8)), *((unsigned long*) (temp_addr - 0x10)), *((unsigned long*) (temp_addr - 0x20)),*((unsigned long*)(temp_addr - 0x28)), *((unsigned long*)(temp_addr - 0x38)), lasttransAddr, bb_count);
    //     // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //     //         "vmcall; \n\t"
    //     //         :::"%rax");

    // }
    
    // instr = decoder->decode((unsigned char *)cr->getPtrToInstruction(crtAddr));
    // crtCate = instr->getCategory();
    
    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");
    
    // // printf ("crtAddr after hook_for_trans_ins in pf: %lx. \n", crtAddr);
    // hook_for_trans_ins (crtAddr & ~0xfff);//determine whether it is a cross page hook or not
    // // printf ("crtAddr after hook_for_trans_ins in pf: %lx. \n", crtAddr);
    // // asm volatile ("movq $0x9843211, %%rax; \n\t"
    // //         "vmcall; \n\t"
    // //         :::"%rax");
    // 
    // if ((crtAddr > uk_border) && (privilege == 3))
    // {
    //     /* restoring user privilege */
    //     restore_user_privilege();
    //     shar_args->user_flag = 3;
    // }
    
    swap_fs (shar_args->fs_base);
    // // swap_fs (target_fs_base);
    
    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");
    return;
}

void restore_hook (void)
{
    if (cross_flag)
    {
        restore_cross_hook();
    }
    else
    {
        /* the first step is to restall the bytes in the hooked place */
        if (crtAddr < uk_border) 
        {
            memcpy ((void*)(crtAddr + offsets[crt_redir_idx]), saved_instr, prob_length);
        }
        else
        {
            memcpy ((void*)(crtAddr - offsets[crt_redir_idx]), saved_instr, prob_length);
        }
    }
    return;
}

void handle_u_bb ()
{
    int i;
    for (i = crt_bb_idx; i < crt_max_u_idx; i ++)
    {
        if (bb_recording[k_u_indicator][i].entry_addr == crtAddr)
        {
            crtAddr = bb_recording[k_u_indicator][i].exit_addr;
            // int ins_length = bb_recording[k_u_indicator][i].exit_ins_length;
            crt_bb_idx = i;
            hook_for_trans_ins (crtAddr & ~0xfff);//determine whether it is a cross page hook or not
            // printf ("found an recorded bb. \n");
            // asm volatile ("movq $0x9843211, %%rax; \n\t"
            //         "movq %0, %%rcx; \n\t"
            //         "vmcall; \n\t"
            //         ::"m"(crtAddr):"%rax", "%rcx");
            break;
        }
    }
    if (i == crt_max_u_idx)
    {
        for (i = crt_bb_idx - 1; i >= 0; i --)
        {
            if (bb_recording[k_u_indicator][i].entry_addr == crtAddr)
            {
                crtAddr = bb_recording[k_u_indicator][i].exit_addr;
                // int ins_length = bb_recording[k_u_indicator][i].exit_ins_length;
                crt_bb_idx = i;
                hook_for_trans_ins (crtAddr & ~0xfff);//determine whether it is a cross page hook or not
                break;
            }

        }
        if ( i == -1)
        {
            crt_bb_idx = crt_max_u_idx;
            bb_recording[k_u_indicator][crt_max_u_idx].entry_addr = crtAddr;
            /* find the next crtAddr and install the hook there */
            find_n_exit();
            bb_recording[k_u_indicator][crt_max_u_idx].exit_addr = crtAddr;
            // bb_recording[k_u_indicator][crt_max_u_idx].exit_ins_length = crt_ins_length;
            bb_recording[k_u_indicator][crt_max_u_idx].category = crtCate;
            // crt_bb_idx = crt_max_u_idx;
            crt_max_u_idx ++;
            if (crt_max_u_idx == max_bb)
            {
                printf ("bb_recording for user space is used up. crt_max_u_idx: %d. crt_max_k_idx: %d. bb_count: %d. \n", crt_max_u_idx, crt_max_k_idx, bb_count);
                asm volatile ("movq $0x9843211, %%rax; \n\t"
                        "vmcall; \n\t"
                        :::"%rax", "%rcx");
            }
        }
    }
    lasttransAddr = crtAddr;
    return;
}

void handle_k_bb ()
{
    int i;
    // /* debug */
    // if (crtAddr == pf_handler_addr)
    // {
    //     printf ("in handle_k_bb.  crt_redt_idx: %d. \n", crt_redir_idx);
    // }
    // /* / */
    for (i = crt_bb_idx; i < crt_max_k_idx; i ++)
    {
        if (bb_recording[k_u_indicator][i].entry_addr == crtAddr)
        {
            crtAddr = bb_recording[k_u_indicator][i].exit_addr;
            // int ins_length = bb_recording[k_u_indicator][i].exit_ins_length;
            crt_bb_idx = i;
            hook_for_trans_ins (crtAddr & ~0xfff);//determine whether it is a cross page hook or not
            break;
        }
    }
    if (i == crt_max_k_idx)
    {
        for (i = crt_bb_idx - 1; i >= 0; i --)
        {
            if (bb_recording[k_u_indicator][i].entry_addr == crtAddr)
            {
                crtAddr = bb_recording[k_u_indicator][i].exit_addr;
                // int ins_length = bb_recording[k_u_indicator][i].exit_ins_length;
                crt_bb_idx = i;
                hook_for_trans_ins (crtAddr & ~0xfff);//determine whether it is a cross page hook or not
                break;
            }

        }
        if (i == -1)
        {

            crt_bb_idx = crt_max_k_idx;
            bb_recording[k_u_indicator][crt_max_k_idx].entry_addr = crtAddr;
            /* find the next crtAddr and install the hook there */
            find_n_exit();
            bb_recording[k_u_indicator][crt_max_k_idx].exit_addr = crtAddr;
            // bb_recording[k_u_indicator][crt_max_k_idx].exit_ins_length = crt_ins_length;
            bb_recording[k_u_indicator][crt_max_k_idx].category = crtCate;
            // crt_bb_idx = crt_max_k_idx;
            crt_max_k_idx ++;
            if (crt_max_k_idx == max_bb)
            {
                printf ("bb_recording for kernel space is used up. crt_max_k_idx: %d, crt_max_u_idx: %d. bb_count: %d. \n", crt_max_k_idx, crt_max_u_idx, bb_count);
                asm volatile ("movq $0x9843211, %%rax; \n\t"
                        "vmcall; \n\t"
                        :::"%rax", "%rcx");
            }
        }
    }
    // /* debug */
    // if (crtAddr == pf_handler_addr)
    // {
    //     printf ("after handle_k_bb. crt_redt_idx: %d. \n", crt_redir_idx);
    // }
    // /* / */
    lasttransAddr = crtAddr;
    return;
}

/* update crtAddr */
void find_n_entry ()
{
    if (bb_recording[k_u_indicator][crt_bb_idx].resolved)
    {
        // printf ("found an recorded bb. target1: %lx. target2: %lx.\n", bb_recording[k_u_indicator][crt_bb_idx].target1, bb_recording[k_u_indicator][crt_bb_idx].target2);
        // asm volatile ("movq $0x9843211, %%rax; \n\t"
        //         "movq %0, %%rcx; \n\t"
        //         "vmcall; \n\t"
        //         ::"m"(crtAddr):"%rax", "%rcx");
        if (bb_recording[k_u_indicator][crt_bb_idx].category == c_CallInsn)
        {
            if (bb_recording[k_u_indicator][crt_bb_idx].target1)
            {
                crtAddr = bb_recording[k_u_indicator][crt_bb_idx].target1;
            }
            else
            {
                instr = decoder->decode((unsigned char *)cr->getPtrToInstruction(crtAddr));
                Expression::Ptr target = instr->getControlFlowTarget();
                Result res;
                Address tempTarget;
                bind_value_for_exp(target);
                if (bb_recording[k_u_indicator][crt_bb_idx].readmem)//get target address from memory
                {
                    std::vector<Expression::Ptr> temp_exp;
                    target->getChildren(temp_exp);
                        
                    target = *(temp_exp.begin());
                    res = target->eval();
                    
                    tempTarget = res.convert<Address>();
                    tempTarget = *((unsigned long*) tempTarget);
                }
                else
                {
                    res = target->eval();
                    tempTarget = res.convert<Address>();
                }
                crtAddr = tempTarget;
            }

            board_ctx->rip = crtAddr;
            board_ctx->rsp -= 0x8;
            *((unsigned long*) (board_ctx->rsp)) = bb_recording[k_u_indicator][crt_bb_idx].target2;
        }
        else if (bb_recording[k_u_indicator][crt_bb_idx].category == c_BranchInsn)
        {
            if (bb_recording[k_u_indicator][crt_bb_idx].aft)
            {
                entryID temp_operation_id = bb_recording[k_u_indicator][crt_bb_idx].operation_id;
                int ret = if_condition_fail(temp_operation_id);
                // printf ("found an recorded bb. target1: %lx. target2: %lx.\n", bb_recording[k_u_indicator][crt_bb_idx].target1, bb_recording[k_u_indicator][crt_bb_idx].target2);
                // asm volatile ("movq $0x9843211, %%rax; \n\t"
                //         "movq %0, %%rcx; \n\t"
                //         "vmcall; \n\t"
                //         ::"m"(crtAddr):"%rax", "%rcx");
                if (ret)//if condition fail, change tempTarget to next instruction
                {
                    crtAddr = bb_recording[k_u_indicator][crt_bb_idx].target2;
                }
                else
                {
                    crtAddr = bb_recording[k_u_indicator][crt_bb_idx].target1;
                }
            }
            else
            {
                if (bb_recording[k_u_indicator][crt_bb_idx].target1)
                {
                    crtAddr = bb_recording[k_u_indicator][crt_bb_idx].target1;
                    // return 1;
                }
                /* This is a indirect jmp, it must be non-conditional */
                else
                {
                    instr = decoder->decode((unsigned char *)cr->getPtrToInstruction(crtAddr));
                    Expression::Ptr target = instr->getControlFlowTarget();
                    Result res;
                    Address tempTarget;
                    bind_value_for_exp(target);
                    if (bb_recording[k_u_indicator][crt_bb_idx].readmem)//get target address from memory
                    {
                        std::vector<Expression::Ptr> temp_exp;
                        target->getChildren(temp_exp);
                    
                        target = *(temp_exp.begin());
                        res = target->eval();
                    
                        tempTarget = res.convert<Address>();
                        tempTarget = *((unsigned long*) tempTarget);
                    }
                    else
                    {
                        res = target->eval();
                        tempTarget = res.convert<Address>();
                    }
                    crtAddr = tempTarget;
                    // printf ("temp_target in jmp instruction: %lx.  \n", tempTarget);
                }
            }

            board_ctx->rip = crtAddr;
            // printf ("crtAddr: %lx. bb_count: %d. \n", crtAddr, bb_count);
            // asm volatile ("movq $0x9843211, %%rax; \n\t"
            //         "movq %0, %%rcx; \n\t"
            //         "vmcall; \n\t"
            //         ::"m"(crtAddr):"%rax", "%rcx");
        }
        else
        {
            printf ("a non direct call or jmp has set its resolved flag. \n");
            asm volatile("movq $0x984311, %%rax; \n\t"
                    "vmcall; \n\t":::"%rax");
        }
    }
    else if (bb_recording[k_u_indicator][crt_bb_idx].category == c_ReturnInsn)
    {
        Address temp_rsp = board_ctx->rsp;
        Address tempTarget = *((unsigned long*) temp_rsp);
      
        // printf ("ret instruction. \n");
        // unsigned long* saved_rsp = (unsigned long*) board_ctx->rsp;
        // printf ("ret, addr: %lx. rsp: %p, in stack: %lx. \n", crtAddr, saved_rsp, *saved_rsp);
        
        /* skip the ret instruction */
        board_ctx->rip = tempTarget;
        board_ctx->rsp += 0x8;

        // /* debug */
        // if (crtAddr == 0x7ffff7ddbbef)
        // {
        //     printf ("rsp: %lx, tempTarget: %lx. before: %lx, %lx. after: %lx. \n", temp_rsp, tempTarget, *((unsigned long*)(temp_rsp + 0x8)), *((unsigned long*)(temp_rsp + 0x10)),  *((unsigned long*)(temp_rsp - 0x8)));
        // }
        // /* / */
       
        crtAddr = tempTarget;

    }
    /* for context switch instructions, remember to reset crt_bb_idx as 0 */
    else if (bb_recording[k_u_indicator][crt_bb_idx].category == c_SyscallInsn)
    {
        /* we should resume from the syscall instruction */
        board_ctx->rip = crtAddr;
        crtAddr = syscallEntry;

        crt_bb_idx = 0;
        printf ("syscall index: %d.\n", board_ctx->rax);
        syscall_count ++;
        /* check if it is exit syscall */
        if (board_ctx->rax == 231)
        {
            shar_args->rcx = board_ctx->rcx;
            shar_args->rax = board_ctx->rax;
            shar_args->rsp = board_ctx->rsp;
            shar_args->rip = board_ctx->rip;
            shar_args->rdi = target_ctx->rdi;
            shar_args->rsi = target_ctx->rsi;
            shar_args->rdx = target_ctx->rdx;
            shar_args->r10 = target_ctx->r10;
            shar_args->r8 = target_ctx->r8;
            shar_args->r9 = target_ctx->r9;
            shar_args->r11 = target_ctx->r11;
            shar_args->rbx = target_ctx->rbx;
            shar_args->rbp = target_ctx->rbp;
            shar_args->r15 = target_ctx->r15;
            shar_args->r14 = target_ctx->r14;
            shar_args->r13 = target_ctx->r13;
            shar_args->r12 = target_ctx->r12;
            shar_args->eflags = target_ctx->eflags;
            
            /* TODO: do we need to restore the msrs and fs/gs base and so on? */ 
            
            shar_args->flag = 2;//request finishes
            asm volatile ("clflush (%0)" :: "r"(&(shar_args->flag)));

            do {
                if (shar_args->guest_timeout_flag == 3)
                    printf ("guest timeout during analysis. \n");
                    break;
            } while (shar_args->flag != 4);
            
            printf ("exit syscall detected. \n");
            printf ("bb count: %d. crt_max_redir_idx: %d. u_bb: %d. k_bb: %d. pg_trans_count: %d. pf_count: %d. syscall_count: %d. selfw_count: %d. \n", bb_count, crt_max_redir_idx, crt_max_u_idx, crt_max_k_idx, pg_trans_count, pf_count, syscall_count, selfw_count);
            printf ("t0 : 0x%llx, t1: 0x%llx, tt: %d. \n", tt0, tt1, tt);
            asm volatile ("movq $0x9843211, %%rax; \n\t"
                    "vmcall; \n\t"
                    :::"%rax");

        }
        else if (board_ctx->rax == 1)
        {
            // debug_flag = 1;
            printf ("writev syscall, bb_count: %d. \n", bb_count);
        }
        // if (board_ctx->rax == 2)
        // {
        //     unsigned long* temp_ptr = (unsigned long*) (target_ctx->rdi);
        //     printf ("temp_ptr: %p, content: %lx. %lx. \n", temp_ptr, *temp_ptr, *(temp_ptr+1));
        //     asm volatile ("movq $0x9843211, %%rax; \n\t"
        //             "vmcall; \n\t"
        //             :::"%rax");
        // }
        // asm volatile ("movq $0x9843211, %%rax; \n\t"
        //         "vmcall; \n\t"
        //         :::"%rax");
        // printf ("syscall index: %d. bb_count: %d, crt_max_u_idx: %d, crt_max_k_idx: %d. \n", board_ctx->rax, bb_count, crt_max_u_idx, crt_max_k_idx);
    }
    else if (bb_recording[k_u_indicator][crt_bb_idx].operation_id == e_sysret)
    {
        board_ctx->rip = crtAddr;
        // printf ("crtAddr for sysret instruction: %lx. \n", crtAddr);
        crtAddr = board_ctx->rcx;

        crt_bb_idx = 0;
        printf ("sysret, return value: %lx. crtAddr: %lx. \n", board_ctx->rax, crtAddr);
        // asm volatile ("movq $0x9843211, %%rax; \n\t"
        //         "vmcall; \n\t"
        //         :::"%rax");

    }
    /* signal will use iret to return to user space */
    else if (bb_recording[k_u_indicator][crt_bb_idx].operation_id == e_iret)
    {
        board_ctx->rip = crtAddr;
        crtAddr = *((unsigned long*) (board_ctx->rsp));

        crt_bb_idx = 0;
        // unsigned long* saved_rsp = (unsigned long*) (board_ctx->rsp);
        // // saced_rsp += 0x3;
        // printf ("iret to: %lx. bb_count: %d. iret to rsp: %lx, iret to cs: %lx, \n", crtAddr, bb_count, *(saved_rsp+0x3), *(saved_rsp+0x1));
        // asm volatile ("movq $0x9843211, %%rax; \n\t"
        //         "vmcall; \n\t"
        //         :::"%rax");

    }
    else
    {
        // // temp_indirect_count ++;
        // tt0 = rdtsc ();
        /* it is a new call/jmp transfer instruction which has not been resolved
         * yet */ 
        instr = decoder->decode((unsigned char *)cr->getPtrToInstruction(crtAddr));
        crtCate = instr->getCategory();
        int ret = calculate_trans_target();
        if (ret == 0)
        {
            printf ("the exit of last bb is not a transfer instruction. crtAddr: %lx.crtCate: %d.  \n", crtAddr, crtCate);
            unsigned long* temp;
            temp = (unsigned long*)crtAddr;
            printf ("content: %lx. %s. \n", *temp, saved_instr);
            printf ("crt_bb_idx:%d, exit:%lx, entry: %lx, target1: %lx. target2: %lx. rsp: %lx. \n", crt_bb_idx, bb_recording[k_u_indicator][crt_bb_idx].exit_addr, bb_recording[k_u_indicator][crt_bb_idx].entry_addr, bb_recording[k_u_indicator][crt_bb_idx].target1, bb_recording[k_u_indicator][crt_bb_idx].target2, board_ctx->rsp);
            cout << "\"" << instr->format() << endl;
            asm volatile("movq $0x984311, %%rax; \n\t"
                    "vmcall; \n\t":::"%rax");
        }
        // tt1 = rdtsc ();
        // tt += tt1 - tt0;
    }
    // /* debugging */
    // if (crtCate == c_CallInsn)
    // {
    //     unsigned long* saved_rsp = (unsigned long*) board_ctx->rsp;
    //     printf ("call, addr: %lx. rsp: %p, rdx: %lx.  \n", crtAddr, saved_rsp, target_ctx->rdx);
    // }
    // if (crtAddr == 0x7ffff7ddb263)
    // if (crtAddr == 0x7ffff7ddb930)
    // {
    //     Address temp_rsp = board_ctx->rsp;
    //     Address tempTarget = *((unsigned long*) temp_rsp);
    //   
    //     printf ("in find n entry. rsp: %lx, tempTarget: %lx. before: %lx, %lx. after: %lx. \n", temp_rsp, tempTarget, *((unsigned long*)(temp_rsp + 0x8)), *((unsigned long*)(temp_rsp + 0x10)),  *((unsigned long*)(temp_rsp - 0x8)));
    //     printf ("resolved.: %lx, target 1: %lx. k_u_indicator: %d, crt_bb_idx: %d. \n", bb_recording[k_u_indicator][crt_bb_idx].resolved, bb_recording[k_u_indicator][crt_bb_idx].target1, k_u_indicator, crt_bb_idx);
    // }
    // // /* / */
    return;
}

// void fd_slice_rsp ()
// {
// 
//     // Assume that block b in function f ends with an indirect jump.
//     Function *f, Block *b; 
//     // Decode the last instruction in this block, which should be a jump
//     const unsigned char * buf =
//         (const unsigned char*) b->obj()->cs()->getPtrToInstruction(b->last());
//     InstructionDecoder dec(buf,
//             InstructionDecoder::maxInstructionLength,
//             b->obj()->cs()->getArch());
//     Instruction::Ptr insn = dec.decode();
//     // Convert the instruction to assignments
//     AssignmentConverter ac(true, true);
//     vector<Assignment::Ptr> assignments;
//     ac.convert(insn, b->last(), f, b, assignments);
//     // printf (": %lx. b->last(): %lx. \n",b->start(), b->last());
//     // An instruction can corresponds to multiple assignment.
//     // Here we look for the assignment that changes the PC.
//     Assignment::Ptr pcAssign;
//     for (auto ait = assignments.begin(); ait != assignments.end(); ++ait) {
//         const AbsRegion &out = (*ait)->out();
//         if (out.absloc().type() == Absloc::Register && out.absloc().reg().isPC()) {
//             pcAssign = *ait;
//             break;
//         }
//     }
//     // Create a Slicer that will start from the given assignment
//     Slicer s(pcAssign, b, f);
//     // printf (": %lx. b->last(): %lx. \n",b->start(), b->last());
// 
//     // We use the customized predicates to control slicing
//     ConstantPred mp;
//     GraphPtr slice = s.backwardSlice(mp);
//     
//     /* Jiaqi */
//     // slice->printDOT("ooo");
//     printf ("%s. \n", f->name().c_str());
//     FILE* fp = fopen("slice.txt", "w");
//     if (fp)
//     {
//         NodeIterator gbegin, gend;
//         slice->allNodes(gbegin, gend);
//         for (; gbegin != gend; ++gbegin) {
//             Node::Ptr ptr = *gbegin;
//             fprintf (fp, "0x%lx\n", ptr->addr());
//             printf ("address of node: %lx. \n", ptr->addr());
//         }
//         fclose(fp);
//     }
// 
//     fp = fopen("slice.txt", "r");
//     if (fp)
//     {
//         char line[128];
//         while (fgets (line, sizeof line, fp))
//         {
//             int tmp = strtol(line, NULL, 16);
//             printf ("tmp: %lx. \n", tmp);
//             fputs(line, stdout);
//         }
//         fclose (fp);
//     }
// 
//     // DataflowAPI::Result_t slRes;
//     // DataflowAPI::SymEval::expand(slice,slRes);
//     // for (DataflowAPI::SymEval::Result_t::const_iterator r_iter = slRes.begin(); r_iter != slRes.end(); ++r_iter) {
//     // for (DataflowAPI::Result_t::const_iterator r_iter = slRes.begin(); r_iter != slRes.end(); ++r_iter) {
//     //     cout << "-----------------" << endl;
//     //     cout << r_iter->first->format();
//     //     cout << " == ";
//     //     cout << (r_iter->second ? r_iter->second->format() : "<NULL>") << endl;
//     // }
//     
//     /* /Jiaqi */
// }

/* update target rip in memory 0x7ff020901fe8 */ 
// update rax in memory 0x7ff020901fe0
// update rcx in memory 0x7ff020901fd8
extern "C" void ana_handler (void);
void ana_handler (void)
{
    // wr_cr0(0x80050033);
    
    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");
    
    shar_args->fs_base = read_fs();
    shar_args->gs_base = read_gs();
    // swap_gs (shar_args->gs_base);
    swap_fs (ana_fs_base);
    bb_count += 1;
    // if (shar_args->fs_base != 0)
    // {
    //     printf ("target fs base set as: %lx. \n", shar_args->fs_base);
    //     asm volatile ("movq $0x9843211, %%rax; \n\t"
    //             "vmcall; \n\t"
    //             :::"%rax");
    // }

    unsigned long privilege;
    asm volatile ("mov %%cs, %%rax; \n\t"
            "andq $0x3, %%rax; \n\t"
            "movq %%rax, %0; \n\t"
            :"=m"(privilege)::"%rax");

    shar_args->user_flag = privilege;
    
    if (privilege == 0x0)
    {
        /* should GP if we also want analyse user program */
        int index = 0xc0000102;
        shar_args->msr_kernel_gs_base = rdmsr(index);
        // shar_args->cr0 = rd_cr0();
        shar_args->cr2 = rd_cr2();
        // shar_args->cr4 = rd_cr4();
        // if (rd_cr0() != shar_args->cr0);
        // {
        //     printf ("target modifies cr0: old: %lx, new: %lx, crtAddr: %lx. \n", shar_args->cr0, rd_cr0(), crtAddr);
        //     shar_args->cr0 = rd_cr0();
        // }
        // if (rd_cr2() != shar_args->cr2);
        // {
        //     printf ("target modifies cr2: old: %lx, new: %lx, crtAddr: %lx. \n", shar_args->cr2, rd_cr2(), crtAddr);
        //     shar_args->cr2 = rd_cr2();
        // }
        // if (rd_cr4() != shar_args->cr4);
        // {
        //     printf ("target modifies cr4: old: %lx, new: %lx, crtAddr: %lx. \n", shar_args->cr4, rd_cr4(), crtAddr);
        //     shar_args->cr4 = rd_cr4();
        // }
    
    }

    
    // /* if a pf is detected, backup user_rip, transfer to analyser when pf
    //  * returns */
    // if (crtAddr == pf_handler_addr)
    // {
    //     asm volatile ("movq %%cr2, %%rax; \n\t"
    //             "movq %%rax, %0; \n\t"
    //             :"=m"(target_cr2)::"%rax");

    //     restore_hook();
    //     board_ctx->rip = crtAddr;

    //     unsigned long* temp_rsp = (unsigned long*) (board_ctx->rsp + 0x8);
    //     crtAddr = *temp_rsp;
    //     iret_to_rip = crtAddr;
    //     *temp_rsp = pf_exit;// resume analyser instead of target user rip directly
    //     // printf ("pf detected , stack: %lx. resume rip: %lx, cr2: %lx. pf_exit: %lx. bb_count: %d. \n", board_ctx->rsp, crtAddr, target_cr2, pf_exit, bb_count);
    //     // asm volatile ("movq $0x7ff020902008, %%rax; \n\t"
    //     //         // "movq (%%rax), %%rax; \n\t"
    //     //         "vmcall; \n\t"
    //     //         :::"%rax");

    //     asm volatile ("movq %0, %%rax; \n\t"
    //             "movq %%rax, %%cr2; \n\t"
    //             ::"m"(target_cr2):"%rax");
    // }
    // /* if a pf return is detected, resume from backuped user_rip */
    // else if (crtAddr == iret_to_rip)
    // {
    //     board_ctx->rip = crtAddr;
    //     printf ("iret detected, crtAddr: %lx, kernel stack: %lx. \n", crtAddr, board_ctx->rsp);
    //     /* check crt_privilege =? crtAddr privilege */
    //     // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //     //         "vmcall; \n\t"
    //     //         :::"%rax");
    //     crt_bb_idx = 0;

    //     if (crtAddr < uk_border)
    //     {
    //         k_u_indicator = 1;
    //         handle_u_bb (); 
    //     }
    //     else 
    //     {
    //         k_u_indicator = 0;
    //         printf ("a kernel space page fault discovered. crtAddr: %lx. \n", crtAddr);
    //         asm volatile ("movq $0x7ff020902008, %%rax; \n\t"
    //                 // "movq (%%rax), %%rax; \n\t"
    //                 "vmcall; \n\t"
    //                 :::"%rax");
    //         if (privilege == 3)
    //         {
    //             switch_to_ring0 ();
    //             shar_args->user_flag = 0;
    //             // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //             //         "vmcall; \n\t"
    //             //         :::"%rax");
    //             handle_k_bb();
    //             /* restoring user privilege */
    //             restore_user_privilege();
    //             shar_args->user_flag = 3;
    //         }
    //         else
    //         {
    //             handle_k_bb();
    //         }
    //     }
    //     iret_to_rip = 0;
    // }
    // /* / */
    // else
    // {
        /* this is the end, time to resume taget VM */
        // if (bb_count == 2299960)
        if (bb_count == 2299960)
        {
            /* restore all registers */
            shar_args->rcx = board_ctx->rcx;
            shar_args->rax = board_ctx->rax;
            shar_args->rsp = board_ctx->rsp;
            shar_args->rip = crtAddr;
            shar_args->rdi = target_ctx->rdi;
            shar_args->rsi = target_ctx->rsi;
            shar_args->rdx = target_ctx->rdx;
            shar_args->r10 = target_ctx->r10;
            shar_args->r8 = target_ctx->r8;
            shar_args->r9 = target_ctx->r9;
            shar_args->r11 = target_ctx->r11;
            shar_args->rbx = target_ctx->rbx;
            shar_args->rbp = target_ctx->rbp;
            shar_args->r15 = target_ctx->r15;
            shar_args->r14 = target_ctx->r14;
            shar_args->r13 = target_ctx->r13;
            shar_args->r12 = target_ctx->r12;
            shar_args->eflags = target_ctx->eflags;
            
            /* TODO: do we need to restore the msrs and fs/gs base and so on? */ 
            
            shar_args->flag = 2;//request finishes
            asm volatile ("clflush (%0)" :: "r"(&(shar_args->flag)));

            do {
                if (shar_args->guest_timeout_flag == 3)
                    printf ("guest timeout during analysis. \n");
                    break;
            } while (shar_args->flag != 4);
           
            asm volatile ("movq $0x9843211, %%rax; \n\t"
                    "movq %0, %%rcx; \n\t"
                    "vmcall; \n\t"
                    ::"m"(crtAddr):"%rax", "%rcx");

            new_round();
            
            printf ("bb count: %d. crt_max_redir_idx: %d. u_bb: %d. k_bb: %d. \n", bb_count, crt_max_redir_idx, crt_max_u_idx, crt_max_k_idx);
            // t1 = rdtsc();
            printf ("t0 : 0x%llx, t1: 0x%llx, t1-t0: %d. : 0x%lx. \n", t0, t1, t1-t0, t1-t0);
            asm volatile ("movq $0x9843211, %%rax; \n\t"
                    "movq %0, %%rcx; \n\t"
                    "vmcall; \n\t"
                    ::"m"(crtAddr):"%rax", "%rcx");
        }
        
        if (crtAddr == lastAddr)
        {
            // t1 = rdtsc();
            printf ("t0 : 0x%llx, t1: 0x%llx, t1-t0: %d. : 0x%lx. \n", t0, t1, t1-t0, t1-t0);
            printf ("bb count: %d. crt_max_redir_idx: %d. u_bb: %d. k_bb: %d. pg_trans_count: %d. pf_count: %d. \n", bb_count, crt_max_redir_idx, crt_max_u_idx, crt_max_k_idx, pg_trans_count, pf_count);
            // unsigned long target_rax = board_ctx->rax;
            // if (target_rax == 0)
            // {
            //     printf ("negative, undetected . \n");
            // }
            // else if (target_rax == 1)
            // {
            //     printf ("positive, detected . \n");
            // }
            // else
            // {
            //     printf ("unknown. rax: %d. \n", target_rax);

            // }
            // unsigned long* tmp = (unsigned long*)target_ctx->rbp;
            // tmp -= 0x2;
            // printf ("digest: %lx. rbp-0x10: %p. \n", *tmp, tmp);
            // tmp -= 0x1;
            // printf ("digest: %lx. rbp-0x18: %p. \n", *tmp, tmp);
            asm volatile ("movq $0x9843211, %%rax; \n\t"
                    "movq %0, %%rcx; \n\t"
                    "vmcall; \n\t"
                    ::"m"(crtAddr):"%rax", "%rcx");
        }

        /* / */

        // if (debug_flag == 1 && (bb_count & 0xf) == 0xf)
        // {
        //     printf ("bb_count: %lx, crtAddr: %lx. \n", bb_count, crtAddr);
        // }
        // if (crtAddr == 0xffffffff817f2ea9)
        // {
        //     debug_flag = 1;
        // }
        // if (debug_flag == 1)
        // {
        //     printf ("bb_count: %lx, crtAddr: %lx. \n", bb_count, crtAddr);
        // }
        // /* debug */
        // if (crtAddr <= uk_border && ((crtAddr & 0x400000) == 0x400000))
        // {
        //     printf ("crtAddr: %lx. \n", crtAddr);
        // }
        /* / */

        restore_hook();
        /* the second step is to save the crtAddr as the next RIP in 0x7ff020902fe8 */
        find_n_entry ();
        // printf ("crtAddr: %lx. \n", crtAddr);
        
        /* check crt_privilege =? crtAddr privilege */
        if (crtAddr < uk_border)
        {
            k_u_indicator = 1;
            handle_u_bb (); 
        }
        else 
        {
            k_u_indicator = 0;
            if (privilege == 3)
            {
                switch_to_ring0 ();
                shar_args->user_flag = 0;
                handle_k_bb();
                /* restoring user privilege */
                restore_user_privilege();
                shar_args->user_flag = 3;
            }
            else
            {
                handle_k_bb();
            }
        }
    // }
        // if (debug_flag == 1)
        // {
        //     printf ("crtAddr: %lx. \n", crtAddr);
        // }
    
    if (privilege == 0x0)
    {
        /* should GP if we also want analyse user program */
        int index = 0xc0000102;
        shar_args->msr_kernel_gs_base = rdmsr(index);
        // shar_args->cr0 = rd_cr0();
        wr_cr2(shar_args->cr2);
        // shar_args->cr4 = rd_cr4();
    
    }
    
    swap_fs (shar_args->fs_base);
    swap_gs (shar_args->gs_base);
    return;
}

extern "C" void store_context (void);
void store_context (void);
asm (" .text");
asm (" .type    store_context, @function");
asm ("store_context: \n");
// asm ("vmcall \n");
// asm ("movq %rsp, %rax \n");//save the stack pointer for debug_handler in order to differentiate a debug exception or a gp exception
// asm ("movq $0x7ff07ffffcc0, %rsp \n");//switch to analyser's secure stack
asm ("movq $0xfffffef07ffffcc0, %rsp \n");//switch to analyser's secure stack

asm ("pushq %rdi \n");
asm ("pushq %rsi \n");
asm ("pushq %rdx \n");
asm ("pushq %r10 \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r11 \n");
asm ("pushq %rbx \n");
asm ("pushq %rbp \n");
asm ("pushq %r15 \n");
asm ("pushq %r14 \n");
asm ("pushq %r13 \n");
asm ("pushq %r12 \n");
asm ("pushf \n");

// asm ("mov $0x80050033, %rax \n");
// asm ("mov %rax, %cr0 \n");//TODO

// asm ("movsd %xmm0, -0x10(%rsp) \n");
// asm ("movsd %xmm1, -0x20(%rsp) \n");
// asm ("movsd %xmm2, -0x30(%rsp) \n");
// asm ("movsd %xmm3, -0x40(%rsp) \n");
// asm ("movsd %xmm4, -0x50(%rsp) \n");
// asm ("movsd %xmm5, -0x60(%rsp) \n");
// asm ("movsd %xmm6, -0x70(%rsp) \n");
// asm ("movsd %xmm7, -0x80(%rsp) \n");
asm ("movaps %xmm0, -0x10(%rsp) \n");
asm ("movaps %xmm1, -0x20(%rsp) \n");
asm ("movaps %xmm2, -0x30(%rsp) \n");
asm ("movaps %xmm3, -0x40(%rsp) \n");
asm ("movaps %xmm4, -0x50(%rsp) \n");
asm ("movaps %xmm5, -0x60(%rsp) \n");
asm ("movaps %xmm6, -0x70(%rsp) \n");
asm ("movaps %xmm7, -0x80(%rsp) \n");
asm ("sub $0x90, %rsp \n");
// asm ("vmcall \n");

asm ("callq ana_handler \n");

asm ("add $0x90, %rsp \n");
asm ("movaps -0x10(%rsp), %xmm0 \n");
asm ("movaps -0x20(%rsp), %xmm1 \n");
asm ("movaps -0x30(%rsp), %xmm2 \n");
asm ("movaps -0x40(%rsp), %xmm3 \n");
asm ("movaps -0x50(%rsp), %xmm4 \n");
asm ("movaps -0x60(%rsp), %xmm5 \n");
asm ("movaps -0x70(%rsp), %xmm6 \n");
asm ("movaps -0x80(%rsp), %xmm7 \n");
// asm ("movsd -0x10(%rsp), %xmm0 \n");
// asm ("movsd -0x20(%rsp), %xmm1 \n");
// asm ("movsd -0x30(%rsp), %xmm2 \n");
// asm ("movsd -0x40(%rsp), %xmm3 \n");
// asm ("movsd -0x50(%rsp), %xmm4 \n");
// asm ("movsd -0x60(%rsp), %xmm5 \n");
// asm ("movsd -0x70(%rsp), %xmm6 \n");
// asm ("movsd -0x80(%rsp), %xmm7 \n");

// asm ("store: \n");
// asm ("vmcall \n");
asm ("popf \n");
asm ("popq %r12 \n");
asm ("popq %r13 \n");
asm ("popq %r14 \n");
asm ("popq %r15 \n");
asm ("popq %rbp \n");
asm ("popq %rbx \n");
asm ("popq %r11 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %r10 \n");
asm ("popq %rdx \n");
asm ("popq %rsi \n");
asm ("popq %rdi \n");

// asm ("movq $0xfffffef0209002c8, %rax \n");//addr of re-enter
asm ("movq $0xfffffef020900279, %rax \n");//addr of re-enter
asm ("pushq %rax \n");

asm ("movq $0x0, %rax \n");
asm ("movq $0x1, %rcx \n");

// asm ("iretq \n");
asm ("retq \n");

unsigned long trans_fd_to_dev_op (int fd, int cmd)
{
    unsigned long k_stack;
    unsigned long off_tss_sp0, off_ks_thdinfo, off_thdinfo_ts, off_ts_files, off_files_fdt, off_fdt_fd, off_file_flop, off_flop_compat_ioctl, off_flop_unlocked_ioctl;
    unsigned long *ts_ptr, *files_ptr, *fdt, *file_ptr, *flop_ptr;
    unsigned long *fdarray;//current fd array
    unsigned long compat_ioctl;
    unsigned long unlocked_ioctl;

    off_tss_sp0 = 0x4;
    off_ks_thdinfo = 0x4000;
    off_thdinfo_ts = 0x0;
    // off_ts_files = 0x590;
    off_ts_files = 0x618;
    off_files_fdt = 0x20;
    off_fdt_fd = 0x8;
    off_file_flop = 0x28;
    off_flop_compat_ioctl = 0x48;
    off_flop_unlocked_ioctl = 0x40;

    // printf ("tss_base: %lx. \n", ana_t_tss);
    k_stack = *((unsigned long*) (ana_t_tss + off_tss_sp0));
    ts_ptr = (unsigned long*)(k_stack - off_ks_thdinfo);
    // printf ("k_stack: %lx. thread_info_addr: %p. \n", k_stack, ts_ptr);
    ts_ptr = (unsigned long*)(*ts_ptr);
    // printf ("task_struct_addr: %p. \n", ts_ptr);
    // unsigned long pid = *((unsigned long*)(((unsigned long) ts_ptr) + 0x428));
    // printf ("pid: %d. \n", pid);
    files_ptr = (unsigned long*) (((unsigned long) ts_ptr) + off_ts_files);
    // printf ("files_struct addr: %p. \n", files_ptr);
    files_ptr = (unsigned long*) (*files_ptr);
    // printf ("files_struct addr: %p. \n", files_ptr);
    fdt = (unsigned long*)(*((unsigned long*) (((unsigned long) files_ptr) + off_files_fdt)));
    // printf ("fdt addr: %p. content: %lx. \n", fdt, *fdt);
    fdarray = (unsigned long*)(*((unsigned long*) (((unsigned long) fdt) + off_fdt_fd)));
    file_ptr = (unsigned long*)(fdarray[fd]);
    // file_ptr ++;
    // printf ("fdarray 0: %lx, 1: %lx.2: %lx, 3: %lx. \n", fdarray[0],fdarray[1],fdarray[2],fdarray[3]);
    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");
    flop_ptr = (unsigned long*)(*((unsigned long*) (((unsigned long) file_ptr) + off_file_flop)));
    // printf ("flop addr: %p. content: %lx. \n", flop_ptr, *flop_ptr);
    // compat_ioctl = *((unsigned long*) (((unsigned long) flop_ptr) + off_flop_compat_ioctl));
    // printf ("compat ioctl: %lx. \n", compat_ioctl);
    unlocked_ioctl = *((unsigned long*) (((unsigned long) flop_ptr) + off_flop_unlocked_ioctl));
    // printf ("unlocked ioctl: %lx. \n", unlocked_ioctl);
    
    return unlocked_ioctl;
}

//the first int3 invoked due to ioctl system call
//the responsibility of this ana_handler1 is to check whether it is our
//interested dev, if yes, install persistent hook in indirect jmp

//the second int3 invoked due to the hook in indirect jmp
//the responsibility of this ana_handler2 is to check indirect transfer target,
//if illegal, start basic block tracing 
extern "C" void int3_ana_handler1 (void);
void int3_ana_handler1 (void)
{
    // wr_cr0(0x80050033);
    
    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");
    
    shar_args->fs_base = read_fs();
    shar_args->gs_base = read_gs();

    swap_fs (ana_fs_base);

    unsigned long privilege;
    asm volatile ("mov %%cs, %%rax; \n\t"
            "andq $0x3, %%rax; \n\t"
            "movq %%rax, %0; \n\t"
            :"=m"(privilege)::"%rax");

    shar_args->user_flag = privilege;
     
    /* should GP if we also want analyse user program */
    int index = 0xc0000102;
    shar_args->msr_kernel_gs_base = rdmsr(index);
    // shar_args->cr0 = rd_cr0();
    shar_args->cr2 = rd_cr2();
 
    unsigned long saved_rip;
    unsigned long saved_rsp;
    unsigned long saved_rflags;

    saved_rip = *((unsigned long*) (int3_stack - 0x28));
    saved_rflags = *((unsigned long*) (int3_stack - 0x18));
    saved_rsp = *((unsigned long*) (int3_stack - 0x10));
    // printf ("saved_rip: %lx, saved_rsp: %lx. saved_rflags: %lx. \n", saved_rip, saved_rsp, saved_rflags);
    // printf ("saved_rax: %lx, saved_rdi: %lx. \n", board_ctx->rax, target_ctx->rdi);
    
    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");
    // ioctl hook is invoked
    int bp_idx = 0;
    if (saved_rip == breakpoint1+1)
        bp_idx = 0x1;
    else if (saved_rip == breakpoint2+1)
        bp_idx = 0x2;
    else if (saved_rip == breakpoint3+1)
        bp_idx = 0x3;
    // switch (saved_rip)
    switch (bp_idx)
    {
        // // case addr_sys_ioctl+1:
        // case 0xffffffff81210821:
        //     int fd, cmd;
        //     unsigned long temp_ioctl_addr;
        //     fd = target_ctx->rdi;
        //     cmd = target_ctx->rsi;
        //     printf ("rdi: %lx. rsi: %lx, rdx: %lx. \n", fd, cmd, target_ctx->rdx);
       
        //     // tt0 = rdtsc ();
        //     temp_ioctl_addr = trans_fd_to_dev_op(fd, cmd);
        //     // tt1 = rdtsc ();
        //     // printf ("tt0: %llx, tt1: %llx. tt1-tt0: %d. \n"); 
        //     // asm volatile ("movq $0x9843211, %%rax; \n\t"
        //     //         "vmcall; \n\t"
        //     //         :::"%rax");
    
        //     if (temp_ioctl_addr == addr_drv_ioctl)//interested dev
        //     {
        //         ins_perst_hook(addr_indt_call);
        //         // printf ("insert int3 at : %lx. \n", addr_indt_call);
        //     }
        //     board_ctx->rip = saved_rip + 0x4;
        //     board_ctx->rsp = saved_rsp;
        //     target_ctx->eflags = saved_rflags;
        //     break;
        case 1:
            printf ("bp1 invoked. rax: %lx. \n", board_ctx->rax);
            board_ctx->rip = saved_rip;
            board_ctx->rsp = saved_rsp;
            target_ctx->eflags = saved_rflags;
   
            /* if it is mprotect or mmap, and the hooked page is inside the
             * affected region */
            // if ()
            // {
            //     ins_perst_hook (breakpoint2);
            // }
            // asm volatile ("movq $0x9843211, %%rax; \n\t"
            //         "vmcall; \n\t"
            //         :::"%rax");
            // printf ("bp invoked. \n");
            break;

        case 2:
            printf ("bp2 invoked. rax: %lx. \n", board_ctx->rax);
            board_ctx->rip = saved_rip;
            board_ctx->rsp = saved_rsp;
            target_ctx->eflags = saved_rflags;
    
            /* restore original byte at bp2 */
            memcpy ((void*)breakpoint2, &orig_instr_int3[2], 0x1);//backup the bytes in the persistent int3 place
            /* time to re-install the hook in user pages */

            break;
        
        case 3:
            printf ("bp3 invoked. rax: %lx. \n", board_ctx->rax);
            board_ctx->rip = saved_rip;
            board_ctx->rsp = saved_rsp;
            target_ctx->eflags = saved_rflags;
    
            /* restore original byte at bp3 */
            memcpy ((void*)breakpoint3, &orig_instr_int3[3], 0x1);//backup the bytes in the persistent int3 place
            /* time to re-install the hook in user pages */

            break;
        // case addr_indt_call+1:
        //     board_ctx->rsp = saved_rsp - 0x8;
        //     unsigned long saved_rax = board_ctx->rax;
        //     printf ("saved_rax: %lx. \n", saved_rax);
        //     // asm volatile ("movq $0x9843211, %%rax; \n\t"
        //     //         "vmcall; \n\t"
        //     //         :::"%rax");
        //     board_ctx->rip = saved_rax;//since it is a call *rax 
        //     target_ctx->eflags = saved_rflags;
        //     crtAddr = board_ctx->rip;

        //     if (shar_args->user_flag == 3)
        //     {
        //         k_u_indicator = 1;
        //         crt_max_u_idx ++;
        //     }
        //     else if (shar_args->user_flag == 0)
        //     {
        //         k_u_indicator = 0;
        //         crt_max_k_idx ++;
        //     }
        //     bb_recording[k_u_indicator][crt_bb_idx].entry_addr = crtAddr;
        //     /* find next instruction to insert hook */
        //     find_n_exit();
        //     bb_recording[k_u_indicator][crt_bb_idx].exit_addr = crtAddr;
        //     bb_recording[k_u_indicator][crt_bb_idx].category = crtCate;

        //     printf ("crtAddr after find_n_exit: %lx. \n", crtAddr);
        //     break;

        default:
            unsigned long int3_t_stack;
            unsigned long off_tss_ist3;
            unsigned long stack_len;
            off_tss_ist3 = 52;
            stack_len = 5*8;
            // printf ("default kernel stack: %lx. \n", *((unsigned long*)(ana_t_tss + 0x4)));
            int3_t_stack = *((unsigned long*) (ana_t_tss + off_tss_ist3));
            int3_t_stack -= stack_len;
            
            printf ("int3 from target detected. int3_t_stack: %lx. \n", int3_t_stack);

            memcpy((void*)int3_t_stack, (void*)(int3_stack-stack_len), stack_len);

            board_ctx->rip = int3_o_addr;
            // board_ctx->rsp = int3_stack-stack_len;
            board_ctx->rsp = int3_t_stack;
            // target_ctx->eflags = saved_rflags;
            // printf ("int3 from target detected. int3_t_stack: %lx. \n", int3_t_stack);

            // asm volatile ("movq $0x9843211, %%rax; \n\t"
            //         "vmcall; \n\t"
            //         :::"%rax");

            break;
    
    }
    swap_fs (shar_args->fs_base);
    swap_gs (shar_args->gs_base);
    return;
}

extern "C" void int3_store_context1 (void);
void int3_store_context1 (void);
asm (" .text");
asm (" .type    int3_store_context1, @function");
asm ("int3_store_context1: \n");
// asm ("vmcall \n");
// asm ("movq %rsp, %rax \n");//save the stack pointer for debug_handler in order to differentiate a debug exception or a gp exception
// asm ("movq $0x7ff07ffffcc0, %rsp \n");//switch to analyser's secure stack
asm ("movq $0xfffffef07ffffcc0, %rsp \n");//switch to analyser's secure stack

asm ("pushq %rdi \n");
asm ("pushq %rsi \n");
asm ("pushq %rdx \n");
asm ("pushq %r10 \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r11 \n");
asm ("pushq %rbx \n");
asm ("pushq %rbp \n");
asm ("pushq %r15 \n");
asm ("pushq %r14 \n");
asm ("pushq %r13 \n");
asm ("pushq %r12 \n");
asm ("pushf \n");

// asm ("mov $0x80050033, %rax \n");
// asm ("mov %rax, %cr0 \n");//TODO

// asm ("movsd %xmm0, -0x10(%rsp) \n");
// asm ("movsd %xmm1, -0x20(%rsp) \n");
// asm ("movsd %xmm2, -0x30(%rsp) \n");
// asm ("movsd %xmm3, -0x40(%rsp) \n");
// asm ("movsd %xmm4, -0x50(%rsp) \n");
// asm ("movsd %xmm5, -0x60(%rsp) \n");
// asm ("movsd %xmm6, -0x70(%rsp) \n");
// asm ("movsd %xmm7, -0x80(%rsp) \n");
asm ("sub $0x90, %rsp \n");
// asm ("vmcall \n");

asm ("callq int3_ana_handler1 \n");

asm ("add $0x90, %rsp \n");
// asm ("movsd -0x10(%rsp), %xmm0 \n");
// asm ("movsd -0x20(%rsp), %xmm1 \n");
// asm ("movsd -0x30(%rsp), %xmm2 \n");
// asm ("movsd -0x40(%rsp), %xmm3 \n");
// asm ("movsd -0x50(%rsp), %xmm4 \n");
// asm ("movsd -0x60(%rsp), %xmm5 \n");
// asm ("movsd -0x70(%rsp), %xmm6 \n");
// asm ("movsd -0x80(%rsp), %xmm7 \n");

// asm ("store: \n");
// asm ("vmcall \n");
asm ("popf \n");
asm ("popq %r12 \n");
asm ("popq %r13 \n");
asm ("popq %r14 \n");
asm ("popq %r15 \n");
asm ("popq %rbp \n");
asm ("popq %rbx \n");
asm ("popq %r11 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %r10 \n");
asm ("popq %rdx \n");
asm ("popq %rsi \n");
asm ("popq %rdi \n");

// asm ("movq $0xfffffef0209002c8, %rax \n");//addr of re-enter
// asm ("movq $0xfffffef020900279, %rax \n");//addr of re-enter
asm ("movq $0xfffffef0209002fd, %rax \n");//addr of re-enter
asm ("pushq %rax \n");

asm ("movq $0x0, %rax \n");
asm ("movq $0x1, %rcx \n");

// asm ("iretq \n");
asm ("retq \n");

extern "C" void pf_ana_handler1 (void);
void pf_ana_handler1 (void)
{
    // wr_cr0(0x80050033);
    
    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");
   
    /* TODO: fix fs base syn */
    shar_args->fs_base = read_fs();
    shar_args->gs_base = read_gs();

    swap_fs (ana_fs_base);

    unsigned long privilege;
    asm volatile ("mov %%cs, %%rax; \n\t"
            "andq $0x3, %%rax; \n\t"
            "movq %%rax, %0; \n\t"
            :"=m"(privilege)::"%rax");

    shar_args->user_flag = privilege;
     
    // /* should GP if we also want analyse user program */
    // int index = 0xc0000102;
    // shar_args->msr_kernel_gs_base = rdmsr(index);
    // // shar_args->cr0 = rd_cr0();
    shar_args->cr2 = rd_cr2();

    pf_count ++;
    // /* debug */
    // unsigned long saved_rip;
    // unsigned long saved_cs;
    // unsigned long saved_rsp;
    // unsigned long saved_rflags;
    // unsigned long saved_err_code;
    // unsigned long t_pf_stack;
    // t_pf_stack = board_ctx->rsp;
    // saved_err_code = *((unsigned long*) (t_pf_stack));
    // // saved_rip = *((unsigned long*) (t_pf_stack -0x8));
    // // saved_rflags = *((unsigned long*) (t_pf_stack - 0x18));
    // // saved_rsp = *((unsigned long*) (t_pf_stack - 0x20));
    // saved_rip = *((unsigned long*) (t_pf_stack + 0x8));
    // saved_cs = *((unsigned long*) (t_pf_stack + 0x10));
    // saved_rflags = *((unsigned long*) (t_pf_stack + 0x18));
    // saved_rsp = *((unsigned long*) (t_pf_stack + 0x20));
    // // printf ("#PF detected, cr2: %lx. pf stack: %lx. err_code: %lx. err_rip: %lx, cs: %lx. rsp: %lx, rflags: %lx. \n", shar_args->cr2, t_pf_stack, saved_err_code, saved_rip, saved_cs, saved_rsp, saved_rflags);
    // printf ("#PF detected, cr2: %lx. err_code: %lx. err_rip: %lx, cs: %lx. rsp: %lx, rflags: %lx. \n", shar_args->cr2, saved_err_code, saved_rip, saved_cs, saved_rsp, saved_rflags);
    // // printf ("crtAddr: %lx, crtCate: %lx, crt_bb_idx: %d. crt_redir_idx: %d, cross_flag: %d.bb_count: %d. \n", crtAddr, crtCate, crt_bb_idx, crt_redir_idx, cross_flag, bb_count);
    
    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");

    // // restore_hook(); // it is not important to restore hook here, since every
    // // time control transfers to a new code page, there is an memcpy operation
    // // to substitute the entire code page content. 
    crt_bb_idx = 0;
    crtAddr = pf_handler_addr;
    k_u_indicator = 0;
    handle_k_bb();
    
    // ins_perst_hook (breakpoint3);
    
    board_ctx->rip = pf_handler_addr;
    
    // printf ("after handle_k_bb, crtAddr: %lx, crtCate: %lx, crt_bb_idx: %d, crt_redir_idx: %d, cross_flag: %d. \n", crtAddr, crtCate, crt_bb_idx, crt_redir_idx, cross_flag);
    // /* debugging */
    // unsigned long* temp_ptr;
    // temp_ptr = (unsigned long*) pf_handler_addr;
    // printf ("temp_ptr: %p, content: %lx, %lx. \n", temp_ptr, *temp_ptr, *(temp_ptr+1));
    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");

    wr_cr2(shar_args->cr2); 
    swap_fs (shar_args->fs_base);
    swap_gs (shar_args->gs_base);
    return;
}

extern "C" void pf_store_context (void);
void pf_store_context (void);
asm (" .text");
asm (" .type    pf_store_context, @function");
asm ("pf_store_context: \n");
// asm ("vmcall \n");
// asm ("movq %rsp, %rax \n");//save the stack pointer for debug_handler in order to differentiate a debug exception or a gp exception
// asm ("movq $0x7ff07ffffcc0, %rsp \n");//switch to analyser's secure stack
asm ("movq $0xfffffef07ffffcc0, %rsp \n");//switch to analyser's secure stack

asm ("pushq %rdi \n");
asm ("pushq %rsi \n");
asm ("pushq %rdx \n");
asm ("pushq %r10 \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r11 \n");
asm ("pushq %rbx \n");
asm ("pushq %rbp \n");
asm ("pushq %r15 \n");
asm ("pushq %r14 \n");
asm ("pushq %r13 \n");
asm ("pushq %r12 \n");
asm ("pushf \n");

asm ("movaps %xmm0, -0x10(%rsp) \n");
asm ("movaps %xmm1, -0x20(%rsp) \n");
asm ("movaps %xmm2, -0x30(%rsp) \n");
asm ("movaps %xmm3, -0x40(%rsp) \n");
asm ("movaps %xmm4, -0x50(%rsp) \n");
asm ("movaps %xmm5, -0x60(%rsp) \n");
asm ("movaps %xmm6, -0x70(%rsp) \n");
asm ("movaps %xmm7, -0x80(%rsp) \n");
asm ("sub $0x90, %rsp \n");
// asm ("vmcall \n");

asm ("callq pf_ana_handler1 \n");

asm ("add $0x90, %rsp \n");
asm ("movaps -0x10(%rsp), %xmm0 \n");
asm ("movaps -0x20(%rsp), %xmm1 \n");
asm ("movaps -0x30(%rsp), %xmm2 \n");
asm ("movaps -0x40(%rsp), %xmm3 \n");
asm ("movaps -0x50(%rsp), %xmm4 \n");
asm ("movaps -0x60(%rsp), %xmm5 \n");
asm ("movaps -0x70(%rsp), %xmm6 \n");
asm ("movaps -0x80(%rsp), %xmm7 \n");

// asm ("vmcall \n");
asm ("popf \n");
asm ("popq %r12 \n");
asm ("popq %r13 \n");
asm ("popq %r14 \n");
asm ("popq %r15 \n");
asm ("popq %rbp \n");
asm ("popq %rbx \n");
asm ("popq %r11 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %r10 \n");
asm ("popq %rdx \n");
asm ("popq %rsi \n");
asm ("popq %rdi \n");

// asm ("movq $0xfffffef0209002c8, %rax \n");//addr of re-enter
asm ("movq $0xfffffef02090038c, %rax \n");//addr of re-enter
asm ("pushq %rax \n");

asm ("movq $0x0, %rax \n");
asm ("movq $0x1, %rcx \n");

// asm ("iretq \n");
asm ("retq \n");

extern "C" void selfw_ana_handler1 (void);
void selfw_ana_handler1 (void)
{
    // wr_cr0(0x80050033);
    
    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");
    
    // shar_args->fs_base = read_fs();
    shar_args->gs_base = read_gs();

    swap_fs (ana_fs_base);

    unsigned long privilege;
    asm volatile ("mov %%cs, %%rax; \n\t"
            "andq $0x3, %%rax; \n\t"
            "movq %%rax, %0; \n\t"
            :"=m"(privilege)::"%rax");

    shar_args->user_flag = privilege;
     
    // /* should GP if we also want analyse user program */
    // int index = 0xc0000102;
    // shar_args->msr_kernel_gs_base = rdmsr(index);
    // // shar_args->cr0 = rd_cr0();
    // shar_args->cr2 = rd_cr2();

    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");
    
    /* synchronize the modification on data page to code page */
    unsigned long ker_addr = redirected_pages[crt_redir_idx];
    unsigned long new_va = new_pages[crt_redir_idx];
    memcpy ((void*)new_va, (void*)ker_addr, 0x1000);
    
    // printf ("self write detected and handled, time to resume target. \n");
    /* since there is a modidication on code page, update the exit_addr of
     * current code block */
    crtAddr = shar_args->rip;
    board_ctx->rip = shar_args->rip;
    if (crtAddr >= bb_recording[k_u_indicator][crt_bb_idx].entry_addr && crtAddr <= bb_recording[k_u_indicator][crt_bb_idx].exit_addr) 
    {
        // bb_recording[k_u_indicator][crt_max_u_idx].entry_addr = crtAddr;
        /* find the next crtAddr and install the hook there */
        find_n_exit();
        bb_recording[k_u_indicator][crt_bb_idx].exit_addr = crtAddr;
        bb_recording[k_u_indicator][crt_bb_idx].category = crtCate;
        // crt_bb_idx = crt_max_u_idx;
        // crt_max_u_idx ++;
    }
    else
    {
        printf ("crtAddr is not within current code block. crtAddr: %lx, entry: %lx, exit: %lx, crt_bb_idx: %d. \n", crtAddr, bb_recording[k_u_indicator][crt_bb_idx].entry_addr, bb_recording[k_u_indicator][crt_bb_idx].exit_addr, crt_bb_idx);
        asm volatile ("movq $0x9843211, %%rax; \n\t"
                "vmcall; \n\t"
                :::"%rax");

    }
  
    // printf ("self write detected and handled, time to resume target. \n");
    selfw_count ++;
    /* flush error instruction related TLB, invlpg requires privilege
     * instruction */
    if (privilege == 3)
    {
        switch_to_ring0 ();
        shar_args->user_flag = 0;
    }
    asm volatile ("movq %0, %%rax; \n\t"
            "invlpg (%%rax); \n\t"
            ::"m"(shar_args->rip):"%rax");
    if (privilege == 3)
    {
        restore_user_privilege();
        shar_args->user_flag = 3;
    }
    // asm volatile ("movq $0x7ff020902008, %%rax; \n\t"
    //         // "movq (%%rax), %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");


    // wr_cr2(shar_args->cr2); 
    swap_fs (shar_args->fs_base);
    swap_gs (shar_args->gs_base);
    return;
}

extern "C" void selfw_store_context (void);
void selfw_store_context (void);
asm (" .text");
asm (" .type    selfw_store_context, @function");
asm ("selfw_store_context: \n");
// asm ("vmcall \n");
// asm ("movq %rsp, %rax \n");//save the stack pointer for debug_handler in order to differentiate a debug exception or a gp exception
// asm ("movq $0x7ff07ffffcc0, %rsp \n");//switch to analyser's secure stack
asm ("movq $0xfffffef07ffffcc0, %rsp \n");//switch to analyser's secure stack

asm ("pushq %rdi \n");
asm ("pushq %rsi \n");
asm ("pushq %rdx \n");
asm ("pushq %r10 \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r11 \n");
asm ("pushq %rbx \n");
asm ("pushq %rbp \n");
asm ("pushq %r15 \n");
asm ("pushq %r14 \n");
asm ("pushq %r13 \n");
asm ("pushq %r12 \n");
asm ("pushf \n");

asm ("movaps %xmm0, -0x10(%rsp) \n");
asm ("movaps %xmm1, -0x20(%rsp) \n");
asm ("movaps %xmm2, -0x30(%rsp) \n");
asm ("movaps %xmm3, -0x40(%rsp) \n");
asm ("movaps %xmm4, -0x50(%rsp) \n");
asm ("movaps %xmm5, -0x60(%rsp) \n");
asm ("movaps %xmm6, -0x70(%rsp) \n");
asm ("movaps %xmm7, -0x80(%rsp) \n");
asm ("sub $0x90, %rsp \n");
// asm ("vmcall \n");

asm ("callq selfw_ana_handler1 \n");

asm ("add $0x90, %rsp \n");
asm ("movaps -0x10(%rsp), %xmm0 \n");
asm ("movaps -0x20(%rsp), %xmm1 \n");
asm ("movaps -0x30(%rsp), %xmm2 \n");
asm ("movaps -0x40(%rsp), %xmm3 \n");
asm ("movaps -0x50(%rsp), %xmm4 \n");
asm ("movaps -0x60(%rsp), %xmm5 \n");
asm ("movaps -0x70(%rsp), %xmm6 \n");
asm ("movaps -0x80(%rsp), %xmm7 \n");

// asm ("vmcall \n");
asm ("popf \n");
asm ("popq %r12 \n");
asm ("popq %r13 \n");
asm ("popq %r14 \n");
asm ("popq %r15 \n");
asm ("popq %rbp \n");
asm ("popq %rbx \n");
asm ("popq %r11 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %r10 \n");
asm ("popq %rdx \n");
asm ("popq %rsi \n");
asm ("popq %rdi \n");

// asm ("movq $0xfffffef0209002c8, %rax \n");//addr of re-enter
asm ("movq $0xfffffef020900279, %rax \n");//addr of re-enter
asm ("pushq %rax \n");

asm ("movq $0x0, %rax \n");
asm ("movq $0x1, %rcx \n");

// asm ("iretq \n");
asm ("retq \n");
void save_ana_fs (void)
{
    unsigned long ana_fs_h, ana_fs_l;
    unsigned long kernel_gs_h, kernel_gs_l;
    asm volatile (
            "mov $0xc0000100, %%rcx; \n\t"//MSR_FS_BASE
            "rdmsr; \n\t"
            "mov %%edx, %0; \n\t"
            "mov %%eax, %1; \n\t"

            :"=m"(ana_fs_h), "=m"(ana_fs_l) ::"%rax", "%rcx", "%rdx");

    ana_fs_base = ((ana_fs_h << 32) & 0xffffffff00000000) | (ana_fs_l & 0xffffffff);
    
    asm volatile ("clflush (%0)" :: "r"(&(ana_fs_base)));
    return;
}

void init_w_page (void)
{
    board_ctx->rcx = shar_args->rcx;
    board_ctx->rax = shar_args->rax;
    board_ctx->rsp = shar_args->rsp;
    board_ctx->rip = shar_args->rip;
    return;
}

/* This call cate is used by analyser to escalate privilege from user to kernel */
void init_call_gate ()
{
    unsigned long* temp_gdt;
    unsigned long call_gate_entry;
    unsigned long call_gate_addr;

    call_gate_addr = (unsigned long) func;
    // temp_gdt = (unsigned long*) shar_args->gdtr;
    temp_gdt = gdt_base;
    call_gate_entry = (call_gate_addr & 0xffff) | (0x10 << 16) | ((unsigned long) (0xec00) << 32) | (((call_gate_addr >> 16) & 0xffff) << 48);
    temp_gdt[12] = call_gate_entry;
    call_gate_entry = (call_gate_addr >> 32) & 0xffffffff;
    temp_gdt[13] = call_gate_entry;
    
    asm volatile ("clflush (%0)" :: "r"(&(temp_gdt[12])));
    
    return;
}

void new_round ()
{
    // unsigned long kernel_gs_h, kernel_gs_l;
    /* last exit is dur to error or io, restore hook and ana's fs here */
    // wr_cr0 (0x80050033);
    
    if (shar_args->exit_wrong_flag == 1)
    {
        swap_fs (ana_fs_base);
        printf ("bb count: %d. crt_max_redir_idx: %d. u_bb: %d. k_bb: %d. pg_trans_count: %d. pf_count: %d. syscall_count: %d. selfw_count: %d. \n", bb_count, crt_max_redir_idx, crt_max_u_idx, crt_max_k_idx, pg_trans_count, pf_count, syscall_count, selfw_count);
        printf ("t0 : 0x%llx, t1: 0x%llx, tt: %d. \n", tt0, tt1, tt);
        // printf ("bb count: %d. crt_max_redir_idx: %d. u_bb: %d. k_bb: %d. \n", bb_count, crt_max_redir_idx, crt_max_u_idx, crt_max_k_idx);
        asm volatile ("movq $0x9843211, %%rax; \n\t"
                "vmcall; \n\t"
                :::"%rax");
        swap_fs (ana_fs_base);
        restore_hook();
    }
        
    /* before issue another interception request, we re-empty the memory where stores global data structures. This is to minimize the latency to target vcpu */
    void* temp;
    temp = &redirected_pages[0];
    memset(temp, 0x0, sizeof(redirected_pages));
    temp = &new_pages[0];
    memset(temp, 0x0, sizeof(new_pages));
    temp = &offsets[0];
    memset(temp, 0x0, sizeof(offsets));
    temp = &bb_recording[0][0];
    memset(temp, 0x0, sizeof(bb_recording));
    temp = page_pool->init;
    memset(temp, 0x0, (((unsigned long)page_pool->next) - ((unsigned long)temp)));
    page_pool->next = temp;

    /* initialize the crt_redir_idx as 0 */
    crt_max_redir_idx = 0;
    crt_redir_idx = crt_max_redir_idx;
    
    crt_bb_idx = 0;
    crt_max_u_idx = crt_max_k_idx = 0;
    cross_flag = 0;
    bb_count = 0;
    
    shar_args->exit_wrong_flag = 0;

    if (rand_exp)//it is in the experiment which continuelly captures target thread randomly
    {
        /* issue vmcall to intercept another target thread */
        asm volatile (// "mfence; \n\t"
                "movq $0xaabbccdd, %%rax; \n\t"
                "vmcall; \n\t"
                :::"%rax");
        initAddr = shar_args->rip;
        crtAddr = initAddr;
        // printf ("user_flag: %d. fs_base: %lx. \n", shar_args->user_flag, shar_args->fs_base);

        if (shar_args->user_flag == 3)
        {
            k_u_indicator = 1;
            crt_max_u_idx ++;
        }
        else if (shar_args->user_flag == 0)
        {
            k_u_indicator = 0;
            crt_max_k_idx ++;
        }
        bb_recording[k_u_indicator][crt_bb_idx].entry_addr = crtAddr;
        /* find next instruction to insert hook */
        find_n_exit();
        bb_recording[k_u_indicator][crt_bb_idx].exit_addr = crtAddr;
        bb_recording[k_u_indicator][crt_bb_idx].category = crtCate;

        init_w_page ();
        int index = 0xc0000102;
        wrmsr (index, shar_args->msr_kernel_gs_base);
        // printf ("msr_kernel_gs_base: %lx. \n", rdmsr(index));

        /* switch to target fs base */
        swap_fs (shar_args->fs_base);
        swap_gs (shar_args->gs_base);
   
        wr_cr2 (shar_args->cr2);
        // wr_cr0 (shar_args->cr0);
        wr_cr0 (0x8005003b);
        // wr_cr4 (shar_args->cr4);
    }
    else//wait for the target hyp to share target thread's context ready
    {
    
        shar_args->flag = 1;
        printf ("init flag. args: %p, flag: %lx\n", shar_args, shar_args->flag);
        
        // asm volatile ("movq $0x9843211, %%rax; \n\t"
        //         "vmcall; \n\t"
        //         :::"%rax");
    
        do {
        } while (shar_args->flag != 0);
    
        memcpy((void*) ana_t_tss, (void*) shar_args->tss_base, 68);
        // asm volatile ("movq $0x9843211, %%rax; \n\t"
        //         "vmcall; \n\t"
        //         :::"%rax");
    
        initAddr = shar_args->rip;
        crtAddr = initAddr;
        // // lastAddr = initAddr + 0x5;
        // // lastAddr = 0x403785;
        // // lastAddr = 0x400a61;
        // 
        if (shar_args->user_flag == 3)
        {
            k_u_indicator = 1;
            crt_max_u_idx ++;
        }
        else if (shar_args->user_flag == 0)
        {
            k_u_indicator = 0;
            crt_max_k_idx ++;
        }
        bb_recording[k_u_indicator][crt_bb_idx].entry_addr = crtAddr;
        /* find next instruction to insert hook */
        find_n_exit();
        bb_recording[k_u_indicator][crt_bb_idx].exit_addr = crtAddr;
        bb_recording[k_u_indicator][crt_bb_idx].category = crtCate;

        switch_to_ring0 ();
        
        init_w_page ();
        int index = 0xc0000102;
        wrmsr (index, shar_args->msr_kernel_gs_base);

        /* switch to target fs base */
        swap_fs (shar_args->fs_base);
        swap_gs (shar_args->gs_base);
   
        wr_cr2 (shar_args->cr2);
        // wr_cr0 (0x8005003b);
        // wr_cr4 (shar_args->cr4);
        // restore_user_privilege ();
    }

    // t0 = rdtsc ();

    if (shar_args->user_flag == 3)
    {
        asm volatile (
                /* prepare stack for iret */
                "movq %0, %%rbx; \n\t"
                "movq %1, %%rax; \n\t"//f_trampoline
                "pushq $0x2b; \n\t"
                "movq 0x60(%%rbx), %%rcx; \n\t"//rsp
                "pushq %%rcx; \n\t"
                "movq 0x50(%%rbx), %%rcx; \n\t"//eflags
                "pushq %%rcx; \n\t"
                "pushq $0x33; \n\t"
                "pushq %%rax; \n\t"

                /* load all registers */
                "movq 0x8(%%rbx), %%rdi; \n\t"
                "movq 0x10(%%rbx), %%rsi; \n\t"
                "movq 0x18(%%rbx), %%rdx; \n\t"
                "movq 0x28(%%rbx), %%r8; \n\t"
                "movq 0x30(%%rbx), %%r9; \n\t"
                "movq 0x38(%%rbx), %%r11; \n\t"
                "movq 0x40(%%rbx), %%r10; \n\t"
                "movq 0x70(%%rbx), %%rbp; \n\t"
                "movq 0x78(%%rbx), %%r12; \n\t"
                "movq 0x80(%%rbx), %%r13; \n\t"
                "movq 0x88(%%rbx), %%r14; \n\t"
                "movq 0x90(%%rbx), %%r15; \n\t"
                "movq 0x68(%%rbx), %%rbx; \n\t"

                "movq $0x0, %%rax; \n\t"
                "movq $0x1, %%rcx; \n\t"

                "iretq; \n\t"

                ::"m"(shar_mem),"m"(f_trampoline):"%rcx","%rax", "%rdx", "%rbx", "%rdi", "%rsi");
    }
    else if (shar_args->user_flag == 0)
    // if (shar_args->user_flag == 0)
    {
        asm volatile (
                /* prepare stack for iret */
                "movq %0, %%rbx; \n\t"
                "movq %1, %%rax; \n\t"//f_trampoline
                "movq 0x50(%%rbx), %%rcx; \n\t"//eflags
                "pushq %%rcx; \n\t"
                "popfq; \n\t"
                "pushq %%rax; \n\t"

                /* load all registers */
                "movq 0x8(%%rbx), %%rdi; \n\t"
                "movq 0x10(%%rbx), %%rsi; \n\t"
                "movq 0x18(%%rbx), %%rdx; \n\t"
                "movq 0x28(%%rbx), %%r8; \n\t"
                "movq 0x30(%%rbx), %%r9; \n\t"
                "movq 0x38(%%rbx), %%r11; \n\t"
                "movq 0x40(%%rbx), %%r10; \n\t"
                "movq 0x70(%%rbx), %%rbp; \n\t"
                "movq 0x78(%%rbx), %%r12; \n\t"
                "movq 0x80(%%rbx), %%r13; \n\t"
                "movq 0x88(%%rbx), %%r14; \n\t"
                "movq 0x90(%%rbx), %%r15; \n\t"
                "movq 0x68(%%rbx), %%rbx; \n\t"

                "movq $0x0, %%rax; \n\t"
                "movq $0x1, %%rcx; \n\t"

                "retq; \n\t"

                // ::"m"(shar_mem),"m"(f_trampoline),"m"(shar_args->fs_base):"%rcx","%rax", "%rdx", "%rbx", "%rdi", "%rsi");
                ::"m"(shar_mem),"m"(f_trampoline):"%rcx","%rax", "%rdx", "%rbx", "%rdi", "%rsi");

    }
    else
    {
        printf ("no user flag sharing. \n");
        asm volatile ("movq $0x9843211, %%rax; \n\t"
                "vmcall; \n\t"
                :::"%rax");

    }
    return; 
}

void init_global_var (void)
{
    void* temp;
    /* initialize redirect_page_pool */
    page_pool = (POOL*) malloc (sizeof(page_pool));
    pool_create (0x1000*max_redirect_idx);
    
    /* empty the memory where stores the global data structures */
    temp = &redirected_pages[0];
    memset(temp, 0x0, sizeof(redirected_pages));
    temp = &new_pages[0];
    memset(temp, 0x0, sizeof(new_pages));
    temp = &offsets[0];
    memset(temp, 0x0, sizeof(offsets));
    temp = &bb_recording[0][0];
    memset(temp, 0x0, sizeof(bb_recording));
    
    crt_redir_idx = crt_max_redir_idx = 0;
    crt_max_u_idx = crt_max_k_idx = 0;
    crt_bb_idx = 0;
    cross_flag = 0;
    bb_count = 0;
    loop_idx = 0;
    iret_to_rip = 0x0;
    int3_array_idx = 0;
    pg_trans_count = 0;
    pf_count = 0;
    debug_flag = 0;

    /* TODO: the address of shar_mem is hardcoded. */
    exit_gate_va = 0xfffffef020900000;
    idt_va = 0xfffffef020901000;
    gdt_va = 0xfffffef020902000;
    tss_va = 0xfffffef020903000;
    data_page = 0xfffffef020905000;
    int3_stack = data_page + 0x1000 - 0x100;//The higher 0x100 is used to store board_ctx, to avoid data confliction
    root_pt_va = 0xfffffef020906000;
    shar_mem = 0xfffffef020907000;
    ana_t_tss = 0xfffffef020908000+0x200;//0x200 is guest_tss_page_offset
    ana_t_gdt = 0xfffffef020909000;
    // pf_handler = 0xfffffef02090d000;  
    pf_stack = 0xfffffef02090e000;  

    ana_stack = 0xfffffef07ffffcc0;
    f_trampoline = exit_gate_va + 0x279;
    pf_exit = exit_gate_va + 0x29f;
    cg_exit = exit_gate_va + 0x297;

    // /* debug */
    // printf ("gdt: %lx. \n", *((unsigned long*)(ana_t_gdt+0x10)));
    // printf ("gdt: %lx. \n", *((unsigned long*)(ana_t_gdt+0x18)));
    // printf ("gdt: %lx. \n", *((unsigned long*)(ana_t_gdt+0x28)));
    // printf ("gdt: %lx. \n", *((unsigned long*)(ana_t_gdt+0x30)));
    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");
    // /* / */
    /* the libc_csu_init is mapped at 0x4118a0, the offset of the call gate to init is
     * 0x9, the selector is 0x03eb */
    // // cg_sel_addr_u = 0x401e20+0x9;
    /* ls */
    // // cg_sel_addr_u = 0x411890+0x47;//call gate selector at: add 0x1, %rbx
    // // cg_sel_addr_u_1 = 0x411890-0x1c;//call gate selector at: mov %rax, 0x90(%rbx)
    // cg_sel_addr_u = 0x411880+0x47;//call gate selector at: add 0x1, %rbx
    // cg_sel_addr_u_1 = 0x411880-0x1c;//call gate selector at: mov %rax, 0x90(%rbx)
    /* pwd */
    // // cg_sel_addr_u = 0x404710+0x47;//call gate selector at: add 0x1, %rbx
    // // cg_sel_addr_u_1 = 0x404710-0x1c;//call gate selector at: mov %rax, 0x90(%rbx)
    // cg_sel_addr_u = 0x4046a0+0x47;//call gate selector at: add 0x1, %rbx
    // cg_sel_addr_u_1 = 0x4046a0-0x1c;//call gate selector at: mov %rax, 0x90(%rbx)
    // /* kill */
    // cg_sel_addr_u = 0x404790+0x47;//call gate selector at: add 0x1, %rbx
    // cg_sel_addr_u_1 = 0x404790-0x1c;//call gate selector at: mov %rax, 0x90(%rbx)
    /* superpi without printf */
    // cg_sel_addr_u = 0x4030c0+0x47;//call gate selector at: add 0x1, %rbx
    // // cg_sel_addr_u_1 = 0x403100-0x1c;//call gate selector at: mov %rax, 0x90(%rbx)
    // cg_sel_addr_u_1 = 0x4030c0+0xc;//call gate selector at: mov %rax, 0x90(%rbx)
    // /* superpi with printf */
    // cg_sel_addr_u = 0x4038b0+0x47;//call gate selector at: add 0x1, %rbx
    // // cg_sel_addr_u_1 = 0x403100-0x1c;//call gate selector at: mov %rax, 0x90(%rbx)
    // cg_sel_addr_u_1 = 0x4038b0+0xc;//call gate selector at: mov %rax, 0x90(%rbx)
    /* uname -a */
    cg_sel_addr_u = 0x403f60+0x47;//call gate selector at: add 0x1, %rbx
    cg_sel_addr_u_1 = 0x403f60-0x1c;//call gate selector at: mov %rax, 0x90(%rbx)
    // /* upx uname -a */
    // cg_sel_addr_u = 0x402c00+0x2f;//call gate selector at: add 0x1, %rbx
    // cg_sel_addr_u_1 = 0x402c00-0x1c;//call gate selector at: mov %rax, 0x90(%rbx)
    /* assume ld is mapped at 0x7ffff7dda000, the offset of first instruction in
     ld is 0x1260 */
    cg_sel_addr_lib = 0x7ffff7ddb212;// 12-19: offset, 1a-1b: selector 0x0103
    cg_sel_addr_k = 0xffffffff817f9054;//54-5b: offset, 5c-5d:selector 0x0f00
    // printf ("lib: %lx, : %lx, \n", cg_sel_addr_lib, *((unsigned long*)cg_sel_addr_lib));
    // printf ("u: %lx, : %lx, \n", cg_sel_addr_u, *((unsigned long*)cg_sel_addr_u));
    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");
    cg_sel_u = 0x01e0 >> 2;
    cg_sel_lib = 0x0103 >> 2;
    cg_sel_k = 0x0f00 >> 2;

    shar_args = (struct args_blk*)shar_mem;
    target_ctx = (struct target_context*)(ana_stack - 0x70);
    // board_ctx = (struct board_context*)(w_page + 0xfc8);
    // board_ctx = (struct board_context*)(data_page + 0xfc0);
    // board_ctx = (struct board_context*)(data_page + 0xfb8);
    board_ctx = (struct board_context*)(data_page + 0xfb0);
    
    board_ctx->user_handler = (unsigned long)store_context;
    board_ctx->int3_exit_handler = (unsigned long)int3_store_context1;
    board_ctx->pf_exit_handler = (unsigned long)pf_store_context;
    board_ctx->selfw_exit_handler = (unsigned long)selfw_store_context;

    pf_handler_addr = 0xffffffff817f90c0;
    /* prepare find_n_exit_pf in pf_stack */
    pf_stack += 0x8;
    *((unsigned long*) pf_stack) = (unsigned long) find_n_exit_pf;
    
    /* initialize the d_prob_instr array as: wrfsbase %rax; mov $0xfffffef020900297, %rax; jmp *rax */  
    // auto init = std::initializer_list<unsigned char>({0xf3, 0x48, 0x0f, 0xae, 0xd0, 0x48, 0xb8, 0x97, 0x02, 0x90, 0x20, 0xf0, 0xfe, 0xff, 0xff, 0xff, 0xe0});
    // auto init = std::initializer_list<unsigned char>({0xf3, 0x48, 0x0f, 0xae, 0xd4, 0x48, 0x89, 0xc4, 0x48, 0xb8, 0x97, 0x02, 0x90, 0x20, 0xf0, 0xfe, 0xff, 0xff, 0xff, 0xe0});
    // std::copy(init.begin(), init.end(), d_prob_instr);
    auto init = std::initializer_list<unsigned char>({0x48, 0xff, 0x2d, 0x00, 0x00, 0x00});//the last 4 bytes are the offset to current rip
    std::copy(init.begin(), init.end(), d_prob_instr);

    per_hook[0] = 0xcc;
    
    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");
    
    save_ana_fs ();
    // int3_o_addr = 0xffffffff8102e100;
    int3_o_addr = 0xffffffff817f8f00;
    
    /* initialize the privilege of analyser as ring 0 */
    shar_args->user_flag = 0;
    
    /* initialize addr_gdt_base, addr_tss_base */
    unsigned char gdtr[10];
    unsigned long tss_base0, tss_base1, tss_base2;
    asm ("sgdt %0; \n\t"
            :"=m"(gdtr)
            :
            :);
    gdt_base = (unsigned long*)(*(unsigned long*)(gdtr + 2));
    // tss_base0 = (gdt_base[8] >> 16) & 0xffffff;
    // tss_base1 = (gdt_base[8] >> 56) & 0xff;
    // tss_base2 = gdt_base[9] & 0xffffffff;
    // // printf ("gdt[8]: %lx, gdt[9]: %lx. \n", gdt_base[8], gdt_base[9]);
    // // printf ("gdt[1]: %lx, gdt[6]: %lx. \n", gdt_base[1], gdt_base[6]);
    // addr_tss_base = (tss_base2 << 32) | (tss_base1 << 24) | tss_base0;
   
    addr_sys_ioctl = 0xffffffff81210820; 
    // addr_sys_ioctl = 0xffffffff817f6ed0; 
    addr_drv = 0xffffffffc00d9000;
    addr_drv_ioctl = addr_drv + 0xb4;
    addr_indt_call = addr_drv + 0xf6;
    // addr_indt_call = addr_drv + 0xe8;
    // addr_indt_call = addr_drv + 0xb4;

    // unsigned char idtr[10];
    // unsigned long* idt_base;
    // asm ("sidt %0; \n\t"
    //         :"=m"(idtr)
    //         :
    //         :);
    // idt_base = (unsigned long*)(*(unsigned long*)(idtr + 2));
    // printf ("idt[14*2]: %lx, idt[14*2+1]: %lx. \n", idt_base[14*2], idt_base[14*2+1]);
    // // // int3_stack = *((unsigned long*) (addr_tss_base + 0x3c));// int3 uses ist[3] as its stack
    // unsigned long tmpp_ptr;
    // tmpp_ptr = addr_tss_base;
    // addr_tss_base = ana_t_tss;
    // printf ("ist[8]: %lx. \n", *((unsigned long*)(addr_tss_base + 0x5c)));
    // printf ("ist[7]: %lx. \n", *((unsigned long*)(addr_tss_base + 0x54)));
    // printf ("ist[6]: %lx. \n", *((unsigned long*)(addr_tss_base + 0x4c)));
    // printf ("ist[5]: %lx. \n", *((unsigned long*)(addr_tss_base + 0x44)));
    // printf ("ist[4]: %lx. \n", *((unsigned long*)(addr_tss_base + 0x3c)));
    // printf ("ist[3]: %lx. \n", *((unsigned long*)(addr_tss_base + 0x34)));
    // printf ("ist[2]: %lx. \n", *((unsigned long*)(addr_tss_base + 0x2c)));
    // printf ("ist[1]: %lx. \n", *((unsigned long*)(addr_tss_base + 0x24)));
    // printf ("reserved: %lx. \n", *((unsigned long*)(addr_tss_base + 0x1c)));
    // printf ("sp2: %lx. \n", *((unsigned long*)(addr_tss_base + 0x14)));
    // printf ("sp1: %lx. \n", *((unsigned long*)(addr_tss_base + 0xc)));
    // printf ("sp0: %lx. \n", *((unsigned long*)(addr_tss_base + 0x4)));
    // addr_tss_base = tmpp_ptr;

    unsigned long addr_new_round;
    addr_new_round = (unsigned long) new_round;
    /* indicate to start analysis. the  pf   bit is cleared from this point */
    asm volatile ("movq $0xbbbbb, %%rax; \n\t"
            "movq %0, %%rbx; \n\t"
            "movq %1, %%rcx; \n\t "
            "vmcall; \n\t"
            ::"m"(addr_new_round), "m"(ana_stack):"%rax", "%rbx", "rcx");

    /* prepare call gate in gdt, The above vmcall redirect the idt, gdt, tr used
     * by analyser in the first EPT. It also pass the rip & rsp of new_round to
     * hyp, so that whenever there is an analysis error, the hyp knows where to
     * resume */
    init_call_gate();
    
    // crtAddr = 0xffffffff817f6f36;
    // find_n_exit();
    // printf ("crtAddr: %lx. \n", crtAddr); 
    // asm volatile ("movq $0x9843211, %%rax; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");

    return;
}

//update store_context in call_gate in GDT
//update long jump target in memory 0x7ff020901ff0

int main(int argc, char **argv)
{
    Address adds, adde;
    adds = 0x0;
    adde = 0xfffffffffffff000;
    sts = new MyCodeSource(adds, adde);
    co = new CodeObject(sts);
    
    cr = *(sts->regions().begin());

    //create an Instruction decoder which will convert the binary opcodes to strings
    decoder = new InstructionDecoder((unsigned char *)cr->getPtrToInstruction(cr->low()), InstructionDecoder::maxInstructionLength, cr->getArch());
        
    // asm volatile ("mov $0x8004003b, %%rax; \n\t"
    //         "mov %%rax, %%cr0; \n\t"
    //         // "vmcall; \n\t"
    //         :::"%rax");
   
    init_global_var ();

    // asm volatile ("mov $0x8004003b, %%rax; \n\t"
    //         // "mov %%rax, %%cr0; \n\t"
    //         "vmcall; \n\t"
    //         :::"%rax");

    new_round (); 
    // printf ("user_flag: %d. \n", shar_args->user_flag);
    
    return 0;
}
