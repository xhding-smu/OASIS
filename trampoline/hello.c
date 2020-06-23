#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <asm/current.h>
#include <asm/page.h>
#include <linux/sched.h>
#include <asm/types.h>
#include <asm/desc.h>
#include <asm/apic.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include "imee.h"

MODULE_LICENSE ("GPL");
// extern struct arg_blk* imee_arg;
extern struct arg_blk imee_arg;
// extern volatile unsigned long last_cr3;
// extern volatile unsigned long last_rsp;
// extern volatile unsigned long last_rip;
// extern volatile int imee_pid;
int vcpu_entry(void);
int vcpu_reentry(void);
static void cr0_wp_off (void)
{
    unsigned long cr0;
    asm ("movq %%cr0, %0;":"=r"(cr0)::);
    cr0 &= ~0x10000;
    asm ("movq %0, %%cr0;"::"r"(cr0):);
    return;
}

static void cr0_wp_on (void)
{
    unsigned long cr0;
    asm ("movq %%cr0, %0;":"=r"(cr0)::);
    cr0 |= 0x10000;
    asm ("movq %0, %%cr0;"::"r"(cr0):);
    return;
}

// static __attribute__ ((noinline)) unsigned long long rdtsc(void)
// {
//     unsigned long long x;
//     asm volatile (".byte 0x0f, 0x31" : "=A"(x));
//     return x;
// }

static noinline unsigned long long rdtsc(void)
{
    unsigned long long x;
    __asm__ volatile (".byte 0x0f, 0x31" : "=A"(x));
    return x;
}

//?during interrupt, whehter swapgs by hardware? if not, swapgs before jump to
//system_call entry?
void syscall_bounce (void)
{
    unsigned long syscall_idx;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
    unsigned long arg4;
    unsigned long arg5;
    unsigned long arg6;
    unsigned long ret_addr;
    unsigned long save_eflags;
    unsigned long rsp;
    syscall_idx = imee_arg.rax;
    arg1 = imee_arg.rdi;
    arg2 = imee_arg.rsi;
    arg3 = imee_arg.rdx;
    arg4 = imee_arg.r10;
    arg5 = imee_arg.r8;
    arg6 = imee_arg.r9;
    ret_addr = imee_arg.rip;
    save_eflags = imee_arg.r11;
    rsp = imee_arg.rsp;

    /* just for syscall performance testing */
    // if (syscall_idx == 0x27)
    // {
    //     unsigned long long t1;
    //     t1 = rdtsc();
    //     printk ("just before getpid handler, t1: %llx, t0: %llx, t1-t0: %d\n", t1, arg2, t1-arg2);
    // }
    /* / */

    asm volatile ("movq %0, %%rax; \n\t"
            "movq %1, %%rdi; \n\t"
            "movq %2, %%rsi; \n\t"
            "movq %3, %%rdx; \n\t"
            "movq %4, %%r10; \n\t"
            "movq %5, %%r8; \n\t"
            "movq %6, %%r9; \n\t"
            "movq %7, %%rcx; \n\t"
            "movq %8, %%r11; \n\t"
            "pushf; \n\t"
            "popq %%rbx; \n\t"
            "and $0xc8ff, %%rbx; \n\t"
            "pushq %%rbx; \n\t"
            "popf; \n\t"
            "movq %9, %%rsp; \n\t"
            "swapgs; \n\t"//switch gs to user space gs before jump to system call entry 
            "movq $0xffffffff817142b0, %%rbx; \n\t"
            "jmpq *%%rbx; \n\t"
            // "jmpq $0xffffffff817142b0; \n\t"//jmp to syscall entry point directly, no need to change stack before jmp
            ::"m"(syscall_idx),"m"(arg1),"m"(arg2),"m"(arg3),"m"(arg4),"m"(arg5),"m"(arg6),"m"(ret_addr),"m"(save_eflags),"m"(rsp):"%rax","%rdi","%rsi","%rdx","%r10","%r8","%r9","%rcx","%r11","%rsp");
    return;
}

static void clear_bp (void)
{
    asm volatile ("pushq %%rax; \n\t"
            "movq $0x0, %%rax; \n\t"
            "movq %%rax, %%DR0; \n\t"
            "movq $0x400, %%rax; \n\t"
            "movq %%rax, %%DR7; \n\t"
            "movq $0xfffe0ff0, %%rax; \n\t"
            "movq %%rax, %%DR6; \n\t"
            "popq %%rax; \n\t"
            :::"%rax");
    return;
}

static void read_bp (void)
{
    unsigned long dr7, dr0;
    asm volatile ("pushq %%rax; \n\t"
            "movq %%DR7, %%rax; \n\t"
            "movq %%rax, %0; \n\t"
            "movq %%DR0, %%rax; \n\t"
            "movq %%rax, %1; \n\t"
            "popq %%rax; \n\t"
            :"=m"(dr7), "=m"(dr0)::"%rax");
    DBG ("initial value for DR7: %lx, DR0: %lx\n", dr7, dr0);
    return;
}

void noinline set_bp (unsigned long dr0, unsigned long dr7)
{
    asm volatile ("pushq %%rax; \n\t"
            "movq %0, %%rax; \n\t"
            "movq %%rax, %%DR0; \n\t"
            "movq %1, %%rax; \n\t"
            "movq %%rax, %%DR7; \n\t"
            "popq %%rax; \n\t"
            ::"m"(dr0), "m"(dr7):"%rax");
    // printk ("now dr0: %lx, dr7: %lx\n", dr0, dr7);
    return 0;
}

void enter_vcpu (unsigned long arg)
{
    int r;
    unsigned long dr_s, dr_z;
    clear_bp();
    // DBG ("bp triggered, rax: %lx \n", arg);
    if (strstr(current->comm, "testtest"))
    {
        // /* just for testing performance */
        // unsigned long long t0;
        // t0 = rdtsc();
        
        /* / */
        /* the following three variable is static in expand vma experiment */
        // last_cr3 = 0x3b32d000;
        // last_rip = 0x7ffda321f000;
        // last_rsp = 0x0;
        // printk ("this is testtest \n");
        if (imee_arg.syscall_flag == 0)//this is return from execve
        {
            // unsigned long fir_cr3;
            // asm volatile("movq %%cr3, %%rax; \n\t"
            //         "movq %%rax, %0; \n\t"
            //         :"=m"(fir_cr3)::"%rax");
            // printk ("----------------------first cr3 in bp: %lx\n", fir_cr3);
            // printk("just before enter dota mode, cpuid : %d, comm: %s\n", smp_processor_id(), current->comm);
            r = vcpu_entry();
            // printk ("return from fisst time vcpu enter, r = %d\n", r);
            // u32 lstar_h;
            // u32 lstar_l;
            // rdmsr (MSR_LSTAR, lstar_l, lstar_h);
            // printk ("when return from vcpu_entry, lstar_h: %x, lstar_l: %x\n", lstar_h, lstar_l);
            // u32 star_h;
            // u32 star_l;
            // rdmsr (MSR_STAR, star_l, star_h);
            // printk ("when return from vcpu_entry, star_h: %x, star_l: %x\n", star_h, star_l);
            // unsigned long cr3;
            // asm volatile("movq %%cr3, %%rax; \n\t"
            //         "movq %%rax, %0; \n\t"
            //         :"=m"(cr3)::"%rax");
            // printk ("----------------------cr3 in bp: %lx\n", cr3);
            // printk("first time return from dota, cpuid : %d, comm: %s\n", smp_processor_id(), current->comm);
            // return;
            if (r == -2)//this is vmcall due to syscall in dota mode
            {
                dr_s = 0x401;
                dr_z = imee_arg.rip;
                set_bp(dr_z, dr_s);
                /* just for test */
                // asm volatile("movq %0, %%rax; \n\t"
                //         "movq %%rax, %%cr3; \n\t"
                //         ::"m"(fir_cr3):"%rax");
                // printk ("----------------------cr3 just before syscall_bounce: %lx\n", fir_cr3);
                /* / */
                syscall_bounce ();
            }
        }
        else if (imee_arg.syscall_flag == 1)//this is return from syscall iuused from dota mode, as syscall_flag is set as 1 in the very first vcpu_entry
        {
            // printk ("return from syscall handling\n");
            // return;
            if (imee_arg.rax == 0xc || imee_arg.rax == 0x9 || imee_arg.rax == 30)//brk; mmap; shmat;
            {
                // imee_arg.ret_rax = arg + 0xffff6a8000000000;
                imee_arg.ret_rax = arg + UK_OFFSET;
            }
            // /* just for performance testing */
            // else if(imee_arg.rax == 0x27)
            // {
            //     imee_arg.ret_rax = t0;
            // }
            /* / */
            else//for brk, the return value is 0/-1, not true?
            {
                if (imee_arg.rax == 19 || imee_arg.rax == 20)//readv; writev; the adjusted memory should be adjusted back
                {
                    unsigned long iov_ptr_addr;
                    // unsigned long iov_addr;
                    iov_ptr_addr = imee_arg.rsi;
                    // iov_addr = *((unsigned long *) iov_ptr_addr);
                    *((unsigned long*)iov_ptr_addr) += UK_OFFSET;
                }

                else if (imee_arg.rax == 46 || imee_arg.rax == 47)//sendmsg; recvmsg;
                {
                    unsigned long* msghdr_addr;
                    unsigned long msg_name_addr;
                    unsigned long msg_iov_ptr_addr;
                    unsigned long msg_iov_addr;
                    unsigned long msg_control_addr;
                    msghdr_addr = imee_arg.rsi;
                    msg_name_addr = msghdr_addr;
                    msg_iov_ptr_addr = msghdr_addr + 0x2;
                    msg_iov_addr = *((unsigned long*) msg_iov_ptr_addr);
                    msg_control_addr = msghdr_addr + 0x4;
                    *((unsigned long*)msg_name_addr) += UK_OFFSET;
                    *((unsigned long*)msg_iov_ptr_addr) += UK_OFFSET;
                    *((unsigned long*)msg_control_addr) += UK_OFFSET;
                    *((unsigned long*)msg_iov_addr) += UK_OFFSET;
                }
                // printk ("return value for brk: %lx\n", arg);
                //
                //for debug
                else if (imee_arg.rax == 51)//getsockname
                {
                    unsigned long* temp_ptr;
                    temp_ptr = imee_arg.rsi;
                    printk ("temp_ptr: %p, content: %lx\n", temp_ptr, *temp_ptr);
                    temp_ptr ++;
                    printk ("temp_ptr: %p, content: %lx\n", temp_ptr, *temp_ptr);
                }

                imee_arg.ret_rax = arg;
            }
            /* just for test */
            // unsigned long cr3;
            // asm volatile("movq %%cr3, %%rax; \n\t"
            //         "movq %%rax, %0; \n\t"
            //         :"=m"(cr3)::"%rax");
            // printk ("=================================cr3 before vcpu_rentry: %lx\n", cr3);
            // printk("cpuid : %d, comm: %s\n", smp_processor_id(), current->comm);
            /* / */
            r = vcpu_reentry();
            // printk("when return from dota mode, cpuid : %d, comm: %s\n", smp_processor_id(), current->comm);
            // return;
            if (r == -2)
            {
                dr_s = 0x401;
                dr_z = imee_arg.rip;
                set_bp(dr_z, dr_s); 
                syscall_bounce ();
            }
            else 
            {
                printk ("not handled, return r: %d\n", r);
            }
        }
    }
out:
    return;
}
static void debug_handler (void);
asm (" .text");
asm (" .type    debug_handler, @function");
asm ("debug_handler: \n");
// asm ("cli \n");
asm ("swapgs \n");
asm ("pushq %rbx \n");
asm ("pushq %rbp \n");
asm ("pushq %r12 \n");
asm ("pushq %r13 \n");
asm ("pushq %r14 \n");
asm ("pushq %r15 \n");
asm ("pushq %rcx \n");//save user space rip
asm ("pushq %r11 \n");//save user space eflags
asm ("pushq %rax \n");//save return value of syscall
asm ("pushq %rdi \n");
asm ("pushq %rsi \n");
asm ("pushq %rdx \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r10 \n");
asm ("pushq %r11 \n");
asm ("movq %rax, %rdi \n");//the arg of deter should be passed in register
asm ("callq enter_vcpu \n");
// asm ("callq new_handler \n");
asm ("movq $0x400, %rax \n");
asm ("movq %rax, %DR7 \n");
asm ("movq $0x0, %rax \n");
asm ("movq %rax, %DR0 \n");
asm ("movq $0xfffe0ff0, %rax \n");
asm ("movq %rax, %DR6 \n");
asm ("popq %r11 \n");
asm ("popq %r10 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %rdx \n");
asm ("popq %rsi \n");
asm ("popq %rdi \n");
asm ("popq %rax \n");
asm ("popq %r11 \n");
asm ("popq %rcx \n");
asm ("popq %r15 \n");
asm ("popq %r14 \n");
asm ("popq %r13 \n");
asm ("popq %r12 \n");
asm ("popq %rbp \n");
asm ("popq %rbx \n");
asm ("swapgs \n");
// asm ("sti \n");
asm ("iretq \n");

unsigned long* idt;
unsigned long old_debug_desc;
int init (void)
{
    unsigned char idtr[10];
    gate_desc s;

    asm ("sidt %0":"=m"(idtr)::);

    idt = (unsigned long*)(*(unsigned long*)(idtr + 2));
    DBG ("idt: %lx\n", *idt);
    
    old_debug_desc = idt[3];
    DBG ("old_debug_desc: %lx\n", old_debug_desc);
    old_debug_desc = idt[2];
    DBG ("old_debug_desc: %lx\n", old_debug_desc);

    cr0_wp_off ();
    pack_gate (&s, GATE_INTERRUPT, (unsigned long) debug_handler, 0, 0, __KERNEL_CS);
    // printk ("new_debug_desc: %lx\n", *((unsigned long*)(&s)));
    idt[0x1*2] = *((unsigned long*) (&s));
    //idt[0x1*2 + 1] = 0x00000000ffffffffUL;
    cr0_wp_on();
    unsigned long cr3;
    asm volatile("movq %%cr3, %%rax; \n\t"
            "movq %%rax, %0; \n\t"
            :"=m"(cr3)::"%rax");
    // printk ("----------------------cr3 in insmod breakpoint: %lx\n", cr3);
    /* the following three variable is static in expand vma experiment */
    // last_cr3 = 0xb4969000;
    // // last_rsp = 0x7fff46158000;
    // // last_rsp = 0x7ffd956e8000;
    // // last_rsp = 0x7ffe803e1000;
    // // last_rsp = 0x555555554000;
    // last_rsp = 0x7fffffffe000;
    // last_rip = 0x0;
    // DBG ("last_cr3: %lx\n", last_cr3);
    return 0;
}

void clean (void)
{
    cr0_wp_off();
    idt[2] = old_debug_desc;
    cr0_wp_on();
    DBG ("recover debug_desc as: %lx\n", idt[2]);
    DBG (KERN_INFO "Goodbye\n");
}

module_init (init);
module_exit (clean);
