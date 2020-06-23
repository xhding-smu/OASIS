#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/binfmts.h>

int my_load_elf_binary(struct linux_binprm *bprm);

void* old_loader_start = (void*) 0xffffffff8120c320UL;
// void* old_loader_start = (void*) 0xffffffff8120c260UL;
// void* old_loader_start = (void*) 0xffffffff8120f5c0UL;

unsigned char inst_stub[5];
unsigned char old_bytes[5];
// 
void print_bytes (void* p, int len)
{
    int i = 0;
    for ( ; i < len; i ++)
    {
        unsigned char* pp = (unsigned char*) p;
        printk ("%02x ", pp[i]);
    }
    printk ("\n");

}

void clear_WP_bit (void)
{
    unsigned long cr0;

    asm volatile ("movq %%cr0, %0;":"=r"(cr0)::);
    printk (KERN_ERR "changing CR0 from %X\n", cr0);
    cr0 &= ~(1 << 16);
    printk (KERN_ERR "to %X, WP_bit cleared.\n", cr0);
    asm volatile ("movq %0, %%cr0;"::"r"(cr0):);
}

void set_WP_bit (void)
{
    unsigned long cr0;

    asm volatile ("movq %%cr0, %0;":"=r"(cr0)::);
    printk (KERN_ERR "changing CR0 from %X\n", cr0);
    cr0 |= (1 << 16);
    printk (KERN_ERR "to %X, WP_bit set\n", cr0);
    asm volatile ("movq %0, %%cr0;"::"r"(cr0):);
}

int proc_filter (struct linux_binprm *bprm)
{
    // printk ("invoked. comm : %s. \n", current->comm);
    if (strstr(bprm->filename, "testtest"))
    {
        // printk ("testtest process. \n");
        int ret = my_load_elf_binary(bprm);
        unsigned long* temp_rsp;
        asm volatile("movq %%rsp, %0; \n\t"
                :"=m"(temp_rsp)::);
        int i =0;
        // for (i; i<40; i ++)
        // {
        //     printk ("rsp: %p, content: %lx. \n", temp_rsp, *temp_rsp);
        //     temp_rsp ++;
        // }
        return ret;
    }
    else
        return 1;
}

static void branch (void);
asm (" .text");
asm (" .type    branch, @function");
asm ("branch: \n");
asm ("pushfq \n");
asm ("pushq %rax \n");
asm ("pushq %rbx \n");
asm ("pushq %rcx \n");
asm ("pushq %rdx \n");
asm ("pushq %rdi \n");
asm ("pushq %rsi \n");
asm ("pushq %rbp \n");
asm ("pushq %r8 \n");
asm ("pushq %r9 \n");
asm ("pushq %r10 \n");
asm ("pushq %r11 \n");
asm ("pushq %r12 \n");
asm ("pushq %r13 \n");
asm ("pushq %r14 \n");
asm ("pushq %r15 \n");
asm ("callq proc_filter \n");
asm ("popq %r15 \n");
asm ("popq %r14 \n");
asm ("popq %r13 \n");
asm ("popq %r12 \n");
asm ("popq %r11 \n");
asm ("popq %r10 \n");
asm ("popq %r9 \n");
asm ("popq %r8 \n");
asm ("popq %rbp \n");
asm ("popq %rsi \n");
asm ("popq %rdi \n");
asm ("popq %rdx \n");
asm ("popq %rcx \n");
asm ("popq %rbx \n");

asm ("cmp $0x0, %rax \n");
asm ("je 1f \n");

asm ("popq %rax \n");
asm ("popfq \n");
asm ("retq \n");

asm ("1: \n");
asm ("addq $0x18, %rsp \n");
asm ("retq \n");

int init ( void)
{

    // WP bit may be getting into our way...
    clear_WP_bit ();

    printk ("old code: ");
    print_bytes (old_loader_start, 26);
    printk ("addr of my_load_elf_binary: %p\n", branch);

    unsigned long offset = ((char*) branch) - ((char*) old_loader_start + 5);
    printk ("offset: %lx\n", offset);
    // inst_stub[0] = 0xe9;
    inst_stub[0] = 0xe8;
    inst_stub[1] = (offset >> 0) & 0xFF;
    inst_stub[2] = (offset >> 8) & 0xFF;
    inst_stub[3] = (offset >> 16) & 0xFF;
    inst_stub[4] = (offset >> 24) & 0xFF;
    printk ("inst_stub: ");
    print_bytes (inst_stub, 5);

    memcpy (old_bytes, old_loader_start, 5);
    memcpy (old_loader_start, inst_stub, 5);
    set_WP_bit ();

    printk ("backup old code: ");
    print_bytes (old_bytes, 5);
    printk ("new loader code: ");
    print_bytes (old_loader_start, 5);

    // now crash..

    return 0;
}

void clean ( void )
{
    clear_WP_bit ();
    memcpy (old_loader_start, old_bytes, 5);
    set_WP_bit ();
}

MODULE_LICENSE ("GPL");
module_init (init);
module_exit (clean);
