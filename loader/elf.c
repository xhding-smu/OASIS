/*
 * linux/fs/binfmt_elf.c
 *
 * These are the functions used to load ELF format executables as used
 * on SVr4 machines.  Information on the format may be found in the book
 * "UNIX SYSTEM V RELEASE 4 Programmers Guide: Ansi C and Programming Support
 * Tools".
 *
 * Copyright 1993, 1994: Eric Youngdale (ericy@cais.com).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/binfmts.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/personality.h>
#include <linux/elfcore.h>
#include <linux/init.h>
#include <linux/highuid.h>
#include <linux/compiler.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/security.h>
#include <linux/random.h>
#include <linux/elf.h>
#include <linux/utsname.h>
#include <linux/coredump.h>
#include <asm/uaccess.h>
#include <asm/param.h>
#include <asm/page.h>

/* hardcoded addresses */

// /* Jiaqi */
// #include <linux/personality.h>
// #include <asm/elf.h>
// #include <asm/vdso.h>
// #include <linux/kvm.h>
// #include <linux/kvm_host.h>
// #include <linux/imee.h>
// #include <sys/mman.h>
#include "imee.h"
// /* Jiaqi */
/* Jiaqi */
#define start_thread (*start_thread_ptr)
void (*start_thread_ptr) (struct pt_regs *regs, unsigned long new_ip, unsigned long new_sp) = 0xffffffff81011400UL; 
/* Jiaqi */
#define arch_randomize_brk (*arch_randomize_brk_ptr)
unsigned long (*arch_randomize_brk_ptr) (struct mm_struct *mm) = 0xffffffff8101bf70UL;
#define find_extend_vma (*find_extend_vma_ptr)
struct vm_area_struct* (*find_extend_vma_ptr) (struct mm_struct *mm, unsigned long addr) = 0xffffffff8117bbd0UL;
// struct vm_area_struct* (*find_extend_vma_ptr) (struct mm_struct *mm, unsigned long addr) = 0xffffffff8117bb10UL;
#define arch_setup_additional_pages (*arch_setup_additional_pages_ptr)
int (*arch_setup_additional_pages_ptr) (struct linux_binprm *bprm, int uses_interp) = 0xffffffff8105e390UL;
// int (*arch_setup_additional_pages_ptr) (struct linux_binprm *bprm, int uses_interp) = 0xffffffff8105e310UL;
// #define arch_add_exec_range_macro (*arch_add_exec_range_ptr)
// void (*arch_add_exec_range_ptr)(struct mm_struct *mm, unsigned long limit) = 0xc1001ea0U;
#define security_bprm_secureexec (*security_bprm_secureexec_ptr)
int (*security_bprm_secureexec_ptr) (struct linux_binprm *bprm) = 0xffffffff812cd330UL;
// int (*security_bprm_secureexec_ptr) (struct linux_binprm *bprm) = 0xffffffff812cd270UL;
#define get_random_int (*get_random_int_ptr)
unsigned int (*get_random_int_ptr) (void) = 0xffffffff81464440UL;
// unsigned int (*get_random_int_ptr) (void) = 0xffffffff814643c0UL;
#define arch_align_stack (*arch_align_stack_ptr)
unsigned long (*arch_align_stack_ptr) (unsigned long sp) = 0xffffffff8101bf10UL;

// #define disable_nx (*((int*) 0xffffffff81eb2fb0UL))
#define randomize_va_space (*((int*) 0xffffffff81d14360UL))
// #define VDSO32_PRELINK 0
// #define VDSO32_vsyscall 0x420
#define vdso_enabled (*((int*) 0xffffffff81d11a20UL))
#define set_personality_64bit (*set_personality_64bit_ptr)
void (*set_personality_64bit_ptr) (void) = 0xffffffff81011920UL;
// #define ADDR_START 0x08000000UL
// 
// #define loader_start 0x08200000UL

#define ADDR_START 0x7ff000000000
// #define loader_start 0x7ff000b00000
// #define loader_start 0x7ff002000000
#define loader_start 0x7ff020000000
// long kvm_vcpu_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg);
// extern struct arg_blk* imee_arg;
extern struct arg_blk imee_arg;
// extern unsigned long* dota_arg_ptr;
// extern int dota_vcpu_entry (int fd);
// unsigned long* dota_arg_ptr;
// EXPORT_SYMBOL_GPL (dota_arg_ptr);
// volatile long (*dota_vcpu_entry_ptr) (int fd);
// EXPORT_SYMBOL_GPL (dota_vcpu_entry_ptr);
// extern int (*dota_vcpu_entry_ptr) (int fd);
// #define dota_vcpu_entry (*dota_vcpu_entry_ptr)
// int (*dota_vcpu_entry_ptr) (int fd) = 0xffffffffa0598370UL;

// #define uk_offset 0xffff6a8000000000 
// #define uk_offset 0xffff7f8000000000//since ld.ko module executes before kvm.ko, so cannot wait kvm.ko to setup UK_OFFSET  
#define uk_offset 0xffff7f0000000000//since ld.ko module executes before kvm.ko, so cannot wait kvm.ko to setup UK_OFFSET  
// #define uk_offset 0x0//since ld.ko module executes before kvm.ko, so cannot wait kvm.ko to setup UK_OFFSET  
// extern unsigned long UK_OFFSET;
// #define uk_offset UK_OFFSET 
/*  /Jiaqi */
#ifndef user_long_t
#define user_long_t long
#endif
#ifndef user_siginfo_t
#define user_siginfo_t siginfo_t
#endif

int my_load_elf_binary(struct linux_binprm *bprm);
static int load_elf_library(struct file* file);
static unsigned long elf_map(struct file *, unsigned long, struct elf_phdr *,
				int, int, unsigned long);

/*
 * If we don't support core dumping, then supply a NULL so we
 * don't even try.
 */
#ifdef CONFIG_ELF_CORE
#define elf_core_dump 0xffffffff8120ac30UL
// #define elf_core_dump 0xffffffff8120ab70UL
// #define elf_core_dump (*elf_core_dump_ptr)
// static int (*elf_core_dump_ptr) (struct coredump_param *cprm) = 0xffffffff8120ac30UL;
#else
#define elf_core_dump	NULL
#endif

#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_MIN_ALIGN	ELF_EXEC_PAGESIZE
#else
#define ELF_MIN_ALIGN	PAGE_SIZE
#endif

#ifndef ELF_CORE_EFLAGS
#define ELF_CORE_EFLAGS	0
#endif

#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

static struct linux_binfmt elf_format = {
	.module		= THIS_MODULE,
	.load_binary	= my_load_elf_binary,
	.load_shlib	= load_elf_library,
	.core_dump	= elf_core_dump,
	.min_coredump	= ELF_EXEC_PAGESIZE,
};

#define BAD_ADDR(x) ((unsigned long)(x) >= TASK_SIZE)

/* Jiaqi: tarverse the target thread's root PT to find a usuable entry */
// install_int_handlers ();
// static start_guest_intercept ()
// {
//     apic->send_IPI_mask();//cannot guarantee success since the loader may run in the same cpu as the targer guest
// }

/* /Jiaqi */
static int set_brk(unsigned long start, unsigned long end)
{
	start = ELF_PAGEALIGN(start);
	end = ELF_PAGEALIGN(end);
	if (end > start) {
		unsigned long addr;
		addr = vm_brk(start, end - start);
		if (BAD_ADDR(addr))
			return addr;
	}
	current->mm->start_brk = current->mm->brk = end;
	return 0;
}

/* We need to explicitly zero any fractional pages
   after the data section (i.e. bss).  This would
   contain the junk from the file that should not
   be in memory
 */
static int padzero(unsigned long elf_bss)
{
	unsigned long nbyte;

	nbyte = ELF_PAGEOFFSET(elf_bss);
	if (nbyte) {
		nbyte = ELF_MIN_ALIGN - nbyte;
		if (clear_user((void __user *) elf_bss, nbyte))
			return -EFAULT;
	}
	return 0;
}

/* Let's use some macros to make this stack manipulation a little clearer */
#ifdef CONFIG_STACK_GROWSUP
#define STACK_ADD(sp, items) ((elf_addr_t __user *)(sp) + (items))
#define STACK_ROUND(sp, items) \
	((15 + (unsigned long) ((sp) + (items))) &~ 15UL)
#define STACK_ALLOC(sp, len) ({ \
	elf_addr_t __user *old_sp = (elf_addr_t __user *)sp; sp += len; \
	old_sp; })
#else
#define STACK_ADD(sp, items) ((elf_addr_t __user *)(sp) - (items))
#define STACK_ROUND(sp, items) \
	(((unsigned long) (sp - items)) &~ 15UL)
#define STACK_ALLOC(sp, len) ({ sp -= len ; sp; })
#endif

#ifndef ELF_BASE_PLATFORM
/*
 * AT_BASE_PLATFORM indicates the "real" hardware/microarchitecture.
 * If the arch defines ELF_BASE_PLATFORM (in asm/elf.h), the value
 * will be copied to the user stack in the same manner as AT_PLATFORM.
 */
#define ELF_BASE_PLATFORM NULL
#endif

static int
create_elf_tables(struct linux_binprm *bprm, struct elfhdr *exec,
		unsigned long load_addr, unsigned long interp_load_addr)
{
	unsigned long p = bprm->p;
	int argc = bprm->argc;
	int envc = bprm->envc;
	elf_addr_t __user *argv;
	elf_addr_t __user *envp;
	elf_addr_t __user *sp;
	elf_addr_t __user *u_platform;
	elf_addr_t __user *u_base_platform;
	elf_addr_t __user *u_rand_bytes;
	const char *k_platform = ELF_PLATFORM;
	const char *k_base_platform = ELF_BASE_PLATFORM;
	unsigned char k_rand_bytes[16];
	int items;
	elf_addr_t *elf_info;
	int ei_index = 0;
	const struct cred *cred = current_cred();
	struct vm_area_struct *vma;

	/*
	 * In some cases (e.g. Hyper-Threading), we want to avoid L1
	 * evictions by the processes running on the same package. One
	 * thing we can do is to shuffle the initial stack for them.
	 */

	p = arch_align_stack(p);

	/*
	 * If this architecture has a platform capability string, copy it
	 * to userspace.  In some cases (Sparc), this info is impossible
	 * for userspace to get any other way, in others (i386) it is
	 * merely difficult.
	 */
	u_platform = NULL;
	if (k_platform) {
		size_t len = strlen(k_platform) + 1;

		u_platform = (elf_addr_t __user *)STACK_ALLOC(p, len);
		if (__copy_to_user(u_platform, k_platform, len))
			return -EFAULT;
	}

	/*
	 * If this architecture has a "base" platform capability
	 * string, copy it to userspace.
	 */
	u_base_platform = NULL;
	if (k_base_platform) {
		size_t len = strlen(k_base_platform) + 1;

		u_base_platform = (elf_addr_t __user *)STACK_ALLOC(p, len);
		if (__copy_to_user(u_base_platform, k_base_platform, len))
			return -EFAULT;
	}

	/*
	 * Generate 16 random bytes for userspace PRNG seeding.
	 */
	get_random_bytes(k_rand_bytes, sizeof(k_rand_bytes));
	u_rand_bytes = (elf_addr_t __user *)
		       STACK_ALLOC(p, sizeof(k_rand_bytes));
	if (__copy_to_user(u_rand_bytes, k_rand_bytes, sizeof(k_rand_bytes)))
		return -EFAULT;

	/* Create the ELF interpreter info */
	elf_info = (elf_addr_t *)current->mm->saved_auxv;
	/* update AT_VECTOR_SIZE_BASE if the number of NEW_AUX_ENT() changes */
#define NEW_AUX_ENT(id, val) \
	do { \
		elf_info[ei_index++] = id; \
		elf_info[ei_index++] = val; \
	} while (0)

#ifdef ARCH_DLINFO
	/* 
	 * ARCH_DLINFO must come first so PPC can do its special alignment of
	 * AUXV.
	 * update AT_VECTOR_SIZE_ARCH if the number of NEW_AUX_ENT() in
	 * ARCH_DLINFO changes
	 */
	ARCH_DLINFO;
#endif
	NEW_AUX_ENT(AT_HWCAP, ELF_HWCAP);
	NEW_AUX_ENT(AT_PAGESZ, ELF_EXEC_PAGESIZE);
	NEW_AUX_ENT(AT_CLKTCK, CLOCKS_PER_SEC);
	NEW_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff);
	NEW_AUX_ENT(AT_PHENT, sizeof(struct elf_phdr));
	NEW_AUX_ENT(AT_PHNUM, exec->e_phnum);
	NEW_AUX_ENT(AT_BASE, interp_load_addr);
	NEW_AUX_ENT(AT_FLAGS, 0);
	NEW_AUX_ENT(AT_ENTRY, exec->e_entry);
	NEW_AUX_ENT(AT_UID, from_kuid_munged(cred->user_ns, cred->uid));
	NEW_AUX_ENT(AT_EUID, from_kuid_munged(cred->user_ns, cred->euid));
	NEW_AUX_ENT(AT_GID, from_kgid_munged(cred->user_ns, cred->gid));
	NEW_AUX_ENT(AT_EGID, from_kgid_munged(cred->user_ns, cred->egid));
 	NEW_AUX_ENT(AT_SECURE, security_bprm_secureexec(bprm));
	NEW_AUX_ENT(AT_RANDOM, (elf_addr_t)(unsigned long)u_rand_bytes);
#ifdef ELF_HWCAP2
	NEW_AUX_ENT(AT_HWCAP2, ELF_HWCAP2);
#endif
	NEW_AUX_ENT(AT_EXECFN, bprm->exec);
	if (k_platform) {
		NEW_AUX_ENT(AT_PLATFORM,
			    (elf_addr_t)(unsigned long)u_platform);
	}
	if (k_base_platform) {
		NEW_AUX_ENT(AT_BASE_PLATFORM,
			    (elf_addr_t)(unsigned long)u_base_platform);
	}
	if (bprm->interp_flags & BINPRM_FLAGS_EXECFD) {
		NEW_AUX_ENT(AT_EXECFD, bprm->interp_data);
	}
#undef NEW_AUX_ENT
	/* AT_NULL is zero; clear the rest too */
	memset(&elf_info[ei_index], 0,
	       sizeof current->mm->saved_auxv - ei_index * sizeof elf_info[0]);

	/* And advance past the AT_NULL entry.  */
	ei_index += 2;

	sp = STACK_ADD(p, ei_index);

	items = (argc + 1) + (envc + 1) + 1;
	bprm->p = STACK_ROUND(sp, items);

	/* Point sp at the lowest address on the stack */
#ifdef CONFIG_STACK_GROWSUP
	sp = (elf_addr_t __user *)bprm->p - items - ei_index;
	bprm->exec = (unsigned long)sp; /* XXX: PARISC HACK */
#else
	sp = (elf_addr_t __user *)bprm->p;
#endif


	/*
	 * Grow the stack manually; some architectures have a limit on how
	 * far ahead a user-space access may be in order to grow the stack.
	 */
	vma = find_extend_vma(current->mm, bprm->p);
	if (!vma)
		return -EFAULT;

	/* Now, let's put argc (and argv, envp if appropriate) on the stack */
	if (__put_user(argc, sp++))
		return -EFAULT;
	argv = sp;
	envp = argv + argc + 1;

	/* Populate argv and envp */
	p = current->mm->arg_end = current->mm->arg_start;
	while (argc-- > 0) {
		size_t len;
		if (__put_user((elf_addr_t)p, argv++))
			return -EFAULT;
		len = strnlen_user((void __user *)p, MAX_ARG_STRLEN);
		if (!len || len > MAX_ARG_STRLEN)
			return -EINVAL;
		p += len;
	}
	if (__put_user(0, argv))
		return -EFAULT;
	current->mm->arg_end = current->mm->env_start = p;
	while (envc-- > 0) {
		size_t len;
		if (__put_user((elf_addr_t)p, envp++))
			return -EFAULT;
		len = strnlen_user((void __user *)p, MAX_ARG_STRLEN);
		if (!len || len > MAX_ARG_STRLEN)
			return -EINVAL;
		p += len;
	}
	if (__put_user(0, envp))
		return -EFAULT;
	current->mm->env_end = p;

	/* Put the elf_info on the stack in the right place.  */
	sp = (elf_addr_t __user *)envp + 1;
	if (copy_to_user(sp, elf_info, ei_index * sizeof(elf_addr_t)))
		return -EFAULT;
	return 0;
}

#ifndef elf_map

static unsigned long elf_map(struct file *filep, unsigned long addr,
		struct elf_phdr *eppnt, int prot, int type,
		unsigned long total_size)
{
	unsigned long map_addr;
	unsigned long size = eppnt->p_filesz + ELF_PAGEOFFSET(eppnt->p_vaddr);
	unsigned long off = eppnt->p_offset - ELF_PAGEOFFSET(eppnt->p_vaddr);
	addr = ELF_PAGESTART(addr);
	size = ELF_PAGEALIGN(size);

	/* mmap() will return -EINVAL if given a zero size, but a
	 * segment with zero filesize is perfectly valid */
	if (!size)
		return addr;

	/*
	* total_size is the size of the ELF (interpreter) image.
	* The _first_ mmap needs to know the full size, otherwise
	* randomization might put this image into an overlapping
	* position with the ELF binary image. (since size < total_size)
	* So we first map the 'big' image - and unmap the remainder at
	* the end. (which unmap is needed for ELF images with holes.)
	*/
	if (total_size) {
		total_size = ELF_PAGEALIGN(total_size);
		map_addr = vm_mmap(filep, addr, total_size, prot, type, off);
		if (!BAD_ADDR(map_addr))
			vm_munmap(map_addr+size, total_size-size);
	} else
		map_addr = vm_mmap(filep, addr, size, prot, type, off);

	return(map_addr);
}

#endif /* !elf_map */

static unsigned long total_mapping_size(struct elf_phdr *cmds, int nr)
{
	int i, first_idx = -1, last_idx = -1;

	for (i = 0; i < nr; i++) {
		if (cmds[i].p_type == PT_LOAD) {
			last_idx = i;
			if (first_idx == -1)
				first_idx = i;
		}
	}
	if (first_idx == -1)
		return 0;

	return cmds[last_idx].p_vaddr + cmds[last_idx].p_memsz -
				ELF_PAGESTART(cmds[first_idx].p_vaddr);
}

/* Jiaqi */
static unsigned long load_elf_interp_new(struct elfhdr *interp_elf_ex,
		struct file *interpreter, unsigned long *interp_map_addr,
		unsigned long no_base)
{
	struct elf_phdr *elf_phdata;
	struct elf_phdr *eppnt;
	unsigned long load_addr = 0;
	int load_addr_set = 0;
	unsigned long last_bss = 0, elf_bss = 0;
	unsigned long error = ~0UL;
	unsigned long total_size;
	int retval, i, size;

    /* Jiaqi */
    unsigned long loader_next_vaddr = loader_start;
    DBG ("The first mapping address for loader: %lx\n", loader_next_vaddr);
    /*  /Jiaqi */

	/* First of all, some simple consistency checks */
	if (interp_elf_ex->e_type != ET_EXEC &&
	    interp_elf_ex->e_type != ET_DYN)
		goto out;
	if (!elf_check_arch(interp_elf_ex))
		goto out;
	if (!interpreter->f_op->mmap)
		goto out;

	/*
	 * If the size of this structure has changed, then punt, since
	 * we will be doing the wrong thing.
	 */
	if (interp_elf_ex->e_phentsize != sizeof(struct elf_phdr))
		goto out;
	if (interp_elf_ex->e_phnum < 1 ||
		interp_elf_ex->e_phnum > 65536U / sizeof(struct elf_phdr))
		goto out;

	/* Now read in all of the header information */
	size = sizeof(struct elf_phdr) * interp_elf_ex->e_phnum;
	if (size > ELF_MIN_ALIGN)
		goto out;
	elf_phdata = kmalloc(size, GFP_KERNEL);
	if (!elf_phdata)
		goto out;

	retval = kernel_read(interpreter, interp_elf_ex->e_phoff,
			     (char *)elf_phdata, size);
	error = -EIO;
	if (retval != size) {
		if (retval < 0)
			error = retval;	
		goto out_close;
	}

	total_size = total_mapping_size(elf_phdata, interp_elf_ex->e_phnum);
	if (!total_size) {
		error = -EINVAL;
		goto out_close;
	}

	eppnt = elf_phdata;
	for (i = 0; i < interp_elf_ex->e_phnum; i++, eppnt++) {
		if (eppnt->p_type == PT_LOAD) {
			int elf_type = MAP_PRIVATE | MAP_DENYWRITE;
			int elf_prot = 0;
			unsigned long vaddr = 0;
			unsigned long k, map_addr;

			if (eppnt->p_flags & PF_R)
		    		elf_prot = PROT_READ;
			if (eppnt->p_flags & PF_W)
				elf_prot |= PROT_WRITE;
			if (eppnt->p_flags & PF_X)
				elf_prot |= PROT_EXEC;
			vaddr = eppnt->p_vaddr;
			if (interp_elf_ex->e_type == ET_EXEC || load_addr_set)
				elf_type |= MAP_FIXED;
			else if (no_base && interp_elf_ex->e_type == ET_DYN)
				/* Jiaqi */
                load_addr = -vaddr;
                // loader_next_vaddr = -vaddr;
                /*  /Jiaqi */
            /* Jiaqi */
            elf_type |= MAP_POPULATE;
			map_addr = elf_map(interpreter, loader_next_vaddr + vaddr, eppnt, elf_prot, elf_type, total_size);
            DBG ("load addr for loader: %lx, size: %lx, elf_type: %lx, elf_prot: %lx, map_addr: %lx\n", loader_next_vaddr+vaddr, total_size, elf_type, elf_prot, map_addr);
            /* check whether the mapping is populated */
            // unsigned long* check_ip;
            // check_ip = 0x7ff000601210UL;
            // printk ("check whether mapping for interpreter is populated: %lx\n", *check_ip);
			// map_addr = elf_map(interpreter, load_addr + vaddr, eppnt, elf_prot, elf_type, total_size);
            /*  /Jiaqi */
			total_size = 0;
			if (!*interp_map_addr)
				*interp_map_addr = map_addr;
			error = map_addr;
			if (BAD_ADDR(map_addr))
				goto out_close;

			if (!load_addr_set &&
			    interp_elf_ex->e_type == ET_DYN) {
				/* Jiaqi */
                load_addr = map_addr - ELF_PAGESTART(vaddr);
				// loader_next_vaddr = map_addr - ELF_PAGESTART(vaddr);
                /* /Jiaqi */
                load_addr_set = 1;
			}

			/*
			 * Check to see if the section's size will overflow the
			 * allowed task size. Note that p_filesz must always be
			 * <= p_memsize so it's only necessary to check p_memsz.
			 */
			/* Jiaqi */
            k = load_addr + eppnt->p_vaddr;
			// k = loader_next_vaddr + eppnt->p_vaddr;
            /* /Jiaqi */
            if (BAD_ADDR(k) ||
			    eppnt->p_filesz > eppnt->p_memsz ||
			    eppnt->p_memsz > TASK_SIZE ||
			    TASK_SIZE - eppnt->p_memsz < k) {
				error = -ENOMEM;
				goto out_close;
			}

			/*
			 * Find the end of the file mapping for this phdr, and
			 * keep track of the largest address we see for this.
			 */
			/* Jiaqi */
            k = load_addr + eppnt->p_vaddr + eppnt->p_filesz;
			// k = loader_next_vaddr + eppnt->p_vaddr + eppnt->p_filesz;
            /* /Jiaqi */
            if (k > elf_bss)
				elf_bss = k;

			/*
			 * Do the same thing for the memory mapping - between
			 * elf_bss and last_bss is the bss section.
			 */
			/* Jiaqi */
            k = load_addr + eppnt->p_memsz + eppnt->p_vaddr;
			// k = loader_next_vaddr + eppnt->p_memsz + eppnt->p_vaddr;
            /* /Jiaqi */
            if (k > last_bss)
				last_bss = k;
		}
	}

	if (last_bss > elf_bss) {
		/*
		 * Now fill out the bss section.  First pad the last page up
		 * to the page boundary, and then perform a mmap to make sure
		 * that there are zero-mapped pages up to and including the
		 * last bss page.
		 */
		if (padzero(elf_bss)) {
			error = -EFAULT;
			goto out_close;
		}

		/* What we have mapped so far */
		elf_bss = ELF_PAGESTART(elf_bss + ELF_MIN_ALIGN - 1);

		/* Map the last of the bss segment */
		error = vm_brk(elf_bss, last_bss - elf_bss);
		if (BAD_ADDR(error))
			goto out_close;
	}

	/* Jiaqi */
    error = load_addr;
    // error = loader_next_vaddr;
    /* /Jiaqi */
out_close:
	kfree(elf_phdata);
out:
	return error;
}
/*  /Jiaqi*/

/* This is much more generalized than the library routine read function,
   so we keep this separate.  Technically the library read function
   is only provided so that we can read a.out libraries that have
   an ELF header */

static unsigned long load_elf_interp(struct elfhdr *interp_elf_ex,
		struct file *interpreter, unsigned long *interp_map_addr,
		unsigned long no_base)
{
	struct elf_phdr *elf_phdata;
	struct elf_phdr *eppnt;
	unsigned long load_addr = 0;
	int load_addr_set = 0;
	unsigned long last_bss = 0, elf_bss = 0;
	unsigned long error = ~0UL;
	unsigned long total_size;
	int retval, i, size;

	/* First of all, some simple consistency checks */
	if (interp_elf_ex->e_type != ET_EXEC &&
	    interp_elf_ex->e_type != ET_DYN)
		goto out;
	if (!elf_check_arch(interp_elf_ex))
		goto out;
	if (!interpreter->f_op->mmap)
		goto out;

	/*
	 * If the size of this structure has changed, then punt, since
	 * we will be doing the wrong thing.
	 */
	if (interp_elf_ex->e_phentsize != sizeof(struct elf_phdr))
		goto out;
	if (interp_elf_ex->e_phnum < 1 ||
		interp_elf_ex->e_phnum > 65536U / sizeof(struct elf_phdr))
		goto out;

	/* Now read in all of the header information */
	size = sizeof(struct elf_phdr) * interp_elf_ex->e_phnum;
	if (size > ELF_MIN_ALIGN)
		goto out;
	elf_phdata = kmalloc(size, GFP_KERNEL);
	if (!elf_phdata)
		goto out;

	retval = kernel_read(interpreter, interp_elf_ex->e_phoff,
			     (char *)elf_phdata, size);
	error = -EIO;
	if (retval != size) {
		if (retval < 0)
			error = retval;	
		goto out_close;
	}

	total_size = total_mapping_size(elf_phdata, interp_elf_ex->e_phnum);
	if (!total_size) {
		error = -EINVAL;
		goto out_close;
	}

	eppnt = elf_phdata;
	for (i = 0; i < interp_elf_ex->e_phnum; i++, eppnt++) {
		if (eppnt->p_type == PT_LOAD) {
			int elf_type = MAP_PRIVATE | MAP_DENYWRITE;
			int elf_prot = 0;
			unsigned long vaddr = 0;
			unsigned long k, map_addr;

			if (eppnt->p_flags & PF_R)
		    		elf_prot = PROT_READ;
			if (eppnt->p_flags & PF_W)
				elf_prot |= PROT_WRITE;
			if (eppnt->p_flags & PF_X)
				elf_prot |= PROT_EXEC;
			vaddr = eppnt->p_vaddr;
			if (interp_elf_ex->e_type == ET_EXEC || load_addr_set)
				elf_type |= MAP_FIXED;
			else if (no_base && interp_elf_ex->e_type == ET_DYN)
				load_addr = -vaddr;

			map_addr = elf_map(interpreter, load_addr + vaddr,
					eppnt, elf_prot, elf_type, total_size);
			total_size = 0;
			if (!*interp_map_addr)
				*interp_map_addr = map_addr;
			error = map_addr;
			if (BAD_ADDR(map_addr))
				goto out_close;

			if (!load_addr_set &&
			    interp_elf_ex->e_type == ET_DYN) {
				load_addr = map_addr - ELF_PAGESTART(vaddr);
				load_addr_set = 1;
			}

			/*
			 * Check to see if the section's size will overflow the
			 * allowed task size. Note that p_filesz must always be
			 * <= p_memsize so it's only necessary to check p_memsz.
			 */
			k = load_addr + eppnt->p_vaddr;
			if (BAD_ADDR(k) ||
			    eppnt->p_filesz > eppnt->p_memsz ||
			    eppnt->p_memsz > TASK_SIZE ||
			    TASK_SIZE - eppnt->p_memsz < k) {
				error = -ENOMEM;
				goto out_close;
			}

			/*
			 * Find the end of the file mapping for this phdr, and
			 * keep track of the largest address we see for this.
			 */
			k = load_addr + eppnt->p_vaddr + eppnt->p_filesz;
			if (k > elf_bss)
				elf_bss = k;

			/*
			 * Do the same thing for the memory mapping - between
			 * elf_bss and last_bss is the bss section.
			 */
			k = load_addr + eppnt->p_memsz + eppnt->p_vaddr;
			if (k > last_bss)
				last_bss = k;
		}
	}

	if (last_bss > elf_bss) {
		/*
		 * Now fill out the bss section.  First pad the last page up
		 * to the page boundary, and then perform a mmap to make sure
		 * that there are zero-mapped pages up to and including the
		 * last bss page.
		 */
		if (padzero(elf_bss)) {
			error = -EFAULT;
			goto out_close;
		}

		/* What we have mapped so far */
		elf_bss = ELF_PAGESTART(elf_bss + ELF_MIN_ALIGN - 1);

		/* Map the last of the bss segment */
		error = vm_brk(elf_bss, last_bss - elf_bss);
		if (BAD_ADDR(error))
			goto out_close;
	}

	error = load_addr;

out_close:
	kfree(elf_phdata);
out:
	return error;
}

/*
 * These are the functions used to load ELF style executables and shared
 * libraries.  There is no binary dependent code anywhere else.
 */

#define INTERPRETER_NONE 0
#define INTERPRETER_ELF 2

#ifndef STACK_RND_MASK
#define STACK_RND_MASK (0x7ff >> (PAGE_SHIFT - 12))	/* 8MB of VA */
#endif

static unsigned long randomize_stack_top(unsigned long stack_top)
{
	unsigned int random_variable = 0;

	if ((current->flags & PF_RANDOMIZE) &&
		!(current->personality & ADDR_NO_RANDOMIZE)) {
		random_variable = get_random_int() & STACK_RND_MASK;
		random_variable <<= PAGE_SHIFT;
	}
#ifdef CONFIG_STACK_GROWSUP
	return PAGE_ALIGN(stack_top) + random_variable;
#else
	return PAGE_ALIGN(stack_top) - random_variable;
#endif
}

/* Jiaqi */
unsigned long trans_hva_to_hpa (unsigned long hva)
{
    /* get PA of shared memory page */
    unsigned long *pml4_ptr, *pdpt_ptr, *pd_ptr, *pt_ptr;

    int pml4_idx, pdpt_idx, pd_idx, pt_idx;

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
                    // DBG ("physical address of shared memory is: %lx\n", pa);
                    return pa;
                }
            }
        }
    }

}
/* / */
int my_load_elf_binary(struct linux_binprm *bprm)
{
    /* Jiaqi */
    // printk (".......\n");
    /* / */
	struct file *interpreter = NULL; /* to shut gcc up */
 	unsigned long load_addr = 0, load_bias = 0;
	int load_addr_set = 0;
	char * elf_interpreter = NULL;
	unsigned long error;
	struct elf_phdr *elf_ppnt, *elf_phdata;
	unsigned long elf_bss, elf_brk;
	int retval, i;
	unsigned int size;
	unsigned long elf_entry;
	unsigned long interp_load_addr = 0;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long reloc_func_desc __maybe_unused = 0;
	int executable_stack = EXSTACK_DEFAULT;
	unsigned long def_flags = 0;
	struct pt_regs *regs = current_pt_regs();
    /* Jiaqi */
    unsigned long next_vaddr = ADDR_START;
    /*  /Jiaqi */
	struct {
		struct elfhdr elf_ex;
		struct elfhdr interp_elf_ex;
	} *loc;

	loc = kmalloc(sizeof(*loc), GFP_KERNEL);
	if (!loc) {
		retval = -ENOMEM;
		goto out_ret;
	}
	
	/* Get the exec-header */
	loc->elf_ex = *((struct elfhdr *)bprm->buf);

	retval = -ENOEXEC;
	/* First of all, some simple consistency checks */
	if (memcmp(loc->elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
		goto out;

	if (loc->elf_ex.e_type != ET_EXEC && loc->elf_ex.e_type != ET_DYN)
		goto out;
	if (!elf_check_arch(&loc->elf_ex))
		goto out;
	if (!bprm->file->f_op->mmap)
		goto out;

	/* Now read in all of the header information */
	if (loc->elf_ex.e_phentsize != sizeof(struct elf_phdr))
		goto out;
	if (loc->elf_ex.e_phnum < 1 ||
	 	loc->elf_ex.e_phnum > 65536U / sizeof(struct elf_phdr))
		goto out;
	size = loc->elf_ex.e_phnum * sizeof(struct elf_phdr);
	retval = -ENOMEM;
	elf_phdata = kmalloc(size, GFP_KERNEL);
	if (!elf_phdata)
		goto out;

	retval = kernel_read(bprm->file, loc->elf_ex.e_phoff,
			     (char *)elf_phdata, size);
	if (retval != size) {
		if (retval >= 0)
			retval = -EIO;
		goto out_free_ph;
	}

	elf_ppnt = elf_phdata;
	elf_bss = 0;
	elf_brk = 0;

	start_code = ~0UL;
	end_code = 0;
	start_data = 0;
	end_data = 0;

	for (i = 0; i < loc->elf_ex.e_phnum; i++) {
		if (elf_ppnt->p_type == PT_INTERP) {
			/* This is the program interpreter used for
			 * shared libraries - for now assume that this
			 * is an a.out format binary
			 */
			retval = -ENOEXEC;
			if (elf_ppnt->p_filesz > PATH_MAX || 
			    elf_ppnt->p_filesz < 2)
				goto out_free_ph;

			retval = -ENOMEM;
			elf_interpreter = kmalloc(elf_ppnt->p_filesz,
						  GFP_KERNEL);
			if (!elf_interpreter)
				goto out_free_ph;

			retval = kernel_read(bprm->file, elf_ppnt->p_offset,
					     elf_interpreter,
					     elf_ppnt->p_filesz);
			if (retval != elf_ppnt->p_filesz) {
				if (retval >= 0)
					retval = -EIO;
				goto out_free_interp;
			}
			/* make sure path is NULL terminated */
			retval = -ENOEXEC;
			if (elf_interpreter[elf_ppnt->p_filesz - 1] != '\0')
				goto out_free_interp;

			interpreter = open_exec(elf_interpreter);
			retval = PTR_ERR(interpreter);
			if (IS_ERR(interpreter))
				goto out_free_interp;

			/*
			 * If the binary is not readable then enforce
			 * mm->dumpable = 0 regardless of the interpreter's
			 * permissions.
			 */
			would_dump(bprm, interpreter);

			retval = kernel_read(interpreter, 0, bprm->buf,
					     BINPRM_BUF_SIZE);
			if (retval != BINPRM_BUF_SIZE) {
				if (retval >= 0)
					retval = -EIO;
				goto out_free_dentry;
			}

			/* Get the exec headers */
			loc->interp_elf_ex = *((struct elfhdr *)bprm->buf);
			break;
		}
		elf_ppnt++;
	}

	elf_ppnt = elf_phdata;
	for (i = 0; i < loc->elf_ex.e_phnum; i++, elf_ppnt++)
		if (elf_ppnt->p_type == PT_GNU_STACK) {
			if (elf_ppnt->p_flags & PF_X)
				executable_stack = EXSTACK_ENABLE_X;
			else
				executable_stack = EXSTACK_DISABLE_X;
			break;
		}

	/* Some simple consistency checks for the interpreter */
	if (elf_interpreter) {
		retval = -ELIBBAD;
		/* Not an ELF interpreter */
		if (memcmp(loc->interp_elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
			goto out_free_dentry;
		/* Verify the interpreter has a valid arch */
		if (!elf_check_arch(&loc->interp_elf_ex))
			goto out_free_dentry;
	}

	/* Flush all traces of the currently running executable */
	retval = flush_old_exec(bprm);
	if (retval)
		goto out_free_dentry;

	/* OK, This is the point of no return */
	current->mm->def_flags = def_flags;

	/* Do this immediately, since STACK_TOP as used in setup_arg_pages
	   may depend on the personality.  */
	SET_PERSONALITY(loc->elf_ex);
	if (elf_read_implies_exec(loc->elf_ex, executable_stack))
		current->personality |= READ_IMPLIES_EXEC;

	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		current->flags |= PF_RANDOMIZE;

	setup_new_exec(bprm);

	/* Do this so that we can load the interpreter, if need be.  We will
	   change some of these later */
    /* Jiaqi */
    if (strstr (bprm->filename, "testtest"))
    // if (strstr (bprm->filename, "svm_learn"))
    // if (strstr (bprm->filename, "svm-train"))
    {
        // stack top at 0x80000000
        retval = setup_arg_pages(bprm, ADDR_START + (1UL << 31), executable_stack);
        // stack top at 0xffffffff
        // retval = setup_arg_pages(bprm, ADDR_START + (1UL << 32), executable_stack);
        DBG ("The mapping address for stack: %lx\n", ADDR_START+(1UL<<31));
    }
    else
    {
    /*  /Jiaqi */
	    retval = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP),
				 executable_stack);
    /* Jiaqi */
    }
    /*  /Jiaqi */
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		goto out_free_dentry;
	}
	
	current->mm->start_stack = bprm->p;

	/* Now we do a little grungy work by mmapping the ELF image into
	   the correct location in memory. */
	for(i = 0, elf_ppnt = elf_phdata;
	    i < loc->elf_ex.e_phnum; i++, elf_ppnt++) {
		int elf_prot = 0, elf_flags;
		unsigned long k, vaddr;

		if (elf_ppnt->p_type != PT_LOAD)
			continue;

		if (unlikely (elf_brk > elf_bss)) {
			unsigned long nbyte;
	            
			/* There was a PT_LOAD segment with p_memsz > p_filesz
			   before this one. Map anonymous pages, if needed,
			   and clear the area.  */
			retval = set_brk(elf_bss + load_bias,
					 elf_brk + load_bias);
			if (retval) {
				send_sig(SIGKILL, current, 0);
				goto out_free_dentry;
			}
			nbyte = ELF_PAGEOFFSET(elf_bss);
			if (nbyte) {
				nbyte = ELF_MIN_ALIGN - nbyte;
				if (nbyte > elf_brk - elf_bss)
					nbyte = elf_brk - elf_bss;
				if (clear_user((void __user *)elf_bss +
							load_bias, nbyte)) {
					/*
					 * This bss-zeroing can fail if the ELF
					 * file specifies odd protections. So
					 * we don't check the return value
					 */
				}
			}
		}

		if (elf_ppnt->p_flags & PF_R)
			elf_prot |= PROT_READ;
		if (elf_ppnt->p_flags & PF_W)
			elf_prot |= PROT_WRITE;
		if (elf_ppnt->p_flags & PF_X)
			elf_prot |= PROT_EXEC;

		elf_flags = MAP_PRIVATE | MAP_DENYWRITE | MAP_EXECUTABLE;

		vaddr = elf_ppnt->p_vaddr;
		if (loc->elf_ex.e_type == ET_EXEC || load_addr_set) {
			elf_flags |= MAP_FIXED;
		} else if (loc->elf_ex.e_type == ET_DYN) {
			/* Try and get dynamic programs out of the way of the
			 * default mmap base, as well as whatever program they
			 * might try to exec.  This is because the brk will
			 * follow the loader, and is not movable.  */
#ifdef CONFIG_ARCH_BINFMT_ELF_RANDOMIZE_PIE
			/* Memory randomization might have been switched off
			 * in runtime via sysctl or explicit setting of
			 * personality flags.
			 * If that is the case, retain the original non-zero
			 * load_bias value in order to establish proper
			 * non-randomized mappings.
			 */
			if (current->flags & PF_RANDOMIZE)
				load_bias = 0;
			else
				load_bias = ELF_PAGESTART(ELF_ET_DYN_BASE - vaddr);
#else
			load_bias = ELF_PAGESTART(ELF_ET_DYN_BASE - vaddr);
#endif
		}

		/* Jiaqi */
        if (strstr (bprm->filename, "testtest"))
        // if (strstr (bprm->filename, "svm_learn"))
        // if (strstr (bprm->filename, "svm-train"))
        {
            // printk ("next_vaddr: %lx, vaddr: %lx\n", next_vaddr, vaddr);
            elf_flags |= MAP_POPULATE;
            error = elf_map(bprm->file, next_vaddr+vaddr, elf_ppnt, elf_prot, elf_flags, 0);
            DBG ("next_vaddr+vaddr: %lx, elf_flags: %lx, elf_prot: %lx, mapped addr: %lx\n", next_vaddr+vaddr, elf_flags, elf_prot, error);
        }
        else
        {
        /*  /Jiaqi */
            error = elf_map(bprm->file, load_bias + vaddr, elf_ppnt,
                    elf_prot, elf_flags, 0);
        /* Jiaqi */
        }
        /* Jiaqi */
        // /* Jiaqi */
        // if (strstr (bprm->filename, "testtest"))
        // {
        //     printk ("mapping segment at: %llx\n", next_vaddr);
        //     error = elf_map(bprm->file, next_vaddr, elf_ppnt, elf_prot, elf_flags, 0);
        //     next_vaddr += (0x1000 + elf_ppnt->p_filesz + ELF_PAGEOFFSET(elf_ppnt->p_vaddr)) & ~0xFFFU;
        // }
        // else
        // {
        // /*  /Jiaqi */
		//     error = elf_map(bprm->file, load_bias + vaddr, elf_ppnt,
		// 		elf_prot, elf_flags, 0);
        // /* Jiaqi */
        // }
        // /*  /Jiaqi */
		if (BAD_ADDR(error)) {
			send_sig(SIGKILL, current, 0);
			retval = IS_ERR((void *)error) ?
				PTR_ERR((void*)error) : -EINVAL;
			goto out_free_dentry;
		}

		if (!load_addr_set) {
			load_addr_set = 1;
			load_addr = (elf_ppnt->p_vaddr - elf_ppnt->p_offset);
			if (loc->elf_ex.e_type == ET_DYN) {
				load_bias += error -
				             ELF_PAGESTART(load_bias + vaddr);
				load_addr += load_bias;
				reloc_func_desc = load_bias;
			}
		}
		k = elf_ppnt->p_vaddr;
		if (k < start_code)
			start_code = k;
		if (start_data < k)
			start_data = k;

		/*
		 * Check to see if the section's size will overflow the
		 * allowed task size. Note that p_filesz must always be
		 * <= p_memsz so it is only necessary to check p_memsz.
		 */
		if (BAD_ADDR(k) || elf_ppnt->p_filesz > elf_ppnt->p_memsz ||
		    elf_ppnt->p_memsz > TASK_SIZE ||
		    TASK_SIZE - elf_ppnt->p_memsz < k) {
			/* set_brk can never work. Avoid overflows. */
			send_sig(SIGKILL, current, 0);
			retval = -EINVAL;
			goto out_free_dentry;
		}

		k = elf_ppnt->p_vaddr + elf_ppnt->p_filesz;

		if (k > elf_bss)
			elf_bss = k;
		if ((elf_ppnt->p_flags & PF_X) && end_code < k)
			end_code = k;
		if (end_data < k)
			end_data = k;
		k = elf_ppnt->p_vaddr + elf_ppnt->p_memsz;
		if (k > elf_brk)
			elf_brk = k;
	}

	loc->elf_ex.e_entry += load_bias;
	elf_bss += load_bias;
	elf_brk += load_bias;
	start_code += load_bias;
	end_code += load_bias;
	start_data += load_bias;
	end_data += load_bias;

	/* Calling set_brk effectively mmaps the pages that we need
	 * for the bss and break sections.  We must do this before
	 * mapping in the interpreter, to make sure it doesn't wind
	 * up getting placed where the bss needs to go.
	 */
	retval = set_brk(elf_bss, elf_brk);
    
    // /* Jiaqi */
    // if (strstr (bprm->filename, "testtest"))
    // {
    //     printk ("elf_bss:%lx, elf_brk: %lx. \n", elf_bss, elf_brk);
    // }
    // /* /Jiaqi */
	if (retval) {
		send_sig(SIGKILL, current, 0);
		goto out_free_dentry;
	}
	if (likely(elf_bss != elf_brk) && unlikely(padzero(elf_bss))) {
		send_sig(SIGSEGV, current, 0);
		retval = -EFAULT; /* Nobody gets to see this, but.. */
		goto out_free_dentry;
	}

	if (elf_interpreter) {
		unsigned long interp_map_addr = 0;

        /* Jiaqi */
        if (strstr (bprm->filename, "testtest"))
        // if (strstr (bprm->filename, "svm_learn"))
        // if (strstr (bprm->filename, "svm-train"))
        {
            // DBG ("elf interpreter exist for testtest \n");
		    elf_entry = load_elf_interp_new(&loc->interp_elf_ex, interpreter, &interp_map_addr, load_bias);
        }
        else
        {
        /*  /Jiaqi */
            elf_entry = load_elf_interp(&loc->interp_elf_ex,
                    interpreter,
                    &interp_map_addr,
                    load_bias);
            /* Jiaqi */
        }
        /*  /Jiaqi */
		if (!IS_ERR((void *)elf_entry)) {
			/*
			 * load_elf_interp() returns relocation
			 * adjustment
			 */
			interp_load_addr = elf_entry;
			elf_entry += loc->interp_elf_ex.e_entry;
		}
		if (BAD_ADDR(elf_entry)) {
			force_sig(SIGSEGV, current);
			retval = IS_ERR((void *)elf_entry) ?
					(int)elf_entry : -EINVAL;
			goto out_free_dentry;
		}
		reloc_func_desc = interp_load_addr;

		allow_write_access(interpreter);
		fput(interpreter);
		kfree(elf_interpreter);
	} else {
		elf_entry = loc->elf_ex.e_entry;
		if (BAD_ADDR(elf_entry)) {
			force_sig(SIGSEGV, current);
			retval = -EINVAL;
			goto out_free_dentry;
		}
	}

	kfree(elf_phdata);

	set_binfmt(&elf_format);

#ifdef ARCH_HAS_SETUP_ADDITIONAL_PAGES
	retval = arch_setup_additional_pages(bprm, !!elf_interpreter);
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		goto out;
	}
#endif /* ARCH_HAS_SETUP_ADDITIONAL_PAGES */

	install_exec_creds(bprm);
	retval = create_elf_tables(bprm, &loc->elf_ex,
			  load_addr, interp_load_addr);
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		goto out;
	}
	/* N.B. passed_fileno might not be initialized? */
	current->mm->end_code = end_code;
	current->mm->start_code = start_code;
	current->mm->start_data = start_data;
	current->mm->end_data = end_data;
	current->mm->start_stack = bprm->p;

#ifdef arch_randomize_brk
	if ((current->flags & PF_RANDOMIZE) && (randomize_va_space > 1)) {
		current->mm->brk = current->mm->start_brk =
			arch_randomize_brk(current->mm);
#ifdef CONFIG_COMPAT_BRK
		current->brk_randomized = 1;
#endif
	}
#endif

	if (current->personality & MMAP_PAGE_ZERO) {
		/* Why this, you ask???  Well SVr4 maps page 0 as read-only,
		   and some applications "depend" upon this behavior.
		   Since we do not have the power to recompile these, we
		   emulate the SVr4 behavior. Sigh. */
		error = vm_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_EXEC,
				MAP_FIXED | MAP_PRIVATE, 0);
	}

#ifdef ELF_PLAT_INIT
	/*
	 * The ABI may specify that certain registers be set up in special
	 * ways (on i386 %edx is the address of a DT_FINI function, for
	 * example.  In addition, it may also specify (eg, PowerPC64 ELF)
	 * that the e_entry field is the address of the function descriptor
	 * for the startup routine, rather than the address of the startup
	 * routine itself.  This macro performs whatever initialization to
	 * the regs structure is required as well as any relocations to the
	 * function descriptor entries when executing dynamically links apps.
	 */
	ELF_PLAT_INIT(regs, reloc_func_desc);
#endif

    /* Jiaqi */
    if (strstr (bprm->filename, "testtest"))
    {
        struct arg_blk* imee_arg_ptr;
        unsigned long ret_mmap;
        struct file* fonsite_wrap;
        struct file* fdummy_handler;
        // unsigned long cr3;
        // asm volatile("movq %%cr3, %%rax; \n\t"
        //         "movq %%rax, %0; \n\t"
        //         :"=m"(cr3)::"%rax");
        // DBG ("----------------------cr3 in execve: %lx\n", cr3);
        imee_arg_ptr = &imee_arg;
        // DBG ("cpuid for to execve testtest: %d\n", smp_processor_id());
        DBG ("rip and rsp passed to kvm are : %lx, %lx respectively.\n", elf_entry, bprm->p);
        imee_arg_ptr->syscall_flag = 0;
        imee_arg_ptr->rip = elf_entry;
        imee_arg_ptr->rsp = bprm->p;
        // DBG ("in execve, address of imee_arg: %p, vcpufd: %d, address of vcpufd: %p, sstub_entry: %lx\n", imee_arg_ptr, imee_arg.vcpu_fd, &(imee_arg.vcpu_fd));
    
        fonsite_wrap = open_exec ("/home/beverly/Documents/signal_toy/sig_wrap/sig_wrap.so");
        if (!IS_ERR(fonsite_wrap))
        {
            // DBG ("open sig_wrapper successfully\n");
            ret_mmap = vm_mmap (fonsite_wrap, onsite_wrapper_addr, 0x1000, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_POPULATE, 0);
            DBG ("fonsite_wrap mapped successful at addr: %lx\n", ret_mmap);
            if (ret_mmap < 0)
            {
                printk ("map sig_wrap fail. \n");
                goto out;
            }
        }
        
        fdummy_handler = open_exec ("/home/beverly/Documents/signal_toy/dummy_handler/hello");
        if (!IS_ERR(fdummy_handler))
        {
            // unsigned long temp_test;
            // DBG ("open dummy_handler successfully\n");
            ret_mmap = vm_mmap (fdummy_handler, dummy_handler_addr, 0x1000, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_POPULATE, 0);
            DBG ("dummy_handler mapped successful at addr: %lx\n", ret_mmap);
            // temp_test = *((unsigned long*)(dummy_handler_addr+0x730));
            // DBG ("test if dummy_handler's mapping populated: %lx\n", temp_test);
            if (ret_mmap < 0)
            {
                printk ("map signal dummy handler fail. \n");
                goto out;
            }
            
            ret_mmap = vm_mmap (fdummy_handler, user_sigflag_addr, 0x1000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_POPULATE | MAP_ANONYMOUS, 0x0);
            memset ((void*)ret_mmap, 0x0, 0x1000);
            DBG ("sig_flag page mapped successful at addr: %lx\n", ret_mmap);
            if (ret_mmap < 0)
            {
                printk ("map sig_flag page fail. \n");
                goto out;
            }
            // temp_test = *((unsigned long*) user_sigflag_addr);
            // DBG ("test if user sigflag is accessable: %lx\n", temp_test);
        }

        /* prepare onsite IDT, tss_struct, PF handler, PF stack */
        struct file* pf_handler;
        pf_handler = open_exec ("/home/beverly/Documents/test_performance/pf_stub/pf.so");
        if (!IS_ERR(pf_handler))
        {
            ret_mmap = vm_mmap (pf_handler, pf_handler_addr, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_PRIVATE | MAP_POPULATE, 0);
            DBG ("pf handler is mapped successful at addr: %lx\n", ret_mmap);
            ret_mmap = vm_mmap (pf_handler, pf_handler_addr+0x1000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_PRIVATE | MAP_POPULATE, 0);
            DBG ("pf stack is mapped successful at addr: %lx\n", ret_mmap);

            memset ((void*)(pf_handler_addr + 0x1000), 0x0, 0x1000);

            imee_arg_ptr->pf_addr = pf_handler_addr;
            imee_arg_ptr->pf_stack = pf_handler_addr + 0x1000;
        }
        /* / */

        /* allocate one page for IDT, GDT, TSS, one page for stack, and one page for debug handler,and one page for shared memory */
        if (imee_arg_ptr->instrum_flag == 1)
        {
            struct file* debug_handler;
            debug_handler = open_exec ("/home/beverly/Documents/test_performance/springboard/hook.so");
            // if (!IS_ERR(debug_handler))
            if (IS_ERR(debug_handler))
            {
                printk ("open hook.so fail. \n");
                goto out;
            }
            ret_mmap = vm_mmap (debug_handler, debug_handler_addr, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_PRIVATE | MAP_POPULATE, 0);
            DBG ("debug handler is mapped successful at addr: %lx\n", ret_mmap);
           
            /* allocate memory for shar_lib's data page and analyser's
             * descriptor tables */
            debug_handler = open_exec ("/home/beverly/Documents/test_performance/springboard/data_page");
            if (IS_ERR(debug_handler))
            {
                printk ("open data_page fail. \n");
                goto out;
            }
            ret_mmap = vm_mmap (debug_handler, debug_handler_addr+0x1000, data_page_num, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_POPULATE, 0);
            if (!access_ok(VERIFY_WRITE, ret_mmap, data_page_num))
            {
                printk ("map data pages fail. \n");
                goto out;
            }
            memset ((void*)(debug_handler_addr + 0x1000), 0x0, data_page_num );
            DBG ("data pages are mapped successful at addr: %lx\n", ret_mmap);
            
            imee_arg_ptr->exit_gate_addr = debug_handler_addr;
            imee_arg_ptr->t_idt_va = debug_handler_addr + 0x1000;
            imee_arg_ptr->t_gdt_va = debug_handler_addr + 0x2000;
            imee_arg_ptr->t_tss_va = debug_handler_addr + 0x3000;
            imee_arg_ptr->stack_addr = debug_handler_addr + 0x5000;
            imee_arg_ptr->root_pt_addr = debug_handler_addr + 0x6000;
            imee_arg_ptr->shar_va = debug_handler_addr + 0x7000;
            imee_arg_ptr->ana_t_tss_va = debug_handler_addr + 0x8000;
            imee_arg_ptr->ana_t_gdt_va = debug_handler_addr + 0x9000;

            imee_arg_ptr->shar_pa = trans_hva_to_hpa(imee_arg_ptr->shar_va);
            imee_arg_ptr->ana_t_tss_pa = trans_hva_to_hpa(imee_arg_ptr->ana_t_tss_va);
            imee_arg_ptr->ana_t_gdt_pa = trans_hva_to_hpa(imee_arg_ptr->ana_t_gdt_va);
            imee_arg_ptr->t_idt_pa = trans_hva_to_hpa(imee_arg_ptr->t_idt_va);
            imee_arg_ptr->t_gdt_pa = trans_hva_to_hpa(imee_arg_ptr->t_gdt_va);
            imee_arg_ptr->t_tss_pa = trans_hva_to_hpa(imee_arg_ptr->t_tss_va);
            imee_arg_ptr->t_tss1_pa = trans_hva_to_hpa(imee_arg_ptr->t_tss_va + 0x1000);
            imee_arg_ptr->t_tss2_pa = trans_hva_to_hpa(imee_arg_ptr->t_tss_va + 0x2000);
            DBG ("idt va: %lx, pa: %lx; \n ", imee_arg_ptr->t_idt_va, imee_arg_ptr->t_idt_pa);
            DBG ("gdt va: %lx, pa: %lx; \n ", imee_arg_ptr->t_gdt_va, imee_arg_ptr->t_gdt_pa);
            DBG ("tss va: %lx, pa: %lx; \n ", imee_arg_ptr->t_tss_va, imee_arg_ptr->t_tss_pa);
            DBG ("tss1 pa: %lx; \n ",  imee_arg_ptr->t_tss1_pa);
            DBG ("tss2 pa: %lx; \n ",  imee_arg_ptr->t_tss2_pa);
            DBG ("ana_t_tss va: %lx, pa: %lx; \n ", imee_arg_ptr->ana_t_tss_va, imee_arg_ptr->ana_t_tss_pa);
            DBG ("shar_mem va: %lx, pa: %lx; \n ", imee_arg_ptr->shar_va, imee_arg_ptr->shar_pa);
        }

        /* / */
        
        /* patch parameters on stack which are related with addr, those paras
         * are passed to ld.so*/
        unsigned long* stack_bottom;
        unsigned long stack_top_test;
        stack_bottom = bprm->p;
        stack_top_test = ADDR_START + (1UL<<31);
        for (stack_bottom; stack_bottom < stack_top_test; stack_bottom ++)
        {
            // printk ("addr: %p, content: %lx\n", stack_bottom, *stack_bottom);
            // if (*stack_bottom >= 0x7ff000000000 && *stack_bottom <= 0x7ff080000000)
            // if (*stack_bottom >= 0x7ff000000000 && *stack_bottom <= 0x7ffff8000000)
            if (*stack_bottom >= 0x7f8000000000 && *stack_bottom <= 0x7fffffffffff)
            {
                *stack_bottom += uk_offset;
                DBG ("patch ~~~~~,addr: %p, content: %lx\n", stack_bottom, *stack_bottom);
            }
        }
        // goto out;
        /* set user space breakpoint */
        unsigned long dr0, dr7;
        dr0 = elf_entry;
        dr7 = 0x401;
        asm volatile ("movq %0, %%rax; \n\t"
                "movq %%rax, %%DR0; \n\t"
                "mfence; \n\t"
                "movq %1, %%rax; \n\t"
                "movq %%rax, %%DR7; \n\t"
                ::"m"(dr0),"m"(dr7):"%rax");
        smp_mb();
        asm volatile ("movq %%DR0, %%rax; \n\t"
                "movq %%rax, %0; \n\t"
                "movq %%DR7, %%rax; \n\t"
                "movq %%rax, %1; \n\t"
                :"=m"(dr0),"=m"(dr7)::"%rax");
        DBG ("set bp in execve as dr0: %lx, dr7: %lx\n", dr0, dr7);
        start_thread(regs, elf_entry, bprm->p);
    }
    else
    {
        /* / Jiaqi */
        start_thread(regs, elf_entry, bprm->p);
        /* Jiaqi */
    }
    /* /Jiaqi */
    retval = 0;
out:
    kfree(loc);
out_ret:
    return retval;

    /* error cleanup */
out_free_dentry:
    allow_write_access(interpreter);
    if (interpreter)
        fput(interpreter);
out_free_interp:
    kfree(elf_interpreter);
out_free_ph:
    kfree(elf_phdata);
    goto out;
}

/* This is really simpleminded and specialized - we are loading an
   a.out library that is given an ELF header. */
static int load_elf_library(struct file *file)
{
	struct elf_phdr *elf_phdata;
	struct elf_phdr *eppnt;
	unsigned long elf_bss, bss, len;
	int retval, error, i, j;
	struct elfhdr elf_ex;

	error = -ENOEXEC;
	retval = kernel_read(file, 0, (char *)&elf_ex, sizeof(elf_ex));
	if (retval != sizeof(elf_ex))
		goto out;

	if (memcmp(elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
		goto out;

	/* First of all, some simple consistency checks */
	if (elf_ex.e_type != ET_EXEC || elf_ex.e_phnum > 2 ||
	    !elf_check_arch(&elf_ex) || !file->f_op->mmap)
		goto out;

	/* Now read in all of the header information */

	j = sizeof(struct elf_phdr) * elf_ex.e_phnum;
	/* j < ELF_MIN_ALIGN because elf_ex.e_phnum <= 2 */

	error = -ENOMEM;
	elf_phdata = kmalloc(j, GFP_KERNEL);
	if (!elf_phdata)
		goto out;

	eppnt = elf_phdata;
	error = -ENOEXEC;
	retval = kernel_read(file, elf_ex.e_phoff, (char *)eppnt, j);
	if (retval != j)
		goto out_free_ph;

	for (j = 0, i = 0; i<elf_ex.e_phnum; i++)
		if ((eppnt + i)->p_type == PT_LOAD)
			j++;
	if (j != 1)
		goto out_free_ph;

	while (eppnt->p_type != PT_LOAD)
		eppnt++;

	/* Now use mmap to map the library into memory. */
	error = vm_mmap(file,
			ELF_PAGESTART(eppnt->p_vaddr),
			(eppnt->p_filesz +
			 ELF_PAGEOFFSET(eppnt->p_vaddr)),
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_FIXED | MAP_PRIVATE | MAP_DENYWRITE,
			(eppnt->p_offset -
			 ELF_PAGEOFFSET(eppnt->p_vaddr)));
	if (error != ELF_PAGESTART(eppnt->p_vaddr))
		goto out_free_ph;

	elf_bss = eppnt->p_vaddr + eppnt->p_filesz;
	if (padzero(elf_bss)) {
		error = -EFAULT;
		goto out_free_ph;
	}

	len = ELF_PAGESTART(eppnt->p_filesz + eppnt->p_vaddr +
			    ELF_MIN_ALIGN - 1);
	bss = eppnt->p_memsz + eppnt->p_vaddr;
	if (bss > len)
		vm_brk(len, bss - len);
	error = 0;

out_free_ph:
	kfree(elf_phdata);
out:
	return error;
}

// static int elf_core_dump(struct coredump_params *cprm)
// {
// 	int has_dumped = 0;
// 	mm_segment_t fs;
// 	int segs;
// 	struct vm_area_struct *vma, *gate_vma;
// 	struct elfhdr *elf = NULL;
// 	loff_t offset = 0, dataoff;
// 	struct elf_note_info info = { };
// 	struct elf_phdr *phdr4note = NULL;
// 	struct elf_shdr *shdr4extnum = NULL;
// 	Elf_Half e_phnum;
// 	elf_addr_t e_shoff;
// 
// 	/*
// 	 * We no longer stop all VM operations.
// 	 * 
// 	 * This is because those proceses that could possibly change map_count
// 	 * or the mmap / vma pages are now blocked in do_exit on current
// 	 * finishing this core dump.
// 	 *
// 	 * Only ptrace can touch these memory addresses, but it doesn't change
// 	 * the map_count or the pages allocated. So no possibility of crashing
// 	 * exists while dumping the mm->vm_next areas to the core file.
// 	 */
//   
// 	/* alloc memory for large data structures: too large to be on stack */
// 	elf = kmalloc(sizeof(*elf), GFP_KERNEL);
// 	if (!elf)
// 		goto out;
// 	/*
// 	 * The number of segs are recored into ELF header as 16bit value.
// 	 * Please check DEFAULT_MAX_MAP_COUNT definition when you modify here.
// 	 */
// 	segs = current->mm->map_count;
// 	segs += elf_core_extra_phdrs();
// 
// 	gate_vma = get_gate_vma(current->mm);
// 	if (gate_vma != NULL)
// 		segs++;
// 
// 	/* for notes section */
// 	segs++;
// 
// 	/* If segs > PN_XNUM(0xffff), then e_phnum overflows. To avoid
// 	 * this, kernel supports extended numbering. Have a look at
// 	 * include/linux/elf.h for further information. */
// 	e_phnum = segs > PN_XNUM ? PN_XNUM : segs;
// 
// 	/*
// 	 * Collect all the non-memory information about the process for the
// 	 * notes.  This also sets up the file header.
// 	 */
// 	if (!fill_note_info(elf, e_phnum, &info, cprm->siginfo, cprm->regs))
// 		goto cleanup;
// 
// 	has_dumped = 1;
// 
// 	fs = get_fs();
// 	set_fs(KERNEL_DS);
// 
// 	offset += sizeof(*elf);				/* Elf header */
// 	offset += segs * sizeof(struct elf_phdr);	/* Program headers */
// 
// 	/* Write notes phdr entry */
// 	{
// 		size_t sz = get_note_info_size(&info);
// 
// 		sz += elf_coredump_extra_notes_size();
// 
// 		phdr4note = kmalloc(sizeof(*phdr4note), GFP_KERNEL);
// 		if (!phdr4note)
// 			goto end_coredump;
// 
// 		fill_elf_note_phdr(phdr4note, sz, offset);
// 		offset += sz;
// 	}
// 
// 	dataoff = offset = roundup(offset, ELF_EXEC_PAGESIZE);
// 
// 	offset += elf_core_vma_data_size(gate_vma, cprm->mm_flags);
// 	offset += elf_core_extra_data_size();
// 	e_shoff = offset;
// 
// 	if (e_phnum == PN_XNUM) {
// 		shdr4extnum = kmalloc(sizeof(*shdr4extnum), GFP_KERNEL);
// 		if (!shdr4extnum)
// 			goto end_coredump;
// 		fill_extnum_info(elf, shdr4extnum, e_shoff, segs);
// 	}
// 
// 	offset = dataoff;
// 
// 	if (!dump_emit(cprm, elf, sizeof(*elf)))
// 		goto end_coredump;
// 
// 	if (!dump_emit(cprm, phdr4note, sizeof(*phdr4note)))
// 		goto end_coredump;
// 
// 	/* Write program headers for segments dump */
// 	for (vma = first_vma(current, gate_vma); vma != NULL;
// 			vma = next_vma(vma, gate_vma)) {
// 		struct elf_phdr phdr;
// 
// 		phdr.p_type = PT_LOAD;
// 		phdr.p_offset = offset;
// 		phdr.p_vaddr = vma->vm_start;
// 		phdr.p_paddr = 0;
// 		phdr.p_filesz = vma_dump_size(vma, cprm->mm_flags);
// 		phdr.p_memsz = vma->vm_end - vma->vm_start;
// 		offset += phdr.p_filesz;
// 		phdr.p_flags = vma->vm_flags & VM_READ ? PF_R : 0;
// 		if (vma->vm_flags & VM_WRITE)
// 			phdr.p_flags |= PF_W;
// 		if (vma->vm_flags & VM_EXEC)
// 			phdr.p_flags |= PF_X;
// 		phdr.p_align = ELF_EXEC_PAGESIZE;
// 
// 		if (!dump_emit(cprm, &phdr, sizeof(phdr)))
// 			goto end_coredump;
// 	}
// 
// 	if (!elf_core_write_extra_phdrs(cprm, offset))
// 		goto end_coredump;
// 
//  	/* write out the notes section */
// 	if (!write_note_info(&info, cprm))
// 		goto end_coredump;
// 
// 	if (elf_coredump_extra_notes_write(cprm))
// 		goto end_coredump;
// 
// 	/* Align to page */
// 	if (!dump_skip(cprm, dataoff - cprm->written))
// 		goto end_coredump;
// 
// 	for (vma = first_vma(current, gate_vma); vma != NULL;
// 			vma = next_vma(vma, gate_vma)) {
// 		unsigned long addr;
// 		unsigned long end;
// 
// 		end = vma->vm_start + vma_dump_size(vma, cprm->mm_flags);
// 
// 		for (addr = vma->vm_start; addr < end; addr += PAGE_SIZE) {
// 			struct page *page;
// 			int stop;
// 
// 			page = get_dump_page(addr);
// 			if (page) {
// 				void *kaddr = kmap(page);
// 				stop = !dump_emit(cprm, kaddr, PAGE_SIZE);
// 				kunmap(page);
// 				page_cache_release(page);
// 			} else
// 				stop = !dump_skip(cprm, PAGE_SIZE);
// 			if (stop)
// 				goto end_coredump;
// 		}
// 	}
// 
// 	if (!elf_core_write_extra_data(cprm))
// 		goto end_coredump;
// 
// 	if (e_phnum == PN_XNUM) {
// 		if (!dump_emit(cprm, shdr4extnum, sizeof(*shdr4extnum)))
// 			goto end_coredump;
// 	}
// 
// end_coredump:
// 	set_fs(fs);
// 
// cleanup:
// 	free_note_info(&info);
// 	kfree(shdr4extnum);
// 	kfree(phdr4note);
// 	kfree(elf);
// out:
// 	return has_dumped;
// }
