#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <linux/kvm.h>
#include <err.h>

#include <sched.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct arg_blk
{
    int instrum_flag;
    int pl_switch;
    unsigned long exit_gate_addr;
    unsigned long t_idt_va;
    unsigned long t_gdt_va;
    unsigned long t_tss_va;
    unsigned long t_idt_pa;
    unsigned long t_gdt_pa;
    unsigned long t_tss_pa;
    unsigned long t_tss1_pa;
    unsigned long t_tss2_pa;
    unsigned long stack_addr;
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

struct arg_blk args;

int kvm, vmfd, vcpufd;
struct kvm_run *run;
size_t mmap_size;

static __attribute__ ((noinline)) unsigned long long rdtsc(void)
{
    unsigned long long x;
    asm volatile (".byte 0x0f, 0x31" : "=A"(x));
    return x;
}

int main(int argc, char *argv[])
{
    cpu_set_t cpuset;
    CPU_ZERO (&cpuset);
    CPU_SET (1, &cpuset);
    sched_setaffinity (0, sizeof (cpuset), &cpuset);
    
    printf ("PID: %d\n", getpid());

    unsigned long long t0, t1;
    asm volatile("mfence; \n\t");
    t0 = rdtsc();
    // kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    kvm = open("/dev/kvm", O_RDWR);
    printf ("kvm: %d\n", kvm);
    if (kvm == -1)
        err(1, "/dev/kvm");
    int ret;
    ret = ioctl (kvm, KVM_GET_API_VERSION, NULL);
    printf ("ret of ioctl kvm: %d\n", ret);

    vmfd = ioctl (kvm, KVM_CREATE_VM, (unsigned long)0);
    /* change FD_CLOEXEC flag */
    int flags = fcntl (vmfd, F_GETFD);
    // printf ("vmfd: %d, flags: %lx\n", vmfd, flags);
    fcntl (vmfd, F_SETFD, 0);
    flags = fcntl(vmfd, F_GETFD);
    printf ("after reset, vmfd: %d, flags: %d\n", vmfd, flags);
    /* / */

    printf ("ret of ioctl creat vm: %d\n", vmfd);
    uint8_t* memory;
    memory = mmap (NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!memory)
        err (1, "allocating guest memory");
    printf ("address of user memory: %p\n", memory);

    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .guest_phys_addr = 0x1000,
        .memory_size = 0x1000,
        .userspace_addr = (uint64_t)memory,
    };
    ret = ioctl (vmfd, KVM_SET_USER_MEMORY_REGION, &region);
    printf ("ret of vm user memory set: %d\n", ret);

     
    vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);
    if (vcpufd == -1)
        err(1, "KVM_CREATE_VCPU");
    /* change FD_CLOEXEC flag */
    flags = fcntl (vcpufd, F_GETFD);
    printf ("vcpufd: %d, flags: %d\n", vcpufd, flags);
    fcntl(vcpufd, F_SETFD, 0);
    flags = fcntl (vcpufd, F_GETFD);
    printf ("after reset, vcpufd: %d, flags: %d\n", vcpufd, flags);
    /* / */
    
    // /* Map the shared kvm_run structure and following data.  */
    // int ret;
    ret = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (ret == -1)
        err(1, "KVM_GET_VCPU_MMAP_SIZE");
    mmap_size = ret;
    printf ("vcpu size: %d\n", ret);
    if (mmap_size < sizeof(*run))
        errx(1, "KVM_GET_VCPU_MMAP_SIZE unexpectedly small");
    run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
    if (!run)
        err(1, "mmap vcpu");

    /* enable or disbale instrumentation by the flag, 1:enable, 0: disable */
    args.instrum_flag = 1;
    // args.instrum_flag = 0;
    // args.pl_switch = 1;
    args.pl_switch = 0;
    /* pass the vcpufd to run_imee in the execve */ 
    
    args.vcpu_fd = vcpufd;
    // pass hardcoded cr3 
    // args.hard_cr3 = 0x9ed8f000;
    // args.hard_cr3 = 0x0;
    args.hard_cr3 = strtol(argv[1], NULL, 16);
    
    ret = ioctl(vcpufd, 0xAEB0, &args);
    if (ret == -1)
        err(1, "KVM_IMEE_SETUP");
    
    // t1 = rdtsc();
    // printf ("t1-t0: %d\n", t1-t0);
    // sleep(0x10000);
   
    printf ("get guest context done !!!, sizeof arg_blk: %lx\n", sizeof(args));
    pid_t fpid = fork();
    printf ("return value of fork : %d\n", fpid);
    if (!fpid) /* this is child process */
    {
        printf ("this is child process\n");
        cpu_set_t cpuset;
        CPU_ZERO (&cpuset);
        CPU_SET (1, &cpuset);
        sched_setaffinity (0, sizeof (cpuset), &cpuset);
        
        // unsigned long long t0;
        asm ("mfence \n");
        t0 = rdtsc(); 
        printf ("t0 before execve: %llx\n", t0);
        // t1 = rdtsc();
        // printf ("t1-t0: %d, 0x%lx\n", t1-t0, t1-t0);
        // // char *args[] = {"/home/beverly/Downloads/svm_light/svm_learn", "/home/beverly/Downloads/svm_light/example1/train.dat", "/home/beverly/Downloads/svm_light/example1/model", (char *)0};
        // char *ex_args[] = {"/home/beverly/Downloads/libsvm-master/svm-train", "/home/beverly/Downloads/libsvm-master/heart_scale", (char *)0};
        // execve(ex_args[0], ex_args, NULL);
        // execve("/home/beverly/Documents/fuse/analyzer/testtest", NULL, NULL);
        // execve("/home/beverly/Documents/test_ptr/testtest", NULL, NULL);
        
        // execve("/home/beverly/Documents/test_performance/testtest", NULL, NULL);
        
        // execve("/home/beverly/Documents/test_performance/hello", NULL, NULL);
        // execve("/home/beverly/Documents/test_performance/host_tester/testtest", NULL, NULL);
        // execve("/home/beverly/Documents/test_performance/host_tester/hello", NULL, NULL);
        // execve("/home/beverly/Documents/network_test/client/testtest", NULL, NULL);
        // execve("/home/beverly/Documents/network/client/testtest", NULL, NULL);
        // char *ex_args[] = {"/home/beverly/Documents/test_performance/testtest", "-H", "10.4.16.55", "-t", "UDP_STREAM", "--", "-m", "1024", 0};
        // char *ex_args[] = {"/home/beverly/Documents/test_performance/testtest", "0xabh", 0};
        // char *ex_args[] = {"/home/beverly/Documents/test_performance/testtest", "10.4.16.55", 0};
        // char *ex_args[] = {"/home/beverly/Documents/test_performance/testtest", 0};
        // char *ex_args[] = {"/home/beverly/Documents/test_performance/testtest","sample.ssh.com", 0};
        // char *ex_args[] = {"/home/beverly/Documents/test_performance/testtest","10.4.16.37", 0};
        // char *ex_args[] = {"/home/beverly/Documents/test_performance/testtest", 0};
        // char *ex_args[] = {"/home/beverly/Documents/test_performance/testtest", "beverly@10.4.20.18", 0};
        // char *ex_args[] = {"/home/beverly/Documents/test_performance/testtest", "beverly-Veriton-M4630G", 0};
        // char *ex_args[] = {"/home/beverly/Documents/test_performance/testtest", 0};
        char *ex_args[] = {"/home/beverly/Documents/test_performance/testtest", "/home/beverly/klee-2.0/klee-2.0/examples/get_sign/get_sign.bc", 0};
        // char *ex_args[] = {"/home/beverly/Documents/test_performance/testtest", "100000", 0};
        // char *ex_args[] = {"/home/beverly/Documents/test_performance/testtest", "10.4.16.37", 0};
        // char *ex_args[] = {"/home/beverly/Documents/netperf/netperf-master/src/netperf", "-H", "10.4.16.55", "-t", "UDP_STREAM", "--", "-m", "1024", 0};
        execve(ex_args[0], ex_args, NULL);
        printf ("execute su\n");
    }
    else
    {
        wait (NULL); /* wait till the child terminates */
    }
    
    return 0;
}

