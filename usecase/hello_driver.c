#include <stdio.h>
#include <oa.h>
struct target_context* target_ctx;
/* The APIs to install perisitent and mobile probe */
extern void install_p_hook (unsigned long addr);
extern void remove_p_hook (unsigned long addr);
extern void install_m_hook (unsigned long addr);
extern void remove_m_hook (unsigned long addr);

/* It returns the address of the next control transfer instruction */
extern unsigned long find_n_exit (unsigned long addr);

/* if addr points to a non-control-transfer instruction, it returns the address of the next instruction; for a transfer instruction, it returns the address of the
 * transfer destination */
/* OASIS also adjusts the target_ctx->rip and the stack context if necessary */
extern unsigned long find_n_entry (unsigned long addr);

/* This is to inform OASIS that analyzer is ready to analyze */
extern int wait_for_request (void);
/* Resume target's execution */
extern void t_run (void);

extern void register_int3 (unsigned long int3_handler);
extern void register_trace(unsigned long trace_handler);

/* if the analyzer does not explicitly specify a ending point, stop onsite trace when it is about to issue exit() syscall */
extern void end_ana (void);

FILE* fp;
unsigned long crtAddr;//Analyzer needs to remember the current address of tracing
unsigned long ana_ending;
unsigned long BP1;
unsigned long BP2;
unsigned long BP3;
unsigned long addr_drv_ioctl;
unsigned long addr_drv_sta;
unsigned long addr_drv_end;

unsigned long trans_fd_to_dev (int fd)
{
    unsigned long *ts_ptr, *files_ptr, *fdt, *file_ptr, *flop_ptr;
    unsigned long *fdarray;//current fd array
    unsigned long off_ts_files, off_files_fdt, off_fdt_fd, off_file_flop, off_flop_unlocked_ioctl;
    unsigned long unlocked_ioctl;

    off_ts_files = 0x670;
    off_files_fdt = 0x20;
    off_fdt_fd = 0x8;
    off_file_flop = 0x28;
    off_flop_unlocked_ioctl = 0x48;

    ts_ptr = (unsigned long*) (target_ctx->GS_BASE+0x15440);//TASK_STRUCT in the PER_CPU area
    
    files_ptr = (unsigned long*) (((unsigned long) ts_ptr) + off_ts_files);
    // fprintf (fp, "files_struct addr: %p. \n", files_ptr);
    files_ptr = (unsigned long*) (*files_ptr);
    // fprintf (fp, "files_struct addr: %p. \n", files_ptr);
    fdt = (unsigned long*)(*((unsigned long*) (((unsigned long) files_ptr) + off_files_fdt)));
    // fprintf (fd, "fdt addr: %p. content: %lx. \n", fdt, *fdt);
    fdarray = (unsigned long*)(*((unsigned long*) (((unsigned long) fdt) + off_fdt_fd)));
    file_ptr = (unsigned long*)(fdarray[fd]);
    flop_ptr = (unsigned long*)(*((unsigned long*) (((unsigned long) file_ptr) + off_file_flop)));
    // fprintf (fp, "flop addr: %p. content: %lx. \n", flop_ptr, *flop_ptr);
    unlocked_ioctl = *((unsigned long*) (((unsigned long) flop_ptr) + off_flop_unlocked_ioctl));
    fprintf (fp, "ioctl handler addr: %lx. \n", unlocked_ioctl);
    return unlocked_ioctl;
}
void ana_trace_handler (void)
{
    unsigned long staAddr;
    remove_m_hook (crtAddr);
    staAddr = find_n_entry (crtAddr);
    if (staAddr == ana_ending)
    {
        fprintf (fp, "one round of analysis ends here. \n");
        end_ana ();
        /* request for a new round of analysis */
        int ret = wait_for_request ();
        if (ret)
        {
            t_run ();
        }
    }
    /* The control transfer destination is out of the driver */
    else if (staAddr >= addr_drv_end || staAddr <= addr_drv_sta)
    {
        crtAddr = *((unsigned long*)(target_ctx->rsp));
        fprintf (fp, "execution transfers to outside, set BP at: %lx. \n", crtAddr);
        BP3 = crtAddr;
        install_p_hook (BP3);
    }
    else
    {
        fprintf (fp, "block entry addr: %lx. \n", crtAddr);
        crtAddr = find_n_exit (staAddr);
        fprintf (fp, "block exit addr: %lx. \n", crtAddr);
        install_m_hook (crtAddr);
    }
    t_run ();
    return;
}

void ana_int3_handler (void)
{
    fprintf (fp, "INT3 event, RIP:%lx, RSP:%lx, CS:%x.\n", target_ctx->saved_rip, target_ctx->saved_rsp, target_ctx->saved_cs);
    
    unsigned long int3_rip = target_ctx->saved_rip - 1;
    if (int3_rip == BP1)
    {
        if (target_ctx->rax == 16)
        {
            int fd = target_ctx->rdi;
            addr_drv_ioctl = trans_fd_to_dev (fd);
            /* initialize the driver's boundary, based on its size and the
             * position of ioctl handler in the driver */
            addr_drv_sta = addr_drv_ioctl - 0x901;
            addr_drv_end = addr_drv_ioctl + 0x138;

            BP2 = addr_drv_ioctl;
            install_p_hook (BP2);
        }
    }
    else if (int3_rip == BP2)
    {
        fprintf (fp, "driver's ioctl handler invokes.\n");
        remove_p_hook(BP2);
        /* initialize the analysis ending point */
        ana_ending = *((unsigned long*) target_ctx->rsp);
        crtAddr = find_n_exit(BP2);
        install_m_hook (crtAddr);
    }
    else if (int3_rip == BP3)
    {
        fprintf (fp, "execution returns to driver.\n");
        remove_p_hook(BP3);
        crtAddr = find_n_exit(BP3);
        install_m_hook (crtAddr);
    }
    t_run ();
    return;
}

int main (void)
{
    //register handlers 
    register_int3 ((unsigned long) ana_int3_handler);
    register_trace((unsigned long) ana_trace_handler);
    
    fp = fopen ("output.txt", "w");

    int ret = wait_for_request ();
    if (ret)
    {
        crtAddr = target_ctx->rip;
        BP1 = target_ctx->T_SYSCALL_ENTRY_AFTER_SWAPGS;//install hook at kernel after it swaps gs 
        install_p_hook (BP1);
        t_run ();
    }
    return 0;
}
