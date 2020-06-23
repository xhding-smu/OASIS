#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oa.h>

/* The structure holds the saved target's CPU context */
struct target_context* target_ctx;

/* The APIs to install and remove INT3-probe and JMP-probe respectively */
extern void install_int3_probe (unsigned long addr); 
extern void remove_int3_probe (unsigned long addr);
extern void install_trace_probe (unsigned long addr); 
extern void remove_trace_probe (unsigned long addr);

/* It returns the address of the exit instruction in current basic block, i.e, the next control transfer instruction */
extern unsigned long find_n_exit (unsigned long addr);

/* If addr points to a non-control-transfer instruction, the function returns addr; if addr points to a transfer instruction, the function returns the address of the transfer destination */
/* OASIS also adjusts the target_ctx->rip and the stack context if necessary */
extern unsigned long find_n_entry (unsigned long addr);

/* This is to inform OASIS that analyzer is ready to analyze */
extern int wait_for_request (void);
/* start/resume the target's execution */
extern void t_run (void);
/* end analysis request */
extern void end_ana (void);

/* For the analyzer to register different handlers */
extern void register_int3 (unsigned long int3_handler);
extern void register_trace (unsigned long trace_handler);
extern void register_pf (unsigned long pf_handler);

#define max_slice 8 //the number of sliced instructions
FILE* fp;
unsigned long slice_array[max_slice]; //the array stores the addresses if the sliced instruction, it is sorted from low addresses to high addresses. 
unsigned long crtAddr; //The analyzer needs to remember the current address of tracing
unsigned long BP1; //The address of breakpoint1
  
/* log the #PF event and end the analysis */
void ana_pf_handler (void)
{
    fprintf (fp,"#PF event, RIP:%lx, RSP:%lx, ERR_CODE:%lx. CR2: %lx. \n", target_ctx->saved_rip, target_ctx->saved_rsp, target_ctx->err_code, target_ctx->cr2);
    fclose (fp);
    end_ana ();
    return;
}

unsigned long *addr_len, *addr_sg, *addr_qc, *addr_n_elem;//the stack address where stores the local variables;
struct ata_queued_cmd* qc;
struct ata_port* ap;
struct ata_bmdma_prd* prd;
int prd_addr, prd_flags_len;
struct scatterlist* sg;
int sg_len, sg_dma_addr;
int pi, len;

/* Initialize the address of interested objects. Some are stored in the stack, some are
 * in the registers. Please acquire fresh values of them from stack or registers
 * accordingly */ 
void init_local (void)
{
    addr_len = target_ctx->rbp-0x2c;
    addr_sg = target_ctx->rbp-0x38;
    addr_qc = target_ctx->rbp-0x40;
    prd = target_ctx->r15;
    pi = target_ctx->r14;
    return;
}

/* A JMP-probe invokes the ana_trace_handler() */
void ana_trace_handler (void)
{
    unsigned long staAddr;
    int slice_idx = -1;
    int i;
    
    remove_trace_probe (crtAddr);//remove the last JMP-probe
    
    /* If it is a sliced instruction, dump the corresponding object and its
     * member */
    for (i = 0; i < max_slice; i ++)
    {
        if (slice_array[i] == crtAddr)
        {
            slice_idx = i;
            break;
        }
    }
    switch (slice_idx)
    {
        case 0 : //after line 2622
            init_local ();
            break;
        case 1 : //after line 2632, get current sg pointer from stack
            sg = *addr_sg;
            sg_len = sg->length;
            sg_dma_addr = sg->dma_address;
            fprintf (fp, "current sg at: %p, its length: 0x%x, its dma address: 0x%x. \n", sg, sg_len, sg_dma_addr);
            break;
        case 2 : //after line 2638 
            len = *addr_len; 
            fprintf (fp, "len is updated as: 0x%x. \n", len);
            break;
        case 3 : //after line 2641, get current pi from R14 register 
            pi = target_ctx->r14;
            prd_addr = prd[pi].addr;
            prd_flags_len = prd[pi].flags_len;
            fprintf (fp, "current pi: %d, updated prd array element with addr: %lx, flags_len: %lx. \n", pi, prd_addr, prd_flags_len);
            break;
        case 4 : //correspond to line 2650 
            fprintf (fp, "the final pi: 0x%lx. \n", target_ctx->r14);
            break;
        case 5: //correspond to line 2650 
            fprintf (fp, "current prd element addr : %lx. \n", target_ctx->r15);
            break;
        case 6 : //correspond to line 2650, the address of prd.flags_len stores in RDI register
            fprintf (fp, "address passed to KASAN: %lx. \n", target_ctx->rdi);
            break;
        default :
            break;
    }
    /* / */
    
    staAddr = find_n_entry (crtAddr);
    crtAddr = find_n_exit (staAddr);
    fprintf (fp, "the execution is about to transfer to: %lx, block ends at: %lx. \n", staAddr, crtAddr);
    
    /* decide the next place to insert JMP-probe. If there is a sliced
     * instruction within the current basic block, insert the probe at the sliced
     * instruction; if not, insert the probe at the exit instruction of current block */
    for (i = 0; i < max_slice; i ++)
    {
        if (slice_array[i] > staAddr && slice_array[i] < crtAddr)
        {
            crtAddr = slice_array[i];
            break;
        }
    }
    /* / */

    install_trace_probe (crtAddr);
    
    /* recording the probe location */
    fprintf (fp, "JMP-probe installed at: %lx, \n", crtAddr);

    t_run (); //resume target;
    return;
}

/* A INT3-probe invokes the ana_int3_handler() */
void ana_int3_handler (void)
{
    unsigned long int3_rip = target_ctx->saved_rip;
    int i;

    if (int3_rip == BP1)
    {
        remove_int3_probe(BP1); //remove the INT3-probe
        fprintf (fp, "target function invoked. \n");
        
        /* collect info from the input ata_queue_cmd pointer, it is stored in RDI
         * register */
        /* Analyzer introspects the target's objects by directly dereferencing them */
        qc = (struct ata_queued_cmd*) target_ctx->rdi;
        ap = qc->ap;
        prd = ap->bmdma_prd;
        fprintf (fp, "from the input parameter ata_queued_cmd, it is at: %p. its ata_port at: %p, its ata_bmdma_prd at: %p. \n", qc, ap, prd);
        sg = qc->sg;
        n_elem = qc->n_elem;
        for (i = 0; i < n_elem; i ++) //travese the sg list, save their addresses and lengths respectively
        {
            sg_len = sg->length;
            sg_dma_addr = sg->dma_address;
            fprintf (fp, "scatterlist sg at: %p, sg_len: 0x%x, sg_dma_len: 0x%x. \n", sg, sg_len, sg_dma_addr);
            sg ++;
        }
        /* / */

        /* decide the next place to insert JMP-probe. If there is a sliced
         * instruction within the current basic block, insert the probe at the sliced
         * instruction; if not, insert the probe at the exit instruction of current block */
        crtAddr = find_n_exit(BP1);
        for (i = 0; i < max_slice; i ++)
        {
            if (slice_array[i] > int3_rip && slice_array[i] < crtAddr)
            {
                // install_trace_probe(slice_array[i]);
                crtAddr = slice_array[i];
                break;
            }
        }
        /* / */
            
        install_trace_probe (crtAddr);

        /* record the probe location */
        fprintf (fp, "JMP-probe installed at: %lx, \n", crtAddr);
    }

    t_run (); //resume target;
    return;
}

int main (void)
{
    //register handlers to OASIS
    register_int3 ((unsigned long) ana_int3_handler);
    register_trace((unsigned long) ana_trace_handler);
    register_pf((unsigned long) ana_pf_handler);
    
    init_slice_array (); //load the addresses of the sliced instructions into slice_array[];
    
    fp = fopen ("output.txt", "w"); //open a local file to save the runtime collected information;
    if (fp != NULL)
    {
        int ret = wait_for_request (); //inform OASIS that it is ready to analyze;
        if (ret)
        {
            unsigned long addr_t_func = 0xffffffff9b5a2420; //defines the address of the target function;
            BP1 = addr_t_func;
            install_int3_probe (BP1); //insert an INT3-probe at the target function;
            fprintf (fp, "analysis starts, insert BP at: %lx. \n", BP1);
            t_run (); // start to execute the target;
        }
    }
    return 0;
}
