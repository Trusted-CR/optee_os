#include <trusted_cr/trusted_cr_checkpointing.h>
#include <kernel/user_ta.h>

void checkpoint_back(struct thread_abort_regs *a_regs, struct thread_svc_regs *s_regs, uint32_t pc) {
	struct thread_specific_data *tsd = thread_get_tsd();
	if(is_user_ta_ctx(tsd->ctx)) {
		struct user_ta_ctx * ctx = to_user_ta_ctx(tsd->ctx);

		if(ctx->uctx.is_trusted_cr_checkpoint) {
			struct trusted_cr_checkpoint * checkpoint = ctx->uctx.checkpoint;


            uint64_t * abort_regs;
            if(a_regs != NULL)
                abort_regs = &a_regs->x0;
            else
                abort_regs = &s_regs->x[0];

            // Checkpoint all registers
            for(int i = 0; i < 31; i++) {
                checkpoint->regs.regs[i] = abort_regs[i];
            }

			// Checkpoint the program counter
			checkpoint->regs.entry_addr = pc;
			// Checkpoint the stack pointer
            if(a_regs != NULL)
			    checkpoint->regs.stack_addr = a_regs->sp_el0;
            else
                checkpoint->regs.stack_addr = s_regs->sp_el0;
			// Checkpoint back pstate
            if(a_regs != NULL)
			    checkpoint->regs.pstate = a_regs->spsr;
            else
                checkpoint->regs.pstate = s_regs->spsr;

			// Checkpoint back tpidr_el0
			asm("mrs %0, tpidr_el0" : "=r" (checkpoint->regs.tpidr_el0_addr));

			// Only backup the floating point registers if the program actually used it
			// Otherwise wrong values will be backed up. 
			if(checkpoint->regs.fp_used) {
				if(ctx->uctx.vfp.saved) {
					// Checkpoint back the FPCR register
					checkpoint->regs.fpcr = ctx->uctx.vfp.vfp.fpcr;
					// Checkpoint back the FPSR register
					checkpoint->regs.fpsr = ctx->uctx.vfp.vfp.fpsr;
					
					// Store vfp registers
					volatile uint64_t * p = NULL;
					for(uint8_t i = 0, vregs_idx = 0; i < 32; i++) {
						p = (volatile uint64_t *) &ctx->uctx.vfp.vfp.reg[i].v[0];
						checkpoint->regs.vregs[vregs_idx++] = *p;
						p++;
						checkpoint->regs.vregs[vregs_idx++] = *p;
					}
				} else {
					// Temporarily enable vfp to retrieve registers
					bool vfp_enabled = true;
					if(!vfp_is_enabled()) {
						// The state was probably lazy saved, that means that the values are still in the vfp registers.

						// To restore the original vfp state after reading the registers.
						vfp_enabled = false;
						
						// Temporarily enable to retrieve registers.
						vfp_enable();
					}

					// Store vfp registers
					vfp_save_extension_regs(checkpoint->regs.vregs);

					// Checkpoint back the FPCR register
					checkpoint->regs.fpcr = read_fpcr();
					// Checkpoint back the FPSR register
					checkpoint->regs.fpsr = read_fpsr();				

					// vfp was disabled beforehand, so disable it again.
					if(!vfp_enabled)
						vfp_disable();
				}
			}
		}
	}
}