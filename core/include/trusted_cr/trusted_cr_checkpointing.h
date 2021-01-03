#ifndef __TRUSTED_CR_CHECKPOINTING_H
#define __TRUSTED_CR_CHECKPOINTING_H

#include <kernel/thread.h>
#include "../kernel/vfp_private.h"

void checkpoint_back(struct thread_abort_regs *a_regs, struct thread_svc_regs *s_regs, uint32_t pc);

#endif /*__TRUSTED_CR_CHECKPOINTING_H*/
