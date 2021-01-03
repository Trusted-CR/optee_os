/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef __KERNEL_USER_MODE_CTX_STRUCT_H
#define __KERNEL_USER_MODE_CTX_STRUCT_H

#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <mm/tee_mmu_types.h>
#include <trusted_cr/trusted_cr_checkpoint.h>

struct user_mode_ctx {
	struct vm_info vm_info;
	struct tee_pager_area_head *areas;
#if defined(CFG_WITH_VFP)
	struct thread_user_vfp_state vfp;
#endif
	struct tee_ta_ctx ctx;
	struct core_mmu_map map;
	struct trusted_cr_checkpoint * checkpoint;
	bool is_trusted_cr_checkpoint;
};
#endif /*__KERNEL_USER_MODE_CTX_STRUCT_H*/

