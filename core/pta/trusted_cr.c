// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */
#include <kernel/pseudo_ta.h>
#include <kernel/user_mode_ctx.h>
#include <mm/tee_mmu.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <trusted_cr/jsmn.h>
#include <trusted_cr/trusted_cr_checkpoint_parser.h>

#define TA_NAME		"trusted_cr.ta"

#define TRUSTED_CR_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1c } }

#define TRUSTED_CR_CHECKPOINT_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1d } }

#define TRUSTED_CR_LOAD_CHECKPOINT	0
#define TRUSTED_CR_CHECKPOINT_BACK	1
#define TRUSTED_CR_CONTINUE_EXECUTION	2

static struct trusted_cr_checkpoint * checkpoint = NULL;
static struct tee_ta_session *s = NULL; 
static struct user_ta_ctx * utc = NULL;

static struct user_ta_ctx * create_user_ta_ctx(TEE_UUID * uuid) {
	TEE_Result res;
	struct user_ta_ctx *utc = NULL;

	/* Register context */
	utc = calloc(1, sizeof(struct user_ta_ctx));
	if (!utc) {
		DMSG("TRUSTED_CR: ERROR OUT OF MEMORY");
		return NULL;
	}

	utc->uctx.ctx.initializing = true;
	utc->uctx.is_trusted_cr_checkpoint = true;
	utc->is_initializing = true;
	TAILQ_INIT(&utc->open_sessions);
	TAILQ_INIT(&utc->cryp_states);
	TAILQ_INIT(&utc->objects);
	TAILQ_INIT(&utc->storage_enums);

	/*
	 * Set context TA operation structure. It is required by generic
	 * implementation to identify userland TA versus pseudo TA contexts.
	 */
	trusted_cr_set_ta_ctx_ops(&utc->uctx.ctx);

	utc->uctx.ctx.uuid = *uuid;
	res = vm_info_init(&utc->uctx);
	if (res) {
		DMSG("TRUSTED_CR: vm_info_init failed: %d", res);
		return NULL;
	}

	return utc;
}

static void jump_to_user_mode(uint32_t pstate, unsigned long entry_func, unsigned long user_sp, uint64_t tpidr_el0_addr, uint64_t * regs) {
	uint32_t exit_status0 = 0;
	uint32_t exit_status1 = 0;

	// Restore the tpidr_el0 register
	asm("msr tpidr_el0, %0" : : "r" (tpidr_el0_addr));
	trusted_cr_thread_enter_user_mode(pstate, entry_func, user_sp, regs, &exit_status0, &exit_status1);
}

static void free_utc(struct user_ta_ctx ** u) {
	struct user_ta_ctx * utc = *u;
	core_mmu_clear_map(&utc->uctx.map);
	struct core_mmu_map_l1_entry * e = NULL;
	if(!TAILQ_EMPTY(&utc->uctx.map.l1_entries)) {
		TAILQ_FOREACH_REVERSE(e, &utc->uctx.map.l1_entries, core_mmu_map_l1_entries, link) {
			TAILQ_REMOVE(&utc->uctx.map.l1_entries, e, link);
			free(e);
		}
	}

	condvar_destroy(&utc->uctx.ctx.busy_cv);
	pgt_flush_ctx(&utc->uctx.ctx);
	TAILQ_REMOVE(&tee_ctxes, &utc->uctx.ctx, link);
	trusted_cr_free_utc(utc);

	*u = NULL;
}

static TEE_Result map_vm_area(struct user_ta_ctx * utc, struct trusted_cr_vm_area * area) {
	if(area == NULL)
		return TEE_ERROR_BAD_PARAMETERS;
#ifndef CFG_DISABLE_PRINTS_FOR_TRUSTED_CR
	DMSG("\n\nTRUSTED_CR - ALLOC: %p - %p", (void *) area->vm_start, area->vm_end);
#endif
	return trusted_cr_alloc_and_map_ldelf_fobj(utc, area->vm_end - area->vm_start,
				       area->protection,
				       &area->vm_start);
}

static void set_vfp_registers(uint64_t * vregs, struct thread_user_vfp_state * state) {
	volatile uint64_t * p = NULL;
	for(uint8_t i = 0, vregs_idx = 0; i < 32; i++) {
		p = (volatile uint64_t *) &state->vfp.reg[i].v[0];
		*p = vregs[vregs_idx++];
		p++;
		*p = vregs[vregs_idx++];
	}
}

static void free_checkpoint(struct trusted_cr_checkpoint ** check) {
	struct trusted_cr_dirty_page * entry = NULL;
	struct trusted_cr_checkpoint * c = *check;

	if(!TAILQ_EMPTY(&c->dirty_pagemap)) {
		TAILQ_FOREACH_REVERSE(entry, &c->dirty_pagemap, trusted_cr_dirty_pagemap, link) {
			TAILQ_REMOVE(&c->dirty_pagemap, entry, link);
			free(entry);
		}
	}

	// Free all allocated trusted_cr_vm_area structs
	if(c->vm_areas != NULL)
		free(c->vm_areas);

	if(c->pagemap_entries != NULL) {
		free(c->pagemap_entries);
	}

	free(c);

	//Reset the original pointer to NULL.
	*check = NULL;
}

static TEE_Result load_checkpoint_data(TEE_Param * binaryData, TEE_Param * binaryDataInformation) {
	TEE_Result res;
	TEE_UUID uuid = TRUSTED_CR_CHECKPOINT_UUID;

	if(s != NULL) {
		free(s);
		s = NULL;
	}

	s = calloc(1, sizeof(struct tee_ta_session));	
	if (!s)
		return TEE_ERROR_OUT_OF_MEMORY;

	s->cancel_mask = true;
	condvar_init(&s->refc_cv);
	condvar_init(&s->lock_cv);
	s->lock_thread = THREAD_ID_INVALID;
	s->ref_count = 1;

	struct checkpoint_file * checkpoint_file_var = binaryDataInformation->memref.buffer;
	
	if(checkpoint != NULL)
		free_checkpoint(&checkpoint);
	
	checkpoint = calloc(1, sizeof(struct trusted_cr_checkpoint));	

	int size = 0;
	int binaryData_index = 0;

	// Copy the checkpoint struct with the registers
	size = sizeof(struct trusted_cr_checkpoint);
	memcpy(checkpoint, binaryData->memref.buffer + binaryData_index, size);
	binaryData_index += size;

	checkpoint->l2_tables_index = 0;
	checkpoint->regs.fp_used = false;
	TAILQ_INIT(&checkpoint->dirty_pagemap);
	
	// Copy over the vm areas
	size = checkpoint->vm_area_count * sizeof(struct trusted_cr_vm_area);
	checkpoint->vm_areas = calloc(1, size);
	memcpy(checkpoint->vm_areas, binaryData->memref.buffer + binaryData_index, size);
	binaryData_index += size;

	// Copy over the pagemap entries
	size = checkpoint->pagemap_entry_count * sizeof(struct trusted_cr_pagemap_entry);
	checkpoint->pagemap_entries = calloc(1, size);
	memcpy(checkpoint->pagemap_entries, binaryData->memref.buffer + binaryData_index, size);
	binaryData_index += size;

	// Create the user TA
	if(utc != NULL) {
		free_utc(&utc);
	}

	utc = create_user_ta_ctx(&uuid);
	if(utc == NULL)
		return TEE_ERROR_GENERIC;

	s->ctx = &utc->uctx.ctx;

	utc->uctx.checkpoint = checkpoint;

	set_vfp_registers(checkpoint->regs.vregs, &utc->uctx.vfp);

	utc->uctx.vfp.vfp.fpsr = checkpoint->regs.fpsr;
	utc->uctx.vfp.vfp.fpcr = checkpoint->regs.fpcr;
	utc->uctx.vfp.lazy_saved = true;
	utc->uctx.vfp.saved = true;
	
	tee_ta_push_current_session(s);

	utc->ldelf_stack_ptr = checkpoint->regs.stack_addr;
	utc->entry_func = checkpoint->regs.entry_addr;

#ifndef CFG_DISABLE_PRINTS_FOR_TRUSTED_CR
	DMSG("\n\nTRUSTED_CR - ALLOCATION COMPLETED!");
#endif

#ifndef CFG_DISABLE_PRINTS_FOR_TRUSTED_CR
	DMSG("TRUSTED_CR - SET CTX!");
#endif
	trusted_cr_tee_mmu_set_ctx(&utc->uctx.ctx);

	struct trusted_cr_vm_area * area = checkpoint->vm_areas;
	for(int i = 0; i < checkpoint->vm_area_count; i++) {
		if(area[i].status & VMA_FILE_PRIVATE) {
			area[i].original_data = binaryDataInformation->memref.buffer 
									+ checkpoint_file_var[EXECUTABLE_BINARY_FILE].buffer_index;
		}
	}

	uint32_t pages_file_index = 0;
	for(int i = 0; i < checkpoint->pagemap_entry_count; i++) {
		checkpoint->pagemap_entries[i].buffer = binaryDataInformation->memref.buffer 	// Data buffer
				+ checkpoint_file_var[PAGES_BINARY_FILE].buffer_index   				// Plus offset of the pages file
				+ SMALL_PAGE_SIZE * pages_file_index;
		pages_file_index += checkpoint->pagemap_entries[i].nr_pages;
	}

#ifndef CFG_DISABLE_PRINTS_FOR_TRUSTED_CR
	DMSG("\n\nTRUSTED_CR - BINARY LOAD ADDRESS %#"PRIxVA, utc->entry_func);
#endif
	utc->is_32bit = false;
	utc->uctx.ctx.ref_count = 1;
	condvar_init(&utc->uctx.ctx.busy_cv);
	TAILQ_INSERT_TAIL(&tee_ctxes, &utc->uctx.ctx, link);

#ifndef CFG_DISABLE_PRINTS_FOR_TRUSTED_CR
	DMSG("\n\nTRUSTED_CR - RUN! Entry address: %p", (void *) checkpoint->regs.entry_addr);
#endif

	jump_to_user_mode(checkpoint->regs.pstate, utc->entry_func, utc->ldelf_stack_ptr, checkpoint->regs.tpidr_el0_addr, checkpoint->regs.regs);
	thread_user_clear_vfp(&utc->uctx.vfp);

	// Copy the return value in the buffer.
	long index = 0;
	memcpy(binaryDataInformation->memref.buffer, &checkpoint->result, sizeof(enum trusted_cr_return_types)); 
	index += sizeof(enum trusted_cr_return_types);
	memcpy(binaryDataInformation->memref.buffer + index, &checkpoint->regs, sizeof(struct trusted_cr_checkpoint_regs));
	index += sizeof(struct trusted_cr_checkpoint_regs);

	tee_ta_pop_current_session();

	return TEE_SUCCESS;
}

static TEE_Result trusted_cr_checkpoint_back(uint32_t param_types,
			     TEE_Param params[TEE_NUM_PARAMS]) {
#ifndef CFG_DISABLE_PRINTS_FOR_TRUSTED_CR
	DMSG("TRUSTED_CR - COPYING DATA BACK");
#endif
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_Param * binaryData = &params[1];

	tee_ta_push_current_session(s);

	trusted_cr_tee_mmu_set_ctx(&utc->uctx.ctx);

	long index = 0;
	memcpy(binaryData->memref.buffer, &checkpoint->regs, sizeof(struct trusted_cr_checkpoint_regs));
	index += sizeof(struct trusted_cr_checkpoint_regs);

	struct trusted_cr_checkpoint_dirty_pages * dirty_pages_info = binaryData->memref.buffer + index;
	index += sizeof(struct trusted_cr_checkpoint_dirty_pages);
	
	dirty_pages_info->dirty_page_count = 0;
	
	struct trusted_cr_dirty_page * entry = NULL;
	TAILQ_FOREACH(entry, &checkpoint->dirty_pagemap, link) {
		// DMSG("GOT A DIRTY ENTRY HERE: %p", entry->vaddr_start);

		dirty_pages_info->dirty_page_count++;
		memcpy(binaryData->memref.buffer + index, entry, sizeof(struct trusted_cr_dirty_page));
		index += sizeof(struct trusted_cr_dirty_page);
	}

	dirty_pages_info->offset = index;
	TAILQ_FOREACH(entry, &checkpoint->dirty_pagemap, link) {
		memcpy(binaryData->memref.buffer + index, entry->vaddr_start, SMALL_PAGE_SIZE);
		index += SMALL_PAGE_SIZE;
	}

	tee_ta_pop_current_session();

	free_checkpoint(&checkpoint);

	free_utc(&utc);

	return TEE_SUCCESS;
}

static TEE_Result trusted_cr_load_checkpoint(uint32_t param_types,
			     TEE_Param params[TEE_NUM_PARAMS]) {
#ifndef CFG_DISABLE_PRINTS_FOR_TRUSTED_CR
	DMSG("Load checkpoint");
#endif

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

#ifndef CFG_DISABLE_PRINTS_FOR_TRUSTED_CR
	IMSG("Got data from NW, size: %d and %d", params[0].memref.size, params[1].memref.size);

	// uint8_t files = params[1].memref.size / sizeof(struct checkpoint_file);
	// DMSG("Second argument contains information about %d checkpoint files", files);
	// if(files == CHECKPOINT_FILES)
	// 	DMSG("Which matches to the expected number: %d/%d", files, CHECKPOINT_FILES);
	// else
	// 	DMSG("Unexpected number of checkpoint files: %d/%d", files, CHECKPOINT_FILES);
#endif

	// LOAD CHECKPOINT DATA
	load_checkpoint_data(&params[0], &params[1]);

	return TEE_SUCCESS;
}

static TEE_Result trusted_cr_continue_execution(uint32_t param_types,
			     TEE_Param params[TEE_NUM_PARAMS]) {
#ifndef CFG_DISABLE_PRINTS_FOR_TRUSTED_CR				 
	DMSG("Continue execution");
#endif

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	tee_ta_push_current_session(s);
#ifndef CFG_DISABLE_PRINTS_FOR_TRUSTED_CR
	DMSG("TRUSTED_CR - SET CTX!");
#endif
	trusted_cr_tee_mmu_set_ctx(&utc->uctx.ctx);

	enum trusted_cr_return_types * return_type = params[0].memref.buffer;
	long index = 0;
	uint64_t * return_value = params[0].memref.buffer + sizeof(enum trusted_cr_return_types);
	index += sizeof(enum trusted_cr_return_types);
	index += sizeof(struct trusted_cr_checkpoint_regs);

	// switch(*return_type) {
	// 	case TRUSTED_CR_SYSCALL_CLOSE:
	// 		checkpoint->regs.regs[0] = *return_value;
	// 		DMSG("CLOSE returned with res: %d", *return_value);
	// 		break;
	// 	case TRUSTED_CR_SYSCALL_OPENAT:
	// 		checkpoint->regs.regs[0] = *return_value;
	// 		DMSG("OPENAT returned with res: %d", *return_value);
	// 		break;
	// 	case TRUSTED_CR_SYSCALL_FSTAT:
	// 	{
	// 		checkpoint->regs.regs[0] = *return_value;
	// 		DMSG("FSTAT returned with res: %d", *return_value);
	// 		DMSG("copy data back to address: %p", checkpoint->regs.regs[1]);
	// 		void * dest = checkpoint->regs.regs[1];
	// 		uint64_t * size = params[0].memref.buffer + sizeof(enum trusted_cr_return_types) + sizeof(struct trusted_cr_checkpoint_regs);
	// 		void * stat = params[0].memref.buffer + sizeof(enum trusted_cr_return_types) + sizeof(struct trusted_cr_checkpoint_regs) + sizeof(uint64_t);
	// 		memcpy(dest, stat, *size);
	// 		break;
	// 	}
	// 	case TRUSTED_CR_SYSCALL_NEWFSTATAT:
	// 	{
	// 		checkpoint->regs.regs[0] = *return_value;
	// 		DMSG("NEWFSTAT returned with res: %d", *return_value);
	// 		DMSG("copy data back to address: %p", checkpoint->regs.regs[2]);
	// 		void * dest = checkpoint->regs.regs[2];
	// 		uint64_t * size = params[0].memref.buffer + sizeof(enum trusted_cr_return_types) + sizeof(struct trusted_cr_checkpoint_regs);
	// 		void * stat = params[0].memref.buffer + sizeof(enum trusted_cr_return_types) + sizeof(struct trusted_cr_checkpoint_regs) + sizeof(uint64_t);
	// 		memcpy(dest, stat, *size);
	// 		break;
	// 	}
	// 	case TRUSTED_CR_SYSCALL_READ:
	// 	{
	// 		checkpoint->regs.regs[0] = *return_value;
	// 		DMSG("READ returned with res: %d", *return_value);
	// 		index += sizeof(uint64_t);
	// 		char * test = params[0].memref.buffer + index;
	// 		void * dest = checkpoint->regs.regs[1];
	// 		uint64_t size = checkpoint->regs.regs[2];
	// 		DMSG("Going to cpy to: %p, size:%d\n", dest, size);
	// 		memcpy(dest, test, size);
	// 		break;
	// 	}
	// 	default:
	// 		break;
	// }

	jump_to_user_mode(checkpoint->regs.pstate, checkpoint->regs.entry_addr, checkpoint->regs.stack_addr, checkpoint->regs.tpidr_el0_addr, checkpoint->regs.regs);

	// Copy the return value in the buffer.
	index = 0;
	memcpy(params[0].memref.buffer, &checkpoint->result, sizeof(enum trusted_cr_return_types)); 
	DMSG("the result was: %d\n", checkpoint->result);
	index += sizeof(enum trusted_cr_return_types);
	memcpy(params[0].memref.buffer + index, &checkpoint->regs, sizeof(struct trusted_cr_checkpoint_regs));
	index += sizeof(struct trusted_cr_checkpoint_regs);

	tee_ta_pop_current_session();

	return TEE_SUCCESS;
}
/*
 * Trusted Application Entry Points
 */

static TEE_Result invoke_command(void *psess __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case TRUSTED_CR_LOAD_CHECKPOINT:
		return trusted_cr_load_checkpoint(ptypes, params);
	case TRUSTED_CR_CHECKPOINT_BACK:
		return trusted_cr_checkpoint_back(ptypes, params);
	case TRUSTED_CR_CONTINUE_EXECUTION:
		return trusted_cr_continue_execution(ptypes, params);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx) {
	(void) sess_ctx; // Susspress unused variable warning
#ifndef CFG_DISABLE_PRINTS_FOR_TRUSTED_CR
	DMSG("Open session to %s", TA_NAME);
#endif
	return TEE_SUCCESS;
}

static void close_session(void *sess_ctx) {
	(void) sess_ctx; // Suspress unused variable warning

	if(checkpoint != NULL)
		free_checkpoint(&checkpoint);


	if(utc != NULL) {
		free_utc(&utc);
	}

	if(s != NULL) {
		free(s);
		s = NULL;
	}
#ifndef CFG_DISABLE_PRINTS_FOR_TRUSTED_CR
	DMSG("Closed session to %s", TA_NAME);
#endif
}

pseudo_ta_register(.uuid = TRUSTED_CR_UUID, .name = TA_NAME,
	.flags = PTA_DEFAULT_FLAGS,
	.open_session_entry_point = open_session,
	.close_session_entry_point = close_session,
	.invoke_command_entry_point = invoke_command);
