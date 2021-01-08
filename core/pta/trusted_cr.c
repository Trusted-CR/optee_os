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
#include <kernel/tee_time.h>

#define TA_NAME		"trusted_cr.ta"

#define TRUSTED_CR_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1c } }

#define TRUSTED_CR_CHECKPOINT_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1d } }

#define TRUSTED_CR_EXECUTE_CHECKPOINT	0
#define TRUSTED_CR_CHECKPOINT_BACK		1
#define TRUSTED_CR_CONTINUE_EXECUTION	2

static struct trusted_cr_checkpoint * checkpoint = NULL;
static struct tee_ta_session *s = NULL; 
static struct user_ta_ctx * utc = NULL;

// Declare functions
static struct user_ta_ctx * create_user_ta_ctx(TEE_UUID * uuid);
static void free_utc(struct user_ta_ctx ** u);
static void free_checkpoint(struct trusted_cr_checkpoint ** check);
static void set_vfp_registers(uint64_t * vregs, struct thread_user_vfp_state * state);
static void jump_to_user_mode(uint32_t pstate, unsigned long entry_func, unsigned long user_sp, uint64_t tpidr_el0_addr, uint64_t * regs);

static TEE_Result trusted_cr_execute_checkpoint(TEE_Param * checkpoint_data, TEE_Param * binary_data_buffer) {
	TEE_Result res;
	TEE_UUID uuid = TRUSTED_CR_CHECKPOINT_UUID;

	// // Keep this piece of code to do time measurements
	// TEE_Time start_time, stop_time;
	// tee_time_get_sys_time(&start_time);
	// tee_time_get_sys_time(&stop_time);

	// DMSG("elapsed: %ds%dms", stop_time.seconds - start_time.seconds, stop_time.millis - start_time.millis);

	// Keep this code to do some security tests: testing access with devmem via the normal world
	// #include <mm/core_memprot.h>
	// vaddr_t vaddr = checkpoint;
	// paddr_t pa = virt_to_phys(vaddr);
	// DMSG("PHYSICAL ADDRESS: %p", pa);

	// Initialize session / context / checkpoint variables
	if(s != NULL) {
		free(s);
		s = NULL;
	}

	s = calloc(1, sizeof(struct tee_ta_session));	
	if (!s)
		return TEE_ERROR_OUT_OF_MEMORY;

	if(checkpoint != NULL)
		free_checkpoint(&checkpoint);
	
	checkpoint = calloc(1, sizeof(struct trusted_cr_checkpoint));	
	int checkpoint_data_index = 0;

	s->cancel_mask = true;
	condvar_init(&s->refc_cv);
	condvar_init(&s->lock_cv);
	s->lock_thread = THREAD_ID_INVALID;
	s->ref_count = 1;

	// The executable data and pages data is stored in the 2nd shared buffer
	struct checkpoint_file * binary_data = binary_data_buffer->memref.buffer;

	// Copy the checkpoint struct with the registers
	int size = sizeof(struct trusted_cr_checkpoint);
	memcpy(checkpoint, checkpoint_data->memref.buffer + checkpoint_data_index, size);
	// Clear the data from the buffer
	memset(checkpoint_data->memref.buffer + checkpoint_data_index, 0, size);
	checkpoint_data_index += size;

	checkpoint->l2_tables_index = 0;
	checkpoint->regs.fp_used = false;
	TAILQ_INIT(&checkpoint->dirty_pagemap);
	
	// Copy over the vm areas
	size = checkpoint->vm_area_count * sizeof(struct trusted_cr_vm_area);
	checkpoint->vm_areas = calloc(1, size);
	memcpy(checkpoint->vm_areas, checkpoint_data->memref.buffer + checkpoint_data_index, size);
	checkpoint_data_index += size;

	// Copy over the pagemap entries
	size = checkpoint->pagemap_entry_count * sizeof(struct trusted_cr_pagemap_entry);
	checkpoint->pagemap_entries = calloc(1, size);
	memcpy(checkpoint->pagemap_entries, checkpoint_data->memref.buffer + checkpoint_data_index, size);
	checkpoint_data_index += size;

	// Create the user TA
	if(utc != NULL) {
		free_utc(&utc);
	}

	utc = create_user_ta_ctx(&uuid);
	if(utc == NULL)
		return TEE_ERROR_GENERIC;

	s->ctx = &utc->uctx.ctx;

	utc->uctx.checkpoint = checkpoint;

	// Copy over the vfp registers to the user TA struct.
	set_vfp_registers(checkpoint->regs.vregs, &utc->uctx.vfp);
	utc->uctx.vfp.vfp.fpsr = checkpoint->regs.fpsr;
	utc->uctx.vfp.vfp.fpcr = checkpoint->regs.fpcr;
	utc->uctx.vfp.lazy_saved = true;
	utc->uctx.vfp.saved = true;
	
	tee_ta_push_current_session(s);

	// Set the TA entry address to the checkpoint pc
	utc->ldelf_stack_ptr = checkpoint->regs.stack_addr;
	// Set the TA stack address to the checkpoint sp
	utc->entry_func = checkpoint->regs.entry_addr;

#ifndef CFG_DISABLE_PRINTS_FOR_TRUSTED_CR
	DMSG("\n\nTRUSTED_CR - ALLOCATION COMPLETED!");
#endif

#ifndef CFG_DISABLE_PRINTS_FOR_TRUSTED_CR
	DMSG("TRUSTED_CR - SET CTX!");
#endif
	trusted_cr_tee_mmu_set_ctx(&utc->uctx.ctx);

	// Set the memory pointers to the correct locations
	struct trusted_cr_vm_area * area = checkpoint->vm_areas;
	for(int i = 0; i < checkpoint->vm_area_count; i++) {
		if(area[i].status & VMA_FILE_PRIVATE) {
			area[i].original_data = binary_data_buffer->memref.buffer 
								  + binary_data[EXECUTABLE_BINARY_FILE].buffer_index;
		}
	}

	// Set the memory pointers to the correct locations
	uint32_t pages_file_index = 0;
	for(int i = 0; i < checkpoint->pagemap_entry_count; i++) {
		checkpoint->pagemap_entries[i].buffer = binary_data_buffer->memref.buffer 	// Data buffer
				+ binary_data[PAGES_BINARY_FILE].buffer_index   				// Plus offset of the pages file
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

	// Jump into the checkpoint code without any page mapped.
	// The pagefault will be catched in abort.c: abort_handler()
	// which will call tee_pager.c: tee_pager_handle_fault() which will
	// map the pages accordingly.
	jump_to_user_mode(checkpoint->regs.pstate, utc->entry_func, utc->ldelf_stack_ptr, checkpoint->regs.tpidr_el0_addr, checkpoint->regs.regs);
	thread_user_clear_vfp(&utc->uctx.vfp);

	// Pretend to copy the pagedata to safe secure world memory and overwriting
	// the normal world accessible memory to zero. The pagedata actually contains
	// the very memory we want to protect so remove it from the buffer.	Right now
	// we don't actually do real copying because OP-TEE is low in memory and there
	// is no paging support. To still incorporate it into benchmarking results do 
	// the exact same amount of copying but this time to the same buffer. Normally
	// this happens before jump_to_user_mode, but because we still need the memory 
	// during execution we just do it here
	memcpy(binary_data_buffer->memref.buffer + binary_data[EXECUTABLE_BINARY_FILE].buffer_index, 
		   binary_data_buffer->memref.buffer 
			+ binary_data[PAGES_BINARY_FILE].buffer_index,
		   binary_data[PAGES_BINARY_FILE].file_size);
	memset(binary_data_buffer->memref.buffer
			+ binary_data[PAGES_BINARY_FILE].buffer_index, 0, 
			binary_data[PAGES_BINARY_FILE].file_size);

	// Copy the return value in the buffer.
	long index = 0;
	memcpy(binary_data_buffer->memref.buffer, &checkpoint->result, sizeof(enum trusted_cr_return_types)); 
	index += sizeof(enum trusted_cr_return_types);
	memcpy(binary_data_buffer->memref.buffer + index, &checkpoint->regs, sizeof(struct trusted_cr_checkpoint_regs));
	index += sizeof(struct trusted_cr_checkpoint_regs);

	tee_ta_pop_current_session();

	return TEE_SUCCESS;
}

// Will be called by the normal world to migrate back
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

	// We store everything in shared buffer 2 because that is the biggest one.
	// The old data in shared buffer 2 is the executable + page data.
	TEE_Param * shared_buffer_2 = &params[1];

	tee_ta_push_current_session(s);

	trusted_cr_tee_mmu_set_ctx(&utc->uctx.ctx);

	// Copy over the checkpoint registers
	long index = 0;
	memcpy(shared_buffer_2->memref.buffer, &checkpoint->regs, sizeof(struct trusted_cr_checkpoint_regs));
	index += sizeof(struct trusted_cr_checkpoint_regs);

	// To keep track of the number of dirty pages
	struct trusted_cr_checkpoint_dirty_pages * dirty_pages_info = shared_buffer_2->memref.buffer + index;
	index += sizeof(struct trusted_cr_checkpoint_dirty_pages);
	dirty_pages_info->dirty_page_count = 0;
	
	// Copy over which memory pages are dirty pages
	struct trusted_cr_dirty_page * entry = NULL;
	TAILQ_FOREACH(entry, &checkpoint->dirty_pagemap, link) {
		// DMSG("GOT A DIRTY ENTRY HERE: %p", entry->vaddr_start);
		dirty_pages_info->dirty_page_count++;
		memcpy(shared_buffer_2->memref.buffer + index, entry, sizeof(struct trusted_cr_dirty_page));
		index += sizeof(struct trusted_cr_dirty_page);
	}

	// Now copy over all the dirty page data itself
	dirty_pages_info->offset = index;
	TAILQ_FOREACH(entry, &checkpoint->dirty_pagemap, link) {
		memcpy(shared_buffer_2->memref.buffer + index, entry->vaddr_start, SMALL_PAGE_SIZE);
		index += SMALL_PAGE_SIZE;
	}

	// And free
	tee_ta_pop_current_session();
	free_checkpoint(&checkpoint);
	free_utc(&utc);

	return TEE_SUCCESS;
}

static TEE_Result trusted_cr_execute_checkpoint_helper(uint32_t param_types,
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
#endif

	// Execute checkpoint
	return trusted_cr_execute_checkpoint(&params[0], &params[1]);
}

// This function could be used to execute a system call in the normal world
// Then the return value could be copied to the secure world where the code
// can continue. The difference here is that the code is paused in the secure
// world. Nothing is unmapped, nothing is migrated back.
// However this code is not supported right now.
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
	case TRUSTED_CR_EXECUTE_CHECKPOINT:
		return trusted_cr_execute_checkpoint_helper(ptypes, params);
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

static void jump_to_user_mode(uint32_t pstate, unsigned long entry_func, unsigned long user_sp, uint64_t tpidr_el0_addr, uint64_t * regs) {
	uint32_t exit_status0 = 0;
	uint32_t exit_status1 = 0;

	// Restore the tpidr_el0 register
	asm("msr tpidr_el0, %0" : : "r" (tpidr_el0_addr));
	trusted_cr_thread_enter_user_mode(pstate, entry_func, user_sp, regs, &exit_status0, &exit_status1);
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