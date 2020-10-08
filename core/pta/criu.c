// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */
#include <kernel/pseudo_ta.h>
#include <kernel/user_mode_ctx.h>
#include <mm/tee_mmu.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <tee_syscall_numbers.h>
#include <tee/arch_svc.h>

// Stolen from arch_svc_private.h
typedef void (*syscall_t)(void);

#define TA_NAME		"criu.ta"

#define CRIU_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1c } }

#define CHECKPOINT_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1d } }

#define CRIU_LOAD_CHECKPOINT	0
#define CRIU_PRINT_HELLO		1

const uint8_t binary_data[4096] __aligned(4096) = {
	0x00, 0x00, 0x80, 0xd2, 0xa8, 0x0b, 0x80, 0xd2,
	0x01, 0x00, 0x00, 0xd4 };

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx)
{
	DMSG("Open session to %s", TA_NAME);

	return TEE_SUCCESS;
}

static void close_session(void *sess_ctx)
{
	DMSG("Closed session to %s", TA_NAME);
}

static struct user_ta_ctx * create_user_ta_ctx(TEE_UUID * uuid) {
	TEE_Result res;
	struct user_ta_ctx *utc = NULL;

	/* Register context */
	utc = calloc(1, sizeof(struct user_ta_ctx));
	if (!utc)
		return TEE_ERROR_OUT_OF_MEMORY;

	utc->uctx.ctx.initializing = true;
	utc->uctx.is_criu_checkpoint = true;
	utc->is_initializing = true;
	TAILQ_INIT(&utc->open_sessions);
	TAILQ_INIT(&utc->cryp_states);
	TAILQ_INIT(&utc->objects);
	TAILQ_INIT(&utc->storage_enums);

	/*
	 * Set context TA operation structure. It is required by generic
	 * implementation to identify userland TA versus pseudo TA contexts.
	 */
	criu_set_ta_ctx_ops(&utc->uctx.ctx);

	utc->uctx.ctx.uuid = *uuid;
	res = vm_info_init(&utc->uctx);
	if (res)
		return res;

	return utc;
}

static void jump_to_user_mode(unsigned long entry_func, unsigned long user_sp) {
	// JUMP TO USER MODE
	unsigned long a0 = 0;
	unsigned long a1 = 0;
	unsigned long a2 = 0;
	unsigned long a3 = 0;
	bool is_32bit = false;
	uint32_t exit_status0 = 0;
	uint32_t exit_status1 = 0;

	thread_enter_user_mode(a0, a1, a2, a3, user_sp, entry_func, is_32bit, &exit_status0, &exit_status1);
}

static void cleanup_allocations(struct tee_ta_session * s, struct user_ta_ctx * utc) {
	// Delete the user TA again
	struct core_mmu_map_l1_entry * e = NULL;
	TAILQ_FOREACH_REVERSE(e, &utc->uctx.map.l1_entries, core_mmu_map_l1_entries, link) {
		DMSG("Entry: idx: %d - table: %p", e->idx, e->table);
		TAILQ_REMOVE(&utc->uctx.map.l1_entries, e, link);
		free(e);
	}

	condvar_destroy(&utc->uctx.ctx.busy_cv);
	pgt_flush_ctx(&utc->uctx.ctx);
	TAILQ_REMOVE(&tee_ctxes, &utc->uctx.ctx, link);
	criu_free_utc(utc);
	free(s);
}

static TEE_Result load_checkpoint_data() {
	TEE_Result res;
	TEE_UUID uuid = { CHECKPOINT_UUID };

	struct tee_ta_session *s = calloc(1, sizeof(struct tee_ta_session));	
	if (!s)
		return TEE_ERROR_OUT_OF_MEMORY;

	s->cancel_mask = true;
	condvar_init(&s->refc_cv);
	condvar_init(&s->lock_cv);
	s->lock_thread = THREAD_ID_INVALID;
	s->ref_count = 1;


	// Create the user TA
	struct user_ta_ctx * utc = create_user_ta_ctx(&uuid);

	s->ctx = &utc->uctx.ctx;

	tee_ta_push_current_session(s);
	vaddr_t stack_addr = 0x40001000;
	vaddr_t code_addr = 0x40202000;

	utc->is_32bit = false;

	DMSG("\n\nCRIU - ALLOC stack: %p", stack_addr);
	res = criu_alloc_and_map_ldelf_fobj(utc, 4096,
				       TEE_MATTR_URW | TEE_MATTR_PRW,
				       &stack_addr);
	if (res)
		return res;
	utc->ldelf_stack_ptr = stack_addr + 4096;

	DMSG("\n\nCRIU - ALLOC code: %p", code_addr);
	res = criu_alloc_and_map_ldelf_fobj(utc, 4096, TEE_MATTR_PRW,
				       &code_addr);
	if (res)
		return res;
	utc->entry_func = code_addr + 0;

	DMSG("\n\nCRIU - ALLOCATION COMPLETED!");

	DMSG("CRIU - SET CTX!");
	criu_tee_mmu_set_ctx(&utc->uctx.ctx);

	memcpy((void *)code_addr, binary_data, sizeof(binary_data));	

	DMSG("CRIU - DATA COPIED OVER!\n\n");

	DMSG("\n\nCRIU - SET PROTECTION BITS");
	res = criu_vm_set_prot(&utc->uctx, code_addr,
			  ROUNDUP(sizeof(binary_data), SMALL_PAGE_SIZE),
			  TEE_MATTR_URX);
	if (res)
		return res;

	DMSG("MY BINARY LOAD ADDRESS %#"PRIxVA, code_addr);


	tee_ta_pop_current_session();

	utc->uctx.ctx.ref_count = 1;
	condvar_init(&utc->uctx.ctx.busy_cv);
	TAILQ_INSERT_TAIL(&tee_ctxes, &utc->uctx.ctx, link);

	criu_tee_mmu_clear_ctx(&utc->uctx.ctx);

	user_mode_ctx_print_mappings(&utc->uctx);

	tee_ta_push_current_session(s);
	jump_to_user_mode(code_addr, utc->ldelf_stack_ptr);
	tee_ta_pop_current_session();

	cleanup_allocations(s, utc);

	return TEE_SUCCESS;
}

static TEE_Result criu_load_checkpoint(uint32_t param_types,
			     TEE_Param params[TEE_NUM_PARAMS]) {
	DMSG("Load checkpoint");

	// LOAD CHECKPOINT DATA
	load_checkpoint_data();

	return TEE_SUCCESS;
}

static TEE_Result criu_print_hello(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	DMSG("HELLO WORLD!");

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
	case CRIU_LOAD_CHECKPOINT:
		return criu_load_checkpoint(ptypes, params);
	case CRIU_PRINT_HELLO:
		return criu_print_hello(ptypes, params);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = CRIU_UUID, .name = TA_NAME,
	.flags = PTA_DEFAULT_FLAGS,
	.open_session_entry_point = open_session,
	.close_session_entry_point = close_session,
	.invoke_command_entry_point = invoke_command);
