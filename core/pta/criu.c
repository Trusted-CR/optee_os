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

extern void dump_xlat_table(vaddr_t va, int level);

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

static void jump_to_user_mode(unsigned long entry_func, unsigned long user_sp, uint64_t * regs) {
	uint32_t exit_status0 = 0;
	uint32_t exit_status1 = 0;

	criu_thread_enter_user_mode(entry_func, user_sp, regs, &exit_status0, &exit_status1);
}

static void cleanup_allocations(struct tee_ta_session * s, struct user_ta_ctx * utc) {
	// Delete the user TA again
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
	criu_free_utc(utc);
	free(s);
}

static void dump_mmu_tables(struct core_mmu_map * map) {
	struct core_mmu_map_l1_entry * e = NULL;
	TAILQ_FOREACH(e, &map->l1_entries, link) {
		dump_xlat_table(e->idx << 30, 2);
	}
}

static TEE_Result load_checkpoint_data(TEE_Param * param) {
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
	vaddr_t stack_addr_start = 0x7ffca46000;
	vaddr_t stack_addr_end   = 0x7ffca48000;
	
	vaddr_t allocated_area_start = 0x744d245000;
	vaddr_t allocated_area_end   = 0x744d248000;

	vaddr_t code_addr_start = 0x40050000;
	vaddr_t code_addr_end   = 0x400dd000;

	vaddr_t data_addr_start = 0x400de000;
	vaddr_t data_addr_end   = 0x400e4000;

	vaddr_t entry_addr = 0x40053ea0;

	uint64_t regs[31];
	regs[0] = 0x7ffca46aa0;
	regs[1] = 0x7ffca46a90;
	regs[2] = 0x9;
	regs[3] = 0xffffffffffffffff;
	regs[4] = 0xffffffffffffffff;
	regs[5] = 0x744ce09009;
	regs[6] = 0xa;
	regs[7] = 0xa;
	regs[8] = 0x65;
	regs[9] = 0xec076ab7fa1fef8d;
	regs[10] = 0x4001;
	regs[11] = 0x0;
	regs[12] = 0x2;
	regs[13] = 0x7ffca46660;
	regs[14] = 0x10;
	regs[15] = 0x400e3d3c;
	regs[16] = 0xffffffff;
	regs[17] = 0x0;
	regs[18] = 0x744e054000;
	regs[19] = 0x1;
	regs[20] = 0x744d247fc0;
	regs[21] = 0x400dea30;
	regs[22] = 0x40050190;
	regs[23] = 0x6474e552;
	regs[24] = 0x40050040;
	regs[25] = 0x0;
	regs[26] = 0x0;
	regs[27] = 0x0;
	regs[28] = 0x0;
	regs[29] = 0x7ffca46ad0;
	regs[30] = 0x40052414;

	utc->is_32bit = false;

	DMSG("\n\nCRIU - ALLOC stack: %p", stack_addr_start);
	res = criu_alloc_and_map_ldelf_fobj(utc, stack_addr_end - stack_addr_start,
				       TEE_MATTR_URW | TEE_MATTR_PRW,
				       &stack_addr_start);
	if (res) {
		DMSG("CRIU - ALLOC stack failed: %d", res);
		return res;
	}
	utc->ldelf_stack_ptr = stack_addr_end;

	DMSG("\n\nCRIU - ALLOC code: %p", code_addr_start);
	res = criu_alloc_and_map_ldelf_fobj(utc, code_addr_end - code_addr_start, TEE_MATTR_PRW,
				       &code_addr_start);
	if (res) {
		DMSG("CRIU - ALLOC code failed: %d", res);
		return res;
	}
	utc->entry_func = entry_addr;

	DMSG("\n\nCRIU - ALLOC data: %p", data_addr_start);
	res = criu_alloc_and_map_ldelf_fobj(utc, data_addr_end - data_addr_start, TEE_MATTR_URW,
				       &data_addr_start);
	if (res) {
		DMSG("CRIU - ALLOC data failed: %d", res);
		return res;
	}

	DMSG("\n\nCRIU - ALLOC another area: %p", allocated_area_start);
	res = criu_alloc_and_map_ldelf_fobj(utc, allocated_area_end - allocated_area_start, TEE_MATTR_URW,
				       &allocated_area_start);
	if (res) {
		DMSG("CRIU - ALLOC another area failed: %d", res);
		return res;
	}

	DMSG("\n\nCRIU - ALLOCATION COMPLETED!");

	DMSG("CRIU - SET CTX!");
	criu_tee_mmu_set_ctx(&utc->uctx.ctx);

	// dump_mmu_tables(&utc->uctx.map);

	DMSG("\n\nCRIU - DATA COPY START!");
	memcpy((void *)code_addr_start, param->memref.buffer, code_addr_end - code_addr_start);	

	uint64_t * sleep_argument_stack_address = 0x7ffca46aa0;
	*sleep_argument_stack_address = 1;

	memset((void *)allocated_area_start, 0, allocated_area_end - allocated_area_start);

	DMSG("CRIU - DATA COPIED OVER!\n\n");


	DMSG("\n\nCRIU - SET PROTECTION BITS");
	res = criu_vm_set_prot(&utc->uctx, code_addr_start,
			  ROUNDUP(code_addr_end - code_addr_start, SMALL_PAGE_SIZE),
			  TEE_MATTR_URX);
	if (res) {
		DMSG("CRIU - SET PROTECTION BITS failed: %d", res);
		return res;
	}

	// dump_mmu_tables(&utc->uctx.map);

	DMSG("CRIU - PROTECTION BITS SET\n\n");

	DMSG("\n\nCRIU - BINARY LOAD ADDRESS %#"PRIxVA, code_addr_start);

	utc->uctx.ctx.ref_count = 1;
	condvar_init(&utc->uctx.ctx.busy_cv);
	TAILQ_INSERT_TAIL(&tee_ctxes, &utc->uctx.ctx, link);

	criu_tee_mmu_set_ctx(&utc->uctx.ctx);

	user_mode_ctx_print_mappings(&utc->uctx);

	DMSG("\n\nCRIU - RUN! Entry address: %p", entry_addr);
	
	jump_to_user_mode(utc->entry_func, utc->ldelf_stack_ptr, regs);
	tee_ta_pop_current_session();

	cleanup_allocations(s, utc);

	return TEE_SUCCESS;
}

static TEE_Result criu_load_checkpoint(uint32_t param_types,
			     TEE_Param params[TEE_NUM_PARAMS]) {
	DMSG("Load checkpoint");

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got data from NW, size: %d and %d", params[0].memref.size, params[1].memref.size);

	DMSG("Second argument contains: %s", params[0].memref.buffer);

	// LOAD CHECKPOINT DATA
	load_checkpoint_data(&params[0]);
	char message[] = "hello from mitchell";
 
	memcpy(params[0].memref.buffer, message, 
			(params[0].memref.size >= sizeof(message) 
			? sizeof(message) : params[0].memref.size));
	
	IMSG("Changed value to: \"%s\"", params[0].memref.buffer);

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
