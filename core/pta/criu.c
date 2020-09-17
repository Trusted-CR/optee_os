// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */
#include <kernel/pseudo_ta.h>
#include <mm/tee_mmu.h>
#include <mm/core_mmu.h>

#define TA_NAME		"criu.ta"

#define CRIU_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1c } }

#define CHECKPOINT_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1d } }

#define CRIU_LOAD_CHECKPOINT	0
#define CRIU_PRINT_HELLO		1

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

static TEE_Result alloc_and_map_ldelf_fobj(size_t sz, uint32_t prot, vaddr_t *va)
{
	size_t num_pgs = 1;
	struct fobj *fobj = fobj_sec_mem_alloc(num_pgs);
	struct mobj *mobj = mobj_with_fobj_alloc(fobj, NULL);
	TEE_Result res = TEE_SUCCESS;

	fobj_put(fobj);
	if (!mobj)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = vm_map(&utc->uctx, va, num_pgs * SMALL_PAGE_SIZE,
		     prot, VM_FLAG_LDELF, mobj, 0);
	mobj_put(mobj);

	return res;
}

static TEE_Result load_checkpoint_data() {
	TEE_Result res;
	vaddr_t code_addr = 0x7000;
	struct mobj *mobj = NULL;
	struct fobj *f = NULL;
	struct vm_region *reg = NULL;
	int num_bytes = 4096;

	// Allocate pages in memory
	f = fobj_ta_mem_alloc(ROUNDUP_DIV(num_bytes, SMALL_PAGE_SIZE));
	if (!f)
		return TEE_ERROR_OUT_OF_MEMORY;

	// Create mobj interface for our memory pages
	mobj = mobj_with_fobj_alloc(f, NULL);
	fobj_put(f);
	if (!mobj)
		return TEE_ERROR_OUT_OF_MEMORY;

	// Create VM mapping
	res = vm_map_pad(&utc->uctx, &code_addr, num_bytes, prot, vm_flags,
			 mobj, 0, pad_begin, pad_end);
	mobj_put(mobj);





	reg = calloc(1, sizeof(*reg));
	if (!reg)
		return TEE_ERROR_OUT_OF_MEMORY;

	reg->mobj = mobj_get(mobj);
	reg->offset = 0;
	reg->va = 0x7000;
	reg->size = 4096;
	reg->attr = TEE_MATTR_VALID_BLOCK | TEE_MATTR_SECURE;
	reg->flags = TEE_MATTR_URWX;










	res = alloc_and_map_ldelf_fobj(utc, ldelf_code_size, TEE_MATTR_PRW,
				       &code_addr);
	if (res)
		return res;
	utc->entry_func = code_addr + ldelf_entry;

	tee_mmu_set_ctx(&utc->uctx.ctx);

	memcpy((void *)code_addr, ldelf_data, ldelf_code_size);
	
	res = vm_set_prot(&utc->uctx, code_addr,
			  ROUNDUP(ldelf_code_size, SMALL_PAGE_SIZE),
			  TEE_MATTR_URX);
	if (res)
		return res;

	DMSG("checkpoint load address %#"PRIxVA, code_addr);

	free(reg);
	
	return TEE_SUCCESS;
}

static TEE_Result criu_load_checkpoint(uint32_t param_types,
			     TEE_Param params[TEE_NUM_PARAMS]) {
	DMSG("Load checkpoint");

	// LOAD CHECKPOINT DATA
	load_checkpoint_data();

	// JUMP TO USER MODE
	unsigned long a0 = 0;
	unsigned long a1 = 0;
	unsigned long a2 = 0;
	unsigned long a3 = 0;
	unsigned long user_sp = 0;
	unsigned long entry_func = 0x800;
	bool is_32bit = false;
	uint32_t *exit_status0 = NULL;
	uint32_t *exit_status1 = NULL;

	thread_enter_user_mode(a0, a1, a2, a3, user_sp, entry_func, is_32bit, exit_status0, exit_status1);

	// TEE_UUID uuid = TA_HELLO_WORLD_UUID;

	// tee_ta_init_custom_ta_session(&uuid, s);

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
