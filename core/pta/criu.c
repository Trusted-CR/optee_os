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

struct criu_vm_area {
	vaddr_t vm_start;
	vaddr_t vm_end;
	void * original_data;
	unsigned long offset;
	uint32_t protection;
};

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

static void jump_to_user_mode(unsigned long entry_func, unsigned long user_sp, uint64_t tpidr_el0_addr, uint64_t * regs) {
	uint32_t exit_status0 = 0;
	uint32_t exit_status1 = 0;

	// Restore the tpidr_el0 register
	asm("msr tpidr_el0, %0" : : "r" (tpidr_el0_addr));
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

static TEE_Result map_vm_area(struct user_ta_ctx * utc, struct criu_vm_area * area) {
	if(area == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("\n\nCRIU - ALLOC: %p", area->vm_start);
	return criu_alloc_and_map_ldelf_fobj(utc, area->vm_end - area->vm_start,
				       area->protection,
				       &area->vm_start);
}

void set_vfp_registers(uint64_t * vregs, struct thread_user_vfp_state * state) {
	volatile uint64_t * p = NULL;
	for(uint8_t i = 0, vregs_idx = 0; i < 32; i++) {
		p = &state->vfp.reg[i].v[0];
		*p = vregs[vregs_idx++];
		p++;
		*p = vregs[vregs_idx++];
	}
}

struct criu_checkpoint {
	uint64_t vregs[64];
	uint64_t regs[31];
	uint64_t entry_addr;
	uint64_t stack_addr;
	uint64_t tpidr_el0_addr;
};


void copy_vm_area_data(struct criu_vm_area * area) {
	memcpy((void *)area->vm_start, area->original_data + area->offset, area->vm_end - area->vm_start);
}

static TEE_Result load_checkpoint_data(TEE_Param * checkpointedBinary, TEE_Param * pageData) {
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

	struct criu_checkpoint checkpoint = {
		.vregs = { 
			723401728380766730,
			723401728380766730,
			2675202428892898632,
			8245935278385007204,
			7310222162287403066,
			7809558913277586791,
			0,
			1024,
			0,
			0,
			4616194021471028225,
			4616194021471028225,
			262144,
			262144,
			9232388042942056450,
			9232388042942056450,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			4616194021471028225,
			4616194021471028225,
			8797167288320,
			524288,
			8796093022208,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0 },
		.regs = {
			0x7ffca46aa0,
			0x7ffca46a90,
			0x9,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0x744ce09009,
			0xa,
			0xa,
			0x65,
			0xec076ab7fa1fef8d,
			0x4001,
			0x0,
			0x2,
			0x7ffca46660,
			0x10,
			0x400e3d3c,
			0xffffffff,
			0x0,
			0x744e054000,
			0x1,
			0x744d247fc0,
			0x400dea30,
			0x40050190,
			0x6474e552,
			0x40050040,
			0x0,
			0x0,
			0x0,
			0x0,
			0x7ffca46ad0,
			0x40052414
		},
		.entry_addr = 0x40053ea4,
		.stack_addr = 0x7ffca46a90,
		.tpidr_el0_addr = 499510443968
	};

	// Create the user TA
	struct user_ta_ctx * utc = create_user_ta_ctx(&uuid);

	s->ctx = &utc->uctx.ctx;

	set_vfp_registers(checkpoint.vregs, &utc->uctx.vfp);
	
	tee_ta_push_current_session(s);

	struct criu_vm_area code = {
		.vm_start		= 0x40050000,
		.vm_end			= 0x400dd000,
		.original_data	= checkpointedBinary->memref.buffer,
		.offset 		= 0,
		.protection		= TEE_MATTR_PRW
	};

	struct criu_vm_area stack = {
		.vm_start		= 0x7ffca45000,
		.vm_end			= 0x7ffca48000,
		.original_data	= pageData->memref.buffer,
		.offset 		= (40-3)*4096,
		.protection		= TEE_MATTR_URW | TEE_MATTR_PRW
	};

	struct criu_vm_area data = {
		.vm_start		= 0x400de000,
		.vm_end			= 0x400e2000,
		.original_data	= checkpointedBinary->memref.buffer,
		.offset 		= 577536,
		.protection		= TEE_MATTR_URW | TEE_MATTR_PRW
	};

	struct criu_vm_area data0 = {
		.vm_start		= 0x400e2000,
		.vm_end			= 0x400e4000,
		.original_data	= pageData->memref.buffer,
		.offset 		= (1 * 4096),
		.protection		= TEE_MATTR_URW | TEE_MATTR_PRW
	};

	struct criu_vm_area data1 = {
		.vm_start		= 0x744d247000,
		.vm_end			= 0x744d248000,
		.original_data	= pageData->memref.buffer,
		.offset 		= 4096*34,
		.protection		= TEE_MATTR_URW | TEE_MATTR_PRW
	};

	struct criu_vm_area data2 = {
		.vm_start		= 0x400e5000,
		.vm_end			= 0x400e9000,
		.original_data	= pageData->memref.buffer,
		.offset 		= 4096*3,
		.protection		= TEE_MATTR_URW | TEE_MATTR_PRW
	};

	struct criu_vm_area data3 = {
		.vm_start		= 0x744ce08000,
		.vm_end			= 0x744ce08000 + (4096 * 2),
		.original_data	= pageData->memref.buffer,
		.offset 		= (19 * 4096),
		.protection		= TEE_MATTR_URW | TEE_MATTR_PRW
	};


	utc->is_32bit = false;

	if (res = map_vm_area(utc, &stack)) {
		DMSG("CRIU - ALLOC stack failed: %d", res);
		return res;
	}

	if (res = map_vm_area(utc, &code)) {
		DMSG("CRIU - ALLOC code failed: %d", res);
		return res;
	}

	if (res = map_vm_area(utc, &data)) {
		DMSG("CRIU - ALLOC data failed: %d", res);
		return res;
	}

	if (res = map_vm_area(utc, &data0)) {
		DMSG("CRIU - ALLOC data0 failed: %d", res);
		return res;
	}	

	if (res = map_vm_area(utc, &data1)) {
		DMSG("CRIU - ALLOC data1 failed: %d", res);
		return res;
	}	
	
	if (res = map_vm_area(utc, &data2)) {
		DMSG("CRIU - ALLOC data2 failed: %d", res);
		return res;
	}

	if (res = map_vm_area(utc, &data3)) {
		DMSG("CRIU - ALLOC data3 failed: %d", res);
		return res;
	}

	utc->ldelf_stack_ptr = checkpoint.stack_addr;
	utc->entry_func = checkpoint.entry_addr;

	DMSG("\n\nCRIU - ALLOCATION COMPLETED!");

	DMSG("CRIU - SET CTX!");
	criu_tee_mmu_set_ctx(&utc->uctx.ctx);

	// dump_mmu_tables(&utc->uctx.map);

	DMSG("\n\nCRIU - DATA COPY START!");

	copy_vm_area_data(&code);
	copy_vm_area_data(&stack);
	copy_vm_area_data(&data);
	copy_vm_area_data(&data0);	
	copy_vm_area_data(&data1);		
	copy_vm_area_data(&data2);		
	copy_vm_area_data(&data3);	

	DMSG("CRIU - DATA COPIED OVER!\n\n");


	DMSG("\n\nCRIU - SET PROTECTION BITS");
	res = criu_vm_set_prot(&utc->uctx, code.vm_start,
			  ROUNDUP(code.vm_end - code.vm_start, SMALL_PAGE_SIZE),
			  TEE_MATTR_URX);
	if (res) {
		DMSG("CRIU - SET PROTECTION BITS failed: %d", res);
		return res;
	}

	// dump_mmu_tables(&utc->uctx.map);

	DMSG("CRIU - PROTECTION BITS SET\n\n");

	DMSG("\n\nCRIU - BINARY LOAD ADDRESS %#"PRIxVA, code.vm_start);

	utc->uctx.ctx.ref_count = 1;
	condvar_init(&utc->uctx.ctx.busy_cv);
	TAILQ_INSERT_TAIL(&tee_ctxes, &utc->uctx.ctx, link);

	criu_tee_mmu_set_ctx(&utc->uctx.ctx);

	user_mode_ctx_print_mappings(&utc->uctx);

	DMSG("\n\nCRIU - RUN! Entry address: %p", checkpoint.entry_addr);
	
	jump_to_user_mode(utc->entry_func, utc->ldelf_stack_ptr, checkpoint.tpidr_el0_addr, checkpoint.regs);
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
	load_checkpoint_data(&params[0], &params[1]);
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
