// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */
#include <compiler.h>
#include <stdio.h>
#include <trace.h>
#include <kernel/pseudo_ta.h>
#include <mm/tee_pager.h>
#include <mm/tee_mm.h>
#include <mm/tee_mmu.h>
#include <string.h>
#include <string_ext.h>
#include <malloc.h>

#define TA_NAME		"criu.ta"

#define CRIU_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1c } }

#define CHECKPOINT_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1d } }

#define CRIU_LOAD_CHECKPOINT	0
#define CRIU_PRINT_HELLO		1

static TEE_Result criu_load_checkpoint(struct tee_ta_session *s,
			     uint32_t param_types,
			     TEE_Param params[TEE_NUM_PARAMS]) {
	DMSG("Load checkpoint");

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
	struct tee_ta_session *s = tee_ta_get_calling_session();

	switch (cmd) {
	case CRIU_LOAD_CHECKPOINT:
		return criu_load_checkpoint(s, ptypes, params);
	case CRIU_PRINT_HELLO:
		return criu_print_hello(ptypes, params);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = CRIU_UUID, .name = TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
