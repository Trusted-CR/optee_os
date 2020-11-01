// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */
#include <kernel/pseudo_ta.h>
#include <kernel/user_mode_ctx.h>
#include <mm/tee_mmu.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <criu/jsmn.h>

#define TA_NAME		"criu.ta"

#define CRIU_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1c } }

#define CHECKPOINT_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1d } }

#define CRIU_LOAD_CHECKPOINT	0

// #define CRIU_TEST_RETURNING
#ifdef CRIU_TEST_RETURNING
// This is test data, consisting of instructions that only executes a sys_exit syscall
const uint8_t test_code_exec_sys_exit[4096] __aligned(4096) = { 
	0x00, 0x00, 0x80, 0xd2, 0xa8, 0x0b, 
	0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4 };
#endif

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

char *sstrstr(char *haystack, char *needle, size_t length)
{
    size_t needle_length = strlen(needle);
    size_t i;
    for (i = 0; i < length; i++) {
        if (i + needle_length > length) {
            return NULL;
        }
        if (strncmp(&haystack[i], needle, needle_length) == 0) {
            return &haystack[i];
        }
    }
    return NULL;
}

static bool parse_checkpoint_core(struct criu_checkpoint * checkpoint, char * json, uint64_t file_size) {
	if(checkpoint == NULL) {
		DMSG("Error: criu_checkpoint struct is NULL");
		return false;
	}

	// Initialize the JSMN json parser
	jsmn_parser parser;
	jsmn_init(&parser);

	// First only determine the number of tokens.
	int items = jsmn_parse(&parser, json, file_size, NULL, 128);\

	jsmntok_t tokens[items];
	
	// Reset position in stream
	jsmn_init(&parser);
	int left = jsmn_parse(&parser, json, file_size, tokens, items);

	// Invalid file.
	if (items < 1 || tokens[0].type != JSMN_OBJECT) {
		DMSG("CRIU: INVALID JSON\n");
		return false;
	}

	// Parse the JSON version of the core checkpoint file (example core-2956.img)
	for(int i = 1; i < items; i++) {
		// Parse all registers
		if (jsoneq(json, &tokens[i], "regs") == 0) { 
			if(tokens[i+1].type == JSMN_ARRAY) {
				for(int y = 0; y < tokens[i+1].size && (y < sizeof(checkpoint->regs)); y++) {
					checkpoint->regs.regs[y] = strtoul(json + tokens[i+y+2].start, NULL, 16);
				}
			}
		// Parse all the VFP registers
		} else if(jsoneq(json, &tokens[i], "vregs") == 0) { 
			if(tokens[i+1].type == JSMN_ARRAY) {
				for(int y = 0; y < tokens[i+1].size && (y < sizeof(checkpoint->regs.vregs)); y++) {
					checkpoint->regs.vregs[y] = strtoul(json + tokens[i+y+2].start, NULL, 10);
				}
			}
		// Parse the checkpoint program counter
		} else if(jsoneq(json, &tokens[i], "pc") == 0) { 
			if(tokens[i+1].type == JSMN_STRING)
				checkpoint->regs.entry_addr = strtoul(json + tokens[i+1].start, NULL, 16);
		// Parse the checkpoint stack pointer
		} else if(jsoneq(json, &tokens[i], "sp") == 0) { 
			if(tokens[i+1].type == JSMN_STRING)
				checkpoint->regs.stack_addr = strtoul(json + tokens[i+1].start, NULL, 16);	
		// Parse the TPIDR_EL0 address
		} else if(jsoneq(json, &tokens[i], "tls") == 0) { 
			if(tokens[i+1].type == JSMN_PRIMITIVE)
				checkpoint->regs.tpidr_el0_addr = strtoul(json + tokens[i+1].start, NULL, 10);
		}
	}

	return true;
}

static bool parse_checkpoint_mm(struct criu_checkpoint * checkpoint, char * json, uint64_t file_size) {
	if(checkpoint == NULL) {
		DMSG("Error: criu_checkpoint struct is NULL");
		return false;
	}

	// Initialize the JSMN json parser
	jsmn_parser parser;
	jsmn_init(&parser);

	// First only determine the number of tokens.
	int items = jsmn_parse(&parser, json, file_size, NULL, 128);\

	jsmntok_t tokens[items];
	
	// Reset position in stream
	jsmn_init(&parser);
	int left = jsmn_parse(&parser, json, file_size, tokens, items);

	// Invalid file.
	if (items < 1 || tokens[0].type != JSMN_OBJECT) {
		DMSG("CRIU: INVALID JSON\n");
		return false;
	}

	// Parse the JSON version of the core checkpoint file (example core-2956.img)
	for(int i = 1; i < items; i++) {
		// Parse the vmas
		if (jsoneq(json, &tokens[i], "vmas") == 0) {
			if(tokens[i+1].type == JSMN_ARRAY) {
				// Allocate the required number of VMA area structs
				checkpoint->vm_area_count = tokens[++i].size; i++;
				checkpoint->vm_areas = malloc(sizeof(struct criu_vm_area) * checkpoint->vm_area_count);

				for(int y = 0; y < checkpoint->vm_area_count; y++, i += (tokens[i].size * 2) + 1) {
					// Set the VMA addresses, offset and initialize the other fields.
					checkpoint->vm_areas[y].vm_start   = strtoul(json + tokens[i+2].start, NULL, 16);
					checkpoint->vm_areas[y].vm_end     = strtoul(json + tokens[i+4].start, NULL, 16);
					checkpoint->vm_areas[y].offset     = strtoul(json + tokens[i+6].start, NULL, 10);
					checkpoint->vm_areas[y].protection = 0;
					checkpoint->vm_areas[y].status     = 0;
					checkpoint->vm_areas[y].dirty      = false;
					
					// Parse the VMA protection bits
					if(sstrstr(json + tokens[i+10].start, "PROT_READ", tokens[i+10].end - tokens[i+10].start) != NULL)
						checkpoint->vm_areas[y].protection |= TEE_MATTR_UR;
					if(sstrstr(json + tokens[i+10].start, "PROT_WRITE", tokens[i+10].end - tokens[i+10].start) != NULL)
						checkpoint->vm_areas[y].protection |= TEE_MATTR_UW;
					if(sstrstr(json + tokens[i+10].start, "PROT_EXEC", tokens[i+10].end - tokens[i+10].start) != NULL)
						checkpoint->vm_areas[y].protection |= TEE_MATTR_UX;

					// Parse the VMA status bits
					if(sstrstr(json + tokens[i+14].start, "VMA_FILE_PRIVATE", tokens[i+14].end - tokens[i+14].start) != NULL)
						checkpoint->vm_areas[y].status |= VMA_FILE_PRIVATE;
				}

				return true;
			}
		}
	}

	return true;
}

static bool parse_checkpoint_pagemap(struct criu_checkpoint * checkpoint, char * json, uint64_t file_size) {
	if(checkpoint == NULL) {
		DMSG("Error: criu_checkpoint struct is NULL");
		return false;
	}

	// Initialize the JSMN json parser
	jsmn_parser parser;
	jsmn_init(&parser);

	// First only determine the number of tokens.
	int items = jsmn_parse(&parser, json, file_size, NULL, 128);\

	jsmntok_t tokens[items];
	
	// Reset position in stream
	jsmn_init(&parser);
	int left = jsmn_parse(&parser, json, file_size, tokens, items);

	// Invalid file.
	if (items < 1 || tokens[0].type != JSMN_OBJECT) {
		DMSG("CRIU: INVALID JSON\n");
		return false;
	}

	// Parse the JSON version of the core checkpoint file (example core-2956.img)
	for(int i = 1; i < items; i++) {
		// Find the 'entries' field in the file
		if (jsoneq(json, &tokens[i], "entries") == 0) {
			if(tokens[i+1].type == JSMN_ARRAY) {
				// Allocate the required number of VMA area structs
				// size - 1 as the first entry is "pages_id": 1, checkout pagemap-*.txt
				// i += 4 to skip the first entry.
				int pagemap_entry_count = tokens[++i].size - 1; i+=4;

				int file_index = 0;
				// Parse all pagemap entries
				for(int y = 0; y < pagemap_entry_count; y++, i += (tokens[i].size * 2) + 1) {
					if(tokens[i].size == 3) {
						// Parse the address, number of pages and initialize the flags.
						struct criu_pagemap_entry_tracker * entry = calloc(1, sizeof(struct criu_pagemap_entry_tracker));
						entry->entry.vaddr_start = strtoul(json + tokens[i+2].start, NULL, 16);
						entry->entry.nr_pages    = strtoul(json + tokens[i+4].start, NULL, 10);
						entry->entry.flags       = 0;
						entry->entry.file_page_index = file_index;
						
						// Parse the flags
						if(sstrstr(json + tokens[i+6].start, "PE_PRESENT", tokens[i+6].end - tokens[i+6].start) != NULL)
							entry->entry.flags |= PE_PRESENT;
						if(sstrstr(json + tokens[i+6].start, "PE_LAZY", tokens[i+6].end - tokens[i+6].start) != NULL)
							entry->entry.flags |= PE_LAZY;

						TAILQ_INSERT_TAIL(&checkpoint->pagemap_entries, entry, link);

						file_index += entry->entry.nr_pages;
					}
				}

				return true;
			}
		}
	}

	return true;
}

static struct user_ta_ctx * create_user_ta_ctx(TEE_UUID * uuid) {
	TEE_Result res;
	struct user_ta_ctx *utc = NULL;

	/* Register context */
	utc = calloc(1, sizeof(struct user_ta_ctx));
	if (!utc) {
		DMSG("CRIU: ERROR OUT OF MEMORY");
		return NULL;
	}

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
	if (res) {
		DMSG("CRIU: vm_info_init failed: %d", res);
		return NULL;
	}

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

// extern void dump_xlat_table(vaddr_t va, int level);
// static void dump_mmu_tables(struct core_mmu_map * map) {
// 	struct core_mmu_map_l1_entry * e = NULL;
// 	TAILQ_FOREACH(e, &map->l1_entries, link) {
// 		dump_xlat_table(e->idx << 30, 2);
// 	}
// }

static TEE_Result map_vm_area(struct user_ta_ctx * utc, struct criu_vm_area * area) {
	if(area == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("\n\nCRIU - ALLOC: %p - %p", (void *) area->vm_start, area->vm_end);
	return criu_alloc_and_map_ldelf_fobj(utc, area->vm_end - area->vm_start,
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

void copy_pagemap_entry(struct criu_pagemap_entry_tracker * entry, void * buffer) {
	if(entry != NULL && entry->entry.vaddr_start != NULL)
		memcpy((void *)entry->entry.vaddr_start, buffer, entry->entry.nr_pages * SMALL_PAGE_SIZE);
}

void copy_vm_area_data(struct criu_vm_area * area) {
	if(area->original_data != NULL)
		memcpy((void *)area->vm_start, area->original_data + area->offset, area->vm_end - area->vm_start);
}

static TEE_Result load_checkpoint_data(TEE_Param * binaryData, TEE_Param * binaryDataInformation) {
	TEE_Result res;
	TEE_UUID uuid = CHECKPOINT_UUID;

	struct tee_ta_session *s = calloc(1, sizeof(struct tee_ta_session));	
	if (!s)
		return TEE_ERROR_OUT_OF_MEMORY;

	s->cancel_mask = true;
	condvar_init(&s->refc_cv);
	condvar_init(&s->lock_cv);
	s->lock_thread = THREAD_ID_INVALID;
	s->ref_count = 1;

	struct checkpoint_file * checkpoint_file_var = binaryDataInformation->memref.buffer;
	struct criu_checkpoint checkpoint = { .l2_tables_index = 0 };
	TAILQ_INIT(&checkpoint.pagemap_entries);

	if(!parse_checkpoint_core(&checkpoint, binaryData->memref.buffer + checkpoint_file_var[CORE_FILE].buffer_index, checkpoint_file_var[CORE_FILE].file_size)) {
		DMSG("Checkpoint file core-*.img file is not valid.");
		return TEE_ERROR_BAD_FORMAT;
	}

	if(!parse_checkpoint_mm(&checkpoint, binaryData->memref.buffer + checkpoint_file_var[MM_FILE].buffer_index, checkpoint_file_var[MM_FILE].file_size)) {
		DMSG("Checkpoint file mm-*.img file is not valid.");
		return TEE_ERROR_BAD_FORMAT;
	}

	if(!parse_checkpoint_pagemap(&checkpoint, binaryData->memref.buffer + checkpoint_file_var[PAGEMAP_FILE].buffer_index, checkpoint_file_var[PAGEMAP_FILE].file_size)) {
		DMSG("Checkpoint file pagemap-*.img file is not valid.");
		return TEE_ERROR_BAD_FORMAT;
	}

	// Create the user TA
	struct user_ta_ctx * utc = create_user_ta_ctx(&uuid);
	if(utc == NULL)
		return TEE_ERROR_GENERIC;

	s->ctx = &utc->uctx.ctx;

	utc->uctx.checkpoint = &checkpoint;

	set_vfp_registers(checkpoint.regs.vregs, &utc->uctx.vfp);
	
	tee_ta_push_current_session(s);

	struct criu_vm_area * area = checkpoint.vm_areas;
	// for(int i = 0; i < checkpoint.vm_area_count; i++) {
	// 	if ((res = map_vm_area(utc, &area[i]))) {
	// 		DMSG("CRIU - ALLOC %p - %p failed: %p", area[i].vm_start, area[i].vm_end, res);
	// 		return res;
	// 	}
	// }

	utc->ldelf_stack_ptr = checkpoint.regs.stack_addr;
	utc->entry_func = checkpoint.regs.entry_addr;

	DMSG("\n\nCRIU - ALLOCATION COMPLETED!");

	DMSG("CRIU - SET CTX!");
	criu_tee_mmu_set_ctx(&utc->uctx.ctx);

	// dump_mmu_tables(&utc->uctx.map);

	DMSG("\n\nCRIU - DATA COPY START!");

	area = checkpoint.vm_areas;
	for(int i = 0; i < checkpoint.vm_area_count; i++) {
		if(area[i].status & VMA_FILE_PRIVATE) {
			area[i].original_data = binaryData->memref.buffer + checkpoint_file_var[EXECUTABLE_BINARY_FILE].buffer_index;
		}
	}

	uint32_t pages_file_index = 0;
	struct criu_pagemap_entry_tracker * entry = NULL;
	TAILQ_FOREACH(entry, &checkpoint.pagemap_entries, link) {
		entry->buffer = binaryData->memref.buffer 								// Data buffer
				+ checkpoint_file_var[PAGES_BINARY_FILE].buffer_index   // Plus offset of the pages file
				+ SMALL_PAGE_SIZE * pages_file_index;
		pages_file_index += entry->entry.nr_pages;
	}

#ifdef CRIU_TEST_RETURNING
	memcpy(checkpoint.entry_addr, test_code_exec_sys_exit, sizeof(test_code_exec_sys_exit));
#endif

	DMSG("CRIU - DATA COPIED OVER!\n\n");


	// DMSG("\n\nCRIU - SET PROTECTION BITS");
	// res = criu_vm_set_prot(&utc->uctx, code.vm_start,
	// 		  ROUNDUP(code.vm_end - code.vm_start, SMALL_PAGE_SIZE),
	// 		  TEE_MATTR_URX);
	// if (res) {
	// 	DMSG("CRIU - SET PROTECTION BITS failed: %d", res);
	// 	return res;
	// }

	// // dump_mmu_tables(&utc->uctx.map);

	// DMSG("CRIU - PROTECTION BITS SET\n\n");

	DMSG("\n\nCRIU - BINARY LOAD ADDRESS %#"PRIxVA, utc->entry_func);

	utc->is_32bit = false;
	utc->uctx.ctx.ref_count = 1;
	condvar_init(&utc->uctx.ctx.busy_cv);
	TAILQ_INSERT_TAIL(&tee_ctxes, &utc->uctx.ctx, link);

	criu_tee_mmu_set_ctx(&utc->uctx.ctx);

	user_mode_ctx_print_mappings(&utc->uctx);

	DMSG("\n\nCRIU - RUN! Entry address: %p", (void *) checkpoint.regs.entry_addr);
	
	jump_to_user_mode(utc->entry_func, utc->ldelf_stack_ptr, checkpoint.regs.tpidr_el0_addr, checkpoint.regs.regs);

	DMSG("CRIU - COPYING DATA BACK");

	long index = 0;
	memcpy(binaryData->memref.buffer, &checkpoint.regs, sizeof(struct criu_checkpoint_regs));
	index += sizeof(struct criu_checkpoint_regs);

	struct criu_checkpoint_dirty_pages * dirty_pages_info = binaryData->memref.buffer + index;
	index += sizeof(struct criu_checkpoint_dirty_pages);
	
	dirty_pages_info->dirty_page_count = 0;
	
	TAILQ_FOREACH(entry, &checkpoint.pagemap_entries, link) {
		if(entry->dirty) {
			DMSG("GOT A DIRTY ENTRY HERE: %p - %p - %d", entry->entry.vaddr_start, entry->entry.vaddr_start + (entry->entry.nr_pages * SMALL_PAGE_SIZE), entry->entry.nr_pages);

			dirty_pages_info->dirty_page_count++;
			memcpy(binaryData->memref.buffer + index, &entry->entry, sizeof(struct criu_pagemap_entry));
			index += sizeof(struct criu_pagemap_entry);
		}
	}

	dirty_pages_info->offset = index;
	TAILQ_FOREACH(entry, &checkpoint.pagemap_entries, link) {
		if(entry->dirty) {
			memcpy(binaryData->memref.buffer + index, entry->entry.vaddr_start, entry->entry.nr_pages * SMALL_PAGE_SIZE);
			index += entry->entry.nr_pages * SMALL_PAGE_SIZE;
		}

		// Free all allocated criu_pagemap_entry structs
		free(entry);
	}

	tee_ta_pop_current_session();


	// Free all allocated criu_vm_area structs
	if(checkpoint.vm_areas != NULL)
		free(checkpoint.vm_areas);
	
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

	uint8_t files = params[1].memref.size / sizeof(struct checkpoint_file);
	DMSG("Second argument contains information about %d checkpoint files", files);
	if(files == CHECKPOINT_FILES)
		DMSG("Which matches to the expected number: %d/%d", files, CHECKPOINT_FILES);
	else
		DMSG("Unexpected number of checkpoint files: %d/%d", files, CHECKPOINT_FILES);
	
	// LOAD CHECKPOINT DATA
	load_checkpoint_data(&params[0], &params[1]);
	char message[] = "hello from mitchell";
 
	memcpy(params[0].memref.buffer, message, 
			(params[0].memref.size >= sizeof(message) 
			? sizeof(message) : params[0].memref.size));
	
	IMSG("Changed value to: \"%s\"", (char *) params[0].memref.buffer);

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
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx) {
	(void) sess_ctx; // Susspress unused variable warning
	DMSG("Open session to %s", TA_NAME);
	return TEE_SUCCESS;
}

static void close_session(void *sess_ctx) {
	(void) sess_ctx; // Suspress unused variable warning
	DMSG("Closed session to %s", TA_NAME);
}

pseudo_ta_register(.uuid = CRIU_UUID, .name = TA_NAME,
	.flags = PTA_DEFAULT_FLAGS,
	.open_session_entry_point = open_session,
	.close_session_entry_point = close_session,
	.invoke_command_entry_point = invoke_command);
