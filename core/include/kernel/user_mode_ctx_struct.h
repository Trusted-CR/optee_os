/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef __KERNEL_USER_MODE_CTX_STRUCT_H
#define __KERNEL_USER_MODE_CTX_STRUCT_H

#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <mm/tee_mmu_types.h>

struct criu_vm_area {
	vaddr_t vm_start;
	vaddr_t vm_end;
	void * original_data;
	unsigned long offset;
	uint32_t protection;
	uint8_t status;
	bool dirty;
};

struct criu_pagemap_entry {
	vaddr_t vaddr;
	unsigned long nr_pages;
	uint8_t flags;
};

struct criu_checkpoint {
	struct criu_vm_area * vm_areas;
	uint32_t vm_area_count;
	struct criu_pagemap_entry * pagemap_entries;
	uint32_t pagemap_entry_count;
	uint64_t vregs[64];
	uint64_t regs[31];
	uint64_t entry_addr;
	uint64_t stack_addr;
	uint64_t tpidr_el0_addr;
};

enum criu_status_bits {
	VMA_AREA_REGULAR  = 1 << 0,
	VMA_FILE_PRIVATE  = 1 << 1
};

enum criu_pte_flags {
	PE_PRESENT  = 1 << 0,
	PE_LAZY     = 1 << 1
};

enum checkpoint_file_types { 
	CORE_FILE = 0,				// core-*.img
	MM_FILE,				// mm-*.img
	PAGEMAP_FILE,			// pagemap-*.img
	PAGES_BINARY_FILE,		// pages-*.img
	EXECUTABLE_BINARY_FILE	// The binary itself that is checkpointed
};

// Subtract the last enum from the first to determine the number of 
// elements in the enum. By doing this we can use the enum values as indexes
// to the checkpoint_files array. Example checkpoint_files[CORE_FILE].
static const int CHECKPOINT_FILES = EXECUTABLE_BINARY_FILE - CORE_FILE + 1; 

struct checkpoint_file {
	enum checkpoint_file_types file_type;
	uint64_t buffer_index;
	uint64_t file_size;
};

struct user_mode_ctx {
	struct vm_info vm_info;
	struct tee_pager_area_head *areas;
#if defined(CFG_WITH_VFP)
	struct thread_user_vfp_state vfp;
#endif
	struct tee_ta_ctx ctx;
	struct core_mmu_map map;
	struct criu_checkpoint * checkpoint;
	bool is_criu_checkpoint;
};
#endif /*__KERNEL_USER_MODE_CTX_STRUCT_H*/

