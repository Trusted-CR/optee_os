#ifndef __CRIU_CHECKPOINT_H
#define __CRIU_CHECKPOINT_H

#include <stdint.h>
#include <stdbool.h>

typedef uintptr_t vaddr_t;

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
	vaddr_t vaddr_start;
	unsigned long file_page_index;
	unsigned long nr_pages;
	uint8_t flags;
	void * buffer;
};

struct criu_dirty_page{
	vaddr_t vaddr_start;
	TAILQ_ENTRY(criu_dirty_page) link;
};

struct criu_merged_page {
	bool is_new;
	struct criu_pagemap_entry entry;
	TAILQ_ENTRY(criu_merged_pagemap) link;
};

TAILQ_HEAD(criu_merged_pagemap, criu_merged_page);

TAILQ_HEAD(criu_dirty_pagemap, criu_dirty_page);

struct criu_checkpoint_regs {
	uint64_t vregs[64];
	uint64_t regs[31];
	uint64_t entry_addr;
	uint64_t stack_addr;
	uint64_t tpidr_el0_addr;
	uint32_t pstate;
	uint32_t fpsr;
	uint32_t fpcr;
	bool fp_used;
};

struct criu_checkpoint_dirty_pages {
	uint32_t dirty_page_count;
	uint32_t offset;
};

enum criu_return_types {
	CRIU_IDLE,
	CRIU_RUNNING,
	CRIU_SYSCALL_WRITE		= 64,
	CRIU_SYSCALL_EXIT		= 93,
	CRIU_SYSCALL_EXIT_GROUP	= 94,
	CRIU_SYSCALL_NANOSLEEP	= 115,
	CRIU_SYSCALL_UNSUPPORTED,
	CRIU_UNDEFINED_ABORT,
	CRIU_OUT_OF_MEMORY,
	CRIU_MIGRATE_BACK,
	CRIU_DATA_DIRTY_CHECKPOINT
};

struct criu_checkpoint {
	enum criu_return_types result;
	// VMA's
	struct criu_vm_area * vm_areas;
	uint32_t vm_area_count;
	// Pagemap entries
	struct criu_pagemap_entry * pagemap_entries;
	uint32_t pagemap_entry_count;
	// Dirty pages
	struct criu_dirty_pagemap dirty_pagemap;
	// Registers
	struct criu_checkpoint_regs regs;
	uint8_t l2_tables_index;
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
	EXECUTABLE_BINARY_FILE = 0,		// The binary itself that is checkpointed
	PAGES_BINARY_FILE,				// pages-*.img
	CORE_FILE,						// core-*.img
	MM_FILE,						// mm-*.img
	PAGEMAP_FILE,					// pagemap-*.img
	FD_INFO_FILE,					// fd_info-*.img
	FILES_FILE						// files.img file
};

struct checkpoint_file {
	enum checkpoint_file_types file_type;
	uint64_t buffer_index;
	uint64_t file_size;
};
struct checkpoint_file_data {
	struct checkpoint_file file;
	char * filename;
	char * buffer;
};

struct criu_fd_info {
	int id;
	int fd;
};

struct criu_file {
	int id;
	char * name;
};

#endif /*__CRIU_CHECKPOINT_H*/
