#ifndef __TRUSTED_CR_CHECKPOINT_H
#define __TRUSTED_CR_CHECKPOINT_H

#include <stdint.h>
#include <stdbool.h>

typedef uintptr_t vaddr_t;

struct trusted_cr_vm_area {
	vaddr_t vm_start;
	vaddr_t vm_end;
	void * original_data;
	unsigned long offset;
	uint32_t protection;
	uint8_t status;
	bool dirty;
};

struct trusted_cr_pagemap_entry {
	vaddr_t vaddr_start;
	unsigned long file_page_index;
	unsigned long nr_pages;
	uint8_t flags;
	void * buffer;
};

struct trusted_cr_dirty_page{
	vaddr_t vaddr_start;
	TAILQ_ENTRY(trusted_cr_dirty_page) link;
};

struct trusted_cr_merged_page {
	bool is_new;
	struct trusted_cr_pagemap_entry entry;
	TAILQ_ENTRY(trusted_cr_merged_pagemap) link;
};

TAILQ_HEAD(trusted_cr_merged_pagemap, trusted_cr_merged_page);

TAILQ_HEAD(trusted_cr_dirty_pagemap, trusted_cr_dirty_page);

struct trusted_cr_checkpoint_regs {
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

struct trusted_cr_checkpoint_dirty_pages {
	uint32_t dirty_page_count;
	uint32_t offset;
};

enum trusted_cr_return_types {
	TRUSTED_CR_IDLE,
	TRUSTED_CR_RUNNING,
	TRUSTED_CR_SYSCALL_WRITE		= 64,
	TRUSTED_CR_SYSCALL_EXIT		= 93,
	TRUSTED_CR_SYSCALL_EXIT_GROUP	= 94,
	TRUSTED_CR_SYSCALL_NANOSLEEP	= 115,
	TRUSTED_CR_SYSCALL_UNSUPPORTED,
	TRUSTED_CR_UNDEFINED_ABORT,
	TRUSTED_CR_OUT_OF_MEMORY,
	TRUSTED_CR_DATA_DIRTY_CHECKPOINT,
	TRUSTED_CR_SYSCALL_MIGRATE_BACK = 1000
};

struct trusted_cr_checkpoint {
	enum trusted_cr_return_types result;
	// VMA's
	struct trusted_cr_vm_area * vm_areas;
	uint32_t vm_area_count;
	// Pagemap entries
	struct trusted_cr_pagemap_entry * pagemap_entries;
	uint32_t pagemap_entry_count;
	// Dirty pages
	struct trusted_cr_dirty_pagemap dirty_pagemap;
	// Registers
	struct trusted_cr_checkpoint_regs regs;
	uint8_t l2_tables_index;
};

enum trusted_cr_status_bits {
	VMA_AREA_REGULAR  = 1 << 0,
	VMA_FILE_PRIVATE  = 1 << 1
};

enum trusted_cr_pte_flags {
	PE_PRESENT  = 1 << 0,
	PE_LAZY     = 1 << 1
};

enum checkpoint_file_types { 
	EXECUTABLE_BINARY_FILE = 0,		// The binary itself that is checkpointed
	PAGES_BINARY_FILE,				// pages-*.img
	CORE_FILE,						// core-*.img
	MM_FILE,						// mm-*.img
	PAGEMAP_FILE,					// pagemap-*.img
	FILES_FILE,						// files.img file
	NUMBER_OF_CHECKPOINT_FILES		// use this little hack to determine the number of elements in the enum
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

struct trusted_cr_fd_info {
	int id;
	int fd;
};

struct trusted_cr_file {
	int id;
	char * name;
};

#endif /*__TRUSTED_CR_CHECKPOINT_H*/
