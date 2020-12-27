#ifndef __CRIU_CHECKPOINT_PARSER_H
#define __CRIU_CHECKPOINT_PARSER_H

#include <string.h>
#include <stdint.h>
#include "criu_checkpoint.h"
#include "jsmn.h"
#include <sys/queue.h>

#ifndef DMSG
#include <stdio.h>
#define DMSG printf
#endif

#define TEE_MATTR_UR			(1 << 7)
#define TEE_MATTR_UW			(1 << 8)
#define TEE_MATTR_UX			(1 << 9)

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

static bool parse_checkpoint_pagemap(struct criu_checkpoint * checkpoint, struct checkpoint_file_data * checkpoint_files) {
	if(checkpoint == NULL) {
		DMSG("Error: checkpoint struct is NULL");
		return false;
	}

	char * json = checkpoint_files[PAGEMAP_FILE].buffer;
	uint64_t file_size = checkpoint_files[PAGEMAP_FILE].file.file_size;

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
				checkpoint->pagemap_entry_count = tokens[++i].size - 1; i+=4;
				checkpoint->pagemap_entries = calloc(1, sizeof(struct criu_pagemap_entry) * checkpoint->pagemap_entry_count);
				if(checkpoint->pagemap_entries == NULL) {
					DMSG("Unable to allocate checkpoint->pagemap_entries: Out of memory");
					return false;
				}

				int file_index = 0;
				// Parse all pagemap entries
				for(int y = 0; y < checkpoint->pagemap_entry_count; y++, i += (tokens[i].size * 2) + 1) {
					if(tokens[i].size == 3) {
						// Parse the address, number of pages and initialize the flags.
						checkpoint->pagemap_entries[y].vaddr_start = strtoul(json + tokens[i+2].start, NULL, 16);
						checkpoint->pagemap_entries[y].nr_pages    = strtoul(json + tokens[i+4].start, NULL, 10);
						checkpoint->pagemap_entries[y].flags       = 0;
						checkpoint->pagemap_entries[y].file_page_index = file_index;
						
						// Parse the flags
						if(sstrstr(json + tokens[i+6].start, "PE_PRESENT", tokens[i+6].end - tokens[i+6].start) != NULL)
							checkpoint->pagemap_entries[y].flags |= PE_PRESENT;
						if(sstrstr(json + tokens[i+6].start, "PE_LAZY", tokens[i+6].end - tokens[i+6].start) != NULL)
							checkpoint->pagemap_entries[y].flags |= PE_LAZY;

						file_index += checkpoint->pagemap_entries[y].nr_pages;
					}
				}

				return true;
			}
		}
	}

	return true;
}

static bool parse_checkpoint_core(struct criu_checkpoint * checkpoint, struct checkpoint_file_data * checkpoint_files) {
	if(checkpoint == NULL) {
		DMSG("Error: criu_checkpoint struct is NULL");
		return false;
	}

	char * json = checkpoint_files[CORE_FILE].buffer;
	uint64_t file_size = checkpoint_files[CORE_FILE].file.file_size;

	// Initialize the JSMN json parser
	jsmn_parser parser;
	jsmn_init(&parser);

	// First only determine the number of tokens.
	int items = jsmn_parse(&parser, json, file_size, NULL, 128);

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
		// Parse the processor state flags
		} else if(jsoneq(json, &tokens[i], "pstate") == 0) { 
			if(tokens[i+1].type == JSMN_STRING)
				checkpoint->regs.pstate = strtoul(json + tokens[i+1].start, NULL, 16);
		// Parse FPSR register
		} else if(jsoneq(json, &tokens[i], "fpsr") == 0) { 
			if(tokens[i+1].type == JSMN_PRIMITIVE)
				checkpoint->regs.fpsr = strtoul(json + tokens[i+1].start, NULL, 10);
		// Parse FPCR register
		} else if(jsoneq(json, &tokens[i], "fpcr") == 0) { 
			if(tokens[i+1].type == JSMN_PRIMITIVE)
				checkpoint->regs.fpcr = strtoul(json + tokens[i+1].start, NULL, 10);
		}
	}

	return true;
}

static bool parse_checkpoint_mm(struct criu_checkpoint * checkpoint, struct checkpoint_file_data * checkpoint_files) {
	if(checkpoint == NULL) {
		DMSG("Error: criu_checkpoint struct is NULL");
		return false;
	}

	char * json = checkpoint_files[MM_FILE].buffer;
	uint64_t file_size = checkpoint_files[MM_FILE].file.file_size;

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
				checkpoint->vm_areas = calloc(1, sizeof(struct criu_vm_area) * checkpoint->vm_area_count);

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

#endif /*__CRIU_CHECKPOINT_PARSER_H*/
