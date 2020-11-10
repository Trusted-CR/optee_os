#ifndef __CRIU_CHECKPOINT_PARSER_H
#define __CRIU_CHECKPOINT_PARSER_H

#include <string.h>
#include <stdint.h>
#include "criu/criu_checkpoint.h"
#include "criu/jsmn.h"
#include <sys/queue.h>

#ifndef DMSG
#include <stdio.h>
#define DMSG printf
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

static bool parse_checkpoint_pagemap(struct criu_pagemap_entries * pagemap_entries, char * json, uint64_t file_size) {
	if(pagemap_entries == NULL) {
		DMSG("Error: pagemap_entries struct is NULL");
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

						TAILQ_INSERT_TAIL(pagemap_entries, entry, link);

						file_index += entry->entry.nr_pages;
					}
				}

				return true;
			}
		}
	}

	return true;
}

#endif /*__CRIU_CHECKPOINT_PARSER_H*/
