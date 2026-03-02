/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __PYSYM_H_
#define __PYSYM_H_

#include <stdint.h>

struct pysym_frame {
	uint32_t symbol_id;
	int32_t inst_idx;
};

/*
 * Userspace-compatible layout of pystacks_message.
 * The BPF-side pystacks_message has implicit padding; this struct
 * uses explicit padding and a union at offset 8 so that pystack_id
 * (written back during stack processing) reuses the probe_time_ns slot.
 */
struct pystack_msg {
	uint16_t type;
	uint16_t len;
	uint8_t _pad0[4];

	union {
		int64_t probe_time_ns;
		uint32_t pystack_id;
	};

	uint8_t thread_state_match;
	uint8_t gil_state;
	uint8_t pthread_id_match;
	uint8_t stack_status;
	uint8_t async_stack_status;
	uint8_t last_frame_statically_compiled;
	uint8_t _pad1[2];

	uint64_t stack_len;
	uint64_t max_stack_depth;

	struct pysym_frame frames[];
};

int pysym_init(int symbols_map_fd, int linetables_map_fd);
void pysym_free(void);
const char *pysym_filename(uint32_t id);
const char *pysym_qualname(uint32_t id);
uint32_t pysym_line_number(uint32_t symbol_id, int32_t inst_idx);

#endif /* __PYSYM_H_ */
