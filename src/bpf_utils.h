/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __BPF_UTILS_H_
#define __BPF_UTILS_H_

#include <stdint.h>

#include "utils.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct wprof_bpf;

struct bpf_state {
	bool detached;
	bool drained;
	struct wprof_bpf *skel;
	struct bpf_link **links;
	int link_cnt;
	struct ring_buffer **rb_managers;
	pthread_t *rb_threads;
	int *perf_timer_fds;
	int *perf_counter_fds;
	int perf_counter_fd_cnt;
	int *rb_map_fds;
	int stats_fd;
	bool *online_mask;
	int num_online_cpus;
};

struct uprobe_binary;

int attach_usdt_probe(struct bpf_state *st, struct bpf_program *prog,
		      const char *binary_path, const char *binary_attach_path,
		      const char *usdt_provider, const char *usdt_name);

#endif /* __BPF_UTILS_H_ */
