// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2026 Meta Platforms, Inc. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* first hit of a utrace trigger, keep in sync with the copy in utrace_trigger.h */
struct utrace_trigger_hit {
	__u32 pid;
	__u32 tid;
	__u32 cpu;
	char comm[16];	/* TASK_COMM_LEN */
};

/* all hits so far, only the first one is reported */
__u64 hit_cnt;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} trigger_rb SEC(".maps");

static __always_inline int fire(void)
{
	struct utrace_trigger_hit *hit;
	__u64 pid_tgid;

	if (__sync_fetch_and_add(&hit_cnt, 1))
		return 0;

	/* the only record ever submitted, so it always fits */
	hit = bpf_ringbuf_reserve(&trigger_rb, sizeof(*hit), 0);
	if (!hit)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	hit->pid = pid_tgid >> 32;
	hit->tid = (__u32)pid_tgid;
	hit->cpu = bpf_get_smp_processor_id();
	bpf_get_current_comm(hit->comm, sizeof(hit->comm));
	bpf_ringbuf_submit(hit, BPF_RB_FORCE_WAKEUP);
	return 0;
}

SEC("?uprobe")
int wprof_trig_uprobe(void *ctx) { return fire(); }

SEC("?uretprobe")
int wprof_trig_uret(void *ctx) { return fire(); }

SEC("?usdt")
int wprof_trig_usdt(void *ctx) { return fire(); }

SEC("?kprobe")
int wprof_trig_kprobe(void *ctx) { return fire(); }

SEC("?kprobe.multi")
int wprof_trig_kmulti(void *ctx) { return fire(); }

SEC("?kretprobe")
int wprof_trig_kret(void *ctx) { return fire(); }

SEC("?kretprobe.multi")
int wprof_trig_kretmulti(void *ctx) { return fire(); }

SEC("?tp")
int wprof_trig_tp(void *ctx) { return fire(); }

SEC("?raw_tp")
int wprof_trig_raw_tp(void *ctx) { return fire(); }

/* fentry/fexit clone templates for bpf: and bpfret: utrace triggers */
SEC("?fentry")
int wprof_trig_bpf_entry(void *ctx) { return fire(); }

SEC("?fexit")
int wprof_trig_bpf_exit(void *ctx) { return fire(); }
