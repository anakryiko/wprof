// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Simple BPF program with a non-inlined subprogram for testing bpf: probes. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} test_cnt SEC(".maps");

static __noinline int utrace_test_handle(const char *name, s32 value)
{
	u32 key = 0;
	u64 *cnt = bpf_map_lookup_elem(&test_cnt, &key);
	if (cnt)
		__sync_fetch_and_add(cnt, value + name[0]);
	return value;
}

SEC("tp/raw_syscalls/sys_enter")
int test_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();

	return utrace_test_handle(task->comm, (s32)ctx->id);
}

char LICENSE[] SEC("license") = "GPL";
