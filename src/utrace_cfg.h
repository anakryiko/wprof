/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __UTRACE_CFG_H_
#define __UTRACE_CFG_H_

#ifndef __bpf__
#include <stdbool.h>
#include <stddef.h>
#endif

enum utrace_type {
	UTRACE_INVALID,
	UTRACE_UPROBE,		/* u:func */
	UTRACE_URETPROBE,	/* uret:func */
	UTRACE_USDT,		/* usdt:provider:name */
	UTRACE_KPROBE,		/* k:func */
	UTRACE_KRETPROBE,	/* kret:func */
	UTRACE_TRACEPOINT,	/* tp:category:name */
	UTRACE_RAW_TRACEPOINT,	/* raw_tp:name */
	UTRACE_UPROBE_SPAN,	/* uspan:func */
	UTRACE_KPROBE_SPAN,	/* kspan:func */
	UTRACE_BPF_PROBE,	/* bpf:prog_name */
	UTRACE_BPF_RETPROBE,	/* bpfret:prog_name */
	UTRACE_BPF_SPAN,	/* bpfspan:prog_name */
	UTRACE_SPAN,		/* two non-span probes joined by + */
};

enum utrace_arg_type {
	UTRACE_ARG_UNKNOWN,
	UTRACE_ARG_U8,
	UTRACE_ARG_U16,
	UTRACE_ARG_U32,
	UTRACE_ARG_U64,
	UTRACE_ARG_S8,
	UTRACE_ARG_S16,
	UTRACE_ARG_S32,
	UTRACE_ARG_S64,
	UTRACE_ARG_STR,
	UTRACE_ARG_PTR,
};

static inline int utrace_arg_size(enum utrace_arg_type t)
{
	switch (t) {
	case UTRACE_ARG_U8:  case UTRACE_ARG_S8:  return 1;
	case UTRACE_ARG_U16: case UTRACE_ARG_S16: return 2;
	case UTRACE_ARG_U32: case UTRACE_ARG_S32: return 4;
	case UTRACE_ARG_U64: case UTRACE_ARG_S64: case UTRACE_ARG_PTR: return 8;
	default: return 0;
	}
}

enum utrace_param_type {
	UTRACE_PARAM_INVALID = 0,
	UTRACE_PARAM_ARG = 1,
	UTRACE_PARAM_CAPTURE_STACK = 1000,
	UTRACE_PARAM_BINARY_PATH,
	UTRACE_PARAM_PID,
};

#define UTRACE_ARG_RET (-1)

#ifndef __bpf__

struct utrace_param {
	enum utrace_param_type type;
	union {
		struct {
			int arg_idx;			/* 0-based arg index, or UTRACE_ARG_RET */
			enum utrace_arg_type arg_type; 	/* defaults to UTRACE_ARG_U64 if omitted */
			char *name;			/* annotation name, NULL = auto "arg<N>" / "ret" */
		} arg;
		struct {
			char *path;
		} binary;
		struct {
			int pid;
		} pid;
	};
};

enum utrace_fmt_seg_type {
	UTRACE_FMT_SEG_LIT,  /* literal string segment */
	UTRACE_FMT_SEG_ARG,  /* argument substitution */
};

struct utrace_fmt_seg {
	enum utrace_fmt_seg_type type;
	union {
		struct {
			const char *s;   /* points into name_fmt string */
			int len;
		} lit;
		struct {
			int arg_idx;                /* positional index into entry-side arg_refs[] */
			enum utrace_arg_type type;  /* cached arg type for formatting */
		} arg;
	};
};

struct utrace_settings {
	char *id;       /* user-defined probe identifier, NULL if unset */
	char *name_fmt; /* format string for slice/instant name, NULL if unset */
	struct utrace_fmt_seg *name_segs; /* pre-compiled name format segments */
	int name_seg_cnt;
};

struct utrace_cfg {
	enum utrace_type type;
	bool wildcard_args;

	struct utrace_param *params;
	int param_cnt;

	struct utrace_settings settings;

	union {
		/* UPROBE, URETPROBE, UPROBE_SPAN */
		struct {
			char *name;
			long off;
		} uprobe;
		/* USDT */
		struct {
			char *provider;
			char *name;
		} usdt;
		/* KPROBE, KRETPROBE, KPROBE_SPAN */
		struct {
			char *name;
			long off;
		} kprobe;
		/* TRACEPOINT */
		struct {
			char *cat;
			char *name;
		} tp;
		/* RAW_TRACEPOINT */
		struct {
			char *name;
		} raw_tp;

		/* BPF_PROBE, BPF_RETPROBE, BPF_SPAN */
		struct {
			char *name;
			int prog_fd;	/* resolved target prog fd (filled during setup) */
			unsigned int btf_func_id; /* BTF func type ID */
		} bpf_prog;

		/* GENERIC SPAN */
		struct {
			struct utrace_cfg *entry;
			struct utrace_cfg *exit;
		} span;
	};
};

struct sbuf;

int utrace_cfg_parse(const char *def);
int utrace_cfg_parse_file(const char *path);
void utrace_cfg_format(const struct utrace_cfg *cfg, struct sbuf *sb);

#endif /* !__bpf__ */

#endif /* __UTRACE_CFG_H_ */
