/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __UTRACE_CFG_H_
#define __UTRACE_CFG_H_

#ifndef __bpf__
#include <stdbool.h>
#include <stddef.h>
#include "elf_utils.h"
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

struct tp_field {
	char *name;
	int offset;
	int size;
	bool is_signed;
	bool is_data_loc;
	bool is_string;		/* char[] array */
};

struct utrace_param {
	enum utrace_param_type type;
	union {
		struct {
			int arg_idx;			/* 0-based arg index, or UTRACE_ARG_RET */
			enum utrace_arg_type arg_type; 	/* defaults to UTRACE_ARG_U64 if omitted */
			char *name;			/* annotation name, NULL = auto "arg<N>" / "ret" */
			int tp_byte_off;		/* TP: byte offset into event struct */
			bool tp_data_loc;		/* TP: __data_loc encoded string field */
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
			const char *attach_path;	/* resolved path used to attach (/proc/<pid>/map_files/... or user path) */
			const char *display_path;	/* human-readable path for logging/output */
			unsigned long attach_off;	/* resolved total offset: sym_offset + off */
		} uprobe;
		/* USDT */
		struct {
			char *provider;
			char *name;
			const char *attach_path;	/* resolved path for attachment */
			const char *display_path;	/* human-readable path for logging */
			struct usdt_info info;		/* discovered arg metadata */
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
			struct tp_field *fields;	/* parsed from tracefs format file */
			int field_cnt;
		} tp;
		/* RAW_TRACEPOINT */
		struct {
			char *name;
			const struct btf_type *proto;		/* resolved FUNC_PROTO from btf_trace_<name> */
			const struct btf_type *name_proto;	/* FUNC_PROTO from __traceiter_<name> (for param names) */
			int arg_cnt;				/* number of tracepoint args (excluding void* ctx) */
		} raw_tp;

		/* BPF_PROBE, BPF_RETPROBE, BPF_SPAN */
		struct {
			char *name;
			int prog_fd;	/* resolved target prog fd (filled during setup) */
			unsigned int btf_func_id; /* BTF func type ID */
			struct btf *btf; /* target prog BTF (valid during setup only) */
		} bpf_prog;

		/* GENERIC SPAN */
		struct {
			struct utrace_cfg *entry;
			struct utrace_cfg *exit;
		} span;
	};
};

struct sbuf;

static inline bool cfg_is_span(const struct utrace_cfg *cfg)
{
	return cfg->type == UTRACE_UPROBE_SPAN || cfg->type == UTRACE_KPROBE_SPAN ||
	       cfg->type == UTRACE_BPF_SPAN || cfg->type == UTRACE_SPAN;
}

/*
 * Iterate the simple sub-configs of a utrace_cfg: for generic UTRACE_SPAN,
 * yields entry then exit leg; for all other cfgs, yields cfg itself once.
 */
#define utrace_for_each_leg(leg, cfg)						\
	for (struct utrace_cfg *___legs[3] = {					\
			(cfg)->type == UTRACE_SPAN ? (cfg)->span.entry : (cfg),	\
			(cfg)->type == UTRACE_SPAN ? (cfg)->span.exit : NULL,	\
			NULL,							\
		}, **___p = ___legs, *leg = *___p;				\
		leg;								\
		leg = *++___p)

void utrace_compile_fmt(const char *fmt, const struct utrace_param *params, int param_cnt,
			struct utrace_fmt_seg **out_segs, int *out_seg_cnt);
int utrace_cfg_parse(const char *def);
int utrace_cfg_parse_file(const char *path);
void utrace_cfg_format(const struct utrace_cfg *cfg, struct sbuf *sb);

#endif /* !__bpf__ */

#endif /* __UTRACE_CFG_H_ */
