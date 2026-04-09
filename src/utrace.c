// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

#include <bpf/btf.h>

#include "utils.h"
#include "env.h"
#include "utrace.h"
#include "utrace_cfg.h"
#include "elf_utils.h"
#include "bpf_utils.h"
#include "proc.h"
#include "wprof.skel.h"

static int add_link(struct bpf_state *st, struct bpf_link *link)
{
	struct bpf_link **tmp;

	tmp = realloc(st->links, (st->link_cnt + 1) * sizeof(struct bpf_link *));
	if (!tmp)
		return -ENOMEM;
	st->links = tmp;
	st->links[st->link_cnt] = link;
	st->link_cnt++;
	return 0;
}

static int add_link_fd(struct bpf_state *st, int fd)
{
	int *tmp;

	tmp = realloc(st->link_fds, (st->link_fd_cnt + 1) * sizeof(int));
	if (!tmp)
		return -ENOMEM;
	st->link_fds = tmp;
	st->link_fds[st->link_fd_cnt] = fd;
	st->link_fd_cnt++;
	return 0;
}

static bool cfg_needs_uprobe(const struct utrace_cfg *cfg)
{
	switch (cfg->type) {
	case UTRACE_UPROBE:
	case UTRACE_UPROBE_SPAN:
		return true;
	default:
		return false;
	}
}

static bool cfg_needs_uretprobe(const struct utrace_cfg *cfg)
{
	switch (cfg->type) {
	case UTRACE_URETPROBE:
	case UTRACE_UPROBE_SPAN:
		return true;
	default:
		return false;
	}
}

static bool cfg_needs_kprobe(const struct utrace_cfg *cfg)
{
	switch (cfg->type) {
	case UTRACE_KPROBE:
	case UTRACE_KPROBE_SPAN:
		return true;
	default:
		return false;
	}
}

static bool cfg_needs_kretprobe(const struct utrace_cfg *cfg)
{
	switch (cfg->type) {
	case UTRACE_KRETPROBE:
	case UTRACE_KPROBE_SPAN:
		return true;
	default:
		return false;
	}
}

int utrace_setup_autoload(struct wprof_bpf *skel)
{
	bool need_uprobe = false, need_uretprobe = false;
	bool need_kprobe = false, need_kretprobe = false;

	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		const struct utrace_cfg *cfg = &env.utrace_cfgs[i];

		need_uprobe |= cfg_needs_uprobe(cfg);
		need_uretprobe |= cfg_needs_uretprobe(cfg);
		need_kprobe |= cfg_needs_kprobe(cfg);
		need_kretprobe |= cfg_needs_kretprobe(cfg);
	}

	if (need_uprobe)
		bpf_program__set_autoload(skel->progs.utrace_uprobe, true);
	if (need_uretprobe)
		bpf_program__set_autoload(skel->progs.utrace_uretprobe, true);
	if (need_kprobe)
		bpf_program__set_autoload(skel->progs.utrace_kprobe, true);
	if (need_kretprobe)
		bpf_program__set_autoload(skel->progs.utrace_kretprobe, true);

	return 0;
}

static bool cfg_is_span(const struct utrace_cfg *cfg)
{
	return cfg->type == UTRACE_UPROBE_SPAN || cfg->type == UTRACE_KPROBE_SPAN || cfg->type == UTRACE_BPF_SPAN;
}

/* Fill a utrace_probe_cfg from utrace_cfg params, filtering args by is_exit */
static void fill_probe_cfg(struct utrace_probe_cfg *pcfg, const struct utrace_cfg *cfg,
			   int utrace_id, enum utrace_event_type event_type, bool is_exit)
{
	memset(pcfg, 0, sizeof(*pcfg));
	pcfg->utrace_id = utrace_id;
	pcfg->event_type = event_type;
	pcfg->probe_type = cfg->type;

	int arg_idx = 0;
	for (int i = 0; i < cfg->param_cnt && arg_idx < MAX_UTRACE_ARGS; i++) {
		const struct utrace_param *p = &cfg->params[i];

		if (p->type == UTRACE_PARAM_CAPTURE_STACK) {
			/* For kspan/uspan exits, skip: same function as entry, stack is redundant */
			if (is_exit && cfg_is_span(cfg))
				continue;
			pcfg->flags |= UTRACE_FL_CAPTURE_STACK;
			continue;
		}
		if (p->type != UTRACE_PARAM_ARG)
			continue;

		/* For spans: ret args go to exit side, non-ret args go to entry side */
		if (event_type == UTRACE_ENTRY && p->arg.arg_idx == UTRACE_ARG_RET)
			continue;
		if (event_type == UTRACE_EXIT && p->arg.arg_idx != UTRACE_ARG_RET)
			continue;

		pcfg->args[arg_idx].type = p->arg.arg_type;
		pcfg->args[arg_idx].idx = p->arg.arg_idx;
		arg_idx++;
	}
	pcfg->arg_cnt = arg_idx;
}

static void cfg_set_binary_path(struct utrace_cfg *cfg, char *path)
{
	cfg->params = realloc(cfg->params, (cfg->param_cnt + 1) * sizeof(*cfg->params));
	struct utrace_param *p = &cfg->params[cfg->param_cnt++];
	memset(p, 0, sizeof(*p));
	p->type = UTRACE_PARAM_BINARY_PATH;
	p->binary.path = path;
}

static const char *cfg_binary_path(const struct utrace_cfg *cfg)
{
	for (int i = 0; i < cfg->param_cnt; i++) {
		if (cfg->params[i].type == UTRACE_PARAM_BINARY_PATH)
			return cfg->params[i].binary.path;
	}
	return NULL;
}

static int cfg_pid(const struct utrace_cfg *cfg)
{
	for (int i = 0; i < cfg->param_cnt; i++) {
		if (cfg->params[i].type == UTRACE_PARAM_PID)
			return cfg->params[i].pid.pid;
	}
	return -1; /* system-wide */
}

static bool cfg_is_kprobe_type(const struct utrace_cfg *cfg)
{
	switch (cfg->type) {
	case UTRACE_KPROBE:
	case UTRACE_KRETPROBE:
	case UTRACE_KPROBE_SPAN:
		return true;
	default:
		return false;
	}
}

static bool cfg_is_bpf_type(const struct utrace_cfg *cfg)
{
	switch (cfg->type) {
	case UTRACE_BPF_PROBE:
	case UTRACE_BPF_RETPROBE:
	case UTRACE_BPF_SPAN:
		return true;
	default:
		return false;
	}
}

/* Chase through typedefs/const/volatile/restrict/type_tag to the underlying type */
static const struct btf_type *btf_skip_modifiers(const struct btf *btf, __u32 id, __u32 *res_id)
{
	const struct btf_type *t;

	for (t = btf__type_by_id(btf, id); btf_is_mod(t); t = btf__type_by_id(btf, id))
		id = t->type;

	if (res_id)
		*res_id = id;
	return t;
}

static int resolve_btf_arg_type(const struct btf *btf, const char *func_name,
				int arg_idx, enum utrace_arg_type *out, const char **name_out)
{
	__s32 func_id = btf__find_by_name_kind(btf, func_name, BTF_KIND_FUNC);
	if (func_id < 0)
		return -ENOENT;

	const struct btf_type *func = btf__type_by_id(btf, func_id);
	const struct btf_type *proto = btf__type_by_id(btf, func->type);
	if (!proto || !btf_is_func_proto(proto))
		return -EINVAL;

	__u32 type_id;
	if (arg_idx == UTRACE_ARG_RET) {
		type_id = proto->type;
		if (!type_id)
			return -ENOENT;
	} else {
		if (arg_idx >= btf_vlen(proto))
			return -ENOENT;
		struct btf_param *params = btf_params(proto);
		type_id = params[arg_idx].type;
		if (name_out) {
			const char *pname = btf__name_by_offset(btf, params[arg_idx].name_off);
			if (*pname)
				*name_out = pname;
		}
	}

	const struct btf_type *t = btf_skip_modifiers(btf, type_id, NULL);

	switch (btf_kind(t)) {
	case BTF_KIND_INT: {
		__u8 encoding = btf_int_encoding(t);
		bool is_signed = encoding & BTF_INT_SIGNED;
		int bits = btf_int_bits(t);

		if (encoding & BTF_INT_BOOL) {
			*out = UTRACE_ARG_U8;
			return 0;
		}

		switch (bits) {
		case 8:  *out = is_signed ? UTRACE_ARG_S8  : UTRACE_ARG_U8;  break;
		case 16: *out = is_signed ? UTRACE_ARG_S16 : UTRACE_ARG_U16; break;
		case 32: *out = is_signed ? UTRACE_ARG_S32 : UTRACE_ARG_U32; break;
		case 64: *out = is_signed ? UTRACE_ARG_S64 : UTRACE_ARG_U64; break;
		default: *out = UTRACE_ARG_U64; break;
		}
		return 0;
	}
	case BTF_KIND_ENUM:
		*out = UTRACE_ARG_S32;
		return 0;
	case BTF_KIND_ENUM64:
		*out = UTRACE_ARG_S64;
		return 0;
	case BTF_KIND_PTR: {
		const struct btf_type *pointee = btf_skip_modifiers(btf, t->type, NULL);
		const char *name = btf__name_by_offset(btf, pointee->name_off);
		if (btf_is_int(pointee) && strcmp(name, "char") == 0)
			*out = UTRACE_ARG_STR;
		else
			*out = UTRACE_ARG_PTR;
		return 0;
	}
	default:
		*out = UTRACE_ARG_U64;
		return 0;
	}
}

static bool cfg_is_ret_probe(enum utrace_type t)
{
	return t == UTRACE_URETPROBE || t == UTRACE_KRETPROBE || t == UTRACE_BPF_RETPROBE;
}

static bool cfg_is_native_span(enum utrace_type t)
{
	return t == UTRACE_KPROBE_SPAN || t == UTRACE_UPROBE_SPAN || t == UTRACE_BPF_SPAN;
}

/* Determine the number of positional args for wildcard expansion */
static int btf_func_arg_cnt(const struct btf *btf, const char *func_name)
{
	if (!btf)
		return -1;

	__s32 func_id = btf__find_by_name_kind(btf, func_name, BTF_KIND_FUNC);
	if (func_id < 0)
		return -1;

	const struct btf_type *func = btf__type_by_id(btf, func_id);
	const struct btf_type *proto = btf__type_by_id(btf, func->type);
	if (!proto || !btf_is_func_proto(proto))
		return -1;

	return btf_vlen(proto);
}

/* Get arg count for a BPF program target from its BTF */
static int bpf_prog_func_arg_cnt(const struct utrace_cfg *cfg)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);

	if (bpf_prog_get_info_by_fd(cfg->bpf_prog.prog_fd, &info, &info_len) || !info.btf_id)
		return -1;

	struct btf *btf = btf__load_from_kernel_by_id(info.btf_id);
	if (!btf)
		return -1;

	const struct btf_type *t = btf__type_by_id(btf, cfg->bpf_prog.btf_func_id);
	if (!t || !btf_is_func(t)) {
		btf__free(btf);
		return -1;
	}

	const struct btf_type *proto = btf__type_by_id(btf, t->type);
	int cnt = (proto && btf_is_func_proto(proto)) ? btf_vlen(proto) : -1;
	btf__free(btf);
	return cnt;
}

/* Expand wildcard_args into individual arg params */
static void expand_wildcard_args(struct utrace_cfg *cfg, const struct btf *btf)
{
	int arg_cnt;
	bool has_ret = cfg_is_ret_probe(cfg->type) || cfg_is_native_span(cfg->type);

	if (cfg_is_ret_probe(cfg->type)) {
		/* ret probes only get arg:ret, no positional args */
		arg_cnt = 0;
	} else if (cfg_is_kprobe_type(cfg)) {
		arg_cnt = btf_func_arg_cnt(btf, cfg->kprobe.name);
		if (arg_cnt < 0)
			arg_cnt = 6;
	} else if (cfg_is_bpf_type(cfg)) {
		arg_cnt = bpf_prog_func_arg_cnt(cfg);
		if (arg_cnt < 0)
			arg_cnt = 6;
	} else {
		arg_cnt = 6;
	}

	/* figure out which arg indices are already explicitly defined */
	bool has_arg[MAX_UTRACE_ARGS] = {};
	bool has_arg_ret = false;
	for (int i = 0; i < cfg->param_cnt; i++) {
		if (cfg->params[i].type != UTRACE_PARAM_ARG)
			continue;
		if (cfg->params[i].arg.arg_idx == UTRACE_ARG_RET)
			has_arg_ret = true;
		else if (cfg->params[i].arg.arg_idx < MAX_UTRACE_ARGS)
			has_arg[cfg->params[i].arg.arg_idx] = true;
	}

	/* cap so total args fit in MAX_UTRACE_ARGS */
	int max_args = MAX_UTRACE_ARGS - (has_ret && !has_arg_ret ? 1 : 0);
	if (arg_cnt > max_args)
		arg_cnt = max_args;

	/* count how many new args we actually need to add */
	int add_cnt = 0;
	for (int i = 0; i < arg_cnt; i++)
		if (!has_arg[i])
			add_cnt++;
	if (has_ret && !has_arg_ret)
		add_cnt++;

	cfg->params = realloc(cfg->params, (cfg->param_cnt + add_cnt) * sizeof(*cfg->params));

	int idx = cfg->param_cnt;

	for (int i = 0; i < arg_cnt; i++) {
		if (has_arg[i])
			continue;
		struct utrace_param *p = &cfg->params[idx++];
		memset(p, 0, sizeof(*p));
		p->type = UTRACE_PARAM_ARG;
		p->arg.arg_idx = i;
		p->arg.arg_type = UTRACE_ARG_UNKNOWN;
	}

	if (has_ret && !has_arg_ret) {
		struct utrace_param *p = &cfg->params[idx++];
		memset(p, 0, sizeof(*p));
		p->type = UTRACE_PARAM_ARG;
		p->arg.arg_idx = UTRACE_ARG_RET;
		p->arg.arg_type = UTRACE_ARG_UNKNOWN;
	}

	cfg->param_cnt += add_cnt;
	cfg->wildcard_args = false;
}

/* Check if a cfg (or its inner span cfgs) needs BTF for wildcard expansion or type resolution */
static bool cfg_needs_btf(const struct utrace_cfg *cfg)
{
	if (cfg->type == UTRACE_SPAN)
		return cfg_needs_btf(cfg->span.entry) || cfg_needs_btf(cfg->span.exit);

	if (cfg->wildcard_args && cfg_is_kprobe_type(cfg))
		return true;

	if (!cfg_is_kprobe_type(cfg))
		return false;

	for (int j = 0; j < cfg->param_cnt; j++) {
		if (cfg->params[j].type != UTRACE_PARAM_ARG)
			continue;
		if (cfg->params[j].arg.arg_type == UTRACE_ARG_UNKNOWN || !cfg->params[j].arg.name)
			return true;
	}
	return false;
}

static int param_sort_key(const struct utrace_param *p)
{
	if (p->type == UTRACE_PARAM_ARG)
		return UTRACE_PARAM_ARG + (p->arg.arg_idx == UTRACE_ARG_RET ? 99 : p->arg.arg_idx);
	return p->type;
}

static int cmp_params(const void *a, const void *b)
{
	return param_sort_key(a) - param_sort_key(b);
}

/* Expand wildcards and resolve arg types/names for a single cfg */
static void augment_cfg_args(struct utrace_cfg *cfg, const struct btf *btf)
{
	if (cfg->type == UTRACE_SPAN) {
		augment_cfg_args(cfg->span.entry, btf);
		augment_cfg_args(cfg->span.exit, btf);
		return;
	}

	if (cfg->wildcard_args)
		expand_wildcard_args(cfg, btf);

	/* For BPF probes, load the target program's BTF for type resolution */
	struct btf *bpf_btf = NULL;
	if (cfg_is_bpf_type(cfg)) {
		struct bpf_prog_info info = {};
		__u32 info_len = sizeof(info);
		if (!bpf_prog_get_info_by_fd(cfg->bpf_prog.prog_fd, &info, &info_len) && info.btf_id)
			bpf_btf = btf__load_from_kernel_by_id(info.btf_id);
	}

	for (int j = 0; j < cfg->param_cnt; j++) {
		struct utrace_param *p = &cfg->params[j];

		if (p->type != UTRACE_PARAM_ARG)
			continue;
		if (p->arg.arg_type != UTRACE_ARG_UNKNOWN && p->arg.name)
			continue;

		if (!cfg_is_kprobe_type(cfg) && !cfg_is_bpf_type(cfg)) {
			if (p->arg.arg_type == UTRACE_ARG_UNKNOWN)
				p->arg.arg_type = UTRACE_ARG_U64;
			continue;
		}

		const struct btf *resolve_btf = cfg_is_bpf_type(cfg) ? bpf_btf : btf;
		const char *func_name = cfg_is_bpf_type(cfg) ? cfg->bpf_prog.name : cfg->kprobe.name;

		if (!resolve_btf) {
			if (p->arg.arg_type == UTRACE_ARG_UNKNOWN)
				p->arg.arg_type = UTRACE_ARG_U64;
			continue;
		}

		enum utrace_arg_type arg_type;
		const char *param_name = NULL;
		int err = resolve_btf_arg_type(resolve_btf, func_name,
					       p->arg.arg_idx, &arg_type, &param_name);
		if (err) {
			if (p->arg.arg_type == UTRACE_ARG_UNKNOWN) {
				wprintf("utrace: failed to resolve BTF type for %s arg %d, defaulting to u64\n",
					func_name,
					p->arg.arg_idx == UTRACE_ARG_RET ? -1 : p->arg.arg_idx);
			}
			arg_type = UTRACE_ARG_U64;
		}
		if (p->arg.arg_type == UTRACE_ARG_UNKNOWN)
			p->arg.arg_type = arg_type;
		if (!p->arg.name && param_name)
			p->arg.name = strdup(param_name);
	}

	btf__free(bpf_btf);

	qsort(cfg->params, cfg->param_cnt, sizeof(*cfg->params), cmp_params);
}

static void utrace_augment_args(void)
{
	bool need_btf = false;

	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		if (cfg_needs_btf(&env.utrace_cfgs[i])) {
			need_btf = true;
			break;
		}
	}

	struct btf *btf = NULL;
	if (need_btf) {
		btf = btf__parse("/sys/kernel/btf/vmlinux", NULL);
		if (!btf)
			wprintf("utrace: failed to load kernel BTF, arg types will default to u64\n");
	}

	for (int i = 0; i < env.utrace_cfg_cnt; i++)
		augment_cfg_args(&env.utrace_cfgs[i], btf);

	btf__free(btf);
}

/*
 * Resolve uprobe binary path by scanning /proc/<pid>/maps for executable VMAs.
 * Returns the /proc/<pid>/map_files/ path in attach_path_out (for ELF lookup and
 * uprobe attach) and the human-readable VMA name in display_path_out (for logging
 * and replay).
 */
static int resolve_uprobe_binary(int pid, const char *sym_name,
				 char **attach_path_out, char **display_path_out,
				 unsigned long *offset_out)
{
	__u32 last_dev_major = 0, last_dev_minor = 0;
	__u64 last_inode = 0;
	struct vma_info *vma;

	wprof_for_each(vma, vma, pid, VMA_QUERY_FILE_BACKED_VMA | VMA_QUERY_VMA_EXECUTABLE) {
		if (vma->vma_name[0] != '/')
			continue;
		/* skip duplicate segments of the same binary */
		if (vma->dev_major == last_dev_major && vma->dev_minor == last_dev_minor && vma->inode == last_inode)
			continue;
		last_dev_major = vma->dev_major;
		last_dev_minor = vma->dev_minor;
		last_inode = vma->inode;

		/* Use /proc/<pid>/map_files/ to access binary through the process's mount namespace */
		char map_file[128];
		snprintf(map_file, sizeof(map_file), "/proc/%d/map_files/%llx-%llx",
			 pid, (unsigned long long)vma->vma_start, (unsigned long long)vma->vma_end);

		unsigned long offset = 0;
		if (elf_find_syms(map_file, STT_FUNC, &sym_name, &offset, 1))
			continue;

		*attach_path_out = strdup(map_file);
		const char *name = vma->vma_name;
		if (str_has_suffix(name, " (deleted)"))
			*display_path_out = strndup(name, strlen(name) - 10);
		else
			*display_path_out = strdup(name);
		*offset_out = offset;
		return 0;
	}

	return -ENOENT;
}

static int find_bpf_prog_by_name(const char *name, int *prog_fd_out, __u32 *btf_func_id_out)
{
	__u32 id = 0;
	int err, prog_fd = -1;

	while (!bpf_prog_get_next_id(id, &id)) {
		struct bpf_prog_info info = {};
		__u32 info_len = sizeof(info);

		prog_fd = bpf_prog_get_fd_by_id(id);
		if (prog_fd < 0)
			continue;

		/* first call to get func_info_cnt */
		err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
		if (err || !info.btf_id || !info.nr_func_info) {
			close(prog_fd);
			continue;
		}

		/* allocate and fetch func_info */
		__u32 func_info_cnt = info.nr_func_info;
		__u32 func_info_rec_size = info.func_info_rec_size;
		void *func_info_buf = calloc(func_info_cnt, func_info_rec_size);

		memset(&info, 0, sizeof(info));
		info_len = sizeof(info);
		info.func_info = (unsigned long long)(uintptr_t)func_info_buf;
		info.nr_func_info = func_info_cnt;
		info.func_info_rec_size = func_info_rec_size;

		err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
		if (err) {
			free(func_info_buf);
			close(prog_fd);
			continue;
		}

		struct btf *btf = btf__load_from_kernel_by_id(info.btf_id);
		if (!btf) {
			free(func_info_buf);
			close(prog_fd);
			continue;
		}

		bool found = false;
		for (__u32 i = 0; i < info.nr_func_info; i++) {
			struct bpf_func_info *fi = func_info_buf + i * func_info_rec_size;
			const struct btf_type *t = btf__type_by_id(btf, fi->type_id);
			if (!t)
				continue;
			const char *func_name = btf__name_by_offset(btf, t->name_off);
			if (!func_name)
				continue;

			if (strcmp(func_name, name) == 0) {
				*prog_fd_out = prog_fd;
				*btf_func_id_out = fi->type_id;
				found = true;
				break;
			}
		}

		btf__free(btf);
		free(func_info_buf);

		if (found)
			return 0;

		close(prog_fd);
	}

	return -ENOENT;
}

int utrace_setup_bpf_targets(struct wprof_bpf *skel)
{
	bool need_fentry = false, need_fexit = false;
	int first_prog_fd = -1;
	const char *first_func_name = NULL;

	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		struct utrace_cfg *cfg = &env.utrace_cfgs[i];

		if (!cfg_is_bpf_type(cfg))
			continue;

		int err = find_bpf_prog_by_name(cfg->bpf_prog.name,
						&cfg->bpf_prog.prog_fd,
						&cfg->bpf_prog.btf_func_id);
		if (err) {
			eprintf("utrace: failed to find BPF program '%s': %d\n", cfg->bpf_prog.name, err);
			return err;
		}

		if (first_prog_fd < 0) {
			first_prog_fd = cfg->bpf_prog.prog_fd;
			first_func_name = cfg->bpf_prog.name;
		}

		switch (cfg->type) {
		case UTRACE_BPF_PROBE:
			need_fentry = true;
			break;
		case UTRACE_BPF_RETPROBE:
			need_fexit = true;
			break;
		case UTRACE_BPF_SPAN:
			need_fentry = true;
			need_fexit = true;
			break;
		default:
			break;
		}
	}

	if (first_prog_fd < 0)
		return 0;

	/*
	 * Set attach target on template programs so they get prepared properly.
	 * The actual target is overridden per-clone, so any valid target works here.
	 * Autoload is enabled so bpf_object__prepare() processes them, but must be
	 * disabled again before bpf_object__load() to prevent loading into kernel
	 * (templates are only used as clone sources).
	 */
	if (need_fentry) {
		int err = bpf_program__set_attach_target(skel->progs.utrace_bpf_entry,
							 first_prog_fd, first_func_name);
		if (err) {
			eprintf("utrace: failed to set fentry attach target: %d\n", err);
			return err;
		}
		bpf_program__set_autoload(skel->progs.utrace_bpf_entry, true);
	}
	if (need_fexit) {
		int err = bpf_program__set_attach_target(skel->progs.utrace_bpf_exit,
							 first_prog_fd, first_func_name);
		if (err) {
			eprintf("utrace: failed to set fexit attach target: %d\n", err);
			return err;
		}
		bpf_program__set_autoload(skel->progs.utrace_bpf_exit, true);
	}

	return 0;
}

/*
 * Called after bpf_object__prepare() but before bpf_object__load().
 * Disables autoload on BPF fentry/fexit templates so they are prepared
 * (for cloning) but not loaded into the kernel.
 */
void utrace_disable_bpf_templates(struct wprof_bpf *skel)
{
	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		enum utrace_type t = env.utrace_cfgs[i].type;

		if (t == UTRACE_BPF_PROBE || t == UTRACE_BPF_SPAN) {
			bpf_program__set_autoload(skel->progs.utrace_bpf_entry, false);
			break;
		}
	}
	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		enum utrace_type t = env.utrace_cfgs[i].type;

		if (t == UTRACE_BPF_RETPROBE || t == UTRACE_BPF_SPAN) {
			bpf_program__set_autoload(skel->progs.utrace_bpf_exit, false);
			break;
		}
	}
}

int utrace_setup(struct bpf_state *st, struct wprof_bpf *skel)
{
	int err;
	int map_fd = bpf_map__fd(skel->maps.utrace_probe_cfgs);
	u32 map_idx = 0;

	utrace_augment_args();

	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		const struct utrace_cfg *cfg = &env.utrace_cfgs[i];
		struct utrace_probe_cfg pcfg;
		const char *binary_path;
		unsigned long sym_offset = 0;
		int pid;
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
		LIBBPF_OPTS(bpf_kprobe_opts, kprobe_opts);
		struct bpf_link *link;

		switch (cfg->type) {
		case UTRACE_UPROBE:
		case UTRACE_URETPROBE:
		case UTRACE_UPROBE_SPAN: {
			char *resolved_path = NULL;
			binary_path = cfg_binary_path(cfg);
			pid = cfg_pid(cfg);

			if (binary_path) {
				const char *sym_name = cfg->uprobe.name;
				err = elf_find_syms(binary_path, STT_FUNC, &sym_name, &sym_offset, 1);
				if (err < 0) {
					eprintf("utrace: failed to resolve symbol '%s' in '%s': %d\n",
						cfg->uprobe.name, binary_path, err);
					return err;
				}
				sym_offset += cfg->uprobe.off;
			} else if (pid >= 0) {
				char *display_path = NULL;
				err = resolve_uprobe_binary(pid, cfg->uprobe.name, &resolved_path, &display_path, &sym_offset);
				if (err) {
					eprintf("utrace: failed to find symbol '%s' in any binary of PID %d: %d\n",
						cfg->uprobe.name, pid, err);
					return err;
				}
				binary_path = resolved_path;
				cfg_set_binary_path(&env.utrace_cfgs[i], display_path);
				sym_offset += cfg->uprobe.off;
			} else {
				eprintf("utrace: uprobe '%s' requires a binary path (path:) or process (pid:)\n", cfg->uprobe.name);
				return -EINVAL;
			}

			if (cfg->type == UTRACE_UPROBE_SPAN) {
				/* Entry half */
				fill_probe_cfg(&pcfg, cfg, i, UTRACE_ENTRY, false);
				err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
				if (err)
					return err;

				uprobe_opts.bpf_cookie = map_idx;
				uprobe_opts.retprobe = false;
				link = bpf_program__attach_uprobe_opts(skel->progs.utrace_uprobe, pid, binary_path, sym_offset, &uprobe_opts);
				if (!link) {
					err = -errno;
					eprintf("utrace: failed to attach uprobe to '%s' in '%s': %d\n",
						cfg->uprobe.name, binary_path, err);
					return err;
				}
				err = add_link(st, link);
				if (err)
					return err;
				map_idx++;

				/* Exit half */
				fill_probe_cfg(&pcfg, cfg, i, UTRACE_EXIT, true);
				err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
				if (err)
					return err;

				LIBBPF_OPTS(bpf_uprobe_opts, ret_opts);
				ret_opts.bpf_cookie = map_idx;
				ret_opts.retprobe = true;
				link = bpf_program__attach_uprobe_opts(skel->progs.utrace_uretprobe, pid, binary_path, sym_offset, &ret_opts);
				if (!link) {
					err = -errno;
					eprintf("utrace: failed to attach uretprobe to '%s' in '%s': %d\n",
						cfg->uprobe.name, binary_path, err);
					return err;
				}
				err = add_link(st, link);
				if (err)
					return err;
				map_idx++;
			} else {
				fill_probe_cfg(&pcfg, cfg, i, UTRACE_INSTANT, false);
				err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
				if (err) {
					eprintf("utrace: failed to update probe cfg map: %d\n", err);
					return err;
				}

				uprobe_opts.bpf_cookie = map_idx;
				uprobe_opts.retprobe = (cfg->type == UTRACE_URETPROBE);
				struct bpf_program *prog = cfg->type == UTRACE_URETPROBE
					? skel->progs.utrace_uretprobe
					: skel->progs.utrace_uprobe;
				link = bpf_program__attach_uprobe_opts(prog, pid, binary_path, sym_offset, &uprobe_opts);
				if (!link) {
					err = -errno;
					eprintf("utrace: failed to attach %s to '%s' in '%s': %d\n",
						cfg->type == UTRACE_URETPROBE ? "uretprobe" : "uprobe",
						cfg->uprobe.name, binary_path, err);
					return err;
				}
				err = add_link(st, link);
				if (err)
					return err;
				map_idx++;
			}
			free(resolved_path);
			break;
		}
		case UTRACE_KPROBE:
		case UTRACE_KRETPROBE: {
			fill_probe_cfg(&pcfg, cfg, i, UTRACE_INSTANT, false);
			err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
			if (err) {
				eprintf("utrace: failed to update probe cfg map: %d\n", err);
				return err;
			}

			kprobe_opts.bpf_cookie = map_idx;
			kprobe_opts.retprobe = (cfg->type == UTRACE_KRETPROBE);
			struct bpf_program *kprog = cfg->type == UTRACE_KRETPROBE
				? skel->progs.utrace_kretprobe
				: skel->progs.utrace_kprobe;
			link = bpf_program__attach_kprobe_opts(kprog, cfg->kprobe.name, &kprobe_opts);
			if (!link) {
				err = -errno;
				eprintf("utrace: failed to attach %s to '%s': %d\n",
					cfg->type == UTRACE_KRETPROBE ? "kretprobe" : "kprobe",
					cfg->kprobe.name, err);
				return err;
			}
			err = add_link(st, link);
			if (err)
				return err;
			map_idx++;
			break;
		}
		case UTRACE_KPROBE_SPAN: {
			/* Entry half */
			fill_probe_cfg(&pcfg, cfg, i, UTRACE_ENTRY, false);
			err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
			if (err)
				return err;

			kprobe_opts.bpf_cookie = map_idx;
			kprobe_opts.retprobe = false;
			link = bpf_program__attach_kprobe_opts(skel->progs.utrace_kprobe, cfg->kprobe.name, &kprobe_opts);
			if (!link) {
				err = -errno;
				eprintf("utrace: failed to attach kprobe span entry to '%s': %d\n", cfg->kprobe.name, err);
				return err;
			}
			err = add_link(st, link);
			if (err)
				return err;
			map_idx++;

			/* Exit half */
			fill_probe_cfg(&pcfg, cfg, i, UTRACE_EXIT, true);
			err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
			if (err)
				return err;

			LIBBPF_OPTS(bpf_kprobe_opts, kret_opts);
			kret_opts.bpf_cookie = map_idx;
			kret_opts.retprobe = true;
			link = bpf_program__attach_kprobe_opts(skel->progs.utrace_kretprobe, cfg->kprobe.name, &kret_opts);
			if (!link) {
				err = -errno;
				eprintf("utrace: failed to attach kprobe span exit to '%s': %d\n", cfg->kprobe.name, err);
				return err;
			}
			err = add_link(st, link);
			if (err)
				return err;
			map_idx++;
			break;
		}
		case UTRACE_BPF_PROBE:
		case UTRACE_BPF_RETPROBE: {
			bool is_exit = (cfg->type == UTRACE_BPF_RETPROBE);
			fill_probe_cfg(&pcfg, cfg, i, UTRACE_INSTANT, false);
			err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
			if (err)
				return err;

			struct bpf_program *tmpl = is_exit ? skel->progs.utrace_bpf_exit : skel->progs.utrace_bpf_entry;
			LIBBPF_OPTS(bpf_prog_load_opts, clone_opts);
			clone_opts.attach_prog_fd = cfg->bpf_prog.prog_fd;
			clone_opts.attach_btf_id = cfg->bpf_prog.btf_func_id;

			int clone_fd = bpf_program__clone(tmpl, &clone_opts);
			if (clone_fd < 0) {
				eprintf("utrace: failed to clone %s for BPF prog '%s': %d\n",
					is_exit ? "fexit" : "fentry", cfg->bpf_prog.name, clone_fd);
				return clone_fd;
			}

			LIBBPF_OPTS(bpf_link_create_opts, lcopts);
			lcopts.tracing.cookie = map_idx;
			int link_fd = bpf_link_create(clone_fd, 0,
						      is_exit ? BPF_TRACE_FEXIT : BPF_TRACE_FENTRY, &lcopts);
			close(clone_fd);
			if (link_fd < 0) {
				err = -errno;
				eprintf("utrace: failed to attach %s to BPF prog '%s': %d\n",
					is_exit ? "fexit" : "fentry", cfg->bpf_prog.name, err);
				return err;
			}
			err = add_link_fd(st, link_fd);
			if (err)
				return err;
			map_idx++;
			break;
		}
		case UTRACE_BPF_SPAN: {
			/* Entry half (fentry) */
			fill_probe_cfg(&pcfg, cfg, i, UTRACE_ENTRY, false);
			err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
			if (err)
				return err;

			LIBBPF_OPTS(bpf_prog_load_opts, entry_clone_opts);
			entry_clone_opts.attach_prog_fd = cfg->bpf_prog.prog_fd;
			entry_clone_opts.attach_btf_id = cfg->bpf_prog.btf_func_id;

			int entry_fd = bpf_program__clone(skel->progs.utrace_bpf_entry, &entry_clone_opts);
			if (entry_fd < 0) {
				eprintf("utrace: failed to clone fentry for BPF prog '%s': %d\n", cfg->bpf_prog.name, entry_fd);
				return entry_fd;
			}

			LIBBPF_OPTS(bpf_link_create_opts, entry_lcopts);
			entry_lcopts.tracing.cookie = map_idx;
			int entry_link_fd = bpf_link_create(entry_fd, 0, BPF_TRACE_FENTRY, &entry_lcopts);
			close(entry_fd);
			if (entry_link_fd < 0) {
				err = -errno;
				eprintf("utrace: failed to attach fentry to BPF prog '%s': %d\n", cfg->bpf_prog.name, err);
				return err;
			}
			err = add_link_fd(st, entry_link_fd);
			if (err)
				return err;
			map_idx++;

			/* Exit half (fexit) */
			fill_probe_cfg(&pcfg, cfg, i, UTRACE_EXIT, true);
			err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
			if (err)
				return err;

			LIBBPF_OPTS(bpf_prog_load_opts, exit_clone_opts);
			exit_clone_opts.attach_prog_fd = cfg->bpf_prog.prog_fd;
			exit_clone_opts.attach_btf_id = cfg->bpf_prog.btf_func_id;

			int exit_fd = bpf_program__clone(skel->progs.utrace_bpf_exit, &exit_clone_opts);
			if (exit_fd < 0) {
				eprintf("utrace: failed to clone fexit for BPF prog '%s': %d\n", cfg->bpf_prog.name, exit_fd);
				return exit_fd;
			}

			LIBBPF_OPTS(bpf_link_create_opts, exit_lcopts);
			exit_lcopts.tracing.cookie = map_idx;
			int exit_link_fd = bpf_link_create(exit_fd, 0, BPF_TRACE_FEXIT, &exit_lcopts);
			close(exit_fd);
			if (exit_link_fd < 0) {
				err = -errno;
				eprintf("utrace: failed to attach fexit to BPF prog '%s': %d\n", cfg->bpf_prog.name, err);
				return err;
			}
			err = add_link_fd(st, exit_link_fd);
			if (err)
				return err;
			map_idx++;
			break;
		}
		default:
			eprintf("utrace: probe type %d not yet supported\n", cfg->type);
			return -EOPNOTSUPP;
		}
	}

	return 0;
}
