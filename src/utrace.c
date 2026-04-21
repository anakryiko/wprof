// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include "bpf/libbpf.h"
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

/* Get arg count for a BPF program target using its pre-loaded BTF */
static int bpf_prog_func_arg_cnt(const struct utrace_cfg *cfg)
{
	if (!cfg->bpf_prog.btf)
		return -ENOENT;

	const struct btf_type *t = btf__type_by_id(cfg->bpf_prog.btf, cfg->bpf_prog.btf_func_id);
	if (!t || !btf_is_func(t))
		return -ESRCH;

	const struct btf_type *proto = btf__type_by_id(cfg->bpf_prog.btf, t->type);
	if (!proto || !btf_is_func_proto(proto))
		return -EINVAL;

	return btf_vlen(proto);
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

		const struct btf *resolve_btf = cfg_is_bpf_type(cfg) ? cfg->bpf_prog.btf : btf;
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

/*
 * Resolve a uprobe cfg's attach target: either use its explicit path: to find
 * the symbol, or discover the binary via the process's /proc/<pid>/maps. Fills
 * cfg->uprobe.attach_path (malloc'd) and cfg->uprobe.attach_off with the final
 * path and total offset so attach time is a straight lookup.
 */
static int resolve_uprobe_cfg(struct utrace_cfg *cfg)
{
	const char *binary_path = cfg_binary_path(cfg);
	int pid = cfg_pid(cfg);
	unsigned long sym_offset = 0;

	if (binary_path) {
		const char *sym_name = cfg->uprobe.name;
		int err = elf_find_syms(binary_path, STT_FUNC, &sym_name, &sym_offset, 1);
		if (err < 0) {
			eprintf("utrace: failed to resolve symbol '%s' in '%s': %d\n",
				cfg->uprobe.name, binary_path, err);
			return err;
		}
		cfg->uprobe.attach_path = binary_path;
		cfg->uprobe.display_path = binary_path;
	} else if (pid >= 0) {
		char *attach_path = NULL, *display_path = NULL;
		int err = resolve_uprobe_binary(pid, cfg->uprobe.name,
						&attach_path, &display_path, &sym_offset);
		if (err) {
			eprintf("utrace: failed to find symbol '%s' in any binary of PID %d: %d\n",
				cfg->uprobe.name, pid, err);
			return err;
		}
		cfg->uprobe.attach_path = attach_path;
		cfg->uprobe.display_path = display_path;
		cfg_set_binary_path(cfg, display_path);
	} else {
		eprintf("utrace: uprobe '%s' requires a binary path (path:) or process (pid:)\n", cfg->uprobe.name);
		return -EINVAL;
	}

	cfg->uprobe.attach_off = sym_offset + cfg->uprobe.off;
	return 0;
}

static int find_bpf_prog_by_name(const char *name, int *prog_fd_out,
				 __u32 *btf_func_id_out, struct btf **btf_out)
{
	__u32 id = 0;
	int err = -ENOENT, prog_fd = -1;
	int match_prog_fd = -1, match_btf_func_id = 0;
	struct btf *match_btf = NULL;
	void *func_info_buf = NULL;
	struct btf *btf = NULL;
	bool found = false;

	while (!bpf_prog_get_next_id(id, &id)) {
		struct bpf_prog_info info;
		__u32 info_len = sizeof(info);

		func_info_buf = NULL;
		btf = NULL;
		found = false;

		memset(&info, 0, sizeof(info));

		prog_fd = bpf_prog_get_fd_by_id(id);
		if (prog_fd < 0)
			continue;

		/* first call to get func_info_cnt */
		err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
		if (err || info.btf_id == 0 || info.nr_func_info == 0)
			goto next;

		/* allocate and fetch func_info */
		__u32 func_info_cnt = info.nr_func_info;
		__u32 func_info_rec_size = info.func_info_rec_size;
		func_info_buf = calloc(func_info_cnt, func_info_rec_size);

		memset(&info, 0, sizeof(info));
		info_len = sizeof(info);
		info.func_info = (unsigned long long)(uintptr_t)func_info_buf;
		info.nr_func_info = func_info_cnt;
		info.func_info_rec_size = func_info_rec_size;

		err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
		if (err)
			goto next;

		btf = btf__load_from_kernel_by_id(info.btf_id);
		if (!btf)
			goto next;

		for (__u32 i = 0; i < info.nr_func_info; i++) {
			struct bpf_func_info *fi = func_info_buf + i * func_info_rec_size;
			const struct btf_type *t = btf__type_by_id(btf, fi->type_id);
			if (!t)
				continue;
			const char *func_name = btf__name_by_offset(btf, t->name_off);
			if (!func_name)
				continue;

			if (strcmp(func_name, name) != 0)
				continue;

			if (match_prog_fd >= 0) {
				eprintf("utrace: BPF function '%s' is ambiguous, can't proceed!\n", name);
				err = -EEXIST;
				goto out;
			}

			match_prog_fd = prog_fd;
			match_btf_func_id = fi->type_id;
			match_btf = btf;
			found = true;
			break;
		}
next:
		free(func_info_buf);
		if (!found) {
			btf__free(btf);
			close(prog_fd);
		}
	}

	if (match_prog_fd >= 0) {
		*prog_fd_out = match_prog_fd;
		*btf_func_id_out = match_btf_func_id;
		*btf_out = match_btf;
		return 0;
	}

	return -ENOENT;

out:
	free(func_info_buf);
	btf__free(btf);
	if (prog_fd >= 0)
		close(prog_fd);
	btf__free(match_btf);
	if (match_prog_fd >= 0)
		close(match_prog_fd);
	return err;
}

int utrace_setup(struct wprof_bpf *skel)
{
	bool need_fentry = false, need_fexit = false;
	int first_prog_fd = -1;
	const char *first_func_name = NULL;
	int map_cnt = 0;

	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		struct utrace_cfg *cfg = &env.utrace_cfgs[i];
		int err;

		map_cnt += cfg_is_span(cfg) ? 2 : 1;

		switch (cfg->type) {
		case UTRACE_UPROBE:
		case UTRACE_URETPROBE:
		case UTRACE_UPROBE_SPAN:
			if (cfg_needs_uprobe(cfg))
				bpf_program__set_autoload(skel->progs.utrace_uprobe, true);
			if (cfg_needs_uretprobe(cfg))
				bpf_program__set_autoload(skel->progs.utrace_uretprobe, true);
			err = resolve_uprobe_cfg(cfg);
			if (err)
				return err;
			break;
		case UTRACE_KPROBE:
		case UTRACE_KRETPROBE:
		case UTRACE_KPROBE_SPAN:
			if (cfg_needs_kprobe(cfg))
				bpf_program__set_autoload(skel->progs.utrace_kprobe, true);
			if (cfg_needs_kretprobe(cfg))
				bpf_program__set_autoload(skel->progs.utrace_kretprobe, true);
			break;
		case UTRACE_BPF_PROBE:
		case UTRACE_BPF_RETPROBE:
		case UTRACE_BPF_SPAN:
			err = find_bpf_prog_by_name(cfg->bpf_prog.name,
						    &cfg->bpf_prog.prog_fd,
						    &cfg->bpf_prog.btf_func_id,
						    &cfg->bpf_prog.btf);
			if (err) {
				eprintf("utrace: failed to find BPF program '%s': %d\n", cfg->bpf_prog.name, err);
				return err;
			}
			if (first_prog_fd < 0) {
				first_prog_fd = cfg->bpf_prog.prog_fd;
				first_func_name = cfg->bpf_prog.name;
			}
			if (cfg->type == UTRACE_BPF_PROBE || cfg->type == UTRACE_BPF_SPAN)
				need_fentry = true;
			if (cfg->type == UTRACE_BPF_RETPROBE || cfg->type == UTRACE_BPF_SPAN)
				need_fexit = true;
			break;
		default:
			break;
		}
	}
	bpf_map__set_autocreate(skel->maps.utrace_probe_cfgs, true);
	bpf_map__set_max_entries(skel->maps.utrace_probe_cfgs, map_cnt);

	if (first_prog_fd >= 0) {
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
	}

	utrace_augment_args();

	/* Free BPF program BTFs — only needed for arg resolution above */
	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		if (cfg_is_bpf_type(&env.utrace_cfgs[i])) {
			btf__free(env.utrace_cfgs[i].bpf_prog.btf);
			env.utrace_cfgs[i].bpf_prog.btf = NULL;
		}
	}

	return 0;
}

int utrace_attach(struct bpf_state *st, struct wprof_bpf *skel)
{
	int err;
	int map_fd = bpf_map__fd(skel->maps.utrace_probe_cfgs);
	u32 map_idx = 0;

	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		const struct utrace_cfg *cfg = &env.utrace_cfgs[i];
		struct utrace_probe_cfg pcfg;
		struct bpf_link *link;

		switch (cfg->type) {
		case UTRACE_UPROBE:
		case UTRACE_URETPROBE:
		case UTRACE_UPROBE_SPAN: {
			const char *attach_path = cfg->uprobe.attach_path;
			const char *display_path = cfg->uprobe.display_path;
			unsigned long attach_off = cfg->uprobe.attach_off;
			int pid = cfg_pid(cfg);

			if (cfg->type == UTRACE_UPROBE || cfg->type == UTRACE_UPROBE_SPAN) {
				fill_probe_cfg(&pcfg, cfg, i, cfg_is_span(cfg) ? UTRACE_ENTRY : UTRACE_INSTANT, false);
				err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
				if (err)
					return err;

				LIBBPF_OPTS(bpf_uprobe_opts, opts, .bpf_cookie = map_idx);
				link = bpf_program__attach_uprobe_opts(skel->progs.utrace_uprobe, pid, attach_path, attach_off, &opts);
				if (!link) {
					err = -errno;
					eprintf("utrace: failed to attach uprobe to '%s' in '%s': %d\n",
						cfg->uprobe.name, display_path, err);
					return err;
				}
				err = add_link(st, link);
				if (err)
					return err;
				map_idx++;
			}
			if (cfg->type == UTRACE_URETPROBE || cfg->type == UTRACE_UPROBE_SPAN) {
				fill_probe_cfg(&pcfg, cfg, i, cfg_is_span(cfg) ? UTRACE_EXIT : UTRACE_INSTANT, cfg_is_span(cfg));
				err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
				if (err)
					return err;

				LIBBPF_OPTS(bpf_uprobe_opts, opts, .bpf_cookie = map_idx, .retprobe = true);
				link = bpf_program__attach_uprobe_opts(skel->progs.utrace_uretprobe, pid, attach_path, attach_off, &opts);
				if (!link) {
					err = -errno;
					eprintf("utrace: failed to attach uretprobe to '%s' in '%s': %d\n",
						cfg->uprobe.name, display_path, err);
					return err;
				}
				err = add_link(st, link);
				if (err)
					return err;
				map_idx++;
			}
			break;
		}
		case UTRACE_KPROBE:
		case UTRACE_KRETPROBE:
		case UTRACE_KPROBE_SPAN: {
			if (cfg->type == UTRACE_KPROBE || cfg->type == UTRACE_KPROBE_SPAN) {
				fill_probe_cfg(&pcfg, cfg, i, cfg_is_span(cfg) ? UTRACE_ENTRY : UTRACE_INSTANT, false);
				err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
				if (err)
					return err;

				LIBBPF_OPTS(bpf_kprobe_opts, opts, .bpf_cookie = map_idx);
				link = bpf_program__attach_kprobe_opts(skel->progs.utrace_kprobe, cfg->kprobe.name, &opts);
				if (!link) {
					err = -errno;
					eprintf("utrace: failed to attach kprobe to '%s': %d\n", cfg->kprobe.name, err);
					return err;
				}
				err = add_link(st, link);
				if (err)
					return err;
				map_idx++;
			}
			if (cfg->type == UTRACE_KRETPROBE || cfg->type == UTRACE_KPROBE_SPAN) {
				fill_probe_cfg(&pcfg, cfg, i, cfg_is_span(cfg) ? UTRACE_EXIT : UTRACE_INSTANT, cfg_is_span(cfg));
				err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
				if (err)
					return err;

				LIBBPF_OPTS(bpf_kprobe_opts, opts, .bpf_cookie = map_idx, .retprobe = true);
				link = bpf_program__attach_kprobe_opts(skel->progs.utrace_kretprobe, cfg->kprobe.name, &opts);
				if (!link) {
					err = -errno;
					eprintf("utrace: failed to attach kretprobe to '%s': %d\n", cfg->kprobe.name, err);
					return err;
				}
				err = add_link(st, link);
				if (err)
					return err;
				map_idx++;
			}
			break;
		}
		case UTRACE_BPF_PROBE:
		case UTRACE_BPF_RETPROBE:
		case UTRACE_BPF_SPAN: {
			if (cfg->type == UTRACE_BPF_PROBE || cfg->type == UTRACE_BPF_SPAN) {
				fill_probe_cfg(&pcfg, cfg, i, cfg_is_span(cfg) ? UTRACE_ENTRY : UTRACE_INSTANT, false);
				err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
				if (err)
					return err;

				LIBBPF_OPTS(bpf_prog_load_opts, clone_opts,
					    .attach_prog_fd = cfg->bpf_prog.prog_fd,
					    .attach_btf_id = cfg->bpf_prog.btf_func_id);
				int clone_fd = bpf_program__clone(skel->progs.utrace_bpf_entry, &clone_opts);
				if (clone_fd < 0) {
					eprintf("utrace: failed to clone fentry for BPF prog '%s': %d\n", cfg->bpf_prog.name, clone_fd);
					return clone_fd;
				}

				LIBBPF_OPTS(bpf_link_create_opts, link_opts, .tracing.cookie = map_idx);
				int link_fd = bpf_link_create(clone_fd, 0, BPF_TRACE_FENTRY, &link_opts);
				close(clone_fd);
				if (link_fd < 0) {
					err = -errno;
					eprintf("utrace: failed to attach fentry to BPF prog '%s': %d\n", cfg->bpf_prog.name, err);
					return err;
				}
				err = add_link_fd(st, link_fd);
				if (err)
					return err;
				map_idx++;
			}
			if (cfg->type == UTRACE_BPF_RETPROBE || cfg->type == UTRACE_BPF_SPAN) {
				fill_probe_cfg(&pcfg, cfg, i, cfg_is_span(cfg) ? UTRACE_EXIT : UTRACE_INSTANT, cfg_is_span(cfg));
				err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
				if (err)
					return err;

				LIBBPF_OPTS(bpf_prog_load_opts, clone_opts,
					    .attach_prog_fd = cfg->bpf_prog.prog_fd,
					    .attach_btf_id = cfg->bpf_prog.btf_func_id);
				int clone_fd = bpf_program__clone(skel->progs.utrace_bpf_exit, &clone_opts);
				if (clone_fd < 0) {
					eprintf("utrace: failed to clone fexit for BPF prog '%s': %d\n", cfg->bpf_prog.name, clone_fd);
					return clone_fd;
				}

				LIBBPF_OPTS(bpf_link_create_opts, link_opts, .tracing.cookie = map_idx);
				int link_fd = bpf_link_create(clone_fd, 0, BPF_TRACE_FEXIT, &link_opts);
				close(clone_fd);
				if (link_fd < 0) {
					err = -errno;
					eprintf("utrace: failed to attach fexit to BPF prog '%s': %d\n", cfg->bpf_prog.name, err);
					return err;
				}
				err = add_link_fd(st, link_fd);
				if (err)
					return err;
				map_idx++;
			}
			break;
		}
		default:
			eprintf("utrace: probe type %d not yet supported\n", cfg->type);
			return -EOPNOTSUPP;
		}
	}

	return 0;
}
