// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

#include "utils.h"
#include "env.h"
#include "utrace.h"
#include "utrace_cfg.h"
#include "elf_utils.h"
#include "bpf_utils.h"
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

/* Fill a utrace_probe_cfg from utrace_cfg params, filtering args by is_exit */
static void fill_probe_cfg(struct utrace_probe_cfg *pcfg, const struct utrace_cfg *cfg,
			   int utrace_id, enum utrace_event_type event_type, bool is_exit, bool is_kernel)
{
	memset(pcfg, 0, sizeof(*pcfg));
	pcfg->utrace_id = utrace_id;
	pcfg->event_type = event_type;
	pcfg->is_kernel = is_kernel;

	int arg_idx = 0;
	for (int i = 0; i < cfg->param_cnt && arg_idx < MAX_UTRACE_ARGS; i++) {
		const struct utrace_param *p = &cfg->params[i];

		if (p->type == UTRACE_PARAM_CAPTURE_STACK)
			pcfg->capture_stack = 1;
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

int utrace_setup(struct bpf_state *st, struct wprof_bpf *skel)
{
	int err;
	int map_fd = bpf_map__fd(skel->maps.utrace_probe_cfgs);
	u32 map_idx = 0;

	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		const struct utrace_cfg *cfg = &env.utrace_cfgs[i];
		struct utrace_probe_cfg pcfg;
		const char *binary_path;
		long sym_offset = 0;
		int pid;
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
		LIBBPF_OPTS(bpf_kprobe_opts, kprobe_opts);
		struct bpf_link *link;

		switch (cfg->type) {
		case UTRACE_UPROBE:
		case UTRACE_URETPROBE: {
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
			} else {
				eprintf("utrace: uprobe '%s' requires a binary path (path: param)\n", cfg->uprobe.name);
				return -EINVAL;
			}

			fill_probe_cfg(&pcfg, cfg, i,
				       cfg->type == UTRACE_UPROBE ? UTRACE_INSTANT : UTRACE_INSTANT,
				       false, false);
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
			break;
		}
		case UTRACE_KPROBE:
		case UTRACE_KRETPROBE: {
			fill_probe_cfg(&pcfg, cfg, i, UTRACE_INSTANT, false, true);
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
		case UTRACE_UPROBE_SPAN: {
			binary_path = cfg_binary_path(cfg);
			pid = cfg_pid(cfg);

			if (!binary_path) {
				eprintf("utrace: uprobe span '%s' requires a binary path (path: param)\n", cfg->uprobe.name);
				return -EINVAL;
			}

			const char *sym_name = cfg->uprobe.name;
			err = elf_find_syms(binary_path, STT_FUNC, &sym_name, &sym_offset, 1);
			if (err < 0) {
				eprintf("utrace: failed to resolve symbol '%s' in '%s': %d\n",
					cfg->uprobe.name, binary_path, err);
				return err;
			}
			sym_offset += cfg->uprobe.off;

			/* Entry half */
			fill_probe_cfg(&pcfg, cfg, i, UTRACE_ENTRY, false, false);
			err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
			if (err)
				return err;

			uprobe_opts.bpf_cookie = map_idx;
			uprobe_opts.retprobe = false;
			link = bpf_program__attach_uprobe_opts(skel->progs.utrace_uprobe, pid, binary_path, sym_offset, &uprobe_opts);
			if (!link) {
				err = -errno;
				eprintf("utrace: failed to attach uprobe span entry to '%s' in '%s': %d\n",
					cfg->uprobe.name, binary_path, err);
				return err;
			}
			err = add_link(st, link);
			if (err)
				return err;
			map_idx++;

			/* Exit half */
			fill_probe_cfg(&pcfg, cfg, i, UTRACE_EXIT, true, false);
			err = bpf_map_update_elem(map_fd, &map_idx, &pcfg, BPF_ANY);
			if (err)
				return err;

			LIBBPF_OPTS(bpf_uprobe_opts, ret_opts);
			ret_opts.bpf_cookie = map_idx;
			ret_opts.retprobe = true;
			link = bpf_program__attach_uprobe_opts(skel->progs.utrace_uretprobe, pid, binary_path, sym_offset, &ret_opts);
			if (!link) {
				err = -errno;
				eprintf("utrace: failed to attach uprobe span exit to '%s' in '%s': %d\n",
					cfg->uprobe.name, binary_path, err);
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
			fill_probe_cfg(&pcfg, cfg, i, UTRACE_ENTRY, false, true);
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
			fill_probe_cfg(&pcfg, cfg, i, UTRACE_EXIT, true, true);
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
		default:
			eprintf("utrace: probe type %d not yet supported\n", cfg->type);
			return -EOPNOTSUPP;
		}
	}

	return 0;
}
