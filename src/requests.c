// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "requests.h"
#include "proc.h"
#include "env.h"
#include "bpf_utils.h"
#include "wprof.skel.h"
#include "data.h"
#include "wevent.h"

static int add_uprobe_binary(u64 dev, u64 inode, const char *path, const char *attach_path)
{
	struct uprobe_binary *binary, key = {};

	if (!env.req_binaries) {
		env.req_binaries = hashmap__new(uprobe_binary_hash_fn, uprobe_binary_equal_fn, NULL);
		if (!env.req_binaries)
			return -ENOMEM;
	}

	key.dev = dev;
	key.inode = inode;
	key.path = strdup(path);
	if (!key.path)
		return -ENOMEM;

	if (hashmap__find(env.req_binaries, &key, NULL)) {
		free(key.path);
		return 0;
	}

	binary = calloc(1, sizeof(*binary));
	if (!binary) {
		free(key.path);
		return -ENOMEM;
	}

	*binary = key;
	if (attach_path)
		binary->attach_path = strdup(attach_path);

	hashmap__set(env.req_binaries, binary, binary, NULL, NULL);

	/*
	wprintf("Added binary: DEV %llu INODE %llu PATH %s ATTACH %s\n",
		dev, inode, path, attach_path ?: path);
	*/

	return 0;
}

static int discover_pid_req_binaries(int pid)
{
	struct vma_info *vma;
	int err = 0;

	wprof_for_each(vma, vma, pid,
		       VMA_QUERY_VMA_EXECUTABLE | VMA_QUERY_FILE_BACKED_VMA) {
		if (vma->vma_name[0] != '/')
			continue; /* special file, ignore */

		/*
		 * Using map_files symlink ensures we bypass
		 * mount namespacing issues and don't care if the file
		 * was deleted from the file system or not.
		 * The only downside is that we now rely on that
		 * specific process to be alive at the time of attachment.
		 */
		char tmp[1024];
		snprintf(tmp, sizeof(tmp), "/proc/%d/map_files/%llx-%llx",
			 pid, vma->vma_start, vma->vma_end);

		u64 dev = makedev(vma->dev_major, vma->dev_minor);
		err = add_uprobe_binary(dev, vma->inode, vma->vma_name, tmp);
		if (err)
			return err;
		/* reset errno, so we don't trigger false error reporting after the loop */
		errno = 0;
	}
	if (errno && (errno != ENOENT && errno != ESRCH)) {
		err = -errno;
		eprintf("Failed VMA iteration for PID %d: %d\n", pid, err);
		return err;
	}

	return 0;
}

int setup_req_tracking_discovery(void)
{
	int err = 0;

	if (env.req_global_discovery) {
		int *pidp, pid;

		wprof_for_each(proc, pidp) {
			pid = *pidp;
			err = discover_pid_req_binaries(pid);
			if (err) {
				eprintf("Failed to discover request tracking binaries for PID %d: %d (skipping...)\n", pid, err);
				continue;
			}
		}
	}

	for (int i = 0; i < env.req_path_cnt; i++) {
		struct stat st;

		err = stat(env.req_paths[i], &st);
		if (err) {
			err = -errno;
			eprintf("Failed to stat() binary '%s' for request tracking: %d (skipping...)\n", env.req_paths[i], err);
			continue;
		}

		err = add_uprobe_binary(st.st_dev, st.st_ino, env.req_paths[i], NULL);
		if (err) {
			eprintf("Failed to record binary path '%s' for request tracking: %d (skipping...)\n", env.req_paths[i], err);
			continue;
		}
	}

	for (int i = 0; i < env.req_pid_cnt; i++) {
		int pid = env.req_pids[i];

		err = discover_pid_req_binaries(pid);
		if (err) {
			eprintf("Failed to discover request tracking binaries for PID %d: %d (skipping...)\n", pid, err);
			continue;
		}
	}

	return 0;
}

static enum req_field parse_field(const char *name)
{
	if (strcasecmp(name, "id") == 0)
		return REQ_FIELD_ID;
	if (strcasecmp(name, "name") == 0)
		return REQ_FIELD_NAME;
	if (strcasecmp(name, "comm") == 0)
		return REQ_FIELD_COMM;
	if (strcasecmp(name, "pid") == 0)
		return REQ_FIELD_PID;
	if (strcasecmp(name, "start") == 0)
		return REQ_FIELD_START;
	if (strcasecmp(name, "end") == 0)
		return REQ_FIELD_END;
	if (strcasecmp(name, "latency") == 0 || strcasecmp(name, "lat") == 0)
		return REQ_FIELD_LATENCY;
	eprintf("Unknown request field '%s' (expected: id, name, comm, pid, start, end, latency/lat)\n", name);
	return REQ_FIELD_INVALID;
}

int req_list_parse_sort(const char *field_name, enum req_sort_order order)
{
	struct req_list_cfg *cfg = env.req_list_cfg;
	enum req_field field;

	field = parse_field(field_name);
	if (field == REQ_FIELD_INVALID)
		return -EINVAL;

	if (order == REQ_ORDER_DEFAULT)
		order = (field == REQ_FIELD_LATENCY) ? REQ_ORDER_DESC : REQ_ORDER_ASC;

	cfg->sorts = realloc(cfg->sorts, (cfg->sort_cnt + 1) * sizeof(*cfg->sorts));
	cfg->sorts[cfg->sort_cnt++] = (struct req_sort_spec){ .field = field, .order = order };
	return 0;
}

static enum req_filter_op parse_filter_op(const char *op)
{
	if (strcmp(op, "==") == 0) return REQ_OP_EQ;
	if (strcmp(op, "=") == 0)  return REQ_OP_EQ;
	if (strcmp(op, "!=") == 0) return REQ_OP_NE;
	if (strcmp(op, "<>") == 0) return REQ_OP_NE;
	if (strcmp(op, "<") == 0)  return REQ_OP_LT;
	if (strcmp(op, ">") == 0)  return REQ_OP_GT;
	if (strcmp(op, "<=") == 0) return REQ_OP_LE;
	if (strcmp(op, ">=") == 0) return REQ_OP_GE;
	if (strcmp(op, "~") == 0)  return REQ_OP_GLOB_MATCH;
	if (strcmp(op, "!~") == 0) return REQ_OP_GLOB_MISMATCH;
	return REQ_OP_INVALID;
}

int req_list_parse_filter(const char *expr)
{
	struct req_list_cfg *cfg = env.req_list_cfg;
	struct req_filter_spec f = {};
	char field_str[16], op_str[3], val_str[256];
	int n;

	if (sscanf(expr, " %15[a-zA-Z] %2[!=<>~] %255s %n", field_str, op_str, val_str, &n) != 3 || expr[n] != '\0') {
		eprintf("Invalid filter expression '%s' (expected: <field><op><value>)\n", expr);
		return -EINVAL;
	}

	f.field = parse_field(field_str);
	if (f.field == REQ_FIELD_INVALID)
		return -EINVAL;

	f.op = parse_filter_op(op_str);
	if (f.op == REQ_OP_INVALID) {
		eprintf("Unknown operator '%s' in filter expression '%s'\n", op_str, expr);
		return -EINVAL;
	}

	switch (f.field) {
	case REQ_FIELD_NAME:
	case REQ_FIELD_COMM:
		f.str_val = strdup(val_str);
		break;
	case REQ_FIELD_ID:
	case REQ_FIELD_PID: {
		if (f.op == REQ_OP_GLOB_MATCH || f.op == REQ_OP_GLOB_MISMATCH) {
			eprintf("Glob operator can only be used with name or comm fields in '%s'\n", expr);
			return -EINVAL;
		}
		char *end;
		errno = 0;
		f.num_val = strtol(val_str, &end, 0);
		if (errno || *end) {
			eprintf("Invalid numeric value in filter '%s'\n", expr);
			return -EINVAL;
		}
		break;
	}
	case REQ_FIELD_START:
	case REQ_FIELD_END:
	case REQ_FIELD_LATENCY: {
		if (f.op == REQ_OP_GLOB_MATCH || f.op == REQ_OP_GLOB_MISMATCH) {
			eprintf("Glob operator can only be used with name or comm fields in '%s'\n", expr);
			return -EINVAL;
		}
		s64 ns = parse_time_units(val_str);
		if (ns < 0) {
			eprintf("Invalid time value in filter '%s'\n", expr);
			return -EINVAL;
		}
		f.num_val = ns;
		break;
	}
	default:
		return -EINVAL;
	}

	cfg->filters = realloc(cfg->filters, (cfg->filter_cnt + 1) * sizeof(*cfg->filters));
	cfg->filters[cfg->filter_cnt++] = f;
	return 0;
}

static const char *fmt_ts(u64 ns, char *buf, size_t buf_sz)
{
	u64 s = ns / 1000000000ULL;
	u64 frac = ns % 1000000000ULL;
	unsigned h = s / 3600, m = (s / 60) % 60;

	if (h)
		snprintf(buf, buf_sz, "%u:%02u:%02llu.%09llu", h, m, s % 60, frac);
	else if (m)
		snprintf(buf, buf_sz, "%u:%02llu.%09llu", m, s % 60, frac);
	else
		snprintf(buf, buf_sz, "%llu.%09llu", s % 60, frac);
	return buf;
}

struct req_entry {
	u64 id;
	const char *name;
	const char *comm;
	int pid;
	u64 start_ns;
	u64 end_ns;
};

static bool filter_cmp(int cmp, enum req_filter_op op)
{
	switch (op) {
	case REQ_OP_EQ:             return cmp == 0;
	case REQ_OP_NE:             return cmp != 0;
	case REQ_OP_LT:             return cmp < 0;
	case REQ_OP_GT:             return cmp > 0;
	case REQ_OP_LE:             return cmp <= 0;
	case REQ_OP_GE:             return cmp >= 0;
	case REQ_OP_GLOB_MATCH:     return cmp == 0;
	case REQ_OP_GLOB_MISMATCH:  return cmp != 0;
	default: eprintf("BUG: unknown filter op %d\n", op); exit(1);
	}
}

static bool req_entry_matches(const struct req_entry *e, const struct req_filter_spec *f)
{
	int cmp;

	switch (f->field) {
	case REQ_FIELD_ID:
		cmp = (e->id > f->num_val) - (e->id < f->num_val);
		break;
	case REQ_FIELD_NAME:
		if (f->op == REQ_OP_GLOB_MATCH || f->op == REQ_OP_GLOB_MISMATCH)
			cmp = wprof_glob_match(f->str_val, e->name) ? 0 : 1;
		else
			cmp = strcmp(e->name, f->str_val);
		break;
	case REQ_FIELD_COMM:
		if (f->op == REQ_OP_GLOB_MATCH || f->op == REQ_OP_GLOB_MISMATCH)
			cmp = wprof_glob_match(f->str_val, e->comm) ? 0 : 1;
		else
			cmp = strcmp(e->comm, f->str_val);
		break;
	case REQ_FIELD_PID:
		cmp = (e->pid > f->num_val) - (e->pid < f->num_val);
		break;
	case REQ_FIELD_START:
		cmp = (e->start_ns > f->num_val) - (e->start_ns < f->num_val);
		break;
	case REQ_FIELD_END:
		cmp = (e->end_ns > f->num_val) - (e->end_ns < f->num_val);
		break;
	case REQ_FIELD_LATENCY: {
		u64 latency_ns = e->end_ns - e->start_ns;
		cmp = (latency_ns > f->num_val) - (latency_ns < f->num_val);
		break;
	}
	default:
		eprintf("BUG: unknown filter field %d\n", f->field);
		exit(1);
	}
	return filter_cmp(cmp, f->op);
}

static int req_entry_cmp(const void *_a, const void *_b, void *ctx)
{
	const struct req_entry *a = _a, *b = _b;
	const struct req_list_cfg *cfg = ctx;

	for (int i = 0; i < cfg->sort_cnt; i++) {
		const struct req_sort_spec *s = &cfg->sorts[i];
		int cmp = 0;

		switch (s->field) {
		case REQ_FIELD_ID:
			cmp = (a->id > b->id) - (a->id < b->id);
			break;
		case REQ_FIELD_NAME:
			cmp = strcmp(a->name, b->name);
			break;
		case REQ_FIELD_COMM:
			cmp = strcmp(a->comm, b->comm);
			break;
		case REQ_FIELD_PID:
			cmp = (a->pid > b->pid) - (a->pid < b->pid);
			break;
		case REQ_FIELD_START:
			cmp = (a->start_ns > b->start_ns) - (a->start_ns < b->start_ns);
			break;
		case REQ_FIELD_END:
			cmp = (a->end_ns > b->end_ns) - (a->end_ns < b->end_ns);
			break;
		case REQ_FIELD_LATENCY: {
			u64 la = a->end_ns - a->start_ns, lb = b->end_ns - b->start_ns;
			cmp = (la > lb) - (la < lb);
			break;
		}
		default:
			eprintf("BUG: unknown sort field %d\n", s->field);
			exit(1);
		}

		if (cmp == 0)
			continue;
		return s->order == REQ_ORDER_DESC ? -cmp : cmp;
	}
	return 0;
}

int req_list_output(struct worker_state *w)
{
	struct req_list_cfg *cfg = env.req_list_cfg;
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wevent_record *rec;
	struct req_entry *entries = NULL;
	int entry_cnt = 0, entry_cap = 0;

	wevent_for_each_event(rec, hdr) {
		const struct wevent *e = rec->e;

		if (e->kind != EV_REQ_EVENT || e->req.req_event != REQ_END)
			continue;
		if (!is_ts_in_range(e->ts))
			continue;

		struct wprof_task task = wevent_resolve_task(hdr, e->task_id);
		struct req_entry ent = {
			.id = e->req.req_id,
			.name = wevent_str(hdr, e->req.req_name_stroff),
			.comm = task.comm,
			.pid = task.pid,
			.start_ns = e->req.req_ts - env.sess_start_ts,
			.end_ns = e->ts - env.sess_start_ts,
		};

		bool pass = true;
		for (int i = 0; i < cfg->filter_cnt; i++) {
			if (!req_entry_matches(&ent, &cfg->filters[i])) {
				pass = false;
				break;
			}
		}
		if (!pass)
			continue;

		if (entry_cnt >= entry_cap) {
			entry_cap = entry_cap ? entry_cap * 3 / 2 : 64;
			entries = realloc(entries, entry_cap * sizeof(*entries));
		}
		entries[entry_cnt++] = ent;
	}

	if (cfg->sort_cnt > 0 && entry_cnt > 1)
		qsort_r(entries, entry_cnt, sizeof(*entries), req_entry_cmp, cfg);

	/* print */
	printf("%12s %12s %8s %-15s %18s  %s\n",
	       "START", "LATENCY (us)", "PID", "COMM", "ID", "NAME");
	printf("%12s %12s %8s %-15s %18s  %s\n",
	       "------------",
	       "------------", "--------", "---------------",
	       "------------------", "----");
	bool show_all = cfg->top_n <= 0 && cfg->bottom_n <= 0;
	bool skipped = false;
	for (int i = 0; i < entry_cnt; i++) {
		bool in_top = cfg->top_n > 0 && i < cfg->top_n;
		bool in_bottom = cfg->bottom_n > 0 && i >= entry_cnt - cfg->bottom_n;
		if (show_all || in_top || in_bottom) {
			char ts1[32];
			printf("%12s %12.3f %8d %-15s %18llu  %s\n",
			       fmt_ts(entries[i].start_ns, ts1, sizeof(ts1)),
			       (entries[i].end_ns - entries[i].start_ns) / 1000.0,
			       entries[i].pid, entries[i].comm,
			       entries[i].id, entries[i].name);
		} else if (!skipped) {
			printf("  ... (%d entries skipped) ...\n", entry_cnt - cfg->top_n - cfg->bottom_n);
			skipped = true;
		}
	}

	free(entries);
	return 0;
}

static int req_id_cmp(const void *_a, const void *_b)
{
	const struct req_id *a = _a, *b = _b;

	if (a->pid != b->pid)
		return a->pid < b->pid ? -1 : 1;
	if (a->req_id != b->req_id)
		return a->req_id < b->req_id ? -1 : 1;
	return 0;
}

int req_filter_build_allowlist(struct worker_state *w, struct req_allowlist *al)
{
	struct req_list_cfg *cfg = env.req_list_cfg;
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wevent_record *rec;
	struct req_id *ids = NULL;
	int cnt = 0, cap = 0;

	wevent_for_each_event(rec, hdr) {
		const struct wevent *e = rec->e;

		if (e->kind != EV_REQ_EVENT || e->req.req_event != REQ_END)
			continue;
		if (!is_ts_in_range(e->ts))
			continue;

		struct wprof_task task = wevent_resolve_task(hdr, e->task_id);
		struct req_entry ent = {
			.id = e->req.req_id,
			.name = wevent_str(hdr, e->req.req_name_stroff),
			.comm = task.comm,
			.pid = task.pid,
			.start_ns = e->req.req_ts - env.sess_start_ts,
			.end_ns = e->ts - env.sess_start_ts,
		};

		bool pass = true;
		for (int i = 0; i < cfg->filter_cnt; i++) {
			if (!req_entry_matches(&ent, &cfg->filters[i])) {
				pass = false;
				break;
			}
		}
		if (!pass)
			continue;

		if (cnt >= cap) {
			cap = cap ? cap * 3 / 2 : 64;
			ids = realloc(ids, cap * sizeof(*ids));
		}
		ids[cnt++] = (struct req_id){ .pid = task.pid, .req_id = e->req.req_id };
	}

	if (cnt > 1)
		qsort(ids, cnt, sizeof(*ids), req_id_cmp);

	al->ids = ids;
	al->cnt = cnt;
	return 0;
}

bool req_allowlist_has(const struct req_allowlist *al, int pid, u64 req_id)
{
	int lo = 0, hi = al->cnt - 1;

	while (lo <= hi) {
		int mid = lo + (hi - lo) / 2;
		const struct req_id *m = &al->ids[mid];

		if (m->pid < pid) {
			lo = mid + 1;
		} else if (m->pid > pid) {
			hi = mid - 1;
		} else if (m->req_id < req_id) {
			lo = mid + 1;
		} else if (m->req_id > req_id) {
			hi = mid - 1;
		} else {
			return true;
		}
	}
	return false;
}

int attach_req_tracking_usdts(struct bpf_state *st)
{
	struct hashmap_entry *entry;
	size_t bkt;
	int err;

	hashmap__for_each_entry(env.req_binaries, entry, bkt) {
		struct uprobe_binary *binary = (struct uprobe_binary *)entry->value;

		err = attach_usdt_probe(st, st->skel->progs.wprof_req_ctx,
					binary->path, binary->attach_path,
					"thrift", "crochet_request_data_context");
		if (err == -ENOENT)
			continue;
		if (err)
			return err;

		if (env.capture_req_experimental) {
			err = attach_usdt_probe(st, st->skel->progs.wprof_req_task_enqueue,
					binary->path, binary->attach_path,
						"folly", "thread_pool_executor_task_enqueued");
			if (err == -ENOENT)
				continue;
			if (err)
				return err;

			err = attach_usdt_probe(st, st->skel->progs.wprof_req_task_dequeue,
					binary->path, binary->attach_path,
						"folly", "thread_pool_executor_task_dequeued");
			if (err == -ENOENT)
				continue;
			if (err)
				return err;

			err = attach_usdt_probe(st, st->skel->progs.wprof_req_task_stats,
						binary->path, binary->attach_path,
						"folly", "thread_pool_executor_task_stats");
			if (err == -ENOENT)
				continue;
			if (err)
				return err;
		}
	}

	return 0;
}
