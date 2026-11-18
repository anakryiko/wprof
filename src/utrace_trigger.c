// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "utils.h"
#include "bpf_utils.h"
#include "utrace_cfg.h"
#include "utrace.h"
#include "utrace_trigger.h"
#include "utrace_trigger.skel.h"

struct utrace_trigger {
	const char *desc;
	struct utrace_trigger_bpf *skel;
	struct utrace_session sess;
	struct bpf_state links;		/* only its links and link_fds */
	struct ring_buffer *rb;
	struct utrace_trigger_hit hit;
	bool fired;
};

static int handle_hit(void *ctx, void *data, size_t size)
{
	struct utrace_trigger *t = ctx;

	memcpy(&t->hit, data, sizeof(t->hit));
	t->fired = true;
	return 0;
}

static void destroy_trigger(struct utrace_trigger *t)
{
	for (int i = 0; i < t->links.link_cnt; i++)
		bpf_link__destroy(t->links.links[i]);
	for (int i = 0; i < t->links.link_fd_cnt; i++)
		close(t->links.link_fds[i]);
	free(t->links.links);
	free(t->links.link_fds);

	ring_buffer__free(t->rb);
	utrace_trigger_bpf__destroy(t->skel);
	utrace_release_btfs(&t->sess);
	free(t->sess.cfgs);
	free(t);
}

int utrace_trigger_start(struct utrace_cfg *cfg, const char *desc, struct utrace_trigger **out)
{
	struct utrace_trigger *t;
	int err;

	t = calloc(1, sizeof(*t));
	t->desc = desc;
	t->sess.cfgs = cfg;
	t->sess.cfg_cnt = 1;

	t->skel = utrace_trigger_bpf__open();
	if (!t->skel) {
		err = -errno;
		eprintf("Failed to open utrace trigger BPF skeleton: %d\n", err);
		goto err_out;
	}

	t->sess.progs = (struct utrace_progs){
		.ut_uprobe = t->skel->progs.wprof_trig_uprobe,
		.ut_uret = t->skel->progs.wprof_trig_uret,
		.ut_usdt = t->skel->progs.wprof_trig_usdt,
		.ut_kprobe = t->skel->progs.wprof_trig_kprobe,
		.ut_kmulti = t->skel->progs.wprof_trig_kmulti,
		.ut_kret = t->skel->progs.wprof_trig_kret,
		.ut_kretmulti = t->skel->progs.wprof_trig_kretmulti,
		.ut_tp = t->skel->progs.wprof_trig_tp,
		.ut_raw_tp = t->skel->progs.wprof_trig_raw_tp,
		.ut_bpf_entry = t->skel->progs.wprof_trig_bpf_entry,
		.ut_bpf_exit = t->skel->progs.wprof_trig_bpf_exit,
	};

	err = utrace_resolve(&t->sess);
	if (err)
		goto err_out;

	err = bpf_object__prepare(t->skel->obj);
	if (err) {
		eprintf("Failed to prepare utrace trigger BPF skeleton: %d\n", err);
		goto err_out;
	}

	/* fentry/fexit templates are only clone sources, same as in the main skeleton */
	bpf_program__set_autoload(t->sess.progs.ut_bpf_entry, false);
	bpf_program__set_autoload(t->sess.progs.ut_bpf_exit, false);

	err = utrace_trigger_bpf__load(t->skel);
	if (err) {
		eprintf("Failed to load utrace trigger BPF skeleton: %d\n", err);
		goto err_out;
	}

	t->rb = ring_buffer__new(bpf_map__fd(t->skel->maps.trigger_rb), handle_hit, t, NULL);
	if (!t->rb) {
		err = -errno;
		eprintf("Failed to create utrace trigger ringbuf: %d\n", err);
		goto err_out;
	}

	err = utrace_attach_cfgs(&t->links, &t->sess, -1);
	if (err)
		goto err_out;

	utrace_release_btfs(&t->sess);
	vprintf("Trigger '%s' attached to %d target(s).\n", desc, t->sess.cfg_cnt);

	*out = t;
	return 0;

err_out:
	destroy_trigger(t);
	return err;
}

int utrace_trigger_fd(const struct utrace_trigger *t)
{
	return ring_buffer__epoll_fd(t->rb);
}

__u64 utrace_trigger_hit_cnt(const struct utrace_trigger *t)
{
	return __atomic_load_n(&t->skel->bss->hit_cnt, __ATOMIC_RELAXED);
}

int utrace_trigger_poll(struct utrace_trigger *t, struct utrace_trigger_hit *hit)
{
	int err;

	err = ring_buffer__consume(t->rb);
	if (err < 0)
		return err;
	if (!t->fired)
		return 0;

	*hit = t->hit;
	return 1;
}

static void *destroy_thread_fn(void *ctx)
{
	pthread_setname_np(pthread_self(), "wprof_cleanup");
	destroy_trigger(ctx);
	return NULL;
}

int utrace_trigger_stop(struct utrace_trigger *t)
{
	pthread_t thread;
	int err;

	if (!t)
		return 0;

	if (t->fired)
		vprintf("Trigger '%s' got hit %llu time(s) before detaching.\n", t->desc, utrace_trigger_hit_cnt(t));

	ring_buffer__free(t->rb);
	t->rb = NULL;

	err = pthread_create(&thread, NULL, destroy_thread_fn, t);
	if (err) {
		/* pthread_create returns the error positively, doesn't set errno */
		err = -err;
		eprintf("Failed to spawn detach thread for trigger '%s': %d\n", t->desc, err);
		return err;
	}
	pthread_detach(thread);
	return 0;
}
