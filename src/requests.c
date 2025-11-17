// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
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
		       PROCMAP_QUERY_VMA_EXECUTABLE | PROCMAP_QUERY_FILE_BACKED_VMA) {
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
