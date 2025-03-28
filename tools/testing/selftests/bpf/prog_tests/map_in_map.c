// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023. Huawei Technologies Co., Ltd */
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <test_progs.h>
#include <bpf/btf.h>

#include "access_map_in_map.skel.h"
#include "update_map_in_htab.skel.h"

struct thread_ctx {
	pthread_barrier_t barrier;
	int outer_map_fd;
	int start, abort;
	int loop, err;
};

static int wait_for_start_or_abort(struct thread_ctx *ctx)
{
	while (!ctx->start && !ctx->abort)
		usleep(1);
	return ctx->abort ? -1 : 0;
}

static void *update_map_fn(void *data)
{
	struct thread_ctx *ctx = data;
	int loop = ctx->loop, err = 0;

	if (wait_for_start_or_abort(ctx) < 0)
		return NULL;
	pthread_barrier_wait(&ctx->barrier);

	while (loop-- > 0) {
		int fd, zero = 0;

		fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, 4, 4, 1, NULL);
		if (fd < 0) {
			err |= 1;
			pthread_barrier_wait(&ctx->barrier);
			continue;
		}

		/* Remove the old inner map */
		if (bpf_map_update_elem(ctx->outer_map_fd, &zero, &fd, 0) < 0)
			err |= 2;
		close(fd);
		pthread_barrier_wait(&ctx->barrier);
	}

	ctx->err = err;

	return NULL;
}

static void *access_map_fn(void *data)
{
	struct thread_ctx *ctx = data;
	int loop = ctx->loop;

	if (wait_for_start_or_abort(ctx) < 0)
		return NULL;
	pthread_barrier_wait(&ctx->barrier);

	while (loop-- > 0) {
		/* Access the old inner map */
		syscall(SYS_getpgid);
		pthread_barrier_wait(&ctx->barrier);
	}

	return NULL;
}

static void test_map_in_map_access(const char *prog_name, const char *map_name)
{
	struct access_map_in_map *skel;
	struct bpf_map *outer_map;
	struct bpf_program *prog;
	struct thread_ctx ctx;
	pthread_t tid[2];
	int err;

	skel = access_map_in_map__open();
	if (!ASSERT_OK_PTR(skel, "access_map_in_map open"))
		return;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "find program"))
		goto out;
	bpf_program__set_autoload(prog, true);

	outer_map = bpf_object__find_map_by_name(skel->obj, map_name);
	if (!ASSERT_OK_PTR(outer_map, "find map"))
		goto out;

	err = access_map_in_map__load(skel);
	if (!ASSERT_OK(err, "access_map_in_map load"))
		goto out;

	err = access_map_in_map__attach(skel);
	if (!ASSERT_OK(err, "access_map_in_map attach"))
		goto out;

	skel->bss->tgid = getpid();

	memset(&ctx, 0, sizeof(ctx));
	pthread_barrier_init(&ctx.barrier, NULL, 2);
	ctx.outer_map_fd = bpf_map__fd(outer_map);
	ctx.loop = 4;

	err = pthread_create(&tid[0], NULL, update_map_fn, &ctx);
	if (!ASSERT_OK(err, "close_thread"))
		goto out;

	err = pthread_create(&tid[1], NULL, access_map_fn, &ctx);
	if (!ASSERT_OK(err, "read_thread")) {
		ctx.abort = 1;
		pthread_join(tid[0], NULL);
		goto out;
	}

	ctx.start = 1;
	pthread_join(tid[0], NULL);
	pthread_join(tid[1], NULL);

	ASSERT_OK(ctx.err, "err");
out:
	access_map_in_map__destroy(skel);
}

static void add_del_fd_htab(int outer_fd)
{
	int inner_fd, err;
	int key = 1;

	inner_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "arr1", 4, 4, 1, NULL);
	if (!ASSERT_OK_FD(inner_fd, "inner1"))
		return;
	err = bpf_map_update_elem(outer_fd, &key, &inner_fd, BPF_NOEXIST);
	close(inner_fd);
	if (!ASSERT_OK(err, "add"))
		return;

	/* Delete */
	err = bpf_map_delete_elem(outer_fd, &key);
	ASSERT_OK(err, "del");
}

static void overwrite_fd_htab(int outer_fd)
{
	int inner_fd, err;
	int key = 1;

	inner_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "arr1", 4, 4, 1, NULL);
	if (!ASSERT_OK_FD(inner_fd, "inner1"))
		return;
	err = bpf_map_update_elem(outer_fd, &key, &inner_fd, BPF_NOEXIST);
	close(inner_fd);
	if (!ASSERT_OK(err, "add"))
		return;

	/* Overwrite */
	inner_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "arr2", 4, 4, 1, NULL);
	if (!ASSERT_OK_FD(inner_fd, "inner2"))
		goto out;
	err = bpf_map_update_elem(outer_fd, &key, &inner_fd, BPF_EXIST);
	close(inner_fd);
	if (!ASSERT_OK(err, "overwrite"))
		goto out;

	err = bpf_map_delete_elem(outer_fd, &key);
	ASSERT_OK(err, "del");
	return;
out:
	bpf_map_delete_elem(outer_fd, &key);
}

static void lookup_delete_fd_htab(int outer_fd)
{
	int key = 1, value;
	int inner_fd, err;

	inner_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "arr1", 4, 4, 1, NULL);
	if (!ASSERT_OK_FD(inner_fd, "inner1"))
		return;
	err = bpf_map_update_elem(outer_fd, &key, &inner_fd, BPF_NOEXIST);
	close(inner_fd);
	if (!ASSERT_OK(err, "add"))
		return;

	/* lookup_and_delete is not supported for htab of maps */
	err = bpf_map_lookup_and_delete_elem(outer_fd, &key, &value);
	ASSERT_EQ(err, -ENOTSUPP, "lookup_del");

	err = bpf_map_delete_elem(outer_fd, &key);
	ASSERT_OK(err, "del");
}

static void batched_lookup_delete_fd_htab(int outer_fd)
{
	int keys[2] = {1, 2}, values[2];
	unsigned int cnt, batch;
	int inner_fd, err;

	inner_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "arr1", 4, 4, 1, NULL);
	if (!ASSERT_OK_FD(inner_fd, "inner1"))
		return;

	err = bpf_map_update_elem(outer_fd, &keys[0], &inner_fd, BPF_NOEXIST);
	close(inner_fd);
	if (!ASSERT_OK(err, "add1"))
		return;

	inner_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "arr2", 4, 4, 1, NULL);
	if (!ASSERT_OK_FD(inner_fd, "inner2"))
		goto out;
	err = bpf_map_update_elem(outer_fd, &keys[1], &inner_fd, BPF_NOEXIST);
	close(inner_fd);
	if (!ASSERT_OK(err, "add2"))
		goto out;

	/* batched lookup_and_delete */
	cnt = ARRAY_SIZE(keys);
	err = bpf_map_lookup_and_delete_batch(outer_fd, NULL, &batch, keys, values, &cnt, NULL);
	ASSERT_TRUE((!err || err == -ENOENT), "delete_batch ret");
	ASSERT_EQ(cnt, ARRAY_SIZE(keys), "delete_batch cnt");

out:
	bpf_map_delete_elem(outer_fd, &keys[0]);
}

static void test_update_map_in_htab(bool preallocate)
{
	struct update_map_in_htab *skel;
	int err, fd;

	skel = update_map_in_htab__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	err = update_map_in_htab__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto out;

	fd = preallocate ? bpf_map__fd(skel->maps.outer_htab_map) :
			   bpf_map__fd(skel->maps.outer_alloc_htab_map);

	add_del_fd_htab(fd);
	overwrite_fd_htab(fd);
	lookup_delete_fd_htab(fd);
	batched_lookup_delete_fd_htab(fd);
out:
	update_map_in_htab__destroy(skel);
}

void test_map_in_map(void)
{
	if (test__start_subtest("acc_map_in_array"))
		test_map_in_map_access("access_map_in_array", "outer_array_map");
	if (test__start_subtest("sleepable_acc_map_in_array"))
		test_map_in_map_access("sleepable_access_map_in_array", "outer_array_map");
	if (test__start_subtest("acc_map_in_htab"))
		test_map_in_map_access("access_map_in_htab", "outer_htab_map");
	if (test__start_subtest("sleepable_acc_map_in_htab"))
		test_map_in_map_access("sleepable_access_map_in_htab", "outer_htab_map");
	if (test__start_subtest("update_map_in_htab"))
		test_update_map_in_htab(true);
	if (test__start_subtest("update_map_in_alloc_htab"))
		test_update_map_in_htab(false);
}
