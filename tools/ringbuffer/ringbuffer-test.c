// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define READ	0
#define WRITE	1

#define min(a, b) (a < b ? a : b)

#define __EXPORTED_HEADERS__
#include <uapi/linux/ringbuffer_sys.h>

#define BUF_NR		4

typedef uint32_t u32;
typedef unsigned long ulong;

static inline struct ringbuffer_desc *ringbuffer(int fd, int rw, u32 size)
{
	ulong addr = 0;
	int ret = syscall(463, fd, rw, size, &addr);
	if (ret < 0)
		errno = -ret;
	return (void *) addr;
}

static inline int ringbuffer_wait(int fd, int rw)
{
	return syscall(464, fd, rw);
}

static inline int ringbuffer_wakeup(int fd, int rw)
{
	return syscall(465, fd, rw);
}

static ssize_t ringbuffer_read(int fd, struct ringbuffer_desc *rb,
			       void *buf, size_t len)
{
	void *rb_data = (void *) rb + rb->data_offset;

	u32 head, orig_tail = rb->tail, tail = orig_tail;

	while ((head = __atomic_load_n(&rb->head, __ATOMIC_ACQUIRE)) == tail)
		ringbuffer_wait(fd, READ);

	while (len && head != tail) {
		u32 tail_masked = tail & rb->mask;
		unsigned b = min(len,
			     min(head - tail,
				 rb->size - tail_masked));

		memcpy(buf, rb_data + tail_masked, b);
		buf += b;
		len -= b;
		tail += b;
	}

	__atomic_store_n(&rb->tail, tail, __ATOMIC_RELEASE);

	__atomic_thread_fence(__ATOMIC_SEQ_CST);

	if (rb->head - orig_tail >= rb->size)
		ringbuffer_wakeup(fd, READ);

	return tail - orig_tail;
}

static ssize_t ringbuffer_write(int fd, struct ringbuffer_desc *rb,
				void *buf, size_t len)
{
	void *rb_data = (void *) rb + rb->data_offset;

	u32 orig_head = rb->head, head = orig_head, tail;

	while (head - (tail = __atomic_load_n(&rb->tail, __ATOMIC_ACQUIRE)) >= rb->size)
		ringbuffer_wait(fd, WRITE);

	while (len && head - tail < rb->size) {
		u32 head_masked = head & rb->mask;
		unsigned b = min(len,
			     min(tail - head + rb->size,
				 rb->size - head_masked));

		memcpy(rb_data + head_masked, buf, b);
		buf += b;
		len -= b;
		head += b;
	}

	__atomic_store_n(&rb->head, head, __ATOMIC_RELEASE);

	__atomic_thread_fence(__ATOMIC_SEQ_CST);

	if ((s32) (rb->tail - orig_head) >= 0)
		ringbuffer_wakeup(fd, WRITE);

	return head - orig_head;
}

static void usage(void)
{
	puts("ringbuffer-test - test ringbuffer syscall\n"
	     "Usage: ringbuffer-test [OPTION]...\n"
	     "\n"
	     "Options:\n"
	     "      --type=(io|ringbuffer)\n"
	     "      --rw=(read|write)\n"
	     "  -h, --help                Display this help and exit\n");
}

static inline ssize_t rb_test_read(int fd, struct ringbuffer_desc *rb,
				   void *buf, size_t len)
{
	return rb
		? ringbuffer_read(fd, rb, buf, len)
		: read(fd, buf, len);
}

static inline ssize_t rb_test_write(int fd, struct ringbuffer_desc *rb,
				    void *buf, size_t len)
{
	return rb
		? ringbuffer_write(fd, rb, buf, len)
		: write(fd, buf, len);
}

int main(int argc, char *argv[])
{
	const struct option longopts[] = {
		{ "type",		required_argument,	NULL, 't' },
		{ "rw",			required_argument,	NULL, 'r' },
		{ "help",		no_argument,		NULL, 'h' },
		{ NULL }
	};
	int use_ringbuffer = false, rw = false;
	int opt;

	while ((opt = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
		switch (opt) {
		case 't':
			if (!strcmp(optarg, "io"))
				use_ringbuffer = false;
			else if (!strcmp(optarg, "ringbuffer") ||
				 !strcmp(optarg, "rb"))
				use_ringbuffer = true;
			else {
				fprintf(stderr, "Invalid type %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'r':
			if (!strcmp(optarg, "read"))
				rw = false;
			else if (!strcmp(optarg, "write"))
				rw = true;
			else {
				fprintf(stderr, "Invalid rw %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case '?':
			fprintf(stderr, "Invalid option %c\n", opt);
			usage();
			exit(EXIT_FAILURE);
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
		}
	}

	int fd = open("/dev/ringbuffer-test", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Error opening /dev/ringbuffer-test: %m\n");
		exit(EXIT_FAILURE);
	}

	struct ringbuffer_desc *rb = NULL;
	if (use_ringbuffer) {
		rb = ringbuffer(fd, rw, 4096);
		if (!rb) {
			fprintf(stderr, "Error from sys_ringbuffer: %m\n");
			exit(EXIT_FAILURE);
		}

		fprintf(stderr, "got ringbuffer %p\n", rb);
	}

	printf("Starting test with ringbuffer=%u, rw=%u\n", use_ringbuffer, rw);
	static const char * const rw_str[] = { "read", "wrote" };

	struct timeval start;
	gettimeofday(&start, NULL);
	size_t nr_prints = 1;

	u32 buf[BUF_NR];
	u32 idx = 0;

	while (true) {
		struct timeval now;
		gettimeofday(&now, NULL);

		struct timeval next_print = start;
		next_print.tv_sec += nr_prints;

		if (timercmp(&now, &next_print, >)) {
			printf("%s %u u32s, %lu mb/sec\n", rw_str[rw], idx,
			       (idx * sizeof(u32) / (now.tv_sec - start.tv_sec)) / (1UL << 20));
			nr_prints++;
			if (nr_prints > 20)
				break;
		}

		if (rw == READ) {
			int r = rb_test_read(fd, rb, buf, sizeof(buf));
			if (r <= 0) {
				fprintf(stderr, "Read returned %i (%m)\n", r);
				exit(EXIT_FAILURE);
			}

			unsigned nr = r / sizeof(u32);
			for (unsigned i = 0; i < nr; i++) {
				if (buf[i] != idx + i) {
					fprintf(stderr, "Read returned wrong data at idx %u: got %u instead\n",
						idx + i, buf[i]);
					exit(EXIT_FAILURE);
				}
			}

			idx += nr;
		} else {
			for (unsigned i = 0; i < BUF_NR; i++)
				buf[i] = idx + i;

			int r = rb_test_write(fd, rb, buf, sizeof(buf));
			if (r <= 0) {
				fprintf(stderr, "Write returned %i (%m)\n", r);
				exit(EXIT_FAILURE);
			}

			unsigned nr = r / sizeof(u32);
			idx += nr;
		}
	}

	exit(EXIT_SUCCESS);
}
