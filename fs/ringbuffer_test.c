// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "%s() " fmt "\n", __func__

#include <linux/device.h>
#include <linux/errname.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/ringbuffer_sys.h>
#include <linux/uio.h>

struct ringbuffer_test_file {
	struct ringbuffer_test_rw {
		struct mutex		lock;
		struct ringbuffer	*rb;
		struct task_struct	*thr;
	} rw[2];
};

#define BUF_NR	4

static int ringbuffer_test_writer(void *p)
{
	struct file *file = p;
	struct ringbuffer_test_file *f = file->private_data;
	struct ringbuffer *rb = f->rw[READ].rb;
	u32 idx = 0;
	u32 buf[BUF_NR];

	while (!kthread_should_stop()) {
		cond_resched();

		struct kvec vec = { buf, sizeof(buf) };
		struct iov_iter iter;
		iov_iter_kvec(&iter, ITER_SOURCE, &vec, 1, sizeof(buf));

		for (unsigned i = 0; i < ARRAY_SIZE(buf); i++)
			buf[i] = idx + i;

		ssize_t ret = ringbuffer_write_iter(rb, &iter, false);
		if (ret < 0)
			continue;
		idx += ret / sizeof(buf[0]);
	}

	return 0;
}

static int ringbuffer_test_reader(void *p)
{
	struct file *file = p;
	struct ringbuffer_test_file *f = file->private_data;
	struct ringbuffer *rb = f->rw[WRITE].rb;
	u32 idx = 0;
	u32 buf[BUF_NR];

	while (!kthread_should_stop()) {
		cond_resched();

		struct kvec vec = { buf, sizeof(buf) };
		struct iov_iter iter;
		iov_iter_kvec(&iter, ITER_DEST, &vec, 1, sizeof(buf));

		ssize_t ret = ringbuffer_read_iter(rb, &iter, false);
		if (ret < 0)
			continue;

		unsigned nr = ret / sizeof(buf[0]);
		for (unsigned i = 0; i < nr; i++)
			if (buf[i] != idx + i)
				pr_err("read wrong data");
		idx += ret / sizeof(buf[0]);
	}

	return 0;
}

static void ringbuffer_test_free(struct ringbuffer_test_file *f)
{
	for (unsigned i = 0; i < ARRAY_SIZE(f->rw); i++)
		if (!IS_ERR_OR_NULL(f->rw[i].thr))
			kthread_stop_put(f->rw[i].thr);
	for (unsigned i = 0; i < ARRAY_SIZE(f->rw); i++)
		if (!IS_ERR_OR_NULL(f->rw[i].rb))
			ringbuffer_free(f->rw[i].rb);
	kfree(f);
}

static int ringbuffer_test_open(struct inode *inode, struct file *file)
{
	static const char * const rw_str[] = { "reader", "writer" };
	int ret = 0;

	struct ringbuffer_test_file *f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;

	for (struct ringbuffer_test_rw *i = f->rw;
	     i < f->rw + ARRAY_SIZE(f->rw);
	     i++) {
		unsigned idx = i - f->rw;

		mutex_init(&i->lock);

		i->rb = ringbuffer_alloc(PAGE_SIZE * 4);
		ret = PTR_ERR_OR_ZERO(i->rb);
		if (ret)
			goto err;

		i->thr = kthread_create(idx == READ
					? ringbuffer_test_reader
					: ringbuffer_test_writer,
					file, "ringbuffer_%s", rw_str[idx]);
		ret = PTR_ERR_OR_ZERO(i->thr);
		if (ret)
			goto err;
		get_task_struct(i->thr);
	}

	file->private_data = f;
	wake_up_process(f->rw[0].thr);
	wake_up_process(f->rw[1].thr);
	return 0;
err:
	ringbuffer_test_free(f);
	return ret;
}

static int ringbuffer_test_release(struct inode *inode, struct file *file)
{
	ringbuffer_test_free(file->private_data);
	return 0;
}

static ssize_t ringbuffer_test_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct ringbuffer_test_file *f = file->private_data;
	struct ringbuffer_test_rw *i = &f->rw[READ];

	ssize_t ret = mutex_lock_interruptible(&i->lock);
	if (ret)
		return ret;

	ret = ringbuffer_read_iter(i->rb, iter, file->f_flags & O_NONBLOCK);
	mutex_unlock(&i->lock);
	return ret;
}

static ssize_t ringbuffer_test_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct ringbuffer_test_file *f = file->private_data;
	struct ringbuffer_test_rw *i = &f->rw[WRITE];

	ssize_t ret = mutex_lock_interruptible(&i->lock);
	if (ret)
		return ret;

	ret = ringbuffer_write_iter(i->rb, iter, file->f_flags & O_NONBLOCK);
	mutex_unlock(&i->lock);
	return ret;
}

static struct ringbuffer *ringbuffer_test_ringbuffer(struct file *file, int rw)
{
	struct ringbuffer_test_file *i = file->private_data;

	BUG_ON(rw > WRITE);

	return i->rw[rw].rb;
}

static const struct file_operations ringbuffer_fops = {
	.owner		= THIS_MODULE,
	.read_iter	= ringbuffer_test_read_iter,
	.write_iter	= ringbuffer_test_write_iter,
	.ringbuffer	= ringbuffer_test_ringbuffer,
	.open		= ringbuffer_test_open,
	.release	= ringbuffer_test_release,
};

static int __init ringbuffer_test_init(void)
{
	int ringbuffer_major = register_chrdev(0, "ringbuffer-test", &ringbuffer_fops);
	if (ringbuffer_major < 0)
		return ringbuffer_major;

	static const struct class ringbuffer_class = { .name = "ringbuffer_test" };
	int ret = class_register(&ringbuffer_class);
	if (ret)
		goto major_out;

	struct device *ringbuffer_device = device_create(&ringbuffer_class, NULL,
				    MKDEV(ringbuffer_major, 0),
				    NULL, "ringbuffer-test");
	ret = PTR_ERR_OR_ZERO(ringbuffer_device);
	if (ret)
		goto class_out;

	return 0;

class_out:
	class_unregister(&ringbuffer_class);
major_out:
	unregister_chrdev(ringbuffer_major, "ringbuffer-test");
	return ret;
}
__initcall(ringbuffer_test_init);
