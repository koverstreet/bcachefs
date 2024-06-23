// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "%s() " fmt "\n", __func__

#include <linux/darray.h>
#include <linux/errname.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/futex.h>
#include <linux/init.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/pseudo_fs.h>
#include <linux/ringbuffer_sys.h>
#include <linux/syscalls.h>
#include <linux/uio.h>

#define RINGBUFFER_FS_MAGIC			0xa10a10a2

static DEFINE_MUTEX(ringbuffer_lock);

static struct vfsmount *ringbuffer_mnt;

struct ringbuffer_mapping {
	ulong			addr;
	struct mm_struct	*mm;
};

struct ringbuffer {
	u32			size;	/* always a power of two */
	u32			mask;	/* size - 1 */
	unsigned		order;
	wait_queue_head_t	wait[2];
	struct ringbuffer_desc	*ptrs;
	void			*data;
	/* hidden internal file for the mmap */
	struct file		*rb_file;
	DARRAY(struct ringbuffer_mapping) mms;
};

static const struct address_space_operations ringbuffer_aops = {
	.dirty_folio	= noop_dirty_folio,
#if 0
	.migrate_folio	= ringbuffer_migrate_folio,
#endif
};

#if 0
static int ringbuffer_mremap(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;
	struct mm_struct *mm = vma->vm_mm;
	struct kioctx_table *table;
	int i, res = -EINVAL;

	spin_lock(&mm->ioctx_lock);
	rcu_read_lock();
	table = rcu_dereference(mm->ioctx_table);
	if (!table)
		goto out_unlock;

	for (i = 0; i < table->nr; i++) {
		struct kioctx *ctx;

		ctx = rcu_dereference(table->table[i]);
		if (ctx && ctx->ringbuffer_file == file) {
			if (!atomic_read(&ctx->dead)) {
				ctx->user_id = ctx->mmap_base = vma->vm_start;
				res = 0;
			}
			break;
		}
	}

out_unlock:
	rcu_read_unlock();
	spin_unlock(&mm->ioctx_lock);
	return res;
}
#endif

static const struct vm_operations_struct ringbuffer_vm_ops = {
#if 0
	.mremap		= ringbuffer_mremap,
#endif
#if IS_ENABLED(CONFIG_MMU)
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= filemap_page_mkwrite,
#endif
};

static int ringbuffer_mmap(struct file *file, struct vm_area_struct *vma)
{
	vm_flags_set(vma, VM_DONTEXPAND);
	vma->vm_ops = &ringbuffer_vm_ops;
	return 0;
}

static const struct file_operations ringbuffer_fops = {
	.mmap = ringbuffer_mmap,
};

void ringbuffer_free(struct ringbuffer *rb)
{
	pr_debug("%px", rb);

	lockdep_assert_held(&ringbuffer_lock);

	darray_for_each(rb->mms, map)
		darray_for_each_reverse(map->mm->ringbuffers, rb2)
			if (rb == *rb2)
				darray_remove_item(&map->mm->ringbuffers, rb2);

	if (rb->rb_file) {
		/* Kills mapping: */
		truncate_setsize(file_inode(rb->rb_file), 0);

		struct address_space *mapping = rb->rb_file->f_mapping;
		spin_lock(&mapping->i_private_lock);
		mapping->i_private_data = NULL;
		spin_unlock(&mapping->i_private_lock);

		fput(rb->rb_file);
	}

	free_pages((ulong) rb->data, get_order(rb->size));
	free_page((ulong) rb->ptrs);
	kfree(rb);
}

static int ringbuffer_alloc_inode(struct ringbuffer *rb)
{
	struct inode *inode = alloc_anon_inode(ringbuffer_mnt->mnt_sb);
	int ret = PTR_ERR_OR_ZERO(inode);
	if (ret)
		goto err;

	inode->i_mapping->a_ops = &ringbuffer_aops;
	inode->i_mapping->i_private_data = rb;
	inode->i_size = rb->size * 2;
	mapping_set_large_folios(inode->i_mapping);

	rb->rb_file = alloc_file_pseudo(inode, ringbuffer_mnt, "[ringbuffer]",
				     O_RDWR, &ringbuffer_fops);
	ret = PTR_ERR_OR_ZERO(rb->rb_file);
	if (ret)
		goto err_iput;

	struct folio *f_ptrs = page_folio(virt_to_page(rb->ptrs));
	struct folio *f_data = page_folio(virt_to_page(rb->data));

	__folio_set_locked(f_ptrs);
	__folio_mark_uptodate(f_ptrs);

	void *shadow = NULL;
	ret = __filemap_add_folio(rb->rb_file->f_mapping, f_ptrs,
				  (1U << rb->order) - 1, GFP_KERNEL, &shadow);
	if (ret)
		goto err;
	folio_unlock(f_ptrs);

	__folio_set_locked(f_data);
	__folio_mark_uptodate(f_data);
	shadow = NULL;
	ret = __filemap_add_folio(rb->rb_file->f_mapping, f_data,
				  1U << rb->order, GFP_KERNEL, &shadow);
	if (ret)
		goto err;
	folio_unlock(f_data);
	return 0;
err_iput:
	iput(inode);
	return ret;
err:
	truncate_setsize(file_inode(rb->rb_file), 0);
	fput(rb->rb_file);
	return ret;
}

static int ringbuffer_map(struct ringbuffer *rb, ulong *addr)
{
	struct mm_struct *mm = current->mm;
	int ret = 0;

	lockdep_assert_held(&ringbuffer_lock);

	if (!rb->rb_file) {
		ret = ringbuffer_alloc_inode(rb);
		if (ret)
			return ret;
	}

	ret = darray_make_room(&rb->mms, 1) ?:
	      darray_make_room(&mm->ringbuffers, 1);
	if (ret)
		return ret;

	ret = mmap_write_lock_killable(mm);
	if (ret)
		return ret;

	ulong unused;
	struct ringbuffer_mapping map = {
		.addr = do_mmap(rb->rb_file, 0, rb->size + PAGE_SIZE,
				PROT_READ|PROT_WRITE,
				MAP_SHARED, 0,
				(1U << rb->order) - 1,
				&unused, NULL),
		.mm = mm,
	};
	mmap_write_unlock(mm);

	ret = PTR_ERR_OR_ZERO((void *) map.addr);
	if (ret)
		return ret;

	ret =   darray_push(&mm->ringbuffers, rb) ?:
		darray_push(&rb->mms, map);
	BUG_ON(ret); /* we preallocated */

	*addr = map.addr;
	return 0;
}

static int ringbuffer_get_addr_or_map(struct ringbuffer *rb, ulong *addr)
{
	lockdep_assert_held(&ringbuffer_lock);

	struct mm_struct *mm = current->mm;

	darray_for_each(rb->mms, map)
		if (map->mm == mm) {
			*addr = map->addr;
			return 0;
		}

	return ringbuffer_map(rb, addr);
}

struct ringbuffer *ringbuffer_alloc(u32 size)
{
	unsigned order = get_order(size);
	size = PAGE_SIZE << order;

	struct ringbuffer *rb = kzalloc(sizeof(*rb), GFP_KERNEL);
	if (!rb)
		return ERR_PTR(-ENOMEM);

	rb->size	= size;
	rb->mask	= size - 1;
	rb->order	= order;
	init_waitqueue_head(&rb->wait[READ]);
	init_waitqueue_head(&rb->wait[WRITE]);

	rb->ptrs = (void *) __get_free_page(GFP_KERNEL|__GFP_ZERO);
	rb->data = (void *) __get_free_pages(GFP_KERNEL|__GFP_ZERO|__GFP_COMP, order);
	if (!rb->ptrs || !rb->data) {
		ringbuffer_free(rb);
		return ERR_PTR(-ENOMEM);
	}

	/* todo - implement a fallback when high order allocation fails */

	rb->ptrs->size	= size;
	rb->ptrs->mask	= size - 1;
	rb->ptrs->data_offset = PAGE_SIZE;

	if (!rb->rb_file) {
		int ret = ringbuffer_alloc_inode(rb);
		if (ret) {
			ringbuffer_free(rb);
			return ERR_PTR(ret);
		}
	}
	return rb;
}

/*
 * XXX: we require synchronization when killing a ringbuffer (because no longer
 * mapped anywhere) to a file that is still open (and in use)
 */
static void ringbuffer_mm_drop(struct mm_struct *mm, struct ringbuffer *rb)
{
	darray_for_each_reverse(rb->mms, map)
		if (mm == map->mm) {
			pr_debug("removing %px from %px", rb, mm);
			darray_remove_item(&rb->mms, map);
		}
}

void ringbuffer_mm_exit(struct mm_struct *mm)
{
	mutex_lock(&ringbuffer_lock);
	darray_for_each_reverse(mm->ringbuffers, rb)
		ringbuffer_mm_drop(mm, *rb);
	mutex_unlock(&ringbuffer_lock);

	darray_exit(&mm->ringbuffers);
}

SYSCALL_DEFINE4(ringbuffer, unsigned, fd, int, rw, u32, size, ulong __user *, ringbufferp)
{
	ulong rb_addr;

	int ret = get_user(rb_addr, ringbufferp);
	if (unlikely(ret))
		return ret;

	if (unlikely(rb_addr || !size || rw > WRITE))
		return -EINVAL;

	struct fd f = fdget(fd);
	if (!f.file)
		return -EBADF;

	struct ringbuffer *rb = f.file->f_op->ringbuffer(f.file, rw);
	if (!rb) {
		ret = -EOPNOTSUPP;
		goto err;
	}

	mutex_lock(&ringbuffer_lock);
	ret = ringbuffer_get_addr_or_map(rb, &rb_addr);
	if (ret)
		goto err_unlock;

	ret = put_user(rb_addr, ringbufferp);
err_unlock:
	mutex_unlock(&ringbuffer_lock);
err:
	fdput(f);
	return ret;
}

static void ringbuffer_futex_key(struct ringbuffer *rb, int rw,
				 union futex_key *key)
{
	struct inode *inode = rb->rb_file->f_inode;

	key->both.offset |= FUT_OFF_INODE; /* inode-based key */
	key->shared.i_seq = get_inode_sequence_number(inode);
	key->shared.pgoff = (1U << rb->order) - 1;
	key->shared.offset = rw == READ
		? offsetof(struct ringbuffer_desc, head)
		: offsetof(struct ringbuffer_desc, tail);
}

ssize_t ringbuffer_read_iter(struct ringbuffer *rb, struct iov_iter *iter, bool nonblocking)
{
	u32 tail = rb->ptrs->tail, orig_tail = tail;
	u32 head = smp_load_acquire(&rb->ptrs->head);

	if (unlikely(head == tail)) {
		if (nonblocking)
			return -EAGAIN;
		int ret = wait_event_interruptible(rb->wait[READ],
			(head = smp_load_acquire(&rb->ptrs->head)) != rb->ptrs->tail);
		if (ret)
			return ret;
	}

	while (iov_iter_count(iter)) {
		u32 tail_masked = tail & rb->mask;
		u32 len = min(iov_iter_count(iter),
			  min(head - tail,
			      rb->size - tail_masked));
		if (!len)
			break;

		len = copy_to_iter(rb->data + tail_masked, len, iter);

		tail += len;
	}

	smp_store_release(&rb->ptrs->tail, tail);

	smp_mb();

	if (rb->ptrs->head - orig_tail >= rb->size)
		wake_up(&rb->wait[WRITE]);

	return tail - orig_tail;
}
EXPORT_SYMBOL_GPL(ringbuffer_read_iter);

ssize_t ringbuffer_write_iter(struct ringbuffer *rb, struct iov_iter *iter, bool nonblocking)
{
	u32 head = rb->ptrs->head, orig_head = head;
	u32 tail = smp_load_acquire(&rb->ptrs->tail);

	if (unlikely(head - tail >= rb->size)) {
		if (nonblocking)
			return -EAGAIN;
		int ret = wait_event_interruptible(rb->wait[WRITE],
			head - (tail = smp_load_acquire(&rb->ptrs->tail)) < rb->size);
		if (ret)
			return ret;
	}

	while (iov_iter_count(iter)) {
		u32 head_masked = head & rb->mask;
		u32 len = min(iov_iter_count(iter),
			  min(tail + rb->size - head,
			      rb->size - head_masked));
		if (!len)
			break;

		len = copy_from_iter(rb->data + head_masked, len, iter);

		head += len;
	}

	smp_store_release(&rb->ptrs->head, head);

	smp_mb();

	if ((s32) (rb->ptrs->tail - orig_head) >= 0)
		wake_up(&rb->wait[READ]);

	return head - orig_head;
}
EXPORT_SYMBOL_GPL(ringbuffer_write_iter);

SYSCALL_DEFINE2(ringbuffer_wait, unsigned, fd, int, rw)
{
	int ret = 0;

	if (rw > WRITE)
		return -EINVAL;

	struct fd f = fdget(fd);
	if (!f.file)
		return -EBADF;

	struct ringbuffer *rb = f.file->f_op->ringbuffer(f.file, rw);
	if (!rb) {
		ret = -EINVAL;
		goto err;
	}

	struct ringbuffer_desc *rp = rb->ptrs;
	wait_event(rb->wait[rw], rw == READ
		   ? rp->head != rp->tail
		   : rp->head - rp->tail < rb->size);
err:
	fdput(f);
	return ret;
}

SYSCALL_DEFINE2(ringbuffer_wakeup, unsigned, fd, int, rw)
{
	int ret = 0;

	if (rw > WRITE)
		return -EINVAL;

	struct fd f = fdget(fd);
	if (!f.file)
		return -EBADF;

	struct ringbuffer *rb = f.file->f_op->ringbuffer(f.file, rw);
	if (!rb) {
		ret = -EINVAL;
		goto err;
	}

	wake_up(&rb->wait[!rw]);
err:
	fdput(f);
	return ret;
}

static int ringbuffer_init_fs_context(struct fs_context *fc)
{
	if (!init_pseudo(fc, RINGBUFFER_FS_MAGIC))
		return -ENOMEM;
	fc->s_iflags |= SB_I_NOEXEC;
	return 0;
}

static int __init ringbuffer_init(void)
{
	static struct file_system_type ringbuffer_fs = {
		.name		= "ringbuffer",
		.init_fs_context = ringbuffer_init_fs_context,
		.kill_sb	= kill_anon_super,
	};
	ringbuffer_mnt = kern_mount(&ringbuffer_fs);
	if (IS_ERR(ringbuffer_mnt))
		panic("Failed to create ringbuffer fs mount.");
	return 0;
}
__initcall(ringbuffer_init);
