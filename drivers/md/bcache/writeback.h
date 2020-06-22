/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHE_WRITEBACK_H
#define _BCACHE_WRITEBACK_H

#define CUTOFF_WRITEBACK	40
#define CUTOFF_WRITEBACK_SYNC	70

#define CUTOFF_WRITEBACK_MAX		70
#define CUTOFF_WRITEBACK_SYNC_MAX	90

#define MAX_WRITEBACKS_IN_PASS  5
#define MAX_WRITESIZE_IN_PASS   5000	/* *512b */

#define WRITEBACK_RATE_UPDATE_SECS_MAX		60
#define WRITEBACK_RATE_UPDATE_SECS_DEFAULT	5

#define BCH_AUTO_GC_DIRTY_THRESHOLD	50

#define BCH_DIRTY_INIT_THRD_MAX	64
/*
 * 14 (16384ths) is chosen here as something that each backing device
 * should be a reasonable fraction of the share, and not to blow up
 * until individual backing devices are a petabyte.
 */
#define WRITEBACK_SHARE_SHIFT   14

struct bch_dirty_init_state;
struct dirty_init_thrd_info {
	struct bch_dirty_init_state	*state;
	struct task_struct		*thread;
};

struct bch_dirty_init_state {
	struct cache_set		*c;
	struct bcache_device		*d;
	int				total_threads;
	int				key_idx;
	spinlock_t			idx_lock;
	atomic_t			started;
	atomic_t			enough;
	wait_queue_head_t		wait;
	struct dirty_init_thrd_info	infos[BCH_DIRTY_INIT_THRD_MAX];
};

void bcache_dev_sectors_dirty_add(struct cache_set *c, unsigned int inode,
				  uint64_t offset, int nr_sectors);

void bch_sectors_dirty_init(struct bcache_device *d);
int bch_cached_dev_writeback_init(struct cached_dev *dc);
int bch_cached_dev_writeback_start(struct cached_dev *dc);

#endif
