/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BLKDEV_H
#define _LINUX_BLKDEV_H

#include <linux/sched.h>
#include <linux/genhd.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/minmax.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/bio.h>
#include <linux/gfp.h>
#include <linux/rcupdate.h>
#include <linux/percpu-refcount.h>
#include <linux/blkzoned.h>
#include <linux/sbitmap.h>

struct module;
struct request_queue;
struct elevator_queue;
struct blk_trace;
struct request;
struct sg_io_hdr;
struct blkcg_gq;
struct blk_flush_queue;
struct kiocb;
struct pr_ops;
struct rq_qos;
struct blk_queue_stats;
struct blk_stat_callback;
struct blk_crypto_profile;

/* Must be consistent with blk_mq_poll_stats_bkt() */
#define BLK_MQ_POLL_STATS_BKTS 16

/* Doing classic polling */
#define BLK_MQ_POLL_CLASSIC -1

/*
 * Maximum number of blkcg policies allowed to be registered concurrently.
 * Defined here to simplify include dependency.
 */
#define BLKCG_MAX_POLS		6

static inline int blk_validate_block_size(unsigned int bsize)
{
	if (bsize < 512 || bsize > PAGE_SIZE || !is_power_of_2(bsize))
		return -EINVAL;

	return 0;
}

static inline bool blk_op_is_passthrough(unsigned int op)
{
	op &= REQ_OP_MASK;
	return op == REQ_OP_DRV_IN || op == REQ_OP_DRV_OUT;
}

/*
 * Zoned block device models (zoned limit).
 *
 * Note: This needs to be ordered from the least to the most severe
 * restrictions for the inheritance in blk_stack_limits() to work.
 */
enum blk_zoned_model {
	BLK_ZONED_NONE = 0,	/* Regular block device */
	BLK_ZONED_HA,		/* Host-aware zoned block device */
	BLK_ZONED_HM,		/* Host-managed zoned block device */
};

/*
 * BLK_BOUNCE_NONE:	never bounce (default)
 * BLK_BOUNCE_HIGH:	bounce all highmem pages
 */
enum blk_bounce {
	BLK_BOUNCE_NONE,
	BLK_BOUNCE_HIGH,
};

struct queue_limits {
	enum blk_bounce		bounce;
	unsigned long		seg_boundary_mask;
	unsigned long		virt_boundary_mask;

	unsigned int		max_hw_sectors;
	unsigned int		max_dev_sectors;
	unsigned int		chunk_sectors;
	unsigned int		max_sectors;
	unsigned int		max_segment_size;
	unsigned int		physical_block_size;
	unsigned int		logical_block_size;
	unsigned int		alignment_offset;
	unsigned int		io_min;
	unsigned int		io_opt;
	unsigned int		max_discard_sectors;
	unsigned int		max_hw_discard_sectors;
	unsigned int		max_write_same_sectors;
	unsigned int		max_write_zeroes_sectors;
	unsigned int		max_zone_append_sectors;
	unsigned int		discard_granularity;
	unsigned int		discard_alignment;
	unsigned int		zone_write_granularity;

	unsigned short		max_segments;
	unsigned short		max_integrity_segments;
	unsigned short		max_discard_segments;

	unsigned char		misaligned;
	unsigned char		discard_misaligned;
	unsigned char		raid_partial_stripes_expensive;
	enum blk_zoned_model	zoned;
};

typedef int (*report_zones_cb)(struct blk_zone *zone, unsigned int idx,
			       void *data);

void blk_queue_set_zoned(struct gendisk *disk, enum blk_zoned_model model);

#ifdef CONFIG_BLK_DEV_ZONED

#define BLK_ALL_ZONES  ((unsigned int)-1)
int blkdev_report_zones(struct block_device *bdev, sector_t sector,
			unsigned int nr_zones, report_zones_cb cb, void *data);
unsigned int blkdev_nr_zones(struct gendisk *disk);
extern int blkdev_zone_mgmt(struct block_device *bdev, enum req_opf op,
			    sector_t sectors, sector_t nr_sectors,
			    gfp_t gfp_mask);
int blk_revalidate_disk_zones(struct gendisk *disk,
			      void (*update_driver_data)(struct gendisk *disk));

extern int blkdev_report_zones_ioctl(struct block_device *bdev, fmode_t mode,
				     unsigned int cmd, unsigned long arg);
extern int blkdev_zone_mgmt_ioctl(struct block_device *bdev, fmode_t mode,
				  unsigned int cmd, unsigned long arg);

#else /* CONFIG_BLK_DEV_ZONED */

static inline unsigned int blkdev_nr_zones(struct gendisk *disk)
{
	return 0;
}

static inline int blkdev_report_zones_ioctl(struct block_device *bdev,
					    fmode_t mode, unsigned int cmd,
					    unsigned long arg)
{
	return -ENOTTY;
}

static inline int blkdev_zone_mgmt_ioctl(struct block_device *bdev,
					 fmode_t mode, unsigned int cmd,
					 unsigned long arg)
{
	return -ENOTTY;
}

#endif /* CONFIG_BLK_DEV_ZONED */

/*
 * Independent access ranges: struct blk_independent_access_range describes
 * a range of contiguous sectors that can be accessed using device command
 * execution resources that are independent from the resources used for
 * other access ranges. This is typically found with single-LUN multi-actuator
 * HDDs where each access range is served by a different set of heads.
 * The set of independent ranges supported by the device is defined using
 * struct blk_independent_access_ranges. The independent ranges must not overlap
 * and must include all sectors within the disk capacity (no sector holes
 * allowed).
 * For a device with multiple ranges, requests targeting sectors in different
 * ranges can be executed in parallel. A request can straddle an access range
 * boundary.
 */
struct blk_independent_access_range {
	struct kobject		kobj;
	struct request_queue	*queue;
	sector_t		sector;
	sector_t		nr_sectors;
};

struct blk_independent_access_ranges {
	struct kobject				kobj;
	bool					sysfs_registered;
	unsigned int				nr_ia_ranges;
	struct blk_independent_access_range	ia_range[];
};

struct request_queue {
	struct request		*last_merge;
	struct elevator_queue	*elevator;

	struct percpu_ref	q_usage_counter;

	struct blk_queue_stats	*stats;
	struct rq_qos		*rq_qos;

	const struct blk_mq_ops	*mq_ops;

	/* sw queues */
	struct blk_mq_ctx __percpu	*queue_ctx;

	unsigned int		queue_depth;

	/* hw dispatch queues */
	struct blk_mq_hw_ctx	**queue_hw_ctx;
	unsigned int		nr_hw_queues;

	/*
	 * The queue owner gets to use this for whatever they like.
	 * ll_rw_blk doesn't touch it.
	 */
	void			*queuedata;

	/*
	 * various queue flags, see QUEUE_* below
	 */
	unsigned long		queue_flags;
	/*
	 * Number of contexts that have called blk_set_pm_only(). If this
	 * counter is above zero then only RQF_PM requests are processed.
	 */
	atomic_t		pm_only;

	/*
	 * ida allocated id for this queue.  Used to index queues from
	 * ioctx.
	 */
	int			id;

	spinlock_t		queue_lock;

	struct gendisk		*disk;

	/*
	 * queue kobject
	 */
	struct kobject kobj;

	/*
	 * mq queue kobject
	 */
	struct kobject *mq_kobj;

#ifdef  CONFIG_BLK_DEV_INTEGRITY
	struct blk_integrity integrity;
#endif	/* CONFIG_BLK_DEV_INTEGRITY */

#ifdef CONFIG_PM
	struct device		*dev;
	enum rpm_status		rpm_status;
#endif

	/*
	 * queue settings
	 */
	unsigned long		nr_requests;	/* Max # of requests */

	unsigned int		dma_pad_mask;
	unsigned int		dma_alignment;

#ifdef CONFIG_BLK_INLINE_ENCRYPTION
	struct blk_crypto_profile *crypto_profile;
#endif

	unsigned int		rq_timeout;
	int			poll_nsec;

	struct blk_stat_callback	*poll_cb;
	struct blk_rq_stat	poll_stat[BLK_MQ_POLL_STATS_BKTS];

	struct timer_list	timeout;
	struct work_struct	timeout_work;

	atomic_t		nr_active_requests_shared_tags;

	struct blk_mq_tags	*sched_shared_tags;

	struct list_head	icq_list;
#ifdef CONFIG_BLK_CGROUP
	DECLARE_BITMAP		(blkcg_pols, BLKCG_MAX_POLS);
	struct blkcg_gq		*root_blkg;
	struct list_head	blkg_list;
#endif

	struct queue_limits	limits;

	unsigned int		required_elevator_features;

#ifdef CONFIG_BLK_DEV_ZONED
	/*
	 * Zoned block device information for request dispatch control.
	 * nr_zones is the total number of zones of the device. This is always
	 * 0 for regular block devices. conv_zones_bitmap is a bitmap of nr_zones
	 * bits which indicates if a zone is conventional (bit set) or
	 * sequential (bit clear). seq_zones_wlock is a bitmap of nr_zones
	 * bits which indicates if a zone is write locked, that is, if a write
	 * request targeting the zone was dispatched. All three fields are
	 * initialized by the low level device driver (e.g. scsi/sd.c).
	 * Stacking drivers (device mappers) may or may not initialize
	 * these fields.
	 *
	 * Reads of this information must be protected with blk_queue_enter() /
	 * blk_queue_exit(). Modifying this information is only allowed while
	 * no requests are being processed. See also blk_mq_freeze_queue() and
	 * blk_mq_unfreeze_queue().
	 */
	unsigned int		nr_zones;
	unsigned long		*conv_zones_bitmap;
	unsigned long		*seq_zones_wlock;
	unsigned int		max_open_zones;
	unsigned int		max_active_zones;
#endif /* CONFIG_BLK_DEV_ZONED */

	int			node;
	struct mutex		debugfs_mutex;
#ifdef CONFIG_BLK_DEV_IO_TRACE
	struct blk_trace __rcu	*blk_trace;
#endif
	/*
	 * for flush operations
	 */
	struct blk_flush_queue	*fq;

	struct list_head	requeue_list;
	spinlock_t		requeue_lock;
	struct delayed_work	requeue_work;

	struct mutex		sysfs_lock;
	struct mutex		sysfs_dir_lock;

	/*
	 * for reusing dead hctx instance in case of updating
	 * nr_hw_queues
	 */
	struct list_head	unused_hctx_list;
	spinlock_t		unused_hctx_lock;

	int			mq_freeze_depth;

#ifdef CONFIG_BLK_DEV_THROTTLING
	/* Throttle data */
	struct throtl_data *td;
#endif
	struct rcu_head		rcu_head;
	wait_queue_head_t	mq_freeze_wq;
	/*
	 * Protect concurrent access to q_usage_counter by
	 * percpu_ref_kill() and percpu_ref_reinit().
	 */
	struct mutex		mq_freeze_lock;

	int			quiesce_depth;

	struct blk_mq_tag_set	*tag_set;
	struct list_head	tag_set_list;
	struct bio_set		bio_split;

	struct dentry		*debugfs_dir;

#ifdef CONFIG_BLK_DEBUG_FS
	struct dentry		*sched_debugfs_dir;
	struct dentry		*rqos_debugfs_dir;
#endif

	bool			mq_sysfs_init_done;

#define BLK_MAX_WRITE_HINTS	5
	u64			write_hints[BLK_MAX_WRITE_HINTS];

	/*
	 * Independent sector access ranges. This is always NULL for
	 * devices that do not have multiple independent access ranges.
	 */
	struct blk_independent_access_ranges *ia_ranges;
};

/* Keep blk_queue_flag_name[] in sync with the definitions below */
#define QUEUE_FLAG_STOPPED	0	/* queue is stopped */
#define QUEUE_FLAG_DYING	1	/* queue being torn down */
#define QUEUE_FLAG_NOMERGES     3	/* disable merge attempts */
#define QUEUE_FLAG_SAME_COMP	4	/* complete on same CPU-group */
#define QUEUE_FLAG_FAIL_IO	5	/* fake timeout */
#define QUEUE_FLAG_NONROT	6	/* non-rotational device (SSD) */
#define QUEUE_FLAG_VIRT		QUEUE_FLAG_NONROT /* paravirt device */
#define QUEUE_FLAG_IO_STAT	7	/* do disk/partitions IO accounting */
#define QUEUE_FLAG_DISCARD	8	/* supports DISCARD */
#define QUEUE_FLAG_NOXMERGES	9	/* No extended merges */
#define QUEUE_FLAG_ADD_RANDOM	10	/* Contributes to random pool */
#define QUEUE_FLAG_SECERASE	11	/* supports secure erase */
#define QUEUE_FLAG_SAME_FORCE	12	/* force complete on same CPU */
#define QUEUE_FLAG_DEAD		13	/* queue tear-down finished */
#define QUEUE_FLAG_INIT_DONE	14	/* queue is initialized */
#define QUEUE_FLAG_STABLE_WRITES 15	/* don't modify blks until WB is done */
#define QUEUE_FLAG_POLL		16	/* IO polling enabled if set */
#define QUEUE_FLAG_WC		17	/* Write back caching */
#define QUEUE_FLAG_FUA		18	/* device supports FUA writes */
#define QUEUE_FLAG_DAX		19	/* device supports DAX */
#define QUEUE_FLAG_STATS	20	/* track IO start and completion times */
#define QUEUE_FLAG_POLL_STATS	21	/* collecting stats for hybrid polling */
#define QUEUE_FLAG_REGISTERED	22	/* queue has been registered to a disk */
#define QUEUE_FLAG_QUIESCED	24	/* queue has been quiesced */
#define QUEUE_FLAG_PCI_P2PDMA	25	/* device supports PCI p2p requests */
#define QUEUE_FLAG_ZONE_RESETALL 26	/* supports Zone Reset All */
#define QUEUE_FLAG_RQ_ALLOC_TIME 27	/* record rq->alloc_time_ns */
#define QUEUE_FLAG_HCTX_ACTIVE	28	/* at least one blk-mq hctx is active */
#define QUEUE_FLAG_NOWAIT       29	/* device supports NOWAIT */

#define QUEUE_FLAG_MQ_DEFAULT	((1 << QUEUE_FLAG_IO_STAT) |		\
				 (1 << QUEUE_FLAG_SAME_COMP) |		\
				 (1 << QUEUE_FLAG_NOWAIT))

void blk_queue_flag_set(unsigned int flag, struct request_queue *q);
void blk_queue_flag_clear(unsigned int flag, struct request_queue *q);
bool blk_queue_flag_test_and_set(unsigned int flag, struct request_queue *q);

#define blk_queue_stopped(q)	test_bit(QUEUE_FLAG_STOPPED, &(q)->queue_flags)
#define blk_queue_dying(q)	test_bit(QUEUE_FLAG_DYING, &(q)->queue_flags)
#define blk_queue_dead(q)	test_bit(QUEUE_FLAG_DEAD, &(q)->queue_flags)
#define blk_queue_init_done(q)	test_bit(QUEUE_FLAG_INIT_DONE, &(q)->queue_flags)
#define blk_queue_nomerges(q)	test_bit(QUEUE_FLAG_NOMERGES, &(q)->queue_flags)
#define blk_queue_noxmerges(q)	\
	test_bit(QUEUE_FLAG_NOXMERGES, &(q)->queue_flags)
#define blk_queue_nonrot(q)	test_bit(QUEUE_FLAG_NONROT, &(q)->queue_flags)
#define blk_queue_stable_writes(q) \
	test_bit(QUEUE_FLAG_STABLE_WRITES, &(q)->queue_flags)
#define blk_queue_io_stat(q)	test_bit(QUEUE_FLAG_IO_STAT, &(q)->queue_flags)
#define blk_queue_add_random(q)	test_bit(QUEUE_FLAG_ADD_RANDOM, &(q)->queue_flags)
#define blk_queue_discard(q)	test_bit(QUEUE_FLAG_DISCARD, &(q)->queue_flags)
#define blk_queue_zone_resetall(q)	\
	test_bit(QUEUE_FLAG_ZONE_RESETALL, &(q)->queue_flags)
#define blk_queue_secure_erase(q) \
	(test_bit(QUEUE_FLAG_SECERASE, &(q)->queue_flags))
#define blk_queue_dax(q)	test_bit(QUEUE_FLAG_DAX, &(q)->queue_flags)
#define blk_queue_pci_p2pdma(q)	\
	test_bit(QUEUE_FLAG_PCI_P2PDMA, &(q)->queue_flags)
#ifdef CONFIG_BLK_RQ_ALLOC_TIME
#define blk_queue_rq_alloc_time(q)	\
	test_bit(QUEUE_FLAG_RQ_ALLOC_TIME, &(q)->queue_flags)
#else
#define blk_queue_rq_alloc_time(q)	false
#endif

#define blk_noretry_request(rq) \
	((rq)->cmd_flags & (REQ_FAILFAST_DEV|REQ_FAILFAST_TRANSPORT| \
			     REQ_FAILFAST_DRIVER))
#define blk_queue_quiesced(q)	test_bit(QUEUE_FLAG_QUIESCED, &(q)->queue_flags)
#define blk_queue_pm_only(q)	atomic_read(&(q)->pm_only)
#define blk_queue_fua(q)	test_bit(QUEUE_FLAG_FUA, &(q)->queue_flags)
#define blk_queue_registered(q)	test_bit(QUEUE_FLAG_REGISTERED, &(q)->queue_flags)
#define blk_queue_nowait(q)	test_bit(QUEUE_FLAG_NOWAIT, &(q)->queue_flags)

extern void blk_set_pm_only(struct request_queue *q);
extern void blk_clear_pm_only(struct request_queue *q);

#define list_entry_rq(ptr)	list_entry((ptr), struct request, queuelist)

#define dma_map_bvec(dev, bv, dir, attrs) \
	dma_map_page_attrs(dev, (bv)->bv_page, (bv)->bv_offset, (bv)->bv_len, \
	(dir), (attrs))

static inline bool queue_is_mq(struct request_queue *q)
{
	return q->mq_ops;
}

#ifdef CONFIG_PM
static inline enum rpm_status queue_rpm_status(struct request_queue *q)
{
	return q->rpm_status;
}
#else
static inline enum rpm_status queue_rpm_status(struct request_queue *q)
{
	return RPM_ACTIVE;
}
#endif

static inline enum blk_zoned_model
blk_queue_zoned_model(struct request_queue *q)
{
	if (IS_ENABLED(CONFIG_BLK_DEV_ZONED))
		return q->limits.zoned;
	return BLK_ZONED_NONE;
}

static inline bool blk_queue_is_zoned(struct request_queue *q)
{
	switch (blk_queue_zoned_model(q)) {
	case BLK_ZONED_HA:
	case BLK_ZONED_HM:
		return true;
	default:
		return false;
	}
}

static inline sector_t blk_queue_zone_sectors(struct request_queue *q)
{
	return blk_queue_is_zoned(q) ? q->limits.chunk_sectors : 0;
}

#ifdef CONFIG_BLK_DEV_ZONED
static inline unsigned int blk_queue_nr_zones(struct request_queue *q)
{
	return blk_queue_is_zoned(q) ? q->nr_zones : 0;
}

static inline unsigned int blk_queue_zone_no(struct request_queue *q,
					     sector_t sector)
{
	if (!blk_queue_is_zoned(q))
		return 0;
	return sector >> ilog2(q->limits.chunk_sectors);
}

static inline bool blk_queue_zone_is_seq(struct request_queue *q,
					 sector_t sector)
{
	if (!blk_queue_is_zoned(q))
		return false;
	if (!q->conv_zones_bitmap)
		return true;
	return !test_bit(blk_queue_zone_no(q, sector), q->conv_zones_bitmap);
}

static inline void blk_queue_max_open_zones(struct request_queue *q,
		unsigned int max_open_zones)
{
	q->max_open_zones = max_open_zones;
}

static inline unsigned int queue_max_open_zones(const struct request_queue *q)
{
	return q->max_open_zones;
}

static inline void blk_queue_max_active_zones(struct request_queue *q,
		unsigned int max_active_zones)
{
	q->max_active_zones = max_active_zones;
}

static inline unsigned int queue_max_active_zones(const struct request_queue *q)
{
	return q->max_active_zones;
}
#else /* CONFIG_BLK_DEV_ZONED */
static inline unsigned int blk_queue_nr_zones(struct request_queue *q)
{
	return 0;
}
static inline bool blk_queue_zone_is_seq(struct request_queue *q,
					 sector_t sector)
{
	return false;
}
static inline unsigned int blk_queue_zone_no(struct request_queue *q,
					     sector_t sector)
{
	return 0;
}
static inline unsigned int queue_max_open_zones(const struct request_queue *q)
{
	return 0;
}
static inline unsigned int queue_max_active_zones(const struct request_queue *q)
{
	return 0;
}
#endif /* CONFIG_BLK_DEV_ZONED */

static inline unsigned int blk_queue_depth(struct request_queue *q)
{
	if (q->queue_depth)
		return q->queue_depth;

	return q->nr_requests;
}

/*
 * default timeout for SG_IO if none specified
 */
#define BLK_DEFAULT_SG_TIMEOUT	(60 * HZ)
#define BLK_MIN_SG_TIMEOUT	(7 * HZ)

/* This should not be used directly - use rq_for_each_segment */
#define for_each_bio(_bio)		\
	for (; _bio; _bio = _bio->bi_next)


extern int blk_register_queue(struct gendisk *disk);
extern void blk_unregister_queue(struct gendisk *disk);
void submit_bio_noacct(struct bio *bio);

extern int blk_lld_busy(struct request_queue *q);
extern void blk_queue_split(struct bio **);
extern int blk_queue_enter(struct request_queue *q, blk_mq_req_flags_t flags);
extern void blk_queue_exit(struct request_queue *q);
extern void blk_sync_queue(struct request_queue *q);

/* Helper to convert REQ_OP_XXX to its string format XXX */
extern const char *blk_op_str(unsigned int op);

int blk_status_to_errno(blk_status_t status);
blk_status_t errno_to_blk_status(int errno);

/* only poll the hardware once, don't continue until a completion was found */
#define BLK_POLL_ONESHOT		(1 << 0)
/* do not sleep to wait for the expected completion time */
#define BLK_POLL_NOSLEEP		(1 << 1)
int bio_poll(struct bio *bio, struct io_comp_batch *iob, unsigned int flags);
int iocb_bio_iopoll(struct kiocb *kiocb, struct io_comp_batch *iob,
			unsigned int flags);

static inline struct request_queue *bdev_get_queue(struct block_device *bdev)
{
	return bdev->bd_queue;	/* this is never NULL */
}

#ifdef CONFIG_BLK_DEV_ZONED

/* Helper to convert BLK_ZONE_ZONE_XXX to its string format XXX */
const char *blk_zone_cond_str(enum blk_zone_cond zone_cond);

static inline unsigned int bio_zone_no(struct bio *bio)
{
	return blk_queue_zone_no(bdev_get_queue(bio->bi_bdev),
				 bio->bi_iter.bi_sector);
}

static inline unsigned int bio_zone_is_seq(struct bio *bio)
{
	return blk_queue_zone_is_seq(bdev_get_queue(bio->bi_bdev),
				     bio->bi_iter.bi_sector);
}
#endif /* CONFIG_BLK_DEV_ZONED */

static inline unsigned int blk_queue_get_max_sectors(struct request_queue *q,
						     int op)
{
	if (unlikely(op == REQ_OP_DISCARD || op == REQ_OP_SECURE_ERASE))
		return min(q->limits.max_discard_sectors,
			   UINT_MAX >> SECTOR_SHIFT);

	if (unlikely(op == REQ_OP_WRITE_SAME))
		return q->limits.max_write_same_sectors;

	if (unlikely(op == REQ_OP_WRITE_ZEROES))
		return q->limits.max_write_zeroes_sectors;

	return q->limits.max_sectors;
}

/*
 * Return maximum size of a request at given offset. Only valid for
 * file system requests.
 */
static inline unsigned int blk_max_size_offset(struct request_queue *q,
					       sector_t offset,
					       unsigned int chunk_sectors)
{
	if (!chunk_sectors) {
		if (q->limits.chunk_sectors)
			chunk_sectors = q->limits.chunk_sectors;
		else
			return q->limits.max_sectors;
	}

	if (likely(is_power_of_2(chunk_sectors)))
		chunk_sectors -= offset & (chunk_sectors - 1);
	else
		chunk_sectors -= sector_div(offset, chunk_sectors);

	return min(q->limits.max_sectors, chunk_sectors);
}

/*
 * Access functions for manipulating queue properties
 */
extern void blk_cleanup_queue(struct request_queue *);
void blk_queue_bounce_limit(struct request_queue *q, enum blk_bounce limit);
extern void blk_queue_max_hw_sectors(struct request_queue *, unsigned int);
extern void blk_queue_chunk_sectors(struct request_queue *, unsigned int);
extern void blk_queue_max_segments(struct request_queue *, unsigned short);
extern void blk_queue_max_discard_segments(struct request_queue *,
		unsigned short);
extern void blk_queue_max_segment_size(struct request_queue *, unsigned int);
extern void blk_queue_max_discard_sectors(struct request_queue *q,
		unsigned int max_discard_sectors);
extern void blk_queue_max_write_same_sectors(struct request_queue *q,
		unsigned int max_write_same_sectors);
extern void blk_queue_max_write_zeroes_sectors(struct request_queue *q,
		unsigned int max_write_same_sectors);
extern void blk_queue_logical_block_size(struct request_queue *, unsigned int);
extern void blk_queue_max_zone_append_sectors(struct request_queue *q,
		unsigned int max_zone_append_sectors);
extern void blk_queue_physical_block_size(struct request_queue *, unsigned int);
void blk_queue_zone_write_granularity(struct request_queue *q,
				      unsigned int size);
extern void blk_queue_alignment_offset(struct request_queue *q,
				       unsigned int alignment);
void disk_update_readahead(struct gendisk *disk);
extern void blk_limits_io_min(struct queue_limits *limits, unsigned int min);
extern void blk_queue_io_min(struct request_queue *q, unsigned int min);
extern void blk_limits_io_opt(struct queue_limits *limits, unsigned int opt);
extern void blk_queue_io_opt(struct request_queue *q, unsigned int opt);
extern void blk_set_queue_depth(struct request_queue *q, unsigned int depth);
extern void blk_set_default_limits(struct queue_limits *lim);
extern void blk_set_stacking_limits(struct queue_limits *lim);
extern int blk_stack_limits(struct queue_limits *t, struct queue_limits *b,
			    sector_t offset);
extern void disk_stack_limits(struct gendisk *disk, struct block_device *bdev,
			      sector_t offset);
extern void blk_queue_update_dma_pad(struct request_queue *, unsigned int);
extern void blk_queue_segment_boundary(struct request_queue *, unsigned long);
extern void blk_queue_virt_boundary(struct request_queue *, unsigned long);
extern void blk_queue_dma_alignment(struct request_queue *, int);
extern void blk_queue_update_dma_alignment(struct request_queue *, int);
extern void blk_queue_rq_timeout(struct request_queue *, unsigned int);
extern void blk_queue_write_cache(struct request_queue *q, bool enabled, bool fua);

struct blk_independent_access_ranges *
disk_alloc_independent_access_ranges(struct gendisk *disk, int nr_ia_ranges);
void disk_set_independent_access_ranges(struct gendisk *disk,
				struct blk_independent_access_ranges *iars);

/*
 * Elevator features for blk_queue_required_elevator_features:
 */
/* Supports zoned block devices sequential write constraint */
#define ELEVATOR_F_ZBD_SEQ_WRITE	(1U << 0)
/* Supports scheduling on multiple hardware queues */
#define ELEVATOR_F_MQ_AWARE		(1U << 1)

extern void blk_queue_required_elevator_features(struct request_queue *q,
						 unsigned int features);
extern bool blk_queue_can_use_dma_map_merging(struct request_queue *q,
					      struct device *dev);

bool __must_check blk_get_queue(struct request_queue *);
extern void blk_put_queue(struct request_queue *);
extern void blk_set_queue_dying(struct request_queue *);

#ifdef CONFIG_BLOCK
/*
 * blk_plug permits building a queue of related requests by holding the I/O
 * fragments for a short period. This allows merging of sequential requests
 * into single larger request. As the requests are moved from a per-task list to
 * the device's request_queue in a batch, this results in improved scalability
 * as the lock contention for request_queue lock is reduced.
 *
 * It is ok not to disable preemption when adding the request to the plug list
 * or when attempting a merge. For details, please see schedule() where
 * blk_flush_plug() is called.
 */
struct blk_plug {
	struct request *mq_list; /* blk-mq requests */

	/* if ios_left is > 1, we can batch tag/rq allocations */
	struct request *cached_rq;
	unsigned short nr_ios;

	unsigned short rq_count;

	bool multiple_queues;
	bool has_elevator;
	bool nowait;

	struct list_head cb_list; /* md requires an unplug callback */
};

struct blk_plug_cb;
typedef void (*blk_plug_cb_fn)(struct blk_plug_cb *, bool);
struct blk_plug_cb {
	struct list_head list;
	blk_plug_cb_fn callback;
	void *data;
};
extern struct blk_plug_cb *blk_check_plugged(blk_plug_cb_fn unplug,
					     void *data, int size);
extern void blk_start_plug(struct blk_plug *);
extern void blk_start_plug_nr_ios(struct blk_plug *, unsigned short);
extern void blk_finish_plug(struct blk_plug *);

void blk_flush_plug(struct blk_plug *plug, bool from_schedule);

static inline bool blk_needs_flush_plug(struct task_struct *tsk)
{
	struct blk_plug *plug = tsk->plug;

	return plug &&
		 (plug->mq_list || !list_empty(&plug->cb_list));
}

int blkdev_issue_flush(struct block_device *bdev);
long nr_blockdev_pages(void);
#else /* CONFIG_BLOCK */
struct blk_plug {
};

static inline void blk_start_plug_nr_ios(struct blk_plug *plug,
					 unsigned short nr_ios)
{
}

static inline void blk_start_plug(struct blk_plug *plug)
{
}

static inline void blk_finish_plug(struct blk_plug *plug)
{
}

static inline void blk_flush_plug(struct blk_plug *plug, bool async)
{
}

static inline bool blk_needs_flush_plug(struct task_struct *tsk)
{
	return false;
}

static inline int blkdev_issue_flush(struct block_device *bdev)
{
	return 0;
}

static inline long nr_blockdev_pages(void)
{
	return 0;
}
#endif /* CONFIG_BLOCK */

extern void blk_io_schedule(void);

extern int blkdev_issue_write_same(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, struct page *page);

#define BLKDEV_DISCARD_SECURE	(1 << 0)	/* issue a secure erase */

extern int blkdev_issue_discard(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, unsigned long flags);
extern int __blkdev_issue_discard(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, int flags,
		struct bio **biop);

#define BLKDEV_ZERO_NOUNMAP	(1 << 0)  /* do not free blocks */
#define BLKDEV_ZERO_NOFALLBACK	(1 << 1)  /* don't write explicit zeroes */

extern int __blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, struct bio **biop,
		unsigned flags);
extern int blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, unsigned flags);

static inline int sb_issue_discard(struct super_block *sb, sector_t block,
		sector_t nr_blocks, gfp_t gfp_mask, unsigned long flags)
{
	return blkdev_issue_discard(sb->s_bdev,
				    block << (sb->s_blocksize_bits -
					      SECTOR_SHIFT),
				    nr_blocks << (sb->s_blocksize_bits -
						  SECTOR_SHIFT),
				    gfp_mask, flags);
}
static inline int sb_issue_zeroout(struct super_block *sb, sector_t block,
		sector_t nr_blocks, gfp_t gfp_mask)
{
	return blkdev_issue_zeroout(sb->s_bdev,
				    block << (sb->s_blocksize_bits -
					      SECTOR_SHIFT),
				    nr_blocks << (sb->s_blocksize_bits -
						  SECTOR_SHIFT),
				    gfp_mask, 0);
}

static inline bool bdev_is_partition(struct block_device *bdev)
{
	return bdev->bd_partno;
}

enum blk_default_limits {
	BLK_MAX_SEGMENTS	= 128,
	BLK_SAFE_MAX_SECTORS	= 255,
	BLK_DEF_MAX_SECTORS	= 2560,
	BLK_MAX_SEGMENT_SIZE	= 65536,
	BLK_SEG_BOUNDARY_MASK	= 0xFFFFFFFFUL,
};

static inline unsigned long queue_segment_boundary(const struct request_queue *q)
{
	return q->limits.seg_boundary_mask;
}

static inline unsigned long queue_virt_boundary(const struct request_queue *q)
{
	return q->limits.virt_boundary_mask;
}

static inline unsigned int queue_max_sectors(const struct request_queue *q)
{
	return q->limits.max_sectors;
}

static inline unsigned int queue_max_bytes(struct request_queue *q)
{
	return min_t(unsigned int, queue_max_sectors(q), INT_MAX >> 9) << 9;
}

static inline unsigned int queue_max_hw_sectors(const struct request_queue *q)
{
	return q->limits.max_hw_sectors;
}

static inline unsigned short queue_max_segments(const struct request_queue *q)
{
	return q->limits.max_segments;
}

static inline unsigned short queue_max_discard_segments(const struct request_queue *q)
{
	return q->limits.max_discard_segments;
}

static inline unsigned int queue_max_segment_size(const struct request_queue *q)
{
	return q->limits.max_segment_size;
}

static inline unsigned int queue_max_zone_append_sectors(const struct request_queue *q)
{

	const struct queue_limits *l = &q->limits;

	return min(l->max_zone_append_sectors, l->max_sectors);
}

static inline unsigned queue_logical_block_size(const struct request_queue *q)
{
	int retval = 512;

	if (q && q->limits.logical_block_size)
		retval = q->limits.logical_block_size;

	return retval;
}

static inline unsigned int bdev_logical_block_size(struct block_device *bdev)
{
	return queue_logical_block_size(bdev_get_queue(bdev));
}

static inline unsigned int queue_physical_block_size(const struct request_queue *q)
{
	return q->limits.physical_block_size;
}

static inline unsigned int bdev_physical_block_size(struct block_device *bdev)
{
	return queue_physical_block_size(bdev_get_queue(bdev));
}

static inline unsigned int queue_io_min(const struct request_queue *q)
{
	return q->limits.io_min;
}

static inline int bdev_io_min(struct block_device *bdev)
{
	return queue_io_min(bdev_get_queue(bdev));
}

static inline unsigned int queue_io_opt(const struct request_queue *q)
{
	return q->limits.io_opt;
}

static inline int bdev_io_opt(struct block_device *bdev)
{
	return queue_io_opt(bdev_get_queue(bdev));
}

static inline unsigned int
queue_zone_write_granularity(const struct request_queue *q)
{
	return q->limits.zone_write_granularity;
}

static inline unsigned int
bdev_zone_write_granularity(struct block_device *bdev)
{
	return queue_zone_write_granularity(bdev_get_queue(bdev));
}

static inline int queue_alignment_offset(const struct request_queue *q)
{
	if (q->limits.misaligned)
		return -1;

	return q->limits.alignment_offset;
}

static inline int queue_limit_alignment_offset(struct queue_limits *lim, sector_t sector)
{
	unsigned int granularity = max(lim->physical_block_size, lim->io_min);
	unsigned int alignment = sector_div(sector, granularity >> SECTOR_SHIFT)
		<< SECTOR_SHIFT;

	return (granularity + lim->alignment_offset - alignment) % granularity;
}

static inline int bdev_alignment_offset(struct block_device *bdev)
{
	struct request_queue *q = bdev_get_queue(bdev);

	if (q->limits.misaligned)
		return -1;
	if (bdev_is_partition(bdev))
		return queue_limit_alignment_offset(&q->limits,
				bdev->bd_start_sect);
	return q->limits.alignment_offset;
}

static inline int queue_discard_alignment(const struct request_queue *q)
{
	if (q->limits.discard_misaligned)
		return -1;

	return q->limits.discard_alignment;
}

static inline int queue_limit_discard_alignment(struct queue_limits *lim, sector_t sector)
{
	unsigned int alignment, granularity, offset;

	if (!lim->max_discard_sectors)
		return 0;

	/* Why are these in bytes, not sectors? */
	alignment = lim->discard_alignment >> SECTOR_SHIFT;
	granularity = lim->discard_granularity >> SECTOR_SHIFT;
	if (!granularity)
		return 0;

	/* Offset of the partition start in 'granularity' sectors */
	offset = sector_div(sector, granularity);

	/* And why do we do this modulus *again* in blkdev_issue_discard()? */
	offset = (granularity + alignment - offset) % granularity;

	/* Turn it back into bytes, gaah */
	return offset << SECTOR_SHIFT;
}

static inline int bdev_discard_alignment(struct block_device *bdev)
{
	struct request_queue *q = bdev_get_queue(bdev);

	if (bdev_is_partition(bdev))
		return queue_limit_discard_alignment(&q->limits,
				bdev->bd_start_sect);
	return q->limits.discard_alignment;
}

static inline unsigned int bdev_write_same(struct block_device *bdev)
{
	struct request_queue *q = bdev_get_queue(bdev);

	if (q)
		return q->limits.max_write_same_sectors;

	return 0;
}

static inline unsigned int bdev_write_zeroes_sectors(struct block_device *bdev)
{
	struct request_queue *q = bdev_get_queue(bdev);

	if (q)
		return q->limits.max_write_zeroes_sectors;

	return 0;
}

static inline enum blk_zoned_model bdev_zoned_model(struct block_device *bdev)
{
	struct request_queue *q = bdev_get_queue(bdev);

	if (q)
		return blk_queue_zoned_model(q);

	return BLK_ZONED_NONE;
}

static inline bool bdev_is_zoned(struct block_device *bdev)
{
	struct request_queue *q = bdev_get_queue(bdev);

	if (q)
		return blk_queue_is_zoned(q);

	return false;
}

static inline sector_t bdev_zone_sectors(struct block_device *bdev)
{
	struct request_queue *q = bdev_get_queue(bdev);

	if (q)
		return blk_queue_zone_sectors(q);
	return 0;
}

static inline unsigned int bdev_max_open_zones(struct block_device *bdev)
{
	struct request_queue *q = bdev_get_queue(bdev);

	if (q)
		return queue_max_open_zones(q);
	return 0;
}

static inline unsigned int bdev_max_active_zones(struct block_device *bdev)
{
	struct request_queue *q = bdev_get_queue(bdev);

	if (q)
		return queue_max_active_zones(q);
	return 0;
}

static inline int queue_dma_alignment(const struct request_queue *q)
{
	return q ? q->dma_alignment : 511;
}

static inline int blk_rq_aligned(struct request_queue *q, unsigned long addr,
				 unsigned int len)
{
	unsigned int alignment = queue_dma_alignment(q) | q->dma_pad_mask;
	return !(addr & alignment) && !(len & alignment);
}

/* assumes size > 256 */
static inline unsigned int blksize_bits(unsigned int size)
{
	unsigned int bits = 8;
	do {
		bits++;
		size >>= 1;
	} while (size > 256);
	return bits;
}

static inline unsigned int block_size(struct block_device *bdev)
{
	return 1 << bdev->bd_inode->i_blkbits;
}

int kblockd_schedule_work(struct work_struct *work);
int kblockd_mod_delayed_work_on(int cpu, struct delayed_work *dwork, unsigned long delay);

#define MODULE_ALIAS_BLOCKDEV(major,minor) \
	MODULE_ALIAS("block-major-" __stringify(major) "-" __stringify(minor))
#define MODULE_ALIAS_BLOCKDEV_MAJOR(major) \
	MODULE_ALIAS("block-major-" __stringify(major) "-*")

#ifdef CONFIG_BLK_INLINE_ENCRYPTION

bool blk_crypto_register(struct blk_crypto_profile *profile,
			 struct request_queue *q);

void blk_crypto_unregister(struct request_queue *q);

#else /* CONFIG_BLK_INLINE_ENCRYPTION */

static inline bool blk_crypto_register(struct blk_crypto_profile *profile,
				       struct request_queue *q)
{
	return true;
}

static inline void blk_crypto_unregister(struct request_queue *q) { }

#endif /* CONFIG_BLK_INLINE_ENCRYPTION */

enum blk_unique_id {
	/* these match the Designator Types specified in SPC */
	BLK_UID_T10	= 1,
	BLK_UID_EUI64	= 2,
	BLK_UID_NAA	= 3,
};

#define NFL4_UFLG_MASK			0x0000003F

struct block_device_operations {
	void (*submit_bio)(struct bio *bio);
	int (*open) (struct block_device *, fmode_t);
	void (*release) (struct gendisk *, fmode_t);
	int (*rw_page)(struct block_device *, sector_t, struct page *, unsigned int);
	int (*ioctl) (struct block_device *, fmode_t, unsigned, unsigned long);
	int (*compat_ioctl) (struct block_device *, fmode_t, unsigned, unsigned long);
	unsigned int (*check_events) (struct gendisk *disk,
				      unsigned int clearing);
	void (*unlock_native_capacity) (struct gendisk *);
	int (*getgeo)(struct block_device *, struct hd_geometry *);
	int (*set_read_only)(struct block_device *bdev, bool ro);
	/* this callback is with swap_lock and sometimes page table lock held */
	void (*swap_slot_free_notify) (struct block_device *, unsigned long);
	int (*report_zones)(struct gendisk *, sector_t sector,
			unsigned int nr_zones, report_zones_cb cb, void *data);
	char *(*devnode)(struct gendisk *disk, umode_t *mode);
	/* returns the length of the identifier or a negative errno: */
	int (*get_unique_id)(struct gendisk *disk, u8 id[16],
			enum blk_unique_id id_type);
	struct module *owner;
	const struct pr_ops *pr_ops;

	/*
	 * Special callback for probing GPT entry at a given sector.
	 * Needed by Android devices, used by GPT scanner and MMC blk
	 * driver.
	 */
	int (*alternative_gpt_sector)(struct gendisk *disk, sector_t *sector);
};

#ifdef CONFIG_COMPAT
extern int blkdev_compat_ptr_ioctl(struct block_device *, fmode_t,
				      unsigned int, unsigned long);
#else
#define blkdev_compat_ptr_ioctl NULL
#endif

extern int bdev_read_page(struct block_device *, sector_t, struct page *);
extern int bdev_write_page(struct block_device *, sector_t, struct page *,
						struct writeback_control *);

static inline void blk_wake_io_task(struct task_struct *waiter)
{
	/*
	 * If we're polling, the task itself is doing the completions. For
	 * that case, we don't need to signal a wakeup, it's enough to just
	 * mark us as RUNNING.
	 */
	if (waiter == current)
		__set_current_state(TASK_RUNNING);
	else
		wake_up_process(waiter);
}

unsigned long disk_start_io_acct(struct gendisk *disk, unsigned int sectors,
		unsigned int op);
void disk_end_io_acct(struct gendisk *disk, unsigned int op,
		unsigned long start_time);

void bio_start_io_acct_time(struct bio *bio, unsigned long start_time);
unsigned long bio_start_io_acct(struct bio *bio);
void bio_end_io_acct_remapped(struct bio *bio, unsigned long start_time,
		struct block_device *orig_bdev);

/**
 * bio_end_io_acct - end I/O accounting for bio based drivers
 * @bio:	bio to end account for
 * @start:	start time returned by bio_start_io_acct()
 */
static inline void bio_end_io_acct(struct bio *bio, unsigned long start_time)
{
	return bio_end_io_acct_remapped(bio, start_time, bio->bi_bdev);
}

int bdev_read_only(struct block_device *bdev);
int set_blocksize(struct block_device *bdev, int size);

const char *bdevname(struct block_device *bdev, char *buffer);
int lookup_bdev(const char *pathname, dev_t *dev);

void blkdev_show(struct seq_file *seqf, off_t offset);

#define BDEVNAME_SIZE	32	/* Largest string for a blockdev identifier */
#define BDEVT_SIZE	10	/* Largest string for MAJ:MIN for blkdev */
#ifdef CONFIG_BLOCK
#define BLKDEV_MAJOR_MAX	512
#else
#define BLKDEV_MAJOR_MAX	0
#endif

struct block_device *blkdev_get_by_path(const char *path, fmode_t mode,
		void *holder);
struct block_device *blkdev_get_by_dev(dev_t dev, fmode_t mode, void *holder);
int bd_prepare_to_claim(struct block_device *bdev, void *holder);
void bd_abort_claiming(struct block_device *bdev, void *holder);
void blkdev_put(struct block_device *bdev, fmode_t mode);

/* just for blk-cgroup, don't use elsewhere */
struct block_device *blkdev_get_no_open(dev_t dev);
void blkdev_put_no_open(struct block_device *bdev);

struct block_device *bdev_alloc(struct gendisk *disk, u8 partno);
void bdev_add(struct block_device *bdev, dev_t dev);
struct block_device *I_BDEV(struct inode *inode);
int truncate_bdev_range(struct block_device *bdev, fmode_t mode, loff_t lstart,
		loff_t lend);

#ifdef CONFIG_BLOCK
void invalidate_bdev(struct block_device *bdev);
int sync_blockdev(struct block_device *bdev);
int sync_blockdev_nowait(struct block_device *bdev);
void sync_bdevs(bool wait);
#else
static inline void invalidate_bdev(struct block_device *bdev)
{
}
static inline int sync_blockdev(struct block_device *bdev)
{
	return 0;
}
static inline int sync_blockdev_nowait(struct block_device *bdev)
{
	return 0;
}
static inline void sync_bdevs(bool wait)
{
}
#endif
int fsync_bdev(struct block_device *bdev);

int freeze_bdev(struct block_device *bdev);
int thaw_bdev(struct block_device *bdev);

struct io_comp_batch {
	struct request *req_list;
	bool need_ts;
	void (*complete)(struct io_comp_batch *);
};

#define DEFINE_IO_COMP_BATCH(name)	struct io_comp_batch name = { }

#define rq_list_add(listptr, rq)	do {		\
	(rq)->rq_next = *(listptr);			\
	*(listptr) = rq;				\
} while (0)

#define rq_list_pop(listptr)				\
({							\
	struct request *__req = NULL;			\
	if ((listptr) && *(listptr))	{		\
		__req = *(listptr);			\
		*(listptr) = __req->rq_next;		\
	}						\
	__req;						\
})

#define rq_list_peek(listptr)				\
({							\
	struct request *__req = NULL;			\
	if ((listptr) && *(listptr))			\
		__req = *(listptr);			\
	__req;						\
})

#define rq_list_for_each(listptr, pos)			\
	for (pos = rq_list_peek((listptr)); pos; pos = rq_list_next(pos)) \

#define rq_list_next(rq)	(rq)->rq_next
#define rq_list_empty(list)	((list) == (struct request *) NULL)

#endif /* _LINUX_BLKDEV_H */
