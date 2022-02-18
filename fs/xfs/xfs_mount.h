// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __XFS_MOUNT_H__
#define	__XFS_MOUNT_H__

struct xlog;
struct xfs_inode;
struct xfs_mru_cache;
struct xfs_ail;
struct xfs_quotainfo;
struct xfs_da_geometry;
struct xfs_perag;

/* dynamic preallocation free space thresholds, 5% down to 1% */
enum {
	XFS_LOWSP_1_PCNT = 0,
	XFS_LOWSP_2_PCNT,
	XFS_LOWSP_3_PCNT,
	XFS_LOWSP_4_PCNT,
	XFS_LOWSP_5_PCNT,
	XFS_LOWSP_MAX,
};

/*
 * Error Configuration
 *
 * Error classes define the subsystem the configuration belongs to.
 * Error numbers define the errors that are configurable.
 */
enum {
	XFS_ERR_METADATA,
	XFS_ERR_CLASS_MAX,
};
enum {
	XFS_ERR_DEFAULT,
	XFS_ERR_EIO,
	XFS_ERR_ENOSPC,
	XFS_ERR_ENODEV,
	XFS_ERR_ERRNO_MAX,
};

#define XFS_ERR_RETRY_FOREVER	-1

/*
 * Although retry_timeout is in jiffies which is normally an unsigned long,
 * we limit the retry timeout to 86400 seconds, or one day.  So even a
 * signed 32-bit long is sufficient for a HZ value up to 24855.  Making it
 * signed lets us store the special "-1" value, meaning retry forever.
 */
struct xfs_error_cfg {
	struct xfs_kobj	kobj;
	int		max_retries;
	long		retry_timeout;	/* in jiffies, -1 = infinite */
};

/*
 * Per-cpu deferred inode inactivation GC lists.
 */
struct xfs_inodegc {
	struct llist_head	list;
	struct work_struct	work;

	/* approximate count of inodes in the list */
	unsigned int		items;
	unsigned int		shrinker_hits;
};

/*
 * The struct xfsmount layout is optimised to separate read-mostly variables
 * from variables that are frequently modified. We put the read-mostly variables
 * first, then place all the other variables at the end.
 *
 * Typically, read-mostly variables are those that are set at mount time and
 * never changed again, or only change rarely as a result of things like sysfs
 * knobs being tweaked.
 */
typedef struct xfs_mount {
	struct xfs_sb		m_sb;		/* copy of fs superblock */
	struct super_block	*m_super;
	struct xfs_ail		*m_ail;		/* fs active log item list */
	struct xfs_buf		*m_sb_bp;	/* buffer for superblock */
	char			*m_rtname;	/* realtime device name */
	char			*m_logname;	/* external log device name */
	struct xfs_da_geometry	*m_dir_geo;	/* directory block geometry */
	struct xfs_da_geometry	*m_attr_geo;	/* attribute block geometry */
	struct xlog		*m_log;		/* log specific stuff */
	struct xfs_inode	*m_rbmip;	/* pointer to bitmap inode */
	struct xfs_inode	*m_rsumip;	/* pointer to summary inode */
	struct xfs_inode	*m_rootip;	/* pointer to root directory */
	struct xfs_quotainfo	*m_quotainfo;	/* disk quota information */
	xfs_buftarg_t		*m_ddev_targp;	/* saves taking the address */
	xfs_buftarg_t		*m_logdev_targp;/* ptr to log device */
	xfs_buftarg_t		*m_rtdev_targp;	/* ptr to rt device */
	struct list_head	m_mount_list;	/* global mount list */
	void __percpu		*m_inodegc;	/* percpu inodegc structures */

	/*
	 * Optional cache of rt summary level per bitmap block with the
	 * invariant that m_rsum_cache[bbno] <= the minimum i for which
	 * rsum[i][bbno] != 0. Reads and writes are serialized by the rsumip
	 * inode lock.
	 */
	uint8_t			*m_rsum_cache;
	struct xfs_mru_cache	*m_filestream;  /* per-mount filestream data */
	struct workqueue_struct *m_buf_workqueue;
	struct workqueue_struct	*m_unwritten_workqueue;
	struct workqueue_struct	*m_reclaim_workqueue;
	struct workqueue_struct	*m_sync_workqueue;
	struct workqueue_struct *m_blockgc_wq;
	struct workqueue_struct *m_inodegc_wq;

	int			m_bsize;	/* fs logical block size */
	uint8_t			m_blkbit_log;	/* blocklog + NBBY */
	uint8_t			m_blkbb_log;	/* blocklog - BBSHIFT */
	uint8_t			m_agno_log;	/* log #ag's */
	uint8_t			m_sectbb_log;	/* sectlog - BBSHIFT */
	uint			m_blockmask;	/* sb_blocksize-1 */
	uint			m_blockwsize;	/* sb_blocksize in words */
	uint			m_blockwmask;	/* blockwsize-1 */
	uint			m_alloc_mxr[2];	/* max alloc btree records */
	uint			m_alloc_mnr[2];	/* min alloc btree records */
	uint			m_bmap_dmxr[2];	/* max bmap btree records */
	uint			m_bmap_dmnr[2];	/* min bmap btree records */
	uint			m_rmap_mxr[2];	/* max rmap btree records */
	uint			m_rmap_mnr[2];	/* min rmap btree records */
	uint			m_refc_mxr[2];	/* max refc btree records */
	uint			m_refc_mnr[2];	/* min refc btree records */
	uint			m_alloc_maxlevels; /* max alloc btree levels */
	uint			m_bm_maxlevels[2]; /* max bmap btree levels */
	uint			m_rmap_maxlevels; /* max rmap btree levels */
	uint			m_refc_maxlevels; /* max refcount btree level */
	unsigned int		m_agbtree_maxlevels; /* max level of all AG btrees */
	xfs_extlen_t		m_ag_prealloc_blocks; /* reserved ag blocks */
	uint			m_alloc_set_aside; /* space we can't use */
	uint			m_ag_max_usable; /* max space per AG */
	int			m_dalign;	/* stripe unit */
	int			m_swidth;	/* stripe width */
	xfs_agnumber_t		m_maxagi;	/* highest inode alloc group */
	uint			m_allocsize_log;/* min write size log bytes */
	uint			m_allocsize_blocks; /* min write size blocks */
	int			m_logbufs;	/* number of log buffers */
	int			m_logbsize;	/* size of each log buffer */
	uint			m_rsumlevels;	/* rt summary levels */
	uint			m_rsumsize;	/* size of rt summary, bytes */
	int			m_fixedfsid[2];	/* unchanged for life of FS */
	uint			m_qflags;	/* quota status flags */
	uint64_t		m_features;	/* active filesystem features */
	uint64_t		m_low_space[XFS_LOWSP_MAX];
	uint64_t		m_low_rtexts[XFS_LOWSP_MAX];
	struct xfs_ino_geometry	m_ino_geo;	/* inode geometry */
	struct xfs_trans_resv	m_resv;		/* precomputed res values */
						/* low free space thresholds */
	unsigned long		m_opstate;	/* dynamic state flags */
	bool			m_always_cow;
	bool			m_fail_unmount;
	bool			m_finobt_nores; /* no per-AG finobt resv. */
	bool			m_update_sb;	/* sb needs update in mount */

	/*
	 * Bitsets of per-fs metadata that have been checked and/or are sick.
	 * Callers must hold m_sb_lock to access these two fields.
	 */
	uint8_t			m_fs_checked;
	uint8_t			m_fs_sick;
	/*
	 * Bitsets of rt metadata that have been checked and/or are sick.
	 * Callers must hold m_sb_lock to access this field.
	 */
	uint8_t			m_rt_checked;
	uint8_t			m_rt_sick;

	/*
	 * End of read-mostly variables. Frequently written variables and locks
	 * should be placed below this comment from now on. The first variable
	 * here is marked as cacheline aligned so they it is separated from
	 * the read-mostly variables.
	 */

	spinlock_t ____cacheline_aligned m_sb_lock; /* sb counter lock */
	struct percpu_counter	m_icount;	/* allocated inodes counter */
	struct percpu_counter	m_ifree;	/* free inodes counter */
	struct percpu_counter	m_fdblocks;	/* free block counter */
	/*
	 * Count of data device blocks reserved for delayed allocations,
	 * including indlen blocks.  Does not include allocated CoW staging
	 * extents or anything related to the rt device.
	 */
	struct percpu_counter	m_delalloc_blks;
	/*
	 * Global count of allocation btree blocks in use across all AGs. Only
	 * used when perag reservation is enabled. Helps prevent block
	 * reservation from attempting to reserve allocation btree blocks.
	 */
	atomic64_t		m_allocbt_blks;

	struct radix_tree_root	m_perag_tree;	/* per-ag accounting info */
	spinlock_t		m_perag_lock;	/* lock for m_perag_tree */
	uint64_t		m_resblks;	/* total reserved blocks */
	uint64_t		m_resblks_avail;/* available reserved blocks */
	uint64_t		m_resblks_save;	/* reserved blks @ remount,ro */
	struct delayed_work	m_reclaim_work;	/* background inode reclaim */
	struct xfs_kobj		m_kobj;
	struct xfs_kobj		m_error_kobj;
	struct xfs_kobj		m_error_meta_kobj;
	struct xfs_error_cfg	m_error_cfg[XFS_ERR_CLASS_MAX][XFS_ERR_ERRNO_MAX];
	struct xstats		m_stats;	/* per-fs stats */
	xfs_agnumber_t		m_agfrotor;	/* last ag where space found */
	xfs_agnumber_t		m_agirotor;	/* last ag dir inode alloced */
	spinlock_t		m_agirotor_lock;/* .. and lock protecting it */

	/* Memory shrinker to throttle and reprioritize inodegc */
	struct shrinker		m_inodegc_shrinker;
	/*
	 * Workqueue item so that we can coalesce multiple inode flush attempts
	 * into a single flush.
	 */
	struct work_struct	m_flush_inodes_work;

	/*
	 * Generation of the filesysyem layout.  This is incremented by each
	 * growfs, and used by the pNFS server to ensure the client updates
	 * its view of the block device once it gets a layout that might
	 * reference the newly added blocks.  Does not need to be persistent
	 * as long as we only allow file system size increments, but if we
	 * ever support shrinks it would have to be persisted in addition
	 * to various other kinds of pain inflicted on the pNFS server.
	 */
	uint32_t		m_generation;
	struct mutex		m_growlock;	/* growfs mutex */

#ifdef DEBUG
	/*
	 * Frequency with which errors are injected.  Replaces xfs_etest; the
	 * value stored in here is the inverse of the frequency with which the
	 * error triggers.  1 = always, 2 = half the time, etc.
	 */
	unsigned int		*m_errortag;
	struct xfs_kobj		m_errortag_kobj;
#endif
} xfs_mount_t;

#define M_IGEO(mp)		(&(mp)->m_ino_geo)

/*
 * Flags for m_features.
 *
 * These are all the active features in the filesystem, regardless of how
 * they are configured.
 */
#define XFS_FEAT_ATTR		(1ULL << 0)	/* xattrs present in fs */
#define XFS_FEAT_NLINK		(1ULL << 1)	/* 32 bit link counts */
#define XFS_FEAT_QUOTA		(1ULL << 2)	/* quota active */
#define XFS_FEAT_ALIGN		(1ULL << 3)	/* inode alignment */
#define XFS_FEAT_DALIGN		(1ULL << 4)	/* data alignment */
#define XFS_FEAT_LOGV2		(1ULL << 5)	/* version 2 logs */
#define XFS_FEAT_SECTOR		(1ULL << 6)	/* sector size > 512 bytes */
#define XFS_FEAT_EXTFLG		(1ULL << 7)	/* unwritten extents */
#define XFS_FEAT_ASCIICI	(1ULL << 8)	/* ASCII only case-insens. */
#define XFS_FEAT_LAZYSBCOUNT	(1ULL << 9)	/* Superblk counters */
#define XFS_FEAT_ATTR2		(1ULL << 10)	/* dynamic attr fork */
#define XFS_FEAT_PARENT		(1ULL << 11)	/* parent pointers */
#define XFS_FEAT_PROJID32	(1ULL << 12)	/* 32 bit project id */
#define XFS_FEAT_CRC		(1ULL << 13)	/* metadata CRCs */
#define XFS_FEAT_V3INODES	(1ULL << 14)	/* Version 3 inodes */
#define XFS_FEAT_PQUOTINO	(1ULL << 15)	/* non-shared proj/grp quotas */
#define XFS_FEAT_FTYPE		(1ULL << 16)	/* inode type in dir */
#define XFS_FEAT_FINOBT		(1ULL << 17)	/* free inode btree */
#define XFS_FEAT_RMAPBT		(1ULL << 18)	/* reverse map btree */
#define XFS_FEAT_REFLINK	(1ULL << 19)	/* reflinked files */
#define XFS_FEAT_SPINODES	(1ULL << 20)	/* sparse inode chunks */
#define XFS_FEAT_META_UUID	(1ULL << 21)	/* metadata UUID */
#define XFS_FEAT_REALTIME	(1ULL << 22)	/* realtime device present */
#define XFS_FEAT_INOBTCNT	(1ULL << 23)	/* inobt block counts */
#define XFS_FEAT_BIGTIME	(1ULL << 24)	/* large timestamps */
#define XFS_FEAT_NEEDSREPAIR	(1ULL << 25)	/* needs xfs_repair */

/* Mount features */
#define XFS_FEAT_NOATTR2	(1ULL << 48)	/* disable attr2 creation */
#define XFS_FEAT_NOALIGN	(1ULL << 49)	/* ignore alignment */
#define XFS_FEAT_ALLOCSIZE	(1ULL << 50)	/* user specified allocation size */
#define XFS_FEAT_LARGE_IOSIZE	(1ULL << 51)	/* report large preferred
						 * I/O size in stat() */
#define XFS_FEAT_WSYNC		(1ULL << 52)	/* synchronous metadata ops */
#define XFS_FEAT_DIRSYNC	(1ULL << 53)	/* synchronous directory ops */
#define XFS_FEAT_DISCARD	(1ULL << 54)	/* discard unused blocks */
#define XFS_FEAT_GRPID		(1ULL << 55)	/* group-ID assigned from directory */
#define XFS_FEAT_SMALL_INUMS	(1ULL << 56)	/* user wants 32bit inodes */
#define XFS_FEAT_IKEEP		(1ULL << 57)	/* keep empty inode clusters*/
#define XFS_FEAT_SWALLOC	(1ULL << 58)	/* stripe width allocation */
#define XFS_FEAT_FILESTREAMS	(1ULL << 59)	/* use filestreams allocator */
#define XFS_FEAT_DAX_ALWAYS	(1ULL << 60)	/* DAX always enabled */
#define XFS_FEAT_DAX_NEVER	(1ULL << 61)	/* DAX never enabled */
#define XFS_FEAT_NORECOVERY	(1ULL << 62)	/* no recovery - dirty fs */
#define XFS_FEAT_NOUUID		(1ULL << 63)	/* ignore uuid during mount */

#define __XFS_HAS_FEAT(name, NAME) \
static inline bool xfs_has_ ## name (struct xfs_mount *mp) \
{ \
	return mp->m_features & XFS_FEAT_ ## NAME; \
}

/* Some features can be added dynamically so they need a set wrapper, too. */
#define __XFS_ADD_FEAT(name, NAME) \
	__XFS_HAS_FEAT(name, NAME); \
static inline void xfs_add_ ## name (struct xfs_mount *mp) \
{ \
	mp->m_features |= XFS_FEAT_ ## NAME; \
	xfs_sb_version_add ## name(&mp->m_sb); \
}

/* Superblock features */
__XFS_ADD_FEAT(attr, ATTR)
__XFS_HAS_FEAT(nlink, NLINK)
__XFS_ADD_FEAT(quota, QUOTA)
__XFS_HAS_FEAT(align, ALIGN)
__XFS_HAS_FEAT(dalign, DALIGN)
__XFS_HAS_FEAT(logv2, LOGV2)
__XFS_HAS_FEAT(sector, SECTOR)
__XFS_HAS_FEAT(extflg, EXTFLG)
__XFS_HAS_FEAT(asciici, ASCIICI)
__XFS_HAS_FEAT(lazysbcount, LAZYSBCOUNT)
__XFS_ADD_FEAT(attr2, ATTR2)
__XFS_HAS_FEAT(parent, PARENT)
__XFS_ADD_FEAT(projid32, PROJID32)
__XFS_HAS_FEAT(crc, CRC)
__XFS_HAS_FEAT(v3inodes, V3INODES)
__XFS_HAS_FEAT(pquotino, PQUOTINO)
__XFS_HAS_FEAT(ftype, FTYPE)
__XFS_HAS_FEAT(finobt, FINOBT)
__XFS_HAS_FEAT(rmapbt, RMAPBT)
__XFS_HAS_FEAT(reflink, REFLINK)
__XFS_HAS_FEAT(sparseinodes, SPINODES)
__XFS_HAS_FEAT(metauuid, META_UUID)
__XFS_HAS_FEAT(realtime, REALTIME)
__XFS_HAS_FEAT(inobtcounts, INOBTCNT)
__XFS_HAS_FEAT(bigtime, BIGTIME)
__XFS_HAS_FEAT(needsrepair, NEEDSREPAIR)

/*
 * Mount features
 *
 * These do not change dynamically - features that can come and go, such as 32
 * bit inodes and read-only state, are kept as operational state rather than
 * features.
 */
__XFS_HAS_FEAT(noattr2, NOATTR2)
__XFS_HAS_FEAT(noalign, NOALIGN)
__XFS_HAS_FEAT(allocsize, ALLOCSIZE)
__XFS_HAS_FEAT(large_iosize, LARGE_IOSIZE)
__XFS_HAS_FEAT(wsync, WSYNC)
__XFS_HAS_FEAT(dirsync, DIRSYNC)
__XFS_HAS_FEAT(discard, DISCARD)
__XFS_HAS_FEAT(grpid, GRPID)
__XFS_HAS_FEAT(small_inums, SMALL_INUMS)
__XFS_HAS_FEAT(ikeep, IKEEP)
__XFS_HAS_FEAT(swalloc, SWALLOC)
__XFS_HAS_FEAT(filestreams, FILESTREAMS)
__XFS_HAS_FEAT(dax_always, DAX_ALWAYS)
__XFS_HAS_FEAT(dax_never, DAX_NEVER)
__XFS_HAS_FEAT(norecovery, NORECOVERY)
__XFS_HAS_FEAT(nouuid, NOUUID)

/*
 * Operational mount state flags
 *
 * Use these with atomic bit ops only!
 */
#define XFS_OPSTATE_UNMOUNTING		0	/* filesystem is unmounting */
#define XFS_OPSTATE_CLEAN		1	/* mount was clean */
#define XFS_OPSTATE_SHUTDOWN		2	/* stop all fs operations */
#define XFS_OPSTATE_INODE32		3	/* inode32 allocator active */
#define XFS_OPSTATE_READONLY		4	/* read-only fs */

/*
 * If set, inactivation worker threads will be scheduled to process queued
 * inodegc work.  If not, queued inodes remain in memory waiting to be
 * processed.
 */
#define XFS_OPSTATE_INODEGC_ENABLED	5
/*
 * If set, background speculative prealloc gc worker threads will be scheduled
 * to process queued blockgc work.  If not, inodes retain their preallocations
 * until explicitly deleted.
 */
#define XFS_OPSTATE_BLOCKGC_ENABLED	6

#define __XFS_IS_OPSTATE(name, NAME) \
static inline bool xfs_is_ ## name (struct xfs_mount *mp) \
{ \
	return test_bit(XFS_OPSTATE_ ## NAME, &mp->m_opstate); \
} \
static inline bool xfs_clear_ ## name (struct xfs_mount *mp) \
{ \
	return test_and_clear_bit(XFS_OPSTATE_ ## NAME, &mp->m_opstate); \
} \
static inline bool xfs_set_ ## name (struct xfs_mount *mp) \
{ \
	return test_and_set_bit(XFS_OPSTATE_ ## NAME, &mp->m_opstate); \
}

__XFS_IS_OPSTATE(unmounting, UNMOUNTING)
__XFS_IS_OPSTATE(clean, CLEAN)
__XFS_IS_OPSTATE(shutdown, SHUTDOWN)
__XFS_IS_OPSTATE(inode32, INODE32)
__XFS_IS_OPSTATE(readonly, READONLY)
__XFS_IS_OPSTATE(inodegc_enabled, INODEGC_ENABLED)
__XFS_IS_OPSTATE(blockgc_enabled, BLOCKGC_ENABLED)

#define XFS_OPSTATE_STRINGS \
	{ (1UL << XFS_OPSTATE_UNMOUNTING),		"unmounting" }, \
	{ (1UL << XFS_OPSTATE_CLEAN),			"clean" }, \
	{ (1UL << XFS_OPSTATE_SHUTDOWN),		"shutdown" }, \
	{ (1UL << XFS_OPSTATE_INODE32),			"inode32" }, \
	{ (1UL << XFS_OPSTATE_READONLY),		"read_only" }, \
	{ (1UL << XFS_OPSTATE_INODEGC_ENABLED),		"inodegc" }, \
	{ (1UL << XFS_OPSTATE_BLOCKGC_ENABLED),		"blockgc" }

/*
 * Max and min values for mount-option defined I/O
 * preallocation sizes.
 */
#define XFS_MAX_IO_LOG		30	/* 1G */
#define XFS_MIN_IO_LOG		PAGE_SHIFT

#define xfs_is_shutdown(mp)		xfs_is_shutdown(mp)
void xfs_do_force_shutdown(struct xfs_mount *mp, int flags, char *fname,
		int lnnum);
#define xfs_force_shutdown(m,f)	\
	xfs_do_force_shutdown(m, f, __FILE__, __LINE__)

#define SHUTDOWN_META_IO_ERROR	0x0001	/* write attempt to metadata failed */
#define SHUTDOWN_LOG_IO_ERROR	0x0002	/* write attempt to the log failed */
#define SHUTDOWN_FORCE_UMOUNT	0x0004	/* shutdown from a forced unmount */
#define SHUTDOWN_CORRUPT_INCORE	0x0008	/* corrupt in-memory data structures */

#define XFS_SHUTDOWN_STRINGS \
	{ SHUTDOWN_META_IO_ERROR,	"metadata_io" }, \
	{ SHUTDOWN_LOG_IO_ERROR,	"log_io" }, \
	{ SHUTDOWN_FORCE_UMOUNT,	"force_umount" }, \
	{ SHUTDOWN_CORRUPT_INCORE,	"corruption" }

/*
 * Flags for xfs_mountfs
 */
#define XFS_MFSI_QUIET		0x40	/* Be silent if mount errors found */

static inline xfs_agnumber_t
xfs_daddr_to_agno(struct xfs_mount *mp, xfs_daddr_t d)
{
	xfs_rfsblock_t ld = XFS_BB_TO_FSBT(mp, d);
	do_div(ld, mp->m_sb.sb_agblocks);
	return (xfs_agnumber_t) ld;
}

static inline xfs_agblock_t
xfs_daddr_to_agbno(struct xfs_mount *mp, xfs_daddr_t d)
{
	xfs_rfsblock_t ld = XFS_BB_TO_FSBT(mp, d);
	return (xfs_agblock_t) do_div(ld, mp->m_sb.sb_agblocks);
}

int xfs_buf_hash_init(struct xfs_perag *pag);
void xfs_buf_hash_destroy(struct xfs_perag *pag);

extern void	xfs_uuid_table_free(void);
extern uint64_t xfs_default_resblks(xfs_mount_t *mp);
extern int	xfs_mountfs(xfs_mount_t *mp);
extern void	xfs_unmountfs(xfs_mount_t *);

/*
 * Deltas for the block count can vary from 1 to very large, but lock contention
 * only occurs on frequent small block count updates such as in the delayed
 * allocation path for buffered writes (page a time updates). Hence we set
 * a large batch count (1024) to minimise global counter updates except when
 * we get near to ENOSPC and we have to be very accurate with our updates.
 */
#define XFS_FDBLOCKS_BATCH	1024

extern int	xfs_mod_fdblocks(struct xfs_mount *mp, int64_t delta,
				 bool reserved);
extern int	xfs_mod_frextents(struct xfs_mount *mp, int64_t delta);

extern int	xfs_readsb(xfs_mount_t *, int);
extern void	xfs_freesb(xfs_mount_t *);
extern bool	xfs_fs_writable(struct xfs_mount *mp, int level);
extern int	xfs_sb_validate_fsb_count(struct xfs_sb *, uint64_t);

extern int	xfs_dev_is_read_only(struct xfs_mount *, char *);

extern void	xfs_set_low_space_thresholds(struct xfs_mount *);

int	xfs_zero_extent(struct xfs_inode *ip, xfs_fsblock_t start_fsb,
			xfs_off_t count_fsb);

struct xfs_error_cfg * xfs_error_get_cfg(struct xfs_mount *mp,
		int error_class, int error);
void xfs_force_summary_recalc(struct xfs_mount *mp);
int xfs_add_incompat_log_feature(struct xfs_mount *mp, uint32_t feature);
bool xfs_clear_incompat_log_features(struct xfs_mount *mp);
void xfs_mod_delalloc(struct xfs_mount *mp, int64_t delta);

#endif	/* __XFS_MOUNT_H__ */
