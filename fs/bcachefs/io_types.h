#ifndef _BCACHE_IO_TYPES_H
#define _BCACHE_IO_TYPES_H

#include <linux/llist.h>
#include <linux/workqueue.h>

struct bio_decompress_worker {
	struct work_struct		work;
	struct llist_head		bio_list;
};

#endif /* _BCACHE_IO_TYPES_H */
