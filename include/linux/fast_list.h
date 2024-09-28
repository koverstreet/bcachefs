#ifndef _LINUX_FAST_LIST_H
#define _LINUX_FAST_LIST_H

#include <linux/generic-radix-tree.h>
#include <linux/idr.h>
#include <linux/percpu.h>

struct fast_list_pcpu;

struct fast_list {
	GENRADIX(void *)	items;
	struct ida		slots_allocated;;
	struct fast_list_pcpu	*buffer;
};

int fast_list_get_idx(struct fast_list *l);
int fast_list_add(struct fast_list *l, void *item);
void fast_list_remove(struct fast_list *l, unsigned idx);
void fast_list_exit(struct fast_list *l);
int fast_list_init(struct fast_list *l);

#endif /* _LINUX_FAST_LIST_H */
