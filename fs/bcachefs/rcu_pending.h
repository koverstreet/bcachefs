/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BCACHEFS_RCU_PENDING_H
#define _BCACHEFS_RCU_PENDING_H

struct pending_rcu_items;
typedef void (*pending_rcu_item_process_fn)(struct pending_rcu_items *, struct rcu_head *);

struct pending_rcu_items_pcpu;

struct pending_rcu_items {
	struct pending_rcu_items_pcpu __percpu *p;
	struct srcu_struct		*srcu;
	pending_rcu_item_process_fn	process;
};

void bch2_pending_rcu_item_enqueue(struct pending_rcu_items *pending, struct rcu_head *obj);
struct rcu_head *bch2_pending_rcu_item_dequeue(struct pending_rcu_items *pending);
struct rcu_head *bch2_pending_rcu_item_dequeue_from_all(struct pending_rcu_items *pending);

void bch2_pending_rcu_items_exit(struct pending_rcu_items *pending);
int bch2_pending_rcu_items_init(struct pending_rcu_items *pending,
				struct srcu_struct *srcu,
				pending_rcu_item_process_fn process);

#endif /* _BCACHEFS_RCU_PENDING_H */
