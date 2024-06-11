// SPDX-License-Identifier: GPL-2.0

#include <linux/generic-radix-tree.h>
#include <linux/percpu.h>
#include <linux/srcu.h>
#include "rcu_pending.h"

static inline unsigned long __get_state_synchronize_rcu(struct srcu_struct *ssp)
{
	return ssp
		? get_state_synchronize_srcu(ssp)
		: get_state_synchronize_rcu();
}

static inline unsigned long __start_poll_synchronize_rcu(struct srcu_struct *ssp)
{
	return ssp
		? start_poll_synchronize_srcu(ssp)
		: start_poll_synchronize_rcu();
}

static inline bool __poll_state_synchronize_rcu(struct srcu_struct *ssp, unsigned long cookie)
{
	return ssp
		? poll_state_synchronize_srcu(ssp, cookie)
		: poll_state_synchronize_rcu(cookie);
}

static inline void __rcu_barrier(struct srcu_struct *ssp)
{
	return ssp
		? srcu_barrier(ssp)
		: rcu_barrier();
}

static inline void __call_rcu(struct srcu_struct *ssp, struct rcu_head *rhp,
			      rcu_callback_t func)
{
	if (ssp)
		call_srcu(ssp, rhp, func);
	else
		call_rcu(rhp, func);
}

struct pending_rcu_items_seq {
	GENRADIX(struct rcu_head *)	objs;
	size_t				nr;
	struct rcu_head			*list;
	unsigned long			seq;
};

struct pending_rcu_items_pcpu {
	struct pending_rcu_items	*parent;
	spinlock_t			lock;
	int				cpu:31;
	bool				rcu_armed:1;
	struct pending_rcu_items_seq	objs[2];
	struct rcu_head			rcu;
	struct work_struct		work;
};

static bool objs_empty(struct pending_rcu_items_seq *objs)
{
	return !objs->nr && !objs->list;
}

static bool __pending_rcu_items_has_pending(struct pending_rcu_items_pcpu *p)
{
	for (struct pending_rcu_items_seq *objs = p->objs;
	     objs < p->objs + ARRAY_SIZE(p->objs); objs++)
		if (!objs_empty(objs))
			return true;
	return false;
}

static bool get_finished_items(struct pending_rcu_items *pending,
			       struct pending_rcu_items_pcpu *p,
			       struct pending_rcu_items_seq *out)
{
	for (struct pending_rcu_items_seq *objs = p->objs;
	     objs < p->objs + ARRAY_SIZE(p->objs); objs++)
		if (!objs_empty(objs) &&
		    __poll_state_synchronize_rcu(pending->srcu, objs->seq)) {
			*out = (struct pending_rcu_items_seq) {
				/*
				 * the genradix can only be modified with atomic instructions,
				 * since we allocate new nodes without
				 * pending_rcu_items_pcpu.lock
				 */
				.objs.tree.root	= xchg(&objs->objs.tree.root, NULL),
				.nr		= objs->nr,
				.list		= objs->list,
			};
			objs->nr	= 0;
			objs->list	= NULL;
			return true;
		}
	return false;
}

static void process_finished_items(struct pending_rcu_items *pending,
				   struct pending_rcu_items_seq *objs)
{
	for (size_t i = 0; i < objs->nr; i++)
		pending->process(pending, *genradix_ptr(&objs->objs, i));
	genradix_free(&objs->objs);

	while (objs->list) {
		struct rcu_head *obj = objs->list;
		objs->list = obj->next;
		pending->process(pending, obj);
	}
}

static void pending_rcu_items_rcu_cb(struct rcu_head *rcu)
{
	struct pending_rcu_items_pcpu *p =
		container_of(rcu, struct pending_rcu_items_pcpu, rcu);

	schedule_work_on(p->cpu, &p->work);
}

static void pending_rcu_items_work(struct work_struct *work)
{
	struct pending_rcu_items_pcpu *p =
		container_of(work, struct pending_rcu_items_pcpu, work);
	struct pending_rcu_items *pending = p->parent;
again:
	spin_lock_irq(&p->lock);
	struct pending_rcu_items_seq finished;
	if (get_finished_items(pending, p, &finished)) {
		spin_unlock_irq(&p->lock);
		process_finished_items(pending, &finished);
		goto again;
	}

	BUG_ON(!p->rcu_armed);
	p->rcu_armed = __pending_rcu_items_has_pending(p);
	if (p->rcu_armed)
		__call_rcu(pending->srcu, &p->rcu, pending_rcu_items_rcu_cb);
	spin_unlock_irq(&p->lock);
}

void bch2_pending_rcu_item_enqueue(struct pending_rcu_items *pending, struct rcu_head *obj)
{
	struct pending_rcu_items_pcpu *p = raw_cpu_ptr(pending->p);
	bool alloc_failed = false;
	unsigned long flags;
retry:
	spin_lock_irqsave(&p->lock, flags);

	struct pending_rcu_items_seq finished;
process_finished:
	if (get_finished_items(pending, p, &finished)) {
		spin_unlock_irqrestore(&p->lock, flags);
		process_finished_items(pending, &finished);
		goto retry;
	}

	struct pending_rcu_items_seq *objs;

	unsigned long seq = __get_state_synchronize_rcu(pending->srcu);
	for (objs = p->objs; objs < p->objs + ARRAY_SIZE(p->objs); objs++)
		if (!objs_empty(objs) && objs->seq == seq)
			goto add;

	seq = __start_poll_synchronize_rcu(pending->srcu);
	for (objs = p->objs; objs < p->objs + ARRAY_SIZE(p->objs); objs++)
		if (objs_empty(objs)) {
			objs->seq = seq;
			goto add;
		}

	goto process_finished;
	struct rcu_head **entry;
add:
	entry = genradix_ptr_alloc(&objs->objs, objs->nr, GFP_ATOMIC|__GFP_NOWARN);
	if (likely(entry)) {
		*entry = obj;
		objs->nr++;
	} else if (likely(!alloc_failed)) {
		spin_unlock_irqrestore(&p->lock, flags);
		alloc_failed = !genradix_ptr_alloc(&objs->objs, objs->nr, GFP_KERNEL);
		goto retry;
	} else {
		obj->next = objs->list;
		objs->list = obj;
	}

	if (!p->rcu_armed) {
		__call_rcu(pending->srcu, &p->rcu, pending_rcu_items_rcu_cb);
		p->rcu_armed = true;
	}
	spin_unlock_irqrestore(&p->lock, flags);
}

static struct rcu_head *pending_rcu_item_pcpu_dequeue(struct pending_rcu_items_pcpu *p)
{
	struct rcu_head *ret = NULL;

	spin_lock_irq(&p->lock);
	unsigned idx = p->objs[1].seq > p->objs[0].seq;

	for (unsigned i = 0; i < 2; i++, idx ^= 1) {
		struct pending_rcu_items_seq *objs = p->objs + idx;

		if (objs->nr) {
			ret = *genradix_ptr(&objs->objs, --objs->nr);
			break;
		}

		if (objs->list) {
			ret = objs->list;
			objs->list = ret->next;
			break;
		}
	}
	spin_unlock_irq(&p->lock);

	return ret;
}

struct rcu_head *bch2_pending_rcu_item_dequeue(struct pending_rcu_items *pending)
{
	return pending_rcu_item_pcpu_dequeue(raw_cpu_ptr(pending->p));
}

struct rcu_head *bch2_pending_rcu_item_dequeue_from_all(struct pending_rcu_items *pending)
{
	struct rcu_head *ret = NULL;
	int cpu;
	for_each_possible_cpu(cpu) {
		ret = pending_rcu_item_pcpu_dequeue(per_cpu_ptr(pending->p, cpu));
		if (ret)
			break;
	}
	return ret;
}

static bool pending_rcu_items_has_pending_or_armed(struct pending_rcu_items *pending)
{
	int cpu;
	for_each_possible_cpu(cpu) {
		struct pending_rcu_items_pcpu *p = per_cpu_ptr(pending->p, cpu);
		spin_lock_irq(&p->lock);
		if (__pending_rcu_items_has_pending(p) || p->rcu_armed) {
			spin_unlock_irq(&p->lock);
			return true;
		}
		spin_unlock_irq(&p->lock);
	}

	return false;
}

void bch2_pending_rcu_items_exit(struct pending_rcu_items *pending)
{
	int cpu;

	if (!pending->p)
		return;

	while (pending_rcu_items_has_pending_or_armed(pending)) {
		__rcu_barrier(pending->srcu);

		for_each_possible_cpu(cpu) {
			struct pending_rcu_items_pcpu *p = per_cpu_ptr(pending->p, cpu);
			flush_work(&p->work);
		}
	}

	for_each_possible_cpu(cpu) {
		struct pending_rcu_items_pcpu *p = per_cpu_ptr(pending->p, cpu);

		WARN_ON(p->objs[0].nr);
		WARN_ON(p->objs[1].nr);
		WARN_ON(p->objs[0].list);
		WARN_ON(p->objs[1].list);

		genradix_free(&p->objs[0].objs);
		genradix_free(&p->objs[1].objs);
	}
	free_percpu(pending->p);
}

int bch2_pending_rcu_items_init(struct pending_rcu_items *pending,
				struct srcu_struct *srcu,
				pending_rcu_item_process_fn process)
{
	pending->p = alloc_percpu(struct pending_rcu_items_pcpu);
	if (!pending->p)
		return -ENOMEM;

	int cpu;
	for_each_possible_cpu(cpu) {
		struct pending_rcu_items_pcpu *p = per_cpu_ptr(pending->p, cpu);
		p->parent	= pending;
		p->cpu		= cpu;
		spin_lock_init(&p->lock);
		INIT_WORK(&p->work, pending_rcu_items_work);
	}

	pending->srcu = srcu;
	pending->process = process;

	return 0;
}
