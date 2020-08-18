// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2017-2020 Mellanox Technologies. All rights reserved */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <net/flow_offload.h>

#include "spectrum.h"
#include "spectrum_span.h"
#include "reg.h"

enum mlxsw_sp_mall_action_type {
	MLXSW_SP_MALL_ACTION_TYPE_MIRROR,
	MLXSW_SP_MALL_ACTION_TYPE_SAMPLE,
};

struct mlxsw_sp_mall_mirror_entry {
	const struct net_device *to_dev;
	int span_id;
};

struct mlxsw_sp_mall_entry {
	struct list_head list;
	unsigned long cookie;
	unsigned int priority;
	enum mlxsw_sp_mall_action_type type;
	bool ingress;
	union {
		struct mlxsw_sp_mall_mirror_entry mirror;
		struct mlxsw_sp_port_sample sample;
	};
	struct rcu_head rcu;
};

static struct mlxsw_sp_mall_entry *
mlxsw_sp_mall_entry_find(struct mlxsw_sp_flow_block *block, unsigned long cookie)
{
	struct mlxsw_sp_mall_entry *mall_entry;

	list_for_each_entry(mall_entry, &block->mall.list, list)
		if (mall_entry->cookie == cookie)
			return mall_entry;

	return NULL;
}

static int
mlxsw_sp_mall_port_mirror_add(struct mlxsw_sp_port *mlxsw_sp_port,
			      struct mlxsw_sp_mall_entry *mall_entry)
{
	struct mlxsw_sp *mlxsw_sp = mlxsw_sp_port->mlxsw_sp;
	struct mlxsw_sp_span_trigger_parms parms;
	enum mlxsw_sp_span_trigger trigger;
	int err;

	if (!mall_entry->mirror.to_dev) {
		netdev_err(mlxsw_sp_port->dev, "Could not find requested device\n");
		return -EINVAL;
	}

	err = mlxsw_sp_span_agent_get(mlxsw_sp, mall_entry->mirror.to_dev,
				      &mall_entry->mirror.span_id);
	if (err)
		return err;

	err = mlxsw_sp_span_analyzed_port_get(mlxsw_sp_port,
					      mall_entry->ingress);
	if (err)
		goto err_analyzed_port_get;

	trigger = mall_entry->ingress ? MLXSW_SP_SPAN_TRIGGER_INGRESS :
					MLXSW_SP_SPAN_TRIGGER_EGRESS;
	parms.span_id = mall_entry->mirror.span_id;
	err = mlxsw_sp_span_agent_bind(mlxsw_sp, trigger, mlxsw_sp_port,
				       &parms);
	if (err)
		goto err_agent_bind;

	return 0;

err_agent_bind:
	mlxsw_sp_span_analyzed_port_put(mlxsw_sp_port, mall_entry->ingress);
err_analyzed_port_get:
	mlxsw_sp_span_agent_put(mlxsw_sp, mall_entry->mirror.span_id);
	return err;
}

static void
mlxsw_sp_mall_port_mirror_del(struct mlxsw_sp_port *mlxsw_sp_port,
			      struct mlxsw_sp_mall_entry *mall_entry)
{
	struct mlxsw_sp *mlxsw_sp = mlxsw_sp_port->mlxsw_sp;
	struct mlxsw_sp_span_trigger_parms parms;
	enum mlxsw_sp_span_trigger trigger;

	trigger = mall_entry->ingress ? MLXSW_SP_SPAN_TRIGGER_INGRESS :
					MLXSW_SP_SPAN_TRIGGER_EGRESS;
	parms.span_id = mall_entry->mirror.span_id;
	mlxsw_sp_span_agent_unbind(mlxsw_sp, trigger, mlxsw_sp_port, &parms);
	mlxsw_sp_span_analyzed_port_put(mlxsw_sp_port, mall_entry->ingress);
	mlxsw_sp_span_agent_put(mlxsw_sp, mall_entry->mirror.span_id);
}

static int mlxsw_sp_mall_port_sample_set(struct mlxsw_sp_port *mlxsw_sp_port,
					 bool enable, u32 rate)
{
	struct mlxsw_sp *mlxsw_sp = mlxsw_sp_port->mlxsw_sp;
	char mpsc_pl[MLXSW_REG_MPSC_LEN];

	mlxsw_reg_mpsc_pack(mpsc_pl, mlxsw_sp_port->local_port, enable, rate);
	return mlxsw_reg_write(mlxsw_sp->core, MLXSW_REG(mpsc), mpsc_pl);
}

static int
mlxsw_sp_mall_port_sample_add(struct mlxsw_sp_port *mlxsw_sp_port,
			      struct mlxsw_sp_mall_entry *mall_entry)
{
	int err;

	if (rtnl_dereference(mlxsw_sp_port->sample)) {
		netdev_err(mlxsw_sp_port->dev, "sample already active\n");
		return -EEXIST;
	}
	rcu_assign_pointer(mlxsw_sp_port->sample, &mall_entry->sample);

	err = mlxsw_sp_mall_port_sample_set(mlxsw_sp_port, true,
					    mall_entry->sample.rate);
	if (err)
		goto err_port_sample_set;
	return 0;

err_port_sample_set:
	RCU_INIT_POINTER(mlxsw_sp_port->sample, NULL);
	return err;
}

static void
mlxsw_sp_mall_port_sample_del(struct mlxsw_sp_port *mlxsw_sp_port)
{
	if (!mlxsw_sp_port->sample)
		return;

	mlxsw_sp_mall_port_sample_set(mlxsw_sp_port, false, 1);
	RCU_INIT_POINTER(mlxsw_sp_port->sample, NULL);
}

static int
mlxsw_sp_mall_port_rule_add(struct mlxsw_sp_port *mlxsw_sp_port,
			    struct mlxsw_sp_mall_entry *mall_entry)
{
	switch (mall_entry->type) {
	case MLXSW_SP_MALL_ACTION_TYPE_MIRROR:
		return mlxsw_sp_mall_port_mirror_add(mlxsw_sp_port, mall_entry);
	case MLXSW_SP_MALL_ACTION_TYPE_SAMPLE:
		return mlxsw_sp_mall_port_sample_add(mlxsw_sp_port, mall_entry);
	default:
		WARN_ON(1);
		return -EINVAL;
	}
}

static void
mlxsw_sp_mall_port_rule_del(struct mlxsw_sp_port *mlxsw_sp_port,
			    struct mlxsw_sp_mall_entry *mall_entry)
{
	switch (mall_entry->type) {
	case MLXSW_SP_MALL_ACTION_TYPE_MIRROR:
		mlxsw_sp_mall_port_mirror_del(mlxsw_sp_port, mall_entry);
		break;
	case MLXSW_SP_MALL_ACTION_TYPE_SAMPLE:
		mlxsw_sp_mall_port_sample_del(mlxsw_sp_port);
		break;
	default:
		WARN_ON(1);
	}
}

static void mlxsw_sp_mall_prio_update(struct mlxsw_sp_flow_block *block)
{
	struct mlxsw_sp_mall_entry *mall_entry;

	if (list_empty(&block->mall.list))
		return;
	block->mall.min_prio = UINT_MAX;
	block->mall.max_prio = 0;
	list_for_each_entry(mall_entry, &block->mall.list, list) {
		if (mall_entry->priority < block->mall.min_prio)
			block->mall.min_prio = mall_entry->priority;
		if (mall_entry->priority > block->mall.max_prio)
			block->mall.max_prio = mall_entry->priority;
	}
}

int mlxsw_sp_mall_replace(struct mlxsw_sp *mlxsw_sp,
			  struct mlxsw_sp_flow_block *block,
			  struct tc_cls_matchall_offload *f)
{
	struct mlxsw_sp_flow_block_binding *binding;
	struct mlxsw_sp_mall_entry *mall_entry;
	__be16 protocol = f->common.protocol;
	struct flow_action_entry *act;
	unsigned int flower_min_prio;
	unsigned int flower_max_prio;
	bool flower_prio_valid;
	int err;

	if (!flow_offload_has_one_action(&f->rule->action)) {
		NL_SET_ERR_MSG(f->common.extack, "Only singular actions are supported");
		return -EOPNOTSUPP;
	}

	if (f->common.chain_index) {
		NL_SET_ERR_MSG(f->common.extack, "Only chain 0 is supported");
		return -EOPNOTSUPP;
	}

	if (mlxsw_sp_flow_block_is_mixed_bound(block)) {
		NL_SET_ERR_MSG(f->common.extack, "Only not mixed bound blocks are supported");
		return -EOPNOTSUPP;
	}

	err = mlxsw_sp_flower_prio_get(mlxsw_sp, block, f->common.chain_index,
				       &flower_min_prio, &flower_max_prio);
	if (err) {
		if (err != -ENOENT) {
			NL_SET_ERR_MSG(f->common.extack, "Failed to get flower priorities");
			return err;
		}
		flower_prio_valid = false;
		/* No flower filters are installed in specified chain. */
	} else {
		flower_prio_valid = true;
	}

	mall_entry = kzalloc(sizeof(*mall_entry), GFP_KERNEL);
	if (!mall_entry)
		return -ENOMEM;
	mall_entry->cookie = f->cookie;
	mall_entry->priority = f->common.prio;
	mall_entry->ingress = mlxsw_sp_flow_block_is_ingress_bound(block);

	act = &f->rule->action.entries[0];

	if (act->id == FLOW_ACTION_MIRRED && protocol == htons(ETH_P_ALL)) {
		if (flower_prio_valid && mall_entry->ingress &&
		    mall_entry->priority >= flower_min_prio) {
			NL_SET_ERR_MSG(f->common.extack, "Failed to add behind existing flower rules");
			err = -EOPNOTSUPP;
			goto errout;
		}
		if (flower_prio_valid && !mall_entry->ingress &&
		    mall_entry->priority <= flower_max_prio) {
			NL_SET_ERR_MSG(f->common.extack, "Failed to add in front of existing flower rules");
			err = -EOPNOTSUPP;
			goto errout;
		}
		mall_entry->type = MLXSW_SP_MALL_ACTION_TYPE_MIRROR;
		mall_entry->mirror.to_dev = act->dev;
	} else if (act->id == FLOW_ACTION_SAMPLE &&
		   protocol == htons(ETH_P_ALL)) {
		if (!mall_entry->ingress) {
			NL_SET_ERR_MSG(f->common.extack, "Sample is not supported on egress");
			err = -EOPNOTSUPP;
			goto errout;
		}
		if (flower_prio_valid &&
		    mall_entry->priority >= flower_min_prio) {
			NL_SET_ERR_MSG(f->common.extack, "Failed to add behind existing flower rules");
			err = -EOPNOTSUPP;
			goto errout;
		}
		if (act->sample.rate > MLXSW_REG_MPSC_RATE_MAX) {
			NL_SET_ERR_MSG(f->common.extack, "Sample rate not supported");
			err = -EOPNOTSUPP;
			goto errout;
		}
		mall_entry->type = MLXSW_SP_MALL_ACTION_TYPE_SAMPLE;
		mall_entry->sample.psample_group = act->sample.psample_group;
		mall_entry->sample.truncate = act->sample.truncate;
		mall_entry->sample.trunc_size = act->sample.trunc_size;
		mall_entry->sample.rate = act->sample.rate;
	} else {
		err = -EOPNOTSUPP;
		goto errout;
	}

	list_for_each_entry(binding, &block->binding_list, list) {
		err = mlxsw_sp_mall_port_rule_add(binding->mlxsw_sp_port,
						  mall_entry);
		if (err)
			goto rollback;
	}

	block->rule_count++;
	if (mall_entry->ingress)
		block->egress_blocker_rule_count++;
	else
		block->ingress_blocker_rule_count++;
	list_add_tail(&mall_entry->list, &block->mall.list);
	mlxsw_sp_mall_prio_update(block);
	return 0;

rollback:
	list_for_each_entry_continue_reverse(binding, &block->binding_list,
					     list)
		mlxsw_sp_mall_port_rule_del(binding->mlxsw_sp_port, mall_entry);
errout:
	kfree(mall_entry);
	return err;
}

void mlxsw_sp_mall_destroy(struct mlxsw_sp_flow_block *block,
			   struct tc_cls_matchall_offload *f)
{
	struct mlxsw_sp_flow_block_binding *binding;
	struct mlxsw_sp_mall_entry *mall_entry;

	mall_entry = mlxsw_sp_mall_entry_find(block, f->cookie);
	if (!mall_entry) {
		NL_SET_ERR_MSG(f->common.extack, "Entry not found");
		return;
	}

	list_del(&mall_entry->list);
	if (mall_entry->ingress)
		block->egress_blocker_rule_count--;
	else
		block->ingress_blocker_rule_count--;
	block->rule_count--;
	list_for_each_entry(binding, &block->binding_list, list)
		mlxsw_sp_mall_port_rule_del(binding->mlxsw_sp_port, mall_entry);
	kfree_rcu(mall_entry, rcu); /* sample RX packets may be in-flight */
	mlxsw_sp_mall_prio_update(block);
}

int mlxsw_sp_mall_port_bind(struct mlxsw_sp_flow_block *block,
			    struct mlxsw_sp_port *mlxsw_sp_port)
{
	struct mlxsw_sp_mall_entry *mall_entry;
	int err;

	list_for_each_entry(mall_entry, &block->mall.list, list) {
		err = mlxsw_sp_mall_port_rule_add(mlxsw_sp_port, mall_entry);
		if (err)
			goto rollback;
	}
	return 0;

rollback:
	list_for_each_entry_continue_reverse(mall_entry, &block->mall.list,
					     list)
		mlxsw_sp_mall_port_rule_del(mlxsw_sp_port, mall_entry);
	return err;
}

void mlxsw_sp_mall_port_unbind(struct mlxsw_sp_flow_block *block,
			       struct mlxsw_sp_port *mlxsw_sp_port)
{
	struct mlxsw_sp_mall_entry *mall_entry;

	list_for_each_entry(mall_entry, &block->mall.list, list)
		mlxsw_sp_mall_port_rule_del(mlxsw_sp_port, mall_entry);
}

int mlxsw_sp_mall_prio_get(struct mlxsw_sp_flow_block *block, u32 chain_index,
			   unsigned int *p_min_prio, unsigned int *p_max_prio)
{
	if (chain_index || list_empty(&block->mall.list))
		/* In case there are no matchall rules, the caller
		 * receives -ENOENT to indicate there is no need
		 * to check the priorities.
		 */
		return -ENOENT;
	*p_min_prio = block->mall.min_prio;
	*p_max_prio = block->mall.max_prio;
	return 0;
}
