/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies. */

#ifndef __MLX5_EN_TC_SAMPLE_H__
#define __MLX5_EN_TC_SAMPLE_H__

#include "eswitch.h"

struct mlx5_flow_attr;
struct mlx5e_tc_psample;
struct mlx5e_post_act;

struct mlx5e_sample_attr {
	u32 group_num;
	u32 rate;
	u32 trunc_size;
	u32 restore_obj_id;
	u32 sampler_id;
	struct mlx5e_sample_flow *sample_flow;
};

#if IS_ENABLED(CONFIG_MLX5_TC_SAMPLE)

void mlx5e_tc_sample_skb(struct sk_buff *skb, struct mlx5_mapped_obj *mapped_obj);

struct mlx5_flow_handle *
mlx5e_tc_sample_offload(struct mlx5e_tc_psample *sample_priv,
			struct mlx5_flow_spec *spec,
			struct mlx5_flow_attr *attr,
			u32 tunnel_id);

void
mlx5e_tc_sample_unoffload(struct mlx5e_tc_psample *sample_priv,
			  struct mlx5_flow_handle *rule,
			  struct mlx5_flow_attr *attr);

struct mlx5e_tc_psample *
mlx5e_tc_sample_init(struct mlx5_eswitch *esw, struct mlx5e_post_act *post_act);

void
mlx5e_tc_sample_cleanup(struct mlx5e_tc_psample *tc_psample);

#else /* CONFIG_MLX5_TC_SAMPLE */

static inline struct mlx5_flow_handle *
mlx5e_tc_sample_offload(struct mlx5e_tc_psample *tc_psample,
			struct mlx5_flow_spec *spec,
			struct mlx5_flow_attr *attr,
			u32 tunnel_id)
{ return ERR_PTR(-EOPNOTSUPP); }

static inline void
mlx5e_tc_sample_unoffload(struct mlx5e_tc_psample *tc_psample,
			  struct mlx5_flow_handle *rule,
			  struct mlx5_flow_attr *attr) {}

static inline struct mlx5e_tc_psample *
mlx5e_tc_sample_init(struct mlx5_eswitch *esw, struct mlx5e_post_act *post_act)
{ return ERR_PTR(-EOPNOTSUPP); }

static inline void
mlx5e_tc_sample_cleanup(struct mlx5e_tc_psample *tc_psample) {}

static inline void
mlx5e_tc_sample_skb(struct sk_buff *skb, struct mlx5_mapped_obj *mapped_obj) {}

#endif /* CONFIG_MLX5_TC_SAMPLE */
#endif /* __MLX5_EN_TC_SAMPLE_H__ */
