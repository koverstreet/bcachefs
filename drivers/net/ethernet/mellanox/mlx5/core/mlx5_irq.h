/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2021 Mellanox Technologies. */

#ifndef __MLX5_IRQ_H__
#define __MLX5_IRQ_H__

#include <linux/mlx5/driver.h>

#define MLX5_COMP_EQS_PER_SF 8

struct mlx5_irq;

int mlx5_irq_table_init(struct mlx5_core_dev *dev);
void mlx5_irq_table_cleanup(struct mlx5_core_dev *dev);
int mlx5_irq_table_create(struct mlx5_core_dev *dev);
void mlx5_irq_table_destroy(struct mlx5_core_dev *dev);
int mlx5_irq_table_get_num_comp(struct mlx5_irq_table *table);
int mlx5_irq_table_get_sfs_vec(struct mlx5_irq_table *table);
struct mlx5_irq_table *mlx5_irq_table_get(struct mlx5_core_dev *dev);

int mlx5_set_msix_vec_count(struct mlx5_core_dev *dev, int devfn,
			    int msix_vec_count);
int mlx5_get_default_msix_vec_count(struct mlx5_core_dev *dev, int num_vfs);

struct mlx5_irq *mlx5_irq_request(struct mlx5_core_dev *dev, u16 vecidx,
				  struct cpumask *affinity);
void mlx5_irq_release(struct mlx5_irq *irq);
int mlx5_irq_attach_nb(struct mlx5_irq *irq, struct notifier_block *nb);
int mlx5_irq_detach_nb(struct mlx5_irq *irq, struct notifier_block *nb);
struct cpumask *mlx5_irq_get_affinity_mask(struct mlx5_irq *irq);
int mlx5_irq_get_index(struct mlx5_irq *irq);

#endif /* __MLX5_IRQ_H__ */
