/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2018 Mellanox Technologies. All rights reserved */

#ifndef _MLXSW_CORE_ENV_H
#define _MLXSW_CORE_ENV_H

#include <linux/ethtool.h>

struct ethtool_modinfo;
struct ethtool_eeprom;

int mlxsw_env_module_temp_thresholds_get(struct mlxsw_core *core, int module,
					 int off, int *temp);

int mlxsw_env_get_module_info(struct mlxsw_core *mlxsw_core, int module,
			      struct ethtool_modinfo *modinfo);

int mlxsw_env_get_module_eeprom(struct net_device *netdev,
				struct mlxsw_core *mlxsw_core, int module,
				struct ethtool_eeprom *ee, u8 *data);

int
mlxsw_env_get_module_eeprom_by_page(struct mlxsw_core *mlxsw_core, u8 module,
				    const struct ethtool_module_eeprom *page,
				    struct netlink_ext_ack *extack);

int mlxsw_env_reset_module(struct net_device *netdev,
			   struct mlxsw_core *mlxsw_core, u8 module,
			   u32 *flags);

int
mlxsw_env_get_module_power_mode(struct mlxsw_core *mlxsw_core, u8 module,
				struct ethtool_module_power_mode_params *params,
				struct netlink_ext_ack *extack);

int
mlxsw_env_set_module_power_mode(struct mlxsw_core *mlxsw_core, u8 module,
				enum ethtool_module_power_mode_policy policy,
				struct netlink_ext_ack *extack);

int
mlxsw_env_module_overheat_counter_get(struct mlxsw_core *mlxsw_core, u8 module,
				      u64 *p_counter);

void mlxsw_env_module_port_map(struct mlxsw_core *mlxsw_core, u8 module);

void mlxsw_env_module_port_unmap(struct mlxsw_core *mlxsw_core, u8 module);

int mlxsw_env_module_port_up(struct mlxsw_core *mlxsw_core, u8 module);

void mlxsw_env_module_port_down(struct mlxsw_core *mlxsw_core, u8 module);

int mlxsw_env_init(struct mlxsw_core *core, struct mlxsw_env **p_env);
void mlxsw_env_fini(struct mlxsw_env *env);

#endif
