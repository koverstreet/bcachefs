// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2019 Mellanox Technologies. */

#include <linux/mlx5/eswitch.h>
#include <linux/err.h>
#include "dr_types.h"

#define DR_DOMAIN_SW_STEERING_SUPPORTED(dmn, dmn_type)	\
	((dmn)->info.caps.dmn_type##_sw_owner ||	\
	 ((dmn)->info.caps.dmn_type##_sw_owner_v2 &&	\
	  (dmn)->info.caps.sw_format_ver <= MLX5_STEERING_FORMAT_CONNECTX_6DX))

static void dr_domain_init_csum_recalc_fts(struct mlx5dr_domain *dmn)
{
	/* Per vport cached FW FT for checksum recalculation, this
	 * recalculation is needed due to a HW bug in STEv0.
	 */
	xa_init(&dmn->csum_fts_xa);
}

static void dr_domain_uninit_csum_recalc_fts(struct mlx5dr_domain *dmn)
{
	struct mlx5dr_fw_recalc_cs_ft *recalc_cs_ft;
	unsigned long i;

	xa_for_each(&dmn->csum_fts_xa, i, recalc_cs_ft) {
		if (recalc_cs_ft)
			mlx5dr_fw_destroy_recalc_cs_ft(dmn, recalc_cs_ft);
	}

	xa_destroy(&dmn->csum_fts_xa);
}

int mlx5dr_domain_get_recalc_cs_ft_addr(struct mlx5dr_domain *dmn,
					u16 vport_num,
					u64 *rx_icm_addr)
{
	struct mlx5dr_fw_recalc_cs_ft *recalc_cs_ft;
	int ret;

	recalc_cs_ft = xa_load(&dmn->csum_fts_xa, vport_num);
	if (!recalc_cs_ft) {
		/* Table hasn't been created yet */
		recalc_cs_ft = mlx5dr_fw_create_recalc_cs_ft(dmn, vport_num);
		if (!recalc_cs_ft)
			return -EINVAL;

		ret = xa_err(xa_store(&dmn->csum_fts_xa, vport_num,
				      recalc_cs_ft, GFP_KERNEL));
		if (ret)
			return ret;
	}

	*rx_icm_addr = recalc_cs_ft->rx_icm_addr;

	return 0;
}

static int dr_domain_init_resources(struct mlx5dr_domain *dmn)
{
	int ret;

	dmn->ste_ctx = mlx5dr_ste_get_ctx(dmn->info.caps.sw_format_ver);
	if (!dmn->ste_ctx) {
		mlx5dr_err(dmn, "SW Steering on this device is unsupported\n");
		return -EOPNOTSUPP;
	}

	ret = mlx5_core_alloc_pd(dmn->mdev, &dmn->pdn);
	if (ret) {
		mlx5dr_err(dmn, "Couldn't allocate PD, ret: %d", ret);
		return ret;
	}

	dmn->uar = mlx5_get_uars_page(dmn->mdev);
	if (IS_ERR(dmn->uar)) {
		mlx5dr_err(dmn, "Couldn't allocate UAR\n");
		ret = PTR_ERR(dmn->uar);
		goto clean_pd;
	}

	dmn->ste_icm_pool = mlx5dr_icm_pool_create(dmn, DR_ICM_TYPE_STE);
	if (!dmn->ste_icm_pool) {
		mlx5dr_err(dmn, "Couldn't get icm memory\n");
		ret = -ENOMEM;
		goto clean_uar;
	}

	dmn->action_icm_pool = mlx5dr_icm_pool_create(dmn, DR_ICM_TYPE_MODIFY_ACTION);
	if (!dmn->action_icm_pool) {
		mlx5dr_err(dmn, "Couldn't get action icm memory\n");
		ret = -ENOMEM;
		goto free_ste_icm_pool;
	}

	ret = mlx5dr_send_ring_alloc(dmn);
	if (ret) {
		mlx5dr_err(dmn, "Couldn't create send-ring\n");
		goto free_action_icm_pool;
	}

	return 0;

free_action_icm_pool:
	mlx5dr_icm_pool_destroy(dmn->action_icm_pool);
free_ste_icm_pool:
	mlx5dr_icm_pool_destroy(dmn->ste_icm_pool);
clean_uar:
	mlx5_put_uars_page(dmn->mdev, dmn->uar);
clean_pd:
	mlx5_core_dealloc_pd(dmn->mdev, dmn->pdn);

	return ret;
}

static void dr_domain_uninit_resources(struct mlx5dr_domain *dmn)
{
	mlx5dr_send_ring_free(dmn, dmn->send_ring);
	mlx5dr_icm_pool_destroy(dmn->action_icm_pool);
	mlx5dr_icm_pool_destroy(dmn->ste_icm_pool);
	mlx5_put_uars_page(dmn->mdev, dmn->uar);
	mlx5_core_dealloc_pd(dmn->mdev, dmn->pdn);
}

static void dr_domain_fill_uplink_caps(struct mlx5dr_domain *dmn,
				       struct mlx5dr_cmd_vport_cap *uplink_vport)
{
	struct mlx5dr_esw_caps *esw_caps = &dmn->info.caps.esw_caps;

	uplink_vport->num = MLX5_VPORT_UPLINK;
	uplink_vport->icm_address_rx = esw_caps->uplink_icm_address_rx;
	uplink_vport->icm_address_tx = esw_caps->uplink_icm_address_tx;
	uplink_vport->vport_gvmi = 0;
	uplink_vport->vhca_gvmi = dmn->info.caps.gvmi;
}

static int dr_domain_query_vport(struct mlx5dr_domain *dmn,
				 u16 vport_number,
				 bool other_vport,
				 struct mlx5dr_cmd_vport_cap *vport_caps)
{
	int ret;

	ret = mlx5dr_cmd_query_esw_vport_context(dmn->mdev,
						 other_vport,
						 vport_number,
						 &vport_caps->icm_address_rx,
						 &vport_caps->icm_address_tx);
	if (ret)
		return ret;

	ret = mlx5dr_cmd_query_gvmi(dmn->mdev,
				    other_vport,
				    vport_number,
				    &vport_caps->vport_gvmi);
	if (ret)
		return ret;

	vport_caps->num = vport_number;
	vport_caps->vhca_gvmi = dmn->info.caps.gvmi;

	return 0;
}

static int dr_domain_query_esw_mngr(struct mlx5dr_domain *dmn)
{
	return dr_domain_query_vport(dmn, 0, false,
				     &dmn->info.caps.vports.esw_manager_caps);
}

static void dr_domain_query_uplink(struct mlx5dr_domain *dmn)
{
	dr_domain_fill_uplink_caps(dmn, &dmn->info.caps.vports.uplink_caps);
}

static struct mlx5dr_cmd_vport_cap *
dr_domain_add_vport_cap(struct mlx5dr_domain *dmn, u16 vport)
{
	struct mlx5dr_cmd_caps *caps = &dmn->info.caps;
	struct mlx5dr_cmd_vport_cap *vport_caps;
	int ret;

	vport_caps = kvzalloc(sizeof(*vport_caps), GFP_KERNEL);
	if (!vport_caps)
		return NULL;

	ret = dr_domain_query_vport(dmn, vport, true, vport_caps);
	if (ret) {
		kvfree(vport_caps);
		return NULL;
	}

	ret = xa_insert(&caps->vports.vports_caps_xa, vport,
			vport_caps, GFP_KERNEL);
	if (ret) {
		mlx5dr_dbg(dmn, "Couldn't insert new vport into xarray (%d)\n", ret);
		kvfree(vport_caps);
		return ERR_PTR(ret);
	}

	return vport_caps;
}

static bool dr_domain_is_esw_mgr_vport(struct mlx5dr_domain *dmn, u16 vport)
{
	struct mlx5dr_cmd_caps *caps = &dmn->info.caps;

	return (caps->is_ecpf && vport == MLX5_VPORT_ECPF) ||
	       (!caps->is_ecpf && vport == 0);
}

struct mlx5dr_cmd_vport_cap *
mlx5dr_domain_get_vport_cap(struct mlx5dr_domain *dmn, u16 vport)
{
	struct mlx5dr_cmd_caps *caps = &dmn->info.caps;
	struct mlx5dr_cmd_vport_cap *vport_caps;

	if (dr_domain_is_esw_mgr_vport(dmn, vport))
		return &caps->vports.esw_manager_caps;

	if (vport == MLX5_VPORT_UPLINK)
		return &caps->vports.uplink_caps;

vport_load:
	vport_caps = xa_load(&caps->vports.vports_caps_xa, vport);
	if (vport_caps)
		return vport_caps;

	vport_caps = dr_domain_add_vport_cap(dmn, vport);
	if (PTR_ERR(vport_caps) == -EBUSY)
		/* caps were already stored by another thread */
		goto vport_load;

	return vport_caps;
}

static void dr_domain_clear_vports(struct mlx5dr_domain *dmn)
{
	struct mlx5dr_cmd_vport_cap *vport_caps;
	unsigned long i;

	xa_for_each(&dmn->info.caps.vports.vports_caps_xa, i, vport_caps) {
		vport_caps = xa_erase(&dmn->info.caps.vports.vports_caps_xa, i);
		kvfree(vport_caps);
	}
}

static int dr_domain_query_fdb_caps(struct mlx5_core_dev *mdev,
				    struct mlx5dr_domain *dmn)
{
	int ret;

	if (!dmn->info.caps.eswitch_manager)
		return -EOPNOTSUPP;

	ret = mlx5dr_cmd_query_esw_caps(mdev, &dmn->info.caps.esw_caps);
	if (ret)
		return ret;

	dmn->info.caps.fdb_sw_owner = dmn->info.caps.esw_caps.sw_owner;
	dmn->info.caps.fdb_sw_owner_v2 = dmn->info.caps.esw_caps.sw_owner_v2;
	dmn->info.caps.esw_rx_drop_address = dmn->info.caps.esw_caps.drop_icm_address_rx;
	dmn->info.caps.esw_tx_drop_address = dmn->info.caps.esw_caps.drop_icm_address_tx;

	xa_init(&dmn->info.caps.vports.vports_caps_xa);

	/* Query eswitch manager and uplink vports only. Rest of the
	 * vports (vport 0, VFs and SFs) will be queried dynamically.
	 */

	ret = dr_domain_query_esw_mngr(dmn);
	if (ret) {
		mlx5dr_err(dmn, "Failed to query eswitch manager vport caps (err: %d)", ret);
		goto free_vports_caps_xa;
	}

	dr_domain_query_uplink(dmn);

	return 0;

free_vports_caps_xa:
	xa_destroy(&dmn->info.caps.vports.vports_caps_xa);

	return ret;
}

static int dr_domain_caps_init(struct mlx5_core_dev *mdev,
			       struct mlx5dr_domain *dmn)
{
	struct mlx5dr_cmd_vport_cap *vport_cap;
	int ret;

	if (MLX5_CAP_GEN(mdev, port_type) != MLX5_CAP_PORT_TYPE_ETH) {
		mlx5dr_err(dmn, "Failed to allocate domain, bad link type\n");
		return -EOPNOTSUPP;
	}

	ret = mlx5dr_cmd_query_device(mdev, &dmn->info.caps);
	if (ret)
		return ret;

	ret = dr_domain_query_fdb_caps(mdev, dmn);
	if (ret)
		return ret;

	switch (dmn->type) {
	case MLX5DR_DOMAIN_TYPE_NIC_RX:
		if (!DR_DOMAIN_SW_STEERING_SUPPORTED(dmn, rx))
			return -ENOTSUPP;

		dmn->info.supp_sw_steering = true;
		dmn->info.rx.type = DR_DOMAIN_NIC_TYPE_RX;
		dmn->info.rx.default_icm_addr = dmn->info.caps.nic_rx_drop_address;
		dmn->info.rx.drop_icm_addr = dmn->info.caps.nic_rx_drop_address;
		break;
	case MLX5DR_DOMAIN_TYPE_NIC_TX:
		if (!DR_DOMAIN_SW_STEERING_SUPPORTED(dmn, tx))
			return -ENOTSUPP;

		dmn->info.supp_sw_steering = true;
		dmn->info.tx.type = DR_DOMAIN_NIC_TYPE_TX;
		dmn->info.tx.default_icm_addr = dmn->info.caps.nic_tx_allow_address;
		dmn->info.tx.drop_icm_addr = dmn->info.caps.nic_tx_drop_address;
		break;
	case MLX5DR_DOMAIN_TYPE_FDB:
		if (!dmn->info.caps.eswitch_manager)
			return -ENOTSUPP;

		if (!DR_DOMAIN_SW_STEERING_SUPPORTED(dmn, fdb))
			return -ENOTSUPP;

		dmn->info.rx.type = DR_DOMAIN_NIC_TYPE_RX;
		dmn->info.tx.type = DR_DOMAIN_NIC_TYPE_TX;
		vport_cap = &dmn->info.caps.vports.esw_manager_caps;

		dmn->info.supp_sw_steering = true;
		dmn->info.tx.default_icm_addr = vport_cap->icm_address_tx;
		dmn->info.rx.default_icm_addr = vport_cap->icm_address_rx;
		dmn->info.rx.drop_icm_addr = dmn->info.caps.esw_rx_drop_address;
		dmn->info.tx.drop_icm_addr = dmn->info.caps.esw_tx_drop_address;
		break;
	default:
		mlx5dr_err(dmn, "Invalid domain\n");
		ret = -EINVAL;
		break;
	}

	return ret;
}

static void dr_domain_caps_uninit(struct mlx5dr_domain *dmn)
{
	dr_domain_clear_vports(dmn);
	xa_destroy(&dmn->info.caps.vports.vports_caps_xa);
}

struct mlx5dr_domain *
mlx5dr_domain_create(struct mlx5_core_dev *mdev, enum mlx5dr_domain_type type)
{
	struct mlx5dr_domain *dmn;
	int ret;

	if (type > MLX5DR_DOMAIN_TYPE_FDB)
		return NULL;

	dmn = kzalloc(sizeof(*dmn), GFP_KERNEL);
	if (!dmn)
		return NULL;

	dmn->mdev = mdev;
	dmn->type = type;
	refcount_set(&dmn->refcount, 1);
	mutex_init(&dmn->info.rx.mutex);
	mutex_init(&dmn->info.tx.mutex);

	if (dr_domain_caps_init(mdev, dmn)) {
		mlx5dr_err(dmn, "Failed init domain, no caps\n");
		goto free_domain;
	}

	dmn->info.max_log_action_icm_sz = DR_CHUNK_SIZE_4K;
	dmn->info.max_log_sw_icm_sz = min_t(u32, DR_CHUNK_SIZE_1024K,
					    dmn->info.caps.log_icm_size);

	if (!dmn->info.supp_sw_steering) {
		mlx5dr_err(dmn, "SW steering is not supported\n");
		goto uninit_caps;
	}

	/* Allocate resources */
	ret = dr_domain_init_resources(dmn);
	if (ret) {
		mlx5dr_err(dmn, "Failed init domain resources\n");
		goto uninit_caps;
	}

	dr_domain_init_csum_recalc_fts(dmn);

	return dmn;

uninit_caps:
	dr_domain_caps_uninit(dmn);
free_domain:
	kfree(dmn);
	return NULL;
}

/* Assure synchronization of the device steering tables with updates made by SW
 * insertion.
 */
int mlx5dr_domain_sync(struct mlx5dr_domain *dmn, u32 flags)
{
	int ret = 0;

	if (flags & MLX5DR_DOMAIN_SYNC_FLAGS_SW) {
		mlx5dr_domain_lock(dmn);
		ret = mlx5dr_send_ring_force_drain(dmn);
		mlx5dr_domain_unlock(dmn);
		if (ret) {
			mlx5dr_err(dmn, "Force drain failed flags: %d, ret: %d\n",
				   flags, ret);
			return ret;
		}
	}

	if (flags & MLX5DR_DOMAIN_SYNC_FLAGS_HW)
		ret = mlx5dr_cmd_sync_steering(dmn->mdev);

	return ret;
}

int mlx5dr_domain_destroy(struct mlx5dr_domain *dmn)
{
	if (refcount_read(&dmn->refcount) > 1)
		return -EBUSY;

	/* make sure resources are not used by the hardware */
	mlx5dr_cmd_sync_steering(dmn->mdev);
	dr_domain_uninit_csum_recalc_fts(dmn);
	dr_domain_uninit_resources(dmn);
	dr_domain_caps_uninit(dmn);
	mutex_destroy(&dmn->info.tx.mutex);
	mutex_destroy(&dmn->info.rx.mutex);
	kfree(dmn);
	return 0;
}

void mlx5dr_domain_set_peer(struct mlx5dr_domain *dmn,
			    struct mlx5dr_domain *peer_dmn)
{
	mlx5dr_domain_lock(dmn);

	if (dmn->peer_dmn)
		refcount_dec(&dmn->peer_dmn->refcount);

	dmn->peer_dmn = peer_dmn;

	if (dmn->peer_dmn)
		refcount_inc(&dmn->peer_dmn->refcount);

	mlx5dr_domain_unlock(dmn);
}
