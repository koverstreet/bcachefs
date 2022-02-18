// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2021, Linaro Limited
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/arm_ffa.h>
#include <linux/errno.h>
#include <linux/scatterlist.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tee_drv.h>
#include <linux/types.h>
#include "optee_private.h"
#include "optee_ffa.h"
#include "optee_rpc_cmd.h"

/*
 * This file implement the FF-A ABI used when communicating with secure world
 * OP-TEE OS via FF-A.
 * This file is divided into the following sections:
 * 1. Maintain a hash table for lookup of a global FF-A memory handle
 * 2. Convert between struct tee_param and struct optee_msg_param
 * 3. Low level support functions to register shared memory in secure world
 * 4. Dynamic shared memory pool based on alloc_pages()
 * 5. Do a normal scheduled call into secure world
 * 6. Driver initialization.
 */

/*
 * 1. Maintain a hash table for lookup of a global FF-A memory handle
 *
 * FF-A assigns a global memory handle for each piece shared memory.
 * This handle is then used when communicating with secure world.
 *
 * Main functions are optee_shm_add_ffa_handle() and optee_shm_rem_ffa_handle()
 */
struct shm_rhash {
	struct tee_shm *shm;
	u64 global_id;
	struct rhash_head linkage;
};

static void rh_free_fn(void *ptr, void *arg)
{
	kfree(ptr);
}

static const struct rhashtable_params shm_rhash_params = {
	.head_offset = offsetof(struct shm_rhash, linkage),
	.key_len     = sizeof(u64),
	.key_offset  = offsetof(struct shm_rhash, global_id),
	.automatic_shrinking = true,
};

static struct tee_shm *optee_shm_from_ffa_handle(struct optee *optee,
						 u64 global_id)
{
	struct tee_shm *shm = NULL;
	struct shm_rhash *r;

	mutex_lock(&optee->ffa.mutex);
	r = rhashtable_lookup_fast(&optee->ffa.global_ids, &global_id,
				   shm_rhash_params);
	if (r)
		shm = r->shm;
	mutex_unlock(&optee->ffa.mutex);

	return shm;
}

static int optee_shm_add_ffa_handle(struct optee *optee, struct tee_shm *shm,
				    u64 global_id)
{
	struct shm_rhash *r;
	int rc;

	r = kmalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return -ENOMEM;
	r->shm = shm;
	r->global_id = global_id;

	mutex_lock(&optee->ffa.mutex);
	rc = rhashtable_lookup_insert_fast(&optee->ffa.global_ids, &r->linkage,
					   shm_rhash_params);
	mutex_unlock(&optee->ffa.mutex);

	if (rc)
		kfree(r);

	return rc;
}

static int optee_shm_rem_ffa_handle(struct optee *optee, u64 global_id)
{
	struct shm_rhash *r;
	int rc = -ENOENT;

	mutex_lock(&optee->ffa.mutex);
	r = rhashtable_lookup_fast(&optee->ffa.global_ids, &global_id,
				   shm_rhash_params);
	if (r)
		rc = rhashtable_remove_fast(&optee->ffa.global_ids,
					    &r->linkage, shm_rhash_params);
	mutex_unlock(&optee->ffa.mutex);

	if (!rc)
		kfree(r);

	return rc;
}

/*
 * 2. Convert between struct tee_param and struct optee_msg_param
 *
 * optee_ffa_from_msg_param() and optee_ffa_to_msg_param() are the main
 * functions.
 */

static void from_msg_param_ffa_mem(struct optee *optee, struct tee_param *p,
				   u32 attr, const struct optee_msg_param *mp)
{
	struct tee_shm *shm = NULL;
	u64 offs_high = 0;
	u64 offs_low = 0;

	p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT +
		  attr - OPTEE_MSG_ATTR_TYPE_FMEM_INPUT;
	p->u.memref.size = mp->u.fmem.size;

	if (mp->u.fmem.global_id != OPTEE_MSG_FMEM_INVALID_GLOBAL_ID)
		shm = optee_shm_from_ffa_handle(optee, mp->u.fmem.global_id);
	p->u.memref.shm = shm;

	if (shm) {
		offs_low = mp->u.fmem.offs_low;
		offs_high = mp->u.fmem.offs_high;
	}
	p->u.memref.shm_offs = offs_low | offs_high << 32;
}

/**
 * optee_ffa_from_msg_param() - convert from OPTEE_MSG parameters to
 *				struct tee_param
 * @optee:	main service struct
 * @params:	subsystem internal parameter representation
 * @num_params:	number of elements in the parameter arrays
 * @msg_params:	OPTEE_MSG parameters
 *
 * Returns 0 on success or <0 on failure
 */
static int optee_ffa_from_msg_param(struct optee *optee,
				    struct tee_param *params, size_t num_params,
				    const struct optee_msg_param *msg_params)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		struct tee_param *p = params + n;
		const struct optee_msg_param *mp = msg_params + n;
		u32 attr = mp->attr & OPTEE_MSG_ATTR_TYPE_MASK;

		switch (attr) {
		case OPTEE_MSG_ATTR_TYPE_NONE:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
			memset(&p->u, 0, sizeof(p->u));
			break;
		case OPTEE_MSG_ATTR_TYPE_VALUE_INPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
			optee_from_msg_param_value(p, attr, mp);
			break;
		case OPTEE_MSG_ATTR_TYPE_FMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_FMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_FMEM_INOUT:
			from_msg_param_ffa_mem(optee, p, attr, mp);
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

static int to_msg_param_ffa_mem(struct optee_msg_param *mp,
				const struct tee_param *p)
{
	struct tee_shm *shm = p->u.memref.shm;

	mp->attr = OPTEE_MSG_ATTR_TYPE_FMEM_INPUT + p->attr -
		   TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;

	if (shm) {
		u64 shm_offs = p->u.memref.shm_offs;

		mp->u.fmem.internal_offs = shm->offset;

		mp->u.fmem.offs_low = shm_offs;
		mp->u.fmem.offs_high = shm_offs >> 32;
		/* Check that the entire offset could be stored. */
		if (mp->u.fmem.offs_high != shm_offs >> 32)
			return -EINVAL;

		mp->u.fmem.global_id = shm->sec_world_id;
	} else {
		memset(&mp->u, 0, sizeof(mp->u));
		mp->u.fmem.global_id = OPTEE_MSG_FMEM_INVALID_GLOBAL_ID;
	}
	mp->u.fmem.size = p->u.memref.size;

	return 0;
}

/**
 * optee_ffa_to_msg_param() - convert from struct tee_params to OPTEE_MSG
 *			      parameters
 * @optee:	main service struct
 * @msg_params:	OPTEE_MSG parameters
 * @num_params:	number of elements in the parameter arrays
 * @params:	subsystem itnernal parameter representation
 * Returns 0 on success or <0 on failure
 */
static int optee_ffa_to_msg_param(struct optee *optee,
				  struct optee_msg_param *msg_params,
				  size_t num_params,
				  const struct tee_param *params)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		const struct tee_param *p = params + n;
		struct optee_msg_param *mp = msg_params + n;

		switch (p->attr) {
		case TEE_IOCTL_PARAM_ATTR_TYPE_NONE:
			mp->attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
			memset(&mp->u, 0, sizeof(mp->u));
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
			optee_to_msg_param_value(mp, p);
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
			if (to_msg_param_ffa_mem(mp, p))
				return -EINVAL;
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

/*
 * 3. Low level support functions to register shared memory in secure world
 *
 * Functions to register and unregister shared memory both for normal
 * clients and for tee-supplicant.
 */

static int optee_ffa_shm_register(struct tee_context *ctx, struct tee_shm *shm,
				  struct page **pages, size_t num_pages,
				  unsigned long start)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	const struct ffa_dev_ops *ffa_ops = optee->ffa.ffa_ops;
	struct ffa_device *ffa_dev = optee->ffa.ffa_dev;
	struct ffa_mem_region_attributes mem_attr = {
		.receiver = ffa_dev->vm_id,
		.attrs = FFA_MEM_RW,
	};
	struct ffa_mem_ops_args args = {
		.use_txbuf = true,
		.attrs = &mem_attr,
		.nattrs = 1,
	};
	struct sg_table sgt;
	int rc;

	rc = optee_check_mem_type(start, num_pages);
	if (rc)
		return rc;

	rc = sg_alloc_table_from_pages(&sgt, pages, num_pages, 0,
				       num_pages * PAGE_SIZE, GFP_KERNEL);
	if (rc)
		return rc;
	args.sg = sgt.sgl;
	rc = ffa_ops->memory_share(ffa_dev, &args);
	sg_free_table(&sgt);
	if (rc)
		return rc;

	rc = optee_shm_add_ffa_handle(optee, shm, args.g_handle);
	if (rc) {
		ffa_ops->memory_reclaim(args.g_handle, 0);
		return rc;
	}

	shm->sec_world_id = args.g_handle;

	return 0;
}

static int optee_ffa_shm_unregister(struct tee_context *ctx,
				    struct tee_shm *shm)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	const struct ffa_dev_ops *ffa_ops = optee->ffa.ffa_ops;
	struct ffa_device *ffa_dev = optee->ffa.ffa_dev;
	u64 global_handle = shm->sec_world_id;
	struct ffa_send_direct_data data = {
		.data0 = OPTEE_FFA_UNREGISTER_SHM,
		.data1 = (u32)global_handle,
		.data2 = (u32)(global_handle >> 32)
	};
	int rc;

	optee_shm_rem_ffa_handle(optee, global_handle);
	shm->sec_world_id = 0;

	rc = ffa_ops->sync_send_receive(ffa_dev, &data);
	if (rc)
		pr_err("Unregister SHM id 0x%llx rc %d\n", global_handle, rc);

	rc = ffa_ops->memory_reclaim(global_handle, 0);
	if (rc)
		pr_err("mem_reclaim: 0x%llx %d", global_handle, rc);

	return rc;
}

static int optee_ffa_shm_unregister_supp(struct tee_context *ctx,
					 struct tee_shm *shm)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	const struct ffa_dev_ops *ffa_ops = optee->ffa.ffa_ops;
	u64 global_handle = shm->sec_world_id;
	int rc;

	/*
	 * We're skipping the OPTEE_FFA_YIELDING_CALL_UNREGISTER_SHM call
	 * since this is OP-TEE freeing via RPC so it has already retired
	 * this ID.
	 */

	optee_shm_rem_ffa_handle(optee, global_handle);
	rc = ffa_ops->memory_reclaim(global_handle, 0);
	if (rc)
		pr_err("mem_reclaim: 0x%llx %d", global_handle, rc);

	shm->sec_world_id = 0;

	return rc;
}

/*
 * 4. Dynamic shared memory pool based on alloc_pages()
 *
 * Implements an OP-TEE specific shared memory pool.
 * The main function is optee_ffa_shm_pool_alloc_pages().
 */

static int pool_ffa_op_alloc(struct tee_shm_pool_mgr *poolm,
			     struct tee_shm *shm, size_t size)
{
	return optee_pool_op_alloc_helper(poolm, shm, size,
					  optee_ffa_shm_register);
}

static void pool_ffa_op_free(struct tee_shm_pool_mgr *poolm,
			     struct tee_shm *shm)
{
	optee_ffa_shm_unregister(shm->ctx, shm);
	free_pages((unsigned long)shm->kaddr, get_order(shm->size));
	shm->kaddr = NULL;
}

static void pool_ffa_op_destroy_poolmgr(struct tee_shm_pool_mgr *poolm)
{
	kfree(poolm);
}

static const struct tee_shm_pool_mgr_ops pool_ffa_ops = {
	.alloc = pool_ffa_op_alloc,
	.free = pool_ffa_op_free,
	.destroy_poolmgr = pool_ffa_op_destroy_poolmgr,
};

/**
 * optee_ffa_shm_pool_alloc_pages() - create page-based allocator pool
 *
 * This pool is used with OP-TEE over FF-A. In this case command buffers
 * and such are allocated from kernel's own memory.
 */
static struct tee_shm_pool_mgr *optee_ffa_shm_pool_alloc_pages(void)
{
	struct tee_shm_pool_mgr *mgr = kzalloc(sizeof(*mgr), GFP_KERNEL);

	if (!mgr)
		return ERR_PTR(-ENOMEM);

	mgr->ops = &pool_ffa_ops;

	return mgr;
}

/*
 * 5. Do a normal scheduled call into secure world
 *
 * The function optee_ffa_do_call_with_arg() performs a normal scheduled
 * call into secure world. During this call may normal world request help
 * from normal world using RPCs, Remote Procedure Calls. This includes
 * delivery of non-secure interrupts to for instance allow rescheduling of
 * the current task.
 */

static void handle_ffa_rpc_func_cmd_shm_alloc(struct tee_context *ctx,
					      struct optee_msg_arg *arg)
{
	struct tee_shm *shm;

	if (arg->num_params != 1 ||
	    arg->params[0].attr != OPTEE_MSG_ATTR_TYPE_VALUE_INPUT) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	switch (arg->params[0].u.value.a) {
	case OPTEE_RPC_SHM_TYPE_APPL:
		shm = optee_rpc_cmd_alloc_suppl(ctx, arg->params[0].u.value.b);
		break;
	case OPTEE_RPC_SHM_TYPE_KERNEL:
		shm = tee_shm_alloc(ctx, arg->params[0].u.value.b,
				    TEE_SHM_MAPPED | TEE_SHM_PRIV);
		break;
	default:
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	if (IS_ERR(shm)) {
		arg->ret = TEEC_ERROR_OUT_OF_MEMORY;
		return;
	}

	arg->params[0] = (struct optee_msg_param){
		.attr = OPTEE_MSG_ATTR_TYPE_FMEM_OUTPUT,
		.u.fmem.size = tee_shm_get_size(shm),
		.u.fmem.global_id = shm->sec_world_id,
		.u.fmem.internal_offs = shm->offset,
	};

	arg->ret = TEEC_SUCCESS;
}

static void handle_ffa_rpc_func_cmd_shm_free(struct tee_context *ctx,
					     struct optee *optee,
					     struct optee_msg_arg *arg)
{
	struct tee_shm *shm;

	if (arg->num_params != 1 ||
	    arg->params[0].attr != OPTEE_MSG_ATTR_TYPE_VALUE_INPUT)
		goto err_bad_param;

	shm = optee_shm_from_ffa_handle(optee, arg->params[0].u.value.b);
	if (!shm)
		goto err_bad_param;
	switch (arg->params[0].u.value.a) {
	case OPTEE_RPC_SHM_TYPE_APPL:
		optee_rpc_cmd_free_suppl(ctx, shm);
		break;
	case OPTEE_RPC_SHM_TYPE_KERNEL:
		tee_shm_free(shm);
		break;
	default:
		goto err_bad_param;
	}
	arg->ret = TEEC_SUCCESS;
	return;

err_bad_param:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_ffa_rpc_func_cmd(struct tee_context *ctx,
				    struct optee_msg_arg *arg)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);

	arg->ret_origin = TEEC_ORIGIN_COMMS;
	switch (arg->cmd) {
	case OPTEE_RPC_CMD_SHM_ALLOC:
		handle_ffa_rpc_func_cmd_shm_alloc(ctx, arg);
		break;
	case OPTEE_RPC_CMD_SHM_FREE:
		handle_ffa_rpc_func_cmd_shm_free(ctx, optee, arg);
		break;
	default:
		optee_rpc_cmd(ctx, optee, arg);
	}
}

static void optee_handle_ffa_rpc(struct tee_context *ctx, u32 cmd,
				 struct optee_msg_arg *arg)
{
	switch (cmd) {
	case OPTEE_FFA_YIELDING_CALL_RETURN_RPC_CMD:
		handle_ffa_rpc_func_cmd(ctx, arg);
		break;
	case OPTEE_FFA_YIELDING_CALL_RETURN_INTERRUPT:
		/* Interrupt delivered by now */
		break;
	default:
		pr_warn("Unknown RPC func 0x%x\n", cmd);
		break;
	}
}

static int optee_ffa_yielding_call(struct tee_context *ctx,
				   struct ffa_send_direct_data *data,
				   struct optee_msg_arg *rpc_arg)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	const struct ffa_dev_ops *ffa_ops = optee->ffa.ffa_ops;
	struct ffa_device *ffa_dev = optee->ffa.ffa_dev;
	struct optee_call_waiter w;
	u32 cmd = data->data0;
	u32 w4 = data->data1;
	u32 w5 = data->data2;
	u32 w6 = data->data3;
	int rc;

	/* Initialize waiter */
	optee_cq_wait_init(&optee->call_queue, &w);
	while (true) {
		rc = ffa_ops->sync_send_receive(ffa_dev, data);
		if (rc)
			goto done;

		switch ((int)data->data0) {
		case TEEC_SUCCESS:
			break;
		case TEEC_ERROR_BUSY:
			if (cmd == OPTEE_FFA_YIELDING_CALL_RESUME) {
				rc = -EIO;
				goto done;
			}

			/*
			 * Out of threads in secure world, wait for a thread
			 * become available.
			 */
			optee_cq_wait_for_completion(&optee->call_queue, &w);
			data->data0 = cmd;
			data->data1 = w4;
			data->data2 = w5;
			data->data3 = w6;
			continue;
		default:
			rc = -EIO;
			goto done;
		}

		if (data->data1 == OPTEE_FFA_YIELDING_CALL_RETURN_DONE)
			goto done;

		/*
		 * OP-TEE has returned with a RPC request.
		 *
		 * Note that data->data4 (passed in register w7) is already
		 * filled in by ffa_ops->sync_send_receive() returning
		 * above.
		 */
		cond_resched();
		optee_handle_ffa_rpc(ctx, data->data1, rpc_arg);
		cmd = OPTEE_FFA_YIELDING_CALL_RESUME;
		data->data0 = cmd;
		data->data1 = 0;
		data->data2 = 0;
		data->data3 = 0;
	}
done:
	/*
	 * We're done with our thread in secure world, if there's any
	 * thread waiters wake up one.
	 */
	optee_cq_wait_final(&optee->call_queue, &w);

	return rc;
}

/**
 * optee_ffa_do_call_with_arg() - Do a FF-A call to enter OP-TEE in secure world
 * @ctx:	calling context
 * @shm:	shared memory holding the message to pass to secure world
 *
 * Does a FF-A call to OP-TEE in secure world and handles eventual resulting
 * Remote Procedure Calls (RPC) from OP-TEE.
 *
 * Returns return code from FF-A, 0 is OK
 */

static int optee_ffa_do_call_with_arg(struct tee_context *ctx,
				      struct tee_shm *shm)
{
	struct ffa_send_direct_data data = {
		.data0 = OPTEE_FFA_YIELDING_CALL_WITH_ARG,
		.data1 = (u32)shm->sec_world_id,
		.data2 = (u32)(shm->sec_world_id >> 32),
		.data3 = shm->offset,
	};
	struct optee_msg_arg *arg = tee_shm_get_va(shm, 0);
	unsigned int rpc_arg_offs = OPTEE_MSG_GET_ARG_SIZE(arg->num_params);
	struct optee_msg_arg *rpc_arg = tee_shm_get_va(shm, rpc_arg_offs);

	return optee_ffa_yielding_call(ctx, &data, rpc_arg);
}

/*
 * 6. Driver initialization
 *
 * During driver inititialization is the OP-TEE Secure Partition is probed
 * to find out which features it supports so the driver can be initialized
 * with a matching configuration.
 */

static bool optee_ffa_api_is_compatbile(struct ffa_device *ffa_dev,
					const struct ffa_dev_ops *ops)
{
	struct ffa_send_direct_data data = { OPTEE_FFA_GET_API_VERSION };
	int rc;

	ops->mode_32bit_set(ffa_dev);

	rc = ops->sync_send_receive(ffa_dev, &data);
	if (rc) {
		pr_err("Unexpected error %d\n", rc);
		return false;
	}
	if (data.data0 != OPTEE_FFA_VERSION_MAJOR ||
	    data.data1 < OPTEE_FFA_VERSION_MINOR) {
		pr_err("Incompatible OP-TEE API version %lu.%lu",
		       data.data0, data.data1);
		return false;
	}

	data = (struct ffa_send_direct_data){ OPTEE_FFA_GET_OS_VERSION };
	rc = ops->sync_send_receive(ffa_dev, &data);
	if (rc) {
		pr_err("Unexpected error %d\n", rc);
		return false;
	}
	if (data.data2)
		pr_info("revision %lu.%lu (%08lx)",
			data.data0, data.data1, data.data2);
	else
		pr_info("revision %lu.%lu", data.data0, data.data1);

	return true;
}

static bool optee_ffa_exchange_caps(struct ffa_device *ffa_dev,
				    const struct ffa_dev_ops *ops,
				    unsigned int *rpc_arg_count)
{
	struct ffa_send_direct_data data = { OPTEE_FFA_EXCHANGE_CAPABILITIES };
	int rc;

	rc = ops->sync_send_receive(ffa_dev, &data);
	if (rc) {
		pr_err("Unexpected error %d", rc);
		return false;
	}
	if (data.data0) {
		pr_err("Unexpected exchange error %lu", data.data0);
		return false;
	}

	*rpc_arg_count = (u8)data.data1;

	return true;
}

static struct tee_shm_pool *optee_ffa_config_dyn_shm(void)
{
	struct tee_shm_pool_mgr *priv_mgr;
	struct tee_shm_pool_mgr *dmabuf_mgr;
	void *rc;

	rc = optee_ffa_shm_pool_alloc_pages();
	if (IS_ERR(rc))
		return rc;
	priv_mgr = rc;

	rc = optee_ffa_shm_pool_alloc_pages();
	if (IS_ERR(rc)) {
		tee_shm_pool_mgr_destroy(priv_mgr);
		return rc;
	}
	dmabuf_mgr = rc;

	rc = tee_shm_pool_alloc(priv_mgr, dmabuf_mgr);
	if (IS_ERR(rc)) {
		tee_shm_pool_mgr_destroy(priv_mgr);
		tee_shm_pool_mgr_destroy(dmabuf_mgr);
	}

	return rc;
}

static void optee_ffa_get_version(struct tee_device *teedev,
				  struct tee_ioctl_version_data *vers)
{
	struct tee_ioctl_version_data v = {
		.impl_id = TEE_IMPL_ID_OPTEE,
		.impl_caps = TEE_OPTEE_CAP_TZ,
		.gen_caps = TEE_GEN_CAP_GP | TEE_GEN_CAP_REG_MEM |
			    TEE_GEN_CAP_MEMREF_NULL,
	};

	*vers = v;
}

static int optee_ffa_open(struct tee_context *ctx)
{
	return optee_open(ctx, true);
}

static const struct tee_driver_ops optee_ffa_clnt_ops = {
	.get_version = optee_ffa_get_version,
	.open = optee_ffa_open,
	.release = optee_release,
	.open_session = optee_open_session,
	.close_session = optee_close_session,
	.invoke_func = optee_invoke_func,
	.cancel_req = optee_cancel_req,
	.shm_register = optee_ffa_shm_register,
	.shm_unregister = optee_ffa_shm_unregister,
};

static const struct tee_desc optee_ffa_clnt_desc = {
	.name = DRIVER_NAME "-ffa-clnt",
	.ops = &optee_ffa_clnt_ops,
	.owner = THIS_MODULE,
};

static const struct tee_driver_ops optee_ffa_supp_ops = {
	.get_version = optee_ffa_get_version,
	.open = optee_ffa_open,
	.release = optee_release_supp,
	.supp_recv = optee_supp_recv,
	.supp_send = optee_supp_send,
	.shm_register = optee_ffa_shm_register, /* same as for clnt ops */
	.shm_unregister = optee_ffa_shm_unregister_supp,
};

static const struct tee_desc optee_ffa_supp_desc = {
	.name = DRIVER_NAME "-ffa-supp",
	.ops = &optee_ffa_supp_ops,
	.owner = THIS_MODULE,
	.flags = TEE_DESC_PRIVILEGED,
};

static const struct optee_ops optee_ffa_ops = {
	.do_call_with_arg = optee_ffa_do_call_with_arg,
	.to_msg_param = optee_ffa_to_msg_param,
	.from_msg_param = optee_ffa_from_msg_param,
};

static void optee_ffa_remove(struct ffa_device *ffa_dev)
{
	struct optee *optee = ffa_dev->dev.driver_data;

	optee_remove_common(optee);

	mutex_destroy(&optee->ffa.mutex);
	rhashtable_free_and_destroy(&optee->ffa.global_ids, rh_free_fn, NULL);

	kfree(optee);
}

static int optee_ffa_probe(struct ffa_device *ffa_dev)
{
	const struct ffa_dev_ops *ffa_ops;
	unsigned int rpc_arg_count;
	struct tee_device *teedev;
	struct optee *optee;
	int rc;

	ffa_ops = ffa_dev_ops_get(ffa_dev);
	if (!ffa_ops) {
		pr_warn("failed \"method\" init: ffa\n");
		return -ENOENT;
	}

	if (!optee_ffa_api_is_compatbile(ffa_dev, ffa_ops))
		return -EINVAL;

	if (!optee_ffa_exchange_caps(ffa_dev, ffa_ops, &rpc_arg_count))
		return -EINVAL;

	optee = kzalloc(sizeof(*optee), GFP_KERNEL);
	if (!optee)
		return -ENOMEM;

	optee->pool = optee_ffa_config_dyn_shm();
	if (IS_ERR(optee->pool)) {
		rc = PTR_ERR(optee->pool);
		optee->pool = NULL;
		goto err;
	}

	optee->ops = &optee_ffa_ops;
	optee->ffa.ffa_dev = ffa_dev;
	optee->ffa.ffa_ops = ffa_ops;
	optee->rpc_arg_count = rpc_arg_count;

	teedev = tee_device_alloc(&optee_ffa_clnt_desc, NULL, optee->pool,
				  optee);
	if (IS_ERR(teedev)) {
		rc = PTR_ERR(teedev);
		goto err;
	}
	optee->teedev = teedev;

	teedev = tee_device_alloc(&optee_ffa_supp_desc, NULL, optee->pool,
				  optee);
	if (IS_ERR(teedev)) {
		rc = PTR_ERR(teedev);
		goto err;
	}
	optee->supp_teedev = teedev;

	rc = tee_device_register(optee->teedev);
	if (rc)
		goto err;

	rc = tee_device_register(optee->supp_teedev);
	if (rc)
		goto err;

	rc = rhashtable_init(&optee->ffa.global_ids, &shm_rhash_params);
	if (rc)
		goto err;
	mutex_init(&optee->ffa.mutex);
	mutex_init(&optee->call_queue.mutex);
	INIT_LIST_HEAD(&optee->call_queue.waiters);
	optee_wait_queue_init(&optee->wait_queue);
	optee_supp_init(&optee->supp);
	ffa_dev_set_drvdata(ffa_dev, optee);

	rc = optee_enumerate_devices(PTA_CMD_GET_DEVICES);
	if (rc) {
		optee_ffa_remove(ffa_dev);
		return rc;
	}

	pr_info("initialized driver\n");
	return 0;
err:
	/*
	 * tee_device_unregister() is safe to call even if the
	 * devices hasn't been registered with
	 * tee_device_register() yet.
	 */
	tee_device_unregister(optee->supp_teedev);
	tee_device_unregister(optee->teedev);
	if (optee->pool)
		tee_shm_pool_free(optee->pool);
	kfree(optee);
	return rc;
}

static const struct ffa_device_id optee_ffa_device_id[] = {
	/* 486178e0-e7f8-11e3-bc5e0002a5d5c51b */
	{ UUID_INIT(0x486178e0, 0xe7f8, 0x11e3,
		    0xbc, 0x5e, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b) },
	{}
};

static struct ffa_driver optee_ffa_driver = {
	.name = "optee",
	.probe = optee_ffa_probe,
	.remove = optee_ffa_remove,
	.id_table = optee_ffa_device_id,
};

int optee_ffa_abi_register(void)
{
	if (IS_REACHABLE(CONFIG_ARM_FFA_TRANSPORT))
		return ffa_register(&optee_ffa_driver);
	else
		return -EOPNOTSUPP;
}

void optee_ffa_abi_unregister(void)
{
	if (IS_REACHABLE(CONFIG_ARM_FFA_TRANSPORT))
		ffa_unregister(&optee_ffa_driver);
}
