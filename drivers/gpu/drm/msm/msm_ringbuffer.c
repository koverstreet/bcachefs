// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2013 Red Hat
 * Author: Rob Clark <robdclark@gmail.com>
 */

#include "msm_ringbuffer.h"
#include "msm_gpu.h"

static uint num_hw_submissions = 8;
MODULE_PARM_DESC(num_hw_submissions, "The max # of jobs to write into ringbuffer (default 8)");
module_param(num_hw_submissions, uint, 0600);

static struct dma_fence *msm_job_run(struct drm_sched_job *job)
{
	struct msm_gem_submit *submit = to_msm_submit(job);
	struct msm_gpu *gpu = submit->gpu;

	submit->hw_fence = msm_fence_alloc(submit->ring->fctx);

	pm_runtime_get_sync(&gpu->pdev->dev);

	/* TODO move submit path over to using a per-ring lock.. */
	mutex_lock(&gpu->dev->struct_mutex);

	msm_gpu_submit(gpu, submit);

	mutex_unlock(&gpu->dev->struct_mutex);

	pm_runtime_put(&gpu->pdev->dev);

	return dma_fence_get(submit->hw_fence);
}

static void msm_job_free(struct drm_sched_job *job)
{
	struct msm_gem_submit *submit = to_msm_submit(job);

	drm_sched_job_cleanup(job);
	msm_gem_submit_put(submit);
}

const struct drm_sched_backend_ops msm_sched_ops = {
	.run_job = msm_job_run,
	.free_job = msm_job_free
};

struct msm_ringbuffer *msm_ringbuffer_new(struct msm_gpu *gpu, int id,
		void *memptrs, uint64_t memptrs_iova)
{
	struct msm_ringbuffer *ring;
	long sched_timeout;
	char name[32];
	int ret;

	/* We assume everwhere that MSM_GPU_RINGBUFFER_SZ is a power of 2 */
	BUILD_BUG_ON(!is_power_of_2(MSM_GPU_RINGBUFFER_SZ));

	ring = kzalloc(sizeof(*ring), GFP_KERNEL);
	if (!ring) {
		ret = -ENOMEM;
		goto fail;
	}

	ring->gpu = gpu;
	ring->id = id;

	ring->start = msm_gem_kernel_new(gpu->dev, MSM_GPU_RINGBUFFER_SZ,
		check_apriv(gpu, MSM_BO_WC | MSM_BO_GPU_READONLY),
		gpu->aspace, &ring->bo, &ring->iova);

	if (IS_ERR(ring->start)) {
		ret = PTR_ERR(ring->start);
		ring->start = NULL;
		goto fail;
	}

	msm_gem_object_set_name(ring->bo, "ring%d", id);

	ring->end   = ring->start + (MSM_GPU_RINGBUFFER_SZ >> 2);
	ring->next  = ring->start;
	ring->cur   = ring->start;

	ring->memptrs = memptrs;
	ring->memptrs_iova = memptrs_iova;

	 /* currently managing hangcheck ourselves: */
	sched_timeout = MAX_SCHEDULE_TIMEOUT;

	ret = drm_sched_init(&ring->sched, &msm_sched_ops,
			num_hw_submissions, 0, sched_timeout,
			NULL, NULL, to_msm_bo(ring->bo)->name);
	if (ret) {
		goto fail;
	}

	INIT_LIST_HEAD(&ring->submits);
	spin_lock_init(&ring->submit_lock);
	spin_lock_init(&ring->preempt_lock);

	snprintf(name, sizeof(name), "gpu-ring-%d", ring->id);

	ring->fctx = msm_fence_context_alloc(gpu->dev, &ring->memptrs->fence, name);

	return ring;

fail:
	msm_ringbuffer_destroy(ring);
	return ERR_PTR(ret);
}

void msm_ringbuffer_destroy(struct msm_ringbuffer *ring)
{
	if (IS_ERR_OR_NULL(ring))
		return;

	drm_sched_fini(&ring->sched);

	msm_fence_context_free(ring->fctx);

	msm_gem_kernel_put(ring->bo, ring->gpu->aspace);

	kfree(ring);
}
