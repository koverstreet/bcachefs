// SPDX-License-Identifier: MIT
/*
 * Copyright © 2021 Intel Corporation
 */

#include "intel_display_types.h"
#include "intel_plane_initial.h"
#include "intel_atomic_plane.h"
#include "intel_display.h"
#include "intel_fb.h"

static bool
intel_reuse_initial_plane_obj(struct drm_i915_private *i915,
			      const struct intel_initial_plane_config *plane_config,
			      struct drm_framebuffer **fb,
			      struct i915_vma **vma)
{
	struct intel_crtc *crtc;

	for_each_intel_crtc(&i915->drm, crtc) {
		struct intel_crtc_state *crtc_state =
			to_intel_crtc_state(crtc->base.state);
		struct intel_plane *plane =
			to_intel_plane(crtc->base.primary);
		struct intel_plane_state *plane_state =
			to_intel_plane_state(plane->base.state);

		if (!crtc_state->uapi.active)
			continue;

		if (!plane_state->ggtt_vma)
			continue;

		if (intel_plane_ggtt_offset(plane_state) == plane_config->base) {
			*fb = plane_state->hw.fb;
			*vma = plane_state->ggtt_vma;
			return true;
		}
	}

	return false;
}

static struct i915_vma *
initial_plane_vma(struct drm_i915_private *i915,
		  struct intel_initial_plane_config *plane_config)
{
	struct drm_i915_gem_object *obj;
	struct i915_vma *vma;
	u32 base, size;

	if (plane_config->size == 0)
		return NULL;

	base = round_down(plane_config->base,
			  I915_GTT_MIN_ALIGNMENT);
	size = round_up(plane_config->base + plane_config->size,
			I915_GTT_MIN_ALIGNMENT);
	size -= base;

	/*
	 * If the FB is too big, just don't use it since fbdev is not very
	 * important and we should probably use that space with FBC or other
	 * features.
	 */
	if (IS_ENABLED(CONFIG_FRAMEBUFFER_CONSOLE) &&
	    size * 2 > i915->stolen_usable_size)
		return NULL;

	obj = i915_gem_object_create_stolen_for_preallocated(i915, base, size);
	if (IS_ERR(obj))
		return NULL;

	/*
	 * Mark it WT ahead of time to avoid changing the
	 * cache_level during fbdev initialization. The
	 * unbind there would get stuck waiting for rcu.
	 */
	i915_gem_object_set_cache_coherency(obj, HAS_WT(i915) ?
					    I915_CACHE_WT : I915_CACHE_NONE);

	switch (plane_config->tiling) {
	case I915_TILING_NONE:
		break;
	case I915_TILING_X:
	case I915_TILING_Y:
		obj->tiling_and_stride =
			plane_config->fb->base.pitches[0] |
			plane_config->tiling;
		break;
	default:
		MISSING_CASE(plane_config->tiling);
		goto err_obj;
	}

	vma = i915_vma_instance(obj, &i915->ggtt.vm, NULL);
	if (IS_ERR(vma))
		goto err_obj;

	if (i915_ggtt_pin(vma, NULL, 0, PIN_MAPPABLE | PIN_OFFSET_FIXED | base))
		goto err_obj;

	if (i915_gem_object_is_tiled(obj) &&
	    !i915_vma_is_map_and_fenceable(vma))
		goto err_obj;

	return vma;

err_obj:
	i915_gem_object_put(obj);
	return NULL;
}

static bool
intel_alloc_initial_plane_obj(struct intel_crtc *crtc,
			      struct intel_initial_plane_config *plane_config)
{
	struct drm_device *dev = crtc->base.dev;
	struct drm_i915_private *dev_priv = to_i915(dev);
	struct drm_mode_fb_cmd2 mode_cmd = { 0 };
	struct drm_framebuffer *fb = &plane_config->fb->base;
	struct i915_vma *vma;

	switch (fb->modifier) {
	case DRM_FORMAT_MOD_LINEAR:
	case I915_FORMAT_MOD_X_TILED:
	case I915_FORMAT_MOD_Y_TILED:
		break;
	default:
		drm_dbg(&dev_priv->drm,
			"Unsupported modifier for initial FB: 0x%llx\n",
			fb->modifier);
		return false;
	}

	vma = initial_plane_vma(dev_priv, plane_config);
	if (!vma)
		return false;

	mode_cmd.pixel_format = fb->format->format;
	mode_cmd.width = fb->width;
	mode_cmd.height = fb->height;
	mode_cmd.pitches[0] = fb->pitches[0];
	mode_cmd.modifier[0] = fb->modifier;
	mode_cmd.flags = DRM_MODE_FB_MODIFIERS;

	if (intel_framebuffer_init(to_intel_framebuffer(fb),
				   vma->obj, &mode_cmd)) {
		drm_dbg_kms(&dev_priv->drm, "intel fb init failed\n");
		goto err_vma;
	}

	plane_config->vma = vma;
	return true;

err_vma:
	i915_vma_put(vma);
	return false;
}

static void
intel_find_initial_plane_obj(struct intel_crtc *crtc,
			     struct intel_initial_plane_config *plane_config)
{
	struct drm_device *dev = crtc->base.dev;
	struct drm_i915_private *dev_priv = to_i915(dev);
	struct intel_crtc_state *crtc_state =
		to_intel_crtc_state(crtc->base.state);
	struct intel_plane *plane =
		to_intel_plane(crtc->base.primary);
	struct intel_plane_state *plane_state =
		to_intel_plane_state(plane->base.state);
	struct drm_framebuffer *fb;
	struct i915_vma *vma;

	/*
	 * TODO:
	 *   Disable planes if get_initial_plane_config() failed.
	 *   Make sure things work if the surface base is not page aligned.
	 */
	if (!plane_config->fb)
		return;

	if (intel_alloc_initial_plane_obj(crtc, plane_config)) {
		fb = &plane_config->fb->base;
		vma = plane_config->vma;
		goto valid_fb;
	}

	/*
	 * Failed to alloc the obj, check to see if we should share
	 * an fb with another CRTC instead
	 */
	if (intel_reuse_initial_plane_obj(dev_priv, plane_config, &fb, &vma))
		goto valid_fb;

	/*
	 * We've failed to reconstruct the BIOS FB.  Current display state
	 * indicates that the primary plane is visible, but has a NULL FB,
	 * which will lead to problems later if we don't fix it up.  The
	 * simplest solution is to just disable the primary plane now and
	 * pretend the BIOS never had it enabled.
	 */
	intel_plane_disable_noatomic(crtc, plane);
	if (crtc_state->bigjoiner) {
		struct intel_crtc *slave =
			crtc_state->bigjoiner_linked_crtc;
		intel_plane_disable_noatomic(slave, to_intel_plane(slave->base.primary));
	}

	return;

valid_fb:
	plane_state->uapi.rotation = plane_config->rotation;
	intel_fb_fill_view(to_intel_framebuffer(fb),
			   plane_state->uapi.rotation, &plane_state->view);

	__i915_vma_pin(vma);
	plane_state->ggtt_vma = i915_vma_get(vma);
	if (intel_plane_uses_fence(plane_state) &&
	    i915_vma_pin_fence(vma) == 0 && vma->fence)
		plane_state->flags |= PLANE_HAS_FENCE;

	plane_state->uapi.src_x = 0;
	plane_state->uapi.src_y = 0;
	plane_state->uapi.src_w = fb->width << 16;
	plane_state->uapi.src_h = fb->height << 16;

	plane_state->uapi.crtc_x = 0;
	plane_state->uapi.crtc_y = 0;
	plane_state->uapi.crtc_w = fb->width;
	plane_state->uapi.crtc_h = fb->height;

	if (plane_config->tiling)
		dev_priv->preserve_bios_swizzle = true;

	plane_state->uapi.fb = fb;
	drm_framebuffer_get(fb);

	plane_state->uapi.crtc = &crtc->base;
	intel_plane_copy_uapi_to_hw_state(plane_state, plane_state, crtc);

	atomic_or(plane->frontbuffer_bit, &to_intel_frontbuffer(fb)->bits);
}

static void plane_config_fini(struct intel_initial_plane_config *plane_config)
{
	if (plane_config->fb) {
		struct drm_framebuffer *fb = &plane_config->fb->base;

		/* We may only have the stub and not a full framebuffer */
		if (drm_framebuffer_read_refcount(fb))
			drm_framebuffer_put(fb);
		else
			kfree(fb);
	}

	if (plane_config->vma)
		i915_vma_put(plane_config->vma);
}

void intel_crtc_initial_plane_config(struct intel_crtc *crtc)
{
	struct drm_i915_private *dev_priv = to_i915(crtc->base.dev);
	struct intel_initial_plane_config plane_config = {};

	/*
	 * Note that reserving the BIOS fb up front prevents us
	 * from stuffing other stolen allocations like the ring
	 * on top.  This prevents some ugliness at boot time, and
	 * can even allow for smooth boot transitions if the BIOS
	 * fb is large enough for the active pipe configuration.
	 */
	dev_priv->display->get_initial_plane_config(crtc, &plane_config);

	/*
	 * If the fb is shared between multiple heads, we'll
	 * just get the first one.
	 */
	intel_find_initial_plane_obj(crtc, &plane_config);

	plane_config_fini(&plane_config);
}
