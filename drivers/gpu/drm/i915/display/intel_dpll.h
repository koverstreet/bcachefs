/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2020 Intel Corporation
 */

#ifndef _INTEL_DPLL_H_
#define _INTEL_DPLL_H_

#include <linux/types.h>

struct dpll;
struct drm_i915_private;
struct intel_crtc;
struct intel_crtc_state;
enum pipe;

void intel_dpll_init_clock_hook(struct drm_i915_private *dev_priv);
int vlv_calc_dpll_params(int refclk, struct dpll *clock);
int pnv_calc_dpll_params(int refclk, struct dpll *clock);
int i9xx_calc_dpll_params(int refclk, struct dpll *clock);
u32 i9xx_dpll_compute_fp(const struct dpll *dpll);
void vlv_compute_dpll(struct intel_crtc_state *crtc_state);
void chv_compute_dpll(struct intel_crtc_state *crtc_state);

int vlv_force_pll_on(struct drm_i915_private *dev_priv, enum pipe pipe,
		     const struct dpll *dpll);
void vlv_force_pll_off(struct drm_i915_private *dev_priv, enum pipe pipe);

void chv_enable_pll(const struct intel_crtc_state *crtc_state);
void chv_disable_pll(struct drm_i915_private *dev_priv, enum pipe pipe);
void vlv_enable_pll(const struct intel_crtc_state *crtc_state);
void vlv_disable_pll(struct drm_i915_private *dev_priv, enum pipe pipe);
void i9xx_enable_pll(const struct intel_crtc_state *crtc_state);
void i9xx_disable_pll(const struct intel_crtc_state *crtc_state);
bool bxt_find_best_dpll(struct intel_crtc_state *crtc_state,
			struct dpll *best_clock);
int chv_calc_dpll_params(int refclk, struct dpll *pll_clock);

void assert_pll_enabled(struct drm_i915_private *i915, enum pipe pipe);
void assert_pll_disabled(struct drm_i915_private *i915, enum pipe pipe);

#endif
