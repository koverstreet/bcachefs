// SPDX-License-Identifier: GPL-2.0
/*
 * This file contains core hardware tag-based KASAN code.
 *
 * Copyright (c) 2020 Google, Inc.
 * Author: Andrey Konovalov <andreyknvl@google.com>
 */

#define pr_fmt(fmt) "kasan: " fmt

#include <linux/init.h>
#include <linux/kasan.h>
#include <linux/kernel.h>
#include <linux/memory.h>
#include <linux/mm.h>
#include <linux/static_key.h>
#include <linux/string.h>
#include <linux/types.h>

#include "kasan.h"

enum kasan_arg {
	KASAN_ARG_DEFAULT,
	KASAN_ARG_OFF,
	KASAN_ARG_ON,
};

enum kasan_arg_mode {
	KASAN_ARG_MODE_DEFAULT,
	KASAN_ARG_MODE_SYNC,
	KASAN_ARG_MODE_ASYNC,
	KASAN_ARG_MODE_ASYMM,
};

enum kasan_arg_stacktrace {
	KASAN_ARG_STACKTRACE_DEFAULT,
	KASAN_ARG_STACKTRACE_OFF,
	KASAN_ARG_STACKTRACE_ON,
};

static enum kasan_arg kasan_arg __ro_after_init;
static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;

/* Whether KASAN is enabled at all. */
DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
EXPORT_SYMBOL(kasan_flag_enabled);

/* Whether the selected mode is synchronous/asynchronous/asymmetric.*/
enum kasan_mode kasan_mode __ro_after_init;
EXPORT_SYMBOL_GPL(kasan_mode);

/* Whether to collect alloc/free stack traces. */
DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);

/* kasan=off/on */
static int __init early_kasan_flag(char *arg)
{
	if (!arg)
		return -EINVAL;

	if (!strcmp(arg, "off"))
		kasan_arg = KASAN_ARG_OFF;
	else if (!strcmp(arg, "on"))
		kasan_arg = KASAN_ARG_ON;
	else
		return -EINVAL;

	return 0;
}
early_param("kasan", early_kasan_flag);

/* kasan.mode=sync/async/asymm */
static int __init early_kasan_mode(char *arg)
{
	if (!arg)
		return -EINVAL;

	if (!strcmp(arg, "sync"))
		kasan_arg_mode = KASAN_ARG_MODE_SYNC;
	else if (!strcmp(arg, "async"))
		kasan_arg_mode = KASAN_ARG_MODE_ASYNC;
	else if (!strcmp(arg, "asymm"))
		kasan_arg_mode = KASAN_ARG_MODE_ASYMM;
	else
		return -EINVAL;

	return 0;
}
early_param("kasan.mode", early_kasan_mode);

/* kasan.stacktrace=off/on */
static int __init early_kasan_flag_stacktrace(char *arg)
{
	if (!arg)
		return -EINVAL;

	if (!strcmp(arg, "off"))
		kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_OFF;
	else if (!strcmp(arg, "on"))
		kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_ON;
	else
		return -EINVAL;

	return 0;
}
early_param("kasan.stacktrace", early_kasan_flag_stacktrace);

static inline const char *kasan_mode_info(void)
{
	if (kasan_mode == KASAN_MODE_ASYNC)
		return "async";
	else if (kasan_mode == KASAN_MODE_ASYMM)
		return "asymm";
	else
		return "sync";
}

/* kasan_init_hw_tags_cpu() is called for each CPU. */
void kasan_init_hw_tags_cpu(void)
{
	/*
	 * There's no need to check that the hardware is MTE-capable here,
	 * as this function is only called for MTE-capable hardware.
	 */

	/* If KASAN is disabled via command line, don't initialize it. */
	if (kasan_arg == KASAN_ARG_OFF)
		return;

	/*
	 * Enable async or asymm modes only when explicitly requested
	 * through the command line.
	 */
	if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
		hw_enable_tagging_async();
	else if (kasan_arg_mode == KASAN_ARG_MODE_ASYMM)
		hw_enable_tagging_asymm();
	else
		hw_enable_tagging_sync();
}

/* kasan_init_hw_tags() is called once on boot CPU. */
void __init kasan_init_hw_tags(void)
{
	/* If hardware doesn't support MTE, don't initialize KASAN. */
	if (!system_supports_mte())
		return;

	/* If KASAN is disabled via command line, don't initialize it. */
	if (kasan_arg == KASAN_ARG_OFF)
		return;

	/* Enable KASAN. */
	static_branch_enable(&kasan_flag_enabled);

	switch (kasan_arg_mode) {
	case KASAN_ARG_MODE_DEFAULT:
		/*
		 * Default to sync mode.
		 */
		fallthrough;
	case KASAN_ARG_MODE_SYNC:
		/* Sync mode enabled. */
		kasan_mode = KASAN_MODE_SYNC;
		break;
	case KASAN_ARG_MODE_ASYNC:
		/* Async mode enabled. */
		kasan_mode = KASAN_MODE_ASYNC;
		break;
	case KASAN_ARG_MODE_ASYMM:
		/* Asymm mode enabled. */
		kasan_mode = KASAN_MODE_ASYMM;
		break;
	}

	switch (kasan_arg_stacktrace) {
	case KASAN_ARG_STACKTRACE_DEFAULT:
		/* Default to enabling stack trace collection. */
		static_branch_enable(&kasan_flag_stacktrace);
		break;
	case KASAN_ARG_STACKTRACE_OFF:
		/* Do nothing, kasan_flag_stacktrace keeps its default value. */
		break;
	case KASAN_ARG_STACKTRACE_ON:
		static_branch_enable(&kasan_flag_stacktrace);
		break;
	}

	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, stacktrace=%s)\n",
		kasan_mode_info(),
		kasan_stack_collection_enabled() ? "on" : "off");
}

void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
{
	/*
	 * This condition should match the one in post_alloc_hook() in
	 * page_alloc.c.
	 */
	bool init = !want_init_on_free() && want_init_on_alloc(flags);

	if (flags & __GFP_SKIP_KASAN_POISON)
		SetPageSkipKASanPoison(page);

	if (flags & __GFP_ZEROTAGS) {
		int i;

		for (i = 0; i != 1 << order; ++i)
			tag_clear_highpage(page + i);
	} else {
		kasan_unpoison_pages(page, order, init);
	}
}

void kasan_free_pages(struct page *page, unsigned int order)
{
	/*
	 * This condition should match the one in free_pages_prepare() in
	 * page_alloc.c.
	 */
	bool init = want_init_on_free();

	kasan_poison_pages(page, order, init);
}

#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)

void kasan_enable_tagging_sync(void)
{
	hw_enable_tagging_sync();
}
EXPORT_SYMBOL_GPL(kasan_enable_tagging_sync);

void kasan_force_async_fault(void)
{
	hw_force_async_tag_fault();
}
EXPORT_SYMBOL_GPL(kasan_force_async_fault);

#endif
