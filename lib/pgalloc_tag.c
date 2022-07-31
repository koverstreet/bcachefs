// SPDX-License-Identifier: GPL-2.0-only
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pgalloc_tag.h>
#include <linux/seq_file.h>

static __init bool need_page_alloc_tagging(void)
{
	return true;
}

static __init void init_page_alloc_tagging(void)
{
}

struct page_ext_operations page_alloc_tagging_ops = {
	.size = sizeof(union codetag_ref),
	.need = need_page_alloc_tagging,
	.init = init_page_alloc_tagging,
};
EXPORT_SYMBOL(page_alloc_tagging_ops);
