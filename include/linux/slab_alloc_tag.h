/* SPDX-License-Identifier: GPL-2.0 */
/*
 * slab allocation tagging
 */
#ifndef _LINUX_SLAB_ALLOC_TAG_H
#define _LINUX_SLAB_ALLOC_TAG_H

#ifdef CONFIG_SLAB_ALLOC_TAGGING

#include <linux/alloc_tag.h>

union codetag_ref *get_slab_tag_ref(const void *objp);

#endif /* CONFIG_SLAB_ALLOC_TAGGING */

#endif /* _LINUX_SLAB_ALLOC_TAG_H */
