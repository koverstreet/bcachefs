// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/slab_alloc_tag.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <../mm/slab.h>

union codetag_ref *get_slab_tag_ref(const void *objp)
{
	struct slabobj_ext *obj_exts;
	union codetag_ref *res = NULL;
	struct slab *slab;
	unsigned int off;

	slab = virt_to_slab(objp);
	/*
	 * We could be given a kmalloc_large() object, skip those. They use
	 * alloc_pages and can be tracked by page allocation tracking.
	 */
	if (!slab)
		goto out;

	obj_exts = slab_obj_exts(slab);
	if (!obj_exts)
		goto out;

	if (!slab->slab_cache)
		goto out;

	off = obj_to_index(slab->slab_cache, slab, objp);
	res = &obj_exts[off].ref;
out:
	return res;
}
EXPORT_SYMBOL(get_slab_tag_ref);
