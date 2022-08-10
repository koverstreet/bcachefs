// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"
#include "alloc_types.h"
#include "buckets.h"
#include "btree_iter.h"
#include "btree_locking.h"
#include "keylist.h"
#include "opts.h"

#include <linux/blktrace_api.h>
#include <linux/six.h>

#define CREATE_TRACE_POINTS
#include <trace/events/bcachefs.h>
