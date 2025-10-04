// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"
#include "alloc_types.h"
#include "buckets.h"
#include "btree/cache.h"
#include "btree/iter.h"
#include "btree/key_cache.h"
#include "btree/locking.h"
#include "btree/interior.h"
#include "keylist.h"
#include "move_types.h"
#include "opts.h"
#include "six.h"

#include <linux/blktrace_api.h>

#define CREATE_TRACE_POINTS
#include "trace.h"
