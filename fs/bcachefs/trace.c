#include "bcache.h"
#include "btree.h"
#include "buckets.h"

#include <linux/blktrace_api.h>
#include "keylist.h"

#define CREATE_TRACE_POINTS
#include <trace/events/bcachefs.h>
