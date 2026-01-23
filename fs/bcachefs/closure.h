#include "vendor/closure.h"

#define closure_wait		bch2_closure_wait
#define closure_return_sync	bch2_closure_return_sync
#define __closure_wake_up	__bch2_closure_wake_up
#define closure_sync_unbounded	bch2_closure_sync_unbounded
