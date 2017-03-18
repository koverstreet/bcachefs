#include "bcache.h"
#include "error.h"
#include "io.h"
#include "super.h"

void bch_inconsistent_error(struct bch_fs *c)
{
	set_bit(BCH_FS_ERROR, &c->flags);

	switch (c->opts.errors) {
	case BCH_ON_ERROR_CONTINUE:
		break;
	case BCH_ON_ERROR_RO:
		if (bch_fs_emergency_read_only(c))
			bch_err(c, "emergency read only");
		break;
	case BCH_ON_ERROR_PANIC:
		panic(bch_fmt(c, "panic after error"));
		break;
	}
}

void bch_fatal_error(struct bch_fs *c)
{
	if (bch_fs_emergency_read_only(c))
		bch_err(c, "emergency read only");
}

void bch_nonfatal_io_error_work(struct work_struct *work)
{
	struct bch_dev *ca = container_of(work, struct bch_dev, io_error_work);
	struct bch_fs *c = ca->fs;
	bool dev;

	mutex_lock(&c->state_lock);
	dev = bch_dev_state_allowed(c, ca, BCH_MEMBER_STATE_RO,
				    BCH_FORCE_IF_DEGRADED);
	if (dev
	    ? __bch_dev_set_state(c, ca, BCH_MEMBER_STATE_RO,
				  BCH_FORCE_IF_DEGRADED)
	    : bch_fs_emergency_read_only(c))
		bch_err(ca,
			"too many IO errors, setting %s RO",
			dev ? "device" : "filesystem");
	mutex_unlock(&c->state_lock);
}

void bch_nonfatal_io_error(struct bch_dev *ca)
{
	queue_work(system_long_wq, &ca->io_error_work);
}
