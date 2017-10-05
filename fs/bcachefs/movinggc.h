#ifndef _BCACHEFS_MOVINGGC_H
#define _BCACHEFS_MOVINGGC_H

/*
 * We can't use the entire copygc reserve in one iteration of copygc: we may
 * need the buckets we're freeing up to go back into the copygc reserve to make
 * forward progress, but if the copygc reserve is full they'll be available for
 * any allocation - and it's possible that in a given iteration, we free up most
 * of the buckets we're going to free before we allocate most of the buckets
 * we're going to allocate.
 *
 * If we only use half of the reserve per iteration, then in steady state we'll
 * always have room in the reserve for the buckets we're going to need in the
 * next iteration:
 */
#define COPYGC_BUCKETS_PER_ITER(ca)					\
	((ca)->free[RESERVE_MOVINGGC].size / 2)

/*
 * Max sectors to move per iteration: Have to take into account internal
 * fragmentation from the multiple write points for each generation:
 */
#define COPYGC_SECTORS_PER_ITER(ca)					\
	((ca)->mi.bucket_size *	COPYGC_BUCKETS_PER_ITER(ca))

void bch2_moving_gc_stop(struct bch_dev *);
int bch2_moving_gc_start(struct bch_dev *);
void bch2_dev_moving_gc_init(struct bch_dev *);

#endif /* _BCACHEFS_MOVINGGC_H */
