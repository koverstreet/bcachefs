// SPDX-License-Identifier: GPL-2.0
#include "bcachefs.h"

#include "alloc/accounting.h"
#include "alloc/background.h"
#include "alloc/backpointers.h"
#include "alloc/buckets.h"
#include "alloc/check.h"
#include "alloc/discard.h"
#include "alloc/foreground.h"
#include "alloc/lru.h"

#include "btree/bkey_buf.h"
#include "btree/cache.h"
#include "btree/key_cache.h"
#include "btree/update.h"
#include "btree/interior.h"
#include "btree/check.h"
#include "btree/write_buffer.h"

#include "data/ec/init.h"

#include "journal/journal.h"

#include "init/error.h"
#include "init/progress.h"
#include "init/recovery.h"

#include "sb/counters.h"

#include "util/clock.h"
#include "util/enumerated_ref.h"
#include "util/varint.h"

#include <linux/kthread.h>
#include <linux/math64.h>
#include <linux/pagemap.h>
#include <linux/sizes.h>
#include <linux/random.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/sched/task.h>
#include <linux/sort.h>
#include <linux/jiffies.h>

/* DOC_LATEX(allocator)
 * \subsubsection{Buckets}
 *
 * The allocator manages space in units called \emph{buckets} --- contiguous
 * regions on each device, typically 512 KB to 16 MB (set at format time with
 * \texttt{--bucket\_size}, default auto-selected based on device size). Each
 * bucket tracks how many dirty and cached sectors it contains, plus metadata
 * such as the oldest journal sequence number referencing it, stripe membership,
 * and generation number.
 *
 * Buckets are append-only: when allocated, a bucket is written to sequentially
 * and never overwritten until the entire bucket is invalidated and reused.
 * This log-structured approach means that stale data cannot be reclaimed in
 * place---copygc must move live data to new buckets before fragmented buckets
 * can be freed.
 *
 * Buckets cycle through a series of states:
 *
 * \begin{description}
 * \item[\texttt{dirty}] Contains live data or metadata. Cannot be reused until
 *   all data is moved or deleted.
 * \item[\texttt{cached}] Contains only cached copies (data with durable replicas
 *   elsewhere). Can be discarded when free space is needed.
 * \item[\texttt{need\_gc\_gens}] Legacy state, retained for compatibility.
 *   Previously used to prevent generation number wraparound; now effectively
 *   unused since the invalidate worker uses backpointers instead of generation
 *   bumping.
 * \item[\texttt{need\_discard}] All data invalidated; waiting for a discard
 *   (TRIM) command to be sent to the device.
 * \item[\texttt{free}] Discarded and ready for allocation.
 * \end{description}
 *
 * Bucket size affects fragmentation and overhead. Larger buckets reduce metadata
 * overhead and improve sequential write performance, but increase internal
 * fragmentation: if a bucket is only partially filled with live data, the
 * remaining space is wasted until copygc moves the live data elsewhere and frees
 * the entire bucket. The \texttt{bcachefs fs usage} command shows per-device
 * bucket counts and fragmentation.
 *
 * \subsubsection{Foreground allocator}
 *
 * The foreground allocator handles allocation requests from active writes. When
 * a write needs space, the allocator selects devices based on the applicable
 * target option (\texttt{foreground\_target}, \texttt{metadata\_target}, etc.).
 * Within the target group, devices are selected by striping across all
 * available devices, weighted by free space --- devices with more free space
 * receive proportionally more allocations, so all devices in the filesystem
 * fill up at roughly the same rate.
 *
 * If the target devices are full, the allocator falls back to any device in
 * the filesystem rather than failing the write. This fallback is deliberate:
 * target options express a preference, not a hard constraint. The only way to
 * get a hard constraint is to use separate filesystems.
 *
 * Each allocation request also specifies a watermark level (see Watermarks
 * below) and a required number of replicas. The allocator picks devices that
 * satisfy the replica count and durability requirements, avoiding placing
 * multiple replicas on the same device.
 *
 * \paragraph{Write points}
 * \label{sec:write-points}
 *
 * \bchdoc{foreground-allocator}
 *
 * \subsubsection{Background allocator}
 *
 * The background allocator runs continuously, producing free buckets for the
 * foreground allocator to consume. It manages three pipelines:
 *
 * \begin{description}
 * \item[Invalidation] Scans for buckets containing only cached data (or no data)
 *   and invalidates them. The invalidate worker walks backpointers to verify no
 *   live references remain before marking buckets for discard. Invalidated
 *   buckets move to the \texttt{need\_discard} state.
 * \item[Discard] Sends TRIM/discard commands to the device for invalidated
 *   buckets, then moves them to the \texttt{free} state. On devices that do not
 *   support discard, this step is a no-op.
 * \item[Freelist management] Maintains a pool of free buckets ready for
 *   immediate allocation. The target free bucket count is tunable and determines
 *   how far ahead the background allocator works.
 * \end{description}
 *
 * When free space is low, copygc kicks in to move live data out of
 * mostly-empty buckets, freeing them for reuse. The copygc reserve ensures that
 * copygc itself always has enough free space to make forward progress, even when
 * the filesystem appears full to user writes.
 *
 * \subsubsection{Watermarks}
 *
 * The allocator uses a tiered watermark system to manage space pressure. Each
 * watermark level reserves progressively more free buckets:
 *
 * \begin{description}
 * \item[\texttt{stripe}] Highest watermark; used for
 *   \hyperref[sec:erasure-coding]{erasure coding} stripe allocation. Most free
 *   space is available.
 * \item[\texttt{normal}] Standard user data writes.
 * \item[\texttt{copygc}] Copygc is allowed to dip into space reserved from
 *   normal writes.
 * \item[\texttt{btree}] Btree node allocation, which must succeed even under
 *   heavy space pressure.
 * \item[\texttt{btree\_copygc}] Btree allocation during copygc.
 * \item[\texttt{reclaim}] \hyperref[sec:journal]{Journal} reclaim---must always
 *   be able to flush dirty btree nodes to free journal space.
 * \item[\texttt{interior\_updates}] The lowest watermark, for btree interior
 *   node updates during splits and merges that must never fail.
 * \end{description}
 *
 * This layered approach ensures that critical internal operations (journal
 * reclaim, btree splits) can always make progress, even when the filesystem is
 * full from the user's perspective.
 *
 * \subsubsection{Accounting}
 *
 * The accounting subsystem maintains exact, transactional counters for all
 * space usage in the filesystem. Every write, delete, or metadata change that
 * affects space usage atomically updates the corresponding accounting entries
 * as part of the same transaction.
 *
 * The system is designed to be extensible: accounting keys are type-tagged
 * unions, so adding a new class of counters requires only defining a new
 * tag and its associated fields. No schema changes, no migration --- new
 * counter types appear in the btree alongside existing ones, and old code
 * simply ignores tags it does not recognize.
 *
 * Accounting entries are stored in a dedicated btree as actual counter values,
 * but updates are applied as deltas and aggregated by the btree write buffer
 * before being flushed. This is how accounting can live in a btree without
 * killing performance: many small increments are batched into a single btree
 * update. Version numbers derived from journal position ensure that journal
 * replay can safely deduplicate updates.
 *
 * \paragraph{What is tracked}
 *
 * \begin{description}
 * \item[\texttt{replicas}] On-disk usage by replication strategy --- which
 *   devices hold copies and how many. This is what \texttt{bcachefs fs usage}
 *   reports as the main usage breakdown.
 * \item[\texttt{dev\_data\_type}] Per-device usage broken down by data type
 *   (user data, btree, cached, parity, etc.), tracking bucket count, live
 *   sectors, and fragmentation.
 * \item[\texttt{compression}] Per-compression-type statistics: number of
 *   extents, uncompressed size, and compressed size on disk.
 * \item[\texttt{nr\_inodes}] Total inode count.
 * \item[\texttt{snapshot}] Per-snapshot on-disk usage.
 * \item[\texttt{btree}] Per-btree metadata usage (total sectors, node count).
 * \item[\texttt{reconcile\_work}] Pending work for the reconcile subsystem,
 *   broken down by type.
 * \item[\texttt{persistent\_reserved}] Sectors reserved by
 *   \texttt{KEY\_TYPE\_reservation} keys (e.g.\ fallocate).
 * \end{description}
 *
 * In memory, frequently-accessed counters (replicas, per-device, compression)
 * are maintained in percpu arrays for lock-free reads. Less frequently accessed
 * counters (per-snapshot, reconcile work) are read from the btree on demand.
 * The \texttt{bcachefs fs usage} command and the
 * \texttt{BCH\_IOCTL\_QUERY\_ACCOUNTING} ioctl both read from this system.
 *
 * \subsubsection{Replicas tracking}
 *
 * The replicas superblock field records every unique data replication
 * configuration in use by the filesystem --- each entry describes a data type
 * (journal, btree, user data, parity) and the set of devices that hold copies.
 * This is the authoritative source for determining whether the filesystem can
 * operate with a given set of devices.
 *
 * \paragraph{Mount decisions}
 *
 * At mount time, bcachefs checks every replicas entry against the set of
 * online devices. For each entry, it counts how many of the listed devices
 * are present and compares against the entry's \texttt{nr\_required} field
 * (normally 1; higher for erasure coding where multiple blocks are needed for
 * reconstruction). If any entry cannot be satisfied, the filesystem cannot
 * mount --- the data described by that entry would be inaccessible.
 *
 * Write-side checks are stricter: the filesystem must have enough read-write
 * devices to satisfy the configured replication levels for journal, metadata,
 * and user data. A filesystem can mount read-only with fewer devices than it
 * needs for read-write operation.
 *
 * \paragraph{Lifecycle}
 *
 * Replicas entries are added lazily: when new data is written with a
 * previously-unseen device combination, the entry is added to the superblock
 * as part of the transaction commit (via integration with the accounting
 * subsystem). Entries are removed when their corresponding accounting counters reach
 * zero --- meaning no data with that replication
 * pattern exists on disk anymore.
 *
 * The tight coupling with accounting means the replicas field stays accurate
 * without expensive scans: as data is written, moved, or deleted, accounting
 * deltas flow through the write buffer, and the replicas field is updated to
 * match.
 *
 * As of version 1.36, user data replicas entries are no longer stored in the
 * superblock --- only journal and metadata entries are. With large numbers of
 * devices, the combinatorial explosion of possible device sets for user data
 * made superblock replicas entries a scalability bottleneck. User data
 * replication is now tracked entirely through the accounting subsystem.
 *
 * \subsubsection{Backpointers}
 * \label{sec:backpointers}
 *
 * Every sector range on disk that contains data or metadata has a corresponding
 * backpointer: a reverse reference from the physical location back to the
 * logical btree entry that owns it. Backpointers answer the question ``what
 * data lives in this bucket?'' without scanning the entire extents btree.
 *
 * Backpointers are stored in a write-buffered btree, keyed by (device, sector
 * offset, discriminator). The value records the btree ID, level, and position
 * of the owning key, plus the data type and bucket generation number.
 *
 * \paragraph{Maintenance}
 *
 * Backpointers are created and deleted automatically by extent triggers: when
 * an extent is written, a backpointer is inserted for each data pointer; when
 * an extent is overwritten or deleted, the corresponding backpointers are
 * removed. Updates go through the write buffer for batching.
 *
 * The discriminator field handles cases where multiple extents share ownership
 * of the same physical block (e.g.\ compressed extents that have been partially
 * overwritten). Erasure code stripes get their own backpointers in a separate
 * \texttt{stripe\_backpointers} btree, since stripe backpointers have different
 * position semantics and lifecycle from extent backpointers.
 *
 * \paragraph{Operations that use backpointers}
 *
 * \begin{itemize}
 * \item \textbf{Copygc}: Finds live extents in fragmented buckets to relocate
 *   them, freeing the bucket for reuse.
 * \item \textbf{Device evacuation}: Finds all extents on a device being removed
 *   and migrates them to other devices.
 * \item \textbf{Scrub}: Walks backpointers in physical order to verify data
 *   integrity without random seeks across the extents btree.
 * \item \textbf{Reconcile}: Tracks extents that need to be moved on rotational
 *   devices for optimal LBA ordering.
 * \end{itemize}
 *
 * \paragraph{Consistency and self-healing}
 *
 * Missing or inconsistent backpointers are detected at runtime --- for example,
 * when the move path looks up backpointers for a bucket and finds they do not
 * match the bucket's sector counts. When a mismatch is detected, the relevant
 * recovery pass is automatically scheduled and run (with rate limiting to avoid
 * overwhelming the system).
 *
 * Three recovery passes verify backpointer integrity bidirectionally:
 * \texttt{check\_extents\_to\_backpointers} ensures every extent has matching
 * backpointers, \texttt{check\_backpointers\_to\_extents} ensures every
 * backpointer points to a valid extent, and
 * \texttt{check\_btree\_backpointers} validates backpointers against bucket
 * allocation state.
 *
 * The key optimization is comparing backpointer sector counts against bucket
 * sector counts: if they agree, the backpointers for that bucket are known to
 * be consistent without walking the extents btree. Only buckets with mismatches
 * need the more expensive bidirectional verification --- essential for larger
 * filesystems where a complete scan would be prohibitively expensive. Each
 * backpointer also records the bucket generation number at creation time, so
 * stale backpointers from reused buckets are detected and cleaned up
 * automatically.
 *
 * \subsubsection{Data structures}
 *
 * The allocator's persistent state is spread across several btrees, each
 * optimized for a different access pattern. The alloc btree is the
 * authoritative record of per-bucket state; the others are derived indexes
 * that accelerate specific operations.
 *
 * \paragraph{Alloc key (\texttt{bch\_alloc\_v4})}
 *
 * Every bucket on every device has a corresponding key in the alloc btree,
 * keyed by (device, bucket number). The value is a \texttt{bch\_alloc\_v4}
 * struct containing:
 *
 * \begin{itemize}
 * \item \texttt{gen} / \texttt{oldest\_gen} --- the current generation number
 *   and the oldest generation still referenced by extents. The difference
 *   between these determines whether the bucket needs a GC-gens pass.
 * \item \texttt{data\_type} --- what kind of data the bucket holds (user, btree,
 *   cached, parity, stripe, etc.), computed by \texttt{alloc\_data\_type()} from
 *   the other fields (see below).
 * \item \texttt{dirty\_sectors} / \texttt{cached\_sectors} /
 *   \texttt{stripe\_sectors} --- sector counts by category.
 * \item \texttt{stripe\_refcount} --- number of erasure-coded stripes
 *   referencing this bucket.
 * \item \texttt{io\_time[READ/WRITE]} --- timestamps for LRU eviction of
 *   cached data.
 * \item \texttt{journal\_seq\_nonempty} / \texttt{journal\_seq\_empty} ---
 *   journal sequence numbers tracking bucket state transitions, used by the
 *   noflush write optimization and the discard path.
 * \item \texttt{nr\_external\_backpointers} --- count of backpointers stored in
 *   the backpointers btree (as opposed to inline backpointers).
 * \end{itemize}
 *
 * The format has evolved through four versions (v1 through v4). Earlier
 * versions used variable-length varint encoding for fields; v4 switched to a
 * fixed-layout struct for simpler access. v4 also added support for inline
 * backpointers stored directly in the alloc key value, avoiding a separate
 * btree lookup for buckets with few backpointers. All versions are converted
 * to \texttt{bch\_alloc\_v4} in memory; the on-disk format is upgraded lazily
 * as keys are rewritten.
 *
 * \paragraph{Bucket state derivation}
 *
 * A bucket's logical state is not stored as a field --- it is \emph{derived}
 * from the alloc key contents by \texttt{alloc\_data\_type()}. The derivation
 * follows a priority chain:
 *
 * \begin{enumerate}
 * \item If \texttt{stripe\_refcount > 0}: the bucket belongs to an erasure-coded
 *   stripe (\texttt{BCH\_DATA\_stripe} or \texttt{BCH\_DATA\_parity}).
 * \item Else if \texttt{dirty\_sectors > 0} or \texttt{stripe\_sectors > 0}:
 *   the bucket contains live data; the type comes from the data that was
 *   written (user, btree, etc.).
 * \item Else if \texttt{cached\_sectors > 0}: the bucket contains only cached
 *   data (\texttt{BCH\_DATA\_cached}).
 * \item Else if the \texttt{NEED\_DISCARD} flag is set: the bucket is
 *   invalidated but awaiting TRIM (\texttt{BCH\_DATA\_need\_discard}).
 * \item Else if \texttt{gen - oldest\_gen >= BUCKET\_GC\_GEN\_MAX}: the
 *   generation gap is too large (\texttt{BCH\_DATA\_need\_gc\_gens}).
 * \item Otherwise: the bucket is free (\texttt{BCH\_DATA\_free}).
 * \end{enumerate}
 *
 * This derivation means bucket state is always consistent with the underlying
 * counters --- there is no separate state field that could get out of sync.
 *
 * \paragraph{Freespace btree}
 *
 * The freespace btree indexes free buckets for fast allocation. Keys are
 * (device, bucket number) with generation bits encoded in the high bits of the
 * offset, so the allocator can scan for free buckets on a given device with a
 * simple btree range scan. This is a derived index: entries are
 * inserted/removed by the alloc key trigger when a bucket transitions to or
 * from the free state. The foreground allocator cross-checks freespace entries
 * against the alloc btree before using a bucket, catching any inconsistencies.
 *
 * \paragraph{Need-discard btree}
 *
 * A simple presence/absence index of buckets in the
 * \texttt{BCH\_DATA\_need\_discard} state. The discard worker iterates this
 * btree to find buckets needing TRIM commands, sends the discards, then
 * updates the alloc key to clear the need-discard flag (which removes the
 * entry from this btree via the trigger). Maintaining a separate index avoids
 * scanning the entire alloc btree to find the small fraction of buckets
 * awaiting discard.
 *
 * \paragraph{Bucket-gens btree}
 *
 * Packs 256 bucket generation numbers into a single btree key
 * (\texttt{bch\_bucket\_gens}). This provides cheap stale-pointer detection:
 * when checking whether an extent pointer is stale, the code only needs to
 * read a small bucket-gens key rather than the full alloc key. This is
 * particularly important for the RCU read path, where looking up a full alloc
 * key would be too expensive.
 *
 * \paragraph{LRU btree}
 *
 * Indexes cached buckets by their last-read timestamp, enabling the
 * invalidation worker to evict the least-recently-used cached data first.
 * Also used with a separate LRU ID for fragmentation-based eviction ordering,
 * so copygc can prioritize the most fragmented buckets. Like the other
 * auxiliary btrees, entries are maintained by the alloc key trigger.
 *
 * \subsubsection{Device labels and targets}
 * \label{sec:disk-groups}
 *
 * Device labels are hierarchical paths delimited by periods --- for example,
 * \texttt{ssd.fast}, \texttt{ssd.slow}, \texttt{hdd.archive}. A target option
 * can reference any prefix of the path: specifying \texttt{ssd} as a target
 * matches all devices whose label starts with \texttt{ssd} (e.g.\
 * \texttt{ssd.fast}, \texttt{ssd.slow}), while \texttt{ssd.fast} matches only
 * that specific label. Labels need not be unique --- multiple devices can share
 * the same label, forming a group.
 *
 * Targets can also reference a device directly by path (e.g.\
 * \texttt{foreground\_target=/dev/sda1}). Internally, both device references
 * and label references resolve to entries in the disk groups superblock field,
 * which maps label strings to device sets.
 *
 * Four target options control where data is placed:
 *
 * \begin{description}
 * \item[\texttt{foreground\_target}] Normal foreground data writes, and
 *   metadata if \texttt{metadata\_target} is not set.
 * \item[\texttt{metadata\_target}] Btree node writes.
 * \item[\texttt{background\_target}] If set, user data is moved to this target
 *   in the background by the reconcile subsystem. The original copy is left in
 *   place but marked as cached.
 * \item[\texttt{promote\_target}] If set, a cached copy is created on this
 *   target when data is read, if no copy exists there already.
 * \end{description}
 *
 * All four options can be set at the filesystem level (format time, mount time,
 * or runtime via sysfs) or on individual files and directories. Target options
 * express a preference, not a hard constraint: if the target devices are full,
 * the allocator falls back to any device in the filesystem.
 *
 * \subsubsection{Consistency and self-healing}
 *
 * The allocator performs runtime consistency checks during normal operation,
 * detecting and repairing problems without requiring an offline fsck.
 *
 * \paragraph{Runtime checks}
 *
 * The foreground allocator validates every bucket before use: the freespace
 * btree entry is cross-checked against the alloc btree to confirm the bucket
 * is actually free, the generation number matches, and no other subsystem has
 * a claim on it (open bucket, nocow lock, superblock region). If a mismatch
 * is detected, the bucket is skipped and an asynchronous repair job is queued
 * to fix the inconsistent entry without blocking allocation.
 *
 * Bucket state transitions are also validated: if a bucket is being marked
 * with a data type that conflicts with its current state (e.g.\ writing user
 * data to a bucket the alloc btree says contains metadata), the inconsistency
 * is flagged and a recovery pass is scheduled. Accounting counters are checked
 * for sanity (e.g.\ negative sector counts indicate lost writes or corruption)
 * and trigger recovery when anomalies are found.
 *
 * \paragraph{Recovery passes}
 *
 * When runtime checks detect problems, they automatically schedule the
 * appropriate recovery pass with rate limiting to avoid overwhelming the system.
 * The key allocator recovery passes are:
 *
 * \begin{description}
 * \item[\texttt{check\_allocations}] Full garbage collection: marks all
 *   referenced buckets by walking extents, btree nodes, and stripes, then
 *   compares against the alloc btree and repairs data types, sector counts,
 *   and stripe references.
 * \item[\texttt{check\_alloc\_info}] Cross-checks the alloc btree against the
 *   freespace, need\_discard, and bucket\_gens btrees, repairing any
 *   mismatches. Can run online.
 * \item[\texttt{check\_lrus}] Verifies LRU entries (used for cached bucket
 *   eviction order) match alloc btree timestamps; removes stale entries.
 * \item[\texttt{check\_alloc\_to\_lru\_refs}] Ensures every cached bucket has
 *   a correct LRU entry.
 * \end{description}
 *
 * Recovery passes are ordered by dependency: \texttt{check\_allocations} must
 * run before the others, since it establishes the ground truth for bucket
 * state. Passes marked \texttt{PASS\_ONLINE} can run on a mounted filesystem
 * without interrupting normal operation.
 */

/* Persistent alloc info: */

static const unsigned BCH_ALLOC_V1_FIELD_BYTES[] = {
#define x(name, bits) [BCH_ALLOC_FIELD_V1_##name] = bits / 8,
	BCH_ALLOC_FIELDS_V1()
#undef x
};

struct bkey_alloc_unpacked {
	u64		journal_seq;
	u8		gen;
	u8		oldest_gen;
	u8		data_type;
	bool		need_discard:1;
	bool		need_inc_gen:1;
#define x(_name, _bits)	u##_bits _name;
	BCH_ALLOC_FIELDS_V2()
#undef  x
};

static inline u64 alloc_field_v1_get(const struct bch_alloc *a,
				     const void **p, unsigned field)
{
	unsigned bytes = BCH_ALLOC_V1_FIELD_BYTES[field];
	u64 v;

	if (!(a->fields & (1 << field)))
		return 0;

	switch (bytes) {
	case 1:
		v = *((const u8 *) *p);
		break;
	case 2:
		v = le16_to_cpup(*p);
		break;
	case 4:
		v = le32_to_cpup(*p);
		break;
	case 8:
		v = le64_to_cpup(*p);
		break;
	default:
		BUG();
	}

	*p += bytes;
	return v;
}

static void bch2_alloc_unpack_v1(struct bkey_alloc_unpacked *out,
				 struct bkey_s_c k)
{
	const struct bch_alloc *in = bkey_s_c_to_alloc(k).v;
	const void *d = in->data;
	unsigned idx = 0;

	out->gen = in->gen;

#define x(_name, _bits) out->_name = alloc_field_v1_get(in, &d, idx++);
	BCH_ALLOC_FIELDS_V1()
#undef  x
}

static int bch2_alloc_unpack_v2(struct bkey_alloc_unpacked *out,
				struct bkey_s_c k)
{
	struct bkey_s_c_alloc_v2 a = bkey_s_c_to_alloc_v2(k);
	const u8 *in = a.v->data;
	const u8 *end = bkey_val_end(a);
	unsigned fieldnr = 0;
	int ret;
	u64 v;

	out->gen	= a.v->gen;
	out->oldest_gen	= a.v->oldest_gen;
	out->data_type	= a.v->data_type;

#define x(_name, _bits)							\
	if (fieldnr < a.v->nr_fields) {					\
		ret = bch2_varint_decode_fast(in, end, &v);		\
		if (ret < 0)						\
			return ret;					\
		in += ret;						\
	} else {							\
		v = 0;							\
	}								\
	out->_name = v;							\
	if (v != out->_name)						\
		return -1;						\
	fieldnr++;

	BCH_ALLOC_FIELDS_V2()
#undef  x
	return 0;
}

static int bch2_alloc_unpack_v3(struct bkey_alloc_unpacked *out,
				struct bkey_s_c k)
{
	struct bkey_s_c_alloc_v3 a = bkey_s_c_to_alloc_v3(k);
	const u8 *in = a.v->data;
	const u8 *end = bkey_val_end(a);
	unsigned fieldnr = 0;
	int ret;
	u64 v;

	out->gen	= a.v->gen;
	out->oldest_gen	= a.v->oldest_gen;
	out->data_type	= a.v->data_type;
	out->need_discard = BCH_ALLOC_V3_NEED_DISCARD(a.v);
	out->need_inc_gen = BCH_ALLOC_V3_NEED_INC_GEN(a.v);
	out->journal_seq = le64_to_cpu(a.v->journal_seq);

#define x(_name, _bits)							\
	if (fieldnr < a.v->nr_fields) {					\
		ret = bch2_varint_decode_fast(in, end, &v);		\
		if (ret < 0)						\
			return ret;					\
		in += ret;						\
	} else {							\
		v = 0;							\
	}								\
	out->_name = v;							\
	if (v != out->_name)						\
		return -1;						\
	fieldnr++;

	BCH_ALLOC_FIELDS_V2()
#undef  x
	return 0;
}

static struct bkey_alloc_unpacked bch2_alloc_unpack(struct bkey_s_c k)
{
	struct bkey_alloc_unpacked ret = { .gen	= 0 };

	switch (k.k->type) {
	case KEY_TYPE_alloc:
		bch2_alloc_unpack_v1(&ret, k);
		break;
	case KEY_TYPE_alloc_v2:
		bch2_alloc_unpack_v2(&ret, k);
		break;
	case KEY_TYPE_alloc_v3:
		bch2_alloc_unpack_v3(&ret, k);
		break;
	}

	return ret;
}

static unsigned bch_alloc_v1_val_u64s(const struct bch_alloc *a)
{
	unsigned i, bytes = offsetof(struct bch_alloc, data);

	for (i = 0; i < ARRAY_SIZE(BCH_ALLOC_V1_FIELD_BYTES); i++)
		if (a->fields & (1 << i))
			bytes += BCH_ALLOC_V1_FIELD_BYTES[i];

	return DIV_ROUND_UP(bytes, sizeof(u64));
}

int bch2_alloc_v1_validate(struct bch_fs *c, struct bkey_s_c k,
			   struct bkey_validate_context from)
{
	struct bkey_s_c_alloc a = bkey_s_c_to_alloc(k);
	int ret = 0;

	/* allow for unknown fields */
	bkey_fsck_err_on(bkey_val_u64s(a.k) < bch_alloc_v1_val_u64s(a.v),
			 c, alloc_v1_val_size_bad,
			 "incorrect value size (%zu < %u)",
			 bkey_val_u64s(a.k), bch_alloc_v1_val_u64s(a.v));
fsck_err:
	return ret;
}

int bch2_alloc_v2_validate(struct bch_fs *c, struct bkey_s_c k,
			   struct bkey_validate_context from)
{
	struct bkey_alloc_unpacked u;
	int ret = 0;

	bkey_fsck_err_on(bch2_alloc_unpack_v2(&u, k),
			 c, alloc_v2_unpack_error,
			 "unpack error");
fsck_err:
	return ret;
}

int bch2_alloc_v3_validate(struct bch_fs *c, struct bkey_s_c k,
			   struct bkey_validate_context from)
{
	struct bkey_alloc_unpacked u;
	int ret = 0;

	bkey_fsck_err_on(bch2_alloc_unpack_v3(&u, k),
			 c, alloc_v3_unpack_error,
			 "unpack error");
fsck_err:
	return ret;
}

int bch2_alloc_v4_validate(struct bch_fs *c, struct bkey_s_c k,
			   struct bkey_validate_context from)
{
	struct bch_alloc_v4 a;
	int ret = 0;

	bkey_val_copy_pad(&a, bkey_s_c_to_alloc_v4(k));

	bkey_fsck_err_on(alloc_v4_u64s_noerror(&a) > bkey_val_u64s(k.k),
			 c, alloc_v4_val_size_bad,
			 "bad val size (%u > %zu)",
			 alloc_v4_u64s_noerror(&a), bkey_val_u64s(k.k));

	bkey_fsck_err_on(!BCH_ALLOC_V4_BACKPOINTERS_START(&a) &&
			 BCH_ALLOC_V4_NR_BACKPOINTERS(&a),
			 c, alloc_v4_backpointers_start_bad,
			 "invalid backpointers_start");

	bkey_fsck_err_on(alloc_data_type(a, a.data_type) != a.data_type,
			 c, alloc_key_data_type_bad,
			 "invalid data type (got %u should be %u)",
			 a.data_type, alloc_data_type(a, a.data_type));

	for (unsigned i = 0; i < 2; i++)
		bkey_fsck_err_on(a.io_time[i] > LRU_TIME_MAX,
				 c, alloc_key_io_time_bad,
				 "invalid io_time[%s]: %llu, max %llu",
				 i == READ ? "read" : "write",
				 a.io_time[i], LRU_TIME_MAX);

	unsigned stripe_sectors = BCH_ALLOC_V4_BACKPOINTERS_START(&a) * sizeof(u64) >
		offsetof(struct bch_alloc_v4, stripe_sectors)
		? a.stripe_sectors
		: 0;

	switch (a.data_type) {
	case BCH_DATA_free:
	case BCH_DATA_need_gc_gens:
	case BCH_DATA_need_discard:
		bkey_fsck_err_on(stripe_sectors ||
				 a.dirty_sectors ||
				 a.cached_sectors ||
				 a.stripe_refcount,
				 c, alloc_key_empty_but_have_data,
				 "empty data type free but have data %u.%u.%u %u",
				 stripe_sectors,
				 a.dirty_sectors,
				 a.cached_sectors,
				 a.stripe_refcount);
		break;
	case BCH_DATA_sb:
	case BCH_DATA_journal:
	case BCH_DATA_btree:
	case BCH_DATA_user:
	case BCH_DATA_parity:
		bkey_fsck_err_on(!a.dirty_sectors &&
				 !stripe_sectors,
				 c, alloc_key_dirty_sectors_0,
				 "data_type %s but dirty_sectors==0",
				 bch2_data_type_str(a.data_type));
		break;
	case BCH_DATA_cached:
		bkey_fsck_err_on(!a.cached_sectors ||
				 a.dirty_sectors ||
				 stripe_sectors ||
				 a.stripe_refcount,
				 c, alloc_key_cached_inconsistency,
				 "data type inconsistency");
		break;
	case BCH_DATA_stripe:
		break;
	}
fsck_err:
	return ret;
}

void bch2_alloc_v4_swab(const struct bch_fs *c, struct bkey_s k)
{
	struct bch_alloc_v4 *a = bkey_s_to_alloc_v4(k).v;

	a->journal_seq_nonempty	= swab64(a->journal_seq_nonempty);
	a->journal_seq_empty	= swab64(a->journal_seq_empty);
	a->flags		= swab32(a->flags);
	a->dirty_sectors	= swab32(a->dirty_sectors);
	a->cached_sectors	= swab32(a->cached_sectors);
	a->io_time[0]		= swab64(a->io_time[0]);
	a->io_time[1]		= swab64(a->io_time[1]);
	a->stripe_refcount	= swab32(a->stripe_refcount);
	a->nr_external_backpointers = swab32(a->nr_external_backpointers);
	a->stripe_sectors	= swab32(a->stripe_sectors);
}

static inline void __bch2_alloc_v4_to_text(struct printbuf *out, struct bch_fs *c,
					   struct bkey_s_c k,
					   const struct bch_alloc_v4 *a)
{
	struct bch_dev *ca = c ? bch2_dev_tryget_noerror(c, k.k->p.inode) : NULL;

	prt_newline(out);

	prt_printf(out, "gen %u oldest_gen %u data_type ", a->gen, a->oldest_gen);
	bch2_prt_data_type(out, a->data_type);
	prt_newline(out);
	prt_printf(out, "journal_seq_nonempty %llu\n",	a->journal_seq_nonempty);
	if (bkey_val_bytes(k.k) > offsetof(struct bch_alloc_v4, journal_seq_empty))
		prt_printf(out, "journal_seq_empty    %llu\n",	a->journal_seq_empty);

	prt_printf(out, "need_discard         %llu\n",	BCH_ALLOC_V4_NEED_DISCARD(a));
	prt_printf(out, "need_inc_gen         %llu\n",	BCH_ALLOC_V4_NEED_INC_GEN(a));
	prt_printf(out, "dirty_sectors        %u\n",	a->dirty_sectors);
	if (bkey_val_bytes(k.k) > offsetof(struct bch_alloc_v4, stripe_sectors))
		prt_printf(out, "stripe_sectors       %u\n",	a->stripe_sectors);
	prt_printf(out, "cached_sectors       %u\n",	a->cached_sectors);
	prt_printf(out, "stripe_refcount      %u\n",	a->stripe_refcount);
	prt_printf(out, "io_time[READ]        %llu\n",	a->io_time[READ]);
	prt_printf(out, "io_time[WRITE]       %llu\n",	a->io_time[WRITE]);

	if (ca)
		prt_printf(out, "fragmentation     %llu\n",	alloc_lru_idx_fragmentation(*a, ca));
	prt_printf(out, "bp_start          %llu\n", BCH_ALLOC_V4_BACKPOINTERS_START(a));

	bch2_dev_put(ca);
}

void bch2_alloc_to_text(struct printbuf *out, struct bch_fs *c, struct bkey_s_c k)
{
	struct bch_alloc_v4 _a;
	const struct bch_alloc_v4 *a = bch2_alloc_to_v4(k, &_a);

	__bch2_alloc_v4_to_text(out, c, k, a);
}

void bch2_alloc_v4_to_text(struct printbuf *out, struct bch_fs *c, struct bkey_s_c k)
{
	__bch2_alloc_v4_to_text(out, c, k, bkey_s_c_to_alloc_v4(k).v);
}

void __bch2_alloc_to_v4(struct bkey_s_c k, struct bch_alloc_v4 *out)
{
	if (k.k->type == KEY_TYPE_alloc_v4) {
		void *src, *dst;

		bkey_val_copy_pad(out, bkey_s_c_to_alloc_v4(k));

		src = alloc_v4_backpointers(out);
		SET_BCH_ALLOC_V4_BACKPOINTERS_START(out, BCH_ALLOC_V4_U64s);
		dst = alloc_v4_backpointers(out);

		if (src < dst)
			memset(src, 0, dst - src);

		SET_BCH_ALLOC_V4_NR_BACKPOINTERS(out, 0);
	} else {
		struct bkey_alloc_unpacked u = bch2_alloc_unpack(k);

		*out = (struct bch_alloc_v4) {
			.journal_seq_nonempty	= u.journal_seq,
			.flags			= u.need_discard,
			.gen			= u.gen,
			.oldest_gen		= u.oldest_gen,
			.data_type		= u.data_type,
			.dirty_sectors		= u.dirty_sectors,
			.cached_sectors		= u.cached_sectors,
			.io_time[READ]		= u.read_time,
			.io_time[WRITE]		= u.write_time,
			.stripe_refcount	= u.stripe != 0,
		};

		SET_BCH_ALLOC_V4_BACKPOINTERS_START(out, BCH_ALLOC_V4_U64s);
	}
}

static noinline struct bkey_i_alloc_v4 *
__bch2_alloc_to_v4_mut(struct btree_trans *trans, struct bkey_s_c k)
{
	struct bkey_i_alloc_v4 *ret;

	ret = bch2_trans_kmalloc(trans, max(bkey_bytes(k.k), sizeof(struct bkey_i_alloc_v4)));
	if (IS_ERR(ret))
		return ret;

	if (k.k->type == KEY_TYPE_alloc_v4) {
		void *src, *dst;

		bkey_reassemble(&ret->k_i, k);

		src = alloc_v4_backpointers(&ret->v);
		SET_BCH_ALLOC_V4_BACKPOINTERS_START(&ret->v, BCH_ALLOC_V4_U64s);
		dst = alloc_v4_backpointers(&ret->v);

		if (src < dst)
			memset(src, 0, dst - src);

		SET_BCH_ALLOC_V4_NR_BACKPOINTERS(&ret->v, 0);
		set_alloc_v4_u64s(ret);
	} else {
		bkey_alloc_v4_init(&ret->k_i);
		ret->k.p = k.k->p;
		bch2_alloc_to_v4(k, &ret->v);
	}
	return ret;
}

static inline struct bkey_i_alloc_v4 *bch2_alloc_to_v4_mut_inlined(struct btree_trans *trans, struct bkey_s_c k)
{
	struct bkey_s_c_alloc_v4 a;

	if (likely(k.k->type == KEY_TYPE_alloc_v4) &&
	    ((a = bkey_s_c_to_alloc_v4(k), true) &&
	     BCH_ALLOC_V4_NR_BACKPOINTERS(a.v) == 0))
		return bch2_bkey_make_mut_noupdate_typed(trans, k, alloc_v4);

	return __bch2_alloc_to_v4_mut(trans, k);
}

struct bkey_i_alloc_v4 *bch2_alloc_to_v4_mut(struct btree_trans *trans, struct bkey_s_c k)
{
	return bch2_alloc_to_v4_mut_inlined(trans, k);
}

struct bkey_i_alloc_v4 *
bch2_trans_start_alloc_update_noupdate(struct btree_trans *trans, struct btree_iter *iter,
				       struct bpos pos)
{
	bch2_trans_iter_init(trans, iter, BTREE_ID_alloc, pos,
			     BTREE_ITER_cached|
			     BTREE_ITER_intent);
	struct bkey_s_c k = bch2_btree_iter_peek_slot(iter);
	int ret = bkey_err(k);
	if (unlikely(ret))
		return ERR_PTR(ret);

	return bch2_alloc_to_v4_mut_inlined(trans, k);
}

__flatten
struct bkey_i_alloc_v4 *bch2_trans_start_alloc_update(struct btree_trans *trans, struct bpos pos,
						      enum btree_iter_update_trigger_flags flags)
{
	CLASS(btree_iter, iter)(trans, BTREE_ID_alloc, pos,
				BTREE_ITER_cached|
				BTREE_ITER_intent);
	struct bkey_s_c k = bch2_btree_iter_peek_slot(&iter);
	int ret = bkey_err(k);
	if (unlikely(ret))
		return ERR_PTR(ret);

	if ((void *) k.v >= trans->mem &&
	    (void *) k.v <  trans->mem + trans->mem_top)
		return container_of(bkey_s_c_to_alloc_v4(k).v, struct bkey_i_alloc_v4, v);

	struct bkey_i_alloc_v4 *a = bch2_alloc_to_v4_mut_inlined(trans, k);
	if (IS_ERR(a))
		return a;

	ret = bch2_trans_update_ip(trans, &iter, &a->k_i, a->k.u64s, flags, _RET_IP_);
	return unlikely(ret) ? ERR_PTR(ret) : a;
}

int bch2_bucket_gens_validate(struct bch_fs *c, struct bkey_s_c k,
			      struct bkey_validate_context from)
{
	int ret = 0;

	bkey_fsck_err_on(bkey_val_bytes(k.k) != sizeof(struct bch_bucket_gens),
			 c, bucket_gens_val_size_bad,
			 "bad val size (%zu != %zu)",
			 bkey_val_bytes(k.k), sizeof(struct bch_bucket_gens));
fsck_err:
	return ret;
}

void bch2_bucket_gens_to_text(struct printbuf *out, struct bch_fs *c, struct bkey_s_c k)
{
	struct bkey_s_c_bucket_gens g = bkey_s_c_to_bucket_gens(k);
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(g.v->gens); i++) {
		if (i)
			prt_char(out, ' ');
		prt_printf(out, "%u", g.v->gens[i]);
	}
}

static int bucket_gens_init_iter(struct btree_trans *trans, struct bkey_s_c k,
				 struct bkey_i_bucket_gens *g,
				 bool *have_bucket_gens_key)
{
	/*
	 * Not a fsck error because this is checked/repaired by
	 * bch2_check_alloc_key() which runs later:
	 */
	if (!bch2_dev_bucket_exists(trans->c, k.k->p))
		return 0;

	unsigned offset;
	struct bpos pos = alloc_gens_pos(k.k->p, &offset);

	if (*have_bucket_gens_key && !bkey_eq(g->k.p, pos)) {
		try(bch2_btree_insert_trans(trans, BTREE_ID_bucket_gens, &g->k_i, 0));
		try(bch2_trans_commit(trans, NULL, NULL, BCH_TRANS_COMMIT_no_enospc));

		*have_bucket_gens_key = false;
	}

	if (!*have_bucket_gens_key) {
		bkey_bucket_gens_init(&g->k_i);
		g->k.p = pos;
		*have_bucket_gens_key = true;
	}

	struct bch_alloc_v4 a;
	g->v.gens[offset] = bch2_alloc_to_v4(k, &a)->gen;
	return 0;
}

int bch2_bucket_gens_init(struct bch_fs *c)
{
	struct bkey_i_bucket_gens g;
	bool have_bucket_gens_key = false;

	CLASS(btree_trans, trans)(c);
	try(for_each_btree_key(trans, iter, BTREE_ID_alloc, POS_MIN,
				 BTREE_ITER_prefetch, k, ({
		bucket_gens_init_iter(trans, k, &g, &have_bucket_gens_key);
	})));

	if (have_bucket_gens_key)
		try(commit_do(trans, NULL, NULL,
				BCH_TRANS_COMMIT_no_enospc,
			bch2_btree_insert_trans(trans, BTREE_ID_bucket_gens, &g.k_i, 0)));

	return 0;
}

int bch2_alloc_read(struct bch_fs *c)
{
	guard(rwsem_read)(&c->state_lock);

	CLASS(btree_trans, trans)(c);
	struct bch_dev *ca = NULL;
	int ret;

	if (c->sb.version_upgrade_complete >= bcachefs_metadata_version_bucket_gens) {
		ret = for_each_btree_key(trans, iter, BTREE_ID_bucket_gens, POS_MIN,
					 BTREE_ITER_prefetch, k, ({
			u64 start = bucket_gens_pos_to_alloc(k.k->p, 0).offset;
			u64 end = bucket_gens_pos_to_alloc(bpos_nosnap_successor(k.k->p), 0).offset;

			if (k.k->type != KEY_TYPE_bucket_gens)
				continue;

			ca = bch2_dev_iterate(c, ca, k.k->p.inode);
			/*
			 * Not a fsck error because this is checked/repaired by
			 * bch2_check_alloc_key() which runs later:
			 */
			if (!ca) {
				bch2_btree_iter_set_pos(&iter, POS(k.k->p.inode + 1, 0));
				continue;
			}

			const struct bch_bucket_gens *g = bkey_s_c_to_bucket_gens(k).v;

			for (u64 b = max_t(u64, ca->mi.first_bucket, start);
			     b < min_t(u64, ca->mi.nbuckets, end);
			     b++)
				*bucket_gen(ca, b) = g->gens[b & KEY_TYPE_BUCKET_GENS_MASK];
			0;
		}));
	} else {
		ret = for_each_btree_key(trans, iter, BTREE_ID_alloc, POS_MIN,
					 BTREE_ITER_prefetch, k, ({
			ca = bch2_dev_iterate(c, ca, k.k->p.inode);
			/*
			 * Not a fsck error because this is checked/repaired by
			 * bch2_check_alloc_key() which runs later:
			 */
			if (!ca) {
				bch2_btree_iter_set_pos(&iter, POS(k.k->p.inode + 1, 0));
				continue;
			}

			if (k.k->p.offset < ca->mi.first_bucket) {
				bch2_btree_iter_set_pos(&iter, POS(k.k->p.inode, ca->mi.first_bucket));
				continue;
			}

			if (k.k->p.offset >= ca->mi.nbuckets) {
				bch2_btree_iter_set_pos(&iter, POS(k.k->p.inode + 1, 0));
				continue;
			}

			struct bch_alloc_v4 a;
			*bucket_gen(ca, k.k->p.offset) = bch2_alloc_to_v4(k, &a)->gen;
			0;
		}));
	}

	bch2_dev_put(ca);
	return ret;
}

/* Free space/discard btree: */

int bch2_bucket_do_freespace_index(struct btree_trans *trans,
				   struct bch_dev *ca,
				   struct bkey_s_c alloc_k,
				   const struct bch_alloc_v4 *a,
				   bool set)
{
	int ret = 0;

	if (a->data_type != BCH_DATA_free)
		return 0;

	struct bpos pos = alloc_freespace_pos(alloc_k.k->p, *a);

	CLASS(btree_iter, iter)(trans, BTREE_ID_freespace, pos, BTREE_ITER_intent);
	struct bkey_s_c old = bkey_try(bch2_btree_iter_peek_slot(&iter));

	need_discard_or_freespace_err_on(ca->mi.freespace_initialized &&
					 !old.k->type != set,
					 trans, alloc_k, set, false, false);

	return bch2_btree_bit_mod_iter(trans, &iter, set);
fsck_err:
	return ret;
}

/*
 * Update need_discard btree via write buffer. Done from the atomic
 * section of the alloc trigger because the key position depends on
 * journal_seq_empty, which is only known after journal reservation.
 */
static int bch2_bucket_do_discard_index(struct btree_trans *trans,
					struct bkey_s_c alloc_k,
					const struct bch_alloc_v4 *a,
					bool set)
{
	if (a->data_type != BCH_DATA_need_discard)
		return 0;

	return bch2_btree_bit_mod_buffered(trans, BTREE_ID_need_discard,
			POS(a->journal_seq_empty, bucket_to_u64(alloc_k.k->p)),
			set);
}

static noinline int bch2_bucket_gen_update(struct btree_trans *trans,
					   struct bpos bucket, u8 gen)
{
	struct bkey_i_bucket_gens *g = errptr_try(bch2_trans_kmalloc(trans, sizeof(*g)));

	unsigned offset;
	struct bpos pos = alloc_gens_pos(bucket, &offset);

	CLASS(btree_iter, iter)(trans, BTREE_ID_bucket_gens, pos, BTREE_ITER_intent);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	if (k.k->type != KEY_TYPE_bucket_gens) {
		bkey_bucket_gens_init(&g->k_i);
		g->k.p = iter.pos;
	} else {
		bkey_reassemble(&g->k_i, k);
	}

	g->v.gens[offset] = gen;

	return bch2_trans_update(trans, &iter, &g->k_i, 0);
}

static inline int bch2_dev_data_type_accounting_mod(struct btree_trans *trans, struct bch_dev *ca,
						    enum bch_data_type data_type,
						    s64 delta_buckets,
						    s64 delta_sectors,
						    s64 delta_fragmented, unsigned flags)
{
	s64 d[3] = { delta_buckets, delta_sectors, delta_fragmented };

	return bch2_disk_accounting_mod2(trans, flags & BTREE_TRIGGER_gc,
					 d, dev_data_type,
					 .dev		= ca->dev_idx,
					 .data_type	= data_type);
}

int bch2_alloc_key_to_dev_counters(struct btree_trans *trans, struct bch_dev *ca,
				   const struct bch_alloc_v4 *old,
				   const struct bch_alloc_v4 *new,
				   unsigned flags)
{
	s64 old_sectors = bch2_bucket_sectors(*old);
	s64 new_sectors = bch2_bucket_sectors(*new);
	if (old->data_type != new->data_type) {
		try(bch2_dev_data_type_accounting_mod(trans, ca, new->data_type,
				 1,  new_sectors,  bch2_bucket_sectors_fragmented(ca, *new), flags));
		try(bch2_dev_data_type_accounting_mod(trans, ca, old->data_type,
				-1, -old_sectors, -bch2_bucket_sectors_fragmented(ca, *old), flags));
	} else if (old_sectors != new_sectors) {
		try(bch2_dev_data_type_accounting_mod(trans, ca, new->data_type,
					 0,
					 new_sectors - old_sectors,
					 bch2_bucket_sectors_fragmented(ca, *new) -
					 bch2_bucket_sectors_fragmented(ca, *old), flags));
	}

	s64 old_unstriped = bch2_bucket_sectors_unstriped(*old);
	s64 new_unstriped = bch2_bucket_sectors_unstriped(*new);
	if (old_unstriped != new_unstriped) {
		try(bch2_dev_data_type_accounting_mod(trans, ca, BCH_DATA_unstriped,
					 !!new_unstriped - !!old_unstriped,
					 new_unstriped - old_unstriped,
					 0,
					 flags));
	}

	return 0;
}

static noinline int inval_bucket_key(struct btree_trans *trans, struct bkey_s_c k)
{
	struct bch_fs *c = trans->c;
	CLASS(printbuf, buf)();
	bch2_fs_inconsistent(c, "reference to invalid bucket\n%s",
			     (bch2_bkey_val_to_text(&buf, c, k), buf.buf));
	return bch_err_throw(c, trigger_alloc);
}

#define eval_state(_a, expr)		({ const struct bch_alloc_v4 *a = _a; expr; })
#define statechange_to(expr)		(!eval_state(old_a, expr) && eval_state(new_a, expr))
#define statechange_from(expr)		(eval_state(old_a, expr) && !eval_state(new_a, expr))
#define statechange(expr)		(eval_state(old_a, expr) != eval_state(new_a, expr))

int bch2_trigger_alloc(struct btree_trans *trans, struct btree_trigger_op op)
{
	struct bch_fs *c = trans->c;
	int ret = 0;

	CLASS(bch2_dev_bucket_tryget, ca)(c, op.new.k->p);
	if (!ca)
		return bch_err_throw(c, trigger_alloc);

	struct bch_alloc_v4 old_a_convert;
	const struct bch_alloc_v4 *old_a = bch2_alloc_to_v4(op.old, &old_a_convert);

	struct bch_alloc_v4 *new_a;
	if (likely(op.new.k->type == KEY_TYPE_alloc_v4)) {
		new_a = bkey_s_to_alloc_v4(op.new).v;
	} else {
		struct bkey_i_alloc_v4 *new_ka =
			errptr_try(bch2_alloc_to_v4_mut_inlined(trans, op.new.s_c));
		new_a = &new_ka->v;
	}

	if (op.flags & BTREE_TRIGGER_transactional) {
		alloc_data_type_set(new_a, new_a->data_type);

		if (statechange_to(!data_type_is_empty(a->data_type))) {
			if ((new_a->data_type != BCH_DATA_sb &&
			     new_a->data_type != BCH_DATA_journal) &&
			    !bch2_bucket_is_open_safe(c, op.new.k->p.inode, op.new.k->p.offset) &&
			    !bch2_bucket_nouse(ca, op.new.k->p.offset)) {
				CLASS(printbuf, buf)();
				prt_printf(&buf, "bucket going empty but not open\n");
				bch2_bkey_val_to_text(&buf, c, op.new.s_c);

				log_fsck_err_on(true, trans,
					alloc_key_bucket_nonempty_to_empty_not_open,
					"%s", buf.buf);
			}

			new_a->io_time[READ] = bch2_current_io_time(c, READ);
			new_a->io_time[WRITE]= bch2_current_io_time(c, WRITE);
			SET_BCH_ALLOC_V4_NEED_INC_GEN(new_a, true);
			SET_BCH_ALLOC_V4_NEED_DISCARD(new_a, true);
		}

		if (data_type_is_empty(new_a->data_type) &&
		    BCH_ALLOC_V4_NEED_INC_GEN(new_a) &&
		    !bch2_bucket_is_open_safe(c, op.new.k->p.inode, op.new.k->p.offset)) {
			if (new_a->oldest_gen == new_a->gen &&
			    !bch2_bucket_sectors_total(*new_a))
				new_a->oldest_gen++;
			new_a->gen++;
			SET_BCH_ALLOC_V4_NEED_INC_GEN(new_a, false);
			alloc_data_type_set(new_a, new_a->data_type);
		}

		if (statechange(a->data_type == BCH_DATA_free) ||
		    (new_a->data_type == BCH_DATA_free &&
		     alloc_freespace_genbits(*old_a) != alloc_freespace_genbits(*new_a))) {
			try(bch2_bucket_do_freespace_index(trans, ca, op.old, old_a, false));
			try(bch2_bucket_do_freespace_index(trans, ca, op.new.s_c, new_a, true));
		}

		/*
		 * Reserve journal space for need_discard btree updates
		 * that will happen in the atomic section via write buffer:
		 */
		if (statechange(a->data_type == BCH_DATA_need_discard) ||
		    (old_a->data_type == BCH_DATA_need_discard &&
		     old_a->journal_seq_empty != new_a->journal_seq_empty))
			trans->extra_journal_u64s += 2 * jset_u64s(BKEY_U64s);

		if (new_a->data_type == BCH_DATA_cached &&
		    !new_a->io_time[READ])
			new_a->io_time[READ] = bch2_current_io_time(c, READ);

		try(bch2_lru_change(trans, op.new.k->p.inode,
				    bucket_to_u64(op.new.k->p),
				    alloc_lru_idx_read(*old_a),
				    alloc_lru_idx_read(*new_a)));

		try(bch2_lru_change(trans,
				    BCH_LRU_BUCKET_FRAGMENTATION,
				    bucket_to_u64(op.new.k->p),
				    alloc_lru_idx_fragmentation(*old_a, ca),
				    alloc_lru_idx_fragmentation(*new_a, ca)));

		if (old_a->gen != new_a->gen)
			try(bch2_bucket_gen_update(trans, op.new.k->p, new_a->gen));

		try(bch2_alloc_key_to_dev_counters(trans, ca, old_a, new_a, op.flags));
	}

	if (op.flags & BTREE_TRIGGER_atomic) {
		u64 transaction_seq = trans->journal_res.seq;
		BUG_ON(!transaction_seq);

		CLASS(printbuf, buf)();
		if (log_fsck_err_on(transaction_seq && new_a->journal_seq_nonempty > transaction_seq,
				    trans, alloc_key_journal_seq_in_future,
				    "bucket journal seq in future (currently at %llu)\n%s",
				    journal_cur_seq(&c->journal),
				    (bch2_bkey_val_to_text(&buf, c, op.new.s_c), buf.buf)))
			new_a->journal_seq_nonempty = transaction_seq;

		if (new_a->gen != old_a->gen) {
			guard(rcu)();
			u8 *gen = bucket_gen(ca, op.new.k->p.offset);
			if (unlikely(!gen))
				return inval_bucket_key(trans, op.new.s_c);
			*gen = new_a->gen;
		}

		if (statechange_to(a->data_type == BCH_DATA_free)) {
			/*
			 * Transitioning to free: should not have NEED_DISCARD set.
			 * Two legitimate paths:
			 *   - from need_discard via the discard path (with
			 *     BTREE_TRIGGER_is_discard)
			 *   - from need_gc_gens via bch2_gc_gens() bumping
			 *     oldest_gen (bucket has been empty the whole time,
			 *     no discard needed - alloc_data_type() just stopped
			 *     returning need_gc_gens)
			 */
			WARN_ON(BCH_ALLOC_V4_NEED_DISCARD(new_a));
			BUG_ON(old_a->data_type != BCH_DATA_need_discard &&
			       old_a->data_type != BCH_DATA_need_gc_gens);

			new_a->journal_seq_nonempty = new_a->journal_seq_empty = 0;

			bch2_alloc_wake_dev(ca);
		}

		if (statechange_to(!data_type_is_empty(a->data_type))) {
			/*
			 * Record journal sequence number of empty -> nonempty
			 * transition: Note that there may be multiple empty ->
			 * nonempty transitions, data in a bucket may be
			 * overwritten while we're still writing to it - so be
			 * careful to only record the first:
			 */
			if (!new_a->journal_seq_nonempty)
				new_a->journal_seq_nonempty = transaction_seq;
		}

		if (statechange_from(a->data_type == BCH_DATA_need_discard)) {
			if (data_type_is_empty(new_a->data_type))
				BUG_ON(!(op.flags & BTREE_TRIGGER_is_discard));
			else
				BUG_ON(!bch2_bucket_is_open_safe(c, op.new.k->p.inode, op.new.k->p.offset));
		}

		if (statechange_to(a->data_type == BCH_DATA_need_discard)) {
			/* Transitioning to need_discard: NEED_DISCARD must be set */
			WARN_ON(!BCH_ALLOC_V4_NEED_DISCARD(new_a));

			/*
			 * Bucket becomes empty: mark it as waiting for a
			 * journal flush, unless updates since empty -> nonempty
			 * transition were never flushed - we may need to ask
			 * the journal not to flush intermediate sequence
			 * numbers:
			 */
			new_a->journal_seq_empty = transaction_seq;

			if (new_a->journal_seq_nonempty ==  new_a->journal_seq_empty ||
			    bch2_journal_noflush_seq(&c->journal,
						     new_a->journal_seq_nonempty,
						     new_a->journal_seq_empty)) {
				new_a->journal_seq_nonempty = new_a->journal_seq_empty = 0;

				if (!bch2_bucket_set_discard_fast(c, op.new.k->p.inode, op.new.k->p.offset))
					bch2_fast_discard_bucket_add(ca, op.new.k->p.offset);
			}
		}

		if (statechange(a->data_type == BCH_DATA_need_discard)) {
			try(bch2_bucket_do_discard_index(trans, op.old, old_a, false));
			try(bch2_bucket_do_discard_index(trans, op.new.s_c, new_a, true));
		}

		if (statechange_to(a->data_type == BCH_DATA_cached) &&
		    !bch2_bucket_is_open(c, op.new.k->p.inode, op.new.k->p.offset) &&
		    should_invalidate_buckets(ca, bch2_dev_usage_read(ca)))
			bch2_dev_do_invalidates(ca);

		if (statechange_to(a->data_type == BCH_DATA_need_gc_gens))
			bch2_gc_gens_async(c);
	}

	if ((op.flags & BTREE_TRIGGER_gc) && (op.flags & BTREE_TRIGGER_insert)) {
		guard(rcu)();
		struct bucket *g = gc_bucket(ca, op.new.k->p.offset);
		if (unlikely(!g))
			return inval_bucket_key(trans, op.new.s_c);
		g->gen_valid	= 1;
		g->gen		= new_a->gen;
	}
fsck_err:
	return ret;
}

/* device removal */

static int bch2_dev_remove_need_discard(struct bch_fs *c, struct bch_dev *ca)
{
	CLASS(btree_trans, trans)(c);
	unsigned dev_idx = ca->dev_idx;

	return for_each_btree_key_commit(trans, iter,
			BTREE_ID_need_discard, POS_MIN,
			BTREE_ITER_intent|BTREE_ITER_prefetch, k,
			NULL, NULL, BCH_TRANS_COMMIT_no_enospc, ({
		struct bpos bucket = u64_to_bucket(k.k->p.offset);
		(bucket.inode == dev_idx)
			? bch2_btree_delete_at(trans, &iter,
					       BTREE_TRIGGER_norun)
			: 0;
	}));
}

int bch2_dev_remove_alloc(struct bch_fs *c, struct bch_dev *ca)
{
	struct bpos start	= POS(ca->dev_idx, 0);
	struct bpos end		= POS(ca->dev_idx, U64_MAX);
	int ret;

	/*
	 * We clear the LRU and need_discard btrees first so that we don't race
	 * with bch2_do_invalidates() and bch2_do_discards_async()
	 */
	ret =   bch2_dev_remove_lrus(c, ca) ?:
		bch2_dev_remove_need_discard(c, ca) ?:
		bch2_btree_delete_range(c, BTREE_ID_freespace, start, end,
					BTREE_TRIGGER_norun) ?:
		bch2_btree_delete_range(c, BTREE_ID_backpointers, start, end,
					BTREE_TRIGGER_norun) ?:
		bch2_btree_delete_range(c, BTREE_ID_bucket_gens, start, end,
					BTREE_TRIGGER_norun) ?:
		bch2_btree_delete_range(c, BTREE_ID_alloc, start, end,
					BTREE_TRIGGER_norun) ?:
		bch2_dev_usage_remove(c, ca);
	bch_err_msg_dev(ca, ret, "removing dev alloc info");
	return ret;
}

/* Bucket IO clocks: */

static int __bch2_bucket_io_time_reset(struct btree_trans *trans, unsigned dev,
				size_t bucket_nr, int rw)
{
	CLASS(btree_iter_uninit, iter)(trans);
	struct bkey_i_alloc_v4 *a =
		errptr_try(bch2_trans_start_alloc_update_noupdate(trans, &iter, POS(dev, bucket_nr)));

	u64 now = bch2_current_io_time(trans->c, rw);
	if (a->v.io_time[rw] == now)
		return 0;

	a->v.io_time[rw] = now;

	try(bch2_trans_update(trans, &iter, &a->k_i, 0));
	try(bch2_trans_commit(trans, NULL, NULL, 0));
	return 0;
}

int bch2_bucket_io_time_reset(struct btree_trans *trans, unsigned dev,
			      size_t bucket_nr, int rw)
{
	if (bch2_trans_relock(trans))
		bch2_trans_begin(trans);

	return nested_lockrestart_do(trans, __bch2_bucket_io_time_reset(trans, dev, bucket_nr, rw));
}

/* Startup/shutdown (ro/rw): */

unsigned long bch2_fs_ra_pages(struct bch_fs *c)
{
	unsigned long ra_pages = 0;
	unsigned long ra_per_dev = c->opts.dev_readahead >> PAGE_SHIFT;

	scoped_guard(rcu)
		for_each_member_device_rcu(c, ca, NULL)
			if (READ_ONCE(ca->disk_sb.bdev))
				ra_pages += ra_per_dev;

	return ra_pages ?: VM_READAHEAD_PAGES;
}

void bch2_recalc_capacity(struct bch_fs *c)
{
	u64 capacity = 0, reserved_sectors = 0, gc_reserve;
	unsigned bucket_size_max = 0;

	lockdep_assert_held(&c->state_lock);

	guard(rcu)();
	for_each_member_device_rcu(c, ca, NULL) {
		if (ca->mi.state != BCH_MEMBER_STATE_rw)
			continue;

		if (!ca->mi.durability)
			continue;

		u64 dev_reserve = 0;

		/*
		 * We need to reserve buckets (from the number
		 * of currently available buckets) against
		 * foreground writes so that mainly copygc can
		 * make forward progress.
		 *
		 * We need enough to refill the various reserves
		 * from scratch - copygc will use its entire
		 * reserve all at once, then run against when
		 * its reserve is refilled (from the formerly
		 * available buckets).
		 *
		 * This reserve is just used when considering if
		 * allocations for foreground writes must wait -
		 * not -ENOSPC calculations.
		 */

		dev_reserve += ca->nr_btree_reserve * 2;
		dev_reserve += ca->mi.nbuckets >> 6; /* copygc reserve */

		dev_reserve += 1;	/* btree write point */
		dev_reserve += 1;	/* copygc write point */
		dev_reserve += 1;	/* rebalance write point */

		dev_reserve *= ca->mi.bucket_size;

		capacity += bucket_to_sector(ca, ca->mi.nbuckets -
					     ca->mi.first_bucket);

		reserved_sectors += dev_reserve * 2;

		bucket_size_max = max_t(unsigned, bucket_size_max,
					ca->mi.bucket_size);
	}

	bch2_set_ra_pages(c, bch2_fs_ra_pages(c));

	gc_reserve = c->opts.gc_reserve_bytes
		? c->opts.gc_reserve_bytes >> 9
		: div64_u64(capacity * c->opts.gc_reserve_percent, 100);

	reserved_sectors = max(gc_reserve, reserved_sectors);

	reserved_sectors = min(reserved_sectors, capacity);

	c->capacity.reserved = reserved_sectors;
	c->capacity.capacity = capacity - reserved_sectors;

	c->capacity.bucket_size_max = bucket_size_max;

	/* Wake up case someone was waiting for buckets */
	bch2_alloc_wake_all(c);
}

u64 bch2_min_rw_member_capacity(struct bch_fs *c)
{
	u64 ret = U64_MAX;

	guard(rcu)();
	for_each_rw_member_rcu(c, ca)
		ret = min(ret, ca->mi.nbuckets * ca->mi.bucket_size);
	return ret;
}

static bool bch2_dev_has_open_write_point(struct bch_fs *c, struct bch_dev *ca)
{
	struct open_bucket *ob;

	for (ob = c->allocator.open_buckets;
	     ob < c->allocator.open_buckets + ARRAY_SIZE(c->allocator.open_buckets);
	     ob++) {
		scoped_guard(spinlock, &ob->lock) {
			if (ob->valid && !ob->on_partial_list &&
			    ob->dev == ca->dev_idx)
				return true;
		}
	}

	return false;
}

void bch2_dev_allocator_set_rw(struct bch_fs *c, struct bch_dev *ca, bool rw)
{
	/* BCH_DATA_free == all rw devs */

	for (unsigned i = 0; i < ARRAY_SIZE(c->allocator.rw_devs); i++) {
		bool data_type_rw = rw;

		if (i != BCH_DATA_free &&
		    !(ca->mi.data_allowed & BIT(i)))
			data_type_rw = false;

		if ((i == BCH_DATA_journal ||
		     i == BCH_DATA_btree) &&
		    !ca->mi.durability)
			data_type_rw = false;

		mod_bit(ca->dev_idx, c->allocator.rw_devs[i].d, data_type_rw);
	}

	c->allocator.rw_devs_change_count++;
}

/* device goes ro: */
void bch2_dev_allocator_remove(struct bch_fs *c, struct bch_dev *ca)
{
	lockdep_assert_held(&c->state_lock);

	/* First, remove device from allocation groups: */
	bch2_dev_allocator_set_rw(c, ca, false);

	/*
	 * Capacity is calculated based off of devices in allocation groups:
	 */
	bch2_recalc_capacity(c);

	bch2_open_buckets_stop(c, ca, false);

	/*
	 * Wake up threads that were blocked on allocation, so they can notice
	 * the device can no longer be removed and the capacity has changed:
	 */
	bch2_alloc_wake_all(c);

	/*
	 * journal_res_get() can block waiting for free space in the journal -
	 * it needs to notice there may not be devices to allocate from anymore:
	 */
	wake_up(&c->journal.wait);

	/* Now wait for any in flight writes: */

	closure_wait_event(&c->allocator.open_buckets_wait,
			   !bch2_dev_has_open_write_point(c, ca));
}

/* device goes rw: */
void bch2_dev_allocator_add(struct bch_fs *c, struct bch_dev *ca)
{
	lockdep_assert_held(&c->state_lock);

	bch2_dev_allocator_set_rw(c, ca, true);
	c->allocator.rw_devs_change_count++;
}

void bch2_fs_allocator_background_init(struct bch_fs *c)
{
	spin_lock_init(&c->allocator.freelist_lock);
}

void bch2_fs_capacity_exit(struct bch_fs *c)
{
	percpu_free_rwsem(&c->capacity.mark_lock);
	if (c->capacity.pcpu) {
		u64 v = percpu_u64_get(&c->capacity.pcpu->online_reserved);
		WARN(v, "online_reserved not 0 at shutdown: %lli", v);
	}

	free_percpu(c->capacity.pcpu);
	free_percpu(c->capacity.usage);
}

int bch2_fs_capacity_init(struct bch_fs *c)
{
	mutex_init(&c->capacity.sectors_available_lock);
	seqcount_init(&c->capacity.usage_lock);

	try(percpu_init_rwsem(&c->capacity.mark_lock));

	if (!(c->capacity.pcpu = alloc_percpu(struct bch_fs_capacity_pcpu)) ||
	    !(c->capacity.usage = alloc_percpu(struct bch_fs_usage_base)))
		return bch_err_throw(c, ENOMEM_fs_other_alloc);

	return 0;
}
