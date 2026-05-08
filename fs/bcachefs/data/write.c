// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2010, 2011 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright 2012 Google, Inc.
 */

/* DOC(data-write-path)
 *
 * Writes go through a pipeline of optional transformations: compression
 * (lz4/zstd/gzip), encryption (ChaCha20), and checksumming, applied in that
 * order. The data is then written to each replica device and the extent
 * metadata is updated in the btree atomically. If encryption or compression
 * are not enabled, those stages are skipped entirely.
 *
 * Write point selection determines which device(s) receive the data and how
 * IO from different sources is segregated into separate buckets — see the
 * foreground allocator documentation.
 *
 * Direct IO can bypass internal buffering when no transformations are needed
 * and the user buffer is properly aligned, avoiding an extra memory copy.
 */

/* DOC_LATEX(data-paths)
 * \subsubsection{Write path}
 *
 * \bchdoc{data-write-path}
 *
 * The normal (COW) write path allocates new disk space, encodes the data
 * (compression, then encryption, then checksumming), writes it to each replica
 * device, and inserts a new extent key into the btree. Because writes always go
 * to new locations, the old data remains intact until the btree update commits ---
 * there is no window where a crash can leave partially-written data.
 *
 * Multiple \hyperref[sec:write-points]{write points} are used, selected by
 * hashing the process ID, to segregate unrelated data and help prevent
 * fragmentation.
 *
 * Writes with checksumming or compression enabled must bounce the data through a
 * temporary buffer for checksum stability (the kernel cannot guarantee that a
 * user buffer won't be modified in flight). This is the main per-write overhead
 * of encoded extents.
 *
 * The \hyperref[time-stats:data_write]{{\tt data\_write}} time stat tracks
 * end-to-end write latency (from submission to btree update). The
 * \hyperref[counters:data_write]{{\tt data\_write}} persistent counter tracks
 * total sectors written.
 *
 * \paragraph{Nocow writes}
 *
 * The nocow write path overwrites data in place, bypassing the encoded-extent
 * pipeline entirely: no checksumming, no compression, no encryption, no COW. This
 * eliminates write amplification and bounce buffer overhead at the cost of data
 * integrity features.
 *
 * Nocow writes require per-bucket locking to avoid racing with the move path.
 * This is normally invisible, but contention can appear under heavy concurrent
 * nocow writes; the
 * \hyperref[time-stats:nocow_lock_contended]{{\tt nocow\_lock\_contended}} time
 * stat tracks this (see \hyperref[sec:debugging]{Debugging tools}). When
 * \hyperref[sec:snapshots]{snapshots} or \hyperref[sec:reflink]{reflinks} create
 * shared extents, even nocow files fall back to COW for those extents.
 *
 * Because nocow writes are not checksummed, they cannot be verified by scrub or
 * self-healed from replicas. On encrypted filesystems, nocow data is stored in
 * plaintext. The option is primarily useful for database and VM workloads that
 * manage their own data integrity and need stable disk offsets or minimal write
 * amplification.
 *
 * \subsubsection{Read path}
 *
 * \bchdoc{data-read-path}
 *
 * The read path looks up the extent covering the requested range and reads the
 * data from disk. With multiple replicas, reads stripe across replicas, preferring
 * the one with the lowest current IO latency. For encoded extents, the entire
 * extent must be read even if only a portion was requested, because the checksum
 * covers the full extent and decompression requires the complete input. This
 * per-extent granularity gives much better compression ratios and much smaller
 * metadata (fewer checksums to store) than block-granular approaches. Buffered IO
 * automatically reads entire extents into the page cache, so the only real
 * downside is to small-block random read performance that doesn't fit in cache ---
 * a workload that is rare outside of benchmarks. Block-granular checksums may be
 * added as an option in the future if there is user demand.
 *
 * \paragraph{Error handling}
 *
 * When a checksum mismatch is detected, the same replica is first re-read up to
 * \texttt{checksum\_err\_retry\_nr} times (default 3) to handle transient errors
 * such as bitflips during bus transfer. If retries do not produce a good read and
 * another replica exists, the read is retried from that replica. On successful
 * retry, the failed replica is immediately repaired by rewriting it from the good
 * copy --- this is self-healing, and it happens transparently on every read. If
 * erasure coding is available, the missing data can be reconstructed from parity
 * even with no good replica. If no valid copy can be obtained, the read returns an
 * IO error to userspace.
 *
 * When an extent with a checksum error must be moved (e.g.\ by copygc or
 * reconcile), the move path recomputes a checksum for the corrupted data so it
 * can be written to the new location, but marks the extent as \emph{poisoned}.
 * Poisoned extents are tracked by the \texttt{BCH\_EXTENT\_FLAG\_poisoned} flag:
 * the data is known bad, but the filesystem can still operate on it (move it,
 * account for it). Reads of poisoned extents return an error rather than silently
 * serving corrupt data.
 *
 * \texttt{KEY\_TYPE\_error} extents represent ranges where data has been
 * permanently lost --- for example, after a force device removal that left extents
 * with no remaining replicas. Reads to these ranges return IO errors. These error
 * keys are visible in \texttt{bcachefs list} output and can help diagnose which
 * files were affected by data loss.
 *
 * The \hyperref[time-stats:data_read]{{\tt data\_read}} time stat tracks
 * end-to-end read latency. The \hyperref[counters:data_read]{{\tt data\_read}}
 * counter tracks total sectors read;
 * \hyperref[counters:data_read_bounce]{{\tt data\_read\_bounce}} counts reads
 * that required a bounce buffer (encoded extents), and
 * \hyperref[counters:data_read_retry]{{\tt data\_read\_retry}} counts reads
 * retried due to checksum failure or stale pointers.
 *
 * \paragraph{Promote (caching)}
 *
 * When \texttt{promote\_target} is set, the read path can copy data from a slow
 * device to a fast device on read. This is how bcachefs implements tiered
 * caching: reads that hit a slow tier (e.g.\ HDD) are transparently promoted to a
 * fast tier (e.g.\ SSD) so that subsequent reads are served from the faster
 * device.
 *
 * Promotion is opportunistic: it is skipped if the data already has a copy on the
 * promote target, if the target is congested, or if the per-CPU promote
 * semaphore is exhausted. Promoted copies are written as cached pointers, so they
 * can be evicted under space pressure without data loss.
 *
 * Relevant counters and time stats:
 * \begin{itemize}
 * \item \hyperref[counters:data_read_promote]{{\tt data\_read\_promote}} ---
 *   sectors promoted
 * \item \hyperref[counters:data_read_nopromote_already_promoted]{{\tt nopromote\_already\_promoted}},
 *   \hyperref[counters:data_read_nopromote_congested]{{\tt nopromote\_congested}},
 *   \hyperref[counters:data_read_nopromote_unwritten]{{\tt nopromote\_unwritten}}
 *   --- reasons promotion was skipped
 * \item \hyperref[time-stats:data_promote]{{\tt data\_promote}} --- promotion
 *   write latency
 * \end{itemize}
 *
 * \subsubsection{Data structures}
 *
 * An extent's value (\texttt{struct bch\_extent}) is a variable-length array of
 * typed entries, each self-describing via a type field encoded in the low bits
 * of the first word (a scheme similar to UTF-8: the position of the first set
 * bit determines the type). The entries are defined by
 * \texttt{union bch\_extent\_entry} and can appear in any order, with one rule:
 * a CRC entry applies to all pointers that follow it until the next CRC entry.
 *
 * \paragraph{Extent pointers} (\texttt{struct bch\_extent\_ptr})
 *
 * Each pointer is the ``where is the data'' record: a device number, a
 * 44-bit sector offset (supporting up to 8\,PiB per device), and a generation
 * number that must match the bucket's current generation to be valid (stale
 * pointers are detected and dropped during reads). Flags distinguish cached
 * pointers (evictable copies on a faster tier) from dirty pointers, and mark
 * unwritten reservations.
 *
 * \paragraph{CRC entries} (\texttt{bch\_extent\_crc32/64/128})
 *
 * CRC entries carry the checksum, compression type, and the geometry needed
 * to handle partially-overwritten extents: \texttt{compressed\_size} and
 * \texttt{uncompressed\_size} record the original extent dimensions, and
 * \texttt{offset} records how far into the uncompressed data the currently
 * live region starts (the live region's size is in \texttt{bkey.size}).
 *
 * Three variants exist as a space optimization. Most extents need only a
 * \texttt{crc32} (8 bytes): it supports extents up to 128 sectors with a
 * 32-bit checksum and no nonce. \texttt{crc64} (16 bytes) extends this to 512
 * sectors, adds a 10-bit nonce for encryption, and carries an 80-bit checksum.
 * \texttt{crc128} (24 bytes) is the full-size form: 8192-sector extents, a
 * 13-bit nonce, and a 128-bit checksum --- required when encryption is enabled,
 * since the ChaCha20/Poly1305 MAC is 128 bits. The write path picks the
 * smallest variant that can represent the extent's parameters; the read path
 * unpacks all three into a common \texttt{bch\_extent\_crc\_unpacked} for
 * uniform handling.
 *
 * A CRC entry applies to every pointer after it until the next CRC entry.
 * Initially all replicas share one CRC, but copygc or tiering may rewrite a
 * single replica (possibly trimming it), producing a new CRC for just that
 * pointer. This is why extents can contain multiple CRC entries.
 *
 * \paragraph{Stripe pointer} (\texttt{struct bch\_extent\_stripe\_ptr})
 *
 * Links an extent to an erasure-coding stripe. The \texttt{idx} field
 * identifies the stripe, and \texttt{block} identifies which block within the
 * stripe this extent occupies. When a read fails, the EC subsystem can
 * reconstruct the data from the stripe's parity blocks.
 *
 * \paragraph{Flags entry} (\texttt{struct bch\_extent\_flags})
 *
 * A bitfield of per-extent flags. Currently the only flag is
 * \texttt{poisoned}: the extent contains data known to be corrupt (e.g.\ it
 * failed checksum verification and could not be repaired). Poisoned extents
 * are kept rather than discarded so that the filesystem can still account for
 * them and move them, but reads return an error.
 *
 * \paragraph{Reconcile entry} (\texttt{struct bch\_extent\_reconcile})
 *
 * Embeds IO options (target, compression, replicas, checksum type, erasure
 * coding) directly in the extent. This exists primarily for reflink indirect
 * extents: since an indirect extent may be referenced by many inodes, there is
 * no single ``owning'' inode to look up IO options from. The reconcile entry
 * records what the extent's options \emph{should} be so that background
 * reconciliation can bring them into compliance.
 *
 * \paragraph{Composition}
 *
 * A typical extent value is a sequence of these entries. Some examples:
 * \begin{itemize}
 *   \item Unchecksummed, single replica: \texttt{[ptr]} --- just one pointer,
 *     no CRC. The pointer's offset is adjusted directly when the extent is
 *     trimmed.
 *   \item Checksummed, 2 replicas: \texttt{[crc32, ptr, ptr]} --- one CRC
 *     covers both pointers (same data was written to both locations).
 *   \item After partial copygc of one replica: \texttt{[crc32, ptr, crc32,
 *     ptr]} --- the second pointer was rewritten to a new location covering
 *     only the live portion, so it gets its own CRC with different size/offset
 *     fields.
 *   \item EC extent with encryption: \texttt{[crc128, ptr, stripe\_ptr]} ---
 *     the 128-bit CRC is required for the encryption MAC, and the stripe
 *     pointer links to the parity stripe.
 *   \item Reflink indirect extent: \texttt{[crc32, ptr, ptr, reconcile]} ---
 *     the reconcile entry records the desired IO options for background
 *     processing.
 * \end{itemize}
 *
 * \subsubsection{Encryption}
 * \label{sec:encryption}
 *
 * bcachefs uses authenticated encryption (AEAD) with ChaCha20/Poly1305. Unlike
 * block-layer encryption (AES-XTS), which operates on fixed blocks with no room
 * for nonces or MACs, bcachefs stores a nonce and cryptographic MAC alongside
 * every data pointer, creating a chain of trust from the superblock down to
 * individual extents: any modification, deletion, reordering, or rollback of
 * metadata is detectable. Encryption is all-or-nothing at the filesystem level
 * and can only be enabled at format time.
 *
 * \paragraph{Key hierarchy}
 *
 * The key hierarchy has three levels:
 * \begin{enumerate}
 * 	\item \textbf{Passphrase}: User-supplied, never stored on disk. Fed to
 * 		the scrypt KDF (parameters stored in the
 * 		\hyperref[sec:superblock]{superblock}'s
 * 		\texttt{bch\_sb\_field\_crypt}) to derive a 256-bit
 * 		passphrase key. The KDF runs entirely in userspace, so
 * 		alternative key sources (hardware tokens, key files) can be
 * 		integrated without kernel changes.
 *
 * 	\item \textbf{Master key}: A random 256-bit key generated at format
 * 		time, stored in the superblock encrypted by the passphrase
 * 		key. A magic value (\texttt{BCH\_KEY\_MAGIC}) stored
 * 		alongside the encrypted master key allows verification of a
 * 		correct passphrase without trial decryption of filesystem
 * 		data. Changing the passphrase re-encrypts only the master key,
 * 		not any filesystem data.
 *
 * 	\item \textbf{Per-extent nonces}: Each extent is encrypted with the
 * 		master key and a 128-bit nonce composed of the extent's
 * 		96-bit version number, compression type, and uncompressed
 * 		size, combined with a per-CRC nonce offset. Data encryption
 * 		uses the \texttt{BCH\_NONCE\_EXTENT} domain separator; the
 * 		Poly1305 MAC key uses \texttt{BCH\_NONCE\_POLY}.
 * \end{enumerate}
 *
 * There is currently no key rotation mechanism: the master key is fixed for the
 * lifetime of the filesystem. Key escrow, multi-passphrase unlock, and hardware
 * key (TPM, FIDO2) support are not implemented.
 *
 * \paragraph{Kernel keyring integration}
 *
 * The kernel never sees the passphrase. Instead, userspace derives the passphrase
 * key via scrypt and adds it to the Linux kernel keyring as a \texttt{user} type
 * key with description \texttt{bcachefs:<UUID>}. At mount time, the kernel calls
 * \texttt{request\_key()} to find this key, uses it to decrypt the master key
 * from the superblock, and caches the decrypted master key in kernel memory for
 * the lifetime of the mount.
 *
 * This design inherits the well-known pain points of the Linux keyring subsystem:
 *
 * \begin{itemize}
 * 	\item \textbf{Session isolation}: Keys added to a session keyring are
 * 		not visible from other sessions of the same user. An
 * 		\texttt{ssh} session that runs \texttt{bcachefs unlock} does
 * 		not make the key available to a different terminal, to
 * 		systemd mount units, or to cron jobs. The key must be added
 * 		to \texttt{KEY\_SPEC\_USER\_KEYRING} (the per-UID keyring) to
 * 		be visible across sessions, but this is not always the
 * 		default.
 *
 * 	\item \textbf{Privilege boundaries}: \texttt{sudo mount} uses root's
 * 		keyring, not the calling user's. Systemd units run in
 * 		isolated session contexts. The key must be explicitly placed
 * 		in a keyring that the mounting process can access.
 * \end{itemize}
 *
 * \paragraph{MAC storage}
 *
 * The Poly1305 MAC is stored in the extent's CRC entry. By default, the MAC is
 * truncated to 80 bits (\texttt{chacha20\_poly1305\_80}), which is sufficient for
 * most threat models. The \texttt{wide\_macs} option stores the full 128-bit MAC
 * at the cost of 8 bytes per extent, and is recommended when the storage device
 * itself is untrusted (e.g. USB drives, network storage) and an attacker can make
 * repeated forgery attempts or perform rollback attacks. Metadata always uses
 * 128-bit MACs regardless of the \texttt{wide\_macs} setting.
 *
 * \paragraph{Nonce reuse with external snapshots}
 *
 * AEAD algorithms require that a (key, nonce) pair is never reused for different
 * plaintexts. bcachefs derives extent nonces from the extent's version number,
 * which is unique within a single filesystem instance. However, if the underlying
 * storage is snapshotted externally (LVM, ZFS zvol, VM snapshot, loop device on a
 * reflinked file) and the snapshot is mounted read-write, both instances share the
 * same master key and will derive the same nonces for new writes to the same
 * logical locations. This breaks ChaCha20's semantic security.
 *
 * bcachefs's own snapshot mechanism does not have this problem: internal snapshots
 * share extents via reflinks with COW semantics, and new writes get new version
 * numbers and therefore new nonces.
 *
 * \textbf{Mitigation}: Never mount an external snapshot of an encrypted volume
 * read-write --- keep external snapshots read-only (\texttt{-o nochanges}).
 * Alternatively, place LUKS between the snapshot layer and bcachefs (e.g.
 * LVM $\to$ LUKS $\to$ bcachefs).
 *
 * \subsubsection{Erasure coding}
 * \label{sec:erasure-coding}
 *
 * Erasure coding uses Reed-Solomon parity (the same algorithm as RAID-5/6) to
 * provide redundancy at lower storage cost than full replication. It is enabled
 * per-inode via the \texttt{erasure\_code} option and uses the
 * \texttt{data\_replicas} setting to determine parity count:
 * \texttt{data\_replicas=2} gives one parity block (RAID-5),
 * \texttt{data\_replicas=3} gives two (RAID-6).
 *
 * \paragraph{Write path}
 *
 * Writes are initially replicated: one copy goes to a bucket queued for a new
 * stripe, and an extra replica provides immediate durability. As full stripes
 * accumulate, P/Q parity is written out and the extra replicas are dropped. This
 * gives us erasure coding with no write hole and no fragmentation of writes ---
 * data is written out in the ideal layout, and since stripes are written once and
 * never updated in place, parity is always consistent.
 *
 * The extra replicas are cheap. Since device write caches are only flushed on
 * journal commit (i.e.\ fsync), the allocator can return the extra-replica buckets
 * to the write point for reuse as soon as the stripe commits. In bandwidth-heavy
 * workloads with nothing doing fsyncs, the extra replicas can be overwritten while
 * still in the device writeback cache --- they only cost bus bandwidth, not real
 * disk writes.
 *
 * The allocator segregates EC and non-EC writes at the open-bucket level: a write
 * requesting EC will only be placed in a bucket already tagged for stripe
 * membership, and non-EC writes will never use such buckets. This means a bug in
 * stripe creation, parity computation, or extent updating is structurally scoped
 * to EC-enabled data: non-EC extents never carry \texttt{stripe\_ptr} entries
 * and are never read through EC reconstruction paths. Btree nodes are never
 * placed in EC buckets; this is explicitly checked and flagged as a filesystem
 * inconsistency.
 *
 * If stripe creation fails partway (e.g.\ a crash between writing parity and
 * updating extents), the extra replicas from the staging phase remain valid;
 * the reconcile subsystem detects the incomplete state and retries. Changing the
 * \texttt{erasure\_code} option at runtime triggers reconcile to add or remove EC
 * protection on existing data.
 *
 * \paragraph{Stripe layout}
 *
 * Each block in a stripe is one bucket on one device. Stripe width is determined
 * dynamically: all eligible devices in the target group are used, up to a maximum
 * of 16 blocks per stripe. Eligible devices must be read-write, have nonzero
 * durability, and share the same bucket size (the most common bucket size among
 * candidates is chosen; devices with a different bucket size are excluded). The
 * minimum is \texttt{redundancy + 2} devices (3 for RAID-5, 4 for RAID-6). With
 * $n$ eligible devices, a stripe has $n - \mathrm{redundancy}$ data blocks and
 * \texttt{redundancy} parity blocks, maximizing storage efficiency. There is no
 * configuration to limit stripe width to a subset of available devices.
 *
 * Stripe fragmentation is tracked in the LRU btree. When all data blocks in a
 * stripe become empty (sector count zero), the stripe is automatically deleted.
 * Partially empty stripes are candidates for reuse: new stripe creation scans
 * the fragmentation LRU for a stripe with matching parameters (same disk label,
 * algorithm, and redundancy), copies the non-empty blocks into the new stripe,
 * and fills the remaining slots with fresh data. This consolidation recovers
 * space without a full copygc pass.
 *
 * \paragraph{On-disk representation}
 *
 * A stripe is stored as a \texttt{bch\_stripe} key in the stripes btree (ID 6),
 * keyed by stripe index. The fixed-size header contains:
 * \begin{itemize}
 * \item \texttt{sectors} --- bucket size (all blocks in a stripe share the same
 *   bucket size)
 * \item \texttt{algorithm} --- Reed-Solomon variant (4 bits)
 * \item \texttt{nr\_blocks} --- total blocks (data + parity)
 * \item \texttt{nr\_redundant} --- number of parity blocks
 * \item \texttt{csum\_type}, \texttt{csum\_granularity\_bits} --- checksum
 *   algorithm and block granularity for per-block checksums
 * \item \texttt{disk\_label} --- target disk label (8 bits; a limitation noted
 *   for a future \texttt{stripe\_v2})
 * \item \texttt{needs\_reconcile} --- flag indicating the stripe needs
 *   reconcile processing (e.g.\ after partial creation or option change)
 * \end{itemize}
 *
 * After the header, three variable-length sections are packed in order:
 * \texttt{nr\_blocks} \texttt{bch\_extent\_ptr} entries (one per block, giving
 * the device, offset, and generation for each bucket); a 2D array of checksums
 * indexed by \texttt{[block][csum\_block]} where the checksum block size is
 * $2^{\mathtt{csum\_granularity\_bits}}$ sectors; and \texttt{nr\_blocks}
 * \texttt{\_\_le16} sector counts tracking how many sectors of live data each
 * block contains (used for fragmentation tracking and stripe deletion).
 *
 * Each data extent that belongs to a stripe carries an inline
 * \texttt{bch\_extent\_stripe\_ptr} entry with three fields:
 * \texttt{idx} (47-bit stripe index into the stripes btree),
 * \texttt{block} (8-bit block number within the stripe), and
 * \texttt{redundancy} (4-bit copy of the stripe's \texttt{nr\_redundant}, so the
 * read path knows the parity level without looking up the stripe).
 *
 * Several auxiliary btrees support EC operations: the
 * \texttt{bucket\_to\_stripe} btree (ID 26) maps each stripe-member bucket to
 * the stripes referencing it, enabling the allocator and copygc to know when a
 * bucket is part of a stripe; the \texttt{stripe\_backpointers} btree (ID 27)
 * stores backpointers indexed by stripe pointer for data on invalid or removed
 * devices, enabling stripe repair without the original device; and the alloc
 * btree tracks per-bucket \texttt{stripe\_refcount} and \texttt{stripe\_sectors}
 * separately from \texttt{dirty\_sectors}. Backpointers for stripe blocks point
 * back to the stripes btree rather than the extents btree.
 *
 * \paragraph{Reconstruction reads}
 *
 * EC reconstruction reads happen when a device is offline or a checksum mismatch
 * is detected: the read path fetches the remaining data blocks plus parity and
 * reconstructs the missing block using the Reed-Solomon algorithm.
 *
 * \paragraph{Consistency and self-healing}
 *
 * Stripe triggers validate bucket accounting on every stripe insert or delete:
 * parity bucket refcounts and dirty sector counts must be consistent. When a
 * mismatch is detected, the bucket is protected from reuse (refcount held at a
 * safe value) and the \texttt{check\_allocations} recovery pass is automatically
 * scheduled to perform a full repair. Stale pointers detected during
 * reconstruction reads similarly trigger recovery.
 *
 * If stripe creation fails partway (e.g.\ crash between writing parity and
 * updating extents), the extra replicas from the staging phase remain valid
 * data, and the reconcile subsystem detects the incomplete state and retries
 * stripe creation.
 *
 * \subsubsection{Reflink}
 * \label{sec:reflink}
 *
 * Reflink (\texttt{cp --reflink}, \texttt{FICLONE} ioctl) creates copies that
 * share underlying storage. The original extent is moved to the reflink btree
 * with a reference count, and a lightweight pointer (\texttt{KEY\_TYPE\_reflink\_p})
 * is left in the extents btree. Reads through a reflink pointer require two btree
 * lookups instead of one: first the reflink\_p, then the actual data pointers in
 * the reflink btree.
 *
 * \paragraph{On-disk representation}
 *
 * In the extents btree, a \texttt{KEY\_TYPE\_reflink\_p} replaces the original
 * extent. It contains an index (\texttt{REFLINK\_P\_IDX}, 56 bits) pointing
 * into the reflink btree (ID 7), plus \texttt{front\_pad} and
 * \texttt{back\_pad} fields. In the reflink btree, a
 * \texttt{KEY\_TYPE\_reflink\_v} stores the actual data pointers, CRCs, and
 * compression metadata (identical to a regular \texttt{KEY\_TYPE\_extent})
 * preceded by a 64-bit reference count.
 *
 * The pad fields exist because copygc or reconcile may split an indirect extent
 * into fragments. Without the pads, fragments outside the pointer's nominal
 * range would have their refcounts leaked. The pads remember the full range
 * originally referenced so that triggers walk all of the fragments when updating
 * refcounts. If the indirect extent is missing in the live data range (e.g.
 * due to corruption), fsck sets the \texttt{REFLINK\_P\_ERROR} flag on the
 * pointer; gaps only in the padded region adjust the pad instead.
 *
 * \paragraph{Creation and lifecycle}
 *
 * When \texttt{cp --reflink} (or the \texttt{FICLONE} ioctl) creates a reflink,
 * the source extent is converted in place. A new \texttt{KEY\_TYPE\_reflink\_v}
 * is allocated at the end of the reflink btree (by seeking to
 * \texttt{POS\_MAX}), containing the original data pointers and a refcount
 * initialized to zero. The source extent is replaced with a
 * \texttt{KEY\_TYPE\_reflink\_p}. If the source is already a
 * \texttt{reflink\_p}, no conversion is needed. A new \texttt{reflink\_p} is
 * then created in the destination file; btree triggers on the inserts increment
 * the refcount.
 *
 * On insertion or deletion of a \texttt{reflink\_p}, the trigger walks the full
 * referenced range (including pad) in the reflink btree and increments or
 * decrements the refcount on each overlapping \texttt{reflink\_v} fragment,
 * expanding the pads if the indirect extent is larger than expected (due to a
 * prior split). Writing new data over a \texttt{reflink\_p} requires no special
 * logic: the normal btree update inserts a regular \texttt{KEY\_TYPE\_extent},
 * the overwrite trigger decrements the refcount, and when a
 * \texttt{reflink\_v}'s refcount reaches zero, its trigger converts the key to
 * \texttt{KEY\_TYPE\_deleted}, cascading through the normal extent trigger to
 * free disk space and remove backpointers.
 *
 * Reflink is currently a one-way transformation: once an extent becomes
 * indirect, it never converts back, even when the refcount drops to 1. The
 * \texttt{reflink\_v} trigger fires at refcount 0 to delete the indirect
 * extent, but does not de-indirect at refcount 1 because the trigger would
 * need to walk transaction updates to find the sole remaining
 * \texttt{reflink\_p}, and operations like \texttt{fcollapse} and
 * \texttt{finsert} can cause transient refcount fluctuations (1 $\to$ 0
 * $\to$ 1) within a single transaction as extents are moved around. With IO
 * option propagation, de-indirecting at refcount 1 is becoming a more
 * pressing concern, since a lone indirect extent with one reference still
 * pays the cost of an extra btree lookup on every read.
 * Additionally, \texttt{reflink\_p} keys are not merged during btree
 * compaction because a merged pointer could span an unbounded number of
 * \texttt{reflink\_v} fragments; merging requires triggers to walk pending
 * transaction updates and diff overlapping \texttt{reflink\_p} ranges.
 *
 * \paragraph{IO option propagation}
 *
 * The \texttt{reflink\_p} carries a
 * \texttt{REFLINK\_P\_MAY\_UPDATE\_OPTIONS} flag that controls whether IO path
 * options (compression, checksum type, replicas, targets) may propagate from the
 * referencing file to the shared indirect extent. This is a security boundary: a
 * reflink copy of data owned by another user must not allow the copier to
 * decrease replicas or change checksum settings on data they do not own. At
 * creation time, the source file's \texttt{reflink\_p} gets this flag set, but
 * the destination's does not (the VFS layer does not yet pass down the
 * permission context needed to determine whether the copier has write access to
 * the source).
 *
 * A \texttt{reflink\_v} has no backpointer to its owning inode, so it cannot
 * look up per-inode IO options at read time. Instead, the indirect extent
 * embeds a \texttt{bch\_extent\_reconcile} entry that stores the desired IO
 * options alongside \texttt{*\_from\_inode} flags recording which options came
 * from a per-inode setting rather than the filesystem default. At creation time
 * no reconcile entry is added; the data is simply copied verbatim from the
 * source extent.
 *
 * When reconcile scans the extents btree and encounters a \texttt{reflink\_p}
 * with \texttt{REFLINK\_P\_MAY\_UPDATE\_OPTIONS} set, it follows through to
 * the corresponding \texttt{reflink\_v} keys in the reflink btree and updates
 * their embedded reconcile entries with the referencing inode's current
 * options. If the on-disk data does not match (e.g. the inode now requests
 * zstd compression but the data is uncompressed), the reconcile entry's
 * \texttt{need\_rb} bits are set and the data is scheduled for background
 * rewrite. Without the flag, reconcile does not propagate that
 * \texttt{reflink\_p}'s inode options to the indirect extent.
 *
 * The \texttt{reflink\_v} can only hold one set of IO options at a time. Since
 * only the source file's \texttt{reflink\_p} currently gets the
 * \texttt{MAY\_UPDATE\_OPTIONS} flag, there is no conflict when multiple files
 * reference the same indirect extent: the source file's options take
 * precedence, and other referencing files cannot influence the indirect
 * extent's IO path behavior. The read path always uses the CRC and compression
 * metadata stored in the \texttt{reflink\_v}'s extent entries (reflecting how
 * the data was actually written), regardless of the referencing file's current
 * options; the referencing inode's options only affect promote decisions.
 *
 * \paragraph{Interaction with snapshots}
 *
 * The reflink btree is not snapshot-aware: \texttt{reflink\_v} keys are shared
 * across all snapshots. The \texttt{reflink\_p} keys in the extents btree are
 * snapshot-aware, so when a file is snapshotted both subvolumes see the same
 * \texttt{reflink\_p} keys through normal snapshot visibility. Writing to
 * either subvolume creates a new extent in that snapshot and decrements the
 * shared refcount; the other snapshot's \texttt{reflink\_p} is unchanged.
 *
 * \paragraph{Consistency and self-healing}
 *
 * When the read path follows a \texttt{reflink\_p} and discovers the
 * corresponding \texttt{reflink\_v} is missing or partially missing, the
 * reference is repaired in-place: \texttt{front\_pad} and \texttt{back\_pad}
 * are adjusted to trim the reference to the valid range, and the
 * \texttt{REFLINK\_P\_ERROR} flag is set if the missing range overlaps actual
 * data. If a previously-errored indirect extent reappears (e.g.\ after btree
 * node recovery), the error flag is cleared automatically.
 *
 * The \texttt{check\_indirect\_extents} recovery pass walks the reflink btree,
 * validates extent sizes, and drops stale device pointers (generation
 * mismatches). This pass can run online.
 *
 * \subsubsection{Inline data extents}
 *
 * bcachefs supports inline data extents, controlled by the \texttt{inline\_data}
 * option (on by default). When the end of a file is being written and is smaller
 * than \texttt{min(blocksize/2, 1024)} bytes, it will be written as an inline data
 * extent. Inline data extents can also be reflinked: the inline data is moved to
 * the reflink btree as a \texttt{KEY\_TYPE\_indirect\_inline\_data} (which carries
 * a refcount and the inline data bytes) and a \texttt{KEY\_TYPE\_reflink\_p} is
 * left in the extents btree, following the same mechanics as regular extent
 * reflinks.
 *
 * \subsubsection{Move path}
 *
 * The move path is the shared IO engine behind copygc, reconcile, and device
 * evacuation. It reads extents via the normal read path, writes them to a new
 * location, and atomically updates pointers.
 *
 * Background move IO is throttled by two runtime-tunable options, both adjustable
 * via sysfs:
 * \begin{itemize}
 * \item \texttt{move\_bytes\_in\_flight} (default 64\,MB) --- total bytes of
 *   outstanding move IO
 * \item \texttt{move\_ios\_in\_flight} (default 64) --- number of outstanding
 *   requests
 * \end{itemize}
 *
 * \noindent Individual consumers can be disabled: \texttt{copygc\_enabled},
 * \texttt{reconcile\_enabled}, and \texttt{reconcile\_on\_ac\_only} (pauses
 * reconcile on battery power).
 *
 * \subsubsection{Reconcile}
 *
 * The reconcile subsystem ensures that all data and metadata is stored correctly
 * according to configured IO path options. It continuously monitors for
 * mismatches between how data is actually stored and how it should be stored ---
 * whether caused by option changes, device additions or removals, degraded
 * replicas, or any other reason --- and rewrites affected extents via the move
 * path.
 *
 * If reconcile detects an inconsistency without an obvious cause (no option
 * change, no device event), it records an error: something unexpected has
 * happened and needs attention. Degraded data (under-replicated due to a device
 * going offline or being removed) is repaired automatically as soon as
 * sufficient devices are available.
 *
 * The design is state-driven rather than event-driven: reconcile looks at what
 * the current state \emph{should be} and compares it to what it \emph{is}. This
 * means multiple operations compose naturally --- for example, evacuating
 * multiple devices simultaneously just works, because each extent is evaluated
 * independently against the current desired state.
 *
 * \paragraph{Work tracking}
 *
 * Work enters the system in two ways: \emph{triggers} on individual extent
 * updates detect mismatches between current data placement and desired options,
 * and \emph{scans} propagate option changes across all affected inodes. Scans
 * are triggered by device state changes (adding, removing, or changing a
 * device's read-write state) and by inode option changes that affect a directory
 * tree.
 *
 * On SSDs, work is tracked in logical key order in the
 * \texttt{reconcile\_work} and \texttt{reconcile\_hipri} btrees, which is
 * cheap since it matches the natural extent btree ordering. On rotational
 * devices, work is additionally tracked in the \texttt{reconcile\_work\_phys}
 * and \texttt{reconcile\_hipri\_phys} btrees, which reorder work by device LBA
 * so it can be processed sequentially. This avoids random seeks on HDDs and
 * enables parallel processing with one thread per device.
 *
 * The \texttt{reconcile\_pending} btree holds work that failed due to
 * insufficient space or devices. Pending work is only retried after device
 * configuration changes, solving the ``rebalance spinning'' problem where the
 * old rebalance thread would burn CPU retrying moves that could never complete.
 *
 * \paragraph{Priority ordering}
 *
 * The reconcile thread processes work in priority order: high-priority metadata
 * (under-replicated or evacuating) first, then high-priority data, then normal
 * metadata (e.g.\ moving stray metadata to \texttt{metadata\_target}), then
 * normal data, then pending retries.
 *
 * The \texttt{bcachefs reconcile status} command shows current progress, and
 * \texttt{bcachefs reconcile wait} blocks until specified work types complete.
 *
 * \paragraph{Consistency and self-healing}
 *
 * Reconcile is inherently self-healing: its entire purpose is to detect and fix
 * mismatches between desired and actual data placement. Beyond normal background
 * operation, the \texttt{check\_reconcile\_work} recovery pass validates the
 * work btrees against actual extent state, removing stale entries and correcting
 * incorrectly-categorized work items (e.g.\ normal-priority work that should be
 * high-priority). This pass can run online.
 *
 * Extent triggers automatically mark data for reconcile whenever a mismatch is
 * detected --- including degraded writes where the desired replica count could
 * not be satisfied. When a failed device is replaced or a new device is added,
 * all pending work in \texttt{reconcile\_pending} is automatically re-evaluated.
 *
 * \subsubsection{Copygc}
 *
 * \bchdoc{copygc}
 *
 * Copygc relies on backpointers to find live data in fragmented buckets. If
 * missing or inconsistent backpointers are detected during copygc, the
 * backpointer recovery pass is automatically scheduled and run (see
 * \hyperref[sec:backpointers]{Backpointers}).
 *
 * \subsubsection{Scrub}
 *
 * Scrub reads all data on a running filesystem and verifies checksums, detecting
 * silent data corruption (bitrot). When a checksum mismatch is found and a valid
 * redundant copy exists (from replication or erasure coding), the corrupted copy
 * is automatically repaired --- the same self-healing mechanism as the normal read
 * path, but applied proactively to all data rather than waiting for application
 * reads to discover corruption.
 *
 * Scrub walks data in physical (LBA) order using backpointers, which is efficient
 * for rotational devices and avoids the random access pattern that would result
 * from walking the logical extent tree. It can be run on a specific device or on
 * all devices. Progress is reported via sysfs and can be monitored with
 * \texttt{bcachefs data scrub}. Nocow data cannot be scrubbed (no checksums).
 */

#include "bcachefs.h"

#include "alloc/buckets.h"
#include "alloc/foreground.h"

#include "btree/bkey_buf.h"
#include "btree/bset.h"
#include "btree/update.h"

#include "data/checksum.h"
#include "data/compress.h"
#include "data/ec/create.h"
#include "data/extent_update.h"
#include "data/keylist.h"
#include "data/move.h"
#include "data/nocow_locking.h"
#include "data/reconcile/trigger.h"
#include "data/write.h"

#include "debug/async_objs.h"

#include "fs/inode.h"

#include "init/dev.h"
#include "init/error.h"
#include "init/fs.h"

#include "journal/journal.h"

#include "sb/io.h"

#include "snapshots/subvolume.h"

#include "util/clock.h"
#include "util/enumerated_ref.h"

#include <linux/blkdev.h>
#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/sched/mm.h>

#ifdef CONFIG_BCACHEFS_DEBUG
static unsigned bch2_write_corrupt_ratio;
module_param_named(write_corrupt_ratio, bch2_write_corrupt_ratio, uint, 0644);
MODULE_PARM_DESC(write_corrupt_ratio, "");
#endif

#ifndef CONFIG_BCACHEFS_NO_LATENCY_ACCT

static inline void bch2_congested_acct(struct bch_dev *ca, u64 io_latency,
				       u64 now, int rw)
{
	u64 latency_capable =
		ca->io_latency[rw].quantiles.entries[QUANTILE_IDX(1)].m;
	/* ideally we'd be taking into account the device's variance here: */
	u64 latency_threshold = latency_capable << (rw == READ ? 2 : 3);
	s64 latency_over = io_latency - latency_threshold;

	if (latency_threshold && latency_over > 0) {
		if (atomic_read(&ca->congested) < CONGESTED_MAX)
			atomic_add((u32) min(U32_MAX, io_latency * 2) /
				   (u32) min(U32_MAX, latency_threshold),
				   &ca->congested);

		ca->congested_last = now;
	} else if (atomic_read(&ca->congested) > 0) {
		atomic_dec(&ca->congested);
	}
}

void bch2_latency_acct(struct bch_dev *ca, u64 submit_time, int rw)
{
	atomic64_t *latency = &ca->cur_latency[rw];
	u64 now = local_clock();
	u64 io_latency = time_after64(now, submit_time)
		? now - submit_time
		: 0;
	u64 old, new;

	old = atomic64_read(latency);
	do {
		/*
		 * If the io latency was reasonably close to the current
		 * latency, skip doing the update and atomic operation - most of
		 * the time:
		 */
		if (abs((int) (old - io_latency)) < (old >> 1) &&
		    now & ~(~0U << 5))
			break;

		new = ewma_add(old, io_latency, 5);
	} while (!atomic64_try_cmpxchg(latency, &old, new));

	/*
	 * Only track read latency for congestion accounting: writes are subject
	 * to heavy queuing delays from page cache writeback:
	 */
	if (rw == READ)
		bch2_congested_acct(ca, io_latency, now, rw);

	__bch2_time_stats_update(&ca->io_latency[rw].stats, submit_time, now);
}

#endif

/* Allocate, free from mempool: */

void bch2_bio_free_pages_pool(struct bch_fs *c, struct bio *bio)
{
	for (struct bio_vec *bv = bio->bi_io_vec;
	     bv < bio->bi_io_vec + bio->bi_vcnt;
	     bv++) {
		void *p = bvec_virt(bv);

		if (bv->bv_len == BIO_BOUNCE_BUF_POOL_LEN)
			mempool_free(p, &c->bio_bounce_bufs);
		else
			free_pages((unsigned long) p, get_order(bv->bv_len));
	}
	bio->bi_vcnt = 0;
}

static void __bch2_bio_alloc_pages_pool(struct bch_fs *c, struct bio *bio,
					unsigned bs, size_t size)
{
	mutex_lock(&c->bio_bounce_pages_lock);

	while (bio->bi_iter.bi_size < size)
		bio_add_virt_nofail(bio,
				    mempool_alloc(&c->bio_bounce_bufs, GFP_NOFS),
				    BIO_BOUNCE_BUF_POOL_LEN);

	bio->bi_iter.bi_size = min(bio->bi_iter.bi_size, size);

	mutex_unlock(&c->bio_bounce_pages_lock);
}

void bch2_bio_alloc_pages_pool(struct bch_fs *c, struct bio *bio,
			       unsigned bs, size_t size)
{
	bch2_bio_alloc_pages(bio, c->opts.block_size, size, GFP_NOFS);

	if (bio->bi_iter.bi_size < size)
		__bch2_bio_alloc_pages_pool(c, bio, bs, size);
}

/* Extent update path: */

int bch2_sum_sector_overwrites(struct btree_trans *trans,
			       struct btree_iter *extent_iter,
			       struct bkey_i *new,
			       bool *usage_increasing,
			       s64 *i_sectors_delta,
			       s64 *disk_sectors_delta)
{
	struct bch_fs *c = trans->c;
	unsigned new_replicas = bch2_bkey_replicas(c, bkey_i_to_s_c(new));
	bool new_compressed = bch2_bkey_sectors_compressed(c, bkey_i_to_s_c(new));

	*usage_increasing	= false;
	*i_sectors_delta	= 0;
	*disk_sectors_delta	= 0;

	CLASS(btree_iter_copy, iter)(extent_iter);
	struct bkey_s_c old;
	int ret = 0;
	for_each_btree_key_max_continue_norestart(iter,
				new->k.p, BTREE_ITER_slots, old, ret) {
		s64 sectors = min(new->k.p.offset, old.k->p.offset) -
			max(bkey_start_offset(&new->k),
			    bkey_start_offset(old.k));

		*i_sectors_delta += sectors *
			(bkey_extent_is_allocation(&new->k) -
			 bkey_extent_is_allocation(old.k));

		*disk_sectors_delta += sectors * bch2_bkey_nr_ptrs_allocated(c, bkey_i_to_s_c(new));
		*disk_sectors_delta -= new->k.p.snapshot == old.k->p.snapshot
			? sectors * bch2_bkey_nr_ptrs_fully_allocated(c, old)
			: 0;

		if (!*usage_increasing &&
		    (new->k.p.snapshot != old.k->p.snapshot ||
		     new_replicas > bch2_bkey_replicas(c, old) ||
		     (!new_compressed && bch2_bkey_sectors_compressed(c, old))))
			*usage_increasing = true;

		if (bkey_ge(old.k->p, new->k.p))
			break;
	}

	return ret;
}

static inline int bch2_extent_update_i_size_sectors(struct btree_trans *trans,
						    struct btree_iter *extent_iter,
						    u64 new_i_size,
						    s64 i_sectors_delta,
						    struct bch_inode_unpacked *inode_u)
{
	/*
	 * Crazy performance optimization:
	 * Every extent update needs to also update the inode: the inode trigger
	 * will set bi->journal_seq to the journal sequence number of this
	 * transaction - for fsync.
	 *
	 * But if that's the only reason we're updating the inode (we're not
	 * updating bi_size or bi_sectors), then we don't need the inode update
	 * to be journalled - if we crash, the bi_journal_seq update will be
	 * lost, but that's fine.
	 */
	unsigned inode_update_flags = BTREE_UPDATE_nojournal;

	CLASS(btree_iter, iter)(trans, BTREE_ID_inodes,
				SPOS(0,
				     extent_iter->pos.inode,
				     extent_iter->snapshot),
				BTREE_ITER_intent|
				BTREE_ITER_cached);
	struct bkey_s_c k = bch2_btree_iter_peek_slot(&iter);

	/*
	 * XXX: we currently need to unpack the inode on every write because we
	 * need the current io_opts, for transactional consistency - inode_v4?
	 */
	int ret = bkey_err(k) ?:
		  bch2_inode_unpack(k, inode_u);
	if (unlikely(ret))
		return ret;

	/*
	 * varint_decode_fast(), in the inode .invalid method, reads up to 7
	 * bytes past the end of the buffer:
	 */
	struct bkey_i *k_mut = errptr_try(bch2_trans_kmalloc_nomemzero(trans, bkey_bytes(k.k) + 8));

	bkey_reassemble(k_mut, k);

	if (unlikely(k_mut->k.type != KEY_TYPE_inode_v3))
		k_mut = errptr_try(bch2_inode_to_v3(trans, k_mut));

	struct bkey_i_inode_v3 *inode = bkey_i_to_inode_v3(k_mut);

	if (!(le64_to_cpu(inode->v.bi_flags) & BCH_INODE_i_size_dirty) &&
	    new_i_size > le64_to_cpu(inode->v.bi_size)) {
		inode->v.bi_size = cpu_to_le64(new_i_size);
		inode_update_flags = 0;
	}

	if (i_sectors_delta) {
		s64 bi_sectors = le64_to_cpu(inode->v.bi_sectors);
		if (unlikely(bi_sectors + i_sectors_delta < 0)) {
			struct bch_fs *c = trans->c;

			CLASS(bch_log_msg, msg)(c);
			prt_printf(&msg.m, "inode %llu i_sectors underflow: %lli + %lli < 0",
				   extent_iter->pos.inode, bi_sectors, i_sectors_delta);

			msg.m.suppress = !bch2_count_fsck_err(c, inode_i_sectors_underflow, &msg.m);

			if (i_sectors_delta < 0)
				i_sectors_delta = -bi_sectors;
			else
				i_sectors_delta = 0;
		}

		le64_add_cpu(&inode->v.bi_sectors, i_sectors_delta);
		inode_update_flags = 0;
	}

	/*
	 * extents, dirents and xattrs updates require that an inode update also
	 * happens - to ensure that if a key exists in one of those btrees with
	 * a given snapshot ID an inode is also present - so we may have to skip
	 * the nojournal optimization:
	 */
	if (inode->k.p.snapshot != iter.snapshot) {
		inode->k.p.snapshot = iter.snapshot;
		inode_update_flags = 0;
	}

	return bch2_trans_update(trans, &iter, &inode->k_i,
				 BTREE_UPDATE_internal_snapshot_node|
				 inode_update_flags);
}

int bch2_extent_update(struct btree_trans *trans,
		       subvol_inum inum,
		       struct btree_iter *iter,
		       struct bkey_i *k, unsigned k_buf_u64s,
		       struct disk_reservation *disk_res,
		       u64 new_i_size,
		       s64 *i_sectors_delta_total,
		       bool check_enospc,
		       u32 change_cookie)
{
	struct bch_fs *c = trans->c;
	struct bpos next_pos;
	bool usage_increasing;
	s64 i_sectors_delta = 0, disk_sectors_delta = 0;

	/*
	 * This traverses us the iterator without changing iter->path->pos to
	 * search_key() (which is pos + 1 for extents): we want there to be a
	 * path already traversed at iter->pos because
	 * bch2_trans_extent_update() will use it to attempt extent merging
	 */
	try(__bch2_btree_iter_traverse(iter));

	try(bch2_extent_trim_atomic(trans, iter, k));

	next_pos = k->k.p;

	try(bch2_sum_sector_overwrites(trans, iter, k,
				       &usage_increasing,
				       &i_sectors_delta,
				       &disk_sectors_delta));

	if (disk_res &&
	    disk_sectors_delta > (s64) disk_res->sectors)
		try(bch2_disk_reservation_add(c, disk_res,
					disk_sectors_delta - disk_res->sectors,
					!check_enospc || !usage_increasing
					? BCH_DISK_RESERVATION_NOFAIL : 0));

	/*
	 * Note:
	 * We always have to do an inode update - even when i_size/i_sectors
	 * aren't changing - for fsync to work properly; fsync relies on
	 * inode->bi_journal_seq which is updated by the trigger code:
	 */
	struct bch_inode_unpacked inode;
	struct bch_inode_opts opts;

	try(bch2_extent_update_i_size_sectors(trans, iter,
					      min(k->k.p.offset << 9, new_i_size),
					      i_sectors_delta, &inode));

	bch2_inode_opts_get_inode(c, &inode, &opts);

	try(bch2_bkey_set_needs_reconcile(trans, NULL, &opts, bkey_i_to_s(k), k_buf_u64s,
					  SET_NEEDS_RECONCILE_foreground,
					  change_cookie));
	try(bch2_trans_update(trans, iter, k,
			      BTREE_TRIGGER_set_needs_reconcile_done));
	try(bch2_trans_commit(trans, disk_res, NULL,
			      BCH_TRANS_COMMIT_no_check_rw|
			      BCH_TRANS_COMMIT_no_enospc));

	if (i_sectors_delta_total)
		*i_sectors_delta_total += i_sectors_delta;
	bch2_btree_iter_set_pos(iter, next_pos);
	return 0;
}

static int bch2_write_index_default(struct bch_write_op *op)
{
	struct bch_fs *c = op->c;
	struct keylist *keys = &op->insert_keys;
	struct bkey_i *k = bch2_keylist_front(keys);
	subvol_inum inum = {
		.subvol = op->subvol,
		.inum	= k->k.p.inode,
	};

	BUG_ON(!inum.subvol);

	CLASS(btree_trans, trans)(c);

	struct bkey_buf sk __cleanup(bch2_bkey_buf_exit);
	bch2_bkey_buf_init(&sk);

	do {
		bch2_trans_begin(trans);

		k = bch2_keylist_front(keys);

		/*
		 * If we did a degraded write, bch2_bkey_set_needs_reconcile() will add
		 * pointers to BCH_SB_MEMBER_INVALID so the extent is accounted as
		 * degraded
		 */
		bch2_bkey_buf_realloc(&sk, k->k.u64s + 1 + BCH_REPLICAS_MAX);
		bch2_bkey_buf_copy(&sk, k);

		int ret = bch2_subvolume_get_snapshot(trans, inum.subvol, &sk.k->k.p.snapshot);
		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (ret)
			return ret;

		CLASS(btree_iter, iter)(trans, BTREE_ID_extents,
					bkey_start_pos(&sk.k->k),
					BTREE_ITER_slots|BTREE_ITER_intent);

		ret =   bch2_extent_update(trans, inum, &iter, sk.k,
					sk.k->k.u64s + 1 + BCH_REPLICAS_MAX,
					&op->res,
					op->new_i_size, &op->i_sectors_delta,
					op->flags & BCH_WRITE_check_enospc,
					op->opts.change_cookie);

		if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
			continue;
		if (ret)
			return ret;

		if (bkey_ge(iter.pos, k->k.p))
			bch2_keylist_pop_front(&op->insert_keys);
		else
			bch2_cut_front(c, iter.pos, k);
	} while (!bch2_keylist_empty(keys));

	return 0;
}

/* Writes */

static void bch2_log_write_error_start(struct printbuf *out, bool full,
				       struct bch_write_op *op, u64 offset)
{
	prt_printf(out, "error writing data at ");

	struct bpos pos = op->pos;
	pos.offset = offset;

	CLASS(btree_trans, trans)(op->c);
	bch2_inum_offset_err_msg_trans(trans, out, op->subvol, pos);
	prt_newline(out);

	bch2_write_op_to_text(out, op);
}

void bch2_write_op_error(struct bch_write_op *op, bool full, u64 offset, const char *fmt, ...)
{
	CLASS(bch_log_msg_ratelimited, msg)(op->c);

	bch2_log_write_error_start(&msg.m, full, op, offset);

	va_list args;
	va_start(args, fmt);
	prt_vprintf(&msg.m, fmt, args);
	va_end(args);
}

/*
 * @cas is the caller's bch_dev pointer array (parallel to @k's ptrs)
 * for the nocow path — those io_refs were already taken by the caller
 * via bkey_get_dev_iorefs and we just transfer them to the per-bio
 * wbios here.  Non-nocow callers pass NULL and we take fresh io_refs
 * via bch2_dev_get_ioref atomically.
 */
void bch2_submit_wbio_replicas(struct bch_write_bio *wbio, struct bch_fs *c,
			       enum bch_data_type type,
			       const struct bkey_i *k,
			       bool nocow, struct bch_dev **cas)
{
	struct bkey_ptrs_c ptrs = bch2_bkey_ptrs_c(bkey_i_to_s_c(k));
	struct bch_write_bio *n;
	unsigned ref_rw  = type == BCH_DATA_btree ? READ : WRITE;
	unsigned ref_idx = type == BCH_DATA_btree
		? (unsigned) BCH_DEV_READ_REF_btree_node_write
		: (unsigned) BCH_DEV_WRITE_REF_io_write;

	BUG_ON(c->opts.nochanges);
	BUG_ON(nocow && !cas);

	const struct bch_extent_ptr *last = NULL;
	bkey_for_each_ptr(ptrs, ptr)
		if (ptr->dev != BCH_SB_MEMBER_INVALID)
			last = ptr;

	BUG_ON(!last);

	/* For nocow, bkey_get_dev_iorefs would have bailed if it hit an
	 * invalid ptr, so cas_idx stays in sync with the iterator. */
	unsigned cas_idx = 0;
	bkey_for_each_ptr(ptrs, ptr) {
		if (ptr->dev == BCH_SB_MEMBER_INVALID)
			continue;

		/*
		 * XXX: btree writes should be using io_ref[WRITE], but we
		 * aren't retrying failed btree writes yet (due to device
		 * removal/ro):
		 */
		struct bch_dev *ca = nocow
			? cas[cas_idx++]
			: bch2_dev_get_ioref(c, ptr->dev, ref_rw, ref_idx);

		if (ptr != last) {
			n = to_wbio(bio_alloc_clone(NULL, &wbio->bio, GFP_NOFS, &c->replica_set));

			n->bio.bi_end_io	= wbio->bio.bi_end_io;
			n->bio.bi_private	= wbio->bio.bi_private;
			n->parent		= wbio;
			n->split		= true;
			n->bounce		= false;
			n->put_bio		= true;
			n->bio.bi_opf		= wbio->bio.bi_opf;
			bio_inc_remaining(&wbio->bio);
		} else {
			n = wbio;
			n->split		= false;
		}

		n->c			= c;
		n->ca			= ca;
		n->dev			= ptr->dev;
		n->nocow		= nocow;
		n->submit_time		= local_clock();
		n->inode_offset		= bkey_start_offset(&k->k);
		if (nocow)
			n->nocow_bucket	= PTR_BUCKET_NR(ca, ptr);
		n->bio.bi_iter.bi_sector = ptr->offset;

		if (likely(n->ca)) {
			this_cpu_add(ca->io_done->sectors[WRITE][type],
				     bio_sectors(&n->bio));

			bio_set_dev(&n->bio, ca->disk_sb.bdev);

			if (type != BCH_DATA_btree && unlikely(c->opts.no_data_io)) {
				bio_endio(&n->bio);
				continue;
			}

			submit_bio(&n->bio);
		} else {
			n->bio.bi_status	= BLK_STS_REMOVED;
			bio_endio(&n->bio);
		}
	}
}

static void __bch2_write(struct bch_write_op *);

static void bch2_write_done(struct closure *cl)
{
	struct bch_write_op *op = container_of(cl, struct bch_write_op, cl);
	struct bch_fs *c = op->c;

	EBUG_ON(op->open_buckets.nr);

	bch2_time_stats_update(&c->times[BCH_TIME_data_write], op->start_time);
	bch2_disk_reservation_put(c, &op->res);

	if (!(op->flags & BCH_WRITE_move))
		enumerated_ref_put(&c->writes, BCH_WRITE_REF_write);
	bch2_keylist_free(&op->insert_keys, op->inline_keys);

	EBUG_ON(cl->parent);
	closure_debug_destroy(cl);
	async_object_list_del(c, write_op, op->list_idx);
	if (op->end_io)
		op->end_io(op);
}

static noinline int bch2_write_drop_io_error_ptrs(struct bch_write_op *op)
{
	struct bch_fs *c = op->c;
	struct keylist *keys = &op->insert_keys;
	struct bkey_i *src, *dst = keys->keys, *n;

	for (src = keys->keys; src != keys->top; src = n) {
		n = bkey_next(src);

		if (bkey_extent_is_direct_data(&src->k)) {
			bch2_bkey_drop_ptrs_noerror(bkey_i_to_s(src), p, entry,
				bch2_dev_io_failures(&op->wbio.failed, p.ptr.dev));

			if (!bch2_bkey_nr_dirty_ptrs(c, bkey_i_to_s_c(src)))
				return bch_err_throw(c, data_write_io);
		}

		if (dst != src)
			memmove_u64s_down(dst, src, src->k.u64s);
		dst = bkey_next(dst);
	}

	keys->top = dst;
	return 0;
}

/**
 * __bch2_write_index - after a write, update index to point to new data
 * @op:		bch_write_op to process
 */
static void __bch2_write_index(struct bch_write_op *op)
{
	struct bch_fs *c = op->c;
	struct keylist *keys = &op->insert_keys;
	int ret = 0;

	if (unlikely(op->io_error)) {
		ret = bch2_write_drop_io_error_ptrs(op);

		CLASS(bch_log_msg, msg)(c);

		/* Separate ratelimit_states for hard and soft errors */
		msg.m.suppress = !ret
			? bch2_ratelimit(c)
			: bch2_ratelimit(c);

		struct bkey_i *k = bch2_keylist_front(&op->insert_keys);
		bch2_log_write_error_start(&msg.m, false, op, bkey_start_offset(&k->k));
		bch2_io_failures_to_text(&msg.m, c, &op->wbio.failed);

		if (!ret) {
			prt_printf(&msg.m, "wrote degraded to ");
			struct bch_devs_list d = bch2_bkey_devs(c, bkey_i_to_s_c(k));
			bch2_devs_list_to_text(&msg.m, c, &d);
			prt_newline(&msg.m);
		} else {
			prt_printf(&msg.m, "error %s\n", bch2_err_str(ret));
		}

		if (ret)
			goto err;
	}

	if (!bch2_keylist_empty(keys)) {
		u64 sectors_start = keylist_sectors(keys);

		ret = !(op->flags & BCH_WRITE_move)
			? bch2_write_index_default(op)
			: bch2_data_update_index_update(op);

		BUG_ON(bch2_err_matches(ret, BCH_ERR_transaction_restart));
		BUG_ON(keylist_sectors(keys) && !ret);

		op->written += sectors_start - keylist_sectors(keys);

		if (unlikely(ret && !bch2_err_matches(ret, EROFS))) {
			struct bkey_i *insert = bch2_keylist_front(&op->insert_keys);

			bch2_write_op_error(op, false, bkey_start_offset(&insert->k),
					    "btree update error: %s", bch2_err_str(ret));
		}

		if (ret)
			goto err;
	}
out:
	/* If some a bucket wasn't written, we can't erasure code it: */
	darray_for_each(op->wbio.failed, i)
		bch2_open_bucket_write_error(c, &op->open_buckets, i->dev,
					     i->errcode ?: -BCH_ERR_data_write_io);

	bch2_open_buckets_put(c, &op->open_buckets);
	return;
err:
	keys->top = keys->keys;
	op->error = ret;
	op->flags |= BCH_WRITE_submitted;
	goto out;
}

static inline void __wp_update_state(struct write_point *wp, enum write_point_state state)
{
	if (state != wp->state) {
		struct task_struct *p = current;
		u64 now = ktime_get_ns();
		u64 runtime = p->se.sum_exec_runtime +
			(now - p->se.exec_start);

		if (state == WRITE_POINT_runnable)
			wp->last_runtime = runtime;
		else if (wp->state == WRITE_POINT_runnable)
			wp->time[WRITE_POINT_running] += runtime - wp->last_runtime;

		if (wp->last_state_change &&
		    time_after64(now, wp->last_state_change))
			wp->time[wp->state] += now - wp->last_state_change;
		wp->state = state;
		wp->last_state_change = now;
	}
}

static inline void wp_update_state(struct write_point *wp, bool running)
{
	enum write_point_state state;

	state = running			 ? WRITE_POINT_runnable:
		!list_empty(&wp->writes) ? WRITE_POINT_waiting_io
					 : WRITE_POINT_stopped;

	__wp_update_state(wp, state);
}

static CLOSURE_CALLBACK(bch2_write_index)
{
	closure_type(op, struct bch_write_op, cl);
	struct write_point *wp = op->wp;
	struct workqueue_struct *wq = index_update_wq(op);
	unsigned long flags;

	if ((op->flags & BCH_WRITE_submitted) &&
	    (op->flags & BCH_WRITE_move))
		bch2_bio_free_pages_pool(op->c, &op->wbio.bio);

	spin_lock_irqsave(&wp->writes_lock, flags);
	if (wp->state == WRITE_POINT_waiting_io)
		__wp_update_state(wp, WRITE_POINT_waiting_work);
	list_add_tail(&op->wp_list, &wp->writes);
	spin_unlock_irqrestore (&wp->writes_lock, flags);

	queue_work(wq, &wp->index_update_work);
}

static inline void bch2_write_queue(struct bch_write_op *op, struct write_point *wp)
{
	op->wp = wp;

	if (wp->state == WRITE_POINT_stopped) {
		spin_lock_irq(&wp->writes_lock);
		__wp_update_state(wp, WRITE_POINT_waiting_io);
		spin_unlock_irq(&wp->writes_lock);
	}
}

void bch2_write_point_do_index_updates(struct work_struct *work)
{
	struct write_point *wp =
		container_of(work, struct write_point, index_update_work);
	struct bch_write_op *op;

	while (1) {
		spin_lock_irq(&wp->writes_lock);
		op = list_pop_entry(&wp->writes, struct bch_write_op, wp_list);
		wp_update_state(wp, op != NULL);
		spin_unlock_irq(&wp->writes_lock);

		if (!op)
			break;

		op->flags |= BCH_WRITE_in_worker;

		__bch2_write_index(op);

		if (!(op->flags & BCH_WRITE_submitted))
			__bch2_write(op);
		else
			bch2_write_done(&op->cl);
	}
}

static void bch2_write_endio(struct bio *bio)
{
	struct closure *cl		= bio->bi_private;
	struct bch_write_op *op		= container_of(cl, struct bch_write_op, cl);
	struct bch_write_bio *wbio	= to_wbio(bio);
	struct bch_write_bio *parent	= wbio->split ? wbio->parent : NULL;
	struct bch_fs *c		= wbio->c;
	struct bch_dev *ca		= wbio->ca;

	bch2_account_io_completion(ca, BCH_MEMBER_ERROR_write,
				   wbio->submit_time, !bio->bi_status);

	if (unlikely(bio->bi_status)) {
		guard(spinlock_irqsave)(&c->write_error_lock);
		bch2_dev_io_failures_mut(&op->wbio.failed, wbio->dev)->errcode =
			__bch2_err_throw(c, -blk_status_to_bch_err(bio->bi_status));
		op->io_error = true;
	}

	if (wbio->nocow) {
		bch2_bucket_nocow_unlock(&c->nocow_locks,
					 POS(ca->dev_idx, wbio->nocow_bucket),
					 BUCKET_NOCOW_LOCK_UPDATE);
		set_bit(wbio->dev, op->devs_need_flush->d);
	}

	if (ca)
		enumerated_ref_put(&ca->io_ref[WRITE],
				   BCH_DEV_WRITE_REF_io_write);

	if (wbio->bounce)
		bch2_bio_free_pages_pool(c, bio);

	if (wbio->put_bio)
		bio_put(bio);

	if (parent)
		bio_endio(&parent->bio);
	else
		closure_put(cl);
}

static void init_append_extent(struct bch_write_op *op,
			       struct write_point *wp,
			       struct bversion version,
			       struct bch_extent_crc_unpacked crc)
{
	struct bch_fs *c = op->c;

	op->pos.offset += crc.uncompressed_size;

	struct bkey_i_extent *e = bkey_extent_init(op->insert_keys.top);
	e->k.p		= op->pos;
	e->k.size	= crc.uncompressed_size;
	e->k.bversion	= version;

	if (crc.csum_type ||
	    crc.compression_type ||
	    crc.nonce)
		bch2_extent_crc_append(c, &e->k_i, crc);

	bch2_alloc_sectors_append_ptrs_inlined(op->c, wp, &e->k_i, crc.compressed_size,
				       op->flags & BCH_WRITE_cached);
	bch2_keylist_push(&op->insert_keys);
}

static struct bio *bch2_write_bio_alloc(struct bch_fs *c,
					struct write_point *wp,
					struct bio *src,
					bool *page_alloc_failed,
					void *buf)
{
	struct bch_write_bio *wbio;
	struct bio *bio;
	unsigned output_available =
		min(wp->sectors_free << 9, src->bi_iter.bi_size);

	/*
	 * XXX: we'll want to delete this later, there's no reason we can't
	 * issue > 2MB bios if we're allocating high order pages
	 *
	 * But bch2_bio_alloc_pages() BUGS() if we ask it to allocate more pages
	 * than fit in the bio, and we're using bio_alloc_bioset() which is
	 * limited to BIO_MAX_VECS
	 */
	output_available = min(output_available, BIO_MAX_VECS * PAGE_SIZE);

	BUG_ON(output_available & (c->opts.block_size - 1));

	unsigned pages = DIV_ROUND_UP(output_available +
				      (buf
				       ? ((unsigned long) buf & (PAGE_SIZE - 1))
				       : 0), PAGE_SIZE);

	pages = min(pages, BIO_MAX_VECS);

	bio = bio_alloc_bioset(NULL, pages, 0, GFP_NOFS, &c->bio_write);
	wbio			= wbio_init(bio);
	wbio->put_bio		= true;
	/* copy WRITE_SYNC flag */
	wbio->bio.bi_opf	= src->bi_opf;

	if (buf) {
		bch2_bio_map(bio, buf, output_available);
		return bio;
	}

	wbio->bounce = true;


	/*
	 * We can't use mempool for more than c->sb.encoded_extent_max
	 * worth of pages, but we'd like to allocate more if we can:
	 */
	bch2_bio_alloc_pages(bio,
			     c->opts.block_size,
			     output_available,
			     GFP_NOFS);

	unsigned required = min(output_available, c->opts.encoded_extent_max);

	if (unlikely(bio->bi_iter.bi_size < required))
		__bch2_bio_alloc_pages_pool(c, bio, c->opts.block_size, required);

	return bio;
}

static int bch2_write_rechecksum(struct bch_fs *c,
				 struct bch_write_op *op,
				 unsigned new_csum_type)
{
	struct bio *bio = &op->wbio.bio;
	struct bch_extent_crc_unpacked new_crc;

	/* bch2_rechecksum_bio() can't encrypt or decrypt data: */

	if (bch2_csum_type_is_encryption(op->crc.csum_type) !=
	    bch2_csum_type_is_encryption(new_csum_type))
		new_csum_type = op->crc.csum_type;

	try(bch2_rechecksum_bio(c, bio, op->version, op->crc,
				NULL, &new_crc,
				op->crc.offset, op->crc.live_size,
				new_csum_type));

	bio_advance(bio, op->crc.offset << 9);
	bio->bi_iter.bi_size = op->crc.live_size << 9;
	op->crc = new_crc;
	return 0;
}

static noinline int bch2_write_prep_encoded_data(struct bch_write_op *op, struct write_point *wp)
{
	struct bch_fs *c = op->c;
	struct bio *bio = &op->wbio.bio;
	struct bch_csum csum;

	BUG_ON(bio_sectors(bio) != op->crc.compressed_size);

	/* Can we just write the entire extent as is? */
	if (op->crc.uncompressed_size == op->crc.live_size &&
	    op->crc.uncompressed_size <= c->opts.encoded_extent_max >> 9 &&
	    op->crc.compressed_size <= wp->sectors_free &&
	    (bch2_csum_type_is_encryption(op->crc.csum_type) ==
	     bch2_csum_type_is_encryption(op->csum_type)) &&
	    (op->crc.compression_type == bch2_compression_opt_to_type(op->compression_opt) ||
	     op->incompressible)) {
		if (!crc_is_compressed(op->crc) &&
		    op->csum_type != op->crc.csum_type)
			try(bch2_write_rechecksum(c, op, op->csum_type));

		return 1;
	}

	/*
	 * If the data is compressed and we couldn't write the entire extent as
	 * is, we have to decompress it:
	 */
	if (crc_is_compressed(op->crc)) {
		/* Last point we can still verify checksum: */
		struct nonce nonce = extent_nonce(op->version, op->crc);
		csum = bch2_checksum_bio(c, op->crc.csum_type, nonce, bio);
		if (bch2_crc_cmp(op->crc.csum, csum) && !c->opts.no_data_io)
			goto csum_err;

		if (bch2_csum_type_is_encryption(op->crc.csum_type)) {
			try(bch2_encrypt_bio(c, op->crc.csum_type, nonce, bio));

			op->crc.csum_type = 0;
			op->crc.csum = (struct bch_csum) { 0, 0 };
		}

		try(bch2_bio_uncompress_inplace(op, bio));
	}

	/*
	 * No longer have compressed data after this point - data might be
	 * encrypted:
	 */

	/*
	 * If the data is checksummed and we're only writing a subset,
	 * rechecksum and adjust bio to point to currently live data:
	 */
	if (op->crc.live_size != op->crc.uncompressed_size ||
	    op->crc.csum_type != op->csum_type)
		try(bch2_write_rechecksum(c, op, op->csum_type));

	/*
	 * If we want to compress the data, it has to be decrypted:
	 */
	if (bch2_csum_type_is_encryption(op->crc.csum_type) &&
	    (op->compression_opt || op->crc.csum_type != op->csum_type)) {
		struct nonce nonce = extent_nonce(op->version, op->crc);
		csum = bch2_checksum_bio(c, op->crc.csum_type, nonce, bio);
		if (bch2_crc_cmp(op->crc.csum, csum) && !c->opts.no_data_io)
			goto csum_err;

		try(bch2_encrypt_bio(c, op->crc.csum_type, nonce, bio));

		op->crc.csum_type = 0;
		op->crc.csum = (struct bch_csum) { 0, 0 };
	}

	return 0;
csum_err:
	bch2_write_op_error(op, false, op->pos.offset,
		"error verifying existing checksum while moving existing data (memory corruption?)\n"
		"  expected %0llx:%0llx got %0llx:%0llx type %s",
		op->crc.csum.hi,
		op->crc.csum.lo,
		csum.hi,
		csum.lo,
		op->crc.csum_type < BCH_CSUM_NR
		? __bch2_csum_types[op->crc.csum_type]
		: "(unknown)");
	return bch_err_throw(c, data_write_csum);
}

static int bch2_write_extent(struct bch_write_op *op, struct write_point *wp,
			     struct bio **_dst)
{
	struct bch_fs *c = op->c;
	struct bio *src = &op->wbio.bio, *dst = src;
	struct bvec_iter saved_iter;
	void *ec_buf;
	unsigned total_output = 0, total_input = 0;
	bool bounce = false;
	bool page_alloc_failed = false;
	int ret, more = 0;

	if (op->incompressible)
		op->compression_opt = 0;

	BUG_ON(!bio_sectors(src));

	ec_buf = bch2_writepoint_ec_buf(c, wp);

	if (unlikely(op->flags & BCH_WRITE_data_encoded)) {
		ret = bch2_write_prep_encoded_data(op, wp);
		if (ret < 0)
			goto err;
		if (ret) {
			BUG_ON(ret != 1);
			if (ec_buf) {
				dst = bch2_write_bio_alloc(c, wp, src,
							   &page_alloc_failed,
							   ec_buf);
				bio_copy_data(dst, src);
				bounce = true;
			}
			init_append_extent(op, wp, op->version, op->crc);
			goto do_write;
		}
	}

	if (ec_buf ||
	    op->compression_opt ||
	    (op->csum_type &&
	     !(op->flags & BCH_WRITE_pages_stable)) ||
	    (bch2_csum_type_is_encryption(op->csum_type) &&
	     !(op->flags & BCH_WRITE_pages_owned))) {
		dst = bch2_write_bio_alloc(c, wp, src,
					   &page_alloc_failed,
					   ec_buf);
		bounce = true;
	}

#ifdef CONFIG_BCACHEFS_DEBUG
	unsigned write_corrupt_ratio = READ_ONCE(bch2_write_corrupt_ratio);
	if (!bounce && write_corrupt_ratio) {
		dst = bch2_write_bio_alloc(c, wp, src,
					   &page_alloc_failed,
					   ec_buf);
		bounce = true;
	}
#endif
	saved_iter = dst->bi_iter;

	do {
		struct bch_extent_crc_unpacked crc = { 0 };
		struct bversion version = op->version;
		size_t dst_len = 0, src_len = 0;

		BUG_ON(src->bi_iter.bi_size & (block_bytes(c) - 1));

		if (page_alloc_failed &&
		    dst->bi_iter.bi_size  < (wp->sectors_free << 9) &&
		    dst->bi_iter.bi_size < c->opts.encoded_extent_max)
			break;

		BUG_ON(op->compression_opt &&
		       (op->flags & BCH_WRITE_data_encoded) &&
		       bch2_csum_type_is_encryption(op->crc.csum_type));
		BUG_ON(op->compression_opt && !bounce);

		crc.compression_type = op->incompressible
			? BCH_COMPRESSION_TYPE_incompressible
			: op->compression_opt
			? bch2_bio_compress(c, dst, &dst_len, src, &src_len,
					    op->compression_opt,
					    op->pos, !(op->flags & BCH_WRITE_pages_stable))
			: 0;
		if (!crc_is_compressed(crc)) {
			dst_len = min(dst->bi_iter.bi_size, src->bi_iter.bi_size);
			dst_len = min_t(unsigned, dst_len, wp->sectors_free << 9);

			if (op->csum_type)
				dst_len = min_t(unsigned, dst_len,
						c->opts.encoded_extent_max);

			if (bounce) {
				swap(dst->bi_iter.bi_size, dst_len);
				bio_copy_data(dst, src);
				swap(dst->bi_iter.bi_size, dst_len);
			}

			src_len = dst_len;
		}

		BUG_ON(!src_len || !dst_len);

		if (bch2_csum_type_is_encryption(op->csum_type)) {
			if (bversion_zero(version)) {
				version.lo = atomic64_inc_return(&c->key_version);
			} else {
				crc.nonce = op->nonce;
				op->nonce += src_len >> 9;
			}
		}

		if ((op->flags & BCH_WRITE_data_encoded) &&
		    !crc_is_compressed(crc) &&
		    bch2_csum_type_is_encryption(op->crc.csum_type) ==
		    bch2_csum_type_is_encryption(op->csum_type)) {
			u8 compression_type = crc.compression_type;
			u16 nonce = crc.nonce;
			/*
			 * Note: when we're using rechecksum(), we need to be
			 * checksumming @src because it has all the data our
			 * existing checksum covers - if we bounced (because we
			 * were trying to compress), @dst will only have the
			 * part of the data the new checksum will cover.
			 *
			 * But normally we want to be checksumming post bounce,
			 * because part of the reason for bouncing is so the
			 * data can't be modified (by userspace) while it's in
			 * flight.
			 */
			ret = bch2_rechecksum_bio(c, src, version, op->crc,
					&crc, &op->crc,
					src_len >> 9,
					bio_sectors(src) - (src_len >> 9),
					op->csum_type);
			if (ret)
				goto err;
			/*
			 * rchecksum_bio sets compression_type on crc from op->crc,
			 * this isn't always correct as sometimes we're changing
			 * an extent from uncompressed to incompressible.
			 */
			crc.compression_type = compression_type;
			crc.nonce = nonce;
		} else {
			if ((op->flags & BCH_WRITE_data_encoded) &&
			    (ret = bch2_rechecksum_bio(c, src, version, op->crc,
					NULL, &op->crc,
					src_len >> 9,
					bio_sectors(src) - (src_len >> 9),
					op->crc.csum_type)))
				goto err;

			crc.compressed_size	= dst_len >> 9;
			crc.uncompressed_size	= src_len >> 9;
			crc.live_size		= src_len >> 9;

			swap(dst->bi_iter.bi_size, dst_len);
			ret = bch2_encrypt_bio(c, op->csum_type,
					       extent_nonce(version, crc), dst);
			if (ret)
				goto err;

			crc.csum = bch2_checksum_bio(c, op->csum_type,
					 extent_nonce(version, crc), dst);
			crc.csum_type = op->csum_type;
			swap(dst->bi_iter.bi_size, dst_len);
		}

		init_append_extent(op, wp, version, crc);

#ifdef CONFIG_BCACHEFS_DEBUG
		if (write_corrupt_ratio) {
			swap(dst->bi_iter.bi_size, dst_len);
			bch2_maybe_corrupt_bio(dst, write_corrupt_ratio);
			swap(dst->bi_iter.bi_size, dst_len);
		}
#endif

		if (dst != src)
			bio_advance(dst, dst_len);
		bio_advance(src, src_len);
		total_output	+= dst_len;
		total_input	+= src_len;
	} while (dst->bi_iter.bi_size &&
		 src->bi_iter.bi_size &&
		 wp->sectors_free &&
		 !bch2_keylist_realloc(&op->insert_keys,
				      op->inline_keys,
				      ARRAY_SIZE(op->inline_keys),
				      BKEY_EXTENT_U64s_MAX));

	more = src->bi_iter.bi_size != 0;

	dst->bi_iter = saved_iter;

	if (dst == src && more) {
		BUG_ON(total_output != total_input);

		dst = bio_split(src, total_input >> 9,
				GFP_NOFS, &c->bio_write);
		wbio_init(dst)->put_bio	= true;
		/* copy WRITE_SYNC flag */
		dst->bi_opf		= src->bi_opf;
	}

	dst->bi_iter.bi_size = total_output;
do_write:
	*_dst = dst;
	return more;
err:
	if (to_wbio(dst)->bounce)
		bch2_bio_free_pages_pool(c, dst);
	if (to_wbio(dst)->put_bio)
		bio_put(dst);

	return ret;
}

static bool bch2_extent_is_writeable(struct bch_write_op *op,
				     struct bkey_s_c k)
{
	struct bch_fs *c = op->c;
	struct bkey_s_c_extent e;
	struct extent_ptr_decoded p;
	const union bch_extent_entry *entry;
	unsigned replicas = 0;

	if (k.k->type != KEY_TYPE_extent)
		return false;

	e = bkey_s_c_to_extent(k);

	guard(rcu)();
	extent_for_each_ptr_decode(e, p, entry) {
		if (crc_is_encoded(p.crc) || p.has_ec)
			return false;

		replicas += !p.ptr.cached
			? bch2_dev_durability(c, p.ptr.dev)
			: 0;
	}

	return replicas >= op->opts.data_replicas;
}

static int bch2_nocow_write_convert_one_unwritten(struct btree_trans *trans,
						  struct btree_iter *iter,
						  struct bch_write_op *op,
						  struct bkey_i *orig,
						  struct bkey_s_c k,
						  u64 new_i_size)
{
	struct bch_fs *c = trans->c;

	if (!bch2_extents_match(c, bkey_i_to_s_c(orig), k)) {
		/* trace this */
		return 0;
	}

	/*
	 * If we did a degraded write, bch2_bkey_set_needs_reconcile() will add
	 * pointers to BCH_SB_MEMBER_INVALID so the extent is accounted as
	 * degraded
	 */
	unsigned new_buf_u64s = k.k->u64s + 1 + BCH_REPLICAS_MAX;
	struct bkey_i *new = errptr_try(bch2_trans_kmalloc_nomemzero(trans,
				new_buf_u64s * sizeof(u64)));

	bkey_reassemble(new, k);
	bch2_cut_front(c, bkey_start_pos(&orig->k), new);
	bch2_cut_back(orig->k.p, new);

	struct bkey_ptrs ptrs = bch2_bkey_ptrs(bkey_i_to_s(new));
	bkey_for_each_ptr(ptrs, ptr)
		ptr->unwritten = 0;

	/*
	 * Note that we're not calling bch2_subvol_get_snapshot() in this path -
	 * that was done when we kicked off the write, and here it's important
	 * that we update the extent that we wrote to - even if a snapshot has
	 * since been created. The write is still outstanding, so we're ok
	 * w.r.t. snapshot atomicity:
	 */
	struct bch_inode_unpacked inode;
	struct bch_inode_opts opts;

	return  bch2_extent_update_i_size_sectors(trans, iter,
					min(new->k.p.offset << 9, new_i_size), 0, &inode) ?:
		(bch2_inode_opts_get_inode(c, &inode, &opts),
		 bch2_bkey_set_needs_reconcile(trans, NULL, &opts, bkey_i_to_s(new),
					       new_buf_u64s,
					       SET_NEEDS_RECONCILE_foreground,
					       op->opts.change_cookie)) ?:
		bch2_trans_update(trans, iter, new,
				  BTREE_UPDATE_internal_snapshot_node|
				  BTREE_TRIGGER_set_needs_reconcile_done);
}

static void bch2_nocow_write_convert_unwritten(struct bch_write_op *op)
{
	struct bch_fs *c = op->c;
	int ret = 0;

	{
		CLASS(btree_trans, trans)(c);

		for_each_keylist_key(&op->insert_keys, orig) {
			ret = for_each_btree_key_max_commit(trans, iter, BTREE_ID_extents,
					     bkey_start_pos(&orig->k), orig->k.p,
					     BTREE_ITER_intent, k,
					     &op->res, NULL,
					     BCH_TRANS_COMMIT_no_enospc, ({
				bch2_nocow_write_convert_one_unwritten(trans, &iter, op, orig, k, op->new_i_size);
			}));
			if (ret)
				break;
		}
	}

	if (ret && !bch2_err_matches(ret, EROFS)) {
		struct bkey_i *insert = bch2_keylist_front(&op->insert_keys);
		bch2_write_op_error(op, false, bkey_start_offset(&insert->k),
				    "btree update error: %s", bch2_err_str(ret));
	}

	if (ret)
		op->error = ret;
}

static void __bch2_nocow_write_done(struct bch_write_op *op)
{
	if (unlikely(op->io_error)) {
		op->error = bch_err_throw(op->c, data_write_io);
	} else if (unlikely(op->flags & BCH_WRITE_convert_unwritten))
		bch2_nocow_write_convert_unwritten(op);
}

static CLOSURE_CALLBACK(bch2_nocow_write_done)
{
	closure_type(op, struct bch_write_op, cl);

	__bch2_nocow_write_done(op);
	bch2_write_done(cl);
}

/*
 * Take an io_ref per ptr, populating @cas (parallel to @ptrs) and
 * returning the number of refs taken on success.  On partial failure,
 * walks back through cas[] to drop the refs taken so far — never
 * re-derives ca via c->devs[idx], which dev_remove may have cleared
 * while our io_ref still pins the dev.
 */
static int bkey_get_dev_iorefs(struct bch_fs *c, struct bkey_ptrs_c ptrs,
			       struct bch_dev **cas)
{
	unsigned i = 0;
	bkey_for_each_ptr(ptrs, ptr) {
		cas[i] = bch2_dev_get_ioref(c, ptr->dev, WRITE,
					    BCH_DEV_WRITE_REF_io_write);
		if (unlikely(!cas[i])) {
			while (i--)
				enumerated_ref_put(&cas[i]->io_ref[WRITE],
						   BCH_DEV_WRITE_REF_io_write);
			return -1;
		}
		i++;
	}

	return i;
}

static int bch2_inode_get_i_size(struct btree_trans *trans, struct bpos inode_pos, u64 *i_size)
{
	CLASS(btree_iter, iter)(trans, BTREE_ID_inodes, inode_pos, BTREE_ITER_cached);
	struct bkey_s_c k = bkey_try(bch2_btree_iter_peek_slot(&iter));

	if (likely(k.k->type == KEY_TYPE_inode_v3)) {
		*i_size = le64_to_cpu(bkey_s_c_to_inode_v3(k).v->bi_size);
	} else {
		struct bch_inode_unpacked inode_u;
		bch2_inode_unpack(k, &inode_u);
		*i_size = inode_u.bi_size;
	}

	return 0;
}

/* returns false if fallaback to cow write path required */
static bool bch2_nocow_write(struct bch_write_op *op)
{
	struct bch_fs *c = op->c;
	struct btree_trans *trans;
	struct btree_iter iter = {};
	struct bkey_s_c k;
	struct bkey_ptrs_c ptrs;
	u32 snapshot;
	const struct bch_extent_ptr *stale_at;
	int stale, ret;
	struct bch_dev *cas[BCH_BKEY_PTRS_MAX];
	int nr_cas = 0;

	if (op->flags & BCH_WRITE_move)
		return false;

	op->flags &= ~BCH_WRITE_convert_unwritten;

	trans = bch2_trans_get(c);
retry:
	bch2_trans_begin(trans);

	ret = bch2_subvolume_get_snapshot(trans, op->subvol, &snapshot);
	if (unlikely(ret))
		goto err;

	u64 i_size;
	ret = bch2_inode_get_i_size(trans, SPOS(0, op->pos.inode, snapshot), &i_size);
	if (unlikely(ret))
		goto err;

	if (op->new_i_size > i_size)
		op->flags |= BCH_WRITE_convert_unwritten;

	bch2_trans_iter_init(trans, &iter, BTREE_ID_extents,
			     SPOS(op->pos.inode, op->pos.offset, snapshot),
			     BTREE_ITER_slots);
	while (1) {
		struct bio *bio = &op->wbio.bio;

		ret = bch2_trans_relock(trans);
		if (ret)
			break;

		bch2_btree_iter_set_pos(&iter, SPOS(op->pos.inode, op->pos.offset, snapshot));
		k = bch2_btree_iter_peek_slot(&iter);
		ret = bkey_err(k);
		if (ret)
			break;

		/* fall back to normal cow write path? */
		if (unlikely(k.k->p.snapshot != snapshot ||
			     !bch2_extent_is_writeable(op, k)))
			break;

		/*
		 * Extent end may not be block-aligned (e.g. after
		 * truncate). Can't split a nocow bio at a non-aligned
		 * point — fall back to COW which allocates new blocks.
		 */
		if (k.k->p.offset < op->pos.offset + bio_sectors(bio) &&
		    (k.k->p.offset - op->pos.offset) & (block_sectors(c) - 1))
			break;

		if (bch2_keylist_realloc(&op->insert_keys,
					 op->inline_keys,
					 ARRAY_SIZE(op->inline_keys),
					 k.k->u64s))
			break;

		/* Get iorefs before dropping btree locks: */
		ptrs = bch2_bkey_ptrs_c(k);
		nr_cas = bkey_get_dev_iorefs(c, ptrs, cas);
		if (nr_cas < 0)
			goto out;

		/* Unlock before taking nocow locks, doing IO: */
		bkey_reassemble(op->insert_keys.top, k);
		k = bkey_i_to_s_c(op->insert_keys.top);
		ptrs = bch2_bkey_ptrs_c(k);

		bch2_trans_unlock(trans);

		bch2_bkey_nocow_lock(c, ptrs, cas, BUCKET_NOCOW_LOCK_UPDATE);

		/*
		 * This could be handled better: If we're able to trylock the
		 * nocow locks with btree locks held we know dirty pointers
		 * can't be stale
		 */
		{
			unsigned i = 0;
			bkey_for_each_ptr(ptrs, ptr) {
				struct bch_dev *ca = cas[i++];

				int gen = bucket_gen_get(ca, PTR_BUCKET_NR(ca, ptr));
				stale = gen < 0 ? gen : gen_after(gen, ptr->gen);
				if (unlikely(stale)) {
					stale_at = ptr;
					goto err_bucket_stale;
				}

				if (ptr->unwritten)
					op->flags |= BCH_WRITE_convert_unwritten;
			}
		}

		bch2_cut_front(c, op->pos, op->insert_keys.top);
		bch2_cut_back(POS(op->pos.inode, op->pos.offset + bio_sectors(bio)), op->insert_keys.top);

		bio = &op->wbio.bio;
		if (k.k->p.offset < op->pos.offset + bio_sectors(bio)) {
			bio = bio_split(bio, k.k->p.offset - op->pos.offset,
					GFP_KERNEL, &c->bio_write);
			wbio_init(bio)->put_bio = true;
			bio->bi_opf = op->wbio.bio.bi_opf;
		} else {
			op->flags |= BCH_WRITE_submitted;
		}

		op->pos.offset += bio_sectors(bio);
		op->written += bio_sectors(bio);

		bio->bi_end_io	= bch2_write_endio;
		bio->bi_private	= &op->cl;
		bio->bi_opf |= REQ_OP_WRITE;
		closure_get(&op->cl);

		bch2_submit_wbio_replicas(to_wbio(bio), c, BCH_DATA_user,
					  op->insert_keys.top, true, cas);

		if (op->flags & BCH_WRITE_convert_unwritten)
			bch2_keylist_push(&op->insert_keys);
		if (op->flags & BCH_WRITE_submitted)
			break;
	}
out:
	bch2_trans_iter_exit(&iter);
err:
	if (bch2_err_matches(ret, BCH_ERR_transaction_restart))
		goto retry;

	bch2_trans_put(trans);
	if (ret) {
		bch2_write_op_error(op, false, op->pos.offset,
				    "%s(): btree lookup error: %s", __func__, bch2_err_str(ret));
		op->error = ret;
		op->flags |= BCH_WRITE_submitted;
	}

	bool submitted = op->flags & BCH_WRITE_submitted;
	if (!submitted) {
		/* fallback to cow write path */
		closure_sync(&op->cl);
		__bch2_nocow_write_done(op);
		op->insert_keys.top = op->insert_keys.keys;
	} else if (op->flags & BCH_WRITE_sync) {
		closure_sync(&op->cl);
		bch2_nocow_write_done(&op->cl.work);
	} else {
		/*
		 * XXX
		 * needs to run out of process context because ei_quota_lock is
		 * a mutex
		 */
		continue_at(&op->cl, bch2_nocow_write_done, index_update_wq(op));
	}
	return submitted;
err_bucket_stale:
	{
		CLASS(printbuf, buf)();
		if (bch2_fs_inconsistent_on(stale < 0, c,
					    "pointer to invalid bucket in nocow path on device %u\n  %s",
					    stale_at->dev,
					    (bch2_bkey_val_to_text(&buf, c, k), buf.buf))) {
			ret = bch_err_throw(c, data_write_invalid_ptr);
		} else {
			/* We can retry this: */
			ret = bch_err_throw(c, transaction_restart);
		}

		bch2_bkey_nocow_unlock(c, k, cas, BUCKET_NOCOW_LOCK_UPDATE);

		for (int i = 0; i < nr_cas; i++)
			enumerated_ref_put(&cas[i]->io_ref[WRITE],
					   BCH_DEV_WRITE_REF_io_write);
	}

	/* Fall back to COW path: */
	goto out;
}

static void __bch2_write(struct bch_write_op *op)
{
	struct bch_fs *c = op->c;
	struct write_point *wp = NULL;
	struct bio *bio = NULL;
	int ret;

	/*
	 * Sync or no?
	 *
	 * If we're running asynchronously, wne may still want to block
	 * synchronously here if we weren't able to submit all of the IO at
	 * once, as that signals backpressure to the caller.
	 */
	bool wait_on_allocator_sync = (op->flags & BCH_WRITE_sync) ||
		(!(op->flags & BCH_WRITE_submitted) &&
		 !(op->flags & BCH_WRITE_in_worker));

	guard(memalloc_flags)(PF_MEMALLOC_NOFS);

	if (unlikely(op->opts.nocow &&
		     c->opts.nocow_enabled) &&
	    bch2_nocow_write(op))
		return;
again:
	op->wbio.failed.nr = 0;

	do {
		struct bkey_i *key_to_write;
		unsigned key_to_write_offset = op->insert_keys.top_p -
			op->insert_keys.keys_p;

		/* +1 for possible cache device: */
		if (op->open_buckets.nr + op->nr_replicas + 1 >
		    ARRAY_SIZE(op->open_buckets.v))
			break;

		if (bch2_keylist_realloc(&op->insert_keys,
					op->inline_keys,
					ARRAY_SIZE(op->inline_keys),
					BKEY_EXTENT_U64s_MAX))
			break;

		CLASS(btree_trans, trans)(c);
		bool io_in_flight = op->open_buckets.nr;

		ret = lockrestart_do(trans, ({
			struct alloc_request *req __free(alloc_request_put) =
				alloc_request_get(trans,
						  op->target,
						  op->opts.erasure_code && !(op->flags & BCH_WRITE_cached),
						  &op->devs_have,
						  op->nr_replicas,
						  op->opts.data_replicas,
						  op->watermark,
						  op->flags,
						  !io_in_flight ? &op->cl : NULL);
			if (!IS_ERR(req))
				req->ec_max_data_blocks = c->opts.ec_max_data_blocks;
			int ret2 = PTR_ERR_OR_ZERO(req) ?:
			bch2_alloc_sectors_req(trans, req, op->write_point, &wp);

			if (bch2_err_matches(ret2, BCH_ERR_operation_blocked)) {
				if (!wait_on_allocator_sync)
					break;

				bch2_wait_on_allocator(trans, c, req, ret2, &op->cl);
				__bch2_write_index(op);
				op->wbio.failed.nr = 0;
				ret2 = bch_err_throw(c, transaction_restart_nested);
			}
			ret2;
		}));
		bch2_trans_unlock_long(trans);
		if (ret && io_in_flight)
			break;

		if (bch2_err_matches(ret, BCH_ERR_operation_blocked))
			break;

		if (unlikely(ret))
			goto err;

		EBUG_ON(!wp);

		bch2_open_bucket_get(c, wp, &op->open_buckets);
		ret = bch2_write_extent(op, wp, &bio);

		bch2_alloc_sectors_done_inlined(c, wp);
err:
		if (ret <= 0) {
			op->flags |= BCH_WRITE_submitted;

			if (unlikely(ret < 0)) {
				op->error = ret;

				/* Extra info on errors from the allocator: */
				if (!(op->flags & BCH_WRITE_move))
					bch2_write_op_error(op, true, op->pos.offset,
							    "%s(): %s", __func__, bch2_err_str(ret));
				break;
			}
		}

		bio->bi_end_io	= bch2_write_endio;
		bio->bi_private	= &op->cl;
		bio->bi_opf |= REQ_OP_WRITE;

		closure_get(bio->bi_private);

		key_to_write = (void *) (op->insert_keys.keys_p +
					 key_to_write_offset);

		bch2_submit_wbio_replicas(to_wbio(bio), c, BCH_DATA_user,
					  key_to_write, false, NULL);
	} while (ret);

	if (op->flags & BCH_WRITE_sync) {
		closure_sync(&op->cl);

		__bch2_write_index(op);

		if (!(op->flags & BCH_WRITE_submitted))
			goto again;
		bch2_write_done(&op->cl);
	} else {
		bch2_write_queue(op, wp);
		continue_at(&op->cl, bch2_write_index, NULL);
	}
}

static void bch2_write_data_inline(struct bch_write_op *op, unsigned data_len)
{
	struct bio *bio = &op->wbio.bio;
	struct bvec_iter iter;
	struct bkey_i_inline_data *id;
	unsigned sectors;
	int ret;

	op->wbio.failed.nr = 0;

	op->flags |= BCH_WRITE_wrote_data_inline;
	op->flags |= BCH_WRITE_submitted;

	bch2_check_set_feature(op->c, BCH_FEATURE_inline_data);

	ret = bch2_keylist_realloc(&op->insert_keys, op->inline_keys,
				   ARRAY_SIZE(op->inline_keys),
				   BKEY_U64s + DIV_ROUND_UP(data_len, 8));
	if (ret) {
		op->error = ret;
		goto err;
	}

	sectors = bio_sectors(bio);
	op->pos.offset += sectors;

	id = bkey_inline_data_init(op->insert_keys.top);
	id->k.p		= op->pos;
	id->k.bversion	= op->version;
	id->k.size	= sectors;

	iter = bio->bi_iter;
	iter.bi_size = data_len;
	memcpy_from_bio(id->v.data, bio, iter);

	while (data_len & 7)
		id->v.data[data_len++] = '\0';
	set_bkey_val_bytes(&id->k, data_len);
	bch2_keylist_push(&op->insert_keys);

	__bch2_write_index(op);
err:
	bch2_write_done(&op->cl);
}

/**
 * bch2_write() - handle a write to a cache device or flash only volume
 * @cl:		&bch_write_op->cl
 *
 * This is the starting point for any data to end up in a cache device; it could
 * be from a normal write, or a writeback write, or a write to a flash only
 * volume - it's also used by the moving garbage collector to compact data in
 * mostly empty buckets.
 *
 * It first writes the data to the cache, creating a list of keys to be inserted
 * (if the data won't fit in a single open bucket, there will be multiple keys);
 * after the data is written it calls bch_journal, and after the keys have been
 * added to the next journal write they're inserted into the btree.
 *
 * If op->discard is true, instead of inserting the data it invalidates the
 * region of the cache represented by op->bio and op->inode.
 */
CLOSURE_CALLBACK(bch2_write)
{
	closure_type(op, struct bch_write_op, cl);
	struct bio *bio = &op->wbio.bio;
	struct bch_fs *c = op->c;
	unsigned data_len;

	if (!(op->flags & BCH_WRITE_move))
		event_add_trace(c, data_write, bio_sectors(bio), buf,
				bch2_write_op_to_text(&buf, op));
	else
		event_add_trace(c, data_update_write, bio_sectors(bio), buf,
				bch2_write_op_to_text(&buf, op));

	EBUG_ON(op->cl.parent);
	BUG_ON(!op->nr_replicas);
	BUG_ON(!op->write_point.v);
	BUG_ON(bkey_eq(op->pos, POS_MAX));

	async_object_list_add(c, write_op, op, &op->list_idx);

	if (op->flags & BCH_WRITE_only_specified_devs)
		op->flags |= BCH_WRITE_alloc_nowait;

	op->start_time = local_clock();
	bch2_keylist_init(&op->insert_keys, op->inline_keys);
	wbio_init(bio)->put_bio = false;

	if (unlikely(bio->bi_iter.bi_size & (c->opts.block_size - 1))) {
		bch2_write_op_error(op, false, op->pos.offset, "misaligned write");
		op->error = bch_err_throw(c, data_write_misaligned);
		__WARN();
		goto err;
	}

	if (c->opts.nochanges) {
		op->error = bch_err_throw(c, erofs_no_writes);
		goto err;
	}

	if (!(op->flags & BCH_WRITE_move) &&
	    !enumerated_ref_tryget(&c->writes, BCH_WRITE_REF_write)) {
		op->error = bch_err_throw(c, erofs_no_writes);
		goto err;
	}

	bch2_increment_clock(c, bio_sectors(bio), WRITE);

	data_len = min_t(u64, bio->bi_iter.bi_size,
			 op->new_i_size - (op->pos.offset << 9));

	if (c->opts.inline_data &&
	    data_len <= min(block_bytes(c) / 2, 1024U)) {
		bch2_write_data_inline(op, data_len);
		return;
	}

	__bch2_write(op);
	return;
err:
	bch2_disk_reservation_put(c, &op->res);

	closure_debug_destroy(&op->cl);
	async_object_list_del(c, write_op, op->list_idx);
	if (op->end_io)
		op->end_io(op);
}

const char * const bch2_write_flags[] = {
#define x(f)	#f,
	BCH_WRITE_FLAGS()
#undef x
	NULL
};

void __bch2_write_op_to_text(struct printbuf *out, struct bch_write_op *op)
{
	if (!out->nr_tabstops)
		printbuf_tabstop_push(out, 32);

	prt_printf(out, "pos:\t");
	bch2_bpos_to_text(out, op->pos);
	prt_newline(out);
	guard(printbuf_indent)(out);

	prt_printf(out, "started:\t");
	bch2_pr_time_units(out, local_clock() - op->start_time);
	prt_newline(out);

	prt_printf(out, "flags:\t");
	prt_bitflags(out, bch2_write_flags, op->flags);
	prt_newline(out);

	prt_printf(out, "watermark:\t%s\n", bch2_watermarks[op->watermark]);

	prt_printf(out, "nr_replicas:\t%u\n", op->nr_replicas);
	prt_printf(out, "devs_have:\t");
	bch2_devs_list_to_text(out, op->c, &op->devs_have);
	prt_newline(out);

	prt_printf(out, "opts:\t");
	bch2_inode_opts_to_text(out, op->c, op->opts);
	prt_newline(out);

	prt_printf(out, "open_buckets:\t%u\n", op->open_buckets.nr);

	prt_printf(out, "ref:\t%u\n", closure_nr_remaining(&op->cl));
	prt_printf(out, "ret\t%s\n", bch2_err_str(op->error));
}

void bch2_write_op_to_text(struct printbuf *out, struct bch_write_op *op)
{
	__bch2_write_op_to_text(out, op);

	if (op->flags & BCH_WRITE_move) {
		guard(printbuf_indent)(out);
		prt_printf(out, "update:\n");
		guard(printbuf_indent)(out);
		struct data_update *u = container_of(op, struct data_update, op);
		bch2_data_update_opts_to_text(out, u->op.c, &u->op.opts, &u->opts);
		prt_newline(out);

		prt_str(out, "old key:\t");
		bch2_bkey_val_to_text(out, u->op.c, bkey_i_to_s_c(u->k.k));
		prt_newline(out);
	}
}

void bch2_fs_io_write_exit(struct bch_fs *c)
{
	bioset_exit(&c->replica_set);
	bioset_exit(&c->bio_write);
}

int bch2_fs_io_write_init(struct bch_fs *c)
{
	if (bioset_init(&c->bio_write,   1, offsetof(struct bch_write_bio, bio), BIOSET_NEED_BVECS) ||
	    bioset_init(&c->replica_set, 4, offsetof(struct bch_write_bio, bio), 0))
		return bch_err_throw(c, ENOMEM_bio_write_init);

	return 0;
}
