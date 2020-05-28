# Bcachefs [![IRC](https://img.shields.io/badge/irc-bcache-brightgreen)](https://kiwiirc.com/nextclient/irc.oftc.net#bcache) [![reddit](https://img.shields.io/reddit/subreddit-subscribers/bcachefs?style=social)](https://www.reddit.com/r/bcachefs/) [![Donate](https://img.shields.io/badge/Donate-Patreon-green.svg)](https://www.patreon.com/bcachefs)

"The COW filesystem for Linux that won't eat your data"

## Features
Bcachefs is an advanced new filesystem for Linux, with an emphasis on reliability and robustness. It has a long list of features, completed or in progress:

- Copy on write (COW) - like zfs or btrfs
- Full data and metadata checksumming
- Multiple devices, including replication and other types of RAID
- Caching
- Compression
- Encryption
- Snapshots
- Scalable - has been tested to 50+ TB, will eventually scale far higher
- Already working and stable, with a small community of users

We prioritize robustness and reliability over features and hype: we make every effort to ensure you won't lose data. It's building on top of a codebase with a pedigree - bcache already has a reasonably good track record for reliability (particularly considering how young upstream bcache is, in terms of engineer man/years). Starting from there, bcachefs development has prioritized incremental development, and keeping things stable, and aggressively fixing design issues as they are found; the bcachefs codebase is considerably more robust and mature than upstream bcache.

Fixing bugs always take priority over features! This means getting features out takes longer, but for a filesystem not losing your data is the biggest feature.

## Founding [![Donate](https://img.shields.io/badge/Donate-Patreon-green.svg)](https://www.patreon.com/bcachefs)

Developing a filesystem is also not cheap or quick or easy; we need funding! 
Please chip in on Patreon - the [Patreon](https://www.patreon.com/bcachefs) page also has more information on the motivation for bcachefs and the state of Linux filesystems, as well as some bcachefs status updates and information on development.

## Support [![IRC](https://img.shields.io/badge/irc-bcache-brightgreen)](https://kiwiirc.com/nextclient/irc.oftc.net#bcache)

Join us in the bcache IRC channel, we have a small group of bcachefs users and testers there: #bcache on OFTC (irc.oftc.net).

## Getting started
Bcachefs is not yet upstream - you'll have to build a kernel to use it.

First, check out the bcache kernel and tools repositories:
```
git clone https://evilpiepirate.org/git/bcachefs.git
git clone https://evilpiepirate.org/git/bcachefs-tools.git
```

Build and install as usual - make sure you enable `CONFIG_BCACHE_FS`. Then, to format and mount a single device with the default options, run:
```
bcachefs format /dev/sda1
mount -t bcachefs /dev/sda1 /mnt
```

For a multi device filesystem, with sda1 caching sdb1:
```
bcachefs format /dev/sd[ab]1 \
    --foreground_target /dev/sda1 \
    --promote-target /dev/sda1 \
    --background_target /dev/sdb1
mount -t bcachefs /dev/sda1:/dev/sdb1 /mnt
```

This will configure the filesystem so that writes will be buffered to /dev/sda1 before being written back to /dev/sdb1 in the background, and that hot data will be promoted to /dev/sda1 for faster access.


See `bcachefs format --help` for more options.

## Documentation
End user documentation is currently fairly minimal; this would be a very helpful area for anyone who wishes to contribute - I would like the bcache man page in the bcachefs-tools repository to be rewritten and expanded.

## Status

Bcachefs can currently be considered beta quality. It has a small pool of outside users and has been stable for quite some time now; there's no reason to expect issues as long as you stick to the currently supported feature set. It's been passing all xfstests for well over a year, and serious bugs are rare at this point. However, given that it's still under active development backups are a good idea.


Performance is generally quite good - generally faster than btrfs, and not far behind xfs/ext4. On metadata intensive benchmarks, it's often considerably faster than xfs/ext4/btrfs.


Normal posix filesystem functionality is all finished - if you're using bcachefs as a replacement for ext4 on a desktop, you shouldn't find anything missing. For servers, NFS export support is still missing (but coming soon) and we don't yet support quotas (probably further off).


Until bcachefs goes upstream I reserve the right to change the on disk format if necessary, but I'm not expecting any more incompatible disk format changes.

### Feature status

   - Full data checksumming

     Fully supported and enabled by default; checksum errors will cause IOs to be retried if there's another replica available.

   - Compression

     Done - LZ4, gzip and ZSTD are currently supported. ZSTD support unfortunately still seems to be slightly buggy, but LZ4 is stable and well tested.

   - Multiple device support

     Done - you can add and remove devices at runtime while the filesystem is in use, migrating data off the device if necessary.

   - Tiering/writeback caching:

     Bcachefs allows you to specify disks (or groups thereof) to be used for three categories of I/O: foreground, background, and promote. Foreground devices accept writes, whose data is copied to background devices asynchronously, and the hot subset of which is copied to the promote devices for performance.

     Basic caching functionality works, but it's not (yet) as configurable as bcache's caching (e.g. you can't specify writethrough caching).

   - Replication (i.e. RAID1/10)

     Done - you can yank out a disk while a filesystem is in use and it'll keep working, transparently handling IO errors. You can then use the rereplicate command to write out another copy of all the degraded data to another device.

   - Erasure coding

     Mostly done, but not quite usable yet. We still need a stripe level compaction path.

   - Encryption

     Whole filesystem AEAD style encryption (with ChaCha20 and Poly1305) is done and merged. I would suggest not relying on it for anything critical until the code has seen more outside review, though.

   - Snapshots

     Snapshot implementation has been started, but snapshots are by far the most complex of the remaining features to implement - it's going to be quite awhile before I can dedicate enough time to finishing them, but I'm very much looking forward to showing off what it'll be able to do.
