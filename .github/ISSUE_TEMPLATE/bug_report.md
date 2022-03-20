---
name: Bug report
about: Create a report to help us improve
title: "<short description> [short commit id]"
labels: bug
assignees: YellowOnion

---

**Please search for duplicates**

**Version**

Make sure you're using a reasonably new version.

Provide the commit hash from the kernel version (preferable) or tools, don't say "I'm using the latest master" as that will very quickly become out of date.

**Generic info**
Provide the output of:
```
bcachefs fs usage
bcachefs show-super
```
**Tools bugs**

* pull the latest version, compile it, do not strip the binary.
* provide the exact commands you used to run.
* run with gdb: `gdb -ex run --args ./bcacehfs <arguments...>`

If you get an assert/segfault etc:
* type `bt` in to and provide the output here.

If the tools lockup:
* run `perf top -p $(pidof bcachefs)` and provide a screenshot.
* press ctrl+c to interrupt the process and provide the output of `bt`.

**Kernel bugs**
Compile the kernel with these flags:

```
CONFIG_PREEMPT=y
CONFIG_BCACHEFS_DEBUG=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_FS=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_FTRACE=y
```
Provide the output of `dmesg` either in a paste-bin or as attachment, if less than 30~ lines just provide inline here.


**Optional Advanced**

If lockup or performance issues:
* run `perf record` and `perf record -e 'bcachefs:*' -o events.data` both during the window of issue and then ctrl+c.
* run `perf archive` to dump symbols.
* archive, compress and upload the files: `perf.data`, `events.data` and `perf.data.tar.bz2`.

Upload large files to a file storage provider:
* provide the output of `bcachefs list_journal -a <list of devices> | zstd -f -T0 -o ../journal.log.zst`
*compress & upload all the `metdata.dump.*` files from: bcachefs dump -o metadata.dump <list of devices>
