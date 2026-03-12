#!/bin/bash
# Prepare pre-populated disk images for the bcachefs SRCU test VM.
#
# Run this ONCE on the host (needs root for loopback mount).
# Creates vm-disks/{fast,slow,swap}-pristine.img with ~60 MB of data
# already on the SSD tier, ready for reconcile when the VM boots.
#
# Usage: sudo ./prepare-vm-disks.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_DIR="$SCRIPT_DIR/vm-disks"
MNT=$(mktemp -d)

mkdir -p "$DISK_DIR"

echo "=== Creating disk images ==="
truncate --size=256M "$DISK_DIR/fast-pristine.img"
truncate --size=256M "$DISK_DIR/slow-pristine.img"
truncate --size=512M "$DISK_DIR/swap-pristine.img"

LOOP_FAST=$(losetup --find --show "$DISK_DIR/fast-pristine.img")
LOOP_SLOW=$(losetup --find --show "$DISK_DIR/slow-pristine.img")
LOOP_SWAP=$(losetup --find --show "$DISK_DIR/swap-pristine.img")

cleanup() {
    umount "$MNT" 2>/dev/null || true
    losetup -d "$LOOP_FAST" 2>/dev/null || true
    losetup -d "$LOOP_SLOW" 2>/dev/null || true
    losetup -d "$LOOP_SWAP" 2>/dev/null || true
    rmdir "$MNT" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Formatting bcachefs (SSD=$LOOP_FAST, HDD=$LOOP_SLOW) ==="
bcachefs format \
    --label=ssd "$LOOP_FAST" \
    --label=hdd "$LOOP_SLOW" \
    --foreground_target=ssd \
    --background_target=hdd \
    --promote_target=ssd \
    --background_compression=zstd \
    --data_replicas=1 \
    --metadata_replicas=1

echo "=== Mounting bcachefs ==="
mount -t bcachefs "$LOOP_FAST:$LOOP_SLOW" "$MNT"

echo "=== Writing 60 MB to SSD tier ==="
for i in $(seq 0 5); do
    dd if=/dev/urandom of="$MNT/testfile$i" bs=1M count=10 status=none
done
sync

echo "=== Filesystem usage ==="
bcachefs fs usage "$MNT" 2>/dev/null || true

echo "=== Unmounting ==="
umount "$MNT"

echo "=== Setting up swap ==="
mkswap "$LOOP_SWAP"

echo "=== Done ==="
echo "Pristine images in $DISK_DIR/"
ls -lh "$DISK_DIR/"*.img
