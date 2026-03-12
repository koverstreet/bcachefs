#!/bin/bash
# Run a bcachefs SRCU lock test VM.
#
# Usage: run-vm-test.sh <label> <bzImage> [initramfs]
#
# Copies the pristine disk images, boots a 128 MB VM with throttled
# bcachefs disks and unthrottled swap, and checks for hangs.
set -euo pipefail

LABEL="${1:?usage: run-vm-test.sh <label> <bzImage> [initramfs]}"
BZIMAGE="${2:?}"
INITRAMFS="${3:-$(dirname "$0")/test-initramfs.img}"
TIMEOUT=300

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_DIR="$SCRIPT_DIR/vm-disks"
LOG="/tmp/vm-$LABEL.log"

# Verify prerequisites
for f in "$BZIMAGE" "$INITRAMFS" \
         "$DISK_DIR/fast-pristine.img" \
         "$DISK_DIR/slow-pristine.img" \
         "$DISK_DIR/swap-pristine.img"; do
    [ -f "$f" ] || { echo "missing: $f"; exit 1; }
done

# Per-run copies (so pristine images stay clean)
FAST=$(mktemp /tmp/bcachefs-fast-XXXXXX.img)
SLOW=$(mktemp /tmp/bcachefs-slow-XXXXXX.img)
SWAP=$(mktemp /tmp/bcachefs-swap-XXXXXX.img)
cp "$DISK_DIR/fast-pristine.img" "$FAST"
cp "$DISK_DIR/slow-pristine.img" "$SLOW"
cp "$DISK_DIR/swap-pristine.img" "$SWAP"
cleanup() { rm -f "$FAST" "$SLOW" "$SWAP"; }
trap cleanup EXIT

echo "[$LABEL] Starting VM (128M RAM, bcachefs throttled, swap unthrottled)..."

timeout "$TIMEOUT" \
    qemu-system-x86_64 \
        -enable-kvm \
        -m 128M \
        -smp 2 \
        -nographic \
        -no-reboot \
        -kernel "$BZIMAGE" \
        -initrd "$INITRAMFS" \
        -append "console=ttyS0 panic=1" \
        -drive file="$FAST",format=raw,if=virtio,cache=none,throttling.bps-write=524288 \
        -drive file="$SLOW",format=raw,if=virtio,cache=none,throttling.bps-write=524288 \
        -drive file="$SWAP",format=raw,if=virtio,cache=none \
    > "$LOG" 2>&1 || true

# Analyze results
echo ""
echo "[$LABEL] === Results ==="

if grep -q "TEST PASSED" "$LOG"; then
    echo "[$LABEL] PASSED"
elif grep -q "TEST FAILED" "$LOG"; then
    echo "[$LABEL] FAILED"
else
    echo "[$LABEL] HUNG or CRASHED (timeout after ${TIMEOUT}s)"
fi

# Show SRCU warnings
srcu_count=$(grep -c "srcu lock" "$LOG" 2>/dev/null || echo 0)
echo "[$LABEL] SRCU warnings: $srcu_count"
grep "srcu lock" "$LOG" 2>/dev/null | head -5 || true

echo ""
echo "[$LABEL] Last 15 lines:"
tail -15 "$LOG"
echo ""
echo "[$LABEL] Full log: $LOG"
