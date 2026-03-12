#!/bin/bash
# Build a minimal initramfs for bcachefs SRCU lock testing.
#
# Uses the static Rust init binary (vm-init-rs) — no busybox, no shared libs.
#
# Usage: ./build-initramfs.sh [output-path]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INITRD="${1:-$SCRIPT_DIR/test-initramfs.img}"
WORKDIR=$(mktemp -d)

echo "Building Rust init (static musl)..."
(cd "$SCRIPT_DIR/vm-init-rs" && cargo build --release --target x86_64-unknown-linux-musl --quiet)

INIT_BIN="$SCRIPT_DIR/vm-init-rs/target/x86_64-unknown-linux-musl/release/vm-init"
if [ ! -f "$INIT_BIN" ]; then
    echo "error: $INIT_BIN not found" >&2
    exit 1
fi

echo "Building initramfs in $WORKDIR"

mkdir -p "$WORKDIR"/{dev,proc,sys,mnt/test,tmp}

# The Rust binary is statically linked — it IS the init
cp "$INIT_BIN" "$WORKDIR/init"
chmod +x "$WORKDIR/init"

# Minimal device nodes (devtmpfs is mounted by init, but console is needed early)
mknod "$WORKDIR/dev/console" c 5 1
mknod "$WORKDIR/dev/null" c 1 3

# Pack it
(cd "$WORKDIR" && find . | cpio --quiet -o -H newc | gzip -9) > "$INITRD"

echo "Initramfs written to $INITRD ($(du -h "$INITRD" | cut -f1))"
rm -rf "$WORKDIR"
