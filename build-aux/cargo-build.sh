#!/bin/sh
set -eu

srcdir=$1
builddir=$2
buildtype=$3
export CARGO_TARGET_DIR="$builddir/target"

case "$buildtype" in
  release|minsize|debugoptimized|plain) cargo_profile=release ;;
  *) cargo_profile=debug ;;
esac

if [ "$cargo_profile" = release ]; then
  cargo build --manifest-path "$srcdir/Cargo.toml" --release
else
  cargo build --manifest-path "$srcdir/Cargo.toml"
fi

cp "$CARGO_TARGET_DIR/$cargo_profile/microvisor" "$builddir/microvisor"
cp "$CARGO_TARGET_DIR/$cargo_profile/microvisor-helper" "$builddir/microvisor-helper"
