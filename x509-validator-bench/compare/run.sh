#!/usr/bin/env bash
#
# Runs every benchmark in the comparison suite and saves each target's raw
# output under `.output/`. Nothing here parses or reformats those numbers —
# the reports are generated from the raw files separately.
#
# The Swift suite runs in parallel with the Rust targets, which is what makes
# a full run quick. It also means the two sides compete for CPU, so a Swift
# number and a Rust number from the same run are not directly comparable;
# rerun with `--sequential` when the cross-language rows are the point.

set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

output=".output"
sequential=0
[[ "${1:-}" == "--sequential" ]] && sequential=1

rm -rf "$output"
mkdir -p "$output"

# Every Rust bench target, with the features it needs. `verifiers` is behind a
# feature because rustls-webpki and rustls-pki-types are optional; openssl and
# verify_peer are left off by default since they need a system library and add
# non-peer rows respectively.
features="aws_lc,ring,rust_crypto,verifiers"
targets=(internals parsers verifiers rust_vs_swift)

run_rust() {
  for target in "${targets[@]}"; do
    echo "==> rust: $target"
    cargo bench --bench "$target" --features "$features" \
      >"$output/$target.txt" 2>&1 \
      || echo "!!! rust: $target failed; see $output/$target.txt"
  done
}

run_swift() {
  if ! command -v swift >/dev/null 2>&1; then
    echo "!!! swift not found; skipping the Swift suite" | tee "$output/swift.txt"
    return
  fi
  echo "==> swift: benchmarks"
  (cd swift && swift package --disable-sandbox benchmark) \
    >"$output/swift.txt" 2>&1 \
    || echo "!!! swift suite failed; see $output/swift.txt"
}

if (( sequential )); then
  run_rust
  run_swift
else
  run_swift &
  swift_pid=$!
  run_rust
  wait "$swift_pid"
fi

echo
echo "raw output in $output/:"
ls -1 "$output"