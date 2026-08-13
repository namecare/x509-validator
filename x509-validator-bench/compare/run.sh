#!/usr/bin/env bash
#
# Runs every benchmark in the comparison suite and saves each target's raw
# output under `.output/`. Nothing here parses or reformats those numbers —
# the reports are generated from the raw files separately.
#
# Usage:
#   ./run.sh                      sequential (comparable numbers)
#   ./run.sh --parallel           overlap Swift with Rust (faster, not comparable)
#   ./run.sh --sample-count 500   more Divan samples per Rust row


set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

output=".output"
sequential=1
sample_count=""

while (( $# )); do
  case "$1" in
    --parallel)     sequential=0 ;;
    # Accepted and ignored: sequential is the default now, but the old runs
    # and notes that pass this flag should not start failing.
    --sequential)   sequential=1 ;;
    --sample-count) sample_count="${2:?--sample-count needs a value}"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

rm -rf "$output"
mkdir -p "$output"

# Every Rust bench target, with the features it needs. `verifiers` is behind a
# feature because rustls-webpki and rustls-pki-types are optional; openssl and
# verify_peer are left off by default since they need a system library and add
# non-peer rows respectively.
features="aws_lc,ring,rust_crypto,verifiers"
targets=(internals parsers verifiers rust_vs_swift)

run_rust() {
  # Divan takes `--sample-count` after the `--` separator, as a bench-binary
  # argument rather than a cargo one.
  local divan_args=()
  [[ -n "$sample_count" ]] && divan_args=(--sample-count "$sample_count")

  for target in "${targets[@]}"; do
    echo "==> rust: $target"
    cargo bench --bench "$target" --features "$features" \
      -- "${divan_args[@]}" \
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
  echo "==> sequential run; all numbers comparable"
  run_rust
  run_swift
else
  echo "!!! parallel run; Rust and Swift contend for CPU and are NOT comparable"
  run_swift &
  swift_pid=$!
  run_rust
  wait "$swift_pid"
fi

echo
echo "raw output in $output/:"
ls -1 "$output"