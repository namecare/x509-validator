# x509-validator-bench-compare

Comparison benchmarks: **which is faster?** Backend against backend, parser
against parser, verifier against verifier, and this port against the original
it came from. Not published.

Its counterpart, `x509-validator-bench-measure`, answers a different question
— *did our own code get slower?* — and is the one to track over time. This
crate is exploratory: run it when choosing a backend or when a dependency
changes.

Uses [divan](https://github.com/nvzqz/divan), which reports fastest / median /
mean per row and is pleasant to read at a terminal.

Figures are wall-clock and are useful for *ranking* on the machine that
produced them, not as portable absolutes — rerun locally before drawing
conclusions on different hardware.

## Layout

Each bench file is self-contained: the workload a row measures — which
certificates, which store, which policy — is written out in the bench
function itself rather than assembled behind a shared table. `src/` holds only
the types the benches cannot declare themselves (the backend registry, the
mock policies) plus fixture re-exports.

Two rules keep the rows readable:

- **`args` carries data, never a target.** A bench argument is the certificate
  chain, corpus, or signature under test.
- **One function per target.** Each backend, parser, or verifier gets its own
  bench function, so every row names what it measures.

| File | Question |
|---|---|
| `benches/internals.rs` | Which of our backends and primitives is fastest? (`mod backend`, `mod crypto_atomics`) |
| `benches/parsers.rs` | Is our parser choice a good one? |
| `benches/verifiers.rs` | Are we competitive with other Rust verifiers? |
| `benches/rust_vs_swift.rs` | Is the port faster than the original? |

## Running

The runner runs every bench target and saves each one's raw output under
`.output/`:

    ./run.sh

It starts the Swift suite in parallel with the Rust targets, which is what
makes a full run quick — but it also means the two sides compete for CPU, so a
Swift number and a Rust number from the same run are not directly comparable.
When the cross-language rows are the point:

    ./run.sh --sequential

One target at a time:

    cargo bench -p x509-validator-bench-compare --bench internals

Filter by name within a target:

    cargo bench -p x509-validator-bench-compare --bench internals -- crypto_atomics

All three crypto backends are compiled in by default and each gets its own
row. To measure a single backend:

    cargo bench -p x509-validator-bench-compare --no-default-features --features ring

## The Swift side

`benches/rust_vs_swift.rs` measures the Rust side only. The other side is a
separate Swift package under [`swift/`](swift), run by its own toolchain:

    cd swift && swift package benchmark

The two never share a process, and `swift-benchmark` and divan do not sample
identically or offer a common machine-readable format, so their raw outputs
land side by side in `.output/` rather than being merged automatically.

## Feature flags

| Feature | Adds | Notes |
|---|---|---|
| `verify_peer` | `x509-verify` rows in `internals`'s `crypto_atomics` | Pure Rust, no extra setup. |
| `openssl` | openssl rows in `parsers` (`read_san`) and `verifiers` | The only dependency needing a system C library. On macOS you may need to set `OPENSSL_DIR` (e.g. via Homebrew's `openssl@3`) for the crate to link. |
| `verifiers` | Compiles the `verifiers` bench at all (`rustls-webpki`, `rustls-pki-types`) | Required just to build that bench; `openssl` is additive on top for its rows. |

## Fixtures

The generated parity certificates live in `x509-validator-testkit`
(`bench_fixtures`), shared with the `measure` crate so both build against one
specification: P-384 CAs, P-256 intermediates and leaves, and validity windows
anchored to a fixed reference time rather than the wall clock.

The Mozilla CA bundle roots are vendored in `x509-validator-testkit`
(`data/mozilla/`) and re-exported from this crate's root as `ROOTS`; see
[`x509-validator-testkit/data/mozilla/README.md`](../../x509-validator-testkit/data/mozilla/README.md)
for provenance. The Apple chain (`x509-validator-testkit/data/apple/`) is a
real, publicly-issued receipt-signing chain; see
[`x509-validator-testkit/data/apple/README.md`](../../x509-validator-testkit/data/apple/README.md).