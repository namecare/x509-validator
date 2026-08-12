# x509-validator-bench-compare

Comparison benchmarks: Backend against backend, parser
against parser, verifier against verifier, and this port against original swift version.

## Layout

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

It starts the Swift suite in parallel with the Rust targets.

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

## Feature flags

| Feature | Adds | Notes |
|---|---|---|
| `verify_peer` | `x509-verify` rows in `internals`'s `crypto_atomics` | Pure Rust, no extra setup. |
| `openssl` | openssl rows in `parsers` (`read_san`) and `verifiers` | The only dependency needing a system C library. On macOS you may need to set `OPENSSL_DIR` (e.g. via Homebrew's `openssl@3`) for the crate to link. |
| `verifiers` | Compiles the `verifiers` bench at all (`rustls-webpki`, `rustls-pki-types`) | Required just to build that bench; `openssl` is additive on top for its rows. |