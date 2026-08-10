# x509-validator-bench-compare

Comparison benchmarks: **which is faster?** Backend against backend, parser
against parser. Not published.

Its counterpart, `x509-validator-bench-measure`, answers a different question
— *did our own code get slower?* — and is the one to track over time. This
crate is exploratory: run it when choosing a backend or when a dependency
changes, and update the tables below.

Uses [divan](https://github.com/nvzqz/divan), which reports fastest / median /
mean per row and is pleasant to read at a terminal.

## Running

    cargo bench -p x509-validator-bench-compare                    # everything
    cargo bench -p x509-validator-bench-compare --bench parsers    # one tier
    cargo bench -p x509-validator-bench-compare -- verify_ecdsa    # filter by name

All three crypto backends are compiled in by default and every backend-varying
benchmark reports one row each. To measure a single backend:

    cargo bench -p x509-validator-bench-compare --no-default-features --features ring

## Tiers

| Bench | Measures | Axis |
|---|---|---|
| `parsers` | DER parsing | x509-parser vs x509-cert |
| `backends` | `BaseVerifier::validate`, end to end | crypto backend |
| `crypto_atomic` | `verify_signature` per algorithm, `sha256` | crypto backend |

## Results

Measured on Darwin arm64 (Apple Silicon), system allocator. Figures are
wall-clock and are useful for *ranking* on this machine, not as portable
absolutes — rerun locally before drawing conclusions on different hardware.
Backend order is aws_lc / ring / rust_crypto. Medians throughout.

### Parsing

| Corpus | x509-parser (ours) | x509-cert |
|---|---|---|
| All 137 WebPKI roots | 296.7µs | 386.6µs |
| Single root (`ROOTS[0]`) | 3.54µs | 3.541µs |
| Apple receipt leaf | 2.999µs | 3.415µs |

**Read this ratio carefully — the two parsers do not do equal work.**
x509-parser returns a view *borrowing* the input buffer; its own docs say
"zero-copy, and so has the same lifetime as the input". x509-cert returns an
*owned, heap-allocated* tree (a `Vec` of extensions, two `RdnSequence`s per
certificate) that outlives its input and can be cloned. The ~30% gap on the
full corpus is largely the cost of that allocation, and it buys real
ergonomic freedom. Being within 30% while allocating is a good showing for
x509-cert, not a poor one.

Two further caveats:

- Both benches touch the extension list inside `black_box`, so neither side is
  credited for work it merely deferred. But x509-parser's `FromDer` path and
  x509-cert's `Decode` path do not necessarily parse extensions to the same
  depth.
- x509-cert's numbers move with the allocator; x509-parser's do not.

Note that *our* parser is not our code: `x509_validator::Certificate` is
a re-export of `x509_parser::certificate::X509Certificate`, so this row is
x509-parser's performance with no wrapper of ours in it.

### End-to-end validation

`BaseVerifier::validate` over a three-certificate chain:

| Scenario | aws_lc | ring | rust_crypto |
|---|---|---|---|
| Plain chain (P-256 + P-384) | 193.4µs | 560.2µs | 1.029ms |
| With cross-signed decoys | 190.1µs | 558.9µs | 1.024ms |
| Apple receipt chain (P-384 ×2) | 315.4µs | 1.032ms | 1.636ms |

The Apple row uses a real, publicly-issued chain (see `data/apple/README.md`);
the others use generated fixtures. Both of its verifications are P-384, which
is why the spread is wider — see finding 1.

### Signature verification

Per call, including SPKI parse and key construction:

| Algorithm | aws_lc | ring | rust_crypto |
|---|---|---|---|
| RSA-2048 | 14.45µs | 16.66µs | 128.4µs |
| RSA-4096 | 48.58µs | 63.54µs | 482.2µs |
| ECDSA P-256 | 38.7µs | 42.08µs | 212.4µs |
| ECDSA P-384 | 147.8µs | 517.7µs | 814.1µs |
| Ed25519 | 25.45µs | 31.16µs | 30.33µs |

### SHA-256

| Input | aws_lc | ring | rust_crypto |
|---|---|---|---|
| 64 B | 67.42ns | 61.88ns | 361.7ns |
| 64 KiB | 26.16µs | 26.33µs | 177.6µs |

## Findings

1. **aws-lc-rs wins every signature-verification workload.** Its margin over
   ring is modest (10–25%) except at ECDSA P-384, where it is 3.5× faster.
   rust_crypto is 4–16× slower than aws-lc-rs on everything except Ed25519,
   where all three are close. For SHA-256, aws-lc-rs and ring are effectively
   tied (ring is faster on small inputs).

2. **Crypto dominates end-to-end validation.** Two P-256/P-384 verifications
   account for nearly all of the three-cert chain figure; parsing the same
   chain costs single-digit microseconds against hundreds. Backend choice is
   close to the only thing determining validation speed.

3. **Cross-signed decoy candidates cost nothing.** The AKI/SKI-based issuer
   ranking sorts the true issuer first and the search returns on first
   success, so decoys are never signature-verified. Adding two cross-signed
   intermediates and a second root did not measurably change validation cost
   (190.1µs vs 193.4µs — within noise).

## Caveats

- Wall-clock numbers from one machine; they rank, they do not port.
- `parse/single_root` uses `ROOTS[0]`, the corpus's largest certificate
  (2007 bytes vs a 1083-byte mean), so that figure is pessimistic relative to
  a median root.
- These benchmarks are not a regression gate and are not meant to be one.
  That is `x509-validator-bench-measure`'s job.

## Fixtures

The generated parity certificates live in `x509-validator-testkit`
(`bench_fixtures`), shared with the `measure` crate so both build against one
specification: P-384 CAs, P-256 intermediates and leaves, and validity windows
anchored to a fixed reference time rather than the wall clock.

The Mozilla CA bundle roots are vendored under `data/mozilla/` and embedded via
`src/roots.rs`; see `data/mozilla/README.md` for provenance. The Apple chain
under `data/apple/` is a real, publicly-issued receipt-signing chain.
