# x509-validator-bench

Benchmarks for `x509-validator`. Not published.

## Running

    cargo bench -p x509-validator-bench                     # everything
    cargo bench -p x509-validator-bench --bench crypto      # one tier
    cargo bench -p x509-validator-bench -- verify_ecdsa     # filter by name

By default all three crypto backends are compiled in and benchmarks that vary
by backend report one row each. To measure a single backend:

    cargo bench -p x509-validator-bench --no-default-features --features ring

## Tiers

| Bench | Measures | Backend axis |
|---|---|---|
| `crypto` | `verify_signature` per algorithm, `sha256` | yes |
| `parse` | `Certificate::from_der` over 137 WebPKI roots | no |
| `policies` | each policy against a prebuilt chain | no |
| `validate` | `BaseVerifier::validate` end to end | yes |
| `verifier` | all 16 validation scenarios as one blob | no |

`crypto` answers which backend is fastest; `validate` shows how much that
matters once parsing and policy work are included. `verifier` mirrors the
reference implementation's benchmark and serves as the regression canary.

## Results

Measured on Darwin arm64 (Apple Silicon). Figures are wall-clock and are
useful for *ranking* backends and tiers on this machine, not as portable
absolutes — rerun locally before drawing conclusions on different hardware.
Backend order throughout is aws_lc / ring / rust_crypto.

### Signature verification

Per call, including SPKI parse and key construction:

| Algorithm | aws_lc | ring | rust_crypto |
|---|---|---|---|
| RSA-2048 | 15.5µs | 17.9µs | 134µs |
| RSA-4096 | 50µs | 65µs | 502µs |
| ECDSA P-256 | 40µs | 43µs | 220µs |
| ECDSA P-384 | 154µs | 528µs | 820µs |
| Ed25519 | 27µs | 33µs | 31µs |

### SHA-256

Per call:

| Input | aws_lc | ring | rust_crypto |
|---|---|---|---|
| 64 B | 55.6ns | 61.4ns | 348.5ns |
| 1 KiB | 541.5ns | 457.5ns | 2.999µs |
| 64 KiB | 25.79µs | 26.16µs | 180.7µs |

### DER parsing (backend-independent)

Single root (`ROOTS[0]`): 3.666µs. All 137 roots: 307.3µs.

### Policy evaluation (backend-independent)

Version: 2.46ns. Expiry: 13.2ns. Basic constraints: 35.82ns. Name
constraints: 41.36ns. RFC 5280 composite: 88.24ns.

### End-to-end validation

`BaseVerifier::validate` over a three-certificate chain:

| Scenario | aws_lc | ring | rust_crypto |
|---|---|---|---|
| Plain chain | 202µs | 560.5µs | 1.024ms |
| With cross-signed decoys | 195.5µs | 561.7µs | 1.018ms |

### Parity blob

All 16 validation scenarios, `DEFAULT_BACKEND`: median 2.728ms.

## Findings

1. **aws-lc-rs wins every signature-verification workload.** Its margin over
   ring is modest (10-25%) except at ECDSA P-384, where it is 3.4x faster.
   rust_crypto is 4-16x slower than aws-lc-rs on everything except Ed25519,
   where all three backends are close. For SHA-256, aws-lc-rs and ring are
   effectively tied (ring is actually faster at 1 KiB).

2. **Crypto dominates end-to-end validation — 95-99% of it.** Policy
   evaluation costs tens of nanoseconds against crypto's hundreds of
   microseconds, roughly a 1000x gap. The per-verification costs from the
   crypto tier sum to almost exactly the end-to-end figures (aws_lc 194µs vs
   192µs measured, ring 571µs vs 550µs, rust_crypto 1040µs vs 1005µs) for a
   chain needing exactly two signature verifications. Backend choice is close
   to the only thing determining validation speed.

3. **Cross-signed decoy candidates cost nothing.** The AKI/SKI-based issuer
   ranking sorts the true issuer first and the search returns on first
   success, so decoys are never signature-verified. Adding two cross-signed
   intermediates and a second root did not measurably change validation cost.

## Caveats

- These are wall-clock numbers from one machine; they rank backends but are
  not portable absolutes.
- There is no regression gate. The suite collects numbers; comparing runs
  across time or machines is manual. Having benchmarks is not the same as
  having regression detection.
- `parse_single_root` benches `ROOTS[0]`, which is the corpus's largest
  certificate (2007 bytes vs a 1083-byte mean), so its figure is pessimistic
  relative to a median root.
- `ServerIdentityPolicy` is benched only for the DNS SAN path; wildcard and
  IP matching are unmeasured.

## Fixtures

Certificates are generated at runtime via `x509-validator-testkit`, matching
the reference specification: P-384 CAs, P-256 intermediates and leaves, and
validity windows anchored to a fixed reference time rather than the wall
clock. See `src/fixtures.rs`.

The Mozilla CA bundle roots used by `parse.rs` are vendored under
`data/mozilla/`; see `data/mozilla/README.md` for provenance.
