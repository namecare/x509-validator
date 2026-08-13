# Comparison results

Generated from `.output/` by `render.py`. Regenerate the raw numbers with `./run.sh`, then re-render with `python3 render.py`.

Every figure is a median. Rust medians come from Divan's `median` column; Swift's come from package-benchmark's p50.

## Backends

End-to-end validation with only the crypto backend swapped. This is the number that decides which backend a consumer should compile in.

Two chains of identical shape — leaf → intermediate → root, two signature verifications each — differing only in the curve of the issuer keys that do the verifying:

- `p256_chain` — a generated all-P-256 chain. Every backend has a dedicated P-256 implementation, so this is the fast curve.
- `apple_receipt_p384` — Apple's real receipt-signing chain (leaf → WWDR G6 → Apple Root CA - G3). The leaf is P-256, but a certificate is verified with its *issuer's* key, and both the intermediate and root are P-384 — so both verifications are P-384.

Comparing the two rows for one backend isolates the curve, since nothing else about the work differs.

| Chain | aws-lc-rs | ring | RustCrypto | Fastest vs next |
| --- | ---: | ---: | ---: | ---: |
| `apple_receipt_p384` | 316.20 µs | 1.07 ms | 822.00 µs | aws-lc-rs **2.60× faster** |
| `p256_chain` | 86.99 µs | 93.79 µs | 269.20 µs | aws-lc-rs **1.08× faster** |

## Crypto primitives

A single signature verification per row, with the chain-building and parsing removed. Where the backend table shows which backend wins overall, this shows which operations it wins on.

| Operation | aws-lc-rs | ring | RustCrypto | Fastest vs next |
| --- | ---: | ---: | ---: | ---: |
| `ecdsa_p256_sha256` | 40.24 µs | 43.79 µs | 132.40 µs | aws-lc-rs **1.09× faster** |
| `ecdsa_p384_sha384` | 152.40 µs | 528.10 µs | 402.40 µs | aws-lc-rs **2.64× faster** |
| `ed25519` | 26.41 µs | 32.37 µs | 29.91 µs | aws-lc-rs **1.13× faster** |
| `rsa_2048_sha256` | 15.08 µs | 17.29 µs | 56.95 µs | aws-lc-rs **1.15× faster** |
| `rsa_4096_sha256` | 50.33 µs | 66.16 µs | 209.90 µs | aws-lc-rs **1.31× faster** |

## Diagnostics overhead

`validate` against `validate_with_diagnostics` on the same chain: what collecting the diagnostic trail costs on a validation that succeeds.

| Entry point | Median | vs `validate` |
| --- | ---: | ---: |
| `validate` | 302.20 µs | — |
| `validate_with_diagnostics` | 310.00 µs | 1.03× slower |

## Parsers

The parser crate we build on against the alternatives, on the same certificates.

### `full_parse`

Parsing a certificate and walking its extensions.

| Corpus | x509-cert | x509-parser | Fastest vs next |
| --- | ---: | ---: | ---: |
| `apple_leaf` | 3.50 µs | 2.79 µs | x509-parser **1.25× faster** |
| `single_root` | 3.62 µs | 3.33 µs | x509-parser **1.09× faster** |
| `webpki_roots` | 373.20 µs | 294.70 µs | x509-parser **1.27× faster** |

### `read_san`

Parsing far enough to read the subjectAltName, the access pattern hostname verification actually uses.

| Corpus | x509-cert | x509-parser | Fastest vs next |
| --- | ---: | ---: | ---: |
| `apple_leaf` | 3.12 µs | 2.79 µs | x509-parser **1.12× faster** |
| `single_root` | 3.42 µs | 3.33 µs | x509-parser **1.02× faster** |
| `webpki_roots` | 372.50 µs | 293.90 µs | x509-parser **1.27× faster** |

## Verifiers

Our validator against the other Rust path-building verifiers, on identical chains.

### `apple_chain`

| Verifier | Median | vs fastest |
| --- | ---: | ---: |
| ours (aws-lc-rs) | 312.60 µs | 1.02× slower |
| ours (ring) | 1.04 ms | 3.39× slower |
| ours (RustCrypto) | 792.00 µs | 2.58× slower |
| rustls-webpki | 306.60 µs | **fastest** |

### `tls_fixture`

| Verifier | Median | vs fastest |
| --- | ---: | ---: |
| ours (aws-lc-rs) | 192.80 µs | 1.01× slower |
| ours (ring) | 563.90 µs | 2.96× slower |
| ours (RustCrypto) | 529.60 µs | 2.78× slower |
| rustls-webpki | 190.40 µs | **fastest** |

## Rust against Swift

This port against the original swift-certificates, on the two workloads both sides measure. Rust figures are Divan medians, Swift figures package-benchmark p50 wall clock; both are already per operation.

> Numbers from a parallel `./run.sh` are not comparable across languages — the two suites contend for the same cores. Use `./run.sh --sequential` when this table is the point.

| Workload | Rust | Swift | Rust vs Swift |
| --- | ---: | ---: | ---: |
| All 16 validation scenarios | 2.68 ms | 5.65 ms | **2.11× faster** |
| Parse the WebPKI roots (x509-cert) | 373.20 µs | 1.70 ms | **4.54× faster** |
| Parse the WebPKI roots (x509-parser) | 294.70 µs | 1.70 ms | **5.76× faster** |

### Rust scenario breakdown

The individual scenarios summed into the row above. Swift measures them only in aggregate, so there is no per-scenario column to compare against.

| Scenario | Rust |
| --- | ---: |
| `a_policy_failure_sends_the_search_down_a_longer_path` | 501.10 µs |
| `rejects_a_root_that_did_not_sign_the_certificate_below_it` | 496.30 µs |
| `cross_signed_root` | 346.70 µs |
| `prefers_an_intermediate_whose_ski_matches` | 234.10 µs |
| `prefers_no_ski_over_a_non_matching_one` | 231.60 µs |
| `roots_in_the_intermediate_store_are_not_a_problem` | 195.30 µs |
| `extra_roots_are_ignored` | 194.00 µs |
| `trivial_chain_building` | 193.20 µs |
| `builds_the_shorter_path_when_both_cross_signed_roots_are_present` | 191.60 µs |
| `a_missing_root_cannot_build` | 43.58 µs |
| `a_trust_root_may_be_a_non_self_signed_intermediate` | 42.37 µs |
| `a_self_signed_certificate_in_the_trust_store_validates` | 1.76 µs |
| `an_unhandled_critical_extension_on_the_leaf_is_policed` | 1.59 µs |
| `a_self_signed_certificate_outside_the_trust_store_is_rejected` | 1.51 µs |
| `a_trust_root_may_be_a_non_self_signed_leaf` | 1.51 µs |
| `a_missing_intermediate_cannot_build` | 1.33 µs |
