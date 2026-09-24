# Vendored suite: rustls/webpki

The `rustls/webpki` integration tests, run against this library, plus the
x509-limbo corpus upstream runs through its own harness.

| Module | Upstream file | Tests |
|---|---|---:|
| `tls_server_certs.rs` | `tls_server_certs.rs` | 29 |
| `integration.rs` | `integration.rs` | 20 |
| `signatures.rs` | `signatures.rs` | 13 |
| `client_auth.rs` | `client_auth.rs` | 4 |
| `custom_ekus.rs` | `custom_ekus.rs` | 3 |
| `cert_without_extensions.rs` | `cert_without_extensions.rs` | 2 |
| `amazon.rs` | `amazon.rs` | 1 |
| `cert_v1_unsupported.rs` | `cert_v1_unsupported.rs` | 1 |
| `x509_limbo.rs` | `x509_limbo.rs` | 1 (9,788 cases) |

Running the whole binary:

    cargo test --features aws_lc --test rustls_webpki

`signatures.rs` runs every assertion against each enabled backend, so run it
with `--all-features` to cover all three at once. The limbo harness is
`#[ignore]`d as upstream's is; run it in release with its summary:

    cargo test --release --features aws_lc --test rustls_webpki x509_limbo -- --include-ignored --nocapture

The limbo corpus comes from the `limbo-harness-support` dev-dependency, pinned
to the same `C2SP/x509-limbo` revision upstream pins.
`fixtures/x509_limbo/exceptions.json` is upstream's own list of cases where
`webpki` knowingly diverges from limbo; a case where this library diverges the
same way is counted as a known divergence rather than a failure, exactly as
upstream counts it.

## Not ported

- `client_auth_revocation.rs`, `crl_tests.rs` — CRL revocation, which this
  library does not implement. Limbo cases carrying CRLs are skipped for the
  same reason.
- Within `amazon.rs`: the revocation arms. Upstream tests each chain against
  four CRL configurations; only its `crls: None` assertions are ported, and
  the CRL fixtures are not vendored. Its expired-leaf and name-matching
  assertions are ported in full.
- Within `integration.rs`: the SCT extraction tests (`no_scts`, `with_scts`)
  — no SCT support here.
- Within `signatures.rs`:
  - `rsa_2048_key_rejected_by_rsa_pkcs1_3072_8192_sha384` and its `_rpk`
    twin. `RSA_PKCS1_3072_8192_SHA384` is a `webpki` algorithm object that
    carries its own 3072-bit key floor; an X.509 AlgorithmIdentifier names
    only `sha384WithRSAEncryption`, so the distinction cannot be expressed.
  - `key_usage_digital_signature_accepted`,
    `key_usage_without_digital_signature_rejected` — they test the KeyUsage
    gate on `EndEntityCert::verify_signature`, an API for verifying an
    arbitrary message against a certificate that this library does not have.
  - `ecdsa_p521_sha512` — the certificate generator here cannot sign with
    P-521 and upstream has no pre-generated SHA-512 signature. P-521 support
    is still exercised by `ecdsa_p521_sha256` and `ecdsa_p521_sha384`.
  - In the `*_rejected_by_other_algorithms` loops, the ECDSA entries that
    differ from the key only in curve. A `webpki` ECDSA algorithm pins a
    curve; an X.509 AlgorithmIdentifier does not, and the curve is taken
    from the key, so `ECDSA_P384_SHA256` against a P-256 key is the valid
    `ecdsa-with-SHA256` over P-256 here. Cross-family entries are kept.
- Within `x509_limbo.rs`: cases with `max_chain_depth`, `signature_algorithms`
  or `key_usage` set are skipped, as upstream skips them. Unlike upstream,
  `CLIENT` cases are run, with `clientAuth` as the required purpose.

## Divergences

Tests marked `#[ignore]` fail against this library. Each is kept with its
upstream assertion intact rather than softened, because the assertion is the
record of the difference. Run them (and watch them fail) with:

    cargo test --all-features --test rustls_webpki -- --include-ignored

All fifteen, and the limbo harness, are confirmed still failing as of this
revision. Grouped by severity, most serious first.

### FAIL-OPEN — this library accepts a chain upstream rejects (3)

These are the security-relevant findings: a chain that should be rejected
validates successfully here.

| Test | Expected upstream | Actual here | Root cause |
|---|---|---|---|
| `wildcard_san_rejected_if_could_match_excluded_subtree` | `Err(NameConstraintViolation)` — a wildcard SAN `*.example.com` must be rejected if it could expand into a name (`evil.example.com`) that an excluded subtree names explicitly. This is upstream's own regression test for **CVE-2025-61727**. | Accepted. | `x509-validator/src/rfc5280/dns_names.rs:25`, `dns_name_matches_constraint`. The DNS-label matcher walks labels from the right as literal byte strings, including the wildcard's own leftmost label. For `*.example.com` vs. excluded `evil.example.com`, `com`==`com` and `example`==`example` match, then the literal string `"*"` is compared against `"evil"` — a length mismatch, so the match fails and the excluded-subtree check concludes the wildcard is *not* excluded. There is no wildcard-aware expansion anywhere in the name-constraints matcher. Note the *permitted*-subtree direction of the same defect fails **closed** — `wildcard_san_rejected_if_could_match_name_outside_permitted_subtree` passes, because a wildcard that matches no permitted subtree is rejected for not matching one. Only the excluded direction is exploitable. Confirmed independently: the constraint genuinely reaches the DER, the literal name `evil.example.com` is correctly rejected by the same issuer, and only the wildcard slips through. **The most serious finding of this port.** |
| `empty_name_constraint_sequences_rejected` | `Err(MalformedNameConstraint)` — RFC 5280 §4.2.1.10 forbids an empty `GeneralSubtrees` SEQUENCE in `permittedSubtrees`/`excludedSubtrees`. | Accepted; the empty sequence is treated as if the field were absent. | Lives in the `x509-parser` dependency, not this crate. `parse_nameconstraints` wraps `many1(complete(parse_subtree))` — which correctly fails to parse zero subtrees — in `opt(complete(...))`, which silently converts that parse failure into "field absent" rather than propagating it. Note the finding rests on the parser evidence, not on the test alone: the test's leaf carries no SANs and an empty CN, so it would also be accepted by a correct parser for want of any name in the sibling subtree. The test proves "not rejected", not "not rejected *because* the empty sequence was swallowed". |
| `ip4_address_san_rejected_if_excluded_is_sparse_cidr_mask` | `Err(InvalidNetworkMaskConstraint)` — a non-contiguous CIDR mask (e.g. `255.0.255.0`) in an excluded IP subtree is malformed and must reject the chain outright. | Accepted. | `x509-validator/src/rfc5280/ip_constraints.rs:24-52`. `is_valid_cidr_mask` correctly *detects* the sparse mask as invalid (unit-tested at `ip_constraints.rs:330-339`) — but `address_is_in_subnet` then returns `false` for an invalid mask, and inside `validate_excluded_subtrees` that `false` is indistinguishable from "this address is legitimately outside the excluded range." There is no path from "the constraint itself is malformed" to "reject the chain." **Lives in this crate's own code**, unlike the other two, making it directly actionable. |

### Fail-closed or benign — stricter than upstream, or a fixture difference (4)

Every entry here is either a chain this library correctly *rejects* that
upstream accepts (safe direction), a case where this library's behaviour is
RFC-correct and upstream's fixture is the outlier, or a capability gap that
rejects uniformly rather than selectively.

| Test | Expected upstream | Actual here | Assessment |
|---|---|---|---|
| `allow_subject_common_name` | `Err` — a query name is invalid unless matched via a SAN entry; `webpki` never falls back to the certificate's commonName. | Accepted. | Divergent, not fail-open in the excluded/permitted-subtree sense (the queried name genuinely is inside the permitted subtree). `ServerIdentityPolicy::has_valid_identity_for_service` deliberately falls back to the subject commonName when no SAN entry matches, documented in its own doc comment as a "deprecated practice" kept intentionally. |
| `we_incorrectly_ignore_name_constraints_on_name_in_subject` | `Ok(())` — upstream's own test name records this as tolerated-but-known upstream behaviour: `webpki` never checks the subject DN against name constraints, only the SAN extension. | Rejected. | `NameConstraintsPolicy::names()` includes the certificate's own subject as a `DirectoryName` GeneralName in the set checked against every constraint. The constraint kind here (`Rfc822Name`) is unsupported regardless of what it's compared against, so the chain is rejected outright. Stricter than upstream, fail-closed, not fail-open. |
| `we_ignore_constraints_on_names_that_do_not_appear_in_cert` | `Ok(())` — an unsupported-kind (`Rfc822Name`) `permittedSubtrees` entry should be silently skipped when the certificate carries no name of that kind at all. | Rejected. | `constraint_kind_is_unsupported` runs before any name/constraint-kind comparison, so the mere presence of an unsupported-kind subtree rejects the whole chain regardless of whether the certificate ever presents a matching name kind. Stricter than upstream, fail-closed. |
| `uri_san_rejected_against_uri_excluded_subtree` | `Err` — the fixture's excluded URI constraint is set to the full URI `https://evil.example.com`. | Accepted. | **Not a security bypass.** `uri_constraints.rs:8` quotes RFC 5280 §4.2.1.10 directly: "For URIs, the constraint applies to the host part of the name." This library extracts the SAN's host and compares host-to-host, per the RFC. Upstream's fixture puts a full URI in the constraint position, which the RFC does not define; the host-to-host comparison correctly finds no match. **Our reading is RFC-correct; upstream's fixture is the outlier here.** Had the constraint been a bare host, this library would reject the chain exactly as its sibling test (`uri_san_rejected_against_uri_permitted_subtree`, which passes) does. |

### Signatures and certificate versions (8)

| Test | Expected upstream | Actual here | Assessment |
|---|---|---|---|
| `ed25519`, `ecdsa_p256_sha256`, `ecdsa_p384_key_rejected_by_other_algorithms`, `ecdsa_p521_key_rejected_by_other_algorithms`, `rsa_2048_key_rejected_by_other_algorithms` | `UnsupportedSignatureAlgorithmForPublicKey` for every cross-family pairing, e.g. an RSA algorithm against an EC key. | `aws_lc` and `ring`: `CryptoError::VerificationFailed`. `rust_crypto`: `CryptoError::InvalidKey`, matching upstream. | Fail-closed. The `aws_lc`/`ring` backend never compares the SPKI's algorithm with the key family the signature algorithm needs, so the key bytes reach the primitive and fail there as a bad signature. The good-signature and bad-signature halves of `ed25519` and `ecdsa_p256_sha256` pass on every backend. |
| `ecdsa_p521_sha256`, `ecdsa_p521_sha384` | `Ok(())` for a valid P-521 signature. | `CryptoError::InvalidKey` on every backend. | Capability gap: no backend supports P-521. |
| `test_cert_v1_unsupported` | A version 1 end-entity certificate is refused. | `RFC5280Policy` accepts it. | RFC 5280 permits v1 certificates, and `VersionPolicy` only rejects a v1 certificate that carries extensions. Upstream refuses v1 outright. Related to the v1-intermediate finding in `tests/sec_report.rs`. |

### x509-limbo

9,788 cases: 9,622 match limbo, 15 skipped, 45 diverge the same way `webpki`
does (the known divergences), and 106 are this library's own:

| Group | Cases | Direction | Root cause |
|---|---:|---|---|
| `bettertls::nameconstraints::*` | 81 | **FAIL-OPEN** | Every one is a leaf with no SAN whose name is matched through the subject CN fallback. The CN is never checked against the issuers' DNS name constraints, so e.g. `CN=test.localhost` under `excluded: DNS:localhost` is accepted. Same defect as `san_less_cn_*` in `tests/sec_report.rs`. |
| `cve::cve-2025-61727`, `rfc5280::nc::nc-forbids-dnsname-wildcard-san` | 2 | **FAIL-OPEN** | The wildcard-versus-excluded-subtree defect of `wildcard_san_rejected_if_could_match_excluded_subtree`. |
| `webpki::san::no-san` | 1 | **FAIL-OPEN** | CN fallback: a leaf without a SAN extension is accepted on its CN. |
| `rfc5280::nc::permitted-empty-sequence-excluded-nonempty`, `webpki::nc::intermediate-permitted-excluded-subtrees-both-empty-sequences`, `webpki::nc::intermediate-permitted-excluded-subtrees-both-null` | 3 | **FAIL-OPEN** | Malformed NameConstraints (empty or NULL subtrees) are read as absent, the defect of `empty_name_constraint_sequences_rejected`. |
| `webpki::ca-as-leaf`, `webpki::ee-basicconstraints-ca`, `rfc5280::leaf-ku-keycertsign` | 3 | accepted | A CA certificate (`cA=TRUE` or `keyCertSign`) is accepted in the end-entity position. |
| `webpki::san::public-suffix-wildcard-san`, `webpki::san::san-wildcard-only-tld`, `webpki::san::wildcard-embedded-leftmost-san` | 3 | accepted | Wildcard matching accepts `*.com`, a bare `*`, and a partial-label `ba*.example.com`. |
| `pathological::nc-dos-1..3` | 3 | accepted | No budget on name-constraint comparisons: 2048 constraints against 2048 names is evaluated to completion instead of being refused. |
| `webpki::v1-cert` | 1 | accepted | A version 2 end-entity certificate is accepted. |
| `rfc5280::nc::nc-permits-email-*`, `rfc5280::nc::nc-forbids-othername-noop` | 6 | fail-closed | rfc822Name and otherName subtrees are unsupported, and any unsupported subtree rejects the chain — the `we_ignore_constraints_on_names_that_do_not_appear_in_cert` divergence. |
| `rfc9881::ml-dsa-44/65/87` | 3 | fail-closed | Capability gap: no ML-DSA support. |
