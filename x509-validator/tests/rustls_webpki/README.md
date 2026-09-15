# Vendored suite: rustls/webpki

The portable part of the `rustls/webpki` integration tests, run against this
library.

| Module | Upstream file | Tests |
|---|---|---:|
| `tls_server_certs.rs` | `tls_server_certs.rs` | 29 |
| `integration.rs` | `integration.rs` | 20 |
| `client_auth.rs` | `client_auth.rs` | 4 |
| `custom_ekus.rs` | `custom_ekus.rs` | 3 |
| `amazon.rs` | `amazon.rs` | 1 |

Running the whole binary:

    cargo test --features aws_lc --test rustls_webpki

## Not ported

- `signatures.rs` — upstream drives `EndEntityCert::verify_signature` and
  `RawPublicKeyEntity::verify_signature`, low-level entry points that check
  one signature over one caller-supplied message under an independently
  named algorithm. This library exposes no such API; reaching the crypto
  layer directly would test the backend rather than the validator, and would
  pin the suite to one backend.
- `cert_v1_unsupported.rs`, `cert_without_extensions.rs` — both assert on
  what `EndEntityCert::try_from` does at construction time. This library has
  no constructor-level gate: `Certificate::parse` accepts these and the
  questions they ask are policy questions, answered elsewhere in
  `tests/version_policy.rs` and `tests/basic_constraints_policy.rs`.
- `client_auth_revocation.rs`, `crl_tests.rs` — CRL revocation, which this
  library does not implement.
- `x509_limbo.rs` — a harness over an external corpus (`x509-limbo`),
  requiring its own submodule, exceptions file and post-quantum algorithms.
  Worth doing on its own terms.
- Within `amazon.rs`: the revocation arms. Upstream tests each chain against
  four CRL configurations; only its `crls: None` assertions are ported, and
  the CRL fixtures are not vendored. Its expired-leaf and name-matching
  assertions are ported in full.
- Within `integration.rs`: the SCT extraction tests (`no_scts`, `with_scts`)
  — no SCT support here.

## Divergences

Tests marked `#[ignore]` fail against this library. Each is kept with its
upstream assertion intact rather than softened, because the assertion is the
record of the difference. Run them (and watch them fail) with:

    cargo test --features aws_lc --test rustls_webpki -- --include-ignored

All seven are confirmed still failing as of this revision. Grouped by
severity, most serious first.

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
