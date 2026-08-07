# Apple receipt-signing chain

A real, publicly-issued certificate chain, vendored so the suite reports at
least one measurement against certificates nobody chose for benchmarking.

| File | Subject | Key |
|---|---|---|
| `receipt_signing_leaf.der` | `CN=Prod ECC Mac App Store and iTunes Store Receipt Signing` | P-256 |
| `wwdr_g6_intermediate.der` | `CN=Apple Worldwide Developer Relations Certification Authority, OU=G6` | P-384 |
| `apple_root_ca_g3.der` | `CN=Apple Root CA - G3` | P-384 |

The leaf and intermediate came from the `x5c` header of a real signed Apple
payload. The root is Apple's published `AppleRootCA-G3.cer`, SHA-256
fingerprint:

    63:34:3A:BF:B8:9A:6A:03:EB:B5:7E:9B:3F:5F:A7:BE:7C:4F:5C:75:6F:30:17:B3:A8:C4:88:C3:65:3E:91:79

Chain verified with `openssl verify` against that root before vendoring.

## Why this chain

Both *verifications* are ECDSA-P384 — the leaf is signed by the
intermediate's P-384 key, and the intermediate by the root's P-384 key. A
chain's cost is set by the issuers' keys, not the subjects', so the leaf's own
P-256 key does not enter into it. P-384 is where the spread between backends
is widest, which makes this the pessimistic real-world case rather than the
average one.

Real certificates also carry policy OIDs and CRL/OCSP pointers that the
generated fixtures do not, so they parse more slowly.

## Validation time

`fixtures::apple::SIGNED_DATE` is `1758579965` (2025-09-22T22:26:05Z), the
`signedDate` of the payload these certificates signed. Expiry is checked
against that instant rather than the wall clock, so the benchmark is
reproducible and keeps working after the leaf expires in October 2027.

## Note

These certificates are public — they ship in the clear in every Apple receipt.
No private keys or payload contents are stored here.