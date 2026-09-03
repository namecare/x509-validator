# Mock certificates

Real DER, kept here so the examples start where an application starts: with
bytes.

| File | Origin |
|---|---|
| `example_com_leaf.der`, `example_com_intermediate_{1,2,3}.der` | Captured from a TLS handshake with example.com. Expires 27 Oct 2026; re-capture with the `openssl s_client` command in the parent README. |
| `signed_transaction.jws` | A signed transaction from Apple's App Store Server Library test suite: a real ES256 JWS whose `x5c` header carries a real three-certificate chain. |
| `apple_test_root_ca.der` | The root that chain reaches. Apple's test root, not the production Apple Root CA - G3 — a real integration pins the production root instead. |

The transaction and its root are valid until 2032.
