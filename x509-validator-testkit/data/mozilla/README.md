# Mozilla CA bundle roots

137 root CA certificates from Mozilla's CA bundle, converted from PEM to raw
DER on 2026-08-07. Embedded by `src/roots.rs` and used by both benchmark
crates, the parsing tests, and the fuzz corpus.

Source certificates were PEM-encoded despite the `.crt` extension; this crate
has no PEM parser, so each was converted once with:

```
openssl x509 -inform pem -in <cert>.crt -outform der -out <cert>.der
```

The roots are used only as a realistic corpus of DER-encoded X.509
certificates — to measure parsing cost, and to seed the fuzzer with encodings
no generator would produce. Their trust status is not relevant here.
