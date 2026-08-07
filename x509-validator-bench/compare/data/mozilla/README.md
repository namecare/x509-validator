# Mozilla CA bundle roots

137 root CA certificates from Mozilla's CA bundle, converted from PEM to raw
DER on 2026-08-07 for use in `benches/parse.rs`.

Source certificates were PEM-encoded despite the `.crt` extension; this crate
has no PEM parser, so each was converted once with:

```
openssl x509 -inform pem -in <cert>.crt -outform der -out <cert>.der
```

The roots are used only as a realistic corpus of DER-encoded X.509
certificates to measure parsing cost; their trust status is not relevant
here.
