<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".local/logo-dark.png">
  <source media="(prefers-color-scheme: light)" srcset=".local/logo-light.png">
  <img width="20%" alt="X509-validator" src=".local/logo-light.png">
</picture>
</p>

# X509Validator Fuzzing

## Fuzzing

Four fuzzers live in `fuzz/fuzzers`: `parse_certificate` (raw DER through the
parser and every accessor), `validate_chain` (chain building and the RFC 5280
policy), `server_identity` (RFC 6125 hostname and IP matching), and
`name_constraints`. They run on every PR for 60s each and nightly for 15
minutes, with the corpus cached between nightly runs.

```sh
cargo install cargo-fuzz --locked
cd fuzz
cargo +nightly fuzz run parse_certificate -- -max_total_time=60

# Reproduce a crash the fuzzer found.
cargo +nightly fuzz run parse_certificate artifacts/parse_certificate/crash-…
```

The committed corpus is built from the certificates vendored in
`x509-validator-testkit/data` — 137 Mozilla roots and a real Apple chain, so
the fuzzer starts from two decades of real-world DER rather than from one
generator's encoding style. Regenerate it with `./admin/seed-fuzz-corpus`
after changing the seeds or the framing. A local run leaves its own
discoveries in `fuzz/corpus`; that is expected, but do not commit them —
re-run the seeder to get back to the curated set.

Each fuzzer parses one flat byte string. `validate_chain`, `server_identity`
and `name_constraints` carve theirs into two-byte length-prefixed frames via
`fuzzers/common`; changing that framing invalidates every corpus entry, so add
a helper rather than editing one.

`validate_chain` reads a leading selector byte choosing between the real
crypto backend and a stub that accepts every signature. The stub exists
because the fuzzer cannot forge a signature that verifies: without it, every
mutated input is rejected before chain building and the search never reaches
the DFS in `validator.rs`. Measured over 45 seconds from an identical chain,
the stub seeds reach ~4600 edges against ~4400 for the real backend.
ftware under the terms of any of these licenses, at your option.