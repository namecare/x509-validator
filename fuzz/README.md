# Fuzz Testing

X509Validator supports fuzz testing using [cargo-fuzz]. Fuzz tests are
automatically run during continuous integration: 60 seconds per target on every
pull request and 15 minutes nightly, with the corpus cached between nightly
runs. You may also run fuzz tests locally. See the [cargo-fuzz setup]
instructions for requirements.

```bash
# List available fuzzing targets.
$ cargo fuzz list
name_constraints
parse_certificate
server_identity
validate_chain

# Run the parse_certificate fuzz target for a fixed period of time (expressed in seconds).
$ cargo fuzz run parse_certificate -- -max_total_time=120

# Reproduce a crash the fuzzer found.
$ cargo fuzz run parse_certificate artifacts/parse_certificate/crash-…

# Clean up generated corpus files
git clean --interactive -- ./corpus
```

`validate_chain` verifies signatures with `x509-validator-fuzzing-provider`,
which accepts everything, so mutated chains still reach chain building.
`validate_chain`, `server_identity` and `name_constraints` take two-byte
length-prefixed frames from `fuzzers/common.rs`; `parse_certificate` takes bare
DER and has a dictionary in `parse_certificate.dict`.

The committed corpus is seeded from the certificates vendored in
`x509-validator-testkit/data`. Regenerate it with `./admin/seed-fuzz-corpus`
after changing the seeds or the framing.

[cargo-fuzz]: https://rust-fuzz.github.io/book/cargo-fuzz.html
[cargo-fuzz setup]: https://rust-fuzz.github.io/book/cargo-fuzz/setup.html
