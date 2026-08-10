# Contributing to X509Validator

Thank you for your interest in contributing to X509Validator! This document
provides guidelines and instructions for contributing.

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting started

The published crate builds on stable Rust, edition 2024, and needs 1.85 or
newer. A nightly toolchain is used for one formatting check, but nothing in
the crate itself requires it.

```sh
git clone https://github.com/namecare/x509-validator
cd x509-validator
cargo test -p x509-validator --features aws_lc --all-targets
```

The workspace also holds `x509-validator-testkit` (certificate-building
helpers plus the vendored Mozilla and Apple certificates under `data/`, never
shipped), `examples`, and `x509-validator-bench`.
`fuzz` is deliberately a *separate* workspace: its `libfuzzer-sys` dependency
only builds on nightly, and keeping it out means `cargo test --workspace` on
stable never tries.

## Reporting bugs

If you find a bug, please open an issue on
[GitHub Issues](https://github.com/namecare/x509-validator/issues). The bug
report template asks for what you would expect us to need:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior vs actual behavior
- Version, platform, and which crypto backend feature you enabled
- A minimal code example if possible

For anything security-relevant, follow [SECURITY.md](SECURITY.md) instead and
report it privately.

## Suggesting features

Feature requests are welcome! Please open an issue with:

- A clear description of the feature
- Use cases and motivation
- Any implementation ideas you may have

## Pull request process

1. Fork the repository and create your branch from `master`
2. Make your changes and ensure tests pass
3. Add tests for any new functionality
4. Update documentation if needed
5. Submit a pull request with a clear description of your changes

The pull request template covers what the description should contain, and
prompts you about breaking changes.

### PR guidelines

- Keep changes focused and atomic
- Follow existing code patterns
- Ensure all tests pass before submitting

Titles use [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/)
— `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:` — with a `!` for
anything breaking, as in `feat!:`. The history is a reasonable guide to the
style.

## Before you push

`admin/check` runs everything CI runs, in the order that fails cheapest first:

```sh
./admin/check
```

It needs a few tools that are not part of a default toolchain. One-time setup:

```sh
rustup toolchain install nightly          # import formatting only
cargo install taplo-cli typos-cli cargo-deny --locked
```

The individual steps, for when you only need one of them:

```sh
# Formatting. The nightly pass handles import grouping and merging, which
# rustfmt cannot yet do on stable.
cargo fmt --all
cargo +nightly fmt-unstable
taplo fmt

# Linting. Runs clippy once per package and once per crypto backend rather
# than over the workspace, because a workspace-wide build unifies features:
# one member enabling a backend would enable it for every other member, and
# the single-backend configuration that users actually get would never be
# linted at all.
./admin/clippy -- --deny warnings

# Tests. One run per backend, for the same reason: `--all-features` compiles
# all three and proves only that they coexist, not that any one of them works
# on its own.
cargo test -p x509-validator --features aws_lc --all-targets
cargo test -p x509-validator --features ring --all-targets
cargo test -p x509-validator --features rust_crypto --all-targets
cargo test -p x509-validator --features aws_lc --doc

# Advisories, licenses, and spelling.
cargo deny --workspace --all-features check
typos --config .github/typos.toml
```

The example in `README.md` is compiled as a doctest, so it is checked by the
doctest run above and cannot drift from the API.

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

## Testing requirements

All contributions should include appropriate tests.

## Core contributors: publishing a release

Releases are cut from `master` and published to crates.io. Only
`x509-validator` is published; `x509-validator-testkit`, `examples`, and
`x509-validator-bench` are workspace-internal and never shipped.

### Pre-publish checks

1. `master` is green and up to date locally.
2. `./admin/check` passes (see [Before you push](#before-you-push)).
3. Bump `version` in `x509-validator/Cargo.toml`, following
   [SemVer](https://semver.org/). A breaking change to the public API needs a
   major bump; check the crate's current major version (`0.x` breaking
   changes bump the minor).
4. Update `CHANGELOG.md`: rename the top (unreleased) entry to the new
   version and today's date, grouped under `### Added` / `### Changed` /
   `### Fixed` / `### Removed` as applicable.
5. Run `cargo package -p x509-validator --features aws_lc,ring,rust_crypto`
   and check the file list it prints — `exclude = ["tests/**"]` in
   `Cargo.toml` is what keeps test fixtures out of the published crate, and
   this is the point to notice if that's drifted.
6. Run `cargo publish -p x509-validator --dry-run --features aws_lc` (each
   backend feature is optional, so the dry run only needs one to compile).

### Publishing

```sh
git commit -am "chore: Release x509-validator vX.Y.Z"
git vX.Y.Z
git push origin master --tags
cargo publish -p x509-validator
```

### After publishing

- Confirm the new version is live on
  [crates.io](https://crates.io/crates/x509-validator) and that
  [docs.rs](https://docs.rs/x509-validator) has built it.
- Open a new empty `### Unreleased` section at the top of `CHANGELOG.md` for
  the next round of changes.
- Create a GitHub release from the tag, using the changelog entry as the
  description.

Thank you for contributing!

