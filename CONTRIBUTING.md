# Contributing to X509Validator

Thank you for your interest in contributing to X509Validator! This document
provides guidelines and instructions for contributing.

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting started

The workspace builds on stable Rust, edition 2024, and needs 1.85 or newer.

```sh
git clone https://github.com/namecare/x509-validator
cd x509-validator
cargo test -p x509-validator --features aws_lc --all-targets
```

The workspace also holds `x509-validator-testkit` (certificate-building
helpers for tests, never shipped), `examples`, and `x509-validator-bench`.

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

Also worth doing before you push:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets
```

## Testing requirements

All contributions should include appropriate tests.

Thank you for contributing!

