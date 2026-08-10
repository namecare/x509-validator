# Security Policy

## Report a security issue

The X509Validator project team welcomes security reports and is committed to
providing prompt attention to security issues.

**Please do not open a public issue for a vulnerability.** Report privately
through either channel:

- [GitHub Security Advisories](https://github.com/namecare/x509-validator/security/advisories/new) — preferred, since the report, the discussion, and the eventual advisory stay in one place.
- Email [support@namecare.app](mailto:support@namecare.app).

There is no bug bounty.

A useful report includes the version, the crypto backend feature in use
(`aws_lc`, `ring`, or `rust_crypto`), the platform, and what an attacker
gains.

Minor issues with no exploitable consequence — a documentation error, a
confusing API — are fine to file on the public
[issue tracker](https://github.com/namecare/x509-validator/issues).

## Advisories

The project team is committed to transparency in the security issue disclosure
process. Fixes are announced in the
[release notes](https://github.com/namecare/x509-validator/releases) and the
[CHANGELOG](CHANGELOG.md), published as a
[GitHub Security Advisory](https://github.com/namecare/x509-validator/security/advisories),
and filed with the
[RustSec advisory database](https://github.com/RustSec/advisory-db) so that
`cargo audit` picks them up.