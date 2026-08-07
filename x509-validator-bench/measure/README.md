# x509-validator-bench-measure

Regression benchmarks: **did our own code get slower?** Not published.

Where the `compare` crate ranks backends and parsers against each other, this
one holds every axis it can still — one backend, one fixed reference time — so
that a change in a number means a change in our code and not in the
environment. Uses [criterion](https://github.com/bheisler/criterion.rs),
which tracks history between runs and is what CI benchmark services ingest.

## Running

    cargo bench -p x509-validator-bench-measure                 # everything
    cargo bench -p x509-validator-bench-measure --bench verifier
    cargo bench -p x509-validator-bench-measure -- --test       # run once, don't measure

Criterion saves each run under `target/criterion/` and reports the delta
against the previous one, so a local before/after is just two runs with the
change in between.

## What is covered

| Bench | Benchmarks | Notes |
|---|---|---|
| `verifier` | 16 scenarios + 1 rollup | parity with the reference implementation |
| `policies` | 11 | every `VerifierPolicy` impl, plus the three identity-matching paths |
| `parse` | 2 | DER parsing over the vendored WebPKI roots |

### Verifier parity

`benches/verifier.rs` mirrors the reference implementation's verifier
benchmark case for case: the same twelve successful and four unsuccessful
scenarios, over fixtures built to the same specification.

It departs from the reference in one deliberate way. The reference runs all
sixteen scenarios as a single measured blob; that is a serviceable canary but
a poor gate, because one number that moves does not say *which* scenario
moved. Here each scenario is its own benchmark, and the blob is kept as
`verifier/all_scenarios` so the reference figure stays comparable.

### Policies

All nine `VerifierPolicy` implementations, plus `ServerIdentityPolicy`'s three
matching paths measured separately: exact DNS, wildcard, and IP. The wildcard
path is the one the implementation itself describes as expensive, and neither
it nor the IP path was measured before — which made them the likeliest places
for a regression to pass unnoticed.

Policy evaluation costs tens of nanoseconds against crypto's hundreds of
microseconds. That gap is exactly why these are benched directly rather than
through the verifier: a policy regression would be invisible in an end-to-end
number.

## Rules

**Benchmark ids are the tracked metric names.** Renaming one starts a fresh
metric with no history — the one way a regression suite quietly stops working.
Treat the strings in `bench_function` as fixed.

**One backend.** `BACKEND` in `src/lib.rs` selects aws-lc-rs by default.
Crypto is the dominant cost of validation, so this choice sets the absolute
scale of every number here; switching it restarts the history.

**Store construction is not timed.** `CertificateStore::from_iter` allocates a
`HashMap` and a subject key per certificate. That is setup, not validation, so
it happens in criterion's batched setup phase. (This is why these figures are
not comparable to the pre-split suite's, which timed it.)

## Correctness

`tests/verifier_scenarios.rs` asserts that all sixteen scenarios actually
produce the outcome their names claim. This is not incidental: a scenario that
quietly returns the wrong `ChainValidationResultOwned` variant still benchmarks
*something*, just not the thing it is named after, and the parity claim becomes
meaningless.

These live in `tests/` rather than as `#[test]` fns inside the bench files,
because `harness = false` means an in-file test would never run.

    cargo test -p x509-validator-bench-measure

## CI

Not yet wired up. Criterion was chosen partly because the services that track
Rust benchmarks over time read its output, but no gate is configured.

Worth knowing before adding one: no comparable Rust crypto or PKI project
gates pull requests on wall-clock benchmarks. rustls — which invests more in
benchmarking than anyone in this space — runs on dedicated bare metal with
Turbo Boost and hyper-threading disabled, and still only *comments* results on
PRs rather than blocking them. ring, rustls-webpki, RustCrypto and quinn do no
regression detection at all, only a job that proves the benches still compile.
Given that crypto dominates these numbers, a wall-clock gate on a shared CI
runner would alert on noise.

The pragmatic first step is a smoke job (`cargo bench -- --test`) so the
benches cannot rot, with trend tracking added later if it earns its keep.

## Fixtures

The parity certificates live in `x509-validator-testkit` (`bench_fixtures`),
shared with the `compare` crate so both build against one specification. The
reference implementation generates its certificates from fresh randomness on
each launch, so there is no fixed data to reproduce — what is fixed there is
the specification (key algorithms, validity windows, extension shapes), and
that is what is matched.
