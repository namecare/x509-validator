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

## HTML report

Every run writes plots and an index page. Open it with:

    open target/criterion/report/index.html      # macOS
    xdg-open target/criterion/report/index.html  # Linux

The index links every benchmark; each one gets a page with its probability
density, iteration-time scatter, and — once there is a previous run to compare
against — a before/after plot. Useful for telling a real regression from a
noisy sample, since the distribution shows the outliers the summary line hides.

Note the directory names are flattened: `verifier/trivial_chain_building`
becomes `target/criterion/verifier_trivial_chain_building/`.

Comparison plots need two runs, so the first run after `cargo clean` shows
none. Baselines work with the report too:

    cargo bench -p x509-validator-bench-measure -- --save-baseline before
    # ...change something...
    cargo bench -p x509-validator-bench-measure -- --baseline before

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

`.github/workflows/benchmarks.yml` runs this suite on the self-hosted
`ubuntu-runner` and posts a delta table on every pull request. It never fails
the build.

That last point is deliberate. No comparable Rust crypto or PKI project gates
pull requests on wall-clock benchmarks. rustls — which invests more in
benchmarking than anyone in this space — runs on dedicated bare metal with
Turbo Boost and hyper-threading disabled, and still only *comments* results on
PRs rather than blocking them. ring, rustls-webpki, RustCrypto and quinn do no
regression detection at all. Since crypto dominates these numbers, a
wall-clock gate would alert on noise more often than on regressions.

### How the comparison works

Criterion detects regressions on its own, but only against baselines it finds
in `target/criterion/`. A hosted runner starts empty, so there is nothing to
compare against and every run reports "no change" — which is why services like
Bencher exist. The self-hosted runner removes that problem: its workspace
persists, so a baseline stays put between jobs.

    push to master   cargo bench -- --save-baseline master
    pull request     cargo bench -- --baseline-lenient master

So every PR is compared against master's numbers **on the same physical
machine**. `--baseline-lenient` rather than `--baseline` so that a newly added
benchmark, which has no entry in the stored baseline, is reported as new
instead of failing the run.

Jobs are serialized through a `concurrency` group. Two benchmark jobs sharing
one `target/criterion/` would overwrite each other's baselines, which corrupts
the comparison rather than merely slowing it down.

### The report

`.github/scripts/criterion-report.py` reads criterion's JSON
(`new/estimates.json`, `change/estimates.json`) rather than parsing `cargo
bench` stdout, which is formatted for humans and reworded between versions.

A benchmark is flagged only when the change clears **both** tests: at least
10% (`REGRESSION_THRESHOLD`), and a confidence interval excluding zero. Either
test alone misreports. Percentage alone flags jitter in the nanosecond-scale
policy benchmarks — `policy/version` is ~3 ns, where half a nanosecond of
drift is 15%. Significance alone flags a rock-steady 0.5% shift nobody can act
on.

The script takes `--since <epoch>` and ignores any benchmark directory not
rewritten by the current run. `target/criterion/` is never cleared on a
persistent runner, so a renamed, removed, or unselected benchmark otherwise
keeps reporting its last known numbers indefinitely — a failure that shows up
only on a persistent runner, which is what makes it easy to miss.

Run it locally against your own last two runs:

    cargo bench -p x509-validator-bench-measure -- --save-baseline before
    # ...change something...
    cargo bench -p x509-validator-bench-measure -- --baseline before
    python3 .github/scripts/criterion-report.py

The full HTML report is uploaded as a build artifact for 14 days. The table
says a number moved; the density and iteration plots are how you tell a real
shift from a couple of outliers.

## Fixtures

The parity certificates live in `x509-validator-testkit` (`bench_fixtures`),
shared with the `compare` crate so both build against one specification. The
reference implementation generates its certificates from fresh randomness on
each launch, so there is no fixed data to reproduce — what is fixed there is
the specification (key algorithms, validity windows, extension shapes), and
that is what is matched.
