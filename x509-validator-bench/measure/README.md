# x509-validator-bench-measure

Regression benchmarks

Uses [criterion](https://github.com/bheisler/criterion.rs), which tracks history between runs and is what CI benchmark services ingest.

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

## CI

`.github/workflows/benchmarks.yml` runs this suite on the self-hosted
`ubuntu-runner` and posts a delta table on every pull request. It never fails
the build.

### The report

`.github/scripts/criterion-report.py` reads criterion's JSON
(`new/estimates.json`, `change/estimates.json`) rather than parsing `cargo
bench` stdout, which is formatted for humans and reworded between versions.

A benchmark is flagged only when the change clears **both** tests: at least
10% (`REGRESSION_THRESHOLD`), and a confidence interval excluding zero.

The script takes `--since <epoch>` and ignores any benchmark directory not
rewritten by the current run. `target/criterion/` is never cleared on a
persistent runner.

Run it locally against your own last two runs:

    cargo bench -p x509-validator-bench-measure -- --save-baseline before
    # ...change something...
    cargo bench -p x509-validator-bench-measure -- --baseline before
    python3 .github/scripts/criterion-report.py


## Fixtures

The certificates live in `x509-validator-testkit`.