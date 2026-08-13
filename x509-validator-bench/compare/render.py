#!/usr/bin/env python3
"""Renders `.output/` into RESULTS.md.

`run.sh` saves each bench target's console output verbatim and does not
interpret it. This script is the interpreting half: it reads those raw files
back, pulls the median out of every row, and emits the comparison tables.
"""

from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(HERE, ".output")
OUT_PATH = os.path.join(HERE, "RESULTS.md")

# Rust arms, in the order their columns should appear. `run.sh` compiles all
# three crypto backends in, so all three normally report.
BACKENDS = ["aws_lc", "ring", "rust_crypto"]
BACKEND_LABEL = {
    "aws_lc": "aws-lc-rs",
    "ring": "ring",
    "rust_crypto": "RustCrypto",
}

PARSER_LABEL = {
    "x509_cert": "x509-cert",
    "x509_parser": "x509-parser",
    "openssl": "OpenSSL",
}

VERIFIER_LABEL = {
    "ours_aws_lc": "ours (aws-lc-rs)",
    "ours_ring": "ours (ring)",
    "ours_rust_crypto": "ours (RustCrypto)",
    "rustls_webpki": "rustls-webpki",
    "openssl": "OpenSSL",
}

# package-benchmark already reports time per operation: `scalingFactor: .kilo`
# scales the units it prints, and `benchmark.scaledIterations` supplies the
# matching loop, so the two cancel. The p50 is therefore directly comparable to
# a Divan median and needs no rescaling here.
#
# Worth stating because the opposite reading is tempting and wrong: treating a
# sample as 1000 operations and dividing puts Swift's whole 16-scenario sweep
# at ~5.5 µs — less time than Rust's single cheapest scenario, and 40× under
# Rust's fastest full sweep. That is not a result, it is a unit error.


# ---------------------------------------------------------------------------
# Divan console output
# ---------------------------------------------------------------------------


def parse_divan(path: str) -> dict[tuple[str, ...], float]:
    """Divan's console table -> {(path, through, the, tree): median_ns}.

    The table is a box-drawing tree whose depth is carried by indentation, and
    whose leaf rows hold the timings:

        internals              fastest   │ slowest   │ median    │ ...
        ├─ backend                       │           │           │
        │  ├─ aws_lc                     │           │           │
        │  │  ├─ apple_receipt  303 µs   │ 374.8 µs  │ 325.3 µs  │ ...

    """
    rows: dict[tuple[str, ...], float] = {}
    if not os.path.exists(path):
        return rows

    stack: list[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if "│" not in line:
                continue

            # Measure the indent on the raw line. The prefix is box drawing and
            # spaces only; it ends at the first character that starts a name.
            match = re.match(r"^((?:[ │]|├─ |╰─ )*)(\S.*)$", line)
            if not match:
                continue
            prefix, rest = match.group(1), match.group(2)
            depth = len(prefix) // 3

            # Now split the REMAINDER into timing columns. The name and
            # `fastest` share the first field, separated by a run of 2+ spaces.
            columns = rest.split("│")
            if len(columns) < 6:
                continue
            name = re.split(r"\s{2,}", columns[0].strip())[0].strip()
            if not name:
                continue

            del stack[depth:]
            stack.append(name)

            ns = parse_duration(columns[2])
            if ns is not None:
                rows[tuple(stack)] = ns

    return rows


def parse_duration(cell: str) -> float | None:
    """"142.9 µs" -> 142900.0. Divan auto-scales the unit per row."""
    parts = cell.split()
    if len(parts) != 2:
        return None
    try:
        value = float(parts[0])
    except ValueError:
        return None
    scale = {"ns": 1.0, "µs": 1e3, "us": 1e3, "ms": 1e6, "s": 1e9}.get(parts[1])
    return value * scale if scale else None


# ---------------------------------------------------------------------------
# package-benchmark console output
# ---------------------------------------------------------------------------


def parse_swift(path: str) -> dict[str, float]:
    """package-benchmark's console tables -> {benchmark_name: ns_per_op}.

    Each benchmark prints a title line, then a boxed percentile table:

        Verifier
        ╒══════════╤══════╤══════╤══════╤ ...
        │ Metric   │   p0 │  p25 │  p50 │ ...
        ╞══════════╪══════╪══════╪══════╪ ...
        │ Time (wall clock) (μs) * │ 5545 │ 5549 │ 5549 │ ...

    p50 is taken as the median, to match the median column read off Divan. The
    unit is parsed out of the metric cell rather than assumed, and the value is
    used as-is — see the note by the imports on why it is not rescaled.

    The title is whatever non-empty line last preceded the box, which is how
    a benchmark's name is recovered — the table itself does not carry it.
    """
    results: dict[str, float] = {}
    if not os.path.exists(path):
        return results

    title: str | None = None
    header: list[str] = []

    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            # The run emits ANSI progress bars; strip them so the leftovers do
            # not masquerade as titles.
            line = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw).rstrip()
            stripped = line.strip()
            if not stripped:
                continue

            if stripped.startswith(("╒", "╞", "╘", "═")):
                continue

            if stripped.startswith("│"):
                cells = [c.strip() for c in stripped.strip("│").split("│")]
                if cells and cells[0] == "Metric":
                    header = cells
                    continue
                if not header or title is None:
                    continue
                # "Time (wall clock) (μs) *" — anything else (throughput,
                # allocations) is not comparable to a Divan median.
                metric = cells[0]
                if not metric.startswith("Time (wall clock)"):
                    continue
                unit_match = re.search(r"\((\wμµ*s|\w+s)\)", metric)
                unit = unit_match.group(1) if unit_match else "ns"
                scale = {
                    "ns": 1.0,
                    "μs": 1e3,
                    "µs": 1e3,
                    "us": 1e3,
                    "ms": 1e6,
                    "s": 1e9,
                }.get(unit)
                if scale is None or "p50" not in header:
                    continue
                try:
                    p50 = float(cells[header.index("p50")])
                except (ValueError, IndexError):
                    continue
                results[title] = p50 * scale
                continue

            # A plain line resets the pending title; the last one before a box
            # is that box's benchmark.
            header = []
            title = stripped

    return results


# ---------------------------------------------------------------------------
# formatting
# ---------------------------------------------------------------------------


def format_ns(ns: float) -> str:
    """Pick a unit per value, so a 3.2 µs row and a 1.06 ms row both read cleanly."""
    if ns < 1_000:
        return f"{ns:.1f} ns"
    if ns < 1_000_000:
        return f"{ns / 1_000:.2f} µs"
    return f"{ns / 1_000_000:.2f} ms"


def format_ratio(subject: float | None, baseline: float | None) -> str:
    """Describe `subject` as a speed multiple of `baseline`.

    The verdict is always about the SUBJECT — "2.01× faster" means the subject
    is faster than the baseline. Both are durations, so the smaller one wins;
    getting the arguments backwards silently inverts the claim while leaving
    the magnitude right, which is the hardest kind of error to spot in a
    rendered table. Pass the column the header names first.

    The direction is spelled out rather than left as a bare "2.01×", so a
    reader never has to work out which way it points.
    """
    if not subject or not baseline:
        return "—"
    if subject <= baseline:
        return f"**{baseline / subject:.2f}× faster**"
    return f"{subject / baseline:.2f}× slower"


def table(header: list[str], rows: list[list[str]]) -> list[str]:
    """A Markdown table, first column left-aligned and the rest right-aligned."""
    align = ["---"] + ["---:"] * (len(header) - 1)
    lines = ["| " + " | ".join(header) + " |",
             "| " + " | ".join(align) + " |"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return lines


def pivot(
    measurements: dict[tuple[str, ...], float],
    group: str,
    arms: list[str],
    labels: dict[str, str],
) -> tuple[list[str], list[str], list[list[str]]]:
    """Turn one Divan subtree into (arms_present, workloads, table_rows).

    Handles both shapes Divan produces under a group: `group/arm/workload`
    (three levels, as in `internals`'s backends) and `group/arm` with no
    workload beneath it (two levels, as in `verifiers`). The flat case is
    modelled as a single unnamed workload so one code path renders both.
    """
    cells: dict[str, dict[str, float]] = {}
    workloads: list[str] = []

    for path, ns in measurements.items():
        if len(path) < 3 or path[1] != group:
            continue
        arm = path[2]
        workload = path[3] if len(path) > 3 else ""
        cells.setdefault(workload, {})[arm] = ns
        if workload not in workloads:
            workloads.append(workload)

    present = [a for a in arms if any(a in row for row in cells.values())]
    present += sorted(
        {a for row in cells.values() for a in row} - set(present)
    )

    rows: list[list[str]] = []
    for workload in workloads:
        row = [f"`{workload}`" if workload else "—"]
        row += [
            format_ns(cells[workload][arm]) if arm in cells[workload] else "—"
            for arm in present
        ]
        if len(present) >= 2:
            # The column is headed "Fastest vs next", so the winner is the
            # subject and the runner-up is the baseline. Naming the winner
            # matters once there are three or more columns: the margin alone
            # does not say which arm earned it.
            ranked = sorted(cells[workload].items(), key=lambda kv: kv[1])
            if len(ranked) >= 2:
                (winner, best), (_, runner_up) = ranked[0], ranked[1]
                row.append(
                    f"{labels.get(winner, winner)} "
                    f"{format_ratio(best, runner_up)}"
                )
            else:
                row.append("—")
        rows.append(row)

    return present, workloads, rows


# ---------------------------------------------------------------------------
# the individual comparison sections
# ---------------------------------------------------------------------------


def section_backends(internals: dict[tuple[str, ...], float]) -> list[str]:
    """`internals`/`backend` — full validation, one column per crypto backend."""
    arms, _, rows = pivot(internals, "backend", BACKENDS, BACKEND_LABEL)
    if not rows:
        return []
    header = ["Chain"] + [BACKEND_LABEL.get(a, a) for a in arms]
    if len(arms) >= 2:
        header.append("Fastest vs next")
    doc = ["## Backends", "",
           "End-to-end validation with only the crypto backend swapped. This "
           "is the number that decides which backend a consumer should "
           "compile in.", "",
           "Two chains of identical shape — leaf → intermediate → root, two "
           "signature verifications each — differing only in the curve of the "
           "issuer keys that do the verifying:", "",
           "- `p256_chain` — a generated all-P-256 chain. Every backend has a "
           "dedicated P-256 implementation, so this is the fast curve.",
           "- `apple_receipt_p384` — Apple's real receipt-signing chain "
           "(leaf → WWDR G6 → Apple Root CA - G3). The leaf is P-256, but a "
           "certificate is verified with its *issuer's* key, and both the "
           "intermediate and root are P-384 — so both verifications are P-384.",
           "",
           "Comparing the two rows for one backend isolates the curve, since "
           "nothing else about the work differs.", ""]
    doc += table(header, rows)
    doc.append("")
    return doc


def section_atomics(internals: dict[tuple[str, ...], float]) -> list[str]:
    """`internals`/`crypto_atomics` — one signature verification per row."""
    arms, _, rows = pivot(internals, "crypto_atomics", BACKENDS, BACKEND_LABEL)
    if not rows:
        return []
    header = ["Operation"] + [BACKEND_LABEL.get(a, a) for a in arms]
    if len(arms) >= 2:
        header.append("Fastest vs next")
    doc = ["## Crypto primitives", "",
           "A single signature verification per row, with the chain-building "
           "and parsing removed. Where the backend table shows which backend "
           "wins overall, this shows which operations it wins on.", ""]
    doc += table(header, rows)
    doc.append("")
    return doc


def section_validate(internals: dict[tuple[str, ...], float]) -> list[str]:
    """`internals`/`validate` — the cost of asking for diagnostics."""
    plain = internals.get(("internals", "validate", "validate"))
    diagnostics = internals.get(("internals", "validate", "validate_with_diagnostics"))
    if plain is None or diagnostics is None:
        return []
    doc = ["## Diagnostics overhead", "",
           "`validate` against `validate_with_diagnostics` on the same chain: "
           "what collecting the diagnostic trail costs on a validation that "
           "succeeds.", ""]
    doc += table(
        ["Entry point", "Median", "vs `validate`"],
        [["`validate`", format_ns(plain), "—"],
         ["`validate_with_diagnostics`", format_ns(diagnostics),
          format_ratio(diagnostics, plain)]],
    )
    doc.append("")
    return doc


def section_parsers(parsers: dict[tuple[str, ...], float]) -> list[str]:
    """`parsers` — each parser crate against the others, per operation."""
    doc: list[str] = []
    intro = {
        "full_parse": "Parsing a certificate and walking its extensions.",
        "read_san": "Parsing far enough to read the subjectAltName, the "
                    "access pattern hostname verification actually uses.",
    }
    for group in ("full_parse", "read_san"):
        arms, _, rows = pivot(parsers, group, list(PARSER_LABEL), PARSER_LABEL)
        if not rows:
            continue
        header = ["Corpus"] + [PARSER_LABEL.get(a, a) for a in arms]
        if len(arms) >= 2:
            header.append("Fastest vs next")
        doc += [f"### `{group}`", "", intro.get(group, ""), ""]
        doc += table(header, rows)
        doc.append("")
    if doc:
        doc = ["## Parsers", "",
               "The parser crate we build on against the alternatives, on the "
               "same certificates.", ""] + doc
    return doc


def section_verifiers(verifiers: dict[tuple[str, ...], float]) -> list[str]:
    """`verifiers` — our validator against other Rust verifiers."""
    doc: list[str] = []
    for group in ("apple_chain", "tls_fixture"):
        arms, _, rows = pivot(verifiers, group, list(VERIFIER_LABEL), VERIFIER_LABEL)
        if not rows:
            continue
        header = ["Verifier", "Median"]
        # This subtree is flat — arm names are the rows, not the columns — so
        # the generic pivot's single "—" workload row is transposed here.
        body = [[VERIFIER_LABEL.get(arm, arm), cell]
                for arm, cell in zip(arms, rows[0][1:])]
        fastest = min(
            (v for v in (parse_back(c) for _, c in body) if v is not None),
            default=None,
        )
        if fastest is not None:
            header.append("vs fastest")
            for row in body:
                value = parse_back(row[1])
                row.append("**fastest**" if value == fastest
                           else format_ratio(value, fastest))
        doc += [f"### `{group}`", ""]
        doc += table(header, body)
        doc.append("")
    if doc:
        doc = ["## Verifiers", "",
               "Our validator against the other Rust path-building verifiers, "
               "on identical chains.", ""] + doc
    return doc


def parse_back(cell: str) -> float | None:
    """Read a formatted duration cell back to ns, for ranking already-built rows."""
    return parse_duration(cell.replace("**", ""))


def section_rust_vs_swift(
    rust: dict[tuple[str, ...], float],
    parsers: dict[tuple[str, ...], float],
    swift: dict[str, float],
) -> list[str]:
    """The port against the original, on the two workloads Swift measures.

    The Swift package benchmarks only two things, and neither lines up with a
    single Rust row:

    - `Verifier` runs all sixteen validation scenarios inside one iteration,
      so its counterpart is the SUM of the sixteen `rust_vs_swift` rows, not
      any one of them.
    - `Parse WebPKI Roots from DER` parses the whole Mozilla bundle and counts
      each certificate's extensions, which is what `parsers/full_parse`'s
      `webpki_roots` corpus does. Both parser crates are shown, since the
      choice of crate is exactly what that row is measuring.

    The per-scenario Rust rows are listed after the comparison. They have no
    Swift counterpart to sit beside, but they are what the summed figure is
    made of, so they are shown as a breakdown rather than dropped.
    """
    scenarios = {path[1]: ns for path, ns in rust.items() if len(path) == 2}
    doc: list[str] = []

    rows: list[list[str]] = []
    if scenarios and "Verifier" in swift:
        total = sum(scenarios.values())
        rows.append([
            f"All {len(scenarios)} validation scenarios",
            format_ns(total),
            format_ns(swift["Verifier"]),
            format_ratio(total, swift["Verifier"]),
        ])

    roots_label = "Parse WebPKI Roots from DER"
    if roots_label in swift:
        for crate in ("x509_cert", "x509_parser"):
            ns = parsers.get(("parsers", "full_parse", crate, "webpki_roots"))
            if ns is None:
                continue
            rows.append([
                f"Parse the WebPKI roots ({PARSER_LABEL[crate]})",
                format_ns(ns),
                format_ns(swift[roots_label]),
                format_ratio(ns, swift[roots_label]),
            ])

    if rows:
        doc += ["## Rust against Swift", "",
                "This port against the original swift-certificates, on the two "
                "workloads both sides measure. Rust figures are Divan "
                "medians, Swift figures package-benchmark p50 wall clock; "
                "both are already per operation.", "",
                "> Numbers from a parallel `./run.sh` are not comparable across "
                "languages — the two suites contend for the same cores. Use "
                "`./run.sh --sequential` when this table is the point.", ""]
        doc += table(["Workload", "Rust", "Swift", "Rust vs Swift"], rows)
        doc.append("")

    if scenarios:
        doc += ["### Rust scenario breakdown", "",
                "The individual scenarios summed into the row above. Swift "
                "measures them only in aggregate, so there is no per-scenario "
                "column to compare against.", ""]
        doc += table(
            ["Scenario", "Rust"],
            [[f"`{name}`", format_ns(ns)]
             for name, ns in sorted(scenarios.items(), key=lambda kv: -kv[1])],
        )
        doc.append("")

    return doc


# ---------------------------------------------------------------------------


def main() -> int:
    if not os.path.isdir(OUTPUT_DIR):
        print(f"error: no {OUTPUT_DIR}; run ./run.sh first", file=sys.stderr)
        return 1

    internals = parse_divan(os.path.join(OUTPUT_DIR, "internals.txt"))
    parsers = parse_divan(os.path.join(OUTPUT_DIR, "parsers.txt"))
    verifiers = parse_divan(os.path.join(OUTPUT_DIR, "verifiers.txt"))
    rust_vs_swift = parse_divan(os.path.join(OUTPUT_DIR, "rust_vs_swift.txt"))
    swift = parse_swift(os.path.join(OUTPUT_DIR, "swift.txt"))

    doc = ["# Comparison results", "",
           "Generated from `.output/` by `render.py`. Regenerate the raw "
           "numbers with `./run.sh`, then re-render with `python3 render.py`.",
           "",
           "Every figure is a median. Rust medians come from Divan's `median` "
           "column; Swift's come from package-benchmark's p50.", ""]

    sections = [
        section_backends(internals),
        section_atomics(internals),
        section_validate(internals),
        section_parsers(parsers),
        section_verifiers(verifiers),
        section_rust_vs_swift(rust_vs_swift, parsers, swift),
    ]

    missing = []
    for name, parsed in (("internals", internals), ("parsers", parsers),
                         ("verifiers", verifiers),
                         ("rust_vs_swift", rust_vs_swift), ("swift", swift)):
        if not parsed:
            missing.append(name)

    for section in sections:
        doc += section

    if missing:
        doc += ["## Missing arms", "",
                "These targets produced no parseable rows; their tables are "
                "absent above. Check `.output/` for a build or run failure.", ""]
        doc += [f"- `{name}`" for name in missing]
        doc.append("")

    text = "\n".join(doc)
    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        fh.write(text)

    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
