#!/usr/bin/env python3
"""Generate the complete Rust/upstream conformance coverage ledger."""

from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any


CONFORMANCE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = CONFORMANCE_DIR.parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--upstream-dir",
        type=Path,
        help="read PARITY_MATRIX.json from an upstream conformance checkout",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=CONFORMANCE_DIR / "COVERAGE.md",
        help="ledger destination (default: conformance/COVERAGE.md)",
    )
    return parser.parse_args()


def read_source() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in (CONFORMANCE_DIR / "SOURCE").read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise ValueError(f"malformed SOURCE line: {raw_line!r}")
        values[key] = value
    for required in ("upstream_repo", "upstream_sha", "fetched_at"):
        if not values.get(required):
            raise ValueError(f"SOURCE is missing {required}")
    return values


def read_tracked_files() -> set[str]:
    tracked = {
        line
        for raw_line in (CONFORMANCE_DIR / "TRACKED_FILES").read_text().splitlines()
        if (line := raw_line.strip()) and not line.startswith("#")
    }
    for path in tracked:
        if path.startswith("/") or ".." in Path(path).parts:
            raise ValueError(f"unsafe tracked path: {path}")
        if not (CONFORMANCE_DIR / path).is_file():
            raise ValueError(f"tracked file is missing locally: {path}")
    return tracked


def load_matrix(source: dict[str, str], upstream_dir: Path | None) -> dict[str, Any]:
    if upstream_dir is not None:
        return json.loads((upstream_dir / "PARITY_MATRIX.json").read_text())

    url = (
        "https://raw.githubusercontent.com/"
        f"{source['upstream_repo']}/{source['upstream_sha']}"
        "/conformance/PARITY_MATRIX.json"
    )
    with urllib.request.urlopen(url) as response:
        return json.load(response)


def load_runner_coverage(tracked: set[str]) -> dict[str, dict[str, Any]]:
    coverage = json.loads((CONFORMANCE_DIR / "RUST_RUNNERS.json").read_text())
    for vector_path, record in coverage.items():
        if vector_path not in tracked:
            raise ValueError(f"runner coverage references an untracked file: {vector_path}")

        runner_path = REPO_ROOT / record["runner"]
        if not runner_path.is_file():
            raise ValueError(f"runner does not exist: {record['runner']}")
        include_path = f"../conformance/{vector_path}"
        if include_path not in runner_path.read_text():
            raise ValueError(
                f"{record['runner']} does not include tracked vector {vector_path}"
            )

        vector_file = json.loads((CONFORMANCE_DIR / vector_path).read_text())
        vector_ids = {vector["id"] for vector in vector_file["vectors"]}
        skipped_ids = record.get("skipped_ids", [])
        if len(skipped_ids) != len(set(skipped_ids)):
            raise ValueError(f"duplicate skipped ID for {vector_path}")
        unknown_ids = set(skipped_ids) - vector_ids
        if unknown_ids:
            raise ValueError(f"unknown skipped IDs for {vector_path}: {unknown_ids}")
    return coverage


def runner_link(runner_path: str) -> str:
    name = Path(runner_path).name
    return f"[`{name}`](../{runner_path})"


def generate() -> str:
    args = parse_args()
    source = read_source()
    tracked = read_tracked_files()
    matrix = load_matrix(source, args.upstream_dir)
    runner_coverage = load_runner_coverage(tracked)

    files = matrix["files"]
    upstream_paths = {f"vectors/{entry['path']}" for entry in files}
    tracked_vectors = {path for path in tracked if path.startswith("vectors/")}
    unknown_tracked = tracked_vectors - upstream_paths
    if unknown_tracked:
        raise ValueError(f"tracked vectors absent from PARITY_MATRIX: {unknown_tracked}")

    matrix_total = sum(entry["total_vectors"] for entry in files)
    summary_total = matrix["summary"]["total_vectors"]
    if len(files) != matrix["summary"]["total_files"] or matrix_total != summary_total:
        raise ValueError("PARITY_MATRIX summary does not match its file rows")

    evaluation = next(
        (entry for entry in files if entry["path"] == "sdk/scripts/evaluation.json"),
        None,
    )
    if evaluation is None or evaluation["total_vectors"] != 5116:
        raise ValueError("sdk/scripts/evaluation.json scope denominator changed")

    vendored_total = 0
    asserted_total = 0
    skipped_total = 0
    rows: list[str] = []

    for entry in files:
        path = f"vectors/{entry['path']}"
        count = entry["total_vectors"]
        vendored = path in tracked_vectors
        if vendored:
            local_count = len(json.loads((CONFORMANCE_DIR / path).read_text())["vectors"])
            if local_count != count:
                raise ValueError(
                    f"vector count mismatch for {path}: local {local_count}, upstream {count}"
                )
            vendored_total += count

        runner = runner_coverage.get(path)
        if runner is None:
            runner_cell = "—"
            asserted = 0
        else:
            runner_cell = runner_link(runner["runner"])
            asserted = count - len(runner.get("skipped_ids", []))

        skipped = count - asserted
        asserted_total += asserted
        skipped_total += skipped
        rows.append(
            "| "
            f"`{path}` | {count} | `{entry['file_level_parity']}` | "
            f"`{entry['reason_category']}` | {'yes' if vendored else 'no'} | "
            f"{runner_cell} | {asserted} | {skipped} |"
        )

    if asserted_total + skipped_total != matrix_total:
        raise ValueError("asserted/skipped totals do not cover the upstream corpus")

    lines = [
        "# Conformance coverage",
        "",
        "<!-- Generated by conformance/scripts/generate-coverage.py; do not edit by hand. -->",
        "",
        (
            "This ledger compares the Rust harness with "
            f"`{source['upstream_repo']}@{source['upstream_sha']}` "
            f"(fetched {source['fetched_at']}). It includes every upstream vector file, "
            "including files this repository neither vendors nor runs."
        ),
        "",
        (
            "`Asserted` counts vectors executed by a Rust runner, including explicit "
            "known-divergence assertions. `Skipped` is the complement: governed skips "
            "inside a runner plus every vector with no Rust runner. Repository-local "
            "vectors under `test-vectors/` are outside the upstream total."
        ),
        "",
        (
            "**Deliberate scope exclusion:** `vectors/sdk/scripts/evaluation.json` "
            f"contains **{evaluation['total_vectors']:,} vectors** and is not vendored or "
            "asserted here. Script evaluation is a separate scope decision; its full "
            "count remains in the denominator and in the table below."
        ),
        "",
        "Regenerate from the pinned upstream metadata:",
        "",
        "```sh",
        "./conformance/scripts/generate-coverage.py",
        "```",
        "",
        "| Upstream vector file | Vectors | Parity class | Reason category | Vendored | Rust runner | Asserted | Skipped |",
        "|---|---:|---|---|:---:|---|---:|---:|",
        *rows,
        (
            f"| **Total** | **{matrix_total:,}** |  |  | "
            f"**{vendored_total:,} vectors** |  | **{asserted_total:,}** | "
            f"**{skipped_total:,}** |"
        ),
        "",
        (
            f"**Totals:** **{vendored_total:,} of {matrix_total:,}** upstream vectors "
            f"vendored; **{asserted_total:,} asserted** by Rust runners; "
            f"**{skipped_total:,} currently skipped or unasserted**."
        ),
        "",
    ]
    args.output.write_text("\n".join(lines))
    return (
        f"Wrote {args.output}: {vendored_total}/{matrix_total} vendored, "
        f"{asserted_total} asserted, {skipped_total} skipped"
    )


if __name__ == "__main__":
    print(generate())
