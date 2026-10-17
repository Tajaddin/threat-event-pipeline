#!/usr/bin/env python3
"""Render load/results/latest.json as the Markdown table the README shows.

    python load/render-results.py                   # print the table
    python load/render-results.py --write README.md # replace the block between the LOAD-RESULTS markers
"""

import json
import pathlib
import sys

START, END = "<!-- LOAD-RESULTS -->", "<!-- /LOAD-RESULTS -->"


def render(path: pathlib.Path) -> str:
    run = json.loads(path.read_text(encoding="utf-8"))
    rows = [
        "| Target events/s | Achieved at ingest | Enriched/s | Detected/s | Indexed/s | Max consumer lag | Detection p95 | Detection p99 | Alerts/s |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for s in run["steps"]:
        rows.append(
            "| {target_eps:,} | {achieved_eps:,.0f} | {enrich_eps:,.0f} | {detect_eps:,.0f} | {index_eps:,.0f} | {max_lag:,.0f} | {detect_p95_ms:,.0f} ms | {detect_p99_ms:,.0f} ms | {alerts_per_s:.1f} |".format(
                **s
            )
        )
    note = (
        f"\nRun {run['run_utc']} UTC, {run['seconds_per_step']} s per step, attack share {run['attack_share']:.0%}, "
        f"seed base {run.get('seed_base', 'n/a')}; {run['machine']}. Rates are 1-minute Prometheus rates read at the end of "
        "each step, lag is the maximum over the step across all consumer groups, latency is ingest-accepted to alert-created "
        "from the detect histogram.\n"
    )
    return "\n".join(rows) + "\n" + note


def main() -> None:
    root = pathlib.Path(__file__).resolve().parent.parent
    table = render(root / "load" / "results" / "latest.json")
    if len(sys.argv) >= 3 and sys.argv[1] == "--write":
        target = root / sys.argv[2]
        text = target.read_text(encoding="utf-8")
        a, b = text.index(START) + len(START), text.index(END)
        target.write_text(text[:a] + "\n" + table + text[b:], encoding="utf-8", newline="\n")
        print(f"wrote {target.relative_to(root)}")
    else:
        print(table, end="")


if __name__ == "__main__":
    main()
