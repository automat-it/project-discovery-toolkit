#!/usr/bin/env python3
"""
aggregate_report.py

Aggregate the output of a full audit run into a single HTML report.

The audit scripts in this repository each write one text file per script
(see the `run_audit.sh` runners in the accompanying docker harness).
This tool walks a directory of those outputs and renders:

  * A summary table: script | exit code | size | wall time
  * A high-level findings roll-up: scripts that produced error markers
    (ERROR, Msg, FATAL, severity ≥ 16) vs scripts that ran clean
  * Per-priority (critical / high / medium / low) success counts
  * An expandable section per script with the raw output

The script is intentionally dependency-free (stdlib only) so it can run
anywhere Python 3.8+ is available.

Usage:

  python3 aggregate_report.py <audit_output_dir> [--out report.html]

  audit_output_dir is expected to have the layout produced by
  run_audit.sh:

    <dir>/
      perf/
        perf_01_top_queries.txt
        perf_02_blocking_and_locks.txt
        ...
      sec/
        sec_01_users_and_privileges.txt
        ...

Exit code is 0 if the report was produced, non-zero on input errors.
The report does NOT fail the run on findings — it is purely a viewer.
"""

from __future__ import annotations

import argparse
import html
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

ERROR_PATTERNS = [
    # PG / psql style
    re.compile(r"^(ERROR|FATAL|PANIC):", re.MULTILINE),
    # MySQL client style
    re.compile(r"^ERROR \d+ \(", re.MULTILINE),
    # SQL Server sqlcmd style — Msg N, Level M (16+ treated as real error)
    re.compile(r"^Msg \d+, Level (1[6-9]|2[0-5]),", re.MULTILINE),
    # Sqlcmd connection errors
    re.compile(r"^Sqlcmd: Error", re.MULTILINE),
]

# Pulled from the trailing metadata block run_audit.sh appends.
EXIT_RE = re.compile(r"^-- Exit code:\s*(\d+)\s*$", re.MULTILINE)
FINISHED_RE = re.compile(r"^-- Finished:\s*(.+)\s*$", re.MULTILINE)
SCRIPT_RE = re.compile(r"^-- Script:\s*(.+)\s*$", re.MULTILINE)
DATABASE_RE = re.compile(r"^-- Database:\s*(.+)\s*$", re.MULTILINE)


@dataclass
class ScriptResult:
    name: str              # perf_01_top_queries
    category: str          # perf | sec | unknown
    priority: str          # critical | high | medium | low | unknown
    path: Path
    size_bytes: int
    exit_code: int | None
    finished_at: str | None
    database: str | None
    error_hits: list[str] = field(default_factory=list)
    # Cached body so render_details() doesn't re-read every file from disk.
    body: str = ""

    @property
    def status(self) -> str:
        if self.exit_code is None:
            return "unknown"
        if self.exit_code != 0:
            return "failed"
        if self.error_hits:
            return "errors"
        return "ok"


PRIORITY_FROM_FILENAME = {
    # The run_audit.sh runners flatten priority out of the output path, so
    # we recover it from the *input* script path that the runner recorded
    # in the "-- Script:" trailer. Script paths look like
    # .../perf/critical/perf_01_top_queries.sql
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def parse_result(path: Path) -> ScriptResult:
    text = path.read_text(errors="replace")
    exit_match = EXIT_RE.search(text)
    finished_match = FINISHED_RE.search(text)
    script_match = SCRIPT_RE.search(text)
    database_match = DATABASE_RE.search(text)

    name = path.stem

    # Prefer category from the parent directory of the output; fall back
    # to heuristics on the name.
    category = path.parent.name if path.parent.name in ("perf", "sec") else "unknown"

    priority = "unknown"
    if script_match:
        parts = script_match.group(1).split("/")
        for part in parts:
            if part in PRIORITY_FROM_FILENAME:
                priority = part
                break

    error_hits: list[str] = []
    # Only scan the body (everything before the trailing metadata block).
    # Anchor on a newline so a stray ``-- Script: ...`` comment inside the
    # script's SQL doesn't truncate the body.
    if script_match:
        body = text[:script_match.start()]
        # If the match wasn't at line start, walk back to the previous newline.
        nl = text.rfind("\n", 0, script_match.start())
        if nl != -1:
            body = text[:nl + 1]
    else:
        body = text
    for pat in ERROR_PATTERNS:
        for m in pat.finditer(body):
            # record the full matching line
            line_start = body.rfind("\n", 0, m.start()) + 1
            line_end = body.find("\n", m.end())
            if line_end == -1:
                line_end = len(body)
            error_hits.append(body[line_start:line_end].strip())
            if len(error_hits) >= 10:
                break

    return ScriptResult(
        name=name,
        category=category,
        priority=priority,
        path=path,
        size_bytes=path.stat().st_size,
        exit_code=int(exit_match.group(1)) if exit_match else None,
        finished_at=finished_match.group(1).strip() if finished_match else None,
        database=database_match.group(1).strip() if database_match else None,
        error_hits=error_hits,
        body=text,
    )


def iter_output_files(root: Path) -> Iterable[Path]:
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            if f.endswith(".txt"):
                yield Path(dirpath) / f


HTML_TEMPLATE = """<!doctype html>
<html><head>
<meta charset="utf-8">
<title>Audit Report — {root}</title>
<style>
 body {{ font-family: -apple-system, system-ui, Segoe UI, sans-serif;
        max-width: 1200px; margin: 2em auto; padding: 0 1em; color: #222; }}
 h1 {{ border-bottom: 2px solid #333; padding-bottom: .3em; }}
 h2 {{ margin-top: 2em; border-bottom: 1px solid #bbb; }}
 table {{ border-collapse: collapse; width: 100%; margin: 1em 0; font-size: 14px; }}
 th, td {{ border: 1px solid #ddd; padding: 6px 10px; text-align: left; }}
 th {{ background: #f4f4f4; }}
 tr.status-ok      td {{ background: #eefaee; }}
 tr.status-errors  td {{ background: #fff3cf; }}
 tr.status-failed  td {{ background: #fde0e0; }}
 tr.status-unknown td {{ background: #eee; }}
 .count {{ display: inline-block; min-width: 2.5em; padding: 2px 8px;
           border-radius: 10px; margin-right: 8px; font-weight: 600; }}
 .count-ok     {{ background: #2b8a3e; color: white; }}
 .count-errors {{ background: #b78105; color: white; }}
 .count-failed {{ background: #a4161a; color: white; }}
 .count-unknown{{ background: #555; color: white; }}
 details {{ margin: .5em 0; padding: .5em 1em; border: 1px solid #ddd; border-radius: 4px; }}
 details[open] {{ background: #fafafa; }}
 pre {{ background: #111; color: #eee; padding: 1em; overflow-x: auto;
         border-radius: 4px; font-size: 12px; max-height: 500px; }}
 .muted {{ color: #666; font-size: 13px; }}
 .err-line {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
              color: #a4161a; font-size: 12px; }}
</style>
</head><body>

<h1>Audit Report</h1>
<p class="muted">Source directory: <code>{root}</code><br>
Generated: {generated}</p>

<h2>Overview</h2>
<p>
  <span class="count count-ok">{n_ok}</span>clean
  <span class="count count-errors">{n_errors}</span>errors in output
  <span class="count count-failed">{n_failed}</span>non-zero exit
  <span class="count count-unknown">{n_unknown}</span>unknown
</p>

<h2>Per-priority summary</h2>
{priority_table}

<h2>Script results</h2>
{results_table}

<h2>Detailed output</h2>
{details_blocks}

</body></html>
"""


def render_priority_table(results: list[ScriptResult]) -> str:
    buckets: dict[tuple[str, str], list[ScriptResult]] = {}
    for r in results:
        buckets.setdefault((r.category, r.priority), []).append(r)

    rows = ["<tr><th>Category</th><th>Priority</th><th>Total</th>"
            "<th>OK</th><th>Errors</th><th>Failed</th></tr>"]
    for (cat, pri), items in sorted(buckets.items()):
        total = len(items)
        ok = sum(1 for i in items if i.status == "ok")
        err = sum(1 for i in items if i.status == "errors")
        fail = sum(1 for i in items if i.status == "failed")
        rows.append(
            f"<tr><td>{html.escape(cat)}</td>"
            f"<td>{html.escape(pri)}</td>"
            f"<td>{total}</td><td>{ok}</td><td>{err}</td><td>{fail}</td></tr>"
        )
    return "<table>" + "".join(rows) + "</table>"


def render_results_table(results: list[ScriptResult]) -> str:
    rows = ["<tr><th>Script</th><th>Category</th><th>Priority</th>"
            "<th>Status</th><th>Exit</th><th>Size</th>"
            "<th>Finished</th><th>Error hits</th></tr>"]
    for r in sorted(results, key=lambda r: (r.category, r.priority, r.name)):
        rows.append(
            f"<tr class=\"status-{r.status}\">"
            f"<td><a href=\"#{html.escape(r.name)}\">{html.escape(r.name)}</a></td>"
            f"<td>{html.escape(r.category)}</td>"
            f"<td>{html.escape(r.priority)}</td>"
            f"<td>{r.status}</td>"
            f"<td>{r.exit_code if r.exit_code is not None else '?'}</td>"
            f"<td>{r.size_bytes:,}</td>"
            f"<td class=\"muted\">{html.escape(r.finished_at or '')}</td>"
            f"<td>{len(r.error_hits)}</td>"
            f"</tr>"
        )
    return "<table>" + "".join(rows) + "</table>"


def render_details(results: list[ScriptResult]) -> str:
    chunks: list[str] = []
    for r in sorted(results, key=lambda r: (r.category, r.priority, r.name)):
        # Use the cached body from parse_result rather than re-reading the
        # file from disk -- halves I/O on large multi-script audit runs.
        body = r.body or r.path.read_text(errors="replace")
        err_block = ""
        if r.error_hits:
            err_block = "<div><strong>Errors detected:</strong><br>" + "".join(
                f'<div class="err-line">{html.escape(l)}</div>' for l in r.error_hits
            ) + "</div>"
        chunks.append(
            f'<details id="{html.escape(r.name)}">'
            f'<summary><strong>{html.escape(r.name)}</strong> '
            f'<span class="muted">({r.category}/{r.priority}, exit {r.exit_code})</span>'
            f'</summary>'
            f'{err_block}'
            f'<pre>{html.escape(body)}</pre>'
            f'</details>'
        )
    return "\n".join(chunks)


def build_report(root: Path, out: Path) -> None:
    results = [parse_result(p) for p in iter_output_files(root)]
    if not results:
        print(f"no .txt outputs found under {root}", file=sys.stderr)
        sys.exit(2)

    from datetime import datetime, timezone
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")

    buckets = {"ok": 0, "errors": 0, "failed": 0, "unknown": 0}
    for r in results:
        buckets[r.status] += 1

    report = HTML_TEMPLATE.format(
        root=html.escape(str(root)),
        generated=html.escape(generated),
        n_ok=buckets["ok"],
        n_errors=buckets["errors"],
        n_failed=buckets["failed"],
        n_unknown=buckets["unknown"],
        priority_table=render_priority_table(results),
        results_table=render_results_table(results),
        details_blocks=render_details(results),
    )

    out.write_text(report, encoding="utf-8")
    print(f"wrote {out} ({len(results)} scripts, "
          f"{buckets['ok']} ok, {buckets['errors']} errors, "
          f"{buckets['failed']} failed, {buckets['unknown']} unknown)")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("directory", type=Path, help="audit output directory")
    p.add_argument("--out", type=Path, default=Path("audit_report.html"),
                   help="output HTML path (default: audit_report.html)")
    args = p.parse_args(argv)

    if not args.directory.is_dir():
        print(f"not a directory: {args.directory}", file=sys.stderr)
        return 2

    build_report(args.directory, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
