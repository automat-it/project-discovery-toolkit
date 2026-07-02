#!/usr/bin/env python3
"""
aggregate_report.py

Aggregate the output of a full audit run into a single HTML report.

The audit scripts in this repository each write one log file per script
(see the `run_audit.sh` runners for postgres/mysql and the `.ps1` runners
for mssql). This tool walks a directory of those outputs and renders:

  * A summary table: script | status | size
  * A high-level findings roll-up: scripts that produced error markers
    (psql ERROR, mysql ERROR NNNN, sqlcmd Msg/Level, FATAL) vs scripts
    that ran clean
  * Per-priority (critical / high / medium / low) success counts
  * An expandable section per script with the raw output (truncated)

The script is intentionally dependency-free (stdlib only) so it can run
anywhere Python 3.8+ is available.

Usage:

  python3 aggregate_report.py <audit_output_dir> [--out report.html]

  audit_output_dir is expected to have the flat layout produced by the
  run_audit.sh runners:

    reports/<engine>_<cat>_<TS>/
      _summary.txt                          ← pass/fail roll-up
      critical_perf_01_top_sql.log          ← <priority>_<script>.log
      high_perf_06_index_audit.log
      medium_perf_11_bloat_estimation.log
      low_perf_16_plan_instability.log
      ...

The runner never writes per-script metadata trailers into the .log files;
priority and script name are recovered from the log FILENAME, and pass/
fail status is read from `_summary.txt` (falling back to scanning the log
for engine error markers).

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
    # PG / psql style. psql prefixes errors with the input location, e.g.
    #   psql:/path/perf_01.sql:26: ERROR:  relation "x" does not exist
    # so the ERROR:/FATAL:/PANIC: token is NOT at line start. Match it
    # anywhere on the line (still anchored to a word boundary).
    re.compile(r"\b(ERROR|FATAL|PANIC):", re.MULTILINE),
    # MySQL client style — server errors are printed to stderr as
    #   ERROR NNNN (SQLSTATE): message
    # Require the 4+ digit code and the "(SQLSTATE)" paren so a data row
    # whose first column happens to read "ERROR ..." doesn't false-positive.
    re.compile(r"^ERROR \d{4} \(", re.MULTILINE),
    # SQL Server sqlcmd style — Msg N, Level M. Broadened to Level 11-25:
    # Level 11-16 are the ordinary "something is wrong" errors (Msg 229
    # "permission denied", the real RDS/least-privilege failure, is
    # Level 14), 17-25 are resource/fatal. Levels 0-10 are informational.
    re.compile(r"^Msg \d+, Level (1[1-9]|2[0-5]),", re.MULTILINE),
    # SQL Server login failures (Msg 18456 & friends may arrive without a
    # Level prefix depending on the driver).
    re.compile(r"^(Login failed|Cannot open database)", re.MULTILINE),
    # Sqlcmd connection errors
    re.compile(r"^Sqlcmd: Error", re.MULTILINE),
]

# `_summary.txt` roll-up lines written by every runner:
#   OK  critical/perf_02_blocking_and_locks.sql
#   FAIL critical/perf_01_top_sql.sql
SUMMARY_LINE_RE = re.compile(
    r"^(OK|FAIL)\s+(?:critical|high|medium|low)/(\S+?)\.sql\s*$",
    re.MULTILINE,
)


PRIORITIES = ("critical", "high", "medium", "low")

# Overall cap on recorded error lines per script (across all patterns), so
# a log full of error rows doesn't balloon the report.
MAX_ERROR_HITS = 10

# Truncate embedded raw-log bodies so one enormous log can't make the whole
# HTML report unopenable. Keep the head and tail (errors surface at either
# end) with an elision marker in the middle.
MAX_BODY_BYTES = 64 * 1024           # ~64 KB total kept per log
_HEAD_BYTES = MAX_BODY_BYTES // 2
_TAIL_BYTES = MAX_BODY_BYTES - _HEAD_BYTES


@dataclass
class ScriptResult:
    name: str              # perf_01_top_sql
    category: str          # perf | sec | unknown
    priority: str          # critical | high | medium | low | unknown
    path: Path
    size_bytes: int
    # OK / FAIL from _summary.txt, or None if the summary didn't cover it.
    summary_status: str | None
    error_hits: list[str] = field(default_factory=list)
    # Cached body so render_details() doesn't re-read every file from disk.
    body: str = ""

    @property
    def status(self) -> str:
        # _summary.txt is authoritative for pass/fail. FAIL always wins.
        if self.summary_status == "FAIL":
            return "failed"
        # Error markers in the log => surface as "errors" even if the runner
        # (or a missing summary) recorded it as OK.
        if self.error_hits:
            return "errors"
        if self.summary_status == "OK":
            return "ok"
        return "unknown"


def parse_summary(root: Path) -> dict[str, str]:
    """Map script stem (e.g. 'perf_01_top_sql') -> 'OK' | 'FAIL'.

    Reads the run's `_summary.txt`. Absent/unreadable => empty map, and
    per-script status falls back to error-marker scanning.
    """
    summary = root / "_summary.txt"
    if not summary.is_file():
        return {}
    text = summary.read_text(errors="replace")
    result: dict[str, str] = {}
    for m in SUMMARY_LINE_RE.finditer(text):
        status, stem = m.group(1), m.group(2)
        # Last write wins; a FAIL is never overwritten by a later OK.
        if result.get(stem) != "FAIL":
            result[stem] = status
    return result


def _split_priority(stem: str) -> tuple[str, str]:
    """Split '<priority>_<script>' -> (priority, script-stem).

    Filenames are e.g. 'critical_perf_01_top_sql'. The priority is the
    prefix before the first underscore; the rest is the script stem.
    """
    prefix, _, rest = stem.partition("_")
    if prefix in PRIORITIES and rest:
        return prefix, rest
    return "unknown", stem


def parse_result(path: Path, summary: dict[str, str]) -> ScriptResult:
    text = path.read_text(errors="replace")

    priority, script_stem = _split_priority(path.stem)

    # Category from the script stem (perf_* / sec_*), else from the run
    # folder name (postgres_perf_<TS> / mysql_sec_<TS>).
    if script_stem.startswith("perf"):
        category = "perf"
    elif script_stem.startswith("sec"):
        category = "sec"
    elif "_perf_" in path.parent.name:
        category = "perf"
    elif "_sec_" in path.parent.name:
        category = "sec"
    else:
        category = "unknown"

    error_hits: list[str] = []
    for pat in ERROR_PATTERNS:
        if len(error_hits) >= MAX_ERROR_HITS:
            break
        for m in pat.finditer(text):
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.end())
            if line_end == -1:
                line_end = len(text)
            error_hits.append(text[line_start:line_end].strip())
            if len(error_hits) >= MAX_ERROR_HITS:
                break

    return ScriptResult(
        name=script_stem,
        category=category,
        priority=priority,
        path=path,
        size_bytes=path.stat().st_size,
        summary_status=summary.get(script_stem),
        error_hits=error_hits,
        body=text,
    )


def _truncate_body(body: str) -> str:
    """Keep head+tail of an over-long log body with an elision marker."""
    raw = body.encode("utf-8", errors="replace")
    if len(raw) <= MAX_BODY_BYTES:
        return body
    head = raw[:_HEAD_BYTES].decode("utf-8", errors="replace")
    tail = raw[-_TAIL_BYTES:].decode("utf-8", errors="replace")
    elided = len(raw) - _HEAD_BYTES - _TAIL_BYTES
    return (
        f"{head}\n\n"
        f"... [{elided:,} bytes elided -- open the raw .log file for the "
        f"full output] ...\n\n"
        f"{tail}"
    )


def iter_output_files(root: Path) -> Iterable[Path]:
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            # Every runner writes one <priority>_<script>.log per script,
            # plus a single _summary.txt roll-up. Ingest the .log files and
            # skip the summary (handled separately).
            if f.endswith(".log"):
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
  <span class="count count-failed">{n_failed}</span>failed
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
            "<th>Status</th><th>Size</th><th>Error hits</th></tr>"]
    for r in sorted(results, key=lambda r: (r.category, r.priority, r.name)):
        rows.append(
            f"<tr class=\"status-{r.status}\">"
            f"<td><a href=\"#{html.escape(r.name)}\">{html.escape(r.name)}</a></td>"
            f"<td>{html.escape(r.category)}</td>"
            f"<td>{html.escape(r.priority)}</td>"
            f"<td>{r.status}</td>"
            f"<td>{r.size_bytes:,}</td>"
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
        body = _truncate_body(body)
        err_block = ""
        if r.error_hits:
            err_block = "<div><strong>Errors detected:</strong><br>" + "".join(
                f'<div class="err-line">{html.escape(l)}</div>' for l in r.error_hits
            ) + "</div>"
        chunks.append(
            f'<details id="{html.escape(r.name)}">'
            f'<summary><strong>{html.escape(r.name)}</strong> '
            f'<span class="muted">({html.escape(r.category)}/'
            f'{html.escape(r.priority)}, {r.status})</span>'
            f'</summary>'
            f'{err_block}'
            f'<pre>{html.escape(body)}</pre>'
            f'</details>'
        )
    return "\n".join(chunks)


def build_report(root: Path, out: Path) -> None:
    summary = parse_summary(root)
    results = [parse_result(p, summary) for p in iter_output_files(root)]
    if not results:
        print(
            f"no per-script .log files found under {root}\n"
            f"  expected the layout produced by run_audit.sh:\n"
            f"    reports/<engine>_<cat>_<TS>/<priority>_<script>.log",
            file=sys.stderr,
        )
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
