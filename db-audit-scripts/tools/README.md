# Audit tools

Helper scripts that sit alongside the engine-specific audit queries.

## `aggregate_report.py`

Walks a report directory produced by any `run_audit.sh` / `run_audit.ps1`
runner (the per-script `.log` files plus the run's `_summary.txt`) and
renders a single HTML report with:

* summary counts (clean / errors in output / failed / unknown)
* per-priority roll-up
* per-script table linking to the raw output
* expandable `<details>` blocks with the full text of each script's output
  (large logs are truncated head+tail so the report stays openable)

Stdlib-only; requires Python 3.8+.

```
python3 tools/aggregate_report.py /path/to/reports/postgres_perf_20260419_120000 --out report.html
open report.html
```

The tool derives each script's priority and name from the log filename
(`<priority>_<script>.log`), reads pass/fail from the run's `_summary.txt`,
and scans each log for engine error markers across all three engines:
psql `ERROR:` / `FATAL:`, mysql `ERROR NNNN (SQLSTATE)`, and sqlcmd
`Msg N, Level 11-25` (so permission-denied `Msg 229, Level 14` is caught).

The tool does **not** edit or re-run anything. A non-zero exit from a
script never fails the aggregator; it just shows up red in the report.
