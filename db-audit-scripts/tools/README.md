# Audit tools

Helper scripts that sit alongside the engine-specific audit queries.

## `aggregate_report.py`

Walks a directory of audit output files (the `.txt` files produced by the
`run_audit.sh` runners in the docker harness) and renders a single HTML
report with:

* summary counts (clean / errors in output / non-zero exit / unknown)
* per-priority roll-up
* per-script table linking to the raw output
* expandable `<details>` blocks with the full text of each script's output

Stdlib-only; requires Python 3.8+.

```
python3 tools/aggregate_report.py /path/to/audit_results/20260419_120000_audit_test --out report.html
open report.html
```

The tool inspects the `-- Script:` / `-- Exit code:` / `-- Finished:`
trailers that `run_audit.sh` appends to each output file, plus well-known
error markers (`ERROR`, `FATAL`, `Msg N, Level 16+`, `Sqlcmd: Error`).

The tool does **not** edit or re-run anything. A non-zero exit from a
script never fails the aggregator; it just shows up red in the report.
