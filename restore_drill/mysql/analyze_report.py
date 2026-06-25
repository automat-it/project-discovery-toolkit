#!/usr/bin/env python3
"""Analyze a MySQL restore-drill report folder and render a branded HTML
report (mysql_restore_analysis.html).

    python3 analyze_report.py <report_dir> [--server LABEL] [--customer NAME] [--out PATH]

The heavy lifting lives in ../_restore_common.py (shared with PostgreSQL);
this wrapper only pins the engine name and default output filename.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _restore_common import cli  # noqa: E402

if __name__ == '__main__':
    raise SystemExit(cli('mysql', 'MySQL', 'mysql_restore_analysis.html'))
