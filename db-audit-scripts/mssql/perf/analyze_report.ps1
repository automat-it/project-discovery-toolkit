#Requires -Version 5.1
<#
.SYNOPSIS
    Parse a SQL Server performance audit report folder and generate a
    customer-friendly HTML summary highlighting potential issues.

.DESCRIPTION
    Reads the report directory produced by run_audit.ps1 (single database)
    or run_all_databases.ps1 (multiple databases), applies a rule set that
    flags known performance issues, and writes one HTML file with an
    executive summary plus a dedicated section per database.

    The analyzer is content-aware: for "diagnostic" scripts (blocking,
    missing indexes, stale stats, ...) it treats any data rows as
    findings; for "inventory" scripts it looks for specific patterns.

    Output: <ReportDir>\perf_analysis.html

.PARAMETER ReportDir
    Folder produced by run_audit.ps1 / run_all_databases.ps1. Either:
      - mssql_audit_all_YYYYMMDD_HHMMSS\   (multi-database)
      - mssql_perf_YYYYMMDD_HHMMSS\        (single-database)

.PARAMETER ServerName
    Optional server label for the report header (purely cosmetic).

.PARAMETER OutFile
    Optional override for the output HTML path. Default:
    <ReportDir>\perf_analysis.html

.EXAMPLE
    .\analyze_report.ps1 -ReportDir "C:\reports\mssql_audit_all_20260429_230243"

.EXAMPLE
    .\analyze_report.ps1 -ReportDir "C:\reports\mssql_perf_20260430_010000" `
                         -ServerName "PROD-SQL-01"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ReportDir,
    [string]$ServerName = "",
    [string]$OutFile    = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path $ReportDir)) {
    Write-Error "Report directory not found: $ReportDir"
    exit 2
}

$ReportDir = (Resolve-Path $ReportDir).Path
if (-not $OutFile) { $OutFile = Join-Path $ReportDir "perf_analysis.html" }

# ===========================================================================
# Rules: each rule applies to a script (by basename suffix match) and either
# flags any non-empty data as a finding, or matches a regex against content.
# Severity: Critical (red), Warning (orange), Info (blue), OK (green).
# ===========================================================================
$Rules = @(
    @{ Script='perf_02_blocking_and_locks';   Mode='HasData'; Severity='Critical'
       Title='Active blocking or long-running transactions'
       Recommendation='Investigate the blocking chain. Long-running transactions block other sessions and bloat the log.' }

    @{ Script='perf_04_wait_events_and_io';   Mode='Pattern'; Severity='Warning'
       Pattern='PAGEIOLATCH_(SH|EX|UP)'
       Title='Storage I/O waits dominant'
       Recommendation='PAGEIOLATCH waits indicate slow disk reads. Check storage latency and buffer pool sizing.' }

    @{ Script='perf_04_wait_events_and_io';   Mode='Pattern'; Severity='Warning'
       Pattern='RESOURCE_SEMAPHORE'
       Title='Memory grant queue waits'
       Recommendation='Queries are waiting for query memory grants. Tune query plans or raise max server memory.' }

    @{ Script='perf_04_wait_events_and_io';   Mode='Pattern'; Severity='Warning'
       Pattern='LCK_M_'
       Title='Lock waits accumulating'
       Recommendation='Sustained lock waits suggest blocking. Cross-reference with perf_02 results.' }

    @{ Script='perf_06_index_audit';          Mode='HasData'; Severity='Warning'
       Title='Index hygiene findings (missing / unused / duplicate indexes)'
       Recommendation='Review the script log. Add missing indexes, drop unused indexes, consolidate duplicates.' }

    @{ Script='perf_07_table_stats_health';   Mode='HasData'; Severity='Warning'
       Title='Stale statistics or high index fragmentation'
       Recommendation='Update stale statistics (modification ratio > 10%). Rebuild indexes with > 30% fragmentation.' }

    @{ Script='perf_09_temp_and_memory_pressure'; Mode='Pattern'; Severity='Critical'
       Pattern='pending_memory_grant_count\s*\n\s*-+\s*\n\s*[1-9]'
       Title='Memory grant requests pending'
       Recommendation='Queries are waiting for memory. Capacity issue. Investigate large grants and resource semaphore.' }

    @{ Script='perf_09_temp_and_memory_pressure'; Mode='Pattern'; Severity='Warning'
       Pattern='PAGELATCH_(SH|EX|UP).*[12]:\d+:[123]'
       Title='TempDB allocation contention'
       Recommendation='PAGELATCH waits on tempdb GAM/SGAM/PFS pages. Add equally-sized tempdb data files (1 per CPU up to 8).' }

    @{ Script='perf_10_replication_and_backup_impact'; Mode='Pattern'; Severity='Warning'
       Pattern='hours_since_full\s*\n\s*-+\s*\n.*\b([7-9]\d|\d{3,})\b'
       Title='Last full backup older than 72 hours'
       Recommendation='Backup gap detected. Verify the backup job and target storage.' }

    @{ Script='perf_15_capacity_and_growth';  Mode='Pattern'; Severity='Critical'
       Pattern='\b(8[0-9]|9[0-9]|100)\.\d+\s*%'
       Title='Identity column or storage above 80% consumed'
       Recommendation='Plan for type widening (INT to BIGINT) or storage expansion before the limit is hit.' }

    @{ Script='perf_25_tempdb_contention';    Mode='HasData'; Severity='Warning'
       Title='TempDB contention metrics returned data'
       Recommendation='Review tempdb file count vs CPU and PFS/GAM/SGAM page latch waits.' }
)

# ===========================================================================
# Helpers
# ===========================================================================

# Detect file encoding by BOM. PowerShell 5.1's default '> $log' redirection
# writes UTF-16 LE; older runs of run_audit.ps1 produced such logs. New runs
# write UTF-8. Read either correctly.
function Get-LogEncoding {
    param([string]$LogPath)
    if (-not (Test-Path $LogPath)) { return [System.Text.Encoding]::UTF8 }
    $bytes = [System.IO.File]::ReadAllBytes($LogPath) | Select-Object -First 4
    if ($bytes.Count -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        return [System.Text.Encoding]::Unicode             # UTF-16 LE BOM
    }
    if ($bytes.Count -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        return [System.Text.Encoding]::BigEndianUnicode    # UTF-16 BE BOM
    }
    if ($bytes.Count -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        return [System.Text.Encoding]::UTF8                # UTF-8 BOM
    }
    # Heuristic for BOM-less UTF-16 LE: ASCII byte followed by 0x00.
    if ($bytes.Count -ge 2 -and $bytes[0] -gt 0 -and $bytes[0] -lt 128 -and $bytes[1] -eq 0) {
        return [System.Text.Encoding]::Unicode
    }
    return [System.Text.Encoding]::UTF8
}

function Read-LogLines {
    param([string]$LogPath)
    if (-not (Test-Path $LogPath)) { return @() }
    $enc = Get-LogEncoding $LogPath
    return [System.IO.File]::ReadAllLines($LogPath, $enc)
}

function Read-LogText {
    param([string]$LogPath)
    if (-not (Test-Path $LogPath)) { return "" }
    $enc = Get-LogEncoding $LogPath
    return [System.IO.File]::ReadAllText($LogPath, $enc)
}

# Determine if a sqlcmd log contains any data rows beyond headers / notes.
function Test-LogHasDataRows {
    param([string]$LogPath)
    $lines = Read-LogLines $LogPath
    if (-not $lines) { return $false }

    $inData = $false
    foreach ($line in $lines) {
        if ($line -match '^[-\s]+$' -and $line -match '-{3,}') { $inData = $true; continue }
        if (-not $inData) { continue }
        if ($line -match '^\s*\(\d+ rows? affected\)\s*$') { $inData = $false; continue }
        if ($line -match '^\s*$')                          { continue }
        if ($line -match '^\[note\]')                       { continue }
        if ($line -match '^Msg\s+\d+,\s*Level')             { continue }
        if ($line -match '^Changed database context')        { continue }
        return $true
    }
    return $false
}

function Get-LogText {
    param([string]$LogPath)
    return (Read-LogText $LogPath)
}

# Parse _summary.txt: yields one row per script with its OK/FAIL status.
function Read-AuditSummary {
    param([string]$SummaryPath)
    if (-not (Test-Path $SummaryPath)) { return @() }
    $entries = @()
    foreach ($line in (Read-LogLines $SummaryPath)) {
        if ($line -match '^(OK|FAIL)\s+(\S+)') {
            $entries += [pscustomobject]@{ Status=$matches[1]; Path=$matches[2] }
        }
    }
    return $entries
}

# Apply rules to one report folder (one database). Returns array of findings.
function Get-Findings {
    param([string]$LogDir)

    $findings = @()
    $summaryPath = Join-Path $LogDir "_summary.txt"
    foreach ($entry in Read-AuditSummary $summaryPath) {
        if ($entry.Status -eq 'FAIL') {
            $logBase = ($entry.Path -replace '/', '_') -replace '\.sql$', '.log'
            $logPath = Join-Path $LogDir $logBase
            $errLines = if (Test-Path $logPath) {
                $sz = (Get-Item $logPath).Length
                if ($sz -eq 0) {
                    "(empty log -- sqlcmd produced no output, likely killed mid-run)"
                } else {
                    (Read-LogLines $logPath |
                        Where-Object { $_ -match '^Msg\s+\d+|^Sqlcmd:|^\[note\]' } |
                        Select-Object -First 5) -join "`n"
                }
            } else { "(no log captured)" }
            $findings += [pscustomobject]@{
                Severity       = 'Critical'
                Script         = $entry.Path
                Title          = "Script execution failed"
                Detail         = $errLines
                Recommendation = "Check connection privileges, sqlcmd version, and the script log file."
            }
        }
    }

    # Apply content rules
    Get-ChildItem $LogDir -Filter '*.log' | ForEach-Object {
        $log     = $_.FullName
        $base    = $_.BaseName  # e.g. critical_perf_01_top_sql
        foreach ($rule in $Rules) {
            if ($base -notmatch [regex]::Escape($rule.Script)) { continue }

            $hit = $false
            $detail = ""
            switch ($rule.Mode) {
                'HasData' {
                    if (Test-LogHasDataRows $log) {
                        $hit = $true
                        $detail = "Diagnostic script returned data rows -- review the full log."
                    }
                }
                'Pattern' {
                    $text = Get-LogText $log
                    if ($text -and ($text -match $rule.Pattern)) {
                        $hit = $true
                        # extract a small snippet of the match for context
                        $snippet = $matches[0]
                        if ($snippet.Length -gt 200) { $snippet = $snippet.Substring(0,200) + '...' }
                        $detail = "Match: " + $snippet
                    }
                }
            }
            if ($hit) {
                $findings += [pscustomobject]@{
                    Severity       = $rule.Severity
                    Script         = $_.Name
                    Title          = $rule.Title
                    Detail         = $detail
                    Recommendation = $rule.Recommendation
                }
            }
        }
    }

    return ,$findings
}

# Discover the report layout. Returns array of "context" objects:
#   @{ Name=<DB or _server>; LogDir=<path containing *.log + _summary.txt> }
function Get-ReportContexts {
    param([string]$Root)

    # Single-DB mode: $Root itself contains *.log and _summary.txt
    if (Test-Path (Join-Path $Root "_summary.txt")) {
        return ,@([pscustomobject]@{ Name = "(single run)"; LogDir = $Root })
    }

    # Multi-DB mode: $Root has sub-folders, each with a mssql_perf_* sub-folder
    $contexts = @()
    Get-ChildItem $Root -Directory | Sort-Object Name | ForEach-Object {
        $dbName = $_.Name
        Get-ChildItem $_.FullName -Directory -Filter 'mssql_perf_*' |
            Sort-Object Name -Descending |
            Select-Object -First 1 | ForEach-Object {
                $contexts += [pscustomobject]@{ Name = $dbName; LogDir = $_.FullName }
            }
    }
    return ,$contexts
}

# ===========================================================================
# HTML generation (self-contained, no external resources)
# ===========================================================================
function Convert-FindingsToHtml {
    param([array]$Findings)
    if (-not $Findings -or $Findings.Count -eq 0) {
        return '<p class="ok">No problems detected by the rule set.</p>'
    }
    $html = "<table class='findings'><thead><tr><th>Severity</th><th>Script</th><th>Finding</th><th>Recommendation</th></tr></thead><tbody>"
    foreach ($f in ($Findings | Sort-Object @{Expression={
            switch ($_.Severity) { 'Critical' {0} 'Warning' {1} 'Info' {2} default {3} }
        }})) {
        $sevClass = $f.Severity.ToLower()
        $html += "<tr class='sev-$sevClass'>"
        $html += "<td><span class='badge $sevClass'>$($f.Severity)</span></td>"
        $html += "<td><code>$([System.Web.HttpUtility]::HtmlEncode($f.Script))</code></td>"
        $html += "<td><strong>$([System.Web.HttpUtility]::HtmlEncode($f.Title))</strong>"
        if ($f.Detail) { $html += "<br><span class='detail'>$([System.Web.HttpUtility]::HtmlEncode($f.Detail))</span>" }
        $html += "</td>"
        $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</td>"
        $html += "</tr>"
    }
    $html += "</tbody></table>"
    return $html
}

Add-Type -AssemblyName System.Web

# ===========================================================================
# Main
# ===========================================================================
$contexts = Get-ReportContexts $ReportDir
if (-not $contexts -or $contexts.Count -eq 0) {
    Write-Error "No report sub-folders found in $ReportDir. Expected mssql_perf_* sub-folders."
    exit 3
}

# Process every context
$report = @()
foreach ($ctx in $contexts) {
    $findings = Get-Findings $ctx.LogDir
    $summary  = Read-AuditSummary (Join-Path $ctx.LogDir "_summary.txt")
    $passed   = ($summary | Where-Object { $_.Status -eq 'OK'   }).Count
    $failed   = ($summary | Where-Object { $_.Status -eq 'FAIL' }).Count
    $crit     = ($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $warn     = ($findings | Where-Object { $_.Severity -eq 'Warning'  }).Count
    $info     = ($findings | Where-Object { $_.Severity -eq 'Info'     }).Count

    $report += [pscustomobject]@{
        Name=$ctx.Name; LogDir=$ctx.LogDir; Findings=$findings
        Passed=$passed; Failed=$failed
        Critical=$crit; Warning=$warn; Info=$info
    }
}

$totalCrit = ($report | Measure-Object -Property Critical -Sum).Sum
$totalWarn = ($report | Measure-Object -Property Warning  -Sum).Sum
$totalFail = ($report | Measure-Object -Property Failed   -Sum).Sum
$now       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$srvLabel  = if ($ServerName) { [System.Web.HttpUtility]::HtmlEncode($ServerName) } else { "(unspecified)" }

$css = @'
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:20px;background:#f5f5f5;color:#222;}
h1{margin:0 0 4px 0;}h2{border-bottom:2px solid #2a6db0;padding-bottom:4px;margin-top:32px;}
header{background:#2a6db0;color:white;padding:24px;border-radius:6px;margin-bottom:20px;}
header p{margin:4px 0;opacity:0.9;}
.summary{background:white;padding:16px;border-radius:6px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,0.1);}
table{border-collapse:collapse;width:100%;background:white;}
th,td{padding:8px 12px;border-bottom:1px solid #e0e0e0;text-align:left;vertical-align:top;}
th{background:#eef2f7;font-weight:600;}
.findings tr:hover{background:#fafbfc;}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:0.85em;font-weight:600;color:white;}
.badge.critical{background:#c0392b;}
.badge.warning {background:#e67e22;}
.badge.info    {background:#2980b9;}
.sev-critical>td:first-child{border-left:4px solid #c0392b;}
.sev-warning >td:first-child{border-left:4px solid #e67e22;}
.sev-info    >td:first-child{border-left:4px solid #2980b9;}
.detail{color:#666;font-size:0.9em;font-family:Consolas,monospace;}
.ok{color:#27ae60;font-weight:600;}
.exec-summary td.num{text-align:right;font-variant-numeric:tabular-nums;}
.exec-summary td.crit{color:#c0392b;font-weight:600;}
.exec-summary td.warn{color:#e67e22;font-weight:600;}
.exec-summary td.fail{color:#c0392b;font-weight:600;}
.toc{background:white;padding:12px 20px;border-radius:6px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,0.1);}
.toc ul{margin:0;padding-left:20px;columns:3;}
.toc a{text-decoration:none;color:#2a6db0;}
.toc a:hover{text-decoration:underline;}
section.db{background:white;padding:16px 20px;border-radius:6px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,0.1);}
section.db h3{margin-top:0;color:#2a6db0;}
.meta{color:#666;font-size:0.9em;margin-bottom:12px;}
code{background:#f0f0f0;padding:1px 6px;border-radius:3px;font-size:0.9em;}
</style>
'@

# Build HTML
$html = @"
<!DOCTYPE html>
<html lang='en'><head><meta charset='UTF-8'>
<title>SQL Server Performance Audit Report</title>
$css
</head><body>
<header>
  <h1>SQL Server Performance Audit Report</h1>
  <p><strong>Server:</strong> $srvLabel</p>
  <p><strong>Report folder:</strong> $([System.Web.HttpUtility]::HtmlEncode($ReportDir))</p>
  <p><strong>Generated:</strong> $now</p>
</header>

<div class='summary'>
<h2 style='margin-top:0;border:none;'>Executive Summary</h2>
<table class='exec-summary'>
<thead><tr><th>Database / Context</th><th>Scripts OK</th><th>Failed</th><th>Critical</th><th>Warning</th><th>Info</th></tr></thead>
<tbody>
"@
foreach ($r in $report) {
    $anchor = ($r.Name -replace '[^A-Za-z0-9]', '_')
    $html += "<tr><td><a href='#db_$anchor'>$([System.Web.HttpUtility]::HtmlEncode($r.Name))</a></td>"
    $html += "<td class='num'>$($r.Passed)</td>"
    $html += "<td class='num fail'>$($r.Failed)</td>"
    $html += "<td class='num crit'>$($r.Critical)</td>"
    $html += "<td class='num warn'>$($r.Warning)</td>"
    $html += "<td class='num'>$($r.Info)</td></tr>`n"
}
$html += "<tr style='font-weight:bold;background:#f0f4f9;'><td>TOTAL</td>"
$html += "<td class='num'>$(($report | Measure-Object -Property Passed -Sum).Sum)</td>"
$html += "<td class='num fail'>$totalFail</td>"
$html += "<td class='num crit'>$totalCrit</td>"
$html += "<td class='num warn'>$totalWarn</td>"
$html += "<td class='num'>$(($report | Measure-Object -Property Info -Sum).Sum)</td></tr>"
$html += "</tbody></table></div>"

# Table of contents (only useful for multi-DB reports)
if ($report.Count -gt 1) {
    $html += "<div class='toc'><h2 style='margin-top:0;border:none;'>Sections</h2><ul>"
    foreach ($r in $report) {
        $anchor = ($r.Name -replace '[^A-Za-z0-9]', '_')
        $html += "<li><a href='#db_$anchor'>$([System.Web.HttpUtility]::HtmlEncode($r.Name))</a></li>"
    }
    $html += "</ul></div>"
}

# Per-database sections
foreach ($r in $report) {
    $anchor = ($r.Name -replace '[^A-Za-z0-9]', '_')
    $html += "<section class='db' id='db_$anchor'>"
    $html += "<h3>$([System.Web.HttpUtility]::HtmlEncode($r.Name))</h3>"
    $html += "<div class='meta'>Logs: <code>$([System.Web.HttpUtility]::HtmlEncode($r.LogDir))</code></div>"
    $html += "<div class='meta'>Scripts run: $($r.Passed + $r.Failed) | OK: $($r.Passed) | Failed: $($r.Failed)</div>"
    $html += (Convert-FindingsToHtml $r.Findings)
    $html += "</section>"
}

$html += "</body></html>"

# Write file (UTF-8 with BOM so browsers detect encoding correctly on Windows)
$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($OutFile, $html, $utf8Bom)

Write-Host ""
Write-Host "================================================================================"
Write-Host "Performance audit analysis complete."
Write-Host "  Databases analyzed : $($report.Count)"
Write-Host "  Critical findings  : $totalCrit"
Write-Host "  Warnings           : $totalWarn"
Write-Host "  Failed scripts     : $totalFail"
Write-Host "  Report             : $OutFile"
Write-Host "================================================================================"
