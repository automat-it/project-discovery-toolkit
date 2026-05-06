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
    [string]$OutFile    = "",        # output PDF path (default: <ReportDir>\perf_analysis.pdf)
    [switch]$KeepHtml,                # keep the intermediate HTML file
    [switch]$NoPdf                    # produce HTML only (skip Edge headless conversion)
)

# Explicitly disable strict mode. Some hosts (PowerShell ISE, custom
# profiles, calling scripts) leave strict mode enabled in the session
# scope; under strict mode pipelines that emit $null or scalar values
# trip "The property 'Length' cannot be found on this object" and abort
# the analyzer before any output is produced. Set-StrictMode -Off
# overrides any inherited setting for the duration of this script.
Set-StrictMode -Off
$ErrorActionPreference = "Stop"

if (-not (Test-Path $ReportDir)) {
    Write-Error "Report directory not found: $ReportDir"
    exit 2
}

$ReportDir = (Resolve-Path $ReportDir).Path
if (-not $OutFile) {
    $ext = if ($NoPdf) { "html" } else { "pdf" }
    $OutFile = Join-Path $ReportDir "perf_analysis.$ext"
}
$HtmlPath = if ($OutFile -like "*.html") { $OutFile } else { [System.IO.Path]::ChangeExtension($OutFile, "html") }

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
#
# Read the BOM via FileStream so empty files return $read=0 and the function
# falls through to UTF-8. Earlier implementation used pipeline + Select-Object
# which yields $null / scalar byte on empty / 1-byte files and tripped
# Set-StrictMode "property Length not found".
function Get-LogEncoding {
    param([string]$LogPath)
    if (-not (Test-Path $LogPath)) { return [System.Text.Encoding]::UTF8 }
    $head = New-Object byte[] 4
    $read = 0
    try {
        $stream = [System.IO.File]::OpenRead($LogPath)
        try   { $read = $stream.Read($head, 0, 4) }
        finally { $stream.Dispose() }
    } catch {
        return [System.Text.Encoding]::UTF8
    }
    if ($read -ge 2 -and $head[0] -eq 0xFF -and $head[1] -eq 0xFE) {
        return [System.Text.Encoding]::Unicode             # UTF-16 LE BOM
    }
    if ($read -ge 2 -and $head[0] -eq 0xFE -and $head[1] -eq 0xFF) {
        return [System.Text.Encoding]::BigEndianUnicode    # UTF-16 BE BOM
    }
    if ($read -ge 3 -and $head[0] -eq 0xEF -and $head[1] -eq 0xBB -and $head[2] -eq 0xBF) {
        return [System.Text.Encoding]::UTF8                # UTF-8 BOM
    }
    # Heuristic for BOM-less UTF-16 LE: ASCII byte followed by 0x00.
    if ($read -ge 2 -and $head[0] -gt 0 -and $head[0] -lt 128 -and $head[1] -eq 0) {
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
                        $snippet = [string]$matches[0]
                        if ($snippet -and $snippet.Length -gt 200) {
                            $snippet = $snippet.Substring(0,200) + '...'
                        }
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
#
# Two layouts to handle:
#   1. multi-DB run (run_all_databases.ps1):
#        <Root>/<DBName>/mssql_perf_<ts>/{_summary.txt, *.log}
#        <Root>/_server/mssql_perf_<ts>/...
#        <Root>/_summary.txt           <-- top-level roll-up: 'OK <db>' / 'FAIL <db>'
#
#   2. single-DB run (run_audit.ps1):
#        <Root>/{_summary.txt, *.log}  <-- _summary.txt lists scripts: 'OK <prio>/<file>.sql'
#
# Try multi-DB first (presence of mssql_perf_* sub-folders is the
# unambiguous signal). Fall back to single-run only when no sub-folders
# match. The previous implementation looked at <Root>/_summary.txt first,
# which mis-classified the multi-DB roll-up file as a single-run summary
# and then tried to read database directories as log files.
function Get-ReportContexts {
    param([string]$Root)

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
    if (@($contexts).Count -gt 0) { return ,$contexts }

    # Fall back: single-DB run -- $Root itself contains *.log + _summary.txt
    if (Test-Path (Join-Path $Root "_summary.txt")) {
        return ,@([pscustomobject]@{ Name = "(single run)"; LogDir = $Root })
    }

    return ,@()
}

# ===========================================================================
# HTML generation
#   Layout: ONE section per severity (Critical / Warning / Info), and
#   inside each severity-section a sub-heading per database listing only
#   the findings of that severity for that database. This matches the
#   customer-facing report style requested.
# ===========================================================================
Add-Type -AssemblyName System.Web

function Convert-DbFindingsToTable {
    param([array]$Findings)
    if (-not $Findings -or @($Findings).Count -eq 0) { return "" }
    $html = "<table class='findings'><thead><tr>" +
            "<th style='width:24%'>Script</th>" +
            "<th style='width:36%'>Finding</th>" +
            "<th style='width:40%'>Recommendation</th>" +
            "</tr></thead><tbody>"
    foreach ($f in $Findings) {
        $html += "<tr>"
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

# Render the section for one severity grouped by database.
function Convert-SeveritySectionToHtml {
    param([string]$Severity, [array]$Report)
    $sevClass = $Severity.ToLower()
    $hits     = @()
    foreach ($r in $Report) {
        $list = @($r.Findings | Where-Object { $_.Severity -eq $Severity })
        if ($list.Count -gt 0) {
            $hits += [pscustomobject]@{ Name=$r.Name; Findings=$list }
        }
    }
    $total = ($hits | Measure-Object -Property @{Expression={@($_.Findings).Count}} -Sum).Sum
    if ($null -eq $total) { $total = 0 }
    $html = "<section class='severity sev-$sevClass'>"
    $html += "<h2 class='sev-h2 sev-$sevClass'><span class='badge $sevClass'>$Severity</span> $Severity Findings <span class='count'>($total total across $(@($hits).Count) database(s))</span></h2>"
    if ($hits.Count -eq 0) {
        $html += "<p class='ok'>No $Severity findings.</p>"
    } else {
        foreach ($h in $hits) {
            $html += "<h3 class='db-heading'>Database: <strong>$([System.Web.HttpUtility]::HtmlEncode($h.Name))</strong> <span class='count'>($(@($h.Findings).Count) finding(s))</span></h3>"
            $html += (Convert-DbFindingsToTable $h.Findings)
        }
    }
    $html += "</section>"
    return $html
}

# Convert HTML to PDF using Microsoft Edge in headless mode. Edge ships
# with every modern Windows install. Returns $true on success.
function Convert-HtmlToPdf {
    param([string]$Html, [string]$Pdf)
    $candidates = @(
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"
    )
    $edge = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $edge) {
        Write-Warning "Microsoft Edge not found. Skipping PDF conversion. Use -NoPdf to suppress this message."
        return $false
    }
    # file:// URL: forward slashes, encoded spaces
    $uri = ([System.Uri](Resolve-Path $Html).Path).AbsoluteUri
    & $edge --headless --disable-gpu --no-pdf-header-footer --print-to-pdf="$Pdf" $uri 2>&1 | Out-Null
    if (Test-Path $Pdf) { return $true }
    Write-Warning "Edge headless run did not produce $Pdf"
    return $false
}

# ===========================================================================
# Main
# ===========================================================================
$contexts = Get-ReportContexts $ReportDir
if (-not $contexts -or @($contexts).Count -eq 0) {
    Write-Error "No report sub-folders found in $ReportDir. Expected mssql_perf_* sub-folders."
    exit 3
}

# Process every context
$report = @()
foreach ($ctx in $contexts) {
    $findings = Get-Findings $ctx.LogDir
    $summary  = Read-AuditSummary (Join-Path $ctx.LogDir "_summary.txt")
    $passed   = @($summary | Where-Object { $_.Status -eq 'OK' }).Count
    $failed   = @($summary | Where-Object { $_.Status -eq 'FAIL' }).Count
    $crit     = @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $warn     = @($findings | Where-Object { $_.Severity -eq 'Warning' }).Count
    $info     = @($findings | Where-Object { $_.Severity -eq 'Info' }).Count

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
@page { size: A4; margin: 18mm 14mm 18mm 14mm; }
body{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:24px;background:#fff;color:#222;font-size:10.5pt;line-height:1.45;}
h1{margin:0 0 4px 0;font-size:22pt;}
h2{font-size:15pt;margin-top:24px;}
h3{font-size:12pt;margin-top:16px;margin-bottom:6px;}
header{background:#2a6db0;color:white;padding:22px 24px;border-radius:6px;margin-bottom:18px;}
header p{margin:4px 0;opacity:0.95;}
.summary{background:#f7f9fc;padding:14px 18px;border-radius:6px;margin-bottom:18px;border:1px solid #dde6ef;}
table{border-collapse:collapse;width:100%;background:white;font-size:9.5pt;}
th,td{padding:6px 8px;border-bottom:1px solid #e0e0e0;text-align:left;vertical-align:top;}
th{background:#eef2f7;font-weight:600;}
.findings{margin-bottom:14px;}
.badge{display:inline-block;padding:2px 10px;border-radius:3px;font-size:0.85em;font-weight:600;color:white;letter-spacing:0.5px;}
.badge.critical{background:#c0392b;}
.badge.warning {background:#e67e22;}
.badge.info    {background:#2980b9;}
section.severity{margin-top:24px;page-break-inside:auto;}
section.sev-critical{border-left:5px solid #c0392b;padding-left:14px;}
section.sev-warning {border-left:5px solid #e67e22;padding-left:14px;}
section.sev-info    {border-left:5px solid #2980b9;padding-left:14px;}
h2.sev-h2{padding:6px 0;border-bottom:2px solid #ddd;}
h2.sev-critical{color:#c0392b;}
h2.sev-warning {color:#e67e22;}
h2.sev-info    {color:#2980b9;}
h2 .count, h3 .count{font-size:0.65em;color:#666;font-weight:400;letter-spacing:0;}
h3.db-heading{background:#f4f6fa;padding:6px 10px;border-radius:4px;margin-top:14px;color:#2a6db0;}
.detail{color:#555;font-size:0.85em;font-family:Consolas,monospace;white-space:pre-wrap;}
.ok{color:#27ae60;font-weight:600;font-style:italic;}
.exec-summary td.num{text-align:right;font-variant-numeric:tabular-nums;}
.exec-summary td.crit{color:#c0392b;font-weight:600;}
.exec-summary td.warn{color:#e67e22;font-weight:600;}
.exec-summary td.fail{color:#c0392b;font-weight:600;}
code{background:#f0f0f0;padding:1px 5px;border-radius:3px;font-size:0.88em;}
section.severity{page-break-before:always;}
section.severity:first-of-type{page-break-before:auto;}
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
<h2 style='margin-top:0;'>Executive Summary</h2>
<p><strong>Databases analyzed:</strong> $(@($report).Count) &nbsp; | &nbsp;
   <strong>Total findings:</strong> $($totalCrit + $totalWarn + (($report | Measure-Object -Property Info -Sum).Sum)) &nbsp; | &nbsp;
   <strong>Failed scripts:</strong> <span class='fail'>$totalFail</span></p>
<table class='exec-summary'>
<thead><tr><th>Database / Context</th><th>Scripts OK</th><th>Failed</th><th>Critical</th><th>Warning</th><th>Info</th></tr></thead>
<tbody>
"@
foreach ($r in $report) {
    $html += "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($r.Name))</td>"
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

# Severity sections (Critical -> Warning -> Info), with per-database
# sub-headings inside each. This matches the customer-facing report
# format (one section per severity, findings grouped by database).
$html += (Convert-SeveritySectionToHtml -Severity 'Critical' -Report $report)
$html += (Convert-SeveritySectionToHtml -Severity 'Warning'  -Report $report)
$html += (Convert-SeveritySectionToHtml -Severity 'Info'     -Report $report)

$html += "</body></html>"

# Write HTML (UTF-8 with BOM so Edge / browsers detect encoding correctly).
$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($HtmlPath, $html, $utf8Bom)

# Convert to PDF unless suppressed.
$pdfMade = $false
if (-not $NoPdf) {
    $pdfPath = if ($OutFile -like "*.pdf") { $OutFile } else { [System.IO.Path]::ChangeExtension($OutFile, "pdf") }
    $pdfMade = Convert-HtmlToPdf -Html $HtmlPath -Pdf $pdfPath
    if ($pdfMade -and -not $KeepHtml -and ($HtmlPath -ne $OutFile)) {
        Remove-Item $HtmlPath -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "================================================================================"
Write-Host "Performance audit analysis complete."
Write-Host "  Databases analyzed : $(@($report).Count)"
Write-Host "  Critical findings  : $totalCrit"
Write-Host "  Warnings           : $totalWarn"
Write-Host "  Failed scripts     : $totalFail"
if ($NoPdf) {
    Write-Host "  Report (HTML)      : $HtmlPath"
} elseif ($pdfMade) {
    Write-Host "  Report (PDF)       : $pdfPath"
    if ($KeepHtml) { Write-Host "  Report (HTML)      : $HtmlPath" }
} else {
    Write-Host "  Report (HTML only) : $HtmlPath  (Edge headless not available -- PDF skipped)"
}
Write-Host "================================================================================"
