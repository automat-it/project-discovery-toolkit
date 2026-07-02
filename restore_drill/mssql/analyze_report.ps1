<#
=============================================================================
Analyze a SQL Server restore-drill report folder and render the branded HTML
(and PDF) report - mssql_restore_analysis.(html|pdf).

    pwsh -File analyze_report.ps1 -ReportDir <dir> [-ServerName LABEL]
         [-Customer NAME] [-OutFile PATH] [-NoPdf]

It parses the structured per-check .log files + _summary.txt the runner
writes and produces the same report layout as the PostgreSQL/MySQL
restore-drill analyzers, reusing the db-audit-scripts shared CSS, brand
assets and (where a browser exists) the toolkit's Convert-HtmlToPdf.
=============================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ReportDir,
    [string]$ServerName = "",
    [string]$Customer   = "",
    [string]$OutFile    = "",
    [switch]$NoPdf
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ReportDir -PathType Container)) { Write-Error "report dir not found: $ReportDir"; exit 2 }
if (-not (Get-ChildItem -LiteralPath $ReportDir -Filter *.log -ErrorAction SilentlyContinue)) { Write-Error "no .log files in $ReportDir"; exit 3 }

# Reuse the toolkit's helpers where available (Esc, Convert-HtmlToPdf).
$libPath = Join-Path $PSScriptRoot "../../db-audit-scripts/mssql/_analyze_lib.ps1"
if (Test-Path $libPath) { try { . $libPath } catch { Write-Host "[warn] could not load $libPath : $($_.Exception.Message) - using built-in fallbacks" } }
if (-not (Get-Command Esc -ErrorAction SilentlyContinue)) {
    function Esc($s) { if ($null -eq $s) { return '' }; return [System.Net.WebUtility]::HtmlEncode([string]$s) }
}

$EngineLabel = 'SQL Server'
$DefaultName = 'mssql_restore_analysis'

# --- per-check metadata (shared check IDs -> remediation + chart bucket) ------
$CheckMeta = @{
    'rd_01_backup_create'   = @{ domain = 'Backup';  rec = 'Investigate why the backup could not be produced (permissions, disk space, backup device). A DR plan with no working backup is the single highest-priority gap.' }
    'rd_02_restore_execute' = @{ domain = 'Restore'; rec = 'The backup exists but cannot be restored, so it is effectively useless. Check the RESTORE errors for version/edition incompatibilities, missing files, or a damaged backup, and re-test.' }
    'rd_02_backup_verify'   = @{ domain = 'Restore'; rec = 'RESTORE VERIFYONLY failed - the backup is incomplete or corrupt and cannot be relied on. Re-take it. Note: verify-only proves the backup is readable, not that data restores faithfully - run a full restore drill periodically.' }
    'rd_03_restore_online'  = @{ domain = 'Restore'; rec = 'The restored database does not come ONLINE. Review the restore log for fatal errors and confirm the recovery instance is healthy.' }
    'rd_04_object_parity'   = @{ domain = 'Integrity'; rec = 'Schema objects are missing after restore. Confirm the backup is a full backup of the whole database and that the RESTORE ran to completion.' }
    'rd_05_rowcount_parity' = @{ domain = 'Integrity'; rec = 'Rows are missing after restore - this is data loss. Verify the backup captured a consistent point in time and look for partial restore failures.' }
    'rd_06_integrity_check' = @{ domain = 'Integrity'; rec = 'DBCC CHECKDB found corruption in the restored copy. The backup itself may contain corruption - run CHECKDB on the source and review storage health.' }
    'rd_07_rto'             = @{ domain = 'Recovery objectives'; rec = 'Restore is slower than the recovery-time objective. Consider instant file initialization, faster storage, compressed backups, or log shipping / Availability Groups for large databases.' }
    'rd_08_rpo_backup_age'  = @{ domain = 'Recovery objectives'; rec = 'The backup is older than the recovery-point objective. Increase full/differential backup frequency and shorten the transaction-log backup interval.' }
    'rd_09_data_checksum'   = @{ domain = 'Integrity'; rec = 'Row-content checksums differ between source and restored copy - silent corruption or an inconsistent backup. Investigate before relying on this backup.' }
}
$TierRank = @{ 'critical' = 0; 'high' = 1; 'medium' = 2; 'low' = 3 }

# --- shared CSS (identical to the db-audit-scripts analyzers) -----------------
$SharedCss = @'
<style>
@page{size:A4 portrait;margin:18mm 14mm;@bottom-center{content:counter(page) ' / ' counter(pages);font-size:8pt;color:#777;}}
@media print{body{background:white !important;padding:0;}.card,section.db{box-shadow:none !important;background:white !important;}}
.page-bg{position:fixed;top:0;left:0;right:0;bottom:0;z-index:-1;background-image:url('ait_bg_page.png');background-size:100% 100%;background-repeat:no-repeat;background-position:center;opacity:0.5;}
.cover{position:relative;width:100%;height:calc(297mm - 36mm);page-break-after:always;break-after:page;background-image:url('ait_bg_cover.png');background-size:100% 100%;background-repeat:no-repeat;background-position:center;color:#000;text-align:center;}
.cover-content{position:absolute;left:0;right:0;top:55%;padding:0 16mm;}
.cover h1{font-size:24pt;font-weight:800;color:#000;margin:0 0 10px;}
.cover .sub{font-size:13pt;color:#333;margin:0 0 4px;font-weight:500;}
.cover .meta{font-size:11pt;color:#444;margin:0 0 6px;}
.cover .date{font-size:11pt;color:#666;margin-top:8px;}
@media screen{.cover{background-color:#f5f5f5;}}
body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;padding:20px;background:#f5f5f5;color:#222;line-height:1.4;font-size:9.5pt;}
h1{margin:0 0 4px 0;}
h2{border-bottom:2px solid #336791;padding-bottom:4px;margin-top:28px;color:#336791;}
h3{margin:14px 0 6px;color:#1F497D;}
.card{background:white;padding:16px 20px;border-radius:6px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,0.1);}
table{border-collapse:collapse;width:100%;background:white;font-size:0.95em;}
th,td{padding:6px 10px;border-bottom:1px solid #e0e0e0;text-align:left;vertical-align:top;}
th{background:#eaf0f6;font-weight:600;color:#1F497D;}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:0.85em;font-weight:600;color:white;}
.detail{color:#555;font-size:0.9em;font-family:Consolas,monospace;white-space:pre-wrap;}
.ok{color:#27ae60;font-weight:600;}
.kpi-row{display:flex;gap:12px;flex-wrap:wrap;margin:6px 0 16px;}
.kpi{flex:1;min-width:160px;background:rgba(255,255,255,0.92);border:1px solid #d6e6b9;border-radius:6px;padding:14px 16px;}
.kpi .num{font-size:22pt;font-weight:700;color:#1F497D;line-height:1.1;display:block;margin-top:4px;}
.kpi .num.crit{color:#c0392b;}.kpi .num.warn{color:#e67e22;}.kpi .num.ok{color:#27ae60;}
.kpi .lbl{font-size:9pt;color:#666;text-transform:uppercase;letter-spacing:0.5px;}
.section{margin:18px 0 10px;}
.section h2{margin:0 0 6px;font-size:17pt;color:#1F497D;border-bottom:1px solid #d6e6f0;padding-bottom:4px;}
.section .intro{color:#444;font-size:10pt;margin:0 0 12px;}
.charts-row{display:flex;flex-wrap:wrap;gap:24px;align-items:flex-start;margin:14px 0 8px;}
.charts-row > div{flex:1;min-width:320px;}
.charts-row h3{margin-top:0;color:#1F497D;font-size:11pt;}
@media print{
    .section{page-break-inside:avoid;break-inside:avoid;}
    .section h2{page-break-after:avoid;break-after:avoid;}
    table.results thead{display:table-header-group;}
    table.results tr{page-break-inside:avoid;break-inside:avoid;}
}
dl.fp{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;font-size:0.95em;margin:0;}
dl.fp dt{font-weight:600;color:#444;}
dl.fp dd{margin:0;font-family:Consolas,monospace;}
.finding{background:white;border-radius:6px;padding:14px 18px;margin:14px 0;box-shadow:0 1px 3px rgba(0,0,0,0.07);border-left:5px solid #999;}
.finding.sev-critical{border-left-color:#c0392b;}
.finding.sev-warning{border-left-color:#e67e22;}
.finding.sev-info{border-left-color:#2980b9;}
.finding-head{display:flex;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:6px;}
.finding-title{font-weight:700;color:#1F497D;font-size:1.05em;flex:1;}
.finding-script{font-size:0.82em;color:#666;}
.finding-rec{background:#f6f8fb;border-radius:4px;padding:6px 10px;margin:4px 0 8px;font-size:0.95em;}
.finding-detail{color:#666;font-size:0.85em;font-family:Consolas,monospace;margin:0 0 4px;white-space:pre-wrap;}
.note{background:#fff8e1;border-left:4px solid #e67e22;padding:8px 12px;border-radius:4px;margin:8px 0;}
.tldr{background:#eef4fb;border-left:5px solid #1F497D;border-radius:5px;padding:13px 18px;margin:4px 0 14px;font-size:11.5pt;color:#1f2d3d;line-height:1.55;page-break-inside:avoid;break-inside:avoid;}
.nextsteps{background:#fff8ef;border:1px solid #f0d9bd;border-radius:6px;padding:4px 20px 14px;margin:0 0 18px;page-break-inside:avoid;break-inside:avoid;}
.nextsteps h3{margin:12px 0 6px;color:#b9651b;border:none;}
.nextsteps ol{margin:6px 0 2px;padding-left:20px;}
.nextsteps li{margin:6px 0;color:#333;font-size:10pt;line-height:1.45;}
pre.cmd{background:#1e1e1e;color:#d4d4d4;padding:10px 14px;border-radius:4px;font-family:Consolas,monospace;font-size:0.85em;white-space:pre-wrap;word-break:break-word;page-break-inside:avoid;margin:4px 0 10px;}
details.sql-index{margin:8px 0 16px;background:#f6f8fb;border:1px solid #d6e6f0;border-radius:4px;padding:8px 12px;}
details.sql-index summary{font-weight:600;color:#1F497D;cursor:pointer;}
.badge.pass{background:#27ae60;}.badge.warn{background:#e67e22;}.badge.fail{background:#c0392b;}
.badge.critical{background:#c0392b;}.badge.warning{background:#e67e22;}.badge.info{background:#2980b9;}
.verdict{display:flex;align-items:baseline;gap:14px;padding:14px 20px;border-radius:8px;margin:6px 0 16px;font-weight:600;line-height:1.45;page-break-inside:avoid;}
.verdict .big{font-size:20pt;font-weight:800;letter-spacing:0.5px;}
.verdict.pass{background:#eafaf1;border-left:6px solid #27ae60;color:#1e7e45;}
.verdict.warn{background:#fff6ec;border-left:6px solid #e67e22;color:#9c5410;}
.verdict.fail{background:#fdecea;border-left:6px solid #c0392b;color:#a02b1f;}
table.results td.st{white-space:nowrap;}
table.results td.metric,table.results td.thr{font-family:Consolas,monospace;font-size:0.9em;white-space:nowrap;}
table.results tr.row-fail td:first-child{border-left:4px solid #c0392b;}
table.results tr.row-warn td:first-child{border-left:4px solid #e67e22;}
table.results tr.row-pass td:first-child{border-left:4px solid #27ae60;}
</style>
'@

# --- parsing ----------------------------------------------------------------
function Parse-CheckLog($path) {
    $fields = @{}; $body = New-Object System.Collections.Generic.List[string]; $inBody = $false
    foreach ($ln in (Get-Content -LiteralPath $path)) {
        if ($ln -like '--- output*') { $inBody = $true; continue }
        if ($inBody) { $body.Add($ln); continue }
        if ($ln -match '^(Check|Tier|Title|Status|Metric|Threshold|Detail):\s*(.*)$') { $fields[$Matches[1].ToLower()] = $Matches[2].Trim() }
    }
    $fields['output'] = ($body -join "`n").Trim()
    return $fields
}
function Parse-Summary($path) {
    $o = @{}
    if (Test-Path $path) {
        foreach ($ln in (Get-Content -LiteralPath $path)) {
            if ($ln -match '^(Engine|Category|Timestamp|Source|Target|Backup|RTO|RPO|Rows|Verdict|Pass|Warn|Fail):\s*(.*)$') { $o[$Matches[1].ToLower()] = $Matches[2].Trim() }
        }
    }
    return $o
}

$checks = @()
foreach ($f in (Get-ChildItem -LiteralPath $ReportDir -Filter *.log | Sort-Object Name)) {
    $c = Parse-CheckLog $f.FullName
    if (-not $c.ContainsKey('check')) { continue }
    $c['logfile'] = $f.Name
    $checks += , $c
}
$checks = @($checks | Sort-Object @{ Expression = { $TierRank[$_['tier']] } }, @{ Expression = { $_['check'] } })
if ($checks.Count -eq 0) { Write-Error "no parseable restore-drill checks in $ReportDir (the .log files are missing the structured header)"; exit 3 }
$summary = Parse-Summary (Join-Path $ReportDir '_summary.txt')

$nPass = @($checks | Where-Object { $_['status'] -eq 'PASS' }).Count
$nWarn = @($checks | Where-Object { $_['status'] -eq 'WARN' }).Count
$nFail = @($checks | Where-Object { $_['status'] -eq 'FAIL' }).Count
$nOther = @($checks | Where-Object { $_['status'] -notin 'PASS', 'WARN', 'FAIL' }).Count
$nFail += $nOther   # unrecognized status counts as non-pass, never success
$total = $checks.Count
# Single canonical verdict: trust _summary.txt only for a known token.
$sv = "$($summary['verdict'])".Trim().ToUpper()
$verdict = if ($sv -in 'PASS', 'WARN', 'FAIL') { $sv } elseif ($nFail) { 'FAIL' } elseif ($nWarn) { 'WARN' } else { 'PASS' }

# --- small render helpers ---------------------------------------------------
function Badge($st) {
    switch ($st) { 'PASS' { "<span class='badge pass'>PASS</span>" } 'WARN' { "<span class='badge warn'>WARN</span>" } 'FAIL' { "<span class='badge fail'>FAIL</span>" } default { Esc $st } }
}
function Status-Donut($passed, $warned, $failed) {
    $tot = $passed + $warned + $failed
    if ($tot -le 0) { return "<p class='ok'>No checks recorded.</p>" }
    $rad = 80; $cx = 110; $cy = 110; $stroke = 30
    $vals = @(@('Passed', $passed, '#27ae60'), @('Warning', $warned, '#e67e22'), @('Failed', $failed, '#c0392b'))
    $nz = @($vals | Where-Object { $_[1] -gt 0 })
    $sb = New-Object System.Text.StringBuilder
    if ($nz.Count -eq 1) {
        [void]$sb.Append("<circle cx='$cx' cy='$cy' r='$rad' fill='$($nz[0][2])'/>")
    }
    else {
        $offset = 0.0
        foreach ($v in $nz) {
            $angle = 360.0 * $v[1] / $tot
            $a1 = ($offset - 90) * [math]::PI / 180.0
            $a2 = ($offset + $angle - 90) * [math]::PI / 180.0
            $x1 = $cx + $rad * [math]::Cos($a1); $y1 = $cy + $rad * [math]::Sin($a1)
            $x2 = $cx + $rad * [math]::Cos($a2); $y2 = $cy + $rad * [math]::Sin($a2)
            $large = if ($angle -gt 180) { 1 } else { 0 }
            # Invariant-culture coords: a comma decimal (de-DE etc.) or thousands
            # separator would corrupt the SVG path data.
            $inv = [Globalization.CultureInfo]::InvariantCulture
            [void]$sb.Append("<path d='M $cx $cy L $($x1.ToString('0.##',$inv)) $($y1.ToString('0.##',$inv)) A $rad $rad 0 $large 1 $($x2.ToString('0.##',$inv)) $($y2.ToString('0.##',$inv)) Z' fill='$($v[2])'/>")
            $offset += $angle
        }
    }
    [void]$sb.Append("<circle cx='$cx' cy='$cy' r='$($rad - $stroke)' fill='white'/>")
    [void]$sb.Append("<text x='$cx' y='$($cy - 3)' text-anchor='middle' font-size='22' font-weight='600' fill='#222'>$tot</text>")
    [void]$sb.Append("<text x='$cx' y='$($cy + 18)' text-anchor='middle' font-size='10' fill='#777'>checks</text>")
    [void]$sb.Append("<g font-family='-apple-system,Segoe UI,Roboto,Helvetica,Arial' font-size='12'>")
    $ly = 30
    foreach ($v in $vals) {
        [void]$sb.Append("<rect x='240' y='$ly' width='14' height='14' fill='$($v[2])'/>")
        [void]$sb.Append("<text x='262' y='$($ly + 12)' fill='#222'>$($v[0]): $($v[1])</text>")
        $ly += 22
    }
    [void]$sb.Append("</g>")
    return "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 380 220' width='380' height='220'>$($sb.ToString())</svg>"
}
function Bar-Chart($items) {
    $items = @($items | Where-Object { $_.Value -gt 0 })
    if ($items.Count -eq 0) { return '' }
    $maxN = ($items | Measure-Object -Property Value -Maximum).Maximum; if ($maxN -le 0) { $maxN = 1 }
    $rowH = 22; $padTop = 10; $padLeft = 200; $width = 600
    $h = $padTop + $rowH * $items.Count + 10
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 $width $h' width='$width' height='$h' font-family='-apple-system,Segoe UI,Roboto,Helvetica,Arial' font-size='12'>")
    $y = $padTop
    foreach ($it in $items) {
        $w = [int](($width - $padLeft - 50) * $it.Value / $maxN)
        [void]$sb.Append("<text x='$($padLeft - 8)' y='$($y + 14)' text-anchor='end' fill='#333'>$(Esc $it.Label)</text>")
        [void]$sb.Append("<rect x='$padLeft' y='$y' width='$w' height='16' fill='#1F497D'/>")
        [void]$sb.Append("<text x='$($padLeft + $w + 6)' y='$($y + 14)' fill='#333'>$($it.Value)</text>")
        $y += $rowH
    }
    [void]$sb.Append("</svg>")
    return $sb.ToString()
}
function KvGrid($pairs) {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<dl class='fp'>")
    foreach ($p in $pairs) {
        $v = if ($p[1]) { $p[1] } else { '(unknown)' }
        [void]$sb.Append("<dt>$(Esc $p[0])</dt><dd>$(Esc $v)</dd>")
    }
    [void]$sb.Append("</dl>")
    return $sb.ToString()
}
function First-Token($s) { if ($s -match '^\s*(\S+)') { return $Matches[1] } else { return '-' } }

# --- headline numbers -------------------------------------------------------
$rto = if ($summary['rto']) { $summary['rto'] } else { '-' }
$rpo = if ($summary['rpo']) { $summary['rpo'] } else { '-' }
$rows = if ($summary['rows']) { $summary['rows'] } else { '-' }
$rtoShort = First-Token $rto
$rpoShort = First-Token $rpo
$backupSize = if ($summary['backup'] -match '\(([^,]+),') { $Matches[1].Trim() } else { 'n/a' }
$srcShort = if ($summary['source']) { ($summary['source'] -split '/')[-1] } else { 'the source database' }
$serverLabel = if ($ServerName) { $ServerName } elseif ($summary['target']) { ($summary['target'] -split '/')[0] } else { '' }
$title = "$EngineLabel Restore-Drill Report"

# --- build HTML -------------------------------------------------------------
$H = New-Object System.Text.StringBuilder
[void]$H.Append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><title>$(Esc $title)</title>$SharedCss</head><body>")

# cover
$cust = if ($Customer) { Esc $Customer } else { '&nbsp;' }
$serverShown = if ($serverLabel) { $serverLabel } else { '(unspecified)' }   # mirror render_cover's fallback
$dateStr = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
[void]$H.Append("<section class='cover'><div class='cover-content'><h1>$(Esc $title)</h1><div class='sub'>$cust</div><div class='meta'><strong>Server:</strong> $(Esc $serverShown) &nbsp;&middot;&nbsp; <strong>1</strong> database analyzed</div><div class='date'>$dateStr</div></div></section><div class='page-bg'></div>")

# executive summary
[void]$H.Append("<div class='section'><h2>Executive summary</h2>")
$vkey = $verdict.ToLower()
$vmsg = switch ($verdict) {
    'PASS' { 'Restore drill passed - the backup is restorable and the restored copy matches the source on every check.' }
    'WARN' { 'Restore drill completed with warnings - the data is recoverable, but one or more recovery objectives were missed.' }
    default { 'Restore drill failed - this backup cannot be relied on for recovery in its current state. Fix before an incident forces the issue.' }
}
[void]$H.Append("<div class='verdict $vkey'><span class='big'>$(Esc $verdict)</span><span>$(Esc $vmsg)</span></div>")

$nonpass = @($checks | Where-Object { $_['status'] -ne 'PASS' } | Sort-Object @{Expression={ if($_['status'] -eq 'FAIL'){0}else{1} }}, @{Expression={ $TierRank[$_['tier']] }})
if ($verdict -eq 'PASS') {
    $tldr = "<strong>Bottom line:</strong> the backup of <em>$(Esc $srcShort)</em> restored cleanly into a throw-away scratch database and matched the source on all $total checks - objects, row counts ($(Esc $rows) rows), integrity and row-content checksums. Recovery is proven, and the restore finished in $(Esc $rto)."
}
elseif ($verdict -eq 'WARN') {
    $plural = if ($nWarn -ne 1) { 's' } else { '' }
    $tldr = "<strong>Bottom line:</strong> the backup of <em>$(Esc $srcShort)</em> restored and verified correctly ($nPass/$total checks passed), but $nWarn recovery-objective warning$plural need attention. The data is recoverable."
}
else {
    $tldr = "<strong>Bottom line:</strong> the restore drill for <em>$(Esc $srcShort)</em> failed $nFail of $total checks. This backup is not currently a reliable recovery source."
}
[void]$H.Append("<div class='tldr'>$tldr</div>")
if ($nonpass.Count -gt 0) {
    [void]$H.Append("<div class='nextsteps'><h3>Next steps - what to fix first</h3><ol>")
    foreach ($c in ($nonpass | Select-Object -First 3)) {
        $rec = if ($CheckMeta.ContainsKey($c['check'])) { $CheckMeta[$c['check']].rec } else { '' }
        [void]$H.Append("<li><strong>$(Esc $c['title'])</strong> - $(Esc $rec)</li>")
    }
    [void]$H.Append("</ol></div>")
}

# KPI cards
$verdictCls = switch ($verdict) { 'PASS' { 'ok' } 'WARN' { 'warn' } default { 'crit' } }
$passCls = if ($nFail -eq 0 -and $nWarn -eq 0) { 'ok' } elseif ($nFail) { 'crit' } else { 'warn' }
$kpis = @(
    @('Drill result', $verdict, $verdictCls),
    @('Checks passed', "$nPass/$total", $passCls),
    @('Restore time (RTO)', $rtoShort, ''),
    @('Backup size', $backupSize, ''),
    @('Backup age (RPO)', $rpoShort, ''),
    @('Rows verified', $rows, '')
)
[void]$H.Append("<div class='kpi-row'>")
foreach ($k in $kpis) {
    $ncls = if ($k[2]) { " $($k[2])" } else { '' }
    [void]$H.Append("<div class='kpi'><div class='lbl'>$(Esc $k[0])</div><span class='num$ncls'>$(Esc $k[1])</span></div>")
}
[void]$H.Append("</div>")

# charts
$domainCounts = [ordered]@{}   # preserve first-seen (priority) order, matching the Python analyzer
foreach ($c in $checks) {
    $dom = if ($CheckMeta.ContainsKey($c['check'])) { $CheckMeta[$c['check']].domain } else { 'Other' }
    if ($domainCounts.Contains($dom)) { $domainCounts[$dom]++ } else { $domainCounts[$dom] = 1 }
}
$barItems = $domainCounts.GetEnumerator() | ForEach-Object { @{ Label = $_.Key; Value = $_.Value } }
[void]$H.Append("<div class='charts-row'><div><h3>Check outcomes</h3>$(Status-Donut $nPass $nWarn $nFail)</div><div><h3>Checks by area</h3>$(Bar-Chart $barItems)</div></div></div>")

# drill parameters
$params = @(
    @('Engine', $EngineLabel),
    @('Source database', $summary['source']),
    @('Scratch database', $summary['target']),
    @('Backup', $summary['backup']),
    @('Recovery time (RTO)', $summary['rto']),
    @('Recovery point (RPO)', $summary['rpo']),
    @('Rows verified', $summary['rows']),
    @('Run timestamp', $summary['timestamp']),
    @('Report folder', (Split-Path -Leaf $ReportDir)),
    @('Generated', $dateStr)
)
[void]$H.Append("<div class='card'><h2 style='margin-top:0;border:none;'>Drill parameters</h2>$(KvGrid $params)</div>")

# results table
[void]$H.Append("<div class='section'><h2>Drill results</h2><p class='intro'>Every check, in priority order. The drill is non-destructive on the source (COPY_ONLY backup); the scratch database is dropped on completion.</p>")
[void]$H.Append("<table class='results'><thead><tr><th>Status</th><th>Tier</th><th>Check</th><th>Result</th><th>Threshold</th><th>Detail</th></tr></thead><tbody>")
foreach ($c in $checks) {
    $st = $c['status']
    $rowcls = switch ($st) { 'PASS' { 'row-pass' } 'WARN' { 'row-warn' } default { 'row-fail' } }
    $metric = if ($c['metric']) { $c['metric'] } else { '-' }
    $thr = if ($c['threshold']) { $c['threshold'] } else { '-' }
    [void]$H.Append("<tr class='$rowcls'><td class='st'>$(Badge $st)</td><td>$(Esc $c['tier'])</td><td>$(Esc $c['title'])</td><td class='metric'>$(Esc $metric)</td><td class='thr'>$(Esc $thr)</td><td class='detail'>$(Esc $c['detail'])</td></tr>")
}
[void]$H.Append("</tbody></table></div>")

# findings
[void]$H.Append("<div class='section'><h2>Findings</h2>")
if ($nonpass.Count -eq 0) {
    [void]$H.Append("<div class='note'><span class='ok'>No issues.</span> Every check passed - the backup is proven restorable and faithful to the source.</div>")
}
else {
    foreach ($c in $nonpass) {
        $sev = switch ($c['status']) { 'FAIL' { 'critical' } 'WARN' { 'warning' } default { 'info' } }
        $rec = if ($CheckMeta.ContainsKey($c['check'])) { $CheckMeta[$c['check']].rec } else { '' }
        [void]$H.Append("<div class='finding sev-$sev'>")
        [void]$H.Append("<div class='finding-head'><span class='finding-title'>$(Esc $c['title'])</span><span class='finding-script'>$(Badge $c['status']) &middot; $(Esc $c['check'])</span></div>")
        if ($c['detail']) { [void]$H.Append("<div class='finding-detail'>$(Esc $c['detail'])</div>") }
        if ($rec) { [void]$H.Append("<div class='finding-rec'>$(Esc $rec)</div>") }
        if ($c['output']) {
            $ex = if ($c['output'].Length -lt 2000) { $c['output'] } else { $c['output'].Substring(0, 2000) + "`n... (truncated, see raw log)" }
            [void]$H.Append("<pre class='cmd'>$(Esc $ex)</pre>")
        }
        [void]$H.Append("</div>")
    }
}
[void]$H.Append("</div>")

# appendix
[void]$H.Append("<div class='section' id='appendix'><h2>Raw check output</h2>")
foreach ($c in $checks) {
    $out = if ($c['output']) { $c['output'] } else { '(no output)' }
    [void]$H.Append("<details class='sql-index'><summary>$(Badge $c['status']) $(Esc $c['logfile'])</summary><pre class='cmd'>$(Esc $out)</pre></details>")
}
[void]$H.Append("</div></body></html>")

# --- write + assets + pdf ---------------------------------------------------
$ext = if ($NoPdf) { 'html' } else { 'pdf' }
if (-not $OutFile) { $OutFile = Join-Path $ReportDir "$DefaultName.$ext" }
# Build the HTML path from directory + basename, not ChangeExtension: a dot in
# a FOLDER name would make ChangeExtension truncate the wrong "extension".
$outDirPart = Split-Path -Parent $OutFile
if (-not $outDirPart) { $outDirPart = '.' }
$htmlPath = Join-Path $outDirPart ([System.IO.Path]::GetFileNameWithoutExtension($OutFile) + '.html')
$html = $H.ToString()
Set-Content -LiteralPath $htmlPath -Value $html -Encoding utf8

# brand assets next to the HTML
$assetsDir = Join-Path $PSScriptRoot '../../db-audit-scripts/assets'
foreach ($a in 'ait_bg_cover.png', 'ait_bg_page.png') {
    $src = Join-Path $assetsDir $a
    if (Test-Path $src) { Copy-Item -LiteralPath $src -Destination (Join-Path (Split-Path -Parent $htmlPath) $a) -Force }
}

if (-not $NoPdf) {
    $ok = $false
    if (Get-Command Convert-HtmlToPdf -ErrorAction SilentlyContinue) {
        # The toolkit's Convert-HtmlToPdf takes the HTML FILE PATH (it loads it
        # into the browser via a file:// URI), not the HTML content string.
        try { Convert-HtmlToPdf -Html $htmlPath -Pdf $OutFile; $ok = (Test-Path $OutFile) } catch { $ok = $false }
    }
    if ($ok) { Write-Host "[OK] wrote $OutFile" }
    else { Write-Host "[warn] no HTML->PDF renderer available; wrote HTML only: $htmlPath" }
}
else {
    Write-Host "[OK] wrote $htmlPath"
}
exit 0
