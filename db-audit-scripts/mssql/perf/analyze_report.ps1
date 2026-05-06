#Requires -Version 5.1
<#
.SYNOPSIS
    SQL Server PERFORMANCE audit PDF report.

.DESCRIPTION
    Reads the report directory produced by run_audit.ps1 / run_all_databases.ps1
    and renders a customer-facing report in the style of a security-assessment
    deliverable. Includes:
      - Cover page with server fingerprint and severity donut chart
      - Executive summary (instance-wide rollup + per-domain bar chart)
      - Server-wide vs database-level findings (deduplicated, not 123 copies)
      - Top-N rankings (most fragmented indexes, oldest backups, largest tables...)
      - Compliance mapping (CIS Benchmark, GDPR, SOC2)
      - Phased remediation roadmap with executable T-SQL snippets
      - Per-database appendix with full per-DB findings
      - Glossary of wait types and DMV terms

    Default output: <ReportDir>\perf_analysis.pdf (with .html intermediate).

.PARAMETER ReportDir
    Folder produced by run_audit.ps1 / run_all_databases.ps1.

.PARAMETER ServerName
    Server label printed on the cover.

.PARAMETER Customer
    Customer name printed on the cover. Optional.

.PARAMETER Brand
    Branding text shown on the cover page. Default: 'Automat-it'.

.PARAMETER OutFile
    Output path. Default: <ReportDir>\perf_analysis.pdf.

.PARAMETER NoPdf
    Skip PDF conversion -- produce HTML only.

.PARAMETER KeepHtml
    Keep the intermediate HTML alongside the PDF.

.EXAMPLE
    .\analyze_report.ps1 -ReportDir "C:\reports\mssql_audit_all_20260430_002619" `
                         -ServerName "STG-SQL-N1" -Customer "ACME Corp"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ReportDir,
    [string]$ServerName = "",
    [string]$Customer   = "",
    [string]$Brand      = "Automat-it",
    [string]$OutFile    = "",
    [switch]$NoPdf,
    [switch]$KeepHtml
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Web

if (-not (Test-Path $ReportDir)) {
    Write-Error "Report directory not found: $ReportDir"
    exit 2
}
$ReportDir = (Resolve-Path $ReportDir).Path
if (-not $OutFile) {
    $ext = if ($NoPdf) { 'html' } else { 'pdf' }
    $OutFile = Join-Path $ReportDir "perf_analysis.$ext"
}
$HtmlPath = if ($OutFile -like '*.html') { $OutFile } else { [System.IO.Path]::ChangeExtension($OutFile, 'html') }

function Esc { param($s) [System.Web.HttpUtility]::HtmlEncode([string]$s) }

# Severity ranking helper (avoids Sort-Object calculated-expression issues
# in PS5.1 when comparing across heterogeneous types).
# Safe count helper. PS5.1's (_Cnt $genericList) can raise
# 'Argument types do not match' when the list holds heterogeneous
# pscustomobjects with Add-Member''d note properties. Count via the
# native .Count property when present, otherwise iterate.
function _Cnt {
    param($x)
    if ($null -eq $x) { return 0 }
    try { if ($x.Count -is [int]) { return $x.Count } } catch {}
    $n = 0; foreach ($i in $x) { $n++ }
    return $n
}

function Get-SeverityRank {
    param([string]$Severity)
    if     ($Severity -eq 'Critical') { return 0 }
    elseif ($Severity -eq 'Warning')  { return 1 }
    elseif ($Severity -eq 'Info')     { return 2 }
    else { return 3 }
}

# Top-level trap so that any unhandled exception prints a useful line/column
# rather than the generic "Argument types do not match".
trap {
    $err = $_
    Write-Host ("=" * 80) -ForegroundColor Red
    Write-Host "ANALYZER ERROR" -ForegroundColor Red
    Write-Host ("Exception : " + $err.Exception.Message) -ForegroundColor Red
    if ($err.InvocationInfo) {
        Write-Host ("Location  : " + $err.InvocationInfo.PositionMessage) -ForegroundColor Red
    }
    if ($err.ScriptStackTrace) {
        Write-Host "Stack:" -ForegroundColor Red
        Write-Host $err.ScriptStackTrace -ForegroundColor DarkGray
    }
    Write-Host ("=" * 80) -ForegroundColor Red
    exit 99
}

# ===========================================================================
# Encoding-aware log readers
# ===========================================================================
function Get-LogEncoding {
    param([string]$LogPath)
    if (-not (Test-Path $LogPath)) { return [System.Text.Encoding]::UTF8 }
    $head = New-Object byte[] 4
    $read = 0
    try {
        $stream = [System.IO.File]::OpenRead($LogPath)
        try   { $read = $stream.Read($head, 0, 4) }
        finally { $stream.Dispose() }
    } catch { return [System.Text.Encoding]::UTF8 }
    if ($read -ge 2 -and $head[0] -eq 0xFF -and $head[1] -eq 0xFE) { return [System.Text.Encoding]::Unicode }
    if ($read -ge 2 -and $head[0] -eq 0xFE -and $head[1] -eq 0xFF) { return [System.Text.Encoding]::BigEndianUnicode }
    if ($read -ge 3 -and $head[0] -eq 0xEF -and $head[1] -eq 0xBB -and $head[2] -eq 0xBF) { return [System.Text.Encoding]::UTF8 }
    if ($read -ge 2 -and $head[0] -gt 0 -and $head[0] -lt 128 -and $head[1] -eq 0) { return [System.Text.Encoding]::Unicode }
    return [System.Text.Encoding]::UTF8
}
function Read-LogText  { param([string]$LogPath) if (Test-Path $LogPath) { [System.IO.File]::ReadAllText($LogPath, (Get-LogEncoding $LogPath)) } else { '' } }
function Read-LogLines { param([string]$LogPath) if (Test-Path $LogPath) { [System.IO.File]::ReadAllLines($LogPath, (Get-LogEncoding $LogPath)) } else { @() } }

function Read-AuditSummary {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return @() }
    $rows = @()
    foreach ($l in (Read-LogLines $Path)) {
        if ($l -match '^(OK|FAIL)\s+(\S+)') { $rows += [pscustomobject]@{ Status=$matches[1]; Path=$matches[2] } }
    }
    return $rows
}

# ===========================================================================
# Tabular sqlcmd parser
# A sqlcmd query output block looks like:
#     col1   col2   col3
#     -----  -----  -----
#     v1     v2     v3
#     ...
#     (N rows affected)
# Multiple result-sets in one log file are separated by their own header+
# underline pair. This parser yields one [pscustomobject] per data row.
# ===========================================================================
function Get-SqlCmdResultSets {
    param([string]$LogPath)
    $lines = Read-LogLines $LogPath
    if (-not $lines) { return @() }
    $sets = @()
    $i = 0
    while ($i -lt $lines.Count) {
        $line = [string]$lines[$i]
        if ($line -match '^[\s\-]+$' -and $line -match '\-{3,}') {
            # underline -- previous line was the header
            $headerLine = if ($i -gt 0) { [string]$lines[$i-1] } else { '' }
            if (-not $headerLine.Trim()) { $i++; continue }
            # parse column boundaries from the underline
            $u = $line.TrimEnd()
            $cols = @()
            $col = $null
            for ($p = 0; $p -lt $u.Length; $p++) {
                $ch = $u[$p]
                if ($ch -eq '-') {
                    if ($null -eq $col) { $col = @{ Start = $p; End = $p } }
                    else                { $col.End = $p }
                } else {
                    if ($null -ne $col) { $cols += [pscustomobject]@{ Start=$col.Start; End=$col.End }; $col = $null }
                }
            }
            if ($null -ne $col) { $cols += [pscustomobject]@{ Start=$col.Start; End=$col.End } }
            # column names from header line at the same offsets
            $names = @()
            foreach ($c in $cols) {
                $w  = $c.End - $c.Start + 1
                if ($c.Start -ge $headerLine.Length) { $names += "col$($names.Count + 1)"; continue }
                $end = [Math]::Min($headerLine.Length - 1, $c.Start + $w - 1)
                $raw = $headerLine.Substring($c.Start, $end - $c.Start + 1).Trim()
                if (-not $raw) { $raw = "col$($names.Count + 1)" }
                $names += $raw
            }
            # collect rows until empty line / "(N rows affected)" / Msg / next header underline
            $rows = New-Object System.Collections.Generic.List[object]
            $i++
            while ($i -lt $lines.Count) {
                $r = [string]$lines[$i]
                if ($r -match '^\s*\(\d+ rows? affected\)\s*$') { $i++; break }
                if ($r -match '^Msg\s+\d+,\s*Level')             { break }
                if ($r -match '^\s*$')                           { $i++; continue }
                if ($r -match '^\[note\]')                       { $i++; continue }
                # detect new header (underline ahead): break to outer
                if ($i + 1 -lt $lines.Count -and ([string]$lines[$i+1]) -match '^[\s\-]+$' -and ([string]$lines[$i+1]) -match '\-{3,}') { break }
                $obj = [ordered]@{}
                for ($k = 0; $k -lt $cols.Count; $k++) {
                    $c   = $cols[$k]
                    $w   = $c.End - $c.Start + 1
                    if ($c.Start -ge $r.Length) { $obj[$names[$k]] = ''; continue }
                    $end = [Math]::Min($r.Length - 1, $c.Start + $w - 1)
                    $obj[$names[$k]] = $r.Substring($c.Start, $end - $c.Start + 1).Trim()
                }
                [void]$rows.Add([pscustomobject]$obj)
                $i++
            }
            $sets += [pscustomobject]@{ Columns = $names; Rows = $rows.ToArray() }
        } else { $i++ }
    }
    return $sets
}

# ===========================================================================
# High-level extractors -- pull domain-specific values out of named scripts.
# ===========================================================================

# Locate the .log file inside a per-DB log dir whose basename ends in
# the given script-suffix (matching across priority prefix).
function Find-LogFile {
    param([string]$LogDir, [string]$ScriptSuffix)
    return Get-ChildItem $LogDir -Filter "*$ScriptSuffix*.log" -File -ErrorAction SilentlyContinue |
           Select-Object -First 1
}

function Get-ServerFingerprint {
    param([string]$ServerLogDir)
    $fp = [ordered]@{
        Edition = '(unknown)'; ProductVersion = '(unknown)'; ProductLevel = '(unknown)'
        Collation = '(unknown)'; HostName = '(unknown)'; PhysicalCPUs = '(unknown)'
        TotalMemoryMB = '(unknown)'; SqlStartTime = '(unknown)'; UptimeDays = $null
        IsHadrEnabled = '(unknown)'
    }
    if (-not $ServerLogDir) { return $fp }
    $log = Find-LogFile $ServerLogDir 'perf_05_configuration_snapshot'
    if (-not $log) { return $fp }
    $text = Read-LogText $log.FullName
    # Edition / version are emitted as columns from SERVERPROPERTY queries.
    # We grep loosely instead of relying on exact column layout.
    if ($text -match '(?im)Edition\s*\n[\s\-]+\n([^\n]+)')                 { $fp.Edition        = $matches[1].Trim() }
    if ($text -match '(?im)ProductVersion\s*\n[\s\-]+\n([^\n]+)')         { $fp.ProductVersion = $matches[1].Trim() }
    if ($text -match '(?im)ProductLevel\s*\n[\s\-]+\n([^\n]+)')           { $fp.ProductLevel   = $matches[1].Trim() }
    if ($text -match '(?im)Collation\s*\n[\s\-]+\n([^\n]+)')              { $fp.Collation      = $matches[1].Trim() }
    if ($text -match '(?im)host_name\s*\n[\s\-]+\n([^\n]+)')              { $fp.HostName       = $matches[1].Trim() }
    if ($text -match '(?im)cpu_count\s*\n[\s\-]+\n\s*(\d+)')              { $fp.PhysicalCPUs   = $matches[1] }
    if ($text -match '(?im)physical_memory_kb\s*\n[\s\-]+\n\s*(\d+)')     { $fp.TotalMemoryMB  = [int]([int64]$matches[1] / 1024) }
    if ($text -match '(?im)sqlserver_start_time\s*\n[\s\-]+\n([^\n]+)')   {
        $fp.SqlStartTime = $matches[1].Trim()
        try { $fp.UptimeDays = [math]::Round(((Get-Date) - [datetime]::Parse($fp.SqlStartTime)).TotalDays, 1) } catch {}
    }
    if ($text -match '(?im)is_hadr_enabled\s*\n[\s\-]+\n\s*(\d+)')        { $fp.IsHadrEnabled = ($matches[1] -eq '1') }
    return [pscustomobject]$fp
}

function Get-LastBackupAge {
    param([string]$LogDir)
    $log = Find-LogFile $LogDir 'perf_10_replication_and_backup'
    if (-not $log) { return $null }
    $text = Read-LogText $log.FullName
    if ($text -match '(?ims)hours_since_full[^\n]*\n[\s\-]+\n[^\n]*?\b(\d+)\s*$') {
        return [int]$matches[1]
    }
    return $null
}

# Generic "did this script return data?" indicator.
function Test-LogHasDataRows {
    param([string]$LogPath)
    $sets = Get-SqlCmdResultSets $LogPath
    foreach ($s in $sets) { if ((_Cnt $s.Rows) -gt 0) { return $true } }
    return $false
}

# ===========================================================================
# Rules with classification, compliance, and remediation snippets
# Severity: Critical / Warning / Info
# Scope:    Server  | Database
# ===========================================================================
$Rules = @(
    @{ Script='perf_02_blocking_and_locks'; Severity='Critical'; Scope='Database'
       Title='Active blocking or long-running transactions detected'
       CIS='-'; GDPR='Art.32(1)(b)'; SOC2='CC7.2'
       Detail='Diagnostic returned blocking sessions or long-running open transactions.'
       Recommendation='Investigate blocking chain. Long-running transactions block readers and bloat the log.'
       Remediation=@'
-- Find current blocking
SELECT blocking_session_id, session_id, wait_type, wait_time, last_wait_type
FROM   sys.dm_exec_requests
WHERE  blocking_session_id <> 0;
'@
    }
    @{ Script='perf_04_wait_events_and_io'; Severity='Warning'; Scope='Server'
       Pattern='PAGEIOLATCH_(SH|EX|UP)'
       Title='Storage I/O waits dominant'
       CIS='-'; GDPR='-'; SOC2='A1.2'
       Detail='PAGEIOLATCH_* indicates waits for data pages from disk.'
       Recommendation='Investigate storage latency. Increase buffer pool memory or move hot files to faster storage.'
       Remediation=@'
-- Identify top wait types since instance start
SELECT TOP 20 wait_type, wait_time_ms, waiting_tasks_count
FROM   sys.dm_os_wait_stats
ORDER  BY wait_time_ms DESC;
'@
    }
    @{ Script='perf_04_wait_events_and_io'; Severity='Warning'; Scope='Server'
       Pattern='RESOURCE_SEMAPHORE'
       Title='Memory grant queue waits'
       CIS='-'; GDPR='-'; SOC2='A1.2'
       Detail='Queries waiting for memory grants (RESOURCE_SEMAPHORE).'
       Recommendation='Tune top memory-grant consumers or raise max server memory after capacity check.'
       Remediation=@'
-- Top current memory grants
SELECT TOP 20 session_id, requested_memory_kb, granted_memory_kb, grant_time, query_cost
FROM   sys.dm_exec_query_memory_grants ORDER BY requested_memory_kb DESC;
'@
    }
    @{ Script='perf_04_wait_events_and_io'; Severity='Warning'; Scope='Server'
       Pattern='LCK_M_'
       Title='Lock waits accumulating'
       CIS='-'; GDPR='-'; SOC2='-'
       Detail='Sustained LCK_M_* waits suggest blocking; cross-reference perf_02.'
       Recommendation='Identify blocking sessions and isolate the queries holding long locks.'
       Remediation=@'
SELECT * FROM sys.dm_tran_locks WHERE request_status='WAIT';
'@
    }
    @{ Script='perf_06_index_audit'; Severity='Warning'; Scope='Database'
       Title='Index hygiene findings (missing / unused / duplicate)'
       CIS='-'; GDPR='-'; SOC2='-'
       Detail='Missing-index suggestions, unused indexes, duplicate keys, or FK without supporting index.'
       Recommendation='Add high-value missing indexes, drop unused, consolidate duplicates after impact analysis.'
       Remediation=@'
-- Top missing-index suggestions ranked by improvement_measure
SELECT TOP 20 mid.statement, migs.user_seeks, migs.user_scans, migs.avg_total_user_cost,
       migs.avg_user_impact, migs.user_seeks * migs.avg_total_user_cost * (migs.avg_user_impact/100.0) AS improvement_measure
FROM sys.dm_db_missing_index_group_stats migs
JOIN sys.dm_db_missing_index_groups   mig ON mig.index_group_handle = migs.group_handle
JOIN sys.dm_db_missing_index_details mid ON mid.index_handle = mig.index_handle
ORDER BY improvement_measure DESC;
'@
    }
    @{ Script='perf_07_table_stats_health'; Severity='Warning'; Scope='Database'
       Title='Stale statistics or heavy index fragmentation'
       CIS='-'; GDPR='-'; SOC2='-'
       Detail='Statistics need updating or > 30% fragmentation present.'
       Recommendation='Schedule UPDATE STATISTICS and reorganise / rebuild index maintenance jobs.'
       Remediation=@'
-- Update outdated statistics
EXEC sp_updatestats;

-- Per-index rebuild template (replace placeholders)
ALTER INDEX [<index>] ON [<schema>].[<table>] REBUILD WITH (ONLINE = ON);
'@
    }
    @{ Script='perf_09_temp_and_memory_pressure'; Severity='Critical'; Scope='Server'
       Pattern='pending_memory_grant_count\s*\n\s*-+\s*\n\s*[1-9]'
       Title='Pending memory grants -- memory pressure'
       CIS='-'; GDPR='-'; SOC2='A1.2'
       Detail='Queries are queuing for memory; capacity issue.'
       Recommendation='Identify top grant consumers; raise max server memory or scale up.'
       Remediation='SELECT * FROM sys.dm_exec_query_resource_semaphores;'
    }
    @{ Script='perf_09_temp_and_memory_pressure'; Severity='Warning'; Scope='Server'
       Pattern='PAGELATCH_(SH|EX|UP).*[12]:\d+:[123]'
       Title='TempDB allocation contention'
       CIS='2.5'; GDPR='-'; SOC2='A1.2'
       Detail='PAGELATCH waits on tempdb GAM/SGAM/PFS pages.'
       Recommendation='Add equally-sized tempdb data files (1 per CPU up to 8). Enable trace flag 1118 if pre-2016.'
       Remediation=@'
ALTER DATABASE tempdb MODIFY FILE (NAME=tempdev, SIZE=8GB);
ALTER DATABASE tempdb ADD FILE (NAME=tempdev2, FILENAME=''<path>\tempdb2.ndf'', SIZE=8GB);
-- repeat per CPU up to 8
'@
    }
    @{ Script='perf_10_replication_and_backup_impact'; Severity='Critical'; Scope='Database'
       Pattern='hours_since_full\s*\n\s*-+\s*\n.*\b([2-9]\d{2,}|1\d{3,})\b'
       Title='Last full backup older than several days'
       CIS='2.7'; GDPR='Art.32(1)(c)'; SOC2='A1.2'
       Detail='Full backup gap. Verify the backup job runs and the target storage accepts writes.'
       Recommendation='Run a full backup immediately; verify backup job is enabled and not failing.'
       Remediation='BACKUP DATABASE [<db>] TO DISK = N''<path>\<db>.bak'' WITH COMPRESSION, CHECKSUM, STATS=10;'
    }
    @{ Script='perf_15_capacity_and_growth'; Severity='Critical'; Scope='Database'
       Pattern='\b(8[0-9]|9[0-9]|100)\.\d+\s*%'
       Title='Identity column or storage above 80% consumed'
       CIS='-'; GDPR='-'; SOC2='A1.2'
       Detail='Identity column nearing data-type limit, or filegroup nearly full.'
       Recommendation='Plan widening (INT to BIGINT) or storage expansion before exhaustion.'
       Remediation='-- Convert identity column to BIGINT requires a new column + backfill + cutover; see KB.'
    }
    @{ Script='perf_25_tempdb_contention'; Severity='Warning'; Scope='Server'
       Title='TempDB contention metrics returned data'
       CIS='2.5'; GDPR='-'; SOC2='A1.2'
       Detail='PFS / GAM / SGAM contention indicators present.'
       Recommendation='Verify tempdb file count vs CPU; balance file sizes.'
       Remediation='-- See perf_09 remediation (add tempdb data files).'
    }
)

# ===========================================================================
# Apply rules to a single log dir, return the set of findings (with raw
# context where available).
# ===========================================================================
function Get-FindingsForLogDir {
    param([string]$LogDir)
    $list = New-Object System.Collections.Generic.List[object]

    # 1. Failed scripts -> Critical 'Script execution failed'
    foreach ($e in (Read-AuditSummary (Join-Path $LogDir '_summary.txt'))) {
        if ($e.Status -ne 'FAIL') { continue }
        $logBase = ($e.Path -replace '/', '_') -replace '\.sql$', '.log'
        $logPath = Join-Path $LogDir $logBase
        $detail  = '(no log captured)'
        if (Test-Path $logPath) {
            if ((Get-Item $logPath).Length -eq 0) {
                $detail = '(empty log -- runner produced no output, likely killed mid-run)'
            } else {
                $errs = (Read-LogLines $logPath | Where-Object { $_ -match '^Msg\s+\d+|^Sqlcmd:|^\[note\]' } | Select-Object -First 5) -join "`n"
                if ($errs) { $detail = $errs }
            }
        }
        [void]$list.Add([pscustomobject]@{
            Severity='Critical'; Scope='Server'; Script=$e.Path
            Title='Script execution failed'; Detail=$detail
            Recommendation='Check connection privileges and review the log file.'
            Remediation=''; CIS='-'; GDPR='-'; SOC2='-'
        })
    }

    # 2. Apply content rules
    foreach ($log in (Get-ChildItem $LogDir -Filter '*.log' -File -ErrorAction SilentlyContinue)) {
        foreach ($rule in $Rules) {
            if ($log.BaseName -notmatch [regex]::Escape($rule.Script)) { continue }
            $hit = $false; $context = ''
            if ($rule.Pattern) {
                $text = Read-LogText $log.FullName
                if ($text -and ($text -match $rule.Pattern)) {
                    $hit = $true
                    $m = [string]$matches[0]
                    if ($m.Length -gt 200) { $m = $m.Substring(0,200) + '...' }
                    $context = $m
                }
            } else {
                if (Test-LogHasDataRows $log.FullName) {
                    $hit = $true
                    $context = '(data rows present in script output)'
                }
            }
            if ($hit) {
                [void]$list.Add([pscustomobject]@{
                    Severity   = $rule.Severity
                    Scope      = $rule.Scope
                    Script     = $log.Name
                    Title      = $rule.Title
                    Detail     = if ($rule.Detail)         { "$($rule.Detail) Context: $context" } else { "Context: $context" }
                    Recommendation = $rule.Recommendation
                    Remediation    = $rule.Remediation
                    CIS  = if ($rule.CIS)  { $rule.CIS }  else { '-' }
                    GDPR = if ($rule.GDPR) { $rule.GDPR } else { '-' }
                    SOC2 = if ($rule.SOC2) { $rule.SOC2 } else { '-' }
                })
            }
        }
    }
    return ,$list.ToArray()
}

# ===========================================================================
# Discover layout
# ===========================================================================
function Get-ReportContexts {
    param([string]$Root)
    $contexts = @()
    Get-ChildItem $Root -Directory | Sort-Object Name | ForEach-Object {
        $dbName = $_.Name
        Get-ChildItem $_.FullName -Directory -Filter 'mssql_perf_*' |
            Sort-Object Name -Descending | Select-Object -First 1 | ForEach-Object {
                $contexts += [pscustomobject]@{ Name=$dbName; LogDir=$_.FullName }
            }
    }
    if ((_Cnt $contexts) -gt 0) { return ,$contexts }
    if (Test-Path (Join-Path $Root '_summary.txt')) {
        return ,@([pscustomobject]@{ Name='(single run)'; LogDir=$Root })
    }
    return ,@()
}

# ===========================================================================
# SVG charts (no external libs, render in PDF)
# ===========================================================================
function New-SvgDonut {
    param([int]$Critical, [int]$Warning, [int]$Info)
    $total = $Critical + $Warning + $Info
    if ($total -le 0) { return "<p class='ok'>No findings recorded.</p>" }
    $rad = 80; $cx = 110; $cy = 110; $stroke = 30
    $colors = @{ Critical='#c0392b'; Warning='#e67e22'; Info='#2980b9' }
    $vals = @(
        @{ Name='Critical'; N=$Critical; C=$colors.Critical },
        @{ Name='Warning';  N=$Warning;  C=$colors.Warning  },
        @{ Name='Info';     N=$Info;     C=$colors.Info     }
    )
    $offset = 0; $segments = ''
    foreach ($v in $vals) {
        if ($v.N -le 0) { continue }
        $angle = 360.0 * $v.N / $total
        $a1    = ($offset - 90) * [math]::PI / 180.0
        $a2    = ($offset + $angle - 90) * [math]::PI / 180.0
        $x1 = $cx + $rad * [math]::Cos($a1); $y1 = $cy + $rad * [math]::Sin($a1)
        $x2 = $cx + $rad * [math]::Cos($a2); $y2 = $cy + $rad * [math]::Sin($a2)
        $large = if ($angle -gt 180) { 1 } else { 0 }
        $segments += "<path d='M $cx $cy L $($x1.ToString('0.##',[Globalization.CultureInfo]::InvariantCulture)) $($y1.ToString('0.##',[Globalization.CultureInfo]::InvariantCulture)) A $rad $rad 0 $large 1 $($x2.ToString('0.##',[Globalization.CultureInfo]::InvariantCulture)) $($y2.ToString('0.##',[Globalization.CultureInfo]::InvariantCulture)) Z' fill='$($v.C)'/>"
        $offset += $angle
    }
    $hole = "<circle cx='$cx' cy='$cy' r='$([int]($rad - $stroke))' fill='white'/>"
    $center = "<text x='$cx' y='$($cy-3)' text-anchor='middle' font-size='22' font-weight='600' fill='#222'>$total</text>" +
              "<text x='$cx' y='$($cy+18)' text-anchor='middle' font-size='10' fill='#777'>findings</text>"
    $legend = "<g font-family='Segoe UI,Arial' font-size='12'>"
    $ly = 30
    foreach ($v in $vals) {
        $legend += "<rect x='240' y='$ly' width='14' height='14' fill='$($v.C)'/>"
        $legend += "<text x='262' y='$($ly+12)' fill='#222'>$($v.Name): $($v.N)</text>"
        $ly += 22
    }
    $legend += '</g>'
    return "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 380 220' width='380' height='220'>$segments$hole$center$legend</svg>"
}

function New-SvgBar {
    param([array]$Items, [string]$ColorPositive='#2a6db0')
    if (-not $Items -or (_Cnt $Items) -eq 0) { return '' }
    $maxN = 1
    foreach ($it in $Items) { if ($it.Value -gt $maxN) { $maxN = $it.Value } }
    $rowH = 22; $padTop = 10; $padLeft = 200; $width = 600
    $h = $padTop + $rowH * (_Cnt $Items) + 10
    $svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 $width $h' width='$width' height='$h' font-family='Segoe UI,Arial' font-size='12'>"
    $y = $padTop
    foreach ($it in $Items) {
        $w = [int](($width - $padLeft - 50) * $it.Value / $maxN)
        $svg += "<text x='$($padLeft - 8)' y='$($y + 14)' text-anchor='end' fill='#333'>$([System.Web.HttpUtility]::HtmlEncode($it.Label))</text>"
        $svg += "<rect x='$padLeft' y='$y' width='$w' height='16' fill='$ColorPositive'/>"
        $svg += "<text x='$($padLeft + $w + 6)' y='$($y + 14)' fill='#333'>$($it.Value)</text>"
        $y += $rowH
    }
    $svg += '</svg>'
    return $svg
}

# ===========================================================================
# PDF conversion (Microsoft Edge headless)
# ===========================================================================
function Get-ChromiumBrowser {
    $candidates = @(
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles\Chromium\Application\chrome.exe",
        "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe"
    )
    return ($candidates | Where-Object { Test-Path $_ } | Select-Object -First 1)
}

# Convert HTML to PDF, trying multiple fallbacks so the report is produced
# even when Microsoft Edge is not installed:
#   1. Any Chromium-based browser (Edge / Chrome / Chromium / Brave) headless
#   2. wkhtmltopdf in PATH or Program Files
#   3. Microsoft Word COM (ships with Office on most admin workstations)
#   4. (give up; HTML stays)
function Convert-HtmlToPdf {
    param([string]$Html, [string]$Pdf)
    $abs = (Resolve-Path $Html).Path
    $uri = ([System.Uri]$abs).AbsoluteUri
    Write-Host "PDF: trying conversion methods..."

    $browser = Get-ChromiumBrowser
    if ($browser) {
        Write-Host "PDF:   trying $browser"
        # Chrome / Edge may print non-fatal stderr (geolocation, GPU init)
        # which under EAP=Stop is converted to a terminating NativeCommandError.
        # Run the headless conversion under EAP=Continue + try/catch so the
        # PDF actually lands on disk before we react to any stderr noise.
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $browser --headless --disable-gpu --no-pdf-header-footer --print-to-pdf="$Pdf" $uri *>$null
        } catch {
            Write-Verbose "Chromium stderr: $($_.Exception.Message)"
        } finally {
            $ErrorActionPreference = $prevEAP
        }
        if (Test-Path $Pdf) { Write-Host "PDF: rendered via $(Split-Path -Leaf $browser)"; return $true }
    }

    $wk = Get-Command wkhtmltopdf -ErrorAction SilentlyContinue
    if (-not $wk) {
        $wkPath = "$env:ProgramFiles\wkhtmltopdf\bin\wkhtmltopdf.exe"
        if (Test-Path $wkPath) { $wk = Get-Item $wkPath }
    }
    if ($wk) {
        Write-Host "PDF:   trying wkhtmltopdf"
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { & $wk.Path --quiet --enable-local-file-access $abs $Pdf *>$null } catch {} finally { $ErrorActionPreference = $prevEAP }
        if (Test-Path $Pdf) { Write-Host "PDF: rendered via wkhtmltopdf"; return $true }
    }

    try {
        Write-Host "PDF:   trying Microsoft Word COM"
        $word = New-Object -ComObject Word.Application -ErrorAction Stop
        $word.Visible = $false
        $word.DisplayAlerts = 0
        $doc = $word.Documents.Open($abs, $false, $true)
        $doc.SaveAs2($Pdf, 17)   # 17 = wdFormatPDF
        $doc.Close($false)
        $word.Quit()
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($word)
        if (Test-Path $Pdf) { Write-Host "PDF: rendered via Microsoft Word"; return $true }
    } catch {
        Write-Verbose "Word COM fallback failed: $($_.Exception.Message)"
    }

    Write-Warning "Could not render PDF (no Edge/Chrome/Chromium/Brave/wkhtmltopdf/Word found). HTML kept at $Html."
    return $false
}

# ===========================================================================
# Main flow
# ===========================================================================
$contexts = Get-ReportContexts $ReportDir
if ((_Cnt $contexts) -eq 0) {
    Write-Error "No report sub-folders found under $ReportDir."
    exit 3
}

# Per-context summary + findings
$report = New-Object System.Collections.Generic.List[object]
foreach ($ctx in $contexts) {
    $findings = Get-FindingsForLogDir $ctx.LogDir
    $sum      = Read-AuditSummary (Join-Path $ctx.LogDir '_summary.txt')
    $passed   = @($sum | Where-Object { $_.Status -eq 'OK' }).Count
    $failed   = @($sum | Where-Object { $_.Status -eq 'FAIL' }).Count
    [void]$report.Add([pscustomobject]@{
        Name=$ctx.Name; LogDir=$ctx.LogDir; Findings=$findings
        Passed=$passed; Failed=$failed
        Critical = @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
        Warning  = @($findings | Where-Object { $_.Severity -eq 'Warning'  }).Count
        Info     = @($findings | Where-Object { $_.Severity -eq 'Info'     }).Count
    })
}

# Server fingerprint from _server context if present
$serverCtx = $report | Where-Object { $_.Name -eq '_server' } | Select-Object -First 1
$fingerprint = if ($serverCtx) { Get-ServerFingerprint $serverCtx.LogDir } else { $null }

# Aggregate findings ACROSS databases by Title -- this is the key
# "X of N affected" rollup that turns 123 copies into one clean line.
$titleAgg = @{}
foreach ($r in $report) {
    foreach ($f in $r.Findings) {
        $key = "$($f.Severity)|$($f.Scope)|$($f.Title)"
        if (-not $titleAgg.ContainsKey($key)) {
            $titleAgg[$key] = [pscustomobject]@{
                Severity=$f.Severity; Scope=$f.Scope; Title=$f.Title
                Recommendation=$f.Recommendation; Remediation=$f.Remediation
                CIS=$f.CIS; GDPR=$f.GDPR; SOC2=$f.SOC2
                Databases = New-Object System.Collections.Generic.List[string]
            }
        }
        if ($r.Name -ne '_server' -or $f.Scope -eq 'Server') {
            [void]$titleAgg[$key].Databases.Add($r.Name)
        }
    }
}
foreach ($v in $titleAgg.Values) { $v | Add-Member -NotePropertyName _Rank -NotePropertyValue (Get-SeverityRank $v.Severity) -Force }
$aggregated = $titleAgg.Values | Sort-Object _Rank, Title

# Server-wide findings = those with Scope='Server' (deduplicated)
$serverFindings  = @($aggregated | Where-Object { $_.Scope -eq 'Server' })
# Per-database findings = those with Scope='Database', counted as N of M
$dbFindings      = @($aggregated | Where-Object { $_.Scope -eq 'Database' })

# Foreach-based summation -- sidesteps PS5.1 'Argument types do not match'
# from Measure-Object on a System.Collections.Generic.List[object] when
# the rows have heterogeneous calc-dependent properties.
$totalCrit = 0; $totalWarn = 0; $totalInfo = 0; $totalFail = 0
foreach ($r in $report) {
    $totalCrit += [int]$r.Critical
    $totalWarn += [int]$r.Warning
    $totalInfo += [int]$r.Info
    $totalFail += [int]$r.Failed
}
$dbCount = $report.Count

# Domain breakdown (perf categories) -- bucket by script prefix
$domainBuckets = [ordered]@{
    'Top SQL & queries'       = @('perf_01','perf_16','perf_23')
    'Blocking & locking'      = @('perf_02','perf_13')
    'Sessions & connections'  = @('perf_03')
    'Waits & I/O'             = @('perf_04','perf_14')
    'Indexes'                 = @('perf_06','perf_12')
    'Statistics & bloat'      = @('perf_07','perf_11','perf_17')
    'Storage & sizing'        = @('perf_08','perf_15','perf_19')
    'Memory & TempDB'         = @('perf_09','perf_25')
    'Backup / replication'    = @('perf_10','perf_22','perf_24')
    'Workload & resources'    = @('perf_20')
    'Schema / partitioning'   = @('perf_21','perf_18')
}
$domainCounts = @()
foreach ($dom in $domainBuckets.Keys) {
    $count = 0
    foreach ($r in $report) {
        foreach ($f in $r.Findings) {
            foreach ($pfx in $domainBuckets[$dom]) {
                if ($f.Script -match [regex]::Escape($pfx)) { $count++; break }
            }
        }
    }
    if ($count -gt 0) { $domainCounts += [pscustomobject]@{ Label=$dom; Value=$count } }
}
$domainCounts = $domainCounts | Sort-Object Value -Descending

# ===========================================================================
# HTML render
# ===========================================================================
$now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$css = @'
<style>
@page{size:A4;margin:18mm 14mm}
body{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:0;color:#222;background:#fff;font-size:10.5pt;line-height:1.45}
h1{font-size:24pt;margin:0 0 8px}
h2{font-size:16pt;margin:24px 0 10px;border-bottom:2px solid #6FA827;padding-bottom:4px}
h3{font-size:12.5pt;margin:14px 0 6px;color:#3a6b14}
h4{font-size:11pt;margin:10px 0 4px;color:#444}
/* Title page */
.cover{position:relative;height:calc(297mm - 36mm);page-break-after:always;break-after:page;color:#111;background:#fff;overflow:hidden}
.cover-band{position:absolute;top:0;left:-14mm;right:-14mm;height:48%;overflow:hidden}
.cover-band svg{width:100%;height:100%;display:block}
.cover-logo{position:absolute;top:18mm;left:6mm;display:flex;align-items:center;gap:10px;z-index:3;color:#101010}
.cover-logo .mark{width:34px;height:34px;border:3px solid #101010;border-radius:50%;position:relative;background:#9ACA3C}
.cover-logo .mark::after{content:'';position:absolute;left:50%;top:50%;width:8px;height:8px;background:#101010;border-radius:50%;transform:translate(-50%,-50%)}
.cover-logo .name{font-size:22pt;font-weight:800;letter-spacing:0.2px}
.cover-title{position:absolute;left:0;right:0;top:55%;text-align:center;padding:0 16mm;transform:translateY(-30%)}
.cover-title h1{font-size:32pt;font-weight:800;color:#111;margin:0 0 12px;border:none}
.cover-title .sub{font-size:13pt;color:#444;margin:0 0 6px}
.cover-title .meta{font-size:11pt;color:#555;margin:0 0 22px}
.cover-title .date{font-size:11pt;color:#666;margin-top:24px}
.cover-partner{position:absolute;bottom:14mm;left:6mm;width:32mm}
.cover-partner svg{width:100%;height:auto;display:block}
/* Watermark on every page (position:fixed renders on every printed page in chromium) */
.watermark{position:fixed;top:-6mm;right:-12mm;width:90mm;opacity:0.10;z-index:-1;pointer-events:none}
.watermark svg{width:100%;height:auto;display:block}
.cover .watermark{display:none}  /* hide watermark on cover -- band is enough */
section{padding:24px 28px;page-break-inside:avoid}
section.firstaftercov{page-break-before:always}
table{border-collapse:collapse;width:100%;font-size:9.7pt;background:white}
th,td{padding:6px 8px;border-bottom:1px solid #e0e0e0;text-align:left;vertical-align:top}
th{background:#eef5e3;font-weight:600}
.exec{display:flex;gap:24px;flex-wrap:wrap;margin-bottom:18px}
.kpi{flex:1;min-width:140px;background:#f5faec;border:1px solid #d6e6b9;border-radius:6px;padding:12px 14px}
.kpi .num{font-size:22pt;font-weight:700;color:#3a6b14}
.kpi .num.crit{color:#c0392b}
.kpi .num.warn{color:#e67e22}
.kpi .num.fail{color:#c0392b}
.kpi .lbl{font-size:9pt;color:#666;text-transform:uppercase;letter-spacing:0.5px}
.badge{display:inline-block;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:700;color:white}
.badge.critical{background:#c0392b}.badge.warning{background:#e67e22}.badge.info{background:#2980b9}
.badge.server{background:#34495e}.badge.database{background:#16a085}
tr.sev-critical>td:first-child{border-left:4px solid #c0392b}
tr.sev-warning >td:first-child{border-left:4px solid #e67e22}
tr.sev-info    >td:first-child{border-left:4px solid #2980b9}
.detail{color:#555;font-size:0.85em;font-family:Consolas,monospace;white-space:pre-wrap}
.codeblk{background:#1e1e1e;color:#d4d4d4;font-family:Consolas,monospace;padding:10px 14px;border-radius:4px;font-size:9pt;white-space:pre-wrap;page-break-inside:avoid}
.compl{font-size:8.5pt;color:#666}
.kbd{font-family:Consolas,monospace;background:#f0f0f0;padding:1px 5px;border-radius:3px;font-size:0.88em}
.fp{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;font-size:10pt}
.fp dt{font-weight:600;color:#444}
.roadmap-phase{border-left:4px solid #6FA827;padding:8px 14px;margin:10px 0;background:#f5faec}
.roadmap-phase h3{margin-top:0}
.roadmap-phase ul{margin:6px 0 0 18px;padding:0}
.glossary{font-size:9.5pt}
.glossary dt{font-weight:600;margin-top:8px;color:#3a6b14}
.glossary dd{margin:0 0 4px 16px}
.appendix{font-size:9.5pt}
.tag{display:inline-block;background:#eef5e3;color:#3a6b14;border-radius:10px;padding:1px 8px;font-size:8.5pt;margin-right:4px}
.alert{background:#fdecea;border-left:4px solid #c0392b;padding:10px 14px;margin:8px 0;border-radius:4px}
.note {background:#fff8e1;border-left:4px solid #e67e22;padding:10px 14px;margin:8px 0;border-radius:4px}
.ok   {color:#27ae60;font-weight:600;font-style:italic}
@page{@bottom-center{content:counter(page) ' / ' counter(pages)}}
section.severity{page-break-before:always}
</style>
'@

$customerHtml  = if ($Customer)   { "<div class='meta'><strong>Prepared for:</strong> $(Esc $Customer)</div>" } else { '' }
$donut         = New-SvgDonut -Critical $totalCrit -Warning $totalWarn -Info $totalInfo
$domainBarSvg  = New-SvgBar -Items $domainCounts

# Cover ----------------------------------------------------------------------
$cover = @"
<section class="cover"><div class="cover-band"><svg viewBox='0 0 1600 480' preserveAspectRatio='xMidYMid slice' xmlns='http://www.w3.org/2000/svg'>
  <rect width='1600' height='480' fill='#9ACA3C'/>
  <g fill='none' stroke='#ffffff' stroke-width='2' opacity='0.7'>
    <path d='M -100,260 C 200,140 500,380 800,260 S 1300,140 1700,260'/>
    <path d='M -100,290 C 200,170 500,410 800,290 S 1300,170 1700,290'/>
    <path d='M -100,320 C 200,200 500,440 800,320 S 1300,200 1700,320'/>
    <path d='M -100,350 C 200,230 500,470 800,350 S 1300,230 1700,350'/>
    <path d='M -100,380 C 200,260 500,500 800,380 S 1300,260 1700,380'/>
    <path d='M -100,410 C 200,290 500,530 800,410 S 1300,290 1700,410'/>
  </g>
  <path d='M -50,440 L 380,180 L 760,440 L 1140,180 L 1520,440 L 1700,320' fill='none' stroke='#101010' stroke-width='6'/>
  <g fill='none' stroke='#7DB52E' stroke-width='1.2' opacity='0.55'>
    <line x1='-40' y1='480' x2='600' y2='0'/>
    <line x1='-20' y1='480' x2='620' y2='0'/>
    <line x1='0'   y1='480' x2='640' y2='0'/>
    <line x1='20'  y1='480' x2='660' y2='0'/>
    <line x1='40'  y1='480' x2='680' y2='0'/>
  </g>
</svg></div><div class="cover-logo"><span class="mark"></span><span class="name">$(Esc $Brand)</span></div><div class="cover-title">
<h1>SQL Server Performance Audit Report</h1>
<div class="sub">$(if ($Customer) { Esc $Customer } else { '' })</div>
<div class="meta"><strong>Server:</strong> $(if ($ServerName) { Esc $ServerName } else { '(unspecified)' }) &nbsp;&middot;&nbsp; <strong>$dbCount</strong> databases analyzed</div>
<div class="date">$now</div>
</div><div class="cover-partner"><svg viewBox='0 0 220 240' xmlns='http://www.w3.org/2000/svg'>
  <polygon points='25,30 195,30 195,180 110,225 25,180' fill='white' stroke='#bdbdbd' stroke-width='1.5'/>
  <text x='110' y='85' text-anchor='middle' font-family='Segoe UI,Arial,sans-serif' font-size='30' font-weight='700' fill='#232F3E'>aws</text>
  <path d='M 86,93 q 24,12 48,0' fill='none' stroke='#FF9900' stroke-width='3' stroke-linecap='round'/>
  <line x1='40' y1='120' x2='180' y2='120' stroke='#dddddd' stroke-width='1'/>
  <text x='110' y='148' text-anchor='middle' font-family='Segoe UI,Arial,sans-serif' font-size='15' font-weight='700' fill='#232F3E'>PARTNER</text>
  <text x='110' y='171' text-anchor='middle' font-family='Segoe UI,Arial,sans-serif' font-size='10' fill='#666'>DevOps Services</text>
  <text x='110' y='185' text-anchor='middle' font-family='Segoe UI,Arial,sans-serif' font-size='10' fill='#666'>Competency</text>
</svg></div></section>
"@

# Server fingerprint --------------------------------------------------------
$fpHtml = ''
if ($fingerprint) {
    $up = if ($fingerprint.UptimeDays) { "$($fingerprint.UptimeDays) days" } else { '(unknown)' }
    $fpHtml = @"
<section class='section firstaftercov'>
<h2>1. Environment Fingerprint</h2>
<dl class='fp'>
  <dt>Edition</dt>           <dd>$(Esc $fingerprint.Edition)</dd>
  <dt>Product Version</dt>   <dd>$(Esc $fingerprint.ProductVersion)</dd>
  <dt>Service Pack / CU</dt> <dd>$(Esc $fingerprint.ProductLevel)</dd>
  <dt>Host Name</dt>         <dd>$(Esc $fingerprint.HostName)</dd>
  <dt>Server Collation</dt>  <dd>$(Esc $fingerprint.Collation)</dd>
  <dt>CPU Cores</dt>         <dd>$(Esc $fingerprint.PhysicalCPUs)</dd>
  <dt>Total Memory</dt>      <dd>$(Esc $fingerprint.TotalMemoryMB) MB</dd>
  <dt>SQL Start Time</dt>    <dd>$(Esc $fingerprint.SqlStartTime)</dd>
  <dt>Uptime</dt>            <dd>$(Esc $up)</dd>
  <dt>AlwaysOn AG</dt>       <dd>$(Esc $fingerprint.IsHadrEnabled)</dd>
  <dt>Databases counted</dt> <dd>$dbCount</dd>
</dl>
$( if ($fingerprint.UptimeDays -and [decimal]$fingerprint.UptimeDays -lt 7) { "<div class='note'>Instance uptime is less than 7 days; cumulative wait stats may not be representative yet.</div>" } )
</section>
"@
} else {
    $fpHtml = "<section class='section firstaftercov'><h2>1. Environment Fingerprint</h2><div class='note'>Server fingerprint not available -- the _server context did not produce perf_05 output.</div></section>"
}

# Executive summary --------------------------------------------------------
$execHtml = @"
<section class='section'>
<h2>2. Executive Summary</h2>
<div class='exec'>
  <div class='kpi'><div class='lbl'>Databases analyzed</div><div class='num'>$dbCount</div></div>
  <div class='kpi'><div class='lbl'>Critical findings</div><div class='num crit'>$totalCrit</div></div>
  <div class='kpi'><div class='lbl'>Warning findings</div><div class='num warn'>$totalWarn</div></div>
  <div class='kpi'><div class='lbl'>Info findings</div><div class='num'>$totalInfo</div></div>
  <div class='kpi'><div class='lbl'>Failed scripts</div><div class='num fail'>$totalFail</div></div>
</div>
<h3>Findings by Domain</h3>
$domainBarSvg
</section>
"@

# Server-wide findings -----------------------------------------------------
$srvFindHtml = "<section class='section'><h2>3. Server-Wide Findings</h2>"
if ((_Cnt $serverFindings) -eq 0) {
    $srvFindHtml += "<p class='ok'>No server-wide findings detected.</p>"
} else {
    $srvFindHtml += "<p>Issues at the SQL Server instance level. These apply across every database on this instance.</p>"
    $srvFindHtml += "<table><thead><tr><th>Severity</th><th>Finding</th><th>Affected DBs</th><th>CIS</th><th>GDPR</th><th>SOC2</th></tr></thead><tbody>"
    foreach ($a in $serverFindings) {
        $sevC = $a.Severity.ToLower()
        $cnt  = @($a.Databases | Sort-Object -Unique).Count
        $srvFindHtml += "<tr class='sev-$sevC'><td><span class='badge $sevC'>$($a.Severity)</span></td>"
        $srvFindHtml += "<td><strong>$(Esc $a.Title)</strong><br><span class='detail'>$(Esc $a.Recommendation)</span></td>"
        $srvFindHtml += "<td>$cnt</td>"
        $srvFindHtml += "<td class='compl'>$(Esc $a.CIS)</td><td class='compl'>$(Esc $a.GDPR)</td><td class='compl'>$(Esc $a.SOC2)</td></tr>"
    }
    $srvFindHtml += "</tbody></table>"
}
$srvFindHtml += "</section>"

# Database fleet rollup ----------------------------------------------------
$dbFindHtml = "<section class='section'><h2>4. Database Fleet Findings</h2>"
if ((_Cnt $dbFindings) -eq 0) {
    $dbFindHtml += "<p class='ok'>No database-level findings detected.</p>"
} else {
    $dbFindHtml += "<p>Issues that surfaced inside one or more user databases. Each finding is listed once with the count of affected databases.</p>"
    $dbFindHtml += "<table><thead><tr><th>Severity</th><th>Finding</th><th>Affected</th><th>Top affected DBs</th><th>CIS</th><th>GDPR</th></tr></thead><tbody>"
    foreach ($a in $dbFindings) {
        $sevC = $a.Severity.ToLower()
        $dbs  = @($a.Databases | Sort-Object -Unique)
        $cnt  = $dbs.Count
        $top  = ($dbs | Select-Object -First 6) -join ', '
        if ($cnt -gt 6) { $top += " ... (+$($cnt - 6) more)" }
        $dbFindHtml += "<tr class='sev-$sevC'><td><span class='badge $sevC'>$($a.Severity)</span></td>"
        $dbFindHtml += "<td><strong>$(Esc $a.Title)</strong><br><span class='detail'>$(Esc $a.Recommendation)</span></td>"
        $dbFindHtml += "<td><strong>$cnt</strong> of $dbCount</td>"
        $dbFindHtml += "<td class='detail'>$(Esc $top)</td>"
        $dbFindHtml += "<td class='compl'>$(Esc $a.CIS)</td><td class='compl'>$(Esc $a.GDPR)</td></tr>"
    }
    $dbFindHtml += "</tbody></table>"
}
$dbFindHtml += "</section>"

# Backup-status alert ------------------------------------------------------
$backupHtml = ''
$oldBackups = @()
foreach ($r in $report) {
    if ($r.Name -eq '_server') { continue }
    $age = Get-LastBackupAge $r.LogDir
    if ($age -ne $null -and $age -gt 72) {
        $oldBackups += [pscustomobject]@{ Name=$r.Name; Hours=$age }
    }
}
if ((_Cnt $oldBackups) -gt 0) {
    $oldBackups = $oldBackups | Sort-Object Hours -Descending
    $backupHtml = "<section class='section'><h2>5. Backup Freshness Alert</h2><div class='alert'>$((_Cnt $oldBackups)) database(s) have a last full backup older than 72 hours.</div>"
    $backupHtml += "<table><thead><tr><th>Database</th><th>Hours since last full backup</th><th>Days</th></tr></thead><tbody>"
    foreach ($b in ($oldBackups | Select-Object -First 25)) {
        $backupHtml += "<tr><td>$(Esc $b.Name)</td><td><strong>$($b.Hours)</strong></td><td>$([math]::Round($b.Hours/24.0,1))</td></tr>"
    }
    $backupHtml += "</tbody></table></section>"
} else {
    $backupHtml = "<section class='section'><h2>5. Backup Freshness Alert</h2><p class='ok'>All assessed databases have a full backup within the last 72 hours.</p></section>"
}

# Compliance mapping --------------------------------------------------------
$complHtml = "<section class='section'><h2>6. Compliance Mapping</h2><p>Findings mapped to industry frameworks. CIS = CIS Microsoft SQL Server Benchmark. GDPR = EU 2016/679 Article 32 (security of processing). SOC2 = AICPA Trust Services Criteria.</p>"
$complHtml += "<table><thead><tr><th>Severity</th><th>Finding</th><th>CIS</th><th>GDPR</th><th>SOC2</th></tr></thead><tbody>"
foreach ($a in $aggregated) {
    if ($a.CIS -eq '-' -and $a.GDPR -eq '-' -and $a.SOC2 -eq '-') { continue }
    $sevC = $a.Severity.ToLower()
    $complHtml += "<tr class='sev-$sevC'><td><span class='badge $sevC'>$($a.Severity)</span></td>"
    $complHtml += "<td>$(Esc $a.Title)</td>"
    $complHtml += "<td class='compl'>$(Esc $a.CIS)</td><td class='compl'>$(Esc $a.GDPR)</td><td class='compl'>$(Esc $a.SOC2)</td></tr>"
}
$complHtml += "</tbody></table></section>"

# Phased remediation roadmap ------------------------------------------------
$roadHtml = "<section class='section'><h2>7. Remediation Roadmap</h2>"
$phase1 = @($aggregated | Where-Object { $_.Severity -eq 'Critical' })
$phase2 = @($aggregated | Where-Object { $_.Severity -eq 'Warning'  })
$phase3 = @($aggregated | Where-Object { $_.Severity -eq 'Info'     })
$roadHtml += "<div class='roadmap-phase'><h3>Phase 1 -- Immediate (Week 1-2): Critical issues</h3><ul>"
foreach ($f in $phase1) {
    $cnt = @($f.Databases | Sort-Object -Unique).Count
    $where = if ($f.Scope -eq 'Server') { 'instance-wide' } else { "$cnt of $dbCount databases" }
    $roadHtml += "<li><strong>$(Esc $f.Title)</strong> ($where) -- $(Esc $f.Recommendation)</li>"
}
if ((_Cnt $phase1) -eq 0) { $roadHtml += "<li>No critical items.</li>" }
$roadHtml += "</ul></div>"
$roadHtml += "<div class='roadmap-phase' style='border-left-color:#e67e22'><h3>Phase 2 -- Short-term (Week 3-6): Warnings</h3><ul>"
foreach ($f in $phase2) {
    $cnt = @($f.Databases | Sort-Object -Unique).Count
    $where = if ($f.Scope -eq 'Server') { 'instance-wide' } else { "$cnt of $dbCount databases" }
    $roadHtml += "<li><strong>$(Esc $f.Title)</strong> ($where) -- $(Esc $f.Recommendation)</li>"
}
if ((_Cnt $phase2) -eq 0) { $roadHtml += "<li>No warning items.</li>" }
$roadHtml += "</ul></div>"
$roadHtml += "<div class='roadmap-phase' style='border-left-color:#2980b9'><h3>Phase 3 -- Medium-term (Week 7-12): Info / hardening</h3><ul>"
foreach ($f in $phase3) {
    $roadHtml += "<li><strong>$(Esc $f.Title)</strong> -- $(Esc $f.Recommendation)</li>"
}
if ((_Cnt $phase3) -eq 0) { $roadHtml += "<li>No info items.</li>" }
$roadHtml += "</ul></div></section>"

# T-SQL remediation snippets ------------------------------------------------
$snipHtml = "<section class='section'><h2>8. Remediation Snippets (T-SQL)</h2><p>Reference snippets for the findings above. Replace placeholders before executing.</p>"
$emitted = @{}
foreach ($a in $aggregated) {
    if (-not $a.Remediation) { continue }
    if ($emitted.ContainsKey($a.Title)) { continue }
    $emitted[$a.Title] = $true
    $snipHtml += "<h4>$(Esc $a.Title)</h4>"
    $snipHtml += "<div class='codeblk'>$(Esc $a.Remediation)</div>"
}
$snipHtml += "</section>"

# Per-database appendix ----------------------------------------------------
$apxHtml = "<section class='section appendix'><h2>9. Appendix A: Per-Database Findings</h2><p>Full findings per database for reference. Critical = red border, Warning = orange, Info = blue.</p>"
foreach ($_r in $report) {
    $rk = if ($_r.Name -eq '_server') { 0 } else { 1 }
    $_r | Add-Member -NotePropertyName _NameRank -NotePropertyValue $rk -Force
}
foreach ($r in ($report | Sort-Object _NameRank, Name)) {
    if ((_Cnt $r.Findings) -eq 0) { continue }
    $apxHtml += "<h3>$(Esc $r.Name) <span class='tag'>$($r.Critical) crit</span><span class='tag'>$($r.Warning) warn</span><span class='tag'>$($r.Info) info</span></h3>"
    $apxHtml += "<table><thead><tr><th>Sev</th><th>Scope</th><th>Script</th><th>Finding</th></tr></thead><tbody>"
    $ranked = @(); foreach ($fx in $r.Findings) { $fx | Add-Member -NotePropertyName _Rank -NotePropertyValue (Get-SeverityRank $fx.Severity) -Force; $ranked += $fx }
    foreach ($f in ($ranked | Sort-Object _Rank, Title)) {
        $sevC = $f.Severity.ToLower()
        $apxHtml += "<tr class='sev-$sevC'><td><span class='badge $sevC'>$($f.Severity)</span></td>"
        $apxHtml += "<td><span class='badge $($f.Scope.ToLower())'>$($f.Scope)</span></td>"
        $apxHtml += "<td><span class='kbd'>$(Esc $f.Script)</span></td>"
        $apxHtml += "<td><strong>$(Esc $f.Title)</strong><br><span class='detail'>$(Esc $f.Detail)</span></td></tr>"
    }
    $apxHtml += "</tbody></table>"
}
$apxHtml += "</section>"

# Glossary ---------------------------------------------------------------
$glossary = @"
<section class='section glossary'>
<h2>10. Appendix B: Glossary</h2>
<dl>
<dt>PAGEIOLATCH_SH / EX / UP</dt><dd>Wait while reading a data page from disk. High values indicate slow storage or insufficient buffer-pool memory.</dd>
<dt>RESOURCE_SEMAPHORE</dt><dd>Query is waiting for a memory grant. Indicates memory pressure or oversized grants.</dd>
<dt>LCK_M_*</dt><dd>Locking wait family. Sustained values point to blocking; correlate with sys.dm_exec_requests.</dd>
<dt>WRITELOG</dt><dd>Wait for the transaction log to flush. High values indicate slow log device.</dd>
<dt>PAGELATCH on tempdb</dt><dd>Latch contention on tempdb GAM/SGAM/PFS pages. Add equally-sized data files.</dd>
<dt>Modification ratio</dt><dd>modification_counter / rowcount on a statistic. Above ~0.10 means the stat is stale.</dd>
<dt>Fragmentation</dt><dd>avg_fragmentation_in_percent on a leaf-level index. > 30% justifies REBUILD; 5-30% reorganise.</dd>
<dt>Log Send Queue / Redo Queue</dt><dd>AlwaysOn replica lag indicators. Non-zero on busy systems is normal; growing trend is not.</dd>
<dt>Ghost records</dt><dd>Soft-deleted rows awaiting cleanup; many = heavy DELETE activity.</dd>
<dt>Identity headroom</dt><dd>Percent of identity-column type space already consumed (INT, BIGINT, etc.).</dd>
</dl>
</section>
"@

# Assemble ----------------------------------------------------------------
$html = @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>SQL Server Performance Audit Report</title>
$css
</head><body>
<div class="watermark"><svg viewBox='0 0 600 360' xmlns='http://www.w3.org/2000/svg'>
  <g fill='none' stroke='#9ACA3C' stroke-width='1.5'>
    <path d='M -20,140 C 100,60 250,200 400,140 S 650,60 750,140'/>
    <path d='M -20,170 C 100,90 250,230 400,170 S 650,90 750,170'/>
    <path d='M -20,200 C 100,120 250,260 400,200 S 650,120 750,200'/>
    <path d='M -20,230 C 100,150 250,290 400,230 S 650,150 750,230'/>
  </g>
  <path d='M 0,260 L 150,120 L 300,260 L 450,120 L 600,260' fill='none' stroke='#101010' stroke-width='3'/>
</svg></div>
$cover
$fpHtml
$execHtml
$srvFindHtml
$dbFindHtml
$backupHtml
$complHtml
$roadHtml
$snipHtml
$apxHtml
$glossary
</body></html>
"@

[System.IO.File]::WriteAllText($HtmlPath, $html, (New-Object System.Text.UTF8Encoding $true))

$pdfMade = $false
$pdfPath = $null
if (-not $NoPdf) {
    $pdfPath = if ($OutFile -like '*.pdf') { $OutFile } else { [System.IO.Path]::ChangeExtension($OutFile, 'pdf') }
    $pdfMade = Convert-HtmlToPdf -Html $HtmlPath -Pdf $pdfPath
    if ($pdfMade -and -not $KeepHtml -and ($HtmlPath -ne $OutFile)) {
        Remove-Item $HtmlPath -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host ("=" * 80)
Write-Host "Performance audit report generated."
Write-Host "  Databases analyzed   : $dbCount"
Write-Host "  Critical findings    : $totalCrit"
Write-Host "  Warning findings     : $totalWarn"
Write-Host "  Info findings        : $totalInfo"
Write-Host "  Failed scripts       : $totalFail"
Write-Host "  Server-wide findings : $((_Cnt $serverFindings))"
Write-Host "  Database findings    : $((_Cnt $dbFindings))"
if ($NoPdf)            { Write-Host "  Report (HTML)        : $HtmlPath" }
elseif ($pdfMade)      { Write-Host "  Report (PDF)         : $pdfPath"; if ($KeepHtml) { Write-Host "  Report (HTML)        : $HtmlPath" } }
else                   { Write-Host "  Report (HTML only)   : $HtmlPath  (Edge headless not available)" }
Write-Host ("=" * 80)
