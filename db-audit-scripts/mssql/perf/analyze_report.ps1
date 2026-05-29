#Requires -Version 5.1
<#
.SYNOPSIS
    SQL Server PERFORMANCE audit PDF report.

.DESCRIPTION
    Reads a report directory produced by run_audit.ps1 / run_all_databases.ps1
    and renders a customer-facing PDF (HTML intermediate). Includes:
      - Cover page (Automat-it brand) with title and metadata
      - Environment fingerprint (edition, version, CPU, RAM, uptime, AG state)
      - Executive summary with severity donut chart and per-domain bars
      - Server-wide vs database-level findings, deduplicated across DBs
      - Backup freshness alert (databases with last full backup > 72h)
      - Compliance mapping (CIS, GDPR Art.32, SOC2)
      - Phased remediation roadmap with executable T-SQL snippets
      - Per-database appendix
      - Glossary of wait types and DMV terms

    Default output: <ReportDir>\mssql_perf_analysis.pdf (with .html intermediate).

.PARAMETER ReportDir
    Folder produced by run_audit.ps1 / run_all_databases.ps1.

.PARAMETER ServerName
    Server label printed on the cover.

.PARAMETER Customer
    Customer name printed on the cover. Optional.

.PARAMETER OutFile
    Output path. Default: <ReportDir>\mssql_perf_analysis.pdf.

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
    [string]$OutFile    = "",
    [switch]$NoPdf,
    [switch]$KeepHtml
)

$ErrorActionPreference = 'Stop'

# Top-level trap so that any unhandled exception prints a useful line/column.
trap {
    $err = $_
    Write-Host ("=" * 80) -ForegroundColor Red
    Write-Host 'ANALYZER ERROR' -ForegroundColor Red
    Write-Host ("Exception : " + $err.Exception.Message) -ForegroundColor Red
    if ($err.InvocationInfo)  { Write-Host ("Location  : " + $err.InvocationInfo.PositionMessage) -ForegroundColor Red }
    if ($err.ScriptStackTrace) { Write-Host 'Stack:' -ForegroundColor Red; Write-Host $err.ScriptStackTrace -ForegroundColor DarkGray }
    Write-Host ("=" * 80) -ForegroundColor Red
    exit 99
}

# Dot-source shared lib (one level up from this script).
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_analyze_lib.ps1')
Clear-LogCache

if (-not (Test-Path $ReportDir)) { Write-Error "Report directory not found: $ReportDir"; exit 2 }
$ReportDir = (Resolve-Path -LiteralPath $ReportDir).Path
if (-not $OutFile) {
    $ext = if ($NoPdf) { 'html' } else { 'pdf' }
    $OutFile = Join-Path $ReportDir "mssql_perf_analysis.$ext"
}
$HtmlPath = if ($OutFile -like '*.html') { $OutFile } else { [System.IO.Path]::ChangeExtension($OutFile, 'html') }

# ===========================================================================
# Fingerprint extractor (perf reads perf_05_configuration_snapshot)
# ===========================================================================
function Get-ServerFingerprint {
    param([string]$ServerLogDir)
    $fp = [ordered]@{
        Edition = '(unknown)'; ProductVersion = '(unknown)'; ProductLevel = '(unknown)'
        Collation = '(unknown)'; HostName = '(unknown)'; PhysicalCPUs = '(unknown)'
        TotalMemoryMB = '(unknown)'; SqlStartTime = '(unknown)'; UptimeDays = $null
        IsHadrEnabled = '(unknown)'
    }
    if (-not $ServerLogDir) { return [pscustomobject]$fp }
    $log = Find-LogFile $ServerLogDir 'perf_05_configuration_snapshot'
    if (-not $log) { return [pscustomobject]$fp }

    # perf_05 result-set layout (sqlcmd horizontal output, parsed by Get-LogResultSets):
    #   set 0: edition, version, patch_level, engine_edition, server_collation,
    #          is_clustered, is_hadr_enabled, full_text_installed, machine_name, server_name
    #   set 1: cpu_count, hyperthread_ratio, physical_memory_gb, committed_gb,
    #          committed_target_gb, max_workers_count, scheduler_count, sqlserver_start_time
    $logPath = $log.FullName
    $v = Get-ColumnValue $logPath @('edition');                          if ($v) { $fp.Edition        = $v }
    $v = Get-ColumnValue $logPath @('version','product_version');        if ($v) { $fp.ProductVersion = $v }
    $v = Get-ColumnValue $logPath @('patch_level','product_level');      if ($v) { $fp.ProductLevel   = $v }
    $v = Get-ColumnValue $logPath @('server_collation','collation');     if ($v) { $fp.Collation      = $v }
    $v = Get-ColumnValue $logPath @('machine_name','host_name','server_name')
    if ($v) { $fp.HostName = $v }
    $v = Get-ColumnValue $logPath @('cpu_count');                        if ($v) { $fp.PhysicalCPUs   = $v }
    $v = Get-ColumnValue $logPath @('physical_memory_gb')
    if ($v) {
        try { $fp.TotalMemoryMB = [int]([double]::Parse($v, [Globalization.CultureInfo]::InvariantCulture) * 1024) } catch {}
    } else {
        $v = Get-ColumnValue $logPath @('physical_memory_kb')
        if ($v) { try { $fp.TotalMemoryMB = [int]([int64]$v / 1024) } catch {} }
    }
    $v = Get-ColumnValue $logPath @('sqlserver_start_time')
    if ($v) {
        $fp.SqlStartTime = $v
        try {
            $dt = [datetime]::Parse($v, [Globalization.CultureInfo]::InvariantCulture)
            $fp.UptimeDays = [math]::Round(((Get-Date) - $dt).TotalDays, 1)
        } catch {}
    }
    $v = Get-ColumnValue $logPath @('is_hadr_enabled')
    if ($null -ne $v -and $v -ne '') {
        $fp.IsHadrEnabled = if ($v -eq '1') { 'Enabled' } elseif ($v -eq '0') { 'Not enabled' } else { $v }
    }
    return [pscustomobject]$fp
}

function Get-LastBackupAge {
    param([string]$LogDir)
    $log = Find-LogFile $LogDir 'perf_10_replication_and_backup'
    if (-not $log) { return $null }
    $text = Get-LogText $log.FullName
    if ($text -match '(?ims)hours_since_full[^\n]*\n[\s\-]+\n[^\n]*?\b(\d+)\s*$') { return [int]$matches[1] }
    return $null
}

# ===========================================================================
# Performance rules
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
       Remediation="SELECT * FROM sys.dm_tran_locks WHERE request_status='WAIT';"
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

# ---------------------------------------------------------------------------
# Per-rule documentation links keyed by Title. Rendered alongside the T-SQL
# remediation in section 8 so the operator has the vendor doc one click away.
# ---------------------------------------------------------------------------
$DocsByTitle = @{
    'Active blocking or long-running transactions detected' = @(
        @{ Name = 'sys.dm_tran_locks'; Url = 'https://learn.microsoft.com/sql/relational-databases/system-dynamic-management-views/sys-dm-tran-locks-transact-sql' }
        @{ Name = 'KILL (Transact-SQL)'; Url = 'https://learn.microsoft.com/sql/t-sql/language-elements/kill-transact-sql' }
    )
    'Storage I/O waits dominant' = @(
        @{ Name = 'I/O wait types'; Url = 'https://learn.microsoft.com/sql/relational-databases/system-dynamic-management-views/sys-dm-os-wait-stats-transact-sql' }
    )
    'Memory grant queue waits' = @(
        @{ Name = 'sys.dm_exec_query_resource_semaphores'; Url = 'https://learn.microsoft.com/sql/relational-databases/system-dynamic-management-views/sys-dm-exec-query-resource-semaphores-transact-sql' }
    )
    'Lock waits accumulating' = @(
        @{ Name = 'Lock and waiting tasks'; Url = 'https://learn.microsoft.com/sql/relational-databases/system-dynamic-management-views/sys-dm-os-waiting-tasks-transact-sql' }
    )
    'Index hygiene findings (missing / unused / duplicate)' = @(
        @{ Name = 'Missing-index DMVs'; Url = 'https://learn.microsoft.com/sql/relational-databases/system-dynamic-management-views/sys-dm-db-missing-index-details-transact-sql' }
        @{ Name = 'CREATE INDEX (Transact-SQL)'; Url = 'https://learn.microsoft.com/sql/t-sql/statements/create-index-transact-sql' }
    )
    'Stale statistics or heavy index fragmentation' = @(
        @{ Name = 'UPDATE STATISTICS'; Url = 'https://learn.microsoft.com/sql/t-sql/statements/update-statistics-transact-sql' }
        @{ Name = 'ALTER INDEX (REORGANIZE/REBUILD)'; Url = 'https://learn.microsoft.com/sql/t-sql/statements/alter-index-transact-sql' }
    )
    'Pending memory grants -- memory pressure' = @(
        @{ Name = 'Memory grant troubleshooting'; Url = 'https://learn.microsoft.com/sql/relational-databases/performance/memory-grants' }
    )
    'TempDB allocation contention' = @(
        @{ Name = 'TempDB optimizations'; Url = 'https://learn.microsoft.com/sql/relational-databases/databases/tempdb-database' }
    )
    'Last full backup older than several days' = @(
        @{ Name = 'BACKUP (Transact-SQL)'; Url = 'https://learn.microsoft.com/sql/t-sql/statements/backup-transact-sql' }
    )
    'Identity column or storage above 80% consumed' = @(
        @{ Name = 'IDENTITY: avoiding overflow'; Url = 'https://learn.microsoft.com/sql/t-sql/statements/create-table-transact-sql-identity-property' }
    )
    'TempDB contention metrics returned data' = @(
        @{ Name = 'TempDB performance best practices'; Url = 'https://learn.microsoft.com/sql/relational-databases/databases/tempdb-database#performance-improvements-in-tempdb' }
    )
}
foreach ($r in $Rules) {
    if ($DocsByTitle.ContainsKey($r.Title)) { $r.Docs = $DocsByTitle[$r.Title] }
}

# Domain breakdown
$DomainBuckets = [ordered]@{
    'Top SQL & queries'      = @('perf_01','perf_16','perf_23')
    'Blocking & locking'     = @('perf_02','perf_13')
    'Sessions & connections' = @('perf_03')
    'Waits & I/O'            = @('perf_04','perf_14')
    'Indexes'                = @('perf_06','perf_12')
    'Statistics & bloat'     = @('perf_07','perf_11','perf_17')
    'Storage & sizing'       = @('perf_08','perf_15','perf_19')
    'Memory & TempDB'        = @('perf_09','perf_25')
    'Backup / replication'   = @('perf_10','perf_22','perf_24')
    'Workload & resources'   = @('perf_20')
    'Schema / partitioning'  = @('perf_21','perf_18')
}

# ===========================================================================
# Main flow
# ===========================================================================
$contexts = Get-ReportContexts -Root $ReportDir -RunFolderFilter 'mssql_perf_*'
if ($contexts.Length -eq 0) { Write-Error "No report sub-folders found under $ReportDir."; exit 3 }

$report      = New-Object System.Collections.Generic.List[object]
$ruleIndex   = @{}
foreach ($ctx in $contexts) {
    $findings = Get-FindingsFromRules -LogDir $ctx.LogDir -Rules $Rules -RuleIndexCache $ruleIndex
    $sum      = Read-AuditSummary (Join-Path $ctx.LogDir '_summary.txt')
    $passed = 0; $failed = 0; $crit = 0; $warn = 0; $info = 0
    foreach ($s in $sum)      { if ($s.Status -eq 'OK') { $passed++ } elseif ($s.Status -eq 'FAIL') { $failed++ } }
    foreach ($f in $findings) {
        switch ($f.Severity) { 'Critical' { $crit++ } 'Warning' { $warn++ } 'Info' { $info++ } }
    }
    [void]$report.Add([pscustomobject]@{
        Name = $ctx.Name; LogDir = $ctx.LogDir; Findings = $findings
        Passed = $passed; Failed = $failed; Critical = $crit; Warning = $warn; Info = $info
    })
}

$serverCtx   = $report.Where({ $_.Name -eq '_server' }, 'First', 1) | Select-Object -First 1
$fingerprint = if ($serverCtx) { Get-ServerFingerprint $serverCtx.LogDir } else { $null }

# Aggregate by Title across DBs
$titleAgg = @{}
foreach ($r in $report) {
    foreach ($f in $r.Findings) {
        $key = "$($f.Severity)|$($f.Scope)|$($f.Title)"
        if (-not $titleAgg.ContainsKey($key)) {
            $titleAgg[$key] = [pscustomobject]@{
                _Rank = $f._Rank
                Severity = $f.Severity; Scope = $f.Scope; Title = $f.Title
                Recommendation = $f.Recommendation; Remediation = $f.Remediation
                Docs = $f.Docs
                CIS = $f.CIS; GDPR = $f.GDPR; SOC2 = $f.SOC2
                Databases = New-Object System.Collections.Generic.List[string]
                UniqueDbsCached = $null
            }
        }
        if ($r.Name -ne '_server' -or $f.Scope -eq 'Server') {
            [void]$titleAgg[$key].Databases.Add($r.Name)
        }
    }
}
# Sort + cache unique-db count once + per-finding anchor for cross-linking
$aggregated = @($titleAgg.Values | Sort-Object _Rank, Title)
$anchorSeen = @{}
foreach ($a in $aggregated) {
    $a.UniqueDbsCached = @($a.Databases | Sort-Object -Unique)
    $slug = New-Slug "$($a.Severity)-$($a.Scope)-$($a.Title)"
    if ($anchorSeen.ContainsKey($slug)) {
        $anchorSeen[$slug]++
        $slug = "$slug-$($anchorSeen[$slug])"
    } else { $anchorSeen[$slug] = 1 }
    Add-Member -InputObject $a -NotePropertyName Anchor -NotePropertyValue "f-$slug" -Force
}
$serverFindings = @($aggregated | Where-Object { $_.Scope -eq 'Server'   })
$dbFindings     = @($aggregated | Where-Object { $_.Scope -eq 'Database' })

# Totals
$totalCrit = 0; $totalWarn = 0; $totalInfo = 0; $totalFail = 0
foreach ($r in $report) {
    $totalCrit += [int]$r.Critical
    $totalWarn += [int]$r.Warning
    $totalInfo += [int]$r.Info
    $totalFail += [int]$r.Failed
}
$dbCount = $report.Count

# Domain counts
$domainCounts = New-Object System.Collections.Generic.List[object]
foreach ($dom in $DomainBuckets.Keys) {
    $count = 0
    foreach ($r in $report) {
        foreach ($f in $r.Findings) {
            foreach ($pfx in $DomainBuckets[$dom]) {
                if ($f.Script.Contains($pfx)) { $count++; break }
            }
        }
    }
    if ($count -gt 0) { [void]$domainCounts.Add([pscustomobject]@{ Label = $dom; Value = $count }) }
}
$domainCounts = @($domainCounts | Sort-Object Value -Descending)

# ===========================================================================
# HTML render -- StringBuilder for everything large
# ===========================================================================
$now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

$css = @'
<style>
@page{size:A4;margin:18mm 14mm;@bottom-center{content:counter(page) ' / ' counter(pages);font-size:8pt;color:#777}}
body{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:0;color:#222;background:#fff;font-size:10.5pt;line-height:1.45}
h1{font-size:22pt;margin:0 0 8px}
h2{font-size:15pt;margin:24px 0 10px;color:#1F497D;padding-bottom:4px;border-bottom:2px solid #6FA827}
h3{font-size:12.5pt;margin:14px 0 6px;color:#1F497D}
h4{font-size:11pt;margin:10px 0 4px;color:#444}
.page-bg{position:fixed;top:0;left:0;right:0;bottom:0;z-index:-1;background-image:url('ait_bg_page.png');background-size:100% 100%;background-repeat:no-repeat;background-position:center;opacity:0.5}
.cover{position:relative;width:100%;height:calc(297mm - 36mm);page-break-after:always;break-after:page;background-image:url('ait_bg_cover.png');background-size:100% 100%;background-repeat:no-repeat;background-position:center;color:#000;text-align:center}
.cover-content{position:absolute;left:0;right:0;top:55%;padding:0 16mm}
.cover h1{font-size:24pt;font-weight:800;color:#000;margin:0 0 10px}
.cover .sub{font-size:13pt;color:#333;margin:0 0 4px;font-weight:500}
.cover .meta{font-size:11pt;color:#444;margin:0 0 6px}
.cover .date{font-size:11pt;color:#666;margin-top:8px}
/* Do NOT avoid breaking inside a whole section: a tall section (long
   findings table) would otherwise jump entirely to the next page and
   leave a large blank gap under the heading. Let the section flow and
   only keep small atomic pieces together (rows, headings, kpi cards). */
section{padding:20px 24px;background:transparent}
section.firstaftercov{page-break-before:always}
h2,h3,h4{page-break-after:avoid;break-after:avoid}
thead{display:table-header-group}
tr{page-break-inside:avoid;break-inside:avoid}
.exec,.kpi,.fp,.roadmap-phase,.glossary{page-break-inside:avoid;break-inside:avoid}
table{border-collapse:collapse;width:100%;font-size:9.5pt;background:rgba(255,255,255,0.92)}
th,td{padding:6px 8px;border-bottom:1px solid #e0e0e0;text-align:left;vertical-align:top}
th{background:#eef5e3;font-weight:600;color:#1F497D}
.exec{display:flex;gap:18px;flex-wrap:wrap;margin-bottom:18px}
.kpi{flex:1;min-width:140px;background:rgba(255,255,255,0.92);border:1px solid #d6e6b9;border-radius:6px;padding:12px 14px}
.kpi .num{font-size:22pt;font-weight:700;color:#1F497D}
.kpi .num.crit{color:#c0392b}.kpi .num.warn{color:#e67e22}.kpi .num.fail{color:#c0392b}
.kpi .lbl{font-size:9pt;color:#666;text-transform:uppercase;letter-spacing:0.5px}
.badge{display:inline-block;padding:1px 8px;border-radius:3px;font-size:0.78em;font-weight:700;color:white}
.badge.critical{background:#c0392b}.badge.warning{background:#e67e22}.badge.info{background:#2980b9}
.badge.server{background:#34495e}.badge.database{background:#16a085}
tr.sev-critical>td:first-child{border-left:4px solid #c0392b}
tr.sev-warning >td:first-child{border-left:4px solid #e67e22}
tr.sev-info    >td:first-child{border-left:4px solid #2980b9}
.detail{color:#555;font-size:0.85em;font-family:Consolas,monospace;white-space:pre-wrap}
.codeblk{background:#1e1e1e;color:#d4d4d4;font-family:Consolas,monospace;padding:10px 14px;border-radius:4px;font-size:9pt;white-space:pre-wrap;page-break-inside:avoid}
ul.docs-list{margin:4px 0 12px;padding-left:18px;font-size:9pt}
ul.docs-list li{margin:2px 0}
ul.docs-list a{color:#1F497D;text-decoration:none;border-bottom:1px dotted #1F497D}
ul.docs-list a:hover{text-decoration:underline}
.compl{font-size:8.5pt;color:#666}
.kbd{font-family:Consolas,monospace;background:#f0f0f0;padding:1px 5px;border-radius:3px;font-size:0.88em}
.fp{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;font-size:10pt;background:rgba(255,255,255,0.92);padding:14px 18px;border-radius:6px}
.fp dt{font-weight:600;color:#444}
.roadmap-phase{border-left:4px solid #6FA827;padding:8px 14px;margin:10px 0;background:rgba(255,255,255,0.92);border-radius:4px}
.roadmap-phase h3{margin-top:0}
.roadmap-phase ul{margin:6px 0 0 18px;padding:0}
.glossary{font-size:9.5pt;background:rgba(255,255,255,0.92);padding:14px 18px;border-radius:6px}
.glossary dt{font-weight:600;margin-top:8px;color:#1F497D}
.glossary dd{margin:0 0 4px 16px}
.appendix{font-size:9.5pt}
.tag{display:inline-block;background:#eef5e3;color:#3a6b14;border-radius:10px;padding:1px 8px;font-size:8.5pt;margin-right:4px}
.alert{background:#fdecea;border-left:4px solid #c0392b;padding:10px 14px;margin:8px 0;border-radius:4px}
.note {background:#fff8e1;border-left:4px solid #e67e22;padding:10px 14px;margin:8px 0;border-radius:4px}
.ok   {color:#27ae60;font-weight:600;font-style:italic}
.issue-list{list-style:none;padding:0;margin:6px 0 0}
.issue-list li{background:rgba(255,255,255,0.92);border-left:4px solid #c0392b;border-radius:4px;padding:8px 12px;margin:6px 0;page-break-inside:avoid}
.issue-list li.warn{border-left-color:#e67e22}
.issue-list .it{display:flex;justify-content:space-between;gap:12px;align-items:baseline}
.issue-list .ti{font-weight:700;color:#1F497D}
.issue-list .sc{font-size:8.5pt;color:#666;white-space:nowrap}
.issue-list .ac{margin:4px 0 0;color:#333;font-size:9.5pt}
.issue-list a.jump{font-size:8.5pt;color:#1F497D;text-decoration:none;border-bottom:1px dotted #1F497D}
section.severity{page-break-before:always}
</style>
'@

$donut        = New-SvgDonut -Critical $totalCrit -Warning $totalWarn -Info $totalInfo
$domainBarSvg = New-SvgBar -Items $domainCounts

$sb = New-Sb
Add-To $sb "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><title>SQL Server Performance Audit Report</title>$css</head><body><div class='page-bg'></div>"

# Cover
$srvLabel = if ($ServerName) { Esc $ServerName } else { '(unspecified)' }
$custHtml = if ($Customer)   { Esc $Customer }   else { '' }
Add-To $sb "<section class='cover'><div class='cover-content'><h1>SQL Server Performance Audit Report</h1><div class='sub'>$custHtml</div><div class='meta'><strong>Server:</strong> $srvLabel &nbsp;&middot;&nbsp; <strong>$dbCount</strong> databases analyzed</div><div class='date'>$now</div></div></section>"

# Executive summary -- placed first so readers see the high-level
# picture (counts, severity mix, domain breakdown) before any details.
Add-To $sb "<section class='section firstaftercov'><h2>1. Executive Summary</h2>"
Add-To $sb "<p>Snapshot of this audit: how many databases were analysed, the severity mix of findings, and which functional areas drove the count.</p>"
Add-To $sb "<div class='exec'>"
Add-To $sb "<div class='kpi'><div class='lbl'>Databases analyzed</div><div class='num'>$dbCount</div></div>"
Add-To $sb "<div class='kpi'><div class='lbl'>Critical findings</div><div class='num crit'>$totalCrit</div></div>"
Add-To $sb "<div class='kpi'><div class='lbl'>Warning findings</div><div class='num warn'>$totalWarn</div></div>"
Add-To $sb "<div class='kpi'><div class='lbl'>Info findings</div><div class='num'>$totalInfo</div></div>"
Add-To $sb "<div class='kpi'><div class='lbl'>Failed scripts</div><div class='num fail'>$totalFail</div></div>"
Add-To $sb "</div>"
Add-To $sb "<div style='display:flex;gap:20px;align-items:flex-start;flex-wrap:wrap'>"
Add-To $sb "<div>$donut</div>"
Add-To $sb "<div style='flex:1;min-width:320px'><h3 style='margin-top:0'>Findings by Domain</h3>$domainBarSvg</div>"
Add-To $sb "</div>"

# What to fix first -- critical / warning issues with their recommended
# action and a link to the detailed row further down. The aggregated
# list is already sorted by severity rank, so taking the top items
# preserves Critical-before-Warning order.
$topIssues = @($aggregated | Where-Object { $_.Severity -in @('Critical','Warning') } | Select-Object -First 10)
Add-To $sb "<h3>Top issues -- what to fix</h3>"
if ($topIssues.Length -eq 0) {
    Add-To $sb "<p class='ok'>No critical or warning issues detected.</p>"
} else {
    Add-To $sb "<p>The highest-priority findings. Click an issue title to jump to the detailed row, affected databases, and the T-SQL remediation snippet.</p>"
    Add-To $sb "<ol class='issue-list'>"
    foreach ($a in $topIssues) {
        $sevC  = $a.Severity.ToLower()
        $where = if ($a.Scope -eq 'Server') { 'instance-wide' } else { "$($a.UniqueDbsCached.Count) of $dbCount databases" }
        $cls   = if ($sevC -eq 'warning') { 'warn' } else { '' }
        Add-To $sb "<li class='$cls'><div class='it'><span class='ti'><a class='jump' href='#$($a.Anchor)'>$(Esc $a.Title)</a></span><span class='sc'><span class='badge $sevC'>$($a.Severity)</span> &middot; $where</span></div><div class='ac'><strong>Action:</strong> $(Esc $a.Recommendation)</div></li>"
    }
    Add-To $sb "</ol>"
}
Add-To $sb "</section>"

# Fingerprint
Add-To $sb "<section class='section'><h2>2. Environment Fingerprint</h2>"
if ($fingerprint) {
    $up = if ($fingerprint.UptimeDays) { "$($fingerprint.UptimeDays) days" } else { '(unknown)' }
    $memTxt = if ($fingerprint.TotalMemoryMB -is [int]) { "{0:N0} MB" -f $fingerprint.TotalMemoryMB } else { '(unknown)' }
    Add-To $sb "<dl class='fp'>"
    Add-To $sb "<dt>Edition</dt><dd>$(Esc $fingerprint.Edition)</dd>"
    Add-To $sb "<dt>Product Version</dt><dd>$(Esc $fingerprint.ProductVersion)</dd>"
    Add-To $sb "<dt>Service Pack / CU</dt><dd>$(Esc $fingerprint.ProductLevel)</dd>"
    Add-To $sb "<dt>Host Name</dt><dd>$(Esc $fingerprint.HostName)</dd>"
    Add-To $sb "<dt>Server Collation</dt><dd>$(Esc $fingerprint.Collation)</dd>"
    Add-To $sb "<dt>CPU Cores</dt><dd>$(Esc $fingerprint.PhysicalCPUs)</dd>"
    Add-To $sb "<dt>Total Memory</dt><dd>$memTxt</dd>"
    Add-To $sb "<dt>SQL Start Time</dt><dd>$(Esc $fingerprint.SqlStartTime)</dd>"
    Add-To $sb "<dt>Uptime</dt><dd>$(Esc $up)</dd>"
    Add-To $sb "<dt>AlwaysOn AG</dt><dd>$(Esc $fingerprint.IsHadrEnabled)</dd>"
    Add-To $sb "<dt>Databases counted</dt><dd>$dbCount</dd>"
    Add-To $sb "</dl>"
    if ($fingerprint.UptimeDays -and [decimal]$fingerprint.UptimeDays -lt 7) {
        Add-To $sb "<div class='note'>Instance uptime is less than 7 days; cumulative wait stats may not be representative yet.</div>"
    }
} else {
    Add-To $sb "<div class='note'>Server fingerprint not available -- the _server context did not produce perf_05 output.</div>"
}
Add-To $sb "</section>"

# Server-wide findings
Add-To $sb "<section class='section'><h2>3. Server-Wide Findings</h2>"
if ($serverFindings.Length -eq 0) {
    Add-To $sb "<p class='ok'>No server-wide findings detected.</p>"
} else {
    Add-To $sb "<p>Issues at the SQL Server instance level. These apply across every database on this instance.</p>"
    Add-To $sb "<table><thead><tr><th>Severity</th><th>Finding</th><th>Affected DBs</th><th>CIS</th><th>GDPR</th><th>SOC2</th></tr></thead><tbody>"
    foreach ($a in $serverFindings) {
        $sevC = $a.Severity.ToLower()
        Add-To $sb "<tr id='$($a.Anchor)' class='sev-$sevC'><td><span class='badge $sevC'>$($a.Severity)</span></td><td><strong>$(Esc $a.Title)</strong><br><span class='detail'>$(Esc $a.Recommendation)</span></td><td>$($a.UniqueDbsCached.Count)</td><td class='compl'>$(Esc $a.CIS)</td><td class='compl'>$(Esc $a.GDPR)</td><td class='compl'>$(Esc $a.SOC2)</td></tr>"
    }
    Add-To $sb "</tbody></table>"
}
Add-To $sb "</section>"

# Database fleet rollup
Add-To $sb "<section class='section'><h2>4. Database Fleet Findings</h2>"
if ($dbFindings.Length -eq 0) {
    Add-To $sb "<p class='ok'>No database-level findings detected.</p>"
} else {
    Add-To $sb "<p>Issues that surfaced inside one or more user databases. Each finding is listed once with the count of affected databases.</p>"
    Add-To $sb "<table><thead><tr><th>Severity</th><th>Finding</th><th>Affected</th><th>Top affected DBs</th><th>CIS</th><th>GDPR</th></tr></thead><tbody>"
    foreach ($a in $dbFindings) {
        $sevC = $a.Severity.ToLower()
        $dbs  = $a.UniqueDbsCached
        $cnt  = $dbs.Count
        $top  = ($dbs | Select-Object -First 6) -join ', '
        if ($cnt -gt 6) { $top += " ... (+$($cnt - 6) more)" }
        Add-To $sb "<tr id='$($a.Anchor)' class='sev-$sevC'><td><span class='badge $sevC'>$($a.Severity)</span></td><td><strong>$(Esc $a.Title)</strong><br><span class='detail'>$(Esc $a.Recommendation)</span></td><td><strong>$cnt</strong> of $dbCount</td><td class='detail'>$(Esc $top)</td><td class='compl'>$(Esc $a.CIS)</td><td class='compl'>$(Esc $a.GDPR)</td></tr>"
    }
    Add-To $sb "</tbody></table>"
}
Add-To $sb "</section>"

# Backup freshness
$oldBackups = New-Object System.Collections.Generic.List[object]
foreach ($r in $report) {
    if ($r.Name -eq '_server') { continue }
    $age = Get-LastBackupAge $r.LogDir
    if ($null -ne $age -and $age -gt 72) { [void]$oldBackups.Add([pscustomobject]@{ Name = $r.Name; Hours = $age }) }
}
Add-To $sb "<section class='section'><h2>5. Backup Freshness Alert</h2>"
if ($oldBackups.Count -gt 0) {
    $oldBackupsArr = @($oldBackups | Sort-Object Hours -Descending)
    Add-To $sb "<div class='alert'>$($oldBackupsArr.Length) database(s) have a last full backup older than 72 hours.</div>"
    Add-To $sb "<table><thead><tr><th>Database</th><th>Hours since last full backup</th><th>Days</th></tr></thead><tbody>"
    foreach ($b in ($oldBackupsArr | Select-Object -First 25)) {
        Add-To $sb "<tr><td>$(Esc $b.Name)</td><td><strong>$($b.Hours)</strong></td><td>$([math]::Round($b.Hours/24.0,1))</td></tr>"
    }
    Add-To $sb "</tbody></table>"
} else {
    Add-To $sb "<p class='ok'>All assessed databases have a full backup within the last 72 hours.</p>"
}
Add-To $sb "</section>"

# Compliance mapping
Add-To $sb "<section class='section'><h2>6. Compliance Mapping</h2><p>Findings mapped to industry frameworks. CIS = CIS Microsoft SQL Server Benchmark. GDPR = EU 2016/679 Article 32 (security of processing). SOC2 = AICPA Trust Services Criteria.</p><table><thead><tr><th>Severity</th><th>Finding</th><th>CIS</th><th>GDPR</th><th>SOC2</th></tr></thead><tbody>"
foreach ($a in $aggregated) {
    if ($a.CIS -eq '-' -and $a.GDPR -eq '-' -and $a.SOC2 -eq '-') { continue }
    $sevC = $a.Severity.ToLower()
    Add-To $sb "<tr class='sev-$sevC'><td><span class='badge $sevC'>$($a.Severity)</span></td><td>$(Esc $a.Title)</td><td class='compl'>$(Esc $a.CIS)</td><td class='compl'>$(Esc $a.GDPR)</td><td class='compl'>$(Esc $a.SOC2)</td></tr>"
}
Add-To $sb "</tbody></table></section>"

# Roadmap
$phases = @(
    @{ Title = 'Phase 1 -- Immediate (Week 1-2): Critical issues'; Sev = 'Critical'; Color = '#c0392b' }
    @{ Title = 'Phase 2 -- Short-term (Week 3-6): Warnings';      Sev = 'Warning';  Color = '#e67e22' }
    @{ Title = 'Phase 3 -- Medium-term (Week 7-12): Info / hardening'; Sev = 'Info'; Color = '#2980b9' }
)
Add-To $sb "<section class='section'><h2>7. Remediation Roadmap</h2>"
foreach ($p in $phases) {
    $items = @($aggregated | Where-Object { $_.Severity -eq $p.Sev })
    Add-To $sb "<div class='roadmap-phase' style='border-left-color:$($p.Color)'><h3>$($p.Title)</h3><ul>"
    if ($items.Length -eq 0) {
        Add-To $sb "<li>No items.</li>"
    } else {
        foreach ($f in $items) {
            $where = if ($f.Scope -eq 'Server') { 'instance-wide' } else { "$($f.UniqueDbsCached.Count) of $dbCount databases" }
            Add-To $sb "<li><strong>$(Esc $f.Title)</strong> ($where) -- $(Esc $f.Recommendation)</li>"
        }
    }
    Add-To $sb "</ul></div>"
}
Add-To $sb "</section>"

# T-SQL snippets + doc links
Add-To $sb "<section class='section'><h2>8. Remediation Snippets (T-SQL) and Further Reading</h2><p>Reference snippets for the findings above. Replace placeholders before executing. Each entry links to vendor documentation for that area.</p>"
$emitted = @{}
foreach ($a in $aggregated) {
    if (-not $a.Remediation -and (-not $a.Docs -or $a.Docs.Count -eq 0)) { continue }
    if ($emitted.ContainsKey($a.Title)) { continue }
    $emitted[$a.Title] = $true
    Add-To $sb "<h4>$(Esc $a.Title)</h4>"
    if ($a.Remediation) {
        Add-To $sb "<div class='codeblk'>$(Esc $a.Remediation)</div>"
    }
    if ($a.Docs -and $a.Docs.Count -gt 0) {
        Add-To $sb "<ul class='docs-list'>"
        foreach ($d in $a.Docs) {
            Add-To $sb "<li><a href='$(Esc $d.Url)' target='_blank' rel='noopener'>$(Esc $d.Name)</a></li>"
        }
        Add-To $sb "</ul>"
    }
}
Add-To $sb "</section>"

# Per-DB appendix
Add-To $sb "<section class='section appendix'><h2>9. Appendix A: Per-Database Findings</h2><p>Full findings per database for reference. Critical = red border, Warning = orange, Info = blue.</p>"
$reportSorted = @($report | Sort-Object @{Expression = { if ($_.Name -eq '_server') { 0 } else { 1 } } }, Name)
foreach ($r in $reportSorted) {
    if ($r.Findings.Length -eq 0) { continue }
    Add-To $sb "<h3>$(Esc $r.Name) <span class='tag'>$($r.Critical) crit</span><span class='tag'>$($r.Warning) warn</span><span class='tag'>$($r.Info) info</span></h3>"
    Add-To $sb "<table><thead><tr><th>Sev</th><th>Scope</th><th>Script</th><th>Finding</th></tr></thead><tbody>"
    foreach ($f in ($r.Findings | Sort-Object _Rank, Title)) {
        $sevC = $f.Severity.ToLower()
        Add-To $sb "<tr class='sev-$sevC'><td><span class='badge $sevC'>$($f.Severity)</span></td><td><span class='badge $($f.Scope.ToLower())'>$($f.Scope)</span></td><td><span class='kbd'>$(Esc $f.Script)</span></td><td><strong>$(Esc $f.Title)</strong><br><span class='detail'>$(Esc $f.Detail)</span></td></tr>"
    }
    Add-To $sb "</tbody></table>"
}
Add-To $sb "</section>"

# Glossary
Add-To $sb @'
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
</body></html>
'@

# Copy assets next to HTML, write HTML, render PDF
Copy-BrandAssets -ScriptDir $PSScriptRoot -HtmlDir (Split-Path -Parent $HtmlPath)
[System.IO.File]::WriteAllText($HtmlPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding $true))

$pdfMade = $false; $pdfPath = $null
if (-not $NoPdf) {
    $pdfPath = if ($OutFile -like '*.pdf') { $OutFile } else { [System.IO.Path]::ChangeExtension($OutFile, 'pdf') }
    $pdfMade = Convert-HtmlToPdf -Html $HtmlPath -Pdf $pdfPath
    if ($pdfMade -and -not $KeepHtml -and ($HtmlPath -ne $OutFile)) {
        Remove-Item -LiteralPath $HtmlPath -ErrorAction SilentlyContinue
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
Write-Host "  Server-wide findings : $($serverFindings.Length)"
Write-Host "  Database findings    : $($dbFindings.Length)"
if ($NoPdf)       { Write-Host "  Report (HTML)        : $HtmlPath" }
elseif ($pdfMade) { Write-Host "  Report (PDF)         : $pdfPath"; if ($KeepHtml) { Write-Host "  Report (HTML)        : $HtmlPath" } }
else              { Write-Host "  Report (HTML only)   : $HtmlPath  (Edge headless not available)" }
Write-Host ("=" * 80)
