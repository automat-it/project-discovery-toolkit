<#
=============================================================================
SQL Server restore drill.

Proves a backup is actually restorable: takes a COPY_ONLY backup of the
source database (non-disruptive to the real backup chain), restores it into
a throw-away scratch database on the same instance, and verifies the
restored copy against the source (object parity, per-table row counts, DBCC
CHECKDB integrity, CHECKSUM_AGG content parity). It also measures the
recovery objectives (RTO = restore time, RPO = backup age). One check -> one
.log file, in priority order, mirroring the db-audit-scripts runners so the
analyzer can turn the folder into a report.

The source is touched non-destructively (COPY_ONLY backup). The scratch
database is created fresh and dropped on exit (unless -Keep). Safe to run
against production.

Uses the ODBC mssql-tools18 'sqlcmd -C' (OpenSSL tolerates the Azure SQL Edge
self-signed cert that go-sqlcmd rejects).
=============================================================================
#>
[CmdletBinding()]
param(
    [string]$Server    = "localhost",
    [string]$Database  = "master",
    [string]$User      = "",
    [string]$Password  = "",
    [string]$Scratch   = "",
    [string]$OutRoot   = "./reports",
    [int]   $RtoSeconds = 900,
    [int]   $RpoHours   = 24,
    [string]$BackupDir = "/var/opt/mssql/data",
    [string]$DataDir   = "/var/opt/mssql/data",
    # RDS for SQL Server cannot BACKUP/RESTORE to local disk. Set this to an S3
    # ARN (e.g. arn:aws:s3:::my-bucket/shop.bak) to use native RDS S3 backup /
    # restore (msdb.dbo.rds_backup_database / rds_restore_database) instead.
    [string]$S3BackupArn = "",
    [switch]$Keep,
    [switch]$Strict,      # exit non-zero on WARN as well as FAIL (for CI gates)
    [switch]$VerifyOnly   # validate the backup (RESTORE VERIFYONLY) without restoring - no scratch DB
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) {
    # The `2>&1` native-command redirect pattern used throughout breaks under
    # Windows PowerShell 5.1 (stderr becomes ErrorRecords / trips -b handling).
    [Console]::Error.WriteLine("ERROR: PowerShell 7+ (pwsh) is required; this is $($PSVersionTable.PSVersion)"); exit 2
}
if (-not (Get-Command sqlcmd -ErrorAction SilentlyContinue)) {
    [Console]::Error.WriteLine("ERROR: sqlcmd not found on PATH"); exit 2
}

$ts = Get-Date -Format "yyyyMMdd_HHmmss"
if (-not $Scratch) { $Scratch = "${Database}_drill_$ts" }
if ($Scratch -eq $Database) { [Console]::Error.WriteLine("ERROR: scratch database (-Scratch) must differ from the source (-Database)"); exit 2 }

$OutDir = Join-Path $OutRoot "mssql_restore_$ts"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$SummaryFile = Join-Path $OutDir "_summary.txt"
"" | Out-File -FilePath $SummaryFile -Encoding utf8
$bak = "$BackupDir/${Database}_restoredrill_$ts.bak"  # unique per run -> no collision between concurrent drills
$rdsMode = [bool]$S3BackupArn                        # RDS native S3 backup/restore

# T-SQL escaping for interpolated values: double '' in N'...' string literals,
# double ]] in [...] identifiers. Prevents a name/ARN with a quote or bracket
# from breaking or injecting the generated T-SQL.
$DbLit  = $Database.Replace("'", "''");     $DbId  = $Database.Replace("]", "]]")
$ScrLit = $Scratch.Replace("'", "''");      $ScrId = $Scratch.Replace("]", "]]")
$S3Lit  = $S3BackupArn.Replace("'", "''")
$BakLit = $bak.Replace("'", "''")

# Pass the password via SQLCMDPASSWORD (read by sqlcmd) so it never appears in
# the process argument list / shell history.
if ($User) { $env:SQLCMDPASSWORD = $Password; $script:authArgs = @('-U', $User) } else { $script:authArgs = @('-E') }
$script:pass = 0; $script:warn = 0; $script:fail = 0; $script:rc = 0
$rtoValue = ''; $rpoValue = ''; $backupBytes = ''; $rowsVerified = ''
$scratchCreated = $false

Write-Host "================================================================================"
Write-Host "SQL Server restore drill$(if($VerifyOnly){' (verify-only)'})"
Write-Host "  source = $Server/$Database"
if ($VerifyOnly) { Write-Host "  mode   = verify-only (no scratch database)" } else { Write-Host "  scratch= $Scratch" }
Write-Host "  output = $OutDir"
Write-Host "================================================================================"

# ---- helpers ----------------------------------------------------------------
function Run-Sql {
    param([string]$Db, [string]$Query, [switch]$Raw, [switch]$File)
    $a = @('-S', $Server) + $script:authArgs + @('-C', '-I', '-b', '-l', '30')
    if ($Db)   { $a += @('-d', $Db) }
    if ($Raw)  { $a += @('-h', '-1', '-W', '-s', '|') }
    if ($File) { $a += @('-i', $Query) } else { $a += @('-Q', $Query) }
    $out = & sqlcmd @a 2>&1 | Out-String
    $script:rc = $LASTEXITCODE
    return $out
}
function Sql-Rows([string]$Out) {
    # Returns the data lines. Callers wrap in @() so a 1-row result that the
    # pipeline unrolls to a scalar is still treated as an array.
    return @($Out -split "`r?`n" | Where-Object { "$_".Trim() -ne '' -and $_ -notmatch '^\(\d+ rows? affected\)$' })
}
function Human([double]$b) {
    $u = 'B','K','M','G','T'; $i = 0
    while ($b -ge 1024 -and $i -lt 4) { $b /= 1024; $i++ }
    if ($i -eq 0) { return ("{0:0} {1}" -f $b, $u[$i]) }
    return ("{0:0.0} {1}" -f $b, $u[$i])
}
# Extract the task_id (first column) from an rds_backup_database /
# rds_restore_database result. Take the first all-digits field so a header or
# stray line can't be mistaken for the id.
function Rds-TaskId([string[]]$Rows) {
    foreach ($r in $Rows) {
        $f0 = (($r -split '\|')[0]).Trim()
        if ($f0 -match '^\d+$') { return $f0 }
    }
    return ''
}
# Poll msdb.dbo.rds_task_status until the task reaches a terminal lifecycle.
# We match the lifecycle value by EXACT pipe-field equality (not a substring
# grep of the whole row), so a hyphenated word like 'error'/'success' inside the
# S3 ARN or database-name column can never cause a false success/failure.
function Wait-RdsTask([string]$TaskId, [int]$TimeoutSec = 3600) {
    if (-not $TaskId) { return @{ ok = $false; text = 'no task id returned by the RDS stored procedure' } }
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $last = ''; $sawRow = $false
    while ((Get-Date) -lt $deadline) {
        # MUST use -Raw: without it sqlcmd emits space-aligned, column-wrapped
        # output (no '|'), so the pipe-field row filter below never matches and
        # the task appears to hang until timeout.
        $last = Run-Sql 'msdb' "exec msdb.dbo.rds_task_status @task_id=$TaskId;" -Raw
        $row = @(Sql-Rows $last) | Where-Object { (($_ -split '\|')[0]).Trim() -eq $TaskId } | Select-Object -First 1
        if ($row) {
            $sawRow = $true
            $fields = @(($row -split '\|') | ForEach-Object { $_.Trim().ToUpper() })
            # Test the lifecycle column by its known ordinal (rds_task_status
            # returns task_id, task_type, database_name, % complete, duration,
            # lifecycle, ... -> index 5), never `-contains` across all fields:
            # 'SUCCESS'/'ERROR' appearing in task_info or the S3 ARN must not
            # be mistaken for the task state.
            $lifecycle = if ($fields.Count -gt 5) { $fields[5] } else { '' }
            if ($lifecycle -eq 'SUCCESS') { return @{ ok = $true;  text = $last } }
            if ($lifecycle -in 'ERROR', 'CANCELLED', 'FAILED') { return @{ ok = $false; text = $last } }
        }
        Start-Sleep -Seconds 10
    }
    # Distinguish a genuine timeout from a parse failure (so a future regression surfaces immediately).
    $why = if ($sawRow) { "timed out after ${TimeoutSec}s waiting for task $TaskId to reach SUCCESS" } else { "could not parse rds_task_status output for task $TaskId (no matching data row)" }
    return @{ ok = $false; text = "$why`n$last" }
}

function Emit {
    param($Tier, $Id, $Title, $Status, $Metric, $Threshold, $Detail, $Raw)
    $log = Join-Path $OutDir "${Tier}_${Id}.log"
    $m = if ($Metric)    { $Metric }    else { '-' }
    $t = if ($Threshold) { $Threshold } else { '-' }
    $d = if ($Detail)    { $Detail }    else { '-' }
    $hdr = @(
        "=== RESTORE DRILL CHECK ========================================================",
        "Check:      $Id", "Tier:       $Tier", "Title:      $Title", "Status:     $Status",
        "Metric:     $m", "Threshold:  $t", "Detail:     $d",
        "--- output ---------------------------------------------------------------------"
    )
    $bodyText = if ($Raw -and "$Raw".Trim() -ne '') { "$Raw".TrimEnd() } else { "(no command output captured)" }
    (($hdr -join "`n") + "`n" + $bodyText + "`n") | Out-File -FilePath $log -Encoding utf8
    switch ($Status) { 'PASS' { $script:pass++ } 'WARN' { $script:warn++ } default { $script:fail++ } }
    ("{0} {1}/{2}" -f $Status, $Tier, $Id) | Out-File -FilePath $SummaryFile -Append -Encoding utf8
    Write-Host ("[{0,-4}] {1,-8} {2}" -f $Status, $Tier, $Id)
}

# Never clobber a pre-existing database: if the scratch name already exists we
# must not RESTORE over it (and must never drop it - $scratchCreated stays
# false). Fail fast before taking the backup. RDS refuses an existing name
# anyway, but this gives a clear message instead of a mid-drill task error.
if (-not $VerifyOnly) {
    $exists = @(Sql-Rows (Run-Sql '' "SET NOCOUNT ON; SELECT CASE WHEN DB_ID(N'$ScrLit') IS NULL THEN 0 ELSE 1 END;" -Raw))
    if ($script:rc -eq 0 -and $exists.Count -gt 0 -and $exists[0].Trim() -eq '1') {
        [Console]::Error.WriteLine("ERROR: scratch database [$Scratch] already exists on $Server - refusing to restore over it; pick another -Scratch name or drop it manually")
        exit 2
    }
}

try {  # ensure cleanup + footer run even if a check throws

# ---- rd_01: backup create (critical) ----------------------------------------
$backupOk = $false
$sw = [Diagnostics.Stopwatch]::StartNew()
if ($rdsMode) {
    # RDS native backup to S3 (async task).
    $rows = @(Sql-Rows (Run-Sql 'msdb' "exec msdb.dbo.rds_backup_database @source_db_name=N'$DbLit', @s3_arn_to_backup_to=N'$S3Lit', @overwrite_s3_backup_file=1, @type=N'FULL';" -Raw))
    if ($script:rc -eq 0) {
        $task = Wait-RdsTask (Rds-TaskId $rows) 1800
        $sw.Stop(); $dur = [math]::Round($sw.Elapsed.TotalSeconds, 2)
        if ($task.ok) {
            $backupOk = $true
            Emit critical rd_01_backup_create "Backup of the source database succeeds" PASS `
                "backup_seconds=$dur" "-" "RDS native backup to S3 completed in ${dur}s" (($rows -join "`n") + "`n" + $task.text)
        } else {
            Emit critical rd_01_backup_create "Backup of the source database succeeds" FAIL `
                "backup_seconds=$dur" "-" "RDS backup task did not succeed - see output" (($rows -join "`n") + "`n" + $task.text)
        }
    } else {
        $sw.Stop()
        Emit critical rd_01_backup_create "Backup of the source database succeeds" FAIL `
            "-" "-" "rds_backup_database failed to start - see output" ($rows -join "`n")
    }
} else {
    $out = Run-Sql '' "BACKUP DATABASE [$DbId] TO DISK=N'$BakLit' WITH COPY_ONLY, INIT, FORMAT, CHECKSUM, NAME=N'restore drill';"
    $sw.Stop(); $dur = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    if ($script:rc -eq 0) {
        $backupOk = $true
        $szRows = @(Sql-Rows (Run-Sql 'msdb' "SET NOCOUNT ON; SELECT TOP 1 CONVERT(bigint, backup_size) FROM msdb.dbo.backupset WHERE database_name=N'$DbLit' AND type='D' AND name=N'restore drill' ORDER BY backup_finish_date DESC;" -Raw))
        if ($szRows.Count -gt 0) { $backupBytes = $szRows[0].Trim() }
        $hb = if ($backupBytes) { Human ([double]$backupBytes) } else { 'n/a' }
        Emit critical rd_01_backup_create "Backup of the source database succeeds" PASS `
            "backup_seconds=$dur;backup_bytes=$backupBytes" "-" `
            "COPY_ONLY backup produced $hb in ${dur}s" ($out + "backup file: $bak ($hb)")
    } else {
        Emit critical rd_01_backup_create "Backup of the source database succeeds" FAIL `
            "backup_seconds=$dur" "-" "BACKUP DATABASE failed - see output" $out
    }
}

# ---- rd_02: restore execute / backup verify (critical) ----------------------
$restoreOk = $false
if ($VerifyOnly) {
    # Verify the backup WITHOUT restoring (no scratch DB). Disk: RESTORE
    # VERIFYONLY WITH CHECKSUM validates the backup set + page checksums. RDS S3
    # has no VERIFYONLY for an S3 .bak - the rds_backup_database task (rd_01)
    # already validates the backup, so we confirm that.
    if ($backupOk) {
        if ($rdsMode) {
            Emit critical rd_02_backup_verify "Backup verifies without restoring" PASS `
                "-" "-" "RDS validates the backup during rds_backup_database; no separate VERIFYONLY for an S3 backup" "rd_01 rds_backup_database task succeeded"
        } else {
            $out = Run-Sql '' "RESTORE VERIFYONLY FROM DISK=N'$BakLit' WITH CHECKSUM;"
            if ($script:rc -eq 0) {
                Emit critical rd_02_backup_verify "Backup verifies without restoring" PASS `
                    "-" "-" "RESTORE VERIFYONLY (with checksum) passed - backup set is complete and readable" $out
            } else {
                Emit critical rd_02_backup_verify "Backup verifies without restoring" FAIL `
                    "-" "-" "RESTORE VERIFYONLY failed - backup is incomplete or corrupt" $out
            }
        }
    } else {
        Emit critical rd_02_backup_verify "Backup verifies without restoring" FAIL "-" "-" "Skipped: backup prerequisite (rd_01) failed" ""
    }
}
elseif ($backupOk -and $rdsMode) {
    # RDS native restore from S3 into a new scratch database (async task).
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $rows = @(Sql-Rows (Run-Sql 'msdb' "exec msdb.dbo.rds_restore_database @restore_db_name=N'$ScrLit', @s3_arn_to_restore_from=N'$S3Lit';" -Raw))
    if ($script:rc -eq 0) {
        $scratchCreated = $true   # the restore creates the db; drop it on cleanup regardless of outcome
        $task = Wait-RdsTask (Rds-TaskId $rows) 3600
        $sw.Stop(); $rtoValue = [math]::Round($sw.Elapsed.TotalSeconds, 2)
        if ($task.ok) {
            $restoreOk = $true
            Emit critical rd_02_restore_execute "Restore into the scratch database completes" PASS `
                "restore_seconds=$rtoValue" "-" "RDS native restore into [$ScrId] completed in ${rtoValue}s" (($rows -join "`n") + "`n" + $task.text)
        } else {
            Emit critical rd_02_restore_execute "Restore into the scratch database completes" FAIL `
                "restore_seconds=$rtoValue" "-" "RDS restore task did not succeed - see output" (($rows -join "`n") + "`n" + $task.text)
        }
    } else {
        $sw.Stop()
        Emit critical rd_02_restore_execute "Restore into the scratch database completes" FAIL `
            "-" "-" "rds_restore_database failed to start - see output" ($rows -join "`n")
    }
}
elseif ($backupOk) {
    $flOut = Run-Sql '' "RESTORE FILELISTONLY FROM DISK=N'$BakLit';" -Raw
    $flRc = $script:rc
    $moves = @()
    $dataDirLit = $DataDir.TrimEnd('/').Replace("'", "''")
    $scrSafe = ($Scratch -replace '[^A-Za-z0-9_]', '_')
    foreach ($line in @(Sql-Rows $flOut)) {
        $f = $line -split '\|'
        if ($f.Count -lt 3) { continue }
        $logical = $f[0].Trim(); $type = $f[2].Trim().ToUpper()
        $logEsc = $logical.Replace("'", "''")                       # logical name -> N'...' literal
        $safe = ($logical -replace '[^A-Za-z0-9_]', '_')            # filesystem-safe physical name
        # Map every file type, not just log: D->.mdf, L->.ldf, S(FILESTREAM/
        # in-memory) and F(legacy full-text) -> a directory target with no
        # extension. The logical name keeps physical paths unique.
        switch ($type) {
            'L'     { $moves += "MOVE N'$logEsc' TO N'$dataDirLit/${scrSafe}_${safe}.ldf'" }
            'S'     { $moves += "MOVE N'$logEsc' TO N'$dataDirLit/${scrSafe}_${safe}'" }
            'F'     { $moves += "MOVE N'$logEsc' TO N'$dataDirLit/${scrSafe}_${safe}'" }
            default { $moves += "MOVE N'$logEsc' TO N'$dataDirLit/${scrSafe}_${safe}.mdf'" }
        }
    }
    if ($flRc -ne 0 -or $moves.Count -eq 0) {
        # Without a file list we would generate a syntactically broken RESTORE -
        # fail explicitly instead.
        Emit critical rd_02_restore_execute "Restore into the scratch database completes" FAIL `
            "-" "-" "could not read the backup file list (RESTORE FILELISTONLY rc=$flRc, $($moves.Count) files parsed)" $flOut
    } else {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    # No REPLACE: the scratch name is verified fresh above, so a restore over an
    # existing database is a bug, not something to force through.
    $restoreSql = "RESTORE DATABASE [$ScrId] FROM DISK=N'$BakLit' WITH " + ($moves -join ', ') + ", RECOVERY;"
    $out = Run-Sql '' $restoreSql
    $sw.Stop(); $rtoValue = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    if ($script:rc -eq 0) {
        $restoreOk = $true; $scratchCreated = $true
        Emit critical rd_02_restore_execute "Restore into the scratch database completes" PASS `
            "restore_seconds=$rtoValue" "-" "Restored into scratch database [$ScrId] in ${rtoValue}s" ($flOut + "`n" + $out)
    } else {
        # the database may have been partially created
        if ((Sql-Rows (Run-Sql '' "SET NOCOUNT ON; SELECT name FROM sys.databases WHERE name=N'$ScrLit';" -Raw)).Count -gt 0) { $scratchCreated = $true }
        Emit critical rd_02_restore_execute "Restore into the scratch database completes" FAIL `
            "restore_seconds=$rtoValue" "-" "RESTORE DATABASE failed - see output" ($flOut + "`n" + $out)
    }
    }
} else {
    Emit critical rd_02_restore_execute "Restore into the scratch database completes" FAIL `
        "-" "-" "Skipped: backup prerequisite (rd_01) failed" ""
}

if (-not $VerifyOnly) {   # rd_03-rd_07 + rd_09 need a restored copy; skipped in verify-only mode

# ---- rd_03: restored database online (critical) -----------------------------
if ($restoreOk) {
    $st = @(Sql-Rows (Run-Sql '' "SET NOCOUNT ON; SELECT state_desc FROM sys.databases WHERE name=N'$ScrLit';" -Raw))
    $probe = Run-Sql $Scratch "SET NOCOUNT ON; SELECT 1 AS ok;"
    if ($st.Count -gt 0 -and $st[0].Trim() -eq 'ONLINE' -and $script:rc -eq 0) {
        Emit critical rd_03_restore_online "Restored database is online and queryable" PASS `
            "-" "-" "Scratch database is ONLINE and accepts queries" ("state_desc=$($st[0].Trim())`n" + $probe)
    } else {
        Emit critical rd_03_restore_online "Restored database is online and queryable" FAIL `
            "-" "-" "Scratch database not ONLINE/queryable after restore" ("state=$($st -join ',')`n" + $probe)
    }
} else {
    Emit critical rd_03_restore_online "Restored database is online and queryable" FAIL `
        "-" "-" "Skipped: restore prerequisite (rd_02) failed" ""
}

$objSql = @"
SET NOCOUNT ON;
SELECT 'tables' AS kind, COUNT(*) AS n FROM sys.tables
UNION ALL SELECT 'views', COUNT(*) FROM sys.views
UNION ALL SELECT 'indexes', COUNT(*) FROM sys.indexes i JOIN sys.tables t ON t.object_id=i.object_id WHERE i.type>0
UNION ALL SELECT 'routines', COUNT(*) FROM sys.objects WHERE type IN ('FN','IF','TF','P')
ORDER BY kind;
"@
$rowSql = "SET NOCOUNT ON; SELECT t.name, SUM(p.row_count) FROM sys.dm_db_partition_stats p JOIN sys.tables t ON t.object_id=p.object_id WHERE p.index_id IN (0,1) GROUP BY t.name ORDER BY t.name;"
$ckSql = @"
SET NOCOUNT ON;
DECLARE @sql nvarchar(max);
-- Label is schema-qualified (same-named tables in different schemas must not
-- collide) and quote-doubled so a quote in a schema/table name can't break the
-- generated literal.
SELECT @sql = STRING_AGG(CONVERT(nvarchar(max), 'SELECT ''' + REPLACE(s.name, '''', '''''') + '.' + REPLACE(t.name, '''', '''''') + ''' AS t, CONVERT(varchar(20), CHECKSUM_AGG(BINARY_CHECKSUM(*))) AS ck FROM ' + QUOTENAME(s.name) + '.' + QUOTENAME(t.name)), ' UNION ALL ')
FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id;
IF @sql IS NOT NULL EXEC(@sql);
"@

# ---- rd_04: object parity (high) --------------------------------------------
if ($restoreOk) {
    $src = @(Sql-Rows (Run-Sql $Database $objSql -Raw) | Sort-Object); $srcRc = $script:rc
    $tgt = @(Sql-Rows (Run-Sql $Scratch  $objSql -Raw) | Sort-Object); $tgtRc = $script:rc
    $raw = "source vs restored object counts (kind|count):`n--- source ---`n" + ($src -join "`n") + "`n--- restored ---`n" + ($tgt -join "`n")
    if ($srcRc -ne 0 -or $tgtRc -ne 0) {
        # Identical error text on both sides must never compare as a PASS.
        Emit high rd_04_object_parity "Schema object counts match the source" FAIL "-" "-" "source/target query failed (rc=$srcRc/$tgtRc) - not verified" $raw
    }
    elseif ($src.Count -eq 0) {
        Emit high rd_04_object_parity "Schema object counts match the source" FAIL "-" "-" "Could not read object counts from the source - not verified" $raw
    }
    elseif (-not (Compare-Object $src $tgt)) {
        Emit high rd_04_object_parity "Schema object counts match the source" PASS "-" "-" "Tables, views, indexes and routines match the source" $raw
    } else {
        Emit high rd_04_object_parity "Schema object counts match the source" FAIL "-" "-" "Object counts differ between source and restored copy" ($raw + "`n--- differences ---`n" + ((Compare-Object $src $tgt | Out-String)))
    }
} else { Emit high rd_04_object_parity "Schema object counts match the source" FAIL "-" "-" "Skipped: restore failed" "" }

# ---- rd_05: row-count parity (high) -----------------------------------------
if ($restoreOk) {
    $src = @(Sql-Rows (Run-Sql $Database $rowSql -Raw) | Sort-Object); $srcRc = $script:rc
    $tgt = @(Sql-Rows (Run-Sql $Scratch  $rowSql -Raw) | Sort-Object); $tgtRc = $script:rc
    # Sum only well-formed integer counts so a stray/error row can't throw.
    $rowsVerified = ($src | ForEach-Object { $v = ($_ -split '\|')[1]; if ("$v".Trim() -match '^\d+$') { [long]("$v".Trim()) } } | Measure-Object -Sum).Sum
    if (-not $rowsVerified) { $rowsVerified = 0 }
    $raw = "per-table row counts (table|rows):`n--- source ---`n" + ($src -join "`n") + "`n--- restored ---`n" + ($tgt -join "`n")
    if ($srcRc -ne 0 -or $tgtRc -ne 0) {
        Emit high rd_05_rowcount_parity "Per-table row counts match the source" FAIL "-" "-" "source/target query failed (rc=$srcRc/$tgtRc) - not verified" $raw
    }
    elseif ($src.Count -eq 0) {
        Emit high rd_05_rowcount_parity "Per-table row counts match the source" WARN "-" "-" "No user tables to compare" $raw
    }
    elseif (-not (Compare-Object $src $tgt)) {
        Emit high rd_05_rowcount_parity "Per-table row counts match the source" PASS "rows=$rowsVerified" "-" "All tables restored with identical row counts ($rowsVerified rows)" $raw
    } else {
        Emit high rd_05_rowcount_parity "Per-table row counts match the source" FAIL "rows=$rowsVerified" "-" "Row counts differ between source and restored copy" ($raw + "`n--- mismatches ---`n" + ((Compare-Object $src $tgt | Out-String)))
    }
} else { Emit high rd_05_rowcount_parity "Per-table row counts match the source" FAIL "-" "-" "Skipped: restore failed" "" }

# ---- rd_06: integrity check (high) - DBCC CHECKDB ---------------------------
if ($restoreOk) {
    $out = Run-Sql '' "DBCC CHECKDB([$ScrId]) WITH NO_INFOMSGS, ALL_ERRORMSGS;"
    if ($script:rc -eq 0) {
        Emit high rd_06_integrity_check "Restored database passes DBCC CHECKDB" PASS "-" "-" "DBCC CHECKDB found 0 allocation/consistency errors" ($(if("$out".Trim()){$out}else{"DBCC CHECKDB completed with no errors reported."}))
    } else {
        Emit high rd_06_integrity_check "Restored database passes DBCC CHECKDB" FAIL "-" "-" "DBCC CHECKDB reported errors on the restored copy" $out
    }
} else { Emit high rd_06_integrity_check "Restored database passes DBCC CHECKDB" FAIL "-" "-" "Skipped: restore failed" "" }

# ---- rd_07: RTO objective (medium) ------------------------------------------
if ($restoreOk -and $rtoValue -ne '') {
    if ([double]$rtoValue -le $RtoSeconds) {
        Emit medium rd_07_rto "Restore meets the RTO target" PASS "restore_seconds=$rtoValue" "rto_seconds<=$RtoSeconds" "Restored in ${rtoValue}s, within the ${RtoSeconds}s RTO target" "restore time ${rtoValue}s vs RTO target ${RtoSeconds}s"
    } else {
        Emit medium rd_07_rto "Restore meets the RTO target" WARN "restore_seconds=$rtoValue" "rto_seconds<=$RtoSeconds" "Restore took ${rtoValue}s, exceeding the ${RtoSeconds}s RTO target" "restore time ${rtoValue}s vs RTO target ${RtoSeconds}s"
    }
} else { Emit medium rd_07_rto "Restore meets the RTO target" FAIL "-" "rto_seconds<=$RtoSeconds" "Skipped: restore did not complete" "" }

}   # end restore-dependent checks (rd_03-rd_07)

# ---- rd_08: RPO / backup freshness (medium) ---------------------------------
if ($backupOk) {
    $rpoNote = ''
    if ($rdsMode) {
        # rds_backup_database does not populate msdb.dbo.backupset; this is an
        # on-demand backup taken seconds ago, so its age is ~0 by construction.
        $rpoValue = '0.00'
        $rpoNote = ' (no prior production backups in msdb - measured the drill''s own backup)'
    } else {
        # The real RPO is the age of the newest NON-drill full backup (the
        # production cadence). Only if none exists do we fall back to measuring
        # the drill's own COPY_ONLY backup, and we say so.
        $ageRows = @(Sql-Rows (Run-Sql 'msdb' "SET NOCOUNT ON; SELECT TOP 1 CONVERT(decimal(10,2), DATEDIFF(MINUTE, backup_finish_date, GETDATE())/60.0) FROM msdb.dbo.backupset WHERE database_name=N'$DbLit' AND type='D' AND name <> N'restore drill' AND is_copy_only=0 ORDER BY backup_finish_date DESC;" -Raw))
        if ($script:rc -eq 0 -and $ageRows.Count -gt 0 -and "$($ageRows[0])".Trim() -match '^\.?\d') {
            $rpoValue = "$($ageRows[0])".Trim()
        } else {
            $ageRows = @(Sql-Rows (Run-Sql 'msdb' "SET NOCOUNT ON; SELECT TOP 1 CONVERT(decimal(10,2), DATEDIFF(MINUTE, backup_finish_date, GETDATE())/60.0) FROM msdb.dbo.backupset WHERE database_name=N'$DbLit' AND type='D' AND name=N'restore drill' ORDER BY backup_finish_date DESC;" -Raw))
            $rpoValue = if ($ageRows.Count -gt 0) { "$($ageRows[0])".Trim() } else { '0.00' }
            $rpoNote = ' (no prior production backups in msdb - measured the drill''s own backup)'
        }
        if ($rpoValue -match '^\.') { $rpoValue = "0$rpoValue" }
    }
    if ([double]$rpoValue -le $RpoHours) {
        Emit medium rd_08_rpo_backup_age "Backup is fresh enough for the RPO target" PASS "backup_age_hours=$rpoValue" "rpo_hours<=$RpoHours" "Backup is ${rpoValue}h old, within the ${RpoHours}h RPO target$rpoNote" "backup age ${rpoValue}h vs RPO target ${RpoHours}h"
    } else {
        Emit medium rd_08_rpo_backup_age "Backup is fresh enough for the RPO target" WARN "backup_age_hours=$rpoValue" "rpo_hours<=$RpoHours" "Backup is ${rpoValue}h old, exceeding the ${RpoHours}h RPO target$rpoNote" "backup age ${rpoValue}h vs RPO target ${RpoHours}h"
    }
} else { Emit medium rd_08_rpo_backup_age "Backup is fresh enough for the RPO target" FAIL "-" "rpo_hours<=$RpoHours" "Skipped: backup failed" "" }

if (-not $VerifyOnly) {
# ---- rd_09: content checksum parity (low) - CHECKSUM_AGG ---------------------
if ($restoreOk) {
    $src = @(Sql-Rows (Run-Sql $Database $ckSql -Raw) | Sort-Object); $srcRc = $script:rc
    $tgt = @(Sql-Rows (Run-Sql $Scratch  $ckSql -Raw) | Sort-Object); $tgtRc = $script:rc
    $raw = "per-table content checksum (table|checksum):`n--- source ---`n" + ($src -join "`n") + "`n--- restored ---`n" + ($tgt -join "`n")
    if ($srcRc -ne 0 -or $tgtRc -ne 0) {
        Emit low rd_09_data_checksum "Row-content checksums match the source" FAIL "-" "-" "source/target query failed (rc=$srcRc/$tgtRc) - not verified" $raw
    }
    elseif ($src.Count -eq 0) {
        Emit low rd_09_data_checksum "Row-content checksums match the source" WARN "-" "-" "No user tables to checksum" $raw
    } else {
        $diff = Compare-Object $src $tgt
        if (-not $diff) {
            # BINARY_CHECKSUM ignores xml/text/image (LOB) columns - be honest.
            Emit low rd_09_data_checksum "Row-content checksums match the source" PASS "-" "-" "Every table's CHECKSUM_AGG matches the source (non-LOB columns) - data is faithful" $raw
        } else {
            Emit low rd_09_data_checksum "Row-content checksums match the source" FAIL "-" "-" "Content checksums differ - restored data does not match the source" ($raw + "`n--- mismatches ---`n" + (($diff | Out-String)))
        }
    }
} else { Emit low rd_09_data_checksum "Row-content checksums match the source" FAIL "-" "-" "Skipped: restore failed" "" }
}   # end rd_09 (verify-only skips it)

}
catch {
    # Record the abort as a hard failure so the verdict is FAIL and the exit
    # code is non-zero - a swallowed exception must never look like success.
    Write-Host "[error] a drill check threw: $($_.Exception.Message)"
    Emit critical rd_00_drill_aborted "Restore drill ran to completion" FAIL `
        "-" "-" "Drill aborted by an unexpected error" $_.Exception.Message
}
finally {
    # ---- cleanup: always drop the scratch database we created -----------------
    if (-not $Keep -and $scratchCreated) {
        try {
            Run-Sql '' "IF DB_ID(N'$ScrLit') IS NOT NULL BEGIN ALTER DATABASE [$ScrId] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$ScrId]; END" | Out-Null
        } catch { Write-Host "[warn] could not drop scratch database $Scratch" }
    }
    # Don't leave the password in the environment after the run.
    Remove-Item Env:SQLCMDPASSWORD -ErrorAction SilentlyContinue
}

# ---- verdict + summary footer -----------------------------------------------
$verdict = if ($script:fail -gt 0) { 'FAIL' } elseif ($script:warn -gt 0) { 'WARN' } else { 'PASS' }
$hb = if ($backupBytes) { Human ([double]$backupBytes) } else { 'n/a' }
$backupDesc = if ($rdsMode) { "$S3BackupArn (RDS native S3)" } else { "$bak ($hb, native)" }
$footer = @(
    "--------------------------------------------------------------------------------",
    "Engine:    mssql",
    "Category:  restore",
    "Mode:      $(if($VerifyOnly){'verify-only'}else{'full-restore'})",
    "Timestamp: $ts",
    "Source:    $Server/$Database",
    "Target:    $(if($VerifyOnly){'(verify-only - no restore performed)'}else{"$Server/$Scratch"})",
    "Backup:    $backupDesc",
    "RTO:       $(if($rtoValue -ne ''){ [string]$rtoValue + 's' }else{ 'n/a' }) (target <= ${RtoSeconds}s)",
    "RPO:       $(if($rpoValue -ne ''){ [string]$rpoValue + 'h since backup' }else{ 'n/a' }) (target <= ${RpoHours}h)",
    "Rows:      $(if($rowsVerified){$rowsVerified}else{0}) verified",
    "Verdict:   $verdict",
    "Pass:      $script:pass",
    "Warn:      $script:warn",
    "Fail:      $script:fail"
)
$footer -join "`n" | Out-File -FilePath $SummaryFile -Append -Encoding utf8
$footer | ForEach-Object { Write-Host $_ }
if (-not $rdsMode -and $backupOk) {
    # The drill never deletes its .bak server-side (the runner may not have
    # filesystem access to the instance). Plain extra line - the analyzer only
    # parses the labelled footer fields, so this cannot break parsing.
    $bakNote = "NOTE: backup file left on server: $bak - delete it manually"
    $bakNote | Out-File -FilePath $SummaryFile -Append -Encoding utf8
    Write-Host $bakNote
}
Write-Host "Report directory: $OutDir"
# Exit non-zero on FAIL (always) and on WARN when -Strict is set.
if ($verdict -eq 'FAIL') { exit 1 }
if ($Strict -and $verdict -eq 'WARN') { exit 1 }
exit 0
