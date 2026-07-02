#Requires -Version 5.1
<#
.SYNOPSIS
    Run the SQL Server audit against every user database on an instance.

.DESCRIPTION
    Enumerates every ONLINE user database (database_id > 4, excludes
    distribution and AG secondaries that disallow reads), then calls
    run_audit.ps1 once per database plus one server-level pass against master.

    Both scripts must reside in the mssql\ root folder. All paths are resolved
    relative to that folder -- no dependency on the caller's working directory
    or any parent folder.

    Output layout
    -------------
    <OutRoot>\
      mssql_audit_all_YYYYMMDD_HHMMSS\
        _summary.txt
        _server\
          mssql_perf_YYYYMMDD_HHMMSS\   <- server-level perf
          mssql_sec_YYYYMMDD_HHMMSS\    <- server-level sec
        <DatabaseName>\
          mssql_perf_YYYYMMDD_HHMMSS\
          mssql_sec_YYYYMMDD_HHMMSS\
        ...

    Authentication
    --------------
    Windows Authentication (default -- recommended for domain environments):
        .\run_all_databases.ps1 -Server "sql-server.internal"

    SQL Server Authentication (password via env):
        $env:SQLCMDPASSWORD = "s3cr3t"
        .\run_all_databases.ps1 -Server "sql-server.internal" -User auditor

.PARAMETER Server
    SQL Server host or host,port  (default: localhost)

.PARAMETER User
    SQL Server login. Omit to use Windows Authentication (-E).

.PARAMETER Password
    SQL Server password. Prefer $env:SQLCMDPASSWORD over this parameter.

.PARAMETER IncludeLike
    T-SQL LIKE pattern -- include only matching database names (default: all).
    Example: 'prod_%'

.PARAMETER ExcludeRegex
    PowerShell regex -- exclude matching database names (applied after IncludeLike).
    Example: 'staging|test'

.PARAMETER Category
    Which audit category to run: perf, sec, or both  (default: both)

.PARAMETER OutRoot
    Root directory for report folders (default: .\reports next to this script)

.EXAMPLE
    # All databases, Windows Auth
    .\run_all_databases.ps1 -Server "sql-server.internal"

.EXAMPLE
    # Perf only, filter by name pattern
    .\run_all_databases.ps1 -Server "sql-server.internal" -Category perf -IncludeLike "prod_%"

.EXAMPLE
    # SQL Server auth, exclude test databases
    $env:SQLCMDPASSWORD = "s3cr3t"
    .\run_all_databases.ps1 -Server "sql-server.internal,1433" -User auditor -ExcludeRegex "test|staging"

.EXAMPLE
    # If execution policy blocks the script
    powershell -ExecutionPolicy Bypass -File .\run_all_databases.ps1 -Server "sql-server.internal"
#>

[CmdletBinding()]
param(
    [string]$Server       = "localhost",
    [string]$User         = "",
    [string]$Password     = "",
    [string]$IncludeLike  = "%",
    [string]$ExcludeRegex = "",

    [ValidateSet("both","perf","sec")]
    [string]$Category = "both",

    [string]$OutRoot  = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# All paths resolve relative to THIS script's folder (mssql\)
$MsqlRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $OutRoot) { $OutRoot = Join-Path $MsqlRoot "reports" }

$Runner = Join-Path $MsqlRoot "run_audit.ps1"
if (-not (Test-Path $Runner)) {
    # Write-Error is TERMINATING under $ErrorActionPreference='Stop', so a
    # following `exit N` would never run and the documented exit code would be
    # lost. Emit to stderr non-terminating and exit explicitly.
    [Console]::Error.WriteLine("run_audit.ps1 not found at $Runner")
    exit 2
}

# ---------------------------------------------------------------------------
# Locate sqlcmd
# ---------------------------------------------------------------------------
if (-not (Get-Command sqlcmd -ErrorAction SilentlyContinue)) {
    [Console]::Error.WriteLine(@"
sqlcmd not found on PATH.
Install via winget:
  winget install Microsoft.go-sqlcmd
  winget install Microsoft.SQLServerCmdLineUtils
"@)
    exit 2
}

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
if ($User) {
    $authArgs = @("-U", $User)
    if ($Password) { $env:SQLCMDPASSWORD = $Password }
} else {
    $authArgs = @("-E")
}
$authLabel = if ($User) { "SQL Server ($User)" } else { "Windows Authentication" }

# ---------------------------------------------------------------------------
# Enumerate user databases
# ---------------------------------------------------------------------------
# Escape single quotes so a database-name pattern containing a quote cannot
# break out of the string literal (T-SQL injection). Legitimate LIKE wildcards
# (% and _) are preserved -- only the quote delimiter is doubled.
$IncludeLikeSql = $IncludeLike -replace "'", "''"

$enumQuery = @"
SET NOCOUNT ON;
SELECT d.name
FROM sys.databases d
LEFT JOIN sys.dm_hadr_database_replica_states drs
  ON drs.database_id = d.database_id AND drs.is_local = 1
LEFT JOIN sys.dm_hadr_availability_replica_states ars
  ON ars.replica_id = drs.replica_id
LEFT JOIN sys.availability_replicas ar
  ON ar.replica_id = drs.replica_id
WHERE d.database_id > 4
  AND d.name <> N'distribution'
  AND d.state_desc = N'ONLINE'
  AND d.name LIKE N'$IncludeLikeSql'
  AND (ars.role_desc IS NULL
       OR ars.role_desc = N'PRIMARY'
       OR ar.secondary_role_allow_connections_desc IN (N'ALL', N'READ_ONLY'))
ORDER BY d.name;
"@

$enumArgs = @("-S", $Server) + $authArgs + @("-d", "master", "-C", "-b", "-h", "-1", "-W", "-Q", $enumQuery)

# Relax ErrorActionPreference around the native call: under 'Stop', a benign
# sqlcmd stderr line raises a terminating NativeCommandError on Windows
# PowerShell 5.1 and aborts the whole fleet run. Capture stdout and stderr
# separately so (a) a stderr warning does not kill the run and (b) a stderr
# line is never mistaken for a database name. (Same workaround as
# run_audit.ps1's per-script invocation.)
$prevPref    = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$enumErrFile = [System.IO.Path]::GetTempFileName()
$enumErr     = $null
try {
    # Redirect only stderr to a temp file so a benign warning line is captured
    # rather than parsed as a database name; stdout (the db list) is returned.
    $rawDbs = & sqlcmd @enumArgs 2>$enumErrFile
    $rc     = $LASTEXITCODE
    if (Test-Path $enumErrFile) {
        $enumErr = (Get-Content -LiteralPath $enumErrFile -Raw -ErrorAction SilentlyContinue)
    }
} finally {
    $ErrorActionPreference = $prevPref
    Remove-Item -LiteralPath $enumErrFile -Force -ErrorAction SilentlyContinue
}

if ($rc -ne 0) {
    [Console]::Error.WriteLine("Database enumeration failed (rc=$rc):`n$enumErr`n$($rawDbs -join "`n")")
    exit 4
}

$databases = $rawDbs |
    Where-Object { $_ -match '\S' -and $_ -notmatch 'rows affected' } |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -ne "" }

if ($ExcludeRegex) {
    $databases = $databases | Where-Object { $_ -notmatch $ExcludeRegex }
}

if (-not $databases) {
    [Console]::Error.WriteLine("No user databases matched (include='$IncludeLike' exclude='$ExcludeRegex')")
    exit 3
}

# ---------------------------------------------------------------------------
# Create root output folder
# ---------------------------------------------------------------------------
$ts      = Get-Date -Format "yyyyMMdd_HHmmss"
$OutFull = Join-Path $OutRoot "mssql_audit_all_$ts"
New-Item -ItemType Directory -Path $OutFull -Force | Out-Null

$dbCount = @($databases).Count

Write-Host ("=" * 80)
Write-Host "SQL Server audit -- multi-database"
Write-Host "  server     = $Server"
Write-Host "  auth       = $authLabel"
Write-Host "  category   = $Category"
Write-Host "  databases  = $dbCount"
@($databases) | ForEach-Object { Write-Host "    - $_" }
Write-Host "  output     = $OutFull"
Write-Host ("=" * 80)

$overallFail = 0
$summary     = [System.Collections.Generic.List[string]]::new()

# ---------------------------------------------------------------------------
# Helper: run run_audit.ps1 for one database
# ---------------------------------------------------------------------------
function Invoke-AuditForDb {
    param([string]$DbName, [string]$SubDir)

    $dbOut   = Join-Path $OutFull $SubDir
    New-Item -ItemType Directory -Path $dbOut -Force | Out-Null

    $runArgs = @(
        "-Server",   $Server,
        "-Database", $DbName,
        "-Category", $Category,
        "-OutRoot",  $dbOut
    )
    if ($User) { $runArgs += @("-User", $User) }
    # Do NOT pass -Password: putting the plaintext secret on the child
    # powershell.exe command line makes it visible in the process list. The
    # child inherits $env:SQLCMDPASSWORD (set in the auth block above), which
    # sqlcmd reads directly, so the password never touches a command line.

    # Use Windows PowerShell on Windows, pwsh on macOS / Linux. $IsWindows is an
    # automatic variable only on PowerShell 6+; under Set-StrictMode -Latest on
    # Windows PowerShell 5.1 it is undefined and referencing it throws. Guard by
    # engine major version, and treat Desktop edition (5.1) as Windows.
    $isWin  = ($PSVersionTable.PSEdition -eq 'Desktop') -or
              ($PSVersionTable.PSVersion.Major -ge 6 -and $IsWindows)
    $shell  = if ($isWin) { 'powershell.exe' } else { 'pwsh' }
    & $shell -ExecutionPolicy Bypass -File $Runner @runArgs | Out-Null
    return $LASTEXITCODE
}

# ---------------------------------------------------------------------------
# Server-level pass (master -- wait stats, AG state, logins, backups)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[*] server-level pass (db=master)"
$rc = Invoke-AuditForDb -DbName "master" -SubDir "_server"
if ($rc -eq 0) {
    Write-Host "  [OK  ] _server"
    $summary.Add("OK   _server")
} else {
    Write-Host "  [FAIL] _server" -ForegroundColor Red
    $summary.Add("FAIL _server")
    $overallFail++
}

# ---------------------------------------------------------------------------
# Per-database passes
# ---------------------------------------------------------------------------
foreach ($db in @($databases)) {
    Write-Host ""
    Write-Host "[*] db=$db"
    $rc = Invoke-AuditForDb -DbName $db -SubDir $db
    if ($rc -eq 0) {
        Write-Host "  [OK  ] $db"
        $summary.Add("OK   $db")
    } else {
        Write-Host "  [FAIL] $db" -ForegroundColor Red
        $summary.Add("FAIL $db")
        $overallFail++
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$summary.Add("--------------------------------------------------------------------------------")
$summary.Add("Engine:      mssql")
$summary.Add("Category:    $Category")
$summary.Add("Timestamp:   $ts")
$summary.Add("Target:      $authLabel @ $Server")
$summary.Add("Databases:   $dbCount")
$summary.Add("Failed runs: $overallFail")

$summary | Set-Content (Join-Path $OutFull "_summary.txt") -Encoding UTF8

Write-Host ""
Write-Host ("-" * 80)
Write-Host "Databases:   $dbCount"
Write-Host "Failed runs: $overallFail"
Write-Host "Report root: $OutFull"

if ($overallFail -gt 0) { exit 1 }
