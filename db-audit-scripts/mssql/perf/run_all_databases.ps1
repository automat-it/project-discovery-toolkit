#Requires -Version 5.1
<#
.SYNOPSIS
    Run the SQL Server performance audit against every user database on an
    instance. Wrapper around run_audit.ps1 that enumerates databases automatically.

.DESCRIPTION
    Queries sys.databases for every ONLINE user database (database_id > 4,
    excludes distribution and AG secondaries that disallow reads), then calls
    run_audit.ps1 once per database plus one server-level pass against master.

    Include / exclude filters let you narrow the list for large instances.

    Authentication modes
    --------------------
    Windows Authentication (default):
        .\run_all_databases.ps1 -Server sql01.corp.local

    SQL Server Authentication:
        $env:SQLCMDPASSWORD = "s3cr3t"
        .\run_all_databases.ps1 -Server sql01.corp.local -User auditor

.PARAMETER Server
    SQL Server host or host,port  (default: localhost)

.PARAMETER User
    SQL Server login. Omit to use Windows Authentication (-E).

.PARAMETER Password
    SQL Server password. Prefer $env:SQLCMDPASSWORD.

.PARAMETER OutRoot
    Root directory for report folders  (default: .\reports)

.PARAMETER IncludeLike
    T-SQL LIKE pattern for database names to include (default: %, all user DBs).
    Example: 'prod_%'

.PARAMETER ExcludeRegex
    PowerShell regex to exclude databases by name, applied after IncludeLike.
    Example: 'staging|test'

.EXAMPLE
    # Windows Auth, all user databases
    .\run_all_databases.ps1 -Server "sql01.corp.local"

.EXAMPLE
    # SQL Server auth, only prod databases, exclude reporting
    $env:SQLCMDPASSWORD = "s3cr3t"
    .\run_all_databases.ps1 -Server "sql01,1433" -User auditor `
        -IncludeLike "prod_%" -ExcludeRegex "reporting|archive"
#>

[CmdletBinding()]
param(
    [string]$Server       = "localhost",
    [string]$User         = "",
    [string]$Password     = "",
    [string]$OutRoot      = ".\reports",
    [string]$IncludeLike  = "%",
    [string]$ExcludeRegex = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Locate sqlcmd and run_audit.ps1
# ---------------------------------------------------------------------------
if (-not (Get-Command sqlcmd -ErrorAction SilentlyContinue)) {
    Write-Error "sqlcmd not found. Install: winget install Microsoft.go-sqlcmd"
    exit 2
}

$ScriptsRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Runner      = Join-Path $ScriptsRoot "run_audit.ps1"
if (-not (Test-Path $Runner)) {
    Write-Error "run_audit.ps1 not found at $Runner"
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

# ---------------------------------------------------------------------------
# Enumerate user databases
# ---------------------------------------------------------------------------
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
  AND d.name <> 'distribution'
  AND d.state_desc = 'ONLINE'
  AND d.name LIKE N'$IncludeLike'
  AND (ars.role_desc IS NULL
       OR ars.role_desc = 'PRIMARY'
       OR ar.secondary_role_allow_connections_desc IN ('ALL','READ_ONLY'))
ORDER BY d.name;
"@

$enumArgs = @("-S", $Server) + $authArgs + @("-d", "master", "-C", "-b", "-h", "-1", "-W", "-Q", $enumQuery)
$rawDbs   = & sqlcmd @enumArgs 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Error "Database enumeration failed:`n$rawDbs"
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
    Write-Error "No user databases matched (include='$IncludeLike' exclude='$ExcludeRegex')"
    exit 3
}

# ---------------------------------------------------------------------------
# Create root output folder
# ---------------------------------------------------------------------------
$ts      = Get-Date -Format "yyyyMMdd_HHmmss"
$OutFull = Join-Path $OutRoot "mssql_perf_all_$ts"
New-Item -ItemType Directory -Path $OutFull -Force | Out-Null

$authLabel = if ($User) { "SQL Server ($User)" } else { "Windows Authentication" }

Write-Host ("=" * 80)
Write-Host "SQL Server performance audit — multi-database"
Write-Host "  server = $Server"
Write-Host "  auth   = $authLabel"
Write-Host "  databases ($($databases.Count)):"
$databases | ForEach-Object { Write-Host "    - $_" }
Write-Host "  output = $OutFull"
Write-Host ("=" * 80)

$overallFail = 0
$summary     = [System.Collections.Generic.List[string]]::new()

# ---------------------------------------------------------------------------
# Helper: invoke run_audit.ps1 for one database
# ---------------------------------------------------------------------------
function Invoke-AuditForDb {
    param([string]$DbName, [string]$SubDir)

    $subOut = Join-Path $OutFull $SubDir
    New-Item -ItemType Directory -Path $subOut -Force | Out-Null

    $runArgs = @("-Server", $Server, "-Database", $DbName, "-OutRoot", $subOut)
    if ($User)     { $runArgs += @("-User", $User) }
    if ($Password) { $runArgs += @("-Password", $Password) }

    & powershell.exe -ExecutionPolicy Bypass -File $Runner @runArgs | Out-Null
    return $LASTEXITCODE
}

# ---------------------------------------------------------------------------
# Server-level pass (master — wait stats, AG state, backups)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[*] server-level pass (db=master) -> $OutFull\_server"
$rc = Invoke-AuditForDb -DbName "master" -SubDir "_server"
if ($rc -eq 0) {
    Write-Host "  _server: OK"
    $summary.Add("OK   _server")
} else {
    Write-Host "  _server: FAIL" -ForegroundColor Red
    $summary.Add("FAIL _server")
    $overallFail++
}

# ---------------------------------------------------------------------------
# Per-database passes
# ---------------------------------------------------------------------------
foreach ($db in $databases) {
    Write-Host ""
    Write-Host "[*] db=$db -> $OutFull\$db"
    $rc = Invoke-AuditForDb -DbName $db -SubDir $db
    if ($rc -eq 0) {
        Write-Host "  ${db}: OK"
        $summary.Add("OK   $db")
    } else {
        Write-Host "  ${db}: FAIL" -ForegroundColor Red
        $summary.Add("FAIL $db")
        $overallFail++
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$summary.Add("--------------------------------------------------------------------------------")
$summary.Add("Engine:      mssql")
$summary.Add("Category:    perf (all databases)")
$summary.Add("Timestamp:   $ts")
$summary.Add("Target:      $authLabel @ $Server")
$summary.Add("Databases:   $($databases.Count)")
$summary.Add("Failed runs: $overallFail")

$summary | Set-Content (Join-Path $OutFull "_summary.txt") -Encoding UTF8

Write-Host ("-" * 80)
Write-Host "Databases:   $($databases.Count)"
Write-Host "Failed runs: $overallFail"
Write-Host "Report root: $OutFull"

if ($overallFail -gt 0) { exit 1 }
