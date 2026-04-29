#Requires -Version 5.1
<#
.SYNOPSIS
    Run SQL Server performance and/or security audit scripts against one
    database and write one log file per script into a timestamped folder.

.DESCRIPTION
    Iterates critical -> high -> medium -> low sub-folders inside the chosen
    category (perf, sec, or both) and runs each *.sql file via sqlcmd.
    Output lands in a timestamped sub-folder of OutRoot.

    This script must reside in the mssql\ root folder (alongside perf\ and
    sec\ sub-folders). It resolves all paths relative to its own location --
    no dependency on the caller's working directory or any parent folder.

    Authentication
    --------------
    Windows Authentication (default -- recommended for domain environments):
        .\run_audit.ps1 -Server "sql-server.internal"

    SQL Server Authentication (password via env -- stays out of shell history):
        $env:SQLCMDPASSWORD = "s3cr3t"
        .\run_audit.ps1 -Server "sql-server.internal" -User auditor

.PARAMETER Server
    SQL Server host or host,port  (default: localhost)

.PARAMETER Database
    Target database  (default: master)

.PARAMETER User
    SQL Server login. Omit to use Windows Authentication (-E).

.PARAMETER Password
    SQL Server password. Prefer $env:SQLCMDPASSWORD over this parameter.

.PARAMETER Category
    Audit category to run: perf, sec, or both  (default: both)

.PARAMETER OutRoot
    Root directory for report folders (default: .\reports next to this script)

.EXAMPLE
    # Windows Auth, both categories, default database (master)
    .\run_audit.ps1 -Server "sql-server.internal"

.EXAMPLE
    # Windows Auth, perf only, specific database
    .\run_audit.ps1 -Server "sql-server.internal" -Database "AppDatabase" -Category perf

.EXAMPLE
    # SQL Server auth, password from env
    $env:SQLCMDPASSWORD = "s3cr3t"
    .\run_audit.ps1 -Server "sql-server.internal,1433" -User auditor -Category sec

.EXAMPLE
    # If execution policy blocks the script
    powershell -ExecutionPolicy Bypass -File .\run_audit.ps1 -Server "sql-server.internal"
#>

[CmdletBinding()]
param(
    [string]$Server   = "localhost",
    [string]$Database = "master",
    [string]$User     = "",
    [string]$Password = "",

    [ValidateSet("both","perf","sec")]
    [string]$Category = "both",

    [string]$OutRoot  = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# All paths resolve relative to THIS script's folder (mssql\)
$MsqlRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $OutRoot) { $OutRoot = Join-Path $MsqlRoot "reports" }

$Categories = if ($Category -eq "both") { @("perf","sec") } else { @($Category) }

# ---------------------------------------------------------------------------
# Locate sqlcmd
# ---------------------------------------------------------------------------
if (-not (Get-Command sqlcmd -ErrorAction SilentlyContinue)) {
    Write-Error @"
sqlcmd not found on PATH.
Install via winget:
  winget install Microsoft.go-sqlcmd          # recommended (no ODBC)
  winget install Microsoft.SQLServerCmdLineUtils
"@
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
# Run scripts for each category
# ---------------------------------------------------------------------------
$totalPass = 0
$totalFail = 0
$ts        = Get-Date -Format "yyyyMMdd_HHmmss"

Write-Host ("=" * 80)
Write-Host "SQL Server audit"
Write-Host "  server     = $Server"
Write-Host "  auth       = $authLabel"
Write-Host "  database   = $Database"
Write-Host "  categories = $($Categories -join ', ')"
Write-Host ("=" * 80)

foreach ($cat in $Categories) {
    $catRoot = Join-Path $MsqlRoot $cat
    if (-not (Test-Path $catRoot)) {
        Write-Warning "Category folder not found: $catRoot -- skipping"
        continue
    }

    $Out = Join-Path $OutRoot "mssql_${cat}_$ts"
    New-Item -ItemType Directory -Path $Out -Force | Out-Null

    Write-Host ""
    Write-Host "--- $cat ---"
    Write-Host "  output = $Out"

    $pass    = 0
    $fail    = 0
    $summary = [System.Collections.Generic.List[string]]::new()

    foreach ($priority in @("critical","high","medium","low")) {
        $dir = Join-Path $catRoot $priority
        if (-not (Test-Path $dir)) { continue }

        Get-ChildItem (Join-Path $dir "*.sql") | Sort-Object Name | ForEach-Object {
            $log = Join-Path $Out "${priority}_$($_.BaseName).log"
            $sqlArgs = @("-S", $Server) + $authArgs + @("-d", $Database, "-C", "-b", "-i", $_.FullName)

            & sqlcmd @sqlArgs > $log 2>&1

            if ($LASTEXITCODE -eq 0) {
                $pass++
                Write-Host ("[OK  ] {0,-8} {1}" -f $priority, $_.Name)
                $summary.Add("OK   $priority/$($_.Name)")
            } else {
                $fail++
                Write-Host ("[FAIL] {0,-8} {1}  -> $log" -f $priority, $_.Name) -ForegroundColor Red
                $summary.Add("FAIL $priority/$($_.Name)")
            }
        }
    }

    $summary.Add("--------------------------------------------------------------------------------")
    $summary.Add("Engine:    mssql")
    $summary.Add("Category:  $cat")
    $summary.Add("Timestamp: $ts")
    $summary.Add("Target:    $authLabel @ $Server / $Database")
    $summary.Add("Pass:      $pass")
    $summary.Add("Fail:      $fail")
    $summary | Set-Content (Join-Path $Out "_summary.txt") -Encoding UTF8

    Write-Host ("  Pass: $pass  Fail: $fail  Report: $Out")
    $totalPass += $pass
    $totalFail += $fail
}

Write-Host ""
Write-Host ("-" * 80)
Write-Host "Total pass: $totalPass  Total fail: $totalFail"

if ($totalFail -gt 0) { exit 1 }
