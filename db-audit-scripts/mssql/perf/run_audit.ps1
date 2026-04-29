#Requires -Version 5.1
<#
.SYNOPSIS
    Run every SQL Server performance audit script in priority order and collect
    the output into a timestamped report folder. One SQL script -> one log file.

.DESCRIPTION
    Iterates critical -> high -> medium -> low sub-folders, runs each *.sql file
    via sqlcmd, writes per-script logs, and writes _summary.txt to the report
    folder.

    Authentication modes
    --------------------
    Windows Authentication (default, recommended for domain environments):
        .\run_audit.ps1 -Server db.internal

    SQL Server Authentication:
        .\run_audit.ps1 -Server db.internal -User auditor -Password 's3cr3t'

    Password from environment variable (preferred — keeps it out of shell history):
        $env:SQLCMDPASSWORD = 's3cr3t'
        .\run_audit.ps1 -Server db.internal -User auditor

.PARAMETER Server
    SQL Server host or host,port  (default: localhost)

.PARAMETER Database
    Default database context (default: master)

.PARAMETER User
    SQL Server login. Omit to use Windows Authentication (-E).

.PARAMETER Password
    SQL Server password. Prefer $env:SQLCMDPASSWORD over this parameter.

.PARAMETER OutRoot
    Root directory for report folders (default: .\reports)

.EXAMPLE
    # Windows Authentication
    .\run_audit.ps1 -Server "sql01.corp.local"

.EXAMPLE
    # SQL Server auth, password from env
    $env:SQLCMDPASSWORD = "s3cr3t"
    .\run_audit.ps1 -Server "sql01.corp.local,1433" -User auditor -Database master

.EXAMPLE
    # SQL Server auth, password inline (avoid on shared machines)
    .\run_audit.ps1 -Server "sql01.corp.local" -User sa -Password "P@ssw0rd" -OutRoot D:\audit
#>

[CmdletBinding()]
param(
    [string]$Server   = "localhost",
    [string]$Database = "master",
    [string]$User     = "",          # empty = Windows Auth
    [string]$Password = "",
    [string]$OutRoot  = ".\reports"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Locate sqlcmd (go-sqlcmd or mssql-tools)
# ---------------------------------------------------------------------------
$sqlcmd = Get-Command sqlcmd -ErrorAction SilentlyContinue
if (-not $sqlcmd) {
    Write-Error @"
sqlcmd not found on PATH.
Install via winget:
  winget install Microsoft.go-sqlcmd          # recommended (no ODBC dependency)
  winget install Microsoft.SQLServerCmdLineUtils
"@
    exit 2
}

# ---------------------------------------------------------------------------
# Build auth arguments
# ---------------------------------------------------------------------------
if ($User) {
    # SQL Server Authentication
    $authArgs = @("-U", $User)
    if ($Password) {
        # set env var so it doesn't appear in process args / Task Manager
        $env:SQLCMDPASSWORD = $Password
    }
    # if Password omitted, rely on $env:SQLCMDPASSWORD already being set
} else {
    # Windows Authentication
    $authArgs = @("-E")
}

# ---------------------------------------------------------------------------
# Create timestamped output folder
# ---------------------------------------------------------------------------
$ts  = Get-Date -Format "yyyyMMdd_HHmmss"
$Out = Join-Path $OutRoot "mssql_perf_$ts"
New-Item -ItemType Directory -Path $Out -Force | Out-Null

$ScriptsRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ("=" * 80)
Write-Host "SQL Server performance audit"
Write-Host "  server   = $Server"
Write-Host "  auth     = $(if ($User) { "SQL Server ($User)" } else { "Windows Authentication" })"
Write-Host "  database = $Database"
Write-Host "  output   = $Out"
Write-Host ("=" * 80)

# ---------------------------------------------------------------------------
# Run scripts
# ---------------------------------------------------------------------------
$pass    = 0
$fail    = 0
$summary = [System.Collections.Generic.List[string]]::new()

foreach ($priority in @("critical","high","medium","low")) {
    $dir = Join-Path $ScriptsRoot $priority
    if (-not (Test-Path $dir)) { continue }

    Get-ChildItem (Join-Path $dir "*.sql") | Sort-Object Name | ForEach-Object {
        $f    = $_.FullName
        $base = $_.BaseName
        $log  = Join-Path $Out "${priority}_${base}.log"

        # -C  trust server certificate (containers / internal CAs)
        # -b  exit non-zero on severity >= 11
        $sqlArgs = @("-S", $Server) + $authArgs + @("-d", $Database, "-C", "-b", "-i", $f)

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

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$summary.Add("--------------------------------------------------------------------------------")
$summary.Add("Engine:    mssql")
$summary.Add("Category:  perf")
$summary.Add("Timestamp: $ts")
$summary.Add("Target:    $(if ($User) { $User } else { "$env:USERDOMAIN\$env:USERNAME" })@$Server/$Database")
$summary.Add("Pass:      $pass")
$summary.Add("Fail:      $fail")

$summary | Set-Content (Join-Path $Out "_summary.txt") -Encoding UTF8

Write-Host ("-" * 80)
Write-Host "Pass:  $pass"
Write-Host "Fail:  $fail"
Write-Host "Report: $Out"

if ($fail -gt 0) { exit 1 }
