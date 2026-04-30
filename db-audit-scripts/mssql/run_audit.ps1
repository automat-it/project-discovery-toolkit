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
    $summaryPath = Join-Path $Out "_summary.txt"
    # Truncate / start summary so partial progress is preserved on Ctrl+C
    Set-Content -Path $summaryPath -Value "" -Encoding UTF8

    Write-Host ""
    Write-Host "--- $cat ---"
    Write-Host "  output = $Out"

    $pass = 0
    $fail = 0

    foreach ($priority in @("critical","high","medium","low")) {
        $dir = Join-Path $catRoot $priority
        if (-not (Test-Path $dir)) { continue }

        Get-ChildItem (Join-Path $dir "*.sql") | Sort-Object Name | ForEach-Object {
            $log = Join-Path $Out "${priority}_$($_.BaseName).log"
            # -t 120 : per-query timeout in seconds (kills hung XE / XML shred queries)
            # -I     : SET QUOTED_IDENTIFIER ON at the connection level. Required
            #          for XML data type methods (FOR XML PATH, .value(), .nodes())
            #          which check QI at compile time. SET QUOTED_IDENTIFIER ON
            #          inside the script is too late once the batch is compiled.
            # Capture sqlcmd output via a pipeline + Out-File -Encoding UTF8 so the
            # log file is plain UTF-8 (default '> $log' on PS 5.1 produces UTF-16 LE
            # which downstream Linux/Python tooling cannot parse).
            $sqlArgs = @("-S", $Server) + $authArgs + @("-d", $Database, "-C", "-I", "-b", "-t", "120", "-i", $_.FullName)

            # Resilient invocation: locally relax ErrorActionPreference so a
            # native sqlcmd-side error (e.g. "Internal error at
            # ReadAndHandleColumnData", ODBC stream glitches on huge XML /
            # NVARCHAR(MAX) rows) does NOT abort the whole multi-database
            # audit. The error message goes to the per-script log; the
            # script is recorded as FAIL and the runner moves on.
            $rc            = -1
            $caughtMessage = $null
            $prevPref      = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                & sqlcmd @sqlArgs *>&1 | Out-File -FilePath $log -Encoding utf8
                $rc = $LASTEXITCODE
            }
            catch {
                $caughtMessage = $_.Exception.Message
                "[runner] sqlcmd raised: $caughtMessage" |
                    Out-File -FilePath $log -Encoding utf8 -Append
                $rc = if ($LASTEXITCODE) { $LASTEXITCODE } else { 1 }
            }
            finally {
                $ErrorActionPreference = $prevPref
            }

            $logSize = if (Test-Path $log) { (Get-Item $log).Length } else { 0 }

            # Fail conditions:
            # 1) sqlcmd exited non-zero (severity >= 11, sqlcmd:error, etc.)
            # 2) sqlcmd was killed mid-run / produced no output -- treat the
            #    empty file as FAIL even though exit code can be 0 in some
            #    interrupt paths.
            # 3) PowerShell caught a NativeCommandError mid-stream (catch above).
            $isFail = ($rc -ne 0) -or ($logSize -eq 0) -or ($null -ne $caughtMessage)

            if ($isFail) {
                $fail++
                $reason =
                    if     ($caughtMessage)  { "native error: $caughtMessage" }
                    elseif ($rc -ne 0)       { "rc=$rc" }
                    else                     { "empty log (sqlcmd produced no output)" }
                Write-Host ("[FAIL] {0,-8} {1}  ({2})  -> $log" -f $priority, $_.Name, $reason) -ForegroundColor Red
                Add-Content -Path $summaryPath -Value "FAIL $priority/$($_.Name)" -Encoding UTF8
            } else {
                $pass++
                Write-Host ("[OK  ] {0,-8} {1}" -f $priority, $_.Name)
                Add-Content -Path $summaryPath -Value "OK   $priority/$($_.Name)" -Encoding UTF8
            }
        }
    }

    # Final tally appended to the summary file (incrementally written above).
    $tail = @(
        "--------------------------------------------------------------------------------",
        "Engine:    mssql",
        "Category:  $cat",
        "Timestamp: $ts",
        "Target:    $authLabel @ $Server / $Database",
        "Pass:      $pass",
        "Fail:      $fail"
    )
    $tail | Add-Content -Path $summaryPath -Encoding UTF8

    Write-Host ("  Pass: $pass  Fail: $fail  Report: $Out")
    $totalPass += $pass
    $totalFail += $fail
}

Write-Host ""
Write-Host ("-" * 80)
Write-Host "Total pass: $totalPass  Total fail: $totalFail"

if ($totalFail -gt 0) { exit 1 }
