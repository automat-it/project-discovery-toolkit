#Requires -Version 5.1
<#
.SYNOPSIS
    Parse a SQL Server security audit report folder and generate a
    customer-friendly HTML summary highlighting potential security issues.

.DESCRIPTION
    Reads the report directory produced by run_audit.ps1 (single database)
    or run_all_databases.ps1 (multiple databases), applies a security rule
    set, and writes one HTML file with an executive summary plus a
    dedicated section per database.

    Output: <ReportDir>\sec_analysis.html

.PARAMETER ReportDir
    Folder produced by run_audit.ps1 / run_all_databases.ps1.

.PARAMETER ServerName
    Optional server label for the report header.

.PARAMETER OutFile
    Optional override for the output HTML path. Default:
    <ReportDir>\sec_analysis.html

.EXAMPLE
    .\analyze_report.ps1 -ReportDir "C:\reports\mssql_audit_all_20260429_230243"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ReportDir,
    [string]$ServerName = "",
    [string]$OutFile    = ""
)

# Strict mode intentionally NOT enabled. Pipelines like
# Where-Object {...} | Measure-Object can produce $null on empty input,
# and PowerShell auto-promotes scalars to arrays differently in strict
# vs non-strict mode -- accessing .Count / .Length on those objects
# trips strict mode and aborts the analyzer before any output is
# produced. Strict mode is not worth its cost for a one-shot reporter.
$ErrorActionPreference = "Stop"

if (-not (Test-Path $ReportDir)) {
    Write-Error "Report directory not found: $ReportDir"
    exit 2
}

$ReportDir = (Resolve-Path $ReportDir).Path
if (-not $OutFile) { $OutFile = Join-Path $ReportDir "sec_analysis.html" }

# ===========================================================================
# Security rules
# ===========================================================================
$Rules = @(
    @{ Script='sec_03_admin_and_superusers';    Mode='HasData'; Severity='Info'
       Title='Privileged accounts inventory'
       Recommendation='Review the list of sysadmin / securityadmin / CONTROL SERVER holders. Reduce membership to the minimum.' }

    @{ Script='sec_04_public_and_excessive_grants'; Mode='HasData'; Severity='Warning'
       Title='Permissions granted to public role or excessive scope'
       Recommendation='Permissions granted to the public role apply to every login. Move them to specific roles.' }

    @{ Script='sec_05_authentication_and_passwords'; Mode='Pattern'; Severity='Critical'
       Pattern='is_policy_checked\s*\n\s*-+\s*\n[^\(]*\b0\b'
       Title='SQL logins with CHECK_POLICY disabled'
       Recommendation='At least one SQL login is excluded from password policy. Enable CHECK_POLICY for all logins.' }

    @{ Script='sec_05_authentication_and_passwords'; Mode='Pattern'; Severity='Warning'
       Pattern='(?i)weak[_\s]*password|password\s*=\s*login_name'
       Title='Weak or trivially guessable passwords detected'
       Recommendation='Force password change for the affected logins.' }

    @{ Script='sec_06_audit_logging';           Mode='Pattern'; Severity='Warning'
       Pattern='server_audits_running\s*\n\s*-+\s*\n.*\b0\b'
       Title='No SQL Server Audit currently running'
       Recommendation='Without an active Server Audit, security-relevant actions are not retained. Enable an audit specification.' }

    @{ Script='sec_07_encryption_status';       Mode='Pattern'; Severity='Warning'
       Pattern='(?i)encryption_state\s*\n\s*-+\s*\n.*\b(0|1)\b'
       Title='Database(s) without TDE in steady state'
       Recommendation='encryption_state 0 = no encryption, 1 = unencrypted. Enable TDE on databases that hold sensitive data.' }

    @{ Script='sec_08_network_exposure';        Mode='HasData'; Severity='Info'
       Title='Linked servers / remote endpoints inventory'
       Recommendation='Review linked-server credentials and endpoint exposure. Remove unused linked servers.' }

    @{ Script='sec_09_sensitive_data_discovery'; Mode='HasData'; Severity='Warning'
       Title='Columns with PII / sensitive name patterns'
       Recommendation='Verify whether these columns hold sensitive data. Apply Always Encrypted or Dynamic Data Masking where appropriate.' }

    @{ Script='sec_10_dangerous_objects';       Mode='Pattern'; Severity='Critical'
       Pattern='(?i)xp_cmdshell.*\b1\b|\b1\b.*xp_cmdshell'
       Title='xp_cmdshell is enabled'
       Recommendation='xp_cmdshell allows shell command execution from T-SQL. Disable unless required and audited.' }

    @{ Script='sec_10_dangerous_objects';       Mode='Pattern'; Severity='Warning'
       Pattern='(?i)\bUNSAFE\b'
       Title='UNSAFE CLR assemblies present'
       Recommendation='UNSAFE assemblies bypass .NET security. Review necessity and consider EXTERNAL_ACCESS or SAFE alternatives.' }

    @{ Script='sec_10_dangerous_objects';       Mode='Pattern'; Severity='Warning'
       Pattern='(?i)\bAd Hoc Distributed Queries\b.*\b1\b|OLE Automation Procedures.*\b1\b'
       Title='Risky surface-area features enabled'
       Recommendation='Disable Ad Hoc Distributed Queries and OLE Automation procedures unless explicitly required.' }

    @{ Script='sec_12_dba_role_review';         Mode='HasData'; Severity='Info'
       Title='DBA / db_owner role expansion'
       Recommendation='Review db_owner / sysadmin chain for least-privilege opportunities.' }

    @{ Script='sec_17_recovery_and_backup_security'; Mode='Pattern'; Severity='Warning'
       Pattern='(?i)\bencrypted\b\s*\n\s*-+\s*\n.*\b0\b'
       Title='Recent backups are not encrypted'
       Recommendation='Backup files are not encrypted. Configure backup encryption (TDE-backed key or certificate).' }

    @{ Script='sec_20_failed_login_patterns';   Mode='HasData'; Severity='Warning'
       Title='Failed-login activity recorded'
       Recommendation='Review failed-login source IPs and login names. Tune brute-force defenses.' }

    @{ Script='sec_22_cert_and_key_expiry';     Mode='Pattern'; Severity='Warning'
       Pattern='(?i)days_to_expiry\s*\n\s*-+\s*\n.*\b(-?\d|[1-9]\d|1[0-7]\d|180)\b'
       Title='Certificate or key expires within 180 days'
       Recommendation='Plan rotation. Expired certificates can take TDE / endpoint encryption offline.' }
)

# ===========================================================================
# Helpers (mirrored from perf analyzer)
# ===========================================================================
# Detect file encoding by BOM. Read via FileStream so empty / 1-byte files
# return $read=0 and the function falls through to UTF-8. The earlier
# pipeline + Select-Object form returned $null on empty files and tripped
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
        return [System.Text.Encoding]::Unicode
    }
    if ($read -ge 2 -and $head[0] -eq 0xFE -and $head[1] -eq 0xFF) {
        return [System.Text.Encoding]::BigEndianUnicode
    }
    if ($read -ge 3 -and $head[0] -eq 0xEF -and $head[1] -eq 0xBB -and $head[2] -eq 0xBF) {
        return [System.Text.Encoding]::UTF8
    }
    if ($read -ge 2 -and $head[0] -gt 0 -and $head[0] -lt 128 -and $head[1] -eq 0) {
        return [System.Text.Encoding]::Unicode
    }
    return [System.Text.Encoding]::UTF8
}

function Read-LogLines {
    param([string]$LogPath)
    if (-not (Test-Path $LogPath)) { return @() }
    return [System.IO.File]::ReadAllLines($LogPath, (Get-LogEncoding $LogPath))
}

function Read-LogText {
    param([string]$LogPath)
    if (-not (Test-Path $LogPath)) { return "" }
    return [System.IO.File]::ReadAllText($LogPath, (Get-LogEncoding $LogPath))
}

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

function Get-Findings {
    param([string]$LogDir)
    $findings = @()

    # Failed scripts
    foreach ($entry in Read-AuditSummary (Join-Path $LogDir "_summary.txt")) {
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
                Severity='Critical'; Script=$entry.Path
                Title='Script execution failed'
                Detail=$errLines
                Recommendation='Check connection privileges, sqlcmd version, and the script log file.'
            }
        }
    }

    # Content rules
    Get-ChildItem $LogDir -Filter '*.log' | ForEach-Object {
        $log = $_.FullName; $base = $_.BaseName
        foreach ($rule in $Rules) {
            if ($base -notmatch [regex]::Escape($rule.Script)) { continue }
            $hit = $false; $detail = ""
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
                        $snippet = $matches[0]
                        if ($snippet.Length -gt 200) { $snippet = $snippet.Substring(0,200) + '...' }
                        $detail = "Match: " + $snippet
                    }
                }
            }
            if ($hit) {
                $findings += [pscustomobject]@{
                    Severity=$rule.Severity; Script=$_.Name
                    Title=$rule.Title; Detail=$detail
                    Recommendation=$rule.Recommendation
                }
            }
        }
    }
    return ,$findings
}

function Get-ReportContexts {
    param([string]$Root)
    if (Test-Path (Join-Path $Root "_summary.txt")) {
        return ,@([pscustomobject]@{ Name = "(single run)"; LogDir = $Root })
    }
    $contexts = @()
    Get-ChildItem $Root -Directory | Sort-Object Name | ForEach-Object {
        $dbName = $_.Name
        Get-ChildItem $_.FullName -Directory -Filter 'mssql_sec_*' |
            Sort-Object Name -Descending |
            Select-Object -First 1 | ForEach-Object {
                $contexts += [pscustomobject]@{ Name = $dbName; LogDir = $_.FullName }
            }
    }
    return ,$contexts
}

# ===========================================================================
# HTML
# ===========================================================================
function Convert-FindingsToHtml {
    param([array]$Findings)
    if (-not $Findings -or $Findings.Count -eq 0) {
        return '<p class="ok">No problems detected by the rule set.</p>'
    }
    $html = "<table class='findings'><thead><tr><th>Severity</th><th>Script</th><th>Finding</th><th>Recommendation</th></tr></thead><tbody>"
    foreach ($f in ($Findings | Sort-Object @{Expression={
            switch ($_.Severity) { 'Critical' {0} 'Warning' {1} 'Info' {2} default {3} }
        }})) {
        $sevClass = $f.Severity.ToLower()
        $html += "<tr class='sev-$sevClass'>"
        $html += "<td><span class='badge $sevClass'>$($f.Severity)</span></td>"
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

Add-Type -AssemblyName System.Web

# ===========================================================================
# Main
# ===========================================================================
$contexts = Get-ReportContexts $ReportDir
if (-not $contexts -or $contexts.Count -eq 0) {
    Write-Error "No report sub-folders found in $ReportDir. Expected mssql_sec_* sub-folders."
    exit 3
}

$report = @()
foreach ($ctx in $contexts) {
    $findings = Get-Findings $ctx.LogDir
    $summary  = Read-AuditSummary (Join-Path $ctx.LogDir "_summary.txt")
    $passed   = ($summary | Where-Object { $_.Status -eq 'OK'   }).Count
    $failed   = ($summary | Where-Object { $_.Status -eq 'FAIL' }).Count
    $crit     = ($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $warn     = ($findings | Where-Object { $_.Severity -eq 'Warning'  }).Count
    $info     = ($findings | Where-Object { $_.Severity -eq 'Info'     }).Count

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
body{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:20px;background:#f5f5f5;color:#222;}
h1{margin:0 0 4px 0;}h2{border-bottom:2px solid #8e44ad;padding-bottom:4px;margin-top:32px;}
header{background:#8e44ad;color:white;padding:24px;border-radius:6px;margin-bottom:20px;}
header p{margin:4px 0;opacity:0.9;}
.summary{background:white;padding:16px;border-radius:6px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,0.1);}
table{border-collapse:collapse;width:100%;background:white;}
th,td{padding:8px 12px;border-bottom:1px solid #e0e0e0;text-align:left;vertical-align:top;}
th{background:#f1eaf6;font-weight:600;}
.findings tr:hover{background:#fafbfc;}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:0.85em;font-weight:600;color:white;}
.badge.critical{background:#c0392b;}
.badge.warning {background:#e67e22;}
.badge.info    {background:#2980b9;}
.sev-critical>td:first-child{border-left:4px solid #c0392b;}
.sev-warning >td:first-child{border-left:4px solid #e67e22;}
.sev-info    >td:first-child{border-left:4px solid #2980b9;}
.detail{color:#666;font-size:0.9em;font-family:Consolas,monospace;}
.ok{color:#27ae60;font-weight:600;}
.exec-summary td.num{text-align:right;font-variant-numeric:tabular-nums;}
.exec-summary td.crit{color:#c0392b;font-weight:600;}
.exec-summary td.warn{color:#e67e22;font-weight:600;}
.exec-summary td.fail{color:#c0392b;font-weight:600;}
.toc{background:white;padding:12px 20px;border-radius:6px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,0.1);}
.toc ul{margin:0;padding-left:20px;columns:3;}
.toc a{text-decoration:none;color:#8e44ad;}
.toc a:hover{text-decoration:underline;}
section.db{background:white;padding:16px 20px;border-radius:6px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,0.1);}
section.db h3{margin-top:0;color:#8e44ad;}
.meta{color:#666;font-size:0.9em;margin-bottom:12px;}
code{background:#f0f0f0;padding:1px 6px;border-radius:3px;font-size:0.9em;}
</style>
'@

$html = @"
<!DOCTYPE html>
<html lang='en'><head><meta charset='UTF-8'>
<title>SQL Server Security Audit Report</title>
$css
</head><body>
<header>
  <h1>SQL Server Security Audit Report</h1>
  <p><strong>Server:</strong> $srvLabel</p>
  <p><strong>Report folder:</strong> $([System.Web.HttpUtility]::HtmlEncode($ReportDir))</p>
  <p><strong>Generated:</strong> $now</p>
</header>

<div class='summary'>
<h2 style='margin-top:0;border:none;'>Executive Summary</h2>
<table class='exec-summary'>
<thead><tr><th>Database / Context</th><th>Scripts OK</th><th>Failed</th><th>Critical</th><th>Warning</th><th>Info</th></tr></thead>
<tbody>
"@
foreach ($r in $report) {
    $anchor = ($r.Name -replace '[^A-Za-z0-9]', '_')
    $html += "<tr><td><a href='#db_$anchor'>$([System.Web.HttpUtility]::HtmlEncode($r.Name))</a></td>"
    $html += "<td class='num'>$($r.Passed)</td>"
    $html += "<td class='num fail'>$($r.Failed)</td>"
    $html += "<td class='num crit'>$($r.Critical)</td>"
    $html += "<td class='num warn'>$($r.Warning)</td>"
    $html += "<td class='num'>$($r.Info)</td></tr>`n"
}
$html += "<tr style='font-weight:bold;background:#f7f0fb;'><td>TOTAL</td>"
$html += "<td class='num'>$(($report | Measure-Object -Property Passed -Sum).Sum)</td>"
$html += "<td class='num fail'>$totalFail</td>"
$html += "<td class='num crit'>$totalCrit</td>"
$html += "<td class='num warn'>$totalWarn</td>"
$html += "<td class='num'>$(($report | Measure-Object -Property Info -Sum).Sum)</td></tr>"
$html += "</tbody></table></div>"

if ($report.Count -gt 1) {
    $html += "<div class='toc'><h2 style='margin-top:0;border:none;'>Sections</h2><ul>"
    foreach ($r in $report) {
        $anchor = ($r.Name -replace '[^A-Za-z0-9]', '_')
        $html += "<li><a href='#db_$anchor'>$([System.Web.HttpUtility]::HtmlEncode($r.Name))</a></li>"
    }
    $html += "</ul></div>"
}

foreach ($r in $report) {
    $anchor = ($r.Name -replace '[^A-Za-z0-9]', '_')
    $html += "<section class='db' id='db_$anchor'>"
    $html += "<h3>$([System.Web.HttpUtility]::HtmlEncode($r.Name))</h3>"
    $html += "<div class='meta'>Logs: <code>$([System.Web.HttpUtility]::HtmlEncode($r.LogDir))</code></div>"
    $html += "<div class='meta'>Scripts run: $($r.Passed + $r.Failed) | OK: $($r.Passed) | Failed: $($r.Failed)</div>"
    $html += (Convert-FindingsToHtml $r.Findings)
    $html += "</section>"
}

$html += "</body></html>"

$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($OutFile, $html, $utf8Bom)

Write-Host ""
Write-Host "================================================================================"
Write-Host "Security audit analysis complete."
Write-Host "  Databases analyzed : $($report.Count)"
Write-Host "  Critical findings  : $totalCrit"
Write-Host "  Warnings           : $totalWarn"
Write-Host "  Failed scripts     : $totalFail"
Write-Host "  Report             : $OutFile"
Write-Host "================================================================================"
