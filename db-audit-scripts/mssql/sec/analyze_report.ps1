#Requires -Version 5.1
<#
.SYNOPSIS
    SQL Server SECURITY audit -- consultant-grade HTML/PDF report.

.DESCRIPTION
    Reads the report directory produced by run_audit.ps1 / run_all_databases.ps1
    and renders a customer-facing security report. Includes:
      - Cover page with server fingerprint and severity donut chart
      - Executive summary (instance-wide rollup + per-domain bar chart)
      - Server-wide vs database-level findings (deduplicated)
      - Top-N rankings (sysadmin holders, weak-password logins, PII columns)
      - Compliance mapping (CIS Benchmark, GDPR, SOC2, HIPAA, PCI)
      - Phased remediation roadmap with executable T-SQL snippets
      - Per-database appendix
      - Glossary
      - Branded footer / watermark

.PARAMETER ReportDir
    Folder produced by run_audit.ps1 / run_all_databases.ps1.

.PARAMETER ServerName
    Server label for the cover.

.PARAMETER Customer
    Customer name printed on the cover.

.PARAMETER Brand
    Branding text in footer.

.PARAMETER OutFile
    Output path. Default: <ReportDir>\sec_analysis.pdf.

.PARAMETER NoPdf
    Skip PDF conversion -- HTML only.

.PARAMETER KeepHtml
    Keep intermediate HTML alongside PDF.

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
    $OutFile = Join-Path $ReportDir "sec_analysis.$ext"
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
# Encoding-aware log readers (mirrors perf analyzer)
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

# Tabular sqlcmd parser (column-fixed) -- mirrors perf analyzer.
function Get-SqlCmdResultSets {
    param([string]$LogPath)
    $lines = Read-LogLines $LogPath
    if (-not $lines) { return @() }
    $sets = @()
    $i = 0
    while ($i -lt $lines.Count) {
        $line = [string]$lines[$i]
        if ($line -match '^[\s\-]+$' -and $line -match '\-{3,}') {
            $headerLine = if ($i -gt 0) { [string]$lines[$i-1] } else { '' }
            if (-not $headerLine.Trim()) { $i++; continue }
            $u = $line.TrimEnd(); $cols = @(); $col = $null
            for ($p = 0; $p -lt $u.Length; $p++) {
                $ch = $u[$p]
                if ($ch -eq '-') {
                    if ($null -eq $col) { $col = @{ Start = $p; End = $p } } else { $col.End = $p }
                } else {
                    if ($null -ne $col) { $cols += [pscustomobject]@{ Start=$col.Start; End=$col.End }; $col = $null }
                }
            }
            if ($null -ne $col) { $cols += [pscustomobject]@{ Start=$col.Start; End=$col.End } }
            $names = @()
            foreach ($c in $cols) {
                $w  = $c.End - $c.Start + 1
                if ($c.Start -ge $headerLine.Length) { $names += "col$($names.Count + 1)"; continue }
                $end = [Math]::Min($headerLine.Length - 1, $c.Start + $w - 1)
                $raw = $headerLine.Substring($c.Start, $end - $c.Start + 1).Trim()
                if (-not $raw) { $raw = "col$($names.Count + 1)" }
                $names += $raw
            }
            $rows = New-Object System.Collections.Generic.List[object]
            $i++
            while ($i -lt $lines.Count) {
                $r = [string]$lines[$i]
                if ($r -match '^\s*\(\d+ rows? affected\)\s*$') { $i++; break }
                if ($r -match '^Msg\s+\d+,\s*Level')             { break }
                if ($r -match '^\s*$')                           { $i++; continue }
                if ($r -match '^\[note\]')                       { $i++; continue }
                if ($i + 1 -lt $lines.Count -and ([string]$lines[$i+1]) -match '^[\s\-]+$' -and ([string]$lines[$i+1]) -match '\-{3,}') { break }
                $obj = [ordered]@{}
                for ($k = 0; $k -lt $cols.Count; $k++) {
                    $c   = $cols[$k]; $w = $c.End - $c.Start + 1
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

function Find-LogFile {
    param([string]$LogDir, [string]$ScriptSuffix)
    return Get-ChildItem $LogDir -Filter "*$ScriptSuffix*.log" -File -ErrorAction SilentlyContinue | Select-Object -First 1
}

function Get-ServerFingerprint {
    param([string]$ServerLogDir)
    # Sec audit doesn't always have a clean fingerprint script; pull what we
    # can from sec_05 (auth mode) + sec_06 (audits) + sec_03 (sysadmin count)
    $fp = [ordered]@{
        AuthMode='(unknown)'; SqlAuth=$null; SysadminMembers=$null
        AuditsConfigured=$null; AuditsRunning=$null; HostName='(unknown)'
    }
    if (-not $ServerLogDir) { return $fp }
    $log05 = Find-LogFile $ServerLogDir 'sec_05_authentication'
    if ($log05) {
        $t = Read-LogText $log05.FullName
        if ($t -match '(?im)authentication_mode\s*\n[\s\-]+\n([^\n]+)') { $fp.AuthMode = $matches[1].Trim() }
    }
    $log06 = Find-LogFile $ServerLogDir 'sec_06_audit_logging'
    if ($log06) {
        $t = Read-LogText $log06.FullName
        if ($t -match '(?im)server_audits_defined\s+server_audits_running[^\n]*\n[\s\-]+\n[^\n]*?(\d+)\s+(\d+)') {
            $fp.AuditsConfigured = [int]$matches[1]
            $fp.AuditsRunning    = [int]$matches[2]
        }
    }
    $log03 = Find-LogFile $ServerLogDir 'sec_03_admin_and_superusers'
    if ($log03) {
        $sets = Get-SqlCmdResultSets $log03.FullName
        if ($sets) {
            $smCount = 0
            foreach ($s in $sets) { $smCount += (_Cnt $s.Rows) }
            $fp.SysadminMembers = $smCount
        }
    }
    return [pscustomobject]$fp
}

# Pull the actual sysadmin / weak-password / PII rows for the Top-N tables.
function Get-SysadminMembers {
    param([string]$LogDir)
    $log = Find-LogFile $LogDir 'sec_03_admin_and_superusers'
    if (-not $log) { return @() }
    $names = @()
    foreach ($s in (Get-SqlCmdResultSets $log.FullName)) {
        # First column heuristic: 'member', 'name', 'login_name'
        if ($s.Columns -and $s.Columns.Count -gt 0) {
            $col = $s.Columns[0]
            foreach ($r in $s.Rows) {
                $v = [string]$r.$col
                if ($v) { $names += $v }
            }
        }
    }
    return ($names | Sort-Object -Unique)
}

function Get-WeakPasswordLogins {
    param([string]$LogDir)
    $log = Find-LogFile $LogDir 'sec_05_authentication'
    if (-not $log) { return @() }
    $rows = @()
    foreach ($s in (Get-SqlCmdResultSets $log.FullName)) {
        # Look for sets that mention weak_password / password_equals_login
        if ($s.Columns -and ($s.Columns -match '(?i)weak|equals_login|password_match')) {
            foreach ($r in $s.Rows) {
                $login = $r.($s.Columns[0])
                if ($login) { $rows += [pscustomobject]@{ Login=$login; Reason=($s.Columns -join ',') } }
            }
        }
    }
    return $rows
}

function Get-PiiColumns {
    param([string]$LogDir)
    $log = Find-LogFile $LogDir 'sec_09_sensitive_data_discovery'
    if (-not $log) { return @() }
    $rows = @()
    foreach ($s in (Get-SqlCmdResultSets $log.FullName)) {
        # Columns of interest: schema_name + table_name + column_name + reason
        $idx = @{}
        for ($k = 0; $k -lt $s.Columns.Count; $k++) {
            $c = $s.Columns[$k]
            if ($c -match '(?i)^schema')       { $idx.schema = $c }
            elseif ($c -match '(?i)^table')    { $idx.table  = $c }
            elseif ($c -match '(?i)^column')   { $idx.column = $c }
            elseif ($c -match '(?i)reason|category|type') { $idx.reason = $c }
        }
        if ($idx.column) {
            foreach ($r in $s.Rows) {
                $rows += [pscustomobject]@{
                    Schema = $r.($idx.schema)
                    Table  = $r.($idx.table)
                    Column = $r.($idx.column)
                    Reason = if ($idx.reason) { $r.($idx.reason) } else { '' }
                }
            }
        }
    }
    return $rows
}

function Test-LogHasDataRows {
    param([string]$LogPath)
    foreach ($s in (Get-SqlCmdResultSets $LogPath)) { if ((_Cnt $s.Rows) -gt 0) { return $true } }
    return $false
}

# ===========================================================================
# Security rules (Severity / Scope / compliance / remediation)
# ===========================================================================
$Rules = @(
    @{ Script='sec_03_admin_and_superusers'; Severity='Info'; Scope='Server'
       Title='Privileged accounts inventory'
       CIS='4.1'; GDPR='Art.32(1)(b)'; SOC2='CC6.1'; HIPAA='164.312(a)(1)'; PCI='7.1'
       Detail='sysadmin / securityadmin / CONTROL SERVER holders are listed.'
       Recommendation='Reduce privileged-role membership to the minimum required and rotate quarterly.'
       Remediation=@'
-- Audit current sysadmin members
SELECT m.name AS member_name
FROM   sys.server_role_members rm
JOIN   sys.server_principals m ON m.principal_id = rm.member_principal_id
JOIN   sys.server_principals r ON r.principal_id = rm.role_principal_id
WHERE  r.name = ''sysadmin'';

-- Remove unneeded membership
ALTER SERVER ROLE sysadmin DROP MEMBER [<login>];
'@
    }
    @{ Script='sec_04_public_and_excessive_grants'; Severity='Warning'; Scope='Server'
       Title='Permissions granted to public role or excessive scope'
       CIS='4.2'; GDPR='Art.32(1)(b)'; SOC2='CC6.1'; HIPAA='164.312(a)(1)'; PCI='7.2'
       Detail='Permissions granted to public apply to every login on the instance/database.'
       Recommendation='Move grants from public to dedicated roles and assign only specific principals.'
       Remediation=@'
-- Inventory public grants at server scope
SELECT p.name, perm.permission_name, perm.state_desc
FROM   sys.server_permissions perm
JOIN   sys.server_principals p ON p.principal_id = perm.grantee_principal_id
WHERE  p.name = ''public'' AND perm.state_desc <> ''GRANT_WITH_GRANT_OPTION'';

-- Revoke unneeded
REVOKE <permission> ON <securable> FROM public;
'@
    }
    @{ Script='sec_05_authentication_and_passwords'; Severity='Critical'; Scope='Server'
       Pattern='(?i)weak_password|password\s*=\s*login_name'
       Title='Weak or trivially guessable passwords detected'
       CIS='3.5'; GDPR='Art.32(1)(b)'; SOC2='CC6.1'; HIPAA='164.308(a)(5)'; PCI='8.2'
       Detail='SQL logins with passwords matching common dictionary words or equal to the login name.'
       Recommendation='Force password change for all matched logins.'
       Remediation=@'
-- Force password change at next login
ALTER LOGIN [<login>] WITH PASSWORD = ''<TempStrongP@ss>'' MUST_CHANGE,
       CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
'@
    }
    @{ Script='sec_05_authentication_and_passwords'; Severity='Critical'; Scope='Server'
       Pattern='is_policy_checked\s*\n\s*-+\s*\n[^\(]*\b0\b'
       Title='SQL logins with CHECK_POLICY disabled'
       CIS='3.4'; GDPR='-'; SOC2='CC6.1'; HIPAA='164.308(a)(5)'; PCI='8.2'
       Detail='At least one SQL login is excluded from password policy enforcement.'
       Recommendation='Enable CHECK_POLICY and CHECK_EXPIRATION on all SQL logins (except service accounts with rotation discipline).'
       Remediation='ALTER LOGIN [<login>] WITH CHECK_POLICY = ON, CHECK_EXPIRATION = ON;'
    }
    @{ Script='sec_06_audit_logging'; Severity='Warning'; Scope='Server'
       Pattern='server_audits_running\s*\n\s*-+\s*\n.*\b0\b'
       Title='No SQL Server Audit currently running'
       CIS='5.1'; GDPR='Art.32(1)(d)'; SOC2='CC7.2'; HIPAA='164.312(b)'; PCI='10.2'
       Detail='Without an active Server Audit, security-relevant actions are not retained.'
       Recommendation='Define a Server Audit and Server Audit Specification covering FAILED_LOGIN_GROUP, SCHEMA_OBJECT_CHANGE_GROUP, AUDIT_CHANGE_GROUP at minimum.'
       Remediation=@'
CREATE SERVER AUDIT [security_audit] TO FILE (FILEPATH=''<path>'', MAXSIZE=256MB, MAX_ROLLOVER_FILES=10);
ALTER  SERVER AUDIT [security_audit] WITH (STATE = ON);
CREATE SERVER AUDIT SPECIFICATION [sec_spec] FOR SERVER AUDIT [security_audit]
   ADD (FAILED_LOGIN_GROUP),
   ADD (SCHEMA_OBJECT_CHANGE_GROUP),
   ADD (SERVER_PRINCIPAL_CHANGE_GROUP),
   ADD (AUDIT_CHANGE_GROUP)
   WITH (STATE = ON);
'@
    }
    @{ Script='sec_07_encryption_status'; Severity='Warning'; Scope='Database'
       Pattern='(?i)encryption_state\s*\n\s*-+\s*\n.*\b(0|1)\b'
       Title='Database not protected by TDE'
       CIS='6.1'; GDPR='Art.32(1)(a)'; SOC2='CC6.7'; HIPAA='164.312(a)(2)(iv)'; PCI='3.4'
       Detail='Database is in encryption_state 0 (none) or 1 (key set, not encrypted).'
       Recommendation='Enable TDE on databases that store sensitive data.'
       Remediation=@'
USE master;
CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256
    ENCRYPTION BY SERVER CERTIFICATE [tde_cert];
ALTER DATABASE [<db>] SET ENCRYPTION ON;
'@
    }
    @{ Script='sec_08_network_exposure'; Severity='Info'; Scope='Server'
       Title='Linked servers / remote endpoints inventory'
       CIS='5.4'; GDPR='-'; SOC2='CC6.6'; HIPAA='-'; PCI='-'
       Detail='Inventory of linked servers, endpoints, and remote connections.'
       Recommendation='Review linked-server credentials and endpoint exposure. Remove unused linked servers.'
       Remediation='EXEC sp_dropserver ''<linked_server_name>'', ''droplogins'';'
    }
    @{ Script='sec_09_sensitive_data_discovery'; Severity='Warning'; Scope='Database'
       Title='Columns with PII / sensitive name patterns'
       CIS='-'; GDPR='Art.30,32'; SOC2='CC6.7'; HIPAA='164.312(e)(2)(ii)'; PCI='3.4'
       Detail='Columns whose names match PII patterns (SSN, credit card, email, phone, DOB, etc.).'
       Recommendation='Verify whether columns hold sensitive data. Apply Always Encrypted, Dynamic Data Masking, or column-level encryption.'
       Remediation=@'
-- Dynamic Data Masking example
ALTER TABLE [<schema>].[<table>] ALTER COLUMN [<col>] ADD MASKED WITH (FUNCTION = ''partial(0,"XXX-XX-",4)'');

-- Always Encrypted (one-time setup -- prefer SSMS wizard for key generation)
'@
    }
    @{ Script='sec_10_dangerous_objects'; Severity='Critical'; Scope='Server'
       Pattern='(?i)xp_cmdshell.*\b1\b|\b1\b.*xp_cmdshell'
       Title='xp_cmdshell is enabled'
       CIS='2.1'; GDPR='Art.32(1)(b)'; SOC2='CC6.6'; HIPAA='-'; PCI='2.2'
       Detail='xp_cmdshell allows shell command execution from T-SQL.'
       Recommendation='Disable xp_cmdshell unless explicitly required and audited.'
       Remediation=@'
EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;
EXEC sp_configure ''xp_cmdshell'', 0; RECONFIGURE;
'@
    }
    @{ Script='sec_10_dangerous_objects'; Severity='Warning'; Scope='Server'
       Pattern='(?i)\bUNSAFE\b'
       Title='UNSAFE CLR assemblies present'
       CIS='2.10'; GDPR='-'; SOC2='CC6.6'; HIPAA='-'; PCI='-'
       Detail='UNSAFE assemblies bypass .NET code-access security.'
       Recommendation='Review necessity; switch to EXTERNAL_ACCESS or SAFE.'
       Remediation='ALTER ASSEMBLY [<asm>] WITH PERMISSION_SET = SAFE;'
    }
    @{ Script='sec_10_dangerous_objects'; Severity='Warning'; Scope='Server'
       Pattern='(?i)\bAd Hoc Distributed Queries\b.*\b1\b|OLE Automation Procedures.*\b1\b'
       Title='Risky surface-area features enabled'
       CIS='2.2'; GDPR='-'; SOC2='CC6.6'; HIPAA='-'; PCI='2.2'
       Detail='Ad Hoc Distributed Queries / OLE Automation procedures are enabled.'
       Recommendation='Disable unless explicitly required.'
       Remediation=@'
EXEC sp_configure ''Ad Hoc Distributed Queries'', 0; RECONFIGURE;
EXEC sp_configure ''Ole Automation Procedures'', 0; RECONFIGURE;
'@
    }
    @{ Script='sec_12_dba_role_review'; Severity='Info'; Scope='Database'
       Title='db_owner / DBA role expansion review'
       CIS='4.3'; GDPR='-'; SOC2='CC6.1'; HIPAA='-'; PCI='7.1'
       Detail='Members of db_owner and adjacent high-privilege roles in user databases.'
       Recommendation='Review db_owner / sysadmin chain for least-privilege opportunities.'
       Remediation='ALTER ROLE db_owner DROP MEMBER [<user>];'
    }
    @{ Script='sec_17_recovery_and_backup_security'; Severity='Warning'; Scope='Database'
       Pattern='(?i)\bencrypted\b\s*\n\s*-+\s*\n.*\b0\b'
       Title='Recent backups are not encrypted'
       CIS='6.2'; GDPR='Art.32(1)(a)'; SOC2='CC6.7'; HIPAA='164.312(a)(2)(iv)'; PCI='3.4'
       Detail='Most recent backup file(s) for one or more databases are not encrypted.'
       Recommendation='Enable backup encryption (TDE-backed key or backup encryption certificate).'
       Remediation=@'
BACKUP DATABASE [<db>] TO DISK=''<path>\<db>.bak''
WITH ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = [backup_cert]),
     COMPRESSION, CHECKSUM;
'@
    }
    @{ Script='sec_20_failed_login_patterns'; Severity='Warning'; Scope='Server'
       Title='Failed-login activity recorded'
       CIS='5.2'; GDPR='Art.32(1)(d)'; SOC2='CC7.2'; HIPAA='164.308(a)(5)'; PCI='8.1'
       Detail='Failed-login entries present in ERRORLOG / Server Audit.'
       Recommendation='Review failed-login source IPs and login names; tune brute-force defenses.'
       Remediation=@'
-- Inspect failed logins from ERRORLOG (last 30 days)
DECLARE @s DATETIME = DATEADD(day, -30, SYSUTCDATETIME());
EXEC xp_readerrorlog 0, 1, N''Login failed'', NULL, @s, NULL, N''DESC'';
'@
    }
    @{ Script='sec_22_cert_and_key_expiry'; Severity='Warning'; Scope='Server'
       Pattern='(?i)days_to_expiry\s*\n\s*-+\s*\n.*\b(-?\d|[1-9]\d|1[0-7]\d|180)\b'
       Title='Certificate or key expires within 180 days'
       CIS='6.3'; GDPR='-'; SOC2='CC6.7'; HIPAA='-'; PCI='3.6'
       Detail='Server certificate / asymmetric key approaching expiry.'
       Recommendation='Plan rotation. Expired TDE certificates take TDE / endpoint encryption offline.'
       Remediation='-- Plan certificate rotation; re-key TDE before expiry.'
    }
)

# ===========================================================================
# Apply rules
# ===========================================================================
function Get-FindingsForLogDir {
    param([string]$LogDir)
    $list = New-Object System.Collections.Generic.List[object]
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
            Remediation=''; CIS='-'; GDPR='-'; SOC2='-'; HIPAA='-'; PCI='-'
        })
    }
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
                    Detail     = if ($rule.Detail) { "$($rule.Detail) Context: $context" } else { "Context: $context" }
                    Recommendation = $rule.Recommendation
                    Remediation    = $rule.Remediation
                    CIS  = if ($rule.CIS)   { $rule.CIS }   else { '-' }
                    GDPR = if ($rule.GDPR)  { $rule.GDPR }  else { '-' }
                    SOC2 = if ($rule.SOC2)  { $rule.SOC2 }  else { '-' }
                    HIPAA= if ($rule.HIPAA) { $rule.HIPAA } else { '-' }
                    PCI  = if ($rule.PCI)   { $rule.PCI }   else { '-' }
                })
            }
        }
    }
    return ,$list.ToArray()
}

function Get-ReportContexts {
    param([string]$Root)
    $contexts = @()
    Get-ChildItem $Root -Directory | Sort-Object Name | ForEach-Object {
        $dbName = $_.Name
        Get-ChildItem $_.FullName -Directory -Filter 'mssql_sec_*' |
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
# SVG charts
# ===========================================================================
function New-SvgDonut {
    param([int]$Critical, [int]$Warning, [int]$Info)
    $total = $Critical + $Warning + $Info
    if ($total -le 0) { return "<p class='ok'>No findings recorded.</p>" }
    $rad = 80; $cx = 110; $cy = 110; $stroke = 30
    $vals = @(
        @{ Name='Critical'; N=$Critical; C='#c0392b' },
        @{ Name='Warning';  N=$Warning;  C='#e67e22' },
        @{ Name='Info';     N=$Info;     C='#2980b9' }
    )
    $offset = 0; $segments = ''
    foreach ($v in $vals) {
        if ($v.N -le 0) { continue }
        $angle = 360.0 * $v.N / $total
        $a1 = ($offset - 90) * [math]::PI / 180.0
        $a2 = ($offset + $angle - 90) * [math]::PI / 180.0
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
    param([array]$Items, [string]$ColorPositive='#8e44ad')
    if (-not $Items -or (_Cnt $Items) -eq 0) { return '' }
    $maxN = 1
    foreach ($it in $Items) { if ($it.Value -gt $maxN) { $maxN = $it.Value } }
    $rowH = 22; $padTop = 10; $padLeft = 220; $width = 620
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
# Main
# ===========================================================================
$contexts = Get-ReportContexts $ReportDir
if ((_Cnt $contexts) -eq 0) { Write-Error "No report sub-folders under $ReportDir."; exit 3 }

$report = New-Object System.Collections.Generic.List[object]
foreach ($ctx in $contexts) {
    $findings = Get-FindingsForLogDir $ctx.LogDir
    $sum      = Read-AuditSummary (Join-Path $ctx.LogDir '_summary.txt')
    $passed   = @($sum | Where-Object { $_.Status -eq 'OK' }).Count
    $failed   = @($sum | Where-Object { $_.Status -eq 'FAIL' }).Count
    [void]$report.Add([pscustomobject]@{
        Name=$ctx.Name; LogDir=$ctx.LogDir; Findings=$findings
        Passed=$passed; Failed=$failed
        Critical=@($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
        Warning =@($findings | Where-Object { $_.Severity -eq 'Warning'  }).Count
        Info    =@($findings | Where-Object { $_.Severity -eq 'Info'     }).Count
    })
}

$serverCtx   = $report | Where-Object { $_.Name -eq '_server' } | Select-Object -First 1
$fingerprint = if ($serverCtx) { Get-ServerFingerprint $serverCtx.LogDir } else { $null }

# Top-N data extraction (server-level pulls)
$sysadmins = if ($serverCtx) { Get-SysadminMembers $serverCtx.LogDir } else { @() }
$weakPwds  = if ($serverCtx) { Get-WeakPasswordLogins $serverCtx.LogDir } else { @() }

# PII scan: aggregate columns across all DBs
$piiAll = New-Object System.Collections.Generic.List[object]
foreach ($r in $report) {
    if ($r.Name -eq '_server') { continue }
    foreach ($p in (Get-PiiColumns $r.LogDir)) {
        [void]$piiAll.Add([pscustomobject]@{
            Database=$r.Name; Schema=$p.Schema; Table=$p.Table; Column=$p.Column; Reason=$p.Reason
        })
    }
}

# Aggregate findings across DBs by Title
$titleAgg = @{}
foreach ($r in $report) {
    foreach ($f in $r.Findings) {
        $key = "$($f.Severity)|$($f.Scope)|$($f.Title)"
        if (-not $titleAgg.ContainsKey($key)) {
            $titleAgg[$key] = [pscustomobject]@{
                Severity=$f.Severity; Scope=$f.Scope; Title=$f.Title
                Recommendation=$f.Recommendation; Remediation=$f.Remediation
                CIS=$f.CIS; GDPR=$f.GDPR; SOC2=$f.SOC2; HIPAA=$f.HIPAA; PCI=$f.PCI
                Databases = New-Object System.Collections.Generic.List[string]
            }
        }
        if ($r.Name -ne '_server' -or $f.Scope -eq 'Server') {
            [void]$titleAgg[$key].Databases.Add($r.Name)
        }
    }
}
foreach ($v in $titleAgg.Values) { $v | Add-Member -NotePropertyName _Rank -NotePropertyValue (Get-SeverityRank $v.Severity) -Force }
$aggregated      = $titleAgg.Values | Sort-Object _Rank, Title
$serverFindings  = @($aggregated | Where-Object { $_.Scope -eq 'Server' })
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

# Domain bucket counts (sec)
$domainBuckets = [ordered]@{
    'Identity & access'       = @('sec_01','sec_02','sec_03','sec_11','sec_12')
    'Public / excessive grants' = @('sec_04')
    'Authentication'          = @('sec_05')
    'Audit & logging'         = @('sec_06','sec_18','sec_19','sec_20')
    'Encryption'              = @('sec_07','sec_22')
    'Network exposure'        = @('sec_08')
    'Sensitive data (PII)'    = @('sec_09')
    'Dangerous objects'       = @('sec_10','sec_15')
    'Backup security'         = @('sec_17')
    'Patch / CVE level'       = @('sec_21')
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
h2{font-size:16pt;margin:24px 0 10px;border-bottom:2px solid #8e44ad;padding-bottom:4px}
h3{font-size:12.5pt;margin:14px 0 6px;color:#8e44ad}
h4{font-size:11pt;margin:10px 0 4px;color:#444}
.cover{page-break-after:always;padding:40px;background:linear-gradient(135deg,#8e44ad 0%,#6f3690 100%);color:white;min-height:240mm}
.cover h1{font-size:30pt}
.cover .meta{margin-top:20px;font-size:11pt}
.cover .meta div{margin:4px 0}
.cover .donut{margin-top:30px;background:white;border-radius:8px;padding:18px;display:inline-block}
.cover .badge{display:inline-block;padding:6px 14px;border-radius:20px;background:rgba(255,255,255,0.2);font-size:10pt;margin-bottom:14px}
.section{padding:24px 28px;page-break-inside:avoid}
.section.firstaftercov{page-break-before:always}
table{border-collapse:collapse;width:100%;font-size:9.7pt;background:white}
th,td{padding:6px 8px;border-bottom:1px solid #e0e0e0;text-align:left;vertical-align:top}
th{background:#f1eaf6;font-weight:600}
.exec{display:flex;gap:24px;flex-wrap:wrap;margin-bottom:18px}
.kpi{flex:1;min-width:140px;background:#faf6fc;border:1px solid #e6dbef;border-radius:6px;padding:12px 14px}
.kpi .num{font-size:22pt;font-weight:700;color:#8e44ad}
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
.roadmap-phase{border-left:4px solid #8e44ad;padding:8px 14px;margin:10px 0;background:#faf6fc}
.roadmap-phase h3{margin-top:0}
.roadmap-phase ul{margin:6px 0 0 18px;padding:0}
.glossary{font-size:9.5pt}
.glossary dt{font-weight:600;margin-top:8px;color:#8e44ad}
.glossary dd{margin:0 0 4px 16px}
.appendix{font-size:9.5pt}
.tag{display:inline-block;background:#f1eaf6;color:#8e44ad;border-radius:10px;padding:1px 8px;font-size:8.5pt;margin-right:4px}
.alert{background:#fdecea;border-left:4px solid #c0392b;padding:10px 14px;margin:8px 0;border-radius:4px}
.note {background:#fff8e1;border-left:4px solid #e67e22;padding:10px 14px;margin:8px 0;border-radius:4px}
.ok   {color:#27ae60;font-weight:600;font-style:italic}
@page{@bottom-center{content:counter(page) ' / ' counter(pages)}}
.watermark{position:fixed;bottom:6mm;right:8mm;font-size:8pt;color:#999}
section.severity{page-break-before:always}
</style>
'@

$customerHtml = if ($Customer) { "<div class='meta'><strong>Prepared for:</strong> $(Esc $Customer)</div>" } else { '' }
$donut = New-SvgDonut -Critical $totalCrit -Warning $totalWarn -Info $totalInfo
$domainBarSvg = New-SvgBar -Items $domainCounts

$cover = @"
<section class='cover'>
  <span class='badge'>SQL Server Security Audit</span>
  <h1>Security Audit Report</h1>
  <div class='meta'>
    <div><strong>Server:</strong> $(Esc ($ServerName | ForEach-Object { if ($_) { $_ } else { '(unspecified)' } }))</div>
    $customerHtml
    <div><strong>Databases analyzed:</strong> $dbCount</div>
    <div><strong>Generated:</strong> $now</div>
    <div><strong>Source:</strong> $(Esc $ReportDir)</div>
  </div>
  <div class='donut'>$donut</div>
</section>
"@

$fpHtml = ''
if ($fingerprint) {
    $fpHtml = @"
<section class='section firstaftercov'>
<h2>1. Environment Fingerprint</h2>
<dl class='fp'>
  <dt>Authentication mode</dt> <dd>$(Esc $fingerprint.AuthMode)</dd>
  <dt>Sysadmin members</dt>    <dd>$(Esc $fingerprint.SysadminMembers)</dd>
  <dt>Server audits configured</dt> <dd>$(Esc $fingerprint.AuditsConfigured)</dd>
  <dt>Server audits running</dt>     <dd>$(Esc $fingerprint.AuditsRunning)</dd>
  <dt>Databases counted</dt>          <dd>$dbCount</dd>
</dl>
$( if ($fingerprint.AuthMode -match '(?i)mixed') { "<div class='note'>Mixed-mode authentication is enabled. SQL logins are evaluated; Windows-only mode reduces attack surface where Active Directory is available.</div>" } )
$( if ($fingerprint.AuditsRunning -ne $null -and $fingerprint.AuditsRunning -lt 1) { "<div class='alert'>No SQL Server Audit is currently running. Security-relevant actions are not retained.</div>" } )
</section>
"@
} else {
    $fpHtml = "<section class='section firstaftercov'><h2>1. Environment Fingerprint</h2><div class='note'>Server fingerprint not available -- _server context did not produce sec_* output.</div></section>"
}

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

$srvFindHtml = "<section class='section'><h2>3. Server-Wide Findings</h2>"
if ((_Cnt $serverFindings) -eq 0) {
    $srvFindHtml += "<p class='ok'>No server-wide findings detected.</p>"
} else {
    $srvFindHtml += "<table><thead><tr><th>Severity</th><th>Finding</th><th>CIS</th><th>GDPR</th><th>SOC2</th><th>HIPAA</th><th>PCI</th></tr></thead><tbody>"
    foreach ($a in $serverFindings) {
        $sevC = $a.Severity.ToLower()
        $srvFindHtml += "<tr class='sev-$sevC'><td><span class='badge $sevC'>$($a.Severity)</span></td>"
        $srvFindHtml += "<td><strong>$(Esc $a.Title)</strong><br><span class='detail'>$(Esc $a.Recommendation)</span></td>"
        $srvFindHtml += "<td class='compl'>$(Esc $a.CIS)</td><td class='compl'>$(Esc $a.GDPR)</td>"
        $srvFindHtml += "<td class='compl'>$(Esc $a.SOC2)</td><td class='compl'>$(Esc $a.HIPAA)</td><td class='compl'>$(Esc $a.PCI)</td></tr>"
    }
    $srvFindHtml += "</tbody></table>"
}
$srvFindHtml += "</section>"

$dbFindHtml = "<section class='section'><h2>4. Database-Level Findings (Fleet Rollup)</h2>"
if ((_Cnt $dbFindings) -eq 0) {
    $dbFindHtml += "<p class='ok'>No database-level findings detected.</p>"
} else {
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

# Top-N data
$topNHtml = "<section class='section'><h2>5. Top-N Inventories</h2>"
$topNHtml += "<h3>5.1 Privileged accounts</h3>"
if ((_Cnt $sysadmins) -eq 0) {
    $topNHtml += "<p class='note'>Privileged-account list could not be extracted.</p>"
} else {
    $topNHtml += "<p>Total entries (sysadmin / equivalent): <strong>$((_Cnt $sysadmins))</strong>. Sample shown.</p><ul>"
    foreach ($s in ($sysadmins | Select-Object -First 25)) { $topNHtml += "<li><span class='kbd'>$(Esc $s)</span></li>" }
    if ((_Cnt $sysadmins) -gt 25) { $topNHtml += "<li>... +$([int]((_Cnt $sysadmins) - 25)) more</li>" }
    $topNHtml += "</ul>"
}
$topNHtml += "<h3>5.2 Weak / trivial passwords</h3>"
if ((_Cnt $weakPwds) -eq 0) {
    $topNHtml += "<p class='ok'>No weak-password matches recorded.</p>"
} else {
    $topNHtml += "<table><thead><tr><th>Login</th><th>Detection rule</th></tr></thead><tbody>"
    foreach ($w in $weakPwds) {
        $topNHtml += "<tr><td><span class='kbd'>$(Esc $w.Login)</span></td><td class='detail'>$(Esc $w.Reason)</td></tr>"
    }
    $topNHtml += "</tbody></table>"
}
$topNHtml += "<h3>5.3 PII / sensitive columns</h3>"
if ((_Cnt $piiAll) -eq 0) {
    $topNHtml += "<p class='ok'>No PII column patterns matched (or sec_09 not run).</p>"
} else {
    $byDb = $piiAll | Group-Object Database | Sort-Object Count -Descending
    $topNHtml += "<p>Total matches: <strong>$((_Cnt $piiAll))</strong> across <strong>$((_Cnt $byDb))</strong> databases.</p>"
    $topNHtml += "<table><thead><tr><th>Database</th><th>PII columns</th></tr></thead><tbody>"
    foreach ($g in ($byDb | Select-Object -First 25)) {
        $topNHtml += "<tr><td>$(Esc $g.Name)</td><td><strong>$($g.Count)</strong></td></tr>"
    }
    $topNHtml += "</tbody></table>"
    $topNHtml += "<h4>Sample columns (first 30)</h4>"
    $topNHtml += "<table><thead><tr><th>Database</th><th>Schema</th><th>Table</th><th>Column</th><th>Reason</th></tr></thead><tbody>"
    foreach ($p in ($piiAll | Select-Object -First 30)) {
        $topNHtml += "<tr><td>$(Esc $p.Database)</td><td>$(Esc $p.Schema)</td><td>$(Esc $p.Table)</td><td><strong>$(Esc $p.Column)</strong></td><td class='detail'>$(Esc $p.Reason)</td></tr>"
    }
    $topNHtml += "</tbody></table>"
}
$topNHtml += "</section>"

# Compliance mapping
$complHtml = "<section class='section'><h2>6. Compliance Mapping</h2><p>Findings mapped to CIS Microsoft SQL Server Benchmark, GDPR Art.32, SOC2 Trust Services Criteria, HIPAA Security Rule, and PCI DSS v4.</p>"
$complHtml += "<table><thead><tr><th>Severity</th><th>Finding</th><th>CIS</th><th>GDPR</th><th>SOC2</th><th>HIPAA</th><th>PCI</th></tr></thead><tbody>"
foreach ($a in $aggregated) {
    if ($a.CIS -eq '-' -and $a.GDPR -eq '-' -and $a.SOC2 -eq '-' -and $a.HIPAA -eq '-' -and $a.PCI -eq '-') { continue }
    $sevC = $a.Severity.ToLower()
    $complHtml += "<tr class='sev-$sevC'><td><span class='badge $sevC'>$($a.Severity)</span></td>"
    $complHtml += "<td>$(Esc $a.Title)</td>"
    $complHtml += "<td class='compl'>$(Esc $a.CIS)</td><td class='compl'>$(Esc $a.GDPR)</td>"
    $complHtml += "<td class='compl'>$(Esc $a.SOC2)</td><td class='compl'>$(Esc $a.HIPAA)</td><td class='compl'>$(Esc $a.PCI)</td></tr>"
}
$complHtml += "</tbody></table></section>"

# Roadmap
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

# T-SQL snippets
$snipHtml = "<section class='section'><h2>8. Remediation Snippets (T-SQL)</h2><p>Reference snippets. Replace placeholders before executing.</p>"
$emitted = @{}
foreach ($a in $aggregated) {
    if (-not $a.Remediation) { continue }
    if ($emitted.ContainsKey($a.Title)) { continue }
    $emitted[$a.Title] = $true
    $snipHtml += "<h4>$(Esc $a.Title)</h4>"
    $snipHtml += "<div class='codeblk'>$(Esc $a.Remediation)</div>"
}
$snipHtml += "</section>"

# Per-DB appendix
$apxHtml = "<section class='section appendix'><h2>9. Appendix A: Per-Database Findings</h2><p>Full findings per database for reference.</p>"
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

$glossary = @"
<section class='section glossary'>
<h2>10. Appendix B: Glossary</h2>
<dl>
<dt>sysadmin</dt><dd>Fixed server role with unrestricted access to the SQL Server instance. Membership should be minimal and reviewed quarterly.</dd>
<dt>CHECK_POLICY / CHECK_EXPIRATION</dt><dd>Login-level flags that bind a SQL login to the host Windows password policy. Both should normally be ON.</dd>
<dt>xp_cmdshell</dt><dd>Extended stored procedure that executes shell commands via T-SQL. High-risk; disable unless explicitly required.</dd>
<dt>TDE (Transparent Data Encryption)</dt><dd>Encrypts the database files and backups at rest using a database encryption key protected by a server certificate.</dd>
<dt>Always Encrypted</dt><dd>Column-level encryption that performs encryption on the client. Even sysadmins cannot read protected values.</dd>
<dt>Dynamic Data Masking (DDM)</dt><dd>Visual masking of column values for non-privileged callers. Not real encryption -- complement, not substitute.</dd>
<dt>Server Audit / Audit Specification</dt><dd>SQL Server's structured auditing facility writing to a file/log target.</dd>
<dt>UNSAFE assembly</dt><dd>CLR assembly with elevated permissions; can call unmanaged code. Audit and prefer SAFE/EXTERNAL_ACCESS.</dd>
<dt>Linked server</dt><dd>Outbound connection to another database server, often with stored credentials. Audit credential strength and usage.</dd>
<dt>CIS Benchmark</dt><dd>Center for Internet Security baseline. Numbers reference the SQL Server Benchmark.</dd>
<dt>GDPR Art.32</dt><dd>EU 2016/679 'Security of processing' -- mandates appropriate technical measures (encryption, integrity, availability).</dd>
</dl>
</section>
"@

$html = @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>SQL Server Security Audit Report</title>
$css
</head><body>
$cover
$fpHtml
$execHtml
$srvFindHtml
$dbFindHtml
$topNHtml
$complHtml
$roadHtml
$snipHtml
$apxHtml
$glossary
<div class='watermark'>$(Esc $Brand) -- generated $now</div>
</body></html>
"@

[System.IO.File]::WriteAllText($HtmlPath, $html, (New-Object System.Text.UTF8Encoding $true))

$pdfMade = $false; $pdfPath = $null
if (-not $NoPdf) {
    $pdfPath = if ($OutFile -like '*.pdf') { $OutFile } else { [System.IO.Path]::ChangeExtension($OutFile, 'pdf') }
    $pdfMade = Convert-HtmlToPdf -Html $HtmlPath -Pdf $pdfPath
    if ($pdfMade -and -not $KeepHtml -and ($HtmlPath -ne $OutFile)) { Remove-Item $HtmlPath -ErrorAction SilentlyContinue }
}

Write-Host ""
Write-Host ("=" * 80)
Write-Host "Security audit report generated."
Write-Host "  Databases analyzed   : $dbCount"
Write-Host "  Critical findings    : $totalCrit"
Write-Host "  Warning findings     : $totalWarn"
Write-Host "  Info findings        : $totalInfo"
Write-Host "  Failed scripts       : $totalFail"
Write-Host "  Server-wide findings : $((_Cnt $serverFindings))"
Write-Host "  Database findings    : $((_Cnt $dbFindings))"
Write-Host "  PII columns recorded : $((_Cnt $piiAll))"
if ($NoPdf)       { Write-Host "  Report (HTML)        : $HtmlPath" }
elseif ($pdfMade) { Write-Host "  Report (PDF)         : $pdfPath"; if ($KeepHtml) { Write-Host "  Report (HTML)        : $HtmlPath" } }
else              { Write-Host "  Report (HTML only)   : $HtmlPath  (Edge headless not available)" }
Write-Host ("=" * 80)
