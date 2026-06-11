#Requires -Version 5.1
<#
.SYNOPSIS
    SQL Server SECURITY audit PDF report.

.DESCRIPTION
    Reads a report directory produced by run_audit.ps1 / run_all_databases.ps1
    and renders a customer-facing PDF (HTML intermediate). Includes:
      - Cover page (Automat-it brand) with title and metadata
      - Environment fingerprint (auth mode, sysadmin count, audit status)
      - Executive summary with severity donut chart and per-domain bars
      - Server-wide vs database-level findings, deduplicated across DBs
      - Top-N inventories: privileged accounts, weak-password logins, PII
      - Compliance mapping (CIS, GDPR Art.32, SOC2, HIPAA, PCI DSS)
      - Phased remediation roadmap with executable T-SQL snippets
      - Per-database appendix
      - Glossary

    Default output: <ReportDir>\mssql_sec_analysis.pdf (with .html intermediate).
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

trap {
    $err = $_
    Write-Host ("=" * 80) -ForegroundColor Red
    Write-Host 'ANALYZER ERROR' -ForegroundColor Red
    Write-Host ("Exception : " + $err.Exception.Message) -ForegroundColor Red
    if ($err.InvocationInfo)   { Write-Host ("Location  : " + $err.InvocationInfo.PositionMessage) -ForegroundColor Red }
    if ($err.ScriptStackTrace) { Write-Host 'Stack:' -ForegroundColor Red; Write-Host $err.ScriptStackTrace -ForegroundColor DarkGray }
    Write-Host ("=" * 80) -ForegroundColor Red
    exit 99
}

. (Join-Path (Split-Path -Parent $PSScriptRoot) '_analyze_lib.ps1')
Clear-LogCache

if (-not (Test-Path $ReportDir)) { Write-Error "Report directory not found: $ReportDir"; exit 2 }
$ReportDir = (Resolve-Path -LiteralPath $ReportDir).Path
if (-not $OutFile) {
    $ext = if ($NoPdf) { 'html' } else { 'pdf' }
    $OutFile = Join-Path $ReportDir "mssql_sec_analysis.$ext"
}
$HtmlPath = if ($OutFile -like '*.html') { $OutFile } else { [System.IO.Path]::ChangeExtension($OutFile, 'html') }

# ===========================================================================
# Sec-specific extractors
# ===========================================================================
function Get-ServerFingerprint {
    param([string]$ServerLogDir)
    $fp = [ordered]@{
        AuthMode = '(unknown)'; SysadminMembers = $null
        AuditsConfigured = $null; AuditsRunning = $null; HostName = '(unknown)'
    }
    if (-not $ServerLogDir) { return [pscustomobject]$fp }

    $log05 = Find-LogFile $ServerLogDir 'sec_05_authentication'
    if ($log05) {
        $v = Get-ColumnValue $log05.FullName @('authentication_mode')
        if ($v) { $fp.AuthMode = $v }
    }
    $log06 = Find-LogFile $ServerLogDir 'sec_06_audit_logging'
    if ($log06) {
        $sets = Get-LogResultSets $log06.FullName
        if ($sets -and $sets.Count -ge 1) { $fp.AuditsConfigured = [int]$sets[0].Rows.Length }
        if ($sets -and $sets.Count -ge 2) {
            $running = 0
            foreach ($row in $sets[1].Rows) {
                $status = [string]$row.status_desc
                if (-not $status) { $status = [string]$row.'status_desc' }
                if ($status -match '(?i)started|running|on') { $running++ }
            }
            $fp.AuditsRunning = $running
        }
    }
    $log03 = Find-LogFile $ServerLogDir 'sec_03_admin_and_superusers'
    if ($log03) {
        $count = 0
        foreach ($s in (Get-LogResultSets $log03.FullName)) { $count += [int]$s.Rows.Length }
        $fp.SysadminMembers = $count
    }
    return [pscustomobject]$fp
}

function Get-SysadminMembers {
    param([string]$LogDir)
    $log = Find-LogFile $LogDir 'sec_03_admin_and_superusers'
    if (-not $log) { return @() }
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($s in (Get-LogResultSets $log.FullName)) {
        if ($s.Columns -and $s.Columns.Length -gt 0) {
            $col = $s.Columns[0]
            foreach ($r in $s.Rows) {
                $v = [string]$r.$col
                if ($v) { [void]$names.Add($v) }
            }
        }
    }
    return ($names | Sort-Object -Unique)
}

function Get-WeakPasswordLogins {
    param([string]$LogDir)
    $log = Find-LogFile $LogDir 'sec_05_authentication'
    if (-not $log) { return @() }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($s in (Get-LogResultSets $log.FullName)) {
        if ($s.Columns -and ($s.Columns -match '(?i)weak|equals_login|password_match')) {
            foreach ($r in $s.Rows) {
                $login = $r.($s.Columns[0])
                if ($login) {
                    [void]$rows.Add([pscustomobject]@{ Login = $login; Reason = ($s.Columns -join ',') })
                }
            }
        }
    }
    return $rows.ToArray()
}

function Get-PiiColumns {
    param([string]$LogDir)
    $log = Find-LogFile $LogDir 'sec_09_sensitive_data_discovery'
    if (-not $log) { return @() }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($s in (Get-LogResultSets $log.FullName)) {
        $idx = @{}
        for ($k = 0; $k -lt $s.Columns.Length; $k++) {
            $c = $s.Columns[$k]
            if     ($c -match '(?i)^schema')                    { $idx.schema = $c }
            elseif ($c -match '(?i)^table')                     { $idx.table  = $c }
            elseif ($c -match '(?i)^column')                    { $idx.column = $c }
            elseif ($c -match '(?i)reason|category|type')       { $idx.reason = $c }
        }
        if ($idx.column) {
            foreach ($r in $s.Rows) {
                [void]$rows.Add([pscustomobject]@{
                    Schema = $r.($idx.schema)
                    Table  = $r.($idx.table)
                    Column = $r.($idx.column)
                    Reason = if ($idx.reason) { $r.($idx.reason) } else { '' }
                })
            }
        }
    }
    return $rows.ToArray()
}

# ===========================================================================
# Security rules
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

# ---------------------------------------------------------------------------
# Per-rule documentation links keyed by Title. Rendered alongside the T-SQL
# remediation in section 8 so the operator has the vendor doc one click away.
# ---------------------------------------------------------------------------
$DocsByTitle = @{
    'Privileged accounts inventory' = @(
        @{ Name = 'Microsoft: Server-Level Roles'; Url = 'https://learn.microsoft.com/sql/relational-databases/security/authentication-access/server-level-roles' }
        @{ Name = 'Microsoft: Principle of Least Privilege guidance'; Url = 'https://learn.microsoft.com/sql/relational-databases/security/permissions-database-engine' }
    )
    'Permissions granted to public role or excessive scope' = @(
        @{ Name = 'GRANT / REVOKE (Transact-SQL)'; Url = 'https://learn.microsoft.com/sql/t-sql/statements/grant-transact-sql' }
    )
    'Weak or trivially guessable passwords detected' = @(
        @{ Name = 'ALTER LOGIN (Transact-SQL)'; Url = 'https://learn.microsoft.com/sql/t-sql/statements/alter-login-transact-sql' }
        @{ Name = 'Password Policy'; Url = 'https://learn.microsoft.com/sql/relational-databases/security/password-policy' }
    )
    'SQL logins with CHECK_POLICY disabled' = @(
        @{ Name = 'Password Policy: CHECK_POLICY'; Url = 'https://learn.microsoft.com/sql/relational-databases/security/password-policy' }
    )
    'No SQL Server Audit currently running' = @(
        @{ Name = 'SQL Server Audit'; Url = 'https://learn.microsoft.com/sql/relational-databases/security/auditing/sql-server-audit-database-engine' }
        @{ Name = 'CREATE SERVER AUDIT SPECIFICATION'; Url = 'https://learn.microsoft.com/sql/t-sql/statements/create-server-audit-specification-transact-sql' }
    )
    'Database not protected by TDE' = @(
        @{ Name = 'Transparent Data Encryption (TDE)'; Url = 'https://learn.microsoft.com/sql/relational-databases/security/encryption/transparent-data-encryption' }
    )
    'Linked servers / remote endpoints inventory' = @(
        @{ Name = 'sp_dropserver'; Url = 'https://learn.microsoft.com/sql/relational-databases/system-stored-procedures/sp-dropserver-transact-sql' }
    )
    'Columns with PII / sensitive name patterns' = @(
        @{ Name = 'Always Encrypted'; Url = 'https://learn.microsoft.com/sql/relational-databases/security/encryption/always-encrypted-database-engine' }
        @{ Name = 'Dynamic Data Masking'; Url = 'https://learn.microsoft.com/sql/relational-databases/security/dynamic-data-masking' }
    )
    'xp_cmdshell is enabled' = @(
        @{ Name = 'xp_cmdshell (Transact-SQL)'; Url = 'https://learn.microsoft.com/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql' }
        @{ Name = 'Server Configuration: xp_cmdshell'; Url = 'https://learn.microsoft.com/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option' }
    )
    'UNSAFE CLR assemblies present' = @(
        @{ Name = 'CLR Integration Security'; Url = 'https://learn.microsoft.com/sql/relational-databases/clr-integration/security/clr-integration-security' }
    )
    'Risky surface-area features enabled' = @(
        @{ Name = 'Ad Hoc Distributed Queries'; Url = 'https://learn.microsoft.com/sql/database-engine/configure-windows/ad-hoc-distributed-queries-server-configuration-option' }
        @{ Name = 'OLE Automation Procedures'; Url = 'https://learn.microsoft.com/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option' }
    )
    'db_owner / DBA role expansion review' = @(
        @{ Name = 'Database-Level Roles'; Url = 'https://learn.microsoft.com/sql/relational-databases/security/authentication-access/database-level-roles' }
    )
    'Recent backups are not encrypted' = @(
        @{ Name = 'Backup encryption'; Url = 'https://learn.microsoft.com/sql/relational-databases/backup-restore/backup-encryption' }
    )
    'Failed-login activity recorded' = @(
        @{ Name = 'xp_readerrorlog'; Url = 'https://learn.microsoft.com/sql/relational-databases/system-stored-procedures/sp-readerrorlog-transact-sql' }
    )
    'Certificate or key expires within 180 days' = @(
        @{ Name = 'Certificates and asymmetric keys'; Url = 'https://learn.microsoft.com/sql/relational-databases/security/encryption/sql-server-and-database-encryption-keys-database-engine' }
    )
}
# Inject Docs into each rule by Title so the finding builder forwards them.
foreach ($r in $Rules) {
    if ($DocsByTitle.ContainsKey($r.Title)) { $r.Docs = $DocsByTitle[$r.Title] }
}

$DomainBuckets = [ordered]@{
    'Identity & access'         = @('sec_01','sec_02','sec_03','sec_11','sec_12')
    'Public / excessive grants' = @('sec_04')
    'Authentication'            = @('sec_05')
    'Audit & logging'           = @('sec_06','sec_18','sec_19','sec_20')
    'Encryption'                = @('sec_07','sec_22')
    'Network exposure'          = @('sec_08')
    'Sensitive data (PII)'      = @('sec_09')
    'Dangerous objects'         = @('sec_10','sec_15')
    'Backup security'           = @('sec_17')
    'Patch / CVE level'         = @('sec_21')
}

# ===========================================================================
# Main
# ===========================================================================
$contexts = Get-ReportContexts -Root $ReportDir -RunFolderFilter 'mssql_sec_*'
if ($contexts.Length -eq 0) { Write-Error "No report sub-folders found under $ReportDir."; exit 3 }

$report    = New-Object System.Collections.Generic.List[object]
$ruleIndex = @{}
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
$sysadmins   = if ($serverCtx) { Get-SysadminMembers $serverCtx.LogDir } else { @() }
$weakPwds    = if ($serverCtx) { Get-WeakPasswordLogins $serverCtx.LogDir } else { @() }

# PII across all DBs
$piiAll = New-Object System.Collections.Generic.List[object]
foreach ($r in $report) {
    if ($r.Name -eq '_server') { continue }
    foreach ($p in (Get-PiiColumns $r.LogDir)) {
        [void]$piiAll.Add([pscustomobject]@{
            Database = $r.Name; Schema = $p.Schema; Table = $p.Table; Column = $p.Column; Reason = $p.Reason
        })
    }
}

# Aggregate by Title
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
                CIS = $f.CIS; GDPR = $f.GDPR; SOC2 = $f.SOC2; HIPAA = $f.HIPAA; PCI = $f.PCI
                Databases = New-Object System.Collections.Generic.List[string]
                UniqueDbsCached = $null
            }
        }
        if ($r.Name -ne '_server' -or $f.Scope -eq 'Server') {
            [void]$titleAgg[$key].Databases.Add($r.Name)
        }
    }
}
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

$totalCrit = 0; $totalWarn = 0; $totalInfo = 0; $totalFail = 0
foreach ($r in $report) {
    $totalCrit += [int]$r.Critical
    $totalWarn += [int]$r.Warning
    $totalInfo += [int]$r.Info
    $totalFail += [int]$r.Failed
}
$dbCount = $report.Count

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
# HTML render
# ===========================================================================
$now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

$css = @'
<style>
@page{size:A4;margin:18mm 14mm;@bottom-center{content:counter(page) ' / ' counter(pages);font-size:8pt;color:#777}}
body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;padding:0;color:#222;background:#fff;font-size:10.5pt;line-height:1.45}
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
.tldr{background:#eef4fb;border-left:5px solid #1F497D;border-radius:5px;padding:13px 18px;margin:4px 0 14px;font-size:11.5pt;color:#1f2d3d;line-height:1.55;page-break-inside:avoid;break-inside:avoid}
.nextsteps{background:#fff8ef;border:1px solid #f0d9bd;border-radius:6px;padding:4px 20px 14px;margin:0 0 18px;page-break-inside:avoid;break-inside:avoid}
.nextsteps h3{margin:12px 0 6px;color:#b9651b;border:none}
.nextsteps ol{margin:6px 0 2px;padding-left:20px}
.nextsteps li{margin:6px 0;color:#333;font-size:10pt;line-height:1.45}
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
Add-To $sb "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><title>SQL Server Security Audit Report</title>$css</head><body><div class='page-bg'></div>"

# Cover
$srvLabel = if ($ServerName) { Esc $ServerName } else { '(unspecified)' }
$custHtml = if ($Customer)   { Esc $Customer }   else { '' }
Add-To $sb "<section class='cover'><div class='cover-content'><h1>SQL Server Security Audit Report</h1><div class='sub'>$custHtml</div><div class='meta'><strong>Server:</strong> $srvLabel &nbsp;&middot;&nbsp; <strong>$dbCount</strong> databases analyzed</div><div class='date'>$now</div></div></section>"

# Executive summary -- placed first so readers see the high-level
# picture (counts, severity mix, domain breakdown) before any details.
Add-To $sb "<section class='section firstaftercov'><h2>1. Executive Summary</h2>"

# At-a-glance: plain-language bottom line + prioritized next steps, so a
# non-technical reader gets the outcome and the actions before the KPI cards.
$glanceTotal = $totalCrit + $totalWarn + $totalInfo
$glanceDbWord = if ($dbCount -eq 1) { 'database' } else { 'databases' }
$glanceRanked = @($aggregated | Where-Object { $_.Severity -in @('Critical','Warning') })
if ($glanceTotal -eq 0) {
    $glanceTldr = "<strong>Bottom line:</strong> this audit ran cleanly across $dbCount $glanceDbWord and found no critical or warning issues against the checks performed."
} else {
    $glanceBits = @()
    if ($totalCrit) { $glanceBits += "<strong>$totalCrit critical</strong>" }
    if ($totalWarn) { $glanceBits += "$totalWarn warning" }
    if ($totalInfo) { $glanceBits += "$totalInfo informational" }
    if ($glanceBits.Count -le 2) { $glanceMix = ($glanceBits -join ' and ') }
    else { $glanceMix = (($glanceBits[0..($glanceBits.Count-2)] -join ', ') + ', and ' + $glanceBits[-1]) }
    $glancePlural = if ($glanceTotal -ne 1) { 's' } else { '' }
    $glanceUrgent = if ($glanceRanked.Count -gt 0) { " The most urgent item is <em>$(Esc $glanceRanked[0].Title)</em>." } else { '' }
    $glanceTldr = "<strong>Bottom line:</strong> across $dbCount $glanceDbWord, this audit surfaced $glanceMix finding$glancePlural.$glanceUrgent"
}
Add-To $sb "<div class='tldr'>$glanceTldr</div>"
if ($glanceRanked.Count -gt 0) {
    Add-To $sb "<div class='nextsteps'><h3>Next steps - what to fix first</h3><ol>"
    foreach ($g in @($glanceRanked | Select-Object -First 3)) {
        Add-To $sb "<li><strong>$(Esc $g.Title)</strong> - $(Esc $g.Recommendation)</li>"
    }
    Add-To $sb "</ol></div>"
}
Add-To $sb "<p>Snapshot of this audit: how many databases were analysed, the severity mix of findings, and which security domains drove the count.</p>"
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

# Top issues -- what to fix first, with anchor links to the detailed row.
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
    $sysTxt = if ($null -ne $fingerprint.SysadminMembers) { $fingerprint.SysadminMembers } else { '(unknown)' }
    $cfgTxt = if ($null -ne $fingerprint.AuditsConfigured) { $fingerprint.AuditsConfigured } else { '(unknown)' }
    $runTxt = if ($null -ne $fingerprint.AuditsRunning)   { $fingerprint.AuditsRunning }   else { '(unknown)' }
    Add-To $sb "<dl class='fp'>"
    Add-To $sb "<dt>Authentication mode</dt><dd>$(Esc $fingerprint.AuthMode)</dd>"
    Add-To $sb "<dt>Sysadmin members</dt><dd>$sysTxt</dd>"
    Add-To $sb "<dt>Server audits configured</dt><dd>$cfgTxt</dd>"
    Add-To $sb "<dt>Server audits running</dt><dd>$runTxt</dd>"
    Add-To $sb "<dt>Databases counted</dt><dd>$dbCount</dd>"
    Add-To $sb "</dl>"
    if ($fingerprint.AuthMode -match '(?i)mixed') {
        Add-To $sb "<div class='note'>Mixed-mode authentication is enabled. SQL logins are evaluated; Windows-only mode reduces attack surface where Active Directory is available.</div>"
    }
    if ($null -ne $fingerprint.AuditsRunning -and $fingerprint.AuditsRunning -lt 1) {
        Add-To $sb "<div class='alert'>No SQL Server Audit is currently running. Security-relevant actions are not retained.</div>"
    }
} else {
    Add-To $sb "<div class='note'>Server fingerprint not available -- _server context did not produce sec_* output.</div>"
}
Add-To $sb "</section>"

# Server-wide findings
Add-To $sb "<section class='section'><h2>3. Server-Wide Findings</h2>"
if ($serverFindings.Length -eq 0) {
    Add-To $sb "<p class='ok'>No server-wide findings detected.</p>"
} else {
    Add-To $sb "<table><thead><tr><th>Severity</th><th>Finding</th><th>CIS</th><th>GDPR</th><th>SOC2</th><th>HIPAA</th><th>PCI</th></tr></thead><tbody>"
    foreach ($a in $serverFindings) {
        $sevC = $a.Severity.ToLower()
        Add-To $sb "<tr id='$($a.Anchor)' class='sev-$sevC'><td><span class='badge $sevC'>$($a.Severity)</span></td><td><strong>$(Esc $a.Title)</strong><br><span class='detail'>$(Esc $a.Recommendation)</span></td><td class='compl'>$(Esc $a.CIS)</td><td class='compl'>$(Esc $a.GDPR)</td><td class='compl'>$(Esc $a.SOC2)</td><td class='compl'>$(Esc $a.HIPAA)</td><td class='compl'>$(Esc $a.PCI)</td></tr>"
    }
    Add-To $sb "</tbody></table>"
}
Add-To $sb "</section>"

# DB fleet rollup
Add-To $sb "<section class='section'><h2>4. Database-Level Findings (Fleet Rollup)</h2>"
if ($dbFindings.Length -eq 0) {
    Add-To $sb "<p class='ok'>No database-level findings detected.</p>"
} else {
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

# Top-N
Add-To $sb "<section class='section'><h2>5. Top-N Inventories</h2>"
Add-To $sb "<h3>5.1 Privileged accounts</h3>"
$smArr = @($sysadmins)
if ($smArr.Length -eq 0) {
    Add-To $sb "<p class='note'>Privileged-account list could not be extracted.</p>"
} else {
    Add-To $sb "<p>Total entries (sysadmin / equivalent): <strong>$($smArr.Length)</strong>. Sample shown.</p><ul>"
    foreach ($s in ($smArr | Select-Object -First 25)) { Add-To $sb "<li><span class='kbd'>$(Esc $s)</span></li>" }
    if ($smArr.Length -gt 25) { Add-To $sb "<li>... +$([int]($smArr.Length - 25)) more</li>" }
    Add-To $sb "</ul>"
}
Add-To $sb "<h3>5.2 Weak / trivial passwords</h3>"
if ($weakPwds.Length -eq 0) {
    Add-To $sb "<p class='ok'>No weak-password matches recorded.</p>"
} else {
    Add-To $sb "<table><thead><tr><th>Login</th><th>Detection rule</th></tr></thead><tbody>"
    foreach ($w in $weakPwds) { Add-To $sb "<tr><td><span class='kbd'>$(Esc $w.Login)</span></td><td class='detail'>$(Esc $w.Reason)</td></tr>" }
    Add-To $sb "</tbody></table>"
}
Add-To $sb "<h3>5.3 PII / sensitive columns</h3>"
$piiArr = $piiAll.ToArray()
if ($piiArr.Length -eq 0) {
    Add-To $sb "<p class='ok'>No PII column patterns matched (or sec_09 not run).</p>"
} else {
    $byDb = $piiArr | Group-Object Database | Sort-Object Count -Descending
    Add-To $sb "<p>Total matches: <strong>$($piiArr.Length)</strong> across <strong>$(@($byDb).Count)</strong> databases.</p>"
    Add-To $sb "<table><thead><tr><th>Database</th><th>PII columns</th></tr></thead><tbody>"
    foreach ($g in ($byDb | Select-Object -First 25)) {
        Add-To $sb "<tr><td>$(Esc $g.Name)</td><td><strong>$($g.Count)</strong></td></tr>"
    }
    Add-To $sb "</tbody></table><h4>Sample columns (first 30)</h4>"
    Add-To $sb "<table><thead><tr><th>Database</th><th>Schema</th><th>Table</th><th>Column</th><th>Reason</th></tr></thead><tbody>"
    foreach ($p in ($piiArr | Select-Object -First 30)) {
        Add-To $sb "<tr><td>$(Esc $p.Database)</td><td>$(Esc $p.Schema)</td><td>$(Esc $p.Table)</td><td><strong>$(Esc $p.Column)</strong></td><td class='detail'>$(Esc $p.Reason)</td></tr>"
    }
    Add-To $sb "</tbody></table>"
}
Add-To $sb "</section>"

# Compliance
Add-To $sb "<section class='section'><h2>6. Compliance Mapping</h2><p>Findings mapped to CIS Microsoft SQL Server Benchmark, GDPR Art.32, SOC2 Trust Services Criteria, HIPAA Security Rule, and PCI DSS v4.</p><table><thead><tr><th>Severity</th><th>Finding</th><th>CIS</th><th>GDPR</th><th>SOC2</th><th>HIPAA</th><th>PCI</th></tr></thead><tbody>"
foreach ($a in $aggregated) {
    if ($a.CIS -eq '-' -and $a.GDPR -eq '-' -and $a.SOC2 -eq '-' -and $a.HIPAA -eq '-' -and $a.PCI -eq '-') { continue }
    $sevC = $a.Severity.ToLower()
    Add-To $sb "<tr class='sev-$sevC'><td><span class='badge $sevC'>$($a.Severity)</span></td><td>$(Esc $a.Title)</td><td class='compl'>$(Esc $a.CIS)</td><td class='compl'>$(Esc $a.GDPR)</td><td class='compl'>$(Esc $a.SOC2)</td><td class='compl'>$(Esc $a.HIPAA)</td><td class='compl'>$(Esc $a.PCI)</td></tr>"
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

# Snippets
Add-To $sb "<section class='section'><h2>8. Remediation Snippets (T-SQL) and Further Reading</h2><p>Reference snippets. Replace placeholders before executing. Each entry links to vendor / standards documentation for the relevant control.</p>"
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
Add-To $sb "<section class='section appendix'><h2>9. Appendix A: Per-Database Findings</h2><p>Full findings per database for reference.</p>"
$reportSorted = @($report | Sort-Object @{Expression = { if ($_.Name -eq '_server') { 0 } else { 1 } } }, Name)
foreach ($r in $reportSorted) {
    if ($r.Findings.Length -eq 0) { continue }
    Add-To $sb "<h3>$(Esc $r.Name) <span class='tag'>$($r.Critical) crit</span><span class='tag'>$($r.Warning) warn</span><span class='tag'>$($r.Info) info</span></h3>"
    Add-To $sb "<table><thead><tr><th>Severity</th><th>Scope</th><th>Script</th><th>Finding</th></tr></thead><tbody>"
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
<dt>sysadmin</dt><dd>Fixed server role with unrestricted access to the SQL Server instance. Membership should be minimal and reviewed quarterly.</dd>
<dt>CHECK_POLICY / CHECK_EXPIRATION</dt><dd>Login-level flags that bind a SQL login to the host Windows password policy. Both should normally be ON.</dd>
<dt>xp_cmdshell</dt><dd>Extended stored procedure that executes shell commands via T-SQL. High-risk; disable unless explicitly required.</dd>
<dt>TDE (Transparent Data Encryption)</dt><dd>Encrypts the database files and backups at rest using a database encryption key protected by a server certificate.</dd>
<dt>Always Encrypted</dt><dd>Column-level encryption performed on the client. Even sysadmins cannot read protected values.</dd>
<dt>Dynamic Data Masking (DDM)</dt><dd>Visual masking of column values for non-privileged callers. Not real encryption -- complement, not substitute.</dd>
<dt>Server Audit / Audit Specification</dt><dd>SQL Server's structured auditing facility writing to a file/log target.</dd>
<dt>UNSAFE assembly</dt><dd>CLR assembly with elevated permissions; can call unmanaged code. Audit and prefer SAFE/EXTERNAL_ACCESS.</dd>
<dt>Linked server</dt><dd>Outbound connection to another database server, often with stored credentials. Audit credential strength and usage.</dd>
<dt>CIS Benchmark</dt><dd>Center for Internet Security baseline. Numbers reference the SQL Server Benchmark.</dd>
<dt>GDPR Art.32</dt><dd>EU 2016/679 'Security of processing' -- mandates appropriate technical measures (encryption, integrity, availability).</dd>
</dl>
</section>
</body></html>
'@

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
Write-Host "Security audit report generated."
Write-Host "  Databases analyzed   : $dbCount"
Write-Host "  Critical findings    : $totalCrit"
Write-Host "  Warning findings     : $totalWarn"
Write-Host "  Info findings        : $totalInfo"
Write-Host "  Failed scripts       : $totalFail"
Write-Host "  Server-wide findings : $($serverFindings.Length)"
Write-Host "  Database findings    : $($dbFindings.Length)"
Write-Host "  PII columns recorded : $($piiAll.Count)"
if ($NoPdf)       { Write-Host "  Report (HTML)        : $HtmlPath" }
elseif ($pdfMade) { Write-Host "  Report (PDF)         : $pdfPath"; if ($KeepHtml) { Write-Host "  Report (HTML)        : $HtmlPath" } }
else              { Write-Host "  Report (HTML only)   : $HtmlPath  (Edge headless not available)" }
Write-Host ("=" * 80)
