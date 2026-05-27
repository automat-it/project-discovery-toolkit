# =============================================================================
# Shared helpers for analyze_report.ps1 (perf + sec). Dot-sourced from each
# analyzer. Set-StrictMode -Off and System.Web type are intentionally pulled
# in here so callers don't have to repeat them.
#
# Performance-critical primitives live here too:
#   - Get-LogText / Get-LogLines / Get-LogResultSets cache the file contents
#     so a single per-DB log is read at most ONCE per analyzer run, even when
#     several rules need to inspect it.
#   - Get-FindingsFromRules pre-indexes the rule list by script suffix so a
#     log file is never compared against rules that can't possibly match.
#   - Add-To wraps StringBuilder appends so HTML construction is O(n) rather
#     than O(n^2) string concatenation.
# =============================================================================

Set-StrictMode -Off
Add-Type -AssemblyName System.Web

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
function Esc {
    param($s)
    [System.Web.HttpUtility]::HtmlEncode([string]$s)
}

function _Cnt {
    # PS5.1's @($genericList).Count can throw 'Argument types do not match' on
    # heterogeneous Add-Member'd objects. Native .Count is safe; iterate as a
    # last resort.
    param($x)
    if ($null -eq $x) { return 0 }
    try { if ($x.Count -is [int]) { return $x.Count } } catch {}
    $n = 0; foreach ($_ in $x) { $n++ }
    return $n
}

function Get-SeverityRank {
    param([string]$Severity)
    switch -Exact ($Severity) {
        'Critical' { 0; return }
        'Warning'  { 1; return }
        'Info'     { 2; return }
        default    { 3 }
    }
}

function New-Sb { [System.Text.StringBuilder]::new() }
function Add-To { param($Sb, [string]$S) [void]$Sb.Append($S) }

# Deterministic anchor id for cross-linking from the executive summary
# to the detailed finding row. Strips characters that aren't safe in
# an HTML id attribute and lowercases the result.
function New-Slug {
    param([string]$Text)
    if (-not $Text) { return 'f' }
    $s = ($Text -replace '[^A-Za-z0-9]+', '-').Trim('-').ToLowerInvariant()
    if (-not $s) { return 'f' }
    if ($s.Length -gt 80) { $s = $s.Substring(0, 80).TrimEnd('-') }
    return $s
}

# -----------------------------------------------------------------------------
# Encoding-aware log reader with per-run cache
#   $script:_LogCache[<FullPath>] = @{ Text=...; Lines=...; Sets=... }
# Sets is computed lazily only when Get-LogResultSets is called.
# -----------------------------------------------------------------------------
$script:_LogCache = @{}
function Clear-LogCache { $script:_LogCache.Clear() }

function Get-LogEncoding {
    param([string]$LogPath)
    if (-not (Test-Path $LogPath)) { return [System.Text.Encoding]::UTF8 }
    $head = New-Object byte[] 4
    $read = 0
    try {
        $stream = [System.IO.File]::OpenRead($LogPath)
        try { $read = $stream.Read($head, 0, 4) } finally { $stream.Dispose() }
    } catch { return [System.Text.Encoding]::UTF8 }
    if ($read -ge 2 -and $head[0] -eq 0xFF -and $head[1] -eq 0xFE) { return [System.Text.Encoding]::Unicode }
    if ($read -ge 2 -and $head[0] -eq 0xFE -and $head[1] -eq 0xFF) { return [System.Text.Encoding]::BigEndianUnicode }
    if ($read -ge 3 -and $head[0] -eq 0xEF -and $head[1] -eq 0xBB -and $head[2] -eq 0xBF) { return [System.Text.Encoding]::UTF8 }
    if ($read -ge 2 -and $head[0] -gt 0 -and $head[0] -lt 128 -and $head[1] -eq 0) { return [System.Text.Encoding]::Unicode }
    return [System.Text.Encoding]::UTF8
}

function Get-LogText {
    param([string]$LogPath)
    if (-not (Test-Path $LogPath)) { return '' }
    $key = $LogPath
    if ($script:_LogCache.ContainsKey($key)) {
        if ($null -ne $script:_LogCache[$key].Text) { return $script:_LogCache[$key].Text }
    } else { $script:_LogCache[$key] = @{ Text = $null; Lines = $null; Sets = $null } }
    $enc = Get-LogEncoding $LogPath
    $script:_LogCache[$key].Text = [System.IO.File]::ReadAllText($LogPath, $enc)
    return $script:_LogCache[$key].Text
}

function Get-LogLines {
    param([string]$LogPath)
    if (-not (Test-Path $LogPath)) { return @() }
    $key = $LogPath
    if (-not $script:_LogCache.ContainsKey($key)) { $script:_LogCache[$key] = @{ Text = $null; Lines = $null; Sets = $null } }
    if ($null -ne $script:_LogCache[$key].Lines) { return $script:_LogCache[$key].Lines }
    if ($null -eq $script:_LogCache[$key].Text) {
        # Read raw bytes once and split rather than read again.
        $enc = Get-LogEncoding $LogPath
        $script:_LogCache[$key].Text = [System.IO.File]::ReadAllText($LogPath, $enc)
    }
    $script:_LogCache[$key].Lines = $script:_LogCache[$key].Text -split "`r?`n"
    return $script:_LogCache[$key].Lines
}

# Back-compat alias for prior name.
Set-Alias -Name Read-LogText  -Value Get-LogText
Set-Alias -Name Read-LogLines -Value Get-LogLines

function Read-AuditSummary {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return @() }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($l in (Get-LogLines $Path)) {
        if ($l -match '^(OK|FAIL)\s+(\S+)') {
            [void]$rows.Add([pscustomobject]@{ Status = $matches[1]; Path = $matches[2] })
        }
    }
    return $rows.ToArray()
}

# -----------------------------------------------------------------------------
# Tabular sqlcmd output parser (cached per file).
# -----------------------------------------------------------------------------
function Get-LogResultSets {
    param([string]$LogPath)
    if (-not (Test-Path $LogPath)) { return @() }
    $key = $LogPath
    if (-not $script:_LogCache.ContainsKey($key)) { $script:_LogCache[$key] = @{ Text = $null; Lines = $null; Sets = $null } }
    if ($null -ne $script:_LogCache[$key].Sets) { return $script:_LogCache[$key].Sets }

    $lines = Get-LogLines $LogPath
    if (-not $lines) { $script:_LogCache[$key].Sets = @(); return @() }
    $sets = New-Object System.Collections.Generic.List[object]
    $i = 0
    while ($i -lt $lines.Length) {
        $line = [string]$lines[$i]
        if ($line -match '^[\s\-]+$' -and $line -match '\-{3,}') {
            $headerLine = if ($i -gt 0) { [string]$lines[$i-1] } else { '' }
            if (-not $headerLine.Trim()) { $i++; continue }
            $u = $line.TrimEnd(); $cols = New-Object System.Collections.Generic.List[object]; $col = $null
            for ($p = 0; $p -lt $u.Length; $p++) {
                $ch = $u[$p]
                if ($ch -eq '-') {
                    if ($null -eq $col) { $col = @{ Start = $p; End = $p } } else { $col.End = $p }
                } else {
                    if ($null -ne $col) { [void]$cols.Add(@{ Start = $col.Start; End = $col.End }); $col = $null }
                }
            }
            if ($null -ne $col) { [void]$cols.Add(@{ Start = $col.Start; End = $col.End }) }
            $names = New-Object System.Collections.Generic.List[string]
            foreach ($c in $cols) {
                $w = $c.End - $c.Start + 1
                if ($c.Start -ge $headerLine.Length) { [void]$names.Add("col$($names.Count + 1)"); continue }
                $end = [Math]::Min($headerLine.Length - 1, $c.Start + $w - 1)
                $raw = $headerLine.Substring($c.Start, $end - $c.Start + 1).Trim()
                if (-not $raw) { $raw = "col$($names.Count + 1)" }
                [void]$names.Add($raw)
            }
            $rows = New-Object System.Collections.Generic.List[object]
            $i++
            while ($i -lt $lines.Length) {
                $r = [string]$lines[$i]
                if ($r -match '^\s*\(\d+ rows? affected\)\s*$') { $i++; break }
                if ($r -match '^Msg\s+\d+,\s*Level')             { break }
                if ($r -match '^\s*$')                           { $i++; continue }
                if ($r -match '^\[note\]')                       { $i++; continue }
                if ($i + 1 -lt $lines.Length -and ([string]$lines[$i+1]) -match '^[\s\-]+$' -and ([string]$lines[$i+1]) -match '\-{3,}') { break }
                $obj = [ordered]@{}
                for ($k = 0; $k -lt $cols.Count; $k++) {
                    $c = $cols[$k]; $w = $c.End - $c.Start + 1
                    if ($c.Start -ge $r.Length) { $obj[$names[$k]] = ''; continue }
                    $end = [Math]::Min($r.Length - 1, $c.Start + $w - 1)
                    $obj[$names[$k]] = $r.Substring($c.Start, $end - $c.Start + 1).Trim()
                }
                [void]$rows.Add([pscustomobject]$obj)
                $i++
            }
            [void]$sets.Add([pscustomobject]@{ Columns = $names.ToArray(); Rows = $rows.ToArray() })
        } else { $i++ }
    }
    $script:_LogCache[$key].Sets = $sets.ToArray()
    return $script:_LogCache[$key].Sets
}

# Back-compat alias
Set-Alias -Name Get-SqlCmdResultSets -Value Get-LogResultSets

function Find-LogFile {
    param([string]$LogDir, [string]$ScriptSuffix)
    Get-ChildItem -LiteralPath $LogDir -Filter "*$ScriptSuffix*.log" -File -ErrorAction SilentlyContinue |
        Select-Object -First 1
}

# Look up a column value across the parsed result sets of a log file.
# Column names are matched case-insensitively after stripping spaces /
# underscores, so 'cpu_count', 'CPU Count', and 'cpucount' all match.
# Returns the first non-empty value found, or $null.
function Get-ColumnValue {
    param(
        [string]$LogPath,
        [string[]]$ColumnAliases,
        [int]$SetIndex = -1   # -1 = search all sets; otherwise restrict to one set
    )
    if (-not (Test-Path $LogPath)) { return $null }
    $sets = Get-LogResultSets $LogPath
    if (-not $sets -or $sets.Count -eq 0) { return $null }
    $aliasNorm = New-Object System.Collections.Generic.List[string]
    foreach ($a in $ColumnAliases) {
        $n = ($a -replace '[\s_]', '').ToLowerInvariant()
        if ($n) { [void]$aliasNorm.Add($n) }
    }
    $setStart = if ($SetIndex -ge 0) { $SetIndex } else { 0 }
    $setEnd   = if ($SetIndex -ge 0) { $SetIndex } else { $sets.Count - 1 }
    for ($si = $setStart; $si -le $setEnd; $si++) {
        if ($si -ge $sets.Count) { continue }
        $set = $sets[$si]
        if (-not $set.Columns) { continue }
        for ($ci = 0; $ci -lt $set.Columns.Length; $ci++) {
            $cnorm = ([string]$set.Columns[$ci] -replace '[\s_]', '').ToLowerInvariant()
            if ($aliasNorm.Contains($cnorm)) {
                foreach ($row in $set.Rows) {
                    $v = [string]$row.($set.Columns[$ci])
                    if ($v -and $v.Trim()) { return $v.Trim() }
                }
            }
        }
    }
    return $null
}

function Test-LogHasDataRows {
    param([string]$LogPath)
    foreach ($s in (Get-LogResultSets $LogPath)) { if ($s.Rows -and $s.Rows.Length -gt 0) { return $true } }
    return $false
}

# -----------------------------------------------------------------------------
# Apply rules to one log dir. The $Rules array is ALSO indexed by script
# suffix on first call so subsequent log files only check the rules that
# could match -- with 100+ DBs and 25 logs each, the prior O(rules x logs)
# per directory is replaced by O(matched rules per log).
# -----------------------------------------------------------------------------
function Get-FindingsFromRules {
    param(
        [string]$LogDir,
        [array]$Rules,
        [hashtable]$RuleIndexCache  # caller-supplied to share across DBs
    )

    if (-not $RuleIndexCache.ContainsKey('built')) {
        $idx = @{}
        foreach ($r in $Rules) {
            $key = $r.Script
            if (-not $idx.ContainsKey($key)) { $idx[$key] = New-Object System.Collections.Generic.List[object] }
            [void]$idx[$key].Add($r)
        }
        $RuleIndexCache['idx']   = $idx
        $RuleIndexCache['built'] = $true
    }
    $idx = $RuleIndexCache['idx']

    $list = New-Object System.Collections.Generic.List[object]

    # 1. Failed scripts -> Critical
    foreach ($e in (Read-AuditSummary (Join-Path $LogDir '_summary.txt'))) {
        if ($e.Status -ne 'FAIL') { continue }
        $logBase = ($e.Path -replace '/', '_') -replace '\.sql$', '.log'
        $logPath = Join-Path $LogDir $logBase
        $detail  = '(no log captured)'
        if (Test-Path $logPath) {
            if ((Get-Item -LiteralPath $logPath).Length -eq 0) {
                $detail = '(empty log -- runner produced no output, likely killed mid-run)'
            } else {
                $errs = (Get-LogLines $logPath |
                         Where-Object { $_ -match '^Msg\s+\d+|^Sqlcmd:|^\[note\]' } |
                         Select-Object -First 5) -join "`n"
                if ($errs) { $detail = $errs }
            }
        }
        [void]$list.Add([pscustomobject]@{
            _Rank = 0
            Severity = 'Critical'; Scope = 'Server'; Script = $e.Path
            Title = 'Script execution failed'; Detail = $detail
            Recommendation = 'Check connection privileges and review the log file.'
            Remediation = ''; CIS = '-'; GDPR = '-'; SOC2 = '-'; HIPAA = '-'; PCI = '-'
        })
    }

    # 2. Apply content rules. For each log file, iterate only matching rules
    # by script suffix (avoids the regex match on every (rule, log) pair).
    foreach ($log in (Get-ChildItem -LiteralPath $LogDir -Filter '*.log' -File -ErrorAction SilentlyContinue)) {
        $base = $log.BaseName
        $logFull = $log.FullName
        $textCached = $null
        foreach ($script in $idx.Keys) {
            if (-not $base.Contains($script)) { continue }
            foreach ($rule in $idx[$script]) {
                $hit = $false; $context = ''
                if ($rule.Pattern) {
                    if ($null -eq $textCached) { $textCached = Get-LogText $logFull }
                    if ($textCached -and ($textCached -match $rule.Pattern)) {
                        $hit = $true
                        $m = [string]$matches[0]
                        if ($m.Length -gt 200) { $m = $m.Substring(0,200) + '...' }
                        $context = $m
                    }
                } else {
                    if (Test-LogHasDataRows $logFull) {
                        $hit = $true
                        $context = '(data rows present in script output)'
                    }
                }
                if ($hit) {
                    [void]$list.Add([pscustomobject]@{
                        _Rank      = Get-SeverityRank $rule.Severity
                        Severity   = $rule.Severity
                        Scope      = $rule.Scope
                        Script     = $log.Name
                        Title      = $rule.Title
                        Detail     = if ($rule.Detail) { "$($rule.Detail) Context: $context" } else { "Context: $context" }
                        Recommendation = $rule.Recommendation
                        Remediation    = $rule.Remediation
                        Docs           = if ($rule.Docs) { $rule.Docs } else { @() }
                        CIS   = if ($rule.CIS)   { $rule.CIS }   else { '-' }
                        GDPR  = if ($rule.GDPR)  { $rule.GDPR }  else { '-' }
                        SOC2  = if ($rule.SOC2)  { $rule.SOC2 }  else { '-' }
                        HIPAA = if ($rule.HIPAA) { $rule.HIPAA } else { '-' }
                        PCI   = if ($rule.PCI)   { $rule.PCI }   else { '-' }
                    })
                }
            }
        }
    }
    return ,$list.ToArray()
}

# -----------------------------------------------------------------------------
# SVG charts (no external libs)
# -----------------------------------------------------------------------------
function New-SvgDonut {
    param([int]$Critical, [int]$Warning, [int]$Info)
    $total = $Critical + $Warning + $Info
    if ($total -le 0) { return "<p class='ok'>No findings recorded.</p>" }
    $rad = 80; $cx = 110; $cy = 110; $stroke = 30
    $vals = @(
        @{ Name = 'Critical'; N = $Critical; C = '#c0392b' },
        @{ Name = 'Warning';  N = $Warning;  C = '#e67e22' },
        @{ Name = 'Info';     N = $Info;     C = '#2980b9' }
    )
    $sb = New-Sb
    $offset = 0
    $inv = [Globalization.CultureInfo]::InvariantCulture
    foreach ($v in $vals) {
        if ($v.N -le 0) { continue }
        $angle = 360.0 * $v.N / $total
        $a1 = ($offset - 90) * [math]::PI / 180.0
        $a2 = ($offset + $angle - 90) * [math]::PI / 180.0
        $x1 = ($cx + $rad * [math]::Cos($a1)).ToString('0.##', $inv)
        $y1 = ($cy + $rad * [math]::Sin($a1)).ToString('0.##', $inv)
        $x2 = ($cx + $rad * [math]::Cos($a2)).ToString('0.##', $inv)
        $y2 = ($cy + $rad * [math]::Sin($a2)).ToString('0.##', $inv)
        $large = if ($angle -gt 180) { 1 } else { 0 }
        Add-To $sb "<path d='M $cx $cy L $x1 $y1 A $rad $rad 0 $large 1 $x2 $y2 Z' fill='$($v.C)'/>"
        $offset += $angle
    }
    Add-To $sb "<circle cx='$cx' cy='$cy' r='$([int]($rad - $stroke))' fill='white'/>"
    Add-To $sb "<text x='$cx' y='$($cy-3)' text-anchor='middle' font-size='22' font-weight='600' fill='#222'>$total</text>"
    Add-To $sb "<text x='$cx' y='$($cy+18)' text-anchor='middle' font-size='10' fill='#777'>findings</text>"
    Add-To $sb "<g font-family='Segoe UI,Arial' font-size='12'>"
    $ly = 30
    foreach ($v in $vals) {
        Add-To $sb "<rect x='240' y='$ly' width='14' height='14' fill='$($v.C)'/>"
        Add-To $sb "<text x='262' y='$($ly+12)' fill='#222'>$($v.Name): $($v.N)</text>"
        $ly += 22
    }
    Add-To $sb '</g>'
    return "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 380 220' width='380' height='220'>$($sb.ToString())</svg>"
}

function New-SvgBar {
    param([array]$Items, [string]$Color = '#1F497D')
    if (-not $Items -or $Items.Length -eq 0) { return '' }
    $maxN = 1
    foreach ($it in $Items) { if ($it.Value -gt $maxN) { $maxN = $it.Value } }
    $rowH = 22; $padTop = 10; $padLeft = 200; $width = 600
    $h = $padTop + $rowH * $Items.Length + 10
    $sb = New-Sb
    Add-To $sb "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 $width $h' width='$width' height='$h' font-family='Segoe UI,Arial' font-size='12'>"
    $y = $padTop
    foreach ($it in $Items) {
        $w = [int](($width - $padLeft - 50) * $it.Value / $maxN)
        Add-To $sb "<text x='$($padLeft - 8)' y='$($y + 14)' text-anchor='end' fill='#333'>$(Esc $it.Label)</text>"
        Add-To $sb "<rect x='$padLeft' y='$y' width='$w' height='16' fill='$Color'/>"
        Add-To $sb "<text x='$($padLeft + $w + 6)' y='$($y + 14)' fill='#333'>$($it.Value)</text>"
        $y += $rowH
    }
    Add-To $sb '</svg>'
    return $sb.ToString()
}

# -----------------------------------------------------------------------------
# PDF conversion (Chromium-based browsers + wkhtmltopdf + Word COM)
# -----------------------------------------------------------------------------
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
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    return $null
}

# Wait up to $TimeoutSeconds for the PDF file to appear AND its size
# to stabilise. Chromium with the legacy --headless flag occasionally
# returns from the parent process before the renderer has flushed the
# PDF to disk; an immediate Test-Path then misses it.
function _Wait-ForPdf {
    param([string]$Pdf, [int]$TimeoutSeconds = 15)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastSize = -1
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $Pdf) {
            $sz = (Get-Item -LiteralPath $Pdf).Length
            if ($sz -gt 0 -and $sz -eq $lastSize) { return $true }
            $lastSize = $sz
        }
        Start-Sleep -Milliseconds 250
    }
    return (Test-Path -LiteralPath $Pdf)
}

function Convert-HtmlToPdf {
    param([string]$Html, [string]$Pdf)
    $abs = (Resolve-Path -LiteralPath $Html).Path
    $uri = ([System.Uri]$abs).AbsoluteUri
    Write-Host 'PDF: trying conversion methods...'
    if (Test-Path -LiteralPath $Pdf) { Remove-Item -LiteralPath $Pdf -Force -ErrorAction SilentlyContinue }

    $browser = Get-ChromiumBrowser
    if ($browser) {
        Write-Host "PDF:   trying $browser"
        # Unique --user-data-dir so an already-running browser instance
        # cannot IPC-handle the --print-to-pdf request and detach the
        # launcher, plus -Wait via Start-Process so we synchronously
        # block until the renderer exits and the file is on disk.
        $tmpProfile = Join-Path $env:TEMP ("_audit_pdf_" + [guid]::NewGuid().ToString('N'))
        $errLog     = Join-Path $env:TEMP ("_audit_chr_" + [guid]::NewGuid().ToString('N') + '.log')
        $args = @(
            '--headless', '--disable-gpu', '--no-pdf-header-footer',
            '--no-first-run', '--no-default-browser-check', '--disable-extensions',
            "--user-data-dir=$tmpProfile",
            "--print-to-pdf=$Pdf",
            $uri
        )
        $prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try {
            # Redirect ONLY stderr so Start-Process does not refuse
            # 'identical paths' validation; chromium does not produce
            # interesting stdout in headless mode.
            Start-Process -FilePath $browser -ArgumentList $args `
                          -Wait -NoNewWindow `
                          -RedirectStandardError $errLog | Out-Null
        } catch {
            Write-Verbose "Chromium launch raised: $($_.Exception.Message)"
        } finally { $ErrorActionPreference = $prevEAP }

        $ok = _Wait-ForPdf -Pdf $Pdf -TimeoutSeconds 15
        Remove-Item -LiteralPath $tmpProfile -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $errLog -Force -ErrorAction SilentlyContinue
        if ($ok) { Write-Host "PDF: rendered via $(Split-Path -Leaf $browser)"; return $true }
    }

    $wk = Get-Command wkhtmltopdf -ErrorAction SilentlyContinue
    if (-not $wk) {
        $wkPath = "$env:ProgramFiles\wkhtmltopdf\bin\wkhtmltopdf.exe"
        if (Test-Path $wkPath) { $wk = Get-Item -LiteralPath $wkPath }
    }
    if ($wk) {
        Write-Host 'PDF:   trying wkhtmltopdf'
        $errLog = Join-Path $env:TEMP ("_audit_wk_" + [guid]::NewGuid().ToString('N') + '.log')
        $prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try {
            Start-Process -FilePath $wk.Path `
                          -ArgumentList @('--quiet','--enable-local-file-access',$abs,$Pdf) `
                          -Wait -NoNewWindow `
                          -RedirectStandardError $errLog | Out-Null
        } catch {} finally { $ErrorActionPreference = $prevEAP }
        Remove-Item -LiteralPath $errLog -Force -ErrorAction SilentlyContinue
        if (_Wait-ForPdf -Pdf $Pdf -TimeoutSeconds 10) { Write-Host 'PDF: rendered via wkhtmltopdf'; return $true }
    }

    try {
        Write-Host 'PDF:   trying Microsoft Word COM'
        $word = New-Object -ComObject Word.Application -ErrorAction Stop
        $word.Visible = $false; $word.DisplayAlerts = 0
        $doc = $word.Documents.Open($abs, $false, $true)
        $doc.SaveAs2($Pdf, 17)   # 17 = wdFormatPDF
        $doc.Close($false); $word.Quit()
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($word)
        if (Test-Path $Pdf) { Write-Host 'PDF: rendered via Microsoft Word'; return $true }
    } catch {}

    # Final defensive check -- if a renderer wrote the PDF asynchronously
    # while we were trying fallbacks, treat it as success.
    if (Test-Path -LiteralPath $Pdf) {
        Write-Host 'PDF: file present (rendered asynchronously)'
        return $true
    }

    Write-Warning "Could not render PDF (no Edge/Chrome/Chromium/Brave/wkhtmltopdf/Word found). HTML kept at $Html."
    return $false
}

# -----------------------------------------------------------------------------
# Asset copy + report-context discovery
# -----------------------------------------------------------------------------
function Copy-BrandAssets {
    param([string]$ScriptDir, [string]$HtmlDir)
    # Brand assets live at db-audit-scripts/assets/ (shared across all
    # engine analyzers). Walk up from the engine dir to find them.
    $assetsDir = Join-Path (Split-Path -Parent (Split-Path -Parent $ScriptDir)) 'assets'
    if (-not (Test-Path $assetsDir)) {
        # Fallback for the historical layout (db-audit-scripts/mssql/assets/)
        $assetsDir = Join-Path (Split-Path -Parent $ScriptDir) 'assets'
    }
    foreach ($asset in 'ait_bg_cover.png','ait_bg_page.png') {
        $src = Join-Path $assetsDir $asset
        $dst = Join-Path $HtmlDir   $asset
        if (Test-Path $src) { Copy-Item -LiteralPath $src -Destination $dst -Force }
    }
}

function Get-ReportContexts {
    param([string]$Root, [string]$RunFolderFilter)
    $contexts = New-Object System.Collections.Generic.List[object]
    foreach ($d in (Get-ChildItem -LiteralPath $Root -Directory | Sort-Object Name)) {
        $run = Get-ChildItem -LiteralPath $d.FullName -Directory -Filter $RunFolderFilter -ErrorAction SilentlyContinue |
               Sort-Object Name -Descending | Select-Object -First 1
        if ($run) { [void]$contexts.Add([pscustomobject]@{ Name = $d.Name; LogDir = $run.FullName }) }
    }
    if ($contexts.Count -gt 0) { return ,$contexts.ToArray() }
    if (Test-Path (Join-Path $Root '_summary.txt')) {
        return ,@([pscustomobject]@{ Name = '(single run)'; LogDir = $Root })
    }
    return ,@()
}
