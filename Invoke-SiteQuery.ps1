#requires -Version 5.1
<#
.SYNOPSIS
    Ask an LLM about a specific site by bundling its documentation directory.

.DESCRIPTION
    Walks a per-site subdirectory of architectural / network documentation,
    bundles every text file's contents and a listing of every binary file,
    then ships the bundle plus your question to an OpenAI-compatible
    chat-completions endpoint and prints the answer.

    Native PowerShell only -- no external modules required. Works on
    Windows PowerShell 5.1 and PowerShell 7+.

    Layout assumed:
        <script-folder>\Invoke-SiteQuery.ps1
        <script-folder>\AAAA\... files describing site AAAA ...
        <script-folder>\ZZZZ\... files describing site ZZZZ ...

.PARAMETER Question
    The question to ask. If not given, you will be prompted.

.PARAMETER Site
    Explicit site code. If omitted, the script tries to find a token in
    your question that matches one of the subdirectory names.

.PARAMETER BaseDir
    Directory containing the per-site subdirectories. Defaults to the
    script's own directory.

.PARAMETER MaxBundleBytes
    Hard cap on the total bundle size sent to the LLM. Default 1MB.

.PARAMETER MaxFileBytes
    Per-file cap; files larger than this are listed but not embedded.
    Default 200KB.

.PARAMETER List
    List all available site codes and exit.

.PARAMETER NoLLM
    Bundle the files and print to the terminal; skip the API call. Useful
    when the host running this script cannot reach the API.

.EXAMPLE
    PS> .\Invoke-SiteQuery.ps1 "what does AAAA have"

.EXAMPLE
    PS> .\Invoke-SiteQuery.ps1 -Site AAAA "where is the fiber demarc?"

.EXAMPLE
    PS> .\Invoke-SiteQuery.ps1 -List
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Question,

    [string]$Site,

    [string]$BaseDir,

    [int]$MaxBundleBytes = 1MB,
    [int]$MaxFileBytes   = 200KB,

    [switch]$List,
    [switch]$NoLLM
)

$ErrorActionPreference = 'Stop'

# --- LLM configuration ----------------------------------------------------
$LLMEndpoint = 'https://xyz.xyz.xyz/v1/chat/completions'
$LLMModel    = 'gemini-2.5-flash'
$SystemPrompt = @'
You are an AI assistant answering questions about a specific site
(building, data center, or remote location). The user has provided
you with that site's documentation as a directory tree plus the
contents of all readable text files. Cite specific filenames when
referencing facts. If a detail would only live in a non-text file
(PDF, image, CAD, or Office document), say so explicitly and
recommend the operator open that file directly.
'@.Trim()

# Force TLS 1.2+ on Windows PowerShell 5.1 for HTTPS to modern endpoints.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# Default base dir = wherever this script lives.
if (-not $BaseDir) {
    $root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $BaseDir = $root
}
$BaseDir = (Resolve-Path -LiteralPath $BaseDir).ProviderPath

# --- File classification --------------------------------------------------

# Extensions we always bundle as text.
$Script:TextExt = @(
    '.txt', '.md', '.markdown',
    '.csv', '.tsv',
    '.json', '.yaml', '.yml', '.toml', '.ini', '.conf', '.cfg',
    '.xml', '.html', '.htm',
    '.log',
    '.ps1', '.psm1', '.psd1',
    '.py', '.sh', '.bat', '.cmd',
    '.run'
)
# Extensions we never try to read as text.
$Script:BinExt = @(
    '.pdf',
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.ico', '.svg', '.webp',
    '.vsd', '.vsdx', '.dwg', '.dxf', '.rvt', '.skp',
    '.zip', '.tar', '.gz', '.7z', '.rar',
    '.exe', '.dll', '.bin', '.iso', '.msi',
    '.mp3', '.mp4', '.mov', '.wav', '.avi'
)

# --- Helpers --------------------------------------------------------------

function Format-Size {
    param([long]$Bytes)
    if ($Bytes -lt 1KB) { return "$Bytes B" }
    if ($Bytes -lt 1MB) { return ('{0:N1} KB' -f ($Bytes / 1KB)) }
    if ($Bytes -lt 1GB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    return ('{0:N1} GB' -f ($Bytes / 1GB))
}

function Test-IsTextFile {
    param([System.IO.FileInfo]$File)

    $ext = $File.Extension.ToLowerInvariant()
    if ($ext -and ($Script:BinExt  -contains $ext)) { return $false }
    if ($ext -and ($Script:TextExt -contains $ext)) { return $true  }

    # Unknown extension: peek the first 8 KB and treat as binary if any
    # null byte appears (heuristic but accurate for almost all cases).
    if ($File.Length -gt $MaxFileBytes) { return $false }
    try {
        $stream = [System.IO.File]::OpenRead($File.FullName)
        $buf = New-Object byte[] 8192
        $n = $stream.Read($buf, 0, $buf.Length)
        $stream.Close()
        for ($i = 0; $i -lt $n; $i++) {
            if ($buf[$i] -eq 0) { return $false }
        }
        return $true
    } catch {
        return $false
    }
}

function Get-SiteCodes {
    param([string]$BaseDir)
    Get-ChildItem -LiteralPath $BaseDir -Directory |
        Where-Object { -not $_.Name.StartsWith('.') } |
        Where-Object { $_.Name -ne '__pycache__' -and $_.Name -ne 'node_modules' } |
        Sort-Object Name |
        Select-Object -ExpandProperty Name
}

function Resolve-SiteFromQuestion {
    param(
        [string]$Question,
        [string[]]$AvailableCodes
    )
    if (-not $Question) { return @() }
    $codeSet = @{}
    foreach ($c in $AvailableCodes) { $codeSet[$c.ToLowerInvariant()] = $c }

    $found = New-Object System.Collections.Generic.HashSet[string]
    foreach ($tok in ($Question -split '[^A-Za-z0-9_-]+')) {
        if (-not $tok) { continue }
        $key = $tok.ToLowerInvariant()
        if ($codeSet.ContainsKey($key)) { [void]$found.Add($codeSet[$key]) }
    }
    return @($found)
}

function New-FileBundle {
    param(
        [string]$SiteDir,
        [int]$MaxBundleBytes,
        [int]$MaxFileBytes
    )

    $sb = [System.Text.StringBuilder]::new()
    $bytesUsed = 0
    $rel = (Resolve-Path -LiteralPath $SiteDir).ProviderPath

    # 1) Directory tree.
    [void]$sb.AppendLine('Directory tree:')
    Get-ChildItem -LiteralPath $SiteDir -Recurse -Force |
        Sort-Object FullName |
        ForEach-Object {
            $r = $_.FullName.Substring($rel.Length).TrimStart('\','/')
            if ($_.PSIsContainer) {
                [void]$sb.AppendLine("  [DIR]      $r/")
            } else {
                $sz = (Format-Size $_.Length).PadLeft(9)
                [void]$sb.AppendLine("  $sz  $r")
            }
        }
    [void]$sb.AppendLine()

    # 2) Classify and emit text content; collect binaries for a tail listing.
    $textFiles   = New-Object System.Collections.ArrayList
    $binaryFiles = New-Object System.Collections.ArrayList
    Get-ChildItem -LiteralPath $SiteDir -Recurse -File -Force |
        Sort-Object FullName |
        ForEach-Object {
            if (Test-IsTextFile -File $_) { [void]$textFiles.Add($_) }
            else                          { [void]$binaryFiles.Add($_) }
        }

    foreach ($f in $textFiles) {
        $r = $f.FullName.Substring($rel.Length).TrimStart('\','/')
        if ($f.Length -gt $MaxFileBytes) {
            [void]$sb.AppendLine("--- $r (skipped: $(Format-Size $f.Length) > MaxFileBytes) ---")
            [void]$sb.AppendLine()
            continue
        }
        if (($bytesUsed + $f.Length) -gt $MaxBundleBytes) {
            [void]$sb.AppendLine("--- $r (skipped: total bundle full) ---")
            [void]$sb.AppendLine()
            continue
        }
        try {
            $content = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8
        } catch {
            [void]$sb.AppendLine("--- $r (read error: $_) ---")
            [void]$sb.AppendLine()
            continue
        }
        [void]$sb.AppendLine("--- $r ---")
        [void]$sb.AppendLine($content)
        [void]$sb.AppendLine()
        $bytesUsed += [Text.Encoding]::UTF8.GetByteCount($content)
    }

    if ($binaryFiles.Count -gt 0) {
        [void]$sb.AppendLine('--- Binary / non-text files in this site (filenames only) ---')
        foreach ($b in $binaryFiles) {
            $r = $b.FullName.Substring($rel.Length).TrimStart('\','/')
            [void]$sb.AppendLine("  $r  ($(Format-Size $b.Length))")
        }
    }

    return $sb.ToString()
}

function Read-ApiKey {
    $sec = Read-Host -Prompt 'LLM API key' -AsSecureString
    if (-not $sec -or $sec.Length -eq 0) { return $null }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try   { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Invoke-LLM {
    param(
        [string]$ApiKey,
        [string]$UserMessage
    )
    $body = @{
        model    = $LLMModel
        messages = @(
            @{ role = 'system'; content = $SystemPrompt }
            @{ role = 'user';   content = $UserMessage }
        )
    } | ConvertTo-Json -Depth 10 -Compress

    $headers = @{
        Authorization = "Bearer $ApiKey"
        Accept        = 'application/json'
    }

    $resp = Invoke-RestMethod -Method Post `
        -Uri $LLMEndpoint `
        -Headers $headers `
        -ContentType 'application/json' `
        -Body $body `
        -TimeoutSec 240

    return $resp.choices[0].message.content
}

# --- Main -----------------------------------------------------------------

if (-not (Test-Path -LiteralPath $BaseDir)) {
    Write-Error "BaseDir not found: $BaseDir"
    exit 1
}

$codes = @(Get-SiteCodes -BaseDir $BaseDir)
if ($codes.Count -eq 0) {
    Write-Error "No site subdirectories found under: $BaseDir"
    exit 1
}

if ($List) {
    Write-Host "Available site codes under ${BaseDir}:"
    $codes | ForEach-Object { Write-Host "  $_" }
    return
}

# Assemble the question text.
$qtext = if ($Question -and $Question.Count -gt 0) {
    ($Question -join ' ').Trim()
} else {
    Read-Host -Prompt 'Question'
}
if (-not $qtext) {
    Write-Error 'No question provided.'
    exit 1
}

# Resolve site code: explicit -Site wins, else parse from question.
$resolvedSite = $null
if ($Site) {
    $match = $codes | Where-Object { $_ -ieq $Site } | Select-Object -First 1
    if (-not $match) {
        Write-Error "Site '$Site' not found. Available: $($codes -join ', ')"
        exit 1
    }
    $resolvedSite = $match
} else {
    $hits = @(Resolve-SiteFromQuestion -Question $qtext -AvailableCodes $codes)
    if ($hits.Count -eq 0) {
        Write-Error ("Could not find a site code in your question. " +
                     "Use -Site <CODE>. Available: $($codes -join ', ')")
        exit 1
    }
    if ($hits.Count -gt 1) {
        Write-Error "Multiple site codes matched: $($hits -join ', '). Use -Site to disambiguate."
        exit 1
    }
    $resolvedSite = $hits[0]
}

$siteDir = Join-Path $BaseDir $resolvedSite
Write-Verbose "Bundling site '$resolvedSite' from $siteDir"

$bundle = New-FileBundle `
    -SiteDir        $siteDir `
    -MaxBundleBytes $MaxBundleBytes `
    -MaxFileBytes   $MaxFileBytes

$payload = @"
Site: $resolvedSite
Question: $qtext

$bundle
"@

if ($NoLLM) {
    Write-Host ''
    Write-Host ('#' * 78)
    Write-Host '# LLM call skipped. Bundle below -- copy from terminal or save to a file.'
    Write-Host ('#' * 78)
    Write-Host ''
    Write-Output $payload
    return
}

$apiKey = Read-ApiKey
if (-not $apiKey) {
    Write-Error 'No API key supplied'
    exit 1
}

Write-Host ("Sending {0:N0} chars to {1} ({2}) ..." -f $payload.Length, $LLMEndpoint, $LLMModel)
try {
    $answer = Invoke-LLM -ApiKey $apiKey -UserMessage $payload
} catch {
    Write-Warning "LLM call failed: $_"
    Write-Host ''
    Write-Host ('#' * 78)
    Write-Host '# Bundle below so you can send it from a host that can reach the API:'
    Write-Host ('#' * 78)
    Write-Output $payload
    exit 4
}

Write-Output $answer
