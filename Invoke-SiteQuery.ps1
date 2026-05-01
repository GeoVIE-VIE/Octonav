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
    Explicit site code(s). Accepts a single value, a comma-separated
    list, or the parameter repeated. If omitted, the script tokenises
    your question and uses every token that matches a subdirectory
    name -- so 'compare AAAA and BBBB' will pull both bundles.

.PARAMETER BaseDir
    Directory containing the per-site subdirectories. Defaults to the
    script's own directory.

.PARAMETER MaxBundleBytes
    Hard cap on the total bundle size sent to the LLM. Default 1MB.

.PARAMETER MaxFileBytes
    Per-file cap; files larger than this are listed but not embedded.
    Default 200KB.

.PARAMETER NoPdfs
    By default every .pdf in the site directory is attached as a
    multimodal content part (base64 data URI, MIME application/pdf)
    so the LLM can read it natively. Pass -NoPdfs if your gateway
    rejects multimodal content -- PDFs will then be listed by
    filename only.

.PARAMETER MaxPdfBytes
    Per-PDF size cap (default 8MB). Larger PDFs are listed but not
    attached.

.PARAMETER MaxAllPdfsBytes
    Total cap on all attached PDFs combined (default 32MB). Once this
    is hit, remaining PDFs are listed but not attached.

.PARAMETER List
    List all available site codes and exit.

.PARAMETER NoLLM
    Bundle the files and print to the terminal; skip the API call. Useful
    when the host running this script cannot reach the API.

.NOTES
    XLSX / XLSM workbooks are extracted to text natively (XLSX is a ZIP
    of XML, so System.IO.Compression handles it). Each sheet is emitted
    as CSV-style rows under a '## Sheet: <name>' header.

.EXAMPLE
    PS> .\Invoke-SiteQuery.ps1 "what does AAAA have"

.EXAMPLE
    PS> .\Invoke-SiteQuery.ps1 -Site AAAA "where is the fiber demarc?"

.EXAMPLE
    PS> .\Invoke-SiteQuery.ps1 "compare AAAA and BBBB IDF counts"

.EXAMPLE
    PS> .\Invoke-SiteQuery.ps1 -Site AAAA,BBBB,CCCC "which sites have a UPS in the MDF?"

.EXAMPLE
    PS> .\Invoke-SiteQuery.ps1 -List
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Question,

    [string[]]$Site,

    [string]$BaseDir,

    [int]$MaxBundleBytes  = 1MB,
    [int]$MaxFileBytes    = 200KB,
    [int]$MaxPdfBytes     = 8MB,
    [int]$MaxAllPdfsBytes = 32MB,

    [switch]$NoPdfs,
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
you with that site's documentation: a directory tree, the contents
of every readable text file (TXT, CSV, MD, JSON, etc.), the
extracted text contents of every Excel workbook (XLSX/XLSM, one
section per sheet), and -- when present -- every PDF attached as a
multimodal document. Cite specific filenames when referencing facts.
If a detail would only live in a non-text non-PDF file (image, CAD,
Visio, Word, ...), say so explicitly and recommend the operator open
that file directly.
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
# Extensions we extract to text natively (XLSX/XLSM = ZIP of XML).
$Script:OfficeExt = @('.xlsx', '.xlsm')
# Extensions handled separately as multimodal PDF attachments.
$Script:PdfExt = @('.pdf')
# Extensions we never try to read as text.
$Script:BinExt = @(
    '.doc', '.docx', '.xls', '.ppt', '.pptx',
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

function Get-FileKind {
    param([System.IO.FileInfo]$File)

    $ext = $File.Extension.ToLowerInvariant()
    if ($ext -and ($Script:PdfExt    -contains $ext)) { return 'pdf'    }
    if ($ext -and ($Script:OfficeExt -contains $ext)) { return 'office' }
    if ($ext -and ($Script:BinExt    -contains $ext)) { return 'binary' }
    if ($ext -and ($Script:TextExt   -contains $ext)) { return 'text'   }

    # Unknown extension: peek the first 8 KB. If any null byte appears
    # the file is almost certainly binary; otherwise treat as text.
    if ($File.Length -gt $MaxFileBytes) { return 'binary' }
    try {
        $stream = [System.IO.File]::OpenRead($File.FullName)
        $buf = New-Object byte[] 8192
        $n = $stream.Read($buf, 0, $buf.Length)
        $stream.Close()
        for ($i = 0; $i -lt $n; $i++) {
            if ($buf[$i] -eq 0) { return 'binary' }
        }
        return 'text'
    } catch {
        return 'binary'
    }
}

function Get-XlsxText {
    <#
    Extract text from an XLSX/XLSM workbook using only .NET BCL
    (System.IO.Compression). Each sheet is rendered as a section
    of CSV-style rows. Strings come from xl/sharedStrings.xml; cells
    that reference shared-string indices, inline strings, and direct
    numeric values are all handled.
    #>
    param(
        [string]$Path,
        [int]$MaxRowsPerSheet = 5000
    )

    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $ns = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        # --- shared strings table ---
        $shared = New-Object System.Collections.Generic.List[string]
        $sst = $zip.Entries | Where-Object { $_.FullName -eq 'xl/sharedStrings.xml' } | Select-Object -First 1
        if ($sst) {
            $stream = $sst.Open()
            try {
                $rdr = New-Object System.IO.StreamReader($stream)
                $sstXml = New-Object System.Xml.XmlDocument
                $sstXml.LoadXml($rdr.ReadToEnd())
            } finally {
                $stream.Dispose()
            }
            $sstNs = New-Object System.Xml.XmlNamespaceManager($sstXml.NameTable)
            $sstNs.AddNamespace('s', $ns)
            foreach ($si in $sstXml.SelectNodes('//s:si', $sstNs)) {
                # <si> contains either a single <t>...</t> or a sequence of
                # rich-text runs <r><t>...</t></r>; concatenate all <t>.
                $tnodes = $si.SelectNodes('.//s:t', $sstNs)
                $val = ''
                foreach ($t in $tnodes) { $val += $t.InnerText }
                [void]$shared.Add($val)
            }
        }

        # --- sheet name map (rId -> human name), best-effort ---
        $sheetNames = @{}
        $wbEntry = $zip.Entries | Where-Object { $_.FullName -eq 'xl/workbook.xml' } | Select-Object -First 1
        if ($wbEntry) {
            $s = $wbEntry.Open()
            try {
                $rdr = New-Object System.IO.StreamReader($s)
                $wbXml = New-Object System.Xml.XmlDocument
                $wbXml.LoadXml($rdr.ReadToEnd())
            } finally { $s.Dispose() }
            $wbNs = New-Object System.Xml.XmlNamespaceManager($wbXml.NameTable)
            $wbNs.AddNamespace('s', $ns)
            $idx = 1
            foreach ($sh in $wbXml.SelectNodes('//s:sheets/s:sheet', $wbNs)) {
                $sheetNames["sheet$idx"] = $sh.GetAttribute('name')
                $idx++
            }
        }

        # --- emit each sheet ---
        $sb = [System.Text.StringBuilder]::new()
        $sheetEntries = $zip.Entries |
            Where-Object { $_.FullName -match '^xl/worksheets/sheet(\d+)\.xml$' } |
            Sort-Object { [int]([regex]::Match($_.FullName, 'sheet(\d+)\.xml').Groups[1].Value) }

        foreach ($sheet in $sheetEntries) {
            $key = [System.IO.Path]::GetFileNameWithoutExtension($sheet.FullName)
            $name = if ($sheetNames.ContainsKey($key)) { $sheetNames[$key] } else { $key }
            [void]$sb.AppendLine("## Sheet: $name")

            $stream = $sheet.Open()
            try {
                $rdr = New-Object System.IO.StreamReader($stream)
                $shXml = New-Object System.Xml.XmlDocument
                $shXml.LoadXml($rdr.ReadToEnd())
            } finally {
                $stream.Dispose()
            }
            $shNs = New-Object System.Xml.XmlNamespaceManager($shXml.NameTable)
            $shNs.AddNamespace('s', $ns)

            $rowCount = 0
            foreach ($row in $shXml.SelectNodes('//s:sheetData/s:row', $shNs)) {
                if ($rowCount -ge $MaxRowsPerSheet) {
                    [void]$sb.AppendLine("... (truncated at $MaxRowsPerSheet rows)")
                    break
                }
                $cells = New-Object System.Collections.Generic.List[string]
                foreach ($c in $row.SelectNodes('s:c', $shNs)) {
                    $t = $c.GetAttribute('t')
                    $v = ''
                    if ($t -eq 's') {
                        $vNode = $c.SelectSingleNode('s:v', $shNs)
                        if ($vNode) {
                            $idx = 0
                            if ([int]::TryParse($vNode.InnerText, [ref]$idx) -and
                                $idx -ge 0 -and $idx -lt $shared.Count) {
                                $v = $shared[$idx]
                            }
                        }
                    } elseif ($t -eq 'inlineStr') {
                        $tNode = $c.SelectSingleNode('s:is/s:t', $shNs)
                        if ($tNode) { $v = $tNode.InnerText }
                    } elseif ($t -eq 'str') {
                        $vNode = $c.SelectSingleNode('s:v', $shNs)
                        if ($vNode) { $v = $vNode.InnerText }
                    } else {
                        $vNode = $c.SelectSingleNode('s:v', $shNs)
                        if ($vNode) { $v = $vNode.InnerText }
                    }
                    # CSV-quote if the value contains separators or quotes.
                    if ($v -match '[,"\r\n]') {
                        $v = '"' + ($v -replace '"', '""') + '"'
                    }
                    $cells.Add($v) | Out-Null
                }
                [void]$sb.AppendLine(($cells -join ','))
                $rowCount++
            }
            [void]$sb.AppendLine()
        }
        return $sb.ToString()
    } finally {
        $zip.Dispose()
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
    <#
    Walks $SiteDir. Returns a hashtable:
        BundleText    -- all text-form content (TXT/CSV/MD/JSON/etc. plus
                         extracted XLSX text) and a tail listing of
                         non-text non-pdf binaries.
        PdfsToAttach  -- FileInfo[] for every PDF the caller should ship
                         as a multimodal part. Per-PDF cap is applied
                         here; the total / per-request cap is applied
                         later by the batch packer in Send-WithBatching.
    #>
    param(
        [string]$SiteDir,
        [int]$MaxBundleBytes,
        [int]$MaxFileBytes,
        [int]$MaxPdfBytes,
        [bool]$NoPdfs
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

    # 2) Classify all files into buckets.
    $textFiles   = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    $officeFiles = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    $pdfFiles    = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    $binaryFiles = New-Object System.Collections.Generic.List[System.IO.FileInfo]

    Get-ChildItem -LiteralPath $SiteDir -Recurse -File -Force |
        Sort-Object FullName |
        ForEach-Object {
            # Capture the FileInfo before entering the switch -- PowerShell's
            # switch statement rebinds $_ inside each case to the matched
            # value, so '$_' inside the case blocks would otherwise be the
            # string 'text'/'office'/etc. instead of the FileInfo.
            $fileInfo = $_
            switch (Get-FileKind -File $fileInfo) {
                'text'   { $textFiles.Add($fileInfo)   | Out-Null }
                'office' { $officeFiles.Add($fileInfo) | Out-Null }
                'pdf'    { $pdfFiles.Add($fileInfo)    | Out-Null }
                default  { $binaryFiles.Add($fileInfo) | Out-Null }
            }
        }

    # 3) Embed text files.
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

    # 4) Extract and embed XLSX/XLSM contents.
    foreach ($f in $officeFiles) {
        $r = $f.FullName.Substring($rel.Length).TrimStart('\','/')
        if ($f.Length -gt (10 * 1MB)) {
            [void]$sb.AppendLine("--- $r (skipped: workbook size $(Format-Size $f.Length) too large) ---")
            [void]$sb.AppendLine()
            continue
        }
        try {
            $extracted = Get-XlsxText -Path $f.FullName
        } catch {
            [void]$sb.AppendLine("--- $r (XLSX extract error: $_) ---")
            [void]$sb.AppendLine()
            continue
        }
        $extractedBytes = [Text.Encoding]::UTF8.GetByteCount($extracted)
        if (($bytesUsed + $extractedBytes) -gt $MaxBundleBytes) {
            [void]$sb.AppendLine("--- $r (skipped: extracted $(Format-Size $extractedBytes) would exceed bundle cap) ---")
            [void]$sb.AppendLine()
            continue
        }
        [void]$sb.AppendLine("--- $r (Excel, extracted) ---")
        [void]$sb.AppendLine($extracted)
        $bytesUsed += $extractedBytes
    }

    # 5) Collect every eligible PDF. The total size cap is no longer
    #    applied here -- chunking happens in Send-WithBatching, which
    #    splits the PDFs into batches each under MaxAllPdfsBytes and
    #    runs a map-reduce across batches when needed. Per-PDF cap
    #    (MaxPdfBytes) still applies because a single PDF that exceeds
    #    a single-request budget cannot be sent at all.
    $attached = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    if (-not $NoPdfs -and $pdfFiles.Count -gt 0) {
        [void]$sb.AppendLine('--- PDFs to attach (will be split into batches if total exceeds per-request cap) ---')
        foreach ($p in $pdfFiles) {
            $r = $p.FullName.Substring($rel.Length).TrimStart('\','/')
            if ($p.Length -gt $MaxPdfBytes) {
                [void]$sb.AppendLine("  [skipped, single PDF too large]  $r  ($(Format-Size $p.Length) > MaxPdfBytes)")
                continue
            }
            [void]$sb.AppendLine("  [attached]                       $r  ($(Format-Size $p.Length))")
            $attached.Add($p) | Out-Null
        }
        [void]$sb.AppendLine()
    } elseif ($pdfFiles.Count -gt 0) {
        [void]$sb.AppendLine('--- PDFs in this site (filenames only; -NoPdfs is set) ---')
        foreach ($p in $pdfFiles) {
            $r = $p.FullName.Substring($rel.Length).TrimStart('\','/')
            [void]$sb.AppendLine("  $r  ($(Format-Size $p.Length))")
        }
        [void]$sb.AppendLine()
    }

    # 6) Other binaries (images, CAD, Word/PPT, Visio, archives, ...).
    if ($binaryFiles.Count -gt 0) {
        [void]$sb.AppendLine('--- Other binary / non-extractable files (filenames only) ---')
        foreach ($b in $binaryFiles) {
            $r = $b.FullName.Substring($rel.Length).TrimStart('\','/')
            [void]$sb.AppendLine("  $r  ($(Format-Size $b.Length))")
        }
    }

    return @{
        BundleText   = $sb.ToString()
        PdfsToAttach = $attached.ToArray()
    }
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
        [object]$UserContent   # string OR array of content parts
    )
    $body = @{
        model    = $LLMModel
        messages = @(
            @{ role = 'system'; content = $SystemPrompt }
            @{ role = 'user';   content = $UserContent }
        )
    } | ConvertTo-Json -Depth 20 -Compress

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

function Invoke-LLMWithMessages {
    <#
    Send a full message array (system + zero or more user/assistant
    turns) and return the assistant's reply. Used by the REPL loop so
    follow-up questions retain conversation history without re-sending
    the file bundle on every turn.
    #>
    param(
        [string]$ApiKey,
        [object[]]$Messages
    )
    $body = @{
        model    = $LLMModel
        messages = $Messages
    } | ConvertTo-Json -Depth 20 -Compress

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

function New-PdfContentPart {
    <#
    Read a PDF file and return an OpenAI-style multimodal content part
    that base64-embeds it as a 'data:application/pdf' URL. Gemini and
    several OpenAI-compatible gateways accept this shape; gateways that
    do not should be invoked with -NoPdfs.
    #>
    param(
        [System.IO.FileInfo]$File
    )
    $bytes = [System.IO.File]::ReadAllBytes($File.FullName)
    $b64 = [Convert]::ToBase64String($bytes)
    return @{
        type      = 'image_url'
        image_url = @{ url = "data:application/pdf;base64,$b64" }
    }
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

# Resolve site codes: explicit -Site wins, else parse from question.
# Multiple sites are allowed and bundled together.
$resolvedSites = New-Object System.Collections.Generic.List[string]
if ($Site -and $Site.Count -gt 0) {
    foreach ($s in $Site) {
        if (-not $s -or -not $s.Trim()) { continue }
        # Allow comma-separated values inside a single -Site argument too.
        foreach ($piece in ($s -split ',')) {
            $piece = $piece.Trim()
            if (-not $piece) { continue }
            $match = $codes | Where-Object { $_ -ieq $piece } | Select-Object -First 1
            if (-not $match) {
                Write-Error "Site '$piece' not found. Available: $($codes -join ', ')"
                exit 1
            }
            if (-not $resolvedSites.Contains($match)) {
                [void]$resolvedSites.Add($match)
            }
        }
    }
} else {
    $hits = @(Resolve-SiteFromQuestion -Question $qtext -AvailableCodes $codes)
    if ($hits.Count -eq 0) {
        Write-Error ("Could not find a site code in your question. " +
                     "Use -Site <CODE>[,<CODE>...]. Available: $($codes -join ', ')")
        exit 1
    }
    foreach ($h in $hits) { [void]$resolvedSites.Add($h) }
}
$resolvedSites = @($resolvedSites)

function Build-SiteContext {
    <#
    Bundle one OR MORE site directories. Returns:
      BundleText  -- text-only payload with per-site banners and the
                     question prefix. Goes into every request, with or
                     without PDFs.
      PdfList     -- @{File; Label} for every PDF to ship.
      PdfCount    -- convenience.
    Chunking into batches happens later in Send-WithBatching using
    MaxAllPdfsBytes as the per-request cap.
    #>
    param(
        [string[]]$SiteCodes,
        [string]$BaseDir,
        [string]$Question,
        [int]$MaxBundleBytes,
        [int]$MaxFileBytes,
        [int]$MaxPdfBytes,
        [bool]$NoPdfs
    )

    $allText = [System.Text.StringBuilder]::new()
    [void]$allText.AppendLine("Sites: $($SiteCodes -join ', ')")
    [void]$allText.AppendLine("Question: $Question")
    [void]$allText.AppendLine()

    $allPdfs = New-Object System.Collections.ArrayList

    foreach ($siteCode in $SiteCodes) {
        $siteDir = Join-Path $BaseDir $siteCode

        $bundle = New-FileBundle `
            -SiteDir         $siteDir `
            -MaxBundleBytes  $MaxBundleBytes `
            -MaxFileBytes    $MaxFileBytes `
            -MaxPdfBytes     $MaxPdfBytes `
            -NoPdfs          $NoPdfs

        $banner = "== $siteCode "
        [void]$allText.AppendLine('=' * 80)
        [void]$allText.AppendLine($banner + ('=' * [Math]::Max(0, 80 - $banner.Length)))
        [void]$allText.AppendLine('=' * 80)
        [void]$allText.AppendLine()
        [void]$allText.Append($bundle.BundleText)
        [void]$allText.AppendLine()

        $rel = (Resolve-Path -LiteralPath $siteDir).ProviderPath
        foreach ($pdf in @($bundle.PdfsToAttach)) {
            $r = $pdf.FullName.Substring($rel.Length).TrimStart('\','/')
            [void]$allPdfs.Add(@{
                File  = $pdf
                Label = "Attached PDF: $siteCode/$r"
            })
        }
    }

    return @{
        BundleText = $allText.ToString()
        PdfList    = @($allPdfs)
        PdfCount   = $allPdfs.Count
    }
}

function Get-PdfBatches {
    <#
    Greedily pack PDFs into batches each <= $BatchByteCap. Returns an
    array of arrays of @{File; Label} items.
    #>
    param(
        $PdfList,
        [int]$BatchByteCap
    )
    $batches = New-Object System.Collections.ArrayList
    if (-not $PdfList -or @($PdfList).Count -eq 0) { return @() }

    $current = New-Object System.Collections.ArrayList
    $used = 0
    foreach ($p in $PdfList) {
        $sz = $p.File.Length
        if ($current.Count -gt 0 -and ($used + $sz) -gt $BatchByteCap) {
            [void]$batches.Add(@($current))
            $current = New-Object System.Collections.ArrayList
            $used = 0
        }
        [void]$current.Add($p)
        $used += $sz
    }
    if ($current.Count -gt 0) { [void]$batches.Add(@($current)) }
    return @($batches)
}

function Build-MultimodalContent {
    <#
    Build an OpenAI chat-completions user message from a text payload
    plus zero or more PDFs. If no PDFs, returns the text directly so
    the simplest possible content shape is sent.
    #>
    param(
        [string]$Text,
        $Pdfs
    )
    if (-not $Pdfs -or @($Pdfs).Count -eq 0) { return $Text }
    $parts = New-Object System.Collections.ArrayList
    [void]$parts.Add(@{ type = 'text'; text = $Text })
    foreach ($p in $Pdfs) {
        [void]$parts.Add(@{ type = 'text'; text = $p.Label })
        [void]$parts.Add((New-PdfContentPart -File $p.File))
    }
    return ,@($parts)
}

function Send-WithBatching {
    <#
    Send the initial query for a site context and return the assistant's
    answer.

    If the site's PDFs all fit in a single request (MaxAllPdfsBytes),
    one chat-completions call is made. Otherwise the PDFs are split
    into batches and a map-reduce is performed:

      * For each batch: an isolated call (system + bundle text + that
        batch's PDFs) extracts a precise list of relevant facts.
      * A final call sends the bundle text + all per-batch fact extracts
        and asks for the actual answer.

    The map-reduce design avoids the trap of letting a multi-turn
    conversation grow past the gateway's per-request cap as more
    batches accumulate. The trade-off is that the final answer is
    produced from the per-batch summaries rather than the original
    PDF bytes -- for visual-only details (floor plans, etc.) the
    summary may be lossy. Lower the per-PDF size or raise
    MaxAllPdfsBytes to avoid chunking when possible.

    The REPL's $Messages list is updated so that subsequent same-site
    follow-ups can carry on naturally:
      * Single-batch: appends user(bundle+pdfs) and assistant(answer).
      * Map-reduce: appends user(bundle+summaries+question) and
        assistant(answer). Original PDFs are NOT in the REPL history.
    #>
    param(
        [string]$ApiKey,
        $Messages,         # System.Collections.Generic.List[object] (loose type to avoid PS5.1 binding glitches)
        [string]$BundleText,
        $PdfList,          # array of @{File; Label}, may be empty
        [int]$BatchByteCap,
        [string]$Question
    )

    $batches = @(Get-PdfBatches -PdfList $PdfList -BatchByteCap $BatchByteCap)

    if ($batches.Count -le 1) {
        $pdfs = if ($batches.Count -eq 1) { @($batches[0]) } else { @() }
        $userContent = Build-MultimodalContent -Text $BundleText -Pdfs $pdfs
        [void]$Messages.Add(@{ role = 'user'; content = $userContent })
        return Invoke-LLMWithMessages -ApiKey $ApiKey -Messages $Messages.ToArray()
    }

    Write-Host ("  PDFs exceed per-request cap; processing in $($batches.Count) batches (map-reduce).")
    $summaries = New-Object System.Collections.ArrayList

    for ($i = 0; $i -lt $batches.Count; $i++) {
        $batch = @($batches[$i])
        $bytes = ($batch | ForEach-Object { $_.File.Length } | Measure-Object -Sum).Sum
        Write-Host ("  Batch $($i+1) of $($batches.Count): $($batch.Count) PDF(s), $(Format-Size $bytes) -- extracting facts...")
        $extractText = $BundleText + "`n`n" +
            "[BATCH $($i+1) of $($batches.Count) -- the question is held until the final round]`n" +
            "Original question: $Question`n`n" +
            "The PDFs attached to THIS message are batch $($i+1) of $($batches.Count). " +
            "Read them and output a precise, self-contained list of facts " +
            "from these PDFs that may be relevant to the question. Include " +
            "specific names, numbers, room/jack IDs, and explicitly cite the " +
            "PDF each fact came from. Do NOT attempt a final answer yet."
        $userContent = Build-MultimodalContent -Text $extractText -Pdfs $batch
        $msgs = @(
            @{ role = 'system'; content = $SystemPrompt }
            @{ role = 'user';   content = $userContent }
        )
        $summary = Invoke-LLMWithMessages -ApiKey $ApiKey -Messages $msgs
        [void]$summaries.Add("=== Batch $($i+1) of $($batches.Count) ===`n$summary")
    }

    Write-Host '  Combining batch fact extracts for the final answer...'
    $finalText = $BundleText + "`n`n" +
        "[Per-batch PDF fact extracts -- used in lieu of resending the PDFs:]`n`n" +
        ($summaries -join "`n`n") + "`n`n" +
        "Now answer the original question using the text bundle above and the batch fact extracts: $Question"

    [void]$Messages.Add(@{ role = 'user'; content = $finalText })
    return Invoke-LLMWithMessages -ApiKey $ApiKey -Messages $Messages.ToArray()
}

# Build the initial site context (used both for -NoLLM and the REPL).
$ctx = Build-SiteContext `
    -SiteCodes       $resolvedSites `
    -BaseDir         $BaseDir `
    -Question        $qtext `
    -MaxBundleBytes  $MaxBundleBytes `
    -MaxFileBytes    $MaxFileBytes `
    -MaxPdfBytes     $MaxPdfBytes `
    -NoPdfs          $NoPdfs.IsPresent

if ($NoLLM) {
    Write-Host ''
    Write-Host ('#' * 78)
    Write-Host '# LLM call skipped. Bundle below -- copy from terminal or save to a file.'
    if ($ctx.PdfCount -gt 0) {
        Write-Host "# (Plus $($ctx.PdfCount) PDF attachment(s) -- not printed.)"
    }
    Write-Host ('#' * 78)
    Write-Host ''
    Write-Output $ctx.BundleText
    return
}

$apiKey = Read-ApiKey
if (-not $apiKey) {
    Write-Error 'No API key supplied'
    exit 1
}

# --- Conversation loop ----------------------------------------------------
# The first user message carries the bundle (and PDFs); follow-up turns
# are plain text appended to the conversation. If a follow-up names a
# different site code, the conversation is reset with that site's
# bundle as a fresh first user message.

function Test-SameSiteSet {
    # Two site-code lists describe the same set, ignoring case/order.
    param([string[]]$A, [string[]]$B)
    if ($A.Count -ne $B.Count) { return $false }
    $aNorm = $A | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object
    $bNorm = $B | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object
    for ($i = 0; $i -lt $aNorm.Count; $i++) {
        if ($aNorm[$i] -ne $bNorm[$i]) { return $false }
    }
    return $true
}

$messages = New-Object System.Collections.ArrayList
[void]$messages.Add(@{ role = 'system'; content = $SystemPrompt })

$currentSites    = @($resolvedSites)
$currentBundle   = $ctx.BundleText
$currentPdfList  = $ctx.PdfList
$currentQuestion = $qtext
$initialTurn     = $true

while ($true) {
    $sitesLabel = $currentSites -join ','

    if ($initialTurn) {
        Write-Host ("Sending [$sitesLabel, bundle + $($ctx.PdfCount) PDF(s)] to $LLMEndpoint ($LLMModel) ...")
        try {
            $answer = Send-WithBatching `
                -ApiKey       $apiKey `
                -Messages     $messages `
                -BundleText   $currentBundle `
                -PdfList      $currentPdfList `
                -BatchByteCap $MaxAllPdfsBytes `
                -Question     $currentQuestion
        } catch {
            Write-Warning "LLM call failed: $_"
            Write-Host ''
            Write-Host ('#' * 78)
            Write-Host '# Bundle below so you can send it from a host that can reach the API:'
            Write-Host ('#' * 78)
            Write-Output $currentBundle
            exit 4
        }
        $initialTurn = $false
    } else {
        Write-Host ("Sending [$sitesLabel, follow-up #$([math]::Floor(($messages.Count - 2) / 2))] to $LLMEndpoint ($LLMModel) ...")
        try {
            $answer = Invoke-LLMWithMessages -ApiKey $apiKey -Messages $messages.ToArray()
        } catch {
            Write-Warning "LLM call failed: $_"
            $messages.RemoveAt($messages.Count - 1)
            Write-Host '(retry your question or press Enter to exit)'
            $answer = $null
        }
    }

    if ($answer) {
        Write-Output ''
        Write-Output $answer
        Write-Output ''
        [void]$messages.Add(@{ role = 'assistant'; content = $answer })
    }

    # Read the next input. Blank input simply re-prompts (so a stray
    # Enter does not nuke the conversation). The only ways out are:
    #   * Type 'exit' / 'quit' / 'q' / ':q'
    #   * Press Ctrl-C
    #   * Send EOF (Read-Host returns $null on EOF -> we exit)
    $followup = $null
    while ($true) {
        Write-Host ''
        Write-Host ('-' * 78)
        Write-Host "Sites in context: $($currentSites -join ', ')   (type 'exit' to quit)"
        Write-Host ('-' * 78)
        $line = Read-Host -Prompt 'Follow-up'
        if ($null -eq $line) {
            # EOF (stdin closed / Ctrl-D)
            $followup = $null
            break
        }
        $trimmed = $line.Trim()
        if (-not $trimmed) {
            Write-Host '(blank input -- type a question, or type exit to quit)'
            continue
        }
        if ($trimmed -in @('exit', 'quit', 'q', ':q', ':quit', ':exit')) {
            $followup = $null
            break
        }
        $followup = $trimmed
        break
    }
    if (-not $followup) { break }

    $hits = @(Resolve-SiteFromQuestion -Question $followup -AvailableCodes $codes)
    $shouldSwitch = ($hits.Count -gt 0 -and -not (Test-SameSiteSet -A $hits -B $currentSites))

    if ($shouldSwitch) {
        Write-Host "Switching context to site(s) '$($hits -join ', ')' (re-bundling, conversation reset)."
        $ctx = Build-SiteContext `
            -SiteCodes       $hits `
            -BaseDir         $BaseDir `
            -Question        $followup `
            -MaxBundleBytes  $MaxBundleBytes `
            -MaxFileBytes    $MaxFileBytes `
            -MaxPdfBytes     $MaxPdfBytes `
            -NoPdfs          $NoPdfs.IsPresent
        $messages.Clear()
        [void]$messages.Add(@{ role = 'system'; content = $SystemPrompt })
        $currentSites    = @($hits)
        $currentBundle   = $ctx.BundleText
        $currentPdfList  = $ctx.PdfList
        $currentQuestion = $followup
        $initialTurn     = $true
    } else {
        # Same site set (or no codes mentioned) -- append a plain text
        # user turn, no PDFs needed.
        [void]$messages.Add(@{ role = 'user'; content = $followup })
    }
}
