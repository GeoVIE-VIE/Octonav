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
    PS> .\Invoke-SiteQuery.ps1 -List
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Question,

    [string]$Site,

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
        PdfsToAttach  -- FileInfo[] for PDFs the caller should ship as
                         multimodal parts. Empty when -NoPdfs is set or
                         no PDFs fit the size caps.
    #>
    param(
        [string]$SiteDir,
        [int]$MaxBundleBytes,
        [int]$MaxFileBytes,
        [int]$MaxPdfBytes,
        [int]$MaxAllPdfsBytes,
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

    # 5) Decide which PDFs to attach (or list, if -NoPdfs).
    $attached = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    if (-not $NoPdfs -and $pdfFiles.Count -gt 0) {
        $pdfBytesUsed = 0
        [void]$sb.AppendLine('--- Attached PDFs (sent to the model as multimodal documents) ---')
        foreach ($p in $pdfFiles) {
            $r = $p.FullName.Substring($rel.Length).TrimStart('\','/')
            if ($p.Length -gt $MaxPdfBytes) {
                [void]$sb.AppendLine("  [skipped, too large]  $r  ($(Format-Size $p.Length) > MaxPdfBytes)")
                continue
            }
            if (($pdfBytesUsed + $p.Length) -gt $MaxAllPdfsBytes) {
                [void]$sb.AppendLine("  [skipped, total cap]   $r  ($(Format-Size $p.Length))")
                continue
            }
            [void]$sb.AppendLine("  [attached]            $r  ($(Format-Size $p.Length))")
            $attached.Add($p) | Out-Null
            $pdfBytesUsed += $p.Length
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

function Build-SiteContext {
    <#
    Bundle a site directory and return the first user-message content
    plus diagnostics. The first user message in a conversation contains
    the directory tree, all extracted text, and any attached PDFs.
    #>
    param(
        [string]$SiteCode,
        [string]$BaseDir,
        [string]$Question,
        [int]$MaxBundleBytes,
        [int]$MaxFileBytes,
        [int]$MaxPdfBytes,
        [int]$MaxAllPdfsBytes,
        [bool]$NoPdfs
    )

    $siteDir = Join-Path $BaseDir $SiteCode
    $bundle = New-FileBundle `
        -SiteDir         $siteDir `
        -MaxBundleBytes  $MaxBundleBytes `
        -MaxFileBytes    $MaxFileBytes `
        -MaxPdfBytes     $MaxPdfBytes `
        -MaxAllPdfsBytes $MaxAllPdfsBytes `
        -NoPdfs          $NoPdfs

    $bundleText  = $bundle.BundleText
    $pdfAttached = @($bundle.PdfsToAttach)

    $payload = @"
Site: $SiteCode
Question: $Question

$bundleText
"@

    if ($pdfAttached.Count -gt 0) {
        $parts = New-Object System.Collections.Generic.List[object]
        [void]$parts.Add(@{ type = 'text'; text = $payload })
        $rel = (Resolve-Path -LiteralPath $siteDir).ProviderPath
        foreach ($p in $pdfAttached) {
            $r = $p.FullName.Substring($rel.Length).TrimStart('\','/')
            [void]$parts.Add(@{ type = 'text'; text = "Attached PDF: $r" })
            [void]$parts.Add((New-PdfContentPart -File $p))
        }
        $userContent = $parts.ToArray()
    } else {
        $userContent = $payload
    }

    return @{
        UserContent = $userContent
        PayloadText = $payload
        PdfCount    = $pdfAttached.Count
    }
}

# Build the initial site context (used both for -NoLLM and the REPL).
$ctx = Build-SiteContext `
    -SiteCode        $resolvedSite `
    -BaseDir         $BaseDir `
    -Question        $qtext `
    -MaxBundleBytes  $MaxBundleBytes `
    -MaxFileBytes    $MaxFileBytes `
    -MaxPdfBytes     $MaxPdfBytes `
    -MaxAllPdfsBytes $MaxAllPdfsBytes `
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
    Write-Output $ctx.PayloadText
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

$messages = New-Object System.Collections.Generic.List[object]
[void]$messages.Add(@{ role = 'system'; content = $SystemPrompt })
[void]$messages.Add(@{ role = 'user';   content = $ctx.UserContent })

$currentSite = $resolvedSite
$turnLabel   = "with bundle + $($ctx.PdfCount) PDF(s)"

while ($true) {
    Write-Host ("Sending [$currentSite, $turnLabel] to $LLMEndpoint ($LLMModel) ...")
    try {
        $answer = Invoke-LLMWithMessages -ApiKey $apiKey -Messages $messages.ToArray()
    } catch {
        Write-Warning "LLM call failed: $_"
        if ($messages.Count -le 2) {
            # No assistant turn yet -- print the bundle so the operator
            # can take it elsewhere.
            Write-Host ''
            Write-Host ('#' * 78)
            Write-Host '# Bundle below so you can send it from a host that can reach the API:'
            Write-Host ('#' * 78)
            Write-Output $ctx.PayloadText
            exit 4
        }
        # Mid-conversation failure: drop the last user turn so the next
        # follow-up can replace it cleanly.
        $messages.RemoveAt($messages.Count - 1)
        Write-Host '(retry your question or press Enter to exit)'
    }

    if ($answer) {
        Write-Output ''
        Write-Output $answer
        Write-Output ''
        [void]$messages.Add(@{ role = 'assistant'; content = $answer })
    }

    $followup = Read-Host -Prompt 'Follow-up (blank to exit; mention another site code to switch context)'
    if (-not $followup -or -not $followup.Trim()) { break }

    # Detect a site change: any matched code that is NOT the current site.
    $hits = @(Resolve-SiteFromQuestion -Question $followup -AvailableCodes $codes)
    $newSite = $null
    foreach ($h in $hits) {
        if ($h -ine $currentSite) { $newSite = $h; break }
    }

    if ($newSite) {
        Write-Host "Switching context to site '$newSite' (re-bundling, conversation reset)."
        $ctx = Build-SiteContext `
            -SiteCode        $newSite `
            -BaseDir         $BaseDir `
            -Question        $followup `
            -MaxBundleBytes  $MaxBundleBytes `
            -MaxFileBytes    $MaxFileBytes `
            -MaxPdfBytes     $MaxPdfBytes `
            -MaxAllPdfsBytes $MaxAllPdfsBytes `
            -NoPdfs          $NoPdfs.IsPresent
        $messages.Clear()
        [void]$messages.Add(@{ role = 'system'; content = $SystemPrompt })
        [void]$messages.Add(@{ role = 'user';   content = $ctx.UserContent })
        $currentSite = $newSite
        $turnLabel   = "with bundle + $($ctx.PdfCount) PDF(s)"
    } else {
        # Same-site follow-up: append a plain text turn.
        [void]$messages.Add(@{ role = 'user'; content = $followup })
        $turnLabel = "follow-up #$([math]::Floor(($messages.Count - 2) / 2))"
    }
}
