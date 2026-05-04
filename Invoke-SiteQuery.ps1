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

.PARAMETER Reindex
    Run an indexing pass that walks every -Site directory in full,
    asks the LLM to produce a structured Markdown summary AND a
    JSON metadata block, and writes them to '.site-summary.md' and
    '.site-data.json' inside each site directory. The master index
    '.sites-index.json' at the base dir is rebuilt afterwards.

.PARAMETER RebuildIndex
    Re-aggregate the master '.sites-index.json' from the existing
    per-site '.site-data.json' files. No LLM calls; cheap and fast.
    Run this after manually editing a site's data.json.

.PARAMETER Full
    Bypass any pre-built '.site-summary.md' and bundle the raw site
    contents (the legacy behaviour). Useful when the summary is
    stale or you want the model to look at original files for a
    specific question.

.PARAMETER List
    List all available site codes and exit. If '.sites-index.json'
    exists at the base dir, prints a tabular view with site name,
    summary length, and key facts. Otherwise just lists directory
    names.

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
    [switch]$NoStream,
    [switch]$Reindex,
    [switch]$RebuildIndex,
    [switch]$Full,
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

# Filenames the indexer writes inside each site directory and at the
# base dir. A site with .site-summary.md uses it as the bundle; the
# master .sites-index.json is rebuilt during -Reindex / -RebuildIndex.
$Script:SummaryFileName  = '.site-summary.md'
$Script:DataFileName     = '.site-data.json'
$Script:MasterIndexName  = '.sites-index.json'

# Delimiters the LLM response is split on during -Reindex. They must
# appear verbatim and on their own line in the model output so the
# response can be reliably parsed into the Markdown and JSON parts.
$Script:DelimSummary = '<<<SITE-SUMMARY-MARKDOWN>>>'
$Script:DelimData    = '<<<SITE-DATA-JSON>>>'

# Prompt used during -Reindex to drive the summary-generation call.
$Script:IndexingPrompt = @"
You are an expert network and physical-site indexer. The operator has
provided the complete contents of one site's documentation directory
(text files, extracted Excel content, and any PDFs). You must produce
TWO outputs in a single response, in the exact order shown below,
each preceded by its own delimiter line on a line by itself:

$($Script:DelimSummary)
<a comprehensive Markdown summary of the site, structured per the
skeleton below; cite specific filenames inline; do NOT invent>
$($Script:DelimData)
<a single JSON object on one or more lines; valid JSON only; no
prose around it; schema also below>

Markdown skeleton (omit sections that have no content):

# Site <CODE> -- <human name if known>

## Identity
- Address, site code, building type, owner, key contacts.

## Network architecture
### Demarcs (carrier handoff points)
### MDF (main distribution frame)
### IDFs (intermediate distribution frames)
### Wireless (controllers, AP counts, SSIDs)

## Power, HVAC, physical
- UPS, generator, cooling, rack inventory, security/access notes.

## Devices and inventory
- Switches, routers, firewalls, APs, with model and serial when known.
- Servers, storage, voice gear if present.

## Notable cabling / fiber
- Strand counts, conduit paths, fiber demarc, key cross-connects.

## Files referenced
- One concise line per non-text file (PDF / Visio / CAD / image)
  describing what the file shows.

## Open questions / undocumented

JSON schema (use null for unknowns; arrays may be empty; do NOT
include keys not in this list):

{
  "site_code":   string,
  "name":        string|null,
  "address":     string|null,
  "site_type":   string|null,         // 'office', 'data center', 'retail', etc.
  "idf_count":   integer|null,
  "ap_count":    integer|null,
  "key_devices": [string],            // model names: 'Cisco Cat 9300', 'ICX 7450-48P', ...
  "key_facts":   [string],            // 5-15 short factual one-liners
  "tags":        [string],            // 3-10 lowercase short tags
  "carriers":    [string],            // ISP / WAN provider names
  "files_referenced": [string]        // important non-text filenames
}

Be exhaustive in the Markdown, concise in the JSON. Do NOT wrap the
JSON in markdown code fences. Do NOT add preamble or commentary
before the first delimiter or after the JSON.
"@.Trim()

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

    try {
        $resp = Invoke-RestMethod -Method Post `
            -Uri $LLMEndpoint `
            -Headers $headers `
            -ContentType 'application/json' `
            -Body $body `
            -TimeoutSec 240
    } catch {
        # Invoke-RestMethod swallows the HTTP response body on error.
        # Pull it out so the operator sees what the gateway actually
        # said. PowerShell exposes it differently on each version:
        #   PS 7+      : $_.ErrorDetails.Message holds the response body.
        #   WinPS 5.1  : $_.Exception.Response.GetResponseStream() reads it.
        $err = $_
        $ex  = $err.Exception
        $status   = $null
        $respBody = $null

        # PS 7+ path
        if ($err.ErrorDetails -and $err.ErrorDetails.Message) {
            $respBody = $err.ErrorDetails.Message
        }
        if ($ex.Response) {
            try { $status = [int]$ex.Response.StatusCode } catch { }
            if (-not $respBody) {
                # WinPS 5.1 path
                try {
                    $stream = $ex.Response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($stream)
                    $respBody = $reader.ReadToEnd()
                } catch { }
            }
        }
        $detail = if ($status -and $respBody) {
            "HTTP $status -- $respBody"
        } elseif ($status) {
            "HTTP $status"
        } elseif ($respBody) {
            $respBody
        } else {
            $ex.Message
        }
        throw "LLM API error: $detail"
    }

    return $resp.choices[0].message.content
}

function Invoke-LLMStream {
    <#
    Same contract as Invoke-LLMWithMessages but uses 'stream: true' --
    delta tokens are written to the host as they arrive, and the full
    accumulated reply is returned at the end.

    Used for any user-facing answer (single-batch initial reply, the
    final reduce reply, and same-site REPL follow-ups). Map-reduce
    extract calls keep using the non-streaming version because their
    output is internal-only and would just clutter the terminal.

    Pure stdlib: System.Net.Http.HttpClient + line-based SSE parser.
    Works on Windows PowerShell 5.1 and PowerShell 7+.
    #>
    param(
        [string]$ApiKey,
        [object[]]$Messages
    )
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

    $bodyJson = @{
        model    = $LLMModel
        messages = $Messages
        stream   = $true
    } | ConvertTo-Json -Depth 20 -Compress

    $client = [System.Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromMinutes(10)
    try {
        $req = [System.Net.Http.HttpRequestMessage]::new('POST', $LLMEndpoint)
        [void]$req.Headers.TryAddWithoutValidation('Authorization', "Bearer $ApiKey")
        [void]$req.Headers.TryAddWithoutValidation('Accept', 'text/event-stream')
        $req.Content = [System.Net.Http.StringContent]::new(
            $bodyJson, [System.Text.Encoding]::UTF8, 'application/json')

        $resp = $client.SendAsync(
            $req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result

        if (-not $resp.IsSuccessStatusCode) {
            $errBody = ''
            try { $errBody = $resp.Content.ReadAsStringAsync().Result } catch {}
            throw "LLM API error: HTTP $([int]$resp.StatusCode) -- $errBody"
        }

        $stream = $resp.Content.ReadAsStreamAsync().Result
        $reader = [System.IO.StreamReader]::new($stream)
        $accumulated = [System.Text.StringBuilder]::new()
        try {
            while (-not $reader.EndOfStream) {
                $line = $reader.ReadLine()
                if (-not $line) { continue }
                if ($line.StartsWith(':')) { continue }   # SSE comment / keep-alive
                if (-not $line.StartsWith('data:')) { continue }
                $data = $line.Substring(5).Trim()
                if ($data -eq '[DONE]') { break }
                try {
                    $obj = $data | ConvertFrom-Json
                } catch { continue }
                $delta = $null
                try { $delta = $obj.choices[0].delta.content } catch {}
                if ($null -ne $delta -and $delta.Length -gt 0) {
                    [Console]::Out.Write($delta)
                    [void]$accumulated.Append($delta)
                }
            }
        } finally {
            $reader.Dispose()
        }
        Write-Host ''   # newline after the streamed answer
        return $accumulated.ToString()
    } finally {
        $client.Dispose()
    }
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

function Update-MasterIndex {
    <#
    Walk every subdirectory of $BaseDir, read each '.site-data.json'
    that exists, and write an aggregated '.sites-index.json' at
    $BaseDir. No LLM calls -- just file I/O.
    #>
    param([string]$BaseDir)
    $entries = New-Object System.Collections.ArrayList
    $dirs = Get-ChildItem -LiteralPath $BaseDir -Directory |
        Where-Object { -not $_.Name.StartsWith('.') } |
        Sort-Object Name
    foreach ($d in $dirs) {
        $dataPath = Join-Path $d.FullName $Script:DataFileName
        if (-not (Test-Path -LiteralPath $dataPath)) { continue }
        try {
            $obj = Get-Content -LiteralPath $dataPath -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch {
            Write-Warning "Skipping $dataPath (invalid JSON: $_)"
            continue
        }
        # Stamp the directory name in case the file's site_code drifted
        # from the folder name.
        if (-not $obj.site_code) {
            $obj | Add-Member -NotePropertyName site_code -NotePropertyValue $d.Name -Force
        }
        [void]$entries.Add($obj)
    }
    $index = [ordered]@{
        indexed_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        site_count = $entries.Count
        sites      = @($entries)
    }
    $masterPath = Join-Path $BaseDir $Script:MasterIndexName
    $index | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $masterPath -Encoding UTF8
    return @{ Path = $masterPath; SiteCount = $entries.Count }
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

# --- RebuildIndex short-circuit (no LLM, no -Site needed) ----------------
if ($RebuildIndex) {
    $r = Update-MasterIndex -BaseDir $BaseDir
    Write-Host ("Rebuilt master index: {0}  ({1} site(s))" -f $r.Path, $r.SiteCount)
    return
}

if ($List) {
    $masterPath = Join-Path $BaseDir $Script:MasterIndexName
    if (Test-Path -LiteralPath $masterPath) {
        try {
            $idx = Get-Content -LiteralPath $masterPath -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch {
            Write-Warning "Master index unreadable ($_) -- falling back to dir listing."
            $idx = $null
        }
        if ($idx -and $idx.sites) {
            Write-Host ("Available sites under {0} (from {1}):" -f $BaseDir, $Script:MasterIndexName)
            Write-Host ''
            # Build a fixed-width manual table -- piping Format-Table
            # through Out-String + Write-Host loses rows on some hosts.
            $sites = @($idx.sites)
            function _f($v) { if ($null -eq $v) { '' } else { [string]$v } }
            $rows = foreach ($s in $sites) {
                [pscustomobject]@{
                    Code    = _f $s.site_code
                    Name    = _f $s.name
                    Type    = _f $s.site_type
                    IDFs    = _f $s.idf_count
                    APs     = _f $s.ap_count
                    Devices = if ($s.key_devices) { ($s.key_devices -join '; ') } else { '' }
                    Tags    = if ($s.tags)        { ($s.tags -join ', ') }        else { '' }
                }
            }
            $cols = @('Code','Name','Type','IDFs','APs','Devices','Tags')
            $widths = @{}
            foreach ($c in $cols) {
                $w = $c.Length
                foreach ($r in $rows) {
                    $v = [string]$r.$c
                    if ($v.Length -gt $w) { $w = $v.Length }
                }
                $widths[$c] = [Math]::Min($w, 60)
            }
            # Build a format string with INDEXED placeholders ({0}, {1}, ...)
            # so each column gets the right value. The earlier
            # all-{0} version made every column show the first value.
            $placeholders = for ($i = 0; $i -lt $cols.Count; $i++) {
                '{' + $i + ',-' + $widths[$cols[$i]] + '}'
            }
            $fmt = $placeholders -join '  '
            $headerVals = foreach ($c in $cols) { $c }
            $sepVals    = foreach ($c in $cols) { '-' * $widths[$c] }
            Write-Host ($fmt -f $headerVals)
            Write-Host ($fmt -f $sepVals)
            foreach ($r in $rows) {
                $vals = foreach ($c in $cols) {
                    $v = [string]$r.$c
                    if ($v.Length -gt $widths[$c]) {
                        $v = $v.Substring(0, $widths[$c] - 1) + [char]0x2026
                    }
                    $v
                }
                Write-Host ($fmt -f $vals)
            }

            # Mention any sites that exist on disk but aren't indexed.
            $indexed = @($sites | ForEach-Object { ([string]$_.site_code).ToLowerInvariant() })
            $unindexed = $codes | Where-Object { $indexed -notcontains $_.ToLowerInvariant() }
            if ($unindexed) {
                Write-Host ''
                Write-Host 'Not indexed yet (run -Reindex):'
                $unindexed | ForEach-Object { Write-Host "  $_" }
            }
            return
        }
    }
    # No master index -- fall back to plain dir listing with a hint.
    Write-Host "Available site codes under ${BaseDir}:"
    $codes | ForEach-Object { Write-Host "  $_" }
    Write-Host ''
    Write-Host "Tip: run with -Site <CODE>[,<CODE>...] -Reindex to build $($Script:MasterIndexName)"
    return
}

# Assemble the question text. -Reindex / -RebuildIndex do not need a question.
$qtext = if ($Question -and $Question.Count -gt 0) {
    ($Question -join ' ').Trim()
} elseif ($Reindex -or $RebuildIndex) {
    ''
} else {
    Read-Host -Prompt 'Question'
}
if (-not $qtext -and -not ($Reindex -or $RebuildIndex)) {
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

function Get-SiteSummaryPath {
    <#
    Return the path to a site's pre-built summary if one exists,
    else $null. The presence of this file is the signal that a site
    has been indexed and queries should send the summary instead of
    re-bundling raw files.
    #>
    param([string]$SiteDir)
    $candidates = @($Script:SummaryFileName, '.site-summary.txt', 'SITE-SUMMARY.md')
    foreach ($name in $candidates) {
        $p = Join-Path $SiteDir $name
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}

function Split-IndexerResponse {
    <#
    Split a -Reindex LLM response into its Markdown and JSON parts.
    Returns @{ Markdown = '<text>'; Data = <object|null> }. The JSON
    parse is best-effort -- if the model emitted slightly invalid
    JSON we return $null for Data and let the caller fall back.
    #>
    param([string]$Response)

    $sumIdx  = $Response.IndexOf($Script:DelimSummary)
    $dataIdx = $Response.IndexOf($Script:DelimData)
    if ($sumIdx -lt 0 -or $dataIdx -lt 0 -or $dataIdx -lt $sumIdx) {
        return @{ Markdown = $Response.Trim(); Data = $null }
    }
    $mdStart = $sumIdx + $Script:DelimSummary.Length
    $md      = $Response.Substring($mdStart, $dataIdx - $mdStart).Trim()
    $jsonRaw = $Response.Substring($dataIdx + $Script:DelimData.Length).Trim()

    # Some models still wrap JSON in fences -- strip them.
    if ($jsonRaw.StartsWith('```')) {
        $jsonRaw = ($jsonRaw -replace '^```(?:json)?\s*', '') -replace '```\s*$', ''
        $jsonRaw = $jsonRaw.Trim()
    }
    $data = $null
    try { $data = $jsonRaw | ConvertFrom-Json -ErrorAction Stop } catch { $data = $null }
    return @{ Markdown = $md; Data = $data }
}

function Build-SiteContext {
    <#
    Bundle one OR MORE site directories. Returns:
      BundleText  -- text-only payload with per-site banners and the
                     question prefix. Goes into every request, with or
                     without PDFs.
      PdfList     -- @{File; Label} for every PDF to ship.
      PdfCount    -- convenience.
      UsedSummary -- $true if any site contributed via .site-summary.md.

    If a site has a pre-built '.site-summary.md' (and -Full was not
    set), that file's content is used instead of walking the raw
    directory. PDFs are NOT attached for summary-backed sites; the
    operator can pass -Full to force a raw-file bundle when the
    summary does not have the answer.

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
        [bool]$NoPdfs,
        [bool]$Full
    )

    $allText = [System.Text.StringBuilder]::new()
    [void]$allText.AppendLine("Sites: $($SiteCodes -join ', ')")
    [void]$allText.AppendLine("Question: $Question")
    [void]$allText.AppendLine()

    $allPdfs = New-Object System.Collections.ArrayList
    $usedSummary = $false

    foreach ($siteCode in $SiteCodes) {
        $siteDir = Join-Path $BaseDir $siteCode

        # Prefer a pre-built summary unless -Full was passed.
        $summaryPath = $null
        if (-not $Full) { $summaryPath = Get-SiteSummaryPath -SiteDir $siteDir }

        if ($summaryPath) {
            $usedSummary = $true
            try {
                $summaryText = Get-Content -LiteralPath $summaryPath -Raw -Encoding UTF8
            } catch {
                Write-Warning "Failed to read $summaryPath -- falling back to raw bundle. ($_)"
                $summaryPath = $null
            }
        }

        if ($summaryPath) {
            $banner = "== $siteCode  (using $($Script:SummaryFileName)) "
            [void]$allText.AppendLine('=' * 80)
            [void]$allText.AppendLine($banner + ('=' * [Math]::Max(0, 80 - $banner.Length)))
            [void]$allText.AppendLine('=' * 80)
            [void]$allText.AppendLine()
            [void]$allText.AppendLine($summaryText)
            [void]$allText.AppendLine()
            continue   # do NOT walk raw files or attach PDFs for this site
        }

        # No summary -> walk the raw site directory.
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
        BundleText  = $allText.ToString()
        PdfList     = @($allPdfs)
        PdfCount    = $allPdfs.Count
        UsedSummary = $usedSummary
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
        if ($Script:UseStreaming) {
            return Invoke-LLMStream        -ApiKey $ApiKey -Messages $Messages.ToArray()
        } else {
            return Invoke-LLMWithMessages  -ApiKey $ApiKey -Messages $Messages.ToArray()
        }
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
    if ($Script:UseStreaming) {
        return Invoke-LLMStream        -ApiKey $ApiKey -Messages $Messages.ToArray()
    } else {
        return Invoke-LLMWithMessages  -ApiKey $ApiKey -Messages $Messages.ToArray()
    }
}

# --- Reindex short-circuit -----------------------------------------------
# For -Reindex we need the API key now, walk every -Site in -Full mode,
# run the indexing pass with the indexing system prompt, split the
# model's response into Markdown + JSON parts, write both per-site
# files, and refresh the master '.sites-index.json' at the end.
if ($Reindex) {
    $apiKey = Read-ApiKey
    if (-not $apiKey) {
        Write-Error 'No API key supplied'
        exit 1
    }
    # Indexing must NOT stream -- we need the full response to split on
    # delimiters before writing the two output files.
    $Script:UseStreaming = $false
    $savedSystemPrompt = $SystemPrompt
    $SystemPrompt = $Script:IndexingPrompt
    try {
        foreach ($siteCode in $resolvedSites) {
            $siteDir = Join-Path $BaseDir $siteCode
            Write-Host ''
            Write-Host ("Indexing site '$siteCode' (this may take a while if there are many PDFs) ...")
            $rctx = Build-SiteContext `
                -SiteCodes       @($siteCode) `
                -BaseDir         $BaseDir `
                -Question        '(indexing pass)' `
                -MaxBundleBytes  $MaxBundleBytes `
                -MaxFileBytes    $MaxFileBytes `
                -MaxPdfBytes     $MaxPdfBytes `
                -NoPdfs          $NoPdfs.IsPresent `
                -Full            $true
            $rmsgs = New-Object System.Collections.ArrayList
            [void]$rmsgs.Add(@{ role = 'system'; content = $Script:IndexingPrompt })
            try {
                $raw = Send-WithBatching `
                    -ApiKey       $apiKey `
                    -Messages     $rmsgs `
                    -BundleText   $rctx.BundleText `
                    -PdfList      $rctx.PdfList `
                    -BatchByteCap $MaxAllPdfsBytes `
                    -Question     'Produce the indexer output for the site above as instructed.'
            } catch {
                Write-Warning "Indexing $siteCode failed: $_"
                continue
            }

            $split   = Split-IndexerResponse -Response $raw
            $summary = $split.Markdown
            $data    = $split.Data
            if (-not $data) {
                Write-Warning "${siteCode}: could not parse JSON metadata; saving Markdown only."
            } else {
                # Stamp / fix up canonical fields.
                $data | Add-Member -NotePropertyName site_code  -NotePropertyValue $siteCode -Force
                $data | Add-Member -NotePropertyName indexed_at -NotePropertyValue (
                    (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) -Force
                $data | Add-Member -NotePropertyName summary_chars -NotePropertyValue $summary.Length -Force
            }

            $summaryPath = Join-Path $siteDir $Script:SummaryFileName
            Set-Content -LiteralPath $summaryPath -Value $summary -Encoding UTF8
            Write-Host ("  wrote {0}  ({1:N0} chars)" -f $summaryPath, $summary.Length)

            if ($data) {
                $dataPath = Join-Path $siteDir $Script:DataFileName
                $data | ConvertTo-Json -Depth 10 |
                    Set-Content -LiteralPath $dataPath -Encoding UTF8
                Write-Host ("  wrote {0}" -f $dataPath)
            }
        }
    } finally {
        $SystemPrompt = $savedSystemPrompt
    }

    # Refresh the master index from the freshly-written per-site data.
    try {
        $idx = Update-MasterIndex -BaseDir $BaseDir
        Write-Host ''
        Write-Host ("Master index updated: {0}  ({1} site(s))" -f $idx.Path, $idx.SiteCount)
    } catch {
        Write-Warning "Could not update master index: $_"
    }

    Write-Host ''
    Write-Host 'Indexing complete. Run again without -Reindex to query against the summaries.'
    return
}

# Build the initial site context (used both for -NoLLM and the REPL).
$ctx = Build-SiteContext `
    -SiteCodes       $resolvedSites `
    -BaseDir         $BaseDir `
    -Question        $qtext `
    -MaxBundleBytes  $MaxBundleBytes `
    -MaxFileBytes    $MaxFileBytes `
    -MaxPdfBytes     $MaxPdfBytes `
    -NoPdfs          $NoPdfs.IsPresent `
    -Full            $Full.IsPresent

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

# Single source of truth for streaming, so Send-WithBatching and the
# REPL pick the same code path.
$Script:UseStreaming = -not $NoStream.IsPresent

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
            Write-Host ''
            Write-Host ('#' * 78) -ForegroundColor Red
            Write-Host '#  LLM CALL FAILED'                     -ForegroundColor Red
            Write-Host ('#' * 78) -ForegroundColor Red
            Write-Host ''
            Write-Host ($_ | Out-String) -ForegroundColor Red
            Write-Host ('#' * 78) -ForegroundColor Red
            Write-Host '#  Common causes:'                      -ForegroundColor Red
            Write-Host '#    HTTP 4xx -- check the API key, model name, or endpoint.' -ForegroundColor Red
            Write-Host '#    HTTP 413 -- payload too large; lower -MaxAllPdfsBytes or use -NoPdfs.' -ForegroundColor Red
            Write-Host '#    Timeout / refused -- gateway unreachable from this host.' -ForegroundColor Red
            Write-Host '#  The bundle was NOT printed. Pass -NoLLM to dump it for offline relay.' -ForegroundColor Red
            Write-Host ('#' * 78) -ForegroundColor Red
            exit 4
        }
        $initialTurn = $false
    } else {
        Write-Host ("Sending [$sitesLabel, follow-up #$([math]::Floor(($messages.Count - 2) / 2))] to $LLMEndpoint ($LLMModel) ...")
        try {
            if ($Script:UseStreaming) {
                $answer = Invoke-LLMStream       -ApiKey $apiKey -Messages $messages.ToArray()
            } else {
                $answer = Invoke-LLMWithMessages -ApiKey $apiKey -Messages $messages.ToArray()
            }
        } catch {
            Write-Host ''
            Write-Host ('#' * 78) -ForegroundColor Red
            Write-Host '#  LLM CALL FAILED (this turn) -- conversation kept; retry or switch sites.' -ForegroundColor Red
            Write-Host ('#' * 78) -ForegroundColor Red
            Write-Host ($_ | Out-String) -ForegroundColor Red
            $messages.RemoveAt($messages.Count - 1)
            $answer = $null
        }
    }

    if ($answer) {
        # When streaming, the answer was already written to the host as
        # tokens arrived; we only need a trailing blank line. When not
        # streaming we still echo it.
        if (-not $Script:UseStreaming) {
            Write-Output ''
            Write-Output $answer
        }
        Write-Output ''
        [void]$messages.Add(@{ role = 'assistant'; content = $answer })
    }

    # Read the next input. Blank input simply re-prompts (so a stray
    # Enter does not nuke the conversation). The only ways out are:
    #   * Type 'exit' / 'quit' / 'q' / ':q'
    #   * Press Ctrl-C
    #   * Stdin closes (we exit with a diagnostic message)
    $followup = $null
    while ($true) {
        Write-Host ''
        Write-Host ('=' * 78)
        Write-Host "  Sites in context: $($currentSites -join ', ')"
        Write-Host "  Type your next question, or 'exit' to quit."
        Write-Host ('=' * 78)
        Write-Host '> ' -NoNewline

        # Try reading via the host UI first (the PowerShell-native path
        # that integrates with ConsoleHost / pwsh / ISE). If that throws
        # or returns nothing, fall back to [Console]::In which works
        # against the underlying stdin handle even when the host UI
        # cannot prompt (e.g., piped input, non-interactive launches).
        $line = $null
        try {
            $line = $Host.UI.ReadLine()
        } catch {
            $line = $null
        }
        if ($null -eq $line) {
            try {
                $line = [Console]::In.ReadLine()
            } catch {
                $line = $null
            }
        }

        if ($null -eq $line) {
            Write-Host ''
            Write-Host '[end-of-input received -- exiting REPL]'
            Write-Host '(if you did not type exit, your shell may not be running pwsh interactively;'
            Write-Host ' try invoking the script directly from a real terminal session.)'
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
            -NoPdfs          $NoPdfs.IsPresent `
            -Full            $Full.IsPresent
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
