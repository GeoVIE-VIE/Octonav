<#
.SYNOPSIS
    Packages .RDOX files (or any files) into OctoNav as embedded Base64 resources
.DESCRIPTION
    Run this script after modifying your .RDOX files to repackage them into the tool.

    Usage:
    1. Place your .RDOX files in the 'resources' folder
    2. Run this script
    3. The files will be embedded into OctoNav-GUI-v2.3.ps1
.EXAMPLE
    .\Package-Resources.ps1
.EXAMPLE
    .\Package-Resources.ps1 -ResourceFolder "C:\MyReports" -FileTypes "*.rdox","*.xml"
#>

param(
    [string]$ResourceFolder = "$PSScriptRoot\resources",
    [string[]]$FileTypes = @("*.rdox", "*.xml", "*.txt"),
    [string]$TargetScript = "$PSScriptRoot\OctoNav-GUI-v2.3.ps1"
)

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  OctoNav Resource Packager" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Create resources folder if it doesn't exist
if (-not (Test-Path $ResourceFolder)) {
    New-Item -ItemType Directory -Path $ResourceFolder -Force | Out-Null
    Write-Host "[INFO] Created resources folder: $ResourceFolder" -ForegroundColor Yellow
    Write-Host "[INFO] Place your .RDOX files in this folder and run this script again." -ForegroundColor Yellow
    Write-Host ""
    exit 0
}

# Find all resource files
$resourceFiles = @()
foreach ($type in $FileTypes) {
    $resourceFiles += Get-ChildItem -Path $ResourceFolder -Filter $type -File -ErrorAction SilentlyContinue
}

if ($resourceFiles.Count -eq 0) {
    Write-Host "[WARNING] No resource files found in: $ResourceFolder" -ForegroundColor Yellow
    Write-Host "[INFO] Supported file types: $($FileTypes -join ', ')" -ForegroundColor Gray
    Write-Host "[INFO] Place your files there and run this script again." -ForegroundColor Gray
    exit 0
}

Write-Host "[INFO] Found $($resourceFiles.Count) file(s) to embed:" -ForegroundColor Green
foreach ($file in $resourceFiles) {
    $sizeKB = [math]::Round($file.Length / 1KB, 2)
    Write-Host "       - $($file.Name) ($sizeKB KB)" -ForegroundColor White
}
Write-Host ""

# Build the embedded resources hashtable entries
$resourceEntries = @()
foreach ($file in $resourceFiles) {
    Write-Host "[ENCODING] $($file.Name)..." -ForegroundColor Cyan -NoNewline

    # Read file and convert to Base64
    $fileBytes = [System.IO.File]::ReadAllBytes($file.FullName)
    $base64 = [Convert]::ToBase64String($fileBytes)

    # Add to entries list
    $resourceEntries += "    '$($file.Name)' = '$base64'"

    Write-Host " Done ($([math]::Round($base64.Length / 1KB, 1)) KB encoded)" -ForegroundColor Green
}

# Build the complete embedded code block
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$resourceHashtable = $resourceEntries -join "`n"

$embeddedCodeLines = @(
    ''
    '# ============================================'
    '# EMBEDDED RESOURCES (Auto-generated)'
    '# ============================================'
    "# Generated: $timestamp"
    "# Files: $($resourceFiles.Count)"
    '# To update: Place files in ''resources'' folder and run Package-Resources.ps1'
    ''
    '$script:EmbeddedResources = @{'
    $resourceHashtable
    '}'
    ''
    'function Get-EmbeddedResourceList {'
    '    <#'
    '    .SYNOPSIS'
    '        Returns list of embedded resource files'
    '    #>'
    '    return $script:EmbeddedResources.Keys | Sort-Object'
    '}'
    ''
    'function Export-EmbeddedResource {'
    '    <#'
    '    .SYNOPSIS'
    '        Exports an embedded resource to the specified path'
    '    .PARAMETER Name'
    '        Name of the resource file to export'
    '    .PARAMETER OutputPath'
    '        Directory to export to (defaults to current directory)'
    '    .PARAMETER Force'
    '        Overwrite existing files'
    '    #>'
    '    param('
    '        [Parameter(Mandatory=$true)]'
    '        [string]$Name,'
    '        [string]$OutputPath = (Get-Location).Path,'
    '        [switch]$Force'
    '    )'
    ''
    '    if (-not $script:EmbeddedResources.ContainsKey($Name)) {'
    '        throw "Resource ''$Name'' not found. Available: $($script:EmbeddedResources.Keys -join '', '')"'
    '    }'
    ''
    '    $outputFile = Join-Path $OutputPath $Name'
    ''
    '    if ((Test-Path $outputFile) -and -not $Force) {'
    '        throw "File already exists: $outputFile. Use -Force to overwrite."'
    '    }'
    ''
    '    $bytes = [Convert]::FromBase64String($script:EmbeddedResources[$Name])'
    '    [System.IO.File]::WriteAllBytes($outputFile, $bytes)'
    ''
    '    return $outputFile'
    '}'
    ''
    'function Export-AllEmbeddedResources {'
    '    <#'
    '    .SYNOPSIS'
    '        Exports all embedded resources to the specified path'
    '    .PARAMETER OutputPath'
    '        Directory to export to (defaults to current directory)'
    '    .PARAMETER Force'
    '        Overwrite existing files'
    '    #>'
    '    param('
    '        [string]$OutputPath = (Get-Location).Path,'
    '        [switch]$Force'
    '    )'
    ''
    '    $exported = @()'
    '    foreach ($resName in $script:EmbeddedResources.Keys) {'
    '        try {'
    '            $file = Export-EmbeddedResource -Name $resName -OutputPath $OutputPath -Force:$Force'
    '            $exported += $file'
    '        }'
    '        catch {'
    '            Write-Warning "Failed to export $($resName): $($_.Exception.Message)"'
    '        }'
    '    }'
    '    return $exported'
    '}'
    ''
    '# ============================================'
    '# END EMBEDDED RESOURCES'
    '# ============================================'
    ''
)

$embeddedCode = $embeddedCodeLines -join "`r`n"

# Read the target script
Write-Host ""
Write-Host "[INFO] Updating $TargetScript..." -ForegroundColor Cyan

if (-not (Test-Path $TargetScript)) {
    Write-Host "[ERROR] Target script not found: $TargetScript" -ForegroundColor Red
    exit 1
}

$scriptLines = Get-Content $TargetScript

# Find the markers
$startMarker = "# EMBEDDED RESOURCES (Auto-generated)"
$endMarker = "# END EMBEDDED RESOURCES"
$insertMarker = "# CREATE TAB CONTROL"

$startIndex = -1
$endIndex = -1
$insertIndex = -1

for ($i = 0; $i -lt $scriptLines.Count; $i++) {
    if ($scriptLines[$i] -match [regex]::Escape($startMarker)) {
        $startIndex = $i - 1  # Include the separator line before
    }
    if ($scriptLines[$i] -match [regex]::Escape($endMarker)) {
        $endIndex = $i + 1  # Include the separator line after
    }
    if ($scriptLines[$i] -match [regex]::Escape($insertMarker)) {
        $insertIndex = $i - 1  # Insert before the separator line
    }
}

$newScriptLines = @()

if ($startIndex -ge 0 -and $endIndex -gt $startIndex) {
    # Replace existing section
    Write-Host "[INFO] Replacing existing embedded resources section (lines $startIndex to $endIndex)" -ForegroundColor Green

    # Add lines before the embedded section
    $newScriptLines += $scriptLines[0..($startIndex - 1)]

    # Add the new embedded code
    $newScriptLines += $embeddedCodeLines

    # Add lines after the embedded section
    if ($endIndex -lt $scriptLines.Count - 1) {
        $newScriptLines += $scriptLines[($endIndex + 1)..($scriptLines.Count - 1)]
    }
}
elseif ($insertIndex -ge 0) {
    # Insert new section
    Write-Host "[INFO] Inserting new embedded resources section at line $insertIndex" -ForegroundColor Green

    # Add lines before the insert point
    $newScriptLines += $scriptLines[0..($insertIndex - 1)]

    # Add the new embedded code
    $newScriptLines += $embeddedCodeLines

    # Add remaining lines
    $newScriptLines += $scriptLines[$insertIndex..($scriptLines.Count - 1)]
}
else {
    Write-Host "[ERROR] Could not find insertion point in script" -ForegroundColor Red
    exit 1
}

# Save the updated script
$newScriptLines | Set-Content $TargetScript -Encoding UTF8

Write-Host "[SUCCESS] Resources embedded successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Packaging Complete!" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Embedded files:" -ForegroundColor White
foreach ($file in $resourceFiles) {
    Write-Host "  - $($file.Name)" -ForegroundColor Gray
}
Write-Host ""
Write-Host "Users can extract files using:" -ForegroundColor Yellow
Write-Host "  - Tools menu > 'Export Resources' in the GUI" -ForegroundColor Gray
Write-Host "  - Or run: Export-AllEmbeddedResources" -ForegroundColor Gray
Write-Host ""
