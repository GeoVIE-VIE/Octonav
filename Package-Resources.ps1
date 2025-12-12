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

# Build the embedded resources hashtable
$embeddedCode = @"

# ============================================
# EMBEDDED RESOURCES (Auto-generated)
# ============================================
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# Files: $($resourceFiles.Count)
# To update: Place files in 'resources' folder and run Package-Resources.ps1

`$script:EmbeddedResources = @{
"@

foreach ($file in $resourceFiles) {
    Write-Host "[ENCODING] $($file.Name)..." -ForegroundColor Cyan -NoNewline

    # Read file and convert to Base64
    $fileBytes = [System.IO.File]::ReadAllBytes($file.FullName)
    $base64 = [Convert]::ToBase64String($fileBytes)

    # Add to hashtable (split long strings for readability)
    $embeddedCode += "`n    '$($file.Name)' = '$base64'"

    Write-Host " Done ($([math]::Round($base64.Length / 1KB, 1)) KB encoded)" -ForegroundColor Green
}

$embeddedCode += @"

}

function Get-EmbeddedResourceList {
    <#
    .SYNOPSIS
        Returns list of embedded resource files
    #>
    return `$script:EmbeddedResources.Keys | Sort-Object
}

function Export-EmbeddedResource {
    <#
    .SYNOPSIS
        Exports an embedded resource to the specified path
    .PARAMETER Name
        Name of the resource file to export
    .PARAMETER OutputPath
        Directory to export to (defaults to current directory)
    .PARAMETER Force
        Overwrite existing files
    #>
    param(
        [Parameter(Mandatory=`$true)]
        [string]`$Name,
        [string]`$OutputPath = (Get-Location).Path,
        [switch]`$Force
    )

    if (-not `$script:EmbeddedResources.ContainsKey(`$Name)) {
        throw "Resource '`$Name' not found. Available: `$(`$script:EmbeddedResources.Keys -join ', ')"
    }

    `$outputFile = Join-Path `$OutputPath `$Name

    if ((Test-Path `$outputFile) -and -not `$Force) {
        throw "File already exists: `$outputFile. Use -Force to overwrite."
    }

    `$bytes = [Convert]::FromBase64String(`$script:EmbeddedResources[`$Name])
    [System.IO.File]::WriteAllBytes(`$outputFile, `$bytes)

    return `$outputFile
}

function Export-AllEmbeddedResources {
    <#
    .SYNOPSIS
        Exports all embedded resources to the specified path
    .PARAMETER OutputPath
        Directory to export to (defaults to current directory)
    .PARAMETER Force
        Overwrite existing files
    #>
    param(
        [string]`$OutputPath = (Get-Location).Path,
        [switch]`$Force
    )

    `$exported = @()
    foreach (`$name in `$script:EmbeddedResources.Keys) {
        try {
            `$file = Export-EmbeddedResource -Name `$name -OutputPath `$OutputPath -Force:`$Force
            `$exported += `$file
        }
        catch {
            Write-Warning "Failed to export `$name: `$(`$_.Exception.Message)"
        }
    }
    return `$exported
}

# ============================================
# END EMBEDDED RESOURCES
# ============================================

"@

# Read the target script
Write-Host ""
Write-Host "[INFO] Updating $TargetScript..." -ForegroundColor Cyan

if (-not (Test-Path $TargetScript)) {
    Write-Host "[ERROR] Target script not found: $TargetScript" -ForegroundColor Red
    exit 1
}

$scriptContent = Get-Content $TargetScript -Raw

# Check if embedded resources section already exists
$startMarker = "# ============================================`n# EMBEDDED RESOURCES (Auto-generated)"
$endMarker = "# ============================================`n# END EMBEDDED RESOURCES`n# ============================================"

if ($scriptContent -match "# EMBEDDED RESOURCES \(Auto-generated\)") {
    # Replace existing section
    $pattern = "(?s)# ============================================\r?\n# EMBEDDED RESOURCES \(Auto-generated\).*?# END EMBEDDED RESOURCES\r?\n# ============================================\r?\n"
    $scriptContent = $scriptContent -replace $pattern, $embeddedCode
    Write-Host "[INFO] Replaced existing embedded resources section" -ForegroundColor Green
}
else {
    # Insert after the module imports (find a good spot)
    # Look for the "CREATE TAB CONTROL" section and insert before it
    $insertPoint = "# ============================================`n# CREATE TAB CONTROL"
    if ($scriptContent -match [regex]::Escape($insertPoint)) {
        $scriptContent = $scriptContent -replace [regex]::Escape($insertPoint), "$embeddedCode`n$insertPoint"
        Write-Host "[INFO] Inserted new embedded resources section" -ForegroundColor Green
    }
    else {
        Write-Host "[ERROR] Could not find insertion point in script" -ForegroundColor Red
        exit 1
    }
}

# Save the updated script
$scriptContent | Set-Content $TargetScript -NoNewline
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
