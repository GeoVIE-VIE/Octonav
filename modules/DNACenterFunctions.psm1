<#
.SYNOPSIS
    DNA Center API Functions Module
.DESCRIPTION
    PowerShell module containing DNA Center API functions for network device management,
    topology analysis, compliance checking, and advanced operations including path tracing
    and command execution.
.AUTHOR
    Integrated by Claude - From OctoNav GUI
.VERSION
    1.0 - Initial module release with 26 DNA Center API functions
.NOTES
    This module provides comprehensive DNA Center integration including:
    - Network device discovery and inventory
    - Health monitoring (network and client)
    - Neighbor discovery (OSPF, CDP, LLDP)
    - Configuration management
    - Advanced troubleshooting (path trace, command runner)
#>

# Enable visual styles for GUI operations
Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue

# Handle errors gracefully
$ErrorActionPreference = "Stop"

# ============================================
# CERTIFICATE VALIDATION BYPASS & TLS SETUP
# ============================================
# Required for DNA Center API calls with self-signed certificates
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
    $certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback == null)
            {
                ServicePointManager.ServerCertificateValidationCallback +=
                    delegate
                    (
                        Object obj,
                        X509Certificate certificate,
                        X509Chain chain,
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
}
[ServerCertificateValidationCallback]::Ignore()
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# ============================================
# GLOBAL VARIABLES
# ============================================

# These should be set by the caller before using these functions
if (-not (Get-Variable -Name "script:dnaCenterToken" -ErrorAction SilentlyContinue)) {
    $global:dnaCenterToken = $null
}
if (-not (Get-Variable -Name "script:dnaCenterTokenExpiry" -ErrorAction SilentlyContinue)) {
    $global:dnaCenterTokenExpiry = $null
}
if (-not (Get-Variable -Name "script:dnaCenterHeaders" -ErrorAction SilentlyContinue)) {
    $global:dnaCenterHeaders = $null
}
if (-not (Get-Variable -Name "script:selectedDnaCenter" -ErrorAction SilentlyContinue)) {
    $global:selectedDnaCenter = $null
}
if (-not (Get-Variable -Name "script:allDNADevices" -ErrorAction SilentlyContinue)) {
    $global:allDNADevices = @()
}
if (-not (Get-Variable -Name "script:selectedDNADevices" -ErrorAction SilentlyContinue)) {
    $global:selectedDNADevices = @()
}
if (-not (Get-Variable -Name "script:outputDir" -ErrorAction SilentlyContinue)) {
    $script:outputDir = if ($env:OCTONAV_OUTPUT_DIR) { $env:OCTONAV_OUTPUT_DIR } else { "C:\DNACenter_Reports" }
}

# ============================================
# VALIDATION FUNCTIONS
# ============================================

function Test-IPAddress {
    param([string]$IPAddress)

    if ([string]::IsNullOrWhiteSpace($IPAddress)) {
        return $false
    }

    # Regex for valid IPv4 address
    if ($IPAddress -notmatch '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
        return $false
    }

    # Additional validation: try to parse as IPAddress
    try {
        $null = [System.Net.IPAddress]::Parse($IPAddress)
        return $true
    } catch {
        return $false
    }
}

function Get-SafeFileName {
    param(
        [string]$InputName,
        [string]$Fallback = "output"
    )

    if ([string]::IsNullOrWhiteSpace($InputName)) {
        return $Fallback
    }

    # Get only the filename component, stripping any path separators
    # This prevents path traversal by removing directory components
    try {
        $safeName = [System.IO.Path]::GetFileName($InputName)
    } catch {
        # If GetFileName fails, use the input but sanitize it
        $safeName = $InputName
    }

    # Remove ALL invalid filename characters using .NET
    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
    foreach ($char in $invalidChars) {
        $safeName = $safeName.Replace($char, '_')
    }

    # Additional sanitization - remove path traversal attempts
    $safeName = $safeName -replace '\.\.+', '_'  # Multiple dots
    $safeName = $safeName -replace '^\.+', ''     # Leading dots
    $safeName = $safeName.Trim()

    # Ensure we don't have an empty or whitespace-only result
    if ([string]::IsNullOrWhiteSpace($safeName)) {
        return $Fallback
    }

    # Limit length to prevent filesystem issues (max 255 chars for most filesystems)
    if ($safeName.Length -gt 200) {
        $safeName = $safeName.Substring(0, 200)
    }

    return $safeName
}

# Apply filters to output lines - matches DNACAPEiv6_COMPLETE behavior
function Invoke-Filters {
    param(
        [string[]]$Lines,
        [string[]]$Filters
    )

    # No filters = return all lines
    if ($Filters.Count -eq 0) {
        return $Lines
    }

    $matchedLines = @()
    foreach ($line in $Lines) {
        foreach ($pattern in $Filters) {
            # Use -like for simple substring matching (case-insensitive)
            if ($line -like "*$pattern*") {
                $matchedLines += $line
                break  # Stop checking other patterns once matched (OR logic)
            }
        }
    }

    return $matchedLines
}

function Test-DnaFilterInput {
    param(
        [string]$Value,
        [string]$FieldName,
        [System.Windows.Forms.RichTextBox]$LogBox
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $true
    }

    $trimmed = $Value.Trim()

    if ($trimmed.Length -gt 128) {
        Write-Log -Message "$FieldName is too long (max 128 characters)" -Color "Red" -LogBox $LogBox
        return $false
    }

    if ($trimmed -notmatch '^[a-zA-Z0-9_.:\-\s]+$') {
        Write-Log -Message "$FieldName contains invalid characters (only alphanumeric, dots, colons, hyphens, underscores allowed)" -Color "Red" -LogBox $LogBox
        return $false
    }

    return $true
}

# ============================================
# HELPER FUNCTIONS - GENERAL
# ============================================

function Get-SanitizedErrorMessage {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    if (-not $ErrorRecord) {
        return "An unknown error occurred"
    }

    # Get base error message without sensitive details
    $message = $ErrorRecord.Exception.Message

    # Remove potentially sensitive information
    # Remove file paths
    $message = $message -replace '[A-Z]:\\[^\s]+', '[PATH]'
    $message = $message -replace '/[^\s]+', '[PATH]'

    # Remove IP addresses (both IPv4 and IPv6)
    $message = $message -replace '\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP]'
    $message = $message -replace '\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b', '[IPv6]'

    # Remove usernames (common patterns)
    $message = $message -replace 'user(name)?[:\s]+[^\s]+', 'user: [REDACTED]'

    # Remove stack trace information
    $message = $message -split "`n" | Select-Object -First 1

    # Limit length
    if ($message.Length -gt 200) {
        $message = $message.Substring(0, 197) + "..."
    }

    return $message
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Color = "Black",
        [System.Windows.Forms.RichTextBox]$LogBox
    )

    if ($LogBox) {
        try {
            $LogBox.Invoke([Action]{
                $LogBox.SelectionStart = $LogBox.TextLength
                $LogBox.SelectionLength = 0
                $LogBox.SelectionColor = switch ($Color) {
                    "Green" { [System.Drawing.Color]::Green }
                    "Red" { [System.Drawing.Color]::Red }
                    "Yellow" { [System.Drawing.Color]::DarkOrange }
                    "Cyan" { [System.Drawing.Color]::DarkCyan }
                    "Magenta" { [System.Drawing.Color]::Magenta }
                    "Gray" { [System.Drawing.Color]::Gray }
                    default { [System.Drawing.Color]::Black }
                }
                $timestamp = Get-Date -Format "HH:mm:ss"
                $LogBox.AppendText("[$timestamp] $Message`r`n")
                $LogBox.SelectionColor = $LogBox.ForeColor
                $LogBox.ScrollToCaret()
            })
        } catch {
            # Silently fail if log box is not available
        }
    }
}

# ============================================
# DNA CENTER HELPER FUNCTIONS
# ============================================

function ConvertTo-ReadableTimestamp {
    param([object]$Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [DateTime]) {
        return ($Value.ToUniversalTime().ToString("u"))
    }

    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

        if ($Value -match '^-?\d+$') {
            try {
                return ConvertTo-ReadableTimestamp([long]$Value)
            } catch {
                return $Value
            }
        }

        try {
            $parsed = Get-Date $Value
            return ($parsed.ToUniversalTime().ToString("u"))
        } catch {
            return $Value
        }
    }

    if ($Value -is [long] -or $Value -is [int]) {
        $numeric = [long]$Value
        try {
            if ($numeric -gt 9999999999) {
                return ([DateTimeOffset]::FromUnixTimeMilliseconds($numeric)).UtcDateTime.ToString("u")
            } elseif ($numeric -gt 0) {
                return ([DateTimeOffset]::FromUnixTimeSeconds($numeric)).UtcDateTime.ToString("u")
            }
        } catch {
            return $numeric.ToString()
        }
        return $numeric.ToString()
    }

    return $Value.ToString()
}

function Wait-ForTask {
    param(
        [string]$TaskId,
        [hashtable]$Headers,
        [string]$DnaCenter,
        [int]$TimeoutSeconds = 300,
        [System.Windows.Forms.RichTextBox]$LogBox
    )

    $startTime = Get-Date
    $completed = $false

    Write-Log -Message "Waiting for task to complete..." -Color "Yellow" -LogBox $LogBox

    while (-not $completed) {
        Start-Sleep -Seconds 2

        try {
            $taskResponse = Invoke-RestMethod -Uri "$DnaCenter/dna/intent/api/v1/task/$TaskId" -Method Get -Headers $Headers

            if ($taskResponse.response) {
                $task = $taskResponse.response

                if ($task.isError) {
                    Write-Log -Message "Task failed: $($task.failureReason)" -Color "Red" -LogBox $LogBox
                    return $null
                }

                if ($task.endTime) {
                    $completed = $true
                    Write-Log -Message "Task completed successfully" -Color "Green" -LogBox $LogBox
                    return $task
                }

                if ($task.progress) {
                    Write-Log -Message "Progress: $($task.progress)" -Color "Cyan" -LogBox $LogBox
                }
            }
        } catch {
            Write-Log -Message "Error checking task status: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
            return $null
        }

        $elapsed = ((Get-Date) - $startTime).TotalSeconds
        if ($elapsed -gt $TimeoutSeconds) {
            Write-Log -Message "Task timed out after $TimeoutSeconds seconds" -Color "Red" -LogBox $LogBox
            return $null
        }
    }

    return $taskResponse.response
}

function Get-TaskFileId {
    param([psobject]$TaskInfo)

    if (-not $TaskInfo) { return $null }

    if ($TaskInfo.fileId) {
        return $TaskInfo.fileId
    }

    if ($TaskInfo.additionalStatusURL -and $TaskInfo.additionalStatusURL -match '/file/([a-f0-9\-]+)') {
        return $Matches[1]
    }

    if ($TaskInfo.progress) {
        try {
            $progressObj = $TaskInfo.progress | ConvertFrom-Json
            if ($progressObj.fileId) {
                return $progressObj.fileId
            }
        } catch {
            if ($TaskInfo.progress -match '"fileId"\s*:\s*"([^"]+)"') {
                return $Matches[1]
            }
        }
    }

    return $null
}

# ============================================
# CONNECTION FUNCTIONS
# ============================================

function Test-DNACTokenValid {
    <#
    .SYNOPSIS
        Tests if DNA Center token is valid and not expired
    .DESCRIPTION
        Checks if the token exists and hasn't expired (with 5 minute buffer)
    .OUTPUTS
        Boolean - $true if token is valid, $false otherwise
    #>
    # Check if token exists and is not expired
    if (-not $global:dnaCenterToken) {
        return $false
    }

    if ($global:dnaCenterTokenExpiry) {
        # Check if token has expired (with 5 minute buffer)
        $expiryWithBuffer = $global:dnaCenterTokenExpiry.AddMinutes(-5)
        if ((Get-Date) -gt $expiryWithBuffer) {
            Write-Verbose "DNA Center token has expired"
            return $false
        }
    }

    return $true
}

function Connect-DNACenter {
    <#
    .SYNOPSIS
        Authenticates to DNA Center and obtains API token
    .DESCRIPTION
        Establishes connection to DNA Center using provided credentials
    .PARAMETER DnaCenter
        DNA Center server URL (e.g., https://dnac.example.com)
    .PARAMETER Username
        Username for authentication
    .PARAMETER Password
        Password for authentication
    .PARAMETER LogBox
        Optional RichTextBox for logging output
    .OUTPUTS
        Boolean - $true if authentication successful, $false otherwise
    #>
    param(
        [string]$DnaCenter,
        [string]$Username,
        [string]$Password,
        [System.Windows.Forms.RichTextBox]$LogBox
    )

    $base64AuthInfo = $null

    try {
        # Validate inputs
        if ([string]::IsNullOrWhiteSpace($Username) -or [string]::IsNullOrWhiteSpace($Password)) {
            Write-Log -Message "Username and password are required" -Color "Red" -LogBox $LogBox
            return $false
        }

        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $Username, $Password)))

        $authUrl = "$DnaCenter/dna/system/api/v1/auth/token"
        $headers = @{
            "Authorization" = "Basic $base64AuthInfo"
            "Content-Type" = "application/json"
        }

        Write-Log -Message "Authenticating to DNA Center..." -Color "Yellow" -LogBox $LogBox
        $response = Invoke-RestMethod -Uri $authUrl -Method Post -Headers $headers -TimeoutSec 30

        if ($response -and $response.Token) {
            Write-Log -Message "Authentication successful!" -Color "Green" -LogBox $LogBox
            $global:dnaCenterToken = $response.Token

            # DNA Center tokens typically expire after 1 hour
            $global:dnaCenterTokenExpiry = (Get-Date).AddHours(1)

            $global:dnaCenterHeaders = @{
                "X-Auth-Token" = $response.Token
                "Content-Type" = "application/json"
            }
            return $true
        } else {
            Write-Log -Message "No token received from server" -Color "Red" -LogBox $LogBox
            return $false
        }
    } catch {
        $sanitizedError = Get-SanitizedErrorMessage -ErrorRecord $_
        Write-Log -Message "Authentication failed: $sanitizedError" -Color "Red" -LogBox $LogBox
        return $false
    } finally {
        # Clear sensitive data from memory
        if ($base64AuthInfo) {
            $base64AuthInfo = $null
        }
        if ($Password) {
            $Password = $null
        }
        # Force garbage collection to clear sensitive data
        [System.GC]::Collect()
    }
}

function Get-AllDNADevices {
    <#
    .SYNOPSIS
        Gets all network devices from DNA Center
    .DESCRIPTION
        Retrieves complete device inventory with pagination support
    .PARAMETER LogBox
        Optional RichTextBox for logging output
    .OUTPUTS
        Boolean - $true if devices loaded successfully, $false otherwise
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    if (-not $global:dnaCenterHeaders) {
        Write-Log -Message "Not authenticated to DNA Center" -Color "Red" -LogBox $LogBox
        return $false
    }

    Write-Log -Message "Loading network devices..." -Color "Yellow" -LogBox $LogBox

    try {
        $pageSize = 500
        $offset = 1
        $pagesFetched = 0
        $aggregatedDevices = [System.Collections.Generic.List[object]]::new()

        while ($true) {
            $uri = "$($global:selectedDnaCenter)/dna/intent/api/v1/network-device?offset=$offset&limit=$pageSize"
            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 60

            $pageDevices = @()
            if ($response -and $response.response) {
                $pageDevices = $response.response
            }

            $retrievedCount = if ($pageDevices) { $pageDevices.Count } else { 0 }

            if ($retrievedCount -le 0) {
                if ($pagesFetched -eq 0) {
                    Write-Log -Message "No devices returned from API" -Color "Red" -LogBox $LogBox
                }
                break
            }

            foreach ($device in $pageDevices) {
                $aggregatedDevices.Add($device)
            }

            $pagesFetched++
            Write-Log -Message "Retrieved $retrievedCount device(s) from page $pagesFetched" -Color "Cyan" -LogBox $LogBox

            if ($retrievedCount -lt $pageSize) {
                break
            }

            $offset += $pageSize
        }

        if ($aggregatedDevices.Count -gt 0) {
            $global:allDNADevices = $aggregatedDevices.ToArray()
            $global:selectedDNADevices = @()
            Write-Log -Message "Loaded $($global:allDNADevices.Count) devices" -Color "Green" -LogBox $LogBox
            return $true
        }

        return $false
    } catch {
        Write-Log -Message "Failed to load devices: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
        return $false
    }
}

function Select-DNADevices {
    <#
    .SYNOPSIS
        Selects loaded devices by hostname, IP, role, and family
    .DESCRIPTION
        Applies filter criteria to select a subset of loaded devices
    .PARAMETER Hostname
        Hostname filter (supports partial match)
    .PARAMETER IPAddress
        Management IP address filter
    .PARAMETER Role
        Device role filter (supports partial match)
    .PARAMETER Family
        Device family filter (supports partial match)
    .PARAMETER LogBox
        Optional RichTextBox for logging output
    .OUTPUTS
        Array of filtered device objects
    #>
    param(
        [string]$Hostname,
        [string]$IPAddress,
        [string]$Role,
        [string]$Family,
        [System.Windows.Forms.RichTextBox]$LogBox
    )

    if (-not $global:allDNADevices -or $global:allDNADevices.Count -eq 0) {
        Write-Log -Message "No devices loaded" -Color "Red" -LogBox $LogBox
        return @()
    }

    if (-not (Test-DnaFilterInput -Value $Hostname -FieldName "Hostname" -LogBox $LogBox)) { return @() }
    if (-not (Test-DnaFilterInput -Value $Role -FieldName "Role" -LogBox $LogBox)) { return @() }
    if (-not (Test-DnaFilterInput -Value $Family -FieldName "Family" -LogBox $LogBox)) { return @() }

    if (-not [string]::IsNullOrWhiteSpace($IPAddress)) {
        $trimmedIp = $IPAddress.Trim()
        if (-not (Test-IPAddress -IPAddress $trimmedIp)) {
            Write-Log -Message "Invalid IP address filter" -Color "Red" -LogBox $LogBox
            return @()
        }
        $IPAddress = $trimmedIp
    }

    $hostPattern = if (-not [string]::IsNullOrWhiteSpace($Hostname)) { [regex]::Escape($Hostname.Trim()) } else { $null }
    $rolePattern = if (-not [string]::IsNullOrWhiteSpace($Role)) { [regex]::Escape($Role.Trim()) } else { $null }
    $familyPattern = if (-not [string]::IsNullOrWhiteSpace($Family)) { [regex]::Escape($Family.Trim()) } else { $null }

    $filtered = $global:allDNADevices | Where-Object {
        ($null -eq $hostPattern -or ($_.hostname -and $_.hostname -match $hostPattern)) -and
        ([string]::IsNullOrWhiteSpace($IPAddress) -or ($_.managementIpAddress -eq $IPAddress)) -and
        ($null -eq $rolePattern -or ($_.role -and $_.role -match $rolePattern)) -and
        ($null -eq $familyPattern -or ($_.family -and $_.family -match $familyPattern))
    }

    $global:selectedDNADevices = $filtered

    $targetDescription = @()
    if ($hostPattern) { $targetDescription += "Hostname" }
    if ($IPAddress) { $targetDescription += "IP" }
    if ($rolePattern) { $targetDescription += "Role" }
    if ($familyPattern) { $targetDescription += "Family" }

    $criteria = if ($targetDescription.Count -gt 0) { $targetDescription -join ", " } else { "No" }

    Write-Log -Message "Applied $criteria filter(s). Selected $($filtered.Count) device(s)." -Color "Green" -LogBox $LogBox

    return $filtered
}

function Reset-DNADeviceSelection {
    <#
    .SYNOPSIS
        Resets device selection to all loaded devices
    .DESCRIPTION
        Clears any applied filters and resets selection to all loaded devices
    .PARAMETER LogBox
        Optional RichTextBox for logging output
    #>
    param(
        [System.Windows.Forms.RichTextBox]$LogBox
    )

    if (-not $global:allDNADevices -or $global:allDNADevices.Count -eq 0) {
        Write-Log -Message "No devices loaded" -Color "Red" -LogBox $LogBox
        return
    }

    $global:selectedDNADevices = $global:allDNADevices
    Write-Log -Message "Device selection reset to all loaded devices ($($global:allDNADevices.Count) devices)" -Color "Green" -LogBox $LogBox
}

# ============================================
# DNA CENTER API FUNCTIONS
# ============================================

function Get-NetworkDevicesBasic {
    <#
    .SYNOPSIS
        Retrieves basic network device information
    .DESCRIPTION
        Exports selected devices with basic info (hostname, IP, serial, platform, etc.)
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching network devices (basic info)..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($global:selectedDNADevices.Count -gt 0) { $global:selectedDNADevices } else { $global:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $deviceList = foreach ($device in $devices) {
            [PSCustomObject]@{
                Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                IPAddress = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                SerialNumber = if ($device.serialNumber) { $device.serialNumber } else { "N/A" }
                Platform = if ($device.platformId) { $device.platformId } else { "N/A" }
                SoftwareVersion = if ($device.softwareVersion) { $device.softwareVersion } else { "N/A" }
                Role = if ($device.role) { $device.role } else { "N/A" }
                ReachabilityStatus = if ($device.reachabilityStatus) { $device.reachabilityStatus } else { "N/A" }
                Family = if ($device.family) { $device.family } else { "N/A" }
                Type = if ($device.type) { $device.type } else { "N/A" }
                UpTime = if ($device.upTime) { $device.upTime } else { "N/A" }
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "NetworkDevices_Basic_$timestamp.csv"
        $deviceList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
        Write-Log -Message "Total devices: $($deviceList.Count)" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-NetworkDevicesDetailed {
    <#
    .SYNOPSIS
        Retrieves detailed network device information
    .DESCRIPTION
        Exports selected devices with comprehensive details
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching network devices (detailed info)..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($global:selectedDNADevices.Count -gt 0) { $global:selectedDNADevices } else { $global:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $deviceList = foreach ($device in $devices) {
            [PSCustomObject]@{
                Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                IPAddress = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                MacAddress = if ($device.macAddress) { $device.macAddress } else { "N/A" }
                SerialNumber = if ($device.serialNumber) { $device.serialNumber } else { "N/A" }
                Platform = if ($device.platformId) { $device.platformId } else { "N/A" }
                SoftwareVersion = if ($device.softwareVersion) { $device.softwareVersion } else { "N/A" }
                SoftwareType = if ($device.softwareType) { $device.softwareType } else { "N/A" }
                Role = if ($device.role) { $device.role } else { "N/A" }
                ReachabilityStatus = if ($device.reachabilityStatus) { $device.reachabilityStatus } else { "N/A" }
                Family = if ($device.family) { $device.family } else { "N/A" }
                Type = if ($device.type) { $device.type } else { "N/A" }
                Series = if ($device.series) { $device.series } else { "N/A" }
                Location = if ($device.location) { $device.location } else { "N/A" }
                MemorySize = if ($device.memorySize) { $device.memorySize } else { "N/A" }
                LastUpdated = if ($device.lastUpdated) { $device.lastUpdated } else { "N/A" }
                UpTime = if ($device.upTime) { $device.upTime } else { "N/A" }
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "NetworkDevices_Detailed_$timestamp.csv"
        $deviceList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
        Write-Log -Message "Total devices: $($deviceList.Count)" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-DeviceInventoryCount {
    <#
    .SYNOPSIS
        Counts and groups devices by family and role
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Calculating device inventory counts..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($global:selectedDNADevices.Count -gt 0) { $global:selectedDNADevices } else { $global:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

        # By Family
        $byFamily = $devices | Group-Object -Property family | ForEach-Object {
            [PSCustomObject]@{
                Family = if ($_.Name) { $_.Name } else { "Unknown" }
                Count = $_.Count
            }
        } | Sort-Object -Property Count -Descending

        $csvPath = Join-Path -Path $script:outputDir -ChildPath "DeviceInventory_ByFamily_$timestamp.csv"
        $byFamily | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Log -Message "By Family: $csvPath" -Color "Green" -LogBox $LogBox

        # By Role
        $byRole = $devices | Group-Object -Property role | ForEach-Object {
            [PSCustomObject]@{
                Role = if ($_.Name) { $_.Name } else { "Unknown" }
                Count = $_.Count
            }
        } | Sort-Object -Property Count -Descending

        $csvPath = Join-Path -Path $script:outputDir -ChildPath "DeviceInventory_ByRole_$timestamp.csv"
        $byRole | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Log -Message "By Role: $csvPath" -Color "Green" -LogBox $LogBox

        Write-Log -Message "Total devices: $($devices.Count)" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-NetworkHealth {
    <#
    .SYNOPSIS
        Retrieves overall network health metrics
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching network health..." -Color "Yellow" -LogBox $LogBox

    try {
        $timestamp_ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/network-health?timestamp=$timestamp_ms" -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 30

        $healthList = @()
        if ($response -and $response.response) {
            foreach ($item in $response.response) {
                $healthList += [PSCustomObject]@{
                    HealthCategory = if ($item.healthCategory) { $item.healthCategory } else { "N/A" }
                    TotalCount = if ($item.totalCount) { $item.totalCount } else { 0 }
                    GoodCount = if ($item.goodCount) { $item.goodCount } else { 0 }
                    FairCount = if ($item.fairCount) { $item.fairCount } else { 0 }
                    BadCount = if ($item.badCount) { $item.badCount } else { 0 }
                    HealthScore = if ($item.healthScore) { $item.healthScore } else { 0 }
                }
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "NetworkHealth_$timestamp.csv"
        $healthList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Failed to retrieve network health: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-ClientHealth {
    <#
    .SYNOPSIS
        Retrieves wireless client health metrics
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching client health..." -Color "Yellow" -LogBox $LogBox

    try {
        $timestamp_ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/client-health?timestamp=$timestamp_ms" -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 30

        $clientList = @()
        if ($response -and $response.response) {
            foreach ($client in $response.response) {
                $clientList += [PSCustomObject]@{
                    SiteId = if ($client.siteId) { $client.siteId } else { "N/A" }
                    TotalCount = if ($client.scoreDetail) { $client.scoreDetail.totalCount } else { 0 }
                    ConnectedCount = if ($client.scoreDetail) { $client.scoreDetail.connectedCount } else { 0 }
                    GoodCount = if ($client.scoreDetail -and $client.scoreDetail.clientCount) { $client.scoreDetail.clientCount.good } else { 0 }
                    FairCount = if ($client.scoreDetail -and $client.scoreDetail.clientCount) { $client.scoreDetail.clientCount.fair } else { 0 }
                    PoorCount = if ($client.scoreDetail -and $client.scoreDetail.clientCount) { $client.scoreDetail.clientCount.poor } else { 0 }
                    HealthScore = if ($client.scoreDetail) { $client.scoreDetail.healthScore } else { 0 }
                }
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "ClientHealth_$timestamp.csv"
        $clientList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Failed to retrieve client health: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-DeviceReachability {
    <#
    .SYNOPSIS
        Retrieves device reachability status
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching device reachability status..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($global:selectedDNADevices.Count -gt 0) { $global:selectedDNADevices } else { $global:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $reachabilityList = foreach ($device in $devices) {
            [PSCustomObject]@{
                Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                IPAddress = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                ReachabilityStatus = if ($device.reachabilityStatus) { $device.reachabilityStatus } else { "N/A" }
                LastUpdated = if ($device.lastUpdated) { $device.lastUpdated } else { "N/A" }
                CollectionStatus = if ($device.collectionStatus) { $device.collectionStatus } else { "N/A" }
                Family = if ($device.family) { $device.family } else { "N/A" }
                Role = if ($device.role) { $device.role } else { "N/A" }
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "DeviceReachability_$timestamp.csv"
        $reachabilityList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-SitesLocations {
    <#
    .SYNOPSIS
        Retrieves site and location information
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching sites and locations..." -Color "Yellow" -LogBox $LogBox

    try {
        $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/site" -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 30

        $siteList = @()
        if ($response -and $response.response) {
            foreach ($site in $response.response) {
                $siteList += [PSCustomObject]@{
                    SiteName = if ($site.name) { $site.name } else { "N/A" }
                    SiteId = if ($site.id) { $site.id } else { "N/A" }
                    ParentId = if ($site.parentId) { $site.parentId } else { "N/A" }
                    Latitude = if ($site.latitude) { $site.latitude } else { "N/A" }
                    Longitude = if ($site.longitude) { $site.longitude } else { "N/A" }
                }
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "Sites_$timestamp.csv"
        $siteList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Failed to retrieve sites: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-ComplianceStatus {
    <#
    .SYNOPSIS
        Retrieves compliance status for devices
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching compliance status..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($global:selectedDNADevices.Count -gt 0) { $global:selectedDNADevices } else { $global:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $complianceList = @()

        foreach ($device in $devices) {
            try {
                $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/compliance/$($device.id)" -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 15

                if ($response -and $response.response) {
                    $complianceList += [PSCustomObject]@{
                        Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                        IPAddress = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                        ComplianceStatus = if ($response.response.status) { $response.response.status } else { "N/A" }
                        LastSyncTime = if ($response.response.lastSyncTime) { $response.response.lastSyncTime } else { "N/A" }
                    }
                }
            } catch {
                $complianceList += [PSCustomObject]@{
                    Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                    IPAddress = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                    ComplianceStatus = "Error: $($_.Exception.Message)"
                    LastSyncTime = "N/A"
                }
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "ComplianceStatus_$timestamp.csv"
        $complianceList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-Templates {
    <#
    .SYNOPSIS
        Retrieves configuration templates
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching configuration templates..." -Color "Yellow" -LogBox $LogBox

    try {
        $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/template-programmer/template" -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 30

        $templateList = @()
        $templates = if ($response.response) { $response.response } else { $response }

        foreach ($template in $templates) {
            $templateList += [PSCustomObject]@{
                TemplateName = if ($template.name) { $template.name } else { "N/A" }
                ProjectName = if ($template.projectName) { $template.projectName } else { "N/A" }
                TemplateId = if ($template.templateId) { $template.templateId } else { "N/A" }
                SoftwareType = if ($template.softwareType) { $template.softwareType } else { "N/A" }
                SoftwareVersion = if ($template.softwareVersion) { $template.softwareVersion } else { "N/A" }
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "Templates_$timestamp.csv"
        $templateList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Failed to retrieve templates: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-PhysicalTopology {
    <#
    .SYNOPSIS
        Retrieves network physical topology information
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching physical topology..." -Color "Yellow" -LogBox $LogBox

    try {
        $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/topology/physical-topology" -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 30

        $linkList = @()
        if ($response -and $response.response -and $response.response.links) {
            foreach ($link in $response.response.links) {
                $linkList += [PSCustomObject]@{
                    SourceDevice = if ($link.source) { $link.source } else { "N/A" }
                    SourceInterface = if ($link.startPortName) { $link.startPortName } else { "N/A" }
                    TargetDevice = if ($link.target) { $link.target } else { "N/A" }
                    TargetInterface = if ($link.endPortName) { $link.endPortName } else { "N/A" }
                    LinkStatus = if ($link.linkStatus) { $link.linkStatus } else { "N/A" }
                }
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "PhysicalTopology_$timestamp.csv"
        $linkList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Failed to retrieve topology: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-OSPFNeighbors {
    <#
    .SYNOPSIS
        Retrieves OSPF neighbor information
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching OSPF neighbors..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($global:selectedDNADevices.Count -gt 0) { $global:selectedDNADevices } else { $global:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $ospfList = @()

        foreach ($device in $devices) {
            try {
                $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/network-device/$($device.id)/ospf-neighbor" -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 15

                if ($response -and $response.response) {
                    foreach ($neighbor in $response.response) {
                        $ospfList += [PSCustomObject]@{
                            Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                            NeighborId = if ($neighbor.neighborId) { $neighbor.neighborId } else { "N/A" }
                            NeighborIp = if ($neighbor.neighborIp) { $neighbor.neighborIp } else { "N/A" }
                            State = if ($neighbor.state) { $neighbor.state } else { "N/A" }
                            Interface = if ($neighbor.interfaceName) { $neighbor.interfaceName } else { "N/A" }
                        }
                    }
                }
            } catch {
                # Device doesn't have OSPF neighbors or API call failed
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "OSPF_Neighbors_$timestamp.csv"
        $ospfList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-CDPNeighbors {
    <#
    .SYNOPSIS
        Retrieves CDP neighbor information
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching CDP neighbors..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($global:selectedDNADevices.Count -gt 0) { $global:selectedDNADevices } else { $global:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $cdpList = @()

        foreach ($device in $devices) {
            try {
                $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/network-device/$($device.id)/neighbor" -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 15

                if ($response -and $response.response) {
                    foreach ($neighbor in $response.response) {
                        if ($neighbor.neighborDevice -or $neighbor.neighborPort) {
                            $cdpList += [PSCustomObject]@{
                                Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                                LocalInterface = if ($neighbor.localInterfaceName) { $neighbor.localInterfaceName } else { "N/A" }
                                NeighborDevice = if ($neighbor.neighborDevice) { $neighbor.neighborDevice } else { "N/A" }
                                NeighborPort = if ($neighbor.neighborPort) { $neighbor.neighborPort } else { "N/A" }
                                Platform = if ($neighbor.platform) { $neighbor.platform } else { "N/A" }
                            }
                        }
                    }
                }
            } catch {
                # Device doesn't have CDP neighbors or API call failed
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "CDP_Neighbors_$timestamp.csv"
        $cdpList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-LLDPNeighbors {
    <#
    .SYNOPSIS
        Retrieves LLDP neighbor information
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching LLDP neighbors..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($global:selectedDNADevices.Count -gt 0) { $global:selectedDNADevices } else { $global:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $lldpList = @()

        foreach ($device in $devices) {
            try {
                $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/network-device/$($device.id)/interface/lldp" -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 15

                if ($response -and $response.response) {
                    foreach ($neighbor in $response.response) {
                        $lldpList += [PSCustomObject]@{
                            Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                            LocalInterface = if ($neighbor.localInterface) { $neighbor.localInterface } else { "N/A" }
                            NeighborDevice = if ($neighbor.systemName) { $neighbor.systemName } else { "N/A" }
                            NeighborPort = if ($neighbor.portId) { $neighbor.portId } else { "N/A" }
                            ManagementAddress = if ($neighbor.managementAddress) { $neighbor.managementAddress } else { "N/A" }
                        }
                    }
                }
            } catch {
                # Device doesn't have LLDP neighbors or API call failed
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "LLDP_Neighbors_$timestamp.csv"
        $lldpList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-AccessPoints {
    <#
    .SYNOPSIS
        Retrieves wireless access point information
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching access points..." -Color "Yellow" -LogBox $LogBox

    try {
        $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/wireless/access-point" -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 30

        $apList = @()
        if ($response -and $response.response) {
            foreach ($ap in $response.response) {
                $apList += [PSCustomObject]@{
                    APName = if ($ap.name) { $ap.name } else { "N/A" }
                    MacAddress = if ($ap.macAddress) { $ap.macAddress } else { "N/A" }
                    IPAddress = if ($ap.ipAddress) { $ap.ipAddress } else { "N/A" }
                    Model = if ($ap.model) { $ap.model } else { "N/A" }
                    Location = if ($ap.location) { $ap.location } else { "N/A" }
                    AdminStatus = if ($ap.adminStatus) { $ap.adminStatus } else { "N/A" }
                    ClientCount = if ($ap.clientCount) { $ap.clientCount } else { 0 }
                }
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "AccessPoints_$timestamp.csv"
        $apList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Failed to retrieve access points: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-IssuesEvents {
    <#
    .SYNOPSIS
        Retrieves network issues and events
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching issues and events..." -Color "Yellow" -LogBox $LogBox

    try {
        $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/issues" -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 30

        $issueList = @()
        if ($response -and $response.response) {
            foreach ($issue in $response.response) {
                $issueList += [PSCustomObject]@{
                    IssueId = if ($issue.issueId) { $issue.issueId } else { "N/A" }
                    Name = if ($issue.name) { $issue.name } else { "N/A" }
                    DeviceId = if ($issue.deviceId) { $issue.deviceId } else { "N/A" }
                    Severity = if ($issue.severity) { $issue.severity } else { "N/A" }
                    Priority = if ($issue.priority) { $issue.priority } else { "N/A" }
                    Status = if ($issue.status) { $issue.status } else { "N/A" }
                    Category = if ($issue.category) { $issue.category } else { "N/A" }
                }
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "Issues_$timestamp.csv"
        $issueList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Failed to retrieve issues: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-SoftwareImageInfo {
    <#
    .SYNOPSIS
        Retrieves software image information
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching software/image information..." -Color "Yellow" -LogBox $LogBox

    try {
        $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/image/importation" -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 30

        $imageList = @()
        if ($response -and $response.response) {
            foreach ($image in $response.response) {
                $imageList += [PSCustomObject]@{
                    ImageName = if ($image.name) { $image.name } else { "N/A" }
                    ImageFamily = if ($image.family) { $image.family } else { "N/A" }
                    Version = if ($image.version) { $image.version } else { "N/A" }
                    Vendor = if ($image.vendor) { $image.vendor } else { "N/A" }
                    FileSize = if ($image.fileSize) { $image.fileSize } else { "N/A" }
                    IsTaggedGolden = if ($image.isTaggedGolden) { $image.isTaggedGolden } else { $false }
                }
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "SoftwareImages_$timestamp.csv"
        $imageList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Failed to retrieve software images: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-VLANs {
    <#
    .SYNOPSIS
        Retrieves VLAN information from devices
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching VLANs..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($global:selectedDNADevices.Count -gt 0) { $global:selectedDNADevices } else { $global:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $vlanList = @()

        foreach ($device in $devices) {
            try {
                $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/interface/network-device/$($device.id)" -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 15

                if ($response -and $response.response) {
                    $vlans = $response.response | Where-Object { $_.vlanId -and $_.vlanId -ne "N/A" } | Select-Object -Property vlanId -Unique

                    foreach ($vlan in $vlans) {
                        $vlanList += [PSCustomObject]@{
                            Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                            IPAddress = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                            VlanId = $vlan.vlanId
                        }
                    }
                }
            } catch {
                # Device doesn't have VLANs or API call failed
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "VLANs_$timestamp.csv"
        $vlanList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-DeviceModules {
    <#
    .SYNOPSIS
        Retrieves hardware module information for devices
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching device module information..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($global:selectedDNADevices.Count -gt 0) { $global:selectedDNADevices } else { $global:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $moduleList = @()

        foreach ($device in $devices) {
            try {
                $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/network-device/module?deviceId=$($device.id)" -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 15

                if ($response -and $response.response) {
                    foreach ($module in $response.response) {
                        $moduleList += [PSCustomObject]@{
                            Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                            ModuleName = if ($module.name) { $module.name } else { "N/A" }
                            PartNumber = if ($module.partNumber) { $module.partNumber } else { "N/A" }
                            SerialNumber = if ($module.serialNumber) { $module.serialNumber } else { "N/A" }
                            Description = if ($module.description) { $module.description } else { "N/A" }
                        }
                    }
                }
            } catch {
                # Device doesn't have modules or API call failed
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "DeviceModules_$timestamp.csv"
        $moduleList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-DeviceInterfaces {
    <#
    .SYNOPSIS
        Retrieves interface information from devices
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching device interfaces..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($global:selectedDNADevices.Count -gt 0) { $global:selectedDNADevices } else { $global:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $interfaceList = @()

        foreach ($device in $devices) {
            try {
                $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/interface/network-device/$($device.id)" -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 15

                if ($response -and $response.response) {
                    foreach ($interface in $response.response) {
                        $interfaceList += [PSCustomObject]@{
                            Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                            InterfaceName = if ($interface.portName) { $interface.portName } else { "N/A" }
                            Status = if ($interface.status) { $interface.status } else { "N/A" }
                            AdminStatus = if ($interface.adminStatus) { $interface.adminStatus } else { "N/A" }
                            Speed = if ($interface.speed) { $interface.speed } else { "N/A" }
                            VlanId = if ($interface.vlanId) { $interface.vlanId } else { "N/A" }
                            IPAddress = if ($interface.ipv4Address) { $interface.ipv4Address } else { "N/A" }
                        }
                    }
                }
            } catch {
                # Device interface query failed
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "DeviceInterfaces_$timestamp.csv"
        $interfaceList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-DeviceConfigurations {
    <#
    .SYNOPSIS
        Retrieves running configurations from devices
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching device configurations..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($global:selectedDNADevices.Count -gt 0) { $global:selectedDNADevices } else { $global:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $configFolder = Join-Path -Path $script:outputDir -ChildPath "DeviceConfigurations_$timestamp"

        # Validate output directory path
        if (-not (Test-Path $script:outputDir)) {
            New-Item -ItemType Directory -Path $script:outputDir -Force | Out-Null
        }

        New-Item -ItemType Directory -Path $configFolder -Force | Out-Null

        $configList = @()

        foreach ($device in $devices) {
            try {
                $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/network-device/$($device.id)/config" -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 30

                $configContent = if ($response.response) { $response.response } else { $response }

                if ($configContent) {
                    $safeHostname = Get-SafeFileName -InputName $device.hostname
                    $configPath = Join-Path -Path $configFolder -ChildPath "$safeHostname.txt"
                    $configContent | Out-File -FilePath $configPath -Encoding UTF8

                    $configList += [PSCustomObject]@{
                        Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                        IPAddress = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                        ConfigFile = $configPath
                        Status = "Success"
                    }
                }
            } catch {
                $configList += [PSCustomObject]@{
                    Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                    IPAddress = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                    ConfigFile = "N/A"
                    Status = "Failed: $($_.Exception.Message)"
                }
            }
        }

        $csvPath = Join-Path -Path $script:outputDir -ChildPath "DeviceConfigurations_$timestamp.csv"
        $configList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
        Write-Log -Message "Config files saved to: $configFolder" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Get-EventSeriesLastTimestamp {
    <#
    .SYNOPSIS
        Retrieves the last timestamp of a specific event series for a device
    .DESCRIPTION
        Helper function to query DNA Center event series and extract last occurrence
    #>
    param(
        [string]$DeviceId,
        [string]$EventId,
        [string]$EventName,
        [hashtable]$AdditionalQuery,
        [System.Windows.Forms.RichTextBox]$LogBox
    )

    if ([string]::IsNullOrWhiteSpace($DeviceId)) {
        return $null
    }

    if (-not (Test-DNACTokenValid)) {
        Write-Log -Message "DNA Center token expired or invalid" -Color "Red" -LogBox $LogBox
        return $null
    }

    $baseUrl = "$($global:selectedDnaCenter)/dna/data/api/v1/event/event-series"
    $queryParts = @()

    if ($EventId) {
        $queryParts += "eventId=$([System.Uri]::EscapeDataString($EventId))"
    }

    if ($EventName) {
        $queryParts += "eventName=$([System.Uri]::EscapeDataString($EventName))"
    }

    $queryParts += "deviceId=$([System.Uri]::EscapeDataString($DeviceId))"
    $queryParts += "limit=1"
    $queryParts += "offset=0"
    $queryParts += "sortBy=eventTimestamp"
    $queryParts += "order=desc"

    if ($AdditionalQuery) {
        foreach ($entry in $AdditionalQuery.GetEnumerator()) {
            $key = $entry.Key
            $value = $entry.Value

            if ([string]::IsNullOrWhiteSpace([string]$key)) { continue }
            if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) { continue }

            $queryParts += "{0}={1}" -f [System.Uri]::EscapeDataString([string]$key), [System.Uri]::EscapeDataString([string]$value)
        }
    }

    $queryString = $queryParts -join '&'
    $requestUrl = if ($queryString) { "$baseUrl?$queryString" } else { $baseUrl }

    try {
        $response = Invoke-RestMethod -Uri $requestUrl -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 30
    } catch {
        return $null
    }

    $records = @()
    if ($response) {
        if ($response.PSObject.Properties['response']) {
            $records = @($response.response)
        } elseif ($response.PSObject.Properties['data']) {
            $records = @($response.data)
        } elseif ($response -is [array]) {
            $records = @($response)
        } else {
            $records = @($response)
        }
    }

    foreach ($record in $records) {
        if (-not $record) { continue }

        $timestampValue = $null
        if ($record.PSObject.Properties['eventTimestamp']) {
            $timestampValue = $record.eventTimestamp
        } elseif ($record.PSObject.Properties['timestamp']) {
            $timestampValue = $record.timestamp
        }

        if ($timestampValue) {
            return ConvertTo-ReadableTimestamp -Value $timestampValue
        }
    }

    return $null
}

function Get-LastDeviceAvailabilityEventTime {
    <#
    .SYNOPSIS
        Retrieves last device availability event time
    .DESCRIPTION
        Gets the last time each device became unreachable
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    try {
        $devices = if ($global:selectedDNADevices.Count -gt 0) { $global:selectedDNADevices } else { $global:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $eventList = @()

        foreach ($device in $devices) {
            $queryHints = @{ tags = 'ASSURANCE' }
            $timestamp = Get-EventSeriesLastTimestamp -DeviceId $device.id -EventName "Device Unreachable" -AdditionalQuery $queryHints -LogBox $LogBox

            $eventList += [PSCustomObject]@{
                Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                IPAddress = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                LastEventTime = if ($timestamp) { $timestamp } else { "N/A" }
                EventType = "Device Unreachable"
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "DeviceAvailabilityEvents_$timestamp.csv"
        $eventList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        $sanitizedError = Get-SanitizedErrorMessage -ErrorRecord $_
        Write-Log -Message "Error: $sanitizedError" -Color "Red" -LogBox $LogBox
    }
}

function Get-LastDisconnectTime {
    <#
    .SYNOPSIS
        Retrieves last device disconnect time
    .DESCRIPTION
        Gets enrichment details including last disconnect timestamp
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    try {
        $devices = if ($global:selectedDNADevices.Count -gt 0) { $global:selectedDNADevices } else { $global:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        if (-not (Test-DNACTokenValid)) {
            Write-Log -Message "DNA Center token expired or invalid" -Color "Red" -LogBox $LogBox
            return
        }

        $disconnectList = @()

        foreach ($device in $devices) {
            $enrichmentUrl = "$($global:selectedDnaCenter)/dna/intent/api/v1/network-device/$($device.id)/enrichment-details"

            try {
                $response = Invoke-RestMethod -Uri $enrichmentUrl -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 30

                $lastDisconnect = $null
                if ($response) {
                    $records = @()
                    if ($response.PSObject.Properties['response']) {
                        $records = @($response.response)
                    } else {
                        $records = @($response)
                    }

                    foreach ($record in $records) {
                        if (-not $record) { continue }

                        $deviceDetails = $null
                        if ($record.PSObject.Properties['deviceDetails']) {
                            $deviceDetails = $record.deviceDetails
                        }

                        if ($deviceDetails -and $deviceDetails.PSObject.Properties['lastDisconnectTime']) {
                            $lastDisconnect = ConvertTo-ReadableTimestamp -Value $deviceDetails.lastDisconnectTime
                        }
                    }
                }

                $disconnectList += [PSCustomObject]@{
                    Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                    IPAddress = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                    LastDisconnectTime = if ($lastDisconnect) { $lastDisconnect } else { "N/A" }
                }
            } catch {
                $disconnectList += [PSCustomObject]@{
                    Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                    IPAddress = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                    LastDisconnectTime = "Error"
                }
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "DeviceLastDisconnect_$timestamp.csv"
        $disconnectList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        $sanitizedError = Get-SanitizedErrorMessage -ErrorRecord $_
        Write-Log -Message "Error: $sanitizedError" -Color "Red" -LogBox $LogBox
    }
}

function Get-LastPingReachableTime {
    <#
    .SYNOPSIS
        Retrieves last ping reachable timestamp for devices
    .DESCRIPTION
        Gets the last time each device was successfully ping-reachable
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    try {
        $devices = if ($global:selectedDNADevices.Count -gt 0) { $global:selectedDNADevices } else { $global:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        if (-not (Test-DNACTokenValid)) {
            Write-Log -Message "DNA Center token expired or invalid" -Color "Red" -LogBox $LogBox
            return
        }

        Write-Log -Message "Retrieving last ping reachable times for $($devices.Count) device(s)..." -Color "Cyan" -LogBox $LogBox

        $reachableList = @()

        foreach ($device in $devices) {
            $lastReachable = "N/A"

            # Try to get last seen/reachable time from device record first
            $deviceId = $device.id

            if ($deviceId) {
                try {
                    $enrichmentUrl = "$($global:selectedDnaCenter)/dna/intent/api/v1/network-device/$deviceId"
                    $response = Invoke-RestMethod -Uri $enrichmentUrl -Method Get -Headers $global:dnaCenterHeaders -TimeoutSec 30

                    if ($response -and $response.response) {
                        $deviceData = $response.response

                        # Try various timestamp properties
                        $lastSeenValue = $null
                        if ($deviceData.PSObject.Properties['lastUpdateTime']) {
                            $lastSeenValue = $deviceData.lastUpdateTime
                        } elseif ($deviceData.PSObject.Properties['lastUpdated']) {
                            $lastSeenValue = $deviceData.lastUpdated
                        } elseif ($deviceData.PSObject.Properties['collectionStatus']) {
                            $lastSeenValue = $deviceData.collectionStatus
                        }

                        if ($lastSeenValue) {
                            $lastReachable = ConvertTo-ReadableTimestamp -Value $lastSeenValue
                        }
                    }
                } catch {
                    # Continue to event-based lookup
                }

                # If still N/A, try event series for ping_reachable
                if ($lastReachable -eq "N/A") {
                    $timestamp = Get-EventSeriesLastTimestamp `
                        -DeviceId $deviceId `
                        -EventName "device_availability:ping_reachable" `
                        -AdditionalQuery @{} `
                        -LogBox $LogBox

                    if ($timestamp) {
                        $lastReachable = $timestamp
                    }
                }

                # If still N/A, try general reachable event
                if ($lastReachable -eq "N/A") {
                    $timestamp = Get-EventSeriesLastTimestamp `
                        -DeviceId $deviceId `
                        -EventName "device_availability:reachable" `
                        -AdditionalQuery @{} `
                        -LogBox $LogBox

                    if ($timestamp) {
                        $lastReachable = $timestamp
                    }
                }
            }

            $reachableList += [PSCustomObject]@{
                Hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
                IPAddress = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                Family = if ($device.family) { $device.family } else { "N/A" }
                LastPingReachable = $lastReachable
            }
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "DeviceLastPingReachable_$timestamp.csv"
        $reachableList | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
    } catch {
        $sanitizedError = Get-SanitizedErrorMessage -ErrorRecord $_
        Write-Log -Message "Error: $sanitizedError" -Color "Red" -LogBox $LogBox
    }
}

function Invoke-PathTrace {
    <#
    .SYNOPSIS
        Performs path trace analysis between two IP addresses
    .DESCRIPTION
        Interactive path trace with protocol and port selection
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    if (-not (Test-DNACTokenValid)) {
        Write-Log -Message "DNA Center token expired or invalid" -Color "Red" -LogBox $LogBox
        [System.Windows.Forms.MessageBox]::Show("Please connect to DNA Center first", "Not Authenticated", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    # Create input dialog
    $pathTraceForm = New-Object System.Windows.Forms.Form
    $pathTraceForm.Text = "Path Trace Configuration"
    $pathTraceForm.Size = New-Object System.Drawing.Size(500, 400)
    $pathTraceForm.StartPosition = "CenterParent"
    $pathTraceForm.FormBorderStyle = "FixedDialog"
    $pathTraceForm.MaximizeBox = $false

    $y = 20

    # Source IP
    $lblSource = New-Object System.Windows.Forms.Label
    $lblSource.Text = "Source IP Address:"
    $lblSource.Location = New-Object System.Drawing.Point(20, $y)
    $lblSource.Size = New-Object System.Drawing.Size(120, 20)
    $pathTraceForm.Controls.Add($lblSource)

    $txtSource = New-Object System.Windows.Forms.TextBox
    $txtSource.Location = New-Object System.Drawing.Point(150, $y)
    $txtSource.Size = New-Object System.Drawing.Size(300, 20)
    $pathTraceForm.Controls.Add($txtSource)

    $y += 40

    # Destination IP
    $lblDest = New-Object System.Windows.Forms.Label
    $lblDest.Text = "Destination IP Address:"
    $lblDest.Location = New-Object System.Drawing.Point(20, $y)
    $lblDest.Size = New-Object System.Drawing.Size(120, 20)
    $pathTraceForm.Controls.Add($lblDest)

    $txtDest = New-Object System.Windows.Forms.TextBox
    $txtDest.Location = New-Object System.Drawing.Point(150, $y)
    $txtDest.Size = New-Object System.Drawing.Size(300, 20)
    $pathTraceForm.Controls.Add($txtDest)

    $y += 40

    # Protocol
    $lblProtocol = New-Object System.Windows.Forms.Label
    $lblProtocol.Text = "Protocol:"
    $lblProtocol.Location = New-Object System.Drawing.Point(20, $y)
    $lblProtocol.Size = New-Object System.Drawing.Size(120, 20)
    $pathTraceForm.Controls.Add($lblProtocol)

    $comboProtocol = New-Object System.Windows.Forms.ComboBox
    $comboProtocol.Location = New-Object System.Drawing.Point(150, $y)
    $comboProtocol.Size = New-Object System.Drawing.Size(150, 20)
    $comboProtocol.DropDownStyle = "DropDownList"
    $comboProtocol.Items.AddRange(@("ICMP", "TCP", "UDP"))
    $comboProtocol.SelectedIndex = 0
    $pathTraceForm.Controls.Add($comboProtocol)

    $y += 40

    # Source Port (optional)
    $lblSourcePort = New-Object System.Windows.Forms.Label
    $lblSourcePort.Text = "Source Port (optional):"
    $lblSourcePort.Location = New-Object System.Drawing.Point(20, $y)
    $lblSourcePort.Size = New-Object System.Drawing.Size(120, 20)
    $pathTraceForm.Controls.Add($lblSourcePort)

    $txtSourcePort = New-Object System.Windows.Forms.TextBox
    $txtSourcePort.Location = New-Object System.Drawing.Point(150, $y)
    $txtSourcePort.Size = New-Object System.Drawing.Size(100, 20)
    $pathTraceForm.Controls.Add($txtSourcePort)

    $y += 40

    # Dest Port (optional)
    $lblDestPort = New-Object System.Windows.Forms.Label
    $lblDestPort.Text = "Dest Port (optional):"
    $lblDestPort.Location = New-Object System.Drawing.Point(20, $y)
    $lblDestPort.Size = New-Object System.Drawing.Size(120, 20)
    $pathTraceForm.Controls.Add($lblDestPort)

    $txtDestPort = New-Object System.Windows.Forms.TextBox
    $txtDestPort.Location = New-Object System.Drawing.Point(150, $y)
    $txtDestPort.Size = New-Object System.Drawing.Size(100, 20)
    $pathTraceForm.Controls.Add($txtDestPort)

    $y += 60

    # Start button
    $btnStart = New-Object System.Windows.Forms.Button
    $btnStart.Text = "Start Path Trace"
    $btnStart.Location = New-Object System.Drawing.Point(150, $y)
    $btnStart.Size = New-Object System.Drawing.Size(120, 30)
    $pathTraceForm.Controls.Add($btnStart)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Location = New-Object System.Drawing.Point(280, $y)
    $btnCancel.Size = New-Object System.Drawing.Size(80, 30)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $pathTraceForm.Controls.Add($btnCancel)
    $pathTraceForm.CancelButton = $btnCancel

    $btnStart.Add_Click({
        # Validate inputs
        if (-not (Test-IPAddress -IPAddress $txtSource.Text.Trim())) {
            [System.Windows.Forms.MessageBox]::Show("Invalid source IP address", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        if (-not (Test-IPAddress -IPAddress $txtDest.Text.Trim())) {
            [System.Windows.Forms.MessageBox]::Show("Invalid destination IP address", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        # Validate ports if provided
        if (-not [string]::IsNullOrWhiteSpace($txtSourcePort.Text)) {
            $port = 0
            if (-not [int]::TryParse($txtSourcePort.Text, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
                [System.Windows.Forms.MessageBox]::Show("Source port must be between 1 and 65535", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($txtDestPort.Text)) {
            $port = 0
            if (-not [int]::TryParse($txtDestPort.Text, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
                [System.Windows.Forms.MessageBox]::Show("Destination port must be between 1 and 65535", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }
        }

        $pathTraceForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $pathTraceForm.Close()
    })

    $result = $pathTraceForm.ShowDialog()

    if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
        return
    }

    # Execute path trace
    $sourceIP = $txtSource.Text.Trim()
    $destIP = $txtDest.Text.Trim()
    $protocol = $comboProtocol.SelectedItem

    Write-Log -Message "Starting path trace: $sourceIP -> $destIP ($protocol)" -Color "Cyan" -LogBox $LogBox

    try {
        # Build request body
        $requestBody = @{
            "sourceIP" = $sourceIP
            "destIP" = $destIP
            "protocol" = $protocol
        }

        if (-not [string]::IsNullOrWhiteSpace($txtSourcePort.Text)) {
            $requestBody["sourcePort"] = [int]$txtSourcePort.Text
        }
        if (-not [string]::IsNullOrWhiteSpace($txtDestPort.Text)) {
            $requestBody["destPort"] = [int]$txtDestPort.Text
        }

        $requestJson = $requestBody | ConvertTo-Json -Depth 10

        $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/flow-analysis" `
            -Method Post `
            -Headers $global:dnaCenterHeaders `
            -Body $requestJson `
            -ContentType "application/json" `
            -TimeoutSec 30

        if ($response -and $response.response -and $response.response.flowAnalysisId) {
            $flowAnalysisId = $response.response.flowAnalysisId
            Write-Log -Message "Flow analysis initiated (ID: $flowAnalysisId)" -Color "Green" -LogBox $LogBox
            Write-Log -Message "Waiting for path trace to complete..." -Color "Yellow" -LogBox $LogBox

            $completed = $false
            $attempts = 0
            $maxAttempts = 30

            while (-not $completed -and $attempts -lt $maxAttempts) {
                Start-Sleep -Seconds 2
                $attempts++

                $statusResponse = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/flow-analysis/$flowAnalysisId" `
                    -Method Get `
                    -Headers $global:dnaCenterHeaders `
                    -TimeoutSec 30

                if ($statusResponse -and $statusResponse.response) {
                    $status = $statusResponse.response.request.status

                    if ($status -eq "COMPLETED") {
                        $completed = $true
                        Write-Log -Message "Path trace completed!" -Color "Green" -LogBox $LogBox

                        # Parse results
                        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                        $csvPath = Join-Path -Path $script:outputDir -ChildPath "PathTrace_${sourceIP}_to_${destIP}_$timestamp.csv"

                        $pathList = @()
                        $hopNumber = 1

                        if ($statusResponse.response.networkElementsInfo) {
                            foreach ($element in $statusResponse.response.networkElementsInfo) {
                                $deviceName = if ($element.name) { $element.name } else { "Unknown" }
                                $deviceIP = if ($element.ip) { $element.ip } else { "N/A" }
                                $deviceType = if ($element.type) { $element.type } else { "N/A" }

                                $ingressInterface = "N/A"
                                if ($element.ingressInterface -and $element.ingressInterface.physicalInterface -and $element.ingressInterface.physicalInterface.name) {
                                    $ingressInterface = $element.ingressInterface.physicalInterface.name
                                }

                                $egressInterface = "N/A"
                                if ($element.egressInterface -and $element.egressInterface.physicalInterface -and $element.egressInterface.physicalInterface.name) {
                                    $egressInterface = $element.egressInterface.physicalInterface.name
                                }

                                $pathList += [PSCustomObject]@{
                                    HopNumber = $hopNumber
                                    DeviceName = $deviceName
                                    DeviceIP = $deviceIP
                                    DeviceType = $deviceType
                                    IngressInterface = $ingressInterface
                                    EgressInterface = $egressInterface
                                    SourceIP = $sourceIP
                                    DestinationIP = $destIP
                                    Protocol = $protocol
                                    TraceTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                }

                                $hopNumber++
                            }
                        }

                        $pathList | Export-Csv -Path $csvPath -NoTypeInformation
                        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $LogBox
                        Write-Log -Message "Total hops: $($pathList.Count)" -Color "Green" -LogBox $LogBox

                        [System.Windows.Forms.MessageBox]::Show("Path trace completed!`nTotal hops: $($pathList.Count)`n`nExported to: $csvPath", "Path Trace Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                        break
                    } elseif ($status -eq "FAILED") {
                        Write-Log -Message "Path trace failed" -Color "Red" -LogBox $LogBox
                        if ($statusResponse.response.request.failureReason) {
                            Write-Log -Message "Reason: $($statusResponse.response.request.failureReason)" -Color "Red" -LogBox $LogBox
                        }
                        break
                    }
                }
            }

            if (-not $completed -and $attempts -ge $maxAttempts) {
                Write-Log -Message "Path trace timed out after $($attempts * 2) seconds" -Color "Red" -LogBox $LogBox
            }
        } else {
            Write-Log -Message "Failed to initiate path trace" -Color "Red" -LogBox $LogBox
        }
    } catch {
        $sanitizedError = Get-SanitizedErrorMessage -ErrorRecord $_
        Write-Log -Message "Error during path trace: $sanitizedError" -Color "Red" -LogBox $LogBox
    }
}

function Get-DNATaskOutputDetails {
    <#
    .SYNOPSIS
        Parses DNA Center CLI command output from various response formats
    .DESCRIPTION
        Handles multiple response formats from DNA Center API file downloads
        Extracted from DNACAPEiv6_COMPLETE(1).txt for robust output parsing
    #>
    param(
        $RawOutput,
        [string]$Command
    )

    $cleanOutput = ""

    # Handle null or empty responses
    if ($null -eq $RawOutput) {
        return ""
    }

    # Handle string responses (simplest case)
    if ($RawOutput -is [string]) {
        $cleanOutput = $RawOutput
    }
    # Handle array responses
    elseif ($RawOutput -is [array]) {
        foreach ($item in $RawOutput) {
            if ($null -eq $item) { continue }

            # Try to find property matching command name (e.g., "show version")
            $itemProps = $item.PSObject.Properties
            $commandKey = $itemProps | Where-Object { $_.Name -match "show" } | Select-Object -First 1

            if ($commandKey) {
                $rawValue = $commandKey.Value
                if ($rawValue -is [string]) {
                    $cleanOutput += $rawValue
                } else {
                    $cleanOutput += ($rawValue | ConvertTo-Json -Depth 10)
                }
            }
            elseif ($item.commandOutput) {
                $cleanOutput += $item.commandOutput
            }
            elseif ($item.output) {
                $cleanOutput += $item.output
            }
            elseif ($item.PSObject.Properties['commandResponses']) {
                # Try commandResponses.SUCCESS format
                if ($item.commandResponses.SUCCESS) {
                    $cleanOutput += ($item.commandResponses.SUCCESS -join "`n")
                }
            }
            else {
                $cleanOutput += ($item | ConvertTo-Json -Depth 10)
            }
        }
    }
    # Handle object responses
    else {
        $outputProps = $RawOutput.PSObject.Properties

        # Try to find property matching command name
        $commandKey = $outputProps | Where-Object { $_.Name -match "show" } | Select-Object -First 1

        if ($commandKey) {
            $rawValue = $commandKey.Value
            if ($rawValue -is [string]) {
                $cleanOutput = $rawValue
            } else {
                $cleanOutput = ($rawValue | ConvertTo-Json -Depth 10)
            }
        }
        elseif ($RawOutput.commandOutput) {
            $cleanOutput = $RawOutput.commandOutput
        }
        elseif ($RawOutput.output) {
            $cleanOutput = $RawOutput.output
        }
        elseif ($RawOutput.PSObject.Properties['commandResponses']) {
            # Try commandResponses.SUCCESS format
            if ($RawOutput.commandResponses.SUCCESS) {
                $cleanOutput = ($RawOutput.commandResponses.SUCCESS -join "`n")
            }
        }
        else {
            $cleanOutput = ($RawOutput | ConvertTo-Json -Depth 10)
        }
    }

    # Clean up escape sequences and formatting
    if (-not [string]::IsNullOrEmpty($cleanOutput)) {
        $cleanOutput = $cleanOutput -replace '\\r\\n', "`n" -replace '\\r', "`n" -replace '\\n', "`n"
        $cleanOutput = $cleanOutput.Trim('"')
        $cleanOutput = $cleanOutput -replace '""', '"' -replace '\\`', '`' -replace '\\\\', '\'
    }

    return $cleanOutput
}

function Invoke-CommandRunner {
    <#
    .SYNOPSIS
        Executes CLI commands on multiple devices
    .DESCRIPTION
        Interactive command execution with output filtering matching DNACAPEiv6 behavior
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)

    if (-not (Test-DNACTokenValid)) {
        Write-Log -Message "DNA Center token expired or invalid" -Color "Red" -LogBox $LogBox
        [System.Windows.Forms.MessageBox]::Show("Please connect to DNA Center first", "Not Authenticated", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    # Use ONLY selected devices - do NOT fallback to all devices
    $devices = $global:selectedDNADevices

    if (-not $devices -or $devices.Count -eq 0) {
        Write-Log -Message "No devices selected. Please use the device selection checkboxes and click 'Apply Selection'." -Color "Yellow" -LogBox $LogBox
        [System.Windows.Forms.MessageBox]::Show("No devices selected!`n`nPlease:`n1. Check the devices you want in the device list`n2. Click 'Apply Selection' button`n3. Then try running CLI Command Runner again", "No Devices Selected", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    # Create main command input dialog with enhanced UI
    $cmdForm = New-Object System.Windows.Forms.Form
    $cmdForm.Text = "CLI Command Runner"
    $cmdForm.Size = New-Object System.Drawing.Size(700, 600)
    $cmdForm.StartPosition = "CenterParent"
    $cmdForm.FormBorderStyle = "FixedDialog"
    $cmdForm.MaximizeBox = $false

    $y = 15

    # Info label
    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Text = "Execute CLI commands on $($devices.Count) selected device(s)"
    $lblInfo.Location = New-Object System.Drawing.Point(20, $y)
    $lblInfo.Size = New-Object System.Drawing.Size(650, 20)
    $lblInfo.Font = New-Object System.Drawing.Font("Arial", 11, [System.Drawing.FontStyle]::Bold)
    $lblInfo.ForeColor = [System.Drawing.Color]::DarkBlue
    $cmdForm.Controls.Add($lblInfo)

    $y += 30

    # Command label
    $lblCommand = New-Object System.Windows.Forms.Label
    $lblCommand.Text = "CLI Command(s) - Enter one command per line:"
    $lblCommand.Location = New-Object System.Drawing.Point(20, $y)
    $lblCommand.Size = New-Object System.Drawing.Size(400, 20)
    $lblCommand.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Bold)
    $cmdForm.Controls.Add($lblCommand)

    $y += 25

    # Command textbox (multiline)
    $txtCommand = New-Object System.Windows.Forms.TextBox
    $txtCommand.Multiline = $true
    $txtCommand.ScrollBars = "Vertical"
    $txtCommand.Location = New-Object System.Drawing.Point(20, $y)
    $txtCommand.Size = New-Object System.Drawing.Size(650, 120)
    $txtCommand.Font = New-Object System.Drawing.Font("Consolas", 9)
    $cmdForm.Controls.Add($txtCommand)

    $y += 130

    # Warning label
    $lblWarning = New-Object System.Windows.Forms.Label
    $lblWarning.Text = "⚠ Note: Pipes (|) are not supported by DNA Center API. Use plain commands only."
    $lblWarning.Location = New-Object System.Drawing.Point(20, $y)
    $lblWarning.Size = New-Object System.Drawing.Size(650, 20)
    $lblWarning.ForeColor = [System.Drawing.Color]::DarkOrange
    $cmdForm.Controls.Add($lblWarning)

    $y += 30

    # Output format section
    $lblFormat = New-Object System.Windows.Forms.Label
    $lblFormat.Text = "Output Format:"
    $lblFormat.Location = New-Object System.Drawing.Point(20, $y)
    $lblFormat.Size = New-Object System.Drawing.Size(150, 20)
    $lblFormat.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Bold)
    $cmdForm.Controls.Add($lblFormat)

    $y += 25

    # Output format radio buttons
    $rbSeparate = New-Object System.Windows.Forms.RadioButton
    $rbSeparate.Text = "Separate files per device (hostname_command.txt)"
    $rbSeparate.Location = New-Object System.Drawing.Point(35, $y)
    $rbSeparate.Size = New-Object System.Drawing.Size(600, 20)
    $rbSeparate.Checked = $true
    $cmdForm.Controls.Add($rbSeparate)

    $y += 25

    $rbConsolidated = New-Object System.Windows.Forms.RadioButton
    $rbConsolidated.Text = "Single consolidated CSV with all results"
    $rbConsolidated.Location = New-Object System.Drawing.Point(35, $y)
    $rbConsolidated.Size = New-Object System.Drawing.Size(600, 20)
    $cmdForm.Controls.Add($rbConsolidated)

    $y += 25

    $rbBoth = New-Object System.Windows.Forms.RadioButton
    $rbBoth.Text = "Both formats (separate files + consolidated CSV)"
    $rbBoth.Location = New-Object System.Drawing.Point(35, $y)
    $rbBoth.Size = New-Object System.Drawing.Size(600, 20)
    $cmdForm.Controls.Add($rbBoth)

    $y += 25

    $rbAll = New-Object System.Windows.Forms.RadioButton
    $rbAll.Text = "All formats (separate + CSV + concatenated text file)"
    $rbAll.Location = New-Object System.Drawing.Point(35, $y)
    $rbAll.Size = New-Object System.Drawing.Size(600, 20)
    $cmdForm.Controls.Add($rbAll)

    $y += 35

    # Filter section
    $lblFilterInfo = New-Object System.Windows.Forms.Label
    $lblFilterInfo.Text = "Output Filters (optional - matches any line containing these patterns, case-insensitive):"
    $lblFilterInfo.Location = New-Object System.Drawing.Point(20, $y)
    $lblFilterInfo.Size = New-Object System.Drawing.Size(650, 20)
    $lblFilterInfo.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Bold)
    $cmdForm.Controls.Add($lblFilterInfo)

    $y += 25

    $lblFilterExample = New-Object System.Windows.Forms.Label
    $lblFilterExample.Text = "Enter patterns separated by commas (e.g: up, Gigabit, 192.168)"
    $lblFilterExample.Location = New-Object System.Drawing.Point(20, $y)
    $lblFilterExample.Size = New-Object System.Drawing.Size(650, 20)
    $lblFilterExample.ForeColor = [System.Drawing.Color]::Gray
    $cmdForm.Controls.Add($lblFilterExample)

    $y += 25

    # Filter textbox
    $txtFilter = New-Object System.Windows.Forms.TextBox
    $txtFilter.Location = New-Object System.Drawing.Point(20, $y)
    $txtFilter.Size = New-Object System.Drawing.Size(650, 20)
    $txtFilter.Font = New-Object System.Drawing.Font("Consolas", 9)
    $cmdForm.Controls.Add($txtFilter)

    $y += 40

    # Buttons
    $btnExecute = New-Object System.Windows.Forms.Button
    $btnExecute.Text = "Execute Commands"
    $btnExecute.Location = New-Object System.Drawing.Point(20, $y)
    $btnExecute.Size = New-Object System.Drawing.Size(140, 35)
    $btnExecute.BackColor = [System.Drawing.Color]::LightGreen
    $cmdForm.Controls.Add($btnExecute)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Location = New-Object System.Drawing.Point(170, $y)
    $btnCancel.Size = New-Object System.Drawing.Size(100, 35)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $cmdForm.Controls.Add($btnCancel)
    $cmdForm.CancelButton = $btnCancel

    $btnExecute.Add_Click({
        if ([string]::IsNullOrWhiteSpace($txtCommand.Text)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter at least one command", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        $cmdForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $cmdForm.Close()
    })

    $result = $cmdForm.ShowDialog()

    if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
        return
    }

    # Parse commands
    $commandLines = $txtCommand.Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    if ($commandLines.Count -eq 0) {
        Write-Log -Message "No valid commands entered" -Color "Red" -LogBox $LogBox
        return
    }

    # Determine output format
    $useSeparateFiles = $rbSeparate.Checked -or $rbBoth.Checked -or $rbAll.Checked
    $useConsolidatedCSV = $rbConsolidated.Checked -or $rbBoth.Checked -or $rbAll.Checked
    $useConcatenatedText = $rbAll.Checked

    # Parse filters (comma-separated)
    $outputFilters = @()
    $filterText = $txtFilter.Text.Trim()
    if (-not [string]::IsNullOrWhiteSpace($filterText)) {
        $outputFilters = $filterText.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        if ($outputFilters.Count -gt 0) {
            Write-Log -Message "Output filters: $($outputFilters -join ', ')" -Color "Yellow" -LogBox $LogBox
        }
    }

    $formatDesc = if ($useSeparateFiles -and $useConsolidatedCSV -and $useConcatenatedText) {
        "separate files + CSV + concatenated text"
    } elseif ($useSeparateFiles -and $useConsolidatedCSV) {
        "separate files + CSV"
    } elseif ($useSeparateFiles) {
        "separate files per device"
    } else {
        "consolidated CSV"
    }

    Write-Log -Message "Executing $($commandLines.Count) command(s) on $($devices.Count) device(s)..." -Color "Cyan" -LogBox $LogBox
    Write-Log -Message "Output format: $formatDesc" -Color "Cyan" -LogBox $LogBox

    # Log selected devices
    Write-Log -Message "Selected devices:" -Color "Cyan" -LogBox $LogBox
    foreach ($dev in $devices) {
        $devHostname = if ($dev.hostname) { $dev.hostname } else { "Unknown" }
        $devIP = if ($dev.managementIpAddress) { $dev.managementIpAddress } else { "N/A" }
        Write-Log -Message "  - $devHostname ($devIP)" -Color "Gray" -LogBox $LogBox
    }

    foreach ($cmd in $commandLines) {
        Write-Log -Message "Command: $cmd" -Color "Yellow" -LogBox $LogBox
    }

    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $outputFolder = Join-Path -Path $script:outputDir -ChildPath "CommandRunner_$timestamp"
        New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null

        $allResults = @()
        $concatenatedContent = ""

        $totalOps = $devices.Count * $commandLines.Count
        $currentOp = 0

        foreach ($device in $devices) {
            $hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
            $deviceId = $device.id

            foreach ($cmd in $commandLines) {
                $currentOp++
                Write-Log -Message "[$currentOp/$totalOps] [$hostname] Submitting: $cmd" -Color "Gray" -LogBox $LogBox

                $requestBody = @{
                    "name" = "GUI-Cmd-$hostname-$(Get-Random)"
                    "commands" = @($cmd)
                    "deviceUuids" = @($deviceId)
                } | ConvertTo-Json -Depth 10

                try {
                    $response = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/network-device-poller/cli/read-request" `
                        -Method Post `
                        -Headers $global:dnaCenterHeaders `
                        -Body $requestBody `
                        -ContentType "application/json" `
                        -TimeoutSec 30

                    if ($response -and $response.response -and $response.response.taskId) {
                        $taskId = $response.response.taskId

                        # Poll for completion
                        $maxWait = 60
                        $waited = 0
                        $fileId = $null

                        while ($waited -lt $maxWait) {
                            Start-Sleep -Seconds 2
                            $waited += 2

                            $taskResponse = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/task/$taskId" `
                                -Method Get `
                                -Headers $global:dnaCenterHeaders `
                                -TimeoutSec 30

                            if ($taskResponse -and $taskResponse.response) {
                                $taskInfo = $taskResponse.response

                                if ($taskInfo.isError) {
                                    Write-Log -Message "[$hostname] Command failed" -Color "Red" -LogBox $LogBox
                                    break
                                } elseif ($taskInfo.endTime) {
                                    # Extract file ID
                                    if ($taskInfo.additionalStatusURL -and $taskInfo.additionalStatusURL -match '/file/([a-f0-9\-]+)') {
                                        $fileId = $Matches[1]
                                    } elseif ($taskInfo.progress) {
                                        try {
                                            $progressData = $taskInfo.progress | ConvertFrom-Json
                                            if ($progressData.fileId) {
                                                $fileId = $progressData.fileId
                                            }
                                        } catch {
                                            if ($taskInfo.progress -match '"fileId"\s*:\s*"([^"]+)"') {
                                                $fileId = $Matches[1]
                                            }
                                        }
                                    }
                                    break
                                }
                            }
                        }

                        if ($fileId) {
                            # Retrieve output
                            $fileResponse = Invoke-RestMethod -Uri "$($global:selectedDnaCenter)/dna/intent/api/v1/file/$fileId" `
                                -Method Get `
                                -Headers $global:dnaCenterHeaders `
                                -TimeoutSec 30

                            # Use robust parsing function to handle various response formats
                            $outputText = Get-DNATaskOutputDetails -RawOutput $fileResponse -Command $cmd

                            if ([string]::IsNullOrWhiteSpace($outputText)) {
                                Write-Log -Message "[$hostname] Warning: Empty output received (output text is blank)" -Color "Yellow" -LogBox $LogBox
                                Write-Log -Message "[$hostname] Debug - File ID: $fileId" -Color "Gray" -LogBox $LogBox
                                $outputText = ""
                            } else {
                                $lineCount = ($outputText -split "`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
                                Write-Log -Message "[$hostname] Retrieved output: $lineCount lines" -Color "Green" -LogBox $LogBox
                            }

                            # Apply filters if specified
                            $filteredOutput = $outputText
                            if ($outputFilters.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($outputText)) {
                                $lines = $outputText -split "`n"
                                $filteredLines = Invoke-Filters -Lines $lines -Filters $outputFilters
                                $filteredOutput = $filteredLines -join "`n"

                                $originalLines = ($lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
                                $filteredLineCount = ($filteredLines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
                                Write-Log -Message "[$hostname] Filtered: $filteredLineCount/$originalLines lines matched" -Color "Yellow" -LogBox $LogBox
                            }

                            # Save to individual file (if requested)
                            $outputFile = "N/A"
                            if ($useSeparateFiles) {
                                $safeHostname = Get-SafeFileName -InputName $hostname
                                $safeCommand = Get-SafeFileName -InputName $cmd
                                $outputFile = Join-Path -Path $outputFolder -ChildPath "${safeHostname}_${safeCommand}.txt"
                                $filteredOutput | Out-File -FilePath $outputFile -Encoding UTF8
                                Write-Log -Message "[$hostname] Saved to: $outputFile" -Color "Green" -LogBox $LogBox
                            }

                            # Add to concatenated content (if requested)
                            if ($useConcatenatedText) {
                                $concatenatedContent += "=" * 80 + "`n"
                                $concatenatedContent += "Device: $hostname`n"
                                $concatenatedContent += "Command: $cmd`n"
                                $concatenatedContent += "=" * 80 + "`n"
                                $concatenatedContent += $filteredOutput + "`n`n"
                            }

                            $allResults += [PSCustomObject]@{
                                Hostname = $hostname
                                DeviceIP = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                                Command = $cmd
                                Status = "Success"
                                OutputFile = $outputFile
                                OutputLength = $filteredOutput.Length
                                Output = if ($useConsolidatedCSV) { $filteredOutput } else { "" }
                            }

                            Write-Log -Message "[$hostname] ✓ Complete" -Color "Green" -LogBox $LogBox
                        } else {
                            $allResults += [PSCustomObject]@{
                                Hostname = $hostname
                                DeviceIP = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                                Command = $cmd
                                Status = "Timeout"
                                OutputFile = "N/A"
                                OutputLength = 0
                                Output = ""
                            }
                            Write-Log -Message "[$hostname] ✗ TIMEOUT - No file ID received after $maxWait seconds" -Color "Red" -LogBox $LogBox
                        }
                    } else {
                        $allResults += [PSCustomObject]@{
                            Hostname = $hostname
                            DeviceIP = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                            Command = $cmd
                            Status = "Submit Failed"
                            OutputFile = "N/A"
                            OutputLength = 0
                            Output = ""
                        }
                        Write-Log -Message "[$hostname] ✗ FAILED - Command submission failed (no task ID returned)" -Color "Red" -LogBox $LogBox
                    }
                } catch {
                    $sanitizedError = Get-SanitizedErrorMessage -ErrorRecord $_
                    $allResults += [PSCustomObject]@{
                        Hostname = $hostname
                        DeviceIP = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                        Command = $cmd
                        Status = "Error: $sanitizedError"
                        OutputFile = "N/A"
                        OutputLength = 0
                        Output = ""
                    }
                    Write-Log -Message "[$hostname] ✗ ERROR: $sanitizedError" -Color "Red" -LogBox $LogBox
                }

                # Small delay between commands
                Start-Sleep -Milliseconds 500
            }
        }

        # Export consolidated CSV (if requested)
        if ($useConsolidatedCSV -and $allResults.Count -gt 0) {
            $csvPath = Join-Path -Path $outputFolder -ChildPath "CommandRunner_Summary_$timestamp.csv"
            $allResults | Export-Csv -Path $csvPath -NoTypeInformation
            Write-Log -Message "Summary CSV: $csvPath" -Color "Green" -LogBox $LogBox
        }

        # Export concatenated text file (if requested)
        if ($useConcatenatedText -and -not [string]::IsNullOrWhiteSpace($concatenatedContent)) {
            $concatPath = Join-Path -Path $outputFolder -ChildPath "CommandRunner_All_Output_$timestamp.txt"
            $concatenatedContent | Out-File -FilePath $concatPath -Encoding UTF8
            Write-Log -Message "Concatenated text: $concatPath" -Color "Green" -LogBox $LogBox
        }

        Write-Log -Message "═══════════════════════════════════════" -Color "Cyan" -LogBox $LogBox
        Write-Log -Message "Command execution complete!" -Color "Green" -LogBox $LogBox
        Write-Log -Message "═══════════════════════════════════════" -Color "Cyan" -LogBox $LogBox

        # Calculate statistics
        $successCount = ($allResults | Where-Object { $_.Status -eq "Success" }).Count
        $timeoutCount = ($allResults | Where-Object { $_.Status -eq "Timeout" }).Count
        $failedCount = ($allResults | Where-Object { $_.Status -like "Submit Failed" }).Count
        $errorCount = ($allResults | Where-Object { $_.Status -like "Error:*" }).Count

        Write-Log -Message "Results Summary:" -Color "Cyan" -LogBox $LogBox
        Write-Log -Message "  Total operations: $totalOps" -Color "White" -LogBox $LogBox
        Write-Log -Message "  Successful: $successCount" -Color "Green" -LogBox $LogBox
        if ($timeoutCount -gt 0) {
            Write-Log -Message "  Timeouts: $timeoutCount" -Color "Yellow" -LogBox $LogBox
        }
        if ($failedCount -gt 0) {
            Write-Log -Message "  Submit failures: $failedCount" -Color "Red" -LogBox $LogBox
        }
        if ($errorCount -gt 0) {
            Write-Log -Message "  Errors: $errorCount" -Color "Red" -LogBox $LogBox
        }

        # Show failed devices
        $failedDevices = $allResults | Where-Object { $_.Status -ne "Success" } | Select-Object -Property Hostname, Command, Status -Unique
        if ($failedDevices.Count -gt 0) {
            Write-Log -Message "" -LogBox $LogBox
            Write-Log -Message "Failed Operations:" -Color "Yellow" -LogBox $LogBox
            foreach ($failed in $failedDevices) {
                Write-Log -Message "  ✗ $($failed.Hostname) - $($failed.Command): $($failed.Status)" -Color "Red" -LogBox $LogBox
            }
        }

        Write-Log -Message "" -LogBox $LogBox
        Write-Log -Message "Output folder: $outputFolder" -Color "Green" -LogBox $LogBox

        $messageText = "Command execution complete!`n`nTotal operations: $totalOps`nSuccessful: $successCount"
        if ($timeoutCount + $failedCount + $errorCount -gt 0) {
            $messageText += "`nFailed: $($timeoutCount + $failedCount + $errorCount)"
        }
        $messageText += "`n`nOutput folder:`n$outputFolder"

        $iconType = if ($successCount -eq $totalOps) { [System.Windows.Forms.MessageBoxIcon]::Information } else { [System.Windows.Forms.MessageBoxIcon]::Warning }
        [System.Windows.Forms.MessageBox]::Show($messageText, "Execution Complete", [System.Windows.Forms.MessageBoxButtons]::OK, $iconType)

        # Open output folder
        Start-Process explorer.exe $outputFolder

    } catch {
        $sanitizedError = Get-SanitizedErrorMessage -ErrorRecord $_
        Write-Log -Message "Error during command execution: $sanitizedError" -Color "Red" -LogBox $LogBox
    }
}

# ============================================
# EXPORTS
# ============================================

Export-ModuleMember -Function @(
    # Connection Functions
    'Test-DNACTokenValid',
    'Connect-DNACenter',
    'Get-AllDNADevices',
    'Select-DNADevices',
    'Reset-DNADeviceSelection',

    # DNA Center API Functions
    'Get-NetworkDevicesBasic',
    'Get-NetworkDevicesDetailed',
    'Get-DeviceInventoryCount',
    'Get-NetworkHealth',
    'Get-ClientHealth',
    'Get-DeviceReachability',
    'Get-SitesLocations',
    'Get-ComplianceStatus',
    'Get-Templates',
    'Get-PhysicalTopology',
    'Get-OSPFNeighbors',
    'Get-CDPNeighbors',
    'Get-LLDPNeighbors',
    'Get-AccessPoints',
    'Get-IssuesEvents',
    'Get-SoftwareImageInfo',
    'Get-VLANs',
    'Get-DeviceModules',
    'Get-DeviceInterfaces',
    'Get-DeviceConfigurations',
    'Get-EventSeriesLastTimestamp',
    'Get-LastDeviceAvailabilityEventTime',
    'Get-LastDisconnectTime',
    'Get-LastPingReachableTime',
    'Invoke-PathTrace',
    'Invoke-CommandRunner',

    # Helper Functions
    'Write-Log',
    'Get-SanitizedErrorMessage',
    'ConvertTo-ReadableTimestamp',
    'Wait-ForTask',
    'Get-TaskFileId',
    'Test-IPAddress',
    'Get-SafeFileName',
    'Invoke-Filters',
    'Test-DnaFilterInput'
)
