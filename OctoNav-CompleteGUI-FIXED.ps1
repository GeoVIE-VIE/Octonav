#Requires -Version 5.1
<#
.SYNOPSIS
    OctoNav Complete GUI - Unified Network Management Tool (Security Hardened + DNACAPEiv6)
.DESCRIPTION
    Comprehensive Windows Forms GUI combining Network Configuration, DHCP Statistics, and DNA Center API functions
    Includes advanced DNACAPEiv6 functions: Path Trace, Last Disconnect Times, Availability Events

    PRIVILEGE REQUIREMENTS:
    - Network Configuration Tab: Requires Administrator privileges
    - All other tabs: Standard user privileges sufficient
.AUTHOR
    Integrated by Claude - In Memory of Zesty.PS1
.VERSION
    2.2 - Privilege Separation (Security Enhancement)
    - Removed global admin requirement
    - Only Network Configuration tab requires elevation
    - DHCP, DNA Center, and other functions run as standard user
    - 23 DNA Center API functions (up from 20)
    - Path Trace with interactive dialog
    - Device availability event tracking
    - Last disconnect time monitoring
    - All security enhancements from v2.0
#>

# Enable visual styles
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# Handle errors gracefully
$ErrorActionPreference = "Stop"

# ============================================
# PRIVILEGE MANAGEMENT
# ============================================

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Tests if the current PowerShell session is running with Administrator privileges
    .DESCRIPTION
        Uses WindowsIdentity and WindowsPrincipal to check if the current user has admin rights
    .OUTPUTS
        Boolean - $true if running as admin, $false otherwise
    #>
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Warning "Unable to determine administrator status: $($_.Exception.Message)"
        return $false
    }
}

# Store admin status globally for performance (check once)
$script:IsRunningAsAdmin = Test-IsAdministrator

# ============================================
# GLOBAL VARIABLES
# ============================================

# DNA Center Configuration - Load from environment or config file
# Set environment variables: DNAC_SERVER1_NAME, DNAC_SERVER1_URL, etc.
# Or create dna_config.json in script directory
function Get-DNACenterServers {
    $configFile = Join-Path $PSScriptRoot "dna_config.json"

    # Try to load from config file first
    if (Test-Path $configFile) {
        try {
            $config = Get-Content $configFile -Raw | ConvertFrom-Json
            if ($config.servers -and $config.servers.Count -gt 0) {
                Write-Verbose "Loaded DNA Center servers from config file"
                return $config.servers
            }
        } catch {
            Write-Warning "Failed to load config file: $($_.Exception.Message)"
        }
    }

    # Try environment variables
    $servers = @()
    for ($i = 1; $i -le 10; $i++) {
        $nameVar = "DNAC_SERVER${i}_NAME"
        $urlVar = "DNAC_SERVER${i}_URL"

        $name = [Environment]::GetEnvironmentVariable($nameVar)
        $url = [Environment]::GetEnvironmentVariable($urlVar)

        if ($name -and $url) {
            $servers += [pscustomobject]@{ Name = $name; Url = $url }
        }
    }

    if ($servers.Count -gt 0) {
        Write-Verbose "Loaded DNA Center servers from environment variables"
        return $servers
    }

    # Fallback to default (prompt user to configure)
    Write-Warning "No DNA Center servers configured. Please create dna_config.json or set environment variables."
    return @([pscustomobject]@{ Name = "Please Configure"; Url = "https://your-dnac-server.example.com" })
}

$script:dnaCenterServers = Get-DNACenterServers
$script:selectedDnaCenter = $null
$script:dnaCenterToken = $null
$script:dnaCenterTokenExpiry = $null
$script:dnaCenterHeaders = $null
$script:allDNADevices = @()
$script:selectedDNADevices = @()

# Output directory - validate and create if needed
$script:outputDir = if ($env:OCTONAV_OUTPUT_DIR) { $env:OCTONAV_OUTPUT_DIR } else { "C:\DNACenter_Reports" }
try {
    if (-not (Test-Path $script:outputDir)) {
        New-Item -ItemType Directory -Path $script:outputDir -Force -ErrorAction Stop | Out-Null
    }
    # Test write permissions
    $testFile = Join-Path $script:outputDir ".writetest"
    "test" | Out-File -FilePath $testFile -ErrorAction Stop
    Remove-Item $testFile -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Cannot write to output directory: $script:outputDir. Using temp directory."
    $script:outputDir = Join-Path $env:TEMP "OctoNav_Reports"
    New-Item -ItemType Directory -Path $script:outputDir -Force -ErrorAction SilentlyContinue | Out-Null
}

# Network Configuration Variables (XFER)
$script:OriginalConfig = $null
$script:TargetAdapter = $null
$script:NewIPAddress = $null
$script:NewGateway = $null
$script:BatchProcess = $null
$script:monitorJob = $null

# DHCP Variables
$script:dhcpResults = @()

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

function Test-PrefixLength {
    param([string]$Prefix)

    try {
        $prefixInt = [int]$Prefix
        return ($prefixInt -ge 0 -and $prefixInt -le 32)
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
function Apply-Filters {
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

function Test-ServerName {
    param([string]$ServerName)

    if ([string]::IsNullOrWhiteSpace($ServerName)) {
        return $false
    }

    $trimmed = $ServerName.Trim()

    # Check length (max DNS name length is 253 characters)
    if ($trimmed.Length -gt 253) {
        return $false
    }

    # Validate DNS hostname format (RFC 1123)
    # Allows: alphanumeric, hyphens, and dots
    # Each label must start/end with alphanumeric
    # Max label length is 63 characters
    if ($trimmed -notmatch '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$') {
        return $false
    }

    # Additional check: no consecutive dots or hyphens at start/end of labels
    if ($trimmed -match '\.\.' -or $trimmed -match '\.-' -or $trimmed -match '-\.') {
        return $false
    }

    return $true
}

function Test-ScopeFilter {
    param([string]$FilterValue)

    if ([string]::IsNullOrWhiteSpace($FilterValue)) {
        return $true
    }

    $trimmed = $FilterValue.Trim()

    # Limit length
    if ($trimmed.Length -gt 128) {
        return $false
    }

    # Only allow safe characters for scope names
    # Alphanumeric, spaces, underscores, hyphens, dots
    if ($trimmed -notmatch '^[a-zA-Z0-9_.\-\s]+$') {
        return $false
    }

    return $true
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

function Initialize-DNACenter {
    param([System.Windows.Forms.RichTextBox]$LogBox)

    try {
        # Ensure output directory exists
        if (-not (Test-Path $script:outputDir)) {
            New-Item -ItemType Directory -Path $script:outputDir -Force | Out-Null
        }

        # Bypass certificate validation (as per user requirements)
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
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13

        Write-Log -Message "DNA Center initialized" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Initialization error: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
        throw
    }
}

function Test-DNACTokenValid {
    # Check if token exists and is not expired
    if (-not $script:dnaCenterToken) {
        return $false
    }

    if ($script:dnaCenterTokenExpiry) {
        # Check if token has expired (with 5 minute buffer)
        $expiryWithBuffer = $script:dnaCenterTokenExpiry.AddMinutes(-5)
        if ((Get-Date) -gt $expiryWithBuffer) {
            Write-Verbose "DNA Center token has expired"
            return $false
        }
    }

    return $true
}

function Connect-DNACenter {
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
            $script:dnaCenterToken = $response.Token

            # DNA Center tokens typically expire after 1 hour
            $script:dnaCenterTokenExpiry = (Get-Date).AddHours(1)

            $script:dnaCenterHeaders = @{
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

function Load-AllDNADevices {
    param([System.Windows.Forms.RichTextBox]$LogBox)

    if (-not $script:dnaCenterHeaders) {
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
            $uri = "$($script:selectedDnaCenter)/dna/intent/api/v1/network-device?offset=$offset&limit=$pageSize"
            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 60

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
            $script:allDNADevices = $aggregatedDevices.ToArray()
            $script:selectedDNADevices = @()
            Write-Log -Message "Loaded $($script:allDNADevices.Count) devices" -Color "Green" -LogBox $LogBox
            return $true
        }

        return $false
    } catch {
        Write-Log -Message "Failed to load devices: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
        return $false
    }
}

function Filter-DNADevices {
    param(
        [string]$Hostname,
        [string]$IPAddress,
        [string]$Role,
        [string]$Family,
        [System.Windows.Forms.RichTextBox]$LogBox
    )

    if (-not $script:allDNADevices -or $script:allDNADevices.Count -eq 0) {
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

    $filtered = $script:allDNADevices | Where-Object {
        ($null -eq $hostPattern -or ($_.hostname -and $_.hostname -match $hostPattern)) -and
        ([string]::IsNullOrWhiteSpace($IPAddress) -or ($_.managementIpAddress -eq $IPAddress)) -and
        ($null -eq $rolePattern -or ($_.role -and $_.role -match $rolePattern)) -and
        ($null -eq $familyPattern -or ($_.family -and $_.family -match $familyPattern))
    }

    $script:selectedDNADevices = $filtered

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    $script:selectedDNADevices = $script:allDNADevices
    Write-Log -Message "Device selection reset to all devices" -Color "Yellow" -LogBox $LogBox
}

# ============================================
# NETWORK CONFIGURATION FUNCTIONS (XFER)
# ============================================

function Restore-NetworkDefaults {
    param([System.Windows.Forms.RichTextBox]$LogBox)

    # Check for administrator privileges
    if (-not $script:IsRunningAsAdmin) {
        Write-Log -Message "ERROR: Network configuration requires Administrator privileges" -Color "Red" -LogBox $LogBox
        Write-Log -Message "Please restart OctoNav as Administrator to use Network Configuration features" -Color "Yellow" -LogBox $LogBox
        [System.Windows.Forms.MessageBox]::Show(
            "Network configuration operations require Administrator privileges.`n`nPlease close OctoNav and restart it by right-clicking and selecting 'Run as Administrator'.",
            "Administrator Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return $false
    }

    Write-Log -Message "Restoring network to default settings..." -Color "Yellow" -LogBox $LogBox

    try {
        if ($script:BatchProcess -and !$script:BatchProcess.HasExited) {
            Write-Log -Message "Stopping RunStandAloneMT.bat process..." -Color "Yellow" -LogBox $LogBox
            Stop-Process -Id $script:BatchProcess.Id -Force -ErrorAction SilentlyContinue
        }

        if ($script:TargetAdapter -and $script:OriginalConfig) {
            $adapter = Get-NetAdapter -InterfaceIndex $script:TargetAdapter.ifIndex -ErrorAction SilentlyContinue

            if ($adapter) {
                if ($script:NewIPAddress) {
                    Write-Log -Message "Removing static IP configuration..." -Color "Yellow" -LogBox $LogBox
                    Remove-NetIPAddress -InterfaceIndex $script:TargetAdapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
                    Remove-NetRoute -InterfaceIndex $script:TargetAdapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
                }

                Write-Log -Message "Restoring DHCP configuration..." -Color "Yellow" -LogBox $LogBox
                Set-NetIPInterface -InterfaceIndex $script:TargetAdapter.ifIndex -Dhcp Enabled -ErrorAction SilentlyContinue
                Set-DnsClientServerAddress -InterfaceIndex $script:TargetAdapter.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue

                $profile = Get-NetConnectionProfile -InterfaceIndex $script:TargetAdapter.ifIndex -ErrorAction SilentlyContinue
                if ($profile -and $script:OriginalConfig.NetworkCategory) {
                    Write-Log -Message "Restoring network category..." -Color "Yellow" -LogBox $LogBox
                    Set-NetConnectionProfile -InterfaceIndex $script:TargetAdapter.ifIndex -NetworkCategory $script:OriginalConfig.NetworkCategory -ErrorAction SilentlyContinue
                }
            }
        }

        Write-Log -Message "Cleanup complete!" -Color "Green" -LogBox $LogBox
    } catch {
        Write-Log -Message "Cleanup error: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
    }
}

function Find-UnidentifiedNetwork {
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Looking for unidentified public networks with APIPA addresses..." -Color "Cyan" -LogBox $LogBox

    try {
        $publicProfiles = Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq 'Public' }

        foreach ($profile in $publicProfiles) {
            $ipAddresses = Get-NetIPAddress -InterfaceIndex $profile.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue

            foreach ($ip in $ipAddresses) {
                if ($ip.IPAddress -match '^169\.254\.') {
                    Write-Log -Message "Found: $($profile.InterfaceAlias) - $($ip.IPAddress)" -Color "Green" -LogBox $LogBox

                    return @{
                        Adapter = Get-NetAdapter -InterfaceIndex $profile.InterfaceIndex
                        Profile = $profile
                        IPAddress = $ip
                    }
                }
            }
        }

        foreach ($profile in $publicProfiles) {
            if ($profile.Name -match 'Unidentified' -or $profile.Name -match 'Network') {
                $adapter = Get-NetAdapter -InterfaceIndex $profile.InterfaceIndex
                $ipAddresses = Get-NetIPAddress -InterfaceIndex $profile.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue

                Write-Log -Message "Found: $($profile.InterfaceAlias)" -Color "Green" -LogBox $LogBox

                return @{
                    Adapter = $adapter
                    Profile = $profile
                    IPAddress = $ipAddresses | Select-Object -First 1
                }
            }
        }

        return $null
    } catch {
        Write-Log -Message "Error finding network: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
        return $null
    }
}

function Set-NetworkConfiguration {
    param(
        $Adapter,
        [string]$IPAddress,
        [string]$Gateway,
        [int]$PrefixLength = 24,
        [System.Windows.Forms.RichTextBox]$LogBox
    )

    # Check for administrator privileges
    if (-not $script:IsRunningAsAdmin) {
        Write-Log -Message "ERROR: Network configuration requires Administrator privileges" -Color "Red" -LogBox $LogBox
        Write-Log -Message "Please restart OctoNav as Administrator to use Network Configuration features" -Color "Yellow" -LogBox $LogBox
        [System.Windows.Forms.MessageBox]::Show(
            "Network configuration operations require Administrator privileges.`n`nPlease close OctoNav and restart it by right-clicking and selecting 'Run as Administrator'.",
            "Administrator Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return $false
    }

    try {
        # Validate inputs
        if (-not (Test-IPAddress -IPAddress $IPAddress)) {
            Write-Log -Message "Invalid IP address format: $IPAddress" -Color "Red" -LogBox $LogBox
            return $false
        }

        if (-not (Test-IPAddress -IPAddress $Gateway)) {
            Write-Log -Message "Invalid gateway format: $Gateway" -Color "Red" -LogBox $LogBox
            return $false
        }

        if (-not (Test-PrefixLength -Prefix $PrefixLength)) {
            Write-Log -Message "Invalid prefix length: $PrefixLength" -Color "Red" -LogBox $LogBox
            return $false
        }

        Write-Log -Message "Applying network configuration..." -Color "Cyan" -LogBox $LogBox

        Remove-NetIPAddress -InterfaceIndex $Adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
        Remove-NetRoute -InterfaceIndex $Adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue

        Write-Log -Message "Setting IP: $IPAddress/$PrefixLength, Gateway: $Gateway" -Color "Yellow" -LogBox $LogBox
        New-NetIPAddress -InterfaceIndex $Adapter.ifIndex -IPAddress $IPAddress -PrefixLength $PrefixLength -DefaultGateway $Gateway -ErrorAction Stop | Out-Null

        Set-NetIPInterface -InterfaceIndex $Adapter.ifIndex -Dhcp Disabled -ErrorAction Stop

        Write-Log -Message "Configuration applied successfully!" -Color "Green" -LogBox $LogBox
        return $true
    } catch {
        Write-Log -Message "Failed to apply configuration: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
        return $false
    }
}

# ============================================
# DHCP FUNCTIONS
# ============================================

function Get-DHCPScopeStatistics {
    param(
        [string[]]$ScopeFilters = @(),
        [string[]]$SpecificServers = @(),
        [bool]$IncludeDNS = $false,
        [bool]$IncludeBadAddresses = $false,
        [System.Windows.Forms.RichTextBox]$LogBox
    )

    try {
        # Get DHCP servers
        if ($SpecificServers.Count -gt 0) {
            Write-Log -Message "Using specified DHCP servers..." -Color "Cyan" -LogBox $LogBox

            # Validate all server names before processing
            $validServers = @()
            foreach ($server in $SpecificServers) {
                $trimmedServer = $server.Trim()
                if (Test-ServerName -ServerName $trimmedServer) {
                    $validServers += $trimmedServer
                } else {
                    Write-Log -Message "Invalid DHCP server name skipped: $trimmedServer" -Color "Yellow" -LogBox $LogBox
                }
            }

            if ($validServers.Count -eq 0) {
                Write-Log -Message "No valid DHCP server names provided" -Color "Red" -LogBox $LogBox
                return @()
            }

            $DHCPServers = $validServers | ForEach-Object {
                [PSCustomObject]@{ DnsName = $_ }
            }
            Write-Log -Message "Validated $($DHCPServers.Count) DHCP server name(s)" -Color "Green" -LogBox $LogBox
        } else {
            Write-Log -Message "Discovering DHCP servers in domain..." -Color "Cyan" -LogBox $LogBox
            try {
                $DHCPServers = Get-DhcpServerInDC
                Write-Log -Message "Found $($DHCPServers.Count) DHCP servers" -Color "Green" -LogBox $LogBox
            } catch {
                $sanitizedError = Get-SanitizedErrorMessage -ErrorRecord $_
                Write-Log -Message "Failed to get DHCP servers: $sanitizedError" -Color "Red" -LogBox $LogBox
                return @()
            }
        }

        # Script block for parallel processing
        $ScriptBlock = {
            param($DHCPServerName, $ScopeFilters, $IncludeDNS, $IncludeBadAddresses)

            $ServerStats = @()

            try {
                $Scopes = Get-DhcpServerv4Scope -ComputerName $DHCPServerName -ErrorAction Stop

                # Apply filtering if scope filters are provided - matches Merged-DHCPScopeStats.ps1
                if ($ScopeFilters -and $ScopeFilters.Count -gt 0) {
                    $OriginalScopeCount = $Scopes.Count
                    Write-Output "Found $OriginalScopeCount total scope(s) on $DHCPServerName, applying filters..."

                    $FilteredScopes = @()
                    foreach ($Filter in $ScopeFilters) {
                        # Explicitly case-insensitive matching using .ToUpper() for both sides
                        $MatchingScopes = $Scopes | Where-Object { $_.Name.ToUpper() -like "*$Filter*" }

                        if ($MatchingScopes) {
                            Write-Output "  Filter '$Filter' matched $($MatchingScopes.Count) scope(s)"
                            $FilteredScopes += $MatchingScopes
                        } else {
                            Write-Output "  Filter '$Filter' matched 0 scopes"
                        }
                    }

                    # Remove duplicates if a scope matched multiple filters
                    $Scopes = $FilteredScopes | Select-Object -Unique

                    if ($Scopes.Count -eq 0) {
                        Write-Output "WARNING: No scopes matching filter criteria on $DHCPServerName"
                        Write-Output "  Filters used: $($ScopeFilters -join ', ')"
                        Write-Output "  Available scope names on this server might not contain these strings"
                        return @()
                    } else {
                        Write-Output "After filtering: $($Scopes.Count) scope(s) will be processed on $DHCPServerName"
                    }
                }

                $AllStatsRaw = Get-DhcpServerv4ScopeStatistics -ComputerName $DHCPServerName -ErrorAction Stop

                $DNSServerMap = @{}
                if ($IncludeDNS) {
                    foreach ($Scope in $Scopes) {
                        try {
                            $DNSOption = Get-DhcpServerv4OptionValue -ComputerName $DHCPServerName -ScopeId $Scope.ScopeId -OptionId 6 -ErrorAction SilentlyContinue
                            if ($DNSOption) {
                                $DNSServerMap[$Scope.ScopeId] = $DNSOption.Value -join ','
                            }
                        } catch {
                            # DNS option not found for this scope
                        }
                    }
                }

                $BadAddressMap = @{}
                if ($IncludeBadAddresses) {
                    foreach ($Scope in $Scopes) {
                        try {
                            $BadAddresses = Get-DhcpServerv4Lease -ComputerName $DHCPServerName -ScopeId $Scope.ScopeId -ErrorAction SilentlyContinue |
                                Where-Object { $_.HostName -eq "BAD_ADDRESS" }

                            $BadAddressMap[$Scope.ScopeId] = if ($BadAddresses) { $BadAddresses.Count } else { 0 }
                        } catch {
                            $BadAddressMap[$Scope.ScopeId] = 0
                        }
                    }
                }

                foreach ($Scope in $Scopes) {
                    $Stats = $AllStatsRaw | Where-Object { $_.ScopeId -eq $Scope.ScopeId }

                    if ($Stats) {
                        $ServerStats += $Stats | Select-Object *,
                            @{Name='DHCPServer'; Expression={$DHCPServerName}},
                            @{Name='Description'; Expression={if (-not [string]::IsNullOrWhiteSpace($Scope.Description)) { $Scope.Description } else { $Scope.Name }}},
                            @{Name='DNSServers'; Expression={$DNSServerMap[$Scope.ScopeId]}},
                            @{Name='BadAddressCount'; Expression={$BadAddressMap[$Scope.ScopeId]}}
                    }
                }
            } catch {
                Write-Error "Error querying $DHCPServerName : $($_.Exception.Message)"
            }

            return $ServerStats
        }

        # Process servers in parallel - maintain constant pool of 20 running jobs
        $Jobs = @()
        $AllStats = @()
        $MaxConcurrentJobs = 20
        $TotalServers = $DHCPServers.Count
        $ServerIndex = 0

        Write-Log -Message "Starting parallel processing of $TotalServers DHCP servers (maintaining 20 concurrent jobs)..." -Color "Cyan" -LogBox $LogBox

        # Start initial batch of jobs (up to 20)
        while ($ServerIndex -lt $TotalServers -and $Jobs.Count -lt $MaxConcurrentJobs) {
            $Server = $DHCPServers[$ServerIndex]
            $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Server.DnsName, $ScopeFilters, $IncludeDNS, $IncludeBadAddresses
            $Jobs += @{
                Job = $Job
                ServerName = $Server.DnsName
                Processed = $false
            }
            $ServerIndex++
        }

        # Process jobs and maintain constant pool of 20
        while ($Jobs | Where-Object { -not $_.Processed }) {
            Start-Sleep -Seconds 2

            # Handle completed jobs
            $CompletedJobs = $Jobs | Where-Object { $_.Job.State -eq 'Completed' -and -not $_.Processed }
            foreach ($CompletedJob in $CompletedJobs) {
                $CompletedJob.Processed = $true
                Write-Log -Message "Completed: $($CompletedJob.ServerName)" -Color "Green" -LogBox $LogBox

                try {
                    $Result = Receive-Job -Job $CompletedJob.Job -ErrorAction Stop
                    if ($Result) {
                        $AllStats += $Result
                    }
                } catch {
                    Write-Log -Message "Failed to receive from $($CompletedJob.ServerName): $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
                }

                Remove-Job -Job $CompletedJob.Job -Force

                # Start new job if more servers remain
                if ($ServerIndex -lt $TotalServers) {
                    $Server = $DHCPServers[$ServerIndex]
                    $NewJob = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Server.DnsName, $ScopeFilters, $IncludeDNS, $IncludeBadAddresses
                    $Jobs += @{
                        Job = $NewJob
                        ServerName = $Server.DnsName
                        Processed = $false
                    }
                    $ServerIndex++
                }
            }

            # Handle failed jobs
            $FailedJobs = $Jobs | Where-Object { $_.Job.State -eq 'Failed' -and -not $_.Processed }
            foreach ($FailedJob in $FailedJobs) {
                $FailedJob.Processed = $true
                Write-Log -Message "Failed: $($FailedJob.ServerName)" -Color "Red" -LogBox $LogBox
                Remove-Job -Job $FailedJob.Job -Force

                # Start new job if more servers remain
                if ($ServerIndex -lt $TotalServers) {
                    $Server = $DHCPServers[$ServerIndex]
                    $NewJob = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Server.DnsName, $ScopeFilters, $IncludeDNS, $IncludeBadAddresses
                    $Jobs += @{
                        Job = $NewJob
                        ServerName = $Server.DnsName
                        Processed = $false
                    }
                    $ServerIndex++
                }
            }
        }

        Write-Log -Message "Found $($AllStats.Count) total DHCP scopes" -Color "Green" -LogBox $LogBox

        return $AllStats
    } catch {
        Write-Log -Message "DHCP collection error: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
        return @()
    }
}

# ============================================
# DNA CENTER API FUNCTIONS (20 Functions)
# ============================================

function Get-NetworkDevicesBasic {
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching network devices (basic info)..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($script:selectedDNADevices.Count -gt 0) { $script:selectedDNADevices } else { $script:allDNADevices }

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching network devices (detailed info)..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($script:selectedDNADevices.Count -gt 0) { $script:selectedDNADevices } else { $script:allDNADevices }

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Calculating device inventory counts..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($script:selectedDNADevices.Count -gt 0) { $script:selectedDNADevices } else { $script:allDNADevices }

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching network health..." -Color "Yellow" -LogBox $LogBox

    try {
        $timestamp_ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/network-health?timestamp=$timestamp_ms" -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 30

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching client health..." -Color "Yellow" -LogBox $LogBox

    try {
        $timestamp_ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/client-health?timestamp=$timestamp_ms" -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 30

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching device reachability status..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($script:selectedDNADevices.Count -gt 0) { $script:selectedDNADevices } else { $script:allDNADevices }

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching sites and locations..." -Color "Yellow" -LogBox $LogBox

    try {
        $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/site" -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 30

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching compliance status..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($script:selectedDNADevices.Count -gt 0) { $script:selectedDNADevices } else { $script:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $complianceList = @()

        foreach ($device in $devices) {
            try {
                $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/compliance/$($device.id)" -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 15

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching configuration templates..." -Color "Yellow" -LogBox $LogBox

    try {
        $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/template-programmer/template" -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 30

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching physical topology..." -Color "Yellow" -LogBox $LogBox

    try {
        $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/topology/physical-topology" -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 30

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching OSPF neighbors..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($script:selectedDNADevices.Count -gt 0) { $script:selectedDNADevices } else { $script:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $ospfList = @()

        foreach ($device in $devices) {
            try {
                $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/network-device/$($device.id)/ospf-neighbor" -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 15

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching CDP neighbors..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($script:selectedDNADevices.Count -gt 0) { $script:selectedDNADevices } else { $script:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $cdpList = @()

        foreach ($device in $devices) {
            try {
                $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/network-device/$($device.id)/neighbor" -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 15

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching LLDP neighbors..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($script:selectedDNADevices.Count -gt 0) { $script:selectedDNADevices } else { $script:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $lldpList = @()

        foreach ($device in $devices) {
            try {
                $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/network-device/$($device.id)/interface/lldp" -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 15

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching access points..." -Color "Yellow" -LogBox $LogBox

    try {
        $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/wireless/access-point" -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 30

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching issues and events..." -Color "Yellow" -LogBox $LogBox

    try {
        $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/issues" -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 30

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching software/image information..." -Color "Yellow" -LogBox $LogBox

    try {
        $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/image/importation" -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 30

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching VLANs..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($script:selectedDNADevices.Count -gt 0) { $script:selectedDNADevices } else { $script:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $vlanList = @()

        foreach ($device in $devices) {
            try {
                $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/interface/network-device/$($device.id)" -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 15

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching device module information..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($script:selectedDNADevices.Count -gt 0) { $script:selectedDNADevices } else { $script:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $moduleList = @()

        foreach ($device in $devices) {
            try {
                $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/network-device/module?deviceId=$($device.id)" -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 15

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching device interfaces..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($script:selectedDNADevices.Count -gt 0) { $script:selectedDNADevices } else { $script:allDNADevices }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
            return
        }

        $interfaceList = @()

        foreach ($device in $devices) {
            try {
                $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/interface/network-device/$($device.id)" -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 15

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    Write-Log -Message "Fetching device configurations..." -Color "Yellow" -LogBox $LogBox

    try {
        $devices = if ($script:selectedDNADevices.Count -gt 0) { $script:selectedDNADevices } else { $script:allDNADevices }

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
                $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/network-device/$($device.id)/config" -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 30

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

# ============================================
# ADVANCED DNA CENTER FUNCTIONS (from DNACAPEiv6)
# ============================================

function Get-EventSeriesLastTimestamp {
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

    $baseUrl = "$($script:selectedDnaCenter)/dna/data/api/v1/event/event-series"
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
        $response = Invoke-RestMethod -Uri $requestUrl -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 30
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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    try {
        $devices = if ($script:selectedDNADevices.Count -gt 0) { $script:selectedDNADevices } else { $script:allDNADevices }

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
    param([System.Windows.Forms.RichTextBox]$LogBox)

    try {
        $devices = if ($script:selectedDNADevices.Count -gt 0) { $script:selectedDNADevices } else { $script:allDNADevices }

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
            $enrichmentUrl = "$($script:selectedDnaCenter)/dna/intent/api/v1/network-device/$($device.id)/enrichment-details"

            try {
                $response = Invoke-RestMethod -Uri $enrichmentUrl -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 30

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

function Invoke-PathTrace {
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

        $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/flow-analysis" `
            -Method Post `
            -Headers $script:dnaCenterHeaders `
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

                $statusResponse = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/flow-analysis/$flowAnalysisId" `
                    -Method Get `
                    -Headers $script:dnaCenterHeaders `
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

function Get-LastPingReachableTime {
    param([System.Windows.Forms.RichTextBox]$LogBox)

    try {
        $devices = if ($script:selectedDNADevices.Count -gt 0) { $script:selectedDNADevices } else { $script:allDNADevices }

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
                    $enrichmentUrl = "$($script:selectedDnaCenter)/dna/intent/api/v1/network-device/$deviceId"
                    $response = Invoke-RestMethod -Uri $enrichmentUrl -Method Get -Headers $script:dnaCenterHeaders -TimeoutSec 30

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

function Invoke-CommandRunner {
    param([System.Windows.Forms.RichTextBox]$LogBox)

    if (-not (Test-DNACTokenValid)) {
        Write-Log -Message "DNA Center token expired or invalid" -Color "Red" -LogBox $LogBox
        [System.Windows.Forms.MessageBox]::Show("Please connect to DNA Center first", "Not Authenticated", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $devices = if ($script:selectedDNADevices.Count -gt 0) { $script:selectedDNADevices } else { $script:allDNADevices }

    if (-not $devices -or $devices.Count -eq 0) {
        Write-Log -Message "No devices available" -Color "Red" -LogBox $LogBox
        [System.Windows.Forms.MessageBox]::Show("Please load devices first", "No Devices", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    # Create command input dialog
    $cmdForm = New-Object System.Windows.Forms.Form
    $cmdForm.Text = "Execute CLI Command"
    $cmdForm.Size = New-Object System.Drawing.Size(600, 350)
    $cmdForm.StartPosition = "CenterParent"
    $cmdForm.FormBorderStyle = "FixedDialog"
    $cmdForm.MaximizeBox = $false

    $y = 20

    # Info label
    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Text = "Execute CLI command on $($devices.Count) device(s)"
    $lblInfo.Location = New-Object System.Drawing.Point(20, $y)
    $lblInfo.Size = New-Object System.Drawing.Size(550, 20)
    $lblInfo.Font = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Bold)
    $cmdForm.Controls.Add($lblInfo)

    $y += 30

    # Command label
    $lblCommand = New-Object System.Windows.Forms.Label
    $lblCommand.Text = "CLI Command(s) - one per line:"
    $lblCommand.Location = New-Object System.Drawing.Point(20, $y)
    $lblCommand.Size = New-Object System.Drawing.Size(200, 20)
    $cmdForm.Controls.Add($lblCommand)

    $y += 25

    # Command textbox (multiline)
    $txtCommand = New-Object System.Windows.Forms.TextBox
    $txtCommand.Multiline = $true
    $txtCommand.ScrollBars = "Vertical"
    $txtCommand.Location = New-Object System.Drawing.Point(20, $y)
    $txtCommand.Size = New-Object System.Drawing.Size(550, 100)
    $txtCommand.Font = New-Object System.Drawing.Font("Consolas", 9)
    $cmdForm.Controls.Add($txtCommand)

    $y += 110

    # Warning label
    $lblWarning = New-Object System.Windows.Forms.Label
    $lblWarning.Text = "Note: Pipes (|) are not supported. Use plain commands only."
    $lblWarning.Location = New-Object System.Drawing.Point(20, $y)
    $lblWarning.Size = New-Object System.Drawing.Size(550, 20)
    $lblWarning.ForeColor = [System.Drawing.Color]::DarkOrange
    $cmdForm.Controls.Add($lblWarning)

    $y += 30

    # Output filter label
    $lblFilter = New-Object System.Windows.Forms.Label
    $lblFilter.Text = "Output Filters (optional, comma-separated patterns, OR logic):"
    $lblFilter.Location = New-Object System.Drawing.Point(20, $y)
    $lblFilter.Size = New-Object System.Drawing.Size(400, 20)
    $cmdForm.Controls.Add($lblFilter)

    $y += 25

    # Filter textbox
    $txtFilter = New-Object System.Windows.Forms.TextBox
    $txtFilter.Location = New-Object System.Drawing.Point(20, $y)
    $txtFilter.Size = New-Object System.Drawing.Size(550, 20)
    $cmdForm.Controls.Add($txtFilter)

    $y += 40

    # Execute button
    $btnExecute = New-Object System.Windows.Forms.Button
    $btnExecute.Text = "Execute"
    $btnExecute.Location = New-Object System.Drawing.Point(20, $y)
    $btnExecute.Size = New-Object System.Drawing.Size(100, 30)
    $cmdForm.Controls.Add($btnExecute)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Location = New-Object System.Drawing.Point(130, $y)
    $btnCancel.Size = New-Object System.Drawing.Size(100, 30)
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

    # Parse filters (comma-separated) - matches DNACAPEiv6_COMPLETE behavior
    $outputFilters = @()
    $filterText = $txtFilter.Text.Trim()
    if (-not [string]::IsNullOrWhiteSpace($filterText)) {
        $outputFilters = $filterText.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        if ($outputFilters.Count -gt 0) {
            Write-Log -Message "Output filters: $($outputFilters -join ', ')" -Color "Yellow" -LogBox $LogBox
        }
    }

    Write-Log -Message "Executing $($commandLines.Count) command(s) on $($devices.Count) device(s)..." -Color "Cyan" -LogBox $LogBox

    foreach ($cmd in $commandLines) {
        Write-Log -Message "Command: $cmd" -Color "Yellow" -LogBox $LogBox
    }

    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $outputFolder = Join-Path -Path $script:outputDir -ChildPath "CommandRunner_$timestamp"
        New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null

        $allResults = @()

        foreach ($device in $devices) {
            $hostname = if ($device.hostname) { $device.hostname } else { "Unknown" }
            $deviceId = $device.id

            foreach ($cmd in $commandLines) {
                Write-Log -Message "[$hostname] Submitting: $cmd" -Color "Gray" -LogBox $LogBox

                $requestBody = @{
                    "name" = "GUI-Cmd-$hostname-$(Get-Random)"
                    "commands" = @($cmd)
                    "deviceUuids" = @($deviceId)
                } | ConvertTo-Json -Depth 10

                try {
                    $response = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/network-device-poller/cli/read-request" `
                        -Method Post `
                        -Headers $script:dnaCenterHeaders `
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

                            $taskResponse = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/task/$taskId" `
                                -Method Get `
                                -Headers $script:dnaCenterHeaders `
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
                            $fileResponse = Invoke-RestMethod -Uri "$($script:selectedDnaCenter)/dna/intent/api/v1/file/$fileId" `
                                -Method Get `
                                -Headers $script:dnaCenterHeaders `
                                -TimeoutSec 30

                            $outputText = ""
                            if ($fileResponse) {
                                if ($fileResponse -is [string]) {
                                    $outputText = $fileResponse
                                } else {
                                    try {
                                        $fileData = $fileResponse | ConvertFrom-Json
                                        if ($fileData -is [array] -and $fileData.Count -gt 0 -and $fileData[0].PSObject.Properties['commandResponses']) {
                                            $outputText = ($fileData[0].commandResponses.SUCCESS -join "`n")
                                        }
                                    } catch {
                                        $outputText = $fileResponse | Out-String
                                    }
                                }
                            }

                            # Apply filters if specified - matches DNACAPEiv6_COMPLETE behavior
                            $filteredOutput = $outputText
                            if ($outputFilters.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($outputText)) {
                                $lines = $outputText -split "`n"
                                $filteredLines = Apply-Filters -Lines $lines -Filters $outputFilters
                                $filteredOutput = $filteredLines -join "`n"
                            }

                            # Save to individual file
                            $safeHostname = Get-SafeFileName -InputName $hostname
                            $safeCommand = Get-SafeFileName -InputName $cmd
                            $outputFile = Join-Path -Path $outputFolder -ChildPath "${safeHostname}_${safeCommand}.txt"
                            $filteredOutput | Out-File -FilePath $outputFile -Encoding UTF8

                            $allResults += [PSCustomObject]@{
                                Hostname = $hostname
                                DeviceIP = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                                Command = $cmd
                                Status = "Success"
                                OutputFile = $outputFile
                                OutputLength = $filteredOutput.Length
                            }

                            Write-Log -Message "[$hostname] Success - output saved" -Color "Green" -LogBox $LogBox
                        } else {
                            $allResults += [PSCustomObject]@{
                                Hostname = $hostname
                                DeviceIP = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                                Command = $cmd
                                Status = "Timeout"
                                OutputFile = "N/A"
                                OutputLength = 0
                            }
                            Write-Log -Message "[$hostname] Timeout - no output received" -Color "Yellow" -LogBox $LogBox
                        }
                    } else {
                        $allResults += [PSCustomObject]@{
                            Hostname = $hostname
                            DeviceIP = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
                            Command = $cmd
                            Status = "Submit Failed"
                            OutputFile = "N/A"
                            OutputLength = 0
                        }
                        Write-Log -Message "[$hostname] Failed to submit command" -Color "Red" -LogBox $LogBox
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
                    }
                    Write-Log -Message "[$hostname] Error: $sanitizedError" -Color "Red" -LogBox $LogBox
                }

                # Small delay between commands
                Start-Sleep -Milliseconds 500
            }
        }

        # Export summary CSV
        $csvPath = Join-Path -Path $outputFolder -ChildPath "CommandRunner_Summary_$timestamp.csv"
        $allResults | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "Command execution complete!" -Color "Green" -LogBox $LogBox
        Write-Log -Message "Output folder: $outputFolder" -Color "Green" -LogBox $LogBox
        Write-Log -Message "Summary CSV: $csvPath" -Color "Green" -LogBox $LogBox

        [System.Windows.Forms.MessageBox]::Show("Command execution complete!`n`nOutput folder: $outputFolder`nSummary: $csvPath", "Execution Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        $sanitizedError = Get-SanitizedErrorMessage -ErrorRecord $_
        Write-Log -Message "Error during command execution: $sanitizedError" -Color "Red" -LogBox $LogBox
    }
}

# ============================================
# CREATE GUI
# ============================================

# Main Form
$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Text = "OctoNav v2.2 - Network Management Tool"
$mainForm.Size = New-Object System.Drawing.Size(1000, 700)
$mainForm.StartPosition = "CenterScreen"
$mainForm.FormBorderStyle = "Sizable"
$mainForm.MaximizeBox = $true
$mainForm.MinimumSize = New-Object System.Drawing.Size(900, 650)

# Create Tab Control
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Size = New-Object System.Drawing.Size(980, 650)
$tabControl.Location = New-Object System.Drawing.Point(10, 10)
$tabControl.Anchor = "Top, Left, Right, Bottom"
$mainForm.Controls.Add($tabControl)

# ============================================
# TAB 1: NETWORK CONFIGURATION (XFER)
# ============================================

$tab1 = New-Object System.Windows.Forms.TabPage
$tab1.Text = "Network Configuration"
$tabControl.Controls.Add($tab1)

# Admin Status Indicator for Network Config Tab
$lblAdminStatus = New-Object System.Windows.Forms.Label
$lblAdminStatus.Size = New-Object System.Drawing.Size(940, 25)
$lblAdminStatus.Location = New-Object System.Drawing.Point(10, 10)
$lblAdminStatus.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblAdminStatus.TextAlign = "MiddleLeft"
if ($script:IsRunningAsAdmin) {
    $lblAdminStatus.Text = "✓ Administrator Privileges: ACTIVE - Network configuration enabled"
    $lblAdminStatus.ForeColor = [System.Drawing.Color]::Green
    $lblAdminStatus.BackColor = [System.Drawing.Color]::FromArgb(230, 255, 230)  # Light green
} else {
    $lblAdminStatus.Text = "⚠ Administrator Required - Right-click and select 'Run as Administrator' to enable this tab"
    $lblAdminStatus.ForeColor = [System.Drawing.Color]::DarkOrange
    $lblAdminStatus.BackColor = [System.Drawing.Color]::FromArgb(255, 245, 230)  # Light orange
}
$tab1.Controls.Add($lblAdminStatus)

# Group Box for Network Settings
$netGroupBox = New-Object System.Windows.Forms.GroupBox
$netGroupBox.Text = "Network Adapter Configuration"
$netGroupBox.Size = New-Object System.Drawing.Size(940, 250)
$netGroupBox.Location = New-Object System.Drawing.Point(10, 40)
$tab1.Controls.Add($netGroupBox)

# Find Network Button
$btnFindNetwork = New-Object System.Windows.Forms.Button
$btnFindNetwork.Text = "Find Unidentified Network"
$btnFindNetwork.Size = New-Object System.Drawing.Size(200, 30)
$btnFindNetwork.Location = New-Object System.Drawing.Point(20, 30)
$netGroupBox.Controls.Add($btnFindNetwork)

# IP Address Label
$lblIPAddress = New-Object System.Windows.Forms.Label
$lblIPAddress.Text = "New IP Address:"
$lblIPAddress.Size = New-Object System.Drawing.Size(120, 20)
$lblIPAddress.Location = New-Object System.Drawing.Point(20, 80)
$netGroupBox.Controls.Add($lblIPAddress)

# IP Address TextBox
$txtIPAddress = New-Object System.Windows.Forms.TextBox
$txtIPAddress.Size = New-Object System.Drawing.Size(200, 20)
$txtIPAddress.Location = New-Object System.Drawing.Point(150, 78)
$netGroupBox.Controls.Add($txtIPAddress)

# Gateway Label
$lblGateway = New-Object System.Windows.Forms.Label
$lblGateway.Text = "Gateway:"
$lblGateway.Size = New-Object System.Drawing.Size(120, 20)
$lblGateway.Location = New-Object System.Drawing.Point(20, 120)
$netGroupBox.Controls.Add($lblGateway)

# Gateway TextBox
$txtGateway = New-Object System.Windows.Forms.TextBox
$txtGateway.Size = New-Object System.Drawing.Size(200, 20)
$txtGateway.Location = New-Object System.Drawing.Point(150, 118)
$netGroupBox.Controls.Add($txtGateway)

# Prefix Length Label
$lblPrefix = New-Object System.Windows.Forms.Label
$lblPrefix.Text = "Prefix Length:"
$lblPrefix.Size = New-Object System.Drawing.Size(120, 20)
$lblPrefix.Location = New-Object System.Drawing.Point(20, 160)
$netGroupBox.Controls.Add($lblPrefix)

# Prefix Length TextBox
$txtPrefix = New-Object System.Windows.Forms.TextBox
$txtPrefix.Text = "24"
$txtPrefix.Size = New-Object System.Drawing.Size(200, 20)
$txtPrefix.Location = New-Object System.Drawing.Point(150, 158)
$netGroupBox.Controls.Add($txtPrefix)

# Apply Configuration Button
$btnApplyConfig = New-Object System.Windows.Forms.Button
$btnApplyConfig.Text = "Apply Configuration"
$btnApplyConfig.Size = New-Object System.Drawing.Size(200, 30)
$btnApplyConfig.Location = New-Object System.Drawing.Point(20, 200)
$netGroupBox.Controls.Add($btnApplyConfig)

# Restore Defaults Button
$btnRestoreDefaults = New-Object System.Windows.Forms.Button
$btnRestoreDefaults.Text = "Restore Defaults"
$btnRestoreDefaults.Size = New-Object System.Drawing.Size(200, 30)
$btnRestoreDefaults.Location = New-Object System.Drawing.Point(240, 200)
$netGroupBox.Controls.Add($btnRestoreDefaults)

# Network Config Log
$netLogBox = New-Object System.Windows.Forms.RichTextBox
$netLogBox.Size = New-Object System.Drawing.Size(940, 310)
$netLogBox.Location = New-Object System.Drawing.Point(10, 300)
$netLogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$netLogBox.ReadOnly = $true
$tab1.Controls.Add($netLogBox)

# Event Handlers for Tab 1
$btnFindNetwork.Add_Click({
    try {
        $networkInfo = Find-UnidentifiedNetwork -LogBox $netLogBox

        if ($networkInfo) {
            $script:TargetAdapter = $networkInfo.Adapter
            $script:OriginalConfig = @{
                NetworkCategory = $networkInfo.Profile.NetworkCategory
                DHCP = (Get-NetIPInterface -InterfaceIndex $script:TargetAdapter.ifIndex -AddressFamily IPv4).Dhcp
            }

            Write-Log -Message "Adapter found and ready for configuration" -Color "Green" -LogBox $netLogBox
        } else {
            Write-Log -Message "No unidentified network found" -Color "Red" -LogBox $netLogBox
        }
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $netLogBox
    }
})

$btnApplyConfig.Add_Click({
    try {
        if (-not $script:TargetAdapter) {
            Write-Log -Message "Please find a network adapter first" -Color "Red" -LogBox $netLogBox
            return
        }

        $ip = $txtIPAddress.Text.Trim()
        $gateway = $txtGateway.Text.Trim()
        $prefixText = $txtPrefix.Text.Trim()

        # Validate IP address
        if (-not (Test-IPAddress -IPAddress $ip)) {
            Write-Log -Message "Invalid IP address format. Please enter a valid IPv4 address (e.g., 192.168.1.100)" -Color "Red" -LogBox $netLogBox
            [System.Windows.Forms.MessageBox]::Show("Invalid IP address format!", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        # Validate gateway
        if (-not (Test-IPAddress -IPAddress $gateway)) {
            Write-Log -Message "Invalid gateway format. Please enter a valid IPv4 address" -Color "Red" -LogBox $netLogBox
            [System.Windows.Forms.MessageBox]::Show("Invalid gateway format!", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        # Validate prefix
        if (-not (Test-PrefixLength -Prefix $prefixText)) {
            Write-Log -Message "Invalid prefix length. Must be between 0 and 32" -Color "Red" -LogBox $netLogBox
            [System.Windows.Forms.MessageBox]::Show("Invalid prefix length! Must be between 0 and 32", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        $prefix = [int]$prefixText
        $script:NewIPAddress = $ip
        $script:NewGateway = $gateway

        $success = Set-NetworkConfiguration -Adapter $script:TargetAdapter -IPAddress $ip -Gateway $gateway -PrefixLength $prefix -LogBox $netLogBox

        if ($success) {
            [System.Windows.Forms.MessageBox]::Show("Network configuration applied successfully!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $netLogBox
        [System.Windows.Forms.MessageBox]::Show("Error applying configuration: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$btnRestoreDefaults.Add_Click({
    try {
        Restore-NetworkDefaults -LogBox $netLogBox
        [System.Windows.Forms.MessageBox]::Show("Network defaults restored!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $netLogBox
    }
})

# ============================================
# TAB 2: DHCP STATISTICS
# ============================================

$tab2 = New-Object System.Windows.Forms.TabPage
$tab2.Text = "DHCP Statistics"
$tabControl.Controls.Add($tab2)

# Info Label
$lblDHCPInfo = New-Object System.Windows.Forms.Label
$lblDHCPInfo.Text = "Collect and analyze DHCP scope statistics from domain DHCP servers"
$lblDHCPInfo.Location = New-Object System.Drawing.Point(15, 15)
$lblDHCPInfo.Size = New-Object System.Drawing.Size(900, 20)
$lblDHCPInfo.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Italic)
$lblDHCPInfo.ForeColor = [System.Drawing.Color]::DarkBlue
$tab2.Controls.Add($lblDHCPInfo)

# Server Configuration Group
$dhcpServerGroupBox = New-Object System.Windows.Forms.GroupBox
$dhcpServerGroupBox.Text = "Server Configuration"
$dhcpServerGroupBox.Size = New-Object System.Drawing.Size(940, 110)
$dhcpServerGroupBox.Location = New-Object System.Drawing.Point(10, 40)
$tab2.Controls.Add($dhcpServerGroupBox)

$lblServerInfo = New-Object System.Windows.Forms.Label
$lblServerInfo.Text = "Specify DHCP servers (comma-separated, leave blank to auto-discover from domain):"
$lblServerInfo.Location = New-Object System.Drawing.Point(15, 25)
$lblServerInfo.Size = New-Object System.Drawing.Size(550, 20)
$lblServerInfo.ForeColor = [System.Drawing.Color]::DarkGreen
$dhcpServerGroupBox.Controls.Add($lblServerInfo)

$lblServerExample = New-Object System.Windows.Forms.Label
$lblServerExample.Text = "Example: dhcp-server1.domain.com, dhcp-server2.domain.com"
$lblServerExample.Location = New-Object System.Drawing.Point(580, 25)
$lblServerExample.Size = New-Object System.Drawing.Size(500, 20)
$lblServerExample.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$lblServerExample.ForeColor = [System.Drawing.Color]::Gray
$dhcpServerGroupBox.Controls.Add($lblServerExample)

$txtSpecificServers = New-Object System.Windows.Forms.TextBox
$txtSpecificServers.Size = New-Object System.Drawing.Size(900, 20)
$txtSpecificServers.Location = New-Object System.Drawing.Point(15, 50)
$txtSpecificServers.MaxLength = 1000
$dhcpServerGroupBox.Controls.Add($txtSpecificServers)

$lblServerNote = New-Object System.Windows.Forms.Label
$lblServerNote.Text = "Note: If blank, all domain DHCP servers will be auto-discovered"
$lblServerNote.Location = New-Object System.Drawing.Point(15, 75)
$lblServerNote.Size = New-Object System.Drawing.Size(900, 20)
$lblServerNote.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$lblServerNote.ForeColor = [System.Drawing.Color]::Gray
$dhcpServerGroupBox.Controls.Add($lblServerNote)

# Scope Filtering Group
$dhcpFilterGroupBox = New-Object System.Windows.Forms.GroupBox
$dhcpFilterGroupBox.Text = "Scope Filtering (Optional)"
$dhcpFilterGroupBox.Size = New-Object System.Drawing.Size(940, 75)
$dhcpFilterGroupBox.Location = New-Object System.Drawing.Point(10, 160)
$tab2.Controls.Add($dhcpFilterGroupBox)

$lblScopeFilter = New-Object System.Windows.Forms.Label
$lblScopeFilter.Text = "Filter by scope names (comma-separated, leave blank for all scopes):"
$lblScopeFilter.Size = New-Object System.Drawing.Size(450, 20)
$lblScopeFilter.Location = New-Object System.Drawing.Point(15, 25)
$dhcpFilterGroupBox.Controls.Add($lblScopeFilter)

$lblFilterExample = New-Object System.Windows.Forms.Label
$lblFilterExample.Text = "Example: VLAN100, Guest-Network, Lab"
$lblFilterExample.Size = New-Object System.Drawing.Size(400, 20)
$lblFilterExample.Location = New-Object System.Drawing.Point(480, 25)
$lblFilterExample.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$lblFilterExample.ForeColor = [System.Drawing.Color]::Gray
$dhcpFilterGroupBox.Controls.Add($lblFilterExample)

$txtScopeFilter = New-Object System.Windows.Forms.TextBox
$txtScopeFilter.Size = New-Object System.Drawing.Size(900, 20)
$txtScopeFilter.Location = New-Object System.Drawing.Point(15, 45)
$txtScopeFilter.MaxLength = 500
$dhcpFilterGroupBox.Controls.Add($txtScopeFilter)

# Collection Options Group
$dhcpOptionsGroupBox = New-Object System.Windows.Forms.GroupBox
$dhcpOptionsGroupBox.Text = "Collection Options"
$dhcpOptionsGroupBox.Size = New-Object System.Drawing.Size(940, 75)
$dhcpOptionsGroupBox.Location = New-Object System.Drawing.Point(10, 245)
$tab2.Controls.Add($dhcpOptionsGroupBox)

$chkIncludeDNS = New-Object System.Windows.Forms.CheckBox
$chkIncludeDNS.Text = "Include DNS Server Information"
$chkIncludeDNS.Size = New-Object System.Drawing.Size(250, 20)
$chkIncludeDNS.Location = New-Object System.Drawing.Point(15, 30)
$dhcpOptionsGroupBox.Controls.Add($chkIncludeDNS)

$lblDNSWarning = New-Object System.Windows.Forms.Label
$lblDNSWarning.Text = "(Slower - adds DNS lookup for each scope)"
$lblDNSWarning.Size = New-Object System.Drawing.Size(300, 20)
$lblDNSWarning.Location = New-Object System.Drawing.Point(270, 30)
$lblDNSWarning.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$lblDNSWarning.ForeColor = [System.Drawing.Color]::DarkOrange
$dhcpOptionsGroupBox.Controls.Add($lblDNSWarning)

$chkIncludeBadAddr = New-Object System.Windows.Forms.CheckBox
$chkIncludeBadAddr.Text = "Track Bad_Address Occurrences"
$chkIncludeBadAddr.Size = New-Object System.Drawing.Size(250, 20)
$chkIncludeBadAddr.Location = New-Object System.Drawing.Point(15, 55)
$dhcpOptionsGroupBox.Controls.Add($chkIncludeBadAddr)

$lblBadAddrWarning = New-Object System.Windows.Forms.Label
$lblBadAddrWarning.Text = "(Slower - queries lease database for conflicts)"
$lblBadAddrWarning.Size = New-Object System.Drawing.Size(300, 20)
$lblBadAddrWarning.Location = New-Object System.Drawing.Point(270, 55)
$lblBadAddrWarning.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$lblBadAddrWarning.ForeColor = [System.Drawing.Color]::DarkOrange
$dhcpOptionsGroupBox.Controls.Add($lblBadAddrWarning)

# Actions Group
$dhcpActionsGroupBox = New-Object System.Windows.Forms.GroupBox
$dhcpActionsGroupBox.Text = "Actions"
$dhcpActionsGroupBox.Size = New-Object System.Drawing.Size(940, 65)
$dhcpActionsGroupBox.Location = New-Object System.Drawing.Point(10, 330)
$tab2.Controls.Add($dhcpActionsGroupBox)

$btnCollectDHCP = New-Object System.Windows.Forms.Button
$btnCollectDHCP.Text = "Collect DHCP Statistics"
$btnCollectDHCP.Size = New-Object System.Drawing.Size(200, 35)
$btnCollectDHCP.Location = New-Object System.Drawing.Point(15, 25)
$btnCollectDHCP.BackColor = [System.Drawing.Color]::LightGreen
$dhcpActionsGroupBox.Controls.Add($btnCollectDHCP)

$btnExportDHCP = New-Object System.Windows.Forms.Button
$btnExportDHCP.Text = "Export to CSV"
$btnExportDHCP.Size = New-Object System.Drawing.Size(150, 35)
$btnExportDHCP.Location = New-Object System.Drawing.Point(230, 25)
$btnExportDHCP.Enabled = $false
$dhcpActionsGroupBox.Controls.Add($btnExportDHCP)

$lblExportHint = New-Object System.Windows.Forms.Label
$lblExportHint.Text = "Results will be automatically exported after collection. Use this button to re-export."
$lblExportHint.Size = New-Object System.Drawing.Size(700, 20)
$lblExportHint.Location = New-Object System.Drawing.Point(395, 33)
$lblExportHint.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$lblExportHint.ForeColor = [System.Drawing.Color]::Gray
$dhcpActionsGroupBox.Controls.Add($lblExportHint)

# DHCP Log
$dhcpLogBox = New-Object System.Windows.Forms.RichTextBox
$dhcpLogBox.Size = New-Object System.Drawing.Size(940, 220)
$dhcpLogBox.Location = New-Object System.Drawing.Point(10, 405)
$dhcpLogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$dhcpLogBox.ReadOnly = $true
$tab2.Controls.Add($dhcpLogBox)

# Event Handlers for Tab 2
$btnCollectDHCP.Add_Click({
    try {
        $btnCollectDHCP.Enabled = $false

        # Parse scope filters - matches Merged-DHCPScopeStats.ps1 logic
        $scopeFilters = @()
        if (-not [string]::IsNullOrWhiteSpace($txtScopeFilter.Text)) {
            $scopeFilters = $txtScopeFilter.Text.Split(',') | ForEach-Object { $_.Trim().ToUpper() }
        }

        # Parse and validate specific servers
        $specificServers = @()
        if (-not [string]::IsNullOrWhiteSpace($txtSpecificServers.Text)) {
            $rawServers = $txtSpecificServers.Text.Split(',') | ForEach-Object { $_.Trim() }

            $validServers = @()
            $invalidServers = @()

            foreach ($server in $rawServers) {
                if (-not [string]::IsNullOrWhiteSpace($server)) {
                    # Allow alphanumeric, dots, hyphens, and underscores for FQDNs
                    if ($server -match '^[a-zA-Z0-9][a-zA-Z0-9.\-_]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$') {
                        $validServers += $server
                    } else {
                        $invalidServers += $server
                    }
                }
            }

            if ($invalidServers.Count -gt 0) {
                $invalidList = $invalidServers -join ', '
                Write-Log -Message "Warning: Invalid server name(s) detected and will be skipped: $invalidList" -Color "Red" -LogBox $dhcpLogBox
                [System.Windows.Forms.MessageBox]::Show("Warning: The following server name(s) contain invalid characters and will be skipped:`n`n$invalidList`n`nOnly alphanumeric characters, dots, hyphens, and underscores are allowed.", "Validation Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            }

            if ($validServers.Count -eq 0 -and $invalidServers.Count -gt 0) {
                Write-Log -Message "Error: No valid servers specified. Operation cancelled." -Color "Red" -LogBox $dhcpLogBox
                $btnCollectDHCP.Enabled = $true
                return
            }

            $specificServers = $validServers
        }

        $includeDNS = $chkIncludeDNS.Checked
        $includeBad = $chkIncludeBadAddr.Checked

        Write-Log -Message "Starting DHCP statistics collection..." -Color "Cyan" -LogBox $dhcpLogBox
        if ($specificServers.Count -gt 0) {
            Write-Log -Message "Using specified servers: $($specificServers -join ', ')" -Color "Yellow" -LogBox $dhcpLogBox
        } else {
            Write-Log -Message "Auto-discovering DHCP servers from domain..." -Color "Yellow" -LogBox $dhcpLogBox
        }
        if ($scopeFilters.Count -gt 0) {
            Write-Log -Message "Applying scope filters: $($scopeFilters -join ', ')" -Color "Yellow" -LogBox $dhcpLogBox
        }

        # Create runspace for background processing
        $script:dhcpRunspace = [runspacefactory]::CreateRunspace()
        $script:dhcpRunspace.ApartmentState = "STA"
        $script:dhcpRunspace.ThreadOptions = "ReuseThread"
        $script:dhcpRunspace.Open()

        # Import required functions into runspace
        $script:dhcpRunspace.SessionStateProxy.SetVariable("ScopeFilters", $scopeFilters)
        $script:dhcpRunspace.SessionStateProxy.SetVariable("SpecificServers", $specificServers)
        $script:dhcpRunspace.SessionStateProxy.SetVariable("IncludeDNS", $includeDNS)
        $script:dhcpRunspace.SessionStateProxy.SetVariable("IncludeBadAddresses", $includeBad)

        # Create PowerShell instance
        $script:dhcpPowerShell = [powershell]::Create()
        $script:dhcpPowerShell.Runspace = $script:dhcpRunspace

        # Add the entire script to run in background
        $scriptBlock = {
            # Capture log messages to send back to the UI
            $LogBuffer = New-Object System.Collections.ArrayList
            function Add-ScopedLog {
                param([string]$Message)
                $null = $LogBuffer.Add($Message)
            }

            # Re-define helper functions needed in runspace
            function Test-ScopeFilter {
                param([string]$FilterValue)
                # Empty/null/whitespace filters are valid (means no filtering)
                if ([string]::IsNullOrWhiteSpace($FilterValue)) { return $true }
                $trimmed = $FilterValue.Trim()
                # Limit length
                if ($trimmed.Length -gt 128) { return $false }
                # Only allow safe characters for scope names
                return $trimmed -match '^[a-zA-Z0-9_.\-\s]+'
            }

            function Test-ServerName {
                param([string]$ServerName)
                return $ServerName -match '^[a-zA-Z0-9\.\-_]+'
            }

            function Get-SanitizedErrorMessage {
                param([System.Management.Automation.ErrorRecord]$ErrorRecord)
                return $ErrorRecord.Exception.Message
            }

            # Main DHCP collection logic (mirrors Merged-DHCPScopeStats.ps1)
            try {
                Add-ScopedLog "Importing DhcpServer module..."
                try {
                    Import-Module DhcpServer -ErrorAction Stop
                } catch {
                    return @{ Success = $false; Error = "Failed to import DhcpServer module: $($_.Exception.Message)"; Results = @(); Logs = $LogBuffer }
                }

                # Use specific servers if provided, otherwise discover from domain
                if ($SpecificServers -and $SpecificServers.Count -gt 0) {
                    Add-ScopedLog "Using specified DHCP servers..."
                    $DHCPServers = @()
                    foreach ($serverName in $SpecificServers) {
                        # Create custom object matching Get-DhcpServerInDC output structure
                        $DHCPServers += [PSCustomObject]@{ DnsName = $serverName; IPAddress = $null }
                    }
                    Add-ScopedLog "Will query $($DHCPServers.Count) specified server(s)"
                } else {
                    Add-ScopedLog "Discovering DHCP servers in domain..."
                    try {
                        $DHCPServers = Get-DhcpServerInDC -ErrorAction Stop
                        Add-ScopedLog "Found $($DHCPServers.Count) DHCP server(s) in domain"
                    } catch {
                        return @{ Success = $false; Error = "Failed to get DHCP servers from domain: $($_.Exception.Message)"; Results = @(); Logs = $LogBuffer }
                    }
                }

                $AllStats = @()
                $TotalServers = $DHCPServers.Count

                foreach ($Server in $DHCPServers) {
                    $dhcpName = $Server.DnsName
                    Add-ScopedLog "Querying DHCP Server: $dhcpName"

                    try {
                        $Scopes = Get-DhcpServerv4Scope -ComputerName $dhcpName -ErrorAction Stop

                        # Apply filtering if scope filters are provided - matches Merged-DHCPScopeStats.ps1
                        if ($ScopeFilters -and $ScopeFilters.Count -gt 0) {
                            $OriginalScopeCount = $Scopes.Count
                            Add-ScopedLog "Found $OriginalScopeCount total scope(s) on $dhcpName, applying filters..."

                            $FilteredScopes = @()
                            foreach ($Filter in $ScopeFilters) {
                                # Explicitly case-insensitive matching using .ToUpper() for both sides
                                $MatchingScopes = $Scopes | Where-Object { $_.Name.ToUpper() -like "*$Filter*" }

                                if ($MatchingScopes) {
                                    Add-ScopedLog "  Filter '$Filter' matched $($MatchingScopes.Count) scope(s)"
                                    $FilteredScopes += $MatchingScopes
                                } else {
                                    Add-ScopedLog "  Filter '$Filter' matched 0 scopes"
                                }
                            }

                            # Remove duplicates if a scope matched multiple filters
                            $Scopes = $FilteredScopes | Select-Object -Unique

                            if ($Scopes.Count -eq 0) {
                                Add-ScopedLog "WARNING: No scopes matching filter criteria on $dhcpName"
                                Add-ScopedLog "  Filters used: $($ScopeFilters -join ', ')"
                                Add-ScopedLog "  Available scope names on this server might not contain these strings"
                                continue
                            } else {
                                Add-ScopedLog "After filtering: $($Scopes.Count) scope(s) will be processed on $dhcpName"
                            }
                        }

                        $AllStatsRaw = Get-DhcpServerv4ScopeStatistics -ComputerName $dhcpName -ErrorAction Stop

                        $DNSServerMap = @{}
                        if ($IncludeDNS) {
                            foreach ($Scope in $Scopes) {
                                try {
                                    $DNSOption = Get-DhcpServerv4OptionValue -ComputerName $dhcpName -ScopeId $Scope.ScopeId -OptionId 6 -ErrorAction SilentlyContinue
                                    if ($DNSOption) { $DNSServerMap[$Scope.ScopeId] = $DNSOption.Value -join ',' }
                                } catch { }
                            }
                        }

                        $BadAddressMap = @{}
                        if ($IncludeBadAddresses) {
                            foreach ($Scope in $Scopes) {
                                try {
                                    $BadAddresses = Get-DhcpServerv4Lease -ComputerName $dhcpName -ScopeId $Scope.ScopeId -ErrorAction SilentlyContinue | Where-Object { $_.HostName -eq "BAD_ADDRESS" }
                                    $BadAddressMap[$Scope.ScopeId] = if ($BadAddresses) { $BadAddresses.Count } else { 0 }
                                } catch { $BadAddressMap[$Scope.ScopeId] = 0 }
                            }
                        }

                        foreach ($Scope in $Scopes) {
                            $Stats = $AllStatsRaw | Where-Object { $_.ScopeId -eq $Scope.ScopeId }
                            if ($Stats) {
                                $AllStats += $Stats | Select-Object *,
                                    @{Name='DHCPServer'; Expression={$dhcpName}},
                                    @{Name='Description'; Expression={if (-not [string]::IsNullOrWhiteSpace($Scope.Description)) { $Scope.Description } else { $Scope.Name }}},
                                    @{Name='DNSServers'; Expression={$DNSServerMap[$Scope.ScopeId]}},
                                    @{Name='BadAddressCount'; Expression={$BadAddressMap[$Scope.ScopeId]}}
                            }
                        }

                        Add-ScopedLog "Collected $($Scopes.Count) scope(s) from $dhcpName"
                    } catch {
                        Add-ScopedLog "Error querying $dhcpName : $($_.Exception.Message)"
                    }
                }

                return @{ Success = $true; Error = $null; Results = $AllStats; ServerCount = $TotalServers; Logs = $LogBuffer; Filters = $ScopeFilters }
            } catch {
                return @{ Success = $false; Error = $_.Exception.Message; Results = @(); Logs = $LogBuffer }
            }
        }

        [void]$script:dhcpPowerShell.AddScript($scriptBlock)
        $script:dhcpAsyncResult = $script:dhcpPowerShell.BeginInvoke()

        # Create timer to poll for completion
        $script:dhcpTimer = New-Object System.Windows.Forms.Timer
        $script:dhcpTimer.Interval = 500  # Check every 500ms

        $script:dhcpTimer.Add_Tick({
            if ($script:dhcpAsyncResult.IsCompleted) {
                $script:dhcpTimer.Stop()
                $script:dhcpTimer.Dispose()

                try {
                    $result = $script:dhcpPowerShell.EndInvoke($script:dhcpAsyncResult)

                    if ($result.Logs) {
                        foreach ($logMsg in $result.Logs) {
                            Write-Log -Message $logMsg -Color "Gray" -LogBox $dhcpLogBox
                        }
                    }

                    if ($result.Success) {
                        $script:dhcpResults = $result.Results
                        if ($script:dhcpResults.Count -gt 0) {
                            $btnExportDHCP.Enabled = $true
                            Write-Log -Message "Collection complete! Found $($script:dhcpResults.Count) scopes from $($result.ServerCount) servers" -Color "Green" -LogBox $dhcpLogBox
                        } else {
                            Write-Log -Message "=== No Results Found ===" -Color "Yellow" -LogBox $dhcpLogBox
                            Write-Log -Message "No DHCP scopes were found matching your criteria" -Color "Yellow" -LogBox $dhcpLogBox

                            if ($result.Filters -and $result.Filters.Count -gt 0) {
                                Write-Log -Message "Filters applied: $($result.Filters -join ', ')" -Color "Cyan" -LogBox $dhcpLogBox
                                Write-Log -Message "Troubleshooting tips:" -Color "Cyan" -LogBox $dhcpLogBox
                                Write-Log -Message "  1. Check if scope names actually contain the filter strings" -Color "White" -LogBox $dhcpLogBox
                                Write-Log -Message "  2. Verify server names are correct and reachable" -Color "White" -LogBox $dhcpLogBox
                                Write-Log -Message "  3. Try running without filters to see all available scopes" -Color "White" -LogBox $dhcpLogBox
                                Write-Log -Message "  4. Check if you have permissions to query the DHCP servers" -Color "White" -LogBox $dhcpLogBox
                            } else {
                                Write-Log -Message "No filters were applied. This might indicate:" -Color "Cyan" -LogBox $dhcpLogBox
                                Write-Log -Message "  - No DHCP servers are available in the domain" -Color "White" -LogBox $dhcpLogBox
                                Write-Log -Message "  - You don't have permissions to query DHCP servers" -Color "White" -LogBox $dhcpLogBox
                                Write-Log -Message "  - DHCP servers are unreachable" -Color "White" -LogBox $dhcpLogBox
                            }
                        }
                    } else {
                        Write-Log -Message "Error: $($result.Error)" -Color "Red" -LogBox $dhcpLogBox
                    }
                } catch {
                    $sanitizedError = Get-SanitizedErrorMessage -ErrorRecord $_
                    Write-Log -Message "Error: $sanitizedError" -Color "Red" -LogBox $dhcpLogBox
                } finally {
                    $script:dhcpPowerShell.Dispose()
                    $script:dhcpRunspace.Close()
                    $script:dhcpRunspace.Dispose()
                    $btnCollectDHCP.Enabled = $true
                }
            }
        })

        $script:dhcpTimer.Start()

    } catch {
        $sanitizedError = Get-SanitizedErrorMessage -ErrorRecord $_
        Write-Log -Message "Error: $sanitizedError" -Color "Red" -LogBox $dhcpLogBox
        $btnCollectDHCP.Enabled = $true
    }
})

$btnExportDHCP.Add_Click({
    try {
        if ($script:dhcpResults.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No DHCP results to export", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "DHCPScopeStats_$timestamp.csv"

        if (-not (Test-Path $script:outputDir)) {
            New-Item -ItemType Directory -Path $script:outputDir -Force | Out-Null
        }

        $script:dhcpResults | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Log -Message "DHCP statistics exported to: $csvPath" -Color "Green" -LogBox $dhcpLogBox
        [System.Windows.Forms.MessageBox]::Show("DHCP statistics exported successfully to:`n$csvPath", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $dhcpLogBox
        [System.Windows.Forms.MessageBox]::Show("Error exporting: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# ============================================
# TAB 3: DNA CENTER
# ============================================

$tab3 = New-Object System.Windows.Forms.TabPage
$tab3.Text = "DNA Center"
$tabControl.Controls.Add($tab3)

# Connection Group
$dnaConnGroupBox = New-Object System.Windows.Forms.GroupBox
$dnaConnGroupBox.Text = "DNA Center Connection"
$dnaConnGroupBox.Size = New-Object System.Drawing.Size(940, 140)
$dnaConnGroupBox.Location = New-Object System.Drawing.Point(10, 10)
$tab3.Controls.Add($dnaConnGroupBox)

# Server Selection
$lblDNAServer = New-Object System.Windows.Forms.Label
$lblDNAServer.Text = "DNA Center Server:"
$lblDNAServer.Size = New-Object System.Drawing.Size(120, 20)
$lblDNAServer.Location = New-Object System.Drawing.Point(20, 30)
$dnaConnGroupBox.Controls.Add($lblDNAServer)

$comboDNAServer = New-Object System.Windows.Forms.ComboBox
$comboDNAServer.Size = New-Object System.Drawing.Size(300, 20)
$comboDNAServer.Location = New-Object System.Drawing.Point(150, 28)
$comboDNAServer.DropDownStyle = "DropDownList"
foreach ($server in $script:dnaCenterServers) {
    $comboDNAServer.Items.Add("$($server.Name) - $($server.Url)") | Out-Null
}
$comboDNAServer.SelectedIndex = 0
$dnaConnGroupBox.Controls.Add($comboDNAServer)

# Username
$lblDNAUser = New-Object System.Windows.Forms.Label
$lblDNAUser.Text = "Username:"
$lblDNAUser.Size = New-Object System.Drawing.Size(120, 20)
$lblDNAUser.Location = New-Object System.Drawing.Point(20, 65)
$dnaConnGroupBox.Controls.Add($lblDNAUser)

$txtDNAUser = New-Object System.Windows.Forms.TextBox
$txtDNAUser.Size = New-Object System.Drawing.Size(300, 20)
$txtDNAUser.Location = New-Object System.Drawing.Point(150, 63)
$dnaConnGroupBox.Controls.Add($txtDNAUser)

# Password
$lblDNAPass = New-Object System.Windows.Forms.Label
$lblDNAPass.Text = "Password:"
$lblDNAPass.Size = New-Object System.Drawing.Size(120, 20)
$lblDNAPass.Location = New-Object System.Drawing.Point(20, 100)
$dnaConnGroupBox.Controls.Add($lblDNAPass)

$txtDNAPass = New-Object System.Windows.Forms.TextBox
$txtDNAPass.Size = New-Object System.Drawing.Size(300, 20)
$txtDNAPass.Location = New-Object System.Drawing.Point(150, 98)
$txtDNAPass.PasswordChar = '*'
$dnaConnGroupBox.Controls.Add($txtDNAPass)

# Connect Button
$btnDNAConnect = New-Object System.Windows.Forms.Button
$btnDNAConnect.Text = "Connect"
$btnDNAConnect.Size = New-Object System.Drawing.Size(120, 30)
$btnDNAConnect.Location = New-Object System.Drawing.Point(480, 28)
$dnaConnGroupBox.Controls.Add($btnDNAConnect)

# Load Devices Button
$btnLoadDevices = New-Object System.Windows.Forms.Button
$btnLoadDevices.Text = "Load Devices"
$btnLoadDevices.Size = New-Object System.Drawing.Size(120, 30)
$btnLoadDevices.Location = New-Object System.Drawing.Point(480, 68)
$btnLoadDevices.Enabled = $false
$dnaConnGroupBox.Controls.Add($btnLoadDevices)

# Device Filters
$dnaFilterGroupBox = New-Object System.Windows.Forms.GroupBox
$dnaFilterGroupBox.Text = "Device Filters"
$dnaFilterGroupBox.Size = New-Object System.Drawing.Size(940, 105)
$dnaFilterGroupBox.Location = New-Object System.Drawing.Point(10, 160)
$tab3.Controls.Add($dnaFilterGroupBox)

$lblFilterHostname = New-Object System.Windows.Forms.Label
$lblFilterHostname.Text = "Hostname contains:"
$lblFilterHostname.Size = New-Object System.Drawing.Size(130, 20)
$lblFilterHostname.Location = New-Object System.Drawing.Point(20, 30)
$dnaFilterGroupBox.Controls.Add($lblFilterHostname)

$txtFilterHostname = New-Object System.Windows.Forms.TextBox
$txtFilterHostname.Size = New-Object System.Drawing.Size(220, 20)
$txtFilterHostname.Location = New-Object System.Drawing.Point(160, 28)
$txtFilterHostname.MaxLength = 128
$txtFilterHostname.Enabled = $false
$dnaFilterGroupBox.Controls.Add($txtFilterHostname)

$lblFilterIP = New-Object System.Windows.Forms.Label
$lblFilterIP.Text = "Management IP:"
$lblFilterIP.Size = New-Object System.Drawing.Size(120, 20)
$lblFilterIP.Location = New-Object System.Drawing.Point(400, 30)
$dnaFilterGroupBox.Controls.Add($lblFilterIP)

$txtFilterIPAddress = New-Object System.Windows.Forms.TextBox
$txtFilterIPAddress.Size = New-Object System.Drawing.Size(180, 20)
$txtFilterIPAddress.Location = New-Object System.Drawing.Point(520, 28)
$txtFilterIPAddress.MaxLength = 64
$txtFilterIPAddress.Enabled = $false
$dnaFilterGroupBox.Controls.Add($txtFilterIPAddress)

$lblFilterRole = New-Object System.Windows.Forms.Label
$lblFilterRole.Text = "Role contains:"
$lblFilterRole.Size = New-Object System.Drawing.Size(110, 20)
$lblFilterRole.Location = New-Object System.Drawing.Point(20, 65)
$dnaFilterGroupBox.Controls.Add($lblFilterRole)

$txtFilterRole = New-Object System.Windows.Forms.TextBox
$txtFilterRole.Size = New-Object System.Drawing.Size(220, 20)
$txtFilterRole.Location = New-Object System.Drawing.Point(160, 63)
$txtFilterRole.MaxLength = 128
$txtFilterRole.Enabled = $false
$dnaFilterGroupBox.Controls.Add($txtFilterRole)

$lblFilterFamily = New-Object System.Windows.Forms.Label
$lblFilterFamily.Text = "Family contains:"
$lblFilterFamily.Size = New-Object System.Drawing.Size(110, 20)
$lblFilterFamily.Location = New-Object System.Drawing.Point(400, 65)
$dnaFilterGroupBox.Controls.Add($lblFilterFamily)

$txtFilterFamily = New-Object System.Windows.Forms.TextBox
$txtFilterFamily.Size = New-Object System.Drawing.Size(180, 20)
$txtFilterFamily.Location = New-Object System.Drawing.Point(520, 63)
$txtFilterFamily.MaxLength = 128
$txtFilterFamily.Enabled = $false
$dnaFilterGroupBox.Controls.Add($txtFilterFamily)

$btnApplyDeviceFilter = New-Object System.Windows.Forms.Button
$btnApplyDeviceFilter.Text = "Apply Filters"
$btnApplyDeviceFilter.Size = New-Object System.Drawing.Size(120, 30)
$btnApplyDeviceFilter.Location = New-Object System.Drawing.Point(730, 28)
$btnApplyDeviceFilter.Enabled = $false
$dnaFilterGroupBox.Controls.Add($btnApplyDeviceFilter)

$btnResetDeviceFilter = New-Object System.Windows.Forms.Button
$btnResetDeviceFilter.Text = "Reset Selection"
$btnResetDeviceFilter.Size = New-Object System.Drawing.Size(120, 30)
$btnResetDeviceFilter.Location = New-Object System.Drawing.Point(870, 28)
$btnResetDeviceFilter.Enabled = $false
$dnaFilterGroupBox.Controls.Add($btnResetDeviceFilter)

$lblDeviceSelectionStatus = New-Object System.Windows.Forms.Label
$lblDeviceSelectionStatus.Text = "Selected devices: None loaded"
$lblDeviceSelectionStatus.Size = New-Object System.Drawing.Size(260, 20)
$lblDeviceSelectionStatus.Location = New-Object System.Drawing.Point(730, 70)
$dnaFilterGroupBox.Controls.Add($lblDeviceSelectionStatus)

# Functions Group
$dnaFuncGroupBox = New-Object System.Windows.Forms.GroupBox
$dnaFuncGroupBox.Text = "DNA Center Functions - 23 Available (Click to Execute)"
$dnaFuncGroupBox.Size = New-Object System.Drawing.Size(940, 210)
$dnaFuncGroupBox.Location = New-Object System.Drawing.Point(10, 275)
$tab3.Controls.Add($dnaFuncGroupBox)

# Create buttons for DNA Center functions in a grid layout
$functions = @(
    @{Name="Device Info (Basic)"; Function="Get-NetworkDevicesBasic"},
    @{Name="Device Info (Detailed)"; Function="Get-NetworkDevicesDetailed"},
    @{Name="Device Inventory Count"; Function="Get-DeviceInventoryCount"},
    @{Name="Device Configurations"; Function="Get-DeviceConfigurations"},
    @{Name="Device Interfaces"; Function="Get-DeviceInterfaces"},
    @{Name="Device Modules"; Function="Get-DeviceModules"},
    @{Name="Network Health"; Function="Get-NetworkHealth"},
    @{Name="Client Health"; Function="Get-ClientHealth"},
    @{Name="Device Reachability"; Function="Get-DeviceReachability"},
    @{Name="Compliance Status"; Function="Get-ComplianceStatus"},
    @{Name="VLANs"; Function="Get-VLANs"},
    @{Name="Software Images"; Function="Get-SoftwareImageInfo"},
    @{Name="Issues/Events"; Function="Get-IssuesEvents"},
    @{Name="Templates"; Function="Get-Templates"},
    @{Name="Sites/Locations"; Function="Get-SitesLocations"},
    @{Name="Physical Topology"; Function="Get-PhysicalTopology"},
    @{Name="OSPF Neighbors"; Function="Get-OSPFNeighbors"},
    @{Name="CDP Neighbors"; Function="Get-CDPNeighbors"},
    @{Name="LLDP Neighbors"; Function="Get-LLDPNeighbors"},
    @{Name="Access Points"; Function="Get-AccessPoints"},
    @{Name="Path Trace"; Function="Invoke-PathTrace"},
    @{Name="Last Disconnect Times"; Function="Get-LastDisconnectTime"},
    @{Name="Availability Events"; Function="Get-LastDeviceAvailabilityEventTime"},
    @{Name="Last Ping Reachable"; Function="Get-LastPingReachableTime"},
    @{Name="Execute CLI Commands"; Function="Invoke-CommandRunner"}
)

$buttonWidth = 170
$buttonHeight = 35
$buttonsPerRow = 6
$xStart = 20
$yStart = 30
$xSpacing = 185
$ySpacing = 45

for ($i = 0; $i -lt $functions.Count; $i++) {
    $row = [Math]::Floor($i / $buttonsPerRow)
    $col = $i % $buttonsPerRow

    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $functions[$i].Name
    $btn.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
    $btn.Location = New-Object System.Drawing.Point(($xStart + ($col * $xSpacing)), ($yStart + ($row * $ySpacing)))
    $btn.Tag = $functions[$i].Function
    $btn.Enabled = $false

    $btn.Add_Click({
        param($sender, $e)
        try {
            $functionName = $sender.Tag
            & $functionName -LogBox $dnaLogBox
        } catch {
            Write-Log -Message "Error executing function: $($_.Exception.Message)" -Color "Red" -LogBox $dnaLogBox
        }
    })

    $dnaFuncGroupBox.Controls.Add($btn)
}

# DNA Log
$dnaLogBox = New-Object System.Windows.Forms.RichTextBox
$dnaLogBox.Size = New-Object System.Drawing.Size(940, 140)
$dnaLogBox.Location = New-Object System.Drawing.Point(10, 495)
$dnaLogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$dnaLogBox.ReadOnly = $true
$tab3.Controls.Add($dnaLogBox)

# Event Handlers for Tab 3
$btnDNAConnect.Add_Click({
    try {
        $selectedIndex = $comboDNAServer.SelectedIndex
        if ($selectedIndex -lt 0) {
            [System.Windows.Forms.MessageBox]::Show("Please select a DNA Center server", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        $script:selectedDnaCenter = $script:dnaCenterServers[$selectedIndex].Url
        $username = $txtDNAUser.Text.Trim()
        $password = $txtDNAPass.Text

        if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter username and password", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        Initialize-DNACenter -LogBox $dnaLogBox

        $success = Connect-DNACenter -DnaCenter $script:selectedDnaCenter -Username $username -Password $password -LogBox $dnaLogBox

        if ($success) {
            $btnLoadDevices.Enabled = $true
            [System.Windows.Forms.MessageBox]::Show("Successfully connected to DNA Center!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } else {
            [System.Windows.Forms.MessageBox]::Show("Failed to connect to DNA Center", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } catch {
        Write-Log -Message "Connection error: $($_.Exception.Message)" -Color "Red" -LogBox $dnaLogBox
        [System.Windows.Forms.MessageBox]::Show("Connection error: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    } finally {
        # Clear password from memory
        $password = $null
        $txtDNAPass.Text = ""
    }
})

$btnLoadDevices.Add_Click({
    try {
        $success = Load-AllDNADevices -LogBox $dnaLogBox

        if ($success) {
            # Enable all function buttons
            foreach ($control in $dnaFuncGroupBox.Controls) {
                if ($control -is [System.Windows.Forms.Button]) {
                    $control.Enabled = $true
                }
            }

            foreach ($control in @($txtFilterHostname, $txtFilterIPAddress, $txtFilterRole, $txtFilterFamily, $btnApplyDeviceFilter, $btnResetDeviceFilter)) {
                $control.Enabled = $true
            }

            $lblDeviceSelectionStatus.Text = "Selected devices: All ($($script:allDNADevices.Count))"

            [System.Windows.Forms.MessageBox]::Show("Devices loaded successfully!`nTotal: $($script:allDNADevices.Count)", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } else {
            [System.Windows.Forms.MessageBox]::Show("Failed to load devices", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } catch {
        Write-Log -Message "Error loading devices: $($_.Exception.Message)" -Color "Red" -LogBox $dnaLogBox
        [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$btnApplyDeviceFilter.Add_Click({
    try {
        $result = Filter-DNADevices -Hostname $txtFilterHostname.Text -IPAddress $txtFilterIPAddress.Text -Role $txtFilterRole.Text -Family $txtFilterFamily.Text -LogBox $dnaLogBox

        if ($result.Count -eq 0) {
            $lblDeviceSelectionStatus.Text = "Selected devices: 0 of $($script:allDNADevices.Count)"
            [System.Windows.Forms.MessageBox]::Show("No devices matched the provided filters.", "No Results", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } else {
            $lblDeviceSelectionStatus.Text = "Selected devices: $($result.Count) of $($script:allDNADevices.Count)"
            [System.Windows.Forms.MessageBox]::Show("Filters applied successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    } catch {
        Write-Log -Message "Error applying filters: $($_.Exception.Message)" -Color "Red" -LogBox $dnaLogBox
        [System.Windows.Forms.MessageBox]::Show("Error applying filters: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$btnResetDeviceFilter.Add_Click({
    try {
        Reset-DNADeviceSelection -LogBox $dnaLogBox
        $txtFilterHostname.Clear()
        $txtFilterIPAddress.Clear()
        $txtFilterRole.Clear()
        $txtFilterFamily.Clear()

        $lblDeviceSelectionStatus.Text = "Selected devices: All ($($script:allDNADevices.Count))"
        [System.Windows.Forms.MessageBox]::Show("Device selection reset to all loaded devices.", "Reset", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        Write-Log -Message "Error resetting filters: $($_.Exception.Message)" -Color "Red" -LogBox $dnaLogBox
        [System.Windows.Forms.MessageBox]::Show("Error resetting filters: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# ============================================
# FORM CLOSING EVENT
# ============================================

$mainForm.Add_FormClosing({
    param($sender, $e)

    try {
        # Cleanup network monitoring if running
        if ($script:monitorJob) {
            Stop-Job -Job $script:monitorJob -ErrorAction SilentlyContinue
            Remove-Job -Job $script:monitorJob -Force -ErrorAction SilentlyContinue
        }

        # Cleanup batch process if running
        if ($script:BatchProcess -and !$script:BatchProcess.HasExited) {
            Stop-Process -Id $script:BatchProcess.Id -Force -ErrorAction SilentlyContinue
        }

        # Clear sensitive data
        $script:dnaCenterToken = $null
        $script:dnaCenterHeaders = $null
    } catch {
        # Silently cleanup
    }
})

# ============================================
# SHOW FORM
# ============================================

Write-Host "OctoNav Complete GUI - Security Hardened Edition" -ForegroundColor Cyan
Write-Host "Starting application..." -ForegroundColor Green
[void]$mainForm.ShowDialog()
