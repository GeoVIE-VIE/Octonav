<#
.SYNOPSIS
    Network Configuration Functions Module for OctoNav GUI

.DESCRIPTION
    Provides network adapter configuration functions for OctoNav.
    Handles DHCP restoration, unidentified network detection, and static IP configuration.
    Requires Administrator privileges for all network modification operations.

.AUTHOR
    OctoNav Development Team

.VERSION
    1.0.0

.NOTES
    Requires: Windows PowerShell with Administrator privileges
    Dependencies: System.Windows.Forms, System.Net
#>

# ============================================
# VALIDATION HELPER FUNCTIONS
# ============================================

<#
.SYNOPSIS
    Validates IPv4 address format

.PARAMETER IPAddress
    The IP address string to validate

.OUTPUTS
    Boolean - $true if valid IPv4 format, $false otherwise
#>
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

<#
.SYNOPSIS
    Validates IPv4 prefix length

.PARAMETER Prefix
    The prefix length (0-32) to validate

.OUTPUTS
    Boolean - $true if valid prefix (0-32), $false otherwise
#>
function Test-PrefixLength {
    param([string]$Prefix)

    try {
        $prefixInt = [int]$Prefix
        return ($prefixInt -ge 0 -and $prefixInt -le 32)
    } catch {
        return $false
    }
}

<#
.SYNOPSIS
    Sanitizes error messages by removing sensitive information

.PARAMETER ErrorRecord
    The error record to sanitize

.OUTPUTS
    String - Sanitized error message with paths, IPs, and usernames redacted
#>
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

<#
.SYNOPSIS
    Validates DNS hostname format

.PARAMETER ServerName
    The server name/hostname to validate

.OUTPUTS
    Boolean - $true if valid DNS name format, $false otherwise
#>
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

# ============================================
# LOGGING FUNCTION
# ============================================

<#
.SYNOPSIS
    Writes colored log messages to a RichTextBox control

.PARAMETER Message
    The message to log

.PARAMETER Color
    The color for the message text (Green, Red, Yellow, Cyan, Magenta)

.PARAMETER LogBox
    The RichTextBox control to write to
#>
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
# NETWORK CONFIGURATION FUNCTIONS
# ============================================

<#
.SYNOPSIS
    Restores network adapter to DHCP configuration

.DESCRIPTION
    Removes any static IP configuration and restores DHCP.
    Requires Administrator privileges.

.PARAMETER LogBox
    Optional RichTextBox control for logging output

.OUTPUTS
    Boolean - $true if successful, $false otherwise

.NOTES
    Requires Administrator privileges.
    Checks $script:IsRunningAsAdmin variable.
#>
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

<#
.SYNOPSIS
    Finds unidentified networks with APIPA addresses

.DESCRIPTION
    Searches for network adapters configured with APIPA addresses (169.254.x.x)
    or networks marked as unidentified. These typically indicate network issues.

.PARAMETER LogBox
    Optional RichTextBox control for logging output

.OUTPUTS
    Hashtable containing Adapter, Profile, and IPAddress objects, or $null if none found
#>
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

<#
.SYNOPSIS
    Applies static IP configuration to a network adapter

.DESCRIPTION
    Configures a network adapter with a static IP address, subnet mask (prefix length),
    and default gateway. Requires Administrator privileges.

.PARAMETER Adapter
    The network adapter object to configure

.PARAMETER IPAddress
    The static IP address (must be valid IPv4 format)

.PARAMETER Gateway
    The default gateway IP address (must be valid IPv4 format)

.PARAMETER PrefixLength
    The subnet prefix length (0-32), defaults to 24 (/24)

.PARAMETER LogBox
    Optional RichTextBox control for logging output

.OUTPUTS
    Boolean - $true if configuration applied successfully, $false otherwise

.NOTES
    Requires Administrator privileges.
    Checks $script:IsRunningAsAdmin variable.
    Validates all IP addresses and prefix length before applying.
#>
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
# MODULE EXPORTS
# ============================================

<#
Export only the public functions for this module
#>
Export-ModuleMember -Function @(
    'Restore-NetworkDefaults',
    'Find-UnidentifiedNetwork',
    'Set-NetworkConfiguration',
    'Test-IPAddress',
    'Test-PrefixLength',
    'Write-Log'
)
