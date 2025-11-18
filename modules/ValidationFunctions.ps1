#Requires -Version 5.1
<#
.SYNOPSIS
    Validation Functions for OctoNav GUI v2.3
.DESCRIPTION
    Input validation and sanitization functions
#>

function Test-IPAddress {
    <#
    .SYNOPSIS
        Validates an IPv4 address
    #>
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
    <#
    .SYNOPSIS
        Validates a network prefix length (0-32)
    #>
    param([string]$Prefix)

    try {
        $prefixInt = [int]$Prefix
        return ($prefixInt -ge 0 -and $prefixInt -le 32)
    } catch {
        return $false
    }
}

function Get-SafeFileName {
    <#
    .SYNOPSIS
        Sanitizes a filename to prevent security issues
    #>
    param(
        [string]$InputName,
        [string]$Fallback = "output"
    )

    if ([string]::IsNullOrWhiteSpace($InputName)) {
        return $Fallback
    }

    # Get only the filename component, stripping any path separators
    try {
        $safeName = [System.IO.Path]::GetFileName($InputName)
    } catch {
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

function Test-ServerName {
    <#
    .SYNOPSIS
        Validates a DNS server name (RFC 1123)
    #>
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
    <#
    .SYNOPSIS
        Validates DHCP scope filter input
    #>
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
    if ($trimmed -notmatch '^[a-zA-Z0-9_.\-\s,]+$') {
        return $false
    }

    return $true
}

function Test-DnaFilterInput {
    <#
    .SYNOPSIS
        Validates DNA Center filter input
    #>
    param(
        [string]$Value,
        [string]$FieldName
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $true
    }

    $trimmed = $Value.Trim()

    if ($trimmed.Length -gt 128) {
        return $false
    }

    if ($trimmed -notmatch '^[a-zA-Z0-9_.:\-\s]+$') {
        return $false
    }

    return $true
}

function Get-SanitizedErrorMessage {
    <#
    .SYNOPSIS
        Sanitizes error messages to remove sensitive information
    #>
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

# Export module members
Export-ModuleMember -Function @(
    'Test-IPAddress',
    'Test-PrefixLength',
    'Get-SafeFileName',
    'Test-ServerName',
    'Test-ScopeFilter',
    'Test-DnaFilterInput',
    'Get-SanitizedErrorMessage'
)
