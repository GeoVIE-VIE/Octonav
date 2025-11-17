#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    OctoNav Complete GUI - Unified Network Management Tool (Security Hardened)
.DESCRIPTION
    Comprehensive Windows Forms GUI combining Network Configuration, DHCP Statistics, and DNA Center API functions
.AUTHOR
    Integrated by Claude - In Memory of Zesty.PS1
.VERSION
    1.1 - Security Hardened
#>

# Enable visual styles
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# Handle errors gracefully
$ErrorActionPreference = "Stop"

# ============================================
# GLOBAL VARIABLES
# ============================================

# DNA Center Configuration
$script:dnaCenterServers = @(
    [pscustomobject]@{ Name = "Tst DNA Center"; Url = "test" },
    [pscustomobject]@{ Name = "Tst DNA Center 2"; Url = "test2" }
)

$script:selectedDnaCenter = $null
$script:dnaCenterToken = $null
$script:dnaCenterHeaders = $null
$script:allDNADevices = @()
$script:selectedDNADevices = @()
$script:outputDir = "C:\DNACenter_Reports"

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
        $InputName = $Fallback
    }

    # Remove invalid characters and path traversal attempts
    $safeName = $InputName -replace '[\\/:*?"<>|]', '_'
    $safeName = $safeName -replace '\.\.', '_'
    $safeName = $safeName.Trim()

    if ([string]::IsNullOrWhiteSpace($safeName)) {
        $safeName = $Fallback
    }

    return $safeName
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
        Write-Log -Message "$FieldName is too long" -Color "Red" -LogBox $LogBox
        return $false
    }

    if ($trimmed -notmatch '^[a-zA-Z0-9_.:\-\s]+$') {
        Write-Log -Message "$FieldName contains invalid characters" -Color "Red" -LogBox $LogBox
        return $false
    }

    return $true
}

# ============================================
# HELPER FUNCTIONS - GENERAL
# ============================================

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

function Connect-DNACenter {
    param(
        [string]$DnaCenter,
        [string]$Username,
        [string]$Password,
        [System.Windows.Forms.RichTextBox]$LogBox
    )

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
        Write-Log -Message "Authentication failed: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
        return $false
    } finally {
        # Clear sensitive data
        $base64AuthInfo = $null
        $Password = $null
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
            $DHCPServers = $SpecificServers | ForEach-Object {
                [PSCustomObject]@{ DnsName = $_ }
            }
        } else {
            Write-Log -Message "Discovering DHCP servers in domain..." -Color "Cyan" -LogBox $LogBox
            try {
                $DHCPServers = Get-DhcpServerInDC
                Write-Log -Message "Found $($DHCPServers.Count) DHCP servers" -Color "Green" -LogBox $LogBox
            } catch {
                Write-Log -Message "Failed to get DHCP servers: $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
                return @()
            }
        }

        # Script block for parallel processing
        $ScriptBlock = {
            param($DHCPServerName, $ScopeFilters, $IncludeDNS, $IncludeBadAddresses)

            $ServerStats = @()

            try {
                $Scopes = Get-DhcpServerv4Scope -ComputerName $DHCPServerName -ErrorAction Stop

                if ($ScopeFilters -and $ScopeFilters.Count -gt 0) {
                    $FilteredScopes = @()
                    foreach ($Filter in $ScopeFilters) {
                        $FilteredScopes += $Scopes | Where-Object { $_.Name -like "*$Filter*" }
                    }
                    $Scopes = $FilteredScopes | Select-Object -Unique

                    if ($Scopes.Count -eq 0) {
                        return @()
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

        # Process servers in parallel
        $Jobs = @()
        $AllStats = @()
        $MaxJobs = 20
        $TotalServers = $DHCPServers.Count

        Write-Log -Message "Starting parallel processing of $TotalServers DHCP servers..." -Color "Cyan" -LogBox $LogBox

        for ($i = 0; $i -lt $DHCPServers.Count; $i += $MaxJobs) {
            $Batch = $DHCPServers[$i..([Math]::Min($i + $MaxJobs - 1, $DHCPServers.Count - 1))]

            foreach ($Server in $Batch) {
                $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Server.DnsName, $ScopeFilters, $IncludeDNS, $IncludeBadAddresses
                $Jobs += @{
                    Job = $Job
                    ServerName = $Server.DnsName
                    Processed = $false
                }
            }

            while ($Jobs | Where-Object { $_.Job.State -eq 'Running' }) {
                Start-Sleep -Seconds 2

                $CompletedInBatch = $Jobs | Where-Object { $_.Job.State -eq 'Completed' -and -not $_.Processed }
                foreach ($CompletedJob in $CompletedInBatch) {
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
                }

                $FailedInBatch = $Jobs | Where-Object { $_.Job.State -eq 'Failed' -and -not $_.Processed }
                foreach ($FailedJob in $FailedInBatch) {
                    $FailedJob.Processed = $true
                    Write-Log -Message "Failed: $($FailedJob.ServerName)" -Color "Red" -LogBox $LogBox
                    Remove-Job -Job $FailedJob.Job -Force
                }
            }
        }

        # Cleanup remaining jobs
        $RemainingJobs = $Jobs | Where-Object { -not $_.Processed }
        foreach ($RemainingJob in $RemainingJobs) {
            if ($RemainingJob.Job.State -eq 'Completed') {
                try {
                    $Result = Receive-Job -Job $RemainingJob.Job
                    if ($Result) {
                        $AllStats += $Result
                    }
                } catch {
                    Write-Log -Message "Failed to receive from $($RemainingJob.ServerName): $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
                }
            }
            Remove-Job -Job $RemainingJob.Job -Force
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
# CREATE GUI
# ============================================

# Main Form
$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Text = "OctoNav - Complete Network Management Tool (Security Hardened)"
$mainForm.Size = New-Object System.Drawing.Size(1200, 800)
$mainForm.StartPosition = "CenterScreen"
$mainForm.FormBorderStyle = "FixedDialog"
$mainForm.MaximizeBox = $true

# Create Tab Control
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Size = New-Object System.Drawing.Size(1180, 750)
$tabControl.Location = New-Object System.Drawing.Point(10, 10)
$mainForm.Controls.Add($tabControl)

# ============================================
# TAB 1: NETWORK CONFIGURATION (XFER)
# ============================================

$tab1 = New-Object System.Windows.Forms.TabPage
$tab1.Text = "Network Configuration"
$tabControl.Controls.Add($tab1)

# Group Box for Network Settings
$netGroupBox = New-Object System.Windows.Forms.GroupBox
$netGroupBox.Text = "Network Adapter Configuration"
$netGroupBox.Size = New-Object System.Drawing.Size(1140, 300)
$netGroupBox.Location = New-Object System.Drawing.Point(10, 10)
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
$netLogBox.Size = New-Object System.Drawing.Size(1140, 380)
$netLogBox.Location = New-Object System.Drawing.Point(10, 320)
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

# DHCP Options Group
$dhcpGroupBox = New-Object System.Windows.Forms.GroupBox
$dhcpGroupBox.Text = "DHCP Collection Options"
$dhcpGroupBox.Size = New-Object System.Drawing.Size(1140, 200)
$dhcpGroupBox.Location = New-Object System.Drawing.Point(10, 10)
$tab2.Controls.Add($dhcpGroupBox)

# Include DNS Checkbox
$chkIncludeDNS = New-Object System.Windows.Forms.CheckBox
$chkIncludeDNS.Text = "Include DNS Server Information (slower)"
$chkIncludeDNS.Size = New-Object System.Drawing.Size(400, 20)
$chkIncludeDNS.Location = New-Object System.Drawing.Point(20, 30)
$dhcpGroupBox.Controls.Add($chkIncludeDNS)

# Include Bad Addresses Checkbox
$chkIncludeBadAddr = New-Object System.Windows.Forms.CheckBox
$chkIncludeBadAddr.Text = "Track Bad_Address Occurrences (slower)"
$chkIncludeBadAddr.Size = New-Object System.Drawing.Size(400, 20)
$chkIncludeBadAddr.Location = New-Object System.Drawing.Point(20, 60)
$dhcpGroupBox.Controls.Add($chkIncludeBadAddr)

# Scope Filter Label
$lblScopeFilter = New-Object System.Windows.Forms.Label
$lblScopeFilter.Text = "Scope Name Filter (comma-separated, optional):"
$lblScopeFilter.Size = New-Object System.Drawing.Size(400, 20)
$lblScopeFilter.Location = New-Object System.Drawing.Point(20, 95)
$dhcpGroupBox.Controls.Add($lblScopeFilter)

# Scope Filter TextBox
$txtScopeFilter = New-Object System.Windows.Forms.TextBox
$txtScopeFilter.Size = New-Object System.Drawing.Size(600, 20)
$txtScopeFilter.Location = New-Object System.Drawing.Point(20, 115)
$dhcpGroupBox.Controls.Add($txtScopeFilter)

# Collect DHCP Stats Button
$btnCollectDHCP = New-Object System.Windows.Forms.Button
$btnCollectDHCP.Text = "Collect DHCP Statistics"
$btnCollectDHCP.Size = New-Object System.Drawing.Size(200, 35)
$btnCollectDHCP.Location = New-Object System.Drawing.Point(20, 150)
$dhcpGroupBox.Controls.Add($btnCollectDHCP)

# Export DHCP Results Button
$btnExportDHCP = New-Object System.Windows.Forms.Button
$btnExportDHCP.Text = "Export to CSV"
$btnExportDHCP.Size = New-Object System.Drawing.Size(150, 35)
$btnExportDHCP.Location = New-Object System.Drawing.Point(240, 150)
$btnExportDHCP.Enabled = $false
$dhcpGroupBox.Controls.Add($btnExportDHCP)

# DHCP Log
$dhcpLogBox = New-Object System.Windows.Forms.RichTextBox
$dhcpLogBox.Size = New-Object System.Drawing.Size(1140, 480)
$dhcpLogBox.Location = New-Object System.Drawing.Point(10, 220)
$dhcpLogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$dhcpLogBox.ReadOnly = $true
$tab2.Controls.Add($dhcpLogBox)

# Event Handlers for Tab 2
$btnCollectDHCP.Add_Click({
    try {
        $btnCollectDHCP.Enabled = $false

        $scopeFilters = @()
        if (-not [string]::IsNullOrWhiteSpace($txtScopeFilter.Text)) {
            $scopeFilters = $txtScopeFilter.Text.Split(',') | ForEach-Object { $_.Trim().ToUpper() }
        }

        $includeDNS = $chkIncludeDNS.Checked
        $includeBad = $chkIncludeBadAddr.Checked

        Write-Log -Message "Starting DHCP statistics collection..." -Color "Cyan" -LogBox $dhcpLogBox

        $script:dhcpResults = Get-DHCPScopeStatistics -ScopeFilters $scopeFilters -IncludeDNS $includeDNS -IncludeBadAddresses $includeBad -LogBox $dhcpLogBox

        if ($script:dhcpResults.Count -gt 0) {
            $btnExportDHCP.Enabled = $true
            Write-Log -Message "Collection complete! Found $($script:dhcpResults.Count) scopes" -Color "Green" -LogBox $dhcpLogBox
        } else {
            Write-Log -Message "No DHCP scopes found" -Color "Yellow" -LogBox $dhcpLogBox
        }
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $dhcpLogBox
    } finally {
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
$dnaConnGroupBox.Size = New-Object System.Drawing.Size(1140, 150)
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
$dnaFilterGroupBox.Size = New-Object System.Drawing.Size(1140, 110)
$dnaFilterGroupBox.Location = New-Object System.Drawing.Point(10, 170)
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
$dnaFuncGroupBox.Text = "DNA Center Functions (Click to Execute)"
$dnaFuncGroupBox.Size = New-Object System.Drawing.Size(1140, 240)
$dnaFuncGroupBox.Location = New-Object System.Drawing.Point(10, 290)
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
    @{Name="Access Points"; Function="Get-AccessPoints"}
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
$dnaLogBox.Size = New-Object System.Drawing.Size(1140, 210)
$dnaLogBox.Location = New-Object System.Drawing.Point(10, 540)
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
