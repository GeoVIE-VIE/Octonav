<#
.SYNOPSIS
    DHCP Functions Module - Provides DHCP scope statistics collection and management

.DESCRIPTION
    This module contains functions for gathering DHCP scope statistics from one or more
    DHCP servers. It supports auto-discovery of DHCP servers, manual server specification,
    scope filtering, DNS information collection, and parallel processing using runspace pools
    for optimal performance.

.VERSION
    1.0

.AUTHOR
    OctoNav

.NOTES
    Requires: PowerShell 5.0+
    Module Dependencies: DHCP Server PowerShell Module (DhcpServer)
#>

<#
.FUNCTION Test-ServerName
.SYNOPSIS
    Validates server name format according to RFC 1123
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

<#
.FUNCTION Get-SanitizedErrorMessage
.SYNOPSIS
    Sanitizes error messages by removing sensitive information
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
.FUNCTION Write-Log
.SYNOPSIS
    Writes colored log messages to a RichTextBox with timestamps
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
                # Suspend layout for better performance during rapid updates
                $LogBox.SuspendLayout()

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

                # Resume layout and force scroll to bottom
                $LogBox.ResumeLayout()
                $LogBox.SelectionStart = $LogBox.TextLength
                $LogBox.ScrollToCaret()
                $LogBox.Refresh()
            })
        } catch {
            # Silently fail if log box is not available
        }
    }
}

<#
.FUNCTION Get-DHCPScopeStatistics
.SYNOPSIS
    Collects DHCP scope statistics from one or more DHCP servers using parallel processing

.DESCRIPTION
    This function retrieves DHCP scope statistics from specified or auto-discovered DHCP servers.
    It uses PowerShell runspace pools for parallel processing (5-10x faster than Start-Job),
    supports scope filtering, and optional DNS server information retrieval.

.PARAMETER ScopeFilters
    Array of scope name filters to apply. Case-insensitive partial matching. If empty, all scopes are returned.

.PARAMETER SpecificServers
    Array of specific DHCP server names to query. If empty, auto-discovers servers in domain.

.PARAMETER IncludeDNS
    Boolean flag to include DNS server information (Option ID 6) for each scope.

.PARAMETER LogBox
    Optional RichTextBox control for logging output with timestamps and colors.

.OUTPUTS
    System.Collections.ArrayList of custom objects containing DHCP scope statistics

.EXAMPLE
    Get-DHCPScopeStatistics -SpecificServers "DHCP-Server01" -LogBox $richTextBox1

.EXAMPLE
    Get-DHCPScopeStatistics -ScopeFilters @("Production", "Test") -IncludeDNS $true
#>
function Get-DHCPScopeStatistics {
    param(
        [string[]]$ScopeFilters = @(),
        [string[]]$SpecificServers = @(),
        [bool]$IncludeDNS = $false,
        [System.Windows.Forms.RichTextBox]$LogBox,
        [scriptblock]$StatusBarCallback = $null
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
                return @{
                    Success = $false
                    Results = @()
                    Error = "No valid DHCP server names provided"
                }
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
                return @{
                    Success = $false
                    Results = @()
                    Error = "Failed to get DHCP servers: $sanitizedError"
                }
            }
        }

        # Script block for parallel processing
        $ScriptBlock = {
            param($DHCPServerName, $ScopeFilters, $IncludeDNS)

            $ServerStats = New-Object System.Collections.ArrayList

            try {
                $Scopes = Get-DhcpServerv4Scope -ComputerName $DHCPServerName -ErrorAction Stop

                # Apply filtering if scope filters are provided
                if ($ScopeFilters -and $ScopeFilters.Count -gt 0) {
                    $FilteredScopes = @()
                    foreach ($Filter in $ScopeFilters) {
                        # Case-insensitive matching
                        $MatchingScopes = $Scopes | Where-Object { $_.Name.ToUpper() -like "*$Filter*" }
                        if ($MatchingScopes) {
                            $FilteredScopes += $MatchingScopes
                        }
                    }

                    # Remove duplicates if a scope matched multiple filters
                    $Scopes = $FilteredScopes | Select-Object -Unique

                    if ($Scopes.Count -eq 0) {
                        Write-Output "WARNING: No scopes matching filter criteria on $DHCPServerName"
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

                foreach ($Scope in $Scopes) {
                    $Stats = $AllStatsRaw | Where-Object { $_.ScopeId -eq $Scope.ScopeId }

                    if ($Stats) {
                        $obj = $Stats | Select-Object *,
                            @{Name='DHCPServer'; Expression={$DHCPServerName}},
                            @{Name='Description'; Expression={if (-not [string]::IsNullOrWhiteSpace($Scope.Description)) { $Scope.Description } else { $Scope.Name }}},
                            @{Name='DNSServers'; Expression={$DNSServerMap[$Scope.ScopeId]}}

                        [void]$ServerStats.Add($obj)
                    }
                }
            } catch {
                Write-Error "Error querying $DHCPServerName : $($_.Exception.Message)"
            }

            return $ServerStats
        }

        # Process servers in parallel using Runspaces (5-10x faster than Start-Job)
        $AllStats = New-Object System.Collections.ArrayList
        $MaxConcurrentJobs = 20
        $CheckIntervalMs = 500
        $TotalServers = $DHCPServers.Count

        Write-Log -Message "Starting parallel processing of $TotalServers DHCP servers (using Runspace Pool)..." -Color "Cyan" -LogBox $LogBox

        # Create runspace pool
        $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxConcurrentJobs)
        $RunspacePool.Open()

        # Track runspaces
        $Runspaces = New-Object System.Collections.ArrayList
        $CompletedCount = 0

        # Start all runspaces
        foreach ($Server in $DHCPServers) {
            $PowerShell = [powershell]::Create()
            $PowerShell.RunspacePool = $RunspacePool

            [void]$PowerShell.AddScript($ScriptBlock)
            [void]$PowerShell.AddArgument($Server.DnsName)
            [void]$PowerShell.AddArgument($ScopeFilters)
            [void]$PowerShell.AddArgument($IncludeDNS)

            $AsyncResult = $PowerShell.BeginInvoke()

            [void]$Runspaces.Add([PSCustomObject]@{
                PowerShell = $PowerShell
                AsyncResult = $AsyncResult
                ServerName = $Server.DnsName
                Completed = $false
            })
        }

        # Monitor runspaces
        while ($Runspaces | Where-Object { -not $_.Completed }) {
            Start-Sleep -Milliseconds $CheckIntervalMs

            foreach ($Runspace in ($Runspaces | Where-Object { -not $_.Completed })) {
                if ($Runspace.AsyncResult.IsCompleted) {
                    $CompletedCount++
                    $Runspace.Completed = $true

                    Write-Log -Message "[$CompletedCount/$TotalServers] Completed: $($Runspace.ServerName)" -Color "Green" -LogBox $LogBox

                    try {
                        $result = $Runspace.PowerShell.EndInvoke($Runspace.AsyncResult)

                        if ($result) {
                            # Add items individually to avoid type casting issues
                            foreach ($item in $result) {
                                if ($item) {
                                    [void]$AllStats.Add($item)
                                }
                            }
                        }
                    } catch {
                        Write-Log -Message "Failed to receive from $($Runspace.ServerName): $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
                    } finally {
                        $Runspace.PowerShell.Dispose()
                    }
                }
            }
        }

        # Cleanup
        $RunspacePool.Close()
        $RunspacePool.Dispose()

        Write-Log -Message "Found $($AllStats.Count) total DHCP scopes" -Color "Green" -LogBox $LogBox

        # Convert ArrayList to array for better compatibility
        $resultsArray = if ($AllStats.Count -gt 0) {
            $AllStats.ToArray()
        } else {
            @()
        }

        return @{
            Success = $true
            Results = $resultsArray
            Error = $null
        }
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Log -Message "DHCP collection error: $errorMessage" -Color "Red" -LogBox $LogBox
        return @{
            Success = $false
            Results = @()
            Error = $errorMessage
        }
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-DHCPScopeStatistics',
    'Test-ServerName',
    'Write-Log',
    'Get-SanitizedErrorMessage'
)
