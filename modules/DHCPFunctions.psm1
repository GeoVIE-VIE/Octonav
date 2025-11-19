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

            $ServerStats = @()  # Use regular array, not ArrayList

            try {
                $Scopes = Get-DhcpServerv4Scope -ComputerName $DHCPServerName -ErrorAction Stop

                Write-Output "DEBUG: Found $($Scopes.Count) total scope(s) on $DHCPServerName"

                # Debug: Show all scope names
                foreach ($s in $Scopes) {
                    Write-Output "DEBUG: Scope found: Name='$($s.Name)', ScopeId='$($s.ScopeId)'"
                }

                # Apply filtering if scope filters are provided
                if ($ScopeFilters -and $ScopeFilters.Count -gt 0) {
                    Write-Output "DEBUG: Applying $($ScopeFilters.Count) filter(s): $($ScopeFilters -join ', ')"

                    $FilteredScopes = @()
                    foreach ($Filter in $ScopeFilters) {
                        Write-Output "DEBUG: Testing filter '$Filter' against scope names..."

                        # Case-insensitive matching
                        $MatchingScopes = $Scopes | Where-Object { $_.Name.ToUpper() -like "*$Filter*" }

                        if ($MatchingScopes) {
                            Write-Output "DEBUG: Filter '$Filter' matched $($MatchingScopes.Count) scope(s)"
                            foreach ($ms in $MatchingScopes) {
                                Write-Output "DEBUG:   - Matched: '$($ms.Name)'"
                            }
                            $FilteredScopes += $MatchingScopes
                        } else {
                            Write-Output "DEBUG: Filter '$Filter' matched 0 scopes"
                        }
                    }

                    # Remove duplicates if a scope matched multiple filters
                    $Scopes = $FilteredScopes | Select-Object -Unique

                    if ($Scopes.Count -eq 0) {
                        Write-Output "WARNING: No scopes matching filter criteria on $DHCPServerName"
                        return @()
                    } else {
                        Write-Output "DEBUG: After filtering: $($Scopes.Count) scope(s) will be processed"
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
                    Write-Output "DEBUG: Processing scope: $($Scope.Name) ($($Scope.ScopeId)) from $DHCPServerName"

                    # Find corresponding statistics
                    $Stats = $AllStatsRaw | Where-Object { $_.ScopeId -eq $Scope.ScopeId }

                    if ($Stats) {
                        Write-Output "DEBUG: Found statistics for scope $($Scope.ScopeId)"

                        # Use Select-Object * with calculated properties (matches working merged script)
                        $ServerStats += $Stats | Select-Object *,
                            @{Name='DHCPServer'; Expression={$DHCPServerName}},
                            @{Name='Description'; Expression={if (-not [string]::IsNullOrWhiteSpace($Scope.Description)) { $Scope.Description } else { $Scope.Name }}},
                            @{Name='DNSServers'; Expression={$DNSServerMap[$Scope.ScopeId]}}

                        Write-Output "DEBUG: Added scope $($Scope.ScopeId) to results (ServerStats count: $($ServerStats.Count))"
                    } else {
                        Write-Output "WARNING: No statistics found for scope $($Scope.ScopeId) - it may be inactive"
                    }
                }

                Write-Output "DEBUG: Collected $($ServerStats.Count) scope(s) from $DHCPServerName - returning to main thread"

            } catch {
                Write-Error "Error querying $DHCPServerName : $($_.Exception.Message)"
            }

            return $ServerStats
        }

        # Process servers in parallel using Start-Job (better serialization than runspaces)
        $Jobs = @()
        $AllStats = @()
        $MaxConcurrentJobs = 20
        $CompletedCount = 0
        $TotalServers = $DHCPServers.Count

        Write-Log -Message "Starting parallel processing of $TotalServers DHCP servers (using Start-Job with batching)..." -Color "Cyan" -LogBox $LogBox

        # Process servers in batches
        for ($i = 0; $i -lt $DHCPServers.Count; $i += $MaxConcurrentJobs) {
            $Batch = $DHCPServers[$i..([Math]::Min($i + $MaxConcurrentJobs - 1, $DHCPServers.Count - 1))]

            Write-Log -Message "Starting batch with $($Batch.Count) servers..." -Color "Info" -LogBox $LogBox

            # Start jobs for current batch
            foreach ($Server in $Batch) {
                $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Server.DnsName, $ScopeFilters, $IncludeDNS
                $Jobs += @{
                    Job = $Job
                    ServerName = $Server.DnsName
                    Processed = $false
                }
            }

            # Wait for current batch to complete
            while ($Jobs | Where-Object { $_.Job.State -eq 'Running' }) {
                Start-Sleep -Seconds 2

                # Check for completed jobs and collect results
                $CompletedInBatch = $Jobs | Where-Object { $_.Job.State -eq 'Completed' -and -not $_.Processed }
                foreach ($CompletedJob in $CompletedInBatch) {
                    $CompletedCount++
                    $CompletedJob.Processed = $true

                    Write-Log -Message "[$CompletedCount/$TotalServers] Completed: $($CompletedJob.ServerName)" -Color "Green" -LogBox $LogBox

                    try {
                        $Result = Receive-Job -Job $CompletedJob.Job -ErrorAction Stop
                        if ($Result) {
                            # Separate debug strings from data objects
                            foreach ($item in $Result) {
                                if ($item -is [string]) {
                                    if ($item -like "DEBUG:*") {
                                        Write-Log -Message $item -Color "Cyan" -LogBox $LogBox
                                    } elseif ($item -like "WARNING:*") {
                                        Write-Log -Message $item -Color "Yellow" -LogBox $LogBox
                                    } else {
                                        Write-Log -Message $item -Color "Magenta" -LogBox $LogBox
                                    }
                                } else {
                                    # It's a scope data object, add to results
                                    $AllStats += $item
                                }
                            }
                        }
                    } catch {
                        Write-Log -Message "Failed to receive from $($CompletedJob.ServerName): $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
                    }

                    Remove-Job -Job $CompletedJob.Job -Force
                }

                # Check for failed jobs
                $FailedInBatch = $Jobs | Where-Object { $_.Job.State -eq 'Failed' -and -not $_.Processed }
                foreach ($FailedJob in $FailedInBatch) {
                    $CompletedCount++
                    $FailedJob.Processed = $true
                    Write-Log -Message "[$CompletedCount/$TotalServers] Failed: $($FailedJob.ServerName)" -Color "Red" -LogBox $LogBox
                    Remove-Job -Job $FailedJob.Job -Force
                }
            }
        }

        # Final cleanup - handle any remaining jobs
        $RemainingJobs = $Jobs | Where-Object { -not $_.Processed }
        foreach ($RemainingJob in $RemainingJobs) {
            if ($RemainingJob.Job.State -eq 'Completed') {
                try {
                    $Result = Receive-Job -Job $RemainingJob.Job
                    if ($Result) {
                        foreach ($item in $Result) {
                            if ($item -is [string]) {
                                if ($item -like "DEBUG:*") {
                                    Write-Log -Message $item -Color "Cyan" -LogBox $LogBox
                                } elseif ($item -like "WARNING:*") {
                                    Write-Log -Message $item -Color "Yellow" -LogBox $LogBox
                                }
                            } else {
                                $AllStats += $item
                            }
                        }
                    }
                } catch {
                    Write-Log -Message "Failed to receive from $($RemainingJob.ServerName): $($_.Exception.Message)" -Color "Red" -LogBox $LogBox
                }
            }
            Remove-Job -Job $RemainingJob.Job -Force
        }

        Write-Log -Message "Found $($AllStats.Count) total DHCP scopes" -Color "Green" -LogBox $LogBox

        $resultsArray = $AllStats

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
