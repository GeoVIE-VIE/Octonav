
<#
.SYNOPSIS
    DHCP Functions Module - Provides DHCP scope statistics collection and management

.DESCRIPTION
    This module contains functions for gathering DHCP scope statistics from one or more
    DHCP servers. It supports auto-discovery of DHCP servers, manual server specification,
    scope filtering, DNS information collection, and parallel processing using runspace pools
    for optimal performance.

.VERSION
    2.0

.AUTHOR
    OctoNav (Original), AI Assistant (Refined)

.NOTES
    Requires: PowerShell 5.0+
    Module Dependencies: DHCP Server PowerShell Module (DhcpServer)
    REFINEMENTS:
    - Removed Start-Job implementation, focusing on the superior Runspace method.
    - Improved error handling to surface the root cause of "0 scopes found" issues.
    - Added pre-flight connectivity checks.
    - Switched to ArrayList for better performance with large datasets.
    - Simplified the data pipeline between runspaces and the main thread.
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
            # Silently fail if log box is not available or disposed
        }
    }
}

<#
.FUNCTION Get-DHCPScopeStatistics
.SYNOPSIS
    Collects DHCP scope statistics from one or more DHCP servers using parallel processing.

.DESCRIPTION
    This function retrieves DHCP scope statistics from specified or auto-discovered DHCP servers.
    It uses PowerShell runspace pools for optimal performance, supports scope filtering, and
    optional DNS server information retrieval. This version provides enhanced error reporting
    to diagnose connectivity and permission issues.

.PARAMETER ScopeFilters
    Array of scope name filters to apply. Case-insensitive partial matching. If empty, all scopes are returned.

.PARAMETER SpecificServers
    Array of specific DHCP server names to query. If empty, auto-discovers servers in domain.

.PARAMETER IncludeDNS
    Boolean flag to include DNS server information (Option ID 6) for each scope.

.PARAMETER LogBox
    Optional RichTextBox control for logging output with timestamps and colors.

.PARAMETER ThrottleLimit
    The maximum number of concurrent server operations. Default is 20.

.PARAMETER StopToken
    Reference to a boolean flag to enable job cancellation.

.OUTPUTS
    System.Collections.ArrayList of custom objects containing DHCP scope statistics.

.EXAMPLE
    Get-DHCPScopeStatistics -SpecificServers "DHCP-Server01" -LogBox $richTextBox1

.EXAMPLE
    Get-DHCPScopeStatistics -ScopeFilters @("Production", "Test") -IncludeDNS $true
#>
function Get-DHCPScopeStatistics {
    [CmdletBinding()]
    param(
        [string[]]$ScopeFilters = @(),
        [string[]]$SpecificServers = @(),
        [bool]$IncludeDNS = $false,
        [System.Windows.Forms.RichTextBox]$LogBox,
        [int]$ThrottleLimit = 20,
        [ref]$StopToken
    )

    try {
        # Get DHCP servers
        if ($SpecificServers.Count -gt 0) {
            Write-Log -Message "Using specified DHCP servers..." -Color "Cyan" -LogBox $LogBox
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
                Write-Log -Message "No valid DHCP server names provided." -Color "Red" -LogBox $LogBox
                return [PSCustomObject]@{ Success = $false; Results = @(); Error = "No valid DHCP server names provided." }
            }
            $DHCPServers = $validServers
        } else {
            Write-Log -Message "Discovering DHCP servers in domain..." -Color "Cyan" -LogBox $LogBox
            try {
                $DHCPServers = (Get-DhcpServerInDC).DnsName
                Write-Log -Message "Found $($DHCPServers.Count) DHCP servers." -Color "Green" -LogBox $LogBox
            } catch {
                $sanitizedError = Get-SanitizedErrorMessage -ErrorRecord $_
                Write-Log -Message "Failed to get DHCP servers: $sanitizedError" -Color "Red" -LogBox $LogBox
                return [PSCustomObject]@{ Success = $false; Results = @(); Error = "Failed to get DHCP servers: $sanitizedError" }
            }
        }
        
        # Pre-flight check for connectivity
        $OnlineServers = @()
        foreach ($server in $DHCPServers) {
            if ($StopToken -and $StopToken.Value) { break }
            Write-Log -Message "Pinging $server..." -Color "Cyan" -LogBox $LogBox
            if (Test-Connection -ComputerName $server -Count 1 -Quiet) {
                $OnlineServers += $server
            } else {
                Write-Log -Message "Server $server is offline or not responding to ping. Skipping." -Color "Red" -LogBox $LogBox
            }
        }
        if ($OnlineServers.Count -eq 0) {
            Write-Log -Message "No DHCP servers are online. Aborting." -Color "Red" -LogBox $LogBox
            return [PSCustomObject]@{ Success = $false; Results = @(); Error = "No DHCP servers are online." }
        }
        $DHCPServers = $OnlineServers

        # This scriptblock does the work on each server
        $ScriptBlock = {
            param($ServerName, $ScopeFilters, $IncludeDNS)

            # Force all errors to be terminating so the try/catch block will catch them
            $ErrorActionPreference = 'Stop'

            # Return object will always indicate success or failure
            $ResultObject = [PSCustomObject]@{
                ServerName = $ServerName
                Success    = $false
                Message    = ""
                Scopes     = @()
            }

            try {
                # CRITICAL: Ensure DhcpServer module is available inside the worker
                Import-Module DhcpServer -ErrorAction Stop

                # Get all scopes from the server
                $Scopes = Get-DhcpServerv4Scope -ComputerName $ServerName
                if (-not $Scopes) {
                    $ResultObject.Message = "No scopes found on server. Check permissions or DHCP service status."
                    return $ResultObject
                }

                # Apply filtering if scope filters are provided
                if ($ScopeFilters -and $ScopeFilters.Count -gt 0) {
                    $FilteredScopes = @()
                    foreach ($Filter in $ScopeFilters) {
                        $FilterUpper = $Filter.ToUpper()
                        $MatchingScopes = $Scopes | Where-Object { $_.Name.ToUpper() -like "*$FilterUpper*" }
                        $FilteredScopes += $MatchingScopes
                    }
                    $Scopes = $FilteredScopes | Select-Object -Unique
                    if ($Scopes.Count -eq 0) {
                        $ResultObject.Message = "No scopes matched the provided filter(s)."
                        return $ResultObject
                    }
                }

                # Get statistics for the (filtered) scopes
                $AllStatsRaw = Get-DhcpServerv4ScopeStatistics -ComputerName $ServerName

                # Get DNS info if requested
                $DNSServerMap = @{}
                if ($IncludeDNS) {
                    foreach ($Scope in $Scopes) {
                        try {
                            $DNSOption = Get-DhcpServerv4OptionValue -ComputerName $ServerName -ScopeId $Scope.ScopeId -OptionId 6 -ErrorAction SilentlyContinue
                            if ($DNSOption) {
                                $DNSServerMap[$Scope.ScopeId] = $DNSOption.Value -join ','
                            }
                        } catch {
                            # DNS option not found for this scope, ignore.
                        }
                    }
                }

                # Combine scope info with statistics
                $ServerStats = foreach ($Scope in $Scopes) {
                    $Stats = $AllStatsRaw | Where-Object { $_.ScopeId -eq $Scope.ScopeId }
                    if ($Stats) {
                        $Stats | Select-Object *,
                            @{Name='DHCPServer'; Expression={$ServerName}},
                            @{Name='Description'; Expression={if (-not [string]::IsNullOrWhiteSpace($Scope.Description)) { $Scope.Description } else { $Scope.Name }}},
                            @{Name='DNSServers'; Expression={$DNSServerMap[$Scope.ScopeId]}}
                    }
                }

                # Return success
                $ResultObject.Success = $true
                $ResultObject.Message = "Successfully retrieved $($ServerStats.Count) scope(s)."
                $ResultObject.Scopes = $ServerStats
                return $ResultObject

            } catch {
                # Catch any terminating error and report it
                $ResultObject.Message = "ERROR: $($_.Exception.Message)"
                return $ResultObject
            }
        }

        # --- Runspace Pool Implementation ---
        Write-Log -Message "Starting parallel processing of $($DHCPServers.Count) DHCP servers (Throttle: $ThrottleLimit)..." -Color "Cyan" -LogBox $LogBox
        
        $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
        $RunspacePool.Open()
        $Runspaces = @()
        
        # Use ArrayList for better performance when adding many items
        [System.Collections.ArrayList]$AllStats = @()

        try {
            foreach ($Server in $DHCPServers) {
                if ($StopToken -and $StopToken.Value) {
                    Write-Log -Message "Stop requested, cancelling remaining servers..." -Color "Yellow" -LogBox $LogBox
                    break
                }
                $PowerShell = [powershell]::Create().AddScript($ScriptBlock).AddArgument($Server).AddArgument($ScopeFilters).AddArgument($IncludeDNS)
                $PowerShell.RunspacePool = $RunspacePool
                $Runspaces += [PSCustomObject]@{
                    PowerShell = $PowerShell
                    AsyncResult = $PowerShell.BeginInvoke()
                    ServerName = $Server
                }
            }

            $CompletedCount = 0
            $TotalServers = $Runspaces.Count

            while ($Runspaces.AsyncResult.IsCompleted -contains $false) {
                if ($StopToken -and $StopToken.Value) {
                    Write-Log -Message "Stop requested during processing..." -Color "Yellow" -LogBox $LogBox
                    break
                }
                Start-Sleep -Milliseconds 200
                foreach ($Runspace in $Runspaces | Where-Object { $_.AsyncResult.IsCompleted -and $_.PowerShell -ne $null }) {
                    $CompletedCount++
                    $ServerResult = $Runspace.PowerShell.EndInvoke($Runspace.AsyncResult)
                    
                    if ($ServerResult.Success) {
                        Write-Log -Message "[$CompletedCount/$TotalServers] Completed: $($Runspace.ServerName) - $($ServerResult.Message)" -Color "Green" -LogBox $LogBox
                        [void]$AllStats.AddRange($ServerResult.Scopes)
                    } else {
                        Write-Log -Message "[$CompletedCount/$TotalServers] Failed: $($Runspace.ServerName) - $($ServerResult.Message)" -Color "Red" -LogBox $LogBox
                    }
                    $Runspace.PowerShell.Dispose()
                    $Runspace.PowerShell = $null # Mark as processed
                }
            }

            # Handle cancellation
            if ($StopToken -and $StopToken.Value) {
                Write-Log -Message "Operation cancelled by user. Collected $($AllStats.Count) scopes before cancellation." -Color "Yellow" -LogBox $LogBox
                return [PSCustomObject]@{ Success = $false; Results = $AllStats; Error = "Operation cancelled by user" }
            }

        } finally {
            $RunspacePool.Close()
            $RunspacePool.Dispose()
        }

        Write-Log -Message "Collection complete. Found $($AllStats.Count) total DHCP scopes." -Color "Green" -LogBox $LogBox
        return [PSCustomObject]@{ Success = $true; Results = $AllStats; Error = $null }

    } catch {
        $errorMessage = $_.Exception.Message
        Write-Log -Message "FATAL ERROR in main function: $errorMessage" -Color "Red" -LogBox $LogBox
        return [PSCustomObject]@{ Success = $false; Results = @(); Error = $errorMessage }
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-DHCPScopeStatistics',
    'Test-ServerName',
    'Write-Log',
    'Get-SanitizedErrorMessage'
)
```
