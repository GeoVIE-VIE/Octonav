<#
.SYNOPSIS
    DHCP Functions Module - Provides DHCP scope statistics collection and management.

.DESCRIPTION
    This module contains functions for gathering DHCP scope statistics from one or more
    DHCP servers. It supports auto-discovery of DHCP servers, manual server specification,
    scope filtering, DNS information collection, and parallel processing using runspace pools
    for optimal performance.

.VERSION
    2.2

.AUTHOR
    OctoNav (Original), AI Assistant (Refined)

.NOTES
    Requires: PowerShell 5.0+
    Module Dependencies: DHCP Server PowerShell Module (DhcpServer)

    REFINEMENTS:
    - Added StatusBarCallback parameter to Get-DHCPScopeStatistics to avoid "parameter cannot be found" errors.
    - Introduced Invoke-StatusBar helper to safely call status bar callbacks.
    - Minor robustness tweaks around collections and error handling.
#>

function Test-ServerName {
    <#
    .SYNOPSIS
        Validates server name format according to RFC 1123.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName
    )

    if ([string]::IsNullOrWhiteSpace($ServerName)) {
        return $false
    }

    $trimmed = $ServerName.Trim()

    if ($trimmed.Length -gt 253) {
        return $false
    }

    # Basic RFC1123 host/FDQN validation
    if ($trimmed -notmatch '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$') {
        return $false
    }

    # Disallow consecutive dots or bad dot/dash combos
    if ($trimmed -match '\.\.' -or $trimmed -match '\.-' -or $trimmed -match '-\.') {
        return $false
    }

    return $true
}

function Get-SanitizedErrorMessage {
    <#
    .SYNOPSIS
        Sanitizes error messages by removing sensitive information.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    if (-not $ErrorRecord) {
        return 'An unknown error occurred'
    }

    $message = $ErrorRecord.Exception.Message

    # Mask paths (Windows + Unix), IPs, and basic user references
    $message = $message -replace '[A-Z]:\\[^\s]+', '[PATH]'
    $message = $message -replace '/[^\s]+', '[PATH]'
    $message = $message -replace '\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP]'
    $message = $message -replace '\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b', '[IPv6]'
    $message = $message -replace 'user(name)?[:\s]+[^\s]+', 'user: [REDACTED]'

    # Single line only
    $message = $message -split "`n" | Select-Object -First 1

    if ($message.Length -gt 200) {
        $message = $message.Substring(0, 197) + '...'
    }

    return $message
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes colored log messages to a RichTextBox with timestamps.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$Color = 'Black',

        [Parameter(Mandatory = $false)]
        [System.Windows.Forms.RichTextBox]$LogBox
    )

    if (-not $LogBox) { return }

    try {
        # Make sure assemblies are loaded if the hosting app hasn't already
        Add-Type -AssemblyName System.Windows.Forms, System.Drawing -ErrorAction SilentlyContinue | Out-Null
    } catch { }

    try {
        $action = [Action]{
            $LogBox.SuspendLayout()

            $LogBox.SelectionStart  = $LogBox.TextLength
            $LogBox.SelectionLength = 0
            $LogBox.SelectionColor  = switch ($Color) {
                'Green'   { [System.Drawing.Color]::Green }
                'Red'     { [System.Drawing.Color]::Red }
                'Yellow'  { [System.Drawing.Color]::DarkOrange }
                'Cyan'    { [System.Drawing.Color]::DarkCyan }
                'Magenta' { [System.Drawing.Color]::Magenta }
                default   { [System.Drawing.Color]::Black }
            }

            $timestamp = Get-Date -Format 'HH:mm:ss'
            $LogBox.AppendText("[$timestamp] $Message`r`n")

            # Reset color and scroll
            $LogBox.SelectionColor = $LogBox.ForeColor
            $LogBox.ResumeLayout()
            $LogBox.SelectionStart = $LogBox.TextLength
            $LogBox.ScrollToCaret()
            $LogBox.Refresh()
        }

        # If called from a different thread, use Invoke
        if ($LogBox.InvokeRequired) {
            $LogBox.Invoke($action)
        } else {
            & $action
        }
    } catch {
        # Silently fail if log box is not available or disposed
    }
}

function Invoke-StatusBar {
    <#
    .SYNOPSIS
        Safely invokes a status bar update callback.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [scriptblock]$Callback,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Callback) { return }

    try {
        & $Callback.Invoke($Message)
    } catch {
        # Do not let UI callback errors break the main logic
    }
}

function Get-DHCPScopeStatistics {
    <#
    .SYNOPSIS
        Collects DHCP scope statistics from one or more DHCP servers using parallel processing.

    .DESCRIPTION
        This function retrieves DHCP scope statistics from specified or auto-discovered DHCP servers.
        It uses PowerShell runspace pools for optimal performance, supports scope filtering, and
        optional DNS server information retrieval. This version provides enhanced error reporting
        to diagnose connectivity and permission issues.

    .PARAMETER ScopeFilters
        Array of scope name filters to apply. Case-insensitive partial matching. If empty,
        all scopes are returned.

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

    .PARAMETER StatusBarCallback
        Optional scriptblock that receives status text for UI status bar updates.

    .OUTPUTS
        PSCustomObject:
        - Success (bool)
        - Results (ArrayList of scope objects)
        - Error (string)

    .EXAMPLE
        Get-DHCPScopeStatistics -SpecificServers 'DHCP-Server01' -LogBox $richTextBox1

    .EXAMPLE
        Get-DHCPScopeStatistics -ScopeFilters @('Production', 'Test') -IncludeDNS $true
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$ScopeFilters = @(),

        [Parameter(Mandatory = $false)]
        [string[]]$SpecificServers = @(),

        [Parameter(Mandatory = $false)]
        [bool]$IncludeDNS = $false,

        [Parameter(Mandatory = $false)]
        [System.Windows.Forms.RichTextBox]$LogBox,

        [Parameter(Mandatory = $false)]
        [int]$ThrottleLimit = 20,

        [Parameter(Mandatory = $false)]
        [ref]$StopToken,

        [Parameter(Mandatory = $false)]
        [scriptblock]$StatusBarCallback
    )

    try {
        # Determine servers
        if ($SpecificServers -and $SpecificServers.Count -gt 0) {
            Invoke-StatusBar -Callback $StatusBarCallback -Message 'Using specified DHCP servers...'
            Write-Log -Message 'Using specified DHCP servers...' -Color 'Cyan' -LogBox $LogBox

            $validServers = @()
            foreach ($server in $SpecificServers) {
                $trimmedServer = $server.Trim()
                if (Test-ServerName -ServerName $trimmedServer) {
                    $validServers += $trimmedServer
                } else {
                    Write-Log -Message "Invalid DHCP server name skipped: $trimmedServer" -Color 'Yellow' -LogBox $LogBox
                }
            }

            if ($validServers.Count -eq 0) {
                $msg = 'No valid DHCP server names provided.'
                Write-Log -Message $msg -Color 'Red' -LogBox $LogBox
                Invoke-StatusBar -Callback $StatusBarCallback -Message $msg
                return [PSCustomObject]@{
                    Success = $false
                    Results = @()
                    Error   = $msg
                }
            }

            $DHCPServers = $validServers
        }
        else {
            Invoke-StatusBar -Callback $StatusBarCallback -Message 'Discovering DHCP servers in domain...'
            Write-Log -Message 'Discovering DHCP servers in domain...' -Color 'Cyan' -LogBox $LogBox
            try {
                $DHCPServers = (Get-DhcpServerInDC).DnsName
                Write-Log -Message "Found $($DHCPServers.Count) DHCP servers." -Color 'Green' -LogBox $LogBox
                Invoke-StatusBar -Callback $StatusBarCallback -Message "Found $($DHCPServers.Count) DHCP servers."
            } catch {
                $sanitizedError = Get-SanitizedErrorMessage -ErrorRecord $_
                $msg = "Failed to get DHCP servers: $sanitizedError"
                Write-Log -Message $msg -Color 'Red' -LogBox $LogBox
                Invoke-StatusBar -Callback $StatusBarCallback -Message $msg
                return [PSCustomObject]@{
                    Success = $false
                    Results = @()
                    Error   = $msg
                }
            }
        }

        # Pre-flight connectivity check
        $OnlineServers = @()
        foreach ($server in $DHCPServers) {
            if ($StopToken -and $StopToken.Value) { break }

            Write-Log -Message "Pinging $server..." -Color 'Cyan' -LogBox $LogBox
            Invoke-StatusBar -Callback $StatusBarCallback -Message "Pinging $server..."

            if (Test-Connection -ComputerName $server -Count 1 -Quiet) {
                $OnlineServers += $server
            } else {
                Write-Log -Message "Server $server is offline or not responding to ping. Skipping." -Color 'Red' -LogBox $LogBox
            }
        }

        if ($OnlineServers.Count -eq 0) {
            $msg = 'No DHCP servers are online. Aborting.'
            Write-Log -Message $msg -Color 'Red' -LogBox $LogBox
            Invoke-StatusBar -Callback $StatusBarCallback -Message $msg
            return [PSCustomObject]@{
                Success = $false
                Results = @()
                Error   = 'No DHCP servers are online.'
            }
        }

        $DHCPServers = $OnlineServers

        # Scriptblock to run per server
        $ScriptBlock = {
            param(
                [string]$ServerName,
                [string[]]$ScopeFilters,
                [bool]$IncludeDNS
            )

            $ErrorActionPreference = 'Stop'

            $ResultObject = [PSCustomObject]@{
                ServerName = $ServerName
                Success    = $false
                Message    = ''
                Scopes     = @()
            }

            try {
                Import-Module DhcpServer -ErrorAction Stop

                $Scopes = Get-DhcpServerv4Scope -ComputerName $ServerName
                if (-not $Scopes) {
                    $ResultObject.Message = 'No scopes found on server. Check permissions or DHCP service status.'
                    return $ResultObject
                }

                # Scope filtering by name
                if ($ScopeFilters -and $ScopeFilters.Count -gt 0) {
                    $FilteredScopes = @()
                    foreach ($Filter in $ScopeFilters) {
                        $FilterUpper = $Filter.ToUpper()
                        $MatchingScopes = $Scopes | Where-Object { $_.Name.ToUpper() -like "*$FilterUpper*" }
                        $FilteredScopes += $MatchingScopes
                    }
                    $Scopes = $FilteredScopes | Select-Object -Unique
                    if (-not $Scopes -or $Scopes.Count -eq 0) {
                        $ResultObject.Message = 'No scopes matched the provided filter(s).'
                        return $ResultObject
                    }
                }

                $AllStatsRaw = Get-DhcpServerv4ScopeStatistics -ComputerName $ServerName

                # Optional DNS server option lookup (OptionId 6)
                $DNSServerMap = @{}
                if ($IncludeDNS) {
                    foreach ($Scope in $Scopes) {
                        try {
                            $DNSOption = Get-DhcpServerv4OptionValue `
                                -ComputerName $ServerName `
                                -ScopeId $Scope.ScopeId `
                                -OptionId 6 `
                                -ErrorAction SilentlyContinue
                            if ($DNSOption) {
                                $DNSServerMap[$Scope.ScopeId] = $DNSOption.Value -join ','
                            }
                        } catch {
                            # Ignore DNS lookup failures per-scope
                        }
                    }
                }

                $ServerStats = foreach ($Scope in $Scopes) {
                    $Stats = $AllStatsRaw | Where-Object { $_.ScopeId -eq $Scope.ScopeId }
                    if ($Stats) {
                        $Stats | Select-Object *,
                            @{ Name = 'DHCPServer';  Expression = { $ServerName } },
                            @{ Name = 'Description'; Expression = {
                                    if (-not [string]::IsNullOrWhiteSpace($Scope.Description)) {
                                        $Scope.Description
                                    } else {
                                        $Scope.Name
                                    }
                                }
                            },
                            @{ Name = 'DNSServers';  Expression = { $DNSServerMap[$Scope.ScopeId] } }
                    }
                }

                $ResultObject.Success = $true
                $ResultObject.Message = "Successfully retrieved $($ServerStats.Count) scope(s)."
                $ResultObject.Scopes  = $ServerStats
                return $ResultObject
            } catch {
                $ResultObject.Message = "ERROR: $($_.Exception.Message)"
                return $ResultObject
            }
        }

        $serverCountMsg = "Starting parallel processing of $($DHCPServers.Count) DHCP servers (Throttle: $ThrottleLimit)..."
        Write-Log -Message $serverCountMsg -Color 'Cyan' -LogBox $LogBox
        Invoke-StatusBar -Callback $StatusBarCallback -Message $serverCountMsg

        # Runspace pool setup
        $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
        $RunspacePool.Open()

        $Runspaces = @()
        $AllStats  = New-Object System.Collections.ArrayList

        try {
            foreach ($Server in $DHCPServers) {
                if ($StopToken -and $StopToken.Value) { break }

                $PowerShell = [powershell]::Create()
                $null = $PowerShell.AddScript($ScriptBlock).AddArgument($Server).AddArgument($ScopeFilters).AddArgument($IncludeDNS)
                $PowerShell.RunspacePool = $RunspacePool

                $Runspaces += [PSCustomObject]@{
                    PowerShell  = $PowerShell
                    AsyncResult = $PowerShell.BeginInvoke()
                    ServerName  = $Server
                }
            }

            $CompletedCount = 0
            $TotalServers   = $Runspaces.Count

            while ($Runspaces.AsyncResult.IsCompleted -contains $false) {
                if ($StopToken -and $StopToken.Value) { break }
                Start-Sleep -Milliseconds 200

                foreach ($Runspace in $Runspaces | Where-Object { $_.AsyncResult.IsCompleted -and $_.PowerShell -ne $null }) {
                    $CompletedCount++
                    $ServerResult = $Runspace.PowerShell.EndInvoke($Runspace.AsyncResult)

                    if ($ServerResult.Success) {
                        $msg = "[$CompletedCount/$TotalServers] Completed: $($Runspace.ServerName) - $($ServerResult.Message)"
                        Write-Log -Message $msg -Color 'Green' -LogBox $LogBox
                        Invoke-StatusBar -Callback $StatusBarCallback -Message $msg

                        if ($ServerResult.Scopes) {
                            [void]$AllStats.AddRange($ServerResult.Scopes)
                        }
                    }
                    else {
                        $msg = "[$CompletedCount/$TotalServers] Failed: $($Runspace.ServerName) - $($ServerResult.Message)"
                        Write-Log -Message $msg -Color 'Red' -LogBox $LogBox
                        Invoke-StatusBar -Callback $StatusBarCallback -Message $msg
                    }

                    $Runspace.PowerShell.Dispose()
                    $Runspace.PowerShell = $null
                }
            }

            if ($StopToken -and $StopToken.Value) {
                $msg = "Operation cancelled by user. Collected $($AllStats.Count) scopes before cancellation."
                Write-Log -Message $msg -Color 'Yellow' -LogBox $LogBox
                Invoke-StatusBar -Callback $StatusBarCallback -Message $msg
                return [PSCustomObject]@{
                    Success = $false
                    Results = $AllStats
                    Error   = 'Operation cancelled by user'
                }
            }
        }
        finally {
            $RunspacePool.Close()
            $RunspacePool.Dispose()
        }

        $completeMsg = "Collection complete. Found $($AllStats.Count) total DHCP scopes."
        Write-Log -Message $completeMsg -Color 'Green' -LogBox $LogBox
        Invoke-StatusBar -Callback $StatusBarCallback -Message $completeMsg

        return [PSCustomObject]@{
            Success = $true
            Results = $AllStats
            Error   = $null
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        $fatalMsg     = "FATAL ERROR in main function: $errorMessage"
        Write-Log -Message $fatalMsg -Color 'Red' -LogBox $LogBox
        Invoke-StatusBar -Callback $StatusBarCallback -Message $fatalMsg

        return [PSCustomObject]@{
            Success = $false
            Results = @()
            Error   = $errorMessage
        }
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-DHCPScopeStatistics',
    'Test-ServerName',
    'Write-Log',
    'Get-SanitizedErrorMessage',
    'Invoke-StatusBar'
)
