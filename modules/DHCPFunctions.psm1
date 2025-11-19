<#
.SYNOPSIS
    DHCP Functions Module - Provides DHCP scope statistics collection and management.

.DESCRIPTION
    Collects DHCP scope statistics from one or more DHCP servers using parallel processing.
    Supports:
    - Auto-discovery of DHCP servers (Get-DhcpServerInDC)
    - Manual server list
    - Scope name filtering
    - Optional DNS option (ID 6) lookup
    - Parallel processing via runspace pool
    - UI integration via RichTextBox logging and StatusBar callback

.NOTES
    Requires: PowerShell 5.1+
    Module Dependencies: DHCP Server PowerShell Module (DhcpServer)
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

    # Basic RFC1123 host/FQDN validation
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

function Invoke-StatusBar {
    <#
    .SYNOPSIS
        Safely invokes a status bar update callback (status, progress, progressText).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [scriptblock]$Callback,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [int]$Progress = 0,

        [Parameter(Mandatory = $false)]
        [string]$ProgressText = $Status
    )

    if (-not $Callback) { return }

    try {
        & $Callback.Invoke($Status, $Progress, $ProgressText)
    } catch {
        # Never let UI callback errors break main logic
    }
}

function Get-DHCPScopeStatistics {
    <#
    .SYNOPSIS
        Collects DHCP scope statistics from one or more DHCP servers using parallel processing.

    .DESCRIPTION
        Retrieves DHCP scope statistics from specified or auto-discovered DHCP servers.
        Uses runspace pools for performance, supports scope filtering, and optional
        DNS server (Option ID 6) lookup. Integrates with OctoNav GUI via logging
        and status bar callback.

    .PARAMETER ScopeFilters
        Array of scope name filters to apply. Case-insensitive partial matching.
        If empty, all scopes are returned.

    .PARAMETER SpecificServers
        Array of specific DHCP server names to query. If empty, auto-discovers
        servers from the domain with Get-DhcpServerInDC.

    .PARAMETER IncludeDNS
        Boolean flag to include DNS server information (Option ID 6) for each scope.

    .PARAMETER LogBox
        Optional RichTextBox control for logging output.

    .PARAMETER ThrottleLimit
        Maximum number of concurrent server operations. Default is 20.

    .PARAMETER StopToken
        Reference to a boolean flag for cancellation. Set to $true to request stop.

    .PARAMETER StatusBarCallback
        Scriptblock callback used by the GUI status bar.
        Signature: param($status, $progress, $progressText)

    .OUTPUTS
        PSCustomObject:
        - Success (bool)
        - Results (ArrayList of scope objects)
        - Error (string)
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
        Write-Host "[DHCP-DEBUG] Get-DHCPScopeStatistics called" -ForegroundColor Cyan
        Write-Host "[DHCP-DEBUG] ScopeFilters: $($ScopeFilters.Count) items" -ForegroundColor Cyan
        Write-Host "[DHCP-DEBUG] SpecificServers: $($SpecificServers.Count) items" -ForegroundColor Cyan
        Write-Host "[DHCP-DEBUG] IncludeDNS: $IncludeDNS" -ForegroundColor Cyan

        # -------------------------
        # Determine DHCP servers
        # -------------------------
        if ($SpecificServers -and $SpecificServers.Count -gt 0) {
            Write-Host "[DHCP-DEBUG] Using specific servers" -ForegroundColor Cyan
            Invoke-StatusBar -Callback $StatusBarCallback -Status 'Using specified DHCP servers...' -Progress 5 -ProgressText 'Validating server names...'
            Write-Log -Message 'Using specified DHCP servers...' -Color 'Info' -LogBox $LogBox -Theme $null

            $validServers = @()
            foreach ($server in $SpecificServers) {
                $trimmedServer = $server.Trim()
                if ([string]::IsNullOrWhiteSpace($trimmedServer)) { continue }

                if (Test-ServerName -ServerName $trimmedServer) {
                    $validServers += $trimmedServer
                } else {
                    Write-Log -Message "Invalid DHCP server name skipped: $trimmedServer" -Color 'Warning' -LogBox $LogBox -Theme $null
                }
            }

            if ($validServers.Count -eq 0) {
                $msg = 'No valid DHCP server names provided.'
                Write-Log -Message $msg -Color 'Error' -LogBox $LogBox -Theme $null
                Invoke-StatusBar -Callback $StatusBarCallback -Status $msg -Progress 0 -ProgressText $msg
                return [PSCustomObject]@{
                    Success = $false
                    Results = @()
                    Error   = $msg
                }
            }

            $DHCPServers = $validServers
            Write-Host "[DHCP-DEBUG] Valid servers: $($DHCPServers.Count)" -ForegroundColor Cyan
        }
        else {
            Write-Host "[DHCP-DEBUG] No specific servers - auto-discovering from AD" -ForegroundColor Cyan
            Invoke-StatusBar -Callback $StatusBarCallback -Status 'Discovering DHCP servers...' -Progress 5 -ProgressText 'Discovering DHCP servers in domain...'
            Write-Log -Message 'Discovering DHCP servers in domain...' -Color 'Info' -LogBox $LogBox -Theme $null

            try {
                $DHCPServers = (Get-DhcpServerInDC).DnsName
                $countMsg = "Found $($DHCPServers.Count) DHCP servers."
                Write-Log -Message $countMsg -Color 'Success' -LogBox $LogBox -Theme $null
                Invoke-StatusBar -Callback $StatusBarCallback -Status $countMsg -Progress 10 -ProgressText $countMsg
            } catch {
                $sanitizedError = Get-SanitizedErrorMessage -ErrorRecord $_
                $msg = "Failed to get DHCP servers: $sanitizedError"
                Write-Log -Message $msg -Color 'Error' -LogBox $LogBox -Theme $null
                Invoke-StatusBar -Callback $StatusBarCallback -Status $msg -Progress 0 -ProgressText $msg
                return [PSCustomObject]@{
                    Success = $false
                    Results = @()
                    Error   = $msg
                }
            }
        }

        if (-not $DHCPServers -or $DHCPServers.Count -eq 0) {
            $msg = 'No DHCP servers available.'
            Write-Log -Message $msg -Color 'Error' -LogBox $LogBox -Theme $null
            Invoke-StatusBar -Callback $StatusBarCallback -Status $msg -Progress 0 -ProgressText $msg
            return [PSCustomObject]@{
                Success = $false
                Results = @()
                Error   = $msg
            }
        }

        # -------------------------
        # Pre-flight connectivity
        # -------------------------
        Write-Log -Message 'Performing pre-flight connectivity checks...' -Color 'Info' -LogBox $LogBox -Theme $null
        Invoke-StatusBar -Callback $StatusBarCallback -Status 'Validating server connectivity...' -Progress 15 -ProgressText 'Pinging DHCP servers...'

        $OnlineServers = @()
        $totalServers  = $DHCPServers.Count
        $i             = 0

        foreach ($server in $DHCPServers) {
            if ($StopToken -and $StopToken.Value) { break }

            $i++
            $pct = 15 + [int](($i / [double]$totalServers) * 10)  # 15–25%

            $pingMsg = "Pinging $server..."
            Write-Log -Message $pingMsg -Color 'Info' -LogBox $LogBox -Theme $null
            Invoke-StatusBar -Callback $StatusBarCallback -Status $pingMsg -Progress $pct -ProgressText $pingMsg

            if (Test-Connection -ComputerName $server -Count 1 -Quiet) {
                $OnlineServers += $server
            } else {
                Write-Log -Message "Server $server is offline or not responding to ping. Skipping." -Color 'Error' -LogBox $LogBox -Theme $null
            }
        }

        if ($OnlineServers.Count -eq 0) {
            $msg = 'No DHCP servers are online. Aborting.'
            Write-Log -Message $msg -Color 'Error' -LogBox $LogBox -Theme $null
            Invoke-StatusBar -Callback $StatusBarCallback -Status $msg -Progress 0 -ProgressText $msg
            return [PSCustomObject]@{
                Success = $false
                Results = @()
                Error   = 'No DHCP servers are online.'
            }
        }

        $DHCPServers = $OnlineServers

        # -------------------------
        # Per-server script block
        # -------------------------
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

                Write-Log -Message "[$ServerName] Querying scopes..." -Color 'Info' -LogBox $LogBox -Theme $null
                $scopeStart = Get-Date
                $Scopes = Get-DhcpServerv4Scope -ComputerName $ServerName -ErrorAction Stop
                $scopeDuration = ((Get-Date) - $scopeStart).TotalSeconds
                Write-Log -Message "[$ServerName] Retrieved $(@($Scopes).Count) scope(s) in $([math]::Round($scopeDuration, 2))s" -Color 'Info' -LogBox $LogBox -Theme $null

                if (-not $Scopes) {
                    $ResultObject.Message = 'No scopes found on server. Check permissions or DHCP service status.'
                    return $ResultObject
                }

                # Log all scope names and descriptions for debugging
                Write-Log -Message "[$ServerName] Scope details:" -Color 'Info' -LogBox $LogBox -Theme $null
                foreach ($s in $Scopes) {
                    $descText = if ($s.Description) { $s.Description } else { "(empty)" }
                    Write-Log -Message "  - ScopeId: $($s.ScopeId), Name: $($s.Name), Description: $descText" -Color 'Info' -LogBox $LogBox -Theme $null
                }

                # Scope description filtering
                if ($ScopeFilters -and $ScopeFilters.Count -gt 0) {
                    Write-Log -Message "[$ServerName] Applying filters to scope descriptions: $($ScopeFilters -join ', ')" -Color 'Info' -LogBox $LogBox -Theme $null
                    $FilteredScopes = @()
                    foreach ($Filter in $ScopeFilters) {
                        if ([string]::IsNullOrWhiteSpace($Filter)) { continue }
                        $FilterUpper = $Filter.ToUpper()
                        Write-Log -Message "[$ServerName] Looking for descriptions containing: '$FilterUpper'" -Color 'Info' -LogBox $LogBox -Theme $null

                        # Match against Description (case-insensitive partial match)
                        $MatchingScopes = $Scopes | Where-Object {
                            $desc = if ($_.Description) { $_.Description.ToUpper() } else { "" }
                            $match = $desc -like "*$FilterUpper*"
                            if ($match) {
                                Write-Log -Message "    MATCH: '$desc' contains '$FilterUpper'" -Color 'Success' -LogBox $LogBox -Theme $null
                            }
                            $match
                        }

                        if ($MatchingScopes) {
                            Write-Log -Message "[$ServerName] Filter '$Filter' matched $(@($MatchingScopes).Count) scope(s)" -Color 'Success' -LogBox $LogBox -Theme $null
                        } else {
                            Write-Log -Message "[$ServerName] Filter '$Filter' matched 0 scopes - none of the descriptions contain '$FilterUpper'" -Color 'Warning' -LogBox $LogBox -Theme $null
                        }
                        $FilteredScopes += $MatchingScopes
                    }

                    $Scopes = $FilteredScopes | Select-Object -Unique
                    if (-not $Scopes -or $Scopes.Count -eq 0) {
                        $ResultObject.Message = 'No scopes matched the provided filter(s).'
                        Write-Log -Message "[$ServerName] No scopes matched filters" -Color 'Warning' -LogBox $LogBox -Theme $null
                        return $ResultObject
                    }
                    Write-Log -Message "[$ServerName] After filtering: $(@($Scopes).Count) scope(s) remaining" -Color 'Info' -LogBox $LogBox -Theme $null
                }

                # Retrieve all statistics at once (more reliable than per-scope queries)
                Write-Log -Message "[$ServerName] Querying scope statistics..." -Color 'Info' -LogBox $LogBox -Theme $null
                $statsStart = Get-Date
                $AllStatsRaw = Get-DhcpServerv4ScopeStatistics -ComputerName $ServerName -ErrorAction Stop
                $statsDuration = ((Get-Date) - $statsStart).TotalSeconds
                Write-Log -Message "[$ServerName] Retrieved statistics for $(@($AllStatsRaw).Count) scope(s) in $([math]::Round($statsDuration, 2))s" -Color 'Info' -LogBox $LogBox -Theme $null

                # Optional DNS server option lookup (OptionId 6)
                $DNSServerMap = @{}
                if ($IncludeDNS) {
                    Write-Log -Message "[$ServerName] Retrieving DNS server options for $(@($Scopes).Count) scope(s)..." -Color 'Info' -LogBox $LogBox -Theme $null
                    $dnsStart = Get-Date
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
                    $dnsDuration = ((Get-Date) - $dnsStart).TotalSeconds
                    Write-Log -Message "[$ServerName] DNS lookup completed in $([math]::Round($dnsDuration, 2))s" -Color 'Info' -LogBox $LogBox -Theme $null
                }

                # Process each scope and match with statistics
                Write-Log -Message "[$ServerName] Matching $(@($Scopes).Count) scope(s) with statistics..." -Color 'Info' -LogBox $LogBox -Theme $null
                $ServerStats = foreach ($Scope in $Scopes) {
                    # Find corresponding statistics using Where-Object
                    $Stats = $AllStatsRaw | Where-Object { $_.ScopeId -eq $Scope.ScopeId }

                    if ($Stats) {
                        # Capture all values as local variables BEFORE Select-Object
                        # This avoids closure issues with the $Scope loop variable
                        $currentServer = $ServerName
                        $currentDescription = if (-not [string]::IsNullOrWhiteSpace($Scope.Description)) {
                            $Scope.Description
                        } else {
                            $Scope.Name
                        }
                        $currentDNSServers = $DNSServerMap[$Scope.ScopeId]

                        # Now use the local variables in Expression blocks
                        $Stats | Select-Object *,
                            @{ Name = 'DHCPServer'; Expression = { $currentServer } },
                            @{ Name = 'Description'; Expression = { $currentDescription } },
                            @{ Name = 'DNSServers'; Expression = { $currentDNSServers } }
                    } else {
                        Write-Log -Message "[$ServerName] WARNING: No statistics found for scope $($Scope.ScopeId) ($($Scope.Name))" -Color 'Warning' -LogBox $LogBox -Theme $null
                    }
                }

                # Filter out any nulls
                $ServerStats = @($ServerStats | Where-Object { $_ -ne $null })
                Write-Log -Message "[$ServerName] Successfully matched $($ServerStats.Count) scope(s) with statistics" -Color 'Success' -LogBox $LogBox -Theme $null

                $ResultObject.Success = $true
                $ResultObject.Message = "Successfully retrieved $($ServerStats.Count) scope(s)."
                $ResultObject.Scopes  = $ServerStats
                return $ResultObject
            } catch {
                $ResultObject.Message = "ERROR: $($_.Exception.Message)"
                return $ResultObject
            }
        }

        # -------------------------
        # Parallel processing
        # -------------------------
        Write-Host "[DHCP-DEBUG] Starting parallel processing of $($DHCPServers.Count) servers" -ForegroundColor Cyan
        $startMsg = "Starting parallel processing of $($DHCPServers.Count) DHCP servers (Throttle: $ThrottleLimit)..."
        Write-Log -Message $startMsg -Color 'Info' -LogBox $LogBox -Theme $null
        Invoke-StatusBar -Callback $StatusBarCallback -Status $startMsg -Progress 25 -ProgressText $startMsg

        $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
        $RunspacePool.Open()
        Write-Host "[DHCP-DEBUG] Runspace pool created and opened" -ForegroundColor Cyan

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

                    $pct = 25 + [int](($CompletedCount / [double]$TotalServers) * 75)  # 25–100%

                    if ($ServerResult.Success) {
                        $msg = "[$CompletedCount/$TotalServers] Completed: $($Runspace.ServerName) - $($ServerResult.Message)"
                        Write-Log -Message $msg -Color 'Success' -LogBox $LogBox -Theme $null
                        Invoke-StatusBar -Callback $StatusBarCallback -Status $msg -Progress $pct -ProgressText $msg

                        if ($ServerResult.Scopes) {
                            [void]$AllStats.AddRange($ServerResult.Scopes)
                        }
                    }
                    else {
                        $msg = "[$CompletedCount/$TotalServers] Failed: $($Runspace.ServerName) - $($ServerResult.Message)"
                        Write-Log -Message $msg -Color 'Error' -LogBox $LogBox -Theme $null
                        Invoke-StatusBar -Callback $StatusBarCallback -Status $msg -Progress $pct -ProgressText $msg
                    }

                    $Runspace.PowerShell.Dispose()
                    $Runspace.PowerShell = $null
                }
            }

            if ($StopToken -and $StopToken.Value) {
                $msg = "Operation cancelled by user. Collected $($AllStats.Count) scopes before cancellation."
                Write-Log -Message $msg -Color 'Warning' -LogBox $LogBox -Theme $null
                Invoke-StatusBar -Callback $StatusBarCallback -Status $msg -Progress 0 -ProgressText $msg
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
        Write-Host "[DHCP-DEBUG] Collection complete - AllStats.Count = $($AllStats.Count)" -ForegroundColor Cyan
        Write-Log -Message $completeMsg -Color 'Success' -LogBox $LogBox -Theme $null
        Invoke-StatusBar -Callback $StatusBarCallback -Status $completeMsg -Progress 100 -ProgressText $completeMsg

        Write-Host "[DHCP-DEBUG] Returning result object" -ForegroundColor Cyan
        return [PSCustomObject]@{
            Success = $true
            Results = $AllStats
            Error   = $null
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        $fatalMsg     = "FATAL ERROR in Get-DHCPScopeStatistics: $errorMessage"
        Write-Log -Message $fatalMsg -Color 'Error' -LogBox $LogBox -Theme $null
        Invoke-StatusBar -Callback $StatusBarCallback -Status $fatalMsg -Progress 0 -ProgressText $fatalMsg

        return [PSCustomObject]@{
            Success = $false
            Results = @()
            Error   = $errorMessage
        }
    }
}

Export-ModuleMember -Function @(
    'Get-DHCPScopeStatistics',
    'Test-ServerName',
    'Get-SanitizedErrorMessage',
    'Invoke-StatusBar'
)
