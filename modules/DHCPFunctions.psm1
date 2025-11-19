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

    # Create debug log array to capture execution flow
    $script:DHCPDebugLog = @()

    try {
        $script:DHCPDebugLog += "[DHCP] Get-DHCPScopeStatistics called"
        $script:DHCPDebugLog += "[DHCP] ScopeFilters: $($ScopeFilters.Count) items - $($ScopeFilters -join ', ')"
        $script:DHCPDebugLog += "[DHCP] SpecificServers: $($SpecificServers.Count) items - $($SpecificServers -join ', ')"
        $script:DHCPDebugLog += "[DHCP] IncludeDNS: $IncludeDNS"

        # -------------------------
        # Determine DHCP servers
        # -------------------------
        if ($SpecificServers -and $SpecificServers.Count -gt 0) {
            $script:DHCPDebugLog += "[DHCP] Using specific servers"
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
                $script:DHCPDebugLog += "[DHCP] ERROR: No valid servers"
                Write-Log -Message $msg -Color 'Error' -LogBox $LogBox -Theme $null
                Invoke-StatusBar -Callback $StatusBarCallback -Status $msg -Progress 0 -ProgressText $msg
                return [PSCustomObject]@{
                    Success = $false
                    Results = @()
                    Error   = $msg
                    DebugLog = $script:DHCPDebugLog
                }
            }

            $DHCPServers = $validServers
            $script:DHCPDebugLog += "[DHCP] Valid servers: $($DHCPServers.Count) - $($DHCPServers -join ', ')"
        }
        else {
            $script:DHCPDebugLog += "[DHCP] No specific servers - auto-discovering from AD"
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

            # Debug log for this scriptblock execution
            $scriptDebug = @()

            $ResultObject = [PSCustomObject]@{
                ServerName = $ServerName
                Success    = $false
                Message    = ''
                Scopes     = @()
                ScriptDebug = $scriptDebug
            }

            try {
                $scriptDebug += "[SB-$ServerName] Scriptblock started"
                $scriptDebug += "[SB-$ServerName] ScopeFilters: $($ScopeFilters -join ', ')"
                $scriptDebug += "[SB-$ServerName] IncludeDNS: $IncludeDNS"

                Import-Module DhcpServer -ErrorAction Stop
                $scriptDebug += "[SB-$ServerName] DhcpServer module imported"

                $scriptDebug += "[SB-$ServerName] Querying scopes from $ServerName..."
                $scopeStart = Get-Date
                $Scopes = Get-DhcpServerv4Scope -ComputerName $ServerName -ErrorAction Stop
                $scopeDuration = ((Get-Date) - $scopeStart).TotalSeconds
                $scriptDebug += "[SB-$ServerName] Retrieved $(@($Scopes).Count) scope(s) in $([math]::Round($scopeDuration, 2))s"

                if (-not $Scopes) {
                    $scriptDebug += "[SB-$ServerName] No scopes found on server"
                    $ResultObject.Message = 'No scopes found on server. Check permissions or DHCP service status.'
                    $ResultObject.ScriptDebug = $scriptDebug
                    return $ResultObject
                }

                # Log all scope names and descriptions for debugging
                $scriptDebug += "[SB-$ServerName] Scope details:"
                foreach ($s in $Scopes) {
                    $descText = if ($s.Description) { $s.Description } else { "(empty)" }
                    $scriptDebug += "[SB-$ServerName]   - ScopeId: $($s.ScopeId), Name: $($s.Name), Description: $descText"
                }

                # Scope description filtering
                if ($ScopeFilters -and $ScopeFilters.Count -gt 0) {
                    $scriptDebug += "[SB-$ServerName] Applying filters to scope descriptions: $($ScopeFilters -join ', ')"
                    $FilteredScopes = @()
                    foreach ($Filter in $ScopeFilters) {
                        if ([string]::IsNullOrWhiteSpace($Filter)) { continue }
                        $FilterUpper = $Filter.ToUpper()
                        $scriptDebug += "[SB-$ServerName] Looking for descriptions containing: '$FilterUpper'"

                        # Match against Description (case-insensitive partial match)
                        $MatchingScopes = $Scopes | Where-Object {
                            $desc = if ($_.Description) { $_.Description.ToUpper() } else { "" }
                            $match = $desc -like "*$FilterUpper*"
                            if ($match) {
                                $scriptDebug += "[SB-$ServerName]    MATCH: '$desc' contains '$FilterUpper'"
                            }
                            $match
                        }

                        if ($MatchingScopes) {
                            $scriptDebug += "[SB-$ServerName] Filter '$Filter' matched $(@($MatchingScopes).Count) scope(s)"
                        } else {
                            $scriptDebug += "[SB-$ServerName] Filter '$Filter' matched 0 scopes - none of the descriptions contain '$FilterUpper'"
                        }
                        $FilteredScopes += $MatchingScopes
                    }

                    $Scopes = $FilteredScopes | Select-Object -Unique
                    if (-not $Scopes -or $Scopes.Count -eq 0) {
                        $scriptDebug += "[SB-$ServerName] No scopes matched filters"
                        $ResultObject.Message = 'No scopes matched the provided filter(s).'
                        $ResultObject.ScriptDebug = $scriptDebug
                        return $ResultObject
                    }
                    $scriptDebug += "[SB-$ServerName] After filtering: $(@($Scopes).Count) scope(s) remaining"
                }

                # Retrieve all statistics at once (more reliable than per-scope queries)
                $scriptDebug += "[SB-$ServerName] Querying scope statistics..."
                $statsStart = Get-Date
                $AllStatsRaw = Get-DhcpServerv4ScopeStatistics -ComputerName $ServerName -ErrorAction Stop
                $statsDuration = ((Get-Date) - $statsStart).TotalSeconds
                $scriptDebug += "[SB-$ServerName] Retrieved statistics for $(@($AllStatsRaw).Count) scope(s) in $([math]::Round($statsDuration, 2))s"

                # Optional DNS server option lookup (OptionId 6)
                $DNSServerMap = @{}
                if ($IncludeDNS) {
                    $scriptDebug += "[SB-$ServerName] Retrieving DNS server options for $(@($Scopes).Count) scope(s)..."
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
                    $scriptDebug += "[SB-$ServerName] DNS lookup completed in $([math]::Round($dnsDuration, 2))s"
                }

                # Process each scope and match with statistics
                $scriptDebug += "[SB-$ServerName] Matching $(@($Scopes).Count) scope(s) with statistics..."
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
                        $scriptDebug += "[SB-$ServerName] WARNING: No statistics found for scope $($Scope.ScopeId) ($($Scope.Name))"
                    }
                }

                # Filter out any nulls
                $ServerStats = @($ServerStats | Where-Object { $_ -ne $null })
                $scriptDebug += "[SB-$ServerName] Successfully matched $($ServerStats.Count) scope(s) with statistics"

                $scriptDebug += "[SB-$ServerName] Collection complete - returning $($ServerStats.Count) scopes"
                $ResultObject.Success = $true
                $ResultObject.Message = "Successfully retrieved $($ServerStats.Count) scope(s)."
                $ResultObject.Scopes  = $ServerStats
                $ResultObject.ScriptDebug = $scriptDebug
                return $ResultObject
            } catch {
                $scriptDebug += "[SB-$ServerName] EXCEPTION: $($_.Exception.Message)"
                $scriptDebug += "[SB-$ServerName] Stack: $($_.ScriptStackTrace)"
                $ResultObject.Message = "ERROR: $($_.Exception.Message)"
                $ResultObject.ScriptDebug = $scriptDebug
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

                    # Display script debug logs from the runspace
                    if ($ServerResult.ScriptDebug) {
                        foreach ($debugLine in $ServerResult.ScriptDebug) {
                            Write-Host $debugLine -ForegroundColor Cyan
                            $script:DHCPDebugLog += $debugLine
                        }
                    }

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
