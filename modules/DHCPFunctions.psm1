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

    .PARAMETER SelectedScopes
        Array of pre-selected scope objects (with ScopeId and Server properties).
        If provided, only these specific scopes will be queried (takes precedence over filters).
        Format: @( @{ScopeId='10.0.1.0'; Server='dhcp1.domain.com'}, ... )

    .PARAMETER ScopeFilters
        Array of scope name filters to apply. Case-insensitive partial matching.
        If empty, all scopes are returned. Ignored if SelectedScopes is provided.

    .PARAMETER SpecificServers
        Array of specific DHCP server names to query. If empty, auto-discovers
        servers from the domain with Get-DhcpServerInDC.

    .PARAMETER IncludeDNS
        Boolean flag to include DNS server information (Option ID 6) for each scope.

    .PARAMETER IncludeOption60
        Boolean flag to include Vendor Class information (Option ID 60) for each scope.

    .PARAMETER IncludeOption43
        Boolean flag to include Vendor-Specific information (Option ID 43) for each scope.

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
        [object[]]$SelectedScopes = @(),

        [Parameter(Mandatory = $false)]
        [string[]]$ScopeFilters = @(),

        [Parameter(Mandatory = $false)]
        [string[]]$SpecificServers = @(),

        [Parameter(Mandatory = $false)]
        [bool]$IncludeDNS = $false,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeOption60 = $false,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeOption43 = $false,

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
        $script:DHCPDebugLog += "[DHCP] SelectedScopes: $($SelectedScopes.Count) items"
        $script:DHCPDebugLog += "[DHCP] ScopeFilters: $($ScopeFilters.Count) items - $($ScopeFilters -join ', ')"
        $script:DHCPDebugLog += "[DHCP] SpecificServers: $($SpecificServers.Count) items - $($SpecificServers -join ', ')"
        $script:DHCPDebugLog += "[DHCP] IncludeDNS: $IncludeDNS"

        # -------------------------
        # Handle pre-selected scopes (takes precedence)
        # -------------------------
        if ($SelectedScopes -and $SelectedScopes.Count -gt 0) {
            $script:DHCPDebugLog += "[DHCP] Using pre-selected scopes (bypassing filters)"
            Write-Log -Message "Querying $($SelectedScopes.Count) pre-selected scope(s)..." -Color 'Info' -LogBox $LogBox -Theme $null
            Invoke-StatusBar -Callback $StatusBarCallback -Status "Processing $($SelectedScopes.Count) selected scopes..." -Progress 10 -ProgressText 'Grouping scopes by server...'

            # Extract unique server names and group scopes by server
            $serverList = @()
            $scopesByServer = @{}

            foreach ($scope in $SelectedScopes) {
                # Skip scopes with null/empty server names
                if ($null -eq $scope -or [string]::IsNullOrWhiteSpace($scope.Server)) {
                    $script:DHCPDebugLog += "[DHCP] WARNING: Skipping scope with null/empty server property"
                    continue
                }

                # Explicitly convert to string and trim to ensure proper format
                $server = ([string]$scope.Server).Trim()
                if ([string]::IsNullOrWhiteSpace($server)) {
                    $script:DHCPDebugLog += "[DHCP] WARNING: Server name is whitespace after conversion"
                    continue
                }

                # Add to unique server list (using -notcontains for reliable array check)
                if ($serverList -notcontains $server) {
                    $serverList += $server
                    $script:DHCPDebugLog += "[DHCP] Added unique server: '$server'"
                }

                # Also maintain hashtable grouping for later scope ID extraction
                if (-not $scopesByServer.ContainsKey($server)) {
                    $scopesByServer[$server] = @()
                }
                $scopesByServer[$server] += $scope
            }

            $script:DHCPDebugLog += "[DHCP] Extracted $($serverList.Count) unique server(s)"

            # Use the extracted server list instead of hashtable keys
            $SpecificServers = $serverList
            # Clear filters since we have specific scopes
            $ScopeFilters = @()

            $script:DHCPDebugLog += "[DHCP] Will query servers: $($SpecificServers -join ', ')"
        }

        # -------------------------
        # Determine DHCP servers
        # -------------------------
        if ($SpecificServers -and $SpecificServers.Count -gt 0) {
            $script:DHCPDebugLog += "[DHCP] Using specific servers"
            Invoke-StatusBar -Callback $StatusBarCallback -Status 'Using specified DHCP servers...' -Progress 5 -ProgressText 'Validating server names...'
            Write-Log -Message 'Using specified DHCP servers...' -Color 'Info' -LogBox $LogBox -Theme $null

            $validServers = @()
            foreach ($server in $SpecificServers) {
                $script:DHCPDebugLog += "[DHCP] Validating server: '$server' (type: $($server.GetType().FullName))"

                # Skip null entries
                if ($null -eq $server) {
                    $script:DHCPDebugLog += "[DHCP] Skipped: server is null"
                    continue
                }

                # Ensure it's a string
                $serverStr = [string]$server
                $trimmedServer = $serverStr.Trim()

                if ([string]::IsNullOrWhiteSpace($trimmedServer)) {
                    $script:DHCPDebugLog += "[DHCP] Skipped: server is whitespace after trim"
                    continue
                }

                $script:DHCPDebugLog += "[DHCP] Testing server name: '$trimmedServer'"
                if (Test-ServerName -ServerName $trimmedServer) {
                    $validServers += $trimmedServer
                    $script:DHCPDebugLog += "[DHCP] Server '$trimmedServer' passed validation"
                } else {
                    $script:DHCPDebugLog += "[DHCP] Server '$trimmedServer' FAILED validation"
                    Write-Log -Message "Invalid DHCP server name skipped: $trimmedServer" -Color 'Warning' -LogBox $LogBox -Theme $null
                }
            }

            if ($validServers.Count -eq 0) {
                $msg = 'No valid DHCP server names provided.'
                $script:DHCPDebugLog += "[DHCP] ERROR: No valid servers after validation"
                $script:DHCPDebugLog += "[DHCP] Original SpecificServers count: $($SpecificServers.Count)"
                $script:DHCPDebugLog += "[DHCP] SpecificServers: $($SpecificServers -join ', ')"

                Write-Log -Message $msg -Color 'Error' -LogBox $LogBox -Theme $null

                # Output debug log to help diagnose the issue
                if ($script:DHCPDebugLog -and $script:DHCPDebugLog.Count -gt 0) {
                    Write-Log -Message "=== Debug Information ===" -Color 'Warning' -LogBox $LogBox -Theme $null
                    foreach ($logEntry in $script:DHCPDebugLog) {
                        Write-Log -Message $logEntry -Color 'Debug' -LogBox $LogBox -Theme $null
                    }
                    Write-Log -Message "=== End Debug ===" -Color 'Warning' -LogBox $LogBox -Theme $null
                }

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
                [bool]$IncludeDNS,
                [string[]]$SelectedScopeIds = @(),
                [bool]$IncludeOption60 = $false,
                [bool]$IncludeOption43 = $false
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
                $scriptDebug += "[SB-$ServerName] SelectedScopeIds: $($SelectedScopeIds.Count) items - $($SelectedScopeIds -join ', ')"
                $scriptDebug += "[SB-$ServerName] ScopeFilters: $($ScopeFilters -join ', ')"
                $scriptDebug += "[SB-$ServerName] IncludeDNS: $IncludeDNS"

                Import-Module DhcpServer -ErrorAction Stop
                $scriptDebug += "[SB-$ServerName] DhcpServer module imported"

                # If specific scope IDs provided, use them directly
                if ($SelectedScopeIds -and $SelectedScopeIds.Count -gt 0) {
                    $scriptDebug += "[SB-$ServerName] Using $($SelectedScopeIds.Count) pre-selected scope ID(s)"

                    # Get scope metadata for the selected IDs
                    $Scopes = @()
                    foreach ($scopeId in $SelectedScopeIds) {
                        try {
                            $scope = Get-DhcpServerv4Scope -ComputerName $ServerName -ScopeId $scopeId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                            if ($scope) {
                                $Scopes += $scope
                            } else {
                                $scriptDebug += "[SB-$ServerName] WARNING: ScopeId $scopeId not found on server"
                            }
                        } catch {
                            $scriptDebug += "[SB-$ServerName] ERROR querying scope $scopeId : $($_.Exception.Message)"
                        }
                    }
                    $scriptDebug += "[SB-$ServerName] Retrieved $(@($Scopes).Count) scope(s) from selected IDs"
                } else {
                    # Original logic: Get all scopes then filter
                    $scriptDebug += "[SB-$ServerName] Querying all scopes from $ServerName..."
                    $scopeStart = Get-Date
                    $Scopes = Get-DhcpServerv4Scope -ComputerName $ServerName -ErrorAction Stop -WarningAction SilentlyContinue
                    $scopeDuration = ((Get-Date) - $scopeStart).TotalSeconds
                    $scriptDebug += "[SB-$ServerName] Retrieved $(@($Scopes).Count) scope(s) in $([math]::Round($scopeDuration, 2))s"
                }

                if (-not $Scopes -or $Scopes.Count -eq 0) {
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

                # Scope name filtering (only if not using pre-selected scopes)
                if ((-not $SelectedScopeIds -or $SelectedScopeIds.Count -eq 0) -and ($ScopeFilters -and $ScopeFilters.Count -gt 0)) {
                    $scriptDebug += "[SB-$ServerName] Applying filters to scope names: $($ScopeFilters -join ', ')"
                    $FilteredScopes = @()
                    foreach ($Filter in $ScopeFilters) {
                        if ([string]::IsNullOrWhiteSpace($Filter)) { continue }
                        $FilterUpper = $Filter.ToUpper()
                        $scriptDebug += "[SB-$ServerName] Looking for names containing: '$FilterUpper'"

                        # Match against Name (case-insensitive partial match)
                        $MatchingScopes = $Scopes | Where-Object {
                            $name = if ($_.Name) { $_.Name.ToUpper() } else { "" }
                            $name -like "*$FilterUpper*"
                        }

                        $matchCount = @($MatchingScopes).Count
                        if ($matchCount -gt 0) {
                            $scriptDebug += "[SB-$ServerName] Filter '$Filter' matched $matchCount scope(s)"
                            foreach ($ms in $MatchingScopes) {
                                $scriptDebug += "[SB-$ServerName]    - MATCH: ScopeId=$($ms.ScopeId), Name='$($ms.Name)'"
                            }
                        } else {
                            $scriptDebug += "[SB-$ServerName] Filter '$Filter' matched 0 scopes"
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

                # Always use bulk query for statistics (fastest - 1 network call)
                $scriptDebug += "[SB-$ServerName] Bulk querying statistics for all scopes on server..."
                $statsStart = Get-Date

                $AllStatsRaw = Get-DhcpServerv4ScopeStatistics -ComputerName $ServerName -ErrorAction Stop
                $statsDuration = ((Get-Date) - $statsStart).TotalSeconds
                $scriptDebug += "[SB-$ServerName] Bulk query retrieved statistics for $(@($AllStatsRaw).Count) scope(s) in $([math]::Round($statsDuration, 2))s"

                # Optional: Build DNS server map if requested (parallel processing)
                $DNSServerMap = @{}
                if ($IncludeDNS) {
                    $scriptDebug += "[SB-$ServerName] Retrieving DNS options for $(@($Scopes).Count) scope(s) in parallel..."
                    $dnsStart = Get-Date

                    # Use runspace pool for parallel scope processing
                    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
                    $RunspacePool.Open()
                    $Jobs = @()

                    foreach ($Scope in $Scopes) {
                        $PowerShell = [powershell]::Create()
                        $PowerShell.RunspacePool = $RunspacePool
                        [void]$PowerShell.AddScript({
                            param($ServerName, $ScopeId)
                            try {
                                $DNSOption = Get-DhcpServerv4OptionValue -ComputerName $ServerName -ScopeId $ScopeId -OptionId 6 -ErrorAction SilentlyContinue
                                return [PSCustomObject]@{
                                    ScopeId = $ScopeId
                                    Value = if ($DNSOption) { $DNSOption.Value -join ',' } else { $null }
                                    Success = $true
                                }
                            } catch {
                                return [PSCustomObject]@{
                                    ScopeId = $ScopeId
                                    Value = $null
                                    Success = $false
                                    Error = $_.Exception.Message
                                }
                            }
                        }).AddArgument($ServerName).AddArgument($Scope.ScopeId)

                        $Jobs += [PSCustomObject]@{
                            PowerShell = $PowerShell
                            Handle = $PowerShell.BeginInvoke()
                            ScopeId = $Scope.ScopeId
                        }
                    }

                    # Collect results
                    foreach ($Job in $Jobs) {
                        $resultArray = $Job.PowerShell.EndInvoke($Job.Handle)
                        if ($resultArray -and $resultArray.Count -gt 0) {
                            $result = $resultArray[0]
                            if ($result.Value) {
                                $DNSServerMap[$result.ScopeId] = $result.Value
                            }
                        }
                        $Job.PowerShell.Dispose()
                    }

                    $RunspacePool.Close()
                    $RunspacePool.Dispose()

                    $dnsDuration = ((Get-Date) - $dnsStart).TotalSeconds
                    $scriptDebug += "[SB-$ServerName] DNS lookup completed in $([math]::Round($dnsDuration, 2))s (parallel)"
                }

                # Optional: Build Option 60 map if requested
                $Option60Map = @{}
                if ($IncludeOption60) {
                    $scriptDebug += "[SB-$ServerName] Retrieving Option 60 for $(@($Scopes).Count) scope(s) in parallel..."
                    $opt60Start = Get-Date

                    # Use runspace pool for parallel scope processing
                    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
                    $RunspacePool.Open()
                    $Jobs = @()

                    foreach ($Scope in $Scopes) {
                        $PowerShell = [powershell]::Create()
                        $PowerShell.RunspacePool = $RunspacePool
                        [void]$PowerShell.AddScript({
                            param($ServerName, $ScopeId)
                            try {
                                $Option60 = Get-DhcpServerv4OptionValue -ComputerName $ServerName -ScopeId $ScopeId -OptionId 60 -ErrorAction SilentlyContinue
                                return [PSCustomObject]@{
                                    ScopeId = $ScopeId
                                    Value = if ($Option60) { $Option60.Value -join ',' } else { $null }
                                    Success = $true
                                }
                            } catch {
                                return [PSCustomObject]@{
                                    ScopeId = $ScopeId
                                    Value = $null
                                    Success = $false
                                }
                            }
                        }).AddArgument($ServerName).AddArgument($Scope.ScopeId)

                        $Jobs += [PSCustomObject]@{
                            PowerShell = $PowerShell
                            Handle = $PowerShell.BeginInvoke()
                            ScopeId = $Scope.ScopeId
                        }
                    }

                    # Collect results
                    foreach ($Job in $Jobs) {
                        $resultArray = $Job.PowerShell.EndInvoke($Job.Handle)
                        if ($resultArray -and $resultArray.Count -gt 0) {
                            $result = $resultArray[0]
                            if ($result.Value) {
                                $Option60Map[$result.ScopeId] = $result.Value
                            }
                        }
                        $Job.PowerShell.Dispose()
                    }

                    $RunspacePool.Close()
                    $RunspacePool.Dispose()

                    $opt60Duration = ((Get-Date) - $opt60Start).TotalSeconds
                    $scriptDebug += "[SB-$ServerName] Option 60 lookup completed in $([math]::Round($opt60Duration, 2))s - collected $($Option60Map.Count) values"
                }

                # Optional: Build Option 43 map if requested
                $Option43Map = @{}
                if ($IncludeOption43) {
                    $scriptDebug += "[SB-$ServerName] Retrieving Option 43 for $(@($Scopes).Count) scope(s) in parallel..."
                    $opt43Start = Get-Date

                    # Use runspace pool for parallel scope processing
                    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, 10)
                    $RunspacePool.Open()
                    $Jobs = @()

                    foreach ($Scope in $Scopes) {
                        $PowerShell = [powershell]::Create()
                        $PowerShell.RunspacePool = $RunspacePool
                        [void]$PowerShell.AddScript({
                            param($ServerName, $ScopeId)
                            try {
                                $Option43 = Get-DhcpServerv4OptionValue -ComputerName $ServerName -ScopeId $ScopeId -OptionId 43 -ErrorAction SilentlyContinue
                                return [PSCustomObject]@{
                                    ScopeId = $ScopeId
                                    Value = if ($Option43) { $Option43.Value -join ',' } else { $null }
                                    Success = $true
                                }
                            } catch {
                                return [PSCustomObject]@{
                                    ScopeId = $ScopeId
                                    Value = $null
                                    Success = $false
                                }
                            }
                        }).AddArgument($ServerName).AddArgument($Scope.ScopeId)

                        $Jobs += [PSCustomObject]@{
                            PowerShell = $PowerShell
                            Handle = $PowerShell.BeginInvoke()
                            ScopeId = $Scope.ScopeId
                        }
                    }

                    # Collect results
                    foreach ($Job in $Jobs) {
                        $resultArray = $Job.PowerShell.EndInvoke($Job.Handle)
                        if ($resultArray -and $resultArray.Count -gt 0) {
                            $result = $resultArray[0]
                            if ($result.Value) {
                                $Option43Map[$result.ScopeId] = $result.Value
                            }
                        }
                        $Job.PowerShell.Dispose()
                    }

                    $RunspacePool.Close()
                    $RunspacePool.Dispose()

                    $opt43Duration = ((Get-Date) - $opt43Start).TotalSeconds
                    $scriptDebug += "[SB-$ServerName] Option 43 lookup completed in $([math]::Round($opt43Duration, 2))s - collected $($Option43Map.Count) values"
                }

                # Match filtered scopes with their statistics
                $scriptDebug += "[SB-$ServerName] Matching $(@($Scopes).Count) scope(s) with statistics..."
                $ServerStats = @()
                foreach ($Scope in $Scopes) {
                    $Stats = $AllStatsRaw | Where-Object { $_.ScopeId -eq $Scope.ScopeId }

                    if ($Stats) {
                        # Build description field
                        $scopeDescription = if (-not [string]::IsNullOrWhiteSpace($Scope.Description)) {
                            $Scope.Description
                        } else {
                            $Scope.Name
                        }

                        $dnsServers = $DNSServerMap[$Scope.ScopeId]
                        $option60Info = $Option60Map[$Scope.ScopeId]
                        $option43Info = $Option43Map[$Scope.ScopeId]

                        # Calculate percentage if not provided or if null
                        $percentageValue = if ($null -ne $Stats.Percentage) {
                            $Stats.Percentage
                        } elseif ($Stats.Free -ne $null -and $Stats.InUse -ne $null) {
                            $total = $Stats.Free + $Stats.InUse
                            if ($total -gt 0) {
                                [math]::Round(($Stats.InUse / $total) * 100, 2)
                            } else {
                                0
                            }
                        } else {
                            0
                        }

                        # Create result object
                        $ServerStats += [PSCustomObject]@{
                            ScopeId = $Stats.ScopeId
                            DHCPServer = $ServerName
                            Description = $scopeDescription
                            SubnetMask = $Stats.SubnetMask
                            StartRange = $Stats.StartRange
                            EndRange = $Stats.EndRange
                            Free = $Stats.Free
                            InUse = $Stats.InUse
                            Percentage = $percentageValue
                            Reserved = $Stats.Reserved
                            Pending = $Stats.Pending
                            AddressesFree = $Stats.Free
                            AddressesInUse = $Stats.InUse
                            PercentageInUse = $percentageValue
                            DNSServers = $dnsServers
                            Option60 = $option60Info
                            Option43 = $option43Info
                        }
                    } else {
                        $scriptDebug += "[SB-$ServerName] WARNING: No statistics found for scope $($Scope.ScopeId)"
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
        # Parallel processing with constant worker pool
        # -------------------------
        $MaxConcurrentJobs = if ($DHCPServers.Count -lt $ThrottleLimit) { $DHCPServers.Count } else { $ThrottleLimit }

        Write-Host "[DHCP-DEBUG] Starting constant worker pool with $MaxConcurrentJobs workers" -ForegroundColor Cyan
        $startMsg = "Starting parallel processing of $($DHCPServers.Count) DHCP servers (maintaining $MaxConcurrentJobs concurrent jobs)..."
        Write-Log -Message $startMsg -Color 'Info' -LogBox $LogBox -Theme $null
        Invoke-StatusBar -Callback $StatusBarCallback -Status $startMsg -Progress 25 -ProgressText $startMsg

        $Jobs = @()
        $AllStats = New-Object System.Collections.ArrayList
        $TotalServers = $DHCPServers.Count
        $ServerIndex = 0

        # Start initial batch of jobs
        while ($ServerIndex -lt $TotalServers -and $Jobs.Count -lt $MaxConcurrentJobs) {
            if ($StopToken -and $StopToken.Value) { break }

            $Server = $DHCPServers[$ServerIndex]
            $filtersArg = if ($ScopeFilters) { ,@($ScopeFilters) } else { ,@() }

            # Get selected scope IDs for this server (if using pre-selected scopes)
            $selectedScopeIdsArg = if ($scopesByServer -and $scopesByServer.ContainsKey($Server)) {
                ,@($scopesByServer[$Server] | ForEach-Object { $_.ScopeId })
            } else {
                ,@()
            }

            $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Server, $filtersArg, $IncludeDNS, $selectedScopeIdsArg, $IncludeOption60, $IncludeOption43
            $Jobs += @{
                Job = $Job
                ServerName = $Server
                Processed = $false
            }
            $ServerIndex++
        }

        $CompletedCount = 0

        # Monitor and maintain constant pool
        while ($Jobs | Where-Object { -not $_.Processed }) {
            if ($StopToken -and $StopToken.Value) { break }
            Start-Sleep -Milliseconds 500

            # Check for completed jobs
            $CompletedInRound = $Jobs | Where-Object { $_.Job.State -eq 'Completed' -and -not $_.Processed }
            foreach ($CompletedJob in $CompletedInRound) {
                $CompletedCount++
                $CompletedJob.Processed = $true

                try {
                    $ServerResult = Receive-Job -Job $CompletedJob.Job -ErrorAction Stop

                    # Display script debug logs
                    if ($ServerResult.ScriptDebug) {
                        foreach ($debugLine in $ServerResult.ScriptDebug) {
                            Write-Host $debugLine -ForegroundColor Cyan
                            $script:DHCPDebugLog += $debugLine
                        }
                    }

                    $pct = 25 + [int](($CompletedCount / [double]$TotalServers) * 75)

                    if ($ServerResult.Success) {
                        $msg = "[$CompletedCount/$TotalServers] Completed: $($CompletedJob.ServerName) - $($ServerResult.Message)"
                        Write-Log -Message $msg -Color 'Success' -LogBox $LogBox -Theme $null
                        Invoke-StatusBar -Callback $StatusBarCallback -Status $msg -Progress $pct -ProgressText $msg

                        if ($ServerResult.Scopes) {
                            [void]$AllStats.AddRange($ServerResult.Scopes)
                        }
                    }
                    else {
                        $msg = "[$CompletedCount/$TotalServers] Failed: $($CompletedJob.ServerName) - $($ServerResult.Message)"
                        Write-Log -Message $msg -Color 'Error' -LogBox $LogBox -Theme $null
                        Invoke-StatusBar -Callback $StatusBarCallback -Status $msg -Progress $pct -ProgressText $msg
                    }
                } catch {
                    $CompletedCount++
                    $pct = 25 + [int](($CompletedCount / [double]$TotalServers) * 75)
                    $msg = "[$CompletedCount/$TotalServers] Failed: $($CompletedJob.ServerName) - Error receiving job results"
                    Write-Log -Message $msg -Color 'Error' -LogBox $LogBox -Theme $null
                    Invoke-StatusBar -Callback $StatusBarCallback -Status $msg -Progress $pct -ProgressText $msg
                }

                Remove-Job -Job $CompletedJob.Job -Force

                # Start next job to maintain pool
                if ($ServerIndex -lt $TotalServers) {
                    $Server = $DHCPServers[$ServerIndex]
                    $filtersArg = if ($ScopeFilters) { ,@($ScopeFilters) } else { ,@() }

                    # Get selected scope IDs for this server (if using pre-selected scopes)
                    $selectedScopeIdsArg = if ($scopesByServer -and $scopesByServer.ContainsKey($Server)) {
                        ,@($scopesByServer[$Server] | ForEach-Object { $_.ScopeId })
                    } else {
                        ,@()
                    }

                    $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Server, $filtersArg, $IncludeDNS, $selectedScopeIdsArg, $IncludeOption60, $IncludeOption43
                    $Jobs += @{
                        Job = $Job
                        ServerName = $Server
                        Processed = $false
                    }
                    $ServerIndex++
                }
            }

            # Check for failed jobs
            $FailedInRound = $Jobs | Where-Object { $_.Job.State -eq 'Failed' -and -not $_.Processed }
            foreach ($FailedJob in $FailedInRound) {
                $CompletedCount++
                $FailedJob.Processed = $true

                $pct = 25 + [int](($CompletedCount / [double]$TotalServers) * 75)
                $msg = "[$CompletedCount/$TotalServers] Failed: $($FailedJob.ServerName)"
                Write-Log -Message $msg -Color 'Error' -LogBox $LogBox -Theme $null
                Invoke-StatusBar -Callback $StatusBarCallback -Status $msg -Progress $pct -ProgressText $msg

                Remove-Job -Job $FailedJob.Job -Force

                # Start next job to maintain pool
                if ($ServerIndex -lt $TotalServers) {
                    $Server = $DHCPServers[$ServerIndex]
                    $filtersArg = if ($ScopeFilters) { ,@($ScopeFilters) } else { ,@() }

                    # Get selected scope IDs for this server (if using pre-selected scopes)
                    $selectedScopeIdsArg = if ($scopesByServer -and $scopesByServer.ContainsKey($Server)) {
                        ,@($scopesByServer[$Server] | ForEach-Object { $_.ScopeId })
                    } else {
                        ,@()
                    }

                    $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Server, $filtersArg, $IncludeDNS, $selectedScopeIdsArg, $IncludeOption60, $IncludeOption43
                    $Jobs += @{
                        Job = $Job
                        ServerName = $Server
                        Processed = $false
                    }
                    $ServerIndex++
                }
            }
        }

        # Clean up any remaining jobs if stopped
        if ($StopToken -and $StopToken.Value) {
            $Jobs | Where-Object { -not $_.Processed } | ForEach-Object {
                Stop-Job -Job $_.Job -ErrorAction SilentlyContinue
                Remove-Job -Job $_.Job -Force -ErrorAction SilentlyContinue
            }

            $msg = "Operation cancelled by user. Collected $($AllStats.Count) scopes before cancellation."
            Write-Log -Message $msg -Color 'Warning' -LogBox $LogBox -Theme $null
            Invoke-StatusBar -Callback $StatusBarCallback -Status $msg -Progress 0 -ProgressText $msg
            return [PSCustomObject]@{
                Success = $false
                Results = $AllStats
                Error   = 'Operation cancelled by user'
                DebugLog = $script:DHCPDebugLog
            }
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
