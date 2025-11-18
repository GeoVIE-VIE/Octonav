#Requires -Version 5.1
<#
.SYNOPSIS
    ULTRA-OPTIMIZED DHCP Scope Statistics Collection Script
.DESCRIPTION
    Collects DHCP scopes with optional filtering and maximum performance:
    - Uses Runspaces (5-10x faster than Start-Job)
    - PowerShell 7+ ForEach-Object -Parallel support (fastest option)
    - ArrayList for efficient data collection
    - Constant concurrency pool for optimal throughput
    - Optional scope/server filtering
    - Optional DNS server retrieval

.NOTES
    Version: 3.1 - Maximum Performance with Filtering
    Performance: 5-10x faster than Start-Job based approaches
    Compatible with: PowerShell 5.1+ (optimized for PS 7+)
#>

# ============================================
# CONFIGURATION
# ============================================

$MaxConcurrentJobs = 20
$CheckIntervalMs = 500  # Check job status every 500ms

# ============================================
# USER INPUT
# ============================================

Write-Host "=== OPTIMIZED DHCP Scope Statistics Collection ===" -ForegroundColor Cyan
Write-Host ""

# Ask if user wants to filter by scope names
$FilterChoice = Read-Host "Do you want to filter by scope/site names? (Y/N, default: N)"
$ScopeNameSearchStrings = @()
$SpecificServers = @()

if ($FilterChoice -eq 'Y' -or $FilterChoice -eq 'y') {
    $ScopeInput = Read-Host "Enter scope/site names to search for (comma separated)"
    if (-not [string]::IsNullOrWhiteSpace($ScopeInput)) {
        $ScopeNameSearchStrings = $ScopeInput.Split(',') | ForEach-Object { $_.Trim().ToUpper() }
        Write-Host "Will filter scopes containing: $($ScopeNameSearchStrings -join ', ')" -ForegroundColor Yellow

        # Ask if they want to specify specific DHCP servers
        $ServerInput = Read-Host "Enter specific DHCP server names to search (comma separated, or press Enter to search all servers)"
        if (-not [string]::IsNullOrWhiteSpace($ServerInput)) {
            $ServerList = $ServerInput.Split(',') | ForEach-Object { $_.Trim() }

            # Validate server names
            $ValidServers = @()
            $InvalidServers = @()
            foreach ($Server in $ServerList) {
                # Allow alphanumeric, dots, hyphens, and underscores for FQDNs
                if ($Server -match '^[a-zA-Z0-9][a-zA-Z0-9.-_]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$') {
                    $ValidServers += $Server
                } else {
                    $InvalidServers += $Server
                }
            }

            if ($InvalidServers.Count -gt 0) {
                Write-Host "Warning: Invalid server name(s) detected and will be skipped:" -ForegroundColor Red
                foreach ($InvalidServer in $InvalidServers) {
                    Write-Host "  - '$InvalidServer' (contains invalid characters or format)" -ForegroundColor Red
                }
            }

            if ($ValidServers.Count -gt 0) {
                $SpecificServers = $ValidServers
                Write-Host "Will search $($ValidServers.Count) valid server(s): $($ValidServers -join ', ')" -ForegroundColor Yellow
            } else {
                Write-Host "No valid servers specified. Will search all DHCP servers in domain" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Will search all DHCP servers in domain" -ForegroundColor Yellow
        }
    }
}

# Ask if user wants to retrieve DNS server information
$RetrieveDNS = Read-Host "Do you want to retrieve DNS server information? (Y/N, default: N - faster)"
$IncludeDNS = ($RetrieveDNS -eq 'Y' -or $RetrieveDNS -eq 'y')

if ($IncludeDNS) {
    Write-Host "DNS server information will be included (this may slow down collection)" -ForegroundColor Yellow
} else {
    Write-Host "Skipping DNS server retrieval for faster processing" -ForegroundColor Green
}

Write-Host ""

# ============================================
# DISCOVER DHCP SERVERS
# ============================================

# Get DHCP servers - either specific ones or all in domain
if ($SpecificServers.Count -gt 0) {
    Write-Host "Using specified DHCP servers..." -ForegroundColor Cyan
    $DHCPServers = $SpecificServers | ForEach-Object {
        [PSCustomObject]@{
            DnsName = $_
        }
    }
    Write-Host "Will query $($DHCPServers.Count) specified DHCP server(s)" -ForegroundColor Green
} else {
    Write-Host "Discovering DHCP servers in domain..." -ForegroundColor Cyan
    try {
        $DHCPServers = Get-DhcpServerInDC
        Write-Host "Found $($DHCPServers.Count) DHCP servers in domain" -ForegroundColor Green
    } catch {
        Write-Error "Failed to get DHCP servers from domain: $($_.Exception.Message)"
        exit 1
    }
}

Write-Host ""

# ============================================
# SCRIPTBLOCK FOR PARALLEL EXECUTION
# ============================================

$ScriptBlock = {
    param(
        $DHCPServerName,
        $ScopeFilters,
        $IncludeDNS
    )

    $ServerStats = New-Object System.Collections.ArrayList

    try {
        # Retrieve all scope info at once
        $Scopes = Get-DhcpServerv4Scope -ComputerName $DHCPServerName -ErrorAction Stop

        # Apply filtering if scope filters are provided
        if ($ScopeFilters -and $ScopeFilters.Count -gt 0) {
            $OriginalScopeCount = $Scopes.Count

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

        # Retrieve all statistics at once
        $AllStatsRaw = Get-DhcpServerv4ScopeStatistics -ComputerName $DHCPServerName -ErrorAction Stop

        # Optionally retrieve DNS server information
        $DNSServerMap = @{}
        if ($IncludeDNS) {
            try {
                foreach ($Scope in $Scopes) {
                    try {
                        $DNSOption = Get-DhcpServerv4OptionValue -ComputerName $DHCPServerName -ScopeId $Scope.ScopeId -OptionId 6 -ErrorAction SilentlyContinue
                        if ($DNSOption) {
                            $DNSServerMap[$Scope.ScopeId] = $DNSOption.Value -join ','
                        }
                    } catch {
                        # Silently skip if DNS option not found
                    }
                }
            } catch {
                Write-Output "Warning: Could not retrieve DNS information for some scopes on $DHCPServerName"
            }
        }

        # Process scopes
        foreach ($Scope in $Scopes) {
            # Find corresponding statistics
            $Stats = $AllStatsRaw | Where-Object { $_.ScopeId -eq $Scope.ScopeId }

            # Get DNS Servers from dictionary
            $DNSServersString = $DNSServerMap[$Scope.ScopeId]

            if ($Stats) {
                $obj = $Stats | Select-Object *,
                    @{Name='DHCPServer'; Expression={$DHCPServerName}},
                    @{Name='Description'; Expression={if (-not [string]::IsNullOrWhiteSpace($Scope.Description)) { $Scope.Description } else { $Scope.Name }}},
                    @{Name='DNSServers'; Expression={$DNSServersString}}

                [void]$ServerStats.Add($obj)
            }
        }

    } catch {
        Write-Error "Error querying DHCP Server $DHCPServerName : $($_.Exception.Message)"
    }

    return $ServerStats
}

# ============================================
# PARALLEL PROCESSING
# ============================================

$TotalServers = $DHCPServers.Count
$AllStats = New-Object System.Collections.ArrayList

Write-Host "Starting parallel processing of $TotalServers DHCP servers..." -ForegroundColor Cyan

# Check PowerShell version and use optimal approach
if ($PSVersionTable.PSVersion.Major -ge 7) {
    # ========================================
    # PowerShell 7+ - Use ForEach-Object -Parallel (FASTEST)
    # ========================================
    Write-Host "Using PowerShell 7+ ForEach-Object -Parallel (optimal performance)" -ForegroundColor Green
    Write-Host ""

    $CompletedJobs = 0
    $TotalServers = $DHCPServers.Count

    $results = $DHCPServers | ForEach-Object -Parallel {
        $server = $_
        $sb = $using:ScriptBlock
        $filters = $using:ScopeNameSearchStrings
        $includeDNS = $using:IncludeDNS

        # Execute script block
        $result = & $sb $server.DnsName $filters $includeDNS

        # Progress tracking
        $completed = $using:CompletedJobs
        $total = $using:TotalServers
        $completedNum = [System.Threading.Interlocked]::Increment([ref]$completed)

        Write-Host "[$completedNum/$total] Completed: $($server.DnsName)" -ForegroundColor Green

        return $result
    } -ThrottleLimit $MaxConcurrentJobs

    # Collect results
    foreach ($result in $results) {
        if ($result) {
            # Add items individually to avoid type casting issues
            foreach ($item in $result) {
                if ($item) {
                    [void]$AllStats.Add($item)
                }
            }
        }
    }

} else {
    # ========================================
    # PowerShell 5.1 - Use Runspaces (Fast)
    # ========================================
    Write-Host "Using Runspace Pool for parallel processing (optimized for PowerShell 5.1)" -ForegroundColor Yellow
    Write-Host ""

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
        [void]$PowerShell.AddArgument($ScopeNameSearchStrings)
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

                Write-Host "[$CompletedCount/$TotalServers] Completed: $($Runspace.ServerName)" -ForegroundColor Green

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
                    Write-Warning "Failed to receive results from $($Runspace.ServerName): $($_.Exception.Message)"
                } finally {
                    $Runspace.PowerShell.Dispose()
                }
            }
        }
    }

    # Cleanup
    $RunspacePool.Close()
    $RunspacePool.Dispose()
}

# ============================================
# OUTPUT RESULTS
# ============================================

Write-Host "`n=== Processing Complete ===" -ForegroundColor Cyan
Write-Host "Found $($AllStats.Count) total DHCP scopes across all servers." -ForegroundColor Green
Write-Host ""

if ($AllStats.Count -gt 0) {
    # Display results
    Write-Host "Displaying results:" -ForegroundColor Cyan

    # Display with or without DNS servers column
    if ($IncludeDNS) {
        $AllStats | Format-Table -Property DHCPServer, ScopeId, AddressesFree, AddressesInUse, PercentageInUse, Description, DNSServers -AutoSize
    } else {
        $AllStats | Format-Table -Property DHCPServer, ScopeId, AddressesFree, AddressesInUse, PercentageInUse, Description -AutoSize
    }

    # Export to CSV
    $OutputPath = "DHCPScopeStats_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

    # Format columns in the requested order: Scope ID, DHCP Server, Description, Addresses Free, Addresses in use, Percentage in use, DNS IP/information
    if ($IncludeDNS) {
        $AllStats | Select-Object ScopeId, DHCPServer, Description, AddressesFree, AddressesInUse, PercentageInUse, DNSServers |
            Export-Csv -Path $OutputPath -NoTypeInformation -Force
    } else {
        $AllStats | Select-Object ScopeId, DHCPServer, Description, AddressesFree, AddressesInUse, PercentageInUse |
            Export-Csv -Path $OutputPath -NoTypeInformation -Force
    }

    Write-Host "`nDone! All DHCP scope statistics saved to $OutputPath." -ForegroundColor Green

    # Performance summary
    Write-Host "`n=== Performance Notes ===" -ForegroundColor Cyan
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        Write-Host "Used ForEach-Object -Parallel (fastest available method)" -ForegroundColor Green
    } else {
        Write-Host "Used Runspace Pool (5-10x faster than Start-Job)" -ForegroundColor Yellow
        Write-Host "Tip: Use PowerShell 7+ for even better performance" -ForegroundColor Yellow
    }
} else {
    Write-Host "`n=== No Results Found ===" -ForegroundColor Yellow
    Write-Host "No DHCP scopes were found matching your criteria." -ForegroundColor Yellow

    if ($ScopeNameSearchStrings.Count -gt 0) {
        Write-Host "`nFilters applied:" -ForegroundColor Cyan
        Write-Host "  Scope name filters: $($ScopeNameSearchStrings -join ', ')" -ForegroundColor White
        if ($SpecificServers.Count -gt 0) {
            Write-Host "  Server filters: $($SpecificServers -join ', ')" -ForegroundColor White
        }
        Write-Host "`nTroubleshooting tips:" -ForegroundColor Cyan
        Write-Host "  1. Check if scope names actually contain the filter strings" -ForegroundColor White
        Write-Host "  2. Verify server names are correct and reachable" -ForegroundColor White
        Write-Host "  3. Try running without filters to see all available scopes" -ForegroundColor White
    }
}
