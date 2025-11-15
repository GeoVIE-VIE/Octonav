# Enhanced DHCP Scope Statistics Collection Script
# Merges parallel processing with optional filtering and DNS retrieval

Write-Host "=== DHCP Scope Statistics Collection ===" -ForegroundColor Cyan
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
            $SpecificServers = $ServerInput.Split(',') | ForEach-Object { $_.Trim() }
            Write-Host "Will only search servers: $($SpecificServers -join ', ')" -ForegroundColor Yellow
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

# Ask if user wants to track bad address occurrences
$TrackBadAddresses = Read-Host "Do you want to track Bad_Address occurrences? (Y/N, default: N - slower)"
$IncludeBadAddresses = ($TrackBadAddresses -eq 'Y' -or $TrackBadAddresses -eq 'y')

if ($IncludeBadAddresses) {
    Write-Host "Bad_Address tracking will be included (this will significantly slow down collection)" -ForegroundColor Yellow
} else {
    Write-Host "Skipping Bad_Address tracking for faster processing" -ForegroundColor Green
}

Write-Host ""

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

# Define the script block that will run for each DHCP server
$ScriptBlock = {
    param(
        $DHCPServerName,
        $ScopeFilters,
        $IncludeDNS,
        $IncludeBadAddresses
    )
    
    $ServerStats = @()
    
    try {
        Write-Output "Querying DHCP Server: $DHCPServerName..."

        # Retrieve all scope info from DHCP server at once
        $Scopes = Get-DhcpServerv4Scope -ComputerName $DHCPServerName -ErrorAction Stop

        # Apply filtering if scope filters are provided
        if ($ScopeFilters -and $ScopeFilters.Count -gt 0) {
            $FilteredScopes = @()
            foreach ($Filter in $ScopeFilters) {
                $FilteredScopes += $Scopes | Where-Object { $_.Name -like "*$Filter*" }
            }
            $Scopes = $FilteredScopes | Select-Object -Unique
            
            if ($Scopes.Count -eq 0) {
                Write-Output "No scopes matching filters found on $DHCPServerName"
                return @()
            }
        }

        # Retrieve all statistics for all scopes at once
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
                        # Silently skip if DNS option not found for this scope
                    }
                }
            } catch {
                Write-Output "Warning: Could not retrieve DNS information for some scopes on $DHCPServerName"
            }
        }

        # Optionally retrieve Bad_Address information
        $BadAddressMap = @{}
        if ($IncludeBadAddresses) {
            try {
                Write-Output "Retrieving Bad_Address information from $DHCPServerName..."
                
                # Get all leases including bad addresses
                foreach ($Scope in $Scopes) {
                    try {
                        $BadAddresses = Get-DhcpServerv4Lease -ComputerName $DHCPServerName -ScopeId $Scope.ScopeId -ErrorAction SilentlyContinue | 
                            Where-Object { $_.HostName -eq "BAD_ADDRESS" }
                        
                        if ($BadAddresses) {
                            $BadAddressMap[$Scope.ScopeId] = $BadAddresses.Count
                        } else {
                            $BadAddressMap[$Scope.ScopeId] = 0
                        }
                    } catch {
                        $BadAddressMap[$Scope.ScopeId] = 0
                    }
                }
            } catch {
                Write-Output "Warning: Could not retrieve Bad_Address information for $DHCPServerName"
            }
        }

        # Process scopes
        foreach ($Scope in $Scopes) {
            Write-Output "Processing scope: $($Scope.Name) ($($Scope.ScopeId)) from $DHCPServerName"

            # Find the corresponding statistics
            $Stats = $AllStatsRaw | Where-Object { $_.ScopeId -eq $Scope.ScopeId }

            # Get DNS Servers from the dictionary
            $DNSServersString = $DNSServerMap[$Scope.ScopeId]
            
            # Get Bad Address count
            $BadAddressCount = if ($IncludeBadAddresses) { $BadAddressMap[$Scope.ScopeId] } else { $null }

            # Add the statistics with additional properties
            if ($Stats) {
                $ServerStats += $Stats | Select-Object *, 
                    @{Name='DHCPServer'; Expression={$DHCPServerName}},
                    @{Name='Description'; Expression={if (-not [string]::IsNullOrWhiteSpace($Scope.Description)) { $Scope.Description } else { $Scope.Name }}}, 
                    @{Name='DNSServers'; Expression={$DNSServersString}},
                    @{Name='BadAddressCount'; Expression={$BadAddressCount}}
            }
        }
        
        Write-Output "Collected $($ServerStats.Count) scopes from $DHCPServerName"
        
    } catch {
        Write-Error "Error querying DHCP Server $DHCPServerName : $($_.Exception.Message)"
    }
    
    return $ServerStats
}

# Create an array to store all jobs
$Jobs = @()
$AllStats = @()

# Maximum number of concurrent jobs
$MaxJobs = 20
$CompletedJobs = 0
$TotalServers = $DHCPServers.Count

Write-Host "`nStarting parallel processing of $TotalServers DHCP servers with maximum $MaxJobs concurrent jobs..." -ForegroundColor Cyan
Write-Host ""

# Process servers in batches
for ($i = 0; $i -lt $DHCPServers.Count; $i += $MaxJobs) {
    $Batch = $DHCPServers[$i..([Math]::Min($i + $MaxJobs - 1, $DHCPServers.Count - 1))]
    
    $BatchNumber = [Math]::Floor($i / $MaxJobs) + 1
    Write-Host "Starting batch $BatchNumber with $($Batch.Count) servers..." -ForegroundColor Yellow
    
    # Start jobs for current batch
    foreach ($Server in $Batch) {
        $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Server.DnsName, $ScopeNameSearchStrings, $IncludeDNS, $IncludeBadAddresses
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
            $CompletedJobs++
            $CompletedJob.Processed = $true
            
            Write-Host "[$CompletedJobs/$TotalServers] Completed: $($CompletedJob.ServerName)" -ForegroundColor Green
            
            try {
                $Result = Receive-Job -Job $CompletedJob.Job -ErrorAction Stop
                if ($Result) {
                    $AllStats += $Result
                }
            } catch {
                Write-Warning "Failed to receive results from $($CompletedJob.ServerName): $($_.Exception.Message)"
            }
            
            # Clean up completed job
            Remove-Job -Job $CompletedJob.Job -Force
        }
        
        # Check for failed jobs
        $FailedInBatch = $Jobs | Where-Object { $_.Job.State -eq 'Failed' -and -not $_.Processed }
        foreach ($FailedJob in $FailedInBatch) {
            $CompletedJobs++
            $FailedJob.Processed = $true
            Write-Warning "[$CompletedJobs/$TotalServers] Failed: $($FailedJob.ServerName)"
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
                $AllStats += $Result
            }
        } catch {
            Write-Warning "Failed to receive results from $($RemainingJob.ServerName): $($_.Exception.Message)"
        }
    }
    Remove-Job -Job $RemainingJob.Job -Force
}

Write-Host "`n=== Processing Complete ===" -ForegroundColor Cyan
Write-Host "Found $($AllStats.Count) total DHCP scopes across all servers." -ForegroundColor Green
Write-Host ""

if ($AllStats.Count -gt 0) {
    # Display all statistics on the screen
    Write-Host "Displaying results:" -ForegroundColor Cyan
    
    if ($IncludeBadAddresses) {
        # Show bad address summary by Scope
        Write-Host "`n=== Bad Address Summary by Scope ===" -ForegroundColor Yellow
        $BadAddressSummary = $AllStats | 
            Where-Object { $_.BadAddressCount -gt 0 } |
            Select-Object @{Name='DHCPServer'; Expression={$_.DHCPServer}},
                         @{Name='ScopeID'; Expression={$_.ScopeId}},
                         @{Name='Description'; Expression={$_.Description}},
                         @{Name='BadAddressCount'; Expression={$_.BadAddressCount}},
                         @{Name='AddressesInUse'; Expression={$_.AddressesInUse}},
                         @{Name='PercentageInUse'; Expression={$_.PercentageInUse}} |
            Sort-Object -Property BadAddressCount -Descending
        
        if ($BadAddressSummary) {
            $BadAddressSummary | Format-Table -AutoSize
            Write-Host "Total Scopes with Bad Addresses: $($BadAddressSummary.Count)" -ForegroundColor Yellow
            Write-Host "Total Bad Addresses Enterprise-wide: $(($BadAddressSummary | Measure-Object -Property BadAddressCount -Sum).Sum)" -ForegroundColor Red
        } else {
            Write-Host "No Bad Addresses found across the enterprise!" -ForegroundColor Green
        }
        Write-Host ""
    }
    
    # Display scope statistics
    if ($IncludeDNS -and $IncludeBadAddresses) {
        $AllStats | Format-Table -Property DHCPServer, ScopeId, AddressesFree, AddressesInUse, PercentageInUse, BadAddressCount, Description, DNSServers -AutoSize
    } elseif ($IncludeBadAddresses) {
        $AllStats | Format-Table -Property DHCPServer, ScopeId, AddressesFree, AddressesInUse, PercentageInUse, BadAddressCount, Description -AutoSize
    } elseif ($IncludeDNS) {
        $AllStats | Format-Table -Property DHCPServer, ScopeId, AddressesFree, AddressesInUse, PercentageInUse, Description, DNSServers -AutoSize
    } else {
        $AllStats | Format-Table -Property DHCPServer, ScopeId, AddressesFree, AddressesInUse, PercentageInUse, Description -AutoSize
    }

    # Output all statistics to a CSV file
    $OutputPath = "DHCPScopeStats.csv"
    
    if ($IncludeDNS -and $IncludeBadAddresses) {
        $AllStats | Select-Object DHCPServer, Description, ScopeId, AddressesFree, AddressesInUse, PercentageInUse, BadAddressCount, DNSServers | Export-Csv -Path $OutputPath -NoTypeInformation -Force
    } elseif ($IncludeBadAddresses) {
        $AllStats | Select-Object DHCPServer, Description, ScopeId, AddressesFree, AddressesInUse, PercentageInUse, BadAddressCount | Export-Csv -Path $OutputPath -NoTypeInformation -Force
    } elseif ($IncludeDNS) {
        $AllStats | Select-Object DHCPServer, Description, ScopeId, AddressesFree, AddressesInUse, PercentageInUse, DNSServers | Export-Csv -Path $OutputPath -NoTypeInformation -Force
    } else {
        $AllStats | Select-Object DHCPServer, Description, ScopeId, AddressesFree, AddressesInUse, PercentageInUse | Export-Csv -Path $OutputPath -NoTypeInformation -Force
    }

    # Create separate bad address summary CSV if tracking is enabled
    if ($IncludeBadAddresses -and $BadAddressSummary) {
        $BadAddressPath = "DHCPBadAddressSummary.csv"
        $BadAddressSummary | Export-Csv -Path $BadAddressPath -NoTypeInformation -Force
        Write-Host "`nBad Address summary saved to $BadAddressPath" -ForegroundColor Yellow
    }

    Write-Host "`nDone! All DHCP scope statistics saved to $OutputPath." -ForegroundColor Green
} else {
    Write-Host "No DHCP scopes found matching your criteria." -ForegroundColor Yellow
}
