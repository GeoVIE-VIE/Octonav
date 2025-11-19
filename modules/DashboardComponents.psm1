#Requires -Version 5.1
<#
.SYNOPSIS
    Dashboard Components for OctoNav GUI v2.3
.DESCRIPTION
    Dashboard tab components and summary information display
#>

function New-DashboardPanel {
    <#
    .SYNOPSIS
        Creates a dashboard information panel
    #>
    param(
        [string]$Title,
        [string]$Value,
        [string]$Icon = "",
        [int]$X,
        [int]$Y,
        [hashtable]$Theme = $null
    )

    $panel = New-Object System.Windows.Forms.GroupBox
    $panel.Text = $Title
    $panel.Location = New-Object System.Drawing.Point($X, $Y)
    $panel.Size = New-Object System.Drawing.Size(220, 100)

    $lblValue = New-Object System.Windows.Forms.Label
    $lblValue.Text = $Value
    $lblValue.Location = New-Object System.Drawing.Point(15, 30)
    $lblValue.Size = New-Object System.Drawing.Size(190, 50)
    $lblValue.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $lblValue.TextAlign = "MiddleCenter"
    $panel.Controls.Add($lblValue)

    return @{
        Panel = $panel
        ValueLabel = $lblValue
    }
}

function Update-DashboardPanel {
    <#
    .SYNOPSIS
        Updates dashboard panel value
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Panel,

        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    try {
        $Panel.ValueLabel.Invoke([Action]{
            $Panel.ValueLabel.Text = $Value
        })
    } catch {
        $Panel.ValueLabel.Text = $Value
    }
}

function Get-CachedDHCPServers {
    <#
    .SYNOPSIS
        Gets DHCP servers from cache file
    .DESCRIPTION
        Reads cached DHCP server list from JSON file. Returns empty array if cache doesn't exist.
    #>
    $cacheFile = Join-Path $PSScriptRoot "..\dhcp_servers_cache.json"

    if (Test-Path $cacheFile) {
        try {
            $cache = Get-Content $cacheFile -Raw | ConvertFrom-Json
            return $cache.Servers
        } catch {
            # Cache file corrupted, return empty
        }
    }

    return @()
}

function Update-DHCPServerCache {
    <#
    .SYNOPSIS
        Discovers DHCP servers and updates cache file
    .DESCRIPTION
        Queries Active Directory for DHCP servers and saves to cache.
        Returns the discovered servers.
    #>
    $cacheFile = Join-Path $PSScriptRoot "..\dhcp_servers_cache.json"

    try {
        # Discover DHCP servers from AD
        $dhcpServers = Get-DhcpServerInDC -ErrorAction Stop

        if ($dhcpServers) {
            $serverList = @($dhcpServers | ForEach-Object {
                [PSCustomObject]@{
                    DnsName = $_.DnsName
                    IPAddress = $_.IPAddress
                }
            })

            # Create cache object
            $cache = @{
                LastUpdated = (Get-Date).ToString("o")
                ServerCount = $serverList.Count
                Servers = $serverList
            }

            # Save to JSON file
            $cache | ConvertTo-Json -Depth 3 | Set-Content $cacheFile -Force

            return $serverList
        }
    } catch {
        Write-Warning "Failed to discover DHCP servers: $($_.Exception.Message)"
    }

    return @()
}

function Get-SystemHealthSummary {
    <#
    .SYNOPSIS
        Gets system health summary information
    #>
    try {
        $health = @{
            AdminPrivileges = Test-IsAdministrator
            NetworkAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue).Count
            DNAConnected = $false
            DHCPServersFound = 0
            LastExportTime = "Never"
        }

        # Check if we have DNA Center connection
        if ($script:dnaCenterToken -and $script:dnaCenterTokenExpiry) {
            if ((Get-Date) -lt $script:dnaCenterTokenExpiry) {
                $health.DNAConnected = $true
            }
        }

        # Check for DHCP servers from cache (fast)
        try {
            $cachedServers = Get-CachedDHCPServers
            if ($cachedServers) {
                $health.DHCPServersFound = @($cachedServers).Count
            }
        } catch {
            # Silently continue if cache read fails
        }

        return $health
    } catch {
        return @{
            AdminPrivileges = $false
            NetworkAdapters = 0
            DNAConnected = $false
            DHCPServersFound = 0
            LastExportTime = "Error"
        }
    }
}

function New-QuickActionButton {
    <#
    .SYNOPSIS
        Creates a quick action button for the dashboard
    #>
    param(
        [string]$Text,
        [int]$X,
        [int]$Y,
        [scriptblock]$OnClick,
        [hashtable]$Theme = $null
    )

    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Location = New-Object System.Drawing.Point($X, $Y)
    $button.Size = New-Object System.Drawing.Size(200, 40)
    $button.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    if ($OnClick) {
        $button.Add_Click($OnClick)
    }

    return $button
}

function Get-RecentActivity {
    <#
    .SYNOPSIS
        Gets recent activity log entries
    #>
    param(
        [hashtable]$Settings,
        [int]$Count = 5
    )

    if ($Settings.ExportHistory) {
        return $Settings.ExportHistory |
            Select-Object -Last $Count |
            ForEach-Object {
                "$($_.Timestamp) - $($_.Operation) ($($_.Format))"
            }
    }

    return @("No recent activity")
}

# Export module members
Export-ModuleMember -Function @(
    'New-DashboardPanel',
    'Update-DashboardPanel',
    'Get-CachedDHCPServers',
    'Update-DHCPServerCache',
    'Get-SystemHealthSummary',
    'New-QuickActionButton',
    'Get-RecentActivity'
)
