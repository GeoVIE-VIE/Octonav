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

        # Check for DHCP servers
        try {
            $dhcpServers = Get-DhcpServerInDC -ErrorAction SilentlyContinue
            if ($dhcpServers) {
                $health.DHCPServersFound = @($dhcpServers).Count
            }
        } catch {
            # Silently continue if DHCP discovery fails
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
    'Get-SystemHealthSummary',
    'New-QuickActionButton',
    'Get-RecentActivity'
)
