#Requires -Version 5.1
<#
.SYNOPSIS
    OctoNav v2.3 - Modular Network Management Tool with Enhanced UI
.DESCRIPTION
    Completely redesigned OctoNav GUI with modular architecture featuring:

    KEY FEATURES:
    - Dashboard Tab: System health overview with quick actions and recent activity
    - Dark Mode Support: Toggle between light and dark themes
    - Enhanced Export: Multiple format support (CSV, Excel, JSON, HTML)
    - Settings Dialog: Comprehensive configuration management
    - TreeView DNA Center: Organized function categories for better navigation
    - Network Configuration: Static IP configuration with admin privilege management
    - DHCP Statistics: Parallel collection with scope filtering
    - DNA Center Integration: 25+ API functions with advanced filtering

    MODULAR ARCHITECTURE:
    - SettingsManager: User preferences and configuration persistence
    - ThemeManager: Light/Dark theme support with dynamic switching
    - ValidationFunctions: Input validation and sanitization
    - HelperFunctions: Logging, status updates, and utility functions
    - ExportManager: Multi-format export with history tracking
    - SettingsDialog: User-friendly settings interface
    - DashboardComponents: System health and quick action panels
    - DNACenterFunctions: 25+ DNA Center API integrations
    - DHCPFunctions: Optimized DHCP statistics collection
    - NetworkConfigFunctions: Network adapter configuration

.AUTHOR
    Integrated by Claude - OctoNav v2.3
.VERSION
    2.3 - Modular Architecture Release
    - Complete module-based refactoring
    - Dashboard tab with system health monitoring
    - TreeView-based DNA Center function navigation
    - Dark mode support
    - Enhanced settings management
    - Multi-format export capabilities
#>

# ============================================
# ASSEMBLY LOADING
# ============================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# Handle errors gracefully
$ErrorActionPreference = "Stop"

# ============================================
# CERTIFICATE VALIDATION BYPASS & TLS SETUP
# ============================================
# Required for DNA Center API calls with self-signed certificates
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
    $certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback == null)
            {
                ServicePointManager.ServerCertificateValidationCallback +=
                    delegate
                    (
                        Object obj,
                        X509Certificate certificate,
                        X509Chain chain,
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
}
[ServerCertificateValidationCallback]::Ignore()
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# ============================================
# MODULE IMPORTS
# ============================================
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

try {
    # Remove all custom modules from session to ensure clean reload
    Get-Module | Where-Object { $_.Path -like "$scriptPath\modules\*" } | Remove-Module -Force -ErrorAction SilentlyContinue

    # Core modules (import with -Global to ensure functions are available)
    Import-Module "$scriptPath\modules\SettingsManager.psm1" -Force -Global -ErrorAction Stop
    Import-Module "$scriptPath\modules\ThemeManager.psm1" -Force -Global -ErrorAction Stop
    Import-Module "$scriptPath\modules\ValidationFunctions.psm1" -Force -Global -ErrorAction Stop
    Import-Module "$scriptPath\modules\HelperFunctions.psm1" -Force -Global -ErrorAction Stop
    Import-Module "$scriptPath\modules\ExportManager.psm1" -Force -Global -ErrorAction Stop

    # UI modules
    Import-Module "$scriptPath\modules\UIEnhancements.psm1" -Force -Global -ErrorAction Stop
    Import-Module "$scriptPath\modules\SettingsDialog.psm1" -Force -Global -ErrorAction Stop
    Import-Module "$scriptPath\modules\DashboardComponents.psm1" -Force -Global -ErrorAction Stop

    # Function modules
    Import-Module "$scriptPath\modules\DNACenterFunctions.psm1" -Force -Global -ErrorAction Stop
    Import-Module "$scriptPath\modules\DHCPFunctions.psm1" -Force -Global -ErrorAction Stop
    Import-Module "$scriptPath\modules\NetworkConfigFunctions.psm1" -Force -Global -ErrorAction Stop

    # Verify critical module functions are available
    $criticalFunctions = @('Write-Log', 'New-EnhancedStatusBar', 'Update-DHCPScopeCache', 'Get-CachedDHCPScopes')
    $missingFunctions = @()

    foreach ($func in $criticalFunctions) {
        if (-not (Get-Command $func -ErrorAction SilentlyContinue)) {
            $missingFunctions += $func
        }
    }

    if ($missingFunctions.Count -gt 0) {
        throw "Critical module functions not loaded: $($missingFunctions -join ', '). Please close PowerShell completely and restart."
    }

    Write-Host "All modules loaded successfully" -ForegroundColor Green
} catch {
    [System.Windows.Forms.MessageBox]::Show(
        "Failed to load required modules: $($_.Exception.Message)`n`nPlease ensure all module files are present in the 'modules' folder.",
        "Module Load Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    exit 1
}

# ============================================
# DEFINE INVOKE-BACKGROUNDOPERATION LOCALLY
# ============================================
# Define this function here instead of in module to ensure System.Windows.Forms.Timer is available

function Invoke-BackgroundOperation
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory=$false)]
        [object[]]$ArgumentList = @(),

        [Parameter(Mandatory=$true)]
        [scriptblock]$OnComplete,

        [Parameter(Mandatory=$true)]
        [System.Windows.Forms.Form]$Form
    )

    # Create runspace
    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()

    # Create PowerShell instance
    $ps = [powershell]::Create()
    $ps.Runspace = $runspace
    [void]$ps.AddScript($ScriptBlock)

    # Add arguments if provided
    if ($ArgumentList -and $ArgumentList.Count -gt 0) {
        foreach ($arg in $ArgumentList) {
            [void]$ps.AddArgument($arg)
        }
    }

    # Start async execution
    $handle = $ps.BeginInvoke()

    # Create timer to poll for completion
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 200

    # Store references in timer tag
    $timer.Tag = @{
        PowerShell = $ps
        Handle = $handle
        Runspace = $runspace
        OnComplete = $OnComplete
    }

    # Add tick handler
    $timer.Add_Tick({
        $data = $this.Tag
        if ($data.Handle.IsCompleted) {
            try {
                $result = $data.PowerShell.EndInvoke($data.Handle)
                & $data.OnComplete $result
            }
            catch {
                Write-Warning "Background operation error: $($_.Exception.Message)"
            }
            finally {
                if ($data.PowerShell) { $data.PowerShell.Dispose() }
                if ($data.Runspace) {
                    $data.Runspace.Close()
                    $data.Runspace.Dispose()
                }
                $this.Stop()
                $this.Dispose()
            }
        }
    })

    $timer.Start()
    return $timer
}

# ============================================
# HELPER FUNCTIONS
# ============================================

function Group-DHCPScopesByScopeId {
    <#
    .SYNOPSIS
        Groups DHCP scope statistics by Scope ID and aggregates redundant scopes
    .DESCRIPTION
        When the same scope exists on multiple servers (for redundancy),
        this function groups them by Scope ID and aggregates the statistics.
    .PARAMETER ScopeData
        Array of scope objects with properties: ScopeId, DHCPServer, Description,
        AddressesFree, AddressesInUse, PercentageInUse, DNSServers (optional)
    .OUTPUTS
        Array of grouped scope objects with combined servers and aggregated statistics
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$ScopeData
    )

    # Group scopes by ScopeId
    $groupedScopes = $ScopeData | Group-Object -Property ScopeId

    $aggregatedResults = @()
    foreach ($group in $groupedScopes) {
        $scopes = $group.Group

        # Get first scope for name/description (should be the same across redundant scopes)
        $firstScope = $scopes[0]

        # Combine server names
        $combinedServers = ($scopes | ForEach-Object { $_.DHCPServer }) -join ', '

        # Aggregate statistics
        $totalFree = ($scopes | Measure-Object -Property AddressesFree -Sum).Sum
        $totalInUse = ($scopes | Measure-Object -Property AddressesInUse -Sum).Sum
        $totalAddresses = $totalFree + $totalInUse

        # Calculate percentage
        $percentageInUse = 0
        if ($totalAddresses -gt 0) {
            $percentageInUse = [math]::Round(($totalInUse / $totalAddresses) * 100, 2)
        }

        # Build aggregated object
        $aggregated = [PSCustomObject]@{
            ScopeId = $group.Name
            DHCPServer = $combinedServers
            Description = $firstScope.Description
            AddressesFree = $totalFree
            AddressesInUse = $totalInUse
            PercentageInUse = $percentageInUse
        }

        # Add DNS servers if they exist
        if ($firstScope.PSObject.Properties.Name -contains 'DNSServers') {
            # Combine unique DNS servers from all redundant scopes
            $allDNS = @()
            foreach ($scope in $scopes) {
                if (-not [string]::IsNullOrWhiteSpace($scope.DNSServers)) {
                    $dnsEntries = $scope.DNSServers -split ',' | ForEach-Object { $_.Trim() }
                    $allDNS += $dnsEntries
                }
            }
            $uniqueDNS = $allDNS | Select-Object -Unique
            $aggregated | Add-Member -NotePropertyName DNSServers -NotePropertyValue ($uniqueDNS -join ', ')
        }

        $aggregatedResults += $aggregated
    }

    return $aggregatedResults
}

function Get-DNACenterServers {
    <#
    .SYNOPSIS
        Loads DNA Center server configurations from JSON file or environment variables
    #>
    $configFile = Join-Path $scriptPath "dna_config.json"

    # Try to load from config file first (silently)
    if (Test-Path $configFile) {
        try {
            $config = Get-Content $configFile -Raw | ConvertFrom-Json
            if ($config.servers -and $config.servers.Count -gt 0) {
                return $config.servers
            }
        } catch {
            # Silently continue if config file is invalid
        }
    }

    # Try environment variables
    $servers = @()
    for ($i = 1; $i -le 10; $i++) {
        $nameVar = "DNAC_SERVER${i}_NAME"
        $urlVar = "DNAC_SERVER${i}_URL"

        $name = [Environment]::GetEnvironmentVariable($nameVar)
        $url = [Environment]::GetEnvironmentVariable($urlVar)

        if ($name -and $url) {
            $servers += [pscustomobject]@{ Name = $name; Url = $url }
        }
    }

    if ($servers.Count -gt 0) {
        return $servers
    }

    # Fallback to default (user will see this in the GUI dropdown)
    return @([pscustomobject]@{ Name = "Please Configure"; Url = "https://your-dnac-server.example.com" })
}

function Add-DNATreeNode {
    <#
    .SYNOPSIS
        Helper function to add TreeNode with Tag property to parent node
    #>
    param(
        [System.Windows.Forms.TreeNode]$ParentNode,
        [string]$Text,
        [string]$Tag
    )
    $node = New-Object System.Windows.Forms.TreeNode($Text)
    $node.Tag = $Tag
    $ParentNode.Nodes.Add($node) | Out-Null
}

# ============================================
# INITIALIZE SETTINGS & GLOBAL VARIABLES
# ============================================

# Load user settings
$script:Settings = Get-OctoNavSettings

# Get initial theme
$script:CurrentTheme = Get-Theme -ThemeName $script:Settings.Theme

# Initialize global variables for DNA Center (use global scope for module access)
$global:dnaCenterToken = $null
$global:dnaCenterTokenExpiry = $null
$global:dnaCenterHeaders = $null
$global:selectedDnaCenter = $null
$global:allDNADevices = @()
$global:selectedDNADevices = @()
$global:dnaCenterServers = @()

# Initialize global variables for DHCP
$script:dhcpResults = @()
$script:dhcpStopRequested = $false
$script:dhcpRunspace = $null
$script:dhcpPowerShell = $null
$script:dhcpAsyncResult = $null
$script:dhcpTimer = $null
$script:dhcpLogsDisplayed = 0

# Initialize global variables for Network Configuration
$script:TargetAdapter = $null
$script:OriginalConfig = $null
$script:NewIPAddress = $null
$script:NewGateway = $null
$script:IsRunningAsAdmin = Test-IsAdministrator

# Output directory
$script:outputDir = if ($script:Settings.DefaultExportPath) {
    $script:Settings.DefaultExportPath
} else {
    "C:\DNACenter_Reports"
}

# Load DNA Center servers from config
$global:dnaCenterServers = Get-DNACenterServers

# ============================================
# CREATE MAIN FORM
# ============================================

$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Text = "OctoNav v2.3 - Network Management Tool"
$mainForm.Size = New-Object System.Drawing.Size($script:Settings.WindowSize.Width, $script:Settings.WindowSize.Height)
$mainForm.StartPosition = "CenterScreen"
$mainForm.FormBorderStyle = "Sizable"
$mainForm.MinimumSize = New-Object System.Drawing.Size(1000, 600)

if ($script:Settings.WindowMaximized) {
    $mainForm.WindowState = "Maximized"
}

# ============================================
# CREATE MENU BAR
# ============================================

$menuStrip = New-Object System.Windows.Forms.MenuStrip

# File Menu
$menuFile = New-Object System.Windows.Forms.ToolStripMenuItem
$menuFile.Text = "&File"

$menuFileExit = New-Object System.Windows.Forms.ToolStripMenuItem
$menuFileExit.Text = "E&xit"
$menuFileExit.ShortcutKeys = [System.Windows.Forms.Keys]::Alt -bor [System.Windows.Forms.Keys]::F4
$menuFileExit.Add_Click({ $mainForm.Close() })
$menuFile.DropDownItems.Add($menuFileExit)

# Tools Menu
$menuTools = New-Object System.Windows.Forms.ToolStripMenuItem
$menuTools.Text = "&Tools"

$menuToolsSettings = New-Object System.Windows.Forms.ToolStripMenuItem
$menuToolsSettings.Text = "&Settings"
$menuToolsSettings.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::S
$menuToolsSettings.Add_Click({
    $newSettings = Show-SettingsDialog -CurrentSettings $script:Settings -ParentForm $mainForm
    if ($newSettings) {
        $script:Settings = $newSettings
        Save-OctoNavSettings -Settings $script:Settings

        # Apply theme if changed
        if ($script:CurrentTheme.Name -ne $script:Settings.Theme) {
            $script:CurrentTheme = Get-Theme -ThemeName $script:Settings.Theme
            Set-ThemeToControl -Control $mainForm -Theme $script:CurrentTheme
        }

        [System.Windows.Forms.MessageBox]::Show(
            "Settings saved successfully!`nSome changes may require restarting the application.",
            "Settings Saved",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
})
$menuTools.DropDownItems.Add($menuToolsSettings)

$menuToolsRefresh = New-Object System.Windows.Forms.ToolStripMenuItem
$menuToolsRefresh.Text = "&Refresh Dashboard"
$menuToolsRefresh.ShortcutKeys = [System.Windows.Forms.Keys]::F5
$menuToolsRefresh.Add_Click({
    if ($tabControl.SelectedIndex -eq 0) {
        # Refresh dashboard
        Update-Dashboard
    }
})
$menuTools.DropDownItems.Add($menuToolsRefresh)

# View Menu
$menuView = New-Object System.Windows.Forms.ToolStripMenuItem
$menuView.Text = "&View"

$menuViewTheme = New-Object System.Windows.Forms.ToolStripMenuItem
$menuViewTheme.Text = "Toggle &Theme"
$menuViewTheme.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::T
$menuViewTheme.Add_Click({
    # Toggle theme
    $newThemeName = if ($script:CurrentTheme.Name -eq "Light") { "Dark" } else { "Light" }
    $script:CurrentTheme = Get-Theme -ThemeName $newThemeName
    $script:Settings.Theme = $newThemeName
    Save-OctoNavSettings -Settings $script:Settings

    # Apply new theme
    Set-ThemeToControl -Control $mainForm -Theme $script:CurrentTheme
})
$menuView.DropDownItems.Add($menuViewTheme)

# Help Menu
$menuHelp = New-Object System.Windows.Forms.ToolStripMenuItem
$menuHelp.Text = "&Help"

$menuHelpAbout = New-Object System.Windows.Forms.ToolStripMenuItem
$menuHelpAbout.Text = "&About"
$menuHelpAbout.Add_Click({
    $aboutText = @"
OctoNav v2.3
Network Management Tool

Modular architecture with enhanced features:
- Dashboard with system health monitoring
- Network Configuration (requires admin)
- DHCP Statistics Collection
- DNA Center API Integration (25+ functions)
- Dark Mode Support
- Multi-format Export (CSV, Excel, JSON, HTML)

Developed by: Claude
Architecture: Modular PowerShell with Windows Forms
"@
    [System.Windows.Forms.MessageBox]::Show(
        $aboutText,
        "About OctoNav v2.3",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
})
$menuHelp.DropDownItems.Add($menuHelpAbout)

# Add menus to menu strip
$menuStrip.Items.Add($menuFile)
$menuStrip.Items.Add($menuTools)
$menuStrip.Items.Add($menuView)
$menuStrip.Items.Add($menuHelp)

$mainForm.Controls.Add($menuStrip)
$mainForm.MainMenuStrip = $menuStrip

# ============================================
# CREATE TAB CONTROL
# ============================================

$tabControl = New-Object System.Windows.Forms.TabControl
$margin = Get-UISpacing -Name "MarginMedium"  # 16px for professional spacing
$tabControl.Location = New-Object System.Drawing.Point($margin, 30)  # 30 for menu bar
$tabControl.Size = New-Object System.Drawing.Size(($mainForm.ClientSize.Width - ($margin * 2)), ($mainForm.ClientSize.Height - 70))
$tabControl.Anchor = "Top,Bottom,Left,Right"
$mainForm.Controls.Add($tabControl)

# ============================================
# TAB 0: DASHBOARD
# ============================================

$tab0 = New-Object System.Windows.Forms.TabPage
$tab0.Text = "Dashboard"
$tabControl.Controls.Add($tab0)
Add-IconToTab -Tab $tab0 -IconName "Stats"

# Title Label
$lblDashboardTitle = New-Object System.Windows.Forms.Label
$lblDashboardTitle.Text = "OctoNav System Dashboard"
$lblDashboardTitle.Location = New-Object System.Drawing.Point(15, 15)
$lblDashboardTitle.Size = New-Object System.Drawing.Size(900, 30)
$lblDashboardTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$tab0.Controls.Add($lblDashboardTitle)

# System Health Panels
$healthGroupBox = New-Object System.Windows.Forms.GroupBox
$healthGroupBox.Text = "System Health"
$healthGroupBox.Location = New-Object System.Drawing.Point(15, 55)
$healthGroupBox.Size = New-Object System.Drawing.Size(920, 130)
$tab0.Controls.Add($healthGroupBox)

# Admin Status Panel
$script:adminPanel = New-DashboardPanel -Title "Admin Status" -Value "Checking..." -X 20 -Y 25 -Theme $script:CurrentTheme
$healthGroupBox.Controls.Add($script:adminPanel.Panel)

# Network Adapters Panel
$script:networkPanel = New-DashboardPanel -Title "Network Adapters" -Value "..." -X 255 -Y 25 -Theme $script:CurrentTheme
$healthGroupBox.Controls.Add($script:networkPanel.Panel)

# DNA Center Connection Panel
$script:dnaPanel = New-DashboardPanel -Title "DNA Center" -Value "Not Connected" -X 490 -Y 25 -Theme $script:CurrentTheme
$healthGroupBox.Controls.Add($script:dnaPanel.Panel)

# DHCP Servers Panel
$script:dhcpPanel = New-DashboardPanel -Title "DHCP Servers" -Value "..." -X 725 -Y 25 -Theme $script:CurrentTheme
$healthGroupBox.Controls.Add($script:dhcpPanel.Panel)

# Quick Actions Group
$quickActionsGroupBox = New-Object System.Windows.Forms.GroupBox
$quickActionsGroupBox.Text = "Quick Actions"
$quickActionsGroupBox.Location = New-Object System.Drawing.Point(15, 195)
$quickActionsGroupBox.Size = New-Object System.Drawing.Size(920, 100)
$tab0.Controls.Add($quickActionsGroupBox)

# Quick Action Buttons
$btnQuickDNA = New-QuickActionButton -Text "Connect to DNA Center" -X 20 -Y 30 -OnClick {
    $tabControl.SelectedIndex = 3  # Switch to DNA Center tab
} -Theme $script:CurrentTheme
$quickActionsGroupBox.Controls.Add($btnQuickDNA)

$btnQuickDHCP = New-QuickActionButton -Text "Collect DHCP Stats" -X 240 -Y 30 -OnClick {
    $tabControl.SelectedIndex = 2  # Switch to DHCP tab
} -Theme $script:CurrentTheme
$quickActionsGroupBox.Controls.Add($btnQuickDHCP)

$btnQuickNetwork = New-QuickActionButton -Text "Configure Network" -X 460 -Y 30 -OnClick {
    $tabControl.SelectedIndex = 1  # Switch to Network Config tab
} -Theme $script:CurrentTheme
$quickActionsGroupBox.Controls.Add($btnQuickNetwork)

$btnRefreshDashboard = New-QuickActionButton -Text "Refresh Dashboard" -X 680 -Y 30 -OnClick {
    Update-Dashboard
} -Theme $script:CurrentTheme
$quickActionsGroupBox.Controls.Add($btnRefreshDashboard)

# Recent Activity Group
$recentActivityGroupBox = New-Object System.Windows.Forms.GroupBox
$recentActivityGroupBox.Text = "Recent Activity"
$recentActivityGroupBox.Location = New-Object System.Drawing.Point(15, 305)
$recentActivityGroupBox.Size = New-Object System.Drawing.Size(920, 280)
$tab0.Controls.Add($recentActivityGroupBox)

$script:lstRecentActivity = New-Object System.Windows.Forms.ListBox
$script:lstRecentActivity.Location = New-Object System.Drawing.Point(15, 25)
$script:lstRecentActivity.Size = New-Object System.Drawing.Size(885, 240)
$script:lstRecentActivity.Font = New-Object System.Drawing.Font("Consolas", 9)
$recentActivityGroupBox.Controls.Add($script:lstRecentActivity)

# Dashboard update function
function Update-Dashboard {
    try {
        $health = Get-SystemHealthSummary

        # Update admin status
        if ($health.AdminPrivileges) {
            Update-DashboardPanel -Panel $script:adminPanel -Value "Active"
            $script:adminPanel.ValueLabel.ForeColor = [System.Drawing.Color]::Green
        } else {
            Update-DashboardPanel -Panel $script:adminPanel -Value "Standard"
            $script:adminPanel.ValueLabel.ForeColor = [System.Drawing.Color]::Orange
        }

        # Update network adapters
        Update-DashboardPanel -Panel $script:networkPanel -Value "$($health.NetworkAdapters)"

        # Update DNA Center status
        if ($health.DNAConnected) {
            Update-DashboardPanel -Panel $script:dnaPanel -Value "Connected"
            $script:dnaPanel.ValueLabel.ForeColor = [System.Drawing.Color]::Green
        } else {
            Update-DashboardPanel -Panel $script:dnaPanel -Value "Disconnected"
            $script:dnaPanel.ValueLabel.ForeColor = [System.Drawing.Color]::Gray
        }

        # Update DHCP servers
        Update-DashboardPanel -Panel $script:dhcpPanel -Value "$($health.DHCPServersFound)"

        # Update recent activity
        $script:lstRecentActivity.Items.Clear()
        $recentActivities = Get-RecentActivity -Settings $script:Settings -Count 10
        foreach ($activity in $recentActivities) {
            $script:lstRecentActivity.Items.Add($activity) | Out-Null
        }

    } catch {
        Write-Host "Error updating dashboard: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================
# TAB 1: NETWORK CONFIGURATION
# ============================================

$tab1 = New-Object System.Windows.Forms.TabPage
$tab1.Text = "Network Configuration"
$tabControl.Controls.Add($tab1)
Add-IconToTab -Tab $tab1 -IconName "Network"

# Admin Status Indicator for Network Config Tab
$lblAdminStatus = New-Object System.Windows.Forms.Label
$lblAdminStatus.Size = New-Object System.Drawing.Size(940, 25)
$lblAdminStatus.Location = New-Object System.Drawing.Point(10, 10)
$lblAdminStatus.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblAdminStatus.TextAlign = "MiddleLeft"
if ($script:IsRunningAsAdmin) {
    $lblAdminStatus.Text = "[OK] Administrator Privileges: ACTIVE - Network configuration enabled"
    $lblAdminStatus.ForeColor = [System.Drawing.Color]::Green
    $lblAdminStatus.BackColor = [System.Drawing.Color]::FromArgb(230, 255, 230)  # Light green
} else {
    $lblAdminStatus.Text = "[!] Administrator Required - Right-click and select 'Run as Administrator' to enable this tab"
    $lblAdminStatus.ForeColor = [System.Drawing.Color]::DarkOrange
    $lblAdminStatus.BackColor = [System.Drawing.Color]::FromArgb(255, 245, 230)  # Light orange
}
$tab1.Controls.Add($lblAdminStatus)

# Group Box for Network Settings
$netGroupBox = New-Object System.Windows.Forms.GroupBox
$netGroupBox.Text = "Network Adapter Configuration"
$netGroupBox.Size = New-Object System.Drawing.Size(940, 250)
$netGroupBox.Location = New-Object System.Drawing.Point(10, 40)
$tab1.Controls.Add($netGroupBox)

# Find Network Button
$btnFindNetwork = New-Object System.Windows.Forms.Button
$btnFindNetwork.Text = "Find Unidentified Network"
$btnFindNetwork.Size = New-Object System.Drawing.Size(200, 30)
$btnFindNetwork.Location = New-Object System.Drawing.Point(20, 30)
$netGroupBox.Controls.Add($btnFindNetwork)

# IP Address Label
$lblIPAddress = New-Object System.Windows.Forms.Label
$lblIPAddress.Text = "New IP Address:"
$lblIPAddress.Size = New-Object System.Drawing.Size(120, 20)
$lblIPAddress.Location = New-Object System.Drawing.Point(20, 80)
$netGroupBox.Controls.Add($lblIPAddress)

# IP Address TextBox
$txtIPAddress = New-Object System.Windows.Forms.TextBox
$txtIPAddress.Size = New-Object System.Drawing.Size(200, 20)
$txtIPAddress.Location = New-Object System.Drawing.Point(150, 78)
$netGroupBox.Controls.Add($txtIPAddress)

# Gateway Label
$lblGateway = New-Object System.Windows.Forms.Label
$lblGateway.Text = "Gateway:"
$lblGateway.Size = New-Object System.Drawing.Size(120, 20)
$lblGateway.Location = New-Object System.Drawing.Point(20, 120)
$netGroupBox.Controls.Add($lblGateway)

# Gateway TextBox
$txtGateway = New-Object System.Windows.Forms.TextBox
$txtGateway.Size = New-Object System.Drawing.Size(200, 20)
$txtGateway.Location = New-Object System.Drawing.Point(150, 118)
$netGroupBox.Controls.Add($txtGateway)

# Prefix Length Label
$lblPrefix = New-Object System.Windows.Forms.Label
$lblPrefix.Text = "Prefix Length:"
$lblPrefix.Size = New-Object System.Drawing.Size(120, 20)
$lblPrefix.Location = New-Object System.Drawing.Point(20, 160)
$netGroupBox.Controls.Add($lblPrefix)

# Prefix Length TextBox
$txtPrefix = New-Object System.Windows.Forms.TextBox
$txtPrefix.Text = "24"
$txtPrefix.Size = New-Object System.Drawing.Size(200, 20)
$txtPrefix.Location = New-Object System.Drawing.Point(150, 158)
$netGroupBox.Controls.Add($txtPrefix)

# Apply Configuration Button
$btnApplyConfig = New-Object System.Windows.Forms.Button
$btnApplyConfig.Text = "Apply Configuration"
$btnApplyConfig.Size = New-Object System.Drawing.Size(200, 30)
$btnApplyConfig.Location = New-Object System.Drawing.Point(20, 200)
$netGroupBox.Controls.Add($btnApplyConfig)

# Restore Defaults Button
$btnRestoreDefaults = New-Object System.Windows.Forms.Button
$btnRestoreDefaults.Text = "Restore Defaults"
$btnRestoreDefaults.Size = New-Object System.Drawing.Size(200, 30)
$btnRestoreDefaults.Location = New-Object System.Drawing.Point(240, 200)
$netGroupBox.Controls.Add($btnRestoreDefaults)

# Network Config Log
$netLogBox = New-Object System.Windows.Forms.RichTextBox
$netLogBox.Size = New-Object System.Drawing.Size(940, 310)
$netLogBox.Location = New-Object System.Drawing.Point(10, 300)
$netLogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$netLogBox.ReadOnly = $true
$netLogBox.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
$netLogBox.WordWrap = $false
$netLogBox.HideSelection = $false
$netLogBox.DetectUrls = $false
$netLogBox.Multiline = $true
$tab1.Controls.Add($netLogBox)

# Event Handlers for Tab 1
$btnFindNetwork.Add_Click({
    try {
        $networkInfo = Find-UnidentifiedNetwork -LogBox $netLogBox

        if ($networkInfo) {
            $script:TargetAdapter = $networkInfo.Adapter
            $script:OriginalConfig = @{
                NetworkCategory = $networkInfo.Profile.NetworkCategory
                DHCP = (Get-NetIPInterface -InterfaceIndex $script:TargetAdapter.ifIndex -AddressFamily IPv4).Dhcp
            }

            Write-Log -Message "Adapter found and ready for configuration" -Color "Success" -LogBox $netLogBox -Theme $script:CurrentTheme
        } else {
            Write-Log -Message "No unidentified network found" -Color "Error" -LogBox $netLogBox -Theme $script:CurrentTheme
        }
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Error" -LogBox $netLogBox -Theme $script:CurrentTheme
    }
})

$btnApplyConfig.Add_Click({
    try {
        if (-not $script:TargetAdapter) {
            Write-Log -Message "Please find a network adapter first" -Color "Warning" -LogBox $netLogBox -Theme $script:CurrentTheme
            [System.Windows.Forms.MessageBox]::Show("Please find a network adapter first using the 'Find Unidentified Network' button", "No Adapter", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        $ip = $txtIPAddress.Text.Trim()
        $gateway = $txtGateway.Text.Trim()
        $prefixText = $txtPrefix.Text.Trim()

        # Validate IP address
        if (-not (Test-IPAddress -IPAddress $ip)) {
            Write-Log -Message 'Invalid IP address format. Please enter a valid IPv4 address (e.g., 192.168.1.100)' -Color 'Error' -LogBox $netLogBox -Theme $script:CurrentTheme
            [System.Windows.Forms.MessageBox]::Show("Invalid IP address format!", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        # Validate gateway
        if (-not (Test-IPAddress -IPAddress $gateway)) {
            Write-Log -Message "Invalid gateway format. Please enter a valid IPv4 address" -Color "Error" -LogBox $netLogBox -Theme $script:CurrentTheme
            [System.Windows.Forms.MessageBox]::Show("Invalid gateway format!", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        # Validate prefix
        if (-not (Test-PrefixLength -Prefix $prefixText)) {
            Write-Log -Message "Invalid prefix length. Must be between 0 and 32" -Color "Error" -LogBox $netLogBox -Theme $script:CurrentTheme
            [System.Windows.Forms.MessageBox]::Show("Invalid prefix length! Must be between 0 and 32", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        $prefix = [int]$prefixText
        $script:NewIPAddress = $ip
        $script:NewGateway = $gateway

        $success = Set-NetworkConfiguration -Adapter $script:TargetAdapter -IPAddress $ip -Gateway $gateway -PrefixLength $prefix -LogBox $netLogBox

        if ($success) {
            [System.Windows.Forms.MessageBox]::Show("Network configuration applied successfully!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Error" -LogBox $netLogBox -Theme $script:CurrentTheme
        [System.Windows.Forms.MessageBox]::Show("Error applying configuration: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$btnRestoreDefaults.Add_Click({
    try {
        # Confirm before restoring
        $result = [System.Windows.Forms.MessageBox]::Show(
            "This will restore network adapter to DHCP and remove static IP configuration. Continue?",
            "Confirm Restore Defaults",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )

        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            Restore-NetworkDefaults -LogBox $netLogBox
            [System.Windows.Forms.MessageBox]::Show("Network defaults restored!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)

            # Clear the target adapter
            $script:TargetAdapter = $null
            $script:OriginalConfig = $null
        }
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Error" -LogBox $netLogBox -Theme $script:CurrentTheme
        [System.Windows.Forms.MessageBox]::Show("Error restoring defaults: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# ============================================
# TAB 2: DHCP STATISTICS
# ============================================

$tab2 = New-Object System.Windows.Forms.TabPage
$tab2.Text = "DHCP Statistics"
$tabControl.Controls.Add($tab2)
Add-IconToTab -Tab $tab2 -IconName "Server"

# Info Label
$lblDHCPInfo = New-Object System.Windows.Forms.Label
$lblDHCPInfo.Text = "Collect and analyze DHCP scope statistics from domain DHCP servers"
$lblDHCPInfo.Location = New-Object System.Drawing.Point(15, 15)
$lblDHCPInfo.Size = New-Object System.Drawing.Size(900, 20)
$lblDHCPInfo.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Italic)
$lblDHCPInfo.ForeColor = [System.Drawing.Color]::DarkBlue
$tab2.Controls.Add($lblDHCPInfo)

# Server Configuration Group
$dhcpServerGroupBox = New-Object System.Windows.Forms.GroupBox
$dhcpServerGroupBox.Text = "Server Selection"
$dhcpServerGroupBox.Size = New-Object System.Drawing.Size(560, 150)
$dhcpServerGroupBox.Location = New-Object System.Drawing.Point(10, 40)
$tab2.Controls.Add($dhcpServerGroupBox)

# Server List Label
$lblServerList = New-Object System.Windows.Forms.Label
$lblServerList.Text = "Select DHCP servers to query (check all that apply):"
$lblServerList.Location = New-Object System.Drawing.Point(15, 20)
$lblServerList.Size = New-Object System.Drawing.Size(350, 20)
$lblServerList.ForeColor = [System.Drawing.Color]::DarkGreen
$dhcpServerGroupBox.Controls.Add($lblServerList)

# Refresh Button
$btnRefreshDHCPServers = New-Object System.Windows.Forms.Button
$btnRefreshDHCPServers.Text = "Refresh Server List"
$btnRefreshDHCPServers.Size = New-Object System.Drawing.Size(150, 25)
$btnRefreshDHCPServers.Location = New-Object System.Drawing.Point(370, 17)
$dhcpServerGroupBox.Controls.Add($btnRefreshDHCPServers)

# Last Refresh Label
$script:lblLastRefresh = New-Object System.Windows.Forms.Label
$script:lblLastRefresh.Text = "Last refreshed: Never"
$script:lblLastRefresh.Location = New-Object System.Drawing.Point(530, 21)
$script:lblLastRefresh.Size = New-Object System.Drawing.Size(400, 20)
$script:lblLastRefresh.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$script:lblLastRefresh.ForeColor = [System.Drawing.Color]::Gray
$dhcpServerGroupBox.Controls.Add($script:lblLastRefresh)

# CheckedListBox for server selection
$script:lstDHCPServers = New-Object System.Windows.Forms.CheckedListBox
$script:lstDHCPServers.Size = New-Object System.Drawing.Size(450, 80)
$script:lstDHCPServers.Location = New-Object System.Drawing.Point(15, 45)
$script:lstDHCPServers.CheckOnClick = $true
$dhcpServerGroupBox.Controls.Add($script:lstDHCPServers)

# Select All / None buttons
$btnSelectAll = New-Object System.Windows.Forms.Button
$btnSelectAll.Text = "Select All"
$btnSelectAll.Size = New-Object System.Drawing.Size(100, 25)
$btnSelectAll.Location = New-Object System.Drawing.Point(480, 45)
$dhcpServerGroupBox.Controls.Add($btnSelectAll)

$btnSelectNone = New-Object System.Windows.Forms.Button
$btnSelectNone.Text = "Select None"
$btnSelectNone.Size = New-Object System.Drawing.Size(100, 25)
$btnSelectNone.Location = New-Object System.Drawing.Point(480, 75)
$dhcpServerGroupBox.Controls.Add($btnSelectNone)

# Manual entry option
$lblManual = New-Object System.Windows.Forms.Label
$lblManual.Text = "Or enter manually (comma-separated):"
$lblManual.Location = New-Object System.Drawing.Point(590, 47)
$lblManual.Size = New-Object System.Drawing.Size(250, 20)
$lblManual.ForeColor = [System.Drawing.Color]::DarkGreen
$dhcpServerGroupBox.Controls.Add($lblManual)

$txtSpecificServers = New-Object System.Windows.Forms.TextBox
$txtSpecificServers.Size = New-Object System.Drawing.Size(330, 20)
$txtSpecificServers.Location = New-Object System.Drawing.Point(590, 70)
$txtSpecificServers.MaxLength = 1000
$dhcpServerGroupBox.Controls.Add($txtSpecificServers)

# Note Label
$lblServerNote = New-Object System.Windows.Forms.Label
$lblServerNote.Text = "Note: Servers are cached from Active Directory. If no servers selected/entered, all domain servers will be queried."
$lblServerNote.Location = New-Object System.Drawing.Point(15, 130)
$lblServerNote.Size = New-Object System.Drawing.Size(900, 20)
$lblServerNote.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$lblServerNote.ForeColor = [System.Drawing.Color]::Gray
$dhcpServerGroupBox.Controls.Add($lblServerNote)

# Scope Selection Group
$dhcpScopeGroupBox = New-Object System.Windows.Forms.GroupBox
$dhcpScopeGroupBox.Text = "Scope Selection (Optional)"
$dhcpScopeGroupBox.Size = New-Object System.Drawing.Size(560, 160)
$dhcpScopeGroupBox.Location = New-Object System.Drawing.Point(10, 200)
$tab2.Controls.Add($dhcpScopeGroupBox)

# Label for scope cache
$lblScopeCache = New-Object System.Windows.Forms.Label
$lblScopeCache.Text = "Select specific scopes from cache (leave empty to collect all):"
$lblScopeCache.Size = New-Object System.Drawing.Size(400, 20)
$lblScopeCache.Location = New-Object System.Drawing.Point(15, 20)
$dhcpScopeGroupBox.Controls.Add($lblScopeCache)

# Refresh scope cache button
$script:btnRefreshScopeCache = New-Object System.Windows.Forms.Button
$script:btnRefreshScopeCache.Text = "Refresh Cache"
$script:btnRefreshScopeCache.Size = New-Object System.Drawing.Size(120, 25)
$script:btnRefreshScopeCache.Location = New-Object System.Drawing.Point(420, 17)
$dhcpScopeGroupBox.Controls.Add($script:btnRefreshScopeCache)

# Cache status label
$script:lblScopeCacheStatus = New-Object System.Windows.Forms.Label
$script:lblScopeCacheStatus.Text = "Cache: Not loaded"
$script:lblScopeCacheStatus.Size = New-Object System.Drawing.Size(350, 20)
$script:lblScopeCacheStatus.Location = New-Object System.Drawing.Point(550, 21)
$script:lblScopeCacheStatus.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$script:lblScopeCacheStatus.ForeColor = [System.Drawing.Color]::Gray
$dhcpScopeGroupBox.Controls.Add($script:lblScopeCacheStatus)

# Filter textbox for scope list
$lblScopeListFilter = New-Object System.Windows.Forms.Label
$lblScopeListFilter.Text = "Filter list:"
$lblScopeListFilter.Size = New-Object System.Drawing.Size(60, 20)
$lblScopeListFilter.Location = New-Object System.Drawing.Point(15, 47)
$dhcpScopeGroupBox.Controls.Add($lblScopeListFilter)

$script:txtScopeListFilter = New-Object System.Windows.Forms.TextBox
$script:txtScopeListFilter.Size = New-Object System.Drawing.Size(390, 20)
$script:txtScopeListFilter.Location = New-Object System.Drawing.Point(80, 45)
$script:txtScopeListFilter.MaxLength = 100
$dhcpScopeGroupBox.Controls.Add($script:txtScopeListFilter)

# CheckedListBox for scope selection
$script:lstDHCPScopes = New-Object System.Windows.Forms.CheckedListBox
$script:lstDHCPScopes.Size = New-Object System.Drawing.Size(690, 75)
$script:lstDHCPScopes.Location = New-Object System.Drawing.Point(15, 70)
$script:lstDHCPScopes.CheckOnClick = $true
$dhcpScopeGroupBox.Controls.Add($script:lstDHCPScopes)

# Select All / None buttons for scopes
$btnSelectAllScopes = New-Object System.Windows.Forms.Button
$btnSelectAllScopes.Text = "Select All"
$btnSelectAllScopes.Size = New-Object System.Drawing.Size(100, 30)
$btnSelectAllScopes.Location = New-Object System.Drawing.Point(720, 70)
$dhcpScopeGroupBox.Controls.Add($btnSelectAllScopes)

$btnSelectNoneScopes = New-Object System.Windows.Forms.Button
$btnSelectNoneScopes.Text = "Select None"
$btnSelectNoneScopes.Size = New-Object System.Drawing.Size(100, 30)
$btnSelectNoneScopes.Location = New-Object System.Drawing.Point(720, 105)
$dhcpScopeGroupBox.Controls.Add($btnSelectNoneScopes)

# Auto-match Scope ID checkbox
$script:chkAutoMatchScopes = New-Object System.Windows.Forms.CheckBox
$script:chkAutoMatchScopes.Text = "Auto-select matching Scope IDs"
$script:chkAutoMatchScopes.Size = New-Object System.Drawing.Size(200, 20)
$script:chkAutoMatchScopes.Location = New-Object System.Drawing.Point(720, 140)
$script:chkAutoMatchScopes.Checked = $true
$dhcpScopeGroupBox.Controls.Add($script:chkAutoMatchScopes)

# Note label
$lblScopeNote = New-Object System.Windows.Forms.Label
$lblScopeNote.Text = "Note: Scope cache is separate from collection. Refresh cache to load all scopes, then select specific ones to query."
$lblScopeNote.Location = New-Object System.Drawing.Point(15, 147)
$lblScopeNote.Size = New-Object System.Drawing.Size(900, 15)
$lblScopeNote.Font = New-Object System.Drawing.Font("Arial", 7, [System.Drawing.FontStyle]::Italic)
$lblScopeNote.ForeColor = [System.Drawing.Color]::Gray
$dhcpScopeGroupBox.Controls.Add($lblScopeNote)

# Collection Options Group
$dhcpOptionsGroupBox = New-Object System.Windows.Forms.GroupBox
$dhcpOptionsGroupBox.Text = "Collection Options"
$dhcpOptionsGroupBox.Size = New-Object System.Drawing.Size(560, 100)
$dhcpOptionsGroupBox.Location = New-Object System.Drawing.Point(10, 370)
$tab2.Controls.Add($dhcpOptionsGroupBox)

$chkIncludeDNS = New-Object System.Windows.Forms.CheckBox
$chkIncludeDNS.Text = "Include DNS Server Information"
$chkIncludeDNS.Size = New-Object System.Drawing.Size(250, 20)
$chkIncludeDNS.Location = New-Object System.Drawing.Point(15, 30)
$dhcpOptionsGroupBox.Controls.Add($chkIncludeDNS)

$lblDNSWarning = New-Object System.Windows.Forms.Label
$lblDNSWarning.Text = "(Slower - adds DNS lookup for each scope)"
$lblDNSWarning.Size = New-Object System.Drawing.Size(300, 20)
$lblDNSWarning.Location = New-Object System.Drawing.Point(270, 30)
$lblDNSWarning.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$lblDNSWarning.ForeColor = [System.Drawing.Color]::DarkOrange
$dhcpOptionsGroupBox.Controls.Add($lblDNSWarning)

# Group by Scope ID checkbox (for export aggregation)
$script:chkGroupByScope = New-Object System.Windows.Forms.CheckBox
$script:chkGroupByScope.Text = "Group Results by Scope ID on Export"
$script:chkGroupByScope.Size = New-Object System.Drawing.Size(280, 20)
$script:chkGroupByScope.Location = New-Object System.Drawing.Point(15, 55)
$script:chkGroupByScope.Checked = $false
$dhcpOptionsGroupBox.Controls.Add($script:chkGroupByScope)

$lblGroupWarning = New-Object System.Windows.Forms.Label
$lblGroupWarning.Text = "(Combines redundant scopes into single row per Scope ID)"
$lblGroupWarning.Size = New-Object System.Drawing.Size(350, 20)
$lblGroupWarning.Location = New-Object System.Drawing.Point(300, 55)
$lblGroupWarning.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$lblGroupWarning.ForeColor = [System.Drawing.Color]::DarkGreen
$dhcpOptionsGroupBox.Controls.Add($lblGroupWarning)

# Concurrency limit control
$lblConcurrency = New-Object System.Windows.Forms.Label
$lblConcurrency.Text = "Parallel Operations:"
$lblConcurrency.Size = New-Object System.Drawing.Size(120, 20)
$lblConcurrency.Location = New-Object System.Drawing.Point(600, 30)
$dhcpOptionsGroupBox.Controls.Add($lblConcurrency)

$script:numConcurrency = New-Object System.Windows.Forms.NumericUpDown
$script:numConcurrency.Minimum = 20
$script:numConcurrency.Maximum = 50
$script:numConcurrency.Value = 20
$script:numConcurrency.Size = New-Object System.Drawing.Size(60, 20)
$script:numConcurrency.Location = New-Object System.Drawing.Point(720, 28)
$dhcpOptionsGroupBox.Controls.Add($script:numConcurrency)

$lblConcurrencyNote = New-Object System.Windows.Forms.Label
$lblConcurrencyNote.Text = "(20-50 servers at once)"
$lblConcurrencyNote.Size = New-Object System.Drawing.Size(150, 20)
$lblConcurrencyNote.Location = New-Object System.Drawing.Point(785, 30)
$lblConcurrencyNote.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$lblConcurrencyNote.ForeColor = [System.Drawing.Color]::Gray
$dhcpOptionsGroupBox.Controls.Add($lblConcurrencyNote)

# Actions Group
$dhcpActionsGroupBox = New-Object System.Windows.Forms.GroupBox
$dhcpActionsGroupBox.Text = "Actions"
$dhcpActionsGroupBox.Size = New-Object System.Drawing.Size(560, 65)
$dhcpActionsGroupBox.Location = New-Object System.Drawing.Point(10, 455)
$tab2.Controls.Add($dhcpActionsGroupBox)

$btnCollectDHCP = New-Object System.Windows.Forms.Button
$btnCollectDHCP.Text = "Collect DHCP Statistics"
$btnCollectDHCP.Size = New-Object System.Drawing.Size(200, 35)
$btnCollectDHCP.Location = New-Object System.Drawing.Point(15, 25)
$btnCollectDHCP.BackColor = [System.Drawing.Color]::LightGreen
$dhcpActionsGroupBox.Controls.Add($btnCollectDHCP)

$btnStopDHCP = New-Object System.Windows.Forms.Button
$btnStopDHCP.Text = "Stop"
$btnStopDHCP.Size = New-Object System.Drawing.Size(100, 35)
$btnStopDHCP.Location = New-Object System.Drawing.Point(230, 25)
$btnStopDHCP.BackColor = [System.Drawing.Color]::LightCoral
$btnStopDHCP.Enabled = $false
$dhcpActionsGroupBox.Controls.Add($btnStopDHCP)

$btnExportDHCP = New-Object System.Windows.Forms.Button
$btnExportDHCP.Text = "Export to CSV"
$btnExportDHCP.Size = New-Object System.Drawing.Size(150, 35)
$btnExportDHCP.Location = New-Object System.Drawing.Point(345, 25)
$btnExportDHCP.Enabled = $false
$dhcpActionsGroupBox.Controls.Add($btnExportDHCP)

$lblExportHint = New-Object System.Windows.Forms.Label
$lblExportHint.Text = "Results auto-exported after collection. Use Export to re-export."
$lblExportHint.Size = New-Object System.Drawing.Size(400, 20)
$lblExportHint.Location = New-Object System.Drawing.Point(510, 33)
$lblExportHint.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$lblExportHint.ForeColor = [System.Drawing.Color]::Gray
$dhcpActionsGroupBox.Controls.Add($lblExportHint)

# Collection Log Label (right side)
$lblCollectionLog = New-Object System.Windows.Forms.Label
$lblCollectionLog.Text = "Collection Log"
$lblCollectionLog.Location = New-Object System.Drawing.Point(600, 15)
$lblCollectionLog.Size = New-Object System.Drawing.Size(200, 20)
$lblCollectionLog.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$lblCollectionLog.ForeColor = [System.Drawing.Color]::DarkBlue
$tab2.Controls.Add($lblCollectionLog)

# DHCP Log (right side panel)
$dhcpLogBox = New-Object System.Windows.Forms.RichTextBox
$dhcpLogBox.Size = New-Object System.Drawing.Size(320, 480)
$dhcpLogBox.Location = New-Object System.Drawing.Point(600, 40)
$dhcpLogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$dhcpLogBox.ReadOnly = $true
$dhcpLogBox.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
$dhcpLogBox.WordWrap = $false
$dhcpLogBox.HideSelection = $false
$dhcpLogBox.DetectUrls = $false
$dhcpLogBox.Multiline = $true
$dhcpLogBox.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$tab2.Controls.Add($dhcpLogBox)

# Event Handlers for Tab 2
$btnCollectDHCP.Add_Click({
    try {
        $btnCollectDHCP.Enabled = $false
        $btnStopDHCP.Enabled = $true
        $btnExportDHCP.Enabled = $false
        $script:dhcpStopRequested = $false

        # Check for selected scopes from cache (new approach - takes precedence)
        $selectedScopes = @()
        if ($script:lstDHCPScopes.CheckedItems.Count -gt 0) {
            # Extract ScopeId and Server from DisplayName format: "Name (ScopeId) - Server"
            foreach ($item in $script:lstDHCPScopes.CheckedItems) {
                $displayName = $item.ToString()
                # Find matching scope in cache
                $matchingScope = $script:allDHCPScopes | Where-Object { $_.DisplayName -eq $displayName }
                if ($matchingScope) {
                    # Validate that essential properties are not null/empty
                    if ([string]::IsNullOrWhiteSpace($matchingScope.Server) -or
                        [string]::IsNullOrWhiteSpace($matchingScope.ScopeId)) {
                        Write-Log -Message "WARNING: Skipping scope with missing Server or ScopeId: $displayName" -Color "Warning" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                        continue
                    }

                    # Explicitly convert to strings to ensure proper serialization to background job
                    $selectedScopes += [PSCustomObject]@{
                        ScopeId = [string]$matchingScope.ScopeId
                        Server = [string]$matchingScope.Server
                        Name = [string]$matchingScope.Name
                    }
                }
            }
            Write-Log -Message "Using $($selectedScopes.Count) pre-selected scope(s) from cache" -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        }

        # Parse scope filters (old approach - only used if no scopes selected from cache)
        $scopeFilters = @()
        if ($selectedScopes.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($txtScopeFilter.Text)) {
            $scopeFilters = $txtScopeFilter.Text.Split(',') | ForEach-Object { $_.Trim() }
            Write-Log -Message "No scopes selected - using filter-based collection" -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        }

        # Gather servers from both CheckedListBox and manual entry
        $specificServers = @()

        # 1. Get checked servers from the list
        $checkedServers = @()
        Write-Log -Message "DEBUG: CheckedItems count: $($script:lstDHCPServers.CheckedItems.Count)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

        foreach ($item in $script:lstDHCPServers.CheckedItems) {
            # Convert to string and log
            $itemStr = $item.ToString()
            Write-Log -Message "DEBUG: Item type: $($item.GetType().FullName)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            Write-Log -Message "DEBUG: Item raw value: '$itemStr'" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            Write-Log -Message "DEBUG: Item length: $($itemStr.Length)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

            # Extract DNS name from "DnsName (IPAddress)" format
            if ($itemStr -match '^(.+?)\s+\(') {
                $serverName = $matches[1].Trim()
                $checkedServers += $serverName
                Write-Log -Message "DEBUG: Regex MATCHED - Extracted: '$serverName'" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            } else {
                Write-Log -Message "DEBUG: Regex FAILED - No match for pattern '^(.+?)\s+\('" -Color "Warning" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                # Try alternative: just use the whole string if no parentheses
                if (-not [string]::IsNullOrWhiteSpace($itemStr)) {
                    Write-Log -Message "DEBUG: Using entire string as server name" -Color "Warning" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                    $checkedServers += $itemStr.Trim()
                }
            }
        }

        # 2. Get manually entered servers
        $manualServers = @()
        if (-not [string]::IsNullOrWhiteSpace($txtSpecificServers.Text)) {
            $rawServers = $txtSpecificServers.Text.Split(',') | ForEach-Object { $_.Trim() }

            $validServers = @()
            $invalidServers = @()

            foreach ($server in $rawServers) {
                if (-not [string]::IsNullOrWhiteSpace($server)) {
                    if ($server -match '^[a-zA-Z0-9][a-zA-Z0-9.\-_]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$') {
                        $validServers += $server
                    } else {
                        $invalidServers += $server
                    }
                }
            }

            if ($invalidServers.Count -gt 0) {
                $invalidList = $invalidServers -join ', '
                Write-Log -Message "Warning: Invalid server name(s) detected and will be skipped: $invalidList" -Color "Red" -LogBox $dhcpLogBox
            }

            if ($validServers.Count -eq 0 -and $invalidServers.Count -gt 0) {
                Write-Log -Message "Error: No valid servers specified. Operation cancelled." -Color "Red" -LogBox $dhcpLogBox
                $btnCollectDHCP.Enabled = $true
                return
            }

            $manualServers = $validServers
        }

        # 3. Combine both sources (remove duplicates)
        Write-Log -Message "DEBUG: checkedServers array contents: $($checkedServers -join ' | ')" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        Write-Log -Message "DEBUG: checkedServers count: $($checkedServers.Count)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

        # Combine and filter - ensure we always have a proper array (even if empty)
        $combinedServers = @($checkedServers) + @($manualServers)
        $specificServers = @($combinedServers | Where-Object {
            $_ -ne $null -and
            -not [string]::IsNullOrWhiteSpace($_)
        } | Select-Object -Unique)

        Write-Log -Message "DEBUG: specificServers after combine: $($specificServers -join ' | ')" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        Write-Log -Message "DEBUG: specificServers count: $($specificServers.Count)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

        # Log server sources
        if ($checkedServers.Count -gt 0) {
            Write-Log -Message "Using $($checkedServers.Count) selected server(s) from list" -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        }
        if ($manualServers.Count -gt 0) {
            Write-Log -Message "Using $($manualServers.Count) manually entered server(s)" -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        }
        if ($specificServers.Count -eq 0) {
            Write-Log -Message "No specific servers selected - will query all domain servers" -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        }

        $includeDNS = $chkIncludeDNS.Checked

        # Call DHCP collection function in background to keep UI responsive
        Write-Log -Message "Starting DHCP statistics collection in background..." -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

        # Log what we're passing to the background operation
        Write-Log -Message "DEBUG: Scope filters: $($scopeFilters.Count) items" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        Write-Log -Message "DEBUG: Specific servers: $($specificServers.Count) items - $($specificServers -join ', ')" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        Write-Log -Message "DEBUG: Include DNS: $includeDNS" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

        # Run collection in background
        $script:dhcpBackgroundTimer = Invoke-BackgroundOperation -ScriptBlock {
            param($selectedScopes, $filters, $servers, $dns, $stopRef, $scriptRoot)

            $debugLog = @()

            try {
                $debugLog += "Background: Starting collection"
                $debugLog += "Background: SelectedScopes count = $($selectedScopes.Count)"

                # Filter out null or invalid scopes to prevent errors
                $selectedScopes = @($selectedScopes | Where-Object {
                    $_ -ne $null -and
                    -not [string]::IsNullOrWhiteSpace($_.Server) -and
                    -not [string]::IsNullOrWhiteSpace($_.ScopeId)
                })
                $debugLog += "Background: SelectedScopes after filtering = $($selectedScopes.Count)"

                $debugLog += "Background: Filters = $($filters -join ', ')"
                $debugLog += "Background: Filters count = $($filters.Count)"

                # Filter out null/empty servers to prevent errors
                $servers = @($servers | Where-Object { $_ -ne $null -and -not [string]::IsNullOrWhiteSpace($_) })

                $debugLog += "Background: Servers = $($servers -join ', ')"
                $debugLog += "Background: Servers count = $($servers.Count)"
                if ($servers.Count -gt 0) {
                    $debugLog += "Background: Servers type = $($servers.GetType().FullName)"
                    $debugLog += "Background:   - First server: '$($servers[0])'"
                    if ($servers[0] -ne $null) {
                        $debugLog += "Background:   - First server type: $($servers[0].GetType().FullName)"
                        $debugLog += "Background:   - First server length: $($servers[0].Length)"
                    }
                }
                $debugLog += "Background: IncludeDNS = $dns"

                # Import required modules in background runspace
                # HelperFunctions first (provides Write-Log used by DHCPFunctions)
                $helperPath = Join-Path $scriptRoot "modules\HelperFunctions.psm1"
                Import-Module $helperPath -Force -ErrorAction Stop
                $debugLog += "Background: Imported HelperFunctions"

                # Then DHCPFunctions
                $dhcpPath = Join-Path $scriptRoot "modules\DHCPFunctions.psm1"
                Import-Module $dhcpPath -Force -ErrorAction Stop
                $debugLog += "Background: Imported DHCPFunctions"

                # Call collection function
                $debugLog += "Background: About to call Get-DHCPScopeStatistics"
                $debugLog += "Background:   - SelectedScopes count: $($selectedScopes.Count)"
                $debugLog += "Background:   - ScopeFilters count: $($filters.Count)"
                $debugLog += "Background:   - SpecificServers count: $($servers.Count)"
                if ($servers.Count -gt 0) {
                    $debugLog += "Background:   - First server: $($servers[0])"
                }
                $debugLog += "Background:   - IncludeDNS: $dns"

                $result = Get-DHCPScopeStatistics -SelectedScopes $selectedScopes -ScopeFilters $filters -SpecificServers $servers -IncludeDNS $dns -StopToken $stopRef

                $debugLog += "Background: Collection completed"
                $debugLog += "Background: Result Success = $($result.Success)"
                $debugLog += "Background: Result Results.Count = $($result.Results.Count)"
                $debugLog += "Background: Result Message = $($result.Message)"
                $debugLog += "Background: Result Error = $($result.Error)"

                if ($result.Results) {
                    $debugLog += "Background: Results type = $($result.Results.GetType().FullName)"
                    $debugLog += "Background: First result = $($result.Results | Select-Object -First 1 | Out-String)"
                }

                # Add debug log to result
                $result | Add-Member -NotePropertyName DebugLog -NotePropertyValue $debugLog -Force

                # Ensure we return the result
                return $result
            }
            catch {
                $debugLog += "Background: EXCEPTION - $($_.Exception.Message)"
                $debugLog += "Background: Stack trace - $($_.ScriptStackTrace)"

                # Return error object if something fails
                return [PSCustomObject]@{
                    Success = $false
                    Results = @()
                    Error = "Background operation error: $($_.Exception.Message)"
                    DebugLog = $debugLog
                }
            }

        } -ArgumentList @((,$selectedScopes), (,$scopeFilters), (,$specificServers), $includeDNS, ([ref]$script:dhcpStopRequested), $scriptPath) -OnComplete {
            param($result)

            # Re-enable buttons
            $btnCollectDHCP.Enabled = $true
            $btnStopDHCP.Enabled = $false

            # PowerShell.EndInvoke returns a PSDataCollection - extract the actual result object
            Write-Log -Message "DEBUG: Raw result type: $($result.GetType().FullName)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            Write-Log -Message "DEBUG: Raw result count: $($result.Count)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

            # Check what's actually in the result collection
            if ($result.Count -gt 0) {
                Write-Log -Message "DEBUG: result[0] type: $($result[0].GetType().FullName)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                if ($result[0].PSObject.Properties.Name -contains 'Success') {
                    Write-Log -Message "DEBUG: result[0] HAS Success property" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                } else {
                    Write-Log -Message "DEBUG: result[0] DOES NOT have Success property" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                    Write-Log -Message "DEBUG: result[0] properties: $($result[0].PSObject.Properties.Name -join ', ')" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                }
            }

            # Extract actual result - avoid using if return value due to PowerShell array unwrapping
            $actualResult = $null
            if ($result -is [System.Collections.ICollection] -and $result.Count -gt 0) {
                Write-Log -Message "DEBUG: Extracting from PSDataCollection (count=$($result.Count))" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                # Check if result[0] has the expected structure
                if ($result[0].PSObject.Properties.Name -contains 'Success') {
                    Write-Log -Message "DEBUG: result[0] has Success property - using it" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                    $actualResult = $result[0]
                } else {
                    Write-Log -Message "DEBUG: result[0] does NOT have Success - using entire result" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                    $actualResult = $result
                }
            } else {
                $actualResult = $result
            }

            Write-Log -Message "DEBUG: ActualResult type: $($actualResult.GetType().FullName)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            if ($actualResult.PSObject.Properties.Name) {
                Write-Log -Message "DEBUG: ActualResult properties: $($actualResult.PSObject.Properties.Name -join ', ')" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            }

            # Display debug log from background runspace
            if ($actualResult -and $actualResult.DebugLog) {
                Write-Log -Message "===== Background Runspace Debug Log =====" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                foreach ($logLine in $actualResult.DebugLog) {
                    Write-Log -Message $logLine -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                }
                Write-Log -Message "===== End Background Debug Log =====" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            }

            # Debug: Log result structure
            if ($actualResult) {
                Write-Log -Message "DEBUG: actualResult.Success = $($actualResult.Success)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                Write-Log -Message "DEBUG: actualResult.Results type = $($actualResult.Results.GetType().FullName)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                Write-Log -Message "DEBUG: actualResult.Results.Count = $($actualResult.Results.Count)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

                if ($actualResult.Results -and $actualResult.Results.Count -gt 0) {
                    Write-Log -Message "DEBUG: Listing all $($actualResult.Results.Count) scope(s) returned:" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                    for ($i = 0; $i -lt $actualResult.Results.Count; $i++) {
                        $scope = $actualResult.Results[$i]
                        Write-Log -Message "DEBUG:   [$($i+1)] ScopeId=$($scope.ScopeId), Server=$($scope.DHCPServer), Desc='$($scope.Description)'" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                    }
                }
            } else {
                Write-Log -Message "DEBUG: actualResult is NULL" -Color "Error" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            }

            if ($actualResult -and $actualResult.Success) {
                Write-Log -Message "DEBUG: Entering Success=true branch" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                Write-Log -Message "DEBUG: actualResult.Results is array? $($actualResult.Results -is [System.Collections.ICollection])" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                Write-Log -Message "DEBUG: actualResult.Results.Count before assignment = $($actualResult.Results.Count)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

                # Convert ArrayList to regular array to avoid assignment issues
                if ($actualResult.Results -and $actualResult.Results.Count -gt 0) {
                    $script:dhcpResults = @()
                    foreach ($item in $actualResult.Results) {
                        $script:dhcpResults += $item
                    }
                } else {
                    $script:dhcpResults = @()
                }

                Write-Log -Message "DEBUG: Assigned to script:dhcpResults, count = $($script:dhcpResults.Count)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                Write-Log -Message "DEBUG: script:dhcpResults type = $($script:dhcpResults.GetType().FullName)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                Write-Log -Message "DEBUG: btnExportDHCP state BEFORE enable = $($btnExportDHCP.Enabled)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

                if ($script:dhcpResults.Count -gt 0) {
                    Write-Log -Message "DEBUG: Count > 0, enabling export button..." -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                    $btnExportDHCP.Enabled = $true
                    Write-Log -Message "DEBUG: btnExportDHCP state AFTER enable = $($btnExportDHCP.Enabled)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                    Write-Log -Message "Collection complete! Found $($script:dhcpResults.Count) scope(s)" -Color "Success" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

                # Auto-export if enabled
                if ($script:Settings.AutoExportAfterCollection) {
                    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                    $exportPath = Join-Path -Path $script:outputDir -ChildPath "DHCPScopeStats_$timestamp.csv"

                    if (-not (Test-Path $script:outputDir)) {
                        New-Item -ItemType Directory -Path $script:outputDir -Force | Out-Null
                    }

                    Write-Log -Message "Auto-exporting $($script:dhcpResults.Count) scope(s)..." -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

                    # Apply grouping if enabled
                    $dataToExport = $script:dhcpResults
                    if ($script:chkGroupByScope.Checked) {
                        Write-Log -Message "Grouping redundant scopes by Scope ID..." -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                        $dataToExport = Group-DHCPScopesByScopeId -ScopeData $script:dhcpResults
                        Write-Log -Message "Grouped into $($dataToExport.Count) unique scope(s)" -Color "Success" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                    }

                    # Format data with specific columns in order (matching optimized script)
                    if ($includeDNS) {
                        $exportData = $dataToExport | Select-Object ScopeId, DHCPServer, Description, AddressesFree, AddressesInUse, PercentageInUse, DNSServers
                    } else {
                        $exportData = $dataToExport | Select-Object ScopeId, DHCPServer, Description, AddressesFree, AddressesInUse, PercentageInUse
                    }

                    $exportedPath = Export-ToCSV -Data $exportData -FilePath $exportPath -IncludeTimestamp:$script:Settings.IncludeTimestampInFilename
                    Add-ExportHistory -Settings $script:Settings -FilePath $exportedPath -Operation "DHCP Statistics" -Format "CSV"
                    Write-Log -Message "Auto-exported to: $exportedPath" -Color "Success" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                }
            } else {
                Write-Log -Message "No DHCP scopes found matching criteria" -Color "Warning" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            }
        } elseif ($actualResult) {
            # Even if not successful, save any partial results collected before stop/error
            if ($actualResult.Results -and $actualResult.Results.Count -gt 0) {
                $script:dhcpResults = @($actualResult.Results)
                $btnExportDHCP.Enabled = $true
                Write-Log -Message "Partial results available: $($script:dhcpResults.Count) scopes collected before operation was stopped" -Color "Warning" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            }

            Write-Log -Message "Error: $($actualResult.Error)" -Color "Error" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

            # Only show error dialog if not a user-requested cancellation
            if ($actualResult.Error -notlike "*cancelled by user*") {
                [System.Windows.Forms.MessageBox]::Show("DHCP collection failed: $($actualResult.Error)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        } else {
            Write-Log -Message "DHCP collection returned no data" -Color "Error" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            [System.Windows.Forms.MessageBox]::Show("DHCP collection failed - no data returned", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }

            # Update status bar
            Update-StatusBar -Status "Ready" -StatusLabel $script:statusLabel -ProgressBar $script:progressBar -ProgressLabel $script:progressLabel
            Hide-Progress -StatusBar $script:StatusBarPanels

        } -Form $mainForm

    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        $btnCollectDHCP.Enabled = $true
        $btnStopDHCP.Enabled = $false
    }
})

$btnStopDHCP.Add_Click({
    Write-Log -Message "Stop requested by user..." -Color "Warning" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
    $script:dhcpStopRequested = $true
    $btnStopDHCP.Enabled = $false
})

# Event Handler: Refresh DHCP Server List
$btnRefreshDHCPServers.Add_Click({
    try {
        $btnRefreshDHCPServers.Enabled = $false
        Write-Log -Message "Discovering DHCP servers from Active Directory..." -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

        # Call the cache update function which discovers and caches servers
        $servers = Update-DHCPServerCache

        if ($servers -and $servers.Count -gt 0) {
            # Clear and populate the CheckedListBox
            $script:lstDHCPServers.Items.Clear()

            foreach ($server in $servers) {
                $displayText = "$($server.DnsName) ($($server.IPAddress))"
                $script:lstDHCPServers.Items.Add($displayText) | Out-Null
            }

            # Update last refresh timestamp
            $script:lblLastRefresh.Text = "Last refreshed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

            Write-Log -Message "Found $($servers.Count) DHCP server(s)" -Color "Success" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        } else {
            Write-Log -Message "No DHCP servers found in Active Directory" -Color "Warning" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            $script:lstDHCPServers.Items.Clear()
            $script:lblLastRefresh.Text = "Last refreshed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') (no servers found)"
        }

        $btnRefreshDHCPServers.Enabled = $true
    } catch {
        Write-Log -Message "Error refreshing server list: $($_.Exception.Message)" -Color "Error" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        $btnRefreshDHCPServers.Enabled = $true
    }
})

# Event Handler: Select All Servers
$btnSelectAll.Add_Click({
    for ($i = 0; $i -lt $script:lstDHCPServers.Items.Count; $i++) {
        $script:lstDHCPServers.SetItemChecked($i, $true)
    }
})

# Event Handler: Select None (uncheck all)
$btnSelectNone.Add_Click({
    for ($i = 0; $i -lt $script:lstDHCPServers.Items.Count; $i++) {
        $script:lstDHCPServers.SetItemChecked($i, $false)
    }
})

# Event Handler: Refresh Scope Cache
$script:btnRefreshScopeCache.Add_Click({
    try {
        Write-Log -Message "Refreshing scope cache..." -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        $script:btnRefreshScopeCache.Enabled = $false
        $script:lblScopeCacheStatus.Text = "Cache: Updating..."
        $script:lblScopeCacheStatus.ForeColor = [System.Drawing.Color]::Orange

        # Get selected servers or use all if none selected
        $serversToQuery = @()
        if ($script:lstDHCPServers.CheckedItems.Count -gt 0) {
            foreach ($item in $script:lstDHCPServers.CheckedItems) {
                $itemStr = $item.ToString()
                if ($itemStr -match '^(.+?)\s+\(') {
                    $serversToQuery += $matches[1].Trim()
                } else {
                    $serversToQuery += $itemStr.Trim()
                }
            }
        }

        # Get concurrency limit from UI
        $throttleLimit = [int]$script:numConcurrency.Value

        # Update cache (runs in parallel now)
        $scopes = if ($serversToQuery.Count -gt 0) {
            Update-DHCPScopeCache -Servers $serversToQuery -ThrottleLimit $throttleLimit
        } else {
            Update-DHCPScopeCache -ThrottleLimit $throttleLimit
        }

        # Store all scopes for filtering
        $script:allDHCPScopes = $scopes

        # Populate list with display names
        $script:lstDHCPScopes.Items.Clear()
        foreach ($scope in $scopes) {
            $script:lstDHCPScopes.Items.Add($scope.DisplayName) | Out-Null
        }

        $script:lblScopeCacheStatus.Text = "Cache: $($scopes.Count) scope(s) loaded ($(Get-Date -Format 'HH:mm:ss'))"
        $script:lblScopeCacheStatus.ForeColor = [System.Drawing.Color]::Green
        Write-Log -Message "Scope cache refreshed: $($scopes.Count) scope(s) found" -Color "Success" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

    } catch {
        $script:lblScopeCacheStatus.Text = "Cache: Error"
        $script:lblScopeCacheStatus.ForeColor = [System.Drawing.Color]::Red
        Write-Log -Message "Error refreshing scope cache: $($_.Exception.Message)" -Color "Error" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
    } finally {
        $script:btnRefreshScopeCache.Enabled = $true
    }
})

# Event Handler: Scope List Filter (real-time filtering)
$script:txtScopeListFilter.Add_TextChanged({
    if (-not $script:allDHCPScopes) {
        return
    }

    $filterText = $script:txtScopeListFilter.Text.Trim()
    $script:lstDHCPScopes.Items.Clear()

    if ([string]::IsNullOrWhiteSpace($filterText)) {
        # No filter - show all
        foreach ($scope in $script:allDHCPScopes) {
            $script:lstDHCPScopes.Items.Add($scope.DisplayName) | Out-Null
        }
    } else {
        # Filter by DisplayName (case-insensitive)
        $filterUpper = $filterText.ToUpper()
        foreach ($scope in $script:allDHCPScopes) {
            if ($scope.DisplayName.ToUpper().Contains($filterUpper)) {
                $script:lstDHCPScopes.Items.Add($scope.DisplayName) | Out-Null
            }
        }
    }
})

# Event Handler: Select All Scopes
$btnSelectAllScopes.Add_Click({
    for ($i = 0; $i -lt $script:lstDHCPScopes.Items.Count; $i++) {
        $script:lstDHCPScopes.SetItemChecked($i, $true)
    }
})

# Event Handler: Select None Scopes
$btnSelectNoneScopes.Add_Click({
    for ($i = 0; $i -lt $script:lstDHCPScopes.Items.Count; $i++) {
        $script:lstDHCPScopes.SetItemChecked($i, $false)
    }
})

# Event Handler: Auto-match Scope IDs when checking a scope
$script:isAutoSelecting = $false
$script:lstDHCPScopes.Add_ItemCheck({
    param($sender, $e)

    try {
        # Only auto-select if the feature is enabled and we're not already in an auto-select operation
        if ($script:chkAutoMatchScopes.Checked -and -not $script:isAutoSelecting) {
            # Only act when checking (not unchecking)
            if ($e.NewValue -eq [System.Windows.Forms.CheckState]::Checked) {
                # Validate that cache exists
                if (-not $script:allDHCPScopes -or $script:allDHCPScopes.Count -eq 0) {
                    return
                }

                # Get the scope that was just checked
                $checkedDisplayName = $script:lstDHCPScopes.Items[$e.Index].ToString()

                # Find the matching scope in cache to get its ScopeId
                $checkedScope = $script:allDHCPScopes | Where-Object { $_.DisplayName -eq $checkedDisplayName } | Select-Object -First 1

                if ($checkedScope -and -not [string]::IsNullOrWhiteSpace($checkedScope.ScopeId)) {
                    # Build a map of visible items for faster lookup (only search filtered list)
                    $visibleScopeMap = @{}
                    for ($i = 0; $i -lt $script:lstDHCPScopes.Items.Count; $i++) {
                        $item = $script:lstDHCPScopes.Items[$i]
                        if ($item) {
                            $displayName = $item.ToString()
                            $scope = $script:allDHCPScopes | Where-Object { $_.DisplayName -eq $displayName } | Select-Object -First 1
                            if ($scope) {
                                $visibleScopeMap[$i] = $scope
                            }
                        }
                    }

                    # Capture all needed variables for the closure
                    $targetScopeId = $checkedScope.ScopeId
                    $checkedIndex = $e.Index
                    $listBox = $script:lstDHCPScopes

                    # Log for debugging
                    Write-Log -Message "Auto-select: Looking for scopes with ScopeId=$targetScopeId (searching $($visibleScopeMap.Count) visible items)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

                    # Set flag to prevent infinite recursion from the auto-select triggering itself
                    $script:isAutoSelecting = $true

                    # Use a timer to defer the selection until after this event completes
                    $autoSelectTimer = New-Object System.Windows.Forms.Timer
                    $autoSelectTimer.Interval = 5  # Reduced from 10ms to 5ms for faster response
                    $autoSelectTimer.Add_Tick({
                        try {
                            # Validate controls still exist
                            if (-not $listBox -or $listBox.IsDisposed) {
                                return
                            }

                            if (-not $visibleScopeMap -or $visibleScopeMap.Count -eq 0) {
                                return
                            }

                            $matchCount = 0
                            # Find all scopes with the same ScopeId and check them - only search visible items
                            foreach ($index in $visibleScopeMap.Keys) {
                                if ($index -ne $checkedIndex -and -not $listBox.GetItemChecked($index)) {
                                    $scope = $visibleScopeMap[$index]

                                    if ($scope -and $scope.ScopeId -eq $targetScopeId) {
                                        $listBox.SetItemChecked($index, $true)
                                        $matchCount++
                                    }
                                }
                            }

                            # Log results
                            if ($matchCount -gt 0) {
                                Write-Log -Message "Auto-select: Selected $matchCount additional scope(s) with matching ScopeId" -Color "Success" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                            } else {
                                Write-Log -Message "Auto-select: No additional scopes found with ScopeId=$targetScopeId" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                            }
                        } catch {
                            # Log error for debugging
                            try {
                                Write-Log -Message "Auto-select error: $($_.Exception.Message)" -Color "Warning" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                            } catch {
                                # Ignore logging errors
                            }
                        } finally {
                            # Stop the timer and reset flag
                            try {
                                $autoSelectTimer.Stop()
                                $autoSelectTimer.Dispose()
                            } catch {
                                # Ignore disposal errors
                            }
                            $script:isAutoSelecting = $false
                        }
                    })
                    $autoSelectTimer.Start()
                }
            }
        }
    } catch {
        # Prevent unhandled exceptions from crashing the application
        # Reset flag to avoid lock-up - don't log as that could cause additional errors
        $script:isAutoSelecting = $false
    }
})

$btnExportDHCP.Add_Click({
    try {
        # Check if results exist and have data
        if (-not $script:dhcpResults -or $script:dhcpResults.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No DHCP results to export. Please collect statistics first.", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "DHCPScopeStats_$timestamp.csv"

        if (-not (Test-Path $script:outputDir)) {
            New-Item -ItemType Directory -Path $script:outputDir -Force | Out-Null
        }

        Write-Log -Message "Exporting $($script:dhcpResults.Count) scope(s) to CSV..." -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

        # Apply grouping if enabled
        $dataToExport = $script:dhcpResults
        if ($script:chkGroupByScope.Checked) {
            Write-Log -Message "Grouping redundant scopes by Scope ID..." -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            $dataToExport = Group-DHCPScopesByScopeId -ScopeData $script:dhcpResults
            Write-Log -Message "Grouped into $($dataToExport.Count) unique scope(s)" -Color "Success" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        }

        # Format data with specific columns in order (check if DNSServers column exists)
        $hasDNSColumn = $dataToExport[0].PSObject.Properties.Name -contains 'DNSServers'
        if ($hasDNSColumn) {
            $exportData = $dataToExport | Select-Object ScopeId, DHCPServer, Description, AddressesFree, AddressesInUse, PercentageInUse, DNSServers
        } else {
            $exportData = $dataToExport | Select-Object ScopeId, DHCPServer, Description, AddressesFree, AddressesInUse, PercentageInUse
        }

        $exportedPath = Export-ToCSV -Data $exportData -FilePath $csvPath -IncludeTimestamp:$script:Settings.IncludeTimestampInFilename

        Write-Log -Message "Exported to: $exportedPath" -Color "Success" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        [System.Windows.Forms.MessageBox]::Show("Export successful!`n`n$exportedPath", "Export Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)

        # Add to export history
        Add-ExportHistory -Settings $script:Settings -FilePath $exportedPath -Operation "DHCP Statistics" -Format "CSV"

    } catch {
        Write-Log -Message "Error exporting: $($_.Exception.Message)" -Color "Error" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        [System.Windows.Forms.MessageBox]::Show("Error exporting: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# ============================================
# TAB 3: DNA CENTER (REDESIGNED WITH TREEVIEW)
# ============================================

$tab3 = New-Object System.Windows.Forms.TabPage
$tab3.Text = "DNA Center"
$tabControl.Controls.Add($tab3)
Add-IconToTab -Tab $tab3 -IconName "DNA"

# Connection Group
$dnaConnGroupBox = New-Object System.Windows.Forms.GroupBox
$dnaConnGroupBox.Text = "DNA Center Connection"
$dnaConnGroupBox.Size = New-Object System.Drawing.Size(940, 140)
$dnaConnGroupBox.Location = New-Object System.Drawing.Point(10, 10)
$tab3.Controls.Add($dnaConnGroupBox)

# Server Label
$lblDNAServer = New-Object System.Windows.Forms.Label
$lblDNAServer.Text = "DNA Center Server:"
$lblDNAServer.Size = New-Object System.Drawing.Size(120, 20)
$lblDNAServer.Location = New-Object System.Drawing.Point(20, 30)
$dnaConnGroupBox.Controls.Add($lblDNAServer)

# Server ComboBox
$comboDNAServer = New-Object System.Windows.Forms.ComboBox
$comboDNAServer.Size = New-Object System.Drawing.Size(350, 20)
$comboDNAServer.Location = New-Object System.Drawing.Point(150, 28)
$comboDNAServer.DropDownStyle = "DropDownList"
foreach ($server in $global:dnaCenterServers) {
    $comboDNAServer.Items.Add("$($server.Name) - $($server.Url)") | Out-Null
}
if ($comboDNAServer.Items.Count -gt 0) {
    $comboDNAServer.SelectedIndex = 0
}
$dnaConnGroupBox.Controls.Add($comboDNAServer)

# Username Label
$lblDNAUser = New-Object System.Windows.Forms.Label
$lblDNAUser.Text = "Username:"
$lblDNAUser.Size = New-Object System.Drawing.Size(120, 20)
$lblDNAUser.Location = New-Object System.Drawing.Point(20, 65)
$dnaConnGroupBox.Controls.Add($lblDNAUser)

# Username TextBox
$txtDNAUser = New-Object System.Windows.Forms.TextBox
$txtDNAUser.Size = New-Object System.Drawing.Size(200, 20)
$txtDNAUser.Location = New-Object System.Drawing.Point(150, 63)
$dnaConnGroupBox.Controls.Add($txtDNAUser)

# Password Label
$lblDNAPass = New-Object System.Windows.Forms.Label
$lblDNAPass.Text = "Password:"
$lblDNAPass.Size = New-Object System.Drawing.Size(120, 20)
$lblDNAPass.Location = New-Object System.Drawing.Point(20, 100)
$dnaConnGroupBox.Controls.Add($lblDNAPass)

# Password TextBox
$txtDNAPass = New-Object System.Windows.Forms.TextBox
$txtDNAPass.Size = New-Object System.Drawing.Size(200, 20)
$txtDNAPass.Location = New-Object System.Drawing.Point(150, 98)
$txtDNAPass.PasswordChar = '*'
$dnaConnGroupBox.Controls.Add($txtDNAPass)

# Connect Button
$btnDNAConnect = New-Object System.Windows.Forms.Button
$btnDNAConnect.Text = "Connect"
$btnDNAConnect.Size = New-Object System.Drawing.Size(120, 30)
$btnDNAConnect.Location = New-Object System.Drawing.Point(370, 63)
$dnaConnGroupBox.Controls.Add($btnDNAConnect)

# Load Devices Button
$btnLoadDevices = New-Object System.Windows.Forms.Button
$btnLoadDevices.Text = "Load Devices"
$btnLoadDevices.Size = New-Object System.Drawing.Size(120, 30)
$btnLoadDevices.Location = New-Object System.Drawing.Point(500, 63)
$btnLoadDevices.Enabled = $false
$dnaConnGroupBox.Controls.Add($btnLoadDevices)

# Device Filter Group
$dnaFilterGroupBox = New-Object System.Windows.Forms.GroupBox
$dnaFilterGroupBox.Text = "Device Filtering (Optional)"
$dnaFilterGroupBox.Size = New-Object System.Drawing.Size(940, 100)
$dnaFilterGroupBox.Location = New-Object System.Drawing.Point(10, 160)
$tab3.Controls.Add($dnaFilterGroupBox)

# Hostname Filter
$lblFilterHostname = New-Object System.Windows.Forms.Label
$lblFilterHostname.Text = "Hostname:"
$lblFilterHostname.Size = New-Object System.Drawing.Size(80, 20)
$lblFilterHostname.Location = New-Object System.Drawing.Point(20, 30)
$dnaFilterGroupBox.Controls.Add($lblFilterHostname)

$txtFilterHostname = New-Object System.Windows.Forms.TextBox
$txtFilterHostname.Size = New-Object System.Drawing.Size(150, 20)
$txtFilterHostname.Location = New-Object System.Drawing.Point(110, 28)
$txtFilterHostname.Enabled = $false
$dnaFilterGroupBox.Controls.Add($txtFilterHostname)

# IP Address Filter
$lblFilterIPAddress = New-Object System.Windows.Forms.Label
$lblFilterIPAddress.Text = "IP Address:"
$lblFilterIPAddress.Size = New-Object System.Drawing.Size(80, 20)
$lblFilterIPAddress.Location = New-Object System.Drawing.Point(280, 30)
$dnaFilterGroupBox.Controls.Add($lblFilterIPAddress)

$txtFilterIPAddress = New-Object System.Windows.Forms.TextBox
$txtFilterIPAddress.Size = New-Object System.Drawing.Size(150, 20)
$txtFilterIPAddress.Location = New-Object System.Drawing.Point(370, 28)
$txtFilterIPAddress.Enabled = $false
$dnaFilterGroupBox.Controls.Add($txtFilterIPAddress)

# Role Filter
$lblFilterRole = New-Object System.Windows.Forms.Label
$lblFilterRole.Text = "Role:"
$lblFilterRole.Size = New-Object System.Drawing.Size(80, 20)
$lblFilterRole.Location = New-Object System.Drawing.Point(540, 30)
$dnaFilterGroupBox.Controls.Add($lblFilterRole)

$txtFilterRole = New-Object System.Windows.Forms.TextBox
$txtFilterRole.Size = New-Object System.Drawing.Size(150, 20)
$txtFilterRole.Location = New-Object System.Drawing.Point(630, 28)
$txtFilterRole.Enabled = $false
$dnaFilterGroupBox.Controls.Add($txtFilterRole)

# Family Filter
$lblFilterFamily = New-Object System.Windows.Forms.Label
$lblFilterFamily.Text = "Family:"
$lblFilterFamily.Size = New-Object System.Drawing.Size(80, 20)
$lblFilterFamily.Location = New-Object System.Drawing.Point(20, 65)
$dnaFilterGroupBox.Controls.Add($lblFilterFamily)

$txtFilterFamily = New-Object System.Windows.Forms.TextBox
$txtFilterFamily.Size = New-Object System.Drawing.Size(150, 20)
$txtFilterFamily.Location = New-Object System.Drawing.Point(110, 63)
$txtFilterFamily.Enabled = $false
$dnaFilterGroupBox.Controls.Add($txtFilterFamily)

# Apply Filter Button
$btnApplyDeviceFilter = New-Object System.Windows.Forms.Button
$btnApplyDeviceFilter.Text = "Apply Filter"
$btnApplyDeviceFilter.Size = New-Object System.Drawing.Size(120, 25)
$btnApplyDeviceFilter.Location = New-Object System.Drawing.Point(280, 63)
$btnApplyDeviceFilter.Enabled = $false
$dnaFilterGroupBox.Controls.Add($btnApplyDeviceFilter)

# Reset Filter Button
$btnResetDeviceFilter = New-Object System.Windows.Forms.Button
$btnResetDeviceFilter.Text = "Reset Filter"
$btnResetDeviceFilter.Size = New-Object System.Drawing.Size(120, 25)
$btnResetDeviceFilter.Location = New-Object System.Drawing.Point(410, 63)
$btnResetDeviceFilter.Enabled = $false
$dnaFilterGroupBox.Controls.Add($btnResetDeviceFilter)

# Device Selection Status
$lblDeviceSelectionStatus = New-Object System.Windows.Forms.Label
$lblDeviceSelectionStatus.Text = "Selected devices: None"
$lblDeviceSelectionStatus.Size = New-Object System.Drawing.Size(400, 20)
$lblDeviceSelectionStatus.Location = New-Object System.Drawing.Point(540, 68)
$lblDeviceSelectionStatus.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Bold)
$lblDeviceSelectionStatus.ForeColor = [System.Drawing.Color]::DarkBlue
$dnaFilterGroupBox.Controls.Add($lblDeviceSelectionStatus)

# TreeView Functions Group
$dnaTreeGroupBox = New-Object System.Windows.Forms.GroupBox
$dnaTreeGroupBox.Text = "DNA Center Functions - TreeView (Double-click to Execute)"
$dnaTreeGroupBox.Size = New-Object System.Drawing.Size(460, 270)
$dnaTreeGroupBox.Location = New-Object System.Drawing.Point(10, 270)
$tab3.Controls.Add($dnaTreeGroupBox)

# TreeView for DNA Center Functions
$script:dnaTreeView = New-Object System.Windows.Forms.TreeView
$script:dnaTreeView.Location = New-Object System.Drawing.Point(15, 25)
$script:dnaTreeView.Size = New-Object System.Drawing.Size(430, 230)
$script:dnaTreeView.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$script:dnaTreeView.ShowLines = $true
$script:dnaTreeView.ShowPlusMinus = $true
$script:dnaTreeView.ShowRootLines = $true
$dnaTreeGroupBox.Controls.Add($script:dnaTreeView)

# Populate TreeView with DNA Center functions
# Device Information category
$nodeDeviceInfo = New-Object System.Windows.Forms.TreeNode("Device Information")
Add-DNATreeNode -ParentNode $nodeDeviceInfo -Text "Basic Information" -Tag "Get-NetworkDevicesBasic"
Add-DNATreeNode -ParentNode $nodeDeviceInfo -Text "Detailed Information" -Tag "Get-NetworkDevicesDetailed"
Add-DNATreeNode -ParentNode $nodeDeviceInfo -Text "Device Count" -Tag "Get-DeviceInventoryCount"
Add-DNATreeNode -ParentNode $nodeDeviceInfo -Text "Device Modules" -Tag "Get-DeviceModules"
Add-DNATreeNode -ParentNode $nodeDeviceInfo -Text "Device Interfaces" -Tag "Get-DeviceInterfaces"
Add-DNATreeNode -ParentNode $nodeDeviceInfo -Text "Device Configurations" -Tag "Get-DeviceConfigurations"
$script:dnaTreeView.Nodes.Add($nodeDeviceInfo) | Out-Null

# Network Health category
$nodeNetworkHealth = New-Object System.Windows.Forms.TreeNode("Network Health")
Add-DNATreeNode -ParentNode $nodeNetworkHealth -Text "Overall Network Health" -Tag "Get-NetworkHealth"
Add-DNATreeNode -ParentNode $nodeNetworkHealth -Text "Client Health" -Tag "Get-ClientHealth"
Add-DNATreeNode -ParentNode $nodeNetworkHealth -Text "Device Reachability" -Tag "Get-DeviceReachability"
Add-DNATreeNode -ParentNode $nodeNetworkHealth -Text "Compliance Status" -Tag "Get-ComplianceStatus"
$script:dnaTreeView.Nodes.Add($nodeNetworkHealth) | Out-Null

# Topology and Neighbors category
$nodeTopology = New-Object System.Windows.Forms.TreeNode("Topology and Neighbors")
Add-DNATreeNode -ParentNode $nodeTopology -Text "Physical Topology" -Tag "Get-PhysicalTopology"
Add-DNATreeNode -ParentNode $nodeTopology -Text "OSPF Neighbors" -Tag "Get-OSPFNeighbors"
Add-DNATreeNode -ParentNode $nodeTopology -Text "CDP Neighbors" -Tag "Get-CDPNeighbors"
Add-DNATreeNode -ParentNode $nodeTopology -Text "LLDP Neighbors" -Tag "Get-LLDPNeighbors"
$script:dnaTreeView.Nodes.Add($nodeTopology) | Out-Null

# Network Services category
$nodeNetworkServices = New-Object System.Windows.Forms.TreeNode("Network Services")
Add-DNATreeNode -ParentNode $nodeNetworkServices -Text "VLANs" -Tag "Get-VLANs"
Add-DNATreeNode -ParentNode $nodeNetworkServices -Text "Templates" -Tag "Get-Templates"
Add-DNATreeNode -ParentNode $nodeNetworkServices -Text "Sites/Locations" -Tag "Get-SitesLocations"
Add-DNATreeNode -ParentNode $nodeNetworkServices -Text "Access Points" -Tag "Get-AccessPoints"
$script:dnaTreeView.Nodes.Add($nodeNetworkServices) | Out-Null

# Software and Issues category
$nodeSoftwareIssues = New-Object System.Windows.Forms.TreeNode("Software and Issues")
Add-DNATreeNode -ParentNode $nodeSoftwareIssues -Text "Software Images" -Tag "Get-SoftwareImageInfo"
Add-DNATreeNode -ParentNode $nodeSoftwareIssues -Text "Issues/Events" -Tag "Get-IssuesEvents"
$script:dnaTreeView.Nodes.Add($nodeSoftwareIssues) | Out-Null

# Advanced Tools category
$nodeAdvanced = New-Object System.Windows.Forms.TreeNode("Advanced Tools")
Add-DNATreeNode -ParentNode $nodeAdvanced -Text "Path Trace" -Tag "Invoke-PathTrace"
Add-DNATreeNode -ParentNode $nodeAdvanced -Text "CLI Command Runner" -Tag "Invoke-CommandRunner"
Add-DNATreeNode -ParentNode $nodeAdvanced -Text "Last Disconnect Times" -Tag "Get-LastDisconnectTime"
Add-DNATreeNode -ParentNode $nodeAdvanced -Text "Availability Events" -Tag "Get-LastDeviceAvailabilityEventTime"
Add-DNATreeNode -ParentNode $nodeAdvanced -Text "Last Ping Reachable" -Tag "Get-LastPingReachableTime"
$script:dnaTreeView.Nodes.Add($nodeAdvanced) | Out-Null

# Expand all nodes by default
$script:dnaTreeView.ExpandAll()

# Context menu for favorites
$dnaTreeContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
$menuAddFavorite = New-Object System.Windows.Forms.ToolStripMenuItem
$menuAddFavorite.Text = "Add to Favorites"
$menuAddFavorite.Add_Click({
    if ($script:dnaTreeView.SelectedNode -and $script:dnaTreeView.SelectedNode.Tag) {
        $functionName = $script:dnaTreeView.SelectedNode.Tag
        if ($script:Settings.FavoriteFunctions -notcontains $functionName) {
            $script:Settings.FavoriteFunctions += $functionName
            Save-OctoNavSettings -Settings $script:Settings
            [System.Windows.Forms.MessageBox]::Show("Added to favorites!", "Favorites", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } else {
            [System.Windows.Forms.MessageBox]::Show("Already in favorites!", "Favorites", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    }
})
$dnaTreeContextMenu.Items.Add($menuAddFavorite)
$script:dnaTreeView.ContextMenuStrip = $dnaTreeContextMenu

# Favorites List
$dnaFavoritesGroupBox = New-Object System.Windows.Forms.GroupBox
$dnaFavoritesGroupBox.Text = "Favorite Functions"
$dnaFavoritesGroupBox.Size = New-Object System.Drawing.Size(460, 270)
$dnaFavoritesGroupBox.Location = New-Object System.Drawing.Point(480, 270)
$tab3.Controls.Add($dnaFavoritesGroupBox)

$script:lstFavorites = New-Object System.Windows.Forms.ListBox
$script:lstFavorites.Location = New-Object System.Drawing.Point(15, 25)
$script:lstFavorites.Size = New-Object System.Drawing.Size(430, 230)
$script:lstFavorites.Font = New-Object System.Drawing.Font("Consolas", 9)
$dnaFavoritesGroupBox.Controls.Add($script:lstFavorites)

# DNA Log
$dnaLogBox = New-Object System.Windows.Forms.RichTextBox
$dnaLogBox.Size = New-Object System.Drawing.Size(940, 90)
$dnaLogBox.Location = New-Object System.Drawing.Point(10, 550)
$dnaLogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$dnaLogBox.ReadOnly = $true
$dnaLogBox.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
$dnaLogBox.WordWrap = $false
$dnaLogBox.HideSelection = $false
$dnaLogBox.DetectUrls = $false
$dnaLogBox.Multiline = $true
$tab3.Controls.Add($dnaLogBox)

# TreeView double-click event handler
$script:dnaTreeView.Add_NodeMouseDoubleClick({
    param($sender, $e)
    try {
        if ($e.Node.Tag) {
            # Check if connected first
            if (-not $global:dnaCenterToken) {
                Write-Log -Message "Please connect to DNA Center first" -Color "Warning" -LogBox $dnaLogBox -Theme $script:CurrentTheme
                [System.Windows.Forms.MessageBox]::Show("Please connect to DNA Center first", "Not Connected", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }

            # Check if devices are loaded
            if (-not $global:allDNADevices -or $global:allDNADevices.Count -eq 0) {
                Write-Log -Message "Please load devices first using the 'Load Devices' button" -Color "Warning" -LogBox $dnaLogBox -Theme $script:CurrentTheme
                [System.Windows.Forms.MessageBox]::Show("Please load devices first using the 'Load Devices' button", "No Devices", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }

            $functionName = $e.Node.Tag
            Write-Log -Message "Executing: $($e.Node.Text)" -Color "Info" -LogBox $dnaLogBox -Theme $script:CurrentTheme
            & $functionName -LogBox $dnaLogBox
        }
    } catch {
        Write-Log -Message "Error executing function: $($_.Exception.Message)" -Color "Error" -LogBox $dnaLogBox -Theme $script:CurrentTheme
        [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Execution Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# Event Handlers for Tab 3
$btnDNAConnect.Add_Click({
    try {
        $selectedIndex = $comboDNAServer.SelectedIndex
        if ($selectedIndex -lt 0) {
            [System.Windows.Forms.MessageBox]::Show("Please select a DNA Center server", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        $global:selectedDnaCenter = $global:dnaCenterServers[$selectedIndex].Url
        $username = $txtDNAUser.Text.Trim()
        $password = $txtDNAPass.Text

        if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter username and password", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        Update-StatusBar -Status "Connecting to DNA Center..." -StatusLabel $script:statusLabel -ProgressBar $script:progressBar -ProgressLabel $script:progressLabel

        $success = Connect-DNACenter -DnaCenter $global:selectedDnaCenter -Username $username -Password $password -LogBox $dnaLogBox

        if ($success) {
            $btnLoadDevices.Enabled = $true
            Update-StatusBar -Status "Ready - Connected to DNA Center" -StatusLabel $script:statusLabel -ProgressBar $script:progressBar -ProgressLabel $script:progressLabel

            # Update enhanced status bar connection status
            $serverName = $global:dnaCenterServers[$selectedIndex].Name
            Update-ConnectionStatus -StatusBar $script:StatusBarPanels -IsConnected $true -ServerName $serverName

            [System.Windows.Forms.MessageBox]::Show("Successfully connected to DNA Center!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } else {
            Update-StatusBar -Status "Ready - Failed to connect to DNA Center" -StatusLabel $script:statusLabel -ProgressBar $script:progressBar -ProgressLabel $script:progressLabel
            Update-ConnectionStatus -StatusBar $script:StatusBarPanels -IsConnected $false
            [System.Windows.Forms.MessageBox]::Show("Failed to connect to DNA Center", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } catch {
        Write-Log -Message "Connection error: $($_.Exception.Message)" -Color "Error" -LogBox $dnaLogBox -Theme $script:CurrentTheme
        [System.Windows.Forms.MessageBox]::Show("Connection error: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    } finally {
        # Clear password from memory
        $password = $null
        $txtDNAPass.Text = ""
    }
})

$btnLoadDevices.Add_Click({
    try {
        Update-StatusBar -Status "Loading devices from DNA Center..." -StatusLabel $script:statusLabel -ProgressBar $script:progressBar -ProgressLabel $script:progressLabel
        $success = Get-AllDNADevices -LogBox $dnaLogBox

        if ($success) {
            # Enable filter controls
            foreach ($control in @($txtFilterHostname, $txtFilterIPAddress, $txtFilterRole, $txtFilterFamily, $btnApplyDeviceFilter, $btnResetDeviceFilter)) {
                $control.Enabled = $true
            }

            $lblDeviceSelectionStatus.Text = "Selected devices: All ($($global:allDNADevices.Count))"
            Update-StatusBar -Status "Ready - Loaded $($global:allDNADevices.Count) devices from DNA Center" -StatusLabel $script:statusLabel -ProgressBar $script:progressBar -ProgressLabel $script:progressLabel

            [System.Windows.Forms.MessageBox]::Show("Devices loaded successfully!`nTotal: $($global:allDNADevices.Count)", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } else {
            Update-StatusBar -Status "Ready - Failed to load devices" -StatusLabel $script:statusLabel -ProgressBar $script:progressBar -ProgressLabel $script:progressLabel
            [System.Windows.Forms.MessageBox]::Show("Failed to load devices", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } catch {
        Write-Log -Message "Error loading devices: $($_.Exception.Message)" -Color "Error" -LogBox $dnaLogBox -Theme $script:CurrentTheme
        [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$btnApplyDeviceFilter.Add_Click({
    try {
        $result = Select-DNADevices -Hostname $txtFilterHostname.Text -IPAddress $txtFilterIPAddress.Text -Role $txtFilterRole.Text -Family $txtFilterFamily.Text -LogBox $dnaLogBox

        if ($result.Count -eq 0) {
            $lblDeviceSelectionStatus.Text = "Selected devices: 0 of $($global:allDNADevices.Count)"
            [System.Windows.Forms.MessageBox]::Show("No devices matched the provided filters.", "No Results", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } else {
            $lblDeviceSelectionStatus.Text = "Selected devices: $($result.Count) of $($global:allDNADevices.Count)"
            [System.Windows.Forms.MessageBox]::Show("Filters applied successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    } catch {
        Write-Log -Message "Error applying filters: $($_.Exception.Message)" -Color "Red" -LogBox $dnaLogBox
        [System.Windows.Forms.MessageBox]::Show("Error applying filters: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$btnResetDeviceFilter.Add_Click({
    try {
        Reset-DNADeviceSelection -LogBox $dnaLogBox
        $txtFilterHostname.Clear()
        $txtFilterIPAddress.Clear()
        $txtFilterRole.Clear()
        $txtFilterFamily.Clear()

        $lblDeviceSelectionStatus.Text = "Selected devices: All ($($global:allDNADevices.Count))"
        [System.Windows.Forms.MessageBox]::Show("Device selection reset to all loaded devices.", "Reset", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        Write-Log -Message "Error resetting filters: $($_.Exception.Message)" -Color "Red" -LogBox $dnaLogBox
        [System.Windows.Forms.MessageBox]::Show("Error resetting filters: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# ============================================
# STATUS BAR
# ============================================

# Create Enhanced Status Bar with segmented panels
$script:StatusBarPanels = New-EnhancedStatusBar -Form $mainForm

# Create references for backward compatibility with existing code
$statusStrip = $script:StatusBarPanels.StatusStrip
$script:statusLabel = $script:StatusBarPanels.StatusLabel
$script:progressBar = $script:StatusBarPanels.ProgressBar
$script:progressLabel = $script:StatusBarPanels.ProgressLabel

# ============================================
# TAB SELECTION EVENT
# ============================================

$tabControl.Add_SelectedIndexChanged({
    if ($tabControl.SelectedIndex -eq 0 -and $script:Settings.ShowDashboardOnStartup) {
        # Refresh dashboard when tab is selected
        Update-Dashboard
    }
})

# ============================================
# FORM CLOSING EVENT
# ============================================

$mainForm.Add_FormClosing({
    param($sender, $e)

    try {
        # Save window size if changed
        if ($mainForm.WindowState -eq "Normal") {
            $script:Settings.WindowSize = @{
                Width = $mainForm.Width
                Height = $mainForm.Height
            }
            $script:Settings.WindowMaximized = $false
        } else {
            $script:Settings.WindowMaximized = ($mainForm.WindowState -eq [System.Windows.Forms.FormWindowState]::Maximized)
        }

        Save-OctoNavSettings -Settings $script:Settings

        # Cleanup DHCP runspace if running
        if ($script:dhcpTimer) {
            $script:dhcpTimer.Stop()
            $script:dhcpTimer.Dispose()
        }
        if ($script:dhcpPowerShell) {
            $script:dhcpPowerShell.Dispose()
        }
        if ($script:dhcpRunspace) {
            $script:dhcpRunspace.Close()
            $script:dhcpRunspace.Dispose()
        }

        # Clear sensitive data
        $global:dnaCenterToken = $null
        $global:dnaCenterHeaders = $null
    } catch {
        # Silently cleanup
    }
})

# ============================================
# APPLY THEME
# ============================================

Set-ThemeToControl -Control $mainForm -Theme $script:CurrentTheme

# ============================================
# INITIAL DHCP SERVER CACHE LOAD
# ============================================

# Load cached DHCP servers on startup
try {
    $cachedServers = Get-CachedDHCPServers

    if ($cachedServers -and $cachedServers.Count -gt 0) {
        # Populate CheckedListBox with cached servers
        foreach ($server in $cachedServers) {
            $displayText = "$($server.DnsName) ($($server.IPAddress))"
            $script:lstDHCPServers.Items.Add($displayText) | Out-Null
        }

        # Read cache file to get LastUpdated timestamp
        $cacheFile = Join-Path $PSScriptRoot "dhcp_servers_cache.json"
        if (Test-Path $cacheFile) {
            $cache = Get-Content $cacheFile -Raw | ConvertFrom-Json
            if ($cache.LastUpdated) {
                $lastUpdated = [DateTime]::Parse($cache.LastUpdated)
                $script:lblLastRefresh.Text = "Last refreshed: $($lastUpdated.ToString('yyyy-MM-dd HH:mm:ss')) (cached)"
            }
        }
    } else {
        # No cache exists - trigger initial discovery in background
        $script:lblLastRefresh.Text = "Discovering servers..."

        # Discover servers in background without blocking startup
        $null = [System.Windows.Forms.Application]::DoEvents()

        $discoveredServers = Update-DHCPServerCache

        if ($discoveredServers -and $discoveredServers.Count -gt 0) {
            foreach ($server in $discoveredServers) {
                $displayText = "$($server.DnsName) ($($server.IPAddress))"
                $script:lstDHCPServers.Items.Add($displayText) | Out-Null
            }
            $script:lblLastRefresh.Text = "Last refreshed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        } else {
            $script:lblLastRefresh.Text = "Last refreshed: Never (no servers found)"
        }
    }
} catch {
    # Silently continue if cache load fails
    $script:lblLastRefresh.Text = "Last refreshed: Never (error loading cache)"
}

# ============================================
# INITIAL DASHBOARD UPDATE
# ============================================

# Initial dashboard update
Update-Dashboard

# ============================================
# SHOW FORM
# ============================================

# Select dashboard tab if configured
if ($script:Settings.ShowDashboardOnStartup) {
    $tabControl.SelectedIndex = 0
}

# Load cached DHCP scopes if available
try {
    $cachedScopes = Get-CachedDHCPScopes
    if ($cachedScopes -and @($cachedScopes).Count -gt 0) {
        $script:allDHCPScopes = $cachedScopes
        foreach ($scope in $cachedScopes) {
            $script:lstDHCPScopes.Items.Add($scope.DisplayName) | Out-Null
        }
        $cacheFile = Join-Path $PSScriptRoot "dhcp_scopes_cache.json"
        if (Test-Path $cacheFile) {
            $cacheInfo = Get-Content $cacheFile -Raw | ConvertFrom-Json
            $lastUpdate = [DateTime]::Parse($cacheInfo.LastUpdated)
            $script:lblScopeCacheStatus.Text = "Cache: $($cachedScopes.Count) scope(s) loaded ($($lastUpdate.ToString('MM/dd HH:mm')))"
            $script:lblScopeCacheStatus.ForeColor = [System.Drawing.Color]::Green
        } else {
            $script:lblScopeCacheStatus.Text = "Cache: $($cachedScopes.Count) scope(s) loaded"
            $script:lblScopeCacheStatus.ForeColor = [System.Drawing.Color]::Green
        }
    }
} catch {
    # Silently continue if cache loading fails
}

# Show the form
[void]$mainForm.ShowDialog()
