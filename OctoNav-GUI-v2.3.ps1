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
# MODULE IMPORTS
# ============================================
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

try {
    # Core modules
    Import-Module "$scriptPath\modules\SettingsManager.psm1" -Force -ErrorAction Stop
    Import-Module "$scriptPath\modules\ThemeManager.psm1" -Force -ErrorAction Stop
    Import-Module "$scriptPath\modules\ValidationFunctions.psm1" -Force -ErrorAction Stop
    Import-Module "$scriptPath\modules\HelperFunctions.psm1" -Force -ErrorAction Stop
    Import-Module "$scriptPath\modules\ExportManager.psm1" -Force -ErrorAction Stop

    # UI modules
    Import-Module "$scriptPath\modules\SettingsDialog.psm1" -Force -ErrorAction Stop
    Import-Module "$scriptPath\modules\DashboardComponents.psm1" -Force -ErrorAction Stop

    # Function modules
    Import-Module "$scriptPath\modules\DNACenterFunctions.psm1" -Force -ErrorAction Stop
    Import-Module "$scriptPath\modules\DHCPFunctions.psm1" -Force -ErrorAction Stop
    Import-Module "$scriptPath\modules\NetworkConfigFunctions.psm1" -Force -ErrorAction Stop

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
# HELPER FUNCTIONS
# ============================================

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

# ============================================
# INITIALIZE SETTINGS & GLOBAL VARIABLES
# ============================================

# Load user settings
$script:Settings = Get-OctoNavSettings

# Get initial theme
$script:CurrentTheme = Get-Theme -ThemeName $script:Settings.Theme

# Initialize global variables for DNA Center
$script:dnaCenterToken = $null
$script:dnaCenterTokenExpiry = $null
$script:dnaCenterHeaders = $null
$script:selectedDnaCenter = $null
$script:allDNADevices = @()
$script:selectedDNADevices = @()
$script:dnaCenterServers = @()

# Initialize global variables for DHCP
$script:dhcpResults = @()
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
$script:dnaCenterServers = Get-DNACenterServers

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
            Apply-ThemeToControl -Control $mainForm -Theme $script:CurrentTheme
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
    Apply-ThemeToControl -Control $mainForm -Theme $script:CurrentTheme
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
$tabControl.Location = New-Object System.Drawing.Point(10, 30)
$tabControl.Size = New-Object System.Drawing.Size(($mainForm.ClientSize.Width - 20), ($mainForm.ClientSize.Height - 70))
$tabControl.Anchor = "Top,Bottom,Left,Right"
$mainForm.Controls.Add($tabControl)

# ============================================
# TAB 0: DASHBOARD
# ============================================

$tab0 = New-Object System.Windows.Forms.TabPage
$tab0.Text = "Dashboard"
$tabControl.Controls.Add($tab0)

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
            $script:lstRecentActivity.Items.Add($activity)
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

            Write-Log -Message "Adapter found and ready for configuration" -Color "Green" -LogBox $netLogBox
        } else {
            Write-Log -Message "No unidentified network found" -Color "Red" -LogBox $netLogBox
        }
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $netLogBox
    }
})

$btnApplyConfig.Add_Click({
    try {
        if (-not $script:TargetAdapter) {
            Write-Log -Message "Please find a network adapter first" -Color "Red" -LogBox $netLogBox
            return
        }

        $ip = $txtIPAddress.Text.Trim()
        $gateway = $txtGateway.Text.Trim()
        $prefixText = $txtPrefix.Text.Trim()

        # Validate IP address
        if (-not (Test-IPAddress -IPAddress $ip)) {
            Write-Log -Message 'Invalid IP address format. Please enter a valid IPv4 address (e.g., 192.168.1.100)' -Color 'Red' -LogBox $netLogBox
            [System.Windows.Forms.MessageBox]::Show("Invalid IP address format!", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        # Validate gateway
        if (-not (Test-IPAddress -IPAddress $gateway)) {
            Write-Log -Message "Invalid gateway format. Please enter a valid IPv4 address" -Color "Red" -LogBox $netLogBox
            [System.Windows.Forms.MessageBox]::Show("Invalid gateway format!", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        # Validate prefix
        if (-not (Test-PrefixLength -Prefix $prefixText)) {
            Write-Log -Message "Invalid prefix length. Must be between 0 and 32" -Color "Red" -LogBox $netLogBox
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
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $netLogBox
        [System.Windows.Forms.MessageBox]::Show("Error applying configuration: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$btnRestoreDefaults.Add_Click({
    try {
        Restore-NetworkDefaults -LogBox $netLogBox
        [System.Windows.Forms.MessageBox]::Show("Network defaults restored!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $netLogBox
    }
})

# ============================================
# TAB 2: DHCP STATISTICS
# ============================================

$tab2 = New-Object System.Windows.Forms.TabPage
$tab2.Text = "DHCP Statistics"
$tabControl.Controls.Add($tab2)

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
$dhcpServerGroupBox.Text = "Server Configuration"
$dhcpServerGroupBox.Size = New-Object System.Drawing.Size(940, 110)
$dhcpServerGroupBox.Location = New-Object System.Drawing.Point(10, 40)
$tab2.Controls.Add($dhcpServerGroupBox)

$lblServerInfo = New-Object System.Windows.Forms.Label
$lblServerInfo.Text = 'Specify DHCP servers (comma-separated, leave blank to auto-discover from domain):'
$lblServerInfo.Location = New-Object System.Drawing.Point(15, 25)
$lblServerInfo.Size = New-Object System.Drawing.Size(550, 20)
$lblServerInfo.ForeColor = [System.Drawing.Color]::DarkGreen
$dhcpServerGroupBox.Controls.Add($lblServerInfo)

$lblServerExample = New-Object System.Windows.Forms.Label
$lblServerExample.Text = "Example: dhcp-server1.domain.com, dhcp-server2.domain.com"
$lblServerExample.Location = New-Object System.Drawing.Point(580, 25)
$lblServerExample.Size = New-Object System.Drawing.Size(500, 20)
$lblServerExample.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$lblServerExample.ForeColor = [System.Drawing.Color]::Gray
$dhcpServerGroupBox.Controls.Add($lblServerExample)

$txtSpecificServers = New-Object System.Windows.Forms.TextBox
$txtSpecificServers.Size = New-Object System.Drawing.Size(900, 20)
$txtSpecificServers.Location = New-Object System.Drawing.Point(15, 50)
$txtSpecificServers.MaxLength = 1000
$dhcpServerGroupBox.Controls.Add($txtSpecificServers)

$lblServerNote = New-Object System.Windows.Forms.Label
$lblServerNote.Text = "Note: If blank, all domain DHCP servers will be auto-discovered"
$lblServerNote.Location = New-Object System.Drawing.Point(15, 75)
$lblServerNote.Size = New-Object System.Drawing.Size(900, 20)
$lblServerNote.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$lblServerNote.ForeColor = [System.Drawing.Color]::Gray
$dhcpServerGroupBox.Controls.Add($lblServerNote)

# Scope Filtering Group
$dhcpFilterGroupBox = New-Object System.Windows.Forms.GroupBox
$dhcpFilterGroupBox.Text = "Scope Filtering (Optional)"
$dhcpFilterGroupBox.Size = New-Object System.Drawing.Size(940, 75)
$dhcpFilterGroupBox.Location = New-Object System.Drawing.Point(10, 160)
$tab2.Controls.Add($dhcpFilterGroupBox)

$lblScopeFilter = New-Object System.Windows.Forms.Label
$lblScopeFilter.Text = 'Filter by scope names (comma-separated, leave blank for all scopes):'
$lblScopeFilter.Size = New-Object System.Drawing.Size(450, 20)
$lblScopeFilter.Location = New-Object System.Drawing.Point(15, 25)
$dhcpFilterGroupBox.Controls.Add($lblScopeFilter)

$lblFilterExample = New-Object System.Windows.Forms.Label
$lblFilterExample.Text = "Example: VLAN100, Guest-Network, Lab"
$lblFilterExample.Size = New-Object System.Drawing.Size(400, 20)
$lblFilterExample.Location = New-Object System.Drawing.Point(480, 25)
$lblFilterExample.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$lblFilterExample.ForeColor = [System.Drawing.Color]::Gray
$dhcpFilterGroupBox.Controls.Add($lblFilterExample)

$txtScopeFilter = New-Object System.Windows.Forms.TextBox
$txtScopeFilter.Size = New-Object System.Drawing.Size(900, 20)
$txtScopeFilter.Location = New-Object System.Drawing.Point(15, 45)
$txtScopeFilter.MaxLength = 500
$dhcpFilterGroupBox.Controls.Add($txtScopeFilter)

# Collection Options Group
$dhcpOptionsGroupBox = New-Object System.Windows.Forms.GroupBox
$dhcpOptionsGroupBox.Text = "Collection Options"
$dhcpOptionsGroupBox.Size = New-Object System.Drawing.Size(940, 75)
$dhcpOptionsGroupBox.Location = New-Object System.Drawing.Point(10, 245)
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

# Actions Group
$dhcpActionsGroupBox = New-Object System.Windows.Forms.GroupBox
$dhcpActionsGroupBox.Text = "Actions"
$dhcpActionsGroupBox.Size = New-Object System.Drawing.Size(940, 65)
$dhcpActionsGroupBox.Location = New-Object System.Drawing.Point(10, 330)
$tab2.Controls.Add($dhcpActionsGroupBox)

$btnCollectDHCP = New-Object System.Windows.Forms.Button
$btnCollectDHCP.Text = "Collect DHCP Statistics"
$btnCollectDHCP.Size = New-Object System.Drawing.Size(200, 35)
$btnCollectDHCP.Location = New-Object System.Drawing.Point(15, 25)
$btnCollectDHCP.BackColor = [System.Drawing.Color]::LightGreen
$dhcpActionsGroupBox.Controls.Add($btnCollectDHCP)

$btnExportDHCP = New-Object System.Windows.Forms.Button
$btnExportDHCP.Text = "Export to CSV"
$btnExportDHCP.Size = New-Object System.Drawing.Size(150, 35)
$btnExportDHCP.Location = New-Object System.Drawing.Point(230, 25)
$btnExportDHCP.Enabled = $false
$dhcpActionsGroupBox.Controls.Add($btnExportDHCP)

$lblExportHint = New-Object System.Windows.Forms.Label
$lblExportHint.Text = "Results will be automatically exported after collection. Use this button to re-export."
$lblExportHint.Size = New-Object System.Drawing.Size(700, 20)
$lblExportHint.Location = New-Object System.Drawing.Point(395, 33)
$lblExportHint.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$lblExportHint.ForeColor = [System.Drawing.Color]::Gray
$dhcpActionsGroupBox.Controls.Add($lblExportHint)

# DHCP Log
$dhcpLogBox = New-Object System.Windows.Forms.RichTextBox
$dhcpLogBox.Size = New-Object System.Drawing.Size(940, 220)
$dhcpLogBox.Location = New-Object System.Drawing.Point(10, 405)
$dhcpLogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$dhcpLogBox.ReadOnly = $true
$dhcpLogBox.ScrollBars = "Vertical"
$dhcpLogBox.WordWrap = $false
$tab2.Controls.Add($dhcpLogBox)

# Event Handlers for Tab 2
$btnCollectDHCP.Add_Click({
    try {
        $btnCollectDHCP.Enabled = $false

        # Parse scope filters
        $scopeFilters = @()
        if (-not [string]::IsNullOrWhiteSpace($txtScopeFilter.Text)) {
            $scopeFilters = $txtScopeFilter.Text.Split(',') | ForEach-Object { $_.Trim().ToUpper() }
        }

        # Parse and validate specific servers
        $specificServers = @()
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

            $specificServers = $validServers
        }

        $includeDNS = $chkIncludeDNS.Checked

        # Call DHCP collection function from module
        $result = Get-DHCPScopeStatistics -ScopeFilters $scopeFilters -SpecificServers $specificServers -IncludeDNS $includeDNS -LogBox $dhcpLogBox -StatusBarCallback {
            param($status, $progress, $progressText)
            Update-StatusBar -Status $status -ProgressValue $progress -ProgressMax 100 -ProgressText $progressText
        }

        if ($result.Success) {
            $script:dhcpResults = $result.Results
            if ($script:dhcpResults.Count -gt 0) {
                $btnExportDHCP.Enabled = $true
                Write-Log -Message "Collection complete! Found $($script:dhcpResults.Count) scopes" -Color "Green" -LogBox $dhcpLogBox

                # Auto-export if enabled
                if ($script:Settings.AutoExportAfterCollection) {
                    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                    $exportPath = Join-Path -Path $script:outputDir -ChildPath "DHCPScopeStats_$timestamp.csv"

                    if (-not (Test-Path $script:outputDir)) {
                        New-Item -ItemType Directory -Path $script:outputDir -Force | Out-Null
                    }

                    Export-ToCSV -Data $script:dhcpResults -OutputPath $exportPath -Settings $script:Settings
                    Write-Log -Message "Auto-exported to: $exportPath" -Color "Cyan" -LogBox $dhcpLogBox
                }
            } else {
                Write-Log -Message "No DHCP scopes found matching criteria" -Color "Yellow" -LogBox $dhcpLogBox
            }
        } else {
            Write-Log -Message "Error: $($result.Error)" -Color "Red" -LogBox $dhcpLogBox
        }

    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color "Red" -LogBox $dhcpLogBox
    } finally {
        $btnCollectDHCP.Enabled = $true
        Update-StatusBar -Status "Ready" -ProgressValue -1
    }
})

$btnExportDHCP.Add_Click({
    try {
        if ($script:dhcpResults.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No DHCP results to export", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = Join-Path -Path $script:outputDir -ChildPath "DHCPScopeStats_$timestamp.csv"

        if (-not (Test-Path $script:outputDir)) {
            New-Item -ItemType Directory -Path $script:outputDir -Force | Out-Null
        }

        Export-ToCSV -Data $script:dhcpResults -OutputPath $csvPath -Settings $script:Settings
        Write-Log -Message "Exported to: $csvPath" -Color "Green" -LogBox $dhcpLogBox
        [System.Windows.Forms.MessageBox]::Show("Export successful!`n`n$csvPath", "Export Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)

    } catch {
        Write-Log -Message "Error exporting: $($_.Exception.Message)" -Color "Red" -LogBox $dhcpLogBox
        [System.Windows.Forms.MessageBox]::Show("Error exporting: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# ============================================
# TAB 3: DNA CENTER (REDESIGNED WITH TREEVIEW)
# ============================================

$tab3 = New-Object System.Windows.Forms.TabPage
$tab3.Text = "DNA Center"
$tabControl.Controls.Add($tab3)

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
foreach ($server in $script:dnaCenterServers) {
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
# Helper function to add child nodes with tags
function Add-DNATreeNode {
    param($ParentNode, $Text, $Tag)
    $node = New-Object System.Windows.Forms.TreeNode($Text)
    $node.Tag = $Tag
    $ParentNode.Nodes.Add($node) | Out-Null
}

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
$dnaLogBox.ScrollBars = "Vertical"
$dnaLogBox.WordWrap = $false
$tab3.Controls.Add($dnaLogBox)

# TreeView double-click event handler
$script:dnaTreeView.Add_NodeMouseDoubleClick({
    param($sender, $e)
    try {
        if ($e.Node.Tag) {
            $functionName = $e.Node.Tag
            Write-Log -Message "Executing: $($e.Node.Text)" -Color "Cyan" -LogBox $dnaLogBox
            & $functionName -LogBox $dnaLogBox
        }
    } catch {
        Write-Log -Message "Error executing function: $($_.Exception.Message)" -Color "Red" -LogBox $dnaLogBox
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

        $script:selectedDnaCenter = $script:dnaCenterServers[$selectedIndex].Url
        $username = $txtDNAUser.Text.Trim()
        $password = $txtDNAPass.Text

        if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter username and password", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        Initialize-DNACenter -LogBox $dnaLogBox
        Update-StatusBar -Status "Connecting to DNA Center..."

        $success = Connect-DNACenter -DnaCenter $script:selectedDnaCenter -Username $username -Password $password -LogBox $dnaLogBox

        if ($success) {
            $btnLoadDevices.Enabled = $true
            Update-StatusBar -Status "Ready - Connected to DNA Center"
            [System.Windows.Forms.MessageBox]::Show("Successfully connected to DNA Center!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } else {
            Update-StatusBar -Status "Ready - Failed to connect to DNA Center"
            [System.Windows.Forms.MessageBox]::Show("Failed to connect to DNA Center", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } catch {
        Write-Log -Message "Connection error: $($_.Exception.Message)" -Color "Red" -LogBox $dnaLogBox
        [System.Windows.Forms.MessageBox]::Show("Connection error: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    } finally {
        # Clear password from memory
        $password = $null
        $txtDNAPass.Text = ""
    }
})

$btnLoadDevices.Add_Click({
    try {
        Update-StatusBar -Status "Loading devices from DNA Center..."
        $success = Load-AllDNADevices -LogBox $dnaLogBox

        if ($success) {
            # Enable filter controls
            foreach ($control in @($txtFilterHostname, $txtFilterIPAddress, $txtFilterRole, $txtFilterFamily, $btnApplyDeviceFilter, $btnResetDeviceFilter)) {
                $control.Enabled = $true
            }

            $lblDeviceSelectionStatus.Text = "Selected devices: All ($($script:allDNADevices.Count))"
            Update-StatusBar -Status "Ready - Loaded $($script:allDNADevices.Count) devices from DNA Center"

            [System.Windows.Forms.MessageBox]::Show("Devices loaded successfully!`nTotal: $($script:allDNADevices.Count)", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } else {
            Update-StatusBar -Status "Ready - Failed to load devices"
            [System.Windows.Forms.MessageBox]::Show("Failed to load devices", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } catch {
        Write-Log -Message "Error loading devices: $($_.Exception.Message)" -Color "Red" -LogBox $dnaLogBox
        [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$btnApplyDeviceFilter.Add_Click({
    try {
        $result = Filter-DNADevices -Hostname $txtFilterHostname.Text -IPAddress $txtFilterIPAddress.Text -Role $txtFilterRole.Text -Family $txtFilterFamily.Text -LogBox $dnaLogBox

        if ($result.Count -eq 0) {
            $lblDeviceSelectionStatus.Text = "Selected devices: 0 of $($script:allDNADevices.Count)"
            [System.Windows.Forms.MessageBox]::Show("No devices matched the provided filters.", "No Results", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } else {
            $lblDeviceSelectionStatus.Text = "Selected devices: $($result.Count) of $($script:allDNADevices.Count)"
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

        $lblDeviceSelectionStatus.Text = "Selected devices: All ($($script:allDNADevices.Count))"
        [System.Windows.Forms.MessageBox]::Show("Device selection reset to all loaded devices.", "Reset", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        Write-Log -Message "Error resetting filters: $($_.Exception.Message)" -Color "Red" -LogBox $dnaLogBox
        [System.Windows.Forms.MessageBox]::Show("Error resetting filters: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# ============================================
# STATUS BAR
# ============================================

$statusStrip = New-Object System.Windows.Forms.StatusStrip
$script:statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$script:statusLabel.Text = "Ready"
$script:statusLabel.Spring = $true
$script:statusLabel.TextAlign = "MiddleLeft"
$statusStrip.Items.Add($script:statusLabel)

$script:progressBar = New-Object System.Windows.Forms.ToolStripProgressBar
$script:progressBar.Size = New-Object System.Drawing.Size(200, 16)
$script:progressBar.Visible = $false
$statusStrip.Items.Add($script:progressBar)

$script:progressLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$script:progressLabel.Text = ""
$script:progressLabel.Visible = $false
$statusStrip.Items.Add($script:progressLabel)

$mainForm.Controls.Add($statusStrip)

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
        $script:dnaCenterToken = $null
        $script:dnaCenterHeaders = $null
    } catch {
        # Silently cleanup
    }
})

# ============================================
# APPLY THEME
# ============================================

Apply-ThemeToControl -Control $mainForm -Theme $script:CurrentTheme

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

# Show the form
[void]$mainForm.ShowDialog()
