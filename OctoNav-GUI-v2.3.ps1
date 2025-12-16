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
    Import-Module "$scriptPath\modules\SecurityFunctions.psm1" -Force -Global -ErrorAction Stop

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

function Populate-DNAFilterComboBoxes {
    <#
    .SYNOPSIS
        Populates DNA Center filter ComboBoxes with unique values from loaded devices
    #>
    param(
        [System.Windows.Forms.ComboBox]$FamilyComboBox,
        [System.Windows.Forms.ComboBox]$RoleComboBox,
        [System.Windows.Forms.ComboBox]$IPComboBox
    )

    if (-not $global:allDNADevices -or $global:allDNADevices.Count -eq 0) {
        return
    }

    # Populate Family ComboBox
    $families = $global:allDNADevices | Where-Object { $_.family } | Select-Object -ExpandProperty family -Unique | Sort-Object
    $FamilyComboBox.Items.Clear()
    $FamilyComboBox.Items.Add("All") | Out-Null
    foreach ($family in $families) {
        $FamilyComboBox.Items.Add($family) | Out-Null
    }
    $FamilyComboBox.SelectedIndex = 0

    # Populate Role ComboBox
    $roles = $global:allDNADevices | Where-Object { $_.role } | Select-Object -ExpandProperty role -Unique | Sort-Object
    $RoleComboBox.Items.Clear()
    $RoleComboBox.Items.Add("All") | Out-Null
    foreach ($role in $roles) {
        $RoleComboBox.Items.Add($role) | Out-Null
    }
    $RoleComboBox.SelectedIndex = 0

    # Populate IP Address ComboBox (only show unique IPs, sorted)
    $ips = $global:allDNADevices | Where-Object { $_.managementIpAddress } | Select-Object -ExpandProperty managementIpAddress -Unique | Sort-Object { [System.Version]$_ }
    $IPComboBox.Items.Clear()
    $IPComboBox.Items.Add("All") | Out-Null
    foreach ($ip in $ips) {
        $IPComboBox.Items.Add($ip) | Out-Null
    }
    $IPComboBox.SelectedIndex = 0
}

function Update-DNADeviceList {
    <#
    .SYNOPSIS
        Filters and populates the DNA Center device CheckedListBox based on current filter criteria
    #>
    param(
        [System.Windows.Forms.CheckedListBox]$DeviceListBox,
        [System.Windows.Forms.TextBox]$HostnameFilter,
        [System.Windows.Forms.ComboBox]$FamilyFilter,
        [System.Windows.Forms.ComboBox]$RoleFilter,
        [System.Windows.Forms.ComboBox]$IPFilter,
        [System.Windows.Forms.Label]$StatusLabel,
        [System.Windows.Forms.CheckBox]$SelectAllCheckbox
    )

    if (-not $global:allDNADevices -or $global:allDNADevices.Count -eq 0) {
        $DeviceListBox.Items.Clear()
        $StatusLabel.Text = "Showing: 0 devices | Selected: 0"
        return
    }

    # Store currently checked device IDs
    $checkedDeviceIds = @()
    for ($i = 0; $i -lt $DeviceListBox.Items.Count; $i++) {
        if ($DeviceListBox.GetItemChecked($i)) {
            # Extract device ID from the item text (format: "hostname - ip - role - family [id]")
            $itemText = $DeviceListBox.Items[$i].ToString()
            if ($itemText -match '\[([^\]]+)\]$') {
                $checkedDeviceIds += $matches[1]
            }
        }
    }

    # Apply filters
    $filtered = $global:allDNADevices | Where-Object {
        $matchesHostname = [string]::IsNullOrWhiteSpace($HostnameFilter.Text) -or ($_.hostname -and $_.hostname -like "*$($HostnameFilter.Text)*")
        $matchesFamily = ($FamilyFilter.SelectedItem -eq "All") -or ($_.family -eq $FamilyFilter.SelectedItem)
        $matchesRole = ($RoleFilter.SelectedItem -eq "All") -or ($_.role -eq $RoleFilter.SelectedItem)
        $matchesIP = ($IPFilter.SelectedItem -eq "All") -or ($_.managementIpAddress -eq $IPFilter.SelectedItem)

        $matchesHostname -and $matchesFamily -and $matchesRole -and $matchesIP
    }

    # Populate CheckedListBox
    $DeviceListBox.BeginUpdate()
    $DeviceListBox.Items.Clear()

    $checkedCount = 0
    foreach ($device in $filtered) {
        $hostname = if ($device.hostname) { $device.hostname } else { "N/A" }
        $ip = if ($device.managementIpAddress) { $device.managementIpAddress } else { "N/A" }
        $role = if ($device.role) { $device.role } else { "N/A" }
        $family = if ($device.family) { $device.family } else { "N/A" }
        $deviceId = if ($device.id) { $device.id } else { "N/A" }

        # Format: "hostname - ip - role - family [id]"
        $displayText = "$hostname - $ip - $role - $family [$deviceId]"
        $index = $DeviceListBox.Items.Add($displayText)

        # Restore checked state if device was previously checked
        if ($checkedDeviceIds -contains $deviceId) {
            $DeviceListBox.SetItemChecked($index, $true)
            $checkedCount++
        }
    }

    $DeviceListBox.EndUpdate()

    # Update status label
    $StatusLabel.Text = "Showing: $($filtered.Count) devices | Selected: $checkedCount"

    # Update Select All checkbox state
    if ($filtered.Count -eq 0) {
        $SelectAllCheckbox.Checked = $false
        $SelectAllCheckbox.Enabled = $false
    } else {
        $SelectAllCheckbox.Enabled = $true
        $SelectAllCheckbox.Checked = ($checkedCount -eq $filtered.Count)
    }
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
$mainForm.MinimumSize = New-Object System.Drawing.Size(1245, 600)

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

# Separator
$menuTools.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator))

# Export Resources Menu Item
$menuToolsExportResources = New-Object System.Windows.Forms.ToolStripMenuItem
$menuToolsExportResources.Text = "Export &Resources..."
$menuToolsExportResources.Add_Click({
    # Check if embedded resources exist
    if (-not $script:EmbeddedResources -or $script:EmbeddedResources.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No embedded resources found in this build.`n`nTo embed resources:`n1. Place files in the 'resources' folder`n2. Run Package-Resources.ps1",
            "No Resources",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
        return
    }

    # Show folder browser dialog
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select folder to export resources to"
    $folderBrowser.ShowNewFolderButton = $true

    if ($folderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $outputPath = $folderBrowser.SelectedPath

        try {
            $exportedFiles = @()
            foreach ($resourceName in $script:EmbeddedResources.Keys) {
                $outputFile = Join-Path $outputPath $resourceName

                # Check if file exists
                if (Test-Path $outputFile) {
                    $overwrite = [System.Windows.Forms.MessageBox]::Show(
                        "File '$resourceName' already exists.`n`nOverwrite?",
                        "File Exists",
                        [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
                        [System.Windows.Forms.MessageBoxIcon]::Question
                    )

                    if ($overwrite -eq [System.Windows.Forms.DialogResult]::Cancel) {
                        return
                    }
                    if ($overwrite -eq [System.Windows.Forms.DialogResult]::No) {
                        continue
                    }
                }

                # Export the file
                $bytes = [Convert]::FromBase64String($script:EmbeddedResources[$resourceName])
                [System.IO.File]::WriteAllBytes($outputFile, $bytes)
                $exportedFiles += $resourceName
            }

            if ($exportedFiles.Count -gt 0) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Successfully exported $($exportedFiles.Count) file(s) to:`n$outputPath`n`nFiles:`n$($exportedFiles -join "`n")",
                    "Export Complete",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
            }
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Error exporting resources:`n`n$($_.Exception.Message)",
                "Export Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    }
})
$menuTools.DropDownItems.Add($menuToolsExportResources)

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
# PORT CONFIGURATION TEMPLATES
# ============================================
# Placeholders: {{INTERFACE}}, {{DESCRIPTION}}, {{VLAN}}, {{OLD_VLAN}}, {{VOICE_VLAN}}, {{STATUS}}
# {{STATUS}} = "no shutdown" or "shutdown" based on Enable checkbox
# {{OLD_VLAN}} only used by FCX 7.3
# NOTE: This section must remain OUTSIDE the EMBEDDED RESOURCES block to survive packaging

$script:PortTemplates = @{
    "Cisco" = @{
        "Type1" = @"
! ========================================
! Cisco - Type1 Configuration
! Edit this template with your 60 lines
! ========================================
interface {{INTERFACE}}
 description {{DESCRIPTION}}
 switchport mode access
 switchport access vlan {{VLAN}}
 switchport voice vlan {{VOICE_VLAN}}
 {{STATUS}}
!
"@
        "Type2" = @"
! Cisco - Type2 Configuration
interface {{INTERFACE}}
 description {{DESCRIPTION}}
 switchport access vlan {{VLAN}}
 switchport voice vlan {{VOICE_VLAN}}
 {{STATUS}}
!
"@
        "Type3" = @"
! Cisco - Type3 Configuration
interface {{INTERFACE}}
 description {{DESCRIPTION}}
 switchport access vlan {{VLAN}}
 {{STATUS}}
!
"@
        "Type4" = @"
! Cisco - Type4 Configuration
interface {{INTERFACE}}
 description {{DESCRIPTION}}
 switchport access vlan {{VLAN}}
 {{STATUS}}
!
"@
        "Type5" = @"
! Cisco - Type5 Configuration
interface {{INTERFACE}}
 description {{DESCRIPTION}}
 switchport access vlan {{VLAN}}
 switchport voice vlan {{VOICE_VLAN}}
 {{STATUS}}
!
"@
        "Type6" = @"
! Cisco - Type6 Configuration
interface {{INTERFACE}}
 description {{DESCRIPTION}}
 switchport access vlan {{VLAN}}
 {{STATUS}}
!
"@
    }
    "ICX/FCX 8030" = @{
        "Type1" = @"
! ========================================
! ICX/FCX 8030 - Type1 Configuration
! Edit this template with your 60 lines
! ========================================
interface {{INTERFACE}}
 port-name {{DESCRIPTION}}
 untagged vlan {{VLAN}}
 dual-mode {{VOICE_VLAN}}
 {{STATUS}}
!
"@
        "Type2" = @"
! ICX/FCX 8030 - Type2 Configuration
interface {{INTERFACE}}
 port-name {{DESCRIPTION}}
 untagged vlan {{VLAN}}
 {{STATUS}}
!
"@
        "Type3" = @"
! ICX/FCX 8030 - Type3 Configuration
interface {{INTERFACE}}
 port-name {{DESCRIPTION}}
 untagged vlan {{VLAN}}
 {{STATUS}}
!
"@
        "Type4" = @"
! ICX/FCX 8030 - Type4 Configuration
interface {{INTERFACE}}
 port-name {{DESCRIPTION}}
 untagged vlan {{VLAN}}
 {{STATUS}}
!
"@
        "Type5" = @"
! ICX/FCX 8030 - Type5 Configuration
interface {{INTERFACE}}
 port-name {{DESCRIPTION}}
 untagged vlan {{VLAN}}
 dual-mode {{VOICE_VLAN}}
 {{STATUS}}
!
"@
        "Type6" = @"
! ICX/FCX 8030 - Type6 Configuration
interface {{INTERFACE}}
 port-name {{DESCRIPTION}}
 untagged vlan {{VLAN}}
 {{STATUS}}
!
"@
    }
    "FCX 7.3" = @{
        "Type1" = @"
! ========================================
! FCX 7.3 - Type1 Configuration
! Edit this template with your 60 lines
! ========================================
interface {{INTERFACE}}
 port-name {{DESCRIPTION}}
 untagged vlan {{VLAN}}
 dual-mode {{VOICE_VLAN}}
 ! Old VLAN was: {{OLD_VLAN}}
 {{STATUS}}
!
"@
        "Type2" = @"
! FCX 7.3 - Type2 Configuration
interface {{INTERFACE}}
 port-name {{DESCRIPTION}}
 untagged vlan {{VLAN}}
 ! Old VLAN was: {{OLD_VLAN}}
 {{STATUS}}
!
"@
        "Type3" = @"
! FCX 7.3 - Type3 Configuration
interface {{INTERFACE}}
 port-name {{DESCRIPTION}}
 untagged vlan {{VLAN}}
 ! Old VLAN was: {{OLD_VLAN}}
 {{STATUS}}
!
"@
        "Type4" = @"
! FCX 7.3 - Type4 Configuration
interface {{INTERFACE}}
 port-name {{DESCRIPTION}}
 untagged vlan {{VLAN}}
 ! Old VLAN was: {{OLD_VLAN}}
 {{STATUS}}
!
"@
        "Type5" = @"
! FCX 7.3 - Type5 Configuration
interface {{INTERFACE}}
 port-name {{DESCRIPTION}}
 untagged vlan {{VLAN}}
 dual-mode {{VOICE_VLAN}}
 ! Old VLAN was: {{OLD_VLAN}}
 {{STATUS}}
!
"@
        "Type6" = @"
! FCX 7.3 - Type6 Configuration
interface {{INTERFACE}}
 port-name {{DESCRIPTION}}
 untagged vlan {{VLAN}}
 ! Old VLAN was: {{OLD_VLAN}}
 {{STATUS}}
!
"@
    }
}

# Helper function to convert PSCustomObject to Hashtable (PowerShell 5.1 compatible)
function ConvertTo-Hashtable {
    param([Parameter(ValueFromPipeline)]$InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $collection = @()
        foreach ($object in $InputObject) { $collection += ConvertTo-Hashtable $object }
        return $collection
    }
    if ($InputObject -is [PSCustomObject]) {
        $hash = @{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $hash[$property.Name] = ConvertTo-Hashtable $property.Value
        }
        return $hash
    }
    return $InputObject
}

# Load saved templates from JSON file (overrides embedded defaults)
$templateFile = Join-Path $PSScriptRoot "PortTemplates.json"
if (Test-Path $templateFile) {
    try {
        Write-Host "Loading PortTemplates.json from: $templateFile" -ForegroundColor Cyan
        $jsonContent = Get-Content $templateFile -Raw
        $savedTemplates = $jsonContent | ConvertFrom-Json | ConvertTo-Hashtable

        $templateCount = 0
        foreach ($vendor in $savedTemplates.Keys) {
            if (-not $script:PortTemplates.ContainsKey($vendor)) {
                $script:PortTemplates[$vendor] = @{}
            }
            foreach ($portType in $savedTemplates[$vendor].Keys) {
                $script:PortTemplates[$vendor][$portType] = $savedTemplates[$vendor][$portType]
                $templateCount++
            }
            Write-Host "  Loaded vendor '$vendor' with $($savedTemplates[$vendor].Keys.Count) port types" -ForegroundColor Green
        }
        Write-Host "Successfully loaded $templateCount templates from JSON file" -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR loading PortTemplates.json: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Yellow
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to load PortTemplates.json:`n`n$($_.Exception.Message)`n`nUsing embedded defaults instead.",
            "Template Load Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
    }
} else {
    Write-Host "PortTemplates.json not found at: $templateFile" -ForegroundColor Yellow
    Write-Host "Using embedded default templates" -ForegroundColor Yellow
}

# ============================================
# EMBEDDED RESOURCES (Auto-generated)
# ============================================
# Generated: Placeholder - No resources embedded yet
# Files: 0
# To update: Place files in 'resources' folder and run Package-Resources.ps1

$script:EmbeddedResources = @{
    # Resources will be added here by Package-Resources.ps1
    # Example: 'template.rdox' = 'base64encodedcontent...'
}

function Get-EmbeddedResourceList {
    <#
    .SYNOPSIS
        Returns list of embedded resource files
    #>
    return $script:EmbeddedResources.Keys | Sort-Object
}

function Export-EmbeddedResource {
    <#
    .SYNOPSIS
        Exports an embedded resource to the specified path
    .PARAMETER Name
        Name of the resource file to export
    .PARAMETER OutputPath
        Directory to export to (defaults to current directory)
    .PARAMETER Force
        Overwrite existing files
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [string]$OutputPath = (Get-Location).Path,
        [switch]$Force
    )

    if (-not $script:EmbeddedResources.ContainsKey($Name)) {
        throw "Resource '$Name' not found. Available: $($script:EmbeddedResources.Keys -join ', ')"
    }

    $outputFile = Join-Path $OutputPath $Name

    if ((Test-Path $outputFile) -and -not $Force) {
        throw "File already exists: $outputFile. Use -Force to overwrite."
    }

    $bytes = [Convert]::FromBase64String($script:EmbeddedResources[$Name])
    [System.IO.File]::WriteAllBytes($outputFile, $bytes)

    return $outputFile
}

function Export-AllEmbeddedResources {
    <#
    .SYNOPSIS
        Exports all embedded resources to the specified path
    .PARAMETER OutputPath
        Directory to export to (defaults to current directory)
    .PARAMETER Force
        Overwrite existing files
    #>
    param(
        [string]$OutputPath = (Get-Location).Path,
        [switch]$Force
    )

    $exported = @()
    foreach ($name in $script:EmbeddedResources.Keys) {
        try {
            $file = Export-EmbeddedResource -Name $name -OutputPath $OutputPath -Force:$Force
            $exported += $file
        }
        catch {
            Write-Warning "Failed to export ${name}: $($_.Exception.Message)"
        }
    }
    return $exported
}

# ============================================
# END EMBEDDED RESOURCES
# ============================================

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
$tab0.AutoScroll = $true
$tab0.AutoScrollMinSize = New-Object System.Drawing.Size(980, 650)
$tab0.Padding = New-Object System.Windows.Forms.Padding(5)
$tabControl.Controls.Add($tab0)
Add-IconToTab -Tab $tab0 -IconName "Stats"

# Title Label
$lblDashboardTitle = New-Object System.Windows.Forms.Label
$lblDashboardTitle.Text = "OctoNav System Dashboard"
$lblDashboardTitle.Location = New-Object System.Drawing.Point(15, 15)
$lblDashboardTitle.Size = New-Object System.Drawing.Size(900, 30)
$lblDashboardTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$lblDashboardTitle.Anchor = "Top,Left,Right"
$tab0.Controls.Add($lblDashboardTitle)

# System Health Panels
$healthGroupBox = New-Object System.Windows.Forms.GroupBox
$healthGroupBox.Text = "System Health"
$healthGroupBox.Location = New-Object System.Drawing.Point(15, 55)
$healthGroupBox.Size = New-Object System.Drawing.Size(920, 130)
$healthGroupBox.Anchor = "Top,Left,Right"
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
$quickActionsGroupBox.Anchor = "Top,Left,Right"
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
$recentActivityGroupBox.Anchor = "Top,Bottom,Left,Right"
$tab0.Controls.Add($recentActivityGroupBox)

$script:lstRecentActivity = New-Object System.Windows.Forms.ListBox
$script:lstRecentActivity.Location = New-Object System.Drawing.Point(15, 25)
$script:lstRecentActivity.Size = New-Object System.Drawing.Size(885, 240)
$script:lstRecentActivity.Font = New-Object System.Drawing.Font("Consolas", 9)
$script:lstRecentActivity.Anchor = "Top,Bottom,Left,Right"
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
$tab1.AutoScroll = $true
$tab1.AutoScrollMinSize = New-Object System.Drawing.Size(980, 680)
$tab1.Padding = New-Object System.Windows.Forms.Padding(5)
$tabControl.Controls.Add($tab1)
Add-IconToTab -Tab $tab1 -IconName "Network"

# Admin Status Indicator for Network Config Tab
$lblAdminStatus = New-Object System.Windows.Forms.Label
$lblAdminStatus.Size = New-Object System.Drawing.Size(940, 25)
$lblAdminStatus.Location = New-Object System.Drawing.Point(10, 10)
$lblAdminStatus.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblAdminStatus.TextAlign = "MiddleLeft"
$lblAdminStatus.Anchor = "Top,Left,Right"
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
$netGroupBox.Anchor = "Top,Left,Right"
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
$txtIPAddress.Text = "192.168.1.101"
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
$txtGateway.Text = "192.168.1.100"
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
$netLogBox.Anchor = "Top,Bottom,Left,Right"
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
$tab2.AutoScroll = $true
$tab2.AutoScrollMinSize = New-Object System.Drawing.Size(1280, 600)
$tab2.Padding = New-Object System.Windows.Forms.Padding(5)
$tabControl.Controls.Add($tab2)
Add-IconToTab -Tab $tab2 -IconName "Server"

# Info Label
$lblDHCPInfo = New-Object System.Windows.Forms.Label
$lblDHCPInfo.Text = "Collect and analyze DHCP scope statistics from domain DHCP servers"
$lblDHCPInfo.Location = New-Object System.Drawing.Point(15, 15)
$lblDHCPInfo.Size = New-Object System.Drawing.Size(900, 20)
$lblDHCPInfo.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)
$lblDHCPInfo.ForeColor = [System.Drawing.Color]::DarkBlue
$lblDHCPInfo.Anchor = "Top,Left"
$tab2.Controls.Add($lblDHCPInfo)

# Server Configuration Group
$dhcpServerGroupBox = New-Object System.Windows.Forms.GroupBox
$dhcpServerGroupBox.Text = "Server Selection"
$dhcpServerGroupBox.Size = New-Object System.Drawing.Size(920, 150)
$dhcpServerGroupBox.Location = New-Object System.Drawing.Point(10, 40)
$dhcpServerGroupBox.Anchor = "Top,Left,Right"
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
$dhcpScopeGroupBox.Size = New-Object System.Drawing.Size(920, 160)
$dhcpScopeGroupBox.Location = New-Object System.Drawing.Point(10, 200)
$dhcpScopeGroupBox.Anchor = "Top,Left,Right"
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
$btnSelectAllScopes.Text = "Select All Visible"
$btnSelectAllScopes.Size = New-Object System.Drawing.Size(120, 30)
$btnSelectAllScopes.Location = New-Object System.Drawing.Point(720, 70)
$dhcpScopeGroupBox.Controls.Add($btnSelectAllScopes)

$btnSelectNoneScopes = New-Object System.Windows.Forms.Button
$btnSelectNoneScopes.Text = "Select None"
$btnSelectNoneScopes.Size = New-Object System.Drawing.Size(100, 30)
$btnSelectNoneScopes.Location = New-Object System.Drawing.Point(720, 105)
$dhcpScopeGroupBox.Controls.Add($btnSelectNoneScopes)

# Visible items count label
$script:lblVisibleScopes = New-Object System.Windows.Forms.Label
$script:lblVisibleScopes.Text = ""
$script:lblVisibleScopes.Size = New-Object System.Drawing.Size(120, 15)
$script:lblVisibleScopes.Location = New-Object System.Drawing.Point(845, 78)
$script:lblVisibleScopes.Font = New-Object System.Drawing.Font("Arial", 7, [System.Drawing.FontStyle]::Italic)
$script:lblVisibleScopes.ForeColor = [System.Drawing.Color]::DarkBlue
$dhcpScopeGroupBox.Controls.Add($script:lblVisibleScopes)

# Note label
$lblScopeNote = New-Object System.Windows.Forms.Label
$lblScopeNote.Text = "Workflow: Refresh cache → Filter (optional) → Select All Visible → Collect DHCP Statistics"
$lblScopeNote.Location = New-Object System.Drawing.Point(15, 147)
$lblScopeNote.Size = New-Object System.Drawing.Size(900, 15)
$lblScopeNote.Font = New-Object System.Drawing.Font("Arial", 7, [System.Drawing.FontStyle]::Italic)
$lblScopeNote.ForeColor = [System.Drawing.Color]::DarkGreen
$dhcpScopeGroupBox.Controls.Add($lblScopeNote)

# Collection Options Group
$dhcpOptionsGroupBox = New-Object System.Windows.Forms.GroupBox
$dhcpOptionsGroupBox.Text = "Collection Options"
$dhcpOptionsGroupBox.Size = New-Object System.Drawing.Size(920, 90)
$dhcpOptionsGroupBox.Location = New-Object System.Drawing.Point(10, 370)
$dhcpOptionsGroupBox.Anchor = "Top,Left,Right"
$tab2.Controls.Add($dhcpOptionsGroupBox)

# Row 1: DNS and Option 60
$chkIncludeDNS = New-Object System.Windows.Forms.CheckBox
$chkIncludeDNS.Text = "Include DNS (Option 6)"
$chkIncludeDNS.Size = New-Object System.Drawing.Size(180, 20)
$chkIncludeDNS.Location = New-Object System.Drawing.Point(15, 25)
$dhcpOptionsGroupBox.Controls.Add($chkIncludeDNS)

$chkIncludeOption60 = New-Object System.Windows.Forms.CheckBox
$chkIncludeOption60.Text = "Include Option 60 (Vendor Class)"
$chkIncludeOption60.Size = New-Object System.Drawing.Size(230, 20)
$chkIncludeOption60.Location = New-Object System.Drawing.Point(210, 25)
$chkIncludeOption60.Checked = $false
$dhcpOptionsGroupBox.Controls.Add($chkIncludeOption60)

$chkIncludeOption43 = New-Object System.Windows.Forms.CheckBox
$chkIncludeOption43.Text = "Include Option 43 (Vendor-Specific)"
$chkIncludeOption43.Size = New-Object System.Drawing.Size(260, 20)
$chkIncludeOption43.Location = New-Object System.Drawing.Point(455, 25)
$chkIncludeOption43.Checked = $false
$dhcpOptionsGroupBox.Controls.Add($chkIncludeOption43)

# Row 2: Group by Scope and Concurrency
$script:chkGroupByScope = New-Object System.Windows.Forms.CheckBox
$script:chkGroupByScope.Text = "Group by Scope ID on Export"
$script:chkGroupByScope.Size = New-Object System.Drawing.Size(210, 20)
$script:chkGroupByScope.Location = New-Object System.Drawing.Point(15, 55)
$script:chkGroupByScope.Checked = $false
$dhcpOptionsGroupBox.Controls.Add($script:chkGroupByScope)

$lblConcurrency = New-Object System.Windows.Forms.Label
$lblConcurrency.Text = "Parallel Operations:"
$lblConcurrency.Size = New-Object System.Drawing.Size(120, 20)
$lblConcurrency.Location = New-Object System.Drawing.Point(455, 55)
$dhcpOptionsGroupBox.Controls.Add($lblConcurrency)

$script:numConcurrency = New-Object System.Windows.Forms.NumericUpDown
$script:numConcurrency.Minimum = 20
$script:numConcurrency.Maximum = 50
$script:numConcurrency.Value = 20
$script:numConcurrency.Size = New-Object System.Drawing.Size(60, 20)
$script:numConcurrency.Location = New-Object System.Drawing.Point(575, 53)
$dhcpOptionsGroupBox.Controls.Add($script:numConcurrency)

$lblConcurrencyNote = New-Object System.Windows.Forms.Label
$lblConcurrencyNote.Text = "(20-50 servers)"
$lblConcurrencyNote.Size = New-Object System.Drawing.Size(100, 20)
$lblConcurrencyNote.Location = New-Object System.Drawing.Point(640, 55)
$lblConcurrencyNote.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
$lblConcurrencyNote.ForeColor = [System.Drawing.Color]::Gray
$dhcpOptionsGroupBox.Controls.Add($lblConcurrencyNote)

# Actions Group
$dhcpActionsGroupBox = New-Object System.Windows.Forms.GroupBox
$dhcpActionsGroupBox.Text = "Actions"
$dhcpActionsGroupBox.Size = New-Object System.Drawing.Size(920, 65)
$dhcpActionsGroupBox.Location = New-Object System.Drawing.Point(10, 465)
$dhcpActionsGroupBox.Anchor = "Top,Left,Right"
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
$lblCollectionLog.Location = New-Object System.Drawing.Point(945, 15)
$lblCollectionLog.Size = New-Object System.Drawing.Size(200, 20)
$lblCollectionLog.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$lblCollectionLog.ForeColor = [System.Drawing.Color]::DarkBlue
$lblCollectionLog.Anchor = "Top,Right"
$tab2.Controls.Add($lblCollectionLog)

# DHCP Log (right side panel)
$dhcpLogBox = New-Object System.Windows.Forms.RichTextBox
$dhcpLogBox.Size = New-Object System.Drawing.Size(280, 480)
$dhcpLogBox.Location = New-Object System.Drawing.Point(945, 40)
$dhcpLogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$dhcpLogBox.ReadOnly = $true
$dhcpLogBox.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
$dhcpLogBox.WordWrap = $false
$dhcpLogBox.HideSelection = $false
$dhcpLogBox.DetectUrls = $false
$dhcpLogBox.Multiline = $true
$dhcpLogBox.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$dhcpLogBox.Anchor = "Top,Bottom,Right"
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
            Write-Log -Message "DEBUG: Processing $($script:lstDHCPScopes.CheckedItems.Count) checked scope(s)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

            # Extract ScopeId and Server from DisplayName format: "Name (ScopeId) - Server"
            foreach ($item in $script:lstDHCPScopes.CheckedItems) {
                $displayName = $item.ToString()
                Write-Log -Message "DEBUG: Looking for scope: $displayName" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

                # Find matching scope in cache - use First to handle duplicates
                $matchingScope = $script:allDHCPScopes | Where-Object { $_.DisplayName -eq $displayName } | Select-Object -First 1

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
                    Write-Log -Message "DEBUG: Added scope $($matchingScope.ScopeId) from server $($matchingScope.Server)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                } else {
                    Write-Log -Message "WARNING: Could not find scope in cache: $displayName" -Color "Warning" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                }
            }
            Write-Log -Message "Using $($selectedScopes.Count) pre-selected scope(s) from cache" -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        } else {
            Write-Log -Message "DEBUG: No scopes checked in list (CheckedItems.Count = 0)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
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

        # When using pre-selected scopes, don't pass separate server list - let Get-DHCPScopeStatistics extract servers internally
        # But show user what servers will be queried for debugging
        if ($specificServers.Count -eq 0 -and $selectedScopes.Count -gt 0) {
            # Extract unique servers just for logging purposes
            $scopeServers = @($selectedScopes |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_.Server) } |
                Select-Object -ExpandProperty Server -Unique)

            if ($scopeServers.Count -gt 0) {
                Write-Log -Message "Will query $($scopeServers.Count) server(s) from selected scopes: $($scopeServers -join ', ')" -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            }

            # NOTE: We do NOT set $specificServers here - let Get-DHCPScopeStatistics extract servers from SelectedScopes internally
            # This avoids array passing issues and lets the function properly group scopes by server
        }

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

        $script:includeDNS = $chkIncludeDNS.Checked
        $script:includeOption60 = $chkIncludeOption60.Checked
        $script:includeOption43 = $chkIncludeOption43.Checked

        # Call DHCP collection function in background to keep UI responsive
        Write-Log -Message "Starting DHCP statistics collection in background..." -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

        # Log what we're passing to the background operation
        Write-Log -Message "DEBUG: Scope filters: $($scopeFilters.Count) items" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        Write-Log -Message "DEBUG: Specific servers: $($specificServers.Count) items - $($specificServers -join ', ')" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        Write-Log -Message "DEBUG: Include DNS: $($script:includeDNS)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        Write-Log -Message "DEBUG: Include Option 60: $($script:includeOption60)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
        Write-Log -Message "DEBUG: Include Option 43: $($script:includeOption43)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

        # Run collection in background
        $script:dhcpBackgroundTimer = Invoke-BackgroundOperation -ScriptBlock {
            param($selectedScopes, $filters, $servers, $dns, $opt60, $opt43, $stopRef, $scriptRoot)

            $debugLog = @()

            try {
                $debugLog += "Background: Starting collection"

                # Flatten all array parameters that may be nested due to comma operator in ArgumentList
                # The comma operator (,$var) prevents unrolling but creates nested arrays

                # Flatten selectedScopes
                if ($selectedScopes -is [array] -and $selectedScopes.Count -eq 1 -and $selectedScopes[0] -is [array]) {
                    $debugLog += "Background: Detected nested selectedScopes array - flattening"
                    $selectedScopes = $selectedScopes[0]
                }

                # Flatten filters
                if ($filters -is [array] -and $filters.Count -eq 1 -and $filters[0] -is [array]) {
                    $debugLog += "Background: Detected nested filters array - flattening"
                    $filters = $filters[0]
                }

                # Flatten servers
                if ($servers -is [array] -and $servers.Count -eq 1 -and $servers[0] -is [array]) {
                    $debugLog += "Background: Detected nested servers array - flattening"
                    $servers = $servers[0]
                }

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
                $servers = @($servers | Where-Object {
                    $_ -ne $null -and
                    $_ -is [string] -and
                    -not [string]::IsNullOrWhiteSpace($_)
                })

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
                $debugLog += "Background:   - IncludeOption60: $opt60"
                $debugLog += "Background:   - IncludeOption43: $opt43"

                $result = Get-DHCPScopeStatistics -SelectedScopes $selectedScopes -ScopeFilters $filters -SpecificServers $servers -IncludeDNS $dns -IncludeOption60 $opt60 -IncludeOption43 $opt43 -StopToken $stopRef

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

        } -ArgumentList @((,$selectedScopes), (,$scopeFilters), (,$specificServers), $script:includeDNS, $script:includeOption60, $script:includeOption43, ([ref]$script:dhcpStopRequested), $scriptPath) -OnComplete {
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

                    # Format data with specific columns in order (build column list dynamically)
                    $exportColumns = @('ScopeId', 'DHCPServer', 'Description', 'AddressesFree', 'AddressesInUse', 'PercentageInUse')

                    # Debug: Log checkbox states during auto-export
                    Write-Log -Message "DEBUG AUTO-EXPORT: includeDNS=$($script:includeDNS), includeOption60=$($script:includeOption60), includeOption43=$($script:includeOption43)" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

                    if ($dataToExport.Count -gt 0) {
                        $firstItem = $dataToExport[0]

                        # Debug: Log available properties
                        $availableProps = $firstItem.PSObject.Properties.Name -join ', '
                        Write-Log -Message "DEBUG AUTO-EXPORT: Available properties: $availableProps" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

                        $hasDNS = $firstItem.PSObject.Properties.Name -contains 'DNSServers'
                        $hasOpt60 = $firstItem.PSObject.Properties.Name -contains 'Option60'
                        $hasOpt43 = $firstItem.PSObject.Properties.Name -contains 'Option43'
                        Write-Log -Message "DEBUG AUTO-EXPORT: hasDNS=$hasDNS, hasOpt60=$hasOpt60, hasOpt43=$hasOpt43" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme

                        if ($hasDNS -and $script:includeDNS) {
                            $exportColumns += 'DNSServers'
                            Write-Log -Message "Including DNS server information in export" -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                        }

                        if ($hasOpt60 -and $script:includeOption60) {
                            $exportColumns += 'Option60'
                            Write-Log -Message "Including Option 60 information in export" -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                        }

                        if ($hasOpt43 -and $script:includeOption43) {
                            $exportColumns += 'Option43'
                            Write-Log -Message "Including Option 43 information in export" -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                        }
                    }

                    Write-Log -Message "DEBUG AUTO-EXPORT: Final export columns: $($exportColumns -join ', ')" -Color "Debug" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
                    $exportData = $dataToExport | Select-Object $exportColumns

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

        # Update visible count label
        $script:lblVisibleScopes.Text = "($($scopes.Count) visible)"

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

    # Update visible count label
    $script:lblVisibleScopes.Text = "($($script:lstDHCPScopes.Items.Count) visible)"
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

        # Format data with specific columns in order (build column list dynamically)
        $exportColumns = @('ScopeId', 'DHCPServer', 'Description', 'AddressesFree', 'AddressesInUse', 'PercentageInUse')

        if ($dataToExport.Count -gt 0) {
            $firstItem = $dataToExport[0]

            if ($firstItem.PSObject.Properties.Name -contains 'DNSServers') {
                $exportColumns += 'DNSServers'
                Write-Log -Message "Including DNS server information in export" -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            }

            if ($firstItem.PSObject.Properties.Name -contains 'Option60') {
                $exportColumns += 'Option60'
                Write-Log -Message "Including Option 60 information in export" -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            }

            if ($firstItem.PSObject.Properties.Name -contains 'Option43') {
                $exportColumns += 'Option43'
                Write-Log -Message "Including Option 43 information in export" -Color "Info" -LogBox $dhcpLogBox -Theme $script:CurrentTheme
            }
        }

        $exportData = $dataToExport | Select-Object $exportColumns

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
$tab3.AutoScroll = $true
$tab3.AutoScrollMinSize = New-Object System.Drawing.Size(980, 920)
$tab3.Padding = New-Object System.Windows.Forms.Padding(5)
$tabControl.Controls.Add($tab3)
Add-IconToTab -Tab $tab3 -IconName "DNA"

# Connection Group
$dnaConnGroupBox = New-Object System.Windows.Forms.GroupBox
$dnaConnGroupBox.Text = "DNA Center Connection"
$dnaConnGroupBox.Size = New-Object System.Drawing.Size(940, 140)
$dnaConnGroupBox.Location = New-Object System.Drawing.Point(10, 10)
$dnaConnGroupBox.Anchor = "Top,Left,Right"
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

# Device Filter & Selection Group (Enhanced)
$dnaFilterGroupBox = New-Object System.Windows.Forms.GroupBox
$dnaFilterGroupBox.Text = "Device Filtering & Selection"
$dnaFilterGroupBox.Size = New-Object System.Drawing.Size(940, 350)
$dnaFilterGroupBox.Location = New-Object System.Drawing.Point(10, 160)
$dnaFilterGroupBox.Anchor = "Top,Left,Right"
$tab3.Controls.Add($dnaFilterGroupBox)

# Row 1: Hostname Search
$lblFilterHostname = New-Object System.Windows.Forms.Label
$lblFilterHostname.Text = "Hostname Search:"
$lblFilterHostname.Size = New-Object System.Drawing.Size(110, 20)
$lblFilterHostname.Location = New-Object System.Drawing.Point(20, 30)
$dnaFilterGroupBox.Controls.Add($lblFilterHostname)

$txtFilterHostname = New-Object System.Windows.Forms.TextBox
$txtFilterHostname.Size = New-Object System.Drawing.Size(200, 20)
$txtFilterHostname.Location = New-Object System.Drawing.Point(135, 28)
$txtFilterHostname.Enabled = $false
$dnaFilterGroupBox.Controls.Add($txtFilterHostname)

# Family Filter (ComboBox)
$lblFilterFamily = New-Object System.Windows.Forms.Label
$lblFilterFamily.Text = "Family:"
$lblFilterFamily.Size = New-Object System.Drawing.Size(50, 20)
$lblFilterFamily.Location = New-Object System.Drawing.Point(360, 30)
$dnaFilterGroupBox.Controls.Add($lblFilterFamily)

$cmbFilterFamily = New-Object System.Windows.Forms.ComboBox
$cmbFilterFamily.Size = New-Object System.Drawing.Size(180, 25)
$cmbFilterFamily.Location = New-Object System.Drawing.Point(415, 28)
$cmbFilterFamily.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$cmbFilterFamily.Enabled = $false
$dnaFilterGroupBox.Controls.Add($cmbFilterFamily)

# Role Filter (ComboBox)
$lblFilterRole = New-Object System.Windows.Forms.Label
$lblFilterRole.Text = "Role:"
$lblFilterRole.Size = New-Object System.Drawing.Size(40, 20)
$lblFilterRole.Location = New-Object System.Drawing.Point(620, 30)
$dnaFilterGroupBox.Controls.Add($lblFilterRole)

$cmbFilterRole = New-Object System.Windows.Forms.ComboBox
$cmbFilterRole.Size = New-Object System.Drawing.Size(180, 25)
$cmbFilterRole.Location = New-Object System.Drawing.Point(665, 28)
$cmbFilterRole.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$cmbFilterRole.Enabled = $false
$dnaFilterGroupBox.Controls.Add($cmbFilterRole)

# Row 2: IP Address Filter (ComboBox)
$lblFilterIPAddress = New-Object System.Windows.Forms.Label
$lblFilterIPAddress.Text = "IP Address:"
$lblFilterIPAddress.Size = New-Object System.Drawing.Size(110, 20)
$lblFilterIPAddress.Location = New-Object System.Drawing.Point(20, 65)
$dnaFilterGroupBox.Controls.Add($lblFilterIPAddress)

$cmbFilterIPAddress = New-Object System.Windows.Forms.ComboBox
$cmbFilterIPAddress.Size = New-Object System.Drawing.Size(200, 25)
$cmbFilterIPAddress.Location = New-Object System.Drawing.Point(135, 63)
$cmbFilterIPAddress.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$cmbFilterIPAddress.Enabled = $false
$dnaFilterGroupBox.Controls.Add($cmbFilterIPAddress)

# Select All Checkbox
$chkSelectAll = New-Object System.Windows.Forms.CheckBox
$chkSelectAll.Text = "Select All (Current Filter)"
$chkSelectAll.Size = New-Object System.Drawing.Size(180, 25)
$chkSelectAll.Location = New-Object System.Drawing.Point(360, 63)
$chkSelectAll.Enabled = $false
$dnaFilterGroupBox.Controls.Add($chkSelectAll)

# Apply Selection Button
$btnApplyDeviceFilter = New-Object System.Windows.Forms.Button
$btnApplyDeviceFilter.Text = "Apply Selection"
$btnApplyDeviceFilter.Size = New-Object System.Drawing.Size(120, 28)
$btnApplyDeviceFilter.Location = New-Object System.Drawing.Point(565, 61)
$btnApplyDeviceFilter.Enabled = $false
$dnaFilterGroupBox.Controls.Add($btnApplyDeviceFilter)

# Reset Filter Button
$btnResetDeviceFilter = New-Object System.Windows.Forms.Button
$btnResetDeviceFilter.Text = "Reset All"
$btnResetDeviceFilter.Size = New-Object System.Drawing.Size(120, 28)
$btnResetDeviceFilter.Location = New-Object System.Drawing.Point(695, 61)
$btnResetDeviceFilter.Enabled = $false
$dnaFilterGroupBox.Controls.Add($btnResetDeviceFilter)

# Device Selection Label
$lblDeviceListTitle = New-Object System.Windows.Forms.Label
$lblDeviceListTitle.Text = "Available Devices (check devices to select):"
$lblDeviceListTitle.Size = New-Object System.Drawing.Size(400, 20)
$lblDeviceListTitle.Location = New-Object System.Drawing.Point(20, 100)
$lblDeviceListTitle.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Bold)
$dnaFilterGroupBox.Controls.Add($lblDeviceListTitle)

# CheckedListBox for Device Selection
$lstDevices = New-Object System.Windows.Forms.CheckedListBox
$lstDevices.Size = New-Object System.Drawing.Size(900, 180)
$lstDevices.Location = New-Object System.Drawing.Point(20, 125)
$lstDevices.CheckOnClick = $true
$lstDevices.Enabled = $false
$lstDevices.Font = New-Object System.Drawing.Font("Consolas", 9)
$dnaFilterGroupBox.Controls.Add($lstDevices)

# Device Selection Status
$lblDeviceSelectionStatus = New-Object System.Windows.Forms.Label
$lblDeviceSelectionStatus.Text = "Showing: 0 devices | Selected: 0"
$lblDeviceSelectionStatus.Size = New-Object System.Drawing.Size(500, 20)
$lblDeviceSelectionStatus.Location = New-Object System.Drawing.Point(20, 315)
$lblDeviceSelectionStatus.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Bold)
$lblDeviceSelectionStatus.ForeColor = [System.Drawing.Color]::DarkBlue
$dnaFilterGroupBox.Controls.Add($lblDeviceSelectionStatus)

# TreeView Functions Group
$dnaTreeGroupBox = New-Object System.Windows.Forms.GroupBox
$dnaTreeGroupBox.Text = "DNA Center Functions - TreeView (Double-click to Execute)"
$dnaTreeGroupBox.Size = New-Object System.Drawing.Size(460, 270)
$dnaTreeGroupBox.Location = New-Object System.Drawing.Point(10, 520)
$dnaTreeGroupBox.Anchor = "Top,Left"
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
$dnaFavoritesGroupBox.Location = New-Object System.Drawing.Point(480, 520)
$dnaFavoritesGroupBox.Anchor = "Top,Right"
$tab3.Controls.Add($dnaFavoritesGroupBox)

$script:lstFavorites = New-Object System.Windows.Forms.ListBox
$script:lstFavorites.Location = New-Object System.Drawing.Point(15, 25)
$script:lstFavorites.Size = New-Object System.Drawing.Size(430, 230)
$script:lstFavorites.Font = New-Object System.Drawing.Font("Consolas", 9)
$dnaFavoritesGroupBox.Controls.Add($script:lstFavorites)

# DNA Log
$dnaLogBox = New-Object System.Windows.Forms.RichTextBox
$dnaLogBox.Size = New-Object System.Drawing.Size(940, 90)
$dnaLogBox.Location = New-Object System.Drawing.Point(10, 800)
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
            # Populate filter ComboBoxes with unique values from loaded devices
            Populate-DNAFilterComboBoxes -FamilyComboBox $cmbFilterFamily -RoleComboBox $cmbFilterRole -IPComboBox $cmbFilterIPAddress

            # Populate device list with all devices
            Update-DNADeviceList -DeviceListBox $lstDevices -HostnameFilter $txtFilterHostname -FamilyFilter $cmbFilterFamily -RoleFilter $cmbFilterRole -IPFilter $cmbFilterIPAddress -StatusLabel $lblDeviceSelectionStatus -SelectAllCheckbox $chkSelectAll

            # Enable filter controls
            foreach ($control in @($txtFilterHostname, $cmbFilterIPAddress, $cmbFilterRole, $cmbFilterFamily, $lstDevices, $chkSelectAll, $btnApplyDeviceFilter, $btnResetDeviceFilter)) {
                $control.Enabled = $true
            }

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
        # Get checked devices from CheckedListBox
        $selectedDevices = @()
        for ($i = 0; $i -lt $lstDevices.Items.Count; $i++) {
            if ($lstDevices.GetItemChecked($i)) {
                $itemText = $lstDevices.Items[$i].ToString()
                # Extract device ID from format: "hostname - ip - role - family [id]"
                if ($itemText -match '\[([^\]]+)\]$') {
                    $deviceId = $matches[1]
                    $device = $global:allDNADevices | Where-Object { $_.id -eq $deviceId }
                    if ($device) {
                        $selectedDevices += $device
                    }
                }
            }
        }

        # Update global selected devices
        $global:selectedDNADevices = $selectedDevices

        if ($selectedDevices.Count -eq 0) {
            Write-Log -Message "No devices selected. DNA Center functions will not have any target devices." -Color "Yellow" -LogBox $dnaLogBox
            [System.Windows.Forms.MessageBox]::Show("No devices selected.`nPlease check devices to select them for DNA Center operations.", "No Selection", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        } else {
            Write-Log -Message "Applied selection: $($selectedDevices.Count) device(s) selected for DNA Center operations" -Color "Green" -LogBox $dnaLogBox
            [System.Windows.Forms.MessageBox]::Show("Selection applied successfully!`nSelected: $($selectedDevices.Count) device(s)", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    } catch {
        Write-Log -Message "Error applying selection: $($_.Exception.Message)" -Color "Red" -LogBox $dnaLogBox
        [System.Windows.Forms.MessageBox]::Show("Error applying selection: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$btnResetDeviceFilter.Add_Click({
    try {
        # Reset filters
        $txtFilterHostname.Clear()
        $cmbFilterIPAddress.SelectedIndex = 0
        $cmbFilterRole.SelectedIndex = 0
        $cmbFilterFamily.SelectedIndex = 0
        $chkSelectAll.Checked = $false

        # Uncheck all devices in the list
        for ($i = 0; $i -lt $lstDevices.Items.Count; $i++) {
            $lstDevices.SetItemChecked($i, $false)
        }

        # Refresh device list (will show all devices)
        Update-DNADeviceList -DeviceListBox $lstDevices -HostnameFilter $txtFilterHostname -FamilyFilter $cmbFilterFamily -RoleFilter $cmbFilterRole -IPFilter $cmbFilterIPAddress -StatusLabel $lblDeviceSelectionStatus -SelectAllCheckbox $chkSelectAll

        # Reset selection to all devices
        Reset-DNADeviceSelection -LogBox $dnaLogBox

        [System.Windows.Forms.MessageBox]::Show("Filters and selection have been reset.", "Reset", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        Write-Log -Message "Error resetting filters: $($_.Exception.Message)" -Color "Red" -LogBox $dnaLogBox
        [System.Windows.Forms.MessageBox]::Show("Error resetting filters: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# Live filtering event handlers for DNA Center device selection
# Flag to prevent recursive updates when Select All is clicked
$script:updatingCheckboxes = $false

$txtFilterHostname.Add_TextChanged({
    if ($lstDevices.Enabled) {
        Update-DNADeviceList -DeviceListBox $lstDevices -HostnameFilter $txtFilterHostname -FamilyFilter $cmbFilterFamily -RoleFilter $cmbFilterRole -IPFilter $cmbFilterIPAddress -StatusLabel $lblDeviceSelectionStatus -SelectAllCheckbox $chkSelectAll
    }
})

$cmbFilterFamily.Add_SelectedIndexChanged({
    if ($lstDevices.Enabled -and $cmbFilterFamily.SelectedIndex -ge 0) {
        Update-DNADeviceList -DeviceListBox $lstDevices -HostnameFilter $txtFilterHostname -FamilyFilter $cmbFilterFamily -RoleFilter $cmbFilterRole -IPFilter $cmbFilterIPAddress -StatusLabel $lblDeviceSelectionStatus -SelectAllCheckbox $chkSelectAll
    }
})

$cmbFilterRole.Add_SelectedIndexChanged({
    if ($lstDevices.Enabled -and $cmbFilterRole.SelectedIndex -ge 0) {
        Update-DNADeviceList -DeviceListBox $lstDevices -HostnameFilter $txtFilterHostname -FamilyFilter $cmbFilterFamily -RoleFilter $cmbFilterRole -IPFilter $cmbFilterIPAddress -StatusLabel $lblDeviceSelectionStatus -SelectAllCheckbox $chkSelectAll
    }
})

$cmbFilterIPAddress.Add_SelectedIndexChanged({
    if ($lstDevices.Enabled -and $cmbFilterIPAddress.SelectedIndex -ge 0) {
        Update-DNADeviceList -DeviceListBox $lstDevices -HostnameFilter $txtFilterHostname -FamilyFilter $cmbFilterFamily -RoleFilter $cmbFilterRole -IPFilter $cmbFilterIPAddress -StatusLabel $lblDeviceSelectionStatus -SelectAllCheckbox $chkSelectAll
    }
})

# Select All checkbox handler
$chkSelectAll.Add_CheckedChanged({
    if ($lstDevices.Enabled -and -not $script:updatingCheckboxes) {
        $script:updatingCheckboxes = $true
        try {
            for ($i = 0; $i -lt $lstDevices.Items.Count; $i++) {
                $lstDevices.SetItemChecked($i, $chkSelectAll.Checked)
            }
            # Update status label
            $checkedCount = if ($chkSelectAll.Checked) { $lstDevices.Items.Count } else { 0 }
            $lblDeviceSelectionStatus.Text = "Showing: $($lstDevices.Items.Count) devices | Selected: $checkedCount"
        } finally {
            $script:updatingCheckboxes = $false
        }
    }
})

# CheckedListBox ItemCheck event to update status in real-time
$lstDevices.Add_ItemCheck({
    param($sender, $e)
    if ($script:updatingCheckboxes) { return }

    # Use BeginInvoke to ensure the checked state is updated before counting
    $lstDevices.BeginInvoke([Action]{
        $checkedCount = 0
        for ($i = 0; $i -lt $lstDevices.Items.Count; $i++) {
            if ($lstDevices.GetItemChecked($i)) {
                $checkedCount++
            }
        }
        $lblDeviceSelectionStatus.Text = "Showing: $($lstDevices.Items.Count) devices | Selected: $checkedCount"
    })
})

# ============================================
# TAB 4: FILE COMPARISON
# ============================================

$tab4 = New-Object System.Windows.Forms.TabPage
$tab4.Text = "File Compare"
$tab4.AutoScroll = $true
$tab4.AutoScrollMinSize = New-Object System.Drawing.Size(980, 700)
$tab4.Padding = New-Object System.Windows.Forms.Padding(5)
$tabControl.Controls.Add($tab4)
Add-IconToTab -Tab $tab4 -IconName "DNA"

# Main container panel for file comparison
$compareMainPanel = New-Object System.Windows.Forms.Panel
$compareMainPanel.Location = New-Object System.Drawing.Point(10, 10)
$compareMainPanel.Size = New-Object System.Drawing.Size(940, 620)
$compareMainPanel.Anchor = "Top,Bottom,Left,Right"
$tab4.Controls.Add($compareMainPanel)

# Title Label with modern styling
$lblCompareTitle = New-Object System.Windows.Forms.Label
$lblCompareTitle.Text = "File Comparison Tool"
$lblCompareTitle.Location = New-Object System.Drawing.Point(0, 0)
$lblCompareTitle.Size = New-Object System.Drawing.Size(940, 35)
$lblCompareTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$lblCompareTitle.ForeColor = [System.Drawing.Color]::FromArgb(30, 60, 114)
$compareMainPanel.Controls.Add($lblCompareTitle)

# File Selection Group Box
$fileSelectGroupBox = New-Object System.Windows.Forms.GroupBox
$fileSelectGroupBox.Text = "Select Files to Compare"
$fileSelectGroupBox.Location = New-Object System.Drawing.Point(0, 40)
$fileSelectGroupBox.Size = New-Object System.Drawing.Size(940, 110)
$fileSelectGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$fileSelectGroupBox.Anchor = "Top,Left,Right"
$compareMainPanel.Controls.Add($fileSelectGroupBox)

# File 1 Selection
$lblFile1 = New-Object System.Windows.Forms.Label
$lblFile1.Text = "Original File:"
$lblFile1.Location = New-Object System.Drawing.Point(15, 28)
$lblFile1.Size = New-Object System.Drawing.Size(90, 23)
$lblFile1.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$fileSelectGroupBox.Controls.Add($lblFile1)

$txtFile1Path = New-Object System.Windows.Forms.TextBox
$txtFile1Path.Location = New-Object System.Drawing.Point(110, 25)
$txtFile1Path.Size = New-Object System.Drawing.Size(680, 23)
$txtFile1Path.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtFile1Path.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 255)
$fileSelectGroupBox.Controls.Add($txtFile1Path)

$btnBrowseFile1 = New-Object System.Windows.Forms.Button
$btnBrowseFile1.Text = "Browse..."
$btnBrowseFile1.Location = New-Object System.Drawing.Point(800, 24)
$btnBrowseFile1.Size = New-Object System.Drawing.Size(120, 26)
$btnBrowseFile1.FlatStyle = "Flat"
$btnBrowseFile1.BackColor = [System.Drawing.Color]::FromArgb(70, 130, 180)
$btnBrowseFile1.ForeColor = [System.Drawing.Color]::White
$btnBrowseFile1.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btnBrowseFile1.Cursor = [System.Windows.Forms.Cursors]::Hand
$fileSelectGroupBox.Controls.Add($btnBrowseFile1)

# File 2 Selection
$lblFile2 = New-Object System.Windows.Forms.Label
$lblFile2.Text = "Modified File:"
$lblFile2.Location = New-Object System.Drawing.Point(15, 63)
$lblFile2.Size = New-Object System.Drawing.Size(90, 23)
$lblFile2.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$fileSelectGroupBox.Controls.Add($lblFile2)

$txtFile2Path = New-Object System.Windows.Forms.TextBox
$txtFile2Path.Location = New-Object System.Drawing.Point(110, 60)
$txtFile2Path.Size = New-Object System.Drawing.Size(680, 23)
$txtFile2Path.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtFile2Path.BackColor = [System.Drawing.Color]::FromArgb(255, 250, 250)
$fileSelectGroupBox.Controls.Add($txtFile2Path)

$btnBrowseFile2 = New-Object System.Windows.Forms.Button
$btnBrowseFile2.Text = "Browse..."
$btnBrowseFile2.Location = New-Object System.Drawing.Point(800, 59)
$btnBrowseFile2.Size = New-Object System.Drawing.Size(120, 26)
$btnBrowseFile2.FlatStyle = "Flat"
$btnBrowseFile2.BackColor = [System.Drawing.Color]::FromArgb(70, 130, 180)
$btnBrowseFile2.ForeColor = [System.Drawing.Color]::White
$btnBrowseFile2.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btnBrowseFile2.Cursor = [System.Windows.Forms.Cursors]::Hand
$fileSelectGroupBox.Controls.Add($btnBrowseFile2)

# Action Buttons Panel
$actionPanel = New-Object System.Windows.Forms.Panel
$actionPanel.Location = New-Object System.Drawing.Point(0, 155)
$actionPanel.Size = New-Object System.Drawing.Size(940, 45)
$compareMainPanel.Controls.Add($actionPanel)

# Primary action - Export HTML Comparison (browser does the diff)
$btnExportDiff = New-Object System.Windows.Forms.Button
$btnExportDiff.Text = "Compare && Export HTML"
$btnExportDiff.Location = New-Object System.Drawing.Point(0, 5)
$btnExportDiff.Size = New-Object System.Drawing.Size(180, 35)
$btnExportDiff.FlatStyle = "Flat"
$btnExportDiff.BackColor = [System.Drawing.Color]::FromArgb(46, 139, 87)
$btnExportDiff.ForeColor = [System.Drawing.Color]::White
$btnExportDiff.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnExportDiff.Cursor = [System.Windows.Forms.Cursors]::Hand
$actionPanel.Controls.Add($btnExportDiff)

$btnSwapFiles = New-Object System.Windows.Forms.Button
$btnSwapFiles.Text = "Swap Files"
$btnSwapFiles.Location = New-Object System.Drawing.Point(190, 5)
$btnSwapFiles.Size = New-Object System.Drawing.Size(100, 35)
$btnSwapFiles.FlatStyle = "Flat"
$btnSwapFiles.BackColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
$btnSwapFiles.ForeColor = [System.Drawing.Color]::White
$btnSwapFiles.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btnSwapFiles.Cursor = [System.Windows.Forms.Cursors]::Hand
$actionPanel.Controls.Add($btnSwapFiles)

$btnClearCompare = New-Object System.Windows.Forms.Button
$btnClearCompare.Text = "Clear"
$btnClearCompare.Location = New-Object System.Drawing.Point(300, 5)
$btnClearCompare.Size = New-Object System.Drawing.Size(80, 35)
$btnClearCompare.FlatStyle = "Flat"
$btnClearCompare.BackColor = [System.Drawing.Color]::FromArgb(178, 34, 34)
$btnClearCompare.ForeColor = [System.Drawing.Color]::White
$btnClearCompare.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btnClearCompare.Cursor = [System.Windows.Forms.Cursors]::Hand
$actionPanel.Controls.Add($btnClearCompare)

# Info label for the action
$lblActionInfo = New-Object System.Windows.Forms.Label
$lblActionInfo.Text = "Comparison is computed in browser (fast, efficient)"
$lblActionInfo.Location = New-Object System.Drawing.Point(400, 12)
$lblActionInfo.Size = New-Object System.Drawing.Size(350, 20)
$lblActionInfo.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lblActionInfo.ForeColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
$actionPanel.Controls.Add($lblActionInfo)

# Results Summary Panel - simplified instructions
$resultsSummaryPanel = New-Object System.Windows.Forms.Panel
$resultsSummaryPanel.Location = New-Object System.Drawing.Point(0, 200)
$resultsSummaryPanel.Size = New-Object System.Drawing.Size(940, 415)
$resultsSummaryPanel.Anchor = "Top,Bottom,Left,Right"
$resultsSummaryPanel.BackColor = [System.Drawing.Color]::FromArgb(248, 249, 250)
$resultsSummaryPanel.BorderStyle = "FixedSingle"
$compareMainPanel.Controls.Add($resultsSummaryPanel)

# Summary Label with clear instructions
$lblComparisonSummary = New-Object System.Windows.Forms.Label
$lblComparisonSummary.Text = "File Comparison Tool`n`n1. Select two files using the 'Browse' buttons above`n2. Click 'Compare && Export HTML' to generate comparison`n3. HTML opens in your browser with:`n   • Professional diff visualization`n   • Navigation between changes (Prev/Next buttons)`n   • Toggle between Unified and Side-by-Side views`n   • Keyboard shortcuts (j/k or arrow keys)`n   • Statistics showing additions, deletions, unchanged lines`n`nThe comparison is computed by your browser's JavaScript engine for maximum speed and efficiency."
$lblComparisonSummary.Location = New-Object System.Drawing.Point(20, 20)
$lblComparisonSummary.Size = New-Object System.Drawing.Size(900, 380)
$lblComparisonSummary.Font = New-Object System.Drawing.Font("Segoe UI", 11)
$lblComparisonSummary.ForeColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
$lblComparisonSummary.TextAlign = "TopCenter"
$lblComparisonSummary.Anchor = "Top,Bottom,Left,Right"
$resultsSummaryPanel.Controls.Add($lblComparisonSummary)

# ============================================
# EMBEDDED RESOURCES PANEL
# ============================================

$resourcesGroupBox = New-Object System.Windows.Forms.GroupBox
$resourcesGroupBox.Text = "Embedded Resources (.RDOX Files)"
$resourcesGroupBox.Location = New-Object System.Drawing.Point(0, 200)
$resourcesGroupBox.Size = New-Object System.Drawing.Size(940, 95)
$resourcesGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$resourcesGroupBox.Anchor = "Bottom,Left,Right"
$compareMainPanel.Controls.Add($resourcesGroupBox)

# Resources ListBox
$script:lstResources = New-Object System.Windows.Forms.ListBox
$script:lstResources.Location = New-Object System.Drawing.Point(15, 22)
$script:lstResources.Size = New-Object System.Drawing.Size(600, 60)
$script:lstResources.Font = New-Object System.Drawing.Font("Consolas", 9)
$script:lstResources.SelectionMode = "MultiExtended"
$script:lstResources.BorderStyle = "FixedSingle"
$resourcesGroupBox.Controls.Add($script:lstResources)

# Populate resources list
if ($script:EmbeddedResources -and $script:EmbeddedResources.Count -gt 0) {
    foreach ($resourceName in ($script:EmbeddedResources.Keys | Sort-Object)) {
        $script:lstResources.Items.Add($resourceName) | Out-Null
    }
} else {
    $script:lstResources.Items.Add("(No embedded resources - run Package-Resources.ps1)") | Out-Null
    $script:lstResources.Enabled = $false
}

# Export to Working Directory button
$btnExportToWorkDir = New-Object System.Windows.Forms.Button
$btnExportToWorkDir.Text = "Export to Working Directory"
$btnExportToWorkDir.Location = New-Object System.Drawing.Point(630, 22)
$btnExportToWorkDir.Size = New-Object System.Drawing.Size(145, 28)
$btnExportToWorkDir.FlatStyle = "Flat"
$btnExportToWorkDir.BackColor = [System.Drawing.Color]::FromArgb(46, 139, 87)
$btnExportToWorkDir.ForeColor = [System.Drawing.Color]::White
$btnExportToWorkDir.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btnExportToWorkDir.Cursor = [System.Windows.Forms.Cursors]::Hand
$resourcesGroupBox.Controls.Add($btnExportToWorkDir)

# Export to Custom Directory button
$btnExportToCustomDir = New-Object System.Windows.Forms.Button
$btnExportToCustomDir.Text = "Export to Folder..."
$btnExportToCustomDir.Location = New-Object System.Drawing.Point(785, 22)
$btnExportToCustomDir.Size = New-Object System.Drawing.Size(140, 28)
$btnExportToCustomDir.FlatStyle = "Flat"
$btnExportToCustomDir.BackColor = [System.Drawing.Color]::FromArgb(70, 130, 180)
$btnExportToCustomDir.ForeColor = [System.Drawing.Color]::White
$btnExportToCustomDir.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btnExportToCustomDir.Cursor = [System.Windows.Forms.Cursors]::Hand
$resourcesGroupBox.Controls.Add($btnExportToCustomDir)

# Info label
$lblResourceInfo = New-Object System.Windows.Forms.Label
$lblResourceInfo.Text = "Select files to export (Ctrl+Click for multiple) or leave empty to export all"
$lblResourceInfo.Location = New-Object System.Drawing.Point(630, 55)
$lblResourceInfo.Size = New-Object System.Drawing.Size(295, 32)
$lblResourceInfo.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$lblResourceInfo.ForeColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
$resourcesGroupBox.Controls.Add($lblResourceInfo)

# Export to Working Directory click handler
$btnExportToWorkDir.Add_Click({
    if (-not $script:EmbeddedResources -or $script:EmbeddedResources.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No embedded resources available.",
            "No Resources",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
        return
    }

    $outputPath = Get-Location
    $selectedItems = @($script:lstResources.SelectedItems)

    # If nothing selected, export all
    if ($selectedItems.Count -eq 0) {
        $selectedItems = @($script:EmbeddedResources.Keys)
    }

    try {
        $exportedFiles = @()
        foreach ($resourceName in $selectedItems) {
            if (-not $script:EmbeddedResources.ContainsKey($resourceName)) { continue }

            $outputFile = Join-Path $outputPath $resourceName

            if (Test-Path $outputFile) {
                $overwrite = [System.Windows.Forms.MessageBox]::Show(
                    "File '$resourceName' already exists in working directory.`n`nOverwrite?",
                    "File Exists",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )
                if ($overwrite -eq [System.Windows.Forms.DialogResult]::No) { continue }
            }

            $bytes = [Convert]::FromBase64String($script:EmbeddedResources[$resourceName])
            [System.IO.File]::WriteAllBytes($outputFile, $bytes)
            $exportedFiles += $resourceName
        }

        if ($exportedFiles.Count -gt 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "Exported $($exportedFiles.Count) file(s) to:`n$outputPath`n`nFiles:`n$($exportedFiles -join "`n")",
                "Export Complete",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Error exporting: $($_.Exception.Message)",
            "Export Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})

# Export to Custom Directory click handler
$btnExportToCustomDir.Add_Click({
    if (-not $script:EmbeddedResources -or $script:EmbeddedResources.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No embedded resources available.",
            "No Resources",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
        return
    }

    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select folder to export resources to"
    $folderBrowser.ShowNewFolderButton = $true

    if ($folderBrowser.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

    $outputPath = $folderBrowser.SelectedPath
    $selectedItems = @($script:lstResources.SelectedItems)

    # If nothing selected, export all
    if ($selectedItems.Count -eq 0) {
        $selectedItems = @($script:EmbeddedResources.Keys)
    }

    try {
        $exportedFiles = @()
        foreach ($resourceName in $selectedItems) {
            if (-not $script:EmbeddedResources.ContainsKey($resourceName)) { continue }

            $outputFile = Join-Path $outputPath $resourceName

            if (Test-Path $outputFile) {
                $overwrite = [System.Windows.Forms.MessageBox]::Show(
                    "File '$resourceName' already exists.`n`nOverwrite?",
                    "File Exists",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )
                if ($overwrite -eq [System.Windows.Forms.DialogResult]::No) { continue }
            }

            $bytes = [Convert]::FromBase64String($script:EmbeddedResources[$resourceName])
            [System.IO.File]::WriteAllBytes($outputFile, $bytes)
            $exportedFiles += $resourceName
        }

        if ($exportedFiles.Count -gt 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "Exported $($exportedFiles.Count) file(s) to:`n$outputPath`n`nFiles:`n$($exportedFiles -join "`n")",
                "Export Complete",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Error exporting: $($_.Exception.Message)",
            "Export Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})

# ============================================
# FILE COMPARISON FUNCTIONS REMOVED
# ============================================
# Diff computation moved to browser JavaScript for performance
# Old functions (Get-LineSimilarity, Get-LineDiff, Compare-FilesContent, etc.) removed

# Browse File 1
$btnBrowseFile1.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Title = "Select Original File"
    $openFileDialog.Filter = "All Files (*.*)|*.*|Text Files (*.txt)|*.txt|Config Files (*.cfg;*.conf;*.ini)|*.cfg;*.conf;*.ini|Log Files (*.log)|*.log|Script Files (*.ps1;*.bat;*.sh)|*.ps1;*.bat;*.sh"
    $openFileDialog.FilterIndex = 1
    $openFileDialog.InitialDirectory = [Environment]::GetFolderPath("MyDocuments")

    if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtFile1Path.Text = $openFileDialog.FileName
    }
})

# Browse File 2
$btnBrowseFile2.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Title = "Select Modified File"
    $openFileDialog.Filter = "All Files (*.*)|*.*|Text Files (*.txt)|*.txt|Config Files (*.cfg;*.conf;*.ini)|*.cfg;*.conf;*.ini|Log Files (*.log)|*.log|Script Files (*.ps1;*.bat;*.sh)|*.ps1;*.bat;*.sh"
    $openFileDialog.FilterIndex = 1
    $openFileDialog.InitialDirectory = [Environment]::GetFolderPath("MyDocuments")

    if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtFile2Path.Text = $openFileDialog.FileName
    }
})

# Swap Files
$btnSwapFiles.Add_Click({
    $temp = $txtFile1Path.Text
    $txtFile1Path.Text = $txtFile2Path.Text
    $txtFile2Path.Text = $temp
})

# Clear
$btnClearCompare.Add_Click({
    $txtFile1Path.Text = ""
    $txtFile2Path.Text = ""
})

# Compare & Export HTML - Primary action (browser does the diff computation)
$btnExportDiff.Add_Click({
    # Validate files are selected
    if ([string]::IsNullOrWhiteSpace($txtFile1Path.Text) -or [string]::IsNullOrWhiteSpace($txtFile2Path.Text)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select both files to compare.",
            "Files Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }

    # Validate files exist
    if (-not (Test-Path $txtFile1Path.Text)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Original file not found:`n$($txtFile1Path.Text)",
            "File Not Found",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return
    }
    if (-not (Test-Path $txtFile2Path.Text)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Modified file not found:`n$($txtFile2Path.Text)",
            "File Not Found",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Title = "Save Comparison Report"
    $saveDialog.Filter = "HTML Report (*.html)|*.html"
    $saveDialog.FilterIndex = 1
    $saveDialog.FileName = "FileComparison_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $btnExportDiff.Enabled = $false
            $btnExportDiff.Text = "Exporting..."
            [System.Windows.Forms.Application]::DoEvents()

            # Read files directly - browser will do the diff
            $file1Lines = [System.IO.File]::ReadAllLines($txtFile1Path.Text)
            $file2Lines = [System.IO.File]::ReadAllLines($txtFile2Path.Text)
            $file1Name = [System.IO.Path]::GetFileName($txtFile1Path.Text)
            $file2Name = [System.IO.Path]::GetFileName($txtFile2Path.Text)

            $writer = [System.IO.StreamWriter]::new($saveDialog.FileName, $false, [System.Text.Encoding]::UTF8)

            $writer.WriteLine(@"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>$file1Name ↔ $file2Name</title>
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;--text:#c9d1d9;--text2:#8b949e;--add-bg:#12261e;--add-border:#238636;--add-text:#3fb950;--del-bg:#2d1b1b;--del-border:#da3633;--del-text:#f85149;--highlight-add:#033a16;--highlight-del:#67060c}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
.toolbar{background:var(--bg2);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;gap:20px;position:sticky;top:0;z-index:100}
.toolbar h1{font-size:16px;font-weight:600;display:flex;align-items:center;gap:8px}
.toolbar h1 svg{width:20px;height:20px;fill:var(--text)}
.files{font-size:13px;color:var(--text2);flex:1}
.files b{color:var(--text);font-weight:500}
.stats{display:flex;gap:12px;font-size:13px}
.stat{padding:4px 12px;border-radius:20px;font-weight:500}
.stat-add{background:var(--add-bg);color:var(--add-text);border:1px solid var(--add-border)}
.stat-del{background:var(--del-bg);color:var(--del-text);border:1px solid var(--del-border)}
.stat-eq{background:var(--bg3);color:var(--text2);border:1px solid var(--border)}
.controls{display:flex;gap:8px;align-items:center}
.btn{background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:5px 12px;border-radius:6px;cursor:pointer;font-size:12px;display:flex;align-items:center;gap:4px}
.btn:hover{background:var(--border)}
.btn.active{background:#238636;border-color:#238636}
.nav-info{font-size:12px;color:var(--text2);min-width:80px;text-align:center}
#progress{padding:40px;text-align:center;color:var(--text2)}
.spinner{border:3px solid var(--bg3);border-top:3px solid #58a6ff;border-radius:50%;width:30px;height:30px;animation:spin 1s linear infinite;margin:0 auto 15px}
@keyframes spin{to{transform:rotate(360deg)}}
#diff{font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:12px}
.hunk{border:1px solid var(--border);margin:16px;border-radius:6px;overflow:hidden}
.hunk-header{background:var(--bg2);padding:8px 16px;color:var(--text2);font-size:12px;border-bottom:1px solid var(--border)}
.row{display:flex;min-height:20px}
.ln{width:50px;padding:0 8px;text-align:right;color:var(--text2);background:var(--bg2);flex-shrink:0;user-select:none;border-right:1px solid var(--border);font-size:11px;line-height:20px}
.code{flex:1;padding:0 12px;white-space:pre-wrap;word-break:break-all;line-height:20px;tab-size:4}
.row-add{background:var(--add-bg)}.row-add .ln{background:#0d2818;color:var(--add-text)}
.row-del{background:var(--del-bg)}.row-del .ln{background:#2a1515;color:var(--del-text)}
.row-ctx{background:var(--bg)}
.row-add .code::before{content:'+';color:var(--add-text);margin-right:8px;font-weight:bold}
.row-del .code::before{content:'−';color:var(--del-text);margin-right:8px;font-weight:bold}
.row-ctx .code::before{content:' ';margin-right:8px}
.hl-add{background:var(--highlight-add);padding:1px 0;border-radius:2px}
.hl-del{background:var(--highlight-del);padding:1px 0;border-radius:2px}
.change-marker{position:absolute;left:0;width:4px;height:100%;background:#58a6ff}
.side{display:flex;width:100%}
.side .panel{flex:1;border-right:1px solid var(--border)}
.side .panel:last-child{border-right:none}
.side .panel-header{background:var(--bg2);padding:8px 12px;font-size:11px;color:var(--text2);border-bottom:1px solid var(--border);font-weight:500}
.side .row{border-bottom:1px solid var(--border)}
.side .row:last-child{border-bottom:none}
.empty-panel{background:var(--bg);min-height:20px}
.current-change{box-shadow:inset 4px 0 0 #58a6ff}
.chk{display:flex;align-items:center;gap:6px;cursor:pointer;font-size:12px;color:var(--text2);padding:5px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg3)}
.chk:hover{background:var(--border)}
.chk input{accent-color:#238636;width:14px;height:14px;cursor:pointer}
</style></head><body>
<div class="toolbar">
<h1><svg viewBox="0 0 16 16"><path d="M8.75 1.75V5H12a.75.75 0 010 1.5H8.75v3.25a.75.75 0 01-1.5 0V6.5H4a.75.75 0 010-1.5h3.25V1.75a.75.75 0 011.5 0zM4 13h8a.75.75 0 010 1.5H4a.75.75 0 010-1.5z"/></svg>Diff</h1>
<div class="files"><b>$file1Name</b> → <b>$file2Name</b></div>
<div class="stats" id="stats"></div>
<div class="controls">
<label class="chk"><input type="checkbox" id="ignoreBlanks" onchange="recompute()"><span>Ignore blank lines</span></label>
<button class="btn" onclick="prevChange()" title="Previous change (↑)">▲ Prev</button>
<span class="nav-info" id="navInfo">-/-</span>
<button class="btn" onclick="nextChange()" title="Next change (↓)">▼ Next</button>
</div>
</div>
<div id="progress"><div class="spinner"></div>Computing differences...</div>
<div id="diff"></div>
<script>
const f1=$($file1Lines | ConvertTo-Json -Compress -Depth 1);
const f2=$($file2Lines | ConvertTo-Json -Compress -Depth 1);
"@)
                    $writer.WriteLine(@'
const CTX=4;
let diffs=[],hunks=[],curHunk=0;

function isBlank(s){return !s||!s.trim();}

function computeDiff(ignoreBlanks){
  const m=f1.length,n=f2.length;
  const m1=new Int32Array(m).fill(-1),m2=new Int32Array(n).fill(-1);

  // If ignoring blanks, pre-match all blank lines as "equal" to reduce noise
  if(ignoreBlanks){
    // Find non-blank line indices
    const nb1=[],nb2=[];
    for(let i=0;i<m;i++)if(!isBlank(f1[i]))nb1.push(i);
    for(let j=0;j<n;j++)if(!isBlank(f2[j]))nb2.push(j);

    // Match non-blank lines at same relative position first
    const len=Math.min(nb1.length,nb2.length);
    for(let k=0;k<len;k++){
      const i=nb1[k],j=nb2[k];
      if(f1[i]===f2[j]){m1[i]=j;m2[j]=i;}
    }

    // Hash remaining non-blank lines
    const h2=new Map();
    for(let j=0;j<n;j++){
      if(m2[j]<0&&!isBlank(f2[j])){
        const k=f2[j];if(!h2.has(k))h2.set(k,[]);h2.get(k).push(j);
      }
    }
    for(let i=0;i<m;i++){
      if(m1[i]>=0||isBlank(f1[i]))continue;
      const arr=h2.get(f1[i]);
      if(arr){for(let k=0;k<arr.length;k++){const j=arr[k];if(m2[j]<0){m1[i]=j;m2[j]=i;arr.splice(k,1);break;}}}
    }

    // Match blank lines to each other
    const blankQ1=[],blankQ2=[];
    for(let i=0;i<m;i++)if(m1[i]<0&&isBlank(f1[i]))blankQ1.push(i);
    for(let j=0;j<n;j++)if(m2[j]<0&&isBlank(f2[j]))blankQ2.push(j);
    const blankMatch=Math.min(blankQ1.length,blankQ2.length);
    for(let k=0;k<blankMatch;k++){m1[blankQ1[k]]=blankQ2[k];m2[blankQ2[k]]=blankQ1[k];}
  } else {
    // Original algorithm: match by position first
    for(let i=0;i<Math.min(m,n);i++)if(f1[i]===f2[i]){m1[i]=i;m2[i]=i;}
    // Hash remaining
    const h2=new Map();
    for(let j=0;j<n;j++)if(m2[j]<0){const k=f2[j];if(!h2.has(k))h2.set(k,[]);h2.get(k).push(j);}
    for(let i=0;i<m;i++){if(m1[i]>=0)continue;const arr=h2.get(f1[i]);if(arr){for(let k=0;k<arr.length;k++){const j=arr[k];if(m2[j]<0){m1[i]=j;m2[j]=i;arr.splice(k,1);break;}}}}
  }

  // Build diffs
  const d=[];let i=0,j=0;
  while(i<m||j<n){
    if(i<m&&m1[i]>=0&&m1[i]===j){d.push({t:'=',i1:i,i2:j});i++;j++;}
    else if(i<m&&m1[i]<0){d.push({t:'-',i1:i,i2:-1});i++;}
    else if(j<n&&m2[j]<0){d.push({t:'+',i1:-1,i2:j});j++;}
    else{if(i<m){d.push({t:'-',i1:i,i2:-1});i++;}if(j<n){d.push({t:'+',i1:-1,i2:j});j++;}}
  }
  return d;
}

function recompute(){
  // Show spinner immediately so checkbox feels responsive
  document.getElementById('progress').style.display='block';
  document.getElementById('diff').innerHTML='';
  // Defer computation to let UI update first
  setTimeout(()=>{
    const ign=document.getElementById('ignoreBlanks').checked;
    diffs=computeDiff(ign);
    hunks=buildHunks(diffs);
    let add=0,del=0,eq=0;
    diffs.forEach(d=>{if(d.t==='+')add++;else if(d.t==='-')del++;else eq++;});
    document.getElementById('stats').innerHTML=`<span class="stat stat-add">+${add}</span><span class="stat stat-del">−${del}</span><span class="stat stat-eq">${eq} unchanged</span>`;
    document.getElementById('progress').style.display='none';
    curHunk=0;
    render();
    if(hunks.length)goToHunk(0);
  },10);
}

function buildHunks(d){
  const h=[];let show=new Set();
  for(let i=0;i<d.length;i++)if(d[i].t!=='=')for(let k=Math.max(0,i-CTX);k<=Math.min(d.length-1,i+CTX);k++)show.add(k);
  let hunk=null,lastI=-99;
  for(let i=0;i<d.length;i++){
    if(!show.has(i))continue;
    if(i-lastI>1&&hunk){h.push(hunk);hunk=null;}
    if(!hunk)hunk={start:i,lines:[],startLine1:d[i].i1>=0?d[i].i1+1:'?',startLine2:d[i].i2>=0?d[i].i2+1:'?'};
    hunk.lines.push(d[i]);
    lastI=i;
  }
  if(hunk)h.push(hunk);
  return h;
}

function esc(s){return s==null?'':String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

function render(){
  let html='';
  hunks.forEach((h,hi)=>{
    html+=`<div class="hunk" id="hunk${hi}"><div class="hunk-header">@@ Lines ${h.startLine1} / ${h.startLine2} @@</div><div class="side"><div class="panel"><div class="panel-header">Original</div>`;
    // Left panel
    h.lines.forEach(d=>{
      if(d.t==='+'){html+=`<div class="row empty-panel"></div>`;}
      else{const ln=d.i1>=0?d.i1+1:'';const cls=d.t==='-'?'row-del':'row-ctx';html+=`<div class="row ${cls}"><div class="ln">${ln}</div><div class="code">${esc(f1[d.i1])}</div></div>`;}
    });
    html+=`</div><div class="panel"><div class="panel-header">Modified</div>`;
    // Right panel
    h.lines.forEach(d=>{
      if(d.t==='-'){html+=`<div class="row empty-panel"></div>`;}
      else{const ln=d.i2>=0?d.i2+1:'';const cls=d.t==='+'?'row-add':'row-ctx';html+=`<div class="row ${cls}"><div class="ln">${ln}</div><div class="code">${esc(f2[d.i2])}</div></div>`;}
    });
    html+=`</div></div></div>`;
  });
  document.getElementById('diff').innerHTML=html||'<div style="padding:40px;text-align:center;color:var(--text2)">Files are identical</div>';
  updateNav();
}

function updateNav(){document.getElementById('navInfo').textContent=hunks.length?`${curHunk+1}/${hunks.length}`:'0/0';}
function goToHunk(i){if(hunks.length===0)return;curHunk=Math.max(0,Math.min(hunks.length-1,i));document.querySelectorAll('.hunk').forEach((e,j)=>e.classList.toggle('current-change',j===curHunk));document.getElementById('hunk'+curHunk)?.scrollIntoView({behavior:'smooth',block:'center'});updateNav();}
function nextChange(){goToHunk(curHunk+1);}
function prevChange(){goToHunk(curHunk-1);}
document.addEventListener('keydown',e=>{if(e.key==='ArrowDown'||e.key==='j'){nextChange();e.preventDefault();}if(e.key==='ArrowUp'||e.key==='k'){prevChange();e.preventDefault();}});

setTimeout(()=>{
  document.getElementById('progress').style.display='none';
  recompute();
},50);
</script></body></html>
'@)
            $writer.Close()

            # Open the HTML file in browser
            Start-Process $saveDialog.FileName

            [System.Windows.Forms.MessageBox]::Show(
                "Comparison report created and opened in browser:`n`n$($saveDialog.FileName)",
                "Export Complete",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            if ($script:StatusBarPanels) {
                Set-StatusMessage -StatusBar $script:StatusBarPanels -Message "Comparison exported: $($saveDialog.FileName)"
            }
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Error creating comparison:`n`n$($_.Exception.Message)",
                "Export Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            if ($script:StatusBarPanels) {
                Set-StatusMessage -StatusBar $script:StatusBarPanels -Message "Comparison failed" -IsError
            }
        }
        finally {
            $btnExportDiff.Enabled = $true
            $btnExportDiff.Text = "Compare && Export HTML"
        }
    }
})

# ============================================
# TAB 5: PORT CONFIGURATION
# ============================================

$tab5 = New-Object System.Windows.Forms.TabPage
$tab5.Text = "Port Config"
$tab5.BackColor = [System.Drawing.Color]::White
$tab5.AutoScroll = $true
$tab5.AutoScrollMinSize = New-Object System.Drawing.Size(950, 650)
$tabControl.Controls.Add($tab5)

# Input GroupBox
$portInputGroup = New-Object System.Windows.Forms.GroupBox
$portInputGroup.Text = "Configuration Parameters"
$portInputGroup.Location = New-Object System.Drawing.Point(10, 10)
$portInputGroup.Size = New-Object System.Drawing.Size(400, 280)
$portInputGroup.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$tab5.Controls.Add($portInputGroup)

# Vendor Label & ComboBox
$lblVendor = New-Object System.Windows.Forms.Label
$lblVendor.Text = "Vendor:"
$lblVendor.Location = New-Object System.Drawing.Point(15, 30)
$lblVendor.Size = New-Object System.Drawing.Size(100, 20)
$portInputGroup.Controls.Add($lblVendor)

$cboVendor = New-Object System.Windows.Forms.ComboBox
$cboVendor.Location = New-Object System.Drawing.Point(120, 27)
$cboVendor.Size = New-Object System.Drawing.Size(250, 25)
$cboVendor.DropDownStyle = "DropDownList"
$cboVendor.Items.AddRange(@("Cisco", "ICX/FCX 8030", "FCX 7.3"))
$cboVendor.SelectedIndex = 0
$portInputGroup.Controls.Add($cboVendor)

# Port Type Label & ComboBox
$lblPortType = New-Object System.Windows.Forms.Label
$lblPortType.Text = "Port Type:"
$lblPortType.Location = New-Object System.Drawing.Point(15, 60)
$lblPortType.Size = New-Object System.Drawing.Size(100, 20)
$portInputGroup.Controls.Add($lblPortType)

$cboPortType = New-Object System.Windows.Forms.ComboBox
$cboPortType.Location = New-Object System.Drawing.Point(120, 57)
$cboPortType.Size = New-Object System.Drawing.Size(250, 25)
$cboPortType.DropDownStyle = "DropDownList"
# Port types will be populated dynamically based on vendor selection
$portInputGroup.Controls.Add($cboPortType)

# Interface Label & TextBox
$lblInterface = New-Object System.Windows.Forms.Label
$lblInterface.Text = "Interface:"
$lblInterface.Location = New-Object System.Drawing.Point(15, 90)
$lblInterface.Size = New-Object System.Drawing.Size(100, 20)
$portInputGroup.Controls.Add($lblInterface)

$txtInterface = New-Object System.Windows.Forms.TextBox
$txtInterface.Location = New-Object System.Drawing.Point(120, 87)
$txtInterface.Size = New-Object System.Drawing.Size(250, 25)
$txtInterface.Text = "Gi1/0/1"
$portInputGroup.Controls.Add($txtInterface)

# Description Label & TextBox
$lblPortDesc = New-Object System.Windows.Forms.Label
$lblPortDesc.Text = "Description:"
$lblPortDesc.Location = New-Object System.Drawing.Point(15, 120)
$lblPortDesc.Size = New-Object System.Drawing.Size(100, 20)
$portInputGroup.Controls.Add($lblPortDesc)

$txtPortDesc = New-Object System.Windows.Forms.TextBox
$txtPortDesc.Location = New-Object System.Drawing.Point(120, 117)
$txtPortDesc.Size = New-Object System.Drawing.Size(250, 25)
$txtPortDesc.Text = "User PC"
$portInputGroup.Controls.Add($txtPortDesc)

# VLAN Label & TextBox
$lblVlan = New-Object System.Windows.Forms.Label
$lblVlan.Text = "VLAN:"
$lblVlan.Location = New-Object System.Drawing.Point(15, 150)
$lblVlan.Size = New-Object System.Drawing.Size(100, 20)
$portInputGroup.Controls.Add($lblVlan)

$txtVlan = New-Object System.Windows.Forms.TextBox
$txtVlan.Location = New-Object System.Drawing.Point(120, 147)
$txtVlan.Size = New-Object System.Drawing.Size(250, 25)
$txtVlan.Text = "100"
$portInputGroup.Controls.Add($txtVlan)

# Old VLAN Label & TextBox (for Vendor X only)
$lblOldVlan = New-Object System.Windows.Forms.Label
$lblOldVlan.Text = "Old VLAN:"
$lblOldVlan.Location = New-Object System.Drawing.Point(15, 180)
$lblOldVlan.Size = New-Object System.Drawing.Size(100, 20)
$portInputGroup.Controls.Add($lblOldVlan)

$txtOldVlan = New-Object System.Windows.Forms.TextBox
$txtOldVlan.Location = New-Object System.Drawing.Point(120, 177)
$txtOldVlan.Size = New-Object System.Drawing.Size(250, 25)
$txtOldVlan.Text = ""
$portInputGroup.Controls.Add($txtOldVlan)

# Voice VLAN Label & TextBox
$lblVoiceVlan = New-Object System.Windows.Forms.Label
$lblVoiceVlan.Text = "Voice VLAN:"
$lblVoiceVlan.Location = New-Object System.Drawing.Point(15, 210)
$lblVoiceVlan.Size = New-Object System.Drawing.Size(100, 20)
$portInputGroup.Controls.Add($lblVoiceVlan)

$txtVoiceVlan = New-Object System.Windows.Forms.TextBox
$txtVoiceVlan.Location = New-Object System.Drawing.Point(120, 207)
$txtVoiceVlan.Size = New-Object System.Drawing.Size(250, 25)
$txtVoiceVlan.Text = "200"
$portInputGroup.Controls.Add($txtVoiceVlan)

# Status Label & TextBox
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = "Status:"
$lblStatus.Location = New-Object System.Drawing.Point(15, 243)
$lblStatus.Size = New-Object System.Drawing.Size(100, 20)
$portInputGroup.Controls.Add($lblStatus)

$txtStatus = New-Object System.Windows.Forms.TextBox
$txtStatus.Location = New-Object System.Drawing.Point(120, 240)
$txtStatus.Size = New-Object System.Drawing.Size(250, 25)
$txtStatus.Text = "no shutdown"
$portInputGroup.Controls.Add($txtStatus)

# Update Port Type dropdown and Old VLAN visibility when vendor changes
$cboVendor.Add_SelectedIndexChanged({
    $vendor = $cboVendor.SelectedItem

    # Show/Hide Old VLAN based on vendor (only FCX 7.3 uses OLD_VLAN for migrations)
    $isFCX73 = $vendor -eq "FCX 7.3"
    $lblOldVlan.Visible = $isFCX73
    $txtOldVlan.Visible = $isFCX73

    # Populate Port Type dropdown based on available templates for this vendor
    $cboPortType.Items.Clear()
    if ($script:PortTemplates.ContainsKey($vendor)) {
        foreach ($portType in $script:PortTemplates[$vendor].Keys) {
            $cboPortType.Items.Add($portType) | Out-Null
        }
        if ($cboPortType.Items.Count -gt 0) {
            $cboPortType.SelectedIndex = 0
        }
    }
})

# Initialize Port Type dropdown with first vendor's templates
# Manually populate since setting SelectedIndex to 0 when already 0 won't trigger the event
$initialVendor = $cboVendor.Items[0]
if ($script:PortTemplates.ContainsKey($initialVendor)) {
    foreach ($portType in $script:PortTemplates[$initialVendor].Keys) {
        $cboPortType.Items.Add($portType) | Out-Null
    }
    if ($cboPortType.Items.Count -gt 0) {
        $cboPortType.SelectedIndex = 0
    }
}
# Also set Old VLAN visibility based on initial vendor
$lblOldVlan.Visible = ($initialVendor -eq "FCX 7.3")
$txtOldVlan.Visible = ($initialVendor -eq "FCX 7.3")

# Generate Button
$btnGenerateConfig = New-Object System.Windows.Forms.Button
$btnGenerateConfig.Text = "Generate Config"
$btnGenerateConfig.Location = New-Object System.Drawing.Point(10, 300)
$btnGenerateConfig.Size = New-Object System.Drawing.Size(130, 35)
$btnGenerateConfig.FlatStyle = "Flat"
$btnGenerateConfig.BackColor = [System.Drawing.Color]::FromArgb(46, 139, 87)
$btnGenerateConfig.ForeColor = [System.Drawing.Color]::White
$btnGenerateConfig.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnGenerateConfig.Cursor = [System.Windows.Forms.Cursors]::Hand
$tab5.Controls.Add($btnGenerateConfig)

# Copy Button
$btnCopyConfig = New-Object System.Windows.Forms.Button
$btnCopyConfig.Text = "Copy to Clipboard"
$btnCopyConfig.Location = New-Object System.Drawing.Point(150, 300)
$btnCopyConfig.Size = New-Object System.Drawing.Size(130, 35)
$btnCopyConfig.FlatStyle = "Flat"
$btnCopyConfig.BackColor = [System.Drawing.Color]::FromArgb(70, 130, 180)
$btnCopyConfig.ForeColor = [System.Drawing.Color]::White
$btnCopyConfig.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btnCopyConfig.Cursor = [System.Windows.Forms.Cursors]::Hand
$tab5.Controls.Add($btnCopyConfig)

# Clear Button
$btnClearConfig = New-Object System.Windows.Forms.Button
$btnClearConfig.Text = "Clear"
$btnClearConfig.Location = New-Object System.Drawing.Point(290, 300)
$btnClearConfig.Size = New-Object System.Drawing.Size(80, 35)
$btnClearConfig.FlatStyle = "Flat"
$btnClearConfig.BackColor = [System.Drawing.Color]::FromArgb(178, 34, 34)
$btnClearConfig.ForeColor = [System.Drawing.Color]::White
$btnClearConfig.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btnClearConfig.Cursor = [System.Windows.Forms.Cursors]::Hand
$tab5.Controls.Add($btnClearConfig)

# Save Template Button
$btnSaveTemplate = New-Object System.Windows.Forms.Button
$btnSaveTemplate.Text = "Save as Template"
$btnSaveTemplate.Location = New-Object System.Drawing.Point(10, 345)
$btnSaveTemplate.Size = New-Object System.Drawing.Size(130, 35)
$btnSaveTemplate.FlatStyle = "Flat"
$btnSaveTemplate.BackColor = [System.Drawing.Color]::FromArgb(128, 0, 128)
$btnSaveTemplate.ForeColor = [System.Drawing.Color]::White
$btnSaveTemplate.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btnSaveTemplate.Cursor = [System.Windows.Forms.Cursors]::Hand
$tab5.Controls.Add($btnSaveTemplate)

# Load Template Button
$btnLoadTemplate = New-Object System.Windows.Forms.Button
$btnLoadTemplate.Text = "Load Template"
$btnLoadTemplate.Location = New-Object System.Drawing.Point(150, 345)
$btnLoadTemplate.Size = New-Object System.Drawing.Size(110, 35)
$btnLoadTemplate.FlatStyle = "Flat"
$btnLoadTemplate.BackColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
$btnLoadTemplate.ForeColor = [System.Drawing.Color]::White
$btnLoadTemplate.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btnLoadTemplate.Cursor = [System.Windows.Forms.Cursors]::Hand
$tab5.Controls.Add($btnLoadTemplate)

# Placeholder help label
$lblPlaceholderHelp = New-Object System.Windows.Forms.Label
$lblPlaceholderHelp.Text = "Placeholders: {{INTERFACE}} {{DESCRIPTION}} {{VLAN}} {{OLD_VLAN}} {{VOICE_VLAN}} {{STATUS}}"
$lblPlaceholderHelp.Location = New-Object System.Drawing.Point(10, 390)
$lblPlaceholderHelp.Size = New-Object System.Drawing.Size(400, 20)
$lblPlaceholderHelp.Font = New-Object System.Drawing.Font("Consolas", 8)
$lblPlaceholderHelp.ForeColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
$tab5.Controls.Add($lblPlaceholderHelp)

# Output GroupBox - now for both output AND template editing
$portOutputGroup = New-Object System.Windows.Forms.GroupBox
$portOutputGroup.Text = "Generated Configuration / Template Editor (paste template with {{PLACEHOLDERS}})"
$portOutputGroup.Location = New-Object System.Drawing.Point(420, 10)
$portOutputGroup.Size = New-Object System.Drawing.Size(500, 600)
$portOutputGroup.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$portOutputGroup.Padding = New-Object System.Windows.Forms.Padding(5, 20, 5, 5)
$tab5.Controls.Add($portOutputGroup)

# Output TextBox - Use Dock=Fill for proper scrolling
$txtConfigOutput = New-Object System.Windows.Forms.TextBox
$txtConfigOutput.Dock = "Fill"
$txtConfigOutput.Multiline = $true
$txtConfigOutput.ScrollBars = "Both"
$txtConfigOutput.WordWrap = $false
$txtConfigOutput.Font = New-Object System.Drawing.Font("Consolas", 10)
$txtConfigOutput.BorderStyle = "Fixed3D"
$portOutputGroup.Controls.Add($txtConfigOutput)

# Generate Config Click Handler
$btnGenerateConfig.Add_Click({
    $vendor = $cboVendor.SelectedItem
    $portType = $cboPortType.SelectedItem

    # Validate selections are not null
    if ($null -eq $vendor -or [string]::IsNullOrWhiteSpace($vendor)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a vendor.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    if ($null -eq $portType -or [string]::IsNullOrWhiteSpace($portType)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a port type. If the Port Type dropdown is empty, no templates are available for the selected vendor.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    if (-not $script:PortTemplates.ContainsKey($vendor)) {
        [System.Windows.Forms.MessageBox]::Show("Vendor '$vendor' not found in templates.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    if (-not $script:PortTemplates[$vendor].ContainsKey($portType)) {
        [System.Windows.Forms.MessageBox]::Show("Port type '$portType' not found for vendor '$vendor'.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    $template = $script:PortTemplates[$vendor][$portType]

    # Replace placeholders
    $config = $template
    $config = $config -replace '\{\{INTERFACE\}\}', $txtInterface.Text
    $config = $config -replace '\{\{DESCRIPTION\}\}', $txtPortDesc.Text
    $config = $config -replace '\{\{VLAN\}\}', $txtVlan.Text
    $config = $config -replace '\{\{OLD_VLAN\}\}', $txtOldVlan.Text
    $config = $config -replace '\{\{VOICE_VLAN\}\}', $txtVoiceVlan.Text
    $config = $config -replace '\{\{STATUS\}\}', $txtStatus.Text

    $txtConfigOutput.Text = $config

    if ($script:StatusBarPanels) {
        Set-StatusMessage -StatusBar $script:StatusBarPanels -Message "Config generated for $vendor - $portType"
    }
})

# Copy to Clipboard Click Handler
$btnCopyConfig.Add_Click({
    if ([string]::IsNullOrWhiteSpace($txtConfigOutput.Text)) {
        [System.Windows.Forms.MessageBox]::Show("No configuration to copy. Generate a config first.", "Nothing to Copy", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }

    [System.Windows.Forms.Clipboard]::SetText($txtConfigOutput.Text)

    if ($script:StatusBarPanels) {
        Set-StatusMessage -StatusBar $script:StatusBarPanels -Message "Configuration copied to clipboard"
    }

    [System.Windows.Forms.MessageBox]::Show("Configuration copied to clipboard!", "Copied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})

# Clear Click Handler
$btnClearConfig.Add_Click({
    $txtInterface.Text = "Gi1/0/1"
    $txtPortDesc.Text = "User PC"
    $txtVlan.Text = "100"
    $txtOldVlan.Text = ""
    $txtVoiceVlan.Text = "200"
    $txtStatus.Text = "no shutdown"
    $txtConfigOutput.Text = ""
})

# Save Template Click Handler
$btnSaveTemplate.Add_Click({
    $vendor = $cboVendor.SelectedItem
    $portType = $cboPortType.SelectedItem
    $templateContent = $txtConfigOutput.Text

    # Validate selections are not null
    if ($null -eq $vendor -or [string]::IsNullOrWhiteSpace($vendor)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a vendor.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    if ($null -eq $portType -or [string]::IsNullOrWhiteSpace($portType)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a port type before saving a template.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    if ([string]::IsNullOrWhiteSpace($templateContent)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please paste your template configuration in the text area first.`n`n" +
            "Use placeholders like {{INTERFACE}}, {{VLAN}}, etc. where variables should go.",
            "No Template Content",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }

    # Confirm save
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Save this template for:`n`n" +
        "Vendor: $vendor`n" +
        "Port Type: $portType`n`n" +
        "This will overwrite any existing template for this combination.",
        "Confirm Save Template",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )

    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    # Save to script's PortTemplates hashtable (runtime only)
    if (-not $script:PortTemplates.ContainsKey($vendor)) {
        $script:PortTemplates[$vendor] = @{}
    }
    $script:PortTemplates[$vendor][$portType] = $templateContent

    # Also save to external JSON file for persistence
    $templateFile = Join-Path $PSScriptRoot "PortTemplates.json"
    try {
        # Load existing or create new
        $savedTemplates = @{}
        if (Test-Path $templateFile) {
            $savedTemplates = Get-Content $templateFile -Raw | ConvertFrom-Json | ConvertTo-Hashtable
        }

        # Update with new template
        if (-not $savedTemplates.ContainsKey($vendor)) {
            $savedTemplates[$vendor] = @{}
        }
        $savedTemplates[$vendor][$portType] = $templateContent

        # Save back to file
        $savedTemplates | ConvertTo-Json -Depth 4 | Set-Content $templateFile -Encoding UTF8

        [System.Windows.Forms.MessageBox]::Show(
            "Template saved successfully!`n`n" +
            "Vendor: $vendor`n" +
            "Port Type: $portType`n`n" +
            "Saved to: $templateFile",
            "Template Saved",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )

        if ($script:StatusBarPanels) {
            Set-StatusMessage -StatusBar $script:StatusBarPanels -Message "Template saved: $vendor / $portType"
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Error saving template file:`n`n$($_.Exception.Message)`n`n" +
            "Template is saved for this session only.",
            "Save Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
    }
})

# Load Template Click Handler - loads current template into editor
$btnLoadTemplate.Add_Click({
    $vendor = $cboVendor.SelectedItem
    $portType = $cboPortType.SelectedItem

    # Validate selections are not null
    if ($null -eq $vendor -or [string]::IsNullOrWhiteSpace($vendor)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a vendor.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    if ($null -eq $portType -or [string]::IsNullOrWhiteSpace($portType)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a port type. If the Port Type dropdown is empty, no templates are available for the selected vendor.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    if ($script:PortTemplates.ContainsKey($vendor) -and $script:PortTemplates[$vendor].ContainsKey($portType)) {
        $txtConfigOutput.Text = $script:PortTemplates[$vendor][$portType]

        if ($script:StatusBarPanels) {
            Set-StatusMessage -StatusBar $script:StatusBarPanels -Message "Template loaded: $vendor / $portType"
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show(
            "No template found for:`n`n" +
            "Vendor: $vendor`n" +
            "Port Type: $portType`n`n" +
            "Paste your config with {{PLACEHOLDERS}} and click 'Save as Template'.",
            "No Template",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
})

# ============================================
# TAB 6: HELP GUIDE
# ============================================

$tab6 = New-Object System.Windows.Forms.TabPage
$tab6.Text = "Help Guide"
$tab6.BackColor = [System.Drawing.Color]::White
$tab6.AutoScroll = $true
$tabControl.Controls.Add($tab6)

# Help content panel
$helpPanel = New-Object System.Windows.Forms.Panel
$helpPanel.Location = New-Object System.Drawing.Point(10, 10)
$helpPanel.Size = New-Object System.Drawing.Size(950, 600)
$helpPanel.AutoScroll = $true
$tab6.Controls.Add($helpPanel)

# Title
$helpTitle = New-Object System.Windows.Forms.Label
$helpTitle.Text = "HOW TO USE PORT CONFIG"
$helpTitle.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$helpTitle.Location = New-Object System.Drawing.Point(10, 10)
$helpTitle.Size = New-Object System.Drawing.Size(900, 40)
$helpTitle.ForeColor = [System.Drawing.Color]::FromArgb(46, 139, 87)
$helpPanel.Controls.Add($helpTitle)

# Help RichTextBox
$helpText = New-Object System.Windows.Forms.RichTextBox
$helpText.Location = New-Object System.Drawing.Point(10, 60)
$helpText.Size = New-Object System.Drawing.Size(910, 520)
$helpText.ReadOnly = $true
$helpText.BorderStyle = "None"
$helpText.BackColor = [System.Drawing.Color]::White
$helpText.Font = New-Object System.Drawing.Font("Segoe UI", 11)
$helpPanel.Controls.Add($helpText)

# Build help content
$helpContent = @"
═══════════════════════════════════════════════════════════════════════════════
                              OCTONAV HELP GUIDE
═══════════════════════════════════════════════════════════════════════════════


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TAB 1: NETWORK CONFIGURATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WHAT IT DOES:
   Changes your computer's IP address. Useful when you need to connect
   directly to a switch or router for configuration.

⚠️  IMPORTANT: You must run OctoNav as Administrator for this tab to work!
   (Right-click the script → "Run as Administrator")


HOW TO USE IT:

   STEP 1: Click "Find Unidentified Network"
      • This finds network adapters that aren't connected to your normal network
      • Usually this is the port you plugged into a switch

   STEP 2: Fill in the IP settings
      • New IP Address: The IP you want (example: 192.168.1.101)
      • Gateway: Usually the switch's IP (example: 192.168.1.1)
      • Prefix Length: Usually 24 (same as subnet mask 255.255.255.0)

   STEP 3: Click "Apply Configuration"
      • Your network adapter now has the new IP address
      • You can now access the switch/router at the gateway address

   STEP 4: When done, click "Restore Defaults"
      • This sets your adapter back to DHCP (automatic IP)
      • Your normal network connection will work again


COMMON SCENARIOS:

   "I need to configure a new switch out of the box"
      1. Plug your laptop into the switch
      2. Find Unidentified Network
      3. Set IP to same subnet as switch (check switch manual for default IP)
      4. Apply Configuration
      5. Open browser, go to switch IP
      6. When done, Restore Defaults

   "What IP should I use?"
      • If switch is 192.168.1.1 → use 192.168.1.100 (same first 3 numbers)
      • If switch is 10.0.0.1 → use 10.0.0.100
      • The last number just needs to be different from the switch


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TAB 2: DHCP STATISTICS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WHAT IT DOES:
   Collects information about DHCP scopes from your Windows DHCP servers.
   Shows you how full each scope is, what options are set, etc.


HOW TO USE IT:

   STEP 1: Select your DHCP servers
      • Click "Refresh Server List" to get servers from Active Directory
      • Check the boxes next to servers you want to query
      • OR type server names manually (comma-separated)

   STEP 2: (Optional) Select specific scopes
      • Click "Refresh Cache" to load all scopes from selected servers
      • Use the filter box to find specific scopes
      • Check the scopes you want, or leave empty for ALL scopes

   STEP 3: Choose what info to collect
      • Include DNS (Option 6) - shows DNS servers in each scope
      • Include Option 60 - shows vendor class info
      • Include Option 43 - shows vendor-specific info

   STEP 4: Click "Collect DHCP Statistics"
      • Wait for it to gather data from all servers
      • Results appear in a table below


WHAT THE RESULTS SHOW:
   • Scope name and IP range
   • How many IPs are used vs available
   • Percentage full (watch for scopes over 80%!)
   • DNS servers assigned to that scope
   • Any special options configured


TIPS:
   • If no servers are selected, it queries ALL domain DHCP servers
   • Use the filter to quickly find scopes by name or IP
   • Export results to CSV for reporting


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TAB 3: DNA CENTER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WHAT IT DOES:
   Connects to Cisco DNA Center to manage network devices.
   You can view devices, run commands, and perform bulk operations.


HOW TO USE IT:

   STEP 1: Connect to DNA Center
      • Select your DNA Center server from the dropdown
      • Enter your username and password
      • Click "Connect"
      • Wait for "Connected" status

   STEP 2: Load devices
      • Click "Load Devices"
      • Wait for the device list to populate

   STEP 3: Filter devices (optional)
      • Hostname Search: Type part of a hostname to filter
      • Family: Filter by device type (switches, routers, etc.)
      • Role: Filter by network role (access, distribution, core)
      • IP Address: Filter by specific IP or subnet

   STEP 4: Select devices
      • Check the boxes next to devices you want to work with
      • Use "Select All (Current Filter)" to check all visible devices
      • The status bar shows how many are selected

   STEP 5: Run a function
      • Double-click a function in the TreeView on the left
      • The function runs on all selected devices
      • Results appear in the output area


AVAILABLE FUNCTIONS:
   • Get Device Info - basic device details
   • Get Interfaces - show all interfaces
   • Get Config - retrieve running config
   • Command Runner - run CLI commands
   • And more in the TreeView...


TIPS:
   • Filter first, then Select All - much faster than checking one by one
   • Use "Reset All" to clear filters and start over
   • Check the status bar to confirm how many devices are selected


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TAB 4: FILE COMPARE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WHAT IT DOES:
   Compares two text files and shows you what changed.
   Perfect for comparing switch configs before/after changes.


HOW TO USE IT:

   STEP 1: Select the ORIGINAL file
      • Click "Browse..." next to "Original File"
      • Pick the BEFORE version (the old config)

   STEP 2: Select the MODIFIED file
      • Click "Browse..." next to "Modified File"
      • Pick the AFTER version (the new config)

   STEP 3: Click "Compare & Export HTML"
      • An HTML file is created and opens in your browser
      • Green = lines that were ADDED
      • Red = lines that were REMOVED
      • Gray = lines that stayed the same


BROWSER FEATURES:
   • Prev/Next buttons - jump between changes
   • Unified view - see changes inline
   • Side-by-Side view - see old and new next to each other
   • Keyboard shortcuts: j/k or arrow keys to navigate
   • Statistics show total additions, deletions, unchanged


OTHER BUTTONS:
   • Swap Files - switches Original and Modified
   • Clear - clears both file selections


EXAMPLE: COMPARING SWITCH CONFIGS

   1. Before making changes, copy the switch config to "config_before.txt"
   2. Make your changes on the switch
   3. Copy the new config to "config_after.txt"
   4. Use File Compare to see exactly what changed
   5. Save the HTML for your change documentation!


EMBEDDED RESOURCES:
   At the bottom of this tab, you can export .RDOX files that are
   packaged with OctoNav. Click "Export to Working Directory" to
   extract them.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TAB 5: PORT CONFIG
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WHAT IT DOES:
   Generates switch port configurations from templates.
   Fill in the blanks, click Generate, copy to your switch.


HOW TO USE IT:

   STEP 1: Pick your switch type
      • Cisco = Regular Cisco switches (uses 'switchport' commands)
      • ICX/FCX 8030 = Brocade ICX or FCX 8030 switches
      • FCX 7.3 = Older FCX switches running 7.3 firmware

   STEP 2: Pick a Port Type
      • Type1 through Type6 are different template styles
      • Each type has slightly different commands

   STEP 3: Fill in the boxes
      • Interface: The port name (example: Gi1/0/1)
      • Description: What's plugged in (example: "John's PC")
      • VLAN: The data VLAN number (example: 100)
      • Voice VLAN: For phones (example: 200)
      • Status: "no shutdown" to enable, "shutdown" to disable

   STEP 4: Click "Generate Config"
      • Config appears in the text box on the right
      • Click "Copy to Clipboard"
      • Paste into your switch!


SAVING CUSTOM TEMPLATES:

   1. Paste your config into the output text box
   2. Replace values with placeholders:
      interface Gi1/0/5  →  interface {{INTERFACE}}
      vlan 100           →  vlan {{VLAN}}
   3. Select Vendor and Port Type
   4. Click "Save as Template"


PLACEHOLDERS:
   {{INTERFACE}}    = Port name
   {{DESCRIPTION}}  = Port description
   {{VLAN}}         = Data VLAN
   {{VOICE_VLAN}}   = Voice VLAN
   {{OLD_VLAN}}     = Old VLAN (FCX 7.3 only)
   {{STATUS}}       = no shutdown / shutdown


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GENERAL TIPS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

• Run as Administrator for Network Configuration tab to work

• Most tabs have a log/output area at the bottom - check there for errors

• Use the View menu to switch between Light and Dark themes

• Settings are saved automatically when you close the app

• If something isn't working, check the log area for error messages

"@

$helpText.Text = $helpContent

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
# TAB 0: DASHBOARD
# ============================================

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

# ============================================
# STARTUP PASSWORD AUTHENTICATION
# ============================================

try {
    # Check if startup password is required (team deployment setting)
    $passwordRequired = Test-StartupPasswordRequired

    if ($passwordRequired) {
        # Startup password enabled - authenticate user
        $passwordExists = Test-StartupPasswordExists

        if ($passwordExists) {
            # Prompt for password
            Write-SecurityAudit -Level Info -Event "OctoNav startup" -Details "Password authentication required"

            $authenticated = Show-StartupPasswordDialog -IsFirstRun:$false

            if (-not $authenticated) {
                Write-SecurityAudit -Level Warning -Event "Authentication failed or cancelled" -Details "Application exit"
                exit 0
            }

            Write-SecurityAudit -Level Success -Event "Authentication successful" -Details "OctoNav starting"
        }
        else {
            # First run - set up startup password
            Write-SecurityAudit -Level Info -Event "First run detected" -Details "Setting up startup password"

            $passwordSet = Show-StartupPasswordDialog -IsFirstRun:$true

            if (-not $passwordSet) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Startup password is required for security.`n`nOctoNav will now exit.",
                    "Password Required",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                Write-SecurityAudit -Level Warning -Event "First run - password not set" -Details "Application exit"
                exit 0
            }

            Write-SecurityAudit -Level Success -Event "First run - password configured" -Details "OctoNav starting"
        }

        # Start session monitoring for auto-lock (only if password required)
        Start-SessionMonitor -Form $mainForm
    }
    else {
        # Team deployment mode - no startup password required
        Write-SecurityAudit -Level Info -Event "OctoNav startup" -Details "Team mode - no startup password"
    }
}
catch {
    [System.Windows.Forms.MessageBox]::Show(
        "Security initialization failed:`n`n$($_.Exception.Message)`n`nOctoNav will now exit.",
        "Security Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    Write-SecurityAudit -Level Critical -Event "Security initialization failed" -Details $_.Exception.Message
    exit 1
}

# Show the form
[void]$mainForm.ShowDialog()
