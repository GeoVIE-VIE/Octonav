#Requires -Version 5.1
<#
.SYNOPSIS
    UI Enhancement Module for OctoNav GUI
.DESCRIPTION
    Provides spacing constants, icon definitions, and helper functions for professional UI layout
#>

# ============================================
# SPACING CONSTANTS (8px grid system)
# ============================================

$script:UISpacing = @{
    # Base grid unit (8px)
    GridUnit = 8

    # Margins (distance from container edges)
    MarginSmall = 8      # 1 grid unit
    MarginMedium = 16    # 2 grid units
    MarginLarge = 24     # 3 grid units
    MarginXLarge = 32    # 4 grid units

    # Padding (internal spacing within controls)
    PaddingSmall = 8     # 1 grid unit
    PaddingMedium = 12   # 1.5 grid units
    PaddingLarge = 16    # 2 grid units

    # Control spacing (between controls)
    ControlGap = 8       # Gap between related controls
    ControlGapMedium = 12
    ControlGapLarge = 16

    # Section spacing (between major sections)
    SectionGap = 20      # 2.5 grid units
    SectionGapLarge = 24 # 3 grid units

    # Button dimensions
    ButtonHeight = 36    # Larger click target
    ButtonHeightSmall = 32
    ButtonWidthStandard = 140
    ButtonWidthSmall = 120
    ButtonWidthLarge = 160

    # Input field dimensions
    InputHeight = 24
    InputHeightLarge = 28

    # GroupBox title offset
    GroupBoxTitleHeight = 20
    GroupBoxContentTop = 28  # Where content starts inside GroupBox
}

# ============================================
# ICON DEFINITIONS (Unicode characters)
# ============================================

$script:UIIcons = @{
    # Status icons
    Success = "✓"
    Error = "✗"
    Warning = "⚠"
    Info = "ℹ"

    # Action icons
    Connect = "🔌"
    Disconnect = "🔌"  # Same icon, different state
    Refresh = "🔄"
    Search = "🔍"
    Filter = "⚙"
    Export = "💾"
    Import = "📁"
    Settings = "⚙"

    # Feature icons
    Network = "🌐"
    Server = "🖥"
    Database = "💾"
    Stats = "📊"
    DNA = "🔬"

    # Navigation
    Forward = "▶"
    Back = "◀"
    Up = "▲"
    Down = "▼"

    # Status indicators
    Online = "●"
    Offline = "○"
    Shield = "🛡"
    User = "👤"
    Time = "🕐"
}

# ============================================
# HELPER FUNCTIONS
# ============================================

function Get-UISpacing {
    <#
    .SYNOPSIS
        Gets a spacing value from the UI spacing constants
    .PARAMETER Name
        The spacing constant name (e.g., "MarginMedium", "ButtonHeight")
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    if ($script:UISpacing.ContainsKey($Name)) {
        return $script:UISpacing[$Name]
    }

    Write-Warning "Unknown spacing constant: $Name"
    return 0
}

function Get-UIIcon {
    <#
    .SYNOPSIS
        Gets an icon character
    .PARAMETER Name
        The icon name (e.g., "Success", "Connect", "Network")
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    if ($script:UIIcons.ContainsKey($Name)) {
        return $script:UIIcons[$Name]
    }

    return ""
}

function New-EnhancedButton {
    <#
    .SYNOPSIS
        Creates a button with improved styling and optional icon
    .PARAMETER Text
        Button text
    .PARAMETER Icon
        Optional icon name from UIIcons
    .PARAMETER Width
        Button width (defaults to standard width)
    .PARAMETER IsPrimary
        If true, styles as primary action button
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Text,

        [string]$Icon = "",

        [int]$Width = 0,

        [switch]$IsPrimary
    )

    $button = New-Object System.Windows.Forms.Button

    # Set text with icon if specified
    if ($Icon -ne "" -and $script:UIIcons.ContainsKey($Icon)) {
        $button.Text = "$($script:UIIcons[$Icon]) $Text"
    } else {
        $button.Text = $Text
    }

    # Set dimensions
    if ($Width -eq 0) {
        $Width = $script:UISpacing.ButtonWidthStandard
    }
    $button.Size = New-Object System.Drawing.Size($Width, $script:UISpacing.ButtonHeight)

    # Apply styling
    $button.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button.FlatAppearance.BorderSize = 0
    $button.Cursor = [System.Windows.Forms.Cursors]::Hand

    # Primary vs Secondary styling (will be further styled by theme)
    if ($IsPrimary) {
        $button.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#0078D4")  # Microsoft blue
        $button.ForeColor = [System.Drawing.Color]::White

        # Add hover effects
        $button.Add_MouseEnter({
            $this.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#005A9E")
        })
        $button.Add_MouseLeave({
            $this.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#0078D4")
        })
    } else {
        # Secondary button - theme will apply colors
        $button.BackColor = [System.Drawing.Color]::WhiteSmoke
        $button.ForeColor = [System.Drawing.Color]::Black

        $button.Add_MouseEnter({
            $this.BackColor = [System.Drawing.Color]::LightGray
        })
        $button.Add_MouseLeave({
            $this.BackColor = [System.Drawing.Color]::WhiteSmoke
        })
    }

    return $button
}

function New-EnhancedStatusBar {
    <#
    .SYNOPSIS
        Creates an enhanced status bar with multiple panels
    .PARAMETER Form
        The parent form
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Windows.Forms.Form]$Form
    )

    $statusStrip = New-Object System.Windows.Forms.StatusStrip
    $statusStrip.SizingGrip = $true
    $statusStrip.Font = New-Object System.Drawing.Font("Segoe UI", 9)

    # Panel 1: Main status message (spring-enabled to take remaining space)
    $statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $statusLabel.Name = "StatusLabel"
    $statusLabel.Text = "Ready"
    $statusLabel.Spring = $true
    $statusLabel.TextAlign = "MiddleLeft"
    $statusStrip.Items.Add($statusLabel) | Out-Null

    # Panel 2: Separator
    $separator1 = New-Object System.Windows.Forms.ToolStripSeparator
    $separator1.Name = "Separator1"
    $statusStrip.Items.Add($separator1) | Out-Null

    # Panel 3: Connection status
    $connectionLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $connectionLabel.Name = "ConnectionStatus"
    $connectionLabel.Text = "$(Get-UIIcon -Name 'Offline') Not Connected"
    $connectionLabel.AutoSize = $true
    $connectionLabel.BorderSides = "Left"
    $connectionLabel.BorderStyle = [System.Windows.Forms.Border3DStyle]::Etched
    $statusStrip.Items.Add($connectionLabel) | Out-Null

    # Panel 4: Separator
    $separator2 = New-Object System.Windows.Forms.ToolStripSeparator
    $separator2.Name = "Separator2"
    $statusStrip.Items.Add($separator2) | Out-Null

    # Panel 5: User/Admin status
    $userLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $userLabel.Name = "UserStatus"

    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        $userLabel.Text = "$(Get-UIIcon -Name 'Shield') Administrator"
        $userLabel.ForeColor = [System.Drawing.Color]::Green
    } else {
        $userLabel.Text = "$(Get-UIIcon -Name 'User') User"
        $userLabel.ForeColor = [System.Drawing.Color]::Gray
    }
    $userLabel.AutoSize = $true
    $userLabel.BorderSides = "Left"
    $userLabel.BorderStyle = [System.Windows.Forms.Border3DStyle]::Etched
    $statusStrip.Items.Add($userLabel) | Out-Null

    # Panel 6: Separator
    $separator3 = New-Object System.Windows.Forms.ToolStripSeparator
    $separator3.Name = "Separator3"
    $statusStrip.Items.Add($separator3) | Out-Null

    # Panel 7: Progress bar (hidden by default)
    $progressBar = New-Object System.Windows.Forms.ToolStripProgressBar
    $progressBar.Name = "ProgressBar"
    $progressBar.Size = New-Object System.Drawing.Size(150, 16)
    $progressBar.Visible = $false
    $statusStrip.Items.Add($progressBar) | Out-Null

    # Panel 8: Progress label (hidden by default)
    $progressLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $progressLabel.Name = "ProgressLabel"
    $progressLabel.Text = ""
    $progressLabel.Visible = $false
    $statusStrip.Items.Add($progressLabel) | Out-Null

    $Form.Controls.Add($statusStrip)

    # Return hashtable with references to all panels for easy access
    return @{
        StatusStrip = $statusStrip
        StatusLabel = $statusLabel
        ConnectionStatus = $connectionLabel
        UserStatus = $userLabel
        ProgressBar = $progressBar
        ProgressLabel = $progressLabel
    }
}

function Update-ConnectionStatus {
    <#
    .SYNOPSIS
        Updates the connection status panel
    .PARAMETER StatusBar
        The status bar hashtable returned by New-EnhancedStatusBar
    .PARAMETER IsConnected
        Connection status
    .PARAMETER ServerName
        Optional server name to display
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$StatusBar,

        [Parameter(Mandatory=$true)]
        [bool]$IsConnected,

        [string]$ServerName = ""
    )

    if ($IsConnected) {
        if ($ServerName -ne "") {
            $StatusBar.ConnectionStatus.Text = "$(Get-UIIcon -Name 'Online') Connected to $ServerName"
        } else {
            $StatusBar.ConnectionStatus.Text = "$(Get-UIIcon -Name 'Online') Connected"
        }
        $StatusBar.ConnectionStatus.ForeColor = [System.Drawing.Color]::Green
    } else {
        $StatusBar.ConnectionStatus.Text = "$(Get-UIIcon -Name 'Offline') Not Connected"
        $StatusBar.ConnectionStatus.ForeColor = [System.Drawing.Color]::Gray
    }
}

function Set-StatusMessage {
    <#
    .SYNOPSIS
        Sets the main status message
    .PARAMETER StatusBar
        The status bar hashtable
    .PARAMETER Message
        The message to display
    .PARAMETER IsError
        If true, displays in red
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$StatusBar,

        [Parameter(Mandatory=$true)]
        [string]$Message,

        [switch]$IsError
    )

    $StatusBar.StatusLabel.Text = $Message

    if ($IsError) {
        $StatusBar.StatusLabel.ForeColor = [System.Drawing.Color]::Red
    } else {
        $StatusBar.StatusLabel.ForeColor = [System.Drawing.Color]::Black
    }
}

function Show-Progress {
    <#
    .SYNOPSIS
        Shows/updates the progress bar
    .PARAMETER StatusBar
        The status bar hashtable
    .PARAMETER Current
        Current progress value
    .PARAMETER Total
        Total progress value
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$StatusBar,

        [Parameter(Mandatory=$true)]
        [int]$Current,

        [Parameter(Mandatory=$true)]
        [int]$Total
    )

    $StatusBar.ProgressBar.Visible = $true
    $StatusBar.ProgressLabel.Visible = $true

    $percentage = [Math]::Round(($Current / $Total) * 100)
    $StatusBar.ProgressBar.Maximum = $Total
    $StatusBar.ProgressBar.Value = $Current
    $StatusBar.ProgressLabel.Text = "$Current/$Total ($percentage%)"
}

function Hide-Progress {
    <#
    .SYNOPSIS
        Hides the progress bar
    .PARAMETER StatusBar
        The status bar hashtable
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$StatusBar
    )

    $StatusBar.ProgressBar.Visible = $false
    $StatusBar.ProgressLabel.Visible = $false
    $StatusBar.ProgressBar.Value = 0
    $StatusBar.ProgressLabel.Text = ""
}

function Add-IconToTab {
    <#
    .SYNOPSIS
        Adds an icon to a tab's text
    .PARAMETER Tab
        The TabPage to modify
    .PARAMETER IconName
        The icon name from UIIcons
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Windows.Forms.TabPage]$Tab,

        [Parameter(Mandatory=$true)]
        [string]$IconName
    )

    $icon = Get-UIIcon -Name $IconName
    if ($icon -ne "") {
        # Store original text if not already stored
        if (-not $Tab.Tag) {
            $Tab.Tag = $Tab.Text
        }
        $Tab.Text = "$icon $($Tab.Tag)"
    }
}

# ============================================
# EXPORT MODULE MEMBERS
# ============================================

Export-ModuleMember -Function @(
    'Get-UISpacing',
    'Get-UIIcon',
    'New-EnhancedButton',
    'New-EnhancedStatusBar',
    'Update-ConnectionStatus',
    'Set-StatusMessage',
    'Show-Progress',
    'Hide-Progress',
    'Add-IconToTab'
)

Export-ModuleMember -Variable @(
    'UISpacing',
    'UIIcons'
)
