#Requires -Version 5.1
<#
.SYNOPSIS
    Theme Manager for OctoNav GUI v2.3
.DESCRIPTION
    Manages Light and Dark themes for the application
#>

# Define color schemes
$script:LightTheme = @{
    Name = "Light"

    # Form/Window
    FormBackColor = [System.Drawing.Color]::White
    FormForeColor = [System.Drawing.Color]::Black

    # Controls
    ControlBackColor = [System.Drawing.Color]::White
    ControlForeColor = [System.Drawing.Color]::Black

    # GroupBox
    GroupBoxBackColor = [System.Drawing.Color]::FromArgb(247, 247, 247)  # Subtle gray tint
    GroupBoxForeColor = [System.Drawing.Color]::Black

    # TextBox/RichTextBox
    TextBoxBackColor = [System.Drawing.Color]::White
    TextBoxForeColor = [System.Drawing.Color]::Black
    TextBoxBorderColor = [System.Drawing.Color]::Gray
    RichTextBoxBackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)  # Subtle background for logs

    # Button
    ButtonBackColor = [System.Drawing.Color]::WhiteSmoke
    ButtonForeColor = [System.Drawing.Color]::Black
    ButtonHoverBackColor = [System.Drawing.Color]::LightGray

    # TabControl
    TabBackColor = [System.Drawing.Color]::White
    TabForeColor = [System.Drawing.Color]::Black

    # StatusStrip
    StatusStripBackColor = [System.Drawing.Color]::WhiteSmoke
    StatusStripForeColor = [System.Drawing.Color]::Black

    # TreeView
    TreeViewBackColor = [System.Drawing.Color]::White
    TreeViewForeColor = [System.Drawing.Color]::Black
    TreeViewLineColor = [System.Drawing.Color]::Gray

    # Log colors
    LogSuccessColor = [System.Drawing.Color]::Green
    LogErrorColor = [System.Drawing.Color]::Red
    LogWarningColor = [System.Drawing.Color]::DarkOrange
    LogInfoColor = [System.Drawing.Color]::DarkCyan
    LogDebugColor = [System.Drawing.Color]::Gray
}

$script:DarkTheme = @{
    Name = "Dark"

    # Form/Window
    FormBackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    FormForeColor = [System.Drawing.Color]::White

    # Controls
    ControlBackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
    ControlForeColor = [System.Drawing.Color]::White

    # GroupBox
    GroupBoxBackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    GroupBoxForeColor = [System.Drawing.Color]::White

    # TextBox/RichTextBox
    TextBoxBackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
    TextBoxForeColor = [System.Drawing.Color]::White
    TextBoxBorderColor = [System.Drawing.Color]::Gray
    RichTextBoxBackColor = [System.Drawing.Color]::FromArgb(35, 35, 35)  # Slightly darker for logs

    # Button
    ButtonBackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    ButtonForeColor = [System.Drawing.Color]::White
    ButtonHoverBackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)

    # TabControl
    TabBackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    TabForeColor = [System.Drawing.Color]::White

    # StatusStrip
    StatusStripBackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
    StatusStripForeColor = [System.Drawing.Color]::White

    # TreeView
    TreeViewBackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
    TreeViewForeColor = [System.Drawing.Color]::White
    TreeViewLineColor = [System.Drawing.Color]::Gray

    # Log colors
    LogSuccessColor = [System.Drawing.Color]::LimeGreen
    LogErrorColor = [System.Drawing.Color]::OrangeRed
    LogWarningColor = [System.Drawing.Color]::Orange
    LogInfoColor = [System.Drawing.Color]::Cyan
    LogDebugColor = [System.Drawing.Color]::LightGray
}

function Get-Theme {
    <#
    .SYNOPSIS
        Gets the specified theme
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Light", "Dark")]
        [string]$ThemeName
    )

    if ($ThemeName -eq "Dark") {
        return $script:DarkTheme
    }
    return $script:LightTheme
}

function Set-ThemeToControl {
    <#
    .SYNOPSIS
        Sets theme to a control and its children recursively
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Windows.Forms.Control]$Control,

        [Parameter(Mandatory=$true)]
        [hashtable]$Theme
    )

    try {
        # Apply theme based on control type
        switch ($Control.GetType().Name) {
            "Form" {
                $Control.BackColor = $Theme.FormBackColor
                $Control.ForeColor = $Theme.FormForeColor
            }
            "GroupBox" {
                $Control.BackColor = $Theme.GroupBoxBackColor
                $Control.ForeColor = $Theme.GroupBoxForeColor
            }
            "TextBox" {
                $Control.BackColor = $Theme.TextBoxBackColor
                $Control.ForeColor = $Theme.TextBoxForeColor
            }
            "RichTextBox" {
                if ($Theme.ContainsKey('RichTextBoxBackColor')) {
                    $Control.BackColor = $Theme.RichTextBoxBackColor
                } else {
                    $Control.BackColor = $Theme.TextBoxBackColor
                }
                $Control.ForeColor = $Theme.TextBoxForeColor
            }
            "Button" {
                $Control.BackColor = $Theme.ButtonBackColor
                $Control.ForeColor = $Theme.ButtonForeColor
                $Control.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
                $Control.FlatAppearance.BorderColor = $Theme.TextBoxBorderColor
            }
            "TabControl" {
                $Control.BackColor = $Theme.TabBackColor
                $Control.ForeColor = $Theme.TabForeColor
            }
            "TabPage" {
                $Control.BackColor = $Theme.FormBackColor
                $Control.ForeColor = $Theme.FormForeColor
            }
            "Label" {
                $Control.ForeColor = $Theme.ControlForeColor
            }
            "TreeView" {
                $Control.BackColor = $Theme.TreeViewBackColor
                $Control.ForeColor = $Theme.TreeViewForeColor
                $Control.LineColor = $Theme.TreeViewLineColor
            }
            "ComboBox" {
                $Control.BackColor = $Theme.ControlBackColor
                $Control.ForeColor = $Theme.ControlForeColor
                $Control.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
            }
            "StatusStrip" {
                $Control.BackColor = $Theme.StatusStripBackColor
                $Control.ForeColor = $Theme.StatusStripForeColor
            }
            "Panel" {
                $Control.BackColor = $Theme.ControlBackColor
                $Control.ForeColor = $Theme.ControlForeColor
            }
            default {
                # Generic control
                if ($Control.BackColor -ne [System.Drawing.Color]::Transparent) {
                    $Control.BackColor = $Theme.ControlBackColor
                }
                $Control.ForeColor = $Theme.ControlForeColor
            }
        }

        # Recursively apply to child controls
        foreach ($child in $Control.Controls) {
            Set-ThemeToControl -Control $child -Theme $Theme
        }
    } catch {
        # Silently continue if unable to apply theme to this control
    }
}

function Get-LogColor {
    <#
    .SYNOPSIS
        Gets the appropriate log color for the current theme
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Theme,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Success", "Error", "Warning", "Info", "Debug")]
        [string]$LogType
    )

    switch ($LogType) {
        "Success" { return $Theme.LogSuccessColor }
        "Error" { return $Theme.LogErrorColor }
        "Warning" { return $Theme.LogWarningColor }
        "Info" { return $Theme.LogInfoColor }
        "Debug" { return $Theme.LogDebugColor }
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Get-Theme',
    'Set-ThemeToControl',
    'Get-LogColor'
)
