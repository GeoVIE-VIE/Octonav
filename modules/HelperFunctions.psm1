#Requires -Version 5.1
<#
.SYNOPSIS
    Helper Functions for OctoNav GUI v2.3
.DESCRIPTION
    General utility and helper functions
#>

function Write-Log {
    <#
    .SYNOPSIS
        Writes a log message to a RichTextBox with color coding
    #>
    param(
        [string]$Message,
        [ValidateSet("Success", "Error", "Warning", "Info", "Debug", "Black")]
        [string]$Color = "Black",
        [System.Windows.Forms.RichTextBox]$LogBox,
        [hashtable]$Theme = $null
    )

    if ($LogBox) {
        try {
            $LogBox.Invoke([Action]{
                # Suspend layout for better performance during rapid updates
                $LogBox.SuspendLayout()

                $LogBox.SelectionStart = $LogBox.TextLength
                $LogBox.SelectionLength = 0

                # Determine color based on type and theme
                if ($Theme) {
                    $LogBox.SelectionColor = switch ($Color) {
                        "Success" { $Theme.LogSuccessColor }
                        "Error" { $Theme.LogErrorColor }
                        "Warning" { $Theme.LogWarningColor }
                        "Info" { $Theme.LogInfoColor }
                        "Debug" { $Theme.LogDebugColor }
                        default { $Theme.ControlForeColor }
                    }
                } else {
                    # Fallback to default colors
                    $LogBox.SelectionColor = switch ($Color) {
                        "Success" { [System.Drawing.Color]::Green }
                        "Error" { [System.Drawing.Color]::Red }
                        "Warning" { [System.Drawing.Color]::DarkOrange }
                        "Info" { [System.Drawing.Color]::DarkCyan }
                        "Debug" { [System.Drawing.Color]::Gray }
                        default { [System.Drawing.Color]::Black }
                    }
                }

                $timestamp = Get-Date -Format "HH:mm:ss"
                $LogBox.AppendText("[$timestamp] $Message`r`n")
                $LogBox.SelectionColor = $LogBox.ForeColor

                # Resume layout and force scroll to bottom
                $LogBox.ResumeLayout()
                $LogBox.SelectionStart = $LogBox.TextLength
                $LogBox.ScrollToCaret()
                $LogBox.Refresh()
            })
        } catch {
            # Silently fail if log box is not available
        }
    }
}

function Update-StatusBar {
    <#
    .SYNOPSIS
        Updates the status bar with status text and progress
    #>
    param(
        [string]$Status = "",
        [int]$ProgressValue = -1,
        [int]$ProgressMax = 100,
        [string]$ProgressText = "",
        [System.Windows.Forms.ToolStripStatusLabel]$StatusLabel = $null,
        [System.Windows.Forms.ToolStripProgressBar]$ProgressBar = $null,
        [System.Windows.Forms.ToolStripStatusLabel]$ProgressLabel = $null
    )

    try {
        if ($StatusLabel) {
            $StatusLabel.GetCurrentParent().Invoke([Action]{
                if ($Status) {
                    $StatusLabel.Text = $Status
                }

                if ($ProgressBar -and $ProgressValue -ge 0) {
                    $ProgressBar.Visible = $true
                    $ProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
                    $ProgressBar.Maximum = $ProgressMax
                    $ProgressBar.Value = [Math]::Min($ProgressValue, $ProgressMax)

                    if ($ProgressLabel -and $ProgressText) {
                        $ProgressLabel.Visible = $true
                        $ProgressLabel.Text = $ProgressText
                    }
                } elseif ($ProgressBar) {
                    # Hide progress indicators
                    $ProgressBar.Visible = $false
                    if ($ProgressLabel) {
                        $ProgressLabel.Visible = $false
                    }
                }
            })
        }
    } catch {
        # Silently fail if status bar not available
    }
}

function Set-MarqueeProgress {
    <#
    .SYNOPSIS
        Sets progress bar to marquee style for indeterminate operations
    #>
    param(
        [System.Windows.Forms.ToolStripProgressBar]$ProgressBar,
        [System.Windows.Forms.ToolStripStatusLabel]$ProgressLabel = $null,
        [string]$Text = "Working..."
    )

    try {
        if ($ProgressBar) {
            $ProgressBar.GetCurrentParent().Invoke([Action]{
                $ProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee
                $ProgressBar.Visible = $true

                if ($ProgressLabel) {
                    $ProgressLabel.Text = $Text
                    $ProgressLabel.Visible = $true
                }
            })
        }
    } catch {
        # Silently fail
    }
}

function Hide-Progress {
    <#
    .SYNOPSIS
        Hides progress indicators
    #>
    param(
        [System.Windows.Forms.ToolStripProgressBar]$ProgressBar,
        [System.Windows.Forms.ToolStripStatusLabel]$ProgressLabel = $null
    )

    try {
        if ($ProgressBar) {
            $ProgressBar.GetCurrentParent().Invoke([Action]{
                $ProgressBar.Visible = $false
                if ($ProgressLabel) {
                    $ProgressLabel.Visible = $false
                }
            })
        }
    } catch {
        # Silently fail
    }
}

function ConvertTo-ReadableTimestamp {
    <#
    .SYNOPSIS
        Converts various timestamp formats to readable format
    #>
    param([object]$Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [DateTime]) {
        return ($Value.ToUniversalTime().ToString("u"))
    }

    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

        if ($Value -match '^-?\d+$') {
            try {
                return ConvertTo-ReadableTimestamp([long]$Value)
            } catch {
                return $Value
            }
        }

        try {
            $parsed = Get-Date $Value
            return ($parsed.ToUniversalTime().ToString("u"))
        } catch {
            return $Value
        }
    }

    if ($Value -is [long] -or $Value -is [int]) {
        $numeric = [long]$Value
        try {
            if ($numeric -gt 9999999999) {
                return ([DateTimeOffset]::FromUnixTimeMilliseconds($numeric)).UtcDateTime.ToString("u")
            } elseif ($numeric -gt 0) {
                return ([DateTimeOffset]::FromUnixTimeSeconds($numeric)).UtcDateTime.ToString("u")
            }
        } catch {
            return $numeric.ToString()
        }
        return $numeric.ToString()
    }

    return $Value.ToString()
}

function Invoke-Filters {
    <#
    .SYNOPSIS
        Invokes filters on output lines (OR logic)
    #>
    param(
        [string[]]$Lines,
        [string[]]$Filters
    )

    # No filters = return all lines
    if ($Filters.Count -eq 0) {
        return $Lines
    }

    $matchedLines = @()
    foreach ($line in $Lines) {
        foreach ($pattern in $Filters) {
            # Use -like for simple substring matching (case-insensitive)
            if ($line -like "*$pattern*") {
                $matchedLines += $line
                break  # Stop checking other patterns once matched (OR logic)
            }
        }
    }

    return $matchedLines
}

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Tests if the current PowerShell session is running with Administrator privileges
    #>
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Show-ToastNotification {
    <#
    .SYNOPSIS
        Shows a Windows toast notification
    #>
    param(
        [string]$Title,
        [string]$Message,
        [string]$Type = "Info"  # Info, Success, Warning, Error
    )

    # This is a placeholder for toast notifications
    # Full implementation would require Windows 10+ toast notification APIs
    # For now, we'll just use a simple balloon tip if available
    Write-Verbose "Toast: [$Type] $Title - $Message"
}

# Export module members
# Note: Invoke-BackgroundOperation is defined in main script (not module) to ensure
# System.Windows.Forms.Timer is available at definition time
Export-ModuleMember -Function @(
    'Write-Log',
    'Update-StatusBar',
    'Set-MarqueeProgress',
    'Hide-Progress',
    'ConvertTo-ReadableTimestamp',
    'Invoke-Filters',
    'Test-IsAdministrator',
    'Show-ToastNotification'
)
