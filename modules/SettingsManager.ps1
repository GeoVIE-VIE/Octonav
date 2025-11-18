#Requires -Version 5.1
<#
.SYNOPSIS
    Settings and Preferences Manager for OctoNav GUI v2.3
.DESCRIPTION
    Manages user settings, preferences, and configuration persistence
#>

# Default settings structure
$script:DefaultSettings = @{
    # Appearance
    Theme = "Light"  # Light or Dark
    WindowSize = @{ Width = 1200; Height = 800 }
    WindowMaximized = $false

    # DNA Center
    DNACenterServers = @()
    LastDNACenterServer = $null
    DefaultTimeout = 30
    CertificateValidation = $false

    # DHCP
    DHCPAutoDiscover = $true
    DHCPDefaultServers = @()
    DHCPCollectDNS = $false
    DHCPParallelServers = 20

    # Export
    DefaultExportFormat = "CSV"  # CSV, Excel, JSON, HTML
    DefaultExportPath = "C:\DNACenter_Reports"
    ExportHistory = @()
    AutoExportAfterCollection = $true
    IncludeTimestampInFilename = $true

    # Advanced
    EnableLogging = $true
    LogLevel = "Info"  # Debug, Info, Warning, Error
    ShowProgressNotifications = $true
    ConfirmDestructiveActions = $true

    # Dashboard
    DashboardRefreshInterval = 300  # seconds
    ShowDashboardOnStartup = $true

    # DNA Center Favorites
    FavoriteFunctions = @()
}

# Settings file path
$script:SettingsPath = Join-Path $PSScriptRoot "..\octonav_settings.json"

function Get-OctoNavSettings {
    <#
    .SYNOPSIS
        Loads OctoNav settings from file or returns defaults
    #>
    try {
        if (Test-Path $script:SettingsPath) {
            $loadedSettings = Get-Content $script:SettingsPath -Raw | ConvertFrom-Json

            # Merge with defaults (in case new settings were added)
            $settings = $script:DefaultSettings.Clone()
            foreach ($key in $loadedSettings.PSObject.Properties.Name) {
                $settings[$key] = $loadedSettings.$key
            }

            return $settings
        }
    } catch {
        Write-Warning "Failed to load settings: $_"
    }

    # Return defaults if file doesn't exist or failed to load
    return $script:DefaultSettings.Clone()
}

function Save-OctoNavSettings {
    <#
    .SYNOPSIS
        Saves OctoNav settings to file
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Settings
    )

    try {
        $Settings | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:SettingsPath -Encoding UTF8 -Force
        return $true
    } catch {
        Write-Warning "Failed to save settings: $_"
        return $false
    }
}

function Reset-OctoNavSettings {
    <#
    .SYNOPSIS
        Resets settings to defaults
    #>
    try {
        if (Test-Path $script:SettingsPath) {
            Remove-Item $script:SettingsPath -Force
        }
        return $script:DefaultSettings.Clone()
    } catch {
        Write-Warning "Failed to reset settings: $_"
        return $null
    }
}

function Add-ExportHistory {
    <#
    .SYNOPSIS
        Adds an export operation to history
    #>
    param(
        [hashtable]$Settings,
        [string]$FilePath,
        [string]$Operation,
        [string]$Format
    )

    $historyEntry = @{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        FilePath = $FilePath
        Operation = $Operation
        Format = $Format
    }

    if (-not $Settings.ExportHistory) {
        $Settings.ExportHistory = @()
    }

    # Keep only last 50 entries
    if ($Settings.ExportHistory.Count -ge 50) {
        $Settings.ExportHistory = $Settings.ExportHistory | Select-Object -Last 49
    }

    $Settings.ExportHistory += $historyEntry
    Save-OctoNavSettings -Settings $Settings
}

function Get-ExportHistory {
    <#
    .SYNOPSIS
        Gets recent export history
    #>
    param(
        [hashtable]$Settings,
        [int]$Count = 10
    )

    if ($Settings.ExportHistory) {
        return $Settings.ExportHistory | Select-Object -Last $Count
    }
    return @()
}

function Add-FavoriteFunction {
    <#
    .SYNOPSIS
        Adds a DNA Center function to favorites
    #>
    param(
        [hashtable]$Settings,
        [string]$FunctionName
    )

    if (-not $Settings.FavoriteFunctions) {
        $Settings.FavoriteFunctions = @()
    }

    if ($FunctionName -notin $Settings.FavoriteFunctions) {
        $Settings.FavoriteFunctions += $FunctionName
        Save-OctoNavSettings -Settings $Settings
        return $true
    }
    return $false
}

function Remove-FavoriteFunction {
    <#
    .SYNOPSIS
        Removes a DNA Center function from favorites
    #>
    param(
        [hashtable]$Settings,
        [string]$FunctionName
    )

    if ($Settings.FavoriteFunctions) {
        $Settings.FavoriteFunctions = $Settings.FavoriteFunctions | Where-Object { $_ -ne $FunctionName }
        Save-OctoNavSettings -Settings $Settings
        return $true
    }
    return $false
}

function Test-IsFavorite {
    <#
    .SYNOPSIS
        Checks if a function is in favorites
    #>
    param(
        [hashtable]$Settings,
        [string]$FunctionName
    )

    return ($Settings.FavoriteFunctions -contains $FunctionName)
}

# Export module members
Export-ModuleMember -Function @(
    'Get-OctoNavSettings',
    'Save-OctoNavSettings',
    'Reset-OctoNavSettings',
    'Add-ExportHistory',
    'Get-ExportHistory',
    'Add-FavoriteFunction',
    'Remove-FavoriteFunction',
    'Test-IsFavorite'
)
