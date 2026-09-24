#Requires -Version 5.1
# Network management GUI: dashboard, network adapter configuration, DHCP scope
# statistics, Cisco DNA Center API functions, file comparison, port configuration
# templates and embedded resource export. Everything is in this one file.
#
# Runs as a standard user; only the Network Configuration tab needs elevation
# (it changes adapter IP settings).
#
# DHCP math: a scope served by a failover pair is counted once (both partners
# report the whole scope), a scope split across servers without failover has its
# parts summed (never more than the scope's address range), and inactive copies
# are not counted - see Get-DhcpScopeAnalysis.
#
# Settings and caches are stored next to this script, or in %LOCALAPPDATA%\OctoNav
# when this folder is read-only for the current user.

# ============================================
# BOOTSTRAP
# ============================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 renders a progress bar for every web request, which makes
# Invoke-RestMethod several times slower on large responses.
$ProgressPreference = 'SilentlyContinue'

$script:AppRoot = if ($PSScriptRoot) { $PSScriptRoot }
    elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
    else { (Get-Location).Path }

function Get-OctoDataDirectory {
    <#
    .SYNOPSIS
        Folder for settings and caches: next to the script (as before) or, when the
        current user cannot write there, %LOCALAPPDATA%\OctoNav.
    #>
    $candidates = @($script:AppRoot)
    if ($env:LOCALAPPDATA) { $candidates += (Join-Path $env:LOCALAPPDATA 'OctoNav') }
    foreach ($dir in $candidates) {
        if ([string]::IsNullOrWhiteSpace($dir)) { continue }
        try {
            if (-not [System.IO.Directory]::Exists($dir)) { [void][System.IO.Directory]::CreateDirectory($dir) }
            $probe = Join-Path $dir ('.octonav_write_test_' + [guid]::NewGuid().ToString('N'))
            [System.IO.File]::WriteAllText($probe, '')
            [System.IO.File]::Delete($probe)
            return $dir
        } catch { }
    }
    return [System.IO.Path]::GetTempPath()
}
$script:DataDir = Get-OctoDataDirectory

function Enable-OctoCertificateBypass {
    <#
    .SYNOPSIS
        Accepts self-signed DNA Center certificates (same behaviour as before).
    .DESCRIPTION
        The callback is compiled from a System.Linq.Expressions lambda instead of
        Add-Type C#, so no C# compiler (csc.exe) starts with the tool, and the
        delegate is safe to call from the parallel request threads.
    #>
    if ([System.Net.ServicePointManager]::ServerCertificateValidationCallback) { return }
    try {
        $parameters = [System.Linq.Expressions.ParameterExpression[]]@(
            [System.Linq.Expressions.Expression]::Parameter([object], 'sender'),
            [System.Linq.Expressions.Expression]::Parameter([System.Security.Cryptography.X509Certificates.X509Certificate], 'certificate'),
            [System.Linq.Expressions.Expression]::Parameter([System.Security.Cryptography.X509Certificates.X509Chain], 'chain'),
            [System.Linq.Expressions.Expression]::Parameter([System.Net.Security.SslPolicyErrors], 'errors'))
        $lambda = [System.Linq.Expressions.Expression]::Lambda(
            [System.Net.Security.RemoteCertificateValidationCallback],
            [System.Linq.Expressions.Expression]::Constant($true),
            $parameters)
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [System.Net.Security.RemoteCertificateValidationCallback]$lambda.Compile()
    } catch {
        if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
            Add-Type -TypeDefinition @'
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class ServerCertificateValidationCallback
{
    public static void Ignore()
    {
        ServicePointManager.ServerCertificateValidationCallback =
            delegate (object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; };
    }
}
'@
        }
        [ServerCertificateValidationCallback]::Ignore()
    }
}

Enable-OctoCertificateBypass
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
# .NET Framework allows only 2 concurrent connections per host by default, which
# would serialize the parallel DNA Center requests. Expect: 100-continue and
# Nagle only add latency to small API calls.
[System.Net.ServicePointManager]::DefaultConnectionLimit = 64
[System.Net.ServicePointManager]::Expect100Continue = $false
[System.Net.ServicePointManager]::UseNagleAlgorithm = $false

# ============================================
# LOGGING & STATUS
# ============================================

$script:LogColorKeys = @{
    'Success' = 'LogSuccessColor'; 'Green'  = 'LogSuccessColor'
    'Error'   = 'LogErrorColor';   'Red'    = 'LogErrorColor'
    'Warning' = 'LogWarningColor'; 'Yellow' = 'LogWarningColor'
    'Info'    = 'LogInfoColor';    'Cyan'   = 'LogInfoColor'
    'Debug'   = 'LogDebugColor';   'Gray'   = 'LogDebugColor'
}

function Write-Log {
    <#
    .SYNOPSIS
        Appends a timestamped, colour-coded line to a RichTextBox log.
    .DESCRIPTION
        Accepts Success/Error/Warning/Info/Debug and Green/Red/Yellow/Cyan/Gray/
        Magenta/White/Black. Colours follow the current theme, so log text stays
        readable in the dark theme.
    #>
    param(
        [string]$Message,
        [string]$Color = 'Black',
        [System.Windows.Forms.RichTextBox]$LogBox,
        [hashtable]$Theme
    )
    if ($null -eq $LogBox -or $LogBox.IsDisposed) { return }
    if ($null -eq $Theme) { $Theme = $script:CurrentTheme }
    $key = $script:LogColorKeys[$Color]
    if ($key -and $Theme) { $textColor = $Theme[$key] }
    elseif ($Color -eq 'Magenta') { $textColor = [System.Drawing.Color]::Magenta }
    elseif ($Theme) { $textColor = $Theme.TextBoxForeColor }
    else { $textColor = $LogBox.ForeColor }
    try {
        $LogBox.SelectionStart = $LogBox.TextLength
        $LogBox.SelectionLength = 0
        $LogBox.SelectionColor = $textColor
        $LogBox.AppendText('[' + [DateTime]::Now.ToString('HH:mm:ss') + '] ' + $Message + "`r`n")
        $LogBox.SelectionColor = $LogBox.ForeColor
        $LogBox.ScrollToCaret()
    } catch { }
}

function Set-OctoStatus {
    <#
    .SYNOPSIS
        Updates the status bar text and (optionally) the progress bar.
    .PARAMETER Percent
        0-100 shows the progress bar; omit (or -1) to hide it.
    #>
    param([string]$Text, [int]$Percent = -1, [string]$ProgressText = '', [switch]$IsError)
    $bar = $script:StatusBarPanels
    if ($null -eq $bar) { return }
    try {
        if ($Text) {
            $bar.StatusLabel.Text = $Text
            $bar.StatusLabel.ForeColor = if ($IsError) { $script:CurrentTheme.ErrorText } else { $script:CurrentTheme.StatusStripForeColor }
        }
        if ($Percent -ge 0) {
            $bar.ProgressBar.Visible = $true
            $bar.ProgressBar.Value = [Math]::Max(0, [Math]::Min(100, $Percent))
            $bar.ProgressLabel.Visible = $true
            $bar.ProgressLabel.Text = if ($ProgressText) { $ProgressText } else { "$Percent%" }
        } else {
            $bar.ProgressBar.Visible = $false
            $bar.ProgressBar.Value = 0
            $bar.ProgressLabel.Visible = $false
            $bar.ProgressLabel.Text = ''
        }
    } catch { }
}

function Update-ConnectionStatus {
    param([bool]$IsConnected, [string]$ServerName = '')
    $bar = $script:StatusBarPanels
    if ($null -eq $bar) { return }
    if ($IsConnected) {
        $bar.ConnectionStatus.Text = if ($ServerName) { "Connected to $ServerName" } else { 'Connected' }
        $bar.ConnectionStatus.Tag = 'Success'
    } else {
        $bar.ConnectionStatus.Text = 'Not connected'
        $bar.ConnectionStatus.Tag = 'Muted'
    }
    $bar.ConnectionStatus.ForeColor = Get-OctoToneColor -Tone $bar.ConnectionStatus.Tag
}

function New-EnhancedStatusBar {
    param([Parameter(Mandatory = $true)][System.Windows.Forms.Form]$Form)

    $statusStrip = New-Object System.Windows.Forms.StatusStrip
    $statusStrip.SizingGrip = $true
    $statusStrip.Font = $script:Fonts.Normal

    $statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $statusLabel.Text = 'Ready'
    $statusLabel.Spring = $true
    $statusLabel.TextAlign = 'MiddleLeft'

    $connectionLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $connectionLabel.Text = 'Not connected'
    $connectionLabel.Tag = 'Muted'

    $userLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    if ($script:IsRunningAsAdmin) {
        $userLabel.Text = 'Administrator'
        $userLabel.Tag = 'Success'
    } else {
        $userLabel.Text = 'Standard user'
        $userLabel.Tag = 'Muted'
    }

    $progressBar = New-Object System.Windows.Forms.ToolStripProgressBar
    $progressBar.Size = New-Object System.Drawing.Size(150, 16)
    $progressBar.Maximum = 100
    $progressBar.Visible = $false

    $progressLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $progressLabel.Visible = $false

    $statusStrip.Items.AddRange([System.Windows.Forms.ToolStripItem[]]@(
        $statusLabel, (New-Object System.Windows.Forms.ToolStripSeparator), $connectionLabel,
        (New-Object System.Windows.Forms.ToolStripSeparator), $userLabel,
        (New-Object System.Windows.Forms.ToolStripSeparator), $progressBar, $progressLabel))
    $Form.Controls.Add($statusStrip)

    return @{
        StatusStrip = $statusStrip; StatusLabel = $statusLabel; ConnectionStatus = $connectionLabel
        UserStatus = $userLabel; ProgressBar = $progressBar; ProgressLabel = $progressLabel
    }
}

function New-DashboardPanel {
    # A small card with a caption and one large value (placed by a TableLayoutPanel)
    param([string]$Title, [string]$Value)
    $panel = New-Object System.Windows.Forms.Panel
    $panel.Tag = 'Card'
    # Design size of one cell; the label is anchored to it before the panel is docked
    $panel.Size = New-Object System.Drawing.Size(278, 100)
    $panel.Dock = 'Fill'
    $panel.Margin = New-Object System.Windows.Forms.Padding(6, 0, 6, 0)
    $panel.Add_Paint($script:OctoBorderPainter)
    $panel.Add_Resize({ $this.Invalidate() })
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = $Title
    $lblTitle.Tag = 'Muted'
    $lblTitle.Location = New-Object System.Drawing.Point(16, 14)
    $lblTitle.AutoSize = $true
    $panel.Controls.Add($lblTitle)
    $lblValue = New-Object System.Windows.Forms.Label
    $lblValue.Text = $Value
    $lblValue.Location = New-Object System.Drawing.Point(14, 38)
    $lblValue.Size = New-Object System.Drawing.Size(250, 44)
    $lblValue.Anchor = 'Top,Left,Right'
    $lblValue.Font = $script:Fonts.StatValue
    $lblValue.AutoEllipsis = $true
    $panel.Controls.Add($lblValue)
    return @{ Panel = $panel; ValueLabel = $lblValue }
}

function Set-DashboardValue {
    param([hashtable]$Panel, [string]$Value, [string]$Tone = '')
    $Panel.ValueLabel.Text = $Value
    if ($Tone) { Set-OctoTone -Control $Panel.ValueLabel -Tone $Tone }
}

# ============================================
# VALIDATION & FORMATTING
# ============================================

function Test-IsAdministrator {
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Test-IPAddress {
    param([string]$IPAddress)
    if ([string]::IsNullOrWhiteSpace($IPAddress)) { return $false }
    if ($IPAddress -notmatch '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') { return $false }
    $parsed = $null
    return [System.Net.IPAddress]::TryParse($IPAddress, [ref]$parsed)
}

function Test-PrefixLength {
    param([string]$Prefix)
    if ("$Prefix".Trim() -notmatch '^\d{1,2}$') { return $false }
    $value = [int]"$Prefix".Trim()
    return ($value -ge 0 -and $value -le 32)
}

function Test-ServerName {
    <#
    .SYNOPSIS
        RFC 1123 host name / FQDN (or IPv4 address) check.
    #>
    param([string]$ServerName)
    if ([string]::IsNullOrWhiteSpace($ServerName)) { return $false }
    $trimmed = $ServerName.Trim()
    if ($trimmed.Length -gt 253) { return $false }
    if ($trimmed -notmatch '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$') { return $false }
    return $true
}

function Get-SafeFileName {
    param([string]$InputName, [string]$Fallback = 'output')
    if ([string]::IsNullOrWhiteSpace($InputName)) { return $Fallback }
    $safeName = $InputName
    foreach ($char in [System.IO.Path]::GetInvalidFileNameChars()) { $safeName = $safeName.Replace($char, '_') }
    $safeName = $safeName -replace '\.\.+', '_'
    $safeName = ($safeName -replace '^\.+', '').Trim()
    if ([string]::IsNullOrWhiteSpace($safeName)) { return $Fallback }
    if ($safeName.Length -gt 200) { $safeName = $safeName.Substring(0, 200) }
    return $safeName
}

function Get-SanitizedErrorMessage {
    <#
    .SYNOPSIS
        Error text without paths, IP addresses, user names or stack traces.
    #>
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    if (-not $ErrorRecord) { return 'An unknown error occurred' }
    $message = [string]$ErrorRecord.Exception.Message
    $message = $message -replace '[A-Z]:\\[^\s]+', '[PATH]'
    $message = $message -replace '/[^\s]+', '[PATH]'
    $message = $message -replace '\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP]'
    $message = $message -replace '\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b', '[IPv6]'
    $message = $message -replace 'user(name)?[:\s]+[^\s]+', 'user: [REDACTED]'
    $message = ($message -split "`n")[0]
    if ($message.Length -gt 200) { $message = $message.Substring(0, 197) + '...' }
    return $message
}

function ConvertTo-ReadableTimestamp {
    <#
    .SYNOPSIS
        Converts epoch seconds/milliseconds, DateTime or date strings to "yyyy-MM-dd HH:mm:ssZ" (UTC).
    #>
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime().ToString('u') }
    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
        $number = 0L
        if ([long]::TryParse($Value, [ref]$number)) { return ConvertTo-ReadableTimestamp -Value $number }
        try { return (Get-Date $Value).ToUniversalTime().ToString('u') } catch { return $Value }
    }
    if ($Value -is [long] -or $Value -is [int] -or $Value -is [double] -or $Value -is [decimal]) {
        $numeric = [long]$Value
        try {
            if ($numeric -gt 9999999999) { return [DateTimeOffset]::FromUnixTimeMilliseconds($numeric).UtcDateTime.ToString('u') }
            if ($numeric -gt 0) { return [DateTimeOffset]::FromUnixTimeSeconds($numeric).UtcDateTime.ToString('u') }
        } catch { }
        return $numeric.ToString()
    }
    return $Value.ToString()
}

function Invoke-Filters {
    <#
    .SYNOPSIS
        Keeps lines containing any of the filters (case-insensitive, OR logic).
    .DESCRIPTION
        Plain text is matched as a literal substring (fast). A filter containing
        a wildcard character (* ? [) keeps the previous -like wildcard behaviour.
    #>
    param([string[]]$Lines, [string[]]$Filters)
    if (-not $Filters -or $Filters.Count -eq 0) { return $Lines }
    $matched = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $Lines) {
        if ($null -eq $line) { continue }
        foreach ($pattern in $Filters) {
            if ($pattern.IndexOfAny([char[]]'*?[') -ge 0) {
                if ($line -like "*$pattern*") { $matched.Add($line); break }
            } elseif ($line.IndexOf($pattern, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $matched.Add($line); break
            }
        }
    }
    return $matched.ToArray()
}

function ConvertTo-Hashtable {
    <#
    .SYNOPSIS
        PSCustomObject (from ConvertFrom-Json) -> nested hashtables.
    #>
    param([Parameter(ValueFromPipeline = $true)]$InputObject)
    process {
        if ($null -eq $InputObject) { return $null }
        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            $collection = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $InputObject) { $collection.Add((ConvertTo-Hashtable -InputObject $item)) }
            return ,$collection.ToArray()
        }
        if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
            $hash = @{}
            foreach ($property in $InputObject.PSObject.Properties) { $hash[$property.Name] = ConvertTo-Hashtable -InputObject $property.Value }
            return $hash
        }
        return $InputObject
    }
}

# ============================================
# CSV EXPORT
# ============================================

function Export-OctoCsv {
    <#
    .SYNOPSIS
        Writes objects to CSV (UTF-8 with BOM, every field quoted - the same output
        as Export-Csv -NoTypeInformation) about twice as fast, with numbers in
        invariant format so Excel/other locales read them the same way.
    .PARAMETER Columns
        Column order; defaults to the first row's properties.
    #>
    param(
        [AllowEmptyCollection()][object[]]$Rows,
        [string[]]$Columns,
        [Parameter(Mandatory = $true)][string]$Path
    )
    if ($null -eq $Rows) { $Rows = @() }
    if (-not $Columns -or $Columns.Count -eq 0) {
        $Columns = @()
        foreach ($row in $Rows) { if ($null -ne $row) { $Columns = @($row.psobject.Properties | ForEach-Object { $_.Name }); break } }
    }
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $writer = [System.IO.StreamWriter]::new($Path, $false, [System.Text.UTF8Encoding]::new($true))
    try {
        $cells = New-Object string[] $Columns.Count
        for ($c = 0; $c -lt $Columns.Count; $c++) { $cells[$c] = '"' + $Columns[$c].Replace('"', '""') + '"' }
        $writer.WriteLine(($cells -join ','))
        foreach ($row in $Rows) {
            if ($null -eq $row) { continue }
            for ($c = 0; $c -lt $Columns.Count; $c++) {
                $v = $row.($Columns[$c])
                if ($null -eq $v) { $s = '' }
                elseif ($v -is [string]) { $s = $v }
                elseif ($v -is [System.IFormattable]) { $s = $v.ToString($null, $invariant) }
                elseif ($v -is [System.Collections.IEnumerable]) { $s = (@($v) -join '; ') }
                else { $s = [string]$v }
                $cells[$c] = '"' + $s.Replace('"', '""') + '"'
            }
            $writer.WriteLine(($cells -join ','))
        }
    } finally {
        $writer.Dispose()
    }
    return $Path
}

function Initialize-OutputDirectory {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'No output folder is set.' }
    if (-not [System.IO.Directory]::Exists($Path)) { [void][System.IO.Directory]::CreateDirectory($Path) }
    return $Path
}

function Get-OctoExportPath {
    <#
    .SYNOPSIS
        Output file path for an export: <folder>\<BaseName>[_yyyyMMdd_HHmmss].<ext>
    #>
    param([string]$Folder, [string]$BaseName, [string]$Extension = 'csv')
    [void](Initialize-OutputDirectory -Path $Folder)
    $name = $BaseName
    if ($null -eq $script:Settings -or $script:Settings.IncludeTimestampInFilename -ne $false) {
        $name += '_' + (Get-Date -Format 'yyyyMMdd_HHmmss')
    }
    return (Join-Path $Folder ($name + '.' + $Extension))
}

# ============================================
# SETTINGS
# ============================================

$script:SettingsPath = Join-Path $script:DataDir 'octonav_settings.json'
$script:DefaultSettings = @{
    Theme                      = 'Light'
    WindowSize                 = @{ Width = 1200; Height = 800 }
    WindowMaximized            = $false
    DHCPParallelServers        = 20
    DefaultExportPath          = 'C:\DNACenter_Reports'
    ExportHistory              = @()
    AutoExportAfterCollection  = $true
    IncludeTimestampInFilename = $true
    ShowDashboardOnStartup     = $true
    FavoriteFunctions          = @()
}

function Get-OctoNavSettings {
    $settings = $script:DefaultSettings.Clone()
    try {
        if (Test-Path -LiteralPath $script:SettingsPath) {
            $loaded = Get-Content -LiteralPath $script:SettingsPath -Raw | ConvertFrom-Json
            foreach ($name in $loaded.PSObject.Properties.Name) { $settings[$name] = $loaded.$name }
        }
    } catch {
        Write-Warning "Failed to load settings: $($_.Exception.Message)"
    }
    if ($settings.Theme -notin @('Light', 'Dark')) { $settings.Theme = 'Light' }
    return $settings
}

function Save-OctoNavSettings {
    param([Parameter(Mandatory = $true)][hashtable]$Settings)
    try {
        $Settings | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:SettingsPath -Encoding UTF8 -Force
        return $true
    } catch {
        Write-Warning "Failed to save settings: $($_.Exception.Message)"
        return $false
    }
}

function Add-ExportHistory {
    param([hashtable]$Settings, [string]$FilePath, [string]$Operation, [string]$Format = 'CSV')
    $entry = @{ Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); FilePath = $FilePath; Operation = $Operation; Format = $Format }
    $history = @($Settings.ExportHistory | Where-Object { $null -ne $_ })
    if ($history.Count -ge 50) { $history = @($history | Select-Object -Last 49) }
    $Settings.ExportHistory = $history + @($entry)
    [void](Save-OctoNavSettings -Settings $Settings)
}

function Get-RecentActivity {
    param([hashtable]$Settings, [int]$Count = 10)
    $history = @($Settings.ExportHistory | Where-Object { $null -ne $_ })
    if ($history.Count -eq 0) { return @('No recent activity') }
    $lines = @(foreach ($h in ($history | Select-Object -Last $Count)) { '{0} - {1} ({2})' -f $h.Timestamp, $h.Operation, $h.Format })
    [array]::Reverse($lines)
    return $lines
}

# ============================================
# THEMES
# ============================================

# Colour tokens per theme. Every control gets its colours from here, so the Light
# and Dark themes stay consistent (and View > Toggle Theme recolours everything).
$script:Themes = @{
    Light = @{
        Name = 'Light'
        WindowBack = '#F3F4F6'; HeaderBack = '#FFFFFF'; CardBack = '#FFFFFF'; CardBorder = '#DFE3E8'
        Text = '#1F2328'; TextMuted = '#5F6B76'
        Accent = '#0F6CBD'; AccentHover = '#115EA3'; AccentPressed = '#0C4A84'; AccentText = '#FFFFFF'
        NavText = '#57606A'; NavSelected = '#0F6CBD'; NavHover = '#1F2328'
        ButtonBack = '#FFFFFF'; ButtonBorder = '#C9CED4'; ButtonHover = '#F0F2F4'; ButtonPressed = '#E4E7EB'; ButtonText = '#1F2328'
        DangerBack = '#C42B1C'; DangerHover = '#A8241A'; DangerPressed = '#8E1F16'; DangerText = '#FFFFFF'
        DisabledBack = '#F3F4F6'; DisabledBorder = '#E1E4E8'; DisabledText = '#A2A9B0'
        InputBack = '#FFFFFF'; InputText = '#1F2328'; LogBack = '#F8F9FB'
        SuccessText = '#107C10'; WarningText = '#9A5B00'; ErrorText = '#C42B1C'
        SuccessBack = '#E3F4E1'; WarningBack = '#FFF4D6'; ErrorBack = '#FDE7E9'
        LogSuccessColor = '#107C10'; LogErrorColor = '#C42B1C'; LogWarningColor = '#9A5B00'; LogInfoColor = '#0F6CBD'; LogDebugColor = '#6E7781'
        TextBoxForeColor = '#1F2328'; StatusStripForeColor = '#5F6B76'
    }
    Dark = @{
        Name = 'Dark'
        WindowBack = '#1C1D20'; HeaderBack = '#25272B'; CardBack = '#2A2C30'; CardBorder = '#3B3E44'
        Text = '#E7E9EC'; TextMuted = '#9BA3AB'
        Accent = '#2373C8'; AccentHover = '#2E84DB'; AccentPressed = '#1B5EA6'; AccentText = '#FFFFFF'
        NavText = '#A9B1B9'; NavSelected = '#6CB4FF'; NavHover = '#E7E9EC'
        ButtonBack = '#34373C'; ButtonBorder = '#4A4F56'; ButtonHover = '#3E4248'; ButtonPressed = '#474B52'; ButtonText = '#E7E9EC'
        DangerBack = '#B8322A'; DangerHover = '#CC3F36'; DangerPressed = '#9E2A23'; DangerText = '#FFFFFF'
        DisabledBack = '#2F3135'; DisabledBorder = '#3B3E44'; DisabledText = '#6C737A'
        InputBack = '#1F2023'; InputText = '#E7E9EC'; LogBack = '#1F2023'
        SuccessText = '#6CCB5F'; WarningText = '#F2B84B'; ErrorText = '#FF8A80'
        SuccessBack = '#1E3A22'; WarningBack = '#3D3014'; ErrorBack = '#45201F'
        LogSuccessColor = '#6CCB5F'; LogErrorColor = '#FF8A80'; LogWarningColor = '#F2B84B'; LogInfoColor = '#6CB4FF'; LogDebugColor = '#9BA3AB'
        TextBoxForeColor = '#E7E9EC'; StatusStripForeColor = '#9BA3AB'
    }
}
foreach ($theme in $script:Themes.Values) {
    foreach ($key in @($theme.Keys)) {
        if ($key -ne 'Name') { $theme[$key] = [System.Drawing.ColorTranslator]::FromHtml($theme[$key]) }
    }
}

function Get-Theme {
    param([string]$ThemeName)
    if ($ThemeName -eq 'Dark') { return $script:Themes.Dark }
    return $script:Themes.Light
}

function Get-OctoToneColor {
    # Text colour for a tone (Success / Warning / Error / Muted / Accent; anything else = normal text)
    param([string]$Tone, [hashtable]$Theme)
    if ($null -eq $Theme) { $Theme = $script:CurrentTheme }
    switch ($Tone) {
        'Success' { return $Theme.SuccessText }
        'Warning' { return $Theme.WarningText }
        'Error' { return $Theme.ErrorText }
        'Muted' { return $Theme.TextMuted }
        'Accent' { return $Theme.NavSelected }
        'InfoSuccess' { return $Theme.SuccessText }
        'InfoWarning' { return $Theme.WarningText }
        default { return $Theme.Text }
    }
}

function Set-OctoTone {
    # Colours a label by meaning; the tone is kept in Tag so a theme change recolours it
    param($Control, [string]$Tone)
    $Control.Tag = $Tone
    $Control.ForeColor = Get-OctoToneColor -Tone $Tone
}

function Set-OctoButtonStyle {
    <#
    .SYNOPSIS
        Flat button colours by role (Tag = Primary / Danger; anything else = secondary)
        and state; runs again whenever the button is enabled or disabled.
    #>
    param($Button, [hashtable]$Theme)
    if ($null -eq $Theme) { $Theme = $script:CurrentTheme }
    if ($null -eq $Theme) { return }
    $Button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $Button.UseVisualStyleBackColor = $false
    $flat = $Button.FlatAppearance
    $flat.BorderSize = 1
    $role = [string]$Button.Tag
    if ($role -eq 'Primary' -and $script:Fonts) { $Button.Font = $script:Fonts.Semibold }
    if (-not $Button.Enabled) {
        $Button.BackColor = $Theme.DisabledBack; $Button.ForeColor = $Theme.DisabledText
        $flat.BorderColor = $Theme.DisabledBorder
        $flat.MouseOverBackColor = $Theme.DisabledBack; $flat.MouseDownBackColor = $Theme.DisabledBack
        return
    }
    switch ($role) {
        'Primary' { $colors = @($Theme.Accent, $Theme.AccentHover, $Theme.AccentPressed, $Theme.AccentText, $Theme.Accent) }
        'Danger' { $colors = @($Theme.DangerBack, $Theme.DangerHover, $Theme.DangerPressed, $Theme.DangerText, $Theme.DangerBack) }
        default { $colors = @($Theme.ButtonBack, $Theme.ButtonHover, $Theme.ButtonPressed, $Theme.ButtonText, $Theme.ButtonBorder) }
    }
    $Button.BackColor = $colors[0]
    $flat.MouseOverBackColor = $colors[1]
    $flat.MouseDownBackColor = $colors[2]
    $Button.ForeColor = $colors[3]
    $flat.BorderColor = $colors[4]
}

# Thin border for cards and log frames (drawn on Paint: WinForms panels have no border colour)
$script:OctoBorderPainter = {
    param($control, $e)
    $color = if ($script:CurrentTheme) { $script:CurrentTheme.CardBorder } else { [System.Drawing.Color]::LightGray }
    $pen = New-Object System.Drawing.Pen($color)
    try { $e.Graphics.DrawRectangle($pen, 0, 0, $control.Width - 1, $control.Height - 1) } finally { $pen.Dispose() }
}
# Line under the navigation bar
$script:OctoBottomLinePainter = {
    param($control, $e)
    $color = if ($script:CurrentTheme) { $script:CurrentTheme.CardBorder } else { [System.Drawing.Color]::LightGray }
    $pen = New-Object System.Drawing.Pen($color)
    try { $e.Graphics.DrawLine($pen, 0, $control.Height - 1, $control.Width, $control.Height - 1) } finally { $pen.Dispose() }
}

function Convert-OctoLogColors {
    <#
    .SYNOPSIS
        Recolours the lines already in a log for another theme (swaps the entries of
        the RTF colour table, so it is fast for long logs too).
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox, [hashtable]$From, [hashtable]$To)
    if ($null -eq $LogBox -or $LogBox.TextLength -eq 0 -or $null -eq $From -or $From.Name -eq $To.Name) { return }
    $rtf = $LogBox.Rtf
    foreach ($key in 'LogSuccessColor', 'LogErrorColor', 'LogWarningColor', 'LogInfoColor', 'LogDebugColor', 'Text') {
        $old = $From[$key]; $new = $To[$key]
        $rtf = $rtf.Replace(('\red{0}\green{1}\blue{2};' -f $old.R, $old.G, $old.B), ('\red{0}\green{1}\blue{2};' -f $new.R, $new.G, $new.B))
    }
    $LogBox.Rtf = $rtf
    $LogBox.SelectionStart = $LogBox.TextLength
    $LogBox.ScrollToCaret()
}

function Set-ThemeToControl {
    <#
    .SYNOPSIS
        Applies a theme to a control and all of its children (iterative walk).
    .DESCRIPTION
        Panels and labels are coloured by their Tag: Card, Header, LogFrame, Page,
        NavIndicator, InfoSuccess / InfoWarning (panels); Muted, Success, Warning,
        Error, NavItem (labels). Buttons by role, see Set-OctoButtonStyle.
    #>
    param(
        [Parameter(Mandatory = $true)][System.Windows.Forms.Control]$Control,
        [Parameter(Mandatory = $true)][hashtable]$Theme
    )
    $stack = [System.Collections.Generic.Stack[object]]::new()
    $stack.Push($Control)
    while ($stack.Count -gt 0) {
        $c = $stack.Pop()
        $tag = [string]$c.Tag
        try {
            switch ($c.GetType().Name) {
                'Form' { $c.BackColor = $Theme.WindowBack; $c.ForeColor = $Theme.Text }
                'Panel' {
                    switch ($tag) {
                        'Card' { $c.BackColor = $Theme.CardBack }
                        'Header' { $c.BackColor = $Theme.HeaderBack }
                        'LogFrame' { $c.BackColor = $Theme.LogBack }
                        'NavIndicator' { $c.BackColor = $Theme.Accent }
                        'InfoSuccess' { $c.BackColor = $Theme.SuccessBack }
                        'InfoWarning' { $c.BackColor = $Theme.WarningBack }
                        default { $c.BackColor = $Theme.WindowBack }
                    }
                    $c.ForeColor = $Theme.Text
                    $c.Invalidate()
                }
                'TableLayoutPanel' { $c.BackColor = $Theme.WindowBack; $c.ForeColor = $Theme.Text }
                'Label' {
                    if ($tag -eq 'NavItem') { $c.ForeColor = $Theme.NavText } else { $c.ForeColor = Get-OctoToneColor -Tone $tag -Theme $Theme }
                }
                'Button' { Set-OctoButtonStyle -Button $c -Theme $Theme }
                { $_ -in 'CheckBox', 'RadioButton' } { $c.ForeColor = $Theme.Text }
                { $_ -in 'TextBox', 'NumericUpDown', 'ComboBox', 'ListBox', 'CheckedListBox' } {
                    # Inside a frame (the template editor) the box takes the frame colour
                    $c.BackColor = if ($c.Parent -and [string]$c.Parent.Tag -eq 'LogFrame') { $Theme.LogBack } else { $Theme.InputBack }
                    $c.ForeColor = $Theme.InputText
                    # A standard drop-down list is drawn like a button and ignores the colours
                    if ($_ -eq 'ComboBox') { $c.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat }
                }
                'RichTextBox' { $c.BackColor = if ($tag -eq 'Card') { $Theme.CardBack } else { $Theme.LogBack }; $c.ForeColor = $Theme.Text }
                'TreeView' { $c.BackColor = $Theme.InputBack; $c.ForeColor = $Theme.InputText; $c.LineColor = $Theme.TextMuted }
                { $_ -in 'MenuStrip', 'StatusStrip' } {
                    $c.BackColor = $Theme.HeaderBack
                    $c.ForeColor = if ($_ -eq 'StatusStrip') { $Theme.TextMuted } else { $Theme.Text }
                    foreach ($item in $c.Items) { if ($item.Tag) { $item.ForeColor = Get-OctoToneColor -Tone ([string]$item.Tag) -Theme $Theme } }
                }
                default { $c.ForeColor = $Theme.Text }
            }
        } catch { }
        foreach ($child in $c.Controls) { $stack.Push($child) }
    }
}

# ============================================
# SECURITY (audit log, optional startup password)
# ============================================

Add-Type -AssemblyName System.Security

# Team deployment setting: $false = no startup password (DHCP cache encryption still applies)
$script:RequireStartupPassword = $false
$script:SecurityConfigFile = Join-Path $script:DataDir 'config\security.dat'
$script:AuditLogFile = Join-Path $script:DataDir 'logs\security_audit.log'
$script:MaxFailedAttempts = 3
$script:LockoutDurationMinutes = 15
$script:SessionTimeoutMinutes = 30
$script:PasswordMinLength = 12
$script:LastActivityTime = Get-Date

function Write-SecurityAudit {
    param(
        [ValidateSet('Success', 'Failure', 'Warning', 'Info', 'Critical')][string]$Level,
        [string]$Event,
        [string]$Details = '',
        [string]$User = $env:USERNAME
    )
    try {
        $entry = '[{0}] [{1}] [{2}] {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $User, $Event
        if ($Details) { $entry += " | Details: $Details" }
        $dir = Split-Path $script:AuditLogFile -Parent
        if (-not [System.IO.Directory]::Exists($dir)) { [void][System.IO.Directory]::CreateDirectory($dir) }
        [System.IO.File]::AppendAllText($script:AuditLogFile, $entry + [Environment]::NewLine)
        if ($Level -eq 'Critical') {
            Write-EventLog -LogName Application -Source 'OctoNav' -EventId 1001 -EntryType Error -Message $entry -ErrorAction SilentlyContinue
        }
    } catch {
        # Auditing must never stop the tool (e.g. read-only folder)
    }
}

function Test-PasswordComplexity {
    param([Parameter(Mandatory = $true)][string]$Password)
    $failed = @()
    if ($Password.Length -lt $script:PasswordMinLength) { $failed += "At least $script:PasswordMinLength characters" }
    if ($Password -cnotmatch '[A-Z]') { $failed += 'At least one uppercase letter' }
    if ($Password -cnotmatch '[a-z]') { $failed += 'At least one lowercase letter' }
    if ($Password -notmatch '[0-9]') { $failed += 'At least one number' }
    if ($Password -notmatch '[^a-zA-Z0-9]') { $failed += 'At least one special character (!@#$%^&*)' }
    return [PSCustomObject]@{ IsValid = ($failed.Count -eq 0); FailedRequirements = $failed }
}

function Protect-WithDPAPI {
    param([Parameter(Mandatory = $true)][string]$PlainText)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [Convert]::ToBase64String($encrypted)
}

function Unprotect-WithDPAPI {
    param([Parameter(Mandatory = $true)][string]$EncryptedText)
    $encrypted = [Convert]::FromBase64String($EncryptedText)
    $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [System.Text.Encoding]::UTF8.GetString($decrypted)
}

function Get-SecurityConfig {
    if (-not (Test-Path -LiteralPath $script:SecurityConfigFile)) { return $null }
    try {
        return (Unprotect-WithDPAPI -EncryptedText (Get-Content -LiteralPath $script:SecurityConfigFile -Raw)) | ConvertFrom-Json
    } catch {
        Write-SecurityAudit -Level Warning -Event 'Failed to load security config' -Details $_.Exception.Message
        return $null
    }
}

function Save-SecurityConfig {
    param([Parameter(Mandatory = $true)][hashtable]$Config)
    $dir = Split-Path $script:SecurityConfigFile -Parent
    if (-not [System.IO.Directory]::Exists($dir)) { [void][System.IO.Directory]::CreateDirectory($dir) }
    Protect-WithDPAPI -PlainText ($Config | ConvertTo-Json -Depth 3) | Set-Content -LiteralPath $script:SecurityConfigFile -Force
    Write-SecurityAudit -Level Info -Event 'Security config saved'
}

function Get-PasswordHash {
    param([Parameter(Mandatory = $true)][string]$Password)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Password))) }
    finally { $sha256.Dispose() }
}

function ConvertFrom-SecureStringPlain {
    param([System.Security.SecureString]$SecureString)
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try { return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

function Test-IsAccountLocked {
    $config = Get-SecurityConfig
    if (-not $config -or -not $config.LockoutUntil) { return $false }
    $lockoutTime = [DateTime]::Parse($config.LockoutUntil)
    $isLocked = (Get-Date) -lt $lockoutTime
    if ($isLocked) {
        $remaining = [math]::Ceiling(($lockoutTime - (Get-Date)).TotalMinutes)
        Write-SecurityAudit -Level Warning -Event 'Access denied - Account locked' -Details "Remaining: $remaining minutes"
    }
    return $isLocked
}

function Register-FailedLoginAttempt {
    $config = Get-SecurityConfig
    $state = @{ FailedAttempts = 0; LastFailedAttempt = $null; LockoutUntil = $null; PasswordHash = $null }
    if ($config) {
        $state.FailedAttempts = if ($config.FailedAttempts) { [int]$config.FailedAttempts } else { 0 }
        $state.LastFailedAttempt = $config.LastFailedAttempt
        $state.LockoutUntil = $config.LockoutUntil
        $state.PasswordHash = $config.PasswordHash
    }
    $state.FailedAttempts++
    $state.LastFailedAttempt = (Get-Date).ToString('o')
    Write-SecurityAudit -Level Failure -Event 'Login failed' -Details "Attempt $($state.FailedAttempts) of $script:MaxFailedAttempts"
    if ($state.FailedAttempts -ge $script:MaxFailedAttempts) {
        $lockoutUntil = (Get-Date).AddMinutes($script:LockoutDurationMinutes)
        $state.LockoutUntil = $lockoutUntil.ToString('o')
        Write-SecurityAudit -Level Critical -Event 'Account locked' -Details "Locked until $lockoutUntil due to $($state.FailedAttempts) failed attempts"
    }
    Save-SecurityConfig -Config $state
}

function Clear-FailedLoginAttempts {
    $config = Get-SecurityConfig
    if ($config) {
        Save-SecurityConfig -Config @{ FailedAttempts = 0; LastFailedAttempt = $null; LockoutUntil = $null; PasswordHash = $config.PasswordHash }
    }
}

function Test-StartupPasswordExists {
    $config = Get-SecurityConfig
    return ($null -ne $config -and $null -ne $config.PasswordHash)
}

function Set-StartupPassword {
    param([Parameter(Mandatory = $true)][System.Security.SecureString]$Password)
    $plain = ConvertFrom-SecureStringPlain -SecureString $Password
    $validation = Test-PasswordComplexity -Password $plain
    if (-not $validation.IsValid) {
        throw "Password does not meet complexity requirements:`n- " + ($validation.FailedRequirements -join "`n- ")
    }
    $config = Get-SecurityConfig
    $state = @{ FailedAttempts = 0; LastFailedAttempt = $null; LockoutUntil = $null }
    if ($config) {
        $state.FailedAttempts = $config.FailedAttempts
        $state.LastFailedAttempt = $config.LastFailedAttempt
        $state.LockoutUntil = $config.LockoutUntil
    }
    $state.PasswordHash = Get-PasswordHash -Password $plain
    $state.PasswordSetDate = (Get-Date).ToString('o')
    Save-SecurityConfig -Config $state
    Write-SecurityAudit -Level Success -Event 'Startup password set/changed'
}

function Test-StartupPassword {
    param([Parameter(Mandatory = $true)][System.Security.SecureString]$Password)
    if (Test-IsAccountLocked) { return $false }
    $config = Get-SecurityConfig
    if (-not $config -or -not $config.PasswordHash) { return $false }
    if ((Get-PasswordHash -Password (ConvertFrom-SecureStringPlain -SecureString $Password)) -eq $config.PasswordHash) {
        Clear-FailedLoginAttempts
        Write-SecurityAudit -Level Success -Event 'Login successful'
        return $true
    }
    Register-FailedLoginAttempt
    return $false
}

function Update-SessionActivity { $script:LastActivityTime = Get-Date }

function Start-SessionMonitor {
    param([Parameter(Mandatory = $true)][System.Windows.Forms.Form]$Form)
    # Any keyboard or mouse input in the window counts as activity
    $Form.KeyPreview = $true
    $Form.Add_KeyDown({ Update-SessionActivity })
    $Form.Add_MouseMove({ Update-SessionActivity })
    $script:SessionTimer = New-Object System.Windows.Forms.Timer
    $script:SessionTimer.Interval = 60000
    $script:SessionTimer.Tag = $Form
    $script:SessionTimer.Add_Tick({
        $idle = ((Get-Date) - $script:LastActivityTime).TotalMinutes
        if ($idle -ge $script:SessionTimeoutMinutes) {
            Write-SecurityAudit -Level Warning -Event 'Auto-lock triggered' -Details "Session timeout after $script:SessionTimeoutMinutes minutes"
            [System.Windows.Forms.MessageBox]::Show("Session expired due to inactivity.`n`nOctoNav will now close for security.", 'Session Timeout', 'OK', 'Warning') | Out-Null
            $this.Tag.Close()
        }
    })
    $script:SessionTimer.Start()
    Update-SessionActivity
}

function Set-OctoDialogStyle {
    # Fonts and colours of the main window for a dialog (when the theme is loaded)
    param($Form)
    $Form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    if ($script:CurrentTheme) { Set-ThemeToControl -Control $Form -Theme $script:CurrentTheme }
}

function Show-StartupPasswordDialog {
    param([switch]$IsFirstRun)

    $form = New-Object System.Windows.Forms.Form
    $form.Text = if ($IsFirstRun) { 'Set OctoNav Startup Password' } else { 'OctoNav Authentication' }
    $form.Size = New-Object System.Drawing.Size(500, 400)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    $y = 20

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = if ($IsFirstRun) { 'Welcome to OctoNav' } else { 'Please authenticate to continue' }
    $lblTitle.Location = New-Object System.Drawing.Point(20, $y)
    $lblTitle.Size = New-Object System.Drawing.Size(450, 25)
    $lblTitle.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 13)
    $lblTitle.Tag = 'Accent'
    $form.Controls.Add($lblTitle)
    $y += 35

    if ($IsFirstRun) {
        $lblInstructions = New-Object System.Windows.Forms.Label
        $lblInstructions.Text = "Please create a strong startup password.`n`nPassword Requirements:`n- Minimum $script:PasswordMinLength characters`n- At least one uppercase letter (A-Z)`n- At least one lowercase letter (a-z)`n- At least one number (0-9)`n- At least one special character (!@#$%^&*)`n`nWARNING: If you forget this password, you will be locked out!"
        $lblInstructions.Location = New-Object System.Drawing.Point(20, $y)
        $lblInstructions.Size = New-Object System.Drawing.Size(450, 185)
        $form.Controls.Add($lblInstructions)
        $y += 195

        $lblPassword = New-Object System.Windows.Forms.Label
        $lblPassword.Text = 'Enter Password:'
        $lblPassword.Location = New-Object System.Drawing.Point(20, $y)
        $lblPassword.Size = New-Object System.Drawing.Size(450, 20)
        $form.Controls.Add($lblPassword)
        $y += 25
        $txtPassword = New-Object System.Windows.Forms.TextBox
        $txtPassword.Location = New-Object System.Drawing.Point(20, $y)
        $txtPassword.Size = New-Object System.Drawing.Size(450, 25)
        $txtPassword.UseSystemPasswordChar = $true
        $form.Controls.Add($txtPassword)
        $y += 35
        $lblConfirm = New-Object System.Windows.Forms.Label
        $lblConfirm.Text = 'Confirm Password:'
        $lblConfirm.Location = New-Object System.Drawing.Point(20, $y)
        $lblConfirm.Size = New-Object System.Drawing.Size(450, 20)
        $form.Controls.Add($lblConfirm)
        $y += 25
        $txtConfirm = New-Object System.Windows.Forms.TextBox
        $txtConfirm.Location = New-Object System.Drawing.Point(20, $y)
        $txtConfirm.Size = New-Object System.Drawing.Size(450, 25)
        $txtConfirm.UseSystemPasswordChar = $true
        $form.Controls.Add($txtConfirm)
        $y += 45

        $btnSetPassword = New-Object System.Windows.Forms.Button
        $btnSetPassword.Text = 'Set Password'
        $btnSetPassword.Location = New-Object System.Drawing.Point(180, $y)
        $btnSetPassword.Size = New-Object System.Drawing.Size(140, 35)
        $btnSetPassword.Tag = 'Primary'
        $form.Controls.Add($btnSetPassword)
        $form.AcceptButton = $btnSetPassword
        $btnSetPassword.Add_Click({
            if ([string]::IsNullOrWhiteSpace($txtPassword.Text)) {
                [System.Windows.Forms.MessageBox]::Show('Please enter a password', 'Validation Error', 'OK', 'Warning') | Out-Null
                return
            }
            if ($txtPassword.Text -ne $txtConfirm.Text) {
                [System.Windows.Forms.MessageBox]::Show('Passwords do not match!', 'Validation Error', 'OK', 'Warning') | Out-Null
                $txtPassword.Clear(); $txtConfirm.Clear(); $txtPassword.Focus()
                return
            }
            try {
                Set-StartupPassword -Password (ConvertTo-SecureString -String $txtPassword.Text -AsPlainText -Force)
                [System.Windows.Forms.MessageBox]::Show("Password set successfully!`n`nOctoNav will now start.", 'Success', 'OK', 'Information') | Out-Null
                $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $form.Close()
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to set password:`n`n$($_.Exception.Message)", 'Error', 'OK', 'Error') | Out-Null
                $txtPassword.Clear(); $txtConfirm.Clear(); $txtPassword.Focus()
            }
        })
    } elseif (Test-IsAccountLocked) {
        $config = Get-SecurityConfig
        $remaining = [math]::Ceiling(([DateTime]::Parse($config.LockoutUntil) - (Get-Date)).TotalMinutes)
        $lblLocked = New-Object System.Windows.Forms.Label
        $lblLocked.Text = "ACCOUNT LOCKED`n`nToo many failed login attempts.`n`nRemaining lockout time: $remaining minutes`n`nPlease try again later."
        $lblLocked.Location = New-Object System.Drawing.Point(20, $y)
        $lblLocked.Size = New-Object System.Drawing.Size(450, 150)
        $lblLocked.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 10)
        $lblLocked.Tag = 'Error'
        $form.Controls.Add($lblLocked)
        $y += 160
        $btnClose = New-Object System.Windows.Forms.Button
        $btnClose.Text = 'Close'
        $btnClose.Location = New-Object System.Drawing.Point(200, $y)
        $btnClose.Size = New-Object System.Drawing.Size(100, 35)
        $btnClose.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Controls.Add($btnClose)
    } else {
        $lblPassword = New-Object System.Windows.Forms.Label
        $lblPassword.Text = 'Enter your password to access OctoNav:'
        $lblPassword.Location = New-Object System.Drawing.Point(20, $y)
        $lblPassword.Size = New-Object System.Drawing.Size(450, 20)
        $form.Controls.Add($lblPassword)
        $y += 30
        $txtPassword = New-Object System.Windows.Forms.TextBox
        $txtPassword.Location = New-Object System.Drawing.Point(20, $y)
        $txtPassword.Size = New-Object System.Drawing.Size(450, 25)
        $txtPassword.UseSystemPasswordChar = $true
        $form.Controls.Add($txtPassword)
        $y += 40
        $lblStatus = New-Object System.Windows.Forms.Label
        $lblStatus.Location = New-Object System.Drawing.Point(20, $y)
        $lblStatus.Size = New-Object System.Drawing.Size(450, 20)
        $lblStatus.Tag = 'Error'
        $form.Controls.Add($lblStatus)
        $y += 30
        $btnLogin = New-Object System.Windows.Forms.Button
        $btnLogin.Text = 'Login'
        $btnLogin.Location = New-Object System.Drawing.Point(150, $y)
        $btnLogin.Size = New-Object System.Drawing.Size(100, 35)
        $btnLogin.Tag = 'Primary'
        $form.Controls.Add($btnLogin)
        $form.AcceptButton = $btnLogin
        $btnExit = New-Object System.Windows.Forms.Button
        $btnExit.Text = 'Exit'
        $btnExit.Location = New-Object System.Drawing.Point(260, $y)
        $btnExit.Size = New-Object System.Drawing.Size(100, 35)
        $btnExit.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Controls.Add($btnExit)
        $form.CancelButton = $btnExit
        $btnLogin.Add_Click({
            if ([string]::IsNullOrWhiteSpace($txtPassword.Text)) { $lblStatus.Text = 'Please enter your password'; return }
            if (Test-StartupPassword -Password (ConvertTo-SecureString -String $txtPassword.Text -AsPlainText -Force)) {
                $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $form.Close()
                return
            }
            $config = Get-SecurityConfig
            $remaining = $script:MaxFailedAttempts - [int]$config.FailedAttempts
            if ($remaining -le 0) {
                [System.Windows.Forms.MessageBox]::Show("Too many failed attempts!`n`nAccount locked for $script:LockoutDurationMinutes minutes.", 'Account Locked', 'OK', 'Error') | Out-Null
                $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
                $form.Close()
            } else {
                $lblStatus.Text = "Incorrect password! Attempts remaining: $remaining"
                $txtPassword.Clear(); $txtPassword.Focus()
            }
        })
    }

    # $y is the top of the button row: fit the window to it
    $form.ClientSize = New-Object System.Drawing.Size(490, ($y + 55))
    Set-OctoDialogStyle -Form $form
    $result = $form.ShowDialog()
    $form.Dispose()
    return ($result -eq [System.Windows.Forms.DialogResult]::OK)
}

# ============================================
# DHCP CACHE (encrypted; format unchanged so existing .dat files still open)
# ============================================

$script:DHCPCachePassword = $null
$script:DHCPCachePasswordTimestamp = $null
$script:DHCPCachePasswordTimeout = 300
$script:DHCPCachePasswordVerified = $false

function Protect-DHCPCache {
    <#
    .SYNOPSIS
        AES-256-CBC + HMAC-SHA256 (PBKDF2, 10,000 iterations, random salt).
        Layout: salt(16) + hmac(32) + ciphertext, Base64.
    #>
    param([string]$PlainText, [System.Security.SecureString]$Password)
    $passwordPlain = ConvertFrom-SecureStringPlain -SecureString $Password
    $salt = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($salt) } finally { $rng.Dispose() }
    $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($passwordPlain, $salt, 10000)
    $encryptionKey = $pbkdf2.GetBytes(32)
    $iv = $pbkdf2.GetBytes(16)
    $hmacKey = $pbkdf2.GetBytes(32)
    $pbkdf2.Dispose()

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $encryptionKey; $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $encryptor = $aes.CreateEncryptor()
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
    $encryptor.Dispose(); $aes.Dispose()

    $hmac = New-Object System.Security.Cryptography.HMACSHA256 (, $hmacKey)
    $signed = New-Object byte[] ($salt.Length + $encryptedBytes.Length)
    [Array]::Copy($salt, 0, $signed, 0, $salt.Length)
    [Array]::Copy($encryptedBytes, 0, $signed, $salt.Length, $encryptedBytes.Length)
    $hash = $hmac.ComputeHash($signed)
    $hmac.Dispose()

    $result = New-Object byte[] ($salt.Length + $hash.Length + $encryptedBytes.Length)
    [Array]::Copy($salt, 0, $result, 0, 16)
    [Array]::Copy($hash, 0, $result, 16, 32)
    [Array]::Copy($encryptedBytes, 0, $result, 48, $encryptedBytes.Length)
    return [Convert]::ToBase64String($result)
}

function Unprotect-DHCPCache {
    <#
    .SYNOPSIS
        Verifies the HMAC, then decrypts (also reads the older salt+ciphertext format).
    #>
    param([string]$EncryptedText, [System.Security.SecureString]$Password)
    try {
        $passwordPlain = ConvertFrom-SecureStringPlain -SecureString $Password
        $data = [Convert]::FromBase64String($EncryptedText.Trim())
        $salt = New-Object byte[] 16
        [Array]::Copy($data, 0, $salt, 0, 16)
        $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($passwordPlain, $salt, 10000)
        $key = $pbkdf2.GetBytes(32)
        $iv = $pbkdf2.GetBytes(16)

        if ($data.Length -gt 48) {
            $hmacKey = $pbkdf2.GetBytes(32)
            $storedHmac = New-Object byte[] 32
            [Array]::Copy($data, 16, $storedHmac, 0, 32)
            $cipher = New-Object byte[] ($data.Length - 48)
            [Array]::Copy($data, 48, $cipher, 0, $cipher.Length)
            $hmac = New-Object System.Security.Cryptography.HMACSHA256 (, $hmacKey)
            $toVerify = New-Object byte[] (16 + $cipher.Length)
            [Array]::Copy($salt, 0, $toVerify, 0, 16)
            [Array]::Copy($cipher, 0, $toVerify, 16, $cipher.Length)
            $computed = $hmac.ComputeHash($toVerify)
            $hmac.Dispose()
            $diff = 0
            for ($i = 0; $i -lt 32; $i++) { $diff = $diff -bor ($storedHmac[$i] -bxor $computed[$i]) }
            if ($diff -ne 0) { throw 'INTEGRITY CHECK FAILED - Data has been tampered with or password is incorrect!' }
        } else {
            $cipher = New-Object byte[] ($data.Length - 16)
            [Array]::Copy($data, 16, $cipher, 0, $cipher.Length)
            Write-Warning 'Old cache format detected (no HMAC). Refresh the cache to upgrade it.'
        }
        $pbkdf2.Dispose()

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key; $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $decryptor = $aes.CreateDecryptor()
        $plain = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)
        $decryptor.Dispose(); $aes.Dispose()
        return [System.Text.Encoding]::UTF8.GetString($plain)
    } catch {
        throw "Decryption failed - Invalid password or corrupted data: $($_.Exception.Message)"
    }
}

function Get-DHCPCachePassword {
    <#
    .SYNOPSIS
        Password dialog for the encrypted DHCP caches.
    .PARAMETER Action
        Load, Save or Confirm (type a new password again) - changes the wording only.
    .PARAMETER Hint
        Which cache the password is for, e.g. "DHCP scopes cache".
    #>
    param([ValidateSet('Save', 'Load', 'Confirm')][string]$Action = 'Load', [string]$Hint = '')
    $what = if ($Hint) { "the $Hint" } else { 'the DHCP cache' }
    $prompt = switch ($Action) {
        'Load' { "Enter the password for $($what):" }
        'Save' { "Password to encrypt $what`n(use the same password as your other DHCP cache):" }
        'Confirm' { 'Type the new DHCP cache password again to confirm it:' }
    }
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'DHCP Cache Password'
    $form.Size = New-Object System.Drawing.Size(420, 210)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $prompt
    $label.Location = New-Object System.Drawing.Point(20, 15)
    $label.Size = New-Object System.Drawing.Size(370, 40)
    $form.Controls.Add($label)
    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(20, 60)
    $textBox.Size = New-Object System.Drawing.Size(370, 25)
    $textBox.UseSystemPasswordChar = $true
    $form.Controls.Add($textBox)
    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Text = 'OK'
    $btnOK.Tag = 'Primary'
    $btnOK.Location = New-Object System.Drawing.Point(214, 105)
    $btnOK.Size = New-Object System.Drawing.Size(84, 32)
    $btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($btnOK)
    $form.AcceptButton = $btnOK
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Cancel'
    $btnCancel.Location = New-Object System.Drawing.Point(306, 105)
    $btnCancel.Size = New-Object System.Drawing.Size(84, 32)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($btnCancel)
    $form.CancelButton = $btnCancel
    Set-OctoDialogStyle -Form $form
    $password = $null
    if ($form.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK -and -not [string]::IsNullOrWhiteSpace($textBox.Text)) {
        $password = ConvertTo-SecureString -String $textBox.Text -AsPlainText -Force
    }
    $textBox.Clear()
    $form.Dispose()
    return $password
}

function Get-SessionCachedPassword {
    <#
    .SYNOPSIS
        Password for the DHCP caches; asked once and remembered for 5 minutes.
        $script:DHCPCachePasswordVerified says whether it has opened or created a
        cache yet (a freshly typed password may be a typo).
    #>
    param([ValidateSet('Save', 'Load')][string]$Action = 'Load', [string]$Hint = '')
    if ($script:DHCPCachePassword -and $script:DHCPCachePasswordTimestamp -and
        ((Get-Date) - $script:DHCPCachePasswordTimestamp).TotalSeconds -lt $script:DHCPCachePasswordTimeout) {
        return $script:DHCPCachePassword
    }
    Clear-SessionCachedPassword
    $password = Get-DHCPCachePassword -Action $Action -Hint $Hint
    if ($password) {
        $script:DHCPCachePassword = $password
        $script:DHCPCachePasswordTimestamp = Get-Date
    }
    return $password
}

function Set-SessionCachedPassword {
    # Remembers a password that is known to be right (it opened or created a cache)
    param([System.Security.SecureString]$Password)
    $script:DHCPCachePassword = $Password
    $script:DHCPCachePasswordTimestamp = Get-Date
    $script:DHCPCachePasswordVerified = $true
}

function Clear-SessionCachedPassword {
    $script:DHCPCachePassword = $null
    $script:DHCPCachePasswordTimestamp = $null
    $script:DHCPCachePasswordVerified = $false
}

function Test-SecureStringEqual {
    param([System.Security.SecureString]$First, [System.Security.SecureString]$Second)
    $a = ConvertFrom-SecureStringPlain -SecureString $First
    $b = ConvertFrom-SecureStringPlain -SecureString $Second
    try { return [string]::Equals($a, $b, [System.StringComparison]::Ordinal) }
    finally { $a = $null; $b = $null }
}

function Test-DhcpCachePassword {
    <#
    .SYNOPSIS
        $true = the password opens an existing cache file, $false = cache files exist
        but it opens none of them, $null = there are no cache files yet.
    #>
    param([System.Security.SecureString]$Password)
    $found = $false
    foreach ($name in @('dhcp_servers_cache.dat', 'dhcp_scopes_cache.dat')) {
        $file = Join-Path $script:DataDir $name
        if (-not (Test-Path -LiteralPath $file)) { continue }
        $found = $true
        try {
            $null = Unprotect-DHCPCache -EncryptedText (Get-Content -LiteralPath $file -Raw) -Password $Password
            return $true
        } catch { }
    }
    if ($found) { return $false }
    return $null
}

function Get-DhcpCacheSavePassword {
    <#
    .SYNOPSIS
        Password for saving a cache, checked so the two caches keep one password:
        a newly typed password must open the existing cache files (catches typos and
        a second password); with no cache files yet it is typed twice.
    #>
    param([string]$Hint = '')
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $password = Get-SessionCachedPassword -Action 'Save' -Hint $Hint
        if (-not $password) { return $null }
        if ($script:DHCPCachePasswordVerified) { return $password }
        $check = Test-DhcpCachePassword -Password $password
        if ($check -eq $true) { Set-SessionCachedPassword -Password $password; return $password }
        if ($check -eq $false) {
            $answer = Show-OctoMessage -Title 'DHCP Cache Password' -Icon Warning -Buttons YesNoCancel -Text (
                "This password does not open your existing DHCP cache files.`n`n" +
                "Yes = type your existing password again`n" +
                "No = use this new password (a cache saved with the old password keeps it until that cache is refreshed)`n" +
                "Cancel = do not save")
            if ("$answer" -eq 'Yes') { Clear-SessionCachedPassword; continue }
            if ("$answer" -ne 'No') { Clear-SessionCachedPassword; return $null }
        }
        # A new password: type it twice so a typo cannot lock the cache
        $confirm = Get-DHCPCachePassword -Action 'Confirm'
        if ($confirm -and (Test-SecureStringEqual -First $password -Second $confirm)) {
            Set-SessionCachedPassword -Password $password
            return $password
        }
        Clear-SessionCachedPassword
        if (-not $confirm) { return $null }
        Show-OctoMessage -Text 'The two passwords do not match. Please try again.' -Title 'DHCP Cache Password' -Icon Warning | Out-Null
    }
    return $null
}

function Write-DhcpCacheFile {
    # Encrypts to a temporary file first, so a failure never damages the existing cache
    param([string]$File, [string]$PlainText, [System.Security.SecureString]$Password)
    $temp = $File + '.tmp'
    Protect-DHCPCache -PlainText $PlainText -Password $Password | Set-Content -LiteralPath $temp -Force
    [System.IO.File]::Copy($temp, $File, $true)
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
}

function Read-DhcpCache {
    <#
    .SYNOPSIS
        Loads the servers or scopes cache: @{ Items; LastUpdated } (Items empty if none).
        Offers to encrypt a legacy unencrypted .json cache, as before.
    .DESCRIPTION
        A cache that does not open with the session password can be retried with
        another password; when the two caches turn out to use different passwords,
        this one can be re-saved with the first password so one opens both.
    #>
    param([ValidateSet('Servers', 'Scopes')][string]$Kind)
    $base = if ($Kind -eq 'Servers') { 'dhcp_servers_cache' } else { 'dhcp_scopes_cache' }
    $datFile = Join-Path $script:DataDir "$base.dat"
    $jsonFile = Join-Path $script:DataDir "$base.json"
    $label = "DHCP $($Kind.ToLower()) cache"
    $empty = @{ Items = @(); LastUpdated = $null }

    if ((Test-Path -LiteralPath $jsonFile) -and -not (Test-Path -LiteralPath $datFile)) {
        try { $jsonContent = Get-Content -LiteralPath $jsonFile -Raw; $cache = $jsonContent | ConvertFrom-Json }
        catch { return $empty }
        $answer = Show-OctoMessage -Title 'Encrypt Unencrypted Cache?' -Icon Warning -Buttons YesNo -Text (
            "SECURITY WARNING: Unencrypted DHCP cache file detected!`n`nFile: $base.json`n`nThis file contains network information and is NOT encrypted.`n`n" +
            "Encrypt it now? (Recommended)`n`nThe unencrypted file is deleted after successful encryption.")
        if ("$answer" -eq 'Yes') {
            $password = Get-DhcpCacheSavePassword -Hint $label
            if ($password) {
                try {
                    Write-DhcpCacheFile -File $datFile -PlainText $jsonContent -Password $password
                    Remove-Item -LiteralPath $jsonFile -Force
                    Show-OctoMessage -Text "Cache encrypted successfully.`n`nYou will need this password to load the cache in the future." -Title 'Encryption Complete' | Out-Null
                } catch {
                    Show-OctoMessage -Text "Failed to encrypt cache file:`n`n$($_.Exception.Message)" -Title 'Encryption Failed' -Icon Error | Out-Null
                }
            }
        }
        return @{ Items = @($cache.$Kind); LastUpdated = $cache.LastUpdated }
    }

    if (-not (Test-Path -LiteralPath $datFile)) { return $empty }
    try { $encrypted = Get-Content -LiteralPath $datFile -Raw }
    catch {
        Show-OctoMessage -Text "The $label file could not be read:`n$($_.Exception.Message)" -Title 'DHCP Cache' -Icon Warning | Out-Null
        return $empty
    }
    $session = Get-SessionCachedPassword -Action 'Load' -Hint $label
    if (-not $session) { return $empty }
    $password = $session
    $plain = $null
    $attempt = 0
    while ($true) {
        $attempt++
        try { $plain = Unprotect-DHCPCache -EncryptedText $encrypted -Password $password; break } catch { }
        if ($attempt -ge 3) {
            Show-OctoMessage -Title 'DHCP Cache Password' -Icon Warning -Text "The $label could not be opened after $attempt tries and is skipped for now.`n`nClick 'Refresh Cache' to rebuild it - it is then saved with your current password." | Out-Null
            return $empty
        }
        $retry = Show-OctoMessage -Title 'DHCP Cache Password' -Icon Warning -Buttons YesNo -Text (
            "The $label could not be opened with this password.`n`n" +
            "It was probably saved with a different password - the password is asked again after 5 minutes, " +
            "so the servers and scopes caches can end up with different ones - or the password was mistyped.`n`n" +
            "Try another password?`n`nNo = skip it for now. 'Refresh Cache' rebuilds it with your current password.")
        if ("$retry" -ne 'Yes') { return $empty }
        $password = Get-DHCPCachePassword -Action 'Load' -Hint $label
        if (-not $password) { return $empty }
    }

    try { $cache = $plain | ConvertFrom-Json }
    catch {
        Show-OctoMessage -Title 'DHCP Cache' -Icon Warning -Text "The $label was decrypted, but its content could not be read:`n$($_.Exception.Message)`n`nClick 'Refresh Cache' to rebuild it." | Out-Null
        return $empty
    }

    if ([object]::ReferenceEquals($password, $session) -or -not $script:DHCPCachePasswordVerified) {
        # This password is now known to be right
        Set-SessionCachedPassword -Password $password
    } else {
        # The session password already opened the other cache: keep one password for both
        $answer = Show-OctoMessage -Title 'DHCP Cache Password' -Icon Question -Buttons YesNo -Text (
            "The $label uses a different password than your other DHCP cache.`n`n" +
            "Re-save it with the password you entered first, so one password opens both caches from now on?")
        if ("$answer" -eq 'Yes') {
            try { Write-DhcpCacheFile -File $datFile -PlainText $plain -Password $session }
            catch { Show-OctoMessage -Title 'DHCP Cache' -Icon Warning -Text "Could not re-save the $($label):`n$($_.Exception.Message)" | Out-Null }
        }
    }
    return @{ Items = @($cache.$Kind | Where-Object { $null -ne $_ }); LastUpdated = $cache.LastUpdated }
}

function Save-DhcpCache {
    <#
    .SYNOPSIS
        Encrypts and saves the servers or scopes cache. Returns $true when saved.
    #>
    param([ValidateSet('Servers', 'Scopes')][string]$Kind, [object[]]$Items)
    $base = if ($Kind -eq 'Servers') { 'dhcp_servers_cache' } else { 'dhcp_scopes_cache' }
    $password = Get-DhcpCacheSavePassword -Hint "DHCP $($Kind.ToLower()) cache"
    if (-not $password) {
        Show-OctoMessage -Title 'Cache Not Saved' -Icon Warning -Text "The DHCP $($Kind.ToLower()) cache was NOT saved because no password was provided.`n`nThe data is still loaded for this session." | Out-Null
        return $false
    }
    $cache = [ordered]@{ LastUpdated = (Get-Date).ToString('o') }
    if ($Kind -eq 'Scopes') { $cache.TotalScopes = @($Items).Count } else { $cache.ServerCount = @($Items).Count }
    $cache[$Kind] = @($Items)
    try {
        $json = $cache | ConvertTo-Json -Depth 4 -Compress
        Write-DhcpCacheFile -File (Join-Path $script:DataDir "$base.dat") -PlainText $json -Password $password
        return $true
    } catch {
        Show-OctoMessage -Title 'Encryption Failed' -Icon Error -Text "Failed to save the encrypted DHCP cache.`n`nError: $($_.Exception.Message)" | Out-Null
        return $false
    }
}

# ============================================
# PARALLEL ENGINE (in-process runspace pool)
# ============================================
# Replaces Start-Job (one powershell.exe process per server, serialized results)
# with an in-process runspace pool: no process start-up, live objects, and the
# UI thread only polls finished work so the window stays responsive.
# Worker scripts are plain text with param($Item, $Shared) and must return ONE
# object. $Shared is a synchronized hashtable (Shared.Stop = cancellation flag).

function New-OctoRunspacePool {
    <#
    .SYNOPSIS
        Opens a runspace pool; the named functions of this script are copied into it.
    .PARAMETER ExtraFunctions
        name -> definition text (lets tests inject stub cmdlets).
    #>
    param(
        [int]$MaxRunspaces = 8,
        [string[]]$FunctionNames = @(),
        [hashtable]$ExtraFunctions = @{}
    )
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    foreach ($name in $FunctionNames) {
        $cmd = Get-Command -Name $name -CommandType Function -ErrorAction Stop
        $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($name, $cmd.Definition))
    }
    foreach ($name in $ExtraFunctions.Keys) {
        $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($name, [string]$ExtraFunctions[$name]))
    }
    $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, $MaxRunspaces), $iss, $Host)
    $pool.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $pool.Open()
    return $pool
}

function Close-OctoRunspacePool {
    <#
    .SYNOPSIS
        Closes a pool without blocking the caller when work is still running.
    #>
    param($Pool, [switch]$Wait)
    if ($null -eq $Pool) { return }
    try {
        if ($Wait) { $Pool.Close(); $Pool.Dispose() }
        else { [void]$Pool.BeginClose($null, $null) }
    } catch { }
}

function Start-OctoTask {
    param($Pool, [string]$Script, $Argument, $Shared)
    $ps = [powershell]::Create()
    $ps.RunspacePool = $Pool
    [void]$ps.AddScript($Script).AddArgument($Argument).AddArgument($Shared)
    return @{ PS = $ps; Handle = $ps.BeginInvoke(); Item = $Argument; Descriptor = $null; Index = -1 }
}

function Receive-OctoTask {
    <#
    .SYNOPSIS
        Ends a finished task. Returns @{ Output = <last output object>; Error = <text or $null> }.
    #>
    param($Task)
    try {
        $out = $Task.PS.EndInvoke($Task.Handle)
        $err = $null
        if ($Task.PS.Streams.Error.Count -gt 0) { $err = [string]$Task.PS.Streams.Error[0] }
        $value = $null
        if ($out.Count -gt 0) { $value = $out[$out.Count - 1] }
        return @{ Output = $value; Error = $err }
    } catch {
        return @{ Output = $null; Error = $_.Exception.Message }
    } finally {
        try { $Task.PS.Dispose() } catch { }
    }
}

function Stop-OctoTask {
    param($Task)
    try { [void]$Task.PS.BeginStop($null, $null) } catch { }
}

function Invoke-OctoParallel {
    <#
    .SYNOPSIS
        Runs a worker script for every item in parallel and waits (UI stays responsive).
    .DESCRIPTION
        Results are returned index-aligned with Items: @{ Output; Error } each.
        Only 2x Throttle tasks are queued at a time, so thousands of items cost
        no more memory than a few dozen. Shared.Stop = $true cancels.
    .PARAMETER MaxInFlight
        At most this many items sent at once (default 2x Throttle); lets a
        caller-owned pool run fewer requests at a time than it has runspaces.
    .OUTPUTS
        object[] (returned with the unary comma so a single result is not unrolled)
    #>
    param(
        [AllowEmptyCollection()][object[]]$Items,
        [Parameter(Mandatory = $true)][string]$Script,
        [hashtable]$Shared,
        [int]$Throttle = 8,
        [scriptblock]$OnProgress,
        [string[]]$FunctionNames = @(),
        [hashtable]$ExtraFunctions = @{},
        $Pool,
        [int]$MaxInFlight = 0,
        [switch]$NoUi
    )
    if ($null -eq $Items) { $Items = @() }
    $results = New-Object object[] $Items.Count
    if ($Items.Count -eq 0) { return ,$results }
    if ($null -eq $Shared) { $Shared = [hashtable]::Synchronized(@{ Stop = $false }) }

    # A caller-owned pool (-Pool) is reused and left open
    $ownPool = ($null -eq $Pool)
    $pool = if ($ownPool) { New-OctoRunspacePool -MaxRunspaces ([Math]::Min($Throttle, $Items.Count)) -FunctionNames $FunctionNames -ExtraFunctions $ExtraFunctions } else { $Pool }
    $pending = [System.Collections.Generic.List[object]]::new()
    $next = 0; $done = 0; $maxQueued = [Math]::Max(2, $Throttle * 2)
    if ($MaxInFlight -gt 0) { $maxQueued = $MaxInFlight }
    $stopped = $false
    try {
        while ($done -lt $Items.Count) {
            while (-not $stopped -and $next -lt $Items.Count -and $pending.Count -lt $maxQueued) {
                $task = Start-OctoTask -Pool $pool -Script $Script -Argument $Items[$next] -Shared $Shared
                $task.Index = $next
                $pending.Add($task)
                $next++
            }

            $progressed = $false
            for ($i = $pending.Count - 1; $i -ge 0; $i--) {
                $task = $pending[$i]
                if ($task.Handle.IsCompleted) {
                    $pending.RemoveAt($i)
                    $result = Receive-OctoTask -Task $task
                    $results[$task.Index] = $result
                    $done++
                    $progressed = $true
                    if ($OnProgress) { & $OnProgress $done $Items.Count $result }
                }
            }

            if ($Shared.Stop -and -not $stopped) {
                $stopped = $true
                foreach ($task in $pending) { Stop-OctoTask -Task $task }
                $pending.Clear()
                break
            }
            if (-not $progressed) {
                if (-not $NoUi) { [System.Windows.Forms.Application]::DoEvents() }
                Start-Sleep -Milliseconds 15
            }
        }
    } finally {
        if ($ownPool) { Close-OctoRunspacePool -Pool $pool -Wait:(-not $stopped) }
    }
    return ,$results
}

# --- Asynchronous jobs (WinForms timer polls the pool; the click handler returns at once)

function Start-OctoJob {
    <#
    .SYNOPSIS
        Creates a timer-driven job around a runspace pool.
    .PARAMETER OnTaskComplete
        param($Job, $Task, $Result) - runs on the UI thread for each finished task;
        may queue follow-up work with Add-OctoJobTask.
    .PARAMETER OnJobComplete
        param($Job) - runs once when nothing is pending (or after Stop-OctoJob).
    #>
    param(
        [Parameter(Mandatory = $true)]$Pool,
        [Parameter(Mandatory = $true)][scriptblock]$OnTaskComplete,
        [Parameter(Mandatory = $true)][scriptblock]$OnJobComplete,
        [hashtable]$Shared,
        [int]$IntervalMs = 150
    )
    if ($null -eq $Shared) { $Shared = [hashtable]::Synchronized(@{ Stop = $false }) }
    $job = @{
        Pool = $Pool; Shared = $Shared; Pending = [System.Collections.Generic.List[object]]::new()
        OnTaskComplete = $OnTaskComplete; OnJobComplete = $OnJobComplete
        Completed = $false; Stopped = $false; InTick = $false; Timer = $null; Data = @{}
    }
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = $IntervalMs
    $timer.Tag = $job
    $timer.Add_Tick({ Invoke-OctoJobTick -Job $this.Tag })
    $job.Timer = $timer
    return $job
}

function Add-OctoJobTask {
    param($Job, [string]$Script, $Argument, $Descriptor)
    if ($Job.Completed -or $Job.Stopped) { return }
    $task = Start-OctoTask -Pool $Job.Pool -Script $Script -Argument $Argument -Shared $Job.Shared
    $task.Descriptor = $Descriptor
    $Job.Pending.Add($task)
    if ($Job.Timer -and -not $Job.Timer.Enabled) { $Job.Timer.Start() }
}

function Invoke-OctoJobTick {
    param($Job)
    # A handler that opens a dialog keeps the message loop (and this timer) running:
    # skip nested ticks instead of processing the same job twice
    if ($Job.Completed -or $Job.InTick) { return }
    $Job.InTick = $true
    try {
        for ($i = $Job.Pending.Count - 1; $i -ge 0; $i--) {
            if ($i -ge $Job.Pending.Count) { continue }
            $task = $Job.Pending[$i]
            if (-not $task.Handle.IsCompleted) { continue }
            $Job.Pending.RemoveAt($i)
            $result = Receive-OctoTask -Task $task
            try { & $Job.OnTaskComplete $Job $task $result } catch { Write-Warning "Task handler error: $($_.Exception.Message)" }
            if ($Job.Completed) { return }
        }
    } finally { $Job.InTick = $false }
    if ($Job.Pending.Count -eq 0) { Complete-OctoJob -Job $Job }
}

function Complete-OctoJob {
    param($Job)
    if ($Job.Completed) { return }
    $Job.Completed = $true
    if ($Job.Timer) { try { $Job.Timer.Stop(); $Job.Timer.Dispose() } catch { } }
    Close-OctoRunspacePool -Pool $Job.Pool -Wait:(-not $Job.Stopped)
    try { & $Job.OnJobComplete $Job } catch { Write-Warning "Job completion error: $($_.Exception.Message)" }
}

function Stop-OctoJob {
    <#
    .SYNOPSIS
        Cancels outstanding work and completes the job immediately with what is done.
    #>
    param($Job)
    if ($null -eq $Job -or $Job.Completed) { return }
    $Job.Stopped = $true
    $Job.Shared.Stop = $true
    foreach ($task in $Job.Pending) { Stop-OctoTask -Task $task }
    $Job.Pending.Clear()
    Complete-OctoJob -Job $Job
}
# ============================================
# DHCP MATH - REDUNDANCY-AWARE SCOPE ANALYSIS
# ============================================
# How Windows DHCP reports a scope that lives on more than one server:
#   * Failover (LoadBalance or HotStandby): both partners replicate the lease
#     database, so EACH partner reports the WHOLE scope's free/in-use numbers.
#     Partners must be de-duplicated (never summed).
#   * Split scope / same ScopeId on unrelated servers (no failover relationship):
#     each server only owns its own part of the pool. Parts must be summed.
#   * Inactive copies of a scope do not hand out addresses, so they are not
#     counted when an active copy exists.
# The failover relationship reported by Get-DhcpServerv4Failover decides which
# case applies - the number of servers holding a ScopeId cannot tell them apart.

function ConvertTo-OctoInt64 {
    param($Value)
    if ($null -eq $Value) { return [long]0 }
    try { return [long]$Value } catch { return [long]0 }
}

function Get-DhcpPercent {
    <#
    .SYNOPSIS
        InUse / Total * 100, rounded half away from zero to 2 decimals.
        [decimal] keeps the rounding exact (no binary floating point drift).
    #>
    param([long]$InUse, [long]$Total)
    if ($Total -le 0) { return [decimal]0 }
    $pct = ([decimal]$InUse * [decimal]100) / [decimal]$Total
    return [math]::Round($pct, 2, [System.MidpointRounding]::AwayFromZero)
}

function ConvertTo-DhcpIPv4Number {
    # "10.1.2.3" -> 167838211; -1 when the text is not an IPv4 address
    param([string]$Address)
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Address.Trim(), [ref]$ip) -or
        $ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return [long]-1 }
    $b = $ip.GetAddressBytes()
    return ([long]$b[0] -shl 24) -bor ([long]$b[1] -shl 16) -bor ([long]$b[2] -shl 8) -bor [long]$b[3]
}

function Get-DhcpRangeSize {
    <#
    .SYNOPSIS
        Number of addresses from the lowest StartRange to the highest EndRange of the
        rows - an upper bound for the distinct addresses of a scope. 0 = unknown.
    #>
    param([object[]]$Rows)
    $low = [long]::MaxValue; $high = [long]-1
    foreach ($r in $Rows) {
        $s = ConvertTo-DhcpIPv4Number -Address ([string]$r.StartRange)
        $e = ConvertTo-DhcpIPv4Number -Address ([string]$r.EndRange)
        if ($s -lt 0 -or $e -lt $s) { return [long]0 }
        if ($s -lt $low) { $low = $s }
        if ($e -gt $high) { $high = $e }
    }
    if ($high -lt 0) { return [long]0 }
    return $high - $low + 1
}

function Get-DhcpServerShortName {
    <#
    .SYNOPSIS
        Lower-cased first DNS label of a server name (IP addresses are kept whole).
    #>
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    $n = $Name.Trim().ToLowerInvariant()
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($n, [ref]$ip)) { return $n }
    $dot = $n.IndexOf('.')
    if ($dot -gt 0) { return $n.Substring(0, $dot) }
    return $n
}

function Merge-DhcpServerList {
    <#
    .SYNOPSIS
        Builds a de-duplicated list of DHCP server names to query.
    .DESCRIPTION
        Querying the same server twice would count its standalone scopes twice,
        so duplicates are removed:
          - names are compared case-insensitively (Get-DhcpServerInDC lists a
            multi-homed server once per IP address)
          - an entry whose IP matches an earlier entry is the same server, unless
            DNS says otherwise: a name that no longer resolves is a stale Active
            Directory entry (the name that does resolve is kept), and two names
            that resolve to different addresses are different servers (both kept)
          - a bare host name ("dhcp01") is dropped when exactly one FQDN with that
            first label ("dhcp01.contoso.com") is also present
    .PARAMETER Entries
        Strings, or objects/hashtables with Name and optional IP.
    .PARAMETER Resolved
        Optional: name -> addresses the name resolves to now (empty = does not resolve).
    .PARAMETER Notes
        Optional list that receives one line for every entry that is not queried on its own.
    #>
    param(
        [AllowEmptyCollection()][object[]]$Entries,
        [hashtable]$Resolved,
        [AllowNull()][System.Collections.Generic.List[string]]$Notes
    )

    $seenNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ipOwner = @{}
    $kept = [System.Collections.Generic.List[object]]::new()

    foreach ($entry in $Entries) {
        if ($null -eq $entry) { continue }
        if ($entry -is [string]) { $name = $entry; $ipText = $null }
        else { $name = [string]$entry.Name; $ipText = [string]$entry.IP }
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $name = $name.Trim()

        $parsed = $null
        $nameIsIp = [System.Net.IPAddress]::TryParse($name, [ref]$parsed)
        if ($nameIsIp -and [string]::IsNullOrWhiteSpace($ipText)) { $ipText = $name }
        $ip = if ([string]::IsNullOrWhiteSpace($ipText)) { '' } else { $ipText.Trim() }
        $item = [pscustomobject]@{ Name = $name; IP = $ip; IsFqdn = ((-not $nameIsIp) -and $name.IndexOf('.') -gt 0) }

        if (-not $seenNames.Add($name)) {
            if ($null -ne $Notes) { $Notes.Add("$name$(if ($ip) { " ($ip)" }): the same server listed again (one entry per IP address)") }
            continue
        }
        if ($ip -and $ipOwner.ContainsKey($ip)) {
            $ownerIndex = $ipOwner[$ip]
            $owner = $kept[$ownerIndex]
            $ownerAddr = $null; $newAddr = $null
            if ($Resolved -and $Resolved.ContainsKey($owner.Name) -and $Resolved.ContainsKey($name)) {
                $ownerAddr = @($Resolved[$owner.Name] | Where-Object { $_ })
                $newAddr = @($Resolved[$name] | Where-Object { $_ })
            }
            if ($null -ne $ownerAddr -and $ownerAddr.Count -eq 0 -and $newAddr.Count -gt 0) {
                # the earlier entry is stale: the live server now has this address
                $kept[$ownerIndex] = $item
                if ($null -ne $Notes) { $Notes.Add("$($owner.Name) ($ip): stale Active Directory entry - the name no longer resolves; $name has this address now") }
                continue
            }
            if ($null -ne $newAddr -and $newAddr.Count -gt 0 -and $ownerAddr.Count -gt 0 -and
                @($newAddr | Where-Object { $ownerAddr -contains $_ }).Count -eq 0) {
                # same address in Active Directory, different machines in DNS: query both
                if ($null -ne $Notes) { $Notes.Add("$name and $($owner.Name) share $ip in Active Directory but resolve to different addresses - both are queried") }
                $kept.Add($item)
                continue
            }
            if ($null -ne $Notes) {
                if ($null -ne $newAddr -and $newAddr.Count -eq 0) { $Notes.Add("$name ($ip): stale Active Directory entry - the name does not resolve; $($owner.Name) has this address") }
                else { $Notes.Add("$name ($ip): same IP address as $($owner.Name) - treated as the same server") }
            }
            continue
        }
        $kept.Add($item)
        if ($ip) { $ipOwner[$ip] = $kept.Count - 1 }
    }

    $fqdnByLabel = @{}
    foreach ($k in $kept) {
        if ($k.IsFqdn) {
            $label = Get-DhcpServerShortName -Name $k.Name
            if ($fqdnByLabel.ContainsKey($label)) { $fqdnByLabel[$label] = '' } else { $fqdnByLabel[$label] = $k.Name }
        }
    }

    $result = [System.Collections.Generic.List[string]]::new()
    foreach ($k in $kept) {
        if (-not $k.IsFqdn -and $k.Name.IndexOf('.') -lt 0) {
            $label = $k.Name.ToLowerInvariant()
            if ($fqdnByLabel.ContainsKey($label) -and $fqdnByLabel[$label]) {
                if ($null -ne $Notes) { $Notes.Add("$($k.Name): short name of $($fqdnByLabel[$label])") }
                continue
            }
        }
        $result.Add($k.Name)
    }
    return $result.ToArray()
}

function Join-OctoDistinct {
    <#
    .SYNOPSIS
        Joins the distinct non-empty values (case-insensitive, first-seen order).
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Values, [string]$Separator = ', ')
    if ($null -eq $Values) { return '' }
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($v in $Values) {
        if ($null -eq $v) { continue }
        $s = ([string]$v).Trim()
        if ($s.Length -gt 0 -and $seen.Add($s)) { $out.Add($s) }
    }
    return ($out -join $Separator)
}

function Get-DhcpScopeAnalysis {
    <#
    .SYNOPSIS
        Groups per-server scope rows by ScopeId and computes redundancy-correct totals.
    .DESCRIPTION
        Input rows are the per-server results of the collector (see New-DhcpScopeRow).

        For each ScopeId:
          1. Duplicate rows from the same server are ignored.
          2. Only active copies count when at least one copy is active.
          3. Copies are clustered: both partners of a failover relationship form one
             cluster; every non-failover copy is its own cluster; a copy whose server
             could not report failover information joins the relationship that names
             it as partner, otherwise such copies are treated as replicas of each
             other (never double counted).
          4. Cluster value = MAX(pool) and MAX(in use) over its members (replicas
             report the same scope-wide numbers). Scope total = SUM over clusters
             (independent pools).
        Every per-server row also gets its own TotalAddresses/PercentageInUse and the
        group's Redundancy and Notes, so a per-server export explains itself.

        Hot loop note: PowerShell function calls cost ~50-100 microseconds each, so the
        per-row percentage (same formula as Get-DhcpPercent) and the distinct-value
        joins are inlined below.
    .OUTPUTS
        PSCustomObject with Groups (one row per ScopeId) and Summary.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Rows,
        [int]$TopCount = 10
    )

    $ignoreCase = [System.StringComparer]::OrdinalIgnoreCase
    $awayFromZero = [System.MidpointRounding]::AwayFromZero

    $order = [System.Collections.Generic.List[string]]::new()
    $byScope = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]]::new($ignoreCase)
    $rowCount = 0
    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        $rowCount++
        $key = ([string]$row.ScopeId).Trim()
        $list = $null
        if (-not $byScope.TryGetValue($key, [ref]$list)) {
            $list = [System.Collections.Generic.List[object]]::new()
            $byScope[$key] = $list
            $order.Add($key)
        }
        $list.Add($row)
    }

    # Distinct-value collectors, allocated once and cleared per scope
    $distinctFields = @('ScopeState', 'FailoverRelationship', 'FailoverPartner', 'FailoverState', 'Option60', 'Option43', 'AllOptions', 'DNSServers')
    $optionFields = @('DNSServers', 'Option60', 'Option43', 'AllOptions')
    $collect = @{}
    foreach ($name in $distinctFields) {
        $collect[$name] = @{ List = [System.Collections.Generic.List[string]]::new(); Seen = [System.Collections.Generic.HashSet[string]]::new($ignoreCase) }
    }
    $members = [System.Collections.Generic.List[object]]::new()
    $active = [System.Collections.Generic.List[object]]::new()
    $inactiveServers = [System.Collections.Generic.List[string]]::new()
    $serverSeen = [System.Collections.Generic.HashSet[string]]::new($ignoreCase)
    $servers = [System.Collections.Generic.List[string]]::new()
    $notes = [System.Collections.Generic.List[string]]::new()
    $clusters = [System.Collections.Generic.List[object]]::new()
    $unknown = [System.Collections.Generic.List[object]]::new()
    $scopeNames = [System.Collections.Generic.List[string]]::new()
    $optionFailedServers = [System.Collections.Generic.List[string]]::new()
    $noStatsRows = 0

    $groups = [System.Collections.Generic.List[object]]::new()
    $stats = @{
        Failover = 0; FailoverDegraded = 0; Single = 0; Split = 0; Unknown = 0; Mixed = 0; Overlap = 0; NameConflict = 0
        Active = 0; Inactive = 0; Total = [long]0; InUse = [long]0; Free = [long]0; Over80 = 0; Over90 = 0
    }
    $top = [System.Collections.Generic.List[object]]::new()

    foreach ($scopeId in $order) {
        $all = $byScope[$scopeId]
        foreach ($c in $collect.Values) { $c.List.Clear(); $c.Seen.Clear() }
        $members.Clear(); $active.Clear(); $inactiveServers.Clear(); $serverSeen.Clear()
        $servers.Clear(); $notes.Clear(); $clusters.Clear(); $unknown.Clear(); $optionFailedServers.Clear()
        $desc = ''

        # --- 1. one row per server; own numbers; distinct display values
        foreach ($m in $all) {
            $server = ([string]$m.DHCPServer).Trim()
            if (-not $serverSeen.Add($server)) {
                $notes.Add("Duplicate result from $server ignored")
                continue
            }
            $members.Add($m)
            $servers.Add($server)
            if ($m.StatsMissing) {
                $notes.Add("No statistics returned by $server - its numbers are unknown (shown as 0)")
                $noStatsRows++
            }
            $u = [long]$m.AddressesInUse
            $t = [long]$m.AddressesFree + $u
            $m.TotalAddresses = $t
            if ($t -gt 0) { $m.PercentageInUse = [math]::Round(([decimal]$u * 100) / $t, 2, $awayFromZero) }
            else { $m.PercentageInUse = [decimal]0 }

            $isInactive = ([string]$m.ScopeState -eq 'InActive')
            if ($isInactive) { $inactiveServers.Add($server) } else { $active.Add($m) }
            if (-not $desc -and -not $isInactive -and -not [string]::IsNullOrWhiteSpace([string]$m.Description)) { $desc = [string]$m.Description }

            $optionsFailed = [bool]$m.OptionsFailed
            if ($optionsFailed) { $optionFailedServers.Add($server) }
            foreach ($name in $distinctFields) {
                # A server whose options could not be read adds none (the partner's values stand)
                if ($optionsFailed -and $optionFields -contains $name) { continue }
                $v = $m.$name
                if ($null -eq $v) { continue }
                $col = $collect[$name]
                $parts = if ($name -eq 'DNSServers') { ([string]$v).Split(',') } else { @([string]$v) }
                foreach ($part in $parts) {
                    $s = $part.Trim()
                    if ($s.Length -gt 0 -and $col.Seen.Add($s)) { $col.List.Add($s) }
                }
            }
        }
        if (-not $desc) {
            foreach ($m in $members) { if (-not [string]::IsNullOrWhiteSpace([string]$m.Description)) { $desc = [string]$m.Description; break } }
        }
        if ($optionFailedServers.Count -gt 0) {
            if ($optionFailedServers.Count -lt $members.Count) {
                $notes.Add("DHCP options could not be read from $($optionFailedServers -join ', ') - the option values shown come from the other server(s)")
            } else {
                # No server answered: the grouped row says '(lookup failed)' too
                foreach ($name in $optionFields) {
                    $v = $members[0].$name
                    if ($null -ne $v) { $collect[$name].List.Add([string]$v) }
                }
                $notes.Add("DHCP options could not be read from $($optionFailedServers -join ', ')")
            }
        }

        # --- 2. active copies only (unless every copy is inactive)
        $isActiveGroup = $active.Count -gt 0
        $contributing = if ($isActiveGroup) { $active } else { $members }
        if ($isActiveGroup -and $inactiveServers.Count -gt 0) {
            $notes.Add("Inactive copy on $($inactiveServers -join ', ') not counted")
        }

        # --- 3. clusters
        $clusterIndex = @{}
        foreach ($m in $contributing) {
            $rel = [string]$m.FailoverRelationship
            if ($rel.Trim().Length -gt 0) {
                $ck = 'FO:' + $rel.Trim().ToLowerInvariant(); $kind = 'Failover'
            } elseif ($m.FailoverInfoAvailable) {
                $ck = 'SA:' + ([string]$m.DHCPServer).Trim().ToLowerInvariant(); $kind = 'Standalone'
            } else {
                $unknown.Add($m); continue
            }
            $c = $clusterIndex[$ck]
            if ($null -eq $c) {
                $c = @{ Kind = $kind; Rows = [System.Collections.Generic.List[object]]::new() }
                $clusterIndex[$ck] = $c
                $clusters.Add($c)
            }
            $c.Rows.Add($m)
        }

        if ($unknown.Count -gt 0) {
            $unknownNames = [System.Collections.Generic.List[string]]::new()
            $leftover = [System.Collections.Generic.List[object]]::new()
            foreach ($u in $unknown) {
                $unknownNames.Add([string]$u.DHCPServer)
                $uShort = Get-DhcpServerShortName -Name $u.DHCPServer
                $target = $null
                foreach ($c in $clusters) {
                    if ($c.Kind -ne 'Failover') { continue }
                    foreach ($r in $c.Rows) {
                        if ($uShort -and (Get-DhcpServerShortName -Name $r.FailoverPartner) -eq $uShort) { $target = $c; break }
                    }
                    if ($target) { break }
                }
                if ($target) { $target.Rows.Add($u) } else { $leftover.Add($u) }
            }
            if ($leftover.Count -eq 1) {
                $clusters.Add(@{ Kind = 'UnknownSingle'; Rows = $leftover })
            } elseif ($leftover.Count -gt 1) {
                $clusters.Add(@{ Kind = 'Unknown'; Rows = $leftover })
            }
            $notes.Add("Failover info unavailable from $($unknownNames -join ', ')")
        }

        # --- 4. cluster values -> scope totals
        $total = [long]0; $inUse = [long]0
        $foCount = 0; $saCount = 0; $unkCount = 0
        $modes = [System.Collections.Generic.List[string]]::new()
        $badStates = [System.Collections.Generic.List[string]]::new()
        foreach ($c in $clusters) {
            $maxPool = [long]0; $maxUse = [long]0; $minPool = [long]::MaxValue
            foreach ($r in $c.Rows) {
                $p = [long]$r.TotalAddresses
                $iu = [long]$r.AddressesInUse
                if ($p -gt $maxPool) { $maxPool = $p }
                if ($p -lt $minPool) { $minPool = $p }
                if ($iu -gt $maxUse) { $maxUse = $iu }
                if ($c.Kind -eq 'Failover') {
                    $mode = [string]$r.FailoverMode
                    if ($mode -and -not $modes.Contains($mode)) { $modes.Add($mode) }
                    $st = [string]$r.FailoverState
                    if ($st -and $st -ne 'Normal' -and -not $badStates.Contains($st)) { $badStates.Add($st) }
                }
            }
            $total += $maxPool
            $inUse += $maxUse

            switch ($c.Kind) {
                'Failover' { $foCount++ }
                'Unknown' { $unkCount++ }
                default { $saCount++ }
            }
            if ($c.Rows.Count -gt 1 -and $minPool -ne $maxPool) {
                $detail = [System.Collections.Generic.List[string]]::new()
                foreach ($r in $c.Rows) { $detail.Add("$($r.DHCPServer)=$($r.TotalAddresses)") }
                $notes.Add("Pool size differs between copies ($($detail -join ', ')) - replicate the failover scope configuration")
            }
            if ($c.Kind -eq 'Failover' -and $c.Rows.Count -eq 1 -and $c.Rows[0].FailoverPartner) {
                $notes.Add("Partner $($c.Rows[0].FailoverPartner) not in results (values from $($c.Rows[0].DHCPServer) cover the whole scope)")
            }
        }
        # --- 4b. summed pools cannot hold more addresses than the scope range: copies
        # that hand out the same addresses without failover are capped at the range
        # Copies with different scope names are usually separate networks (sites)
        # that reuse the same subnet: they keep their own pools and are flagged.
        $overlap = $false; $nameConflict = $false
        if ($clusters.Count -gt 1) {
            $scopeNames.Clear()
            foreach ($m in $contributing) {
                $n = ([string]$m.Name).Trim()
                if ($n.Length -gt 0 -and -not ($scopeNames -contains $n)) { $scopeNames.Add($n) }
            }
            if ($scopeNames.Count -gt 1) {
                $nameConflict = $true
                $notes.Add("Scope names differ ('" + ($scopeNames -join "' / '") + "') - probably separate networks reusing this subnet; each pool is counted")
            } else {
                $rangeSize = Get-DhcpRangeSize -Rows $contributing
                if ($rangeSize -gt 0 -and $total -gt $rangeSize) {
                    $notes.Add("Copies overlap: the pools add up to $total addresses but the scope range holds $rangeSize - counted as $rangeSize (use failover, or exclusions that do not overlap)")
                    $total = $rangeSize
                    if ($inUse -gt $total) { $inUse = $total }
                    $overlap = $true
                }
            }
        }
        $free = $total - $inUse

        # --- 5. classification
        if ($foCount -ge 1 -and $saCount -eq 0 -and $unkCount -eq 0) {
            $redundancy = if ($modes.Count -gt 0) { "Failover ($($modes -join '/'))" } else { 'Failover' }
            if ($badStates.Count -gt 0) { $redundancy += ' - DEGRADED: ' + ($badStates -join '/') }
            $category = 'Failover'
        } elseif ($foCount -eq 0 -and $unkCount -eq 0 -and $saCount -eq 1) {
            if ($clusters[0].Kind -eq 'UnknownSingle') {
                $redundancy = 'Unknown (failover info unavailable)'; $category = 'Unknown'
            } else {
                $redundancy = 'None (single server)'; $category = 'Single'
            }
        } elseif ($foCount -eq 0 -and $unkCount -eq 0 -and $saCount -gt 1) {
            $redundancy = "Split/duplicate scope ($saCount servers, no failover - pools summed)"; $category = 'Split'
        } elseif ($foCount -eq 0 -and $saCount -eq 0 -and $unkCount -ge 1) {
            $redundancy = 'Assumed failover (failover info unavailable - not summed)'; $category = 'Unknown'
        } else {
            $parts = [System.Collections.Generic.List[string]]::new()
            if ($foCount -gt 0) { $parts.Add("$foCount failover relationship(s)") }
            if ($saCount -gt 0) { $parts.Add("$saCount standalone copy(ies)") }
            if ($unkCount -gt 0) { $parts.Add('copies without failover info') }
            $redundancy = 'Mixed: ' + ($parts -join ' + ') + ' - independent pools summed'; $category = 'Mixed'
        }

        if ($overlap) { $redundancy += ' - OVERLAPPING POOLS (capped at scope range)' }
        if ($nameConflict) { $redundancy += ' - DIFFERENT SCOPE NAMES (separate networks?)' }
        $notesText = $notes -join '; '
        foreach ($m in $all) {
            $m.Redundancy = $redundancy
            $m.Notes = $notesText
        }

        # --- 6. grouped row
        if ($total -gt 0) { $pct = [math]::Round(([decimal]$inUse * 100) / $total, 2, $awayFromZero) } else { $pct = [decimal]0 }
        $group = [pscustomobject][ordered]@{
            ScopeId              = $scopeId
            DHCPServer           = ($servers -join ', ')
            Description          = $desc
            AddressesFree        = $free
            AddressesInUse       = $inUse
            PercentageInUse      = $pct
            DNSServers           = ($collect['DNSServers'].List -join ', ')
            Option60             = ($collect['Option60'].List -join ' || ')
            Option43             = ($collect['Option43'].List -join ' || ')
            AllOptions           = ($collect['AllOptions'].List -join ' || ')
            TotalAddresses       = $total
            ScopeState           = ($collect['ScopeState'].List -join '/')
            Redundancy           = $redundancy
            FailoverRelationship = ($collect['FailoverRelationship'].List -join ', ')
            FailoverPartner      = ($collect['FailoverPartner'].List -join ', ')
            FailoverState        = ($collect['FailoverState'].List -join '/')
            ServerCount          = $members.Count
            Notes                = $notesText
        }
        $groups.Add($group)

        # --- 7. summary (only scopes that can hand out addresses)
        if ($isActiveGroup) {
            $stats[$category]++
            if ($category -eq 'Failover' -and $badStates.Count -gt 0) { $stats.FailoverDegraded++ }
            $stats.Active++
            if ($overlap) { $stats.Overlap++ }
            if ($nameConflict) { $stats.NameConflict++ }
            $stats.Total += $total
            $stats.InUse += $inUse
            $stats.Free += $free
            if ($total -gt 0) {
                if ($pct -ge 90) { $stats.Over90++ }
                if ($pct -ge 80) { $stats.Over80++ }
                # keep the $TopCount fullest scopes (small sorted insertion list)
                $pos = $top.Count
                while ($pos -gt 0 -and ($top[$pos - 1].PercentageInUse -lt $pct -or
                        ($top[$pos - 1].PercentageInUse -eq $pct -and $top[$pos - 1].AddressesInUse -lt $inUse))) { $pos-- }
                if ($pos -lt $TopCount) {
                    $top.Insert($pos, $group)
                    if ($top.Count -gt $TopCount) { $top.RemoveAt($top.Count - 1) }
                }
            }
        } else {
            $stats.Inactive++
        }
    }

    $summary = [pscustomobject][ordered]@{
        ServerRows       = $rowCount
        UniqueScopes     = $groups.Count
        ActiveScopes     = $stats.Active
        InactiveScopes   = $stats.Inactive
        FailoverScopes   = $stats.Failover
        DegradedFailover = $stats.FailoverDegraded
        SingleServer     = $stats.Single
        SplitScopes      = $stats.Split
        MixedScopes      = $stats.Mixed
        UnknownScopes    = $stats.Unknown
        OverlapScopes    = $stats.Overlap
        DifferentNameScopes = $stats.NameConflict
        NoStatsRows      = $noStatsRows
        TotalAddresses   = $stats.Total
        AddressesInUse   = $stats.InUse
        AddressesFree    = $stats.Free
        PercentageInUse  = (Get-DhcpPercent -InUse $stats.InUse -Total $stats.Total)
        ScopesOver80     = $stats.Over80
        ScopesOver90     = $stats.Over90
        Top              = $top.ToArray()
    }

    return [pscustomobject]@{
        Groups  = $groups.ToArray()
        Summary = $summary
    }
}

function New-DhcpScopeRow {
    <#
    .SYNOPSIS
        Creates a per-server scope row with every field the analysis/export use.
    #>
    param(
        [string]$ScopeId, [string]$DHCPServer, [string]$Name, [string]$Description,
        [string]$SubnetMask, [string]$StartRange, [string]$EndRange, [string]$ScopeState = 'Active',
        [long]$AddressesFree, [long]$AddressesInUse, [long]$Reserved, [long]$Pending, [bool]$StatsMissing = $false,
        [bool]$FailoverInfoAvailable = $true, [string]$FailoverRelationship, [string]$FailoverPartner,
        [string]$FailoverMode, [string]$FailoverState, [string]$FailoverServerRole
    )
    [pscustomobject][ordered]@{
        ScopeId               = $ScopeId
        DHCPServer            = $DHCPServer
        Name                  = $Name
        Description           = if ([string]::IsNullOrWhiteSpace($Description)) { $Name } else { $Description }
        SubnetMask            = $SubnetMask
        StartRange            = $StartRange
        EndRange              = $EndRange
        ScopeState            = $ScopeState
        AddressesFree         = $AddressesFree
        AddressesInUse        = $AddressesInUse
        Reserved              = $Reserved
        Pending               = $Pending
        StatsMissing          = $StatsMissing
        FailoverInfoAvailable = $FailoverInfoAvailable
        FailoverRelationship  = $FailoverRelationship
        FailoverPartner       = $FailoverPartner
        FailoverMode          = $FailoverMode
        FailoverState         = $FailoverState
        FailoverServerRole    = $FailoverServerRole
        DNSServers            = $null
        Option60              = $null
        Option43              = $null
        AllOptions            = $null
        OptionsFailed         = $false
        TotalAddresses        = $null
        PercentageInUse       = $null
        Redundancy            = $null
        Notes                 = $null
    }
}
# ============================================
# DHCP COLLECTION (runspace workers + state machine)
# ============================================
# Per server: reachability check + 3 bulk RPC calls (scopes, statistics, failover).
# Options (DNS/60/43/all) are ONE Get-DhcpServerv4OptionValue -Brief call per scope,
# spread over the pool in batches so one big server does not serialize the run.

function Test-DhcpServerReachable {
    <#
    .SYNOPSIS
        Fast reachability check that needs no admin rights: ICMP echo, then TCP 135
        (RPC endpoint mapper used by the DHCP management API). A server that blocks
        ping but answers RPC is still queried.
    .DESCRIPTION
        One lost packet must not drop a server (and all of its scopes) from a run,
        so a failed check is repeated once with twice the timeouts.
    #>
    param([string]$ComputerName, [int]$PingTimeoutMs = 1000, [int]$TcpTimeoutMs = 1500, [int]$Attempts = 2)
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $ping = [System.Net.NetworkInformation.Ping]::new()
        try {
            if ($ping.Send($ComputerName, $PingTimeoutMs * $attempt).Status -eq [System.Net.NetworkInformation.IPStatus]::Success) { return $true }
        } catch { } finally { $ping.Dispose() }
        $tcp = [System.Net.Sockets.TcpClient]::new()
        try {
            $ar = $tcp.BeginConnect($ComputerName, 135, $null, $null)
            if ($ar.AsyncWaitHandle.WaitOne($TcpTimeoutMs * $attempt) -and $tcp.Connected) { return $true }
        } catch { } finally { $tcp.Close() }
    }
    return $false
}

$script:DhcpWorkerFunctions = @('Test-DhcpServerReachable')
$script:DhcpWorkerScripts = @{}

$script:DhcpWorkerScripts.Discover = @'
param($Item, $Shared)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    try { $null = Get-Command -Name Get-DhcpServerInDC -ErrorAction Stop } catch { Import-Module DhcpServer -ErrorAction Stop }
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($s in @(Get-DhcpServerInDC -ErrorAction Stop)) {
        if ($null -eq $s) { continue }
        $list.Add([pscustomobject]@{ Name = [string]$s.DnsName; IP = [string]$s.IPAddress })
    }
    # Different names registered with the same IP: look the names up now, so a stale
    # entry (server gone, address reused) is not taken for the live server
    $namesByIp = @{}
    foreach ($e in $list) {
        if (-not $e.IP -or -not $e.Name) { continue }
        if (-not $namesByIp.ContainsKey($e.IP)) { $namesByIp[$e.IP] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) }
        [void]$namesByIp[$e.IP].Add($e.Name)
    }
    $resolved = @{}
    foreach ($ip in @($namesByIp.Keys)) {
        if ($namesByIp[$ip].Count -lt 2) { continue }
        foreach ($n in $namesByIp[$ip]) {
            try { $resolved[$n] = @([System.Net.Dns]::GetHostAddresses($n) | ForEach-Object { $_.IPAddressToString }) }
            catch { $resolved[$n] = @() }
        }
    }
    [pscustomobject]@{ Success = $true; Servers = $list.ToArray(); Resolved = $resolved; Message = '' }
} catch {
    [pscustomobject]@{ Success = $false; Servers = @(); Message = $_.Exception.Message }
}
'@

$script:DhcpWorkerScripts.Server = @'
param($Item, $Shared)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$server = [string]$Item.Server
$out = [ordered]@{
    Server = $server; Success = $false; Reachable = $true; Cancelled = $false; Message = ''
    Rows = @(); ScopeCount = 0; MissingScopeIds = @(); NoStatsCount = 0; RelationshipCount = 0
    FailoverInfoAvailable = $false; FailoverError = ''; ElapsedMs = 0
}
try {
    # Second attempt after an error: give a busy server / network a moment first
    if ($Item.Retry) {
        $until = [DateTime]::UtcNow.AddMilliseconds([int]$Item.RetryDelayMs)
        while ([DateTime]::UtcNow -lt $until -and -not $Shared.Stop) { Start-Sleep -Milliseconds 100 }
        $sw.Restart()
    }
    if ($Shared.Stop) {
        $out.Cancelled = $true
        $out.Message = 'Cancelled'
    } elseif (-not (Test-DhcpServerReachable -ComputerName $server)) {
        $out.Reachable = $false
        $out.Message = 'Unreachable (no ping reply and RPC port 135 closed)'
    } else {
        try { $null = Get-Command -Name Get-DhcpServerv4Scope -ErrorAction Stop } catch { Import-Module DhcpServer -ErrorAction Stop }

        # 1 call: every scope on the server
        $scopes = @(Get-DhcpServerv4Scope -ComputerName $server -ErrorAction Stop -WarningAction SilentlyContinue)

        if ($Item.ScopeIds) {
            $want = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($id in $Item.ScopeIds) { [void]$want.Add([string]$id) }
            $kept = [System.Collections.Generic.List[object]]::new()
            foreach ($sc in $scopes) { if ($want.Remove($sc.ScopeId.ToString())) { $kept.Add($sc) } }
            $out.MissingScopeIds = @($want)
            $scopes = $kept.ToArray()
        } elseif ($Item.NameFilters) {
            $kept = [System.Collections.Generic.List[object]]::new()
            foreach ($sc in $scopes) {
                $scopeName = [string]$sc.Name
                foreach ($f in $Item.NameFilters) {
                    if ($f -and $scopeName.IndexOf([string]$f, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $kept.Add($sc); break }
                }
            }
            $scopes = $kept.ToArray()
        }

        if ($scopes.Count -gt 0) {
            # 1 call: statistics for every scope (indexed, not searched per scope)
            $statsById = @{}
            foreach ($st in @(Get-DhcpServerv4ScopeStatistics -ComputerName $server -ErrorAction Stop)) {
                if ($null -ne $st) { $statsById[$st.ScopeId.ToString()] = $st }
            }
            # A scope missing from the bulk answer is asked for on its own before
            # it is reported without numbers (it is never dropped silently)
            foreach ($sc in $scopes) {
                $id = $sc.ScopeId.ToString()
                if ($statsById.ContainsKey($id)) { continue }
                try {
                    $one = @(Get-DhcpServerv4ScopeStatistics -ComputerName $server -ScopeId $id -ErrorAction Stop)
                    if ($one.Count -gt 0 -and $null -ne $one[0]) { $statsById[$id] = $one[0] }
                } catch { }
            }

            # 1 call: failover relationships = which scopes are replicated, and with whom
            $foById = @{}
            try {
                $rels = @(Get-DhcpServerv4Failover -ComputerName $server -ErrorAction Stop)
                foreach ($rel in $rels) {
                    if ($null -eq $rel) { continue }
                    $out.RelationshipCount++
                    foreach ($sid in @($rel.ScopeId)) { if ($null -ne $sid) { $foById[$sid.ToString()] = $rel } }
                }
                $out.FailoverInfoAvailable = $true
            } catch {
                $foMessage = $_.Exception.Message
                if ($foMessage -match 'procedure number is out of range|1745|0x6D1') {
                    # DHCP servers older than Windows Server 2012 cannot do failover at all
                    $out.FailoverInfoAvailable = $true
                } else {
                    $out.FailoverError = $foMessage
                }
            }

            $rows = [System.Collections.Generic.List[object]]::new()
            $noStats = 0
            foreach ($sc in $scopes) {
                $id = $sc.ScopeId.ToString()
                $st = $statsById[$id]
                $statsMissing = ($null -eq $st)
                if ($statsMissing) {
                    $noStats++
                    $free = 0; $used = 0; $resv = 0; $pend = 0
                } else {
                    $free = $st.AddressesFree; if ($null -eq $free) { $free = $st.Free }
                    $used = $st.AddressesInUse; if ($null -eq $used) { $used = $st.InUse }
                    $resv = $st.ReservedAddress; if ($null -eq $resv) { $resv = $st.Reserved }
                    $pend = $st.PendingOffers; if ($null -eq $pend) { $pend = $st.Pending }
                }
                $rel = $foById[$id]
                $desc = [string]$sc.Description
                if ([string]::IsNullOrWhiteSpace($desc)) { $desc = [string]$sc.Name }
                # Field list must match New-DhcpScopeRow (checked by the test suite)
                $rows.Add([pscustomobject][ordered]@{
                    ScopeId               = $id
                    DHCPServer            = $server
                    Name                  = [string]$sc.Name
                    Description           = $desc
                    SubnetMask            = [string]$sc.SubnetMask
                    StartRange            = [string]$sc.StartRange
                    EndRange              = [string]$sc.EndRange
                    ScopeState            = [string]$sc.State
                    AddressesFree         = [long]$free
                    AddressesInUse        = [long]$used
                    Reserved              = [long]$resv
                    Pending               = [long]$pend
                    StatsMissing          = $statsMissing
                    FailoverInfoAvailable = [bool]$out.FailoverInfoAvailable
                    FailoverRelationship  = $(if ($rel) { [string]$rel.Name } else { '' })
                    FailoverPartner       = $(if ($rel) { [string]$rel.PartnerServer } else { '' })
                    FailoverMode          = $(if ($rel) { [string]$rel.Mode } else { '' })
                    FailoverState         = $(if ($rel) { [string]$rel.State } else { '' })
                    FailoverServerRole    = $(if ($rel) { [string]$rel.ServerRole } else { '' })
                    DNSServers            = $null
                    Option60              = $null
                    Option43              = $null
                    AllOptions            = $null
                    OptionsFailed         = $false
                    TotalAddresses        = $null
                    PercentageInUse       = $null
                    Redundancy            = $null
                    Notes                 = $null
                })
            }
            $out.Rows = $rows.ToArray()
            $out.ScopeCount = $rows.Count
            $out.NoStatsCount = $noStats
            if ($noStats -gt 0) { $out.Message = "$noStats scope(s) returned no statistics (listed with 0 / 0, see Notes)" }
        }
        $out.Success = $true
    }
} catch {
    $out.Message = $_.Exception.Message
}
$out.ElapsedMs = [int]$sw.ElapsedMilliseconds
[pscustomobject]$out
'@

$script:DhcpWorkerScripts.Options = @'
param($Item, $Shared)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$scopeOptions = @{}
$failures = @{}
$message = ''
try {
    $failingSince = $null
    if ($Item.Retry) {
        # Second try (the scopes that failed): give the server a moment first. It
        # runs as one batch, so the server is asked one scope at a time.
        $until = [DateTime]::UtcNow.AddMilliseconds([int]$Item.RetryDelayMs)
        while ([DateTime]::UtcNow -lt $until -and -not $Shared.Stop) { Start-Sleep -Milliseconds 100 }
        if (-not $Shared.Stop -and -not (Test-DhcpServerReachable -ComputerName ([string]$Item.Server))) {
            throw 'Unreachable (no ping reply and RPC port 135 closed)'
        }
    }
    try { $null = Get-Command -Name Get-DhcpServerv4OptionValue -ErrorAction Stop } catch { Import-Module DhcpServer -ErrorAction Stop }
    # -Brief skips the option-name lookup (Microsoft's recommended fast path)
    $useBrief = (Get-Command -Name Get-DhcpServerv4OptionValue).Parameters.ContainsKey('Brief')
    foreach ($id in $Item.ScopeIds) {
        if ($Shared.Stop) { break }
        if ($null -ne $failingSince -and ([DateTime]::UtcNow - $failingSince).TotalMilliseconds -ge [int]$Item.GiveUpMs) {
            # Every lookup has failed for a while: do not wait out each remaining one
            $failures[[string]$id] = 'Skipped - every lookup on this server had failed for {0:N0} s' -f ([int]$Item.GiveUpMs / 1000)
            continue
        }
        $callStart = [DateTime]::UtcNow
        $entry = @{ DNSServers = $null; Option60 = $null; Option43 = $null; AllOptions = $null }
        try {
            $splat = @{ ComputerName = [string]$Item.Server; ScopeId = [string]$id; ErrorAction = 'Stop' }
            if ($useBrief) { $splat.Brief = $true }
            $all = [System.Collections.Generic.List[string]]::new()
            # One call returns every option set at scope level (same values the
            # old per-option calls returned)
            foreach ($opt in @(Get-DhcpServerv4OptionValue @splat)) {
                if ($null -eq $opt) { continue }
                $oid = [int]$opt.OptionId
                $vals = @($opt.Value)
                switch ($oid) {
                    6 { $entry.DNSServers = $vals -join ',' }
                    60 { $entry.Option60 = $vals -join ',' }
                    43 { $entry.Option43 = $vals -join ',' }
                }
                $all.Add(('{0}:{1}' -f $oid, ($vals -join ';')))
            }
            if ($all.Count -gt 0) { $entry.AllOptions = $all -join ' | ' }
            $scopeOptions[[string]$id] = $entry
            $failingSince = $null
        } catch {
            # A failed lookup is reported as failed, never as "no options set"
            $failures[[string]$id] = $_.Exception.Message
            if ($Item.Retry -and $null -eq $failingSince) { $failingSince = $callStart }
        }
    }
} catch {
    # The whole batch failed (e.g. the module did not load): every scope not answered failed
    $message = $_.Exception.Message
    foreach ($id in $Item.ScopeIds) {
        $key = [string]$id
        if (-not $scopeOptions.ContainsKey($key) -and -not $failures.ContainsKey($key)) { $failures[$key] = $message }
    }
}
[pscustomobject]@{ Server = [string]$Item.Server; ScopeOptions = $scopeOptions; Failures = $failures; Cancelled = [bool]$Shared.Stop; Message = $message }
'@

$script:DhcpWorkerScripts.ScopeList = @'
param($Item, $Shared)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$server = [string]$Item.Server
$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    if ($Item.Retry) {
        $until = [DateTime]::UtcNow.AddMilliseconds([int]$Item.RetryDelayMs)
        while ([DateTime]::UtcNow -lt $until -and -not $Shared.Stop) { Start-Sleep -Milliseconds 100 }
        $sw.Restart()
    }
    if ($Shared.Stop) { return [pscustomobject]@{ Server = $server; Success = $false; Scopes = @(); Message = 'Cancelled'; ElapsedMs = 0 } }
    if (-not (Test-DhcpServerReachable -ComputerName $server)) {
        return [pscustomobject]@{ Server = $server; Success = $false; Scopes = @(); Message = 'Unreachable (no ping reply and RPC port 135 closed)'; ElapsedMs = [int]$sw.ElapsedMilliseconds }
    }
    try { $null = Get-Command -Name Get-DhcpServerv4Scope -ErrorAction Stop } catch { Import-Module DhcpServer -ErrorAction Stop }
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($sc in @(Get-DhcpServerv4Scope -ComputerName $server -ErrorAction Stop -WarningAction SilentlyContinue)) {
        if ($null -eq $sc) { continue }
        # Same shape as the existing encrypted cache files
        $list.Add([pscustomobject][ordered]@{
            ScopeId     = $sc.ScopeId.ToString()
            Name        = [string]$sc.Name
            Description = $(if ($sc.Description) { [string]$sc.Description } else { '' })
            Server      = $server
            SubnetMask  = [string]$sc.SubnetMask
            StartRange  = [string]$sc.StartRange
            EndRange    = [string]$sc.EndRange
            State       = [string]$sc.State
            DisplayName = ('{0} ({1}) - {2}' -f $sc.Name, $sc.ScopeId, $server)
        })
    }
    [pscustomobject]@{ Server = $server; Success = $true; Scopes = $list.ToArray(); Message = ''; ElapsedMs = [int]$sw.ElapsedMilliseconds }
} catch {
    [pscustomobject]@{ Server = $server; Success = $false; Scopes = @(); Message = $_.Exception.Message; ElapsedMs = [int]$sw.ElapsedMilliseconds }
}
'@

function New-DhcpCollectionState {
    <#
    .SYNOPSIS
        State for one statistics collection run.
    .PARAMETER Request
        @{ Servers; ScopeIdsByServer; NameFilters; IncludeDNS; IncludeOption60;
           IncludeOption43; ShowAllOptions; Throttle; OptionBatchSize }
    #>
    param([hashtable]$Request)
    if (-not $Request.OptionBatchSize) { $Request.OptionBatchSize = 25 }
    if (-not $Request.Throttle) { $Request.Throttle = 20 }
    if ($null -eq $Request.RetryDelayMs) { $Request.RetryDelayMs = 3000 }
    # Second try of option lookups: a server failing every lookup for this long is skipped
    if ($null -eq $Request.RetryGiveUpMs) { $Request.RetryGiveUpMs = 60000 }
    return @{
        Request           = $Request
        Rows              = [System.Collections.Generic.List[object]]::new()
        RowIndex          = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
        Servers           = [System.Collections.Generic.List[string]]::new()
        ServerResults     = [System.Collections.Generic.List[object]]::new()
        ServersDone       = 0
        ServersFailed     = 0
        Retries           = 0
        RetryRecovered    = 0
        OptionBatches     = 0
        OptionBatchesDone = 0
        OptionScopes      = 0
        OptionScopesDone  = 0
        OptionPending     = @{}   # server -> @{ Batches = first-try batches still running; Failed = scope ID -> error }
        OptionRetries     = 0     # scope lookups asked a second time
        OptionRetriesDone = 0
        OptionRecovered   = 0     # ... that succeeded on it
        OptionFailures    = 0     # scope lookups that failed twice
        OptionFailed      = [System.Collections.Generic.List[object]]::new()
        Log               = [System.Collections.Generic.List[object]]::new()
        Error             = $null
        Stopwatch         = [System.Diagnostics.Stopwatch]::StartNew()
    }
}

function Add-DhcpLog {
    param($State, [string]$Color, [string]$Message)
    $State.Log.Add(@{ Color = $Color; Message = $Message })
}

function Test-DhcpOptionsRequested {
    param([hashtable]$Request)
    return [bool]($Request.IncludeDNS -or $Request.IncludeOption60 -or $Request.IncludeOption43 -or $Request.ShowAllOptions)
}

function New-DhcpServerTasks {
    param($State, [string[]]$Servers)
    $req = $State.Request
    $tasks = [System.Collections.Generic.List[object]]::new()
    foreach ($s in $Servers) {
        $State.Servers.Add($s)
        $ids = $null
        if ($req.ScopeIdsByServer -and $req.ScopeIdsByServer.ContainsKey($s)) { $ids = [string[]]@($req.ScopeIdsByServer[$s]) }
        $tasks.Add(@{ Kind = 'Server'; Item = @{ Server = $s; ScopeIds = $ids; NameFilters = $req.NameFilters } })
    }
    Add-DhcpLog $State 'Info' ("Querying {0} server(s), up to {1} in parallel..." -f $Servers.Count, $req.Throttle)
    return $tasks.ToArray()
}

function Get-DhcpStartTasks {
    param($State)
    $servers = @($State.Request.Servers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($servers.Count -gt 0) { return @(New-DhcpServerTasks -State $State -Servers $servers) }
    Add-DhcpLog $State 'Info' 'No servers selected - discovering DHCP servers in Active Directory...'
    return @(@{ Kind = 'Discover'; Item = @{} })
}

function Receive-DhcpTaskResult {
    <#
    .SYNOPSIS
        Folds one finished worker result into the collection state.
    .OUTPUTS
        Follow-up task descriptors (wrap the call in @() - may be none or one).
    #>
    param($State, [hashtable]$Descriptor, [hashtable]$Result)
    $req = $State.Request
    $out = $Result.Output
    $next = [System.Collections.Generic.List[object]]::new()

    switch ($Descriptor.Kind) {
        'Discover' {
            if ($out -and $out.Success) {
                $mergeNotes = [System.Collections.Generic.List[string]]::new()
                $names = @(Merge-DhcpServerList -Entries @($out.Servers) -Resolved $out.Resolved -Notes $mergeNotes)
                if ($names.Count -eq 0) {
                    $State.Error = 'No DHCP servers are registered in Active Directory.'
                    Add-DhcpLog $State 'Error' $State.Error
                } else {
                    foreach ($line in @(Get-DhcpServerListLines -EntryCount @($out.Servers).Count -ServerCount $names.Count -Notes $mergeNotes)) { $State.Log.Add($line) }
                    foreach ($t in @(New-DhcpServerTasks -State $State -Servers $names)) { $next.Add($t) }
                }
            } else {
                $msg = if ($out) { $out.Message } else { $Result.Error }
                $State.Error = "Failed to discover DHCP servers: $msg"
                Add-DhcpLog $State 'Error' $State.Error
            }
        }
        'Server' {
            $server = [string]$Descriptor.Item.Server
            $isRetry = [bool]$Descriptor.Item.Retry
            $failed = ($null -eq $out) -or (-not $out.Success)
            $cancelled = ($null -ne $out) -and [bool]$out.Cancelled
            if ($failed -and -not $cancelled -and -not $isRetry) {
                # One lost packet, busy server or RPC hiccup must not drop a server
                # (and every scope only it serves): try once more after a pause
                $reason = if ($null -ne $out) { $out.Message } elseif ($Result.Error) { $Result.Error } else { 'No result returned' }
                $retryItem = @{}
                foreach ($k in $Descriptor.Item.Keys) { $retryItem[$k] = $Descriptor.Item[$k] }
                $retryItem.Retry = 1
                $retryItem.RetryDelayMs = $req.RetryDelayMs
                $next.Add(@{ Kind = 'Server'; Item = $retryItem })
                $State.Retries++
                Add-DhcpLog $State 'Warning' ('{0} - {1} - trying again' -f $server, $reason)
                return $next.ToArray()
            }
            $State.ServersDone++
            if ($isRetry -and -not $failed) { $State.RetryRecovered++ }
            $prefix = '[{0}/{1}] {2}' -f $State.ServersDone, $State.Servers.Count, $server
            if ($isRetry) { $prefix += ' (2nd try)' }
            $status = 'OK'; $message = ''; $scopeCount = 0; $seconds = 0
            if ($null -eq $out) {
                $status = 'Failed'
                $message = if ($Result.Error) { $Result.Error } else { 'No result returned' }
            } elseif (-not $out.Success) {
                $status = if ($out.Reachable) { 'Failed' } else { 'Unreachable' }
                $message = $out.Message
                $seconds = $out.ElapsedMs / 1000
            } else {
                $rows = @($out.Rows)
                foreach ($row in $rows) {
                    $State.Rows.Add($row)
                    $State.RowIndex[$server + '|' + $row.ScopeId] = $row
                }
                $scopeCount = $rows.Count
                $seconds = $out.ElapsedMs / 1000
                $fo = if ($out.FailoverInfoAvailable) { "$($out.RelationshipCount) failover relationship(s)" } else { 'failover info unavailable' }
                $line = '{0} - {1} scope(s), {2} ({3:N1}s)' -f $prefix, $scopeCount, $fo, $seconds
                if ($out.Message) { $line += " - $($out.Message)" }
                $missing = @($out.MissingScopeIds).Count
                if ($missing -gt 0) { $line += " - $missing selected scope(s) no longer exist" }
                Add-DhcpLog $State $(if ($out.FailoverInfoAvailable) { 'Success' } else { 'Warning' }) $line
                $message = $out.Message

                if ((Test-DhcpOptionsRequested $req) -and $scopeCount -gt 0) {
                    $batchCount = 0
                    $order = [System.Collections.Generic.List[string]]::new()
                    $batch = [System.Collections.Generic.List[string]]::new()
                    foreach ($row in $rows) {
                        $order.Add([string]$row.ScopeId)
                        $batch.Add([string]$row.ScopeId)
                        if ($batch.Count -ge $req.OptionBatchSize) {
                            $next.Add(@{ Kind = 'Options'; Item = @{ Server = $server; ScopeIds = $batch.ToArray() } })
                            $batchCount++
                            $batch.Clear()
                        }
                    }
                    if ($batch.Count -gt 0) {
                        $next.Add(@{ Kind = 'Options'; Item = @{ Server = $server; ScopeIds = $batch.ToArray() } })
                        $batchCount++
                    }
                    $State.OptionBatches += $batchCount
                    $State.OptionScopes += $scopeCount
                    $State.OptionPending[$server] = @{ Batches = $batchCount; Order = $order.ToArray(); Failed = @{} }
                }
            }
            if ($status -ne 'OK') {
                $State.ServersFailed++
                Add-DhcpLog $State 'Error' ('{0} - {1}: {2}' -f $prefix, $status.ToUpper(), $message)
            }
            $State.ServerResults.Add([pscustomobject][ordered]@{
                Server = $server; Status = $status; Scopes = $scopeCount; Seconds = [math]::Round($seconds, 1); Message = $message
            })
        }
        'Options' {
            $State.OptionBatchesDone++
            $server = [string]$Descriptor.Item.Server
            $isRetry = [bool]$Descriptor.Item.Retry
            $ids = @($Descriptor.Item.ScopeIds)
            $answers = @{}
            $failures = @{}
            if ($null -eq $out) {
                # The batch itself failed: none of its scopes were read
                $reason = if ($Result.Error) { $Result.Error } else { 'No result returned' }
                foreach ($id in $ids) { $failures[[string]$id] = $reason }
            } else {
                if ($out.ScopeOptions) { $answers = $out.ScopeOptions }
                if ($out.Failures) { $failures = $out.Failures }
            }
            foreach ($id in @($answers.Keys)) {
                $row = $null
                if ($State.RowIndex.TryGetValue($server + '|' + $id, [ref]$row)) {
                    $v = $answers[$id]
                    if ($req.IncludeDNS) { $row.DNSServers = $v.DNSServers }
                    if ($req.IncludeOption60) { $row.Option60 = $v.Option60 }
                    if ($req.IncludeOption43) { $row.Option43 = $v.Option43 }
                    if ($req.ShowAllOptions) { $row.AllOptions = $v.AllOptions }
                }
            }
            # Failed scopes in the order they were asked for
            $failedIds = [System.Collections.Generic.List[string]]::new()
            foreach ($id in $ids) { if ($failures.ContainsKey([string]$id)) { $failedIds.Add([string]$id) } }

            if ($isRetry) {
                $State.OptionRetriesDone += $ids.Count
                $State.OptionRecovered += $answers.Count
                if ($failedIds.Count -gt 0) {
                    foreach ($id in $failedIds) { Set-DhcpOptionsFailed -State $State -Server $server -ScopeId $id -Message ([string]$failures[$id]) }
                    $shown = @($failedIds | Select-Object -First 5) -join ', '
                    if ($failedIds.Count -gt 5) { $shown += " and $($failedIds.Count - 5) more" }
                    Add-DhcpLog $State 'Error' ('{0} - options still unreadable on the second try for {1} scope(s): {2} ({3})' -f $server, $failedIds.Count, $shown, $failures[$failedIds[0]])
                }
                return $next.ToArray()
            }

            # First try: failures wait until every batch of this server is back, then
            # get ONE second try together (one scope at a time, after a pause) - the
            # server is no longer busy with the parallel first round by then
            $State.OptionScopesDone += $ids.Count
            $pending = $State.OptionPending[$server]
            if ($null -eq $pending) {
                $pending = @{ Batches = 1; Order = [string[]]$ids; Failed = @{} }
                $State.OptionPending[$server] = $pending
            }
            foreach ($id in $failedIds) { $pending.Failed[$id] = [string]$failures[$id] }
            $pending.Batches--
            if ($pending.Batches -le 0 -and $pending.Failed.Count -gt 0) {
                $retryIds = [string[]]@(foreach ($id in $pending.Order) { if ($pending.Failed.ContainsKey($id)) { $id } })
                $firstReason = $pending.Failed[$retryIds[0]]
                if ($null -ne $out -and $out.Cancelled) {
                    foreach ($id in $retryIds) { Set-DhcpOptionsFailed -State $State -Server $server -ScopeId $id -Message $pending.Failed[$id] }
                } else {
                    $next.Add(@{ Kind = 'Options'; Item = @{ Server = $server; ScopeIds = $retryIds; Retry = 1; RetryDelayMs = $req.RetryDelayMs; GiveUpMs = $req.RetryGiveUpMs } })
                    $State.OptionBatches++
                    $State.OptionRetries += $retryIds.Count
                    Add-DhcpLog $State 'Warning' ('{0} - options could not be read for {1} scope(s) ({2}) - trying them again, one at a time' -f $server, $retryIds.Count, $firstReason)
                }
                $pending.Failed.Clear()
            }
        }
    }
    return $next.ToArray()
}

function Set-DhcpOptionsFailed {
    # Marks a scope whose options could not be read (after the second try): its
    # option columns say so instead of looking like "no option set"
    param($State, [string]$Server, [string]$ScopeId, [string]$Message)
    $req = $State.Request
    $row = $null
    if ($State.RowIndex.TryGetValue($Server + '|' + $ScopeId, [ref]$row)) {
        $row.OptionsFailed = $true
        $marker = '(lookup failed)'
        if ($req.IncludeDNS) { $row.DNSServers = $marker }
        if ($req.IncludeOption60) { $row.Option60 = $marker }
        if ($req.IncludeOption43) { $row.Option43 = $marker }
        if ($req.ShowAllOptions) { $row.AllOptions = $marker }
    }
    $State.OptionFailures++
    $State.OptionFailed.Add([pscustomobject]@{ Server = $Server; ScopeId = $ScopeId; Message = $Message })
}

function Get-DhcpSummaryLines {
    <#
    .SYNOPSIS
        Human-readable summary of an analysis (de-duplicated capacity etc).
    #>
    param($Analysis, $State)
    $s = $Analysis.Summary
    $lines = [System.Collections.Generic.List[object]]::new()
    if ($State) {
        $ok = $State.ServersDone - $State.ServersFailed
        $lines.Add(@{ Color = 'Info'; Message = ('Collected {0} scope row(s) from {1}/{2} server(s) in {3:N1}s' -f $s.ServerRows, $ok, $State.Servers.Count, $State.Stopwatch.Elapsed.TotalSeconds) })
        if ($State.Retries -gt 0) {
            $lines.Add(@{ Color = 'Info'; Message = ('{0} server(s) needed a second try - {1} succeeded on it' -f $State.Retries, $State.RetryRecovered) })
        }
        $failedServers = @($State.ServerResults | Where-Object { $_.Status -ne 'OK' })
        if ($failedServers.Count -gt 0) {
            $names = @($failedServers | Select-Object -First 10 | ForEach-Object { $_.Server })
            $more = if ($failedServers.Count -gt 10) { " and $($failedServers.Count - 10) more" } else { '' }
            $lines.Add(@{ Color = 'Error'; Message = ('{0} server(s) could not be read: {1}{2} - scopes that only they serve are missing (failover partners still report theirs)' -f $failedServers.Count, ($names -join ', '), $more) })
        }
        if ($State.OptionRetries -gt 0) {
            $lines.Add(@{ Color = 'Info'; Message = ('Options: {0} scope lookup(s) needed a second try - {1} succeeded on it' -f $State.OptionRetries, $State.OptionRecovered) })
        }
        if ($State.OptionFailures -gt 0) {
            $lines.Add(@{ Color = 'Warning'; Message = ("Options: {0} of {1} scope lookup(s) failed twice - their option columns say '(lookup failed)':" -f $State.OptionFailures, $State.OptionScopes) })
            foreach ($f in @($State.OptionFailed | Select-Object -First 10)) {
                $lines.Add(@{ Color = 'Warning'; Message = ('  {0,-15} {1}: {2}' -f $f.ScopeId, $f.Server, $f.Message) })
            }
            if ($State.OptionFailed.Count -gt 10) { $lines.Add(@{ Color = 'Warning'; Message = ('  ... and {0} more' -f ($State.OptionFailed.Count - 10)) }) }
        }
    }
    $unique = 'Unique scopes: {0:N0} (active {1:N0}, inactive {2:N0})' -f $s.UniqueScopes, $s.ActiveScopes, $s.InactiveScopes
    if ($s.ServerRows -gt $s.UniqueScopes) {
        $unique += (' from {0:N0} scope rows - {1:N0} row(s) are the same scope on another server (failover partner or split scope) and count once' -f $s.ServerRows, ($s.ServerRows - $s.UniqueScopes))
    }
    $lines.Add(@{ Color = 'Info'; Message = $unique })
    if ($State) {
        # (assigned first: the function returns its list of groups as one array)
        $identical = Find-DhcpIdenticalServers -Rows $State.Rows.ToArray()
        foreach ($twins in $identical) {
            $lines.Add(@{ Color = 'Warning'; Message = ('{0} returned identical scopes (same IDs, names, ranges and pool sizes) without a failover relationship - probably one server listed twice in Active Directory under different names, so its scopes are counted twice' -f (@($twins) -join ' and ')) })
        }
    }
    $lines.Add(@{ Color = 'Info'; Message = ('Redundancy: failover {0} (degraded {1}) | single server {2} | split {3} | mixed {4} | unknown {5}' -f $s.FailoverScopes, $s.DegradedFailover, $s.SingleServer, $s.SplitScopes, $s.MixedScopes, $s.UnknownScopes) })
    if ($s.NoStatsRows -gt 0) {
        $lines.Add(@{ Color = 'Warning'; Message = ('{0} scope(s) returned no statistics, even when asked one by one - listed with 0 / 0 (see Notes)' -f $s.NoStatsRows) })
    }
    if ($s.DifferentNameScopes -gt 0) {
        $lines.Add(@{ Color = 'Warning'; Message = ('{0} scope ID(s) exist on several servers under different scope names - probably separate networks reusing the subnet. The per-server export lists each one; the grouped export shows each scope ID once (see Notes)' -f $s.DifferentNameScopes) })
    }
    if ($s.OverlapScopes -gt 0) {
        $lines.Add(@{ Color = 'Warning'; Message = ('{0} scope(s) run on several servers without failover and their pools overlap - counted at most once per address (see Notes)' -f $s.OverlapScopes) })
    }
    $lines.Add(@{ Color = 'Success'; Message = ('Capacity (active, de-duplicated): {0:N0} addresses | in use {1:N0} ({2}%) | free {3:N0}' -f $s.TotalAddresses, $s.AddressesInUse, $s.PercentageInUse, $s.AddressesFree) })
    $warnColor = if ($s.ScopesOver90 -gt 0) { 'Warning' } else { 'Info' }
    $lines.Add(@{ Color = $warnColor; Message = ('Scopes >= 90% full: {0} | >= 80% full: {1}' -f $s.ScopesOver90, $s.ScopesOver80) })
    if (@($s.Top).Count -gt 0) {
        $lines.Add(@{ Color = 'Info'; Message = 'Fullest scopes:' })
        foreach ($g in $s.Top) {
            $lines.Add(@{ Color = $(if ($g.PercentageInUse -ge 90) { 'Warning' } else { 'Info' }); Message = ('  {0,6}%  {1,-15} {2}' -f $g.PercentageInUse, $g.ScopeId, $g.Description) })
        }
    }
    return $lines.ToArray()
}

function Get-DhcpServerListLines {
    # Log lines for "N Active Directory entries -> M servers", with every skipped entry
    param([int]$EntryCount, [int]$ServerCount, [AllowNull()][System.Collections.Generic.List[string]]$Notes)
    $lines = [System.Collections.Generic.List[object]]::new()
    $lines.Add(@{ Color = 'Success'; Message = ('Active Directory lists {0} DHCP server entr{1} - {2} server(s) to query' -f $EntryCount, $(if ($EntryCount -eq 1) { 'y' } else { 'ies' }), $ServerCount) })
    if ($Notes) {
        foreach ($n in $Notes) {
            $color = if ($n -like '*stale*' -or $n -like '*both are queried*') { 'Warning' } else { 'Info' }
            $lines.Add(@{ Color = $color; Message = "  $n" })
        }
    }
    return $lines.ToArray()
}

function Find-DhcpIdenticalServers {
    <#
    .SYNOPSIS
        Groups of servers that returned exactly the same scopes (IDs, names, ranges,
        states and pool sizes) without a failover relationship between them -
        usually one server listed twice in Active Directory under two names.
    .DESCRIPTION
        Pool size (free + in use) is part of the comparison, so the two halves of a
        split scope (different exclusions) and failover partners are not reported.
    #>
    param([AllowEmptyCollection()][object[]]$Rows)
    $scopesByServer = @{}
    $partners = @{}
    foreach ($r in $Rows) {
        $server = [string]$r.DHCPServer
        if (-not $scopesByServer.ContainsKey($server)) {
            $scopesByServer[$server] = [System.Collections.Generic.List[string]]::new()
            $partners[$server] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }
        $pool = [long]$r.AddressesFree + [long]$r.AddressesInUse
        $scopesByServer[$server].Add(('{0}|{1}|{2}|{3}|{4}|{5}' -f $r.ScopeId, $r.Name, $r.StartRange, $r.EndRange, $r.ScopeState, $pool).ToLowerInvariant())
        if ($r.FailoverPartner) { [void]$partners[$server].Add((Get-DhcpServerShortName -Name ([string]$r.FailoverPartner))) }
    }
    $serversBySignature = @{}
    foreach ($server in $scopesByServer.Keys) {
        $items = $scopesByServer[$server].ToArray()
        [Array]::Sort($items, [System.StringComparer]::Ordinal)
        $signature = [string]::Join("`n", $items)
        if (-not $serversBySignature.ContainsKey($signature)) { $serversBySignature[$signature] = [System.Collections.Generic.List[string]]::new() }
        $serversBySignature[$signature].Add($server)
    }
    $groups = [System.Collections.Generic.List[object]]::new()
    foreach ($signature in $serversBySignature.Keys) {
        $servers = $serversBySignature[$signature]
        if ($servers.Count -lt 2) { continue }
        $linked = $false
        foreach ($a in $servers) {
            foreach ($b in $servers) {
                if ($a -ne $b -and $partners[$a].Contains((Get-DhcpServerShortName -Name $b))) { $linked = $true }
            }
        }
        if (-not $linked) {
            $sorted = $servers.ToArray()
            [Array]::Sort($sorted, [System.StringComparer]::OrdinalIgnoreCase)
            $groups.Add($sorted)
        }
    }
    return ,$groups.ToArray()
}

function Compare-DhcpScopeCache {
    <#
    .SYNOPSIS
        Explains "missing" scopes: every cached scope on a server queried in this run
        that the run did not return, with the reason (server failed / scope removed).
    .OUTPUTS
        @{ Checked; Missing = Server, ScopeId, Name, Reason; NotInCache }
    #>
    param($State, [AllowEmptyCollection()][object[]]$CachedScopes)
    $results = @{}
    foreach ($r in $State.ServerResults) { $results[(Get-DhcpServerShortName -Name ([string]$r.Server))] = $r }
    $ignoreCase = [System.StringComparer]::OrdinalIgnoreCase
    $collected = [System.Collections.Generic.HashSet[string]]::new($ignoreCase)
    foreach ($row in $State.Rows) { [void]$collected.Add((Get-DhcpServerShortName -Name ([string]$row.DHCPServer)) + '|' + [string]$row.ScopeId) }
    $cached = [System.Collections.Generic.HashSet[string]]::new($ignoreCase)
    $missing = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $CachedScopes) {
        if ($null -eq $c -or -not $c.Server -or -not $c.ScopeId) { continue }
        $short = Get-DhcpServerShortName -Name ([string]$c.Server)
        $r = $results[$short]
        if ($null -eq $r) { continue }   # server was not part of this run
        $key = $short + '|' + [string]$c.ScopeId
        if (-not $cached.Add($key) -or $collected.Contains($key)) { continue }
        $reason = if ($r.Status -ne 'OK') { "$($r.Server) $($r.Status.ToLower()): $($r.Message)" } else { "no longer on $($r.Server) (deleted or moved)" }
        $missing.Add([pscustomobject]@{ Server = [string]$c.Server; ScopeId = [string]$c.ScopeId; Name = [string]$c.Name; Reason = $reason })
    }
    $notInCache = 0
    foreach ($k in $collected) { if (-not $cached.Contains($k)) { $notInCache++ } }
    return @{ Checked = $cached.Count; Missing = $missing.ToArray(); NotInCache = $notInCache }
}

function Get-DhcpCacheCheckLines {
    param($Comparison, [int]$MaxListed = 25)
    $lines = [System.Collections.Generic.List[object]]::new()
    if ($Comparison.Checked -eq 0) { return $lines.ToArray() }
    $miss = @($Comparison.Missing)
    if ($miss.Count -eq 0) {
        $lines.Add(@{ Color = 'Success'; Message = ('Scope cache check: all {0} cached scope(s) on the queried servers were collected' -f $Comparison.Checked) })
    } else {
        $lines.Add(@{ Color = 'Warning'; Message = ('Scope cache check: {0} of {1} cached scope(s) were NOT collected:' -f $miss.Count, $Comparison.Checked) })
        foreach ($grp in @($miss | Group-Object -Property Reason | Sort-Object -Property Count -Descending)) {
            $lines.Add(@{ Color = 'Warning'; Message = ('  {0} x {1}' -f $grp.Count, $grp.Name) })
        }
        foreach ($m in @($miss | Select-Object -First $MaxListed)) {
            $lines.Add(@{ Color = 'Info'; Message = ('    {0,-15} {1} ({2})' -f $m.ScopeId, $m.Name, $m.Server) })
        }
        if ($miss.Count -gt $MaxListed) { $lines.Add(@{ Color = 'Info'; Message = ('    ... and {0} more' -f ($miss.Count - $MaxListed)) }) }
    }
    if ($Comparison.NotInCache -gt 0) {
        $lines.Add(@{ Color = 'Info'; Message = ('{0} collected scope(s) are not in the scope cache yet - Refresh Cache to be able to select them' -f $Comparison.NotInCache) })
    }
    return $lines.ToArray()
}

function Get-DhcpExportColumns {
    param([hashtable]$Options, [switch]$Grouped)
    $cols = [System.Collections.Generic.List[string]]::new()
    foreach ($c in @('ScopeId', 'DHCPServer', 'Description', 'AddressesFree', 'AddressesInUse', 'PercentageInUse')) { $cols.Add($c) }
    if ($Options.IncludeDNS) { $cols.Add('DNSServers') }
    if ($Options.IncludeOption60) { $cols.Add('Option60') }
    if ($Options.IncludeOption43) { $cols.Add('Option43') }
    if ($Options.ShowAllOptions) { $cols.Add('AllOptions') }
    foreach ($c in @('TotalAddresses', 'ScopeState', 'Redundancy', 'FailoverPartner', 'FailoverState')) { $cols.Add($c) }
    if ($Grouped) { $cols.Add('ServerCount') }
    $cols.Add('Notes')
    return $cols.ToArray()
}
# ============================================
# DNA CENTER
# ============================================

$script:Dna = @{
    Token = $null; TokenExpiry = $null; Headers = $null; BaseUrl = $null; ServerName = $null
    Devices = @(); Selected = @(); DeviceById = @{}; Busy = $false; Shared = $null; Pool = $null
}
$script:DnaThrottle = 6
# Pause before the second try of requests that failed with a temporary error
$script:DnaRetryDelayMs = 5000

# GET worker for parallel requests; retries HTTP 429 (rate limit) with back-off
$script:DnaGetWorker = @'
param($Item, $Shared)
$ProgressPreference = 'SilentlyContinue'
for ($attempt = 1; $attempt -le 5; $attempt++) {
    try {
        $response = Invoke-RestMethod -Uri $Item.Url -Method Get -Headers $Shared.Headers -TimeoutSec $Shared.TimeoutSec -ErrorAction Stop
        return [pscustomobject]@{ Response = $response; Error = $null; Status = 200 }
    } catch {
        $status = 0
        $retryAfter = 0
        try {
            $status = [int]$_.Exception.Response.StatusCode
            [void][int]::TryParse([string]$_.Exception.Response.Headers['Retry-After'], [ref]$retryAfter)
        } catch { }
        if ($status -eq 429 -and $attempt -lt 5 -and -not $Shared.Stop) {
            Start-Sleep -Seconds ([Math]::Min(15, [Math]::Max($retryAfter, 2 * $attempt)))
            continue
        }
        return [pscustomobject]@{ Response = $null; Error = $_.Exception.Message; Status = $status }
    }
}
'@

# CLI Command Runner worker: submit -> poll task -> download output (one command, one device)
$script:DnaCommandWorker = @'
param($Item, $Shared)
$ProgressPreference = 'SilentlyContinue'
$base = $Shared.BaseUrl
$headers = $Shared.Headers
$result = [ordered]@{ Index = $Item.Index; Status = ''; FileResponse = $null; FileId = $null; Error = $null }
function Invoke-WithRetry([scriptblock]$Call) {
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try { return (& $Call) }
        catch {
            $code = 0
            try { $code = [int]$_.Exception.Response.StatusCode } catch { }
            if ($code -eq 429 -and $attempt -lt 5 -and -not $Shared.Stop) { Start-Sleep -Seconds (2 * $attempt) } else { throw }
        }
    }
}
try {
    $body = @{
        name        = 'GUI-Cmd-' + $Item.Hostname + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        commands    = @($Item.Command)
        deviceUuids = @($Item.DeviceId)
    } | ConvertTo-Json -Depth 5
    $submit = Invoke-WithRetry { Invoke-RestMethod -Uri "$base/dna/intent/api/v1/network-device-poller/cli/read-request" -Method Post -Headers $headers -Body $body -ContentType 'application/json' -TimeoutSec 30 -ErrorAction Stop }
    if (-not $submit -or -not $submit.response -or -not $submit.response.taskId) {
        $result.Status = 'Submit Failed'
    } else {
        $taskId = $submit.response.taskId
        $fileId = $null
        $failure = $null
        $deadline = [DateTime]::UtcNow.AddSeconds($Shared.MaxWaitSeconds)
        while ([DateTime]::UtcNow -lt $deadline -and -not $Shared.Stop) {
            Start-Sleep -Milliseconds 1500
            $task = (Invoke-WithRetry { Invoke-RestMethod -Uri "$base/dna/intent/api/v1/task/$taskId" -Method Get -Headers $headers -TimeoutSec 30 -ErrorAction Stop }).response
            if (-not $task) { continue }
            if ($task.isError) { $failure = if ($task.failureReason) { [string]$task.failureReason } else { 'Task reported an error' }; break }
            if ($task.endTime) {
                if ($task.additionalStatusURL -and $task.additionalStatusURL -match '/file/([a-f0-9\-]+)') { $fileId = $Matches[1] }
                elseif ($task.progress) {
                    try { $progress = $task.progress | ConvertFrom-Json; if ($progress.fileId) { $fileId = $progress.fileId } }
                    catch { if ($task.progress -match '"fileId"\s*:\s*"([^"]+)"') { $fileId = $Matches[1] } }
                }
                break
            }
        }
        if ($failure) {
            $result.Status = 'Failed'
            $result.Error = $failure
        } elseif ($Shared.Stop -and -not $fileId) {
            $result.Status = 'Cancelled'
        } elseif (-not $fileId) {
            $result.Status = 'Timeout'
        } else {
            $result.FileId = $fileId
            $result.FileResponse = Invoke-WithRetry { Invoke-RestMethod -Uri "$base/dna/intent/api/v1/file/$fileId" -Method Get -Headers $headers -TimeoutSec 30 -ErrorAction Stop }
            $result.Status = 'Downloaded'
        }
    }
} catch {
    $result.Status = 'Error'
    $result.Error = $_.Exception.Message
}
[pscustomobject]$result
'@

function Test-DNACTokenValid {
    if (-not $script:Dna.Token) { return $false }
    if ($script:Dna.TokenExpiry -and (Get-Date) -gt $script:Dna.TokenExpiry.AddMinutes(-5)) { return $false }
    return $true
}

function Connect-DNACenter {
    param([string]$DnaCenter, [string]$Username, [string]$Password, [System.Windows.Forms.RichTextBox]$LogBox)
    $base64AuthInfo = $null
    try {
        if ([string]::IsNullOrWhiteSpace($Username) -or [string]::IsNullOrWhiteSpace($Password)) {
            Write-Log -Message 'Username and password are required' -Color 'Red' -LogBox $LogBox
            return $false
        }
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(('{0}:{1}' -f $Username, $Password)))
        $headers = @{ 'Authorization' = "Basic $base64AuthInfo"; 'Content-Type' = 'application/json' }
        Write-Log -Message 'Authenticating to DNA Center...' -Color 'Yellow' -LogBox $LogBox
        $response = Invoke-RestMethod -Uri "$DnaCenter/dna/system/api/v1/auth/token" -Method Post -Headers $headers -TimeoutSec 30
        if ($response -and $response.Token) {
            $script:Dna.Token = $response.Token
            $script:Dna.TokenExpiry = (Get-Date).AddHours(1)
            $script:Dna.Headers = @{ 'X-Auth-Token' = $response.Token; 'Content-Type' = 'application/json' }
            $script:Dna.BaseUrl = $DnaCenter.TrimEnd('/')
            Write-Log -Message 'Authentication successful!' -Color 'Green' -LogBox $LogBox
            return $true
        }
        Write-Log -Message 'No token received from server' -Color 'Red' -LogBox $LogBox
        return $false
    } catch {
        Write-Log -Message "Authentication failed: $(Get-SanitizedErrorMessage -ErrorRecord $_)" -Color 'Red' -LogBox $LogBox
        return $false
    } finally {
        $base64AuthInfo = $null
        $Password = $null
        [System.GC]::Collect()
    }
}

function Invoke-DnaGet {
    param([string]$Path, [int]$TimeoutSec = 30)
    return Invoke-RestMethod -Uri ($script:Dna.BaseUrl + $Path) -Method Get -Headers $script:Dna.Headers -TimeoutSec $TimeoutSec
}

function Get-DnaResult {
    param($Result)
    if ($Result -and $Result.Output) { return $Result.Output }
    # No result at all = the run was stopped before this request was sent
    if ($null -eq $Result) { return [pscustomobject]@{ Response = $null; Error = 'Not run (stopped)'; Status = -1 } }
    $err = if ($Result.Error) { $Result.Error } else { 'No result' }
    return [pscustomobject]@{ Response = $null; Error = $err; Status = 0 }
}

function Test-DnaRetryable {
    # Temporary failures worth a second try: no answer / timeout (0), 408, 429 and 5xx.
    # 4xx answers (bad request, expired token, not found) would fail again.
    param($Result)
    if ($null -eq $Result -or -not $Result.Error) { return $false }
    $status = [int]$Result.Status
    return ($status -eq 0 -or $status -eq 408 -or $status -eq 429 -or $status -ge 500)
}

function Get-DnaPool {
    # One pool for the session: runspaces (and Invoke-RestMethod's module) load once
    if ($null -eq $script:Dna.Pool) { $script:Dna.Pool = New-OctoRunspacePool -MaxRunspaces $script:DnaThrottle }
    return $script:Dna.Pool
}

function Invoke-DnaParallel {
    <#
    .SYNOPSIS
        Runs a DNA worker for each item on the session pool, with progress in the status bar.
    .PARAMETER RetryFailed
        GET worker only: requests that failed with a temporary error (no answer,
        timeout, HTTP 408 / 429 / 5xx - after the worker's own 429 back-off) are
        sent once more after a pause, two at a time instead of six.
    #>
    param(
        [object[]]$Items, [string]$Script, [hashtable]$Extra = @{}, [string]$Activity = 'Working', [scriptblock]$OnResult,
        [switch]$RetryFailed, [System.Windows.Forms.RichTextBox]$LogBox
    )
    $shared = [hashtable]::Synchronized(@{ Stop = $false; Headers = $script:Dna.Headers.Clone(); BaseUrl = $script:Dna.BaseUrl; TimeoutSec = 15 })
    foreach ($k in $Extra.Keys) { $shared[$k] = $Extra[$k] }
    $script:Dna.Shared = $shared
    try {
        $results = Invoke-OctoParallel -Items $Items -Script $Script -Shared $shared -Throttle $script:DnaThrottle -Pool (Get-DnaPool) -OnProgress {
            param($done, $count, $r)
            if ($OnResult) { & $OnResult $done $count $r }
            if ($done -eq $count -or ($done % 5) -eq 0) {
                Set-OctoStatus -Text "$Activity..." -Percent ([int](100 * $done / $count)) -ProgressText "$done/$count"
            }
        }

        if ($RetryFailed -and -not $shared.Stop) {
            $retry = [System.Collections.Generic.List[int]]::new()
            for ($i = 0; $i -lt $results.Count; $i++) {
                if (Test-DnaRetryable -Result (Get-DnaResult -Result $results[$i])) { $retry.Add($i) }
            }
            if ($retry.Count -gt 0) {
                $firstError = (Get-DnaResult -Result $results[$retry[0]]).Error
                Write-Log -Message ('{0} - {1} request(s) failed ({2}) - trying them again, two at a time' -f $Activity, $retry.Count, $firstError) -Color 'Warning' -LogBox $LogBox
                Set-OctoStatus -Text "$Activity - pausing before the second try..."
                $until = [DateTime]::UtcNow.AddMilliseconds($script:DnaRetryDelayMs)
                while ([DateTime]::UtcNow -lt $until -and -not $shared.Stop) {
                    [System.Windows.Forms.Application]::DoEvents()
                    Start-Sleep -Milliseconds 40
                }
                $retryItems = @(foreach ($i in $retry) { $Items[$i] })
                $tries = @{ NoAnswerInRow = 0; GaveUp = $false }
                $second = Invoke-OctoParallel -Items $retryItems -Script $Script -Shared $shared -MaxInFlight 2 -Pool (Get-DnaPool) -OnProgress {
                    param($done, $count, $r)
                    $rr = Get-DnaResult -Result $r
                    if ($rr.Error -and [int]$rr.Status -eq 0) { $tries.NoAnswerInRow++ } else { $tries.NoAnswerInRow = 0 }
                    # DNA Center not answering at all: stop instead of waiting out every timeout again
                    if ($tries.NoAnswerInRow -ge 6 -and $done -lt $count -and -not $tries.GaveUp) { $tries.GaveUp = $true; $shared.Stop = $true }
                    Set-OctoStatus -Text "$Activity (second try)..." -Percent ([int](100 * $done / $count)) -ProgressText "$done/$count"
                }
                $recovered = 0; $notSent = 0
                for ($k = 0; $k -lt $retry.Count; $k++) {
                    if ($null -eq $second[$k]) { $notSent++; continue }   # stopped before it was answered
                    $results[$retry[$k]] = $second[$k]
                    if (-not (Get-DnaResult -Result $second[$k]).Error) { $recovered++ }
                }
                if ($tries.GaveUp) {
                    Write-Log -Message ('{0} - DNA Center did not answer 6 second tries in a row - the other {1} request(s) were not tried again' -f $Activity, $notSent) -Color 'Warning' -LogBox $LogBox
                }
                $tried = $retry.Count - $notSent
                Write-Log -Message ('{0} - second try: {1} of {2} succeeded' -f $Activity, $recovered, $tried) -Color $(if ($recovered -eq $retry.Count) { 'Success' } else { 'Warning' }) -LogBox $LogBox
            }
        }
    } finally {
        $script:Dna.Shared = $null
        Set-OctoStatus -Text 'Ready'
    }
    return ,$results
}

function Invoke-DnaDeviceRequests {
    <#
    .SYNOPSIS
        GET <PathTemplate> for every device in parallel ({id} = device id).
        Returns index-aligned results: .Response / .Error per device.
    .DESCRIPTION
        Temporary failures get a second try; devices that still fail are named in the log.
    #>
    param([object[]]$Devices, [string]$PathTemplate, [int]$TimeoutSec = 15, [string]$Activity = 'Querying devices', [System.Windows.Forms.RichTextBox]$LogBox)
    $items = New-Object object[] $Devices.Count
    for ($i = 0; $i -lt $Devices.Count; $i++) {
        $items[$i] = @{ Url = $script:Dna.BaseUrl + $PathTemplate.Replace('{id}', [System.Uri]::EscapeDataString([string]$Devices[$i].id)) }
    }
    $raw = Invoke-DnaParallel -Items $items -Script $script:DnaGetWorker -Extra @{ TimeoutSec = $TimeoutSec } -Activity $Activity -RetryFailed -LogBox $LogBox
    $out = New-Object object[] $raw.Count
    for ($i = 0; $i -lt $raw.Count; $i++) { $out[$i] = Get-DnaResult -Result $raw[$i] }
    Write-DnaFailedDevices -Devices $Devices -Results $out -What $Activity -LogBox $LogBox
    return ,$out
}

function Write-DnaFailedDevices {
    <#
    .SYNOPSIS
        Names the devices whose request failed (after the second try) in the log.
    #>
    param([object[]]$Devices, [object[]]$Results, [string]$What, [System.Windows.Forms.RichTextBox]$LogBox, [int]$MaxListed = 10)
    $failed = [System.Collections.Generic.List[int]]::new()
    $notRun = 0
    for ($i = 0; $i -lt $Results.Count; $i++) {
        $r = $Results[$i]
        if ($null -eq $r -or -not $r.Error) { continue }
        if ($r.Status -eq -1) { $notRun++ } else { $failed.Add($i) }
    }
    if ($notRun -gt 0) { Write-Log -Message ('{0} - {1} device(s) not queried (stopped)' -f $What, $notRun) -Color 'Warning' -LogBox $LogBox }
    if ($failed.Count -eq 0) { return }
    Write-Log -Message ('{0} - {1} of {2} device(s) failed:' -f $What, $failed.Count, $Results.Count) -Color 'Warning' -LogBox $LogBox
    foreach ($i in @($failed | Select-Object -First $MaxListed)) {
        $d = $Devices[$i]
        $name = if ($d.hostname) { [string]$d.hostname } else { [string]$d.id }
        $ip = if ($d.managementIpAddress) { " ($($d.managementIpAddress))" } else { '' }
        Write-Log -Message ('  {0}{1}: {2}' -f $name, $ip, $Results[$i].Error) -Color 'Warning' -LogBox $LogBox
    }
    if ($failed.Count -gt $MaxListed) { Write-Log -Message ('  ... and {0} more' -f ($failed.Count - $MaxListed)) -Color 'Warning' -LogBox $LogBox }
}

function Get-AllDNADevices {
    <#
    .SYNOPSIS
        Loads the device inventory (pages of 500 fetched in parallel when the count is known).
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)
    if (-not $script:Dna.Headers) {
        Write-Log -Message 'Not authenticated to DNA Center' -Color 'Red' -LogBox $LogBox
        return $false
    }
    Write-Log -Message 'Loading network devices...' -Color 'Yellow' -LogBox $LogBox
    $pageSize = 500
    try {
        $devices = [System.Collections.Generic.List[object]]::new()
        $nextOffset = 1
        $lastPageFull = $true

        $count = 0
        try {
            $countResponse = Invoke-DnaGet -Path '/dna/intent/api/v1/network-device/count'
            if ($null -ne $countResponse.response) { $count = [int]$countResponse.response }
        } catch { }

        if ($count -gt $pageSize) {
            $items = [System.Collections.Generic.List[object]]::new()
            for ($o = 1; $o -le $count; $o += $pageSize) {
                $items.Add(@{ Url = "$($script:Dna.BaseUrl)/dna/intent/api/v1/network-device?offset=$o&limit=$pageSize" })
            }
            Write-Log -Message "Inventory reports $count device(s) - fetching $($items.Count) pages in parallel" -Color 'Cyan' -LogBox $LogBox
            $pages = Invoke-DnaParallel -Items $items.ToArray() -Script $script:DnaGetWorker -Extra @{ TimeoutSec = 60 } -Activity 'Loading devices' -RetryFailed -LogBox $LogBox
            foreach ($p in $pages) {
                $r = Get-DnaResult -Result $p
                if ($r.Error) { throw "Device page failed: $($r.Error)" }
                $pageDevices = @($r.Response.response)
                foreach ($d in $pageDevices) { $devices.Add($d) }
                $lastPageFull = ($pageDevices.Count -ge $pageSize)
            }
            $nextOffset = 1 + $items.Count * $pageSize
        }

        # Serial paging (small inventories, unknown count, or devices added meanwhile)
        while ($lastPageFull) {
            $response = Invoke-DnaGet -Path "/dna/intent/api/v1/network-device?offset=$nextOffset&limit=$pageSize" -TimeoutSec 60
            $pageDevices = @()
            if ($response -and $response.response) { $pageDevices = @($response.response) }
            foreach ($d in $pageDevices) { $devices.Add($d) }
            if ($pageDevices.Count -gt 0) { Write-Log -Message "Retrieved $($pageDevices.Count) device(s) at offset $nextOffset" -Color 'Cyan' -LogBox $LogBox }
            $lastPageFull = ($pageDevices.Count -ge $pageSize)
            $nextOffset += $pageSize
        }

        # Pages fetched while the inventory changes can overlap - keep one entry per device id
        $unique = [System.Collections.Generic.List[object]]::new()
        $byId = @{}
        foreach ($d in $devices) {
            $id = [string]$d.id
            if ($id -and $byId.ContainsKey($id)) { continue }
            if ($id) { $byId[$id] = $d }
            $unique.Add($d)
        }
        if ($unique.Count -eq 0) {
            Write-Log -Message 'No devices returned from API' -Color 'Red' -LogBox $LogBox
            return $false
        }
        $script:Dna.Devices = $unique.ToArray()
        $script:Dna.DeviceById = $byId
        $script:Dna.Selected = @()
        Write-Log -Message "Loaded $($unique.Count) devices" -Color 'Green' -LogBox $LogBox
        return $true
    } catch {
        Write-Log -Message "Failed to load devices: $($_.Exception.Message)" -Color 'Red' -LogBox $LogBox
        return $false
    }
}

function Reset-DNADeviceSelection {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    if (-not $script:Dna.Devices -or $script:Dna.Devices.Count -eq 0) {
        Write-Log -Message 'No devices loaded' -Color 'Red' -LogBox $LogBox
        return
    }
    $script:Dna.Selected = $script:Dna.Devices
    Write-Log -Message "Device selection reset to all loaded devices ($($script:Dna.Devices.Count) devices)" -Color 'Green' -LogBox $LogBox
}

function Get-DnaTargetDevices {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    $devices = if ($script:Dna.Selected.Count -gt 0) { $script:Dna.Selected } else { $script:Dna.Devices }
    if (-not $devices -or $devices.Count -eq 0) {
        Write-Log -Message 'No devices available' -Color 'Red' -LogBox $LogBox
        return $null
    }
    return ,@($devices)
}

function Export-DnaRows {
    param([AllowEmptyCollection()][object[]]$Rows, [string]$BaseName, [string]$Operation, [System.Windows.Forms.RichTextBox]$LogBox, [string[]]$Columns)
    if (-not $Rows -or $Rows.Count -eq 0) {
        Write-Log -Message "$Operation - no data returned, nothing exported" -Color 'Yellow' -LogBox $LogBox
        return $null
    }
    $path = Get-OctoExportPath -Folder $script:outputDir -BaseName $BaseName
    [void](Export-OctoCsv -Rows $Rows -Columns $Columns -Path $path)
    Write-Log -Message "Exported $($Rows.Count) row(s) to: $path" -Color 'Green' -LogBox $LogBox
    Add-ExportHistory -Settings $script:Settings -FilePath $path -Operation $Operation
    return $path
}

# ---------- Device information (local data) ----------

function Get-NetworkDevicesBasic {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    $devices = Get-DnaTargetDevices -LogBox $LogBox
    if (-not $devices) { return }
    $rows = foreach ($d in $devices) {
        [PSCustomObject][ordered]@{
            Hostname = $(if ($d.hostname) { $d.hostname } else { 'Unknown' }); IPAddress = $(if ($d.managementIpAddress) { $d.managementIpAddress } else { 'N/A' }); SerialNumber = $(if ($d.serialNumber) { $d.serialNumber } else { 'N/A' })
            Platform = $(if ($d.platformId) { $d.platformId } else { 'N/A' }); SoftwareVersion = $(if ($d.softwareVersion) { $d.softwareVersion } else { 'N/A' }); Role = $(if ($d.role) { $d.role } else { 'N/A' })
            ReachabilityStatus = $(if ($d.reachabilityStatus) { $d.reachabilityStatus } else { 'N/A' }); Family = $(if ($d.family) { $d.family } else { 'N/A' }); Type = $(if ($d.type) { $d.type } else { 'N/A' }); UpTime = $(if ($d.upTime) { $d.upTime } else { 'N/A' })
        }
    }
    [void](Export-DnaRows -Rows @($rows) -BaseName 'NetworkDevices_Basic' -Operation 'DNA - Basic Information' -LogBox $LogBox)
}

function Get-NetworkDevicesDetailed {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    $devices = Get-DnaTargetDevices -LogBox $LogBox
    if (-not $devices) { return }
    $rows = foreach ($d in $devices) {
        [PSCustomObject][ordered]@{
            Hostname = $(if ($d.hostname) { $d.hostname } else { 'Unknown' }); IPAddress = $(if ($d.managementIpAddress) { $d.managementIpAddress } else { 'N/A' }); MacAddress = $(if ($d.macAddress) { $d.macAddress } else { 'N/A' })
            SerialNumber = $(if ($d.serialNumber) { $d.serialNumber } else { 'N/A' }); Platform = $(if ($d.platformId) { $d.platformId } else { 'N/A' }); SoftwareVersion = $(if ($d.softwareVersion) { $d.softwareVersion } else { 'N/A' })
            SoftwareType = $(if ($d.softwareType) { $d.softwareType } else { 'N/A' }); Role = $(if ($d.role) { $d.role } else { 'N/A' }); ReachabilityStatus = $(if ($d.reachabilityStatus) { $d.reachabilityStatus } else { 'N/A' })
            Family = $(if ($d.family) { $d.family } else { 'N/A' }); Type = $(if ($d.type) { $d.type } else { 'N/A' }); Series = $(if ($d.series) { $d.series } else { 'N/A' }); Location = $(if ($d.location) { $d.location } else { 'N/A' })
            MemorySize = $(if ($d.memorySize) { $d.memorySize } else { 'N/A' }); LastUpdated = $(if ($d.lastUpdated) { $d.lastUpdated } else { 'N/A' }); UpTime = $(if ($d.upTime) { $d.upTime } else { 'N/A' })
        }
    }
    [void](Export-DnaRows -Rows @($rows) -BaseName 'NetworkDevices_Detailed' -Operation 'DNA - Detailed Information' -LogBox $LogBox)
}

function Get-DeviceInventoryCount {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    $devices = Get-DnaTargetDevices -LogBox $LogBox
    if (-not $devices) { return }
    $byFamily = $devices | Group-Object -Property family | ForEach-Object { [PSCustomObject]@{ Family = $(if ($_.Name) { $_.Name } else { 'Unknown' }); Count = $_.Count } } | Sort-Object -Property Count -Descending
    [void](Export-DnaRows -Rows @($byFamily) -BaseName 'DeviceInventory_ByFamily' -Operation 'DNA - Inventory by Family' -LogBox $LogBox)
    $byRole = $devices | Group-Object -Property role | ForEach-Object { [PSCustomObject]@{ Role = $(if ($_.Name) { $_.Name } else { 'Unknown' }); Count = $_.Count } } | Sort-Object -Property Count -Descending
    [void](Export-DnaRows -Rows @($byRole) -BaseName 'DeviceInventory_ByRole' -Operation 'DNA - Inventory by Role' -LogBox $LogBox)
    Write-Log -Message "Total devices: $($devices.Count)" -Color 'Green' -LogBox $LogBox
}

function Get-DeviceReachability {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    $devices = Get-DnaTargetDevices -LogBox $LogBox
    if (-not $devices) { return }
    $rows = foreach ($d in $devices) {
        [PSCustomObject][ordered]@{
            Hostname = $(if ($d.hostname) { $d.hostname } else { 'Unknown' }); IPAddress = $(if ($d.managementIpAddress) { $d.managementIpAddress } else { 'N/A' }); ReachabilityStatus = $(if ($d.reachabilityStatus) { $d.reachabilityStatus } else { 'N/A' })
            LastUpdated = $(if ($d.lastUpdated) { $d.lastUpdated } else { 'N/A' }); CollectionStatus = $(if ($d.collectionStatus) { $d.collectionStatus } else { 'N/A' }); Family = $(if ($d.family) { $d.family } else { 'N/A' }); Role = $(if ($d.role) { $d.role } else { 'N/A' })
        }
    }
    [void](Export-DnaRows -Rows @($rows) -BaseName 'DeviceReachability' -Operation 'DNA - Device Reachability' -LogBox $LogBox)
}

# ---------- Single API calls ----------

function Get-NetworkHealth {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    Write-Log -Message 'Fetching network health...' -Color 'Yellow' -LogBox $LogBox
    try {
        $response = Invoke-DnaGet -Path "/dna/intent/api/v1/network-health?timestamp=$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
        $rows = foreach ($item in @($response.response)) {
            if ($null -eq $item) { continue }
            [PSCustomObject][ordered]@{
                HealthCategory = $(if ($item.healthCategory) { $item.healthCategory } else { 'N/A' }); TotalCount = $(if ($item.totalCount) { $item.totalCount } else { 0 }); GoodCount = $(if ($item.goodCount) { $item.goodCount } else { 0 })
                FairCount = $(if ($item.fairCount) { $item.fairCount } else { 0 }); BadCount = $(if ($item.badCount) { $item.badCount } else { 0 }); HealthScore = $(if ($item.healthScore) { $item.healthScore } else { 0 })
            }
        }
        [void](Export-DnaRows -Rows @($rows) -BaseName 'NetworkHealth' -Operation 'DNA - Network Health' -LogBox $LogBox)
    } catch {
        Write-Log -Message "Failed to retrieve network health: $($_.Exception.Message)" -Color 'Red' -LogBox $LogBox
    }
}

function Get-ClientHealth {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    Write-Log -Message 'Fetching client health...' -Color 'Yellow' -LogBox $LogBox
    try {
        $response = Invoke-DnaGet -Path "/dna/intent/api/v1/client-health?timestamp=$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
        $rows = foreach ($client in @($response.response)) {
            if ($null -eq $client) { continue }
            $sd = $client.scoreDetail
            [PSCustomObject][ordered]@{
                SiteId = $(if ($client.siteId) { $client.siteId } else { 'N/A' })
                TotalCount = $(if ($sd) { $sd.totalCount } else { 0 })
                ConnectedCount = $(if ($sd) { $sd.connectedCount } else { 0 })
                GoodCount = $(if ($sd -and $sd.clientCount) { $sd.clientCount.good } else { 0 })
                FairCount = $(if ($sd -and $sd.clientCount) { $sd.clientCount.fair } else { 0 })
                PoorCount = $(if ($sd -and $sd.clientCount) { $sd.clientCount.poor } else { 0 })
                HealthScore = $(if ($sd) { $sd.healthScore } else { 0 })
            }
        }
        [void](Export-DnaRows -Rows @($rows) -BaseName 'ClientHealth' -Operation 'DNA - Client Health' -LogBox $LogBox)
    } catch {
        Write-Log -Message "Failed to retrieve client health: $($_.Exception.Message)" -Color 'Red' -LogBox $LogBox
    }
}

function Get-SitesLocations {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    Write-Log -Message 'Fetching sites and locations...' -Color 'Yellow' -LogBox $LogBox
    try {
        $response = Invoke-DnaGet -Path '/dna/intent/api/v1/site'
        $rows = foreach ($site in @($response.response)) {
            if ($null -eq $site) { continue }
            [PSCustomObject][ordered]@{
                SiteName = $(if ($site.name) { $site.name } else { 'N/A' }); SiteId = $(if ($site.id) { $site.id } else { 'N/A' }); ParentId = $(if ($site.parentId) { $site.parentId } else { 'N/A' })
                Latitude = $(if ($site.latitude) { $site.latitude } else { 'N/A' }); Longitude = $(if ($site.longitude) { $site.longitude } else { 'N/A' })
            }
        }
        [void](Export-DnaRows -Rows @($rows) -BaseName 'Sites' -Operation 'DNA - Sites' -LogBox $LogBox)
    } catch {
        Write-Log -Message "Failed to retrieve sites: $($_.Exception.Message)" -Color 'Red' -LogBox $LogBox
    }
}

function Get-Templates {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    Write-Log -Message 'Fetching configuration templates...' -Color 'Yellow' -LogBox $LogBox
    try {
        $response = Invoke-DnaGet -Path '/dna/intent/api/v1/template-programmer/template'
        $templates = if ($response.response) { $response.response } else { $response }
        $rows = foreach ($t in @($templates)) {
            if ($null -eq $t) { continue }
            [PSCustomObject][ordered]@{
                TemplateName = $(if ($t.name) { $t.name } else { 'N/A' }); ProjectName = $(if ($t.projectName) { $t.projectName } else { 'N/A' }); TemplateId = $(if ($t.templateId) { $t.templateId } else { 'N/A' })
                SoftwareType = $(if ($t.softwareType) { $t.softwareType } else { 'N/A' }); SoftwareVersion = $(if ($t.softwareVersion) { $t.softwareVersion } else { 'N/A' })
            }
        }
        [void](Export-DnaRows -Rows @($rows) -BaseName 'Templates' -Operation 'DNA - Templates' -LogBox $LogBox)
    } catch {
        Write-Log -Message "Failed to retrieve templates: $($_.Exception.Message)" -Color 'Red' -LogBox $LogBox
    }
}

function Get-PhysicalTopology {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    Write-Log -Message 'Fetching physical topology...' -Color 'Yellow' -LogBox $LogBox
    try {
        $response = Invoke-DnaGet -Path '/dna/intent/api/v1/topology/physical-topology'
        $links = if ($response -and $response.response) { @($response.response.links) } else { @() }
        $rows = foreach ($link in $links) {
            if ($null -eq $link) { continue }
            [PSCustomObject][ordered]@{
                SourceDevice = $(if ($link.source) { $link.source } else { 'N/A' }); SourceInterface = $(if ($link.startPortName) { $link.startPortName } else { 'N/A' }); TargetDevice = $(if ($link.target) { $link.target } else { 'N/A' })
                TargetInterface = $(if ($link.endPortName) { $link.endPortName } else { 'N/A' }); LinkStatus = $(if ($link.linkStatus) { $link.linkStatus } else { 'N/A' })
            }
        }
        [void](Export-DnaRows -Rows @($rows) -BaseName 'PhysicalTopology' -Operation 'DNA - Physical Topology' -LogBox $LogBox)
    } catch {
        Write-Log -Message "Failed to retrieve topology: $($_.Exception.Message)" -Color 'Red' -LogBox $LogBox
    }
}

function Get-AccessPoints {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    Write-Log -Message 'Fetching access points...' -Color 'Yellow' -LogBox $LogBox
    try {
        $response = Invoke-DnaGet -Path '/dna/intent/api/v1/wireless/access-point'
        $rows = foreach ($ap in @($response.response)) {
            if ($null -eq $ap) { continue }
            [PSCustomObject][ordered]@{
                APName = $(if ($ap.name) { $ap.name } else { 'N/A' }); MacAddress = $(if ($ap.macAddress) { $ap.macAddress } else { 'N/A' }); IPAddress = $(if ($ap.ipAddress) { $ap.ipAddress } else { 'N/A' }); Model = $(if ($ap.model) { $ap.model } else { 'N/A' })
                Location = $(if ($ap.location) { $ap.location } else { 'N/A' }); AdminStatus = $(if ($ap.adminStatus) { $ap.adminStatus } else { 'N/A' }); ClientCount = $(if ($ap.clientCount) { $ap.clientCount } else { 0 })
            }
        }
        [void](Export-DnaRows -Rows @($rows) -BaseName 'AccessPoints' -Operation 'DNA - Access Points' -LogBox $LogBox)
    } catch {
        Write-Log -Message "Failed to retrieve access points: $($_.Exception.Message)" -Color 'Red' -LogBox $LogBox
    }
}

function Get-IssuesEvents {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    Write-Log -Message 'Fetching issues and events...' -Color 'Yellow' -LogBox $LogBox
    try {
        $response = Invoke-DnaGet -Path '/dna/intent/api/v1/issues'
        $rows = foreach ($issue in @($response.response)) {
            if ($null -eq $issue) { continue }
            [PSCustomObject][ordered]@{
                IssueId = $(if ($issue.issueId) { $issue.issueId } else { 'N/A' }); Name = $(if ($issue.name) { $issue.name } else { 'N/A' }); DeviceId = $(if ($issue.deviceId) { $issue.deviceId } else { 'N/A' }); Severity = $(if ($issue.severity) { $issue.severity } else { 'N/A' })
                Priority = $(if ($issue.priority) { $issue.priority } else { 'N/A' }); Status = $(if ($issue.status) { $issue.status } else { 'N/A' }); Category = $(if ($issue.category) { $issue.category } else { 'N/A' })
            }
        }
        [void](Export-DnaRows -Rows @($rows) -BaseName 'Issues' -Operation 'DNA - Issues' -LogBox $LogBox)
    } catch {
        Write-Log -Message "Failed to retrieve issues: $($_.Exception.Message)" -Color 'Red' -LogBox $LogBox
    }
}

function Get-SoftwareImageInfo {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    Write-Log -Message 'Fetching software/image information...' -Color 'Yellow' -LogBox $LogBox
    try {
        $response = Invoke-DnaGet -Path '/dna/intent/api/v1/image/importation'
        $rows = foreach ($image in @($response.response)) {
            if ($null -eq $image) { continue }
            [PSCustomObject][ordered]@{
                ImageName = $(if ($image.name) { $image.name } else { 'N/A' }); ImageFamily = $(if ($image.family) { $image.family } else { 'N/A' }); Version = $(if ($image.version) { $image.version } else { 'N/A' }); Vendor = $(if ($image.vendor) { $image.vendor } else { 'N/A' })
                FileSize = $(if ($image.fileSize) { $image.fileSize } else { 'N/A' }); IsTaggedGolden = $(if ($image.isTaggedGolden) { $image.isTaggedGolden } else { $false })
            }
        }
        [void](Export-DnaRows -Rows @($rows) -BaseName 'SoftwareImages' -Operation 'DNA - Software Images' -LogBox $LogBox)
    } catch {
        Write-Log -Message "Failed to retrieve software images: $($_.Exception.Message)" -Color 'Red' -LogBox $LogBox
    }
}

# ---------- Per-device API calls (parallel) ----------

function Get-ComplianceStatus {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    $devices = Get-DnaTargetDevices -LogBox $LogBox
    if (-not $devices) { return }
    Write-Log -Message "Fetching compliance status for $($devices.Count) device(s)..." -Color 'Yellow' -LogBox $LogBox
    $results = Invoke-DnaDeviceRequests -Devices $devices -PathTemplate '/dna/intent/api/v1/compliance/{id}' -Activity 'Compliance status' -LogBox $LogBox
    $rows = for ($i = 0; $i -lt $devices.Count; $i++) {
        $d = $devices[$i]; $r = $results[$i]
        if ($r.Error) {
            [PSCustomObject][ordered]@{ Hostname = $(if ($d.hostname) { $d.hostname } else { 'Unknown' }); IPAddress = $(if ($d.managementIpAddress) { $d.managementIpAddress } else { 'N/A' }); ComplianceStatus = "Error: $($r.Error)"; LastSyncTime = 'N/A' }
        } elseif ($r.Response -and $r.Response.response) {
            [PSCustomObject][ordered]@{
                Hostname = $(if ($d.hostname) { $d.hostname } else { 'Unknown' }); IPAddress = $(if ($d.managementIpAddress) { $d.managementIpAddress } else { 'N/A' })
                ComplianceStatus = $(if ($r.Response.response.status) { $r.Response.response.status } else { 'N/A' }); LastSyncTime = $(if ($r.Response.response.lastSyncTime) { $r.Response.response.lastSyncTime } else { 'N/A' })
            }
        }
    }
    [void](Export-DnaRows -Rows @($rows) -BaseName 'ComplianceStatus' -Operation 'DNA - Compliance Status' -LogBox $LogBox)
}

function Get-DnaNeighborReport {
    param([System.Windows.Forms.RichTextBox]$LogBox, [string]$PathTemplate, [string]$What, [string]$BaseName, [scriptblock]$RowBuilder)
    $devices = Get-DnaTargetDevices -LogBox $LogBox
    if (-not $devices) { return }
    Write-Log -Message "Fetching $What for $($devices.Count) device(s)..." -Color 'Yellow' -LogBox $LogBox
    $results = Invoke-DnaDeviceRequests -Devices $devices -PathTemplate $PathTemplate -Activity $What -LogBox $LogBox
    $rows = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $devices.Count; $i++) {
        $r = $results[$i]
        if (-not $r.Response -or -not $r.Response.response) { continue }
        foreach ($entry in @($r.Response.response)) {
            if ($null -eq $entry) { continue }
            $row = & $RowBuilder $devices[$i] $entry
            if ($row) { $rows.Add($row) }
        }
    }
    [void](Export-DnaRows -Rows $rows.ToArray() -BaseName $BaseName -Operation "DNA - $What" -LogBox $LogBox)
}

function Get-OSPFNeighbors {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    Get-DnaNeighborReport -LogBox $LogBox -PathTemplate '/dna/intent/api/v1/network-device/{id}/ospf-neighbor' -What 'OSPF neighbors' -BaseName 'OSPF_Neighbors' -RowBuilder {
        param($d, $n)
        [PSCustomObject][ordered]@{
            Hostname = $(if ($d.hostname) { $d.hostname } else { 'Unknown' }); NeighborId = $(if ($n.neighborId) { $n.neighborId } else { 'N/A' }); NeighborIp = $(if ($n.neighborIp) { $n.neighborIp } else { 'N/A' })
            State = $(if ($n.state) { $n.state } else { 'N/A' }); Interface = $(if ($n.interfaceName) { $n.interfaceName } else { 'N/A' })
        }
    }
}

function Get-CDPNeighbors {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    Get-DnaNeighborReport -LogBox $LogBox -PathTemplate '/dna/intent/api/v1/network-device/{id}/neighbor' -What 'CDP neighbors' -BaseName 'CDP_Neighbors' -RowBuilder {
        param($d, $n)
        if ($n.neighborDevice -or $n.neighborPort) {
            [PSCustomObject][ordered]@{
                Hostname = $(if ($d.hostname) { $d.hostname } else { 'Unknown' }); LocalInterface = $(if ($n.localInterfaceName) { $n.localInterfaceName } else { 'N/A' }); NeighborDevice = $(if ($n.neighborDevice) { $n.neighborDevice } else { 'N/A' })
                NeighborPort = $(if ($n.neighborPort) { $n.neighborPort } else { 'N/A' }); Platform = $(if ($n.platform) { $n.platform } else { 'N/A' })
            }
        }
    }
}

function Get-LLDPNeighbors {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    Get-DnaNeighborReport -LogBox $LogBox -PathTemplate '/dna/intent/api/v1/network-device/{id}/interface/lldp' -What 'LLDP neighbors' -BaseName 'LLDP_Neighbors' -RowBuilder {
        param($d, $n)
        [PSCustomObject][ordered]@{
            Hostname = $(if ($d.hostname) { $d.hostname } else { 'Unknown' }); LocalInterface = $(if ($n.localInterface) { $n.localInterface } else { 'N/A' }); NeighborDevice = $(if ($n.systemName) { $n.systemName } else { 'N/A' })
            NeighborPort = $(if ($n.portId) { $n.portId } else { 'N/A' }); ManagementAddress = $(if ($n.managementAddress) { $n.managementAddress } else { 'N/A' })
        }
    }
}

function Get-DeviceModules {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    Get-DnaNeighborReport -LogBox $LogBox -PathTemplate '/dna/intent/api/v1/network-device/module?deviceId={id}' -What 'device modules' -BaseName 'DeviceModules' -RowBuilder {
        param($d, $m)
        [PSCustomObject][ordered]@{
            Hostname = $(if ($d.hostname) { $d.hostname } else { 'Unknown' }); ModuleName = $(if ($m.name) { $m.name } else { 'N/A' }); PartNumber = $(if ($m.partNumber) { $m.partNumber } else { 'N/A' })
            SerialNumber = $(if ($m.serialNumber) { $m.serialNumber } else { 'N/A' }); Description = $(if ($m.description) { $m.description } else { 'N/A' })
        }
    }
}

function Get-DeviceInterfaces {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    Get-DnaNeighborReport -LogBox $LogBox -PathTemplate '/dna/intent/api/v1/interface/network-device/{id}' -What 'device interfaces' -BaseName 'DeviceInterfaces' -RowBuilder {
        param($d, $n)
        [PSCustomObject][ordered]@{
            Hostname = $(if ($d.hostname) { $d.hostname } else { 'Unknown' }); InterfaceName = $(if ($n.portName) { $n.portName } else { 'N/A' }); Status = $(if ($n.status) { $n.status } else { 'N/A' }); AdminStatus = $(if ($n.adminStatus) { $n.adminStatus } else { 'N/A' })
            Speed = $(if ($n.speed) { $n.speed } else { 'N/A' }); VlanId = $(if ($n.vlanId) { $n.vlanId } else { 'N/A' }); IPAddress = $(if ($n.ipv4Address) { $n.ipv4Address } else { 'N/A' })
        }
    }
}

function Get-VLANs {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    $devices = Get-DnaTargetDevices -LogBox $LogBox
    if (-not $devices) { return }
    Write-Log -Message "Fetching VLANs for $($devices.Count) device(s)..." -Color 'Yellow' -LogBox $LogBox
    $results = Invoke-DnaDeviceRequests -Devices $devices -PathTemplate '/dna/intent/api/v1/interface/network-device/{id}' -Activity 'VLANs' -LogBox $LogBox
    $rows = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $devices.Count; $i++) {
        $r = $results[$i]
        if (-not $r.Response -or -not $r.Response.response) { continue }
        $seen = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($iface in @($r.Response.response)) {
            $vlan = [string]$iface.vlanId
            if (-not $vlan -or $vlan -eq 'N/A' -or -not $seen.Add($vlan)) { continue }
            $rows.Add([PSCustomObject][ordered]@{ Hostname = $(if ($devices[$i].hostname) { $devices[$i].hostname } else { 'Unknown' }); IPAddress = $(if ($devices[$i].managementIpAddress) { $devices[$i].managementIpAddress } else { 'N/A' }); VlanId = $iface.vlanId })
        }
    }
    [void](Export-DnaRows -Rows $rows.ToArray() -BaseName 'VLANs' -Operation 'DNA - VLANs' -LogBox $LogBox)
}

function Get-DeviceConfigurations {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    $devices = Get-DnaTargetDevices -LogBox $LogBox
    if (-not $devices) { return }
    Write-Log -Message "Fetching configurations for $($devices.Count) device(s)..." -Color 'Yellow' -LogBox $LogBox
    try {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $configFolder = Join-Path (Initialize-OutputDirectory -Path $script:outputDir) "DeviceConfigurations_$timestamp"
        [void][System.IO.Directory]::CreateDirectory($configFolder)
        $results = Invoke-DnaDeviceRequests -Devices $devices -PathTemplate '/dna/intent/api/v1/network-device/{id}/config' -TimeoutSec 30 -Activity 'Device configurations' -LogBox $LogBox
        $usedNames = @{}
        $rows = for ($i = 0; $i -lt $devices.Count; $i++) {
            $d = $devices[$i]; $r = $results[$i]
            $hostname = $(if ($d.hostname) { $d.hostname } else { 'Unknown' })
            if ($r.Error) {
                [PSCustomObject][ordered]@{ Hostname = $hostname; IPAddress = $(if ($d.managementIpAddress) { $d.managementIpAddress } else { 'N/A' }); ConfigFile = 'N/A'; Status = "Failed: $($r.Error)" }
                continue
            }
            $content = if ($r.Response.response) { $r.Response.response } else { $r.Response }
            if (-not $content) { continue }
            $safe = Get-SafeFileName -InputName $d.hostname
            if ($usedNames.ContainsKey($safe)) { $usedNames[$safe]++; $safe = "${safe}_$($usedNames[$safe])" } else { $usedNames[$safe] = 1 }
            $configPath = Join-Path $configFolder "$safe.txt"
            [System.IO.File]::WriteAllText($configPath, [string]$content, [System.Text.UTF8Encoding]::new($true))
            [PSCustomObject][ordered]@{ Hostname = $hostname; IPAddress = $(if ($d.managementIpAddress) { $d.managementIpAddress } else { 'N/A' }); ConfigFile = $configPath; Status = 'Success' }
        }
        [void](Export-DnaRows -Rows @($rows) -BaseName 'DeviceConfigurations' -Operation 'DNA - Device Configurations' -LogBox $LogBox)
        Write-Log -Message "Config files saved to: $configFolder" -Color 'Green' -LogBox $LogBox
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color 'Red' -LogBox $LogBox
    }
}

function Get-DnaEventSeriesUrl {
    param([string]$DeviceId, [string]$EventName, [hashtable]$AdditionalQuery)
    $parts = [System.Collections.Generic.List[string]]::new()
    if ($EventName) { $parts.Add('eventName=' + [System.Uri]::EscapeDataString($EventName)) }
    $parts.Add('deviceId=' + [System.Uri]::EscapeDataString($DeviceId))
    foreach ($p in @('limit=1', 'offset=0', 'sortBy=eventTimestamp', 'order=desc')) { $parts.Add($p) }
    if ($AdditionalQuery) {
        foreach ($entry in $AdditionalQuery.GetEnumerator()) {
            if ([string]::IsNullOrWhiteSpace([string]$entry.Key) -or [string]::IsNullOrWhiteSpace([string]$entry.Value)) { continue }
            $parts.Add([System.Uri]::EscapeDataString([string]$entry.Key) + '=' + [System.Uri]::EscapeDataString([string]$entry.Value))
        }
    }
    # Built by concatenation: "$baseUrl?$query" would read a variable named 'baseUrl?'
    # (previously every event-series request was sent to an invalid URL)
    return "$($script:Dna.BaseUrl)/dna/data/api/v1/event/event-series?" + ($parts -join '&')
}

function Get-DnaEventTimestamp {
    param($Response)
    if (-not $Response) { return $null }
    $records = if ($Response.PSObject.Properties['response']) { @($Response.response) }
        elseif ($Response.PSObject.Properties['data']) { @($Response.data) }
        else { @($Response) }
    foreach ($record in $records) {
        if (-not $record) { continue }
        $value = $null
        if ($record.PSObject.Properties['eventTimestamp']) { $value = $record.eventTimestamp }
        elseif ($record.PSObject.Properties['timestamp']) { $value = $record.timestamp }
        if ($value) { return ConvertTo-ReadableTimestamp -Value $value }
    }
    return $null
}

function Get-DnaEventTimestamps {
    <#
    .SYNOPSIS
        Latest event timestamp per device (parallel), index-aligned; $null when none.
    #>
    param([object[]]$Devices, [string]$EventName, [hashtable]$AdditionalQuery, [string]$Activity, [System.Windows.Forms.RichTextBox]$LogBox)
    $items = New-Object object[] $Devices.Count
    for ($i = 0; $i -lt $Devices.Count; $i++) {
        $items[$i] = @{ Url = (Get-DnaEventSeriesUrl -DeviceId ([string]$Devices[$i].id) -EventName $EventName -AdditionalQuery $AdditionalQuery) }
    }
    $raw = Invoke-DnaParallel -Items $items -Script $script:DnaGetWorker -Extra @{ TimeoutSec = 30 } -Activity $Activity -RetryFailed -LogBox $LogBox
    $results = New-Object object[] $raw.Count
    for ($i = 0; $i -lt $raw.Count; $i++) { $results[$i] = Get-DnaResult -Result $raw[$i] }
    Write-DnaFailedDevices -Devices $Devices -Results $results -What $Activity -LogBox $LogBox
    $out = New-Object object[] $Devices.Count
    for ($i = 0; $i -lt $results.Count; $i++) { $out[$i] = Get-DnaEventTimestamp -Response $results[$i].Response }
    return ,$out
}

function Get-LastDeviceAvailabilityEventTime {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    $devices = Get-DnaTargetDevices -LogBox $LogBox
    if (-not $devices) { return }
    Write-Log -Message "Fetching last availability events for $($devices.Count) device(s)..." -Color 'Yellow' -LogBox $LogBox
    $times = Get-DnaEventTimestamps -Devices $devices -EventName 'Device Unreachable' -AdditionalQuery @{ tags = 'ASSURANCE' } -Activity 'Availability events' -LogBox $LogBox
    $rows = for ($i = 0; $i -lt $devices.Count; $i++) {
        [PSCustomObject][ordered]@{
            Hostname = $(if ($devices[$i].hostname) { $devices[$i].hostname } else { 'Unknown' }); IPAddress = $(if ($devices[$i].managementIpAddress) { $devices[$i].managementIpAddress } else { 'N/A' })
            LastEventTime = $(if ($times[$i]) { $times[$i] } else { 'N/A' }); EventType = 'Device Unreachable'
        }
    }
    [void](Export-DnaRows -Rows @($rows) -BaseName 'DeviceAvailabilityEvents' -Operation 'DNA - Availability Events' -LogBox $LogBox)
}

function Get-LastDisconnectTime {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    if (-not (Test-DNACTokenValid)) { Write-Log -Message 'DNA Center token expired or invalid' -Color 'Red' -LogBox $LogBox; return }
    $devices = Get-DnaTargetDevices -LogBox $LogBox
    if (-not $devices) { return }
    Write-Log -Message "Fetching last disconnect times for $($devices.Count) device(s)..." -Color 'Yellow' -LogBox $LogBox
    $results = Invoke-DnaDeviceRequests -Devices $devices -PathTemplate '/dna/intent/api/v1/network-device/{id}/enrichment-details' -TimeoutSec 30 -Activity 'Last disconnect times' -LogBox $LogBox
    $rows = for ($i = 0; $i -lt $devices.Count; $i++) {
        $r = $results[$i]
        $value = 'N/A'
        if ($r.Error) {
            $value = 'Error'
        } elseif ($r.Response) {
            $records = if ($r.Response.PSObject.Properties['response']) { @($r.Response.response) } else { @($r.Response) }
            foreach ($record in $records) {
                if ($record -and $record.PSObject.Properties['deviceDetails'] -and $record.deviceDetails -and $record.deviceDetails.PSObject.Properties['lastDisconnectTime']) {
                    $converted = ConvertTo-ReadableTimestamp -Value $record.deviceDetails.lastDisconnectTime
                    if ($converted) { $value = $converted }
                }
            }
        }
        [PSCustomObject][ordered]@{ Hostname = $(if ($devices[$i].hostname) { $devices[$i].hostname } else { 'Unknown' }); IPAddress = $(if ($devices[$i].managementIpAddress) { $devices[$i].managementIpAddress } else { 'N/A' }); LastDisconnectTime = $value }
    }
    [void](Export-DnaRows -Rows @($rows) -BaseName 'DeviceLastDisconnect' -Operation 'DNA - Last Disconnect Times' -LogBox $LogBox)
}

function Get-LastPingReachableTime {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    if (-not (Test-DNACTokenValid)) { Write-Log -Message 'DNA Center token expired or invalid' -Color 'Red' -LogBox $LogBox; return }
    $devices = Get-DnaTargetDevices -LogBox $LogBox
    if (-not $devices) { return }
    Write-Log -Message "Retrieving last ping reachable times for $($devices.Count) device(s)..." -Color 'Cyan' -LogBox $LogBox

    $values = New-Object object[] $devices.Count
    $results = Invoke-DnaDeviceRequests -Devices $devices -PathTemplate '/dna/intent/api/v1/network-device/{id}' -TimeoutSec 30 -Activity 'Device records' -LogBox $LogBox
    for ($i = 0; $i -lt $devices.Count; $i++) {
        $data = $results[$i].Response
        if (-not $data -or -not $data.response) { continue }
        $data = $data.response
        $seen = $null
        if ($data.PSObject.Properties['lastUpdateTime']) { $seen = $data.lastUpdateTime }
        elseif ($data.PSObject.Properties['lastUpdated']) { $seen = $data.lastUpdated }
        elseif ($data.PSObject.Properties['collectionStatus']) { $seen = $data.collectionStatus }
        if ($seen) { $values[$i] = ConvertTo-ReadableTimestamp -Value $seen }
    }

    # Fall back to availability events, only for devices still without a value
    foreach ($eventName in @('device_availability:ping_reachable', 'device_availability:reachable')) {
        $missing = @(for ($i = 0; $i -lt $devices.Count; $i++) { if (-not $values[$i]) { $i } })
        if ($missing.Count -eq 0) { break }
        $subset = @(foreach ($i in $missing) { $devices[$i] })
        $times = Get-DnaEventTimestamps -Devices $subset -EventName $eventName -AdditionalQuery @{} -Activity "Reachability events ($eventName)" -LogBox $LogBox
        for ($k = 0; $k -lt $missing.Count; $k++) { if ($times[$k]) { $values[$missing[$k]] = $times[$k] } }
    }

    $rows = for ($i = 0; $i -lt $devices.Count; $i++) {
        [PSCustomObject][ordered]@{
            Hostname = $(if ($devices[$i].hostname) { $devices[$i].hostname } else { 'Unknown' }); IPAddress = $(if ($devices[$i].managementIpAddress) { $devices[$i].managementIpAddress } else { 'N/A' })
            Family = $(if ($devices[$i].family) { $devices[$i].family } else { 'N/A' }); LastPingReachable = $(if ($values[$i]) { $values[$i] } else { 'N/A' })
        }
    }
    [void](Export-DnaRows -Rows @($rows) -BaseName 'DeviceLastPingReachable' -Operation 'DNA - Last Ping Reachable' -LogBox $LogBox)
}

function Wait-OctoUi {
    <#
    .SYNOPSIS
        Sleeps while keeping the window responsive.
    #>
    param([int]$Milliseconds)
    $until = [DateTime]::UtcNow.AddMilliseconds($Milliseconds)
    while ([DateTime]::UtcNow -lt $until) {
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 40
    }
}

function Invoke-PathTrace {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    if (-not (Test-DNACTokenValid)) {
        Write-Log -Message 'DNA Center token expired or invalid' -Color 'Red' -LogBox $LogBox
        [System.Windows.Forms.MessageBox]::Show('Please connect to DNA Center first', 'Not Authenticated', 'OK', 'Warning') | Out-Null
        return
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Path Trace Configuration'
    $form.Size = New-Object System.Drawing.Size(500, 400)
    $form.StartPosition = 'CenterParent'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $fields = @(
        @{ Label = 'Source IP Address:'; Name = 'Source'; Width = 300 },
        @{ Label = 'Destination IP Address:'; Name = 'Dest'; Width = 300 },
        @{ Label = 'Protocol:'; Name = 'Protocol'; Width = 150 },
        @{ Label = 'Source Port (optional):'; Name = 'SourcePort'; Width = 100 },
        @{ Label = 'Dest Port (optional):'; Name = 'DestPort'; Width = 100 }
    )
    $inputs = @{}
    $y = 20
    foreach ($f in $fields) {
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Text = $f.Label
        $lbl.Location = New-Object System.Drawing.Point(20, ($y + 3))
        $lbl.Size = New-Object System.Drawing.Size(145, 20)
        $form.Controls.Add($lbl)
        if ($f.Name -eq 'Protocol') {
            $ctl = New-Object System.Windows.Forms.ComboBox
            $ctl.DropDownStyle = 'DropDownList'
            $ctl.Items.AddRange(@('ICMP', 'TCP', 'UDP'))
            $ctl.SelectedIndex = 0
        } else {
            $ctl = New-Object System.Windows.Forms.TextBox
        }
        $ctl.Location = New-Object System.Drawing.Point(170, $y)
        $ctl.Size = New-Object System.Drawing.Size($f.Width, 23)
        $form.Controls.Add($ctl)
        $inputs[$f.Name] = $ctl
        $y += 40
    }
    $y += 20
    $btnStart = New-Object System.Windows.Forms.Button
    $btnStart.Text = 'Start Path Trace'
    $btnStart.Tag = 'Primary'
    $btnStart.Location = New-Object System.Drawing.Point(170, $y)
    $btnStart.Size = New-Object System.Drawing.Size(130, 32)
    $form.Controls.Add($btnStart)
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Cancel'
    $btnCancel.Location = New-Object System.Drawing.Point(308, $y)
    $btnCancel.Size = New-Object System.Drawing.Size(90, 32)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($btnCancel)
    $form.CancelButton = $btnCancel
    $form.ClientSize = New-Object System.Drawing.Size(490, ($y + 52))
    Set-OctoDialogStyle -Form $form
    $btnStart.Add_Click({
        if (-not (Test-IPAddress -IPAddress $inputs.Source.Text.Trim())) { [System.Windows.Forms.MessageBox]::Show('Invalid source IP address', 'Validation Error', 'OK', 'Warning') | Out-Null; return }
        if (-not (Test-IPAddress -IPAddress $inputs.Dest.Text.Trim())) { [System.Windows.Forms.MessageBox]::Show('Invalid destination IP address', 'Validation Error', 'OK', 'Warning') | Out-Null; return }
        foreach ($portField in @('SourcePort', 'DestPort')) {
            $text = $inputs[$portField].Text
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                $port = 0
                if (-not [int]::TryParse($text, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
                    [System.Windows.Forms.MessageBox]::Show('Ports must be between 1 and 65535', 'Validation Error', 'OK', 'Warning') | Out-Null
                    return
                }
            }
        }
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })
    if ($form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

    $sourceIP = $inputs.Source.Text.Trim()
    $destIP = $inputs.Dest.Text.Trim()
    $protocol = [string]$inputs.Protocol.SelectedItem
    $body = @{ sourceIP = $sourceIP; destIP = $destIP; protocol = $protocol }
    if (-not [string]::IsNullOrWhiteSpace($inputs.SourcePort.Text)) { $body.sourcePort = [int]$inputs.SourcePort.Text }
    if (-not [string]::IsNullOrWhiteSpace($inputs.DestPort.Text)) { $body.destPort = [int]$inputs.DestPort.Text }
    Write-Log -Message "Starting path trace: $sourceIP -> $destIP ($protocol)" -Color 'Cyan' -LogBox $LogBox

    try {
        $response = Invoke-RestMethod -Uri "$($script:Dna.BaseUrl)/dna/intent/api/v1/flow-analysis" -Method Post -Headers $script:Dna.Headers -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json' -TimeoutSec 30
        if (-not ($response -and $response.response -and $response.response.flowAnalysisId)) {
            Write-Log -Message 'Failed to initiate path trace' -Color 'Red' -LogBox $LogBox
            return
        }
        $flowId = $response.response.flowAnalysisId
        Write-Log -Message "Flow analysis initiated (ID: $flowId) - waiting for completion..." -Color 'Green' -LogBox $LogBox
        for ($attempt = 1; $attempt -le 30; $attempt++) {
            Wait-OctoUi -Milliseconds 2000
            $status = Invoke-RestMethod -Uri "$($script:Dna.BaseUrl)/dna/intent/api/v1/flow-analysis/$flowId" -Method Get -Headers $script:Dna.Headers -TimeoutSec 30
            if (-not ($status -and $status.response)) { continue }
            $state = $status.response.request.status
            if ($state -eq 'COMPLETED') {
                $hop = 0
                $traceTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                $rows = foreach ($element in @($status.response.networkElementsInfo)) {
                    if ($null -eq $element) { continue }
                    $hop++
                    $ingress = if ($element.ingressInterface -and $element.ingressInterface.physicalInterface -and $element.ingressInterface.physicalInterface.name) { $element.ingressInterface.physicalInterface.name } else { 'N/A' }
                    $egress = if ($element.egressInterface -and $element.egressInterface.physicalInterface -and $element.egressInterface.physicalInterface.name) { $element.egressInterface.physicalInterface.name } else { 'N/A' }
                    [PSCustomObject][ordered]@{
                        HopNumber = $hop; DeviceName = $(if ($element.name) { $element.name } else { 'Unknown' }); DeviceIP = $(if ($element.ip) { $element.ip } else { 'N/A' }); DeviceType = $(if ($element.type) { $element.type } else { 'N/A' })
                        IngressInterface = $ingress; EgressInterface = $egress; SourceIP = $sourceIP; DestinationIP = $destIP; Protocol = $protocol; TraceTime = $traceTime
                    }
                }
                $path = Export-DnaRows -Rows @($rows) -BaseName "PathTrace_${sourceIP}_to_${destIP}" -Operation 'DNA - Path Trace' -LogBox $LogBox
                [System.Windows.Forms.MessageBox]::Show("Path trace completed!`nTotal hops: $hop`n`nExported to: $path", 'Path Trace Complete', 'OK', 'Information') | Out-Null
                return
            }
            if ($state -eq 'FAILED') {
                Write-Log -Message 'Path trace failed' -Color 'Red' -LogBox $LogBox
                if ($status.response.request.failureReason) { Write-Log -Message "Reason: $($status.response.request.failureReason)" -Color 'Red' -LogBox $LogBox }
                return
            }
        }
        Write-Log -Message 'Path trace timed out after 60 seconds' -Color 'Red' -LogBox $LogBox
    } catch {
        Write-Log -Message "Error during path trace: $(Get-SanitizedErrorMessage -ErrorRecord $_)" -Color 'Red' -LogBox $LogBox
    }
}

function Get-DnaCommandResponseText {
    <#
    .SYNOPSIS
        Text from commandResponses.SUCCESS, which DNA Center returns as an object
        keyed by the command ("show version": "<output>").
    #>
    param($Success, [string]$Command)
    if ($null -eq $Success) { return '' }
    if ($Success -is [string]) { return $Success }
    if ($Success -is [System.Collections.IEnumerable]) { return (@($Success) -join "`n") }
    $props = @($Success.PSObject.Properties)
    foreach ($p in $props) { if ($p.Name -eq $Command) { return [string]$p.Value } }
    return (@($props | ForEach-Object { [string]$_.Value }) -join "`n")
}

function Get-DNATaskOutputDetails {
    <#
    .SYNOPSIS
        Extracts CLI output text from the DNA Center file response formats.
    #>
    param($RawOutput, [string]$Command)
    if ($null -eq $RawOutput) { return '' }
    $clean = [System.Text.StringBuilder]::new()
    $items = if ($RawOutput -is [string]) { $null } elseif ($RawOutput -is [array]) { $RawOutput } else { @($RawOutput) }
    if ($null -eq $items) {
        [void]$clean.Append($RawOutput)
    } else {
        foreach ($item in $items) {
            if ($null -eq $item) { continue }
            $showKey = $null
            foreach ($p in $item.PSObject.Properties) { if ($p.Name -match 'show') { $showKey = $p; break } }
            if ($showKey) {
                if ($showKey.Value -is [string]) { [void]$clean.Append($showKey.Value) } else { [void]$clean.Append(($showKey.Value | ConvertTo-Json -Depth 10)) }
            } elseif ($item.commandOutput) {
                [void]$clean.Append($item.commandOutput)
            } elseif ($item.output) {
                [void]$clean.Append($item.output)
            } elseif ($item.PSObject.Properties['commandResponses']) {
                [void]$clean.Append((Get-DnaCommandResponseText -Success $item.commandResponses.SUCCESS -Command $Command))
            } else {
                [void]$clean.Append(($item | ConvertTo-Json -Depth 10))
            }
        }
    }
    $text = $clean.ToString()
    if (-not [string]::IsNullOrEmpty($text)) {
        $text = $text -replace '\\r\\n', "`n" -replace '\\r', "`n" -replace '\\n', "`n"
        $text = $text.Trim('"')
        $text = $text -replace '""', '"' -replace '\\`', '`' -replace '\\\\', '\'
    }
    return $text
}

function Get-DnaCommandFailureText {
    <#
    .SYNOPSIS
        FAILURE / BLACKLISTED text from a command runner file response ('' if none).
    #>
    param($RawOutput)
    if ($null -eq $RawOutput -or $RawOutput -is [string]) { return '' }
    foreach ($item in @($RawOutput)) {
        if ($null -eq $item -or -not $item.PSObject.Properties['commandResponses']) { continue }
        foreach ($kind in @('FAILURE', 'BLACKLISTED')) {
            $v = $item.commandResponses.$kind
            if ($null -eq $v) { continue }
            $text = if ($v -is [string]) { $v } else { (@($v.PSObject.Properties | ForEach-Object { "$($_.Name): $($_.Value)" }) -join '; ') }
            if (-not [string]::IsNullOrWhiteSpace($text)) { return "${kind}: $text" }
        }
    }
    return ''
}

function Invoke-CommandRunner {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    if (-not (Test-DNACTokenValid)) {
        Write-Log -Message 'DNA Center token expired or invalid' -Color 'Red' -LogBox $LogBox
        [System.Windows.Forms.MessageBox]::Show('Please connect to DNA Center first', 'Not Authenticated', 'OK', 'Warning') | Out-Null
        return
    }
    # Only explicitly selected devices - never all devices
    $devices = @($script:Dna.Selected)
    if ($devices.Count -eq 0) {
        Write-Log -Message "No devices selected. Check devices in the list and click 'Apply Selection'." -Color 'Yellow' -LogBox $LogBox
        [System.Windows.Forms.MessageBox]::Show("No devices selected!`n`n1. Check the devices you want in the device list`n2. Click 'Apply Selection'`n3. Run CLI Command Runner again", 'No Devices Selected', 'OK', 'Warning') | Out-Null
        return
    }

    $cmdForm = New-Object System.Windows.Forms.Form
    $cmdForm.Text = 'CLI Command Runner'
    $cmdForm.Size = New-Object System.Drawing.Size(700, 600)
    $cmdForm.StartPosition = 'CenterParent'
    $cmdForm.FormBorderStyle = 'FixedDialog'
    $cmdForm.MaximizeBox = $false
    $y = 15
    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Text = "Execute CLI commands on $($devices.Count) selected device(s)"
    $lblInfo.Location = New-Object System.Drawing.Point(20, $y)
    $lblInfo.Size = New-Object System.Drawing.Size(650, 20)
    $lblInfo.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 11)
    $lblInfo.Tag = 'Accent'
    $cmdForm.Controls.Add($lblInfo)
    $y += 30
    $lblCommand = New-Object System.Windows.Forms.Label
    $lblCommand.Text = 'CLI Command(s) - Enter one command per line:'
    $lblCommand.Location = New-Object System.Drawing.Point(20, $y)
    $lblCommand.Size = New-Object System.Drawing.Size(400, 20)
    $cmdForm.Controls.Add($lblCommand)
    $y += 25
    $txtCommand = New-Object System.Windows.Forms.TextBox
    $txtCommand.Multiline = $true
    $txtCommand.ScrollBars = 'Vertical'
    $txtCommand.Location = New-Object System.Drawing.Point(20, $y)
    $txtCommand.Size = New-Object System.Drawing.Size(650, 120)
    $txtCommand.Font = New-Object System.Drawing.Font('Consolas', 9)
    $cmdForm.Controls.Add($txtCommand)
    $y += 130
    $lblWarning = New-Object System.Windows.Forms.Label
    $lblWarning.Text = 'Note: pipes (|) are not supported by the DNA Center API - use plain commands only.'
    $lblWarning.Location = New-Object System.Drawing.Point(20, $y)
    $lblWarning.Size = New-Object System.Drawing.Size(650, 20)
    $lblWarning.Tag = 'Warning'
    $cmdForm.Controls.Add($lblWarning)
    $y += 30
    $lblFormat = New-Object System.Windows.Forms.Label
    $lblFormat.Text = 'Output Format:'
    $lblFormat.Location = New-Object System.Drawing.Point(20, $y)
    $lblFormat.Size = New-Object System.Drawing.Size(150, 20)
    $cmdForm.Controls.Add($lblFormat)
    $y += 25
    $radios = @{}
    foreach ($opt in @(
            @{ Key = 'Separate'; Text = 'Separate files per device (hostname_command.txt)' },
            @{ Key = 'Consolidated'; Text = 'Single consolidated CSV with all results' },
            @{ Key = 'Both'; Text = 'Both formats (separate files + consolidated CSV)' },
            @{ Key = 'All'; Text = 'All formats (separate + CSV + concatenated text file)' })) {
        $rb = New-Object System.Windows.Forms.RadioButton
        $rb.Text = $opt.Text
        $rb.Location = New-Object System.Drawing.Point(35, $y)
        $rb.Size = New-Object System.Drawing.Size(600, 20)
        $cmdForm.Controls.Add($rb)
        $radios[$opt.Key] = $rb
        $y += 25
    }
    $radios.Separate.Checked = $true
    $y += 10
    $lblFilterInfo = New-Object System.Windows.Forms.Label
    $lblFilterInfo.Text = 'Output Filters (optional - keeps lines containing any pattern, case-insensitive), e.g.: up, Gigabit, 192.168'
    $lblFilterInfo.Location = New-Object System.Drawing.Point(20, $y)
    $lblFilterInfo.Size = New-Object System.Drawing.Size(650, 36)
    $cmdForm.Controls.Add($lblFilterInfo)
    $y += 40
    $txtFilter = New-Object System.Windows.Forms.TextBox
    $txtFilter.Location = New-Object System.Drawing.Point(20, $y)
    $txtFilter.Size = New-Object System.Drawing.Size(650, 23)
    $txtFilter.Font = New-Object System.Drawing.Font('Consolas', 9)
    $cmdForm.Controls.Add($txtFilter)
    $y += 40
    $btnExecute = New-Object System.Windows.Forms.Button
    $btnExecute.Text = 'Execute Commands'
    $btnExecute.Location = New-Object System.Drawing.Point(20, $y)
    $btnExecute.Size = New-Object System.Drawing.Size(150, 34)
    $btnExecute.Tag = 'Primary'
    $cmdForm.Controls.Add($btnExecute)
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Cancel'
    $btnCancel.Location = New-Object System.Drawing.Point(178, $y)
    $btnCancel.Size = New-Object System.Drawing.Size(100, 34)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $cmdForm.Controls.Add($btnCancel)
    $cmdForm.CancelButton = $btnCancel
    $cmdForm.ClientSize = New-Object System.Drawing.Size(690, ($y + 54))
    Set-OctoDialogStyle -Form $cmdForm
    $btnExecute.Add_Click({
        if ([string]::IsNullOrWhiteSpace($txtCommand.Text)) {
            [System.Windows.Forms.MessageBox]::Show('Please enter at least one command', 'Validation Error', 'OK', 'Warning') | Out-Null
            return
        }
        $cmdForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $cmdForm.Close()
    })
    if ($cmdForm.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

    $commands = @($txtCommand.Text -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($commands.Count -eq 0) { Write-Log -Message 'No valid commands entered' -Color 'Red' -LogBox $LogBox; return }
    $useSeparate = $radios.Separate.Checked -or $radios.Both.Checked -or $radios.All.Checked
    $useCsv = $radios.Consolidated.Checked -or $radios.Both.Checked -or $radios.All.Checked
    $useConcat = $radios.All.Checked
    $filters = @($txtFilter.Text.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($filters.Count -gt 0) { Write-Log -Message "Output filters: $($filters -join ', ')" -Color 'Yellow' -LogBox $LogBox }

    $total = $devices.Count * $commands.Count
    Write-Log -Message "Executing $($commands.Count) command(s) on $($devices.Count) device(s) - $total operation(s), $script:DnaThrottle at a time..." -Color 'Cyan' -LogBox $LogBox

    try {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $outputFolder = Join-Path (Initialize-OutputDirectory -Path $script:outputDir) "CommandRunner_$timestamp"
        [void][System.IO.Directory]::CreateDirectory($outputFolder)

        $ops = [System.Collections.Generic.List[object]]::new()
        foreach ($device in $devices) {
            foreach ($cmd in $commands) {
                $ops.Add(@{ Index = $ops.Count; DeviceId = [string]$device.id; Hostname = ($(if ($device.hostname) { $device.hostname } else { 'Unknown' })); IP = ($(if ($device.managementIpAddress) { $device.managementIpAddress } else { 'N/A' })); Command = $cmd })
            }
        }
        $opArray = $ops.ToArray()
        $allResults = New-Object object[] $opArray.Count
        $concat = [System.Text.StringBuilder]::new()
        $usedFiles = @{}

        # Each finished operation is parsed, filtered and saved as soon as it arrives
        $onResult = {
            param($done, $count, $r)
            $res = $r.Output
            if (-not $res) { $res = [pscustomobject]@{ Index = -1; Status = 'Error'; FileResponse = $null; Error = $r.Error } }
            $idx = [int]$res.Index
            if ($idx -lt 0) { return }
            $op = $opArray[$idx]
            $status = $res.Status
            $outputFile = 'N/A'
            $text = ''
            if ($status -eq 'Downloaded') {
                $text = Get-DNATaskOutputDetails -RawOutput $res.FileResponse -Command $op.Command
                $failure = Get-DnaCommandFailureText -RawOutput $res.FileResponse
                if ([string]::IsNullOrWhiteSpace($text) -and $failure) {
                    $status = "Failed: $failure"
                } else {
                    $status = 'Success'
                    if ($filters.Count -gt 0 -and $text) { $text = (Invoke-Filters -Lines ($text -split "`n") -Filters $filters) -join "`n" }
                    if ($useSeparate) {
                        $name = (Get-SafeFileName -InputName $op.Hostname) + '_' + (Get-SafeFileName -InputName $op.Command)
                        if ($usedFiles.ContainsKey($name)) { $usedFiles[$name]++; $name += "_$($usedFiles[$name])" } else { $usedFiles[$name] = 1 }
                        $outputFile = Join-Path $outputFolder "$name.txt"
                        [System.IO.File]::WriteAllText($outputFile, $text, [System.Text.UTF8Encoding]::new($true))
                    }
                    if ($useConcat) {
                        [void]$concat.Append(('=' * 80) + "`n" + "Device: $($op.Hostname)`nCommand: $($op.Command)`n" + ('=' * 80) + "`n" + $text + "`n`n")
                    }
                }
            } elseif ($status -eq 'Failed' -or $status -eq 'Error') {
                $status = "$($status): $($res.Error)"
            }
            $allResults[$idx] = [PSCustomObject][ordered]@{
                Hostname = $op.Hostname; DeviceIP = $op.IP; Command = $op.Command; Status = $status
                OutputFile = $outputFile; OutputLength = $text.Length; Output = $(if ($useCsv) { $text } else { '' })
            }
            $color = if ($status -eq 'Success') { 'Green' } else { 'Red' }
            $lines = if ($status -eq 'Success') { " ($(@($text -split "`n" | Where-Object { $_.Trim() }).Count) lines)" } else { '' }
            Write-Log -Message "[$done/$count] $($op.Hostname) - $($op.Command): $status$lines" -Color $color -LogBox $LogBox
        }
        $null = Invoke-DnaParallel -Items $opArray -Script $script:DnaCommandWorker -Extra @{ MaxWaitSeconds = 60 } -Activity 'Running commands' -OnResult $onResult

        $results = @($allResults | Where-Object { $null -ne $_ })
        if ($useCsv -and $results.Count -gt 0) {
            $csvPath = Export-OctoCsv -Rows $results -Path (Join-Path $outputFolder "CommandRunner_Summary_$timestamp.csv")
            Write-Log -Message "Summary CSV: $csvPath" -Color 'Green' -LogBox $LogBox
        }
        if ($useConcat -and $concat.Length -gt 0) {
            $concatPath = Join-Path $outputFolder "CommandRunner_All_Output_$timestamp.txt"
            [System.IO.File]::WriteAllText($concatPath, $concat.ToString(), [System.Text.UTF8Encoding]::new($true))
            Write-Log -Message "Concatenated text: $concatPath" -Color 'Green' -LogBox $LogBox
        }

        $success = @($results | Where-Object { $_.Status -eq 'Success' }).Count
        $failedCount = $total - $success
        Write-Log -Message "Command execution complete: $success of $total succeeded" -Color $(if ($failedCount) { 'Yellow' } else { 'Green' }) -LogBox $LogBox
        Write-Log -Message "Output folder: $outputFolder" -Color 'Green' -LogBox $LogBox
        Add-ExportHistory -Settings $script:Settings -FilePath $outputFolder -Operation 'DNA - CLI Command Runner' -Format 'TXT/CSV'

        $message = "Command execution complete!`n`nTotal operations: $total`nSuccessful: $success"
        if ($failedCount -gt 0) { $message += "`nFailed/not run: $failedCount" }
        $message += "`n`nOutput folder:`n$outputFolder"
        [System.Windows.Forms.MessageBox]::Show($message, 'Execution Complete', 'OK', $(if ($failedCount) { 'Warning' } else { 'Information' })) | Out-Null
        Start-Process explorer.exe $outputFolder
    } catch {
        Write-Log -Message "Error during command execution: $(Get-SanitizedErrorMessage -ErrorRecord $_)" -Color 'Red' -LogBox $LogBox
    }
}

# ============================================
# NETWORK ADAPTER CONFIGURATION (needs Administrator)
# ============================================

function Show-AdminRequiredMessage {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    Write-Log -Message 'Network configuration requires Administrator privileges' -Color 'Red' -LogBox $LogBox
    Write-Log -Message 'Restart OctoNav with "Run as Administrator" to use this tab (everything else works without it)' -Color 'Yellow' -LogBox $LogBox
    [System.Windows.Forms.MessageBox]::Show(
        "Changing adapter settings requires Administrator privileges.`n`nClose OctoNav and start it with 'Run as Administrator' to use this tab. All other tabs work without it.",
        'Administrator Required', 'OK', 'Warning') | Out-Null
}

function Find-UnidentifiedNetwork {
    <#
    .SYNOPSIS
        Finds a Public-profile adapter with an APIPA (169.254.x.x) address, or an
        unidentified network.
    #>
    param([System.Windows.Forms.RichTextBox]$LogBox)
    Write-Log -Message 'Looking for unidentified public networks with APIPA addresses...' -Color 'Cyan' -LogBox $LogBox
    try {
        $publicProfiles = @(Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq 'Public' })
        foreach ($netProfile in $publicProfiles) {
            foreach ($ip in @(Get-NetIPAddress -InterfaceIndex $netProfile.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
                if ($ip.IPAddress -match '^169\.254\.') {
                    Write-Log -Message "Found: $($netProfile.InterfaceAlias) - $($ip.IPAddress)" -Color 'Green' -LogBox $LogBox
                    return @{ Adapter = (Get-NetAdapter -InterfaceIndex $netProfile.InterfaceIndex); Profile = $netProfile; IPAddress = $ip }
                }
            }
        }
        foreach ($netProfile in $publicProfiles) {
            if ($netProfile.Name -match 'Unidentified' -or $netProfile.Name -match 'Network') {
                Write-Log -Message "Found: $($netProfile.InterfaceAlias)" -Color 'Green' -LogBox $LogBox
                return @{
                    Adapter = (Get-NetAdapter -InterfaceIndex $netProfile.InterfaceIndex)
                    Profile = $netProfile
                    IPAddress = (Get-NetIPAddress -InterfaceIndex $netProfile.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1)
                }
            }
        }
        return $null
    } catch {
        Write-Log -Message "Error finding network: $($_.Exception.Message)" -Color 'Red' -LogBox $LogBox
        return $null
    }
}

function Set-NetworkConfiguration {
    param($Adapter, [string]$IPAddress, [string]$Gateway, [int]$PrefixLength = 24, [System.Windows.Forms.RichTextBox]$LogBox)
    if (-not $script:IsRunningAsAdmin) { Show-AdminRequiredMessage -LogBox $LogBox; return $false }
    try {
        if (-not (Test-IPAddress -IPAddress $IPAddress)) { Write-Log -Message "Invalid IP address format: $IPAddress" -Color 'Red' -LogBox $LogBox; return $false }
        if (-not (Test-IPAddress -IPAddress $Gateway)) { Write-Log -Message "Invalid gateway format: $Gateway" -Color 'Red' -LogBox $LogBox; return $false }
        if (-not (Test-PrefixLength -Prefix $PrefixLength)) { Write-Log -Message "Invalid prefix length: $PrefixLength" -Color 'Red' -LogBox $LogBox; return $false }

        Write-Log -Message 'Applying network configuration...' -Color 'Cyan' -LogBox $LogBox
        Remove-NetIPAddress -InterfaceIndex $Adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
        Remove-NetRoute -InterfaceIndex $Adapter.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log -Message "Setting IP: $IPAddress/$PrefixLength, Gateway: $Gateway" -Color 'Yellow' -LogBox $LogBox
        New-NetIPAddress -InterfaceIndex $Adapter.ifIndex -IPAddress $IPAddress -PrefixLength $PrefixLength -DefaultGateway $Gateway -ErrorAction Stop | Out-Null
        Set-NetIPInterface -InterfaceIndex $Adapter.ifIndex -Dhcp Disabled -ErrorAction Stop
        Write-Log -Message 'Setting network profile to Private...' -Color 'Yellow' -LogBox $LogBox
        Set-NetConnectionProfile -InterfaceIndex $Adapter.ifIndex -NetworkCategory Private -ErrorAction Stop
        Write-Log -Message 'Configuration applied successfully!' -Color 'Green' -LogBox $LogBox
        return $true
    } catch {
        Write-Log -Message "Failed to apply configuration: $($_.Exception.Message)" -Color 'Red' -LogBox $LogBox
        return $false
    }
}

function Restore-NetworkDefaults {
    param([System.Windows.Forms.RichTextBox]$LogBox)
    if (-not $script:IsRunningAsAdmin) { Show-AdminRequiredMessage -LogBox $LogBox; return $false }
    Write-Log -Message 'Restoring network to default settings...' -Color 'Yellow' -LogBox $LogBox
    try {
        if ($script:BatchProcess -and -not $script:BatchProcess.HasExited) {
            Write-Log -Message 'Stopping RunStandAloneMT.bat process...' -Color 'Yellow' -LogBox $LogBox
            Stop-Process -Id $script:BatchProcess.Id -Force -ErrorAction SilentlyContinue
        }
        if ($script:TargetAdapter -and $script:OriginalConfig) {
            $index = $script:TargetAdapter.ifIndex
            if (Get-NetAdapter -InterfaceIndex $index -ErrorAction SilentlyContinue) {
                if ($script:NewIPAddress) {
                    Write-Log -Message 'Removing static IP configuration...' -Color 'Yellow' -LogBox $LogBox
                    Remove-NetIPAddress -InterfaceIndex $index -Confirm:$false -ErrorAction SilentlyContinue
                    Remove-NetRoute -InterfaceIndex $index -Confirm:$false -ErrorAction SilentlyContinue
                }
                Write-Log -Message 'Restoring DHCP configuration...' -Color 'Yellow' -LogBox $LogBox
                Set-NetIPInterface -InterfaceIndex $index -Dhcp Enabled -ErrorAction SilentlyContinue
                Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses -ErrorAction SilentlyContinue
                if ($script:OriginalConfig.NetworkCategory -and (Get-NetConnectionProfile -InterfaceIndex $index -ErrorAction SilentlyContinue)) {
                    Write-Log -Message 'Restoring network category...' -Color 'Yellow' -LogBox $LogBox
                    Set-NetConnectionProfile -InterfaceIndex $index -NetworkCategory $script:OriginalConfig.NetworkCategory -ErrorAction SilentlyContinue
                }
            }
        }
        Write-Log -Message 'Cleanup complete!' -Color 'Green' -LogBox $LogBox
        return $true
    } catch {
        Write-Log -Message "Cleanup error: $($_.Exception.Message)" -Color 'Red' -LogBox $LogBox
        return $false
    }
}

# ============================================
# PORT CONFIGURATION TEMPLATES
# ============================================
# Placeholders: {{INTERFACE}}, {{DESCRIPTION}}, {{VLAN}}, {{OLD_VLAN}}, {{VOICE_VLAN}}, {{STATUS}}
# {{STATUS}} = "no shutdown" or "shutdown"; {{OLD_VLAN}} is only used by FCX 7.3.
# Saved templates (PortTemplates.json) override these defaults.

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

$script:PortTemplatesFile = Join-Path $script:DataDir 'PortTemplates.json'
foreach ($candidate in @($script:PortTemplatesFile, (Join-Path $script:AppRoot 'PortTemplates.json'))) {
    if (-not (Test-Path -LiteralPath $candidate)) { continue }
    try {
        $savedTemplates = Get-Content -LiteralPath $candidate -Raw | ConvertFrom-Json | ConvertTo-Hashtable
        foreach ($vendor in $savedTemplates.Keys) {
            if (-not $script:PortTemplates.ContainsKey($vendor)) { $script:PortTemplates[$vendor] = @{} }
            foreach ($portType in $savedTemplates[$vendor].Keys) { $script:PortTemplates[$vendor][$portType] = $savedTemplates[$vendor][$portType] }
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to load PortTemplates.json:`n`n$($_.Exception.Message)`n`nUsing the built-in templates instead.", 'Template Load Error', 'OK', 'Warning') | Out-Null
    }
    break
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
    foreach ($resName in $script:EmbeddedResources.Keys) {
        try {
            $file = Export-EmbeddedResource -Name $resName -OutputPath $OutputPath -Force:$Force
            $exported += $file
        }
        catch {
            Write-Warning "Failed to export $($resName): $($_.Exception.Message)"
        }
    }
    return $exported
}

# ============================================
# END EMBEDDED RESOURCES
# ============================================

function Export-OctoResources {
    <#
    .SYNOPSIS
        Writes the chosen embedded resources to a folder, asking before overwriting.
    #>
    param([string[]]$Names, [string]$Folder)
    $exported = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $Names) {
        if (-not $script:EmbeddedResources.ContainsKey($name)) { continue }
        $target = Join-Path $Folder $name
        if (Test-Path -LiteralPath $target) {
            $answer = [System.Windows.Forms.MessageBox]::Show("File '$name' already exists.`n`nOverwrite?", 'File Exists', 'YesNoCancel', 'Question')
            if ($answer -eq [System.Windows.Forms.DialogResult]::Cancel) { break }
            if ($answer -eq [System.Windows.Forms.DialogResult]::No) { continue }
        }
        [System.IO.File]::WriteAllBytes($target, [Convert]::FromBase64String($script:EmbeddedResources[$name]))
        $exported.Add($name)
    }
    if ($exported.Count -gt 0) {
        [System.Windows.Forms.MessageBox]::Show("Exported $($exported.Count) file(s) to:`n$Folder`n`nFiles:`n$($exported -join "`n")", 'Export Complete', 'OK', 'Information') | Out-Null
    }
}

# ============================================
# APPLICATION STATE
# ============================================

$script:Settings = Get-OctoNavSettings
$script:CurrentTheme = Get-Theme -ThemeName $script:Settings.Theme
$script:IsRunningAsAdmin = Test-IsAdministrator
$script:outputDir = if ($env:OCTONAV_OUTPUT_DIR) { $env:OCTONAV_OUTPUT_DIR }
    elseif ($script:Settings.DefaultExportPath) { [string]$script:Settings.DefaultExportPath }
    else { 'C:\DNACenter_Reports' }
$script:AppClosing = $false

# Network configuration tab
$script:TargetAdapter = $null
$script:OriginalConfig = $null
$script:NewIPAddress = $null
$script:NewGateway = $null
$script:BatchProcess = $null

# DHCP tab
$script:dhcpResults = @()
$script:dhcpAnalysis = $null
$script:dhcpRunOptions = @{}
$script:dhcpJob = $null
$script:dhcpState = $null
$script:dhcpCacheJob = $null
$script:allDHCPScopes = @()
$script:scopeByDisplayName = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:scopeNamesUpper = @()
$script:selectedScopeNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:suppressScopeItemCheck = $false
$script:scopeCacheUpdated = $null
$script:dhcpRunUsedSelection = $false
$script:dhcpServerResolved = @{}

# DNA Center tab
$script:dnaVisibleDevices = [System.Collections.Generic.List[object]]::new()
$script:dnaCheckedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:dnaUpdatingChecks = $false

# Shared fonts (one GDI object each instead of one per control)
$script:Fonts = @{
    Normal      = New-Object System.Drawing.Font('Segoe UI', 9)
    Semibold    = New-Object System.Drawing.Font('Segoe UI Semibold', 9)
    CardTitle   = New-Object System.Drawing.Font('Segoe UI Semibold', 10.5)
    Nav         = New-Object System.Drawing.Font('Segoe UI', 10)
    NavSelected = New-Object System.Drawing.Font('Segoe UI Semibold', 10)
    StatValue   = New-Object System.Drawing.Font('Segoe UI Semibold', 18)
    Body        = New-Object System.Drawing.Font('Segoe UI', 10)
    HelpTitle   = New-Object System.Drawing.Font('Segoe UI Semibold', 16)
    HelpHeading = New-Object System.Drawing.Font('Segoe UI Semibold', 12.5)
    HelpLabel   = New-Object System.Drawing.Font('Segoe UI Semibold', 10)
    Spacer      = New-Object System.Drawing.Font('Segoe UI', 5)
    Mono        = New-Object System.Drawing.Font('Consolas', 9)
    MonoLarge   = New-Object System.Drawing.Font('Consolas', 10)
}

function New-OctoControl {
    <#
    .SYNOPSIS
        Creates a WinForms control: -Bounds x,y[,w,h], ordered -Props, optional -Parent.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [int[]]$Bounds,
        [System.Collections.IDictionary]$Props,
        $Parent
    )
    $c = New-Object -TypeName ('System.Windows.Forms.' + $Type)
    # Buttons are recoloured whenever they are enabled or disabled
    if ($Type -eq 'Button') { $c.Add_EnabledChanged({ Set-OctoButtonStyle -Button $this }) }
    if ($Bounds) {
        $c.Location = New-Object System.Drawing.Point($Bounds[0], $Bounds[1])
        if ($Bounds.Count -ge 4) { $c.Size = New-Object System.Drawing.Size($Bounds[2], $Bounds[3]) }
    }
    if ($Props) { foreach ($key in $Props.Keys) { $c.$key = $Props[$key] } }
    if ($Parent) { [void]$Parent.Controls.Add($c) }
    return $c
}

function New-OctoCard {
    <#
    .SYNOPSIS
        A bordered panel with a title - the building block of every tab.
        Content starts at y = 48 (the title row is 12..40).
    #>
    param([int[]]$Bounds, [string]$Title, $Parent, [string]$Anchor = 'Top,Left')
    $card = New-OctoControl Panel $Bounds ([ordered]@{ Tag = 'Card'; Anchor = $Anchor }) $Parent
    $card.Add_Paint($script:OctoBorderPainter)
    $card.Add_Resize({ $this.Invalidate() })
    if ($Title) { [void](New-OctoControl Label @(15, 15) ([ordered]@{ Text = $Title; AutoSize = $true; Font = $script:Fonts.CardTitle; Tag = 'CardTitle' }) $card) }
    return $card
}

function New-OctoFrame {
    # Bordered area with a little padding for one docked text control (logs, editor)
    param([int[]]$Bounds, $Parent, [string]$Anchor = 'Top,Bottom,Left,Right')
    $frame = New-OctoControl Panel $Bounds ([ordered]@{ Tag = 'LogFrame'; Anchor = $Anchor; Padding = (New-Object System.Windows.Forms.Padding(8, 6, 1, 1)) }) $Parent
    $frame.Add_Paint($script:OctoBorderPainter)
    $frame.Add_Resize({ $this.Invalidate() })
    return $frame
}

function New-OctoLogBox {
    # Read-only log inside a frame
    param([int[]]$Bounds, $Parent, [string]$Anchor = 'Top,Bottom,Left,Right', [bool]$WordWrap = $true)
    $frame = New-OctoFrame -Bounds $Bounds -Parent $Parent -Anchor $Anchor
    return New-OctoControl RichTextBox $null ([ordered]@{
        Dock = 'Fill'; BorderStyle = 'None'; Font = $script:Fonts.Mono; ReadOnly = $true; ScrollBars = 'Vertical'
        WordWrap = $WordWrap; HideSelection = $false; DetectUrls = $false; Multiline = $true
    }) $frame
}

function Show-OctoMessage {
    param([string]$Text, [string]$Title = 'OctoNav', [string]$Icon = 'Information', [string]$Buttons = 'OK')
    return [System.Windows.Forms.MessageBox]::Show($Text, $Title, $Buttons, $Icon)
}

# ============================================
# STARTUP SECURITY CHECK (before the window is built)
# ============================================

try {
    if ($script:RequireStartupPassword) {
        if (Test-StartupPasswordExists) {
            Write-SecurityAudit -Level Info -Event 'OctoNav startup' -Details 'Password authentication required'
            if (-not (Show-StartupPasswordDialog)) {
                Write-SecurityAudit -Level Warning -Event 'Authentication failed or cancelled' -Details 'Application exit'
                exit 0
            }
            Write-SecurityAudit -Level Success -Event 'Authentication successful' -Details 'OctoNav starting'
        } else {
            Write-SecurityAudit -Level Info -Event 'First run detected' -Details 'Setting up startup password'
            if (-not (Show-StartupPasswordDialog -IsFirstRun)) {
                Show-OctoMessage -Text "Startup password is required for security.`n`nOctoNav will now exit." -Title 'Password Required' -Icon Warning | Out-Null
                Write-SecurityAudit -Level Warning -Event 'First run - password not set' -Details 'Application exit'
                exit 0
            }
            Write-SecurityAudit -Level Success -Event 'First run - password configured' -Details 'OctoNav starting'
        }
    } else {
        Write-SecurityAudit -Level Info -Event 'OctoNav startup' -Details 'Team mode - no startup password'
    }
} catch {
    Show-OctoMessage -Text "Security initialization failed:`n`n$($_.Exception.Message)`n`nOctoNav will now exit." -Title 'Security Error' -Icon Error | Out-Null
    Write-SecurityAudit -Level Critical -Event 'Security initialization failed' -Details $_.Exception.Message
    exit 1
}

# ============================================
# MAIN FORM
# ============================================

$mainForm = New-Object System.Windows.Forms.Form
$mainForm.SuspendLayout()
$mainForm.Text = 'OctoNav - Network Management Tool'
$windowWidth = 1245; $windowHeight = 800
try {
    if ($script:Settings.WindowSize.Width -ge 800) { $windowWidth = [int]$script:Settings.WindowSize.Width }
    if ($script:Settings.WindowSize.Height -ge 500) { $windowHeight = [int]$script:Settings.WindowSize.Height }
} catch { }
$mainForm.Size = New-Object System.Drawing.Size($windowWidth, $windowHeight)
$mainForm.StartPosition = 'CenterScreen'
$mainForm.FormBorderStyle = 'Sizable'
$mainForm.MinimumSize = New-Object System.Drawing.Size(1000, 600)
$mainForm.Font = $script:Fonts.Normal
if ($script:Settings.WindowMaximized) { $mainForm.WindowState = 'Maximized' }

# ============================================
# MENU BAR
# ============================================

$menuStrip = New-Object System.Windows.Forms.MenuStrip
$menuStrip.Padding = New-Object System.Windows.Forms.Padding(6, 3, 0, 1)

$menuFile = New-Object System.Windows.Forms.ToolStripMenuItem('&File')
$menuFileExit = New-Object System.Windows.Forms.ToolStripMenuItem('E&xit')
$menuFileExit.ShortcutKeys = [System.Windows.Forms.Keys]::Alt -bor [System.Windows.Forms.Keys]::F4
$menuFileExit.Add_Click({ $mainForm.Close() })
[void]$menuFile.DropDownItems.Add($menuFileExit)

$menuTools = New-Object System.Windows.Forms.ToolStripMenuItem('&Tools')
$menuToolsRefresh = New-Object System.Windows.Forms.ToolStripMenuItem('&Refresh Dashboard')
$menuToolsRefresh.ShortcutKeys = [System.Windows.Forms.Keys]::F5
$menuToolsRefresh.Add_Click({ Update-Dashboard -IncludeAdapters })
[void]$menuTools.DropDownItems.Add($menuToolsRefresh)
[void]$menuTools.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator))
$menuToolsExportResources = New-Object System.Windows.Forms.ToolStripMenuItem('Export &Resources...')
$menuToolsExportResources.Add_Click({
    if (-not $script:EmbeddedResources -or $script:EmbeddedResources.Count -eq 0) {
        Show-OctoMessage -Text "No embedded resources found in this build.`n`nTo embed resources:`n1. Place files in the 'resources' folder`n2. Run Package-Resources.ps1" -Title 'No Resources' | Out-Null
        return
    }
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = 'Select folder to export resources to'
    if ($folderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try { Export-OctoResources -Names @($script:EmbeddedResources.Keys) -Folder $folderBrowser.SelectedPath }
        catch { Show-OctoMessage -Text "Error exporting resources:`n`n$($_.Exception.Message)" -Title 'Export Error' -Icon Error | Out-Null }
    }
})
[void]$menuTools.DropDownItems.Add($menuToolsExportResources)

$menuView = New-Object System.Windows.Forms.ToolStripMenuItem('&View')
$menuViewTheme = New-Object System.Windows.Forms.ToolStripMenuItem('Toggle &Theme')
$menuViewTheme.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::T
$menuViewTheme.Add_Click({
    $previous = $script:CurrentTheme
    $newTheme = if ($previous.Name -eq 'Light') { 'Dark' } else { 'Light' }
    $script:CurrentTheme = Get-Theme -ThemeName $newTheme
    $script:Settings.Theme = $newTheme
    [void](Save-OctoNavSettings -Settings $script:Settings)
    Set-OctoTheme
    foreach ($log in @($netLogBox, $dhcpLogBox, $dnaLogBox)) { Convert-OctoLogColors -LogBox $log -From $previous -To $script:CurrentTheme }
})
[void]$menuView.DropDownItems.Add($menuViewTheme)
[void]$menuView.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator))
# Menu shortcuts work wherever the focus is (Ctrl+Tab never reaches a form's KeyDown)
$menuViewNextTab = New-Object System.Windows.Forms.ToolStripMenuItem('&Next Tab')
$menuViewNextTab.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::Tab
$menuViewNextTab.Add_Click({ Select-OctoPage -Index (($script:OctoPageIndex + 1) % $script:OctoPages.Count) })
[void]$menuView.DropDownItems.Add($menuViewNextTab)
$menuViewPreviousTab = New-Object System.Windows.Forms.ToolStripMenuItem('&Previous Tab')
$menuViewPreviousTab.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::Shift -bor [System.Windows.Forms.Keys]::Tab
$menuViewPreviousTab.Add_Click({ Select-OctoPage -Index (($script:OctoPageIndex + $script:OctoPages.Count - 1) % $script:OctoPages.Count) })
[void]$menuView.DropDownItems.Add($menuViewPreviousTab)

$menuHelp = New-Object System.Windows.Forms.ToolStripMenuItem('&Help')
$menuHelpAbout = New-Object System.Windows.Forms.ToolStripMenuItem('&About')
$menuHelpAbout.Add_Click({
    $about = "OctoNav`n`n" +
        "- Dashboard`n- Network Configuration (requires admin)`n- DHCP Statistics (failover-aware)`n" +
        "- DNA Center API functions`n- File Compare, Port Config, RDOX Exports`n`n" +
        "Settings folder: $script:DataDir"
    Show-OctoMessage -Text $about -Title 'About OctoNav' | Out-Null
})
[void]$menuHelp.DropDownItems.Add($menuHelpAbout)

$menuStrip.Items.AddRange([System.Windows.Forms.ToolStripItem[]]@($menuFile, $menuTools, $menuView, $menuHelp))

# ============================================
# NAVIGATION BAR AND PAGES
# ============================================
# Every page is laid out for PageSize: a smaller window scrolls, a larger one stretches
$script:PageSize = New-Object System.Drawing.Size(1180, 610)
$script:OctoPages = [System.Collections.Generic.List[object]]::new()
$script:OctoNavItems = [System.Collections.Generic.List[object]]::new()
$script:OctoPageIndex = -1

$script:navBar = New-OctoControl Panel $null ([ordered]@{ Dock = 'Top'; Height = 42; Tag = 'Header' })
$script:navBar.Add_Paint($script:OctoBottomLinePainter)
$script:navBar.Add_Resize({ $this.Invalidate() })
$script:navIndicator = New-OctoControl Panel @(0, 39, 10, 3) ([ordered]@{ Tag = 'NavIndicator' }) $script:navBar
# Pages are filled while the host is suspended, so their controls are anchored to PageSize
$script:pageHost = New-OctoControl Panel $null ([ordered]@{ Dock = 'Fill'; Tag = 'Page' })
$script:pageHost.SuspendLayout()
# Docking order (see Show): status bar, menu, navigation bar, then pages fill the rest
$mainForm.Controls.Add($script:pageHost)
$mainForm.Controls.Add($script:navBar)
$mainForm.Controls.Add($menuStrip)
$mainForm.MainMenuStrip = $menuStrip

function New-OctoTab {
    <#
    .SYNOPSIS
        Adds a page and its entry in the navigation bar.
    #>
    param([string]$Text)
    $page = New-Object System.Windows.Forms.Panel
    $page.Text = $Text
    $page.Tag = 'Page'
    $page.Size = $script:PageSize
    $page.AutoScroll = $true
    $page.AutoScrollMinSize = $script:PageSize
    $page.Dock = 'Fill'
    $page.Visible = $false
    $script:pageHost.Controls.Add($page)
    $script:OctoPages.Add($page)

    $x = 8
    if ($script:OctoNavItems.Count -gt 0) { $x = $script:OctoNavItems[$script:OctoNavItems.Count - 1].Right }
    $width = [System.Windows.Forms.TextRenderer]::MeasureText($Text, $script:Fonts.NavSelected).Width + 28
    $navItem = New-OctoControl Label @($x, 0, $width, 39) ([ordered]@{ Text = $Text; TextAlign = 'MiddleCenter'; Font = $script:Fonts.Nav; Tag = 'NavItem'; Cursor = [System.Windows.Forms.Cursors]::Hand }) $script:navBar
    $navItem.Add_Click({ Select-OctoPage -Index $script:OctoNavItems.IndexOf($this) })
    $navItem.Add_MouseEnter({ if ($script:OctoNavItems.IndexOf($this) -ne $script:OctoPageIndex) { $this.ForeColor = $script:CurrentTheme.NavHover } })
    $navItem.Add_MouseLeave({ Update-OctoNav })
    $script:OctoNavItems.Add($navItem)
    return $page
}

function Select-OctoPage {
    param([int]$Index)
    if ($Index -lt 0 -or $Index -ge $script:OctoPages.Count) { return }
    # Show the new page before hiding the old one (no flash of the empty host)
    $script:OctoPages[$Index].Visible = $true
    for ($i = 0; $i -lt $script:OctoPages.Count; $i++) { if ($i -ne $Index) { $script:OctoPages[$i].Visible = $false } }
    $script:OctoPageIndex = $Index
    Update-OctoNav
}

function Update-OctoNav {
    # Selected entry: accent colour, semibold, underline
    for ($i = 0; $i -lt $script:OctoNavItems.Count; $i++) {
        $navItem = $script:OctoNavItems[$i]
        if ($i -eq $script:OctoPageIndex) {
            $navItem.ForeColor = $script:CurrentTheme.NavSelected
            $navItem.Font = $script:Fonts.NavSelected
            $script:navIndicator.Location = New-Object System.Drawing.Point(($navItem.Left + 12), 39)
            $script:navIndicator.Size = New-Object System.Drawing.Size([Math]::Max(0, $navItem.Width - 24), 3)
        } else {
            $navItem.ForeColor = $script:CurrentTheme.NavText
            $navItem.Font = $script:Fonts.Nav
        }
    }
}

# ============================================
# TAB: DASHBOARD
# ============================================

$tab0 = New-OctoTab -Text 'Dashboard'
# Four equal status cards that stretch with the window
$statsTable = New-OctoControl TableLayoutPanel @(10, 16, 1160, 100) ([ordered]@{ ColumnCount = 4; RowCount = 1; Anchor = 'Top,Left,Right' }) $tab0
foreach ($i in 1..4) { [void]$statsTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 25))) }
[void]$statsTable.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$script:adminPanel = New-DashboardPanel -Title 'Admin Status' -Value '...'
$script:networkPanel = New-DashboardPanel -Title 'Network Adapters' -Value '...'
$script:dnaPanel = New-DashboardPanel -Title 'DNA Center' -Value 'Not Connected'
$script:dhcpPanel = New-DashboardPanel -Title 'DHCP Servers' -Value '...'
$column = 0
foreach ($p in @($script:adminPanel, $script:networkPanel, $script:dnaPanel, $script:dhcpPanel)) { $statsTable.Controls.Add($p.Panel, $column, 0); $column++ }
$activityCard = New-OctoCard -Bounds @(16, 128, 1148, 466) -Title 'Recent Activity' -Parent $tab0 -Anchor 'Top,Bottom,Left,Right'
$script:lstRecentActivity = New-OctoControl ListBox @(16, 48, 1116, 402) ([ordered]@{ Font = $script:Fonts.Body; BorderStyle = 'None'; IntegralHeight = $false; Anchor = 'Top,Bottom,Left,Right' }) $activityCard

function Update-Dashboard {
    param([switch]$IncludeAdapters)
    try {
        if ($script:IsRunningAsAdmin) { Set-DashboardValue -Panel $script:adminPanel -Value 'Active' -Tone Success }
        else { Set-DashboardValue -Panel $script:adminPanel -Value 'Standard' -Tone Warning }
        if ($IncludeAdapters) {
            Set-DashboardValue -Panel $script:networkPanel -Value ([string]@(Get-NetAdapter -ErrorAction SilentlyContinue).Count)
        }
        if (Test-DNACTokenValid) { Set-DashboardValue -Panel $script:dnaPanel -Value 'Connected' -Tone Success }
        else { Set-DashboardValue -Panel $script:dnaPanel -Value 'Disconnected' -Tone Muted }
        Set-DashboardValue -Panel $script:dhcpPanel -Value ([string]$script:lstDHCPServers.Items.Count)
        $script:lstRecentActivity.BeginUpdate()
        try {
            $script:lstRecentActivity.Items.Clear()
            $script:lstRecentActivity.Items.AddRange([object[]]@(Get-RecentActivity -Settings $script:Settings -Count 10))
        } finally { $script:lstRecentActivity.EndUpdate() }
    } catch {
        Write-Warning "Error updating dashboard: $($_.Exception.Message)"
    }
}

# ============================================
# TAB: NETWORK CONFIGURATION
# ============================================

$tab1 = New-OctoTab -Text 'Network Configuration'
$adminTone = if ($script:IsRunningAsAdmin) { 'InfoSuccess' } else { 'InfoWarning' }
$adminBar = New-OctoControl Panel @(16, 16, 1148, 40) ([ordered]@{ Tag = $adminTone; Anchor = 'Top,Left,Right' }) $tab1
$lblAdminStatus = New-OctoControl Label $null ([ordered]@{ Dock = 'Fill'; TextAlign = 'MiddleLeft'; Font = $script:Fonts.Semibold; Tag = $adminTone; Padding = (New-Object System.Windows.Forms.Padding(12, 0, 12, 0)) }) $adminBar
$lblAdminStatus.Text = if ($script:IsRunningAsAdmin) { 'Running as Administrator - network configuration is enabled' }
    else { "Running as a standard user - this tab needs 'Run as Administrator'. All other tabs work normally." }
$netCard = New-OctoCard -Bounds @(16, 68, 380, 316) -Title 'Adapter Configuration' -Parent $tab1
$btnFindNetwork = New-OctoControl Button @(16, 48, 348, 32) ([ordered]@{ Text = 'Find Unidentified Network' }) $netCard
[void](New-OctoControl Label @(16, 101, 120, 20) ([ordered]@{ Text = 'New IP Address' }) $netCard)
$txtIPAddress = New-OctoControl TextBox @(140, 98, 224, 23) ([ordered]@{ Text = '192.168.1.101' }) $netCard
[void](New-OctoControl Label @(16, 135, 120, 20) ([ordered]@{ Text = 'Gateway' }) $netCard)
$txtGateway = New-OctoControl TextBox @(140, 132, 224, 23) ([ordered]@{ Text = '192.168.1.100' }) $netCard
[void](New-OctoControl Label @(16, 169, 120, 20) ([ordered]@{ Text = 'Prefix Length' }) $netCard)
$txtPrefix = New-OctoControl TextBox @(140, 166, 60, 23) ([ordered]@{ Text = '24' }) $netCard
$btnApplyConfig = New-OctoControl Button @(16, 212, 170, 34) ([ordered]@{ Text = 'Apply Configuration'; Tag = 'Primary' }) $netCard
$btnRestoreDefaults = New-OctoControl Button @(194, 212, 170, 34) ([ordered]@{ Text = 'Restore Defaults' }) $netCard
[void](New-OctoControl Label @(16, 258, 348, 50) ([ordered]@{ Text = 'Apply sets this address on the unidentified (169.254.x.x) adapter and starts the TFTP server. Restore Defaults switches it back to DHCP.'; Tag = 'Muted' }) $netCard)
$netLogCard = New-OctoCard -Bounds @(408, 68, 756, 526) -Title 'Log' -Parent $tab1 -Anchor 'Top,Bottom,Left,Right'
$netLogBox = New-OctoLogBox -Bounds @(16, 48, 724, 462) -Parent $netLogCard -WordWrap $false

function Set-TargetAdapter {
    param($NetworkInfo)
    $script:TargetAdapter = $NetworkInfo.Adapter
    $script:OriginalConfig = @{
        NetworkCategory = $NetworkInfo.Profile.NetworkCategory
        DHCP = (Get-NetIPInterface -InterfaceIndex $script:TargetAdapter.ifIndex -AddressFamily IPv4).Dhcp
    }
}

$btnFindNetwork.Add_Click({
    try {
        $networkInfo = Find-UnidentifiedNetwork -LogBox $netLogBox
        if ($networkInfo) {
            Set-TargetAdapter -NetworkInfo $networkInfo
            Write-Log -Message 'Adapter found and ready for configuration' -Color 'Success' -LogBox $netLogBox
        } else {
            Write-Log -Message 'No unidentified network found' -Color 'Error' -LogBox $netLogBox
        }
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color 'Error' -LogBox $netLogBox
    }
})

$btnApplyConfig.Add_Click({
    try {
        $ip = $txtIPAddress.Text.Trim()
        $gateway = $txtGateway.Text.Trim()
        $prefixText = $txtPrefix.Text.Trim()
        if (-not $script:IsRunningAsAdmin) { Show-AdminRequiredMessage -LogBox $netLogBox; return }
        if (-not (Test-IPAddress -IPAddress $ip)) {
            Write-Log -Message 'Invalid IP address format. Please enter a valid IPv4 address (e.g., 192.168.1.100)' -Color 'Error' -LogBox $netLogBox
            Show-OctoMessage -Text 'Invalid IP address format!' -Title 'Validation Error' -Icon Warning | Out-Null
            return
        }
        if (-not (Test-IPAddress -IPAddress $gateway)) {
            Write-Log -Message 'Invalid gateway format. Please enter a valid IPv4 address' -Color 'Error' -LogBox $netLogBox
            Show-OctoMessage -Text 'Invalid gateway format!' -Title 'Validation Error' -Icon Warning | Out-Null
            return
        }
        if (-not (Test-PrefixLength -Prefix $prefixText)) {
            Write-Log -Message 'Invalid prefix length. Must be a whole number between 0 and 32' -Color 'Error' -LogBox $netLogBox
            Show-OctoMessage -Text 'Invalid prefix length! Must be between 0 and 32' -Title 'Validation Error' -Icon Warning | Out-Null
            return
        }
        if (-not $script:TargetAdapter) {
            Write-Log -Message 'Finding unidentified network adapter...' -Color 'Cyan' -LogBox $netLogBox
            $networkInfo = Find-UnidentifiedNetwork -LogBox $netLogBox
            if (-not $networkInfo) {
                Write-Log -Message 'No unidentified network found. Cannot apply configuration.' -Color 'Error' -LogBox $netLogBox
                Show-OctoMessage -Text 'No unidentified network found. Please ensure the network adapter is connected and has an APIPA address (169.254.x.x).' -Title 'No Network Found' -Icon Warning | Out-Null
                return
            }
            Set-TargetAdapter -NetworkInfo $networkInfo
            Write-Log -Message "Adapter found: $($script:TargetAdapter.Name)" -Color 'Success' -LogBox $netLogBox
        }
        $script:NewIPAddress = $ip
        $script:NewGateway = $gateway
        if (Set-NetworkConfiguration -Adapter $script:TargetAdapter -IPAddress $ip -Gateway $gateway -PrefixLength ([int]$prefixText) -LogBox $netLogBox) {
            Write-Log -Message 'Network configuration applied successfully!' -Color 'Success' -LogBox $netLogBox
            $batFile = Join-Path $script:AppRoot 'RunStandAloneMT.bat'
            if (Test-Path -LiteralPath $batFile) {
                Write-Log -Message 'Starting TFTP server (RunStandAloneMT.bat)...' -Color 'Cyan' -LogBox $netLogBox
                try {
                    $psi = New-Object System.Diagnostics.ProcessStartInfo
                    $psi.FileName = 'cmd.exe'
                    $psi.Arguments = "/c `"$batFile`""
                    $psi.WorkingDirectory = $script:AppRoot
                    $psi.UseShellExecute = $true
                    $script:BatchProcess = [System.Diagnostics.Process]::Start($psi)
                    Write-Log -Message "TFTP server started (PID: $($script:BatchProcess.Id))" -Color 'Success' -LogBox $netLogBox
                } catch {
                    Write-Log -Message "Failed to start TFTP server: $($_.Exception.Message)" -Color 'Warning' -LogBox $netLogBox
                }
            } else {
                Write-Log -Message 'RunStandAloneMT.bat not found - TFTP server not started' -Color 'Warning' -LogBox $netLogBox
            }
            Show-OctoMessage -Text 'Network configuration applied successfully!' -Title 'Success' | Out-Null
        }
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color 'Error' -LogBox $netLogBox
        Show-OctoMessage -Text "Error applying configuration: $($_.Exception.Message)" -Title 'Error' -Icon Error | Out-Null
    }
})

$btnRestoreDefaults.Add_Click({
    try {
        if (-not $script:IsRunningAsAdmin) { Show-AdminRequiredMessage -LogBox $netLogBox; return }
        $answer = Show-OctoMessage -Text 'This will stop the TFTP server (if running), restore the network adapter to DHCP, and remove the static IP configuration. Continue?' -Title 'Confirm Restore Defaults' -Icon Question -Buttons YesNo
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        if ($script:BatchProcess -and -not $script:BatchProcess.HasExited) {
            Write-Log -Message 'Stopping TFTP server...' -Color 'Yellow' -LogBox $netLogBox
            try {
                Stop-Process -Id $script:BatchProcess.Id -Force -ErrorAction SilentlyContinue
                Write-Log -Message 'TFTP server stopped' -Color 'Success' -LogBox $netLogBox
            } catch {
                Write-Log -Message "Warning: Could not stop TFTP server: $($_.Exception.Message)" -Color 'Warning' -LogBox $netLogBox
            }
        }
        $script:BatchProcess = $null
        if (Restore-NetworkDefaults -LogBox $netLogBox) {
            Show-OctoMessage -Text 'Network defaults restored!' -Title 'Success' | Out-Null
        }
        $script:TargetAdapter = $null
        $script:OriginalConfig = $null
        $script:NewIPAddress = $null
        $script:NewGateway = $null
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color 'Error' -LogBox $netLogBox
        Show-OctoMessage -Text "Error restoring defaults: $($_.Exception.Message)" -Title 'Error' -Icon Error | Out-Null
    }
})

# ============================================
# TAB: DHCP STATISTICS
# ============================================

$tab2 = New-OctoTab -Text 'DHCP Statistics'
$toolTip = New-Object System.Windows.Forms.ToolTip
$toolTip.AutoPopDelay = 15000

# --- Servers (left column)
$dhcpServerCard = New-OctoCard -Bounds @(16, 16, 700, 200) -Title 'DHCP Servers' -Parent $tab2
$script:lblLastRefresh = New-OctoControl Label @(140, 19, 380, 20) ([ordered]@{ Text = 'Last refreshed: Never'; Tag = 'Muted' }) $dhcpServerCard
$btnRefreshDHCPServers = New-OctoControl Button @(534, 12, 150, 28) ([ordered]@{ Text = 'Refresh Server List' }) $dhcpServerCard
$script:lstDHCPServers = New-OctoControl CheckedListBox @(16, 50, 420, 104) ([ordered]@{ CheckOnClick = $true; IntegralHeight = $false }) $dhcpServerCard
$btnSelectAll = New-OctoControl Button @(448, 50, 114, 28) ([ordered]@{ Text = 'Select All' }) $dhcpServerCard
$btnSelectNone = New-OctoControl Button @(570, 50, 114, 28) ([ordered]@{ Text = 'Select None' }) $dhcpServerCard
[void](New-OctoControl Label @(448, 91, 236, 18) ([ordered]@{ Text = 'Or enter names (comma-separated)' }) $dhcpServerCard)
$txtSpecificServers = New-OctoControl TextBox @(448, 111, 236, 23) ([ordered]@{ MaxLength = 1000 }) $dhcpServerCard
[void](New-OctoControl Label @(16, 166, 668, 20) ([ordered]@{ Text = 'Nothing selected or entered = all DHCP servers in Active Directory. The server list is cached.'; Tag = 'Muted' }) $dhcpServerCard)

# --- Scopes (left column, grows with the window)
$dhcpScopeCard = New-OctoCard -Bounds @(16, 228, 700, 314) -Title 'Scopes (Optional)' -Parent $tab2 -Anchor 'Top,Bottom,Left'
$script:lblScopeCacheStatus = New-OctoControl Label @(162, 19, 380, 20) ([ordered]@{ Text = 'Cache: Not loaded'; Tag = 'Muted' }) $dhcpScopeCard
$script:btnRefreshScopeCache = New-OctoControl Button @(554, 12, 130, 28) ([ordered]@{ Text = 'Refresh Cache' }) $dhcpScopeCard
[void](New-OctoControl Label @(16, 55, 40, 20) ([ordered]@{ Text = 'Filter' }) $dhcpScopeCard)
$script:ScopeFilterPlaceholder = 'e.g., SITE1, SITE2 (min 3 chars)'
$script:PrefixFilterPlaceholder = 'e.g., ZA (2+ chars)'
$script:txtScopeListFilter = New-OctoControl TextBox @(60, 52, 290, 23) ([ordered]@{ MaxLength = 500; Text = $script:ScopeFilterPlaceholder }) $dhcpScopeCard
[void](New-OctoControl Label @(366, 55, 40, 20) ([ordered]@{ Text = 'Prefix' }) $dhcpScopeCard)
$script:txtPrefixFilter = New-OctoControl TextBox @(410, 52, 136, 23) ([ordered]@{ MaxLength = 10; Text = $script:PrefixFilterPlaceholder }) $dhcpScopeCard
$script:lstDHCPScopes = New-OctoControl CheckedListBox @(16, 86, 530, 184) ([ordered]@{ CheckOnClick = $true; IntegralHeight = $false; Anchor = 'Top,Bottom,Left' }) $dhcpScopeCard
$btnSelectAllScopes = New-OctoControl Button @(558, 86, 126, 28) ([ordered]@{ Text = 'Select All Visible' }) $dhcpScopeCard
$btnSelectNoneScopes = New-OctoControl Button @(558, 120, 126, 28) ([ordered]@{ Text = 'Select None' }) $dhcpScopeCard
$script:lblVisibleScopes = New-OctoControl Label @(558, 156, 126, 40) ([ordered]@{ Tag = 'Muted' }) $dhcpScopeCard
[void](New-OctoControl Label @(16, 280, 668, 20) ([ordered]@{ Text = 'Refresh Cache, filter (comma = OR), then Select All Visible. Selections are kept when the filter changes.'; Tag = 'Muted'; Anchor = 'Bottom,Left' }) $dhcpScopeCard)

# --- Actions (bottom left)
$btnCollectDHCP = New-OctoControl Button @(16, 554, 220, 40) ([ordered]@{ Text = 'Collect DHCP Statistics'; Tag = 'Primary'; Anchor = 'Bottom,Left' }) $tab2
$btnStopDHCP = New-OctoControl Button @(244, 554, 90, 40) ([ordered]@{ Text = 'Stop'; Tag = 'Danger'; Enabled = $false; Anchor = 'Bottom,Left' }) $tab2

# --- Options (right column)
$dhcpOptionsCard = New-OctoCard -Bounds @(728, 16, 436, 136) -Title 'Options' -Parent $tab2 -Anchor 'Top,Left,Right'
$chkIncludeDNS = New-OctoControl CheckBox @(16, 46, 200, 22) ([ordered]@{ Text = 'DNS Servers (Option 6)' }) $dhcpOptionsCard
$chkIncludeOption60 = New-OctoControl CheckBox @(224, 46, 200, 22) ([ordered]@{ Text = 'Option 60 (Vendor Class)' }) $dhcpOptionsCard
$chkIncludeOption43 = New-OctoControl CheckBox @(16, 72, 200, 22) ([ordered]@{ Text = 'Option 43 (Vendor-Specific)' }) $dhcpOptionsCard
$script:chkShowAllOptions = New-OctoControl CheckBox @(224, 72, 200, 22) ([ordered]@{ Text = 'All Configured Options' }) $dhcpOptionsCard
$script:chkGroupByScope = New-OctoControl CheckBox @(16, 98, 200, 22) ([ordered]@{ Text = 'Group by Scope ID on Export' }) $dhcpOptionsCard
[void](New-OctoControl Label @(224, 100, 100, 20) ([ordered]@{ Text = 'Parallel queries' }) $dhcpOptionsCard)
$defaultParallel = 20
try { if ([int]$script:Settings.DHCPParallelServers -ge 1 -and [int]$script:Settings.DHCPParallelServers -le 64) { $defaultParallel = [int]$script:Settings.DHCPParallelServers } } catch { }
$script:numConcurrency = New-OctoControl NumericUpDown @(328, 97, 60, 23) ([ordered]@{ Minimum = 1; Maximum = 64; Value = $defaultParallel }) $dhcpOptionsCard
$toolTip.SetToolTip($script:chkGroupByScope, "One row per Scope ID:`n- failover partners report the whole scope, so they are counted once`n- split scopes (same ID, no failover) have their pools added together`n- inactive copies are not counted")
$toolTip.SetToolTip($script:numConcurrency, 'How many DHCP servers (and option lookups) are queried at the same time.')

# --- Log and export (right column)
$dhcpLogCard = New-OctoCard -Bounds @(728, 164, 436, 430) -Title 'Collection Log' -Parent $tab2 -Anchor 'Top,Bottom,Left,Right'
$btnExportDHCPWorkDir = New-OctoControl Button @(140, 12, 148, 28) ([ordered]@{ Text = 'Export to Working Dir'; Enabled = $false; Anchor = 'Top,Right' }) $dhcpLogCard
$btnExportDHCPFolder = New-OctoControl Button @(296, 12, 124, 28) ([ordered]@{ Text = 'Export to Folder...'; Enabled = $false; Anchor = 'Top,Right' }) $dhcpLogCard
$dhcpLogBox = New-OctoLogBox -Bounds @(16, 50, 404, 340) -Parent $dhcpLogCard
[void](New-OctoControl Label @(16, 398, 404, 20) ([ordered]@{ Text = 'Results are exported automatically after each collection.'; Tag = 'Muted'; Anchor = 'Bottom,Left,Right' }) $dhcpLogCard)

# --- Helpers -----------------------------------------------------------------

function Write-DhcpStateLog {
    # Moves queued collector messages into the log box
    param($State)
    if ($null -eq $State) { return }
    foreach ($entry in $State.Log) { Write-Log -Message $entry.Message -Color $entry.Color -LogBox $dhcpLogBox }
    $State.Log.Clear()
}

function Set-DhcpServerList {
    param([object[]]$Servers)
    $items = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $Servers) {
        if ($null -eq $s -or [string]::IsNullOrWhiteSpace([string]$s.DnsName)) { continue }
        if ($seen.Add([string]$s.DnsName)) { $items.Add(('{0} ({1})' -f $s.DnsName, $s.IPAddress)) }
    }
    $script:lstDHCPServers.BeginUpdate()
    try {
        $script:lstDHCPServers.Items.Clear()
        $script:lstDHCPServers.Items.AddRange($items.ToArray())
    } finally { $script:lstDHCPServers.EndUpdate() }
    Set-DashboardValue -Panel $script:dhcpPanel -Value ([string]$items.Count)
}

function Get-CheckedDhcpServerEntries {
    # "dhcp01.contoso.com (10.1.1.5)" -> @{ Name; IP }
    foreach ($item in $script:lstDHCPServers.CheckedItems) {
        $text = [string]$item
        if ($text -match '^(.+?)\s+\(([^)]*)\)\s*$') { @{ Name = $Matches[1].Trim(); IP = $Matches[2].Trim() } }
        elseif ($text.Trim()) { @{ Name = $text.Trim(); IP = $null } }
    }
}

function Set-DhcpScopeList {
    <#
    .SYNOPSIS
        Replaces the scope cache in memory and shows it (sorted by display name).
    #>
    param([object[]]$Scopes)
    $valid = [System.Collections.Generic.List[object]]::new()
    foreach ($s in $Scopes) { if ($null -ne $s -and $s.DisplayName) { $valid.Add($s) } }
    $sorted = $valid.ToArray()
    $keys = [string[]]@(foreach ($s in $sorted) { [string]$s.DisplayName })
    [Array]::Sort($keys, $sorted, [System.StringComparer]::OrdinalIgnoreCase)
    $script:allDHCPScopes = $sorted
    $script:scopeNamesUpper = [string[]]@(foreach ($k in $keys) { $k.ToUpperInvariant() })
    $script:scopeByDisplayName.Clear()
    foreach ($s in $sorted) { $script:scopeByDisplayName[[string]$s.DisplayName] = $s }
    $script:selectedScopeNames.Clear()
    Reset-ScopeFilterBoxes
    Update-ScopeListView
}

function Reset-ScopeFilterBoxes {
    $script:filterChangeFromCode = $true
    try {
        $script:txtScopeListFilter.Text = $script:ScopeFilterPlaceholder
        $script:txtPrefixFilter.Text = $script:PrefixFilterPlaceholder
    } finally { $script:filterChangeFromCode = $false }
    Update-ScopeFilterColors
}

function Update-ScopeFilterColors {
    # Placeholder text is muted, typed text is normal (also after a theme change)
    foreach ($pair in @(@($script:txtScopeListFilter, $script:ScopeFilterPlaceholder), @($script:txtPrefixFilter, $script:PrefixFilterPlaceholder))) {
        $pair[0].ForeColor = if ($pair[0].Text -eq $pair[1]) { $script:CurrentTheme.TextMuted } else { $script:CurrentTheme.InputText }
    }
}

function Update-ScopeCountLabel {
    $visible = $script:lstDHCPScopes.Items.Count
    $selected = $script:selectedScopeNames.Count
    $script:lblVisibleScopes.Text = if ($selected -gt 0) { "$visible visible`n$selected selected" } else { "$visible visible" }
}

function Update-ScopeListView {
    <#
    .SYNOPSIS
        Applies the Contains filter (3+ chars, comma = OR) and Prefix filter (2+ chars)
        to the cached scopes and shows the matches, keeping earlier selections.
    #>
    $containsText = $script:txtScopeListFilter.Text.Trim()
    if ($containsText -eq $script:ScopeFilterPlaceholder) { $containsText = '' }
    $prefixText = $script:txtPrefixFilter.Text.Trim()
    if ($prefixText -eq $script:PrefixFilterPlaceholder) { $prefixText = '' }

    $containsTerms = @($containsText.Split(',') | ForEach-Object { $_.Trim().ToUpperInvariant() } | Where-Object { $_.Length -ge 3 })
    $prefixTerms = @($prefixText.Split(',') | ForEach-Object { $_.Trim().ToUpperInvariant() } | Where-Object { $_.Length -ge 2 })
    $containsWaiting = $containsText -and $containsTerms.Count -eq 0
    $prefixWaiting = $prefixText -and $prefixTerms.Count -eq 0
    if ($containsWaiting -and $prefixWaiting) { $script:lblVisibleScopes.Text = '(filter: 3+ chars, prefix: 2+ chars)'; return }
    if ($containsWaiting) { $script:lblVisibleScopes.Text = '(type 3+ chars to filter)'; return }
    if ($prefixWaiting) { $script:lblVisibleScopes.Text = '(type 2+ chars for prefix)'; return }

    $matchesList = [System.Collections.Generic.List[object]]::new()
    $names = $script:scopeNamesUpper
    $scopes = $script:allDHCPScopes
    for ($i = 0; $i -lt $names.Count; $i++) {
        $upper = $names[$i]
        if ($prefixTerms.Count -gt 0) {
            $ok = $false
            foreach ($p in $prefixTerms) { if ($upper.StartsWith($p, [System.StringComparison]::Ordinal)) { $ok = $true; break } }
            if (-not $ok) { continue }
        }
        if ($containsTerms.Count -gt 0) {
            $ok = $false
            foreach ($t in $containsTerms) { if ($upper.Contains($t)) { $ok = $true; break } }
            if (-not $ok) { continue }
        }
        $matchesList.Add([string]$scopes[$i].DisplayName)
    }

    $list = $script:lstDHCPScopes
    $list.BeginUpdate()
    $script:suppressScopeItemCheck = $true
    try {
        $list.Items.Clear()
        $list.Items.AddRange($matchesList.ToArray())
        if ($script:selectedScopeNames.Count -gt 0) {
            for ($i = 0; $i -lt $list.Items.Count; $i++) {
                if ($script:selectedScopeNames.Contains([string]$list.Items[$i])) { $list.SetItemChecked($i, $true) }
            }
        }
    } finally {
        $script:suppressScopeItemCheck = $false
        $list.EndUpdate()
    }
    Update-ScopeCountLabel
}

function Set-DhcpBusy {
    param([bool]$Busy)
    $btnCollectDHCP.Enabled = -not $Busy
    $btnStopDHCP.Enabled = $Busy
    $script:btnRefreshScopeCache.Enabled = -not $Busy
    $btnRefreshDHCPServers.Enabled = -not $Busy
}

function Start-DhcpServerDiscovery {
    <#
    .SYNOPSIS
        Refreshes the server list from Active Directory in the background.
    #>
    param([switch]$Quiet)
    if ($script:dhcpJob -and -not $script:dhcpJob.Completed) { return }
    Set-DhcpBusy -Busy $true
    $btnStopDHCP.Enabled = $false
    $script:lblLastRefresh.Text = 'Discovering servers...'
    if (-not $Quiet) { Write-Log -Message 'Discovering DHCP servers from Active Directory...' -Color 'Info' -LogBox $dhcpLogBox }
    $pool = New-OctoRunspacePool -MaxRunspaces 1 -FunctionNames $script:DhcpWorkerFunctions
    $script:dhcpJob = Start-OctoJob -Pool $pool -OnTaskComplete {
        param($job, $task, $result)
        $out = $result.Output
        if ($out -and $out.Success) {
            # Show the servers that will actually be queried (duplicates / stale entries merged)
            $script:dhcpServerResolved = $out.Resolved
            $notes = [System.Collections.Generic.List[string]]::new()
            $names = @(Merge-DhcpServerList -Entries @($out.Servers) -Resolved $out.Resolved -Notes $notes)
            $ipByName = @{}
            foreach ($s in $out.Servers) { if ($s.Name -and -not $ipByName.ContainsKey([string]$s.Name)) { $ipByName[[string]$s.Name] = [string]$s.IP } }
            $servers = @(foreach ($n in $names) { [pscustomobject]@{ DnsName = $n; IPAddress = $ipByName[$n] } })
            Set-DhcpServerList -Servers $servers
            $script:lblLastRefresh.Text = "Last refreshed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            foreach ($line in @(Get-DhcpServerListLines -EntryCount @($out.Servers).Count -ServerCount $names.Count -Notes $notes)) {
                Write-Log -Message $line.Message -Color $line.Color -LogBox $dhcpLogBox
            }
            if ($servers.Count -gt 0) { [void](Save-DhcpCache -Kind Servers -Items $servers) }
        } else {
            $msg = if ($out) { $out.Message } else { $result.Error }
            $script:lblLastRefresh.Text = 'Last refreshed: failed'
            Write-Log -Message "Server discovery failed: $msg" -Color 'Error' -LogBox $dhcpLogBox
        }
    } -OnJobComplete {
        param($job)
        Set-DhcpBusy -Busy $false
    }
    Add-OctoJobTask -Job $script:dhcpJob -Script $script:DhcpWorkerScripts.Discover -Argument @{} -Descriptor @{ Kind = 'Discover' }
}

function Start-DhcpScopeCacheRefresh {
    if ($script:dhcpJob -and -not $script:dhcpJob.Completed) { return }
    $servers = @(Merge-DhcpServerList -Entries @(Get-CheckedDhcpServerEntries) -Resolved $script:dhcpServerResolved)
    Set-DhcpBusy -Busy $true
    $script:lblScopeCacheStatus.Text = 'Cache: Updating...'
    Set-OctoTone -Control $script:lblScopeCacheStatus -Tone Warning
    $pool = New-OctoRunspacePool -MaxRunspaces ([int]$script:numConcurrency.Value) -FunctionNames $script:DhcpWorkerFunctions
    $script:dhcpJob = Start-OctoJob -Pool $pool -OnTaskComplete {
        param($job, $task, $result)
        $data = $job.Data
        $out = $result.Output
        if ($task.Descriptor.Kind -eq 'Discover') {
            if ($out -and $out.Success) {
                $script:dhcpServerResolved = $out.Resolved
                $notes = [System.Collections.Generic.List[string]]::new()
                $names = @(Merge-DhcpServerList -Entries @($out.Servers) -Resolved $out.Resolved -Notes $notes)
                foreach ($line in @(Get-DhcpServerListLines -EntryCount @($out.Servers).Count -ServerCount $names.Count -Notes $notes)) {
                    Write-Log -Message $line.Message -Color $line.Color -LogBox $dhcpLogBox
                }
                $data.Total = $names.Count
                foreach ($n in $names) { Add-OctoJobTask -Job $job -Script $script:DhcpWorkerScripts.ScopeList -Argument @{ Server = $n } -Descriptor @{ Kind = 'ScopeList' } }
            } else {
                Write-Log -Message "Server discovery failed: $(if ($out) { $out.Message } else { $result.Error })" -Color 'Error' -LogBox $dhcpLogBox
            }
            return
        }
        $ok = $out -and $out.Success
        $server = if ($out) { $out.Server } else { [string]$task.Item.Server }
        $msg = if ($out) { $out.Message } elseif ($result.Error) { $result.Error } else { 'No result returned' }
        if (-not $ok -and -not $task.Item.Retry -and $msg -ne 'Cancelled') {
            # A busy server or RPC hiccup must not leave its scopes out of the cache: one more try after a pause
            Write-Log -Message ('{0}: {1} - trying again' -f $server, $msg) -Color 'Warning' -LogBox $dhcpLogBox
            Add-OctoJobTask -Job $job -Script $script:DhcpWorkerScripts.ScopeList -Argument @{ Server = $server; Retry = 1; RetryDelayMs = 3000 } -Descriptor @{ Kind = 'ScopeList' }
            return
        }
        $data.Done++
        $label = if ($task.Item.Retry) { "$server (2nd try)" } else { $server }
        if ($ok) {
            foreach ($s in $out.Scopes) { $data.Scopes.Add($s) }
            Write-Log -Message ('[{0}/{1}] {2}: {3} scope(s) ({4:N1}s)' -f $data.Done, $data.Total, $label, @($out.Scopes).Count, ($out.ElapsedMs / 1000)) -Color 'Success' -LogBox $dhcpLogBox
        } else {
            $data.Failed.Add($server)
            Write-Log -Message ('[{0}/{1}] {2}: FAILED - {3}' -f $data.Done, $data.Total, $label, $msg) -Color 'Error' -LogBox $dhcpLogBox
        }
        if ($data.Total -gt 0) { Set-OctoStatus -Text 'Refreshing scope cache...' -Percent ([int](100 * $data.Done / $data.Total)) -ProgressText "$($data.Done)/$($data.Total) servers" }
    } -OnJobComplete {
        param($job)
        $data = $job.Data
        Set-OctoStatus -Text 'Ready'
        Set-DhcpBusy -Busy $false
        if ($job.Stopped) {
            $script:lblScopeCacheStatus.Text = 'Cache: refresh cancelled'
            Set-OctoTone -Control $script:lblScopeCacheStatus -Tone Muted
            return
        }
        $scopes = $data.Scopes.ToArray()
        Set-DhcpScopeList -Scopes $scopes
        $script:scopeCacheUpdated = Get-Date
        $script:lblScopeCacheStatus.Text = "Cache: $($scopes.Count) scope(s) loaded ($(Get-Date -Format 'HH:mm:ss'))"
        Set-OctoTone -Control $script:lblScopeCacheStatus -Tone Success
        Write-Log -Message "Scope cache refreshed: $($scopes.Count) scope(s) in $([math]::Round($data.Stopwatch.Elapsed.TotalSeconds, 1))s" -Color 'Success' -LogBox $dhcpLogBox
        if ($data.Failed.Count -gt 0) {
            Write-Log -Message ('{0} server(s) failed twice and are not in the cache: {1} - Refresh Cache again to add them' -f $data.Failed.Count, ($data.Failed -join ', ')) -Color 'Warning' -LogBox $dhcpLogBox
        }
        if ($scopes.Count -gt 0) { [void](Save-DhcpCache -Kind Scopes -Items $scopes) }
    }
    $script:dhcpJob.Data.Scopes = [System.Collections.Generic.List[object]]::new()
    $script:dhcpJob.Data.Failed = [System.Collections.Generic.List[string]]::new()
    $script:dhcpJob.Data.Done = 0
    $script:dhcpJob.Data.Total = $servers.Count
    $script:dhcpJob.Data.Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    if ($servers.Count -gt 0) {
        Write-Log -Message "Refreshing scope cache from $($servers.Count) selected server(s)..." -Color 'Info' -LogBox $dhcpLogBox
        foreach ($s in $servers) { Add-OctoJobTask -Job $script:dhcpJob -Script $script:DhcpWorkerScripts.ScopeList -Argument @{ Server = $s } -Descriptor @{ Kind = 'ScopeList' } }
    } else {
        Write-Log -Message 'Refreshing scope cache from all domain DHCP servers...' -Color 'Info' -LogBox $dhcpLogBox
        Add-OctoJobTask -Job $script:dhcpJob -Script $script:DhcpWorkerScripts.Discover -Argument @{} -Descriptor @{ Kind = 'Discover' }
    }
}

function Start-DhcpCollection {
    if ($script:dhcpJob -and -not $script:dhcpJob.Completed) { return }

    $request = @{
        Servers          = @()
        ScopeIdsByServer = $null
        NameFilters      = @()
        IncludeDNS       = $chkIncludeDNS.Checked
        IncludeOption60  = $chkIncludeOption60.Checked
        IncludeOption43  = $chkIncludeOption43.Checked
        ShowAllOptions   = $script:chkShowAllOptions.Checked
        Throttle         = [int]$script:numConcurrency.Value
        OptionBatchSize  = 25
    }

    $script:dhcpRunUsedSelection = $false
    $allCachedSelected = ($script:selectedScopeNames.Count -gt 0 -and $script:selectedScopeNames.Count -ge $script:scopeByDisplayName.Count)
    if ($allCachedSelected) {
        # Everything in the cache is selected: read every scope on those servers, so
        # scopes created after the cache was saved are not silently left out
        $request.Servers = @(Merge-DhcpServerList -Entries @($script:allDHCPScopes | ForEach-Object { [string]$_.Server } | Where-Object { $_ }))
        Write-Log -Message "All $($script:selectedScopeNames.Count) cached scope(s) are selected - collecting every scope on their $($request.Servers.Count) server(s)" -Color 'Info' -LogBox $dhcpLogBox
    } elseif ($script:selectedScopeNames.Count -gt 0) {
        # Selected scopes take precedence: only their servers are queried, only those scope IDs
        $script:dhcpRunUsedSelection = $true
        if ($script:scopeCacheUpdated) {
            Write-Log -Message "Selected scopes come from the scope cache saved $($script:scopeCacheUpdated.ToString('yyyy-MM-dd HH:mm')) - newer scopes are not included" -Color 'Info' -LogBox $dhcpLogBox
        }
        $map = @{}
        $missing = 0
        foreach ($name in $script:selectedScopeNames) {
            $scope = $null
            if (-not $script:scopeByDisplayName.TryGetValue($name, [ref]$scope) -or -not $scope.Server -or -not $scope.ScopeId) { $missing++; continue }
            $server = [string]$scope.Server
            if (-not $map.ContainsKey($server)) { $map[$server] = [System.Collections.Generic.List[string]]::new() }
            $map[$server].Add([string]$scope.ScopeId)
        }
        if ($map.Count -eq 0) {
            # never fall back to "all servers" when the user picked scopes
            Write-Log -Message 'The selected scopes have no server / scope ID in the cache - refresh the scope cache and select them again' -Color 'Error' -LogBox $dhcpLogBox
            return
        }
        $request.Servers = @(Merge-DhcpServerList -Entries @($map.Keys))
        # A bare host name merged into its FQDN keeps its scopes under the FQDN
        $request.ScopeIdsByServer = @{}
        foreach ($k in $map.Keys) {
            $target = $k
            if ($request.Servers -notcontains $k) {
                $short = Get-DhcpServerShortName -Name $k
                foreach ($s in $request.Servers) { if ((Get-DhcpServerShortName -Name $s) -eq $short) { $target = $s; break } }
            }
            if (-not $request.ScopeIdsByServer.ContainsKey($target)) { $request.ScopeIdsByServer[$target] = @() }
            $request.ScopeIdsByServer[$target] = @($request.ScopeIdsByServer[$target] + $map[$k].ToArray() | Select-Object -Unique)
        }
        $hidden = $script:selectedScopeNames.Count - @($script:lstDHCPScopes.CheckedItems).Count
        $note = if ($hidden -gt 0) { " ($hidden hidden by the current filter)" } else { '' }
        Write-Log -Message "Using $($script:selectedScopeNames.Count - $missing) selected scope(s) on $($request.Servers.Count) server(s)$note" -Color 'Info' -LogBox $dhcpLogBox
    } else {
        $entries = [System.Collections.Generic.List[object]]::new()
        foreach ($e in @(Get-CheckedDhcpServerEntries)) { $entries.Add($e) }
        if (-not [string]::IsNullOrWhiteSpace($txtSpecificServers.Text)) {
            $invalid = [System.Collections.Generic.List[string]]::new()
            foreach ($raw in $txtSpecificServers.Text.Split(',')) {
                $name = $raw.Trim()
                if (-not $name) { continue }
                if (Test-ServerName -ServerName $name) { $entries.Add(@{ Name = $name; IP = $null }) } else { $invalid.Add($name) }
            }
            if ($invalid.Count -gt 0) { Write-Log -Message "Invalid server name(s) skipped: $($invalid -join ', ')" -Color 'Warning' -LogBox $dhcpLogBox }
            if ($entries.Count -eq 0) {
                Write-Log -Message 'No valid servers specified. Operation cancelled.' -Color 'Error' -LogBox $dhcpLogBox
                return
            }
        }
        $notes = [System.Collections.Generic.List[string]]::new()
        $request.Servers = @(Merge-DhcpServerList -Entries $entries.ToArray() -Resolved $script:dhcpServerResolved -Notes $notes)
        foreach ($n in $notes) { Write-Log -Message "  $n" -Color 'Info' -LogBox $dhcpLogBox }
    }

    $script:dhcpState = New-DhcpCollectionState -Request $request
    $script:dhcpRunOptions = @{ IncludeDNS = $request.IncludeDNS; IncludeOption60 = $request.IncludeOption60; IncludeOption43 = $request.IncludeOption43; ShowAllOptions = $request.ShowAllOptions }
    Set-DhcpBusy -Busy $true
    $btnExportDHCPWorkDir.Enabled = $false
    $btnExportDHCPFolder.Enabled = $false
    Set-OctoStatus -Text 'Collecting DHCP statistics...' -Percent 0

    $pool = New-OctoRunspacePool -MaxRunspaces $request.Throttle -FunctionNames $script:DhcpWorkerFunctions
    $script:dhcpJob = Start-OctoJob -Pool $pool -OnTaskComplete {
        param($job, $task, $result)
        $state = $script:dhcpState
        foreach ($next in @(Receive-DhcpTaskResult -State $state -Descriptor $task.Descriptor -Result $result)) {
            Add-OctoJobTask -Job $job -Script $script:DhcpWorkerScripts[$next.Kind] -Argument $next.Item -Descriptor $next
        }
        Write-DhcpStateLog -State $state
        $serverCount = [Math]::Max(1, $state.Servers.Count)
        if ($state.ServersDone -lt $state.Servers.Count -or $state.OptionBatches -eq 0) {
            Set-OctoStatus -Text 'Collecting DHCP statistics...' -Percent ([int](100 * $state.ServersDone / $serverCount)) -ProgressText "$($state.ServersDone)/$($state.Servers.Count) servers"
        } elseif ($state.OptionScopesDone -ge $state.OptionScopes -and $state.OptionRetriesDone -lt $state.OptionRetries) {
            Set-OctoStatus -Text 'Retrying failed option lookups...' -Percent ([int](100 * $state.OptionRetriesDone / $state.OptionRetries)) -ProgressText "$($state.OptionRetriesDone)/$($state.OptionRetries) scopes"
        } else {
            Set-OctoStatus -Text 'Collecting DHCP options...' -Percent ([int](100 * $state.OptionScopesDone / [Math]::Max(1, $state.OptionScopes))) -ProgressText "$($state.OptionScopesDone)/$($state.OptionScopes) scopes"
        }
    } -OnJobComplete {
        param($job)
        Complete-DhcpCollection -Job $job
    }
    foreach ($t in @(Get-DhcpStartTasks -State $script:dhcpState)) {
        Add-OctoJobTask -Job $script:dhcpJob -Script $script:DhcpWorkerScripts[$t.Kind] -Argument $t.Item -Descriptor $t
    }
    Write-DhcpStateLog -State $script:dhcpState
}

function Complete-DhcpCollection {
    param($Job)
    if ($script:AppClosing) { return }
    $state = $script:dhcpState
    Write-DhcpStateLog -State $state
    Set-DhcpBusy -Busy $false
    Set-OctoStatus -Text 'Ready'
    if ($Job.Stopped) { Write-Log -Message 'Collection stopped by user - keeping the results collected so far' -Color 'Warning' -LogBox $dhcpLogBox }

    $rows = $state.Rows.ToArray()
    if ($rows.Count -eq 0) {
        $script:dhcpResults = @()
        $script:dhcpAnalysis = $null
        if ($state.Error) {
            if (-not $Job.Stopped) { Show-OctoMessage -Text "DHCP collection failed: $($state.Error)" -Title 'Error' -Icon Error | Out-Null }
        } else {
            Write-Log -Message 'No DHCP scopes found matching the criteria' -Color 'Warning' -LogBox $dhcpLogBox
        }
        return
    }

    $script:dhcpResults = $rows
    $script:dhcpAnalysis = Get-DhcpScopeAnalysis -Rows $rows
    foreach ($line in @(Get-DhcpSummaryLines -Analysis $script:dhcpAnalysis -State $state)) {
        Write-Log -Message $line.Message -Color $line.Color -LogBox $dhcpLogBox
    }
    # Name every cached scope this run did not return, with the reason
    if (-not $script:dhcpRunUsedSelection -and @($script:allDHCPScopes).Count -gt 0 -and -not $Job.Stopped) {
        $comparison = Compare-DhcpScopeCache -State $state -CachedScopes @($script:allDHCPScopes)
        foreach ($line in @(Get-DhcpCacheCheckLines -Comparison $comparison)) {
            Write-Log -Message $line.Message -Color $line.Color -LogBox $dhcpLogBox
        }
    }
    $btnExportDHCPWorkDir.Enabled = $true
    $btnExportDHCPFolder.Enabled = $true

    if ($script:Settings.AutoExportAfterCollection -and -not $Job.Stopped) {
        try { [void](Export-DhcpResults -Folder $script:outputDir) }
        catch { Write-Log -Message "Auto-export failed: $($_.Exception.Message)" -Color 'Error' -LogBox $dhcpLogBox }
    }
}

function Export-DhcpResults {
    <#
    .SYNOPSIS
        Writes the last collection to CSV (per server, or grouped by Scope ID).
    #>
    param([string]$Folder, [switch]$ShowMessage)
    if (-not $script:dhcpResults -or $script:dhcpResults.Count -eq 0) {
        Show-OctoMessage -Text 'No DHCP results to export. Please collect statistics first.' -Title 'Warning' -Icon Warning | Out-Null
        return $null
    }
    $grouped = $script:chkGroupByScope.Checked
    $rows = if ($grouped) { $script:dhcpAnalysis.Groups } else { $script:dhcpResults }
    $columns = Get-DhcpExportColumns -Options $script:dhcpRunOptions -Grouped:$grouped
    $baseName = if ($grouped) { 'DHCPScopeStats_Grouped' } else { 'DHCPScopeStats' }
    $path = Get-OctoExportPath -Folder $Folder -BaseName $baseName
    [void](Export-OctoCsv -Rows $rows -Columns $columns -Path $path)
    $kind = if ($grouped) { 'unique scope(s), failover-aware' } else { 'server row(s)' }
    Write-Log -Message "Exported $(@($rows).Count) $kind to: $path" -Color 'Success' -LogBox $dhcpLogBox
    Add-ExportHistory -Settings $script:Settings -FilePath $path -Operation 'DHCP Statistics'
    if ($ShowMessage) { Show-OctoMessage -Text "Export successful!`n`n$path" -Title 'Export Complete' | Out-Null }
    return $path
}

# --- Event handlers -----------------------------------------------------------

$btnCollectDHCP.Add_Click({
    try { Start-DhcpCollection }
    catch {
        Write-Log -Message "Error: $($_.Exception.Message)" -Color 'Error' -LogBox $dhcpLogBox
        Set-DhcpBusy -Busy $false
    }
})
$btnStopDHCP.Add_Click({
    Write-Log -Message 'Stop requested by user...' -Color 'Warning' -LogBox $dhcpLogBox
    $btnStopDHCP.Enabled = $false
    Stop-OctoJob -Job $script:dhcpJob
})
$btnRefreshDHCPServers.Add_Click({
    try { Start-DhcpServerDiscovery } catch { Write-Log -Message "Error refreshing server list: $($_.Exception.Message)" -Color 'Error' -LogBox $dhcpLogBox; Set-DhcpBusy -Busy $false }
})
$btnSelectAll.Add_Click({ for ($i = 0; $i -lt $script:lstDHCPServers.Items.Count; $i++) { $script:lstDHCPServers.SetItemChecked($i, $true) } })
$btnSelectNone.Add_Click({ for ($i = 0; $i -lt $script:lstDHCPServers.Items.Count; $i++) { $script:lstDHCPServers.SetItemChecked($i, $false) } })
$script:btnRefreshScopeCache.Add_Click({
    try { Start-DhcpScopeCacheRefresh }
    catch {
        $script:lblScopeCacheStatus.Text = 'Cache: Error'
        Set-OctoTone -Control $script:lblScopeCacheStatus -Tone Error
        Write-Log -Message "Error refreshing scope cache: $($_.Exception.Message)" -Color 'Error' -LogBox $dhcpLogBox
        Set-DhcpBusy -Busy $false
    }
})

# Placeholder text for the two filter boxes
foreach ($box in @($script:txtScopeListFilter, $script:txtPrefixFilter)) {
    $box.Add_GotFocus({
        $placeholder = if ($this -eq $script:txtScopeListFilter) { $script:ScopeFilterPlaceholder } else { $script:PrefixFilterPlaceholder }
        if ($this.Text -eq $placeholder) {
            $script:filterChangeFromCode = $true
            $this.Text = ''
            $this.ForeColor = $script:CurrentTheme.InputText
            $script:filterChangeFromCode = $false
        }
    })
    $box.Add_LostFocus({
        if ([string]::IsNullOrWhiteSpace($this.Text)) {
            $script:filterChangeFromCode = $true
            $this.Text = if ($this -eq $script:txtScopeListFilter) { $script:ScopeFilterPlaceholder } else { $script:PrefixFilterPlaceholder }
            $this.ForeColor = $script:CurrentTheme.TextMuted
            $script:filterChangeFromCode = $false
        }
    })
    # Filter after typing pauses (250 ms) instead of on every keystroke
    $box.Add_TextChanged({
        if ($script:filterChangeFromCode) { return }
        $script:scopeFilterTimer.Stop()
        $script:scopeFilterTimer.Start()
    })
}
$script:scopeFilterTimer = New-Object System.Windows.Forms.Timer
$script:scopeFilterTimer.Interval = 250
$script:scopeFilterTimer.Add_Tick({
    $script:scopeFilterTimer.Stop()
    Update-ScopeListView
})

$btnSelectAllScopes.Add_Click({
    $list = $script:lstDHCPScopes
    $list.BeginUpdate()
    $script:suppressScopeItemCheck = $true
    try {
        for ($i = 0; $i -lt $list.Items.Count; $i++) {
            $list.SetItemChecked($i, $true)
            [void]$script:selectedScopeNames.Add([string]$list.Items[$i])
        }
    } finally {
        $script:suppressScopeItemCheck = $false
        $list.EndUpdate()
    }
    Update-ScopeCountLabel
})
$btnSelectNoneScopes.Add_Click({
    $list = $script:lstDHCPScopes
    $list.BeginUpdate()
    $script:suppressScopeItemCheck = $true
    try { foreach ($i in @($list.CheckedIndices)) { $list.SetItemChecked($i, $false) } }
    finally {
        $script:suppressScopeItemCheck = $false
        $list.EndUpdate()
    }
    $script:selectedScopeNames.Clear()
    Update-ScopeCountLabel
})
$script:lstDHCPScopes.Add_ItemCheck({
    param($sender, $e)
    if ($script:suppressScopeItemCheck) { return }
    $name = [string]$script:lstDHCPScopes.Items[$e.Index]
    if ($e.NewValue -eq [System.Windows.Forms.CheckState]::Checked) { [void]$script:selectedScopeNames.Add($name) }
    else { [void]$script:selectedScopeNames.Remove($name) }
    Update-ScopeCountLabel
})

$btnExportDHCPWorkDir.Add_Click({
    try { [void](Export-DhcpResults -Folder (Get-Location).Path -ShowMessage) }
    catch {
        Write-Log -Message "Error exporting: $($_.Exception.Message)" -Color 'Error' -LogBox $dhcpLogBox
        Show-OctoMessage -Text "Error exporting: $($_.Exception.Message)" -Title 'Error' -Icon Error | Out-Null
    }
})
$btnExportDHCPFolder.Add_Click({
    try {
        $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderBrowser.Description = 'Select folder to export DHCP Statistics'
        if ($folderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            [void](Export-DhcpResults -Folder $folderBrowser.SelectedPath -ShowMessage)
        }
    } catch {
        Write-Log -Message "Error exporting: $($_.Exception.Message)" -Color 'Error' -LogBox $dhcpLogBox
        Show-OctoMessage -Text "Error exporting: $($_.Exception.Message)" -Title 'Error' -Icon Error | Out-Null
    }
})

# ============================================
# TAB: DNA CENTER
# ============================================

function Get-DNACenterServers {
    <#
    .SYNOPSIS
        DNA Center servers from dna_config.json, or DNAC_SERVER<n>_NAME / _URL
        environment variables (n = 1..10).
    #>
    foreach ($dir in @($script:AppRoot, $script:DataDir) | Select-Object -Unique) {
        $configFile = Join-Path $dir 'dna_config.json'
        if (-not (Test-Path -LiteralPath $configFile)) { continue }
        try {
            $config = Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json
            $servers = @($config.servers | Where-Object { $_ -and $_.Name -and $_.Url })
            if ($servers.Count -gt 0) { return $servers }
        } catch { }
    }
    $servers = @()
    for ($i = 1; $i -le 10; $i++) {
        $name = [Environment]::GetEnvironmentVariable("DNAC_SERVER${i}_NAME")
        $url = [Environment]::GetEnvironmentVariable("DNAC_SERVER${i}_URL")
        if ($name -and $url) { $servers += [pscustomobject]@{ Name = $name; Url = $url } }
    }
    if ($servers.Count -gt 0) { return $servers }
    return @([pscustomobject]@{ Name = 'Please Configure'; Url = 'https://your-dnac-server.example.com' })
}

$script:dnaCenterServers = @(Get-DNACenterServers)
$script:dnaDeviceEntries = @()
$script:DnaFunctionNames = @{}

$tab3 = New-OctoTab -Text 'DNA Center'

# --- Connection (left column)
$dnaConnCard = New-OctoCard -Bounds @(16, 16, 640, 162) -Title 'Connection' -Parent $tab3
[void](New-OctoControl Label @(16, 51, 80, 20) ([ordered]@{ Text = 'Server' }) $dnaConnCard)
$comboDNAServer = New-OctoControl ComboBox @(100, 48, 524, 23) ([ordered]@{ DropDownStyle = 'DropDownList' }) $dnaConnCard
foreach ($server in $script:dnaCenterServers) { [void]$comboDNAServer.Items.Add("$($server.Name) - $($server.Url)") }
if ($comboDNAServer.Items.Count -gt 0) { $comboDNAServer.SelectedIndex = 0 }
[void](New-OctoControl Label @(16, 85, 80, 20) ([ordered]@{ Text = 'Username' }) $dnaConnCard)
$txtDNAUser = New-OctoControl TextBox @(100, 82, 180, 23) $null $dnaConnCard
[void](New-OctoControl Label @(300, 85, 70, 20) ([ordered]@{ Text = 'Password' }) $dnaConnCard)
$txtDNAPass = New-OctoControl TextBox @(374, 82, 250, 23) ([ordered]@{ UseSystemPasswordChar = $true }) $dnaConnCard
$btnDNAConnect = New-OctoControl Button @(16, 118, 110, 30) ([ordered]@{ Text = 'Connect'; Tag = 'Primary' }) $dnaConnCard
$btnLoadDevices = New-OctoControl Button @(134, 118, 120, 30) ([ordered]@{ Text = 'Load Devices'; Enabled = $false }) $dnaConnCard
$btnDNAStop = New-OctoControl Button @(262, 118, 80, 30) ([ordered]@{ Text = 'Stop'; Tag = 'Danger'; Enabled = $false }) $dnaConnCard
[void](New-OctoControl Label @(354, 124, 230, 20) ([ordered]@{ Text = 'Stop cancels the running report'; Tag = 'Muted' }) $dnaConnCard)

# --- Device filtering and selection (left column, grows with the window)
$dnaDeviceCard = New-OctoCard -Bounds @(16, 190, 640, 404) -Title 'Devices' -Parent $tab3 -Anchor 'Top,Bottom,Left'
[void](New-OctoControl Label @(16, 51, 72, 20) ([ordered]@{ Text = 'Hostname' }) $dnaDeviceCard)
$txtFilterHostname = New-OctoControl TextBox @(90, 48, 210, 23) ([ordered]@{ Enabled = $false }) $dnaDeviceCard
[void](New-OctoControl Label @(316, 51, 66, 20) ([ordered]@{ Text = 'Family' }) $dnaDeviceCard)
$cmbFilterFamily = New-OctoControl ComboBox @(384, 48, 240, 23) ([ordered]@{ DropDownStyle = 'DropDownList'; Enabled = $false }) $dnaDeviceCard
[void](New-OctoControl Label @(16, 83, 72, 20) ([ordered]@{ Text = 'Role' }) $dnaDeviceCard)
$cmbFilterRole = New-OctoControl ComboBox @(90, 80, 210, 23) ([ordered]@{ DropDownStyle = 'DropDownList'; Enabled = $false }) $dnaDeviceCard
[void](New-OctoControl Label @(316, 83, 66, 20) ([ordered]@{ Text = 'IP Address' }) $dnaDeviceCard)
$cmbFilterIPAddress = New-OctoControl ComboBox @(384, 80, 240, 23) ([ordered]@{ DropDownStyle = 'DropDownList'; Enabled = $false }) $dnaDeviceCard
# Column captions line up with the fixed-width device list below
[void](New-OctoControl Label @(35, 114, 589, 16) ([ordered]@{ Text = ('{0,-36} {1,-16} {2,-14} {3}' -f 'HOSTNAME', 'IP ADDRESS', 'ROLE', 'FAMILY'); Font = $script:Fonts.Mono; Tag = 'Muted' }) $dnaDeviceCard)
$lstDevices = New-OctoControl CheckedListBox @(16, 132, 608, 186) ([ordered]@{ CheckOnClick = $true; Enabled = $false; Font = $script:Fonts.Mono; IntegralHeight = $false; Anchor = 'Top,Bottom,Left' }) $dnaDeviceCard
$chkSelectAll = New-OctoControl CheckBox @(16, 326, 200, 22) ([ordered]@{ Text = 'Select All (Current Filter)'; Enabled = $false; Anchor = 'Bottom,Left' }) $dnaDeviceCard
$lblDeviceSelectionStatus = New-OctoControl Label @(224, 328, 400, 20) ([ordered]@{ Text = 'Showing: 0 devices | Selected: 0'; Anchor = 'Bottom,Left' }) $dnaDeviceCard
$btnApplyDeviceFilter = New-OctoControl Button @(16, 358, 140, 30) ([ordered]@{ Text = 'Apply Selection'; Tag = 'Primary'; Enabled = $false; Anchor = 'Bottom,Left' }) $dnaDeviceCard
$btnResetDeviceFilter = New-OctoControl Button @(164, 358, 100, 30) ([ordered]@{ Text = 'Reset All'; Enabled = $false; Anchor = 'Bottom,Left' }) $dnaDeviceCard

# --- Functions and favorites (right column)
$dnaFunctionsCard = New-OctoCard -Bounds @(668, 16, 496, 248) -Title 'Functions (double-click to run)' -Parent $tab3 -Anchor 'Top,Left,Right'
$script:dnaTreeView = New-OctoControl TreeView @(16, 48, 236, 184) ([ordered]@{ ShowLines = $true; ShowPlusMinus = $true; ShowRootLines = $true; HideSelection = $false }) $dnaFunctionsCard
[void](New-OctoControl Label @(264, 50, 216, 18) ([ordered]@{ Text = 'Favorites (right-click a function to add)'; Tag = 'Muted' }) $dnaFunctionsCard)
$script:lstFavorites = New-OctoControl ListBox @(264, 70, 216, 162) ([ordered]@{ IntegralHeight = $false; Anchor = 'Top,Left,Right' }) $dnaFunctionsCard

$dnaTree = [ordered]@{
    'Device Information'     = @(
        @('Basic Information', 'Get-NetworkDevicesBasic'), @('Detailed Information', 'Get-NetworkDevicesDetailed'),
        @('Device Count', 'Get-DeviceInventoryCount'), @('Device Modules', 'Get-DeviceModules'),
        @('Device Interfaces', 'Get-DeviceInterfaces'), @('Device Configurations', 'Get-DeviceConfigurations'))
    'Network Health'         = @(
        @('Overall Network Health', 'Get-NetworkHealth'), @('Client Health', 'Get-ClientHealth'),
        @('Device Reachability', 'Get-DeviceReachability'), @('Compliance Status', 'Get-ComplianceStatus'))
    'Topology and Neighbors' = @(
        @('Physical Topology', 'Get-PhysicalTopology'), @('OSPF Neighbors', 'Get-OSPFNeighbors'),
        @('CDP Neighbors', 'Get-CDPNeighbors'), @('LLDP Neighbors', 'Get-LLDPNeighbors'))
    'Network Services'       = @(
        @('VLANs', 'Get-VLANs'), @('Templates', 'Get-Templates'),
        @('Sites/Locations', 'Get-SitesLocations'), @('Access Points', 'Get-AccessPoints'))
    'Software and Issues'    = @(
        @('Software Images', 'Get-SoftwareImageInfo'), @('Issues/Events', 'Get-IssuesEvents'))
    'Advanced Tools'         = @(
        @('Path Trace', 'Invoke-PathTrace'), @('CLI Command Runner', 'Invoke-CommandRunner'),
        @('Last Disconnect Times', 'Get-LastDisconnectTime'), @('Availability Events', 'Get-LastDeviceAvailabilityEventTime'),
        @('Last Ping Reachable', 'Get-LastPingReachableTime'))
}
$script:dnaTreeView.BeginUpdate()
foreach ($category in $dnaTree.Keys) {
    $parent = New-Object System.Windows.Forms.TreeNode($category)
    foreach ($entry in $dnaTree[$category]) {
        $node = New-Object System.Windows.Forms.TreeNode($entry[0])
        $node.Tag = $entry[1]
        [void]$parent.Nodes.Add($node)
        $script:DnaFunctionNames[$entry[1]] = $entry[0]
    }
    [void]$script:dnaTreeView.Nodes.Add($parent)
}
$script:dnaTreeView.ExpandAll()
$script:dnaTreeView.EndUpdate()

# --- Log (right column, grows with the window)
$dnaLogCard = New-OctoCard -Bounds @(668, 276, 496, 222) -Title 'Log' -Parent $tab3 -Anchor 'Top,Bottom,Left,Right'
$dnaLogBox = New-OctoLogBox -Bounds @(16, 48, 464, 158) -Parent $dnaLogCard -WordWrap $false

# --- Export folder (right column, bottom)
$dnaExportCard = New-OctoCard -Bounds @(668, 510, 496, 84) -Title 'Export Folder' -Parent $tab3 -Anchor 'Bottom,Left,Right'
$btnDNAExportWorkDir = New-OctoControl Button @(166, 12, 112, 28) ([ordered]@{ Text = 'Use Working Dir'; Anchor = 'Top,Right' }) $dnaExportCard
$btnDNAExportFolder = New-OctoControl Button @(286, 12, 116, 28) ([ordered]@{ Text = 'Browse Folder...'; Anchor = 'Top,Right' }) $dnaExportCard
$btnDNAExportDefault = New-OctoControl Button @(410, 12, 70, 28) ([ordered]@{ Text = 'Default'; Anchor = 'Top,Right' }) $dnaExportCard
$script:txtDNAExportPath = New-OctoControl TextBox @(16, 48, 464, 23) ([ordered]@{ Text = $script:outputDir; ReadOnly = $true; Anchor = 'Top,Left,Right' }) $dnaExportCard

# --- Device list helpers ----------------------------------------------------------

function Set-DnaFilterControlsEnabled {
    param([bool]$Enabled)
    foreach ($control in @($txtFilterHostname, $cmbFilterIPAddress, $cmbFilterRole, $cmbFilterFamily, $lstDevices, $chkSelectAll, $btnApplyDeviceFilter, $btnResetDeviceFilter)) {
        $control.Enabled = $Enabled
    }
}

function Set-DnaComboItems {
    param([System.Windows.Forms.ComboBox]$Combo, [string[]]$Values)
    $Combo.BeginUpdate()
    try {
        $Combo.Items.Clear()
        [void]$Combo.Items.Add('All')
        if ($Values.Count -gt 0) { $Combo.Items.AddRange([object[]]$Values) }
        $Combo.SelectedIndex = 0
    } finally { $Combo.EndUpdate() }
}

function Initialize-DnaDeviceEntries {
    <#
    .SYNOPSIS
        Builds the filter data once per device load (display text, filter keys) and
        fills the Family / Role / IP drop-downs.
    #>
    $entries = [System.Collections.Generic.List[object]]::new()
    $families = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $roles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ips = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($d in $script:Dna.Devices) {
        $hostname = if ($d.hostname) { [string]$d.hostname } else { 'N/A' }
        $ip = if ($d.managementIpAddress) { [string]$d.managementIpAddress } else { 'N/A' }
        $role = if ($d.role) { [string]$d.role } else { 'N/A' }
        $family = if ($d.family) { [string]$d.family } else { 'N/A' }
        if ($d.family) { [void]$families.Add($family) }
        if ($d.role) { [void]$roles.Add($role) }
        if ($d.managementIpAddress) { [void]$ips.Add($ip) }
        $entries.Add(@{
            Id = [string]$d.id; Hostname = $hostname; HostUpper = $hostname.ToUpperInvariant()
            IP = $ip; Role = $role; Family = $family
            Text = ('{0,-36} {1,-16} {2,-14} {3}' -f $hostname, $ip, $role, $family)
        })
    }
    $script:dnaDeviceEntries = $entries.ToArray()

    $familyList = [string[]]@($families); [Array]::Sort($familyList, [System.StringComparer]::OrdinalIgnoreCase)
    $roleList = [string[]]@($roles); [Array]::Sort($roleList, [System.StringComparer]::OrdinalIgnoreCase)
    # IPv4 addresses sort numerically; anything else (IPv6, names) after them, alphabetically
    $ipList = [string[]]@($ips)
    $ipKeys = New-Object 'string[]' $ipList.Count
    for ($i = 0; $i -lt $ipList.Count; $i++) {
        $parsed = $null
        if ([System.Net.IPAddress]::TryParse($ipList[$i], [ref]$parsed) -and $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            $b = $parsed.GetAddressBytes()
            $ipKeys[$i] = '0' + ('{0:D3}{1:D3}{2:D3}{3:D3}' -f $b[0], $b[1], $b[2], $b[3])
        } else {
            $ipKeys[$i] = '1' + $ipList[$i].ToUpperInvariant()
        }
    }
    [Array]::Sort($ipKeys, $ipList, [System.StringComparer]::Ordinal)

    $script:dnaUpdatingChecks = $true
    try {
        Set-DnaComboItems -Combo $cmbFilterFamily -Values $familyList
        Set-DnaComboItems -Combo $cmbFilterRole -Values $roleList
        Set-DnaComboItems -Combo $cmbFilterIPAddress -Values $ipList
        $txtFilterHostname.Text = ''
    } finally { $script:dnaUpdatingChecks = $false }
    $script:dnaCheckedIds.Clear()
}

function Update-DnaSelectionLabel {
    param([int]$VisibleChecked = -1)
    if ($VisibleChecked -lt 0) { $VisibleChecked = $lstDevices.CheckedIndices.Count }
    $hidden = $script:dnaCheckedIds.Count - $VisibleChecked
    $text = "Showing: $($lstDevices.Items.Count) devices | Selected: $($script:dnaCheckedIds.Count)"
    if ($hidden -gt 0) { $text += " ($hidden hidden by the filter)" }
    $applied = @($script:Dna.Selected).Count
    if ($applied -gt 0) { $text += " | Applied: $applied" }
    $lblDeviceSelectionStatus.Text = $text
}

function Update-DnaDeviceList {
    <#
    .SYNOPSIS
        Shows the devices matching the hostname / family / role / IP filters,
        keeping every checked device checked (also those currently hidden).
    #>
    $hostText = $txtFilterHostname.Text.Trim()
    $useWildcard = $hostText.IndexOfAny([char[]]'*?[') -ge 0
    $hostUpper = $hostText.ToUpperInvariant()
    $family = [string]$cmbFilterFamily.SelectedItem
    $role = [string]$cmbFilterRole.SelectedItem
    $ip = [string]$cmbFilterIPAddress.SelectedItem
    $anyFamily = (-not $family) -or $family -eq 'All'
    $anyRole = (-not $role) -or $role -eq 'All'
    $anyIp = (-not $ip) -or $ip -eq 'All'
    $pattern = "*$hostText*"

    $visible = $script:dnaVisibleDevices
    $visible.Clear()
    $texts = [System.Collections.Generic.List[string]]::new()
    foreach ($e in $script:dnaDeviceEntries) {
        if (-not $anyFamily -and $e.Family -ne $family) { continue }
        if (-not $anyRole -and $e.Role -ne $role) { continue }
        if (-not $anyIp -and $e.IP -ne $ip) { continue }
        if ($hostText) {
            if ($useWildcard) {
                $ok = $false
                try { $ok = $e.Hostname -like $pattern } catch { $ok = $e.HostUpper.Contains($hostUpper) }
                if (-not $ok) { continue }
            } elseif (-not $e.HostUpper.Contains($hostUpper)) { continue }
        }
        $visible.Add($e)
        $texts.Add($e.Text)
    }

    $checkedVisible = 0
    $lstDevices.BeginUpdate()
    $script:dnaUpdatingChecks = $true
    try {
        $lstDevices.Items.Clear()
        $lstDevices.Items.AddRange([object[]]$texts.ToArray())
        if ($script:dnaCheckedIds.Count -gt 0) {
            for ($i = 0; $i -lt $visible.Count; $i++) {
                if ($script:dnaCheckedIds.Contains($visible[$i].Id)) { $lstDevices.SetItemChecked($i, $true); $checkedVisible++ }
            }
        }
        $chkSelectAll.Enabled = ($visible.Count -gt 0)
        $chkSelectAll.Checked = ($visible.Count -gt 0 -and $checkedVisible -eq $visible.Count)
    } finally {
        $script:dnaUpdatingChecks = $false
        $lstDevices.EndUpdate()
    }
    Update-DnaSelectionLabel -VisibleChecked $checkedVisible
}

function Clear-DnaDeviceUi {
    $script:dnaDeviceEntries = @()
    $script:dnaVisibleDevices.Clear()
    $script:dnaCheckedIds.Clear()
    $script:dnaUpdatingChecks = $true
    try {
        $lstDevices.Items.Clear()
        foreach ($combo in @($cmbFilterFamily, $cmbFilterRole, $cmbFilterIPAddress)) { $combo.Items.Clear() }
        $txtFilterHostname.Text = ''
        $chkSelectAll.Checked = $false
    } finally { $script:dnaUpdatingChecks = $false }
    Set-DnaFilterControlsEnabled -Enabled $false
    Update-DnaSelectionLabel -VisibleChecked 0
}

function Update-DnaFavorites {
    $favorites = @($script:Settings.FavoriteFunctions | Where-Object { $_ -and $script:DnaFunctionNames.ContainsKey([string]$_) } | Select-Object -Unique)
    $script:lstFavorites.BeginUpdate()
    try {
        $script:lstFavorites.Items.Clear()
        foreach ($f in $favorites) { [void]$script:lstFavorites.Items.Add(('{0}  ({1})' -f $script:DnaFunctionNames[[string]$f], $f)) }
    } finally { $script:lstFavorites.EndUpdate() }
}

function Set-DnaBusy {
    param([bool]$Busy)
    $script:Dna.Busy = $Busy
    $btnDNAStop.Enabled = $Busy
    $btnDNAConnect.Enabled = -not $Busy
    $btnLoadDevices.Enabled = (-not $Busy) -and [bool]$script:Dna.Headers
    $script:dnaTreeView.Enabled = -not $Busy
    $script:lstFavorites.Enabled = -not $Busy
}

function Invoke-DnaFunction {
    <#
    .SYNOPSIS
        Runs one DNA Center report / tool by function name (from the tree or favorites).
    #>
    param([string]$FunctionName)
    if (-not $FunctionName -or -not $script:DnaFunctionNames.ContainsKey($FunctionName)) { return }
    if ($script:Dna.Busy) {
        Write-Log -Message 'Another DNA Center operation is still running - wait for it or click Stop' -Color 'Warning' -LogBox $dnaLogBox
        return
    }
    if (-not (Test-DNACTokenValid)) {
        $msg = if ($script:Dna.Token) { 'The DNA Center session has expired - please connect again' } else { 'Please connect to DNA Center first' }
        Write-Log -Message $msg -Color 'Warning' -LogBox $dnaLogBox
        Show-OctoMessage -Text $msg -Title 'Not Connected' -Icon Warning | Out-Null
        return
    }
    if ($FunctionName -ne 'Invoke-PathTrace' -and (-not $script:Dna.Devices -or $script:Dna.Devices.Count -eq 0)) {
        Write-Log -Message "Please load devices first using the 'Load Devices' button" -Color 'Warning' -LogBox $dnaLogBox
        Show-OctoMessage -Text "Please load devices first using the 'Load Devices' button" -Title 'No Devices' -Icon Warning | Out-Null
        return
    }
    Write-Log -Message "Executing: $($script:DnaFunctionNames[$FunctionName])" -Color 'Info' -LogBox $dnaLogBox
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Set-DnaBusy -Busy $true
    try {
        & $FunctionName -LogBox $dnaLogBox
        Write-Log -Message ('Finished: {0} ({1:N1}s)' -f $script:DnaFunctionNames[$FunctionName], $sw.Elapsed.TotalSeconds) -Color 'Info' -LogBox $dnaLogBox
    } catch {
        Write-Log -Message "Error executing function: $($_.Exception.Message)" -Color 'Error' -LogBox $dnaLogBox
        Show-OctoMessage -Text "Error: $($_.Exception.Message)" -Title 'Execution Error' -Icon Error | Out-Null
    } finally {
        Set-DnaBusy -Busy $false
        Set-OctoStatus -Text 'Ready'
        Update-Dashboard
    }
}

function Set-DnaExportPath {
    param([string]$Path)
    $script:outputDir = $Path
    $script:txtDNAExportPath.Text = $Path
    $env:OCTONAV_OUTPUT_DIR = $Path
    Write-Log -Message "Export path set to: $Path" -Color 'Info' -LogBox $dnaLogBox
}

# --- Event handlers -------------------------------------------------------------

$script:dnaTreeView.Add_NodeMouseDoubleClick({
    param($sender, $e)
    if ($e.Node -and $e.Node.Tag) { Invoke-DnaFunction -FunctionName ([string]$e.Node.Tag) }
})
$script:dnaTreeView.Add_KeyDown({
    param($sender, $e)
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter -and $script:dnaTreeView.SelectedNode -and $script:dnaTreeView.SelectedNode.Tag) {
        $e.Handled = $true
        Invoke-DnaFunction -FunctionName ([string]$script:dnaTreeView.SelectedNode.Tag)
    }
})
# Right-click selects the node under the mouse so the context menu acts on it
$script:dnaTreeView.Add_NodeMouseClick({
    param($sender, $e)
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right) { $script:dnaTreeView.SelectedNode = $e.Node }
})

$dnaTreeContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
$menuAddFavorite = New-Object System.Windows.Forms.ToolStripMenuItem('Add to Favorites')
$menuAddFavorite.Add_Click({
    $node = $script:dnaTreeView.SelectedNode
    if (-not $node -or -not $node.Tag) { return }
    $name = [string]$node.Tag
    $current = @($script:Settings.FavoriteFunctions | Where-Object { $_ })
    if ($current -contains $name) {
        Show-OctoMessage -Text 'Already in favorites!' -Title 'Favorites' | Out-Null
        return
    }
    $script:Settings.FavoriteFunctions = @($current + $name)
    [void](Save-OctoNavSettings -Settings $script:Settings)
    Update-DnaFavorites
})
[void]$dnaTreeContextMenu.Items.Add($menuAddFavorite)
$script:dnaTreeView.ContextMenuStrip = $dnaTreeContextMenu

function Get-SelectedFavoriteName {
    $item = [string]$script:lstFavorites.SelectedItem
    if ($item -match '\(([^()]+)\)\s*$') { return $Matches[1] }
    return $null
}
$script:lstFavorites.Add_DoubleClick({
    $name = Get-SelectedFavoriteName
    if ($name) { Invoke-DnaFunction -FunctionName $name }
})
$script:lstFavorites.Add_MouseDown({
    param($sender, $e)
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right) {
        $index = $script:lstFavorites.IndexFromPoint($e.Location)
        if ($index -ge 0) { $script:lstFavorites.SelectedIndex = $index }
    }
})
$favoritesContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
$menuRemoveFavorite = New-Object System.Windows.Forms.ToolStripMenuItem('Remove from Favorites')
$menuRemoveFavorite.Add_Click({
    $name = Get-SelectedFavoriteName
    if (-not $name) { return }
    $script:Settings.FavoriteFunctions = @($script:Settings.FavoriteFunctions | Where-Object { $_ -and $_ -ne $name })
    [void](Save-OctoNavSettings -Settings $script:Settings)
    Update-DnaFavorites
})
[void]$favoritesContextMenu.Items.Add($menuRemoveFavorite)
$script:lstFavorites.ContextMenuStrip = $favoritesContextMenu

$btnDNAConnect.Add_Click({
    $password = $null
    try {
        $selectedIndex = $comboDNAServer.SelectedIndex
        if ($selectedIndex -lt 0) {
            Show-OctoMessage -Text 'Please select a DNA Center server' -Title 'Warning' -Icon Warning | Out-Null
            return
        }
        $server = $script:dnaCenterServers[$selectedIndex]
        $username = $txtDNAUser.Text.Trim()
        $password = $txtDNAPass.Text
        if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password)) {
            Show-OctoMessage -Text 'Please enter username and password' -Title 'Warning' -Icon Warning | Out-Null
            return
        }
        Set-OctoStatus -Text 'Connecting to DNA Center...'
        $previousUrl = $script:Dna.BaseUrl
        $mainForm.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        try { $success = Connect-DNACenter -DnaCenter $server.Url -Username $username -Password $password -LogBox $dnaLogBox }
        finally { $mainForm.Cursor = [System.Windows.Forms.Cursors]::Default }

        if ($success) {
            $script:Dna.ServerName = $server.Name
            # Devices loaded from another DNA Center are no longer valid
            if ($previousUrl -and $previousUrl -ne $script:Dna.BaseUrl) {
                $script:Dna.Devices = @(); $script:Dna.Selected = @(); $script:Dna.DeviceById = @{}
                Clear-DnaDeviceUi
                Write-Log -Message 'Switched DNA Center - please load devices again' -Color 'Warning' -LogBox $dnaLogBox
            }
            $btnLoadDevices.Enabled = $true
            Set-OctoStatus -Text 'Ready - Connected to DNA Center'
            Update-ConnectionStatus -IsConnected $true -ServerName $server.Name
            Update-Dashboard
            Show-OctoMessage -Text 'Successfully connected to DNA Center!' -Title 'Success' | Out-Null
        } else {
            Set-OctoStatus -Text 'Ready - Failed to connect to DNA Center' -IsError
            Update-ConnectionStatus -IsConnected $false
            Update-Dashboard
            Show-OctoMessage -Text 'Failed to connect to DNA Center' -Title 'Error' -Icon Error | Out-Null
        }
    } catch {
        Write-Log -Message "Connection error: $($_.Exception.Message)" -Color 'Error' -LogBox $dnaLogBox
        Show-OctoMessage -Text "Connection error: $($_.Exception.Message)" -Title 'Error' -Icon Error | Out-Null
    } finally {
        $password = $null
        $txtDNAPass.Text = ''
    }
})

$btnLoadDevices.Add_Click({
    if ($script:Dna.Busy) { return }
    if (-not (Test-DNACTokenValid)) {
        Show-OctoMessage -Text 'The DNA Center session has expired - please connect again' -Title 'Not Connected' -Icon Warning | Out-Null
        return
    }
    Set-DnaBusy -Busy $true
    try {
        Set-OctoStatus -Text 'Loading devices from DNA Center...'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        if (Get-AllDNADevices -LogBox $dnaLogBox) {
            Initialize-DnaDeviceEntries
            Update-DnaDeviceList
            Set-DnaFilterControlsEnabled -Enabled $true
            Write-Log -Message ('Device list ready ({0:N1}s)' -f $sw.Elapsed.TotalSeconds) -Color 'Info' -LogBox $dnaLogBox
            Set-OctoStatus -Text "Ready - Loaded $($script:Dna.Devices.Count) devices from DNA Center"
        } else {
            Set-OctoStatus -Text 'Ready - Failed to load devices' -IsError
            Show-OctoMessage -Text 'Failed to load devices' -Title 'Error' -Icon Error | Out-Null
        }
    } catch {
        Write-Log -Message "Error loading devices: $($_.Exception.Message)" -Color 'Error' -LogBox $dnaLogBox
        Show-OctoMessage -Text "Error: $($_.Exception.Message)" -Title 'Error' -Icon Error | Out-Null
    } finally {
        Set-DnaBusy -Busy $false
    }
})

$btnDNAStop.Add_Click({
    if ($script:Dna.Shared) {
        $script:Dna.Shared.Stop = $true
        Write-Log -Message 'Stop requested - cancelling outstanding requests...' -Color 'Warning' -LogBox $dnaLogBox
    }
})

$btnApplyDeviceFilter.Add_Click({
    try {
        $selected = [System.Collections.Generic.List[object]]::new()
        foreach ($id in $script:dnaCheckedIds) {
            $device = $script:Dna.DeviceById[$id]
            if ($device) { $selected.Add($device) }
        }
        $script:Dna.Selected = $selected.ToArray()
        Update-DnaSelectionLabel
        if ($selected.Count -eq 0) {
            Write-Log -Message 'No devices selected - reports will use all loaded devices; CLI Command Runner needs a selection' -Color 'Yellow' -LogBox $dnaLogBox
            Show-OctoMessage -Text "No devices selected.`nCheck devices to select them for DNA Center operations." -Title 'No Selection' -Icon Warning | Out-Null
        } else {
            $hidden = $script:dnaCheckedIds.Count - $lstDevices.CheckedIndices.Count
            $note = if ($hidden -gt 0) { " ($hidden not visible with the current filter)" } else { '' }
            Write-Log -Message "Applied selection: $($selected.Count) device(s) selected for DNA Center operations$note" -Color 'Green' -LogBox $dnaLogBox
            Show-OctoMessage -Text "Selection applied successfully!`nSelected: $($selected.Count) device(s)$note" -Title 'Success' | Out-Null
        }
    } catch {
        Write-Log -Message "Error applying selection: $($_.Exception.Message)" -Color 'Red' -LogBox $dnaLogBox
    }
})

$btnResetDeviceFilter.Add_Click({
    try {
        $script:dnaUpdatingChecks = $true
        try {
            $txtFilterHostname.Text = ''
            foreach ($combo in @($cmbFilterFamily, $cmbFilterRole, $cmbFilterIPAddress)) { if ($combo.Items.Count -gt 0) { $combo.SelectedIndex = 0 } }
        } finally { $script:dnaUpdatingChecks = $false }
        $script:dnaCheckedIds.Clear()
        Reset-DNADeviceSelection -LogBox $dnaLogBox
        Update-DnaDeviceList
        Show-OctoMessage -Text 'Filters and selection have been reset.' -Title 'Reset' | Out-Null
    } catch {
        Write-Log -Message "Error resetting filters: $($_.Exception.Message)" -Color 'Red' -LogBox $dnaLogBox
    }
})

# Hostname search waits for a typing pause (250 ms); drop-downs filter immediately
$script:dnaFilterTimer = New-Object System.Windows.Forms.Timer
$script:dnaFilterTimer.Interval = 250
$script:dnaFilterTimer.Add_Tick({
    $script:dnaFilterTimer.Stop()
    if ($lstDevices.Enabled) { Update-DnaDeviceList }
})
$txtFilterHostname.Add_TextChanged({
    if ($script:dnaUpdatingChecks) { return }
    $script:dnaFilterTimer.Stop()
    $script:dnaFilterTimer.Start()
})
foreach ($combo in @($cmbFilterFamily, $cmbFilterRole, $cmbFilterIPAddress)) {
    $combo.Add_SelectedIndexChanged({
        if ($script:dnaUpdatingChecks -or -not $lstDevices.Enabled) { return }
        Update-DnaDeviceList
    })
}

$chkSelectAll.Add_CheckedChanged({
    if ($script:dnaUpdatingChecks -or -not $lstDevices.Enabled) { return }
    $check = $chkSelectAll.Checked
    $visible = $script:dnaVisibleDevices
    $lstDevices.BeginUpdate()
    $script:dnaUpdatingChecks = $true
    try {
        for ($i = 0; $i -lt $visible.Count; $i++) {
            $lstDevices.SetItemChecked($i, $check)
            if ($check) { [void]$script:dnaCheckedIds.Add($visible[$i].Id) } else { [void]$script:dnaCheckedIds.Remove($visible[$i].Id) }
        }
    } finally {
        $script:dnaUpdatingChecks = $false
        $lstDevices.EndUpdate()
    }
    Update-DnaSelectionLabel -VisibleChecked $(if ($check) { $visible.Count } else { 0 })
})

$lstDevices.Add_ItemCheck({
    param($sender, $e)
    if ($script:dnaUpdatingChecks) { return }
    if ($e.Index -lt 0 -or $e.Index -ge $script:dnaVisibleDevices.Count) { return }
    $id = $script:dnaVisibleDevices[$e.Index].Id
    $visibleChecked = $lstDevices.CheckedIndices.Count
    if ($e.NewValue -eq [System.Windows.Forms.CheckState]::Checked) {
        [void]$script:dnaCheckedIds.Add($id)
        if ($e.CurrentValue -ne [System.Windows.Forms.CheckState]::Checked) { $visibleChecked++ }
    } else {
        [void]$script:dnaCheckedIds.Remove($id)
        if ($e.CurrentValue -eq [System.Windows.Forms.CheckState]::Checked) { $visibleChecked-- }
    }
    Update-DnaSelectionLabel -VisibleChecked $visibleChecked
})

$btnDNAExportWorkDir.Add_Click({ Set-DnaExportPath -Path (Get-Location).Path })
$btnDNAExportFolder.Add_Click({
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = 'Select folder for exports'
    $folderBrowser.ShowNewFolderButton = $true
    if ($folderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Set-DnaExportPath -Path $folderBrowser.SelectedPath }
})
$btnDNAExportDefault.Add_Click({
    $default = if ($script:Settings.DefaultExportPath) { [string]$script:Settings.DefaultExportPath } else { 'C:\DNACenter_Reports' }
    Set-DnaExportPath -Path $default
})

Update-DnaFavorites

# ============================================
# TAB: FILE COMPARE
# ============================================

$tab4 = New-OctoTab -Text 'File Compare'
$compareFilesCard = New-OctoCard -Bounds @(16, 16, 1148, 176) -Title 'Files to Compare' -Parent $tab4 -Anchor 'Top,Left,Right'
[void](New-OctoControl Label @(16, 51, 90, 20) ([ordered]@{ Text = 'Original File' }) $compareFilesCard)
$txtFile1Path = New-OctoControl TextBox @(110, 48, 914, 23) ([ordered]@{ Font = $script:Fonts.Mono; Anchor = 'Top,Left,Right' }) $compareFilesCard
$btnBrowseFile1 = New-OctoControl Button @(1034, 46, 98, 28) ([ordered]@{ Text = 'Browse...'; Anchor = 'Top,Right' }) $compareFilesCard
[void](New-OctoControl Label @(16, 85, 90, 20) ([ordered]@{ Text = 'Modified File' }) $compareFilesCard)
$txtFile2Path = New-OctoControl TextBox @(110, 82, 914, 23) ([ordered]@{ Font = $script:Fonts.Mono; Anchor = 'Top,Left,Right' }) $compareFilesCard
$btnBrowseFile2 = New-OctoControl Button @(1034, 80, 98, 28) ([ordered]@{ Text = 'Browse...'; Anchor = 'Top,Right' }) $compareFilesCard
$btnExportDiff = New-OctoControl Button @(16, 124, 200, 36) ([ordered]@{ Text = 'Compare && Export HTML'; Tag = 'Primary' }) $compareFilesCard
$btnSwapFiles = New-OctoControl Button @(224, 124, 110, 36) ([ordered]@{ Text = 'Swap Files' }) $compareFilesCard
$btnClearCompare = New-OctoControl Button @(342, 124, 80, 36) ([ordered]@{ Text = 'Clear' }) $compareFilesCard
[void](New-OctoControl Label @(438, 133, 600, 20) ([ordered]@{ Text = 'The comparison runs in your browser - fast, and works offline.'; Tag = 'Muted' }) $compareFilesCard)
$compareHowCard = New-OctoCard -Bounds @(16, 204, 1148, 390) -Title 'How It Works' -Parent $tab4 -Anchor 'Top,Bottom,Left,Right'
[void](New-OctoControl Label @(16, 48, 1116, 326) ([ordered]@{
    Text = "1.  Select the original and the modified file with the Browse buttons.`n" +
        "2.  Click 'Compare && Export HTML' and choose where to save the report.`n" +
        "3.  The report opens in your browser:`n" +
        "       - side-by-side view with the changed characters highlighted`n" +
        "       - Prev / Next buttons and keyboard navigation (j / k or the arrow keys)`n" +
        "       - counts of added, removed and unchanged lines`n" +
        "       - an 'Ignore blank lines' option`n`n" +
        "Lines are matched with a minimal diff (longest common subsequence), so repeated lines such as '!' or 'exit'`n" +
        "in switch configurations do not make unrelated lines show up as changed."
    Font = $script:Fonts.Body; Anchor = 'Top,Bottom,Left,Right'
}) $compareHowCard)

function ConvertTo-JsStringArray {
    <#
    .SYNOPSIS
        Lines -> JavaScript array literal that is safe inside an HTML <script> block.
    .DESCRIPTION
        Always returns an array (also for an empty or one-line file) and escapes
        quotes, backslashes, control characters and < > & (so "</script>" in a
        file cannot end the script). Plain String.Replace on the joined text is
        much faster than ConvertTo-Json for large files in Windows PowerShell.
    #>
    param([AllowEmptyCollection()][string[]]$Lines)
    if ($null -eq $Lines -or $Lines.Count -eq 0) { return '[]' }
    $text = [string]::Join("`n", $Lines)
    $text = $text.Replace('\', '\\').Replace('"', '\"').Replace("`t", '\t')
    foreach ($code in @(0x3C, 0x3E, 0x26, 0x2028, 0x2029)) { $text = $text.Replace([string][char]$code, ('\u{0:x4}' -f $code)) }
    if ($text -match '[\x00-\x08\x0b-\x1f]') {
        $text = [regex]::Replace($text, '[\x00-\x08\x0b-\x1f]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
    }
    return '["' + $text.Replace("`n", '","') + '"]'
}

$script:DiffHtmlHead = @'
<!DOCTYPE html><html><head><meta charset="utf-8"><title>__FILE1__ &harr; __FILE2__</title>
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;--text:#c9d1d9;--text2:#8b949e;--add-bg:#12261e;--add-border:#238636;--add-text:#3fb950;--del-bg:#2d1b1b;--del-border:#da3633;--del-text:#f85149;--highlight-add:#033a16;--highlight-del:#67060c}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
.toolbar{background:var(--bg2);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;gap:20px;position:sticky;top:0;z-index:100;flex-wrap:wrap}
.toolbar h1{font-size:16px;font-weight:600}
.files{font-size:13px;color:var(--text2);flex:1}
.files b{color:var(--text);font-weight:500}
.stats{display:flex;gap:12px;font-size:13px}
.stat{padding:4px 12px;border-radius:20px;font-weight:500}
.stat-add{background:var(--add-bg);color:var(--add-text);border:1px solid var(--add-border)}
.stat-del{background:var(--del-bg);color:var(--del-text);border:1px solid var(--del-border)}
.stat-eq{background:var(--bg3);color:var(--text2);border:1px solid var(--border)}
.controls{display:flex;gap:8px;align-items:center}
.btn{background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:5px 12px;border-radius:6px;cursor:pointer;font-size:12px}
.btn:hover{background:var(--border)}
.nav-info{font-size:12px;color:var(--text2);min-width:80px;text-align:center}
#progress{padding:40px;text-align:center;color:var(--text2)}
.spinner{border:3px solid var(--bg3);border-top:3px solid #58a6ff;border-radius:50%;width:30px;height:30px;animation:spin 1s linear infinite;margin:0 auto 15px}
@keyframes spin{to{transform:rotate(360deg)}}
#diff{font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:12px}
.hunk{border:1px solid var(--border);margin:16px;border-radius:6px;overflow:hidden}
.hunk-header{background:var(--bg2);padding:8px 16px;color:var(--text2);font-size:12px;border-bottom:1px solid var(--border)}
.srow{display:flex;border-bottom:1px solid var(--border)}
.srow:last-child{border-bottom:none}
.srow.head .half{background:var(--bg2);padding:6px 12px;font-size:11px;color:var(--text2);font-weight:500}
.half{flex:1 1 50%;display:flex;min-width:0;min-height:20px;border-right:1px solid var(--border)}
.half:last-child{border-right:none}
.ln{width:50px;padding:0 8px;text-align:right;color:var(--text2);background:var(--bg2);flex-shrink:0;user-select:none;border-right:1px solid var(--border);font-size:11px;line-height:20px}
.code{flex:1;min-width:0;padding:0 12px;white-space:pre-wrap;word-break:break-all;line-height:20px;tab-size:4}
.row-add{background:var(--add-bg)}.row-add .ln{background:#0d2818;color:var(--add-text)}
.row-del{background:var(--del-bg)}.row-del .ln{background:#2a1515;color:var(--del-text)}
.row-ctx{background:var(--bg)}
.row-add .code::before{content:'+';color:var(--add-text);margin-right:8px;font-weight:bold}
.row-del .code::before{content:'\2212';color:var(--del-text);margin-right:8px;font-weight:bold}
.row-ctx .code::before{content:' ';margin-right:8px}
.empty-panel{background:var(--bg)}
.hl-add{background:var(--highlight-add);padding:1px 0;border-radius:2px}
.hl-del{background:var(--highlight-del);padding:1px 0;border-radius:2px}
.current-change{box-shadow:inset 4px 0 0 #58a6ff}
.same{padding:40px;text-align:center;color:var(--text2)}
.chk{display:flex;align-items:center;gap:6px;cursor:pointer;font-size:12px;color:var(--text2);padding:5px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg3)}
.chk input{accent-color:#238636;width:14px;height:14px;cursor:pointer}
</style></head><body>
<div class="toolbar">
<h1>Diff</h1>
<div class="files"><b>__FILE1__</b> &rarr; <b>__FILE2__</b></div>
<div class="stats" id="stats"></div>
<div class="controls">
<label class="chk"><input type="checkbox" id="ignoreBlanks" onchange="recompute()"><span>Ignore blank lines</span></label>
<button class="btn" onclick="prevChange()" title="Previous change (k / arrow up)">&#9650; Prev</button>
<span class="nav-info" id="navInfo">-/-</span>
<button class="btn" onclick="nextChange()" title="Next change (j / arrow down)">&#9660; Next</button>
</div>
</div>
<div id="progress"><div class="spinner"></div>Computing differences...</div>
<div id="diff"></div>
<script>
'@

$script:DiffHtmlScript = @'
// DIFF-ENGINE-BEGIN
var CTX=4,MAXD=2000,GAPD=500;
var diffs=[],hunks=[],curHunk=0;
function isBlank(s){return !s||!s.trim();}

// Myers shortest edit script over two Int32Arrays of line ids. Returns the matched
// index pairs [[i,j],...] in ascending order, or null when more than maxD lines differ.
function myersPairs(a,b,maxD){
  var n=a.length,m=b.length,max=Math.min(n+m,maxD),off=max+1;
  var v=new Int32Array(2*max+3),trace=[];
  for(var d=0;d<=max;d++){
    trace.push(v.slice(off-d-1,off+d+2));
    for(var k=-d;k<=d;k+=2){
      var x=(k===-d||(k!==d&&v[off+k-1]<v[off+k+1]))?v[off+k+1]:v[off+k-1]+1,y=x-k;
      while(x<n&&y<m&&a[x]===b[y]){x++;y++;}
      v[off+k]=x;
      if(x>=n&&y>=m)return backtrack(trace,n,m);
    }
  }
  return null;
}
function backtrack(trace,n,m){
  var pairs=[],x=n,y=m;
  for(var d=trace.length-1;d>=0;d--){
    var v=trace[d],o=d+1,k=x-y;
    var pk=(k===-d||(k!==d&&v[o+k-1]<v[o+k+1]))?k+1:k-1;
    var px=v[o+pk],py=px-pk;
    while(x>px&&y>py){x--;y--;pairs.push([x,y]);}
    x=px;y=py;
  }
  return pairs.reverse();
}
// Fallback for very different files: lines that occur exactly once in each file
// (longest increasing run of them) are anchors; the gaps between anchors are
// diffed again when they are small enough.
function anchorPairs(a,b){
  var ca=new Map(),cb=new Map(),pb=new Map(),cand=[],i,j,t;
  for(i=0;i<a.length;i++)ca.set(a[i],(ca.get(a[i])||0)+1);
  for(j=0;j<b.length;j++){cb.set(b[j],(cb.get(b[j])||0)+1);pb.set(b[j],j);}
  for(i=0;i<a.length;i++){if(ca.get(a[i])===1&&cb.get(a[i])===1)cand.push([i,pb.get(a[i])]);}
  var tails=[],tailIdx=[],prev=new Int32Array(cand.length);
  for(t=0;t<cand.length;t++){
    var jj=cand[t][1],lo=0,hi=tails.length;
    while(lo<hi){var mid=(lo+hi)>>1;if(tails[mid]<jj)lo=mid+1;else hi=mid;}
    tails[lo]=jj;tailIdx[lo]=t;prev[t]=lo>0?tailIdx[lo-1]:-1;
  }
  var out=[];t=tailIdx.length?tailIdx[tailIdx.length-1]:-1;
  while(t>=0){out.push(cand[t]);t=prev[t];}
  return out.reverse();
}
function fallbackPairs(a,b){
  var anchors=anchorPairs(a,b),out=[],pa=0,pb=0;
  function gap(ea,eb){
    if(ea>pa&&eb>pb){
      var r=myersPairs(a.subarray(pa,ea),b.subarray(pb,eb),GAPD);
      if(r)for(var t=0;t<r.length;t++)out.push([pa+r[t][0],pb+r[t][1]]);
    }
  }
  for(var t=0;t<anchors.length;t++){gap(anchors[t][0],anchors[t][1]);out.push(anchors[t]);pa=anchors[t][0]+1;pb=anchors[t][1]+1;}
  gap(a.length,b.length);
  return out;
}
function lcsPairs(A,B){
  var n=A.length,m=B.length,pairs=[],pre=0,suf=0,i,j,t;
  while(pre<n&&pre<m&&A[pre]===B[pre]){pairs.push([pre,pre]);pre++;}
  while(suf<n-pre&&suf<m-pre&&A[n-1-suf]===B[m-1-suf])suf++;
  // A line that never occurs on the other side cannot match: keep it out of the search
  var inA=new Set(),inB=new Set(),xa=[],xb=[];
  for(i=pre;i<n-suf;i++)inA.add(A[i]);
  for(j=pre;j<m-suf;j++)inB.add(B[j]);
  for(i=pre;i<n-suf;i++)if(inB.has(A[i]))xa.push(i);
  for(j=pre;j<m-suf;j++)if(inA.has(B[j]))xb.push(j);
  var a=new Int32Array(xa.length),b=new Int32Array(xb.length);
  for(t=0;t<xa.length;t++)a[t]=A[xa[t]];
  for(t=0;t<xb.length;t++)b[t]=B[xb[t]];
  var mid=myersPairs(a,b,MAXD)||fallbackPairs(a,b);
  for(t=0;t<mid.length;t++)pairs.push([xa[mid[t][0]],xb[mid[t][1]]]);
  for(t=suf;t>0;t--)pairs.push([n-t,m-t]);
  return pairs;
}
// Edit list over the original line numbers: {t:'='|'-'|'+', i1, i2}
function computeDiff(ignoreBlanks){
  var ia=[],ib=[],ids=new Map(),i,j,t;
  for(i=0;i<f1.length;i++)if(!ignoreBlanks||!isBlank(f1[i]))ia.push(i);
  for(j=0;j<f2.length;j++)if(!ignoreBlanks||!isBlank(f2[j]))ib.push(j);
  function id(s){var v=ids.get(s);if(v===undefined){v=ids.size;ids.set(s,v);}return v;}
  var A=new Int32Array(ia.length),B=new Int32Array(ib.length);
  for(t=0;t<ia.length;t++)A[t]=id(f1[ia[t]]);
  for(t=0;t<ib.length;t++)B[t]=id(f2[ib[t]]);
  var pairs=lcsPairs(A,B),d=[],p=0,q=0;
  for(t=0;t<pairs.length;t++){
    var x=pairs[t][0],y=pairs[t][1];
    while(p<x)d.push({t:'-',i1:ia[p++],i2:-1});
    while(q<y)d.push({t:'+',i1:-1,i2:ib[q++]});
    d.push({t:'=',i1:ia[p++],i2:ib[q++]});
  }
  while(p<A.length)d.push({t:'-',i1:ia[p++],i2:-1});
  while(q<B.length)d.push({t:'+',i1:-1,i2:ib[q++]});
  return d;
}
function buildHunks(d){
  var show=new Uint8Array(d.length),h=[],hunk=null,i,k;
  for(i=0;i<d.length;i++)if(d[i].t!=='='){for(k=Math.max(0,i-CTX);k<=Math.min(d.length-1,i+CTX);k++)show[k]=1;}
  for(i=0;i<d.length;i++){
    if(!show[i]){hunk=null;continue;}
    if(!hunk){hunk={lines:[]};h.push(hunk);}
    hunk.lines.push(d[i]);
  }
  return h;
}
// Side-by-side rows: [leftLine, rightLine, kind]; a block of removed lines is paired
// with the block of added lines that replaces it, the shorter side padded with blanks
function hunkRows(lines){
  var rows=[],k=0;
  while(k<lines.length){
    if(lines[k].t==='='){rows.push([lines[k].i1,lines[k].i2,'=']);k++;continue;}
    var dels=[],adds=[];
    while(k<lines.length&&lines[k].t!=='='){if(lines[k].t==='-')dels.push(lines[k].i1);else adds.push(lines[k].i2);k++;}
    for(var r=0;r<Math.max(dels.length,adds.length);r++)rows.push([r<dels.length?dels[r]:-1,r<adds.length?adds[r]:-1,'x']);
  }
  return rows;
}
// DIFF-ENGINE-END

function charDiff(s1,s2){
  if(!s1&&!s2)return{del:[],add:[]};
  if(!s1)return{del:[],add:[[0,s2.length]]};
  if(!s2)return{del:[[0,s1.length]],add:[]};
  var pre=0;while(pre<s1.length&&pre<s2.length&&s1[pre]===s2[pre])pre++;
  var suf=0;while(suf<s1.length-pre&&suf<s2.length-pre&&s1[s1.length-1-suf]===s2[s2.length-1-suf])suf++;
  var d1=s1.length-suf,a1=s2.length-suf;
  return{del:d1>pre?[[pre,d1]]:[],add:a1>pre?[[pre,a1]]:[]};
}
function esc(s){return s==null?'':String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function renderWithHighlight(text,ranges,hlClass){
  if(!ranges||ranges.length===0)return esc(text);
  var result='',lastEnd=0;
  for(var r=0;r<ranges.length;r++){
    var s=ranges[r][0],e=ranges[r][1];
    if(s>lastEnd)result+=esc(text.slice(lastEnd,s));
    result+='<span class="'+hlClass+'">'+esc(text.slice(s,e))+'</span>';
    lastEnd=e;
  }
  if(lastEnd<text.length)result+=esc(text.slice(lastEnd));
  return result;
}
function cell(cls,ln,html){return '<div class="half '+cls+'"><div class="ln">'+ln+'</div><div class="code">'+html+'</div></div>';}
var EMPTY='<div class="half empty-panel"><div class="ln"></div><div class="code"></div></div>';

function render(){
  var out=[];
  hunks.forEach(function(h,hi){
    var s1='',s2='';
    h.lines.forEach(function(d){if(s1===''&&d.i1>=0)s1=d.i1+1;if(s2===''&&d.i2>=0)s2=d.i2+1;});
    out.push('<div class="hunk" id="hunk'+hi+'"><div class="hunk-header">@@ Lines '+(s1||'-')+' / '+(s2||'-')+' @@</div><div class="srow head"><div class="half">Original</div><div class="half">Modified</div></div>');
    hunkRows(h.lines).forEach(function(row){
      var i1=row[0],i2=row[1];
      if(row[2]==='='){out.push('<div class="srow">'+cell('row-ctx',i1+1,esc(f1[i1]))+cell('row-ctx',i2+1,esc(f2[i2]))+'</div>');return;}
      var left=EMPTY,right=EMPTY;
      if(i1>=0&&i2>=0){
        var cd=charDiff(f1[i1],f2[i2]);
        left=cell('row-del',i1+1,renderWithHighlight(f1[i1],cd.del,'hl-del'));
        right=cell('row-add',i2+1,renderWithHighlight(f2[i2],cd.add,'hl-add'));
      }else if(i1>=0){left=cell('row-del',i1+1,esc(f1[i1]));}
      else{right=cell('row-add',i2+1,esc(f2[i2]));}
      out.push('<div class="srow">'+left+right+'</div>');
    });
    out.push('</div>');
  });
  var ign=document.getElementById('ignoreBlanks').checked;
  document.getElementById('diff').innerHTML=out.join('')||('<div class="same">No differences'+(ign?' (blank lines ignored)':'')+' - the files are identical</div>');
  updateNav();
}
function recompute(){
  document.getElementById('progress').style.display='block';
  document.getElementById('diff').innerHTML='';
  setTimeout(function(){
    diffs=computeDiff(document.getElementById('ignoreBlanks').checked);
    hunks=buildHunks(diffs);
    var add=0,del=0,eq=0;
    diffs.forEach(function(d){if(d.t==='+')add++;else if(d.t==='-')del++;else eq++;});
    document.getElementById('stats').innerHTML='<span class="stat stat-add">+'+add+'</span><span class="stat stat-del">&minus;'+del+'</span><span class="stat stat-eq">'+eq+' unchanged</span>';
    document.getElementById('progress').style.display='none';
    curHunk=0;
    render();
    if(hunks.length)goToHunk(0);
  },10);
}
function updateNav(){document.getElementById('navInfo').textContent=hunks.length?(curHunk+1)+'/'+hunks.length:'0/0';}
function goToHunk(i){
  if(hunks.length===0)return;
  curHunk=Math.max(0,Math.min(hunks.length-1,i));
  var all=document.querySelectorAll('.hunk');
  for(var j=0;j<all.length;j++)all[j].classList.toggle('current-change',j===curHunk);
  var el=document.getElementById('hunk'+curHunk);
  if(el)el.scrollIntoView({behavior:'smooth',block:'center'});
  updateNav();
}
function nextChange(){goToHunk(curHunk+1);}
function prevChange(){goToHunk(curHunk-1);}
document.addEventListener('keydown',function(e){
  if(e.target&&e.target.tagName==='INPUT')return;
  if(e.key==='ArrowDown'||e.key==='j'){nextChange();e.preventDefault();}
  if(e.key==='ArrowUp'||e.key==='k'){prevChange();e.preventDefault();}
});
setTimeout(recompute,50);
</script></body></html>
'@

function Export-FileComparisonHtml {
    <#
    .SYNOPSIS
        Writes the self-contained HTML comparison report (the browser computes the diff).
    #>
    param([string]$OriginalPath, [string]$ModifiedPath, [string]$OutputPath)
    $name1 = [System.Net.WebUtility]::HtmlEncode([System.IO.Path]::GetFileName($OriginalPath))
    $name2 = [System.Net.WebUtility]::HtmlEncode([System.IO.Path]::GetFileName($ModifiedPath))
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append($script:DiffHtmlHead.Replace('__FILE1__', $name1).Replace('__FILE2__', $name2))
    [void]$builder.Append('var f1=').Append((ConvertTo-JsStringArray -Lines ([System.IO.File]::ReadAllLines($OriginalPath)))).Append(";`n")
    [void]$builder.Append('var f2=').Append((ConvertTo-JsStringArray -Lines ([System.IO.File]::ReadAllLines($ModifiedPath)))).Append(";`n")
    [void]$builder.Append($script:DiffHtmlScript)
    [System.IO.File]::WriteAllText($OutputPath, $builder.ToString(), [System.Text.UTF8Encoding]::new($true))
}

$compareFileFilter = 'All Files (*.*)|*.*|Text Files (*.txt)|*.txt|Config Files (*.cfg;*.conf;*.ini)|*.cfg;*.conf;*.ini|Log Files (*.log)|*.log|Script Files (*.ps1;*.bat;*.sh)|*.ps1;*.bat;*.sh'
function Select-CompareFile {
    param([string]$Title, [System.Windows.Forms.TextBox]$Target)
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = $Title
    $dialog.Filter = $compareFileFilter
    $dialog.InitialDirectory = if ($Target.Text -and (Test-Path -LiteralPath $Target.Text)) { Split-Path -Parent $Target.Text } else { [Environment]::GetFolderPath('MyDocuments') }
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $Target.Text = $dialog.FileName }
}
$btnBrowseFile1.Add_Click({ Select-CompareFile -Title 'Select Original File' -Target $txtFile1Path })
$btnBrowseFile2.Add_Click({ Select-CompareFile -Title 'Select Modified File' -Target $txtFile2Path })
$btnSwapFiles.Add_Click({
    $temp = $txtFile1Path.Text
    $txtFile1Path.Text = $txtFile2Path.Text
    $txtFile2Path.Text = $temp
})
$btnClearCompare.Add_Click({ $txtFile1Path.Text = ''; $txtFile2Path.Text = '' })

$btnExportDiff.Add_Click({
    $file1 = $txtFile1Path.Text.Trim().Trim('"')
    $file2 = $txtFile2Path.Text.Trim().Trim('"')
    if (-not $file1 -or -not $file2) {
        Show-OctoMessage -Text 'Please select both files to compare.' -Title 'Files Required' -Icon Warning | Out-Null
        return
    }
    foreach ($pair in @(@('Original', $file1), @('Modified', $file2))) {
        if (-not (Test-Path -LiteralPath $pair[1] -PathType Leaf)) {
            Show-OctoMessage -Text "$($pair[0]) file not found:`n$($pair[1])" -Title 'File Not Found' -Icon Error | Out-Null
            return
        }
    }
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Title = 'Save Comparison Report'
    $saveDialog.Filter = 'HTML Report (*.html)|*.html'
    $saveDialog.FileName = "FileComparison_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    if ($saveDialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
    try {
        $btnExportDiff.Enabled = $false
        $btnExportDiff.Text = 'Exporting...'
        Set-OctoStatus -Text 'Creating comparison report...'
        [System.Windows.Forms.Application]::DoEvents()
        Export-FileComparisonHtml -OriginalPath $file1 -ModifiedPath $file2 -OutputPath $saveDialog.FileName
        Add-ExportHistory -Settings $script:Settings -FilePath $saveDialog.FileName -Operation 'File Compare' -Format 'HTML'
        Set-OctoStatus -Text "Comparison exported: $($saveDialog.FileName)"
        Start-Process -FilePath $saveDialog.FileName
    } catch {
        Set-OctoStatus -Text 'Comparison failed' -IsError
        Show-OctoMessage -Text "Error creating comparison:`n`n$($_.Exception.Message)" -Title 'Export Error' -Icon Error | Out-Null
    } finally {
        $btnExportDiff.Enabled = $true
        $btnExportDiff.Text = 'Compare && Export HTML'
    }
})

# ============================================
# TAB: RDOX EXPORTS
# ============================================

$tab7 = New-OctoTab -Text 'RDOX Exports'
$resourcesCard = New-OctoCard -Bounds @(16, 16, 1148, 578) -Title 'Embedded RDOX Files' -Parent $tab7 -Anchor 'Top,Bottom,Left,Right'
[void](New-OctoControl Label @(16, 46, 900, 20) ([ordered]@{ Text = 'Select files to export (Ctrl+Click for several), or select none to export all of them.'; Tag = 'Muted' }) $resourcesCard)
$script:lstResources = New-OctoControl ListBox @(16, 72, 916, 490) ([ordered]@{ Font = $script:Fonts.MonoLarge; SelectionMode = 'MultiExtended'; Anchor = 'Top,Bottom,Left,Right'; IntegralHeight = $false }) $resourcesCard
if ($script:EmbeddedResources -and $script:EmbeddedResources.Count -gt 0) {
    $script:lstResources.Items.AddRange([object[]]@(Get-EmbeddedResourceList))
} else {
    [void]$script:lstResources.Items.Add('(No embedded resources - run Package-Resources.ps1)')
    $script:lstResources.Enabled = $false
}
$btnExportToWorkDir = New-OctoControl Button @(948, 72, 184, 34) ([ordered]@{ Text = 'Export to Working Directory'; Tag = 'Primary'; Anchor = 'Top,Right' }) $resourcesCard
$btnExportToCustomDir = New-OctoControl Button @(948, 114, 184, 34) ([ordered]@{ Text = 'Export to Folder...'; Anchor = 'Top,Right' }) $resourcesCard

function Export-SelectedResources {
    param([string]$Folder)
    if (-not $script:EmbeddedResources -or $script:EmbeddedResources.Count -eq 0) {
        Show-OctoMessage -Text 'No embedded resources available.' -Title 'No Resources' | Out-Null
        return
    }
    $names = @($script:lstResources.SelectedItems | ForEach-Object { [string]$_ })
    if ($names.Count -eq 0) { $names = @(Get-EmbeddedResourceList) }
    try { Export-OctoResources -Names $names -Folder $Folder }
    catch { Show-OctoMessage -Text "Error exporting: $($_.Exception.Message)" -Title 'Export Error' -Icon Error | Out-Null }
}
$btnExportToWorkDir.Add_Click({ Export-SelectedResources -Folder (Get-Location).Path })
$btnExportToCustomDir.Add_Click({
    if (-not $script:EmbeddedResources -or $script:EmbeddedResources.Count -eq 0) {
        Show-OctoMessage -Text 'No embedded resources available.' -Title 'No Resources' | Out-Null
        return
    }
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = 'Select folder to export resources to'
    $folderBrowser.ShowNewFolderButton = $true
    if ($folderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Export-SelectedResources -Folder $folderBrowser.SelectedPath }
})

# ============================================
# TAB: PORT CONFIGURATION
# ============================================

$tab5 = New-OctoTab -Text 'Port Config'
$portInputCard = New-OctoCard -Bounds @(16, 16, 400, 578) -Title 'Configuration Parameters' -Parent $tab5 -Anchor 'Top,Bottom,Left'
# Old VLAN is last: it is hidden for vendors that do not use it, without leaving a gap
$portFields = [ordered]@{
    Vendor = 'Vendor'; PortType = 'Port Type'; Interface = 'Interface'; Description = 'Description'
    Vlan = 'VLAN'; VoiceVlan = 'Voice VLAN'; Status = 'Status'; OldVlan = 'Old VLAN'
}
$portDefaults = @{ Interface = 'Gi1/0/1'; Description = 'User PC'; Vlan = '100'; OldVlan = ''; VoiceVlan = '200'; Status = 'no shutdown' }
$portInputs = @{}
$portLabels = @{}
$y = 48
foreach ($key in $portFields.Keys) {
    $portLabels[$key] = New-OctoControl Label @(16, ($y + 3), 100, 20) ([ordered]@{ Text = $portFields[$key] }) $portInputCard
    if ($key -eq 'Vendor' -or $key -eq 'PortType') {
        $portInputs[$key] = New-OctoControl ComboBox @(120, $y, 264, 23) ([ordered]@{ DropDownStyle = 'DropDownList' }) $portInputCard
    } else {
        $portInputs[$key] = New-OctoControl TextBox @(120, $y, 264, 23) ([ordered]@{ Text = $portDefaults[$key] }) $portInputCard
    }
    $y += 34
}
$cboVendor = $portInputs.Vendor
$cboPortType = $portInputs.PortType
[void]$cboVendor.Items.AddRange([object[]]@('Cisco', 'ICX/FCX 8030', 'FCX 7.3'))

$btnGenerateConfig = New-OctoControl Button @(16, 330, 118, 34) ([ordered]@{ Text = 'Generate Config'; Tag = 'Primary' }) $portInputCard
$btnCopyConfig = New-OctoControl Button @(142, 330, 134, 34) ([ordered]@{ Text = 'Copy to Clipboard' }) $portInputCard
$btnClearConfig = New-OctoControl Button @(284, 330, 100, 34) ([ordered]@{ Text = 'Clear' }) $portInputCard
$btnSaveTemplate = New-OctoControl Button @(16, 372, 130, 34) ([ordered]@{ Text = 'Save as Template' }) $portInputCard
$btnLoadTemplate = New-OctoControl Button @(154, 372, 122, 34) ([ordered]@{ Text = 'Load Template' }) $portInputCard
[void](New-OctoControl Label @(16, 422, 368, 18) ([ordered]@{ Text = 'Placeholders'; Font = $script:Fonts.Semibold }) $portInputCard)
[void](New-OctoControl Label @(16, 442, 368, 40) ([ordered]@{ Text = "{{INTERFACE}} {{DESCRIPTION}} {{VLAN}}`n{{VOICE_VLAN}} {{OLD_VLAN}} {{STATUS}}"; Font = $script:Fonts.Mono; Tag = 'Muted' }) $portInputCard)
$portOutputCard = New-OctoCard -Bounds @(428, 16, 736, 578) -Title 'Configuration / Template Editor' -Parent $tab5 -Anchor 'Top,Bottom,Left,Right'
[void](New-OctoControl Label @(272, 19, 448, 20) ([ordered]@{ Text = 'Paste a template with {{PLACEHOLDERS}} here, or generate a configuration.'; Tag = 'Muted'; Anchor = 'Top,Left,Right' }) $portOutputCard)
$portEditorFrame = New-OctoFrame -Bounds @(16, 48, 704, 514) -Parent $portOutputCard
$txtConfigOutput = New-OctoControl TextBox $null ([ordered]@{ Dock = 'Fill'; BorderStyle = 'None'; Multiline = $true; ScrollBars = 'Both'; WordWrap = $false; Font = $script:Fonts.MonoLarge; MaxLength = 0 }) $portEditorFrame

function ConvertTo-WindowsNewLines {
    # A multi-line TextBox shows a line break only for CR LF
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [regex]::Replace($Text, "\r\n|\r|\n", "`r`n")
}

function Update-PortTypeList {
    $vendor = [string]$cboVendor.SelectedItem
    $isFCX73 = ($vendor -eq 'FCX 7.3')
    $portLabels.OldVlan.Visible = $isFCX73
    $portInputs.OldVlan.Visible = $isFCX73
    $cboPortType.BeginUpdate()
    try {
        $cboPortType.Items.Clear()
        if ($vendor -and $script:PortTemplates.ContainsKey($vendor)) {
            $types = [string[]]@($script:PortTemplates[$vendor].Keys)
            [Array]::Sort($types, [System.StringComparer]::OrdinalIgnoreCase)
            if ($types.Count -gt 0) { $cboPortType.Items.AddRange([object[]]$types) }
            if ($cboPortType.Items.Count -gt 0) { $cboPortType.SelectedIndex = 0 }
        }
    } finally { $cboPortType.EndUpdate() }
}
$cboVendor.Add_SelectedIndexChanged({ Update-PortTypeList })
$cboVendor.SelectedIndex = 0

function Get-SelectedPortTemplateKey {
    param([switch]$RequireTemplate)
    $vendor = [string]$cboVendor.SelectedItem
    $portType = [string]$cboPortType.SelectedItem
    if (-not $vendor) { Show-OctoMessage -Text 'Please select a vendor.' -Title 'Error' -Icon Error | Out-Null; return $null }
    if (-not $portType) {
        Show-OctoMessage -Text 'Please select a port type. If the Port Type dropdown is empty, no templates are available for the selected vendor.' -Title 'Error' -Icon Error | Out-Null
        return $null
    }
    if ($RequireTemplate -and -not ($script:PortTemplates.ContainsKey($vendor) -and $script:PortTemplates[$vendor].ContainsKey($portType))) {
        Show-OctoMessage -Text "No template found for:`n`nVendor: $vendor`nPort Type: $portType`n`nPaste your config with {{PLACEHOLDERS}} and click 'Save as Template'." -Title 'No Template' | Out-Null
        return $null
    }
    return @{ Vendor = $vendor; PortType = $portType }
}

$btnGenerateConfig.Add_Click({
    $key = Get-SelectedPortTemplateKey -RequireTemplate
    if (-not $key) { return }
    # Literal replacement: '$' or '\' in a description is copied as typed
    $config = [string]$script:PortTemplates[$key.Vendor][$key.PortType]
    $config = $config.Replace('{{INTERFACE}}', $portInputs.Interface.Text).Replace('{{DESCRIPTION}}', $portInputs.Description.Text)
    $config = $config.Replace('{{VLAN}}', $portInputs.Vlan.Text).Replace('{{OLD_VLAN}}', $portInputs.OldVlan.Text)
    $config = $config.Replace('{{VOICE_VLAN}}', $portInputs.VoiceVlan.Text).Replace('{{STATUS}}', $portInputs.Status.Text)
    $txtConfigOutput.Text = ConvertTo-WindowsNewLines -Text $config
    Set-OctoStatus -Text "Config generated for $($key.Vendor) - $($key.PortType)"
})
$btnCopyConfig.Add_Click({
    if ([string]::IsNullOrWhiteSpace($txtConfigOutput.Text)) {
        Show-OctoMessage -Text 'No configuration to copy. Generate a config first.' -Title 'Nothing to Copy' | Out-Null
        return
    }
    try {
        [System.Windows.Forms.Clipboard]::SetText($txtConfigOutput.Text)
        Set-OctoStatus -Text 'Configuration copied to clipboard'
    } catch {
        Show-OctoMessage -Text "Could not copy to the clipboard: $($_.Exception.Message)" -Title 'Clipboard' -Icon Warning | Out-Null
    }
})
$btnClearConfig.Add_Click({
    foreach ($k in $portDefaults.Keys) { $portInputs[$k].Text = $portDefaults[$k] }
    $txtConfigOutput.Text = ''
})
$btnSaveTemplate.Add_Click({
    $key = Get-SelectedPortTemplateKey
    if (-not $key) { return }
    $templateContent = $txtConfigOutput.Text
    if ([string]::IsNullOrWhiteSpace($templateContent)) {
        Show-OctoMessage -Text "Please paste your template configuration in the text area first.`n`nUse placeholders like {{INTERFACE}}, {{VLAN}}, etc. where variables should go." -Title 'No Template Content' -Icon Warning | Out-Null
        return
    }
    $confirm = Show-OctoMessage -Text "Save this template for:`n`nVendor: $($key.Vendor)`nPort Type: $($key.PortType)`n`nThis will overwrite any existing template for this combination." -Title 'Confirm Save Template' -Icon Question -Buttons YesNo
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    if (-not $script:PortTemplates.ContainsKey($key.Vendor)) { $script:PortTemplates[$key.Vendor] = @{} }
    $script:PortTemplates[$key.Vendor][$key.PortType] = $templateContent
    try {
        $saved = @{}
        if (Test-Path -LiteralPath $script:PortTemplatesFile) { $saved = Get-Content -LiteralPath $script:PortTemplatesFile -Raw | ConvertFrom-Json | ConvertTo-Hashtable }
        if (-not $saved) { $saved = @{} }
        if (-not $saved.ContainsKey($key.Vendor)) { $saved[$key.Vendor] = @{} }
        $saved[$key.Vendor][$key.PortType] = $templateContent
        $saved | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $script:PortTemplatesFile -Encoding UTF8
        Set-OctoStatus -Text "Template saved: $($key.Vendor) / $($key.PortType)"
        Show-OctoMessage -Text "Template saved successfully!`n`nVendor: $($key.Vendor)`nPort Type: $($key.PortType)`n`nSaved to: $script:PortTemplatesFile" -Title 'Template Saved' | Out-Null
    } catch {
        Show-OctoMessage -Text "Error saving template file:`n`n$($_.Exception.Message)`n`nTemplate is saved for this session only." -Title 'Save Error' -Icon Warning | Out-Null
    }
})
$btnLoadTemplate.Add_Click({
    $key = Get-SelectedPortTemplateKey -RequireTemplate
    if (-not $key) { return }
    $txtConfigOutput.Text = ConvertTo-WindowsNewLines -Text ([string]$script:PortTemplates[$key.Vendor][$key.PortType])
    Set-OctoStatus -Text "Template loaded: $($key.Vendor) / $($key.PortType)"
})

# ============================================
# TAB: HELP GUIDE
# ============================================

$tab6 = New-OctoTab -Text 'Help Guide'
$helpCard = New-OctoCard -Bounds @(16, 16, 1148, 578) -Parent $tab6 -Anchor 'Top,Bottom,Left,Right'
$helpText = New-OctoControl RichTextBox @(24, 18, 1108, 544) ([ordered]@{
    ReadOnly = $true; BorderStyle = 'None'; Anchor = 'Top,Bottom,Left,Right'; DetectUrls = $false; WordWrap = $true; Tag = 'Card'
}) $helpCard

# '# ' title, '## ' section, '### ' label, '- ' bullet ('  - ' nested), '1. ' step
$script:HelpMarkup = @'
# OctoNav Help
OctoNav runs as a standard user. Only the Network Configuration tab needs "Run as Administrator" (it changes adapter IP settings).
Switch tabs with the bar at the top, or with Ctrl+Tab and Ctrl+Shift+Tab.
## Network Configuration
### What it does
Changes your computer's IP address and starts the TFTP server - useful when you connect directly to a switch for configuration or firmware uploads. This tab needs Administrator rights (right-click the script and choose "Run as Administrator").
### How to use it
1. Fill in the IP settings:
  - New IP Address: the address you want (example: 192.168.1.101)
  - Gateway: usually the switch's IP (example: 192.168.1.1)
  - Prefix Length: usually 24 (the same as subnet mask 255.255.255.0)
2. Click "Apply Configuration". It finds the unidentified network adapter, applies your IP settings, changes the network from Public to Private and starts the TFTP server (RunStandAloneMT.bat) if it is present.
3. When you are done, click "Restore Defaults". It stops the TFTP server and sets the adapter back to DHCP (automatic IP).
### Which IP should I use?
- If the switch is 192.168.1.1, use for example 192.168.1.100 (the same first three numbers).
- The last number just has to be different from the switch.
## DHCP Statistics
### What it does
Collects scope usage from your Windows DHCP servers, many servers at once.
### How to use it
1. Select DHCP servers:
  - "Refresh Server List" reads the servers from Active Directory
  - Check the servers you want, or type names (comma-separated)
  - Nothing selected = all domain DHCP servers
2. Optional - select specific scopes:
  - "Refresh Cache" loads all scopes
  - Filter (3+ characters, comma = OR) and Prefix (2+ characters)
  - "Select All Visible"; selections are kept when you change the filter
  - The server and scope caches are encrypted with ONE password. If a cache does not open, you can type its password again or skip it; after a skip, "Refresh Cache" rebuilds it with your current password.
3. Options:
  - DNS Servers (Option 6), Option 60, Option 43, or all configured options
  - Parallel queries: how many servers are queried at the same time
4. Click "Collect DHCP Statistics" ("Stop" keeps what is collected so far):
  - A summary is written to the log and a CSV is exported automatically
  - A server that fails is tried once more; servers that still fail are named in the summary (scopes only they serve are missing)
  - An option lookup that fails is tried once more (one scope at a time, after the server's other lookups finish). If it fails again, its option columns say "(lookup failed)" and the summary lists it
  - After a full collection the log compares the result with the scope cache and lists every cached scope that was not collected, and why
### How the numbers are calculated (redundancy-aware)
- Failover partners (load balance or hot standby) both report the WHOLE scope, so a failover scope is counted ONCE - not twice.
- A scope split across servers without failover (split scope) has each server's part of the pool added together.
- Added-up pools can never exceed the scope's address range: copies that hand out the same addresses without failover are capped at the range and marked "OVERLAPPING POOLS".
- The same scope ID under different scope names on different servers is treated as separate networks (each pool counted), marked "DIFFERENT SCOPE NAMES". The per-server export lists each one.
- Inactive copies of a scope are not counted.
- "Group by Scope ID on Export" writes one row per scope with the columns Redundancy, FailoverPartner, FailoverState and Notes (for example a degraded failover relationship or pools that differ between partners).
- Percentage in use = in use / (in use + free), per scope and overall.
- The log shows two counts: scope ROWS (one per scope per server - what the old tool reported) and UNIQUE scopes (a scope on a failover pair or split across servers is one scope).
- A server listed more than once in Active Directory (one entry per IP, aliases, stale entries whose name no longer resolves) is queried once; the log lists every skipped entry and why.
## DNA Center
1. Select the server, enter username and password, and click "Connect".
2. Click "Load Devices".
3. Optional - filter by hostname, family, role or IP.
4. Check devices and click "Apply Selection". No selection = reports use all loaded devices; the CLI Command Runner always needs a selection.
5. Double-click a function in the tree (or a favorite). Right-click a function to add it to Favorites.
- Device queries run in parallel; "Stop" cancels a running report.
- A request that fails for a temporary reason (no answer, timeout, rate limit, server error) is tried once more after a pause, 2 at a time. Devices that still fail are named in the log with the error.
- Reports are exported as CSV to the Export Folder.
## File Compare
1. Browse to the ORIGINAL (before) file and the MODIFIED (after) file.
2. Click "Compare & Export HTML" and choose where to save the report.
3. The report opens in your browser:
  - Green = added lines, red = removed lines, changed characters highlighted
  - Prev / Next buttons; keyboard: j / k or the arrow keys
  - "Ignore blank lines" option
"Swap Files" switches the two files, "Clear" empties both boxes.
## Port Config
1. Pick the switch type (Cisco, ICX/FCX 8030, FCX 7.3) and a Port Type.
2. Fill in Interface, Description, VLAN, Voice VLAN and Status (Old VLAN is only used by FCX 7.3).
3. Click "Generate Config", then "Copy to Clipboard".
Custom templates: paste your config into the editor, replace the values with placeholders, select Vendor and Port Type, and click "Save as Template".
### Placeholders
- {{INTERFACE}} - port name
- {{DESCRIPTION}} - port description
- {{VLAN}} - data VLAN
- {{VOICE_VLAN}} - voice VLAN
- {{OLD_VLAN}} - old VLAN (FCX 7.3 only)
- {{STATUS}} - no shutdown / shutdown
## General Tips
- Each tab has a log or status area - check it when something fails
- View > Toggle Theme (Ctrl+T) switches between the Light and Dark themes
- The RDOX Exports tab exports embedded resource files
- Settings and caches are stored next to OctoNav.ps1, or in %LOCALAPPDATA%\OctoNav when that folder is read-only
- The window size is saved when you close OctoNav
'@

function Set-OctoHelpText {
    <#
    .SYNOPSIS
        Renders the help markup with the current theme's colours.
    #>
    $theme = $script:CurrentTheme
    $helpText.Clear()
    foreach ($raw in ($script:HelpMarkup -split "`r?`n")) {
        $text = $raw; $font = $script:Fonts.Body; $color = $theme.Text
        $indent = 0; $hanging = 0; $bullet = $false; $gap = $false
        if ($raw.StartsWith('# ')) { $text = $raw.Substring(2); $font = $script:Fonts.HelpTitle; $color = $theme.NavSelected }
        elseif ($raw.StartsWith('## ')) { $text = $raw.Substring(3); $font = $script:Fonts.HelpHeading; $gap = $true }
        elseif ($raw.StartsWith('### ')) { $text = $raw.Substring(4); $font = $script:Fonts.HelpLabel; $gap = $true }
        elseif ($raw -match '^(\s*)- (.*)$') { $text = $Matches[2]; $bullet = $true; $indent = if ($Matches[1]) { 44 } else { 22 } }
        elseif ($raw -match '^\d+\. ') { $indent = 4; $hanging = 18 }
        # A small empty line before headings (the RichTextBox has no paragraph spacing)
        $lines = [System.Collections.Generic.List[object]]::new()
        if ($gap) { $lines.Add(@('', $script:Fonts.Spacer)) }
        $lines.Add(@($text, $font))
        foreach ($line in $lines) {
            $helpText.SelectionStart = $helpText.TextLength
            $helpText.SelectionLength = 0
            $helpText.SelectionFont = $line[1]
            $helpText.SelectionColor = $color
            $helpText.SelectionBullet = ($bullet -and $line[0])
            $helpText.BulletIndent = 8
            $helpText.SelectionIndent = $indent
            $helpText.SelectionHangingIndent = $hanging
            $helpText.AppendText($line[0] + "`n")
        }
    }
    $helpText.SelectionStart = 0
    $helpText.ScrollToCaret()
}

# ============================================
# STATUS BAR, THEME, CACHES, SHOW
# ============================================

$script:StatusBarPanels = New-EnhancedStatusBar -Form $mainForm
# Docked last = fills what the status bar, menu and navigation bar leave
$script:pageHost.BringToFront()

function Set-OctoTheme {
    # Recolours the whole window for $script:CurrentTheme
    $mainForm.SuspendLayout()
    try {
        Set-ThemeToControl -Control $mainForm -Theme $script:CurrentTheme
        Update-OctoNav
        Update-ScopeFilterColors
        Set-OctoHelpText
    } finally { $mainForm.ResumeLayout() }
    $mainForm.Invalidate($true)
}

Select-OctoPage -Index 0
Set-OctoTheme

function ConvertTo-OctoDateTime {
    # Cache timestamps are ISO 8601 strings (older caches: local date/time text)
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime]) { return $Value }
    $parsed = [DateTime]::MinValue
    if ([DateTime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed) -or
        [DateTime]::TryParse([string]$Value, [ref]$parsed)) {
        if ($parsed.Kind -eq [DateTimeKind]::Utc) { $parsed = $parsed.ToLocalTime() }
        return $parsed
    }
    return $null
}

try {
    $serverCache = Read-DhcpCache -Kind Servers
    if (@($serverCache.Items).Count -gt 0) {
        Set-DhcpServerList -Servers @($serverCache.Items)
        $updated = ConvertTo-OctoDateTime $serverCache.LastUpdated
        $script:lblLastRefresh.Text = if ($updated) { "Last refreshed: $($updated.ToString('yyyy-MM-dd HH:mm:ss')) (cached)" } else { 'Last refreshed: (cached)' }
    }
} catch {
    $script:lblLastRefresh.Text = 'Last refreshed: Never (error loading cache)'
}

try {
    $scopeCache = Read-DhcpCache -Kind Scopes
    if (@($scopeCache.Items).Count -gt 0) {
        Set-DhcpScopeList -Scopes @($scopeCache.Items)
        $updated = ConvertTo-OctoDateTime $scopeCache.LastUpdated
        $script:scopeCacheUpdated = $updated
        $when = if ($updated) { " ($($updated.ToString('MM/dd HH:mm')))" } else { '' }
        $script:lblScopeCacheStatus.Text = "Cache: $($script:allDHCPScopes.Count) scope(s) loaded$when"
        Set-OctoTone -Control $script:lblScopeCacheStatus -Tone Success
    }
} catch { }

if ($script:RequireStartupPassword) { Start-SessionMonitor -Form $mainForm }

# Slow lookups run after the window is on screen
$mainForm.Add_Shown({
    $mainForm.Activate()
    Update-Dashboard -IncludeAdapters
    if ($script:lstDHCPServers.Items.Count -eq 0) {
        try { Start-DhcpServerDiscovery -Quiet } catch { $script:lblLastRefresh.Text = 'Last refreshed: Never' }
    }
})

$mainForm.Add_FormClosing({
    $script:AppClosing = $true
    try {
        if ($script:dhcpJob -and -not $script:dhcpJob.Completed) { Stop-OctoJob -Job $script:dhcpJob }
        if ($script:Dna.Shared) { $script:Dna.Shared.Stop = $true }
        $bounds = if ($mainForm.WindowState -eq [System.Windows.Forms.FormWindowState]::Normal) { $mainForm.Bounds } else { $mainForm.RestoreBounds }
        if ($bounds.Width -ge 800 -and $bounds.Height -ge 500) { $script:Settings.WindowSize = @{ Width = $bounds.Width; Height = $bounds.Height } }
        $script:Settings.WindowMaximized = ($mainForm.WindowState -eq [System.Windows.Forms.FormWindowState]::Maximized)
        [void](Save-OctoNavSettings -Settings $script:Settings)
    } catch { }
})

$mainForm.ResumeLayout()
$script:pageHost.ResumeLayout()
[void]$mainForm.ShowDialog()

if ($script:SessionTimer) { try { $script:SessionTimer.Stop(); $script:SessionTimer.Dispose() } catch { } }
Close-OctoRunspacePool -Pool $script:Dna.Pool
$mainForm.Dispose()
