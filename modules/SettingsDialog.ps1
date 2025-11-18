#Requires -Version 5.1
<#
.SYNOPSIS
    Settings Dialog for OctoNav GUI v2.3
.DESCRIPTION
    GUI dialog for managing application settings and preferences
#>

function Show-SettingsDialog {
    <#
    .SYNOPSIS
        Shows the settings/preferences dialog
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Settings,

        [hashtable]$Theme = $null
    )

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "OctoNav Settings"
    $form.Size = New-Object System.Drawing.Size(600, 500)
    $form.StartPosition = "CenterParent"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

    # Tab Control for settings categories
    $tabControl = New-Object System.Windows.Forms.TabControl
    $tabControl.Location = New-Object System.Drawing.Point(10, 10)
    $tabControl.Size = New-Object System.Drawing.Size(560, 400)
    $form.Controls.Add($tabControl)

    # ============================================
    # APPEARANCE TAB
    # ============================================
    $tabAppearance = New-Object System.Windows.Forms.TabPage
    $tabAppearance.Text = "Appearance"
    $tabControl.Controls.Add($tabAppearance)

    # Theme selection
    $lblTheme = New-Object System.Windows.Forms.Label
    $lblTheme.Text = "Theme:"
    $lblTheme.Location = New-Object System.Drawing.Point(20, 20)
    $lblTheme.Size = New-Object System.Drawing.Size(100, 20)
    $tabAppearance.Controls.Add($lblTheme)

    $comboTheme = New-Object System.Windows.Forms.ComboBox
    $comboTheme.Location = New-Object System.Drawing.Point(130, 20)
    $comboTheme.Size = New-Object System.Drawing.Size(150, 20)
    $comboTheme.DropDownStyle = "DropDownList"
    $comboTheme.Items.AddRange(@("Light", "Dark"))
    $comboTheme.SelectedItem = $Settings.Theme
    $tabAppearance.Controls.Add($comboTheme)

    # Window size
    $lblWindowSize = New-Object System.Windows.Forms.Label
    $lblWindowSize.Text = "Default Window Size:"
    $lblWindowSize.Location = New-Object System.Drawing.Point(20, 60)
    $lblWindowSize.Size = New-Object System.Drawing.Size(120, 20)
    $tabAppearance.Controls.Add($lblWindowSize)

    $txtWidth = New-Object System.Windows.Forms.TextBox
    $txtWidth.Location = New-Object System.Drawing.Point(150, 60)
    $txtWidth.Size = New-Object System.Drawing.Size(60, 20)
    $txtWidth.Text = $Settings.WindowSize.Width
    $tabAppearance.Controls.Add($txtWidth)

    $lblX = New-Object System.Windows.Forms.Label
    $lblX.Text = "x"
    $lblX.Location = New-Object System.Drawing.Point(215, 60)
    $lblX.Size = New-Object System.Drawing.Size(15, 20)
    $lblX.TextAlign = "MiddleCenter"
    $tabAppearance.Controls.Add($lblX)

    $txtHeight = New-Object System.Windows.Forms.TextBox
    $txtHeight.Location = New-Object System.Drawing.Point(235, 60)
    $txtHeight.Size = New-Object System.Drawing.Size(60, 20)
    $txtHeight.Text = $Settings.WindowSize.Height
    $tabAppearance.Controls.Add($txtHeight)

    # ============================================
    # DNA CENTER TAB
    # ============================================
    $tabDNA = New-Object System.Windows.Forms.TabPage
    $tabDNA.Text = "DNA Center"
    $tabControl.Controls.Add($tabDNA)

    # Default timeout
    $lblTimeout = New-Object System.Windows.Forms.Label
    $lblTimeout.Text = "Default Timeout (seconds):"
    $lblTimeout.Location = New-Object System.Drawing.Point(20, 20)
    $lblTimeout.Size = New-Object System.Drawing.Size(150, 20)
    $tabDNA.Controls.Add($lblTimeout)

    $txtTimeout = New-Object System.Windows.Forms.TextBox
    $txtTimeout.Location = New-Object System.Drawing.Point(180, 20)
    $txtTimeout.Size = New-Object System.Drawing.Size(60, 20)
    $txtTimeout.Text = $Settings.DefaultTimeout
    $tabDNA.Controls.Add($txtTimeout)

    # Certificate validation
    $chkCertValidation = New-Object System.Windows.Forms.CheckBox
    $chkCertValidation.Text = "Enable Certificate Validation"
    $chkCertValidation.Location = New-Object System.Drawing.Point(20, 60)
    $chkCertValidation.Size = New-Object System.Drawing.Size(250, 20)
    $chkCertValidation.Checked = $Settings.CertificateValidation
    $tabDNA.Controls.Add($chkCertValidation)

    # ============================================
    # DHCP TAB
    # ============================================
    $tabDHCP = New-Object System.Windows.Forms.TabPage
    $tabDHCP.Text = "DHCP"
    $tabControl.Controls.Add($tabDHCP)

    # Auto-discover
    $chkAutoDiscover = New-Object System.Windows.Forms.CheckBox
    $chkAutoDiscover.Text = "Auto-discover DHCP servers by default"
    $chkAutoDiscover.Location = New-Object System.Drawing.Point(20, 20)
    $chkAutoDiscover.Size = New-Object System.Drawing.Size(300, 20)
    $chkAutoDiscover.Checked = $Settings.DHCPAutoDiscover
    $tabDHCP.Controls.Add($chkAutoDiscover)

    # Collect DNS info
    $chkCollectDNS = New-Object System.Windows.Forms.CheckBox
    $chkCollectDNS.Text = "Collect DNS information by default"
    $chkCollectDNS.Location = New-Object System.Drawing.Point(20, 50)
    $chkCollectDNS.Size = New-Object System.Drawing.Size(300, 20)
    $chkCollectDNS.Checked = $Settings.DHCPCollectDNS
    $tabDHCP.Controls.Add($chkCollectDNS)

    # Parallel servers
    $lblParallel = New-Object System.Windows.Forms.Label
    $lblParallel.Text = "Parallel Server Collection:"
    $lblParallel.Location = New-Object System.Drawing.Point(20, 90)
    $lblParallel.Size = New-Object System.Drawing.Size(150, 20)
    $tabDHCP.Controls.Add($lblParallel)

    $txtParallel = New-Object System.Windows.Forms.TextBox
    $txtParallel.Location = New-Object System.Drawing.Point(180, 90)
    $txtParallel.Size = New-Object System.Drawing.Size(60, 20)
    $txtParallel.Text = $Settings.DHCPParallelServers
    $tabDHCP.Controls.Add($txtParallel)

    # ============================================
    # EXPORT TAB
    # ============================================
    $tabExport = New-Object System.Windows.Forms.TabPage
    $tabExport.Text = "Export"
    $tabControl.Controls.Add($tabExport)

    # Default format
    $lblFormat = New-Object System.Windows.Forms.Label
    $lblFormat.Text = "Default Export Format:"
    $lblFormat.Location = New-Object System.Drawing.Point(20, 20)
    $lblFormat.Size = New-Object System.Drawing.Size(130, 20)
    $tabExport.Controls.Add($lblFormat)

    $comboFormat = New-Object System.Windows.Forms.ComboBox
    $comboFormat.Location = New-Object System.Drawing.Point(160, 20)
    $comboFormat.Size = New-Object System.Drawing.Size(100, 20)
    $comboFormat.DropDownStyle = "DropDownList"
    $comboFormat.Items.AddRange(@("CSV", "JSON", "HTML", "Excel"))
    $comboFormat.SelectedItem = $Settings.DefaultExportFormat
    $tabExport.Controls.Add($comboFormat)

    # Default export path
    $lblExportPath = New-Object System.Windows.Forms.Label
    $lblExportPath.Text = "Default Export Directory:"
    $lblExportPath.Location = New-Object System.Drawing.Point(20, 60)
    $lblExportPath.Size = New-Object System.Drawing.Size(130, 20)
    $tabExport.Controls.Add($lblExportPath)

    $txtExportPath = New-Object System.Windows.Forms.TextBox
    $txtExportPath.Location = New-Object System.Drawing.Point(20, 85)
    $txtExportPath.Size = New-Object System.Drawing.Size(410, 20)
    $txtExportPath.Text = $Settings.DefaultExportPath
    $tabExport.Controls.Add($txtExportPath)

    $btnBrowse = New-Object System.Windows.Forms.Button
    $btnBrowse.Text = "Browse..."
    $btnBrowse.Location = New-Object System.Drawing.Point(440, 83)
    $btnBrowse.Size = New-Object System.Drawing.Size(80, 24)
    $btnBrowse.Add_Click({
        $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderDialog.SelectedPath = $txtExportPath.Text
        if ($folderDialog.ShowDialog() -eq "OK") {
            $txtExportPath.Text = $folderDialog.SelectedPath
        }
    })
    $tabExport.Controls.Add($btnBrowse)

    # Auto-export
    $chkAutoExport = New-Object System.Windows.Forms.CheckBox
    $chkAutoExport.Text = "Automatically export after data collection"
    $chkAutoExport.Location = New-Object System.Drawing.Point(20, 120)
    $chkAutoExport.Size = New-Object System.Drawing.Size(300, 20)
    $chkAutoExport.Checked = $Settings.AutoExportAfterCollection
    $tabExport.Controls.Add($chkAutoExport)

    # Include timestamp
    $chkTimestamp = New-Object System.Windows.Forms.CheckBox
    $chkTimestamp.Text = "Include timestamp in filenames"
    $chkTimestamp.Location = New-Object System.Drawing.Point(20, 150)
    $chkTimestamp.Size = New-Object System.Drawing.Size(300, 20)
    $chkTimestamp.Checked = $Settings.IncludeTimestampInFilename
    $tabExport.Controls.Add($chkTimestamp)

    # ============================================
    # ADVANCED TAB
    # ============================================
    $tabAdvanced = New-Object System.Windows.Forms.TabPage
    $tabAdvanced.Text = "Advanced"
    $tabControl.Controls.Add($tabAdvanced)

    # Enable logging
    $chkLogging = New-Object System.Windows.Forms.CheckBox
    $chkLogging.Text = "Enable detailed logging"
    $chkLogging.Location = New-Object System.Drawing.Point(20, 20)
    $chkLogging.Size = New-Object System.Drawing.Size(250, 20)
    $chkLogging.Checked = $Settings.EnableLogging
    $tabAdvanced.Controls.Add($chkLogging)

    # Show progress notifications
    $chkNotifications = New-Object System.Windows.Forms.CheckBox
    $chkNotifications.Text = "Show progress notifications"
    $chkNotifications.Location = New-Object System.Drawing.Point(20, 50)
    $chkNotifications.Size = New-Object System.Drawing.Size(250, 20)
    $chkNotifications.Checked = $Settings.ShowProgressNotifications
    $tabAdvanced.Controls.Add($chkNotifications)

    # Confirm destructive actions
    $chkConfirm = New-Object System.Windows.Forms.CheckBox
    $chkConfirm.Text = "Confirm before destructive actions"
    $chkConfirm.Location = New-Object System.Drawing.Point(20, 80)
    $chkConfirm.Size = New-Object System.Drawing.Size(250, 20)
    $chkConfirm.Checked = $Settings.ConfirmDestructiveActions
    $tabAdvanced.Controls.Add($chkConfirm)

    # Show dashboard on startup
    $chkDashboard = New-Object System.Windows.Forms.CheckBox
    $chkDashboard.Text = "Show dashboard tab on startup"
    $chkDashboard.Location = New-Object System.Drawing.Point(20, 110)
    $chkDashboard.Size = New-Object System.Drawing.Size(250, 20)
    $chkDashboard.Checked = $Settings.ShowDashboardOnStartup
    $tabAdvanced.Controls.Add($chkDashboard)

    # ============================================
    # BUTTONS
    # ============================================
    $btnSave = New-Object System.Windows.Forms.Button
    $btnSave.Text = "Save"
    $btnSave.Location = New-Object System.Drawing.Point(280, 420)
    $btnSave.Size = New-Object System.Drawing.Size(100, 30)
    $btnSave.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($btnSave)
    $form.AcceptButton = $btnSave

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Location = New-Object System.Drawing.Point(390, 420)
    $btnCancel.Size = New-Object System.Drawing.Size(100, 30)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($btnCancel)
    $form.CancelButton = $btnCancel

    $btnReset = New-Object System.Windows.Forms.Button
    $btnReset.Text = "Reset to Defaults"
    $btnReset.Location = New-Object System.Drawing.Point(20, 420)
    $btnReset.Size = New-Object System.Drawing.Size(120, 30)
    $btnReset.Add_Click({
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Are you sure you want to reset all settings to defaults?",
            "Confirm Reset",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            $form.Tag = "RESET"
            $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $form.Close()
        }
    })
    $form.Controls.Add($btnReset)

    # Apply theme if provided
    if ($Theme) {
        # Import and apply theme
        try {
            Import-Module "$PSScriptRoot\ThemeManager.ps1" -Force -ErrorAction Stop
            Apply-ThemeToControl -Control $form -Theme $Theme
        } catch {
            # Silently continue if theme application fails
        }
    }

    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        if ($form.Tag -eq "RESET") {
            return "RESET"
        }

        # Update settings
        $newSettings = $Settings.Clone()
        $newSettings.Theme = $comboTheme.SelectedItem
        $newSettings.WindowSize = @{
            Width = [int]$txtWidth.Text
            Height = [int]$txtHeight.Text
        }
        $newSettings.DefaultTimeout = [int]$txtTimeout.Text
        $newSettings.CertificateValidation = $chkCertValidation.Checked
        $newSettings.DHCPAutoDiscover = $chkAutoDiscover.Checked
        $newSettings.DHCPCollectDNS = $chkCollectDNS.Checked
        $newSettings.DHCPParallelServers = [int]$txtParallel.Text
        $newSettings.DefaultExportFormat = $comboFormat.SelectedItem
        $newSettings.DefaultExportPath = $txtExportPath.Text
        $newSettings.AutoExportAfterCollection = $chkAutoExport.Checked
        $newSettings.IncludeTimestampInFilename = $chkTimestamp.Checked
        $newSettings.EnableLogging = $chkLogging.Checked
        $newSettings.ShowProgressNotifications = $chkNotifications.Checked
        $newSettings.ConfirmDestructiveActions = $chkConfirm.Checked
        $newSettings.ShowDashboardOnStartup = $chkDashboard.Checked

        return $newSettings
    }

    return $null
}

# Export module members
Export-ModuleMember -Function 'Show-SettingsDialog'
