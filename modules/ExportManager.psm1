#Requires -Version 5.1
<#
.SYNOPSIS
    Export Manager for OctoNav GUI v2.3
.DESCRIPTION
    Handles data export in multiple formats (CSV, Excel, JSON, HTML)
#>

function Export-ToCSV {
    <#
    .SYNOPSIS
        Exports data to CSV format
    #>
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Data,

        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [switch]$IncludeTimestamp
    )

    try {
        $outputPath = $FilePath
        if ($IncludeTimestamp) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $directory = Split-Path $FilePath -Parent
            $filename = Split-Path $FilePath -LeafBase
            $extension = Split-Path $FilePath -Extension
            $outputPath = Join-Path $directory "${filename}_${timestamp}${extension}"
        }

        $Data | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
        return $outputPath
    } catch {
        throw "Failed to export CSV: $_"
    }
}

function Export-ToJSON {
    <#
    .SYNOPSIS
        Exports data to JSON format
    #>
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Data,

        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [switch]$IncludeTimestamp
    )

    try {
        $outputPath = $FilePath
        if ($IncludeTimestamp) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $directory = Split-Path $FilePath -Parent
            $filename = Split-Path $FilePath -LeafBase
            $extension = Split-Path $FilePath -Extension
            $outputPath = Join-Path $directory "${filename}_${timestamp}${extension}"
        }

        $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputPath -Encoding UTF8
        return $outputPath
    } catch {
        throw "Failed to export JSON: $_"
    }
}

function Export-ToHTML {
    <#
    .SYNOPSIS
        Exports data to HTML format with styling
    #>
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Data,

        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [string]$Title = "OctoNav Export",

        [switch]$IncludeTimestamp
    )

    try {
        $outputPath = $FilePath
        if ($IncludeTimestamp) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $directory = Split-Path $FilePath -Parent
            $filename = Split-Path $FilePath -LeafBase
            $extension = Split-Path $FilePath -Extension
            $outputPath = Join-Path $directory "${filename}_${timestamp}${extension}"
        }

        $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>$Title</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        h1 {
            color: #333;
            border-bottom: 3px solid #0078d4;
            padding-bottom: 10px;
        }
        .meta {
            color: #666;
            font-size: 0.9em;
            margin-bottom: 20px;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th {
            background-color: #0078d4;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: bold;
        }
        td {
            border: 1px solid #ddd;
            padding: 10px;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tr:hover {
            background-color: #e8f4f8;
        }
    </style>
</head>
<body>
    <h1>$Title</h1>
    <div class="meta">
        Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
        Records: $($Data.Count)
    </div>
"@

        $htmlFooter = @"
</body>
</html>
"@

        $htmlTable = $Data | ConvertTo-Html -Fragment
        $htmlContent = $htmlHeader + $htmlTable + $htmlFooter

        $htmlContent | Out-File -FilePath $outputPath -Encoding UTF8
        return $outputPath
    } catch {
        throw "Failed to export HTML: $_"
    }
}

function Export-ToExcel {
    <#
    .SYNOPSIS
        Exports data to Excel format (using COM object if available)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Data,

        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [string]$WorksheetName = "Sheet1",

        [switch]$IncludeTimestamp
    )

    try {
        $outputPath = $FilePath
        if ($IncludeTimestamp) {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $directory = Split-Path $FilePath -Parent
            $filename = Split-Path $FilePath -LeafBase
            $extension = Split-Path $FilePath -Extension
            $outputPath = Join-Path $directory "${filename}_${timestamp}${extension}"
        }

        # Check if ImportExcel module is available
        if (Get-Module -ListAvailable -Name ImportExcel) {
            Import-Module ImportExcel -ErrorAction Stop
            $Data | Export-Excel -Path $outputPath -WorksheetName $WorksheetName -AutoSize -TableName "Data" -BoldTopRow
            return $outputPath
        }

        # Fallback: try to use Excel COM object
        try {
            $excel = New-Object -ComObject Excel.Application
            $excel.Visible = $false
            $excel.DisplayAlerts = $false

            $workbook = $excel.Workbooks.Add()
            $worksheet = $workbook.Worksheets.Item(1)
            $worksheet.Name = $WorksheetName

            # Get column headers
            $properties = $Data[0].PSObject.Properties.Name
            for ($i = 0; $i -lt $properties.Count; $i++) {
                $worksheet.Cells.Item(1, $i + 1) = $properties[$i]
            }

            # Add data
            $row = 2
            foreach ($item in $Data) {
                for ($i = 0; $i -lt $properties.Count; $i++) {
                    $worksheet.Cells.Item($row, $i + 1) = $item.($properties[$i])
                }
                $row++
            }

            # Format headers
            $headerRange = $worksheet.Range($worksheet.Cells.Item(1, 1), $worksheet.Cells.Item(1, $properties.Count))
            $headerRange.Font.Bold = $true
            $headerRange.Interior.ColorIndex = 15

            # Auto-fit columns
            $worksheet.UsedRange.Columns.AutoFit() | Out-Null

            # Save and close
            $workbook.SaveAs($outputPath)
            $workbook.Close()
            $excel.Quit()

            # Clean up COM objects
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($worksheet) | Out-Null
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($workbook) | Out-Null
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()

            return $outputPath
        } catch {
            # If Excel COM fails, fall back to CSV with .xlsx extension warning
            throw "Excel export requires ImportExcel module or Microsoft Excel. Use CSV format instead."
        }
    } catch {
        throw "Failed to export Excel: $_"
    }
}

function Export-Data {
    <#
    .SYNOPSIS
        Exports data to the specified format
    #>
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Data,

        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        [ValidateSet("CSV", "JSON", "HTML", "Excel")]
        [string]$Format,

        [string]$Title = "OctoNav Export",

        [string]$WorksheetName = "Sheet1",

        [switch]$IncludeTimestamp
    )

    if (-not $Data -or $Data.Count -eq 0) {
        throw "No data to export"
    }

    switch ($Format) {
        "CSV" {
            return Export-ToCSV -Data $Data -FilePath $FilePath -IncludeTimestamp:$IncludeTimestamp
        }
        "JSON" {
            return Export-ToJSON -Data $Data -FilePath $FilePath -IncludeTimestamp:$IncludeTimestamp
        }
        "HTML" {
            return Export-ToHTML -Data $Data -FilePath $FilePath -Title $Title -IncludeTimestamp:$IncludeTimestamp
        }
        "Excel" {
            return Export-ToExcel -Data $Data -FilePath $FilePath -WorksheetName $WorksheetName -IncludeTimestamp:$IncludeTimestamp
        }
    }
}

function Show-ExportDialog {
    <#
    .SYNOPSIS
        Shows a dialog to select export format and options
    #>
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Data,

        [string]$DefaultFileName = "export",

        [string]$DefaultPath = "C:\",

        [hashtable]$Settings = $null
    )

    Add-Type -AssemblyName System.Windows.Forms

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Export Options"
    $form.Size = New-Object System.Drawing.Size(500, 300)
    $form.StartPosition = "CenterParent"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

    # Format selection
    $lblFormat = New-Object System.Windows.Forms.Label
    $lblFormat.Text = "Export Format:"
    $lblFormat.Location = New-Object System.Drawing.Point(20, 20)
    $lblFormat.Size = New-Object System.Drawing.Size(100, 20)
    $form.Controls.Add($lblFormat)

    $comboFormat = New-Object System.Windows.Forms.ComboBox
    $comboFormat.Location = New-Object System.Drawing.Point(120, 20)
    $comboFormat.Size = New-Object System.Drawing.Size(150, 20)
    $comboFormat.DropDownStyle = "DropDownList"
    $comboFormat.Items.AddRange(@("CSV", "JSON", "HTML", "Excel"))
    if ($Settings -and $Settings.DefaultExportFormat) {
        $comboFormat.SelectedItem = $Settings.DefaultExportFormat
    } else {
        $comboFormat.SelectedIndex = 0
    }
    $form.Controls.Add($comboFormat)

    # Include timestamp checkbox
    $chkTimestamp = New-Object System.Windows.Forms.CheckBox
    $chkTimestamp.Text = "Include timestamp in filename"
    $chkTimestamp.Location = New-Object System.Drawing.Point(20, 60)
    $chkTimestamp.Size = New-Object System.Drawing.Size(250, 20)
    if ($Settings) {
        $chkTimestamp.Checked = $Settings.IncludeTimestampInFilename
    } else {
        $chkTimestamp.Checked = $true
    }
    $form.Controls.Add($chkTimestamp)

    # File path
    $lblPath = New-Object System.Windows.Forms.Label
    $lblPath.Text = "Save to:"
    $lblPath.Location = New-Object System.Drawing.Point(20, 100)
    $lblPath.Size = New-Object System.Drawing.Size(100, 20)
    $form.Controls.Add($lblPath)

    $txtPath = New-Object System.Windows.Forms.TextBox
    $txtPath.Location = New-Object System.Drawing.Point(20, 120)
    $txtPath.Size = New-Object System.Drawing.Size(360, 20)
    if ($Settings -and $Settings.DefaultExportPath) {
        $txtPath.Text = Join-Path $Settings.DefaultExportPath "$DefaultFileName.csv"
    } else {
        $txtPath.Text = Join-Path $DefaultPath "$DefaultFileName.csv"
    }
    $form.Controls.Add($txtPath)

    $btnBrowse = New-Object System.Windows.Forms.Button
    $btnBrowse.Text = "Browse..."
    $btnBrowse.Location = New-Object System.Drawing.Point(390, 118)
    $btnBrowse.Size = New-Object System.Drawing.Size(80, 24)
    $btnBrowse.Add_Click({
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = "CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json|HTML Files (*.html)|*.html|Excel Files (*.xlsx)|*.xlsx|All Files (*.*)|*.*"
        if ($saveDialog.ShowDialog() -eq "OK") {
            $txtPath.Text = $saveDialog.FileName
        }
    })
    $form.Controls.Add($btnBrowse)

    # Buttons
    $btnExport = New-Object System.Windows.Forms.Button
    $btnExport.Text = "Export"
    $btnExport.Location = New-Object System.Drawing.Point(200, 220)
    $btnExport.Size = New-Object System.Drawing.Size(100, 30)
    $btnExport.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($btnExport)
    $form.AcceptButton = $btnExport

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Location = New-Object System.Drawing.Point(310, 220)
    $btnCancel.Size = New-Object System.Drawing.Size(100, 30)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($btnCancel)
    $form.CancelButton = $btnCancel

    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return @{
            Format = $comboFormat.SelectedItem
            FilePath = $txtPath.Text
            IncludeTimestamp = $chkTimestamp.Checked
        }
    }

    return $null
}

# Export module members
Export-ModuleMember -Function @(
    'Export-ToCSV',
    'Export-ToJSON',
    'Export-ToHTML',
    'Export-ToExcel',
    'Export-Data',
    'Show-ExportDialog'
)
