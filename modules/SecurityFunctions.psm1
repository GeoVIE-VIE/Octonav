#Requires -Version 5.1
<#
.SYNOPSIS
    Security Functions Module for OctoNav
.DESCRIPTION
    Comprehensive security features including password management, DPAPI encryption,
    audit logging, session management, and access control
#>

# ============================================
# LOAD REQUIRED ASSEMBLIES
# ============================================

# Load System.Security for DPAPI (ProtectedData class)
try {
    Add-Type -AssemblyName System.Security -ErrorAction Stop
}
catch {
    throw "Failed to load System.Security assembly required for DPAPI encryption: $($_.Exception.Message)"
}

# ============================================
# CONFIGURATION
# ============================================

$script:SecurityConfigFile = Join-Path $PSScriptRoot "..\config\security.dat"
$script:AuditLogFile = Join-Path $PSScriptRoot "..\logs\security_audit.log"
$script:MaxFailedAttempts = 3
$script:LockoutDurationMinutes = 15
$script:SessionTimeoutMinutes = 30
$script:PasswordMinLength = 12
$script:LastActivityTime = Get-Date

# Ensure directories exist
$configDir = Split-Path $script:SecurityConfigFile -Parent
$logDir = Split-Path $script:AuditLogFile -Parent
if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

# ============================================
# AUDIT LOGGING
# ============================================

function Write-SecurityAudit {
    <#
    .SYNOPSIS
        Writes security events to audit log
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Success', 'Failure', 'Warning', 'Info', 'Critical')]
        [string]$Level,

        [Parameter(Mandatory=$true)]
        [string]$Event,

        [string]$Details = "",

        [string]$User = $env:USERNAME
    )

    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Level] [$User] $Event"
        if ($Details) {
            $logEntry += " | Details: $Details"
        }

        # Append to log file
        Add-Content -Path $script:AuditLogFile -Value $logEntry -ErrorAction SilentlyContinue

        # Also write to event log if critical
        if ($Level -eq 'Critical') {
            Write-EventLog -LogName Application -Source "OctoNav" -EventId 1001 -EntryType Error -Message $logEntry -ErrorAction SilentlyContinue
        }
    }
    catch {
        # Fail silently - don't break app if logging fails
        Write-Warning "Audit logging failed: $($_.Exception.Message)"
    }
}

# ============================================
# PASSWORD VALIDATION
# ============================================

function Test-PasswordComplexity {
    <#
    .SYNOPSIS
        Validates password meets complexity requirements
    .DESCRIPTION
        Requirements:
        - Minimum 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
        - At least one special character
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Password
    )

    $requirements = @{
        MinLength = $Password.Length -ge $script:PasswordMinLength
        HasUppercase = $Password -cmatch '[A-Z]'
        HasLowercase = $Password -cmatch '[a-z]'
        HasNumber = $Password -match '[0-9]'
        HasSpecial = $Password -match '[^a-zA-Z0-9]'
    }

    $failed = @()
    if (-not $requirements.MinLength) { $failed += "At least $script:PasswordMinLength characters" }
    if (-not $requirements.HasUppercase) { $failed += "At least one uppercase letter" }
    if (-not $requirements.HasLowercase) { $failed += "At least one lowercase letter" }
    if (-not $requirements.HasNumber) { $failed += "At least one number" }
    if (-not $requirements.HasSpecial) { $failed += "At least one special character (!@#$%^&*)" }

    return [PSCustomObject]@{
        IsValid = $failed.Count -eq 0
        FailedRequirements = $failed
    }
}

# ============================================
# DPAPI ENCRYPTION (Windows Data Protection)
# ============================================

function Protect-WithDPAPI {
    <#
    .SYNOPSIS
        Encrypts data using Windows DPAPI (current user scope)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$PlainText
    )

    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
        $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
            $bytes,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [Convert]::ToBase64String($encrypted)
    }
    catch {
        throw "DPAPI encryption failed: $($_.Exception.Message)"
    }
}

function Unprotect-WithDPAPI {
    <#
    .SYNOPSIS
        Decrypts data using Windows DPAPI
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$EncryptedText
    )

    try {
        $encrypted = [Convert]::FromBase64String($EncryptedText)
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encrypted,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    }
    catch {
        throw "DPAPI decryption failed: $($_.Exception.Message)"
    }
}

# ============================================
# LOCKOUT MANAGEMENT
# ============================================

function Get-SecurityConfig {
    <#
    .SYNOPSIS
        Loads security configuration from encrypted file
    #>
    if (Test-Path $script:SecurityConfigFile) {
        try {
            $encrypted = Get-Content $script:SecurityConfigFile -Raw
            $json = Unprotect-WithDPAPI -EncryptedText $encrypted
            return $json | ConvertFrom-Json
        }
        catch {
            Write-SecurityAudit -Level Warning -Event "Failed to load security config" -Details $_.Exception.Message
            return $null
        }
    }
    return $null
}

function Save-SecurityConfig {
    <#
    .SYNOPSIS
        Saves security configuration to encrypted file
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Config
    )

    try {
        $json = $Config | ConvertTo-Json -Depth 3
        $encrypted = Protect-WithDPAPI -PlainText $json
        $encrypted | Set-Content $script:SecurityConfigFile -Force
        Write-SecurityAudit -Level Info -Event "Security config saved"
    }
    catch {
        Write-SecurityAudit -Level Warning -Event "Failed to save security config" -Details $_.Exception.Message
        throw
    }
}

function Test-IsAccountLocked {
    <#
    .SYNOPSIS
        Checks if account is currently locked due to failed attempts
    #>
    $config = Get-SecurityConfig
    if (-not $config -or -not $config.LockoutUntil) {
        return $false
    }

    $lockoutTime = [DateTime]::Parse($config.LockoutUntil)
    $isLocked = (Get-Date) -lt $lockoutTime

    if ($isLocked) {
        $remainingMinutes = [math]::Ceiling(($lockoutTime - (Get-Date)).TotalMinutes)
        Write-SecurityAudit -Level Warning -Event "Access denied - Account locked" -Details "Remaining: $remainingMinutes minutes"
    }

    return $isLocked
}

function Register-FailedLoginAttempt {
    <#
    .SYNOPSIS
        Records a failed login attempt and triggers lockout if threshold exceeded
    #>
    $config = Get-SecurityConfig
    if (-not $config) {
        $config = @{
            FailedAttempts = 0
            LastFailedAttempt = $null
            LockoutUntil = $null
        }
    } else {
        # Convert to hashtable
        $config = @{
            FailedAttempts = if ($config.FailedAttempts) { $config.FailedAttempts } else { 0 }
            LastFailedAttempt = $config.LastFailedAttempt
            LockoutUntil = $config.LockoutUntil
            PasswordHash = $config.PasswordHash
        }
    }

    $config.FailedAttempts++
    $config.LastFailedAttempt = (Get-Date).ToString("o")

    Write-SecurityAudit -Level Failure -Event "Login failed" -Details "Attempt $($config.FailedAttempts) of $script:MaxFailedAttempts"

    if ($config.FailedAttempts -ge $script:MaxFailedAttempts) {
        $lockoutUntil = (Get-Date).AddMinutes($script:LockoutDurationMinutes)
        $config.LockoutUntil = $lockoutUntil.ToString("o")
        Write-SecurityAudit -Level Critical -Event "Account locked" -Details "Locked until $lockoutUntil due to $($config.FailedAttempts) failed attempts"
    }

    Save-SecurityConfig -Config $config
}

function Clear-FailedLoginAttempts {
    <#
    .SYNOPSIS
        Clears failed login attempts after successful login
    #>
    $config = Get-SecurityConfig
    if ($config) {
        $config = @{
            FailedAttempts = 0
            LastFailedAttempt = $null
            LockoutUntil = $null
            PasswordHash = $config.PasswordHash
        }
        Save-SecurityConfig -Config $config
    }
}

# ============================================
# PASSWORD MANAGEMENT
# ============================================

function Get-PasswordHash {
    <#
    .SYNOPSIS
        Creates SHA256 hash of password for verification
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Password
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
    $hash = $sha256.ComputeHash($bytes)
    return [Convert]::ToBase64String($hash)
}

function Test-StartupPasswordExists {
    <#
    .SYNOPSIS
        Checks if startup password is configured
    #>
    $config = Get-SecurityConfig
    return ($null -ne $config -and $null -ne $config.PasswordHash)
}

function Set-StartupPassword {
    <#
    .SYNOPSIS
        Sets or changes the startup password
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Security.SecureString]$Password
    )

    # Convert SecureString to plain text
    $passwordPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($passwordPtr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPtr)

    # Validate complexity
    $validation = Test-PasswordComplexity -Password $passwordPlain
    if (-not $validation.IsValid) {
        throw "Password does not meet complexity requirements:`n- " + ($validation.FailedRequirements -join "`n- ")
    }

    # Hash the password
    $hash = Get-PasswordHash -Password $passwordPlain

    # Load existing config or create new
    $config = Get-SecurityConfig
    if (-not $config) {
        $config = @{
            FailedAttempts = 0
            LastFailedAttempt = $null
            LockoutUntil = $null
        }
    } else {
        $config = @{
            FailedAttempts = $config.FailedAttempts
            LastFailedAttempt = $config.LastFailedAttempt
            LockoutUntil = $config.LockoutUntil
        }
    }

    $config.PasswordHash = $hash
    $config.PasswordSetDate = (Get-Date).ToString("o")

    Save-SecurityConfig -Config $config
    Write-SecurityAudit -Level Success -Event "Startup password set/changed"
}

function Test-StartupPassword {
    <#
    .SYNOPSIS
        Validates startup password
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Security.SecureString]$Password
    )

    # Check if locked
    if (Test-IsAccountLocked) {
        return $false
    }

    $config = Get-SecurityConfig
    if (-not $config -or -not $config.PasswordHash) {
        return $false
    }

    # Convert SecureString to plain text
    $passwordPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($passwordPtr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPtr)

    # Hash and compare
    $providedHash = Get-PasswordHash -Password $passwordPlain

    if ($providedHash -eq $config.PasswordHash) {
        Clear-FailedLoginAttempts
        Write-SecurityAudit -Level Success -Event "Login successful"
        return $true
    }
    else {
        Register-FailedLoginAttempt
        return $false
    }
}

# ============================================
# SESSION MANAGEMENT
# ============================================

function Update-SessionActivity {
    <#
    .SYNOPSIS
        Updates last activity timestamp
    #>
    $script:LastActivityTime = Get-Date
}

function Test-SessionExpired {
    <#
    .SYNOPSIS
        Checks if session has expired due to inactivity
    #>
    $idleMinutes = ((Get-Date) - $script:LastActivityTime).TotalMinutes

    if ($idleMinutes -ge $script:SessionTimeoutMinutes) {
        Write-SecurityAudit -Level Warning -Event "Session expired" -Details "Idle for $([math]::Round($idleMinutes, 1)) minutes"
        return $true
    }

    return $false
}

function Start-SessionMonitor {
    <#
    .SYNOPSIS
        Starts background session timeout monitoring
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Windows.Forms.Form]$Form
    )

    $script:SessionTimer = New-Object System.Windows.Forms.Timer
    $script:SessionTimer.Interval = 60000  # Check every minute

    $script:SessionTimer.Add_Tick({
        if (Test-SessionExpired) {
            Write-SecurityAudit -Level Warning -Event "Auto-lock triggered" -Details "Session timeout after $script:SessionTimeoutMinutes minutes"

            [System.Windows.Forms.MessageBox]::Show(
                "Session expired due to inactivity.`n`nOctoNav will now close for security.",
                "Session Timeout",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )

            $Form.Close()
        }
    })

    $script:SessionTimer.Start()
    Update-SessionActivity
}

# ============================================
# STARTUP PASSWORD DIALOG
# ============================================

function Show-StartupPasswordDialog {
    <#
    .SYNOPSIS
        Shows startup password authentication dialog
    #>
    param(
        [switch]$IsFirstRun
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = if ($IsFirstRun) { "Set OctoNav Startup Password" } else { "OctoNav Authentication" }
    $form.Size = New-Object System.Drawing.Size(500, 400)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true

    $y = 20

    # Title
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = if ($IsFirstRun) { "Welcome to OctoNav" } else { "Please authenticate to continue" }
    $lblTitle.Location = New-Object System.Drawing.Point(20, $y)
    $lblTitle.Size = New-Object System.Drawing.Size(450, 25)
    $lblTitle.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
    $lblTitle.ForeColor = [System.Drawing.Color]::DarkBlue
    $form.Controls.Add($lblTitle)

    $y += 35

    if ($IsFirstRun) {
        # First run instructions
        $lblInstructions = New-Object System.Windows.Forms.Label
        $lblInstructions.Text = @"
This is your first time running OctoNav with security enabled.
Please create a strong startup password.

Password Requirements:
- Minimum 12 characters
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one number (0-9)
- At least one special character (!@#$%^&*)

WARNING: If you forget this password, you will be locked out!
"@
        $lblInstructions.Location = New-Object System.Drawing.Point(20, $y)
        $lblInstructions.Size = New-Object System.Drawing.Size(450, 140)
        $lblInstructions.Font = New-Object System.Drawing.Font("Arial", 9)
        $form.Controls.Add($lblInstructions)

        $y += 150

        # Password
        $lblPassword = New-Object System.Windows.Forms.Label
        $lblPassword.Text = "Enter Password:"
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

        # Confirm Password
        $lblConfirm = New-Object System.Windows.Forms.Label
        $lblConfirm.Text = "Confirm Password:"
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

        # Set Password Button
        $btnSetPassword = New-Object System.Windows.Forms.Button
        $btnSetPassword.Text = "Set Password"
        $btnSetPassword.Location = New-Object System.Drawing.Point(180, $y)
        $btnSetPassword.Size = New-Object System.Drawing.Size(140, 35)
        $btnSetPassword.BackColor = [System.Drawing.Color]::LightGreen
        $form.Controls.Add($btnSetPassword)
        $form.AcceptButton = $btnSetPassword

        $btnSetPassword.Add_Click({
            if ([string]::IsNullOrWhiteSpace($txtPassword.Text)) {
                [System.Windows.Forms.MessageBox]::Show("Please enter a password", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }

            if ($txtPassword.Text -ne $txtConfirm.Text) {
                [System.Windows.Forms.MessageBox]::Show("Passwords do not match!", "Validation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                $txtPassword.Clear()
                $txtConfirm.Clear()
                $txtPassword.Focus()
                return
            }

            try {
                $securePassword = ConvertTo-SecureString -String $txtPassword.Text -AsPlainText -Force
                Set-StartupPassword -Password $securePassword

                [System.Windows.Forms.MessageBox]::Show("Password set successfully!`n`nOctoNav will now start.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)

                $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $form.Close()
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to set password:`n`n$($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                $txtPassword.Clear()
                $txtConfirm.Clear()
                $txtPassword.Focus()
            }
        })
    }
    else {
        # Check if locked
        if (Test-IsAccountLocked) {
            $config = Get-SecurityConfig
            $lockoutTime = [DateTime]::Parse($config.LockoutUntil)
            $remainingMinutes = [math]::Ceiling(($lockoutTime - (Get-Date)).TotalMinutes)

            $lblLocked = New-Object System.Windows.Forms.Label
            $lblLocked.Text = @"
ACCOUNT LOCKED

Too many failed login attempts.

This account is locked for security.
Remaining lockout time: $remainingMinutes minutes

Please try again later.
"@
            $lblLocked.Location = New-Object System.Drawing.Point(20, $y)
            $lblLocked.Size = New-Object System.Drawing.Size(450, 150)
            $lblLocked.Font = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Bold)
            $lblLocked.ForeColor = [System.Drawing.Color]::Red
            $form.Controls.Add($lblLocked)

            $y += 160

            $btnClose = New-Object System.Windows.Forms.Button
            $btnClose.Text = "Close"
            $btnClose.Location = New-Object System.Drawing.Point(200, $y)
            $btnClose.Size = New-Object System.Drawing.Size(100, 35)
            $form.Controls.Add($btnClose)

            $btnClose.Add_Click({
                $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
                $form.Close()
            })
        }
        else {
            # Login form
            $lblPassword = New-Object System.Windows.Forms.Label
            $lblPassword.Text = "Enter your password to access OctoNav:"
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

            # Status label for failed attempts
            $lblStatus = New-Object System.Windows.Forms.Label
            $lblStatus.Text = ""
            $lblStatus.Location = New-Object System.Drawing.Point(20, $y)
            $lblStatus.Size = New-Object System.Drawing.Size(450, 20)
            $lblStatus.ForeColor = [System.Drawing.Color]::Red
            $form.Controls.Add($lblStatus)

            $y += 30

            $btnLogin = New-Object System.Windows.Forms.Button
            $btnLogin.Text = "Login"
            $btnLogin.Location = New-Object System.Drawing.Point(150, $y)
            $btnLogin.Size = New-Object System.Drawing.Size(100, 35)
            $btnLogin.BackColor = [System.Drawing.Color]::LightGreen
            $form.Controls.Add($btnLogin)
            $form.AcceptButton = $btnLogin

            $btnExit = New-Object System.Windows.Forms.Button
            $btnExit.Text = "Exit"
            $btnExit.Location = New-Object System.Drawing.Point(260, $y)
            $btnExit.Size = New-Object System.Drawing.Size(100, 35)
            $form.Controls.Add($btnExit)
            $form.CancelButton = $btnExit

            $btnExit.Add_Click({
                $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
                $form.Close()
            })

            $btnLogin.Add_Click({
                if ([string]::IsNullOrWhiteSpace($txtPassword.Text)) {
                    $lblStatus.Text = "Please enter your password"
                    return
                }

                $securePassword = ConvertTo-SecureString -String $txtPassword.Text -AsPlainText -Force

                if (Test-StartupPassword -Password $securePassword) {
                    $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
                    $form.Close()
                }
                else {
                    $config = Get-SecurityConfig
                    $remaining = $script:MaxFailedAttempts - $config.FailedAttempts

                    if ($remaining -le 0) {
                        [System.Windows.Forms.MessageBox]::Show(
                            "Too many failed attempts!`n`nAccount locked for $script:LockoutDurationMinutes minutes.",
                            "Account Locked",
                            [System.Windows.Forms.MessageBoxButtons]::OK,
                            [System.Windows.Forms.MessageBoxIcon]::Error
                        )
                        $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
                        $form.Close()
                    }
                    else {
                        $lblStatus.Text = "Incorrect password! Attempts remaining: $remaining"
                        $txtPassword.Clear()
                        $txtPassword.Focus()
                    }
                }
            })
        }
    }

    $result = $form.ShowDialog()
    $form.Dispose()

    return ($result -eq [System.Windows.Forms.DialogResult]::OK)
}

# ============================================
# EXPORTS
# ============================================

Export-ModuleMember -Function @(
    'Write-SecurityAudit',
    'Test-PasswordComplexity',
    'Protect-WithDPAPI',
    'Unprotect-WithDPAPI',
    'Test-StartupPasswordExists',
    'Set-StartupPassword',
    'Test-StartupPassword',
    'Show-StartupPasswordDialog',
    'Update-SessionActivity',
    'Test-SessionExpired',
    'Start-SessionMonitor',
    'Test-IsAccountLocked'
)
