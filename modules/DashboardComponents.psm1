#Requires -Version 5.1
<#
.SYNOPSIS
    Dashboard Components for OctoNav GUI v2.3
.DESCRIPTION
    Dashboard tab components and summary information display
#>

# ============================================
# DHCP CACHE ENCRYPTION FUNCTIONS
# ============================================

function Protect-DHCPCache {
    <#
    .SYNOPSIS
        Encrypts DHCP cache data with AES-256 encryption and HMAC integrity check
    .PARAMETER PlainText
        The plain text data to encrypt (JSON string)
    .PARAMETER Password
        SecureString password for encryption
    .DESCRIPTION
        Security features:
        - AES-256-CBC encryption
        - PBKDF2 key derivation (10,000 iterations)
        - HMAC-SHA256 for integrity verification
        - Random salt per encryption
    #>
    param(
        [string]$PlainText,
        [System.Security.SecureString]$Password
    )

    try {
        # Convert SecureString password to key using PBKDF2
        $passwordPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($passwordPtr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPtr)

        # Generate salt (16 bytes)
        $salt = New-Object byte[] 16
        $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
        $rng.GetBytes($salt)

        # Derive key from password using PBKDF2 (10000 iterations)
        $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($passwordPlain, $salt, 10000)
        $encryptionKey = $pbkdf2.GetBytes(32)  # 256-bit AES key
        $iv = $pbkdf2.GetBytes(16)   # 128-bit IV
        $hmacKey = $pbkdf2.GetBytes(32)  # 256-bit HMAC key

        # Create AES encryptor
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $encryptionKey
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        # Encrypt the data
        $encryptor = $aes.CreateEncryptor()
        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
        $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

        # Calculate HMAC over salt + encrypted data
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = $hmacKey
        $dataToSign = New-Object byte[] ($salt.Length + $encryptedBytes.Length)
        [Array]::Copy($salt, 0, $dataToSign, 0, $salt.Length)
        [Array]::Copy($encryptedBytes, 0, $dataToSign, $salt.Length, $encryptedBytes.Length)
        $hmacHash = $hmac.ComputeHash($dataToSign)

        # Combine: salt + hmac + encrypted data
        $result = New-Object byte[] ($salt.Length + $hmacHash.Length + $encryptedBytes.Length)
        [Array]::Copy($salt, 0, $result, 0, $salt.Length)
        [Array]::Copy($hmacHash, 0, $result, $salt.Length, $hmacHash.Length)
        [Array]::Copy($encryptedBytes, 0, $result, $salt.Length + $hmacHash.Length, $encryptedBytes.Length)

        # Clean up
        $aes.Dispose()
        $encryptor.Dispose()
        $hmac.Dispose()

        # Return as Base64
        return [Convert]::ToBase64String($result)
    }
    catch {
        throw "Encryption failed: $($_.Exception.Message)"
    }
}

function Unprotect-DHCPCache {
    <#
    .SYNOPSIS
        Decrypts DHCP cache data with HMAC integrity verification
    .PARAMETER EncryptedText
        The Base64-encoded encrypted data
    .PARAMETER Password
        SecureString password for decryption
    .DESCRIPTION
        Verifies HMAC before decryption to detect tampering.
        Throws error if HMAC verification fails or password is wrong.
    #>
    param(
        [string]$EncryptedText,
        [System.Security.SecureString]$Password
    )

    try {
        # Convert SecureString password to plain text
        $passwordPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($passwordPtr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPtr)

        # Decode from Base64
        $encryptedData = [Convert]::FromBase64String($EncryptedText)

        # Check if this has HMAC (new format) or old format
        # Old format: salt(16) + encrypted
        # New format: salt(16) + hmac(32) + encrypted
        $hasHMAC = $encryptedData.Length -gt 48  # Minimum for new format

        if ($hasHMAC) {
            # Extract salt (first 16 bytes)
            $salt = New-Object byte[] 16
            [Array]::Copy($encryptedData, 0, $salt, 0, 16)

            # Extract HMAC (next 32 bytes)
            $storedHmac = New-Object byte[] 32
            [Array]::Copy($encryptedData, 16, $storedHmac, 0, 32)

            # Extract encrypted content (remaining bytes)
            $encryptedBytes = New-Object byte[] ($encryptedData.Length - 48)
            [Array]::Copy($encryptedData, 48, $encryptedBytes, 0, $encryptedBytes.Length)

            # Derive keys from password using PBKDF2 (must match encryption)
            $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($passwordPlain, $salt, 10000)
            $encryptionKey = $pbkdf2.GetBytes(32)  # 256-bit AES key
            $iv = $pbkdf2.GetBytes(16)   # 128-bit IV
            $hmacKey = $pbkdf2.GetBytes(32)  # 256-bit HMAC key

            # Verify HMAC to detect tampering
            $hmac = New-Object System.Security.Cryptography.HMACSHA256
            $hmac.Key = $hmacKey
            $dataToVerify = New-Object byte[] ($salt.Length + $encryptedBytes.Length)
            [Array]::Copy($salt, 0, $dataToVerify, 0, $salt.Length)
            [Array]::Copy($encryptedBytes, 0, $dataToVerify, $salt.Length, $encryptedBytes.Length)
            $computedHmac = $hmac.ComputeHash($dataToVerify)

            # Constant-time comparison to prevent timing attacks
            $hmacValid = $true
            for ($i = 0; $i -lt 32; $i++) {
                if ($storedHmac[$i] -ne $computedHmac[$i]) {
                    $hmacValid = $false
                }
            }

            if (-not $hmacValid) {
                $hmac.Dispose()
                throw "INTEGRITY CHECK FAILED - Data has been tampered with or password is incorrect!"
            }

            $hmac.Dispose()

            # Create AES decryptor
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = $encryptionKey
            $aes.IV = $iv
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

            # Decrypt the data
            $decryptor = $aes.CreateDecryptor()
            $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
            $plainText = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)

            # Clean up
            $aes.Dispose()
            $decryptor.Dispose()

            return $plainText
        }
        else {
            # Old format without HMAC - still support for backward compatibility
            # Extract salt (first 16 bytes)
            $salt = New-Object byte[] 16
            [Array]::Copy($encryptedData, 0, $salt, 0, 16)

            # Extract encrypted content (remaining bytes)
            $encryptedBytes = New-Object byte[] ($encryptedData.Length - 16)
            [Array]::Copy($encryptedData, 16, $encryptedBytes, 0, $encryptedBytes.Length)

            # Derive key from password using PBKDF2
            $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($passwordPlain, $salt, 10000)
            $key = $pbkdf2.GetBytes(32)  # 256-bit key
            $iv = $pbkdf2.GetBytes(16)   # 128-bit IV

            # Create AES decryptor
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = $key
            $aes.IV = $iv
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

            # Decrypt the data
            $decryptor = $aes.CreateDecryptor()
            $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
            $plainText = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)

            # Clean up
            $aes.Dispose()
            $decryptor.Dispose()

            Write-Warning "Old cache format detected (no HMAC). Please refresh cache to upgrade security."

            return $plainText
        }
    }
    catch {
        throw "Decryption failed - Invalid password or corrupted data: $($_.Exception.Message)"
    }
}

function Get-DHCPCachePassword {
    <#
    .SYNOPSIS
        Prompts user for DHCP cache password
    .PARAMETER Action
        Either "Save" or "Load" to customize the prompt message
    #>
    param(
        [ValidateSet("Save", "Load")]
        [string]$Action = "Load"
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "DHCP Cache Password"
    $form.Size = New-Object System.Drawing.Size(400, 200)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Enter password to $Action DHCP cache:"
    $label.Location = New-Object System.Drawing.Point(20, 20)
    $label.Size = New-Object System.Drawing.Size(350, 20)
    $form.Controls.Add($label)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(20, 50)
    $textBox.Size = New-Object System.Drawing.Size(350, 25)
    $textBox.UseSystemPasswordChar = $true
    $form.Controls.Add($textBox)

    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Text = "OK"
    $btnOK.Location = New-Object System.Drawing.Point(150, 90)
    $btnOK.Size = New-Object System.Drawing.Size(80, 30)
    $btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($btnOK)
    $form.AcceptButton = $btnOK

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Location = New-Object System.Drawing.Point(240, 90)
    $btnCancel.Size = New-Object System.Drawing.Size(80, 30)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($btnCancel)
    $form.CancelButton = $btnCancel

    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK -and -not [string]::IsNullOrWhiteSpace($textBox.Text)) {
        $securePassword = ConvertTo-SecureString -String $textBox.Text -AsPlainText -Force
        $textBox.Clear()
        $form.Dispose()
        return $securePassword
    }

    $form.Dispose()
    return $null
}

# ============================================
# DASHBOARD COMPONENTS
# ============================================

function New-DashboardPanel {
    <#
    .SYNOPSIS
        Creates a dashboard information panel
    #>
    param(
        [string]$Title,
        [string]$Value,
        [string]$Icon = "",
        [int]$X,
        [int]$Y,
        [hashtable]$Theme = $null
    )

    $panel = New-Object System.Windows.Forms.GroupBox
    $panel.Text = $Title
    $panel.Location = New-Object System.Drawing.Point($X, $Y)
    $panel.Size = New-Object System.Drawing.Size(220, 100)

    $lblValue = New-Object System.Windows.Forms.Label
    $lblValue.Text = $Value
    $lblValue.Location = New-Object System.Drawing.Point(15, 30)
    $lblValue.Size = New-Object System.Drawing.Size(190, 50)
    $lblValue.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $lblValue.TextAlign = "MiddleCenter"
    $panel.Controls.Add($lblValue)

    return @{
        Panel = $panel
        ValueLabel = $lblValue
    }
}

function Update-DashboardPanel {
    <#
    .SYNOPSIS
        Updates dashboard panel value
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Panel,

        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    try {
        $Panel.ValueLabel.Invoke([Action]{
            $Panel.ValueLabel.Text = $Value
        })
    } catch {
        $Panel.ValueLabel.Text = $Value
    }
}

function Get-CachedDHCPServers {
    <#
    .SYNOPSIS
        Gets DHCP servers from cache file
    .DESCRIPTION
        Reads cached DHCP server list from JSON file. Returns empty array if cache doesn't exist.
    #>
    $cacheFile = Join-Path $PSScriptRoot "..\dhcp_servers_cache.json"

    if (Test-Path $cacheFile) {
        try {
            $cache = Get-Content $cacheFile -Raw | ConvertFrom-Json
            return $cache.Servers
        } catch {
            # Cache file corrupted, return empty
        }
    }

    return @()
}

function Update-DHCPServerCache {
    <#
    .SYNOPSIS
        Discovers DHCP servers and updates cache file
    .DESCRIPTION
        Queries Active Directory for DHCP servers and saves to cache.
        Returns the discovered servers.
    #>
    $cacheFile = Join-Path $PSScriptRoot "..\dhcp_servers_cache.json"

    try {
        # Import DHCP Server module (required for Get-DhcpServerInDC)
        Import-Module DhcpServer -ErrorAction Stop

        # Discover DHCP servers from AD
        $dhcpServers = Get-DhcpServerInDC -ErrorAction Stop

        if ($dhcpServers) {
            $serverList = @($dhcpServers | ForEach-Object {
                [PSCustomObject]@{
                    DnsName = $_.DnsName
                    IPAddress = $_.IPAddress
                }
            })

            # Create cache object
            $cache = @{
                LastUpdated = (Get-Date).ToString("o")
                ServerCount = $serverList.Count
                Servers = $serverList
            }

            # Save to JSON file
            $cache | ConvertTo-Json -Depth 3 | Set-Content $cacheFile -Force

            return $serverList
        }
    } catch {
        Write-Warning "Failed to discover DHCP servers: $($_.Exception.Message)"
    }

    return @()
}

function Get-CachedDHCPScopes {
    <#
    .SYNOPSIS
        Gets DHCP scopes from encrypted cache file with auto-migration
    .DESCRIPTION
        Reads cached DHCP scope list from encrypted file. Automatically detects
        and offers to encrypt old unencrypted .json files. Prompts for password.
    #>
    $cacheFileDat = Join-Path $PSScriptRoot "..\dhcp_scopes_cache.dat"
    $cacheFileJson = Join-Path $PSScriptRoot "..\dhcp_scopes_cache.json"

    # Check for old unencrypted .json file first
    if ((Test-Path $cacheFileJson) -and -not (Test-Path $cacheFileDat)) {
        $result = [System.Windows.Forms.MessageBox]::Show(
            "SECURITY WARNING: Unencrypted DHCP cache file detected!`n`n" +
            "File: dhcp_scopes_cache.json`n`n" +
            "This file contains sensitive network information and is NOT encrypted.`n`n" +
            "Would you like to encrypt it now? (Recommended)`n`n" +
            "The old unencrypted file will be deleted after successful encryption.",
            "Encrypt Unencrypted Cache?",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )

        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            try {
                # Read old unencrypted cache
                $jsonContent = Get-Content $cacheFileJson -Raw
                $cache = $jsonContent | ConvertFrom-Json

                # Prompt for password to encrypt
                $password = Get-DHCPCachePassword -Action "Save"
                if (-not $password) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Encryption cancelled. Old unencrypted file remains.`n`nPlease encrypt it as soon as possible for security.",
                        "Encryption Cancelled",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Warning
                    )
                    return $cache.Scopes
                }

                # Encrypt the cache
                $encryptedData = Protect-DHCPCache -PlainText $jsonContent -Password $password
                $encryptedData | Set-Content $cacheFileDat -Force

                # Delete old unencrypted file
                Remove-Item $cacheFileJson -Force

                [System.Windows.Forms.MessageBox]::Show(
                    "Cache encrypted successfully!`n`n" +
                    "Old unencrypted file deleted.`n" +
                    "New encrypted file: dhcp_scopes_cache.dat`n`n" +
                    "You will need this password to load the cache in the future.",
                    "Encryption Complete",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )

                return $cache.Scopes
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show(
                    "Failed to encrypt cache file:`n`n$($_.Exception.Message)`n`n" +
                    "Old unencrypted file remains.",
                    "Encryption Failed",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )

                # Still try to return the scopes
                try {
                    $jsonContent = Get-Content $cacheFileJson -Raw
                    $cache = $jsonContent | ConvertFrom-Json
                    return $cache.Scopes
                }
                catch {
                    return @()
                }
            }
        }
        else {
            # User declined encryption, load from unencrypted file
            try {
                $jsonContent = Get-Content $cacheFileJson -Raw
                $cache = $jsonContent | ConvertFrom-Json
                return $cache.Scopes
            }
            catch {
                return @()
            }
        }
    }

    # Load from encrypted .dat file
    if (Test-Path $cacheFileDat) {
        try {
            # Prompt for password
            $password = Get-DHCPCachePassword -Action "Load"
            if (-not $password) {
                Write-Warning "Password required to load DHCP cache"
                return @()
            }

            # Read encrypted data
            $encryptedContent = Get-Content $cacheFileDat -Raw

            # Decrypt the cache
            $decryptedJson = Unprotect-DHCPCache -EncryptedText $encryptedContent -Password $password

            # Parse JSON
            $cache = $decryptedJson | ConvertFrom-Json
            return $cache.Scopes
        }
        catch {
            # Decryption failed or cache corrupted
            Write-Warning "Failed to load DHCP cache: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to decrypt DHCP cache.`n`n" +
                "Possible causes:`n" +
                "- Incorrect password`n" +
                "- File tampering detected (HMAC verification failed)`n" +
                "- Corrupted file`n`n" +
                "Error: $($_.Exception.Message)",
                "Decryption Failed",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    }

    return @()
}

function Update-DHCPScopeCache {
    <#
    .SYNOPSIS
        Queries all DHCP servers and caches all scopes using parallel processing with encryption
    .DESCRIPTION
        Retrieves all scopes from all domain DHCP servers and saves metadata to encrypted cache.
        Does NOT cache statistics (they change frequently), only scope metadata.
        Uses parallel job pool for improved performance.
        Prompts for password to encrypt the cache file.
    .PARAMETER Servers
        Optional array of specific servers to query. If not provided, queries all domain servers.
    .PARAMETER ThrottleLimit
        Maximum number of concurrent server operations. Default is 20.
    #>
    param(
        [string[]]$Servers = @(),
        [int]$ThrottleLimit = 20
    )

    $cacheFile = Join-Path $PSScriptRoot "..\dhcp_scopes_cache.dat"

    try {
        # Import DHCP Server module (required for Get-DhcpServerInDC and Get-DhcpServerv4Scope)
        Import-Module DhcpServer -ErrorAction Stop

        # Get DHCP servers
        if ($Servers.Count -eq 0) {
            $dhcpServers = Get-DhcpServerInDC -ErrorAction Stop
            $Servers = $dhcpServers.DnsName
        }

        $totalServers = $Servers.Count
        if ($totalServers -eq 0) {
            Write-Warning "No DHCP servers found"
            return @()
        }

        # Per-server script block
        $ScriptBlock = {
            param([string]$ServerName)

            $resultScopes = @()
            try {
                Import-Module DhcpServer -ErrorAction Stop
                $scopes = Get-DhcpServerv4Scope -ComputerName $ServerName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

                if ($scopes) {
                    foreach ($scope in $scopes) {
                        $resultScopes += [PSCustomObject]@{
                            ScopeId = $scope.ScopeId.ToString()
                            Name = $scope.Name
                            Description = if ($scope.Description) { $scope.Description } else { "" }
                            Server = $ServerName
                            SubnetMask = $scope.SubnetMask.ToString()
                            StartRange = $scope.StartRange.ToString()
                            EndRange = $scope.EndRange.ToString()
                            State = $scope.State
                            DisplayName = "$($scope.Name) ($($scope.ScopeId)) - $ServerName"
                        }
                    }
                }

                return [PSCustomObject]@{
                    Success = $true
                    ServerName = $ServerName
                    Scopes = $resultScopes
                    Error = $null
                }
            } catch {
                return [PSCustomObject]@{
                    Success = $false
                    ServerName = $ServerName
                    Scopes = @()
                    Error = $_.Exception.Message
                }
            }
        }

        # Initialize job pool
        $MaxConcurrentJobs = if ($totalServers -lt $ThrottleLimit) { $totalServers } else { $ThrottleLimit }
        $Jobs = @()
        $allScopes = @()
        $ServerIndex = 0
        $CompletedCount = 0

        # Start initial batch of jobs
        while ($ServerIndex -lt $totalServers -and $Jobs.Count -lt $MaxConcurrentJobs) {
            $Server = $Servers[$ServerIndex]
            $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Server
            $Jobs += @{
                Job = $Job
                ServerName = $Server
                Processed = $false
            }
            $ServerIndex++
        }

        # Monitor and maintain constant pool
        while ($Jobs | Where-Object { -not $_.Processed }) {
            Start-Sleep -Milliseconds 500

            # Check for completed jobs
            $CompletedInRound = $Jobs | Where-Object { $_.Job.State -eq 'Completed' -and -not $_.Processed }
            foreach ($CompletedJob in $CompletedInRound) {
                $CompletedCount++
                $CompletedJob.Processed = $true

                try {
                    $ServerResult = Receive-Job -Job $CompletedJob.Job -ErrorAction Stop

                    Write-Progress -Activity "Caching DHCP Scopes" -Status "Completed: $($CompletedJob.ServerName) ($CompletedCount/$totalServers)" -PercentComplete (($CompletedCount / $totalServers) * 100)

                    if ($ServerResult.Success -and $ServerResult.Scopes) {
                        $allScopes += $ServerResult.Scopes
                    } elseif (-not $ServerResult.Success) {
                        Write-Warning "Failed to query scopes from $($CompletedJob.ServerName): $($ServerResult.Error)"
                    }
                } catch {
                    Write-Warning "Error receiving results from $($CompletedJob.ServerName): $($_.Exception.Message)"
                }

                Remove-Job -Job $CompletedJob.Job -Force

                # Start next job to maintain pool
                if ($ServerIndex -lt $totalServers) {
                    $Server = $Servers[$ServerIndex]
                    $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Server
                    $Jobs += @{
                        Job = $Job
                        ServerName = $Server
                        Processed = $false
                    }
                    $ServerIndex++
                }
            }

            # Check for failed jobs
            $FailedInRound = $Jobs | Where-Object { $_.Job.State -eq 'Failed' -and -not $_.Processed }
            foreach ($FailedJob in $FailedInRound) {
                $CompletedCount++
                $FailedJob.Processed = $true

                Write-Progress -Activity "Caching DHCP Scopes" -Status "Failed: $($FailedJob.ServerName) ($CompletedCount/$totalServers)" -PercentComplete (($CompletedCount / $totalServers) * 100)
                Write-Warning "Job failed for server: $($FailedJob.ServerName)"

                Remove-Job -Job $FailedJob.Job -Force

                # Start next job to maintain pool
                if ($ServerIndex -lt $totalServers) {
                    $Server = $Servers[$ServerIndex]
                    $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Server
                    $Jobs += @{
                        Job = $Job
                        ServerName = $Server
                        Processed = $false
                    }
                    $ServerIndex++
                }
            }
        }

        Write-Progress -Activity "Caching DHCP Scopes" -Completed

        # Prompt for password to encrypt cache
        $password = Get-DHCPCachePassword -Action "Save"
        if (-not $password) {
            Write-Warning "Password required to save encrypted DHCP cache. Cache not saved."
            [System.Windows.Forms.MessageBox]::Show(
                "DHCP cache was NOT saved because no password was provided.`n`nThe scopes were collected but the cache file requires a password for encryption.",
                "Cache Not Saved",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return $allScopes
        }

        # Create cache object
        $cache = @{
            LastUpdated = (Get-Date).ToString("o")
            TotalScopes = $allScopes.Count
            ServerCount = $Servers.Count
            Scopes = $allScopes
        }

        # Convert to JSON
        $jsonData = $cache | ConvertTo-Json -Depth 3

        # Encrypt and save
        try {
            $encryptedData = Protect-DHCPCache -PlainText $jsonData -Password $password
            $encryptedData | Set-Content $cacheFile -Force

            Write-Host "DHCP cache encrypted and saved successfully to: $cacheFile" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to encrypt and save DHCP cache: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to save encrypted DHCP cache.`n`nError: $($_.Exception.Message)",
                "Encryption Failed",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }

        return $allScopes
    } catch {
        Write-Warning "Failed to build DHCP scope cache: $($_.Exception.Message)"
        return @()
    }
}

function Get-SystemHealthSummary {
    <#
    .SYNOPSIS
        Gets system health summary information
    #>
    try {
        $health = @{
            AdminPrivileges = Test-IsAdministrator
            NetworkAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue).Count
            DNAConnected = $false
            DHCPServersFound = 0
            LastExportTime = "Never"
        }

        # Check if we have DNA Center connection
        if ($script:dnaCenterToken -and $script:dnaCenterTokenExpiry) {
            if ((Get-Date) -lt $script:dnaCenterTokenExpiry) {
                $health.DNAConnected = $true
            }
        }

        # Check for DHCP servers from cache (fast)
        try {
            $cachedServers = Get-CachedDHCPServers
            if ($cachedServers) {
                $health.DHCPServersFound = @($cachedServers).Count
            }
        } catch {
            # Silently continue if cache read fails
        }

        return $health
    } catch {
        return @{
            AdminPrivileges = $false
            NetworkAdapters = 0
            DNAConnected = $false
            DHCPServersFound = 0
            LastExportTime = "Error"
        }
    }
}

function New-QuickActionButton {
    <#
    .SYNOPSIS
        Creates a quick action button for the dashboard
    #>
    param(
        [string]$Text,
        [int]$X,
        [int]$Y,
        [scriptblock]$OnClick,
        [hashtable]$Theme = $null
    )

    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Location = New-Object System.Drawing.Point($X, $Y)
    $button.Size = New-Object System.Drawing.Size(200, 40)
    $button.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    if ($OnClick) {
        $button.Add_Click($OnClick)
    }

    return $button
}

function Get-RecentActivity {
    <#
    .SYNOPSIS
        Gets recent activity log entries
    #>
    param(
        [hashtable]$Settings,
        [int]$Count = 5
    )

    if ($Settings.ExportHistory) {
        return $Settings.ExportHistory |
            Select-Object -Last $Count |
            ForEach-Object {
                "$($_.Timestamp) - $($_.Operation) ($($_.Format))"
            }
    }

    return @("No recent activity")
}

# Export module members
Export-ModuleMember -Function @(
    'New-DashboardPanel',
    'Update-DashboardPanel',
    'Get-CachedDHCPServers',
    'Update-DHCPServerCache',
    'Get-CachedDHCPScopes',
    'Update-DHCPScopeCache',
    'Get-SystemHealthSummary',
    'New-QuickActionButton',
    'Get-RecentActivity'
)
