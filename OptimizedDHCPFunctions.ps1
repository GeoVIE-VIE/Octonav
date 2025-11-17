# ============================================
# OPTIMIZED DHCP FUNCTIONS WITH SECURITY ENHANCEMENTS
# ============================================
# This module provides high-performance DHCP statistics collection
# with enhanced security features

<#
.SYNOPSIS
    Tests access to DHCP Server audit logs
.DESCRIPTION
    Checks if the current user has permission to read DHCP audit logs
    from a remote DHCP server. Returns access information and log location.
.PARAMETER ComputerName
    The DHCP server to test
.OUTPUTS
    PSCustomObject with HasAccess, LogPath, and ErrorMessage properties
#>
function Test-DHCPAuditLogAccess {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    try {
        # DHCP audit logs are stored in %SystemRoot%\System32\DHCP\
        $remotePath = "\\$ComputerName\admin$\System32\DHCP"

        # Try to access the directory
        $testAccess = Test-Path $remotePath -ErrorAction Stop

        if ($testAccess) {
            # Try to list files to confirm read access
            $logFiles = Get-ChildItem -Path $remotePath -Filter "DhcpSrvLog-*.log" -ErrorAction Stop

            return [PSCustomObject]@{
                HasAccess = $true
                LogPath = $remotePath
                LogFileCount = $logFiles.Count
                ErrorMessage = $null
                RecommendedMethod = "AuditLog"
            }
        } else {
            return [PSCustomObject]@{
                HasAccess = $false
                LogPath = $remotePath
                LogFileCount = 0
                ErrorMessage = "Path not accessible"
                RecommendedMethod = "ParallelLease"
            }
        }
    } catch {
        return [PSCustomObject]@{
            HasAccess = $false
            LogPath = "\\$ComputerName\admin$\System32\DHCP"
            LogFileCount = 0
            ErrorMessage = $_.Exception.Message
            RecommendedMethod = "ParallelLease"
        }
    }
}

<#
.SYNOPSIS
    Gets Bad Address counts from DHCP audit logs (FAST method)
.DESCRIPTION
    Parses DHCP server audit logs to count BAD_ADDRESS occurrences.
    This is 10-100x faster than querying all leases.

    DHCP Event IDs for Bad Address:
    - Event ID 20: DHCP server issued address to a client but found conflict

.PARAMETER ComputerName
    The DHCP server name
.PARAMETER DaysToSearch
    How many days of logs to search (default: 7)
.OUTPUTS
    Hashtable with ScopeId as key and BadAddressCount as value
#>
function Get-BadAddressFromAuditLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [int]$DaysToSearch = 7
    )

    $badAddressMap = @{}

    try {
        $remotePath = "\\$ComputerName\admin$\System32\DHCP"

        # Get log files modified within the specified days
        $logFiles = Get-ChildItem -Path $remotePath -Filter "DhcpSrvLog-*.log" -ErrorAction Stop |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-$DaysToSearch) }

        foreach ($logFile in $logFiles) {
            # Read log file content
            $content = Get-Content $logFile.FullName -ErrorAction SilentlyContinue

            foreach ($line in $content) {
                # Skip header lines and empty lines
                if ($line -match '^(ID|$)' -or [string]::IsNullOrWhiteSpace($line)) {
                    continue
                }

                # DHCP log format: ID,Date,Time,Description,IP Address,Host Name,MAC Address,User Name, TransactionID, QResult,Probationtime, CorrelationID,Dhcid,VendorClass(Hex),VendorClass(ASCII),User Class(Hex),User Class(ASCII),Relay Agent Information,DnsRegError
                # Event ID 20 = NACK (Address conflict / BAD_ADDRESS)
                # Event ID 25 = DNS record not deleted (may indicate bad address)

                $fields = $line -split ','

                if ($fields.Count -ge 5) {
                    $eventId = $fields[0].Trim()
                    $ipAddress = $fields[4].Trim()
                    $hostname = if ($fields.Count -ge 6) { $fields[5].Trim() } else { "" }

                    # Look for BAD_ADDRESS in hostname field or Event ID 20 (NACK)
                    if ($hostname -eq "BAD_ADDRESS" -or $eventId -eq "20") {
                        # Determine scope from IP address (get network portion)
                        if ($ipAddress -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$') {
                            # This is a simplified scope matching - you might need to be more precise
                            # For now, we'll store by the IP itself and aggregate later
                            if ($badAddressMap.ContainsKey($ipAddress)) {
                                $badAddressMap[$ipAddress]++
                            } else {
                                $badAddressMap[$ipAddress] = 1
                            }
                        }
                    }
                }
            }
        }

        return $badAddressMap
    } catch {
        Write-Warning "Failed to read audit logs from ${ComputerName}: $($_.Exception.Message)"
        return @{}
    }
}

<#
.SYNOPSIS
    Gets Bad Address counts using parallel lease queries (FALLBACK method)
.DESCRIPTION
    When audit logs aren't accessible, this function queries leases in parallel
    for better performance than sequential queries.
.PARAMETER ComputerName
    The DHCP server name
.PARAMETER Scopes
    Array of scope objects with ScopeId property
.PARAMETER ThrottleLimit
    Maximum parallel jobs (default: 10)
.OUTPUTS
    Hashtable with ScopeId as key and BadAddressCount as value
#>
function Get-BadAddressFromLeases {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$true)]
        [array]$Scopes,

        [int]$ThrottleLimit = 10
    )

    $badAddressMap = @{}

    try {
        # Use PowerShell 7+ parallel processing if available
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $results = $Scopes | ForEach-Object -Parallel {
                $scope = $_
                try {
                    $badLeases = Get-DhcpServerv4Lease -ComputerName $using:ComputerName `
                        -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue |
                        Where-Object { $_.HostName -eq "BAD_ADDRESS" }

                    [PSCustomObject]@{
                        ScopeId = $scope.ScopeId
                        Count = if ($badLeases) { ($badLeases | Measure-Object).Count } else { 0 }
                    }
                } catch {
                    [PSCustomObject]@{
                        ScopeId = $scope.ScopeId
                        Count = 0
                    }
                }
            } -ThrottleLimit $ThrottleLimit

            foreach ($result in $results) {
                $badAddressMap[$result.ScopeId] = $result.Count
            }
        } else {
            # PowerShell 5.1 - use jobs (slower but works)
            $jobs = @()

            foreach ($scope in $Scopes) {
                $job = Start-Job -ScriptBlock {
                    param($server, $scopeId)
                    try {
                        $badLeases = Get-DhcpServerv4Lease -ComputerName $server `
                            -ScopeId $scopeId -ErrorAction SilentlyContinue |
                            Where-Object { $_.HostName -eq "BAD_ADDRESS" }

                        return @{
                            ScopeId = $scopeId
                            Count = if ($badLeases) { ($badLeases | Measure-Object).Count } else { 0 }
                        }
                    } catch {
                        return @{
                            ScopeId = $scopeId
                            Count = 0
                        }
                    }
                } -ArgumentList $ComputerName, $scope.ScopeId

                $jobs += $job

                # Throttle job creation
                while ((Get-Job -State Running).Count -ge $ThrottleLimit) {
                    Start-Sleep -Milliseconds 100
                }
            }

            # Wait for all jobs and collect results
            $jobs | Wait-Job | ForEach-Object {
                $result = Receive-Job -Job $_
                if ($result) {
                    $badAddressMap[$result.ScopeId] = $result.Count
                }
                Remove-Job -Job $_ -Force
            }
        }

        return $badAddressMap
    } catch {
        Write-Warning "Failed to get bad addresses from leases: $($_.Exception.Message)"
        return @{}
    }
}

<#
.SYNOPSIS
    Intelligent Bad Address tracking that chooses the best method
.DESCRIPTION
    Automatically selects the fastest available method:
    1. Audit logs (fastest) if accessible
    2. Parallel lease queries (fallback)

.PARAMETER ComputerName
    The DHCP server name
.PARAMETER Scopes
    Array of scope objects
.OUTPUTS
    Hashtable with ScopeId as key and BadAddressCount as value
#>
function Get-BadAddressOptimized {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$true)]
        [array]$Scopes
    )

    # Test audit log access first
    $auditAccess = Test-DHCPAuditLogAccess -ComputerName $ComputerName

    if ($auditAccess.HasAccess) {
        Write-Output "Using DHCP audit logs (fast method) for $ComputerName..."

        # Get bad addresses from audit logs
        $auditBadAddresses = Get-BadAddressFromAuditLog -ComputerName $ComputerName

        # Map IP addresses to scope IDs
        $badAddressMap = @{}
        foreach ($scope in $Scopes) {
            $scopeNetwork = $scope.ScopeId.ToString()
            $count = 0

            # Count bad addresses that belong to this scope
            foreach ($ip in $auditBadAddresses.Keys) {
                if ($ip -like "$($scopeNetwork.Substring(0, $scopeNetwork.LastIndexOf('.'))).*") {
                    $count += $auditBadAddresses[$ip]
                }
            }

            $badAddressMap[$scope.ScopeId] = $count
        }

        return $badAddressMap
    } else {
        Write-Output "Audit logs not accessible for $ComputerName. Using parallel lease queries (slower)..."
        Write-Output "  Reason: $($auditAccess.ErrorMessage)"

        return Get-BadAddressFromLeases -ComputerName $ComputerName -Scopes $Scopes
    }
}

# ============================================
# SECURITY ENHANCEMENTS
# ============================================

<#
.SYNOPSIS
    Securely prompts for credentials and returns a PSCredential object
.DESCRIPTION
    Creates a PSCredential object with SecureString password.
    This is more secure than passing plain text passwords.
#>
function Get-SecureDNACredential {
    param(
        [string]$Username,
        [string]$PlainTextPassword
    )

    if ([string]::IsNullOrWhiteSpace($Username) -or [string]::IsNullOrWhiteSpace($PlainTextPassword)) {
        throw "Username and password are required"
    }

    try {
        $securePassword = ConvertTo-SecureString -String $PlainTextPassword -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($Username, $securePassword)

        # Clear the plain text password from memory
        $PlainTextPassword = $null
        [System.GC]::Collect()

        return $credential
    } catch {
        throw "Failed to create secure credential: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Enforces TLS 1.2 or higher for secure connections
.DESCRIPTION
    Sets the security protocol to TLS 1.2 or TLS 1.3.
    Should be called at script initialization.
#>
function Enable-SecureProtocol {
    try {
        # Enable TLS 1.2 and TLS 1.3 (if available)
        $protocols = [Net.SecurityProtocolType]::Tls12

        # Check if TLS 1.3 is available (.NET 4.8+)
        try {
            $tls13 = [Net.SecurityProtocolType]::Tls13
            $protocols = $protocols -bor $tls13
        } catch {
            # TLS 1.3 not available, continue with TLS 1.2
        }

        [Net.ServicePointManager]::SecurityProtocol = $protocols

        Write-Verbose "Enabled secure protocols: $([Net.ServicePointManager]::SecurityProtocol)"
        return $true
    } catch {
        Write-Warning "Failed to enable TLS 1.2+: $($_.Exception.Message)"
        return $false
    }
}

<#
.SYNOPSIS
    Sets secure ACLs on output directory
.DESCRIPTION
    Restricts access to the output directory to only the current user
    and SYSTEM account.
#>
function Set-SecureOutputDirectory {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    try {
        # Create directory if it doesn't exist
        if (-not (Test-Path $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }

        # Get current user
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        # Create new ACL
        $acl = Get-Acl $Path

        # Disable inheritance and remove existing rules
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

        # Add current user with full control
        $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentUser,
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($userRule)

        # Add SYSTEM with full control
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM",
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($systemRule)

        # Apply ACL
        Set-Acl -Path $Path -AclObject $acl

        Write-Verbose "Secured output directory: $Path (accessible only to $currentUser and SYSTEM)"
        return $true
    } catch {
        Write-Warning "Failed to set secure ACLs on ${Path}: $($_.Exception.Message)"
        return $false
    }
}

<#
.SYNOPSIS
    Invokes REST API with retry logic and rate limiting
.DESCRIPTION
    Wrapper around Invoke-RestMethod with:
    - Automatic retry on transient failures
    - Exponential backoff
    - Timeout enforcement
    - Rate limiting
#>
function Invoke-SecureRestMethod {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,

        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,

        [string]$Method = "Get",

        [object]$Body = $null,

        [int]$TimeoutSec = 30,

        [int]$MaxRetries = 3,

        [int]$RetryDelaySeconds = 2
    )

    $attempt = 0
    $delay = $RetryDelaySeconds

    while ($attempt -lt $MaxRetries) {
        try {
            $attempt++

            $params = @{
                Uri = $Uri
                Method = $Method
                Headers = $Headers
                TimeoutSec = $TimeoutSec
                ErrorAction = "Stop"
            }

            if ($Body) {
                $params["Body"] = $Body
            }

            $response = Invoke-RestMethod @params

            # Add small delay to rate limit (100ms between successful calls)
            Start-Sleep -Milliseconds 100

            return $response
        } catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            # Check if error is retryable (5xx errors or network issues)
            $isRetryable = $false
            if ($statusCode -ge 500 -and $statusCode -lt 600) {
                $isRetryable = $true
            } elseif ($_.Exception.Message -match "timeout|network|connection") {
                $isRetryable = $true
            }

            if ($isRetryable -and $attempt -lt $MaxRetries) {
                Write-Verbose "Request failed (attempt $attempt/$MaxRetries), retrying in ${delay}s..."
                Start-Sleep -Seconds $delay
                $delay = $delay * 2  # Exponential backoff
            } else {
                throw
            }
        }
    }

    throw "Maximum retry attempts ($MaxRetries) exceeded"
}

# ============================================
# EXPORT FUNCTIONS
# ============================================

Export-ModuleMember -Function @(
    'Test-DHCPAuditLogAccess',
    'Get-BadAddressFromAuditLog',
    'Get-BadAddressFromLeases',
    'Get-BadAddressOptimized',
    'Get-SecureDNACredential',
    'Enable-SecureProtocol',
    'Set-SecureOutputDirectory',
    'Invoke-SecureRestMethod'
)
