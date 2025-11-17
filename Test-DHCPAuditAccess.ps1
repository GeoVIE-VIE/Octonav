#Requires -Version 5.1
<#
.SYNOPSIS
    Test script to check DHCP audit log access and demonstrate optimizations
.DESCRIPTION
    This script helps you determine:
    1. If you have access to DHCP server audit logs
    2. Which method will be used for BadAddress tracking
    3. Performance comparison between methods

.EXAMPLE
    .\Test-DHCPAuditAccess.ps1
    Interactive mode - prompts for DHCP servers

.EXAMPLE
    .\Test-DHCPAuditAccess.ps1 -DHCPServers "dhcp01.domain.com","dhcp02.domain.com"
    Tests specific DHCP servers
#>

param(
    [string[]]$DHCPServers = @()
)

# Import the optimized functions
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module "$scriptPath\OptimizedDHCPFunctions.ps1" -Force

Write-Host "=== DHCP Audit Log Access Test ===" -ForegroundColor Cyan
Write-Host ""

# If no servers specified, discover or prompt
if ($DHCPServers.Count -eq 0) {
    Write-Host "Discovering DHCP servers in domain..." -ForegroundColor Yellow
    try {
        $discoveredServers = Get-DhcpServerInDC -ErrorAction Stop
        if ($discoveredServers) {
            Write-Host "Found $($discoveredServers.Count) DHCP server(s):" -ForegroundColor Green
            $discoveredServers | ForEach-Object { Write-Host "  - $($_.DnsName)" }
            Write-Host ""

            $choice = Read-Host "Test all discovered servers? (Y/N)"
            if ($choice -eq 'Y' -or $choice -eq 'y') {
                $DHCPServers = $discoveredServers.DnsName
            } else {
                $serverInput = Read-Host "Enter DHCP server names (comma separated)"
                if (-not [string]::IsNullOrWhiteSpace($serverInput)) {
                    $DHCPServers = $serverInput.Split(',') | ForEach-Object { $_.Trim() }
                }
            }
        }
    } catch {
        Write-Host "Could not discover DHCP servers: $($_.Exception.Message)" -ForegroundColor Red
        $serverInput = Read-Host "Enter DHCP server names manually (comma separated)"
        if (-not [string]::IsNullOrWhiteSpace($serverInput)) {
            $DHCPServers = $serverInput.Split(',') | ForEach-Object { $_.Trim() }
        }
    }
}

if ($DHCPServers.Count -eq 0) {
    Write-Host "No DHCP servers specified. Exiting." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Testing Audit Log Access ===" -ForegroundColor Cyan
Write-Host ""

$results = @()

foreach ($server in $DHCPServers) {
    Write-Host "Testing: $server" -ForegroundColor Yellow

    # Test audit log access
    $access = Test-DHCPAuditLogAccess -ComputerName $server

    if ($access.HasAccess) {
        Write-Host "  ✓ Audit logs accessible!" -ForegroundColor Green
        Write-Host "    Path: $($access.LogPath)" -ForegroundColor Gray
        Write-Host "    Log files found: $($access.LogFileCount)" -ForegroundColor Gray
        Write-Host "    Recommended method: Audit Log Parsing (FAST)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Audit logs NOT accessible" -ForegroundColor Red
        Write-Host "    Path: $($access.LogPath)" -ForegroundColor Gray
        Write-Host "    Error: $($access.ErrorMessage)" -ForegroundColor Red
        Write-Host "    Recommended method: Parallel Lease Query (SLOWER)" -ForegroundColor Yellow
    }

    $results += [PSCustomObject]@{
        Server = $server
        HasAuditAccess = $access.HasAccess
        LogPath = $access.LogPath
        LogFiles = $access.LogFileCount
        Method = $access.RecommendedMethod
        Error = $access.ErrorMessage
    }

    Write-Host ""
}

# Summary
Write-Host "=== Summary ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$withAccess = ($results | Where-Object { $_.HasAuditAccess }).Count
$withoutAccess = ($results | Where-Object { -not $_.HasAuditAccess }).Count

Write-Host ""
Write-Host "Servers with audit log access: $withAccess" -ForegroundColor Green
Write-Host "Servers without access: $withoutAccess" -ForegroundColor $(if ($withoutAccess -gt 0) { "Yellow" } else { "Green" })
Write-Host ""

if ($withoutAccess -gt 0) {
    Write-Host "=== How to Gain Audit Log Access ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Option 1: Administrative Share Access" -ForegroundColor Yellow
    Write-Host "  - Requires membership in Domain Admins or DHCP Administrators"
    Write-Host "  - Logs location: \\<server>\admin$\System32\DHCP\"
    Write-Host ""
    Write-Host "Option 2: File Share (Recommended for non-admins)" -ForegroundColor Yellow
    Write-Host "  1. On DHCP server, create share: C:\DHCP_Logs"
    Write-Host "  2. Grant Read access to your user account"
    Write-Host "  3. Modify script to use: \\<server>\DHCP_Logs"
    Write-Host ""
    Write-Host "Option 3: Use Parallel Lease Query (Current Fallback)" -ForegroundColor Yellow
    Write-Host "  - No changes needed, but slower performance"
    Write-Host "  - Requires DHCP Users or DHCP Administrators group membership"
    Write-Host ""
}

# Performance estimation
Write-Host "=== Performance Impact ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Estimated time to collect BadAddress statistics:" -ForegroundColor White
Write-Host ""

foreach ($result in $results) {
    if ($result.HasAuditAccess) {
        Write-Host "  $($result.Server): ~5-10 seconds (Audit log method)" -ForegroundColor Green
    } else {
        Write-Host "  $($result.Server): ~2-10 minutes (Lease query method)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=== Recommendations ===" -ForegroundColor Cyan
Write-Host ""

if ($withAccess -eq $results.Count) {
    Write-Host "✓ All servers support fast audit log method!" -ForegroundColor Green
    Write-Host "  BadAddress tracking will be very fast (~seconds per server)" -ForegroundColor Green
} elseif ($withAccess -gt 0) {
    Write-Host "⚠ Mixed access - some servers will be slow" -ForegroundColor Yellow
    Write-Host "  Consider enabling audit log access on remaining servers" -ForegroundColor Yellow
} else {
    Write-Host "⚠ No audit log access on any server" -ForegroundColor Yellow
    Write-Host "  BadAddress tracking will use slower lease query method" -ForegroundColor Yellow
    Write-Host "  Expected time: 2-10 minutes per server depending on scope size" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Use the optimized functions in your DHCP statistics scripts"
Write-Host "  2. The Get-BadAddressOptimized function will automatically choose the best method"
Write-Host "  3. Consider using the Merged-DHCPScopeStats-Optimized.ps1 script"
Write-Host ""

# Export results
$outputPath = "DHCPAuditAccessTest.csv"
$results | Export-Csv -Path $outputPath -NoTypeInformation -Force
Write-Host "Results saved to: $outputPath" -ForegroundColor Green
