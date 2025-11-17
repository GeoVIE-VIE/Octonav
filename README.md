# OctoNav - Complete Network Management Tool

## Overview
OctoNav is a comprehensive Windows PowerShell GUI application for network management, combining:
- Network adapter configuration (XFER functionality)
- DHCP scope statistics collection
- Cisco DNA Center API integration

**Current Version**: 2.1 - Security Hardened + DNACAPEiv6 Integration

---

## Files in Repository

### Main Application
- **OctoNav-CompleteGUI-FIXED.ps1** - Main GUI application (2,288 lines)
  - ✅ Merged: XFER network configuration (Tab 1)
  - ✅ Merged: DHCP statistics collection (Tab 2)
  - ✅ Merged: DNA Center API functions (Tab 3 - 20 functions)

### Standalone Scripts
- **Merged-DHCPScopeStats.ps1** - Standalone DHCP statistics script (329 lines)
  - Functionality merged into main GUI
  - Can still be used independently

- **XFER** - Standalone network configuration script (387 lines)
  - Functionality merged into main GUI
  - Can still be used independently

- **DNACAPEiv6_COMPLETE(1).txt** - Extended DNA Center CLI script (3,943 lines)
  - ⚠️ **NOT merged into GUI**
  - Command-line interactive menu system
  - Contains additional DNA Center functions not in GUI:
    - Get-LastPingReachableTime
    - Get-LastDisconnectTime
    - Get-LastDeviceAvailabilityEventTime
    - Advanced device selection menus
    - ASCII art banner
    - Progress indicators
  - Use this for advanced DNA Center operations

### Configuration Files
- **dna_config.json.example** - DNA Center server configuration template
- **SECURITY_IMPROVEMENTS.md** - Detailed security enhancement documentation

---

## Merge Status Summary

| File | Status | Location in GUI | Lines |
|------|--------|----------------|-------|
| XFER | ✅ Merged | Tab 1: Network Configuration | 387 |
| Merged-DHCPScopeStats.ps1 | ✅ Merged | Tab 2: DHCP Statistics | 329 |
| DNA Center (Core API) | ✅ Merged | Tab 3: DNA Center (23 functions) | - |
| DNACAPEiv6 Advanced Functions | ✅ Merged | Tab 3: Path Trace, Availability Events, Last Disconnect | 469 |
| DNACAPEiv6_COMPLETE(1).txt | ✅ Kept as Standalone | CLI script with interactive menus | 3,943 |

**Note**: DNACAPEiv6_COMPLETE(1).txt remains available as a standalone CLI tool with interactive menus, ASCII banners, and CLI command execution features. The core API functions have been merged into the GUI.

---

## Requirements

### System Requirements
- Windows PowerShell 5.1 or later
- Administrator privileges (required for network configuration)
- Windows Forms .NET assemblies

### Module Requirements
- **For DHCP Tab**:
  - DhcpServer module
  - Domain membership (or specific server names)

- **For DNA Center Tab**:
  - Internet/network access to DNA Center
  - Valid DNA Center credentials

---

## Setup

### 1. Configure DNA Center Servers

**Option A: JSON Configuration File (Recommended)**

Create `dna_config.json` in the script directory:
```json
{
  "servers": [
    {
      "Name": "Production DNA Center",
      "Url": "https://dnac-prod.example.com"
    },
    {
      "Name": "Development DNA Center",
      "Url": "https://dnac-dev.example.com"
    }
  ]
}
```

**Option B: Environment Variables**
```powershell
$env:DNAC_SERVER1_NAME = "Production DNA Center"
$env:DNAC_SERVER1_URL = "https://dnac-prod.example.com"
$env:DNAC_SERVER2_NAME = "Dev DNA Center"
$env:DNAC_SERVER2_URL = "https://dnac-dev.example.com"
```

### 2. Configure Output Directory (Optional)
```powershell
$env:OCTONAV_OUTPUT_DIR = "D:\Reports\OctoNav"
```

Default: `C:\DNACenter_Reports`

### 3. Set Execution Policy
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## Usage

### Launch the GUI
```powershell
.\OctoNav-CompleteGUI-FIXED.ps1
```

### Tab 1: Network Configuration
1. Click "Find Unidentified Network" to detect APIPA networks
2. Enter new IP address, gateway, and prefix length
3. Click "Apply Configuration"
4. Use "Restore Defaults" to revert changes

**Security Note**: Validates all IP addresses and prefix lengths before applying.

### Tab 2: DHCP Statistics
1. (Optional) Enter scope name filters (comma-separated)
2. Choose options:
   - Include DNS Server Information (slower)
   - Track Bad_Address Occurrences (slower)
3. Click "Collect DHCP Statistics"
4. Export results to CSV

**Security Note**: Server names and scope filters are validated against injection attacks.

### Tab 3: DNA Center
1. Select DNA Center server from dropdown
2. Enter credentials and click "Connect"
3. Click "Load Devices" to fetch network inventory
4. (Optional) Apply device filters
5. Click any function button to execute and export data

**Available Functions** (23 total):

**Core Device Information:**
- Device Information (Basic & Detailed)
- Device Inventory Count
- Device Configurations
- Device Interfaces & Modules
- Device Reachability

**Network Health & Monitoring:**
- Network & Client Health
- Compliance Status
- Last Disconnect Times (NEW - from DNACAPEiv6)
- Availability Events (NEW - from DNACAPEiv6)

**Topology & Neighbors:**
- Physical Topology
- OSPF, CDP, LLDP Neighbors

**Network Services:**
- VLANs, Templates, Sites
- Access Points
- Software Images
- Issues/Events

**Advanced Analysis:**
- Path Trace (NEW - from DNACAPEiv6) - Interactive network path analysis

**Security Note**: Credentials cleared from memory after authentication. Tokens expire after 1 hour.

---

## Security Features

### Input Validation
- ✅ IP address validation (regex + .NET parsing)
- ✅ DNS hostname validation (RFC 1123)
- ✅ Scope filter character whitelisting
- ✅ Filename sanitization with path traversal protection
- ✅ Prefix length range validation

### Credential Protection
- ✅ Passwords cleared from memory after use
- ✅ Base64 credentials explicitly nullified
- ✅ Forced garbage collection
- ✅ No credentials stored in config files

### Error Handling
- ✅ Sanitized error messages (no sensitive data leakage)
- ✅ File paths, IPs, usernames redacted
- ✅ Stack traces removed
- ✅ Length-limited error output

### Code Security
- ✅ No dynamic code execution (`Invoke-Expression`, etc.)
- ✅ Parameterized cmdlet calls
- ✅ Regex input escaping
- ✅ Proper resource cleanup

**For detailed security information**, see: `SECURITY_IMPROVEMENTS.md`

---

## Output Files

All exports are CSV files saved to the configured output directory:

### DHCP Tab
- `DHCPScopeStats_YYYYMMDD_HHMMSS.csv`
- `DHCPBadAddressSummary_YYYYMMDD_HHMMSS.csv` (if tracking enabled)

### DNA Center Tab
- `NetworkDevices_Basic_YYYYMMDD_HHMMSS.csv`
- `NetworkDevices_Detailed_YYYYMMDD_HHMMSS.csv`
- `DeviceInventory_ByFamily_YYYYMMDD_HHMMSS.csv`
- `DeviceInventory_ByRole_YYYYMMDD_HHMMSS.csv`
- `NetworkHealth_YYYYMMDD_HHMMSS.csv`
- `ClientHealth_YYYYMMDD_HHMMSS.csv`
- `DeviceReachability_YYYYMMDD_HHMMSS.csv`
- `ComplianceStatus_YYYYMMDD_HHMMSS.csv`
- `Sites_YYYYMMDD_HHMMSS.csv`
- `Templates_YYYYMMDD_HHMMSS.csv`
- `PhysicalTopology_YYYYMMDD_HHMMSS.csv`
- `OSPF_Neighbors_YYYYMMDD_HHMMSS.csv`
- `CDP_Neighbors_YYYYMMDD_HHMMSS.csv`
- `LLDP_Neighbors_YYYYMMDD_HHMMSS.csv`
- `VLANs_YYYYMMDD_HHMMSS.csv`
- `DeviceModules_YYYYMMDD_HHMMSS.csv`
- `DeviceInterfaces_YYYYMMDD_HHMMSS.csv`
- `SoftwareImages_YYYYMMDD_HHMMSS.csv`
- `Issues_YYYYMMDD_HHMMSS.csv`
- `AccessPoints_YYYYMMDD_HHMMSS.csv`
- `DeviceConfigurations_YYYYMMDD_HHMMSS/` (folder with individual config files)
- `DeviceLastDisconnect_YYYYMMDD_HHMMSS.csv` (NEW - last disconnect times)
- `DeviceAvailabilityEvents_YYYYMMDD_HHMMSS.csv` (NEW - availability event timestamps)
- `PathTrace_SOURCE_to_DEST_YYYYMMDD_HHMMSS.csv` (NEW - network path trace results)

---

## Troubleshooting

### "Please Configure" appears in server dropdown
- Create `dna_config.json` in script directory
- OR set `DNAC_SERVER1_NAME` and `DNAC_SERVER1_URL` environment variables

### DHCP functions fail
- Ensure DhcpServer PowerShell module is installed
- Run as Administrator
- Verify domain membership or provide specific server names

### DNA Center authentication fails
- Check DNA Center URL is correct (must start with https://)
- Verify credentials are correct
- Check network connectivity to DNA Center
- Review firewall rules

### Network configuration doesn't apply
- Ensure running as Administrator
- Check network adapter is in correct state
- Verify IP address format is correct

### Output directory errors
- Check write permissions on `C:\DNACenter_Reports`
- Set `OCTONAV_OUTPUT_DIR` to writable location
- Script will fall back to temp directory if needed

---

## Using DNACAPEiv6_COMPLETE (Advanced)

For advanced DNA Center operations not available in the GUI:

```powershell
powershell.exe -ExecutionPolicy Bypass -File "DNACAPEiv6_COMPLETE(1).txt"
```

This provides:
- Interactive menu system
- Additional timestamp functions
- Device availability tracking
- Last ping/disconnect times
- More granular device selection

---

## Version History

### v2.1 (Current)
- **MAJOR**: Merged DNACAPEiv6 advanced functions into GUI
- Added Path Trace function with interactive dialog
- Added Last Disconnect Times function
- Added Availability Events function
- Increased DNA Center functions from 20 to 23
- All security hardening from v2.0 maintained
- DNACAPEiv6_COMPLETE kept as standalone CLI tool

### v2.0
- Enhanced input validation (server names, scope filters)
- Strengthened path traversal protection
- Configuration file support (JSON + environment variables)
- API token expiration tracking
- Error message sanitization
- Improved credential clearing
- Output directory validation

### v1.1
- Initial security hardening
- Certificate validation bypass (as per requirements)
- Basic input validation
- Credential clearing on exit

### v1.0
- Initial merge of XFER, DHCP, and DNA Center functions
- Windows Forms GUI
- Three-tab interface

---

## Known Limitations

1. **Certificate Validation**: Disabled for DNA Center (as per user requirements)
2. **Token Refresh**: Manual re-authentication required after 1 hour
3. **API Rate Limiting**: Not implemented
4. **Audit Logging**: Events only shown in GUI, not logged to file
5. **MFA**: DNA Center multi-factor authentication not supported

---

## Credits

- **Original Author**: In Memory of Zesty.PS1
- **Integration & Security**: Claude
- **DNA Center API**: Cisco DNA Center REST API
- **DHCP Module**: Microsoft DhcpServer PowerShell Module

---

## License

This tool is provided as-is for network management purposes.

---

## Support

For issues, questions, or contributions:
1. Review `SECURITY_IMPROVEMENTS.md` for security details
2. Check `dna_config.json.example` for configuration guidance
3. Test with standalone scripts if GUI issues occur

---

**Last Updated**: 2024
**Script Version**: 2.0
