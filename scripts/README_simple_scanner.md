# Simple WISP Scanner

A straightforward Windows security scanner that reads the CIS JSON baseline and checks system settings accordingly.

## Overview

This scanner is designed to be simple and reliable, focusing on basic validation of Windows security settings against the CIS baseline without complex parsing or dependencies.

## Features

- **Simple JSON parsing** - Reads the CIS baseline directly
- **Three check types**:
  - `secpol` - Security Policy settings (via secedit export)
  - `registry` - Registry key/value checks (via reg query)
  - `auditpol` - Audit Policy settings (via auditpol command)
- **Clear output** - Easy-to-read results with pass/fail status
- **Progress tracking** - Shows progress during scanning
- **Error handling** - Graceful handling of missing settings

## Usage

### Basic Usage
```powershell
.\simple_scanner.ps1
```

### Custom Parameters
```powershell
.\simple_scanner.ps1 -BaselinePath "path\to\baseline.json" -OutputPath "path\to\results.txt"
```

### Parameters
- `-BaselinePath` - Path to the JSON baseline file (default: `baselines\cis-windows-server-2022-member-server.json`)
- `-OutputPath` - Path for the output report (default: `reports\simple_results.txt`)

## Requirements

- Windows PowerShell 5.1 or later
- Administrative privileges (for registry and security policy access)
- CIS JSON baseline file

## How It Works

1. **Loads JSON baseline** - Parses the CIS rules from the JSON file
2. **Exports security policy** - Uses `secedit /export` to get current security settings
3. **Gets audit policy** - Uses `auditpol /get` to retrieve audit settings
4. **Processes each rule** - Checks settings based on the rule type:
   - **secpol**: Looks for settings in the exported security policy
   - **registry**: Queries registry keys/values directly
   - **auditpol**: Searches audit policy output for settings
5. **Generates report** - Creates a detailed report with results

## Output Format

The scanner generates a text report with:
- Summary statistics (total rules, compliance rate)
- Detailed results for each rule including:
  - Rule ID and title
  - Check type (secpol/registry/auditpol)
  - Status (PASS/FAIL)
  - Current vs expected values
  - Details about the check

## Example Output

```
Simple WISP Scanner Report
Generated: 2025-06-25 14:30:00
Computer: WIN-SERVER01
OS: Microsoft Windows Server 2022 Standard Evaluation 2009 (64-bit)

SUMMARY
=======
Total Rules: 408
Compliant: 45
Non-Compliant: 363
Compliance Rate: 11.03%

DETAILED RESULTS
================================================================================

Rule ID: 1.1.1
Title: (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'
Type: secpol
Status: FAIL
Current Value: 
Expected Value: 24 passwords remembered on domain members. 0 passwords remembered on stand-alone servers
Details: Setting not found in security policy
--------------------------------------------------------------------------------
```

## Advantages

- **Simple and reliable** - No complex parsing or dependencies
- **Fast execution** - Minimal overhead
- **Clear results** - Easy to understand output
- **Error resilient** - Handles missing settings gracefully
- **Maintainable** - Easy to modify and extend

## Limitations

- **Basic matching** - Uses simple string matching for settings
- **Limited validation** - Doesn't perform complex value validation
- **No remediation** - Only reports issues, doesn't fix them
- **Windows only** - Designed specifically for Windows systems

## Troubleshooting

### Common Issues

1. **"Failed to export security policy"**
   - Ensure running with administrative privileges
   - Check if secedit is available on the system

2. **"Registry value not found"**
   - Verify registry paths in the baseline are correct
   - Check if registry keys exist on the target system

3. **"Audit policy setting not found"**
   - Ensure auditpol command is available
   - Check if audit policy settings are configured

### Debug Mode

To see more detailed output, you can modify the script to add `-Verbose` parameters to the commands or add additional Write-Host statements for debugging.

## Future Enhancements

Potential improvements for future versions:
- More sophisticated value validation
- Support for additional check types
- Remediation capabilities
- HTML report generation
- Integration with other security tools 