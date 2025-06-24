# WASP Quick Start Guide

> **Note:** The official CIS Excel benchmark file is a prerequisite and must be downloaded separately from the [Center for Internet Security](https://www.cisecurity.org/benchmark/microsoft_windows_server). It is not included in this repository.

Get WASP (Windows Audit & Security Profiler) running in 5 minutes!

## 🚀 Quick Setup

### 1. Prerequisites
- Windows Server 2016/2019/2022
- PowerShell 5.1 or later
- Administrator privileges (recommended)
- **Official CIS Excel Benchmark File** (download from CIS website)

### 2. Download & Setup
```powershell
# Clone the repository
git clone https://github.com/yourusername/wasp.git
cd wasp

# Download the official CIS Excel benchmark file from the CIS website and place it in a safe location (not included in this repository)

# Install Python dependencies (for Excel conversion)
python -m pip install -r requirements.txt

# Set execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 3. Run Your First Scan
```powershell
# Basic scan with default CIS baseline
.\scripts\scan.ps1

# Quick test with sample baseline
.\scripts\scan.ps1 -BaselinePath ".\baselines\test-baseline.json" -Verbose
```

## 📊 Understanding Results

### Sample Output
```
WASP - Windows Audit & Security Profiler
CIS Compliance Scanner for Windows Server Systems
Version: 1.0.0

================================================================================
SECTION: Loading Baseline
================================================================================

Loaded baseline: WASP Test Baseline
Total rules: 3

================================================================================
SECTION: Processing Rules
================================================================================

Rule TEST-001: PASS - Test Registry Rule - Ensure UAC is enabled
Rule TEST-002: FAIL - Test Service Rule - Ensure Print Spooler is disabled
Rule TEST-003: PASS - Test Audit Policy Rule - Ensure System Integrity is audited

================================================================================
SECTION: Generating Report
================================================================================

Report saved to: .\reports\wasp-scan-2024-01-15-1430.txt

SCAN COMPLETED
Total Rules Processed: 3
Compliant: 2
Non-Compliant: 1
Compliance Rate: 66.67%
```

### Result Interpretation
- **PASS**: System is compliant with this rule
- **FAIL**: System is not compliant (needs remediation)
- **Compliance Rate**: Percentage of passed rules

## 🔧 Common Commands

### Basic Scanning
```powershell
# Full CIS compliance scan
.\scripts\scan.ps1

# Scan with custom baseline
.\scripts\scan.ps1 -BaselinePath ".\baselines\my-baseline.json"

# Verbose output for debugging
.\scripts\scan.ps1 -Verbose
```

### Selective Scanning
```powershell
# Skip specific check types
.\scripts\scan.ps1 -SkipRegistry -SkipServices

# Only registry checks
.\scripts\scan.ps1 -SkipServices -SkipAuditPolicy -SkipSecurityPolicy

# Only service checks
.\scripts\scan.ps1 -SkipRegistry -SkipAuditPolicy -SkipSecurityPolicy
```

### Custom Output
```powershell
# Specify output location
.\scripts\scan.ps1 -OutputPath "C:\Reports\my-compliance-report.txt"

# Use timestamp in filename
.\scripts\scan.ps1 -OutputPath ".\reports\scan-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
```

## 📋 Creating Custom Baselines

### From CIS Excel Files
```powershell
# Download the official CIS Excel benchmark file from the CIS website (not included in this repository)

# Convert CIS Excel to JSON
python tools\cis-excel-to-json.py "CIS_Windows_Server_2022_Benchmark.xlsx" "my-baseline.json"

# Use the converted baseline
.\scripts\scan.ps1 -BaselinePath "my-baseline.json"
```

### Manual Baseline Creation
Create a JSON file like this:
```json
{
  "name": "My Custom Baseline",
  "version": "1.0.0",
  "description": "Custom security baseline",
  "rules": [
    {
      "id": "CUSTOM-001",
      "title": "Ensure specific registry setting",
      "check_type": "registry",
      "target": "HKLM:\\SOFTWARE\\MyApp",
      "registry_name": "SecuritySetting",
      "expected_value": "1",
      "skip": false
    }
  ]
}
```

## 🐛 Troubleshooting

### Common Issues

**"Execution policy error"**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**"Access denied" errors**
- Run PowerShell as Administrator
- Check file permissions

**"Baseline file not found"**
- Verify the file path is correct
- Check file permissions

**"Registry value not found"**
- Verify the registry path exists
- Run as Administrator for HKLM access

### Debug Mode
```powershell
# Enable verbose output
.\scripts\scan.ps1 -Verbose

# Check PowerShell version
$PSVersionTable.PSVersion

# Test baseline file
Get-Content ".\baselines\test-baseline.json" | ConvertFrom-Json
```

## 📈 Next Steps

1. **Run a full CIS scan** to assess your system
2. **Review the detailed report** in the reports folder
3. **Create custom baselines** for your specific requirements
4. **Automate scanning** with scheduled tasks
5. **Integrate with your security workflow**

## 📞 Need Help?

- **Issues**: [GitHub Issues](https://github.com/yourusername/wasp/issues)
- **Documentation**: [Full README](README.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)

---

**Happy Scanning!** 🐝 