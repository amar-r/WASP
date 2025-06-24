# WASP - Windows Audit & Security Profiler

A comprehensive PowerShell-based security scanner for Windows Server systems that validates compliance against CIS (Center for Internet Security) benchmarks.

## 🚀 Features

- **CIS Compliance Scanning**: Validates Windows Server systems against CIS benchmarks
- **Multiple Check Types**: Registry, Security Policy, Audit Policy, and Services
- **JSON Baseline Support**: Uses structured JSON baselines for easy customization
- **Comprehensive Reporting**: Generates detailed compliance reports
- **Modular Architecture**: Separate modules for different check types
- **Real-time Progress**: Shows scanning progress with detailed output
- **Error Handling**: Robust error handling and graceful failure recovery

## 📋 Requirements

- **Windows Server 2016/2019/2022** (tested on Windows Server 2022)
- **PowerShell 5.1 or later**
- **Administrator privileges** (recommended for best results)
- **Official CIS Excel Benchmark File** (must be downloaded separately from the Center for Internet Security)
- **CIS Excel to JSON Converter** (included in `tools/` directory)

## 🛠️ Installation

1. **Clone the repository**:
   ```powershell
   git clone https://github.com/yourusername/wasp.git
   cd wasp
   ```

2. **Download the official CIS Excel benchmark file** from the [Center for Internet Security](https://www.cisecurity.org/benchmark/microsoft_windows_server) and place it in a safe location (not included in this repository).

3. **Verify PowerShell execution policy**:
   ```powershell
   Get-ExecutionPolicy
   # If restricted, run: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

4. **Install Python dependencies** (for Excel to JSON conversion):
   ```powershell
   python -m pip install -r requirements.txt
   ```

## 📖 Usage

### Basic Usage

Run a compliance scan using the default baseline:

```powershell
.\scripts\scan.ps1
```

### Advanced Usage

```powershell
# Use custom baseline
.\scripts\scan.ps1 -BaselinePath ".\baselines\custom-baseline.json"

# Specify output location
.\scripts\scan.ps1 -OutputPath ".\reports\my-scan-report.txt"

# Skip specific check types
.\scripts\scan.ps1 -SkipRegistry -SkipServices

# Scan only Level 1 CIS controls
.\scripts\scan.ps1 -CISLevel Level1

# Scan only Level 2 CIS controls
.\scripts\scan.ps1 -CISLevel Level2

# Scan both levels (default)
.\scripts\scan.ps1 -CISLevel Both

# Enable verbose output
.\scripts\scan.ps1 -Verbose
```

### Command Line Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `BaselinePath` | string | `.\baselines\cis-windows-server-2022-member-server.json` | Path to JSON baseline file |
| `OutputPath` | string | `.\reports\wasp-scan-YYYY-MM-DD-HHMM.txt` | Path for output report |
| `Verbose` | switch | `false` | Enable verbose output |
| `SkipRegistry` | switch | `false` | Skip registry compliance checks |
| `SkipSecurityPolicy` | switch | `false` | Skip security policy checks |
| `SkipAuditPolicy` | switch | `false` | Skip audit policy checks |
| `SkipServices` | switch | `false` | Skip service compliance checks |
| `CISLevel` | string | `Both` | CIS level to scan: `Level1`, `Level2`, or `Both` |

## 📊 Baseline Format

WASP uses JSON baselines with the following structure:

```json
{
  "name": "CIS Windows Server 2022 Member Server",
  "version": "1.0.0",
  "description": "CIS benchmark for Windows Server 2022 Member Server",
  "rules": [
    {
      "id": "1.1.1",
      "title": "Ensure 'Enforce password history' is set to '24 or more password(s)'",
      "check_type": "registry",
      "target": "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
      "registry_name": "PasswordHistorySize",
      "expected_value": "24",
      "skip": false
    },
    {
      "id": "2.2.1",
      "title": "Ensure 'Print Spooler' is set to 'Disabled'",
      "check_type": "service",
      "service_name": "Spooler",
      "expected_status": "Stopped",
      "expected_start_type": "Disabled",
      "skip": false
    }
  ]
}
```

### Rule Types

#### Registry Rules
```json
{
  "check_type": "registry",
  "target": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
  "registry_name": "EnableLUA",
  "expected_value": "1"
}
```

#### Service Rules
```json
{
  "check_type": "service",
  "service_name": "Spooler",
  "expected_status": "Stopped",
  "expected_start_type": "Disabled"
}
```

#### Audit Policy Rules
```json
{
  "check_type": "audit_policy",
  "audit_category": "System",
  "audit_subcategory": "Security System Extension",
  "expected_setting": "Success"
}
```

## 🔧 Creating Custom Baselines

### From CIS Excel Files

1. **Download the official CIS Excel benchmark file** from the [CIS website](https://www.cisecurity.org/benchmark/microsoft_windows_server) (not included in this repository).

2. **Convert CIS Excel to JSON**:
   ```powershell
   python tools\cis-excel-to-json.py "path\to\cis-benchmark.xlsx" "output\baseline.json"
   ```

2. **Customize the baseline**:
   - Edit the JSON file to add/remove rules
   - Set `skip: true` to disable specific rules
   - Modify expected values for your environment

### Manual Baseline Creation

Create a JSON file following the baseline format above. Include only the rules you want to check.

## 📈 Sample Output

```
WASP - Windows Audit & Security Profiler
CIS Compliance Scanner for Windows Server Systems
Version: 1.0.0

================================================================================
SECTION: Loading Baseline
================================================================================

Loaded baseline: CIS Windows Server 2022 Member Server
Total rules: 408

================================================================================
SECTION: Exporting Security Policy
================================================================================

Security policy exported successfully

================================================================================
SECTION: Processing Rules
================================================================================

Rule 1.1.1: PASS - Ensure 'Enforce password history' is set to '24 or more password(s)'
Rule 1.1.2: FAIL - Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'
Rule 2.2.1: PASS - Ensure 'Print Spooler' is set to 'Disabled'

================================================================================
SECTION: Generating Report
================================================================================

Report saved to: .\reports\wasp-scan-2024-01-15-1430.txt

SCAN COMPLETED
Total Rules Processed: 408
Compliant: 342
Non-Compliant: 66
Compliance Rate: 83.82%
```

## 📁 Project Structure

```
WASP/
├── baselines/                    # JSON baseline files
│   ├── cis-windows-server-2022-member-server.json
│   └── custom-baselines/
├── reports/                      # Generated scan reports
├── scripts/                      # PowerShell scripts
│   ├── scan.ps1                  # Main scanner script
│   └── checks/                   # Check modules
│       ├── registry.ps1          # Registry checks
│       ├── services.ps1          # Service checks
│       ├── auditpol.ps1          # Audit policy checks
│       └── secpol.ps1            # Security policy checks
├── tools/                        # Utility tools
│   └── cis-excel-to-json.py      # Excel to JSON converter
├── requirements.txt              # Python dependencies
└── README.md                     # This file
```

## 🔍 Check Types

### Registry Checks
- Validates registry values against expected settings
- Uses both direct registry queries and security policy export
- Supports DWORD, String, and Multi-String values

### Security Policy Checks
- Exports security policy using `secedit /export`
- Parses policy file for registry settings
- More reliable than direct registry access

### Service Checks
- Validates service status and startup type
- Uses `Get-Service` with JSON output for reliability
- Supports all Windows service states

### Audit Policy Checks
- Uses `auditpol /get /category:*` for comprehensive audit settings
- Parses hierarchical audit policy structure
- Validates both categories and subcategories

## 🛡️ Security Considerations

- **Administrator Privileges**: Some checks require elevated privileges
- **Execution Policy**: Ensure PowerShell execution policy allows script execution
- **Baseline Validation**: Always review baselines before use in production
- **Network Access**: No external network access required for scanning

## 🐛 Troubleshooting

### Common Issues

1. **"Execution policy error"**:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

2. **"Access denied" errors**:
   - Run PowerShell as Administrator
   - Check file permissions

3. **"Baseline file not found"**:
   - Verify baseline file path
   - Check file permissions

4. **"Registry value not found"**:
   - Verify registry path exists
   - Check if running as Administrator

### Debug Mode

Enable verbose output for detailed debugging:

```powershell
.\scripts\scan.ps1 -Verbose
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Development Setup

```powershell
# Clone and setup development environment
git clone https://github.com/yourusername/wasp.git
cd wasp
python -m pip install -r requirements.txt
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **CIS (Center for Internet Security)** for the benchmark standards
- **Microsoft** for PowerShell and Windows Server documentation
- **Open source community** for inspiration and tools

## 📞 Support

- **Issues**: Report bugs and feature requests through GitHub Issues
- **Documentation**: Check the README and project structure for usage information
- **Contributing**: See the Contributing section above for development guidelines

For questions about CIS benchmarks and compliance standards, refer to the [Center for Internet Security](https://www.cisecurity.org/) official documentation.