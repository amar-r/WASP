# WASP - Windows Audit & Security Profiler

A PowerShell-based security scanner for Windows Server systems that validates compliance against CIS (Center for Internet Security) benchmarks using the official CIS Excel benchmark file.

## Features

- **CIS Compliance Scanning**: Validates Windows Server systems against CIS benchmarks
- **Multiple Check Types**: Registry, Security Policy, and Audit Policy
- **Excel Baseline Support**: Uses the official CIS Excel benchmark as the source of truth
- **Comprehensive Reporting**: Generates compliance reports
- **No Python/JSON Required**: Pure PowerShell workflow
- **Built-in Help**: Script includes comprehensive PowerShell help documentation

## Requirements

- **Windows Server 2016/2019/2022** (tested on Windows Server 2022)
- **PowerShell 5.1 or later**
- **Administrator privileges** (recommended for best results)
- **Official CIS Excel Benchmark File** (must be downloaded separately from the Center for Internet Security)
- **ImportExcel PowerShell Module**

### Install ImportExcel Module
```powershell
Install-Module -Name ImportExcel -Scope CurrentUser
```

## Installation

1. **Clone the repository**:
   ```powershell
   git clone https://github.com/amar-r/wasp.git
   cd wasp
   ```

2. **Download the official CIS Excel benchmark file** from the [Center for Internet Security](https://www.cisecurity.org/benchmark/microsoft_windows_server) and place it in the `baselines/` directory.

3. **Verify PowerShell execution policy**:
   ```powershell
   Get-ExecutionPolicy
   # If restricted, run: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## Usage

### Basic Usage

Run a compliance scan using the Excel baseline:

```powershell
# Default usage (Excel file in baselines/)
./scripts/Start-WaspScan.ps1
```

Or specify a custom Excel path and output location:

```powershell
./scripts/Start-WaspScan.ps1 -ExcelPath ".\baselines\CIS_Microsoft_Windows_Server_2022_Benchmark_v4.0.0.xlsx" -OutputPath ".\reports\my-wasp-report.txt"
```

### Get Help

The script includes built-in PowerShell help:

```powershell
# Get detailed help
Get-Help ./scripts/Start-WaspScan.ps1

# Get parameter information
Get-Help ./scripts/Start-WaspScan.ps1 -Parameter ExcelPath
```

### Command Line Parameters

| Parameter    | Type   | Default                                                    | Description                        |
|--------------|--------|------------------------------------------------------------|------------------------------------|
| `ExcelPath`  | string | `./baselines/CIS_Microsoft_Windows_Server_2022_Benchmark_v4.0.0.xlsx` | Path to CIS Excel file             |
| `OutputPath` | string | `./reports/report.txt`                                     | Path for output report             |

## Project Structure

```
WASP/
├── baselines/                    # Place CIS Excel file here
│   └── [CIS_Microsoft_Windows_Server_2022_Benchmark_v4.0.0.xlsx]  # Add your Excel file here
├── reports/                      # Generated scan reports
├── scripts/                      # PowerShell scripts
│   └── Start-WaspScan.ps1        # Main scanner script (with built-in help)
├── tests/                        # Archived/legacy scripts and tools
└── README.md                     # This file
```

## Sample Output

```
Total Checks: 408
Passed Checks: 342
Failed Checks: 66
Percent Passed: 83.82%

id            : 1.1.1
title         : Ensure 'Enforce password history' is set to '24 or more password(s)'
pass          : True
currentValue  : 24
expectedValue : 24 or more password(s)
type          : secPol
...
```

## Security Considerations

- **Administrator Privileges**: Some checks require elevated privileges
- **Execution Policy**: Ensure PowerShell execution policy allows script execution
- **Excel File**: Always review the CIS Excel file before use in production
- **Network Access**: No external network access required for scanning

## Troubleshooting

### Common Issues

1. **"Execution policy error"**:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

2. **"Access denied" errors**:
   - Run PowerShell as Administrator
   - Check file permissions

3. **"Excel file not found"**:
   - Verify Excel file path
   - Check file permissions
   - Ensure the Excel file is in the baselines/ directory

4. **"Registry value not found"**:
   - Verify registry path exists
   - Check if running as Administrator

5. **"ImportExcel module not found"**:
   ```powershell
   Install-Module -Name ImportExcel -Scope CurrentUser
   ```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.