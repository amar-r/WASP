# WASP Release Checklist

## Pre-Release Testing

### ✅ Windows Server Testing
- [ ] Test on Windows Server 2022 (primary target)
- [ ] Test on Windows Server 2019 (compatibility)
- [ ] Test with Administrator privileges
- [ ] Test with limited privileges
- [ ] Test all check types: Registry, Services, Audit Policy, Security Policy
- [ ] Test error conditions and edge cases
- [ ] Verify output format consistency

### ✅ Baseline Testing
- [ ] Test with test-baseline.json (3 rules)
- [ ] Test with full CIS baseline (400+ rules)
- [ ] Test Excel to JSON converter with real CIS files
- [ ] Verify JSON baseline format validation
- [ ] Test skip functionality

### ✅ Error Handling
- [ ] Test missing baseline file
- [ ] Test invalid JSON format
- [ ] Test missing registry keys
- [ ] Test service not found
- [ ] Test audit policy access denied
- [ ] Test security policy export failure

## Documentation Review

### ✅ README.md
- [ ] Installation instructions clear
- [ ] Usage examples work
- [ ] Parameter descriptions accurate
- [ ] Sample output matches actual output
- [ ] Troubleshooting section complete

### ✅ CONTRIBUTING.md
- [ ] Development setup instructions
- [ ] Code style guidelines
- [ ] Testing requirements
- [ ] Pull request process

### ✅ Code Documentation
- [ ] All functions have comments
- [ ] Complex logic explained
- [ ] Error handling documented
- [ ] Parameter validation clear

## Release Preparation

### ✅ File Organization
- [ ] Remove test files and temporary files
- [ ] Verify .gitignore excludes appropriate files
- [ ] Check for sensitive data in code
- [ ] Ensure all files have proper headers

### ✅ Version Information
- [ ] Update version numbers in scripts
- [ ] Update version in README
- [ ] Create version tag
- [ ] Update release notes

### ✅ Dependencies
- [ ] Verify requirements.txt is complete
- [ ] Test Python dependencies installation
- [ ] Document PowerShell version requirements
- [ ] List Windows Server version compatibility

## Post-Release

### ✅ Monitoring
- [ ] Monitor GitHub issues
- [ ] Respond to user questions
- [ ] Track download statistics
- [ ] Collect user feedback

### ✅ Maintenance
- [ ] Plan for CIS benchmark updates
- [ ] Consider additional check types
- [ ] Performance optimization opportunities
- [ ] Feature requests evaluation

## Release Notes Template

```markdown
# WASP v1.0.0 - Initial Release

## Features
- CIS compliance scanning for Windows Server systems
- Support for Registry, Services, Audit Policy, and Security Policy checks
- JSON baseline format with skip functionality
- Excel to JSON converter for CIS benchmarks
- Comprehensive reporting and error handling

## Supported Platforms
- Windows Server 2022 (primary)
- Windows Server 2019
- Windows Server 2016

## Requirements
- PowerShell 5.1 or later
- Administrator privileges (recommended)
- Python 3.7+ (for Excel conversion)

## Installation
1. Clone the repository
2. Install Python dependencies: `pip install -r requirements.txt`
3. Set PowerShell execution policy if needed
4. Run: `.\scripts\scan.ps1`

## Known Issues
- None at this time

## Future Plans
- Additional check types (Group Policy, File System)
- GUI interface
- Scheduled scanning capabilities
- Integration with CI/CD pipelines
``` 