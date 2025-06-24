# Contributing to WASP

Thank you for your interest in contributing to WASP (Windows Audit & Security Profiler)! This document provides guidelines and information for contributors.

## 🚀 Getting Started

### Prerequisites

- **PowerShell 5.1 or later**
- **Windows Server 2016/2019/2022** (for testing)
- **Python 3.7+** (for Excel to JSON conversion tools)
- **Git** for version control

### Development Setup

1. **Fork and clone the repository**:
   ```powershell
   git clone https://github.com/yourusername/wasp.git
   cd wasp
   ```

2. **Install Python dependencies**:
   ```powershell
   python -m pip install -r requirements.txt
   ```

3. **Verify PowerShell execution policy**:
   ```powershell
   Get-ExecutionPolicy
   # If restricted: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

## 📋 Contribution Guidelines

### Code Style

#### PowerShell Scripts
- Use **PascalCase** for function names
- Use **camelCase** for variables
- Use **UPPER_CASE** for constants
- Include comprehensive error handling
- Add verbose comments for complex logic
- Use consistent indentation (4 spaces)

#### Python Scripts
- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Include docstrings for all functions
- Use meaningful variable names

### File Structure

```
WASP/
├── baselines/              # JSON baseline files
├── reports/                # Generated scan reports
├── scripts/                # PowerShell scripts
│   ├── scan.ps1           # Main scanner
│   └── checks/            # Check modules
├── tools/                  # Utility tools
├── tests/                  # Test files (future)
└── docs/                   # Documentation (future)
```

### Adding New Check Types

1. **Create a new check module** in `scripts/checks/`
2. **Follow the naming convention**: `[checktype].ps1`
3. **Implement required functions**:
   - `Test-[CheckType]Compliance` - Main compliance test function
   - `Get-[CheckType]Data` - Data retrieval function
   - Helper functions as needed

4. **Update the main scanner** to include your check type
5. **Add documentation** for your check type

### Example Check Module Structure

```powershell
# New Check Module for WASP Scanner
# Handles [check_type]-based CIS compliance checks

function Test-[CheckType]Compliance {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule
    )
    
    $result = @{
        RuleId = $Rule.id
        Title = $Rule.title
        CheckType = "[CheckType]"
        Compliant = $false
        CurrentValue = $null
        ExpectedValue = $Rule.expected_value
        Details = ""
        Error = $null
    }
    
    try {
        # Implementation here
    }
    catch {
        $result.Error = $_.Exception.Message
        $result.Details = "Error: $($result.Error)"
    }
    
    return $result
}

Export-ModuleMember -Function Test-[CheckType]Compliance
```

## 🧪 Testing

### Running Tests

1. **Test on Windows Server VM**:
   ```powershell
   .\scripts\scan.ps1 -Verbose
   ```

2. **Test with custom baseline**:
   ```powershell
   .\scripts\scan.ps1 -BaselinePath ".\baselines\test-baseline.json" -Verbose
   ```

3. **Test individual check types**:
   ```powershell
   .\scripts\scan.ps1 -SkipRegistry -SkipServices -Verbose
   ```

### Test Requirements

- Test on **Windows Server 2022** (primary target)
- Test on **Windows Server 2019** (compatibility)
- Test with **different privilege levels**
- Test **error conditions** and edge cases
- Verify **output format** consistency

## 📝 Documentation

### Updating Documentation

1. **README.md** - Main project documentation
2. **CONTRIBUTING.md** - This file
3. **Inline comments** - Code documentation
4. **Function help** - PowerShell help text

### Documentation Standards

- Use **clear, concise language**
- Include **examples** where helpful
- Maintain **consistent formatting**
- Update **version numbers** when needed
- Include **screenshots** for UI changes

## 🔧 Development Workflow

### Feature Development

1. **Create a feature branch**:
   ```powershell
   git checkout -b feature/new-check-type
   ```

2. **Make your changes**:
   - Write code
   - Add tests
   - Update documentation

3. **Test thoroughly**:
   - Run on Windows Server VM
   - Test error conditions
   - Verify output format

4. **Commit your changes**:
   ```powershell
   git add .
   git commit -m "Add new check type: [description]"
   ```

5. **Push and create pull request**:
   ```powershell
   git push origin feature/new-check-type
   ```

### Bug Fixes

1. **Create a bug fix branch**:
   ```powershell
   git checkout -b fix/bug-description
   ```

2. **Fix the issue**:
   - Identify root cause
   - Implement fix
   - Add regression tests

3. **Test the fix**:
   - Verify bug is resolved
   - Ensure no new issues introduced
   - Test related functionality

4. **Submit pull request** with detailed description

## 🐛 Reporting Issues

### Issue Template

When reporting issues, please include:

1. **Environment**:
   - Windows Server version
   - PowerShell version
   - Execution policy setting

2. **Steps to reproduce**:
   - Exact commands run
   - Baseline file used
   - Expected vs actual behavior

3. **Error messages**:
   - Full error output
   - Stack traces if available

4. **Additional context**:
   - Screenshots if relevant
   - Log files if available

### Issue Categories

- **Bug** - Something isn't working
- **Enhancement** - New feature request
- **Documentation** - Documentation improvements
- **Question** - General questions

## 🔒 Security

### Security Guidelines

- **Never commit sensitive data** (passwords, keys, etc.)
- **Use environment variables** for configuration
- **Validate all inputs** thoroughly
- **Follow principle of least privilege**
- **Report security issues** privately

### Security Testing

- Test with **limited privileges**
- Verify **no data leakage**
- Test **input validation**
- Check **error handling**

## 📊 Performance

### Performance Guidelines

- **Minimize registry queries** where possible
- **Use efficient data structures**
- **Avoid unnecessary file I/O**
- **Optimize for large baselines**
- **Profile performance** on target systems

### Performance Testing

- Test with **large baseline files** (1000+ rules)
- Measure **execution time**
- Monitor **memory usage**
- Test **concurrent execution**

## 🤝 Community

### Communication

- **Be respectful** and inclusive
- **Provide constructive feedback**
- **Help other contributors**
- **Follow the code of conduct**

### Getting Help

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - General questions and discussions
- **Pull Requests** - Code reviews and contributions

## 📄 License

By contributing to WASP, you agree that your contributions will be licensed under the MIT License.

## 🙏 Acknowledgments

Thank you for contributing to WASP! Your contributions help make Windows Server security assessment more accessible and effective for the community.

---

**Note**: These guidelines are living documents. Feel free to suggest improvements or clarifications through issues or pull requests. 