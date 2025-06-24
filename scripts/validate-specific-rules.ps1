# WASP - Specific Rule Validation Script
# Validates specific rules that showed false positives/negatives
# Version: 1.0.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\reports\specific-validation-$(Get-Date -Format 'yyyy-MM-dd-HHmm').txt"
)

# Import check modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module "$scriptPath\checks\secpol.ps1" -Force
Import-Module "$scriptPath\checks\auditpol.ps1" -Force
Import-Module "$scriptPath\checks\registry.ps1" -Force

# Function to write colored output
function Write-ColorOutput {
    param($Message, $Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

# Function to write section headers
function Write-Section {
    param($Title)
    Write-ColorOutput "`n" -Color Cyan
    Write-ColorOutput ("=" * 80) -Color Cyan
    Write-ColorOutput "VALIDATION: $Title" -Color Cyan
    Write-ColorOutput ("=" * 80) -Color Cyan
    Write-ColorOutput "`n" -Color Cyan
}

# Function to validate Rule 1.1.3 - Minimum Password Age
function Test-Rule-1-1-3 {
    Write-Section "Rule 1.1.3 - Minimum Password Age"
    
    Write-ColorOutput "Expected: 1 or more day(s)" -Color Yellow
    Write-ColorOutput "Current Result: FAIL (Current Value: 0)" -Color Red
    Write-ColorOutput "`nValidating with multiple methods:" -Color White
    
    # Method 1: Security Policy Export
    Write-ColorOutput "`nMethod 1: Security Policy Export" -Color Cyan
    $secpol = Export-SecurityPolicy
    if ($secpol) {
        $value = Get-SecurityPolicyValue -RegistryPath "MinimumPasswordAge" -PolicyContent $secpol
        Write-ColorOutput "  Value: $value" -Color White
        $shouldPass = if ([int]::TryParse($value, [ref]$null)) { [int]$value -ge 1 } else { $false }
        Write-ColorOutput "  Should Pass: $shouldPass" -Color $(if ($shouldPass) { "Green" } else { "Red" })
    } else {
        Write-ColorOutput "  Failed to export security policy" -Color Red
    }
    
    # Method 2: Net Accounts
    Write-ColorOutput "`nMethod 2: Net Accounts" -Color Cyan
    $netOutput = net accounts 2>&1
    if ($netOutput -match "Minimum password age \(days\):\s*(\d+)") {
        $value = $matches[1]
        Write-ColorOutput "  Value: $value" -Color White
        $shouldPass = [int]$value -ge 1
        Write-ColorOutput "  Should Pass: $shouldPass" -Color $(if ($shouldPass) { "Green" } else { "Red" })
    } else {
        Write-ColorOutput "  Failed to get value from net accounts" -Color Red
    }
    
    # Method 3: Direct Registry Query
    Write-ColorOutput "`nMethod 3: Direct Registry Query" -Color Cyan
    $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "MinimumPasswordAge" -ErrorAction SilentlyContinue
    if ($regValue) {
        $value = $regValue.MinimumPasswordAge
        Write-ColorOutput "  Value: $value" -Color White
        $shouldPass = [int]$value -ge 1
        Write-ColorOutput "  Should Pass: $shouldPass" -Color $(if ($shouldPass) { "Green" } else { "Red" })
    } else {
        Write-ColorOutput "  Registry value not found" -Color Red
    }
    
    # Method 4: Group Policy
    Write-ColorOutput "`nMethod 4: Group Policy" -Color Cyan
    $gpOutput = gpresult /r 2>&1
    if ($gpOutput -match "Minimum password age.*(\d+)") {
        $value = $matches[1]
        Write-ColorOutput "  Value: $value" -Color White
        $shouldPass = [int]$value -ge 1
        Write-ColorOutput "  Should Pass: $shouldPass" -Color $(if ($shouldPass) { "Green" } else { "Red" })
    } else {
        Write-ColorOutput "  Not found in group policy output" -Color Yellow
    }
}

# Function to validate Rule 1.2.2 - Account Lockout Threshold
function Test-Rule-1-2-2 {
    Write-Section "Rule 1.2.2 - Account Lockout Threshold"
    
    Write-ColorOutput "Expected: 5 or fewer invalid logon attempt(s), but not 0" -Color Yellow
    Write-ColorOutput "Current Result: FAIL (Current Value: 10)" -Color Red
    Write-ColorOutput "`nValidating with multiple methods:" -Color White
    
    # Method 1: Security Policy Export
    Write-ColorOutput "`nMethod 1: Security Policy Export" -Color Cyan
    $secpol = Export-SecurityPolicy
    if ($secpol) {
        $value = Get-SecurityPolicyValue -RegistryPath "LockoutBadCount" -PolicyContent $secpol
        Write-ColorOutput "  Value: $value" -Color White
        $shouldPass = if ([int]::TryParse($value, [ref]$null)) { [int]$value -le 5 -and [int]$value -gt 0 } else { $false }
        Write-ColorOutput "  Should Pass: $shouldPass" -Color $(if ($shouldPass) { "Green" } else { "Red" })
    } else {
        Write-ColorOutput "  Failed to export security policy" -Color Red
    }
    
    # Method 2: Net Accounts
    Write-ColorOutput "`nMethod 2: Net Accounts" -Color Cyan
    $netOutput = net accounts 2>&1
    if ($netOutput -match "Lockout threshold:\s*(\d+)") {
        $value = $matches[1]
        Write-ColorOutput "  Value: $value" -Color White
        $shouldPass = [int]$value -le 5 -and [int]$value -gt 0
        Write-ColorOutput "  Should Pass: $shouldPass" -Color $(if ($shouldPass) { "Green" } else { "Red" })
    } else {
        Write-ColorOutput "  Failed to get value from net accounts" -Color Red
    }
}

# Function to validate Rule 2.3.2.1 - SCENoApplyLegacyAuditPolicy
function Test-Rule-2-3-2-1 {
    Write-Section "Rule 2.3.2.1 - SCENoApplyLegacyAuditPolicy"
    
    Write-ColorOutput "Expected: 1 (Enabled)" -Color Yellow
    Write-ColorOutput "Current Result: PASS (but should be registry check)" -Color Yellow
    Write-ColorOutput "`nValidating with multiple methods:" -Color White
    
    # Method 1: Direct Registry Query
    Write-ColorOutput "`nMethod 1: Direct Registry Query" -Color Cyan
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue
    if ($regValue) {
        $value = $regValue.SCENoApplyLegacyAuditPolicy
        Write-ColorOutput "  Value: $value" -Color White
        $shouldPass = $value -eq 1
        Write-ColorOutput "  Should Pass: $shouldPass" -Color $(if ($shouldPass) { "Green" } else { "Red" })
    } else {
        Write-ColorOutput "  Registry value not found" -Color Red
    }
    
    # Method 2: Group Policy
    Write-ColorOutput "`nMethod 2: Group Policy" -Color Cyan
    $gpOutput = gpresult /r 2>&1
    if ($gpOutput -match "Audit: No auditing.*Enabled") {
        Write-ColorOutput "  Found in Group Policy: Enabled" -Color White
        Write-ColorOutput "  Should Pass: True" -Color Green
    } else {
        Write-ColorOutput "  Not found in group policy output" -Color Yellow
    }
}

# Function to validate Rule 1.1.6 - Relax Minimum Password Length Limits
function Test-Rule-1-1-6 {
    Write-Section "Rule 1.1.6 - Relax Minimum Password Length Limits"
    
    Write-ColorOutput "Expected: Enabled" -Color Yellow
    Write-ColorOutput "Current Result: FAIL (Setting not found)" -Color Red
    Write-ColorOutput "`nValidating with multiple methods:" -Color White
    
    # Method 1: Security Policy Export
    Write-ColorOutput "`nMethod 1: Security Policy Export" -Color Cyan
    $secpol = Export-SecurityPolicy
    if ($secpol) {
        $value = Get-SecurityPolicyValue -RegistryPath "RelaxMinimumPasswordLengthLimits" -PolicyContent $secpol
        if ($value) {
            Write-ColorOutput "  Value: $value" -Color White
            $shouldPass = $value -eq "1"
            Write-ColorOutput "  Should Pass: $shouldPass" -Color $(if ($shouldPass) { "Green" } else { "Red" })
        } else {
            Write-ColorOutput "  Setting not found in security policy" -Color Yellow
        }
    } else {
        Write-ColorOutput "  Failed to export security policy" -Color Red
    }
    
    # Method 2: Direct Registry Query
    Write-ColorOutput "`nMethod 2: Direct Registry Query" -Color Cyan
    $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "RelaxMinimumPasswordLengthLimits" -ErrorAction SilentlyContinue
    if ($regValue) {
        $value = $regValue.RelaxMinimumPasswordLengthLimits
        Write-ColorOutput "  Value: $value" -Color White
        $shouldPass = $value -eq 1
        Write-ColorOutput "  Should Pass: $shouldPass" -Color $(if ($shouldPass) { "Green" } else { "Red" })
    } else {
        Write-ColorOutput "  Registry value not found" -Color Red
    }
    
    # Method 3: Group Policy
    Write-ColorOutput "`nMethod 3: Group Policy" -Color Cyan
    $gpOutput = gpresult /r 2>&1
    if ($gpOutput -match "Relax minimum password length limits.*Enabled") {
        Write-ColorOutput "  Found in Group Policy: Enabled" -Color White
        Write-ColorOutput "  Should Pass: True" -Color Green
    } else {
        Write-ColorOutput "  Not found in group policy output" -Color Yellow
    }
}

# Function to generate validation report
function Write-ValidationReport {
    param($OutputPath)
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $computerName = $env:COMPUTERNAME
    
    $report = @"
WASP - Specific Rule Validation Report
Generated: $timestamp
Computer: $computerName

This report validates specific rules that showed false positives/negatives
in the WASP scanner results.

VALIDATION SUMMARY
==================
- Rule 1.1.3: Minimum Password Age (should be 1+ days)
- Rule 1.2.2: Account Lockout Threshold (should be 5 or fewer, but not 0)
- Rule 2.3.2.1: SCENoApplyLegacyAuditPolicy (should be registry check)
- Rule 1.1.6: Relax Minimum Password Length Limits (setting not found)

RECOMMENDATIONS
===============
1. Compare values from multiple validation methods
2. Identify the most authoritative source for each setting
3. Update scanner logic based on validation results
4. Consider adding cross-validation between methods

"@
    
    # Write to file
    $report | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-ColorOutput "Validation report saved to: $OutputPath" -Color Green
}

# Main execution
Write-ColorOutput "WASP - Specific Rule Validation Script" -Color Cyan
Write-ColorOutput "Validating rules that showed false positives/negatives" -Color Cyan
Write-ColorOutput "Version: 1.0.0`n" -Color Cyan

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-ColorOutput "WARNING: This script should be run as Administrator for best results." -Color Yellow
}

# Run validation tests
Test-Rule-1-1-3
Test-Rule-1-2-2
Test-Rule-2-3-2-1
Test-Rule-1-1-6

# Generate validation report
Write-Section "Generating Validation Report"
Write-ValidationReport -OutputPath $OutputPath

Write-ColorOutput "`nVALIDATION COMPLETED" -Color Cyan
Write-ColorOutput "Check the output above for validation results" -Color White
Write-ColorOutput "Validation report saved to: $OutputPath" -Color Green 