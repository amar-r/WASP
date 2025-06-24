# WASP - Check Validation Script
# Validates the accuracy of WASP scanner checks against known good values
# Version: 1.0.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\reports\validation-report-$(Get-Date -Format 'yyyy-MM-dd-HHmm').txt",
    
    [Parameter(Mandatory = $false)]
    [switch]$TestSecurityPolicy,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestRegistry,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestAuditPolicy,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestServices,
    
    [Parameter(Mandatory = $false)]
    [switch]$AllTests
)

# Import check modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module "$scriptPath\checks\secpol.ps1" -Force
Import-Module "$scriptPath\checks\auditpol.ps1" -Force
Import-Module "$scriptPath\checks\registry.ps1" -Force
Import-Module "$scriptPath\checks\services.ps1" -Force

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

# Function to compare values and report differences
function Compare-Values {
    param(
        [string]$TestName,
        [string]$ExpectedValue,
        [string]$ActualValue,
        [string]$Method
    )
    
    $match = ($ExpectedValue -eq $ActualValue)
    $status = if ($match) { "PASS" } else { "FAIL" }
    $color = if ($match) { "Green" } else { "Red" }
    
    Write-ColorOutput "  $TestName: $status" -Color $color
    Write-ColorOutput "    Expected: $ExpectedValue" -Color White
    Write-ColorOutput "    Actual:   $ActualValue" -Color White
    Write-ColorOutput "    Method:   $Method" -Color Gray
    
    return @{
        TestName = $TestName
        Status = $status
        Expected = $ExpectedValue
        Actual = $ActualValue
        Method = $Method
        Match = $match
    }
}

# Function to validate security policy checks
function Test-SecurityPolicyValidation {
    Write-Section "Security Policy Validation"
    
    $results = @()
    
    # Test 1: Minimum Password Age
    Write-ColorOutput "Testing Minimum Password Age:" -Color Yellow
    
    # Method 1: Direct registry query
    $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "MinimumPasswordAge" -ErrorAction SilentlyContinue
    $regResult = Compare-Values -TestName "Registry Query" -ExpectedValue "1" -ActualValue $regValue.MinimumPasswordAge -Method "Get-ItemProperty"
    $results += $regResult
    
    # Method 2: Security policy export
    $secpol = Export-SecurityPolicy
    if ($secpol) {
        $secpolValue = Get-SecurityPolicyValue -RegistryPath "MinimumPasswordAge" -PolicyContent $secpol
        $secpolResult = Compare-Values -TestName "Security Policy Export" -ExpectedValue "1" -ActualValue $secpolValue -Method "secedit /export"
        $results += $secpolResult
    }
    
    # Method 3: Net accounts
    $netOutput = net accounts 2>&1
    if ($netOutput -match "Minimum password age \(days\):\s*(\d+)") {
        $netValue = $matches[1]
        $netResult = Compare-Values -TestName "Net Accounts" -ExpectedValue "1" -ActualValue $netValue -Method "net accounts"
        $results += $netResult
    }
    
    # Test 2: Maximum Password Age
    Write-ColorOutput "`nTesting Maximum Password Age:" -Color Yellow
    
    # Method 1: Direct registry query
    $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "MaximumPasswordAge" -ErrorAction SilentlyContinue
    $regResult = Compare-Values -TestName "Registry Query" -ExpectedValue "42" -ActualValue $regValue.MaximumPasswordAge -Method "Get-ItemProperty"
    $results += $regResult
    
    # Method 2: Security policy export
    if ($secpol) {
        $secpolValue = Get-SecurityPolicyValue -RegistryPath "MaximumPasswordAge" -PolicyContent $secpol
        $secpolResult = Compare-Values -TestName "Security Policy Export" -ExpectedValue "42" -ActualValue $secpolValue -Method "secedit /export"
        $results += $secpolResult
    }
    
    return $results
}

# Function to validate registry checks
function Test-RegistryValidation {
    Write-Section "Registry Validation"
    
    $results = @()
    
    # Test 1: UAC Settings
    Write-ColorOutput "Testing UAC Settings:" -Color Yellow
    
    # Method 1: Direct registry query
    $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    $regResult = Compare-Values -TestName "EnableLUA Registry" -ExpectedValue "1" -ActualValue $regValue.EnableLUA -Method "Get-ItemProperty"
    $results += $regResult
    
    # Method 2: Group Policy (if available)
    $gpOutput = gpresult /r 2>&1
    if ($gpOutput -match "User Account Control: Run all administrators in Admin Approval Mode.*Enabled") {
        $gpResult = Compare-Values -TestName "Group Policy" -ExpectedValue "Enabled" -ActualValue "Enabled" -Method "gpresult /r"
        $results += $gpResult
    }
    
    return $results
}

# Function to validate audit policy checks
function Test-AuditPolicyValidation {
    Write-Section "Audit Policy Validation"
    
    $results = @()
    
    # Test 1: Audit Logon Events
    Write-ColorOutput "Testing Audit Logon Events:" -Color Yellow
    
    # Method 1: auditpol command
    $auditpolOutput = auditpol /get /category:"Logon" 2>&1
    if ($auditpolOutput -match "Logon.*Success and Failure") {
        $auditpolResult = Compare-Values -TestName "AuditPol Command" -ExpectedValue "Success and Failure" -ActualValue "Success and Failure" -Method "auditpol /get"
        $results += $auditpolResult
    }
    
    # Method 2: Registry query
    $regValue = Get-ItemProperty -Path "HKLM:\SECURITY\Policy\PolAdtEv" -Name "AuditLogonEvents" -ErrorAction SilentlyContinue
    if ($regValue) {
        $regResult = Compare-Values -TestName "Audit Registry" -ExpectedValue "3" -ActualValue $regValue.AuditLogonEvents -Method "Registry Query"
        $results += $regResult
    }
    
    return $results
}

# Function to validate service checks
function Test-ServiceValidation {
    Write-Section "Service Validation"
    
    $results = @()
    
    # Test 1: Telnet Service
    Write-ColorOutput "Testing Telnet Service:" -Color Yellow
    
    # Method 1: Get-Service
    $service = Get-Service -Name "TelnetClient" -ErrorAction SilentlyContinue
    if ($service) {
        $serviceResult = Compare-Values -TestName "Get-Service" -ExpectedValue "Stopped" -ActualValue $service.Status -Method "Get-Service"
        $results += $serviceResult
    }
    
    # Method 2: sc command
    $scOutput = sc query "TelnetClient" 2>&1
    if ($scOutput -match "STATE.*:.*STOPPED") {
        $scResult = Compare-Values -TestName "SC Command" -ExpectedValue "STOPPED" -ActualValue "STOPPED" -Method "sc query"
        $results += $scResult
    }
    
    return $results
}

# Function to generate validation report
function Write-ValidationReport {
    param($Results, $OutputPath)
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $computerName = $env:COMPUTERNAME
    
    $report = @"
WASP - Check Validation Report
Generated: $timestamp
Computer: $computerName

VALIDATION SUMMARY
==================

"@
    
    $totalTests = $Results.Count
    $passedTests = ($Results | Where-Object { $_.Status -eq "PASS" }).Count
    $failedTests = $totalTests - $passedTests
    $passRate = if ($totalTests -gt 0) { [math]::Round(($passedTests / $totalTests) * 100, 2) } else { 0 }
    
    $report += "Total Tests: $totalTests`n"
    $report += "Passed: $passedTests`n"
    $report += "Failed: $failedTests`n"
    $report += "Pass Rate: $passRate%`n`n"
    
    $report += "DETAILED RESULTS`n"
    $report += ("=" * 80) + "`n`n"
    
    foreach ($result in $Results) {
        $report += "Test: $($result.TestName)`n"
        $report += "Status: $($result.Status)`n"
        $report += "Expected: $($result.Expected)`n"
        $report += "Actual: $($result.Actual)`n"
        $report += "Method: $($result.Method)`n"
        $report += "-" * 40 + "`n`n"
    }
    
    # Write to file
    $report | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-ColorOutput "Validation report saved to: $OutputPath" -Color Green
}

# Main execution
Write-ColorOutput "WASP - Check Validation Script" -Color Cyan
Write-ColorOutput "Validating scanner accuracy against known good values" -Color Cyan
Write-ColorOutput "Version: 1.0.0`n" -Color Cyan

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-ColorOutput "WARNING: This script should be run as Administrator for best results." -Color Yellow
}

# Initialize results array
$allResults = @()

# Run validation tests based on parameters
if ($TestSecurityPolicy -or $AllTests) {
    $allResults += Test-SecurityPolicyValidation
}

if ($TestRegistry -or $AllTests) {
    $allResults += Test-RegistryValidation
}

if ($TestAuditPolicy -or $AllTests) {
    $allResults += Test-AuditPolicyValidation
}

if ($TestServices -or $AllTests) {
    $allResults += Test-ServiceValidation
}

# If no specific tests selected, run all
if (-not ($TestSecurityPolicy -or $TestRegistry -or $TestAuditPolicy -or $TestServices -or $AllTests)) {
    Write-ColorOutput "No specific tests selected. Running all validation tests..." -Color Yellow
    $allResults += Test-SecurityPolicyValidation
    $allResults += Test-RegistryValidation
    $allResults += Test-AuditPolicyValidation
    $allResults += Test-ServiceValidation
}

# Generate validation report
Write-Section "Generating Validation Report"
Write-ValidationReport -Results $allResults -OutputPath $OutputPath

# Final summary
$passedCount = ($allResults | Where-Object { $_.Status -eq "PASS" }).Count
$totalCount = $allResults.Count
$passRate = if ($totalCount -gt 0) { [math]::Round(($passedCount / $totalCount) * 100, 2) } else { 0 }

Write-ColorOutput "`nVALIDATION COMPLETED" -Color Cyan
Write-ColorOutput "Total Tests: $totalCount" -Color White
Write-ColorOutput "Passed: $passedCount" -Color Green
Write-ColorOutput "Failed: $($totalCount - $passedCount)" -Color Red
Write-ColorOutput "Pass Rate: $passRate%" -Color $(if ($passRate -ge 90) { "Green" } elseif ($passRate -ge 70) { "Yellow" } else { "Red" })
Write-ColorOutput "Validation report saved to: $OutputPath" -Color Green 