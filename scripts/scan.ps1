# WASP - Windows Audit & Security Profiler
# CIS Compliance Scanner for Windows Server Systems
# Version: 1.0.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$BaselinePath = ".\baselines\cis-windows-server-2022-member-server.json",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\reports\wasp-scan-$(Get-Date -Format 'yyyy-MM-dd-HHmm').txt",
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipRegistry,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipSecurityPolicy,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipAuditPolicy,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipServices,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Level1", "Level2", "Both")]
    [string]$CISLevel = "Both"
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
    Write-ColorOutput "SECTION: $Title" -Color Cyan
    Write-ColorOutput ("=" * 80) -Color Cyan
    Write-ColorOutput "`n" -Color Cyan
}

# Function to check if baseline file exists
function Test-BaselineFile {
    param($Path)
    if (!(Test-Path $Path)) {
        Write-ColorOutput "ERROR: Baseline file not found: $Path" -Color Red
        Write-ColorOutput "Please ensure the baseline file exists and the path is correct." -Color Red
        exit 1
    }
}

# Function to load and parse JSON baseline
function Load-Baseline {
    param($Path)
    try {
        $baseline = Get-Content $Path -Raw | ConvertFrom-Json
        
        # Handle different baseline structures
        if ($baseline.metadata) {
            # New structure with metadata
            $baselineName = "CIS Windows Server 2022 Member Server (from metadata)"
            $totalRules = $baseline.rules.Count
        } else {
            # Direct structure
            $baselineName = $baseline.name
            $totalRules = $baseline.rules.Count
        }
        
        Write-ColorOutput "Loaded baseline: $baselineName" -Color Green
        Write-ColorOutput "Total rules: $totalRules" -Color Green
        return $baseline
    }
    catch {
        Write-ColorOutput "ERROR: Failed to parse baseline file: $($_.Exception.Message)" -Color Red
        exit 1
    }
}

# Function to generate report
function Write-Report {
    param($Results, $OutputPath)
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $computerName = $env:COMPUTERNAME
    $osInfo = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsArchitecture
    
    $report = @"
WASP - Windows Audit & Security Profiler Report
Generated: $timestamp
Computer: $computerName
OS: $($osInfo.WindowsProductName) $($osInfo.WindowsVersion) ($($osInfo.OsArchitecture))

"@
    
    # Summary
    $totalRules = $Results.Count
    $compliantRules = ($Results | Where-Object { $_.Compliant }).Count
    $nonCompliantRules = $totalRules - $compliantRules
    $complianceRate = if ($totalRules -gt 0) { [math]::Round(($compliantRules / $totalRules) * 100, 2) } else { 0 }
    
    $report += @"

SUMMARY
=======
Total Rules: $totalRules
Compliant: $compliantRules
Non-Compliant: $nonCompliantRules
Compliance Rate: $complianceRate%

"@
    
    # Detailed Results
    $report += "DETAILED RESULTS`n"
    $report += ("=" * 80) + "`n`n"
    
    foreach ($result in $Results) {
        $status = if ($result.Compliant) { "PASS" } else { "FAIL" }
        $report += "Rule ID: $($result.RuleId)`n"
        $report += "Title: $($result.Title)`n"
        $report += "Type: $($result.CheckType)`n"
        $report += "Status: $status`n"
        
        if ($result.CheckType -eq "Registry") {
            $report += "Current Value: $($result.CurrentValue)`n"
            $report += "Expected Value: $($result.ExpectedValue)`n"
        } elseif ($result.CheckType -eq "Service") {
            $report += "Current Status: $($result.CurrentStatus)`n"
            $report += "Current Start Type: $($result.CurrentStartType)`n"
            if ($result.ExpectedStartType) {
                $report += "Expected Start Type: $($result.ExpectedStartType)`n"
            }
        } elseif ($result.CheckType -eq "AuditPolicy") {
            $report += "Current Setting: $($result.CurrentSetting)`n"
            $report += "Expected Setting: $($result.ExpectedSetting)`n"
        } elseif ($result.CheckType -eq "SecurityPolicy") {
            $report += "Current Value: $($result.CurrentValue)`n"
            $report += "Expected Value: $($result.ExpectedValue)`n"
        }
        
        $report += "Details: $($result.Details)`n"
        if ($result.Error) {
            $report += "Error: $($result.Error)`n"
        }
        $report += "-" * 80 + "`n`n"
    }
    
    # Write to file
    $report | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-ColorOutput "Report saved to: $OutputPath" -Color Green
}

# Function to clean up text encoding issues
function Clean-Text {
    param([string]$Text)
    
    if ([string]::IsNullOrEmpty($Text)) {
        return $Text
    }
    
    # Just return the text as-is to avoid encoding issues
    return $Text
}

# Function to filter rules by CIS level
function Filter-RulesByLevel {
    param(
        [array]$Rules,
        [string]$Level
    )
    
    switch ($Level) {
        "Level1" {
            return $Rules | Where-Object { $_.level -eq "Level 1" }
        }
        "Level2" {
            return $Rules | Where-Object { $_.level -eq "Level 2" }
        }
        "Both" {
            return $Rules
        }
        default {
            return $Rules
        }
    }
}

# Main execution
Write-ColorOutput "WASP - Windows Audit & Security Profiler" -Color Cyan
Write-ColorOutput "CIS Compliance Scanner for Windows Server Systems" -Color Cyan
Write-ColorOutput "Version: 1.0.0`n" -Color Cyan

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-ColorOutput "WARNING: This script should be run as Administrator for best results." -Color Yellow
}

# Load baseline
Write-Section "Loading Baseline"
Test-BaselineFile -Path $BaselinePath
$baseline = Load-Baseline -Path $BaselinePath

# Filter rules by CIS level
$filteredRules = Filter-RulesByLevel -Rules $baseline.rules -Level $CISLevel
Write-ColorOutput "CIS Level Filter: $CISLevel" -Color Cyan
Write-ColorOutput "Filtered rules: $($filteredRules.Count)" -Color Green

# Initialize results array
$results = @()

# Export security policy (for security policy checks)
Write-Section "Exporting Security Policy"
$securityPolicy = Export-SecurityPolicy
if ($securityPolicy) {
    Write-ColorOutput "Security policy exported successfully" -Color Green
} else {
    Write-ColorOutput "Warning: Failed to export security policy" -Color Yellow
}

# Get audit policy settings
Write-Section "Retrieving Audit Policy Settings"
$auditPolicy = Get-AuditPolicySettings
if ($auditPolicy) {
    Write-ColorOutput "Audit policy retrieved successfully" -Color Green
} else {
    Write-ColorOutput "Warning: Failed to retrieve audit policy" -Color Yellow
}

# Process rules
Write-Section "Processing Rules"
$processedCount = 0

foreach ($rule in $filteredRules) {
    try {
        if ($rule.skip -eq $true) {
            Write-ColorOutput "Skipping rule $($rule.id) - marked as skip" -Color Yellow
            continue
        }
        
        $processedCount++
        Write-Progress -Activity "Processing Rules" -Status "Processing rule $($rule.id)" -PercentComplete (($processedCount / $filteredRules.Count) * 100)
        
        # Clean up the title to handle encoding issues
        $cleanTitle = Clean-Text -Text $rule.title
        
        switch ($rule.check_type) {
            "registry" {
                if (-not $SkipRegistry) {
                    $result = Test-RegistryCompliance -Rule $rule -PolicyContent $securityPolicy
                    $results += $result
                    
                    $status = if ($result.Compliant) { "PASS" } else { "FAIL" }
                    Write-ColorOutput "Rule $($rule.id): $status - $cleanTitle" -Color $(if ($result.Compliant) { "Green" } else { "Red" })
                }
            }
            "service" {
                if (-not $SkipServices) {
                    $result = Test-ServiceCompliance -Rule $rule
                    $results += $result
                    
                    $status = if ($result.Compliant) { "PASS" } else { "FAIL" }
                    Write-ColorOutput "Rule $($rule.id): $status - $cleanTitle" -Color $(if ($result.Compliant) { "Green" } else { "Red" })
                }
            }
            "audit_policy" {
                if (-not $SkipAuditPolicy) {
                    $result = Test-AuditPolicyCompliance -Rule $rule -AuditPolicyOutput $auditPolicy
                    $results += $result
                    
                    $status = if ($result.Compliant) { "PASS" } else { "FAIL" }
                    Write-ColorOutput "Rule $($rule.id): $status - $cleanTitle" -Color $(if ($result.Compliant) { "Green" } else { "Red" })
                }
            }
            "secpol" {
                if (-not $SkipSecurityPolicy) {
                    $result = Test-SecurityPolicyCompliance -Rule $rule -PolicyContent $securityPolicy
                    $results += $result
                    $status = if ($result.Compliant) { "PASS" } else { "FAIL" }
                    Write-ColorOutput "Rule $($rule.id): $status - $cleanTitle" -Color $(if ($result.Compliant) { "Green" } else { "Red" })
                }
            }
            "auditpol" {
                if (-not $SkipAuditPolicy) {
                    $result = Test-AuditPolicyCompliance -Rule $rule -AuditPolicyOutput $auditPolicy
                    $results += $result
                    $status = if ($result.Compliant) { "PASS" } else { "FAIL" }
                    Write-ColorOutput "Rule $($rule.id): $status - $cleanTitle" -Color $(if ($result.Compliant) { "Green" } else { "Red" })
                }
            }
            "security_policy" {
                if (-not $SkipSecurityPolicy) {
                    $result = Test-SecurityPolicyCompliance -Rule $rule -PolicyContent $securityPolicy
                    $results += $result
                    $status = if ($result.Compliant) { "PASS" } else { "FAIL" }
                    Write-ColorOutput "Rule $($rule.id): $status - $cleanTitle" -Color $(if ($result.Compliant) { "Green" } else { "Red" })
                }
            }
            default {
                Write-ColorOutput "Warning: Unknown check type '$($rule.check_type)' for rule $($rule.id)" -Color Yellow
            }
        }
    }
    catch {
        Write-ColorOutput "ERROR: Failed to process rule $($rule.id): $($_.Exception.Message)" -Color Red
        Write-ColorOutput "Continuing with next rule..." -Color Yellow
        continue
    }
}

Write-Progress -Activity "Processing Rules" -Completed

# Generate report
Write-Section "Generating Report"
Write-Report -Results $results -OutputPath $OutputPath

# Final summary
$compliantCount = ($results | Where-Object { $_.Compliant }).Count
$totalCount = $results.Count
$complianceRate = if ($totalCount -gt 0) { [math]::Round(($compliantCount / $totalCount) * 100, 2) } else { 0 }

Write-ColorOutput "`nSCAN COMPLETED" -Color Cyan
Write-ColorOutput "CIS Level: $CISLevel" -Color White
Write-ColorOutput "Total Rules Processed: $totalCount" -Color White
Write-ColorOutput "Compliant: $compliantCount" -Color Green
Write-ColorOutput "Non-Compliant: $($totalCount - $compliantCount)" -Color Red
Write-ColorOutput "Compliance Rate: $complianceRate%" -Color $(if ($complianceRate -ge 80) { "Green" } elseif ($complianceRate -ge 60) { "Yellow" } else { "Red" })
Write-ColorOutput "Report saved to: $OutputPath" -Color Green 