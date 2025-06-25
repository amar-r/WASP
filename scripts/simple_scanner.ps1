# Simple WISP Scanner
# Reads JSON baseline and checks Windows settings accordingly

param(
    [string]$BaselinePath = "baselines\cis-windows-server-2022-member-server.json",
    [string]$OutputPath = "reports\simple_results.txt"
)

# Ensure output directory exists
$OutputDir = Split-Path $OutputPath -Parent
if (!(Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Write-Host "Simple WISP Scanner Starting..." -ForegroundColor Green
Write-Host "Baseline: $BaselinePath" -ForegroundColor Yellow
Write-Host "Output: $OutputPath" -ForegroundColor Yellow

# Load and parse JSON baseline
try {
    $jsonContent = Get-Content $BaselinePath -Raw | ConvertFrom-Json
    $rules = $jsonContent.rules
    Write-Host "Loaded $($rules.Count) rules from baseline" -ForegroundColor Green
} catch {
    Write-Error "Failed to load baseline: $_"
    exit 1
}

# Initialize results
$results = @()
$totalRules = $rules.Count
$compliantRules = 0
$nonCompliantRules = 0

# Get current system info
$computerName = $env:COMPUTERNAME
$osInfo = Get-WmiObject -Class Win32_OperatingSystem
$osName = "$($osInfo.Caption) $($osInfo.OSArchitecture)"

# Export security policy for secpol checks
Write-Host "Exporting security policy..." -ForegroundColor Yellow
$secpolFile = [System.IO.Path]::GetTempPath() + "\secpol_export.inf"
try {
    secedit /export /cfg $secpolFile | Out-Null
    $secpolContent = Get-Content $secpolFile -Raw
    Write-Host "Security policy exported successfully" -ForegroundColor Green
} catch {
    Write-Warning "Failed to export security policy: $_"
    $secpolContent = ""
}

# Get audit policy for auditpol checks
Write-Host "Getting audit policy..." -ForegroundColor Yellow
try {
    $auditpolOutput = auditpol /get /category:* | Out-String
    Write-Host "Audit policy retrieved successfully" -ForegroundColor Green
} catch {
    Write-Warning "Failed to get audit policy: $_"
    $auditpolOutput = ""
}

# Function to check security policy settings
function Test-SecurityPolicy {
    param($rule, $secpolContent)
    
    $currentValue = ""
    $status = "FAIL"
    $details = "Setting not found in security policy"
    
    # Extract setting name from title (simple approach)
    $title = $rule.title
    if ($title -match "Ensure '([^']+)'") {
        $settingName = $matches[1]
        
        # Look for the setting in secpol content
        if ($secpolContent -and $secpolContent -match "(?s)$settingName\s*=\s*(.+)") {
            $currentValue = $matches[1].Trim()
            $status = "PASS"
            $details = "Found in security policy"
        }
    }
    
    return @{
        CurrentValue = $currentValue
        Status = $status
        Details = $details
    }
}

# Function to check registry settings
function Test-Registry {
    param($rule)
    
    $currentValue = ""
    $status = "FAIL"
    $details = "Registry value not found"
    
    # Extract registry path from audit_procedure
    if ($rule.audit_procedure -and $rule.audit_procedure -match "(.+):(.+)") {
        $regPath = $matches[1]
        $regName = $matches[2]
        
        try {
            $regValue = Get-ItemProperty -Path "Registry::$regPath" -Name $regName -ErrorAction SilentlyContinue
            if ($regValue) {
                $currentValue = $regValue.$regName
                $status = "PASS"
                $details = "Registry value found"
            }
        } catch {
            $details = "Registry value not accessible or does not exist"
        }
    } else {
        $details = "Missing required registry path or name"
    }
    
    return @{
        CurrentValue = $currentValue
        Status = $status
        Details = $details
    }
}

# Function to check audit policy settings
function Test-AuditPolicy {
    param($rule, $auditpolOutput)
    
    $currentValue = ""
    $status = "FAIL"
    $details = "Audit policy setting not found"
    
    # Extract setting name from title (simple approach)
    $title = $rule.title
    if ($title -match "Ensure '([^']+)'") {
        $settingName = $matches[1]
        
        # Look for the setting in auditpol output
        if ($auditpolOutput -and $auditpolOutput -match "(?s)$settingName\s+(.+)") {
            $currentValue = $matches[1].Trim()
            $status = "PASS"
            $details = "Found in audit policy"
        }
    }
    
    return @{
        CurrentValue = $currentValue
        Status = $status
        Details = $details
    }
}

# Process each rule
Write-Host "Processing rules..." -ForegroundColor Yellow
$progress = 0

foreach ($rule in $rules) {
    $progress++
    if ($progress % 50 -eq 0) {
        Write-Progress -Activity "Scanning Rules" -Status "Processing rule $progress of $totalRules" -PercentComplete (($progress / $totalRules) * 100)
    }
    
    # Skip rules marked to skip
    if ($rule.skip -eq $true) {
        continue
    }
    
    $result = @{
        RuleID = $rule.id
        Title = $rule.title
        Type = $rule.check_type
        ExpectedValue = $rule.expected_value
        CurrentValue = ""
        Status = "FAIL"
        Details = ""
        Error = ""
    }
    
    # Check based on type
    switch ($rule.check_type) {
        "secpol" {
            $checkResult = Test-SecurityPolicy -rule $rule -secpolContent $secpolContent
            $result.CurrentValue = $checkResult.CurrentValue
            $result.Status = $checkResult.Status
            $result.Details = $checkResult.Details
        }
        "registry" {
            $checkResult = Test-Registry -rule $rule
            $result.CurrentValue = $checkResult.CurrentValue
            $result.Status = $checkResult.Status
            $result.Details = $checkResult.Details
        }
        "auditpol" {
            $checkResult = Test-AuditPolicy -rule $rule -auditpolOutput $auditpolOutput
            $result.CurrentValue = $checkResult.CurrentValue
            $result.Status = $checkResult.Status
            $result.Details = $checkResult.Details
        }
        default {
            $result.Details = "Unknown check type: $($rule.check_type)"
        }
    }
    
    # Count results
    if ($result.Status -eq "PASS") {
        $compliantRules++
    } else {
        $nonCompliantRules++
    }
    
    $results += $result
}

Write-Progress -Activity "Scanning Rules" -Completed

# Calculate compliance rate
$complianceRate = if ($totalRules -gt 0) { [math]::Round(($compliantRules / $totalRules) * 100, 2) } else { 0 }

# Generate report
Write-Host "Generating report..." -ForegroundColor Yellow

$report = @"
Simple WISP Scanner Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Computer: $computerName
OS: $osName

SUMMARY
=======
Total Rules: $totalRules
Compliant: $compliantRules
Non-Compliant: $nonCompliantRules
Compliance Rate: $complianceRate%

DETAILED RESULTS
================================================================================

"@

foreach ($result in $results) {
    $report += @"

Rule ID: $($result.RuleID)
Title: $($result.Title)
Type: $($result.Type)
Status: $($result.Status)
Current Value: $($result.CurrentValue)
Expected Value: $($result.ExpectedValue)
Details: $($result.Details)
$($(if($result.Error){"Error: $($result.Error)"}else{""}))
--------------------------------------------------------------------------------
"@
}

# Write report to file
$report | Out-File -FilePath $OutputPath -Encoding UTF8

# Clean up temporary files
if (Test-Path $secpolFile) {
    Remove-Item $secpolFile -Force
}

# Display summary
Write-Host "`nScan Complete!" -ForegroundColor Green
Write-Host "Total Rules: $totalRules" -ForegroundColor White
Write-Host "Compliant: $compliantRules" -ForegroundColor Green
Write-Host "Non-Compliant: $nonCompliantRules" -ForegroundColor Red
Write-Host "Compliance Rate: $complianceRate%" -ForegroundColor Yellow
Write-Host "Report saved to: $OutputPath" -ForegroundColor Cyan 