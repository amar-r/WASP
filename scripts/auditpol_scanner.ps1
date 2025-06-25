# AuditPol-Only WISP Scanner
# Checks only auditpol rules from the CIS JSON baseline

param(
    [string]$BaselinePath = "baselines\cis-windows-server-2022-member-server.json",
    [string]$OutputPath = "reports\auditpol_results.txt"
)

# Ensure output directory exists
$OutputDir = Split-Path $OutputPath -Parent
if (!(Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Write-Host "AuditPol-Only WISP Scanner Starting..." -ForegroundColor Green
Write-Host "Baseline: $BaselinePath" -ForegroundColor Yellow
Write-Host "Output: $OutputPath" -ForegroundColor Yellow

# Load and parse JSON baseline
try {
    $jsonContent = Get-Content $BaselinePath -Raw | ConvertFrom-Json
    $rules = $jsonContent.rules | Where-Object { $_.check_type -eq "auditpol" -and !$_.skip }
    Write-Host "Loaded $($rules.Count) auditpol rules from baseline" -ForegroundColor Green
} catch {
    Write-Error "Failed to load baseline: $_"
    exit 1
}

# Get audit policy for auditpol checks
Write-Host "Getting audit policy..." -ForegroundColor Yellow
try {
    $auditpolOutput = auditpol /get /category:* 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Audit policy retrieved successfully" -ForegroundColor Green
    } else {
        Write-Warning "auditpol failed with exit code $LASTEXITCODE"
        $auditpolOutput = ""
    }
} catch {
    Write-Warning "Failed to get audit policy: $_"
    $auditpolOutput = ""
}

# Function to check audit policy settings
function Test-AuditPolicy {
    param($rule, $auditpolOutput)
    
    $currentValue = ""
    $status = "FAIL"
    $details = "Audit policy setting not found"
    
    if (-not $auditpolOutput) {
        $details = "Audit policy export failed or is empty"
        return @{
            CurrentValue = $currentValue
            Status = $status
            Details = $details
        }
    }
    
    # Extract setting name from title (simple approach)
    $title = $rule.title
    if ($title -match "Ensure '([^']+)'") {
        $settingName = $matches[1]
        
        # Look for the setting in auditpol output - try multiple patterns
        $patterns = @(
            "(?s)$settingName\s+(.+)",
            "(?s)$settingName\s+(.+?)(?:\r?\n|$)",
            "(?s)$settingName\s+(.+?)(?:\r?\n\s*\r?\n|$)"
        )
        
        foreach ($pattern in $patterns) {
            if ($auditpolOutput -match $pattern) {
                $currentValue = $matches[1].Trim()
                $status = "PASS"
                $details = "Found in audit policy"
                break
            }
        }
        
        if ($status -eq "FAIL") {
            $details = "Setting '$settingName' not found in audit policy output"
        }
    } else {
        $details = "Could not extract setting name from title: $title"
    }
    
    return @{
        CurrentValue = $currentValue
        Status = $status
        Details = $details
    }
}

# Process each auditpol rule
Write-Host "Processing auditpol rules..." -ForegroundColor Yellow
$results = @()
$progress = 0
$totalRules = $rules.Count
$compliantRules = 0
$nonCompliantRules = 0

foreach ($rule in $rules) {
    $progress++
    if ($progress % 10 -eq 0) {
        Write-Progress -Activity "Scanning AuditPol Rules" -Status "Processing rule $progress of $totalRules" -PercentComplete (($progress / $totalRules) * 100)
    }
    
    $result = @{
        RuleID = $rule.id
        Title = $rule.title
        ExpectedValue = $rule.expected_value
        CurrentValue = ""
        Status = "FAIL"
        Details = ""
    }
    
    $checkResult = Test-AuditPolicy -rule $rule -auditpolOutput $auditpolOutput
    $result.CurrentValue = $checkResult.CurrentValue
    $result.Status = $checkResult.Status
    $result.Details = $checkResult.Details
    
    if ($result.Status -eq "PASS") {
        $compliantRules++
    } else {
        $nonCompliantRules++
    }
    
    $results += $result
}

Write-Progress -Activity "Scanning AuditPol Rules" -Completed

# Calculate compliance rate
$complianceRate = if ($totalRules -gt 0) { [math]::Round(($compliantRules / $totalRules) * 100, 2) } else { 0 }

# Generate report
Write-Host "Generating report..." -ForegroundColor Yellow

$report = @"
AuditPol-Only WISP Scanner Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

SUMMARY
=======
Total AuditPol Rules: $totalRules
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
Status: $($result.Status)
Current Value: $($result.CurrentValue)
Expected Value: $($result.ExpectedValue)
Details: $($result.Details)
--------------------------------------------------------------------------------
"@
}

# Write report to file
$report | Out-File -FilePath $OutputPath -Encoding UTF8

# Display summary
Write-Host "`nScan Complete!" -ForegroundColor Green
Write-Host "Total AuditPol Rules: $totalRules" -ForegroundColor White
Write-Host "Compliant: $compliantRules" -ForegroundColor Green
Write-Host "Non-Compliant: $nonCompliantRules" -ForegroundColor Red
Write-Host "Compliance Rate: $complianceRate%" -ForegroundColor Yellow
Write-Host "Report saved to: $OutputPath" -ForegroundColor Cyan 