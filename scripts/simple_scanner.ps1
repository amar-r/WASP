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
$secpolFile = "reports\secpol_export.inf"
try {
    # Run secedit export and capture output
    $seceditResult = secedit /export /cfg $secpolFile 2>&1
    if ($LASTEXITCODE -eq 0) {
        if (Test-Path $secpolFile) {
            $secpolContent = Get-Content $secpolFile -Raw -ErrorAction SilentlyContinue
            if ($secpolContent) {
                Write-Host "Security policy exported successfully to $secpolFile" -ForegroundColor Green
                Write-Host "File size: $((Get-Item $secpolFile).Length) bytes" -ForegroundColor Cyan
            } else {
                Write-Warning "Security policy file is empty"
                $secpolContent = ""
            }
        } else {
            Write-Warning "Security policy file was not created"
            $secpolContent = ""
        }
    } else {
        Write-Warning "secedit export failed with exit code $LASTEXITCODE"
        Write-Warning "Output: $seceditResult"
        $secpolContent = ""
    }
} catch {
    Write-Warning "Failed to export security policy: $_"
    $secpolContent = ""
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

# Function to check security policy settings
function Test-SecurityPolicy {
    param($rule, $secpolContent)
    
    $currentValue = ""
    $status = "FAIL"
    $details = "Setting not found in security policy"
    
    if (-not $secpolContent) {
        $details = "Security policy export failed or is empty"
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
        
        # Look for the setting in secpol content - try multiple patterns
        $patterns = @(
            "(?s)$settingName\s*=\s*(.+)",
            "(?s)$settingName\s*=\s*(.+?)(?:\r?\n|$)",
            "(?s)$settingName\s*=\s*(.+?)(?:\r?\n\s*\r?\n|$)"
        )
        
        foreach ($pattern in $patterns) {
            if ($secpolContent -match $pattern) {
                $currentValue = $matches[1].Trim()
                $status = "PASS"
                $details = "Found in security policy"
                break
            }
        }
        
        if ($status -eq "FAIL") {
            $details = "Setting '$settingName' not found in security policy export"
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
            } else {
                $details = "Registry value not found at $regPath\$regName"
            }
        } catch {
            $details = "Registry value not accessible or does not exist: $regPath\$regName"
        }
    } else {
        $details = "Missing required registry path or name in audit_procedure: $($rule.audit_procedure)"
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

# Keep the secpol file for debugging (don't delete it)
Write-Host "Security policy export saved to: $secpolFile" -ForegroundColor Cyan

# Display summary
Write-Host "`nScan Complete!" -ForegroundColor Green
Write-Host "Total Rules: $totalRules" -ForegroundColor White
Write-Host "Compliant: $compliantRules" -ForegroundColor Green
Write-Host "Non-Compliant: $nonCompliantRules" -ForegroundColor Red
Write-Host "Compliance Rate: $complianceRate%" -ForegroundColor Yellow
Write-Host "Report saved to: $OutputPath" -ForegroundColor Cyan 