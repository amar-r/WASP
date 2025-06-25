# AuditPol Scanner using GPResult XML
# Checks auditpol rules using structured XML data from gpresult

param(
    [string]$BaselinePath = "baselines\cis-windows-server-2022-member-server.json",
    [string]$OutputPath = "reports\auditpol_gpresult_results.txt",
    [string]$GpResultXmlPath = "reports\gpresult.xml"
)

# Ensure output directory exists
$OutputDir = Split-Path $OutputPath -Parent
if (!(Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Write-Host "AuditPol GPResult Scanner Starting..." -ForegroundColor Green
Write-Host "Baseline: $BaselinePath" -ForegroundColor Yellow
Write-Host "Output: $OutputPath" -ForegroundColor Yellow
Write-Host "GPResult XML: $GpResultXmlPath" -ForegroundColor Yellow

# Load and parse JSON baseline
try {
    $jsonContent = Get-Content $BaselinePath -Raw | ConvertFrom-Json
    $rules = $jsonContent.rules | Where-Object { $_.check_type -eq "auditpol" -and !$_.skip }
    Write-Host "Loaded $($rules.Count) auditpol rules from baseline" -ForegroundColor Green
} catch {
    Write-Error "Failed to load baseline: $_"
    exit 1
}

# Get GPResult XML data
Write-Host "Getting GPResult XML data..." -ForegroundColor Yellow
try {
    # Run gpresult to get XML output
    $gpresultResult = gpresult /xml $GpResultXmlPath 2>&1
    if ($LASTEXITCODE -eq 0) {
        if (Test-Path $GpResultXmlPath) {
            Write-Host "GPResult XML exported successfully to $GpResultXmlPath" -ForegroundColor Green
            Write-Host "File size: $((Get-Item $GpResultXmlPath).Length) bytes" -ForegroundColor Cyan
            
            # Load and parse XML
            $xmlContent = [xml](Get-Content $GpResultXmlPath -Raw)
            Write-Host "XML parsed successfully" -ForegroundColor Green
        } else {
            Write-Warning "GPResult XML file was not created"
            $xmlContent = $null
        }
    } else {
        Write-Warning "gpresult failed with exit code $LASTEXITCODE"
        Write-Warning "Output: $gpresultResult"
        $xmlContent = $null
    }
} catch {
    Write-Warning "Failed to get GPResult XML: $_"
    $xmlContent = $null
}

# Function to extract audit policy settings from XML
function Get-AuditPolicyFromXml {
    param($xmlContent)
    
    $auditSettings = @{}
    
    if (-not $xmlContent) {
        return $auditSettings
    }
    
    try {
        # Navigate through XML structure to find audit policy settings
        # The exact path depends on the XML structure from gpresult
        
        # Try different possible paths for audit policy settings
        $possiblePaths = @(
            "//AuditPolicy",
            "//AuditPolicySettings", 
            "//SecuritySettings/AuditPolicy",
            "//ComputerSettings/SecuritySettings/AuditPolicy",
            "//RsopData/ComputerResults/ExtensionData/Extension/AuditPolicy"
        )
        
        foreach ($path in $possiblePaths) {
            $nodes = $xmlContent.SelectNodes($path)
            if ($nodes -and $nodes.Count -gt 0) {
                Write-Host "Found audit policy data at path: $path" -ForegroundColor Green
                
                # Extract settings from the nodes
                foreach ($node in $nodes) {
                    if ($node.Name) {
                        $auditSettings[$node.Name] = $node.InnerText
                    }
                    # Also check child nodes
                    foreach ($child in $node.ChildNodes) {
                        if ($child.Name) {
                            $auditSettings[$child.Name] = $child.InnerText
                        }
                    }
                }
                break
            }
        }
        
        # If no audit policy found in XML, try to get it from auditpol command as fallback
        if ($auditSettings.Count -eq 0) {
            Write-Host "No audit policy found in XML, trying auditpol command..." -ForegroundColor Yellow
            $auditpolOutput = auditpol /get /category:* 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0) {
                # Parse auditpol output into hashtable
                $lines = $auditpolOutput -split "`r?`n"
                foreach ($line in $lines) {
                    if ($line -match "^\s*([^:]+):\s*(.+)$") {
                        $settingName = $matches[1].Trim()
                        $settingValue = $matches[2].Trim()
                        $auditSettings[$settingName] = $settingValue
                    }
                }
                Write-Host "Extracted $($auditSettings.Count) settings from auditpol output" -ForegroundColor Green
            }
        }
        
    } catch {
        Write-Warning "Error parsing XML: $_"
    }
    
    return $auditSettings
}

# Function to check audit policy settings
function Test-AuditPolicy {
    param($rule, $auditSettings)
    
    $currentValue = ""
    $status = "FAIL"
    $details = "Audit policy setting not found"
    
    if (-not $auditSettings -or $auditSettings.Count -eq 0) {
        $details = "No audit policy data available"
        return @{
            CurrentValue = $currentValue
            Status = $status
            Details = $details
        }
    }
    
    # Extract setting name from title
    $title = $rule.title
    if ($title -match "Ensure '([^']+)'") {
        $settingName = $matches[1]
        
        # Try to find the setting in our audit settings hashtable
        if ($auditSettings.ContainsKey($settingName)) {
            $currentValue = $auditSettings[$settingName]
            $status = "PASS"
            $details = "Found in audit policy data"
        } else {
            # Try partial matches
            $matchingKeys = $auditSettings.Keys | Where-Object { $_ -like "*$settingName*" -or $settingName -like "*$_*" }
            if ($matchingKeys) {
                $currentValue = "Multiple matches found: $($matchingKeys -join ', ')"
                $status = "PASS"
                $details = "Found partial matches in audit policy data"
            } else {
                $details = "Setting '$settingName' not found in audit policy data"
            }
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

# Get audit policy settings from XML
$auditSettings = Get-AuditPolicyFromXml -xmlContent $xmlContent

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
    
    $checkResult = Test-AuditPolicy -rule $rule -auditSettings $auditSettings
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
AuditPol GPResult Scanner Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

SUMMARY
=======
Total AuditPol Rules: $totalRules
Compliant: $compliantRules
Non-Compliant: $nonCompliantRules
Compliance Rate: $complianceRate%
Audit Settings Found: $($auditSettings.Count)

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
Write-Host "Audit Settings Found: $($auditSettings.Count)" -ForegroundColor Cyan
Write-Host "Report saved to: $OutputPath" -ForegroundColor Cyan
Write-Host "GPResult XML saved to: $GpResultXmlPath" -ForegroundColor Cyan 