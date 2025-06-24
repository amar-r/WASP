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

# Function to get registry value using JSON output
function Get-RegistryValue {
    param($Path, $Name)
    try {
        $result = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue | ConvertTo-Json -Compress
        if ($result -eq "{}" -or $result -eq "") {
            return $null
        }
        $json = $result | ConvertFrom-Json
        return $json.$Name
    }
    catch {
        return $null
    }
}

# Function to get registry value from security policy export
function Get-SecurityPolicyValue {
    param($RegistryPath, $PolicyContent)
    $pattern = [regex]::Escape($RegistryPath) + "=\d+,(.+)"
    $match = [regex]::Match($PolicyContent, $pattern)
    if ($match.Success) {
        return $match.Groups[1].Value.Trim('"')
    }
    return $null
}

# Function to check registry compliance
function Test-RegistryCompliance {
    param($Rule, $PolicyContent)
    
    $result = @{
        RuleId = $Rule.id
        Title = $Rule.title
        CheckType = "Registry"
        Compliant = $false
        CurrentValue = $null
        ExpectedValue = $Rule.expected_value
        Details = ""
    }
    
    try {
        $registryPath = $Rule.target
        $registryName = $Rule.registry_name
        
        # Try security policy first (more reliable)
        if ($PolicyContent) {
            $currentValue = Get-SecurityPolicyValue -RegistryPath $registryPath -PolicyContent $PolicyContent
            if ($currentValue -ne $null) {
                $result.CurrentValue = $currentValue
                $result.Details = "Found in security policy export"
            }
        }
        
        # Fallback to direct registry query
        if ($result.CurrentValue -eq $null) {
            $currentValue = Get-RegistryValue -Path $registryPath -Name $registryName
            $result.CurrentValue = $currentValue
            $result.Details = "Found via direct registry query"
        }
        
        # Check compliance
        if ($result.CurrentValue -ne $null) {
            $result.Compliant = ($result.CurrentValue -eq $result.ExpectedValue)
        } else {
            $result.Details = "Registry value not found"
        }
    }
    catch {
        $result.Details = "Error: $($_.Exception.Message)"
        Write-ColorOutput "Warning: Error processing registry rule $($Rule.id): $($_.Exception.Message)" -Color Yellow
    }
    
    return $result
}

# Function to get service status using JSON output
function Get-ServiceStatus {
    param($ServiceName)
    try {
        $result = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | ConvertTo-Json -Compress
        if ($result -eq "{}" -or $result -eq "") {
            return $null
        }
        $json = $result | ConvertFrom-Json
        return @{
            Name = $json.Name
            Status = $json.Status
            StartType = $json.StartType
        }
    }
    catch {
        return $null
    }
}

# Function to check service compliance
function Test-ServiceCompliance {
    param($Rule)
    
    $result = @{
        RuleId = $Rule.id
        Title = $Rule.title
        CheckType = "Service"
        Compliant = $false
        CurrentStatus = $null
        CurrentStartType = $null
        ExpectedStatus = $Rule.expected_status
        ExpectedStartType = $Rule.expected_start_type
        Details = ""
    }
    
    try {
        $serviceInfo = Get-ServiceStatus -ServiceName $Rule.service_name
        if ($serviceInfo) {
            $result.CurrentStatus = $serviceInfo.Status
            $result.CurrentStartType = $serviceInfo.StartType
            
            # Check both status and start type
            $statusMatch = ($result.CurrentStatus -eq $result.ExpectedStatus)
            $startTypeMatch = ($result.CurrentStartType -eq $result.ExpectedStartType)
            $result.Compliant = $statusMatch -and $startTypeMatch
            
            $result.Details = "Service found - Status: $($result.CurrentStatus), StartType: $($result.CurrentStartType)"
        } else {
            $result.Details = "Service not found"
        }
    }
    catch {
        $result.Details = "Error: $($_.Exception.Message)"
    }
    
    return $result
}

# Function to get audit policy settings
function Get-AuditPolicySettings {
    try {
        $output = auditpol /get /category:* 2>&1
        return $output
    }
    catch {
        return $null
    }
}

# Function to check audit policy compliance
function Test-AuditPolicyCompliance {
    param($Rule, $AuditPolicyOutput)
    
    $result = @{
        RuleId = $Rule.id
        Title = $Rule.title
        CheckType = "AuditPolicy"
        Compliant = $false
        CurrentSetting = $null
        ExpectedSetting = $Rule.expected_setting
        Details = ""
    }
    
    try {
        if ($AuditPolicyOutput) {
            # Parse audit policy output to find the specific setting
            $lines = $AuditPolicyOutput -split "`n"
            foreach ($line in $lines) {
                if ($line -match $Rule.audit_category -and $line -match $Rule.audit_subcategory) {
                    if ($line -match $result.ExpectedSetting) {
                        $result.Compliant = $true
                        $result.CurrentSetting = $result.ExpectedSetting
                        $result.Details = "Audit policy setting matches expected value"
                    } else {
                        $result.CurrentSetting = $line.Trim()
                        $result.Details = "Audit policy setting does not match expected value"
                    }
                    break
                }
            }
            
            if ($result.CurrentSetting -eq $null) {
                $result.Details = "Audit policy setting not found"
            }
        } else {
            $result.Details = "Failed to retrieve audit policy settings"
        }
    }
    catch {
        $result.Details = "Error: $($_.Exception.Message)"
    }
    
    return $result
}

# Function to export security policy
function Export-SecurityPolicy {
    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        $output = secedit /export /cfg $tempFile 2>&1
        if (Test-Path $tempFile) {
            $content = Get-Content $tempFile -Raw
            Remove-Item $tempFile -Force
            return $content
        }
        return $null
    }
    catch {
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
        return $null
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
            $report += "Expected Status: $($result.ExpectedStatus)`n"
            $report += "Expected Start Type: $($result.ExpectedStartType)`n"
        } elseif ($result.CheckType -eq "AuditPolicy") {
            $report += "Current Setting: $($result.CurrentSetting)`n"
            $report += "Expected Setting: $($result.ExpectedSetting)`n"
        }
        
        $report += "Details: $($result.Details)`n"
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
    
    # Use .NET methods to handle encoding more safely
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $cleanText = [System.Text.Encoding]::UTF8.GetString($bytes)
        
        # Simple replacements for common issues
        $cleanText = $cleanText -replace 'â€œ', '"'
        $cleanText = $cleanText -replace 'â€', '"'
        $cleanText = $cleanText -replace 'â€™', "'"
        $cleanText = $cleanText -replace 'â€¦', '...'
        
        return $cleanText
    }
    catch {
        # If encoding fails, return original text
        return $Text
    }
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

# Export security policy (for registry checks)
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
                    # Treat secpol as security policy checks (similar to registry but using security policy export)
                    $result = Test-RegistryCompliance -Rule $rule -PolicyContent $securityPolicy
                    $results += $result
                    
                    $status = if ($result.Compliant) { "PASS" } else { "FAIL" }
                    Write-ColorOutput "Rule $($rule.id): $status - $cleanTitle" -Color $(if ($result.Compliant) { "Green" } else { "Red" })
                }
            }
            "auditpol" {
                if (-not $SkipAuditPolicy) {
                    # Treat auditpol as audit policy checks
                    $result = Test-AuditPolicyCompliance -Rule $rule -AuditPolicyOutput $auditPolicy
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