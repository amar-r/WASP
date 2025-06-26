#Requires -Modules ImportExcel

<#
.SYNOPSIS
    WASP - Windows Audit & Security Profiler (Excel Edition)
    Scans Windows Server systems for CIS compliance using the official CIS Excel benchmark file.

.DESCRIPTION
    This script reads the official CIS Microsoft Windows Server Benchmark Excel file and checks registry, security policy, and audit policy settings for compliance. It generates a summary report of pass/fail results.

.PARAMETER ExcelPath
    Path to the CIS Excel benchmark file. Default: .\baselines\CIS_Microsoft_Windows_Server_2022_Benchmark_v4.0.0.xlsx

.PARAMETER OutputPath
    Path for the output report. Default: .\reports\report.txt

.EXAMPLE
    # Basic usage (Excel file in baselines/)
    ./scripts/Start-WaspScan.ps1

.EXAMPLE
    # Specify custom Excel and output paths
    ./scripts/Start-WaspScan.ps1 -ExcelPath ".\baselines\CIS_Microsoft_Windows_Server_2022_Benchmark_v4.0.0.xlsx" -OutputPath ".\reports\my-wasp-report.txt"

.REQUIREMENTS
    - Windows Server 2016/2019/2022
    - PowerShell 5.1 or later
    - ImportExcel PowerShell module (Install-Module -Name ImportExcel -Scope CurrentUser)
    - Administrator privileges (recommended)
    - Official CIS Excel Benchmark file (download from Center for Internet Security)

.NOTES
    Author: WASP Project
    License: MIT
    https://github.com/amar-r/wasp
#>

param(
    [string]$ExcelPath = ".\baselines\CIS_Microsoft_Windows_Server_2022_Benchmark_v4.0.0.xlsx",
    [string]$OutputPath = ".\reports\report.txt"
)

# Create reports directory
New-Item -ItemType Directory -Path ".\reports" -Force | Out-Null

# Load Excel data
try {
    $level1Rules = Import-Excel $ExcelPath -WorksheetName "Level 1 - Member Server"
    Write-Host "Loaded Excel data successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to load Excel file: $_"
    exit 1
}

# Get audit policy data
$auditPolicyOutput = auditpol.exe /get /category:*
$settingColumnWidth = $auditPolicyOutput[2].IndexOf("Setting")
$auditPolicySettings = @{}
ForEach ($policyLine in $auditPolicyOutput) {
    If ($policyLine.Length -gt $settingColumnWidth) {
        $auditPolicySettings.Add($policyLine.SubString(0, $settingColumnWidth).Trim(), $policyLine.SubString($settingColumnWidth).Trim())
    }
}

# Process rules
$scanResults = foreach ($excelRule in $level1Rules) {
    if ($null -ne $excelRule.'Recommendation #') {
        # Extract remediation procedure from code blocks
        $remediationPath = if ($excelRule.'Remediation Procedure' -match '\`\`([^\`]+)\`\`') {
            $Matches[1].Trim()
        }

        # Extract expected value from title
        $expectedSettingValue = if ($excelRule.Title -match "'.*'([^']+)'.*$") {
            $Matches[1]
        }

        $ruleResult = [PSCustomObject]@{
            id            = $excelRule.'Recommendation #'
            title         = $excelRule.Title
            remediation   = $remediationPath
            expectedValue = $expectedSettingValue
            checkEnabled  = $true
        }

        # Determine check type and perform validation
        switch -Regex ($excelRule.'Audit Procedure') {
            HK.*\\ {
                if ($excelRule.'Audit Procedure' -match "HK.*\\.*") {
                    $ruleResult | Add-Member -MemberType NoteProperty -Name "registryKey" -Value $Matches[0]
                    $ruleResult | Add-Member -MemberType NoteProperty -Name "type" -Value "registry"
                    
                    $registryPath = $Matches[0] -split ":"
                    $currentRegistryValue = try {
                        (Get-ItemProperty registry::$($registryPath[0]) -ErrorAction Stop).($registryPath[1])
                    } catch {
                        "Key not found"
                    }
                    
                    $expectedRegistryValue = if ($expectedSettingValue -eq "Enabled") { 1 } elseif ($expectedSettingValue -eq "Disabled") { 0 } else { $expectedSettingValue }
                    $registryCompliance = $currentRegistryValue -eq $expectedRegistryValue
                    
                    $ruleResult | Add-Member -MemberType NoteProperty -Name "currentValue" -Value $currentRegistryValue 
                    $ruleResult | Add-Member -MemberType NoteProperty -Name "pass" -Value $registryCompliance
                }
            }
            auditpol {
                if ($excelRule.Title -match "'Audit ([^']+)'") {
                    $auditPolicyKey = $Matches[1]
                    $ruleResult | Add-Member -MemberType NoteProperty -Name "auditPolKey" -Value $auditPolicyKey
                    $ruleResult | Add-Member -MemberType NoteProperty -Name "type" -Value "auditPol"
                    $ruleResult | Add-Member -MemberType NoteProperty -Name "currentValue" -Value $auditPolicySettings[$auditPolicyKey]
                    $ruleResult | Add-Member -MemberType NoteProperty -Name "pass" -Value ($auditPolicySettings[$auditPolicyKey] -eq $expectedSettingValue)
                }                
            }
            default { 
                $ruleResult | Add-Member -MemberType NoteProperty -Name "type" -Value "secPol" 
            }
        }

        $ruleResult
    }
}

# Generate summary
$totalRulesChecked = $scanResults.Count
$compliantRules = ($scanResults | Where-Object {$_.pass -eq $true}).Count
$nonCompliantRules = ($scanResults | Where-Object {$_.pass -eq $false}).Count
$compliancePercentage = [math]::Round(($compliantRules / $totalRulesChecked * 100), 2)

# Output results
$summaryReport = @"
Total Checks: $totalRulesChecked
Passed Checks: $compliantRules
Failed Checks: $nonCompliantRules
Percent Passed: $compliancePercentage%
"@

$summaryReport | Out-File $OutputPath
$scanResults | Out-File $OutputPath -Append

Write-Host $summaryReport -ForegroundColor Cyan
Write-Host "Report saved to: $OutputPath" -ForegroundColor Green