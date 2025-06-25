# Audit Policy Check Module for WASP Scanner
# Handles audit policy-based CIS compliance checks

function Test-AuditPolicyCompliance {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule,
        
        [Parameter(Mandatory = $false)]
        [string]$AuditPolicyOutput
    )
    
    $result = @{
        RuleId = $Rule.id
        Title = $Rule.title
        CheckType = "AuditPolicy"
        Compliant = $false
        CurrentSetting = $null
        ExpectedSetting = $Rule.expected_value
        Details = ""
        Error = $null
    }
    
    try {
        if ($AuditPolicyOutput) {
            # Parse audit policy output to find the specific setting
            $lines = $AuditPolicyOutput -split "`n"
            foreach ($line in $lines) {
                # Look for the specific audit category and subcategory
                if ($line -match $Rule.audit_category -and $line -match $Rule.audit_subcategory) {
                    # Extract the actual setting from the line
                    if ($line -match "(Success|Failure|Success and Failure|No Auditing)") {
                        $currentSetting = $matches[1]
                        $result.CurrentSetting = $currentSetting
                        
                        # Compare with expected value
                        if ($currentSetting -eq $result.ExpectedSetting) {
                            $result.Compliant = $true
                            $result.Details = "Audit policy setting matches expected value"
                        } else {
                            $result.Details = "Audit policy setting does not match expected value"
                        }
                    } else {
                        $result.CurrentSetting = $line.Trim()
                        $result.Details = "Could not parse audit policy setting from line"
                    }
                    break
                }
            }
            
            if ($result.CurrentSetting -eq $null) {
                $result.Compliant = $false
                $result.Details = "Audit policy setting not found"
            }
        } else {
            $result.Details = "Failed to retrieve audit policy settings"
        }
    }
    catch {
        $result.Error = $_.Exception.Message
        $result.Details = "Error: $($result.Error)"
    }
    
    return $result
}

function Get-AuditPolicySettings {
    try {
        $output = auditpol /get /category:* 2>&1
        return $output
    }
    catch {
        return $null
    }
}

function Get-AuditPolicySubcategories {
    try {
        $output = auditpol /get /subcategory:* 2>&1
        return $output
    }
    catch {
        return $null
    }
}

function Parse-AuditPolicyOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )
    
    $settings = @{}
    $lines = $Output -split "`n"
    $currentCategory = ""
    
    foreach ($line in $lines) {
        $line = $line.Trim()
        if ($line -match "^([A-Za-z\s]+)$" -and $line -notmatch "^\s") {
            # This is a category header
            $currentCategory = $line
            $settings[$currentCategory] = @{}
        } elseif ($line -match "^\s+(.+)\s+(Success|Failure|Success and Failure|No Auditing)$") {
            # This is a subcategory with setting
            $subcategory = $matches[1].Trim()
            $setting = $matches[2]
            if ($currentCategory -ne "") {
                $settings[$currentCategory][$subcategory] = $setting
            }
        }
    }
    
    return $settings
}

function Test-AuditPolicySetting {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $true)]
        [string]$Subcategory,
        
        [Parameter(Mandatory = $true)]
        [string]$ExpectedSetting,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$AuditSettings
    )
    
    if ($AuditSettings.ContainsKey($Category) -and $AuditSettings[$Category].ContainsKey($Subcategory)) {
        $currentSetting = $AuditSettings[$Category][$Subcategory]
        return @{
            Compliant = ($currentSetting -eq $ExpectedSetting)
            CurrentSetting = $currentSetting
            ExpectedSetting = $ExpectedSetting
        }
    }
    
    return @{
        Compliant = $false
        CurrentSetting = $null
        ExpectedSetting = $ExpectedSetting
    }
} 