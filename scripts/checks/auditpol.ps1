# Audit Policy Check Module for WASP Scanner
# Handles audit policy-based CIS compliance checks

function Test-AuditPolicyCompliance {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule,
        
        [Parameter(Mandatory = $false)]
        [string[]]$AuditPolicyOutput
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
            # Convert string array to lines for processing
            $lines = if ($AuditPolicyOutput -is [string]) {
                $AuditPolicyOutput -split "`n"
            } else {
                $AuditPolicyOutput
            }
            
            # Extract subcategory name from the rule title
            # Handle different title formats:
            # "(L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'"
            # "(L1) Ensure 'Audit Security Group Management' is set to include 'Success'"
            $subcategoryName = ""
            if ($Rule.title -match "Ensure 'Audit (.+?)' is set to") {
                $subcategoryName = $matches[1]
            } elseif ($Rule.title -match "Ensure 'Audit (.+?)' is set to include") {
                $subcategoryName = $matches[1]
            }
            
            if ($subcategoryName -eq "") {
                $result.Details = "Could not extract subcategory name from rule title: $($Rule.title)"
                return $result
            }
            
            # Parse the audit policy output to find the subcategory
            $currentCategory = ""
            $found = $false
            
            foreach ($line in $lines) {
                $line = $line.Trim()
                
                # Check if this is a category header (no leading spaces)
                if ($line -match "^([A-Za-z/\s]+)$" -and $line -notmatch "^\s") {
                    $currentCategory = $line
                }
                # Check if this is a subcategory line (has leading spaces and contains the subcategory name)
                elseif ($line -match "^\s+(.+?)\s+(Success|Failure|Success and Failure|No Auditing)\s*$") {
                    $subcategory = $matches[1].Trim()
                    $setting = $matches[2]
                    
                    # Check if this subcategory matches what we're looking for
                    if ($subcategory -eq $subcategoryName) {
                        $result.CurrentSetting = $setting
                        
                        # Compare with expected value
                        if ($setting -eq $result.ExpectedSetting) {
                            $result.Compliant = $true
                            $result.Details = "Audit policy setting matches expected value"
                        } else {
                            $result.Details = "Audit policy setting does not match expected value"
                        }
                        $found = $true
                        break
                    }
                }
            }
            
            if (-not $found) {
                $result.Compliant = $false
                $result.Details = "Audit policy subcategory '$subcategoryName' not found in output"
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