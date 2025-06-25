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
        # Use the audit_procedure field if available, otherwise extract from audit_command
        $auditCommand = ""
        if ($Rule.audit_procedure -and $Rule.audit_procedure.Trim() -ne "") {
            # Extract command from audit_procedure if it contains code blocks
            if ($Rule.audit_procedure -match "```\s*\n(.*?)\n\s*```") {
                $auditCommand = $matches[1].Trim()
            } else {
                # Use the audit_procedure as-is if no code blocks
                $auditCommand = $Rule.audit_procedure.Trim()
            }
        } elseif ($Rule.audit_command) {
            $auditCommand = $Rule.audit_command
        }
        
        if ($auditCommand -eq "") {
            $result.Details = "Could not extract audit command from rule"
            $result.Error = "No audit procedure or command found in rule"
            return $result
        }
        
        # Execute the specific auditpol command
        try {
            $output = Invoke-Expression $auditCommand 2>&1
            $outputLines = if ($output -is [string]) {
                $output -split "`n"
            } else {
                $output
            }
            
            # Parse the output to find the setting value
            $currentSetting = $null
            foreach ($line in $outputLines) {
                $line = $line.Trim()
                # Look for lines that contain the setting value
                if ($line -match "(Success|Failure|Success and Failure|No Auditing)") {
                    $currentSetting = $matches[1]
                    break
                }
            }
            
            if ($currentSetting -ne $null) {
                $result.CurrentSetting = $currentSetting
                
                # Compare with expected value
                if ($currentSetting -eq $result.ExpectedSetting) {
                    $result.Compliant = $true
                    $result.Details = "Audit policy setting matches expected value"
                } else {
                    $result.Details = "Audit policy setting does not match expected value"
                }
            } else {
                $result.Details = "Could not parse setting value from auditpol output"
                $result.Error = "No valid audit setting found in command output"
            }
        }
        catch {
            $result.Error = $_.Exception.Message
            $result.Details = "Error executing audit command: $($result.Error)"
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