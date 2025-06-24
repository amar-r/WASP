# Security Policy Check Module for WASP Scanner
# Handles security policy-based CIS compliance checks

function Export-SecurityPolicy {
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = $null
    )
    
    if (-not $OutputPath) {
        $OutputPath = [System.IO.Path]::GetTempFileName()
    }
    
    try {
        $output = secedit /export /cfg $OutputPath 2>&1
        if (Test-Path $OutputPath) {
            $content = Get-Content $OutputPath -Raw
            if (-not $OutputPath.Contains([System.IO.Path]::GetTempPath())) {
                # Don't delete if it's a user-specified path
                return $content
            } else {
                Remove-Item $OutputPath -Force
                return $content
            }
        }
        return $null
    }
    catch {
        if (Test-Path $OutputPath -and $OutputPath.Contains([System.IO.Path]::GetTempPath())) {
            Remove-Item $OutputPath -Force
        }
        return $null
    }
}

function Parse-SecurityPolicy {
    param([string]$PolicyContent)
    
    $sections = @{}
    $currentSection = ""
    $lines = $PolicyContent -split "`n"
    
    foreach ($line in $lines) {
        $line = $line.Trim()
        
        # Skip empty lines
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        
        # Check if this is a section header
        if ($line -match "^\[(.+)\]$") {
            $currentSection = $matches[1]
            $sections[$currentSection] = @{}
            continue
        }
        
        # Parse key-value pairs
        if ($line -match "^(.+?)\s*=\s*(.+)$") {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            
            if ($currentSection -and $sections.ContainsKey($currentSection)) {
                $sections[$currentSection][$key] = $value
            }
        }
    }
    
    return $sections
}

function Get-SecurityPolicyValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath,
        
        [Parameter(Mandatory = $true)]
        [string]$PolicyContent
    )
    
    $pattern = [regex]::Escape($RegistryPath) + "=\d+,(.+)"
    $match = [regex]::Match($PolicyContent, $pattern)
    if ($match.Success) {
        return $match.Groups[1].Value.Trim('"')
    }
    return $null
}

function Get-SecurityPolicySection {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SectionName,
        
        [Parameter(Mandatory = $true)]
        [string]$PolicyContent
    )
    
    $sections = Parse-SecurityPolicy -PolicyContent $PolicyContent
    if ($sections.ContainsKey($SectionName)) {
        return $sections[$SectionName]
    }
    
    return $null
}

function Test-NumericCompliance {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CurrentValue,
        
        [Parameter(Mandatory = $true)]
        [string]$ExpectedValue
    )
    
    # Convert current value to integer for comparison
    if (-not [int]::TryParse($CurrentValue, [ref]$null)) {
        return $false
    }
    
    $current = [int]$CurrentValue
    
    # Parse expected value patterns
    switch -Regex ($ExpectedValue) {
        "^(\d+)\s+or\s+more\s+password\(s\)$" {
            $minValue = [int]$matches[1]
            return $current -ge $minValue
        }
        "^(\d+)\s+or\s+more\s+minute\(s\)$" {
            $minValue = [int]$matches[1]
            return $current -ge $minValue
        }
        "^(\d+)\s+or\s+more\s+day\(s\)$" {
            $minValue = [int]$matches[1]
            return $current -ge $minValue
        }
        "^(\d+)\s+or\s+more\s+character\(s\)$" {
            $minValue = [int]$matches[1]
            return $current -ge $minValue
        }
        "^(\d+)\s+or\s+fewer\s+invalid\s+logon\s+attempt\(s\),\s+but\s+not\s+0$" {
            $maxValue = [int]$matches[1]
            return $current -le $maxValue -and $current -gt 0
        }
        "^(\d+)\s+or\s+fewer\s+days,\s+but\s+not\s+0$" {
            $maxValue = [int]$matches[1]
            return $current -le $maxValue -and $current -gt 0
        }
        "^(\d+)\s+or\s+fewer\s+minute\(s\)$" {
            $maxValue = [int]$matches[1]
            return $current -le $maxValue
        }
        "^(\d+)\s+or\s+fewer\s+second\(s\)$" {
            $maxValue = [int]$matches[1]
            return $current -le $maxValue
        }
        "^(\d+)\s+or\s+fewer\s+hour\(s\),\s+but\s+not\s+0$" {
            $maxValue = [int]$matches[1]
            return $current -le $maxValue -and $current -gt 0
        }
        "^(\d+)$" {
            $exactValue = [int]$matches[1]
            return $current -eq $exactValue
        }
        default {
            # Fallback to exact string comparison for non-numeric patterns
            return $CurrentValue -eq $ExpectedValue
        }
    }
}

function Test-SecurityPolicyCompliance {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule,
        
        [Parameter(Mandatory = $false)]
        [string]$PolicyContent
    )
    
    $result = @{
        RuleId = $Rule.id
        Title = $Rule.title
        CheckType = "SecurityPolicy"
        Compliant = $false
        CurrentValue = $null
        ExpectedValue = $Rule.expected_value
        Details = ""
        Error = $null
    }
    
    try {
        if (-not $PolicyContent) {
            $PolicyContent = Export-SecurityPolicy
        }
        
        if ($PolicyContent) {
            # Parse the policy content into sections
            $sections = Parse-SecurityPolicy -PolicyContent $PolicyContent
            
            # Determine which section to check based on the rule target
            $sectionToCheck = $null
            $settingName = $null
            
            switch ($Rule.target) {
                "Account Policies" {
                    $sectionToCheck = "System Access"
                    # Map CIS rule titles to actual setting names in security_policy.inf
                    switch -Wildcard ($Rule.title) {
                        "*Enforce password history*" { $settingName = "PasswordHistorySize" }
                        "*Maximum password age*" { $settingName = "MaximumPasswordAge" }
                        "*Minimum password age*" { $settingName = "MinimumPasswordAge" }
                        "*Minimum password length*" { $settingName = "MinimumPasswordLength" }
                        "*Password must meet complexity requirements*" { $settingName = "PasswordComplexity" }
                        "*Relax minimum password length limits*" { $settingName = "RelaxMinimumPasswordLengthLimits" }
                        "*Store passwords using reversible encryption*" { $settingName = "ClearTextPassword" }
                        "*Account lockout duration*" { $settingName = "LockoutDuration" }
                        "*Account lockout threshold*" { $settingName = "LockoutBadCount" }
                        "*Allow Administrator account lockout*" { $settingName = "AllowAdministratorLockout" }
                        "*Reset account lockout counter after*" { $settingName = "ResetLockoutCount" }
                        default { $settingName = $Rule.specific_setting }
                    }
                }
                "User Rights Assignment" {
                    $sectionToCheck = "Privilege Rights"
                    # Map CIS rule titles to privilege rights
                    switch -Wildcard ($Rule.title) {
                        "*Access Credential Manager as a trusted caller*" { $settingName = "SeTrustedCredManAccessPrivilege" }
                        "*Access this computer from the network*" { $settingName = "SeNetworkLogonRight" }
                        "*Act as part of the operating system*" { $settingName = "SeTcbPrivilege" }
                        "*Adjust memory quotas for a process*" { $settingName = "SeIncreaseQuotaPrivilege" }
                        "*Allow log on locally*" { $settingName = "SeInteractiveLogonRight" }
                        "*Allow log on through Remote Desktop Services*" { $settingName = "SeRemoteInteractiveLogonRight" }
                        "*Back up files and directories*" { $settingName = "SeBackupPrivilege" }
                        "*Change the system time*" { $settingName = "SeSystemtimePrivilege" }
                        "*Change the time zone*" { $settingName = "SeTimeZonePrivilege" }
                        "*Create a pagefile*" { $settingName = "SeCreatePagefilePrivilege" }
                        "*Create a token object*" { $settingName = "SeCreateTokenPrivilege" }
                        "*Create global objects*" { $settingName = "SeCreateGlobalPrivilege" }
                        "*Create permanent shared objects*" { $settingName = "SeCreatePermanentPrivilege" }
                        "*Create symbolic links*" { $settingName = "SeCreateSymbolicLinkPrivilege" }
                        "*Debug programs*" { $settingName = "SeDebugPrivilege" }
                        "*Deny access to this computer from the network*" { $settingName = "SeDenyNetworkLogonRight" }
                        "*Deny log on as a batch job*" { $settingName = "SeDenyBatchLogonRight" }
                        "*Deny log on as a service*" { $settingName = "SeDenyServiceLogonRight" }
                        "*Deny log on locally*" { $settingName = "SeDenyInteractiveLogonRight" }
                        "*Deny log on through Remote Desktop Services*" { $settingName = "SeDenyRemoteInteractiveLogonRight" }
                        "*Enable computer and user accounts to be trusted for delegation*" { $settingName = "SeEnableDelegationPrivilege" }
                        "*Force shutdown from a remote system*" { $settingName = "SeRemoteShutdownPrivilege" }
                        "*Generate security audits*" { $settingName = "SeAuditPrivilege" }
                        "*Impersonate a client after authentication*" { $settingName = "SeImpersonatePrivilege" }
                        "*Increase scheduling priority*" { $settingName = "SeIncreaseBasePriorityPrivilege" }
                        "*Load and unload device drivers*" { $settingName = "SeLoadDriverPrivilege" }
                        "*Lock pages in memory*" { $settingName = "SeLockMemoryPrivilege" }
                        "*Manage auditing and security log*" { $settingName = "SeSecurityPrivilege" }
                        "*Modify an object label*" { $settingName = "SeRelabelPrivilege" }
                        "*Modify firmware environment values*" { $settingName = "SeSystemEnvironmentPrivilege" }
                        "*Perform volume maintenance tasks*" { $settingName = "SeManageVolumePrivilege" }
                        "*Profile single process*" { $settingName = "SeProfileSingleProcessPrivilege" }
                        "*Profile system performance*" { $settingName = "SeSystemProfilePrivilege" }
                        "*Replace a process level token*" { $settingName = "SeAssignPrimaryTokenPrivilege" }
                        "*Restore files and directories*" { $settingName = "SeRestorePrivilege" }
                        "*Shut down the system*" { $settingName = "SeShutdownPrivilege" }
                        "*Take ownership of files or other objects*" { $settingName = "SeTakeOwnershipPrivilege" }
                        default { $settingName = $Rule.specific_setting }
                    }
                }
                default {
                    # Fallback to registry-style parsing for other settings
                    $currentValue = Get-SecurityPolicyValue -RegistryPath $Rule.target -PolicyContent $PolicyContent
                    $result.CurrentValue = $currentValue
                    
                    if ($currentValue -ne $null) {
                        $result.Compliant = ($currentValue -eq $result.ExpectedValue)
                        $result.Details = "Value found in security policy export (registry style)"
                    } else {
                        $result.Details = "Value not found in security policy export"
                    }
                    return $result
                }
            }
            
            # Check the appropriate section for the setting
            if ($sectionToCheck -and $sections.ContainsKey($sectionToCheck) -and $settingName) {
                $section = $sections[$sectionToCheck]
                if ($section.ContainsKey($settingName)) {
                    $currentValue = $section[$settingName]
                    $result.CurrentValue = $currentValue
                    $result.Details = "Found in $sectionToCheck section"
                    
                    # Handle different value formats
                    switch ($settingName) {
                        "PasswordComplexity" {
                            # 1 = Enabled, 0 = Disabled
                            $expected = if ($result.ExpectedValue -eq "Enabled") { "1" } else { "0" }
                            $result.Compliant = ($currentValue -eq $expected)
                        }
                        "ClearTextPassword" {
                            # 0 = Disabled, 1 = Enabled
                            $expected = if ($result.ExpectedValue -eq "Disabled") { "0" } else { "1" }
                            $result.Compliant = ($currentValue -eq $expected)
                        }
                        "AllowAdministratorLockout" {
                            # 1 = Enabled, 0 = Disabled
                            $expected = if ($result.ExpectedValue -eq "Enabled") { "1" } else { "0" }
                            $result.Compliant = ($currentValue -eq $expected)
                        }
                        default {
                            # For numeric values, implement intelligent validation
                            $result.Compliant = Test-NumericCompliance -CurrentValue $currentValue -ExpectedValue $result.ExpectedValue
                        }
                    }
                } else {
                    $result.Details = "Setting '$settingName' not found in $sectionToCheck section"
                }
            } else {
                $result.Details = "Section '$sectionToCheck' not found or setting name not determined"
            }
        } else {
            $result.Details = "Failed to export security policy"
        }
    }
    catch {
        $result.Error = $_.Exception.Message
        $result.Details = "Error: $($result.Error)"
    }
    
    return $result
}

function Parse-SecurityPolicyFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyContent
    )
    
    $settings = @{}
    $lines = $PolicyContent -split "`n"
    
    foreach ($line in $lines) {
        $line = $line.Trim()
        if ($line -match "^([^=]+)=(.+)$") {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            $settings[$key] = $value
        }
    }
    
    return $settings
}

function Get-SecurityPolicySetting {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SettingName,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$PolicySettings
    )
    
    if ($PolicySettings.ContainsKey($SettingName)) {
        return $PolicySettings[$SettingName]
    }
    
    return $null
} 