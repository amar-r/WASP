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
            $currentValue = Get-SecurityPolicyValue -RegistryPath $Rule.target -PolicyContent $PolicyContent
            $result.CurrentValue = $currentValue
            
            if ($currentValue -ne $null) {
                $result.Compliant = ($currentValue -eq $result.ExpectedValue)
                $result.Details = "Value found in security policy export"
            } else {
                $result.Details = "Value not found in security policy export"
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

Export-ModuleMember -Function Export-SecurityPolicy, Parse-SecurityPolicy, Get-SecurityPolicyValue, Get-SecurityPolicySection, Test-SecurityPolicyCompliance, Parse-SecurityPolicyFile, Get-SecurityPolicySetting 