# Registry Check Module for WASP Scanner
# Handles registry-based CIS compliance checks

function Test-RegistryValueCompliance {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CurrentValue,
        
        [Parameter(Mandatory = $true)]
        [string]$ExpectedValue
    )
    
    # Convert current value to string for comparison
    $current = $CurrentValue.ToString()
    
    # Handle Enabled/Disabled conversion
    if ($ExpectedValue -eq "Enabled") {
        return $current -eq "1"
    }
    if ($ExpectedValue -eq "Disabled") {
        return $current -eq "0"
    }
    
    # Handle numeric patterns
    if ([int]::TryParse($current, [ref]$null)) {
        $currentNum = [int]$current
        
        # Parse expected value patterns
        switch -Regex ($ExpectedValue) {
            "^(\d+)\s+or\s+more$" {
                $minValue = [int]$matches[1]
                return $currentNum -ge $minValue
            }
            "^(\d+)\s+or\s+fewer$" {
                $maxValue = [int]$matches[1]
                return $currentNum -le $maxValue
            }
            "^(\d+)\s+or\s+fewer\s+days,\s+but\s+not\s+0$" {
                $maxValue = [int]$matches[1]
                return $currentNum -le $maxValue -and $currentNum -gt 0
            }
            "^(\d+)\s+or\s+fewer\s+hours,\s+but\s+not\s+0$" {
                $maxValue = [int]$matches[1]
                return $currentNum -le $maxValue -and $currentNum -gt 0
            }
            "^(\d+)\s+or\s+fewer\s+seconds$" {
                $maxValue = [int]$matches[1]
                return $currentNum -le $maxValue
            }
            "^(\d+)\s+or\s+fewer\s+minutes$" {
                $maxValue = [int]$matches[1]
                return $currentNum -le $maxValue
            }
            "^(\d+)$" {
                $exactValue = [int]$matches[1]
                return $currentNum -eq $exactValue
            }
            default {
                # Fallback to exact string comparison
                return $current -eq $ExpectedValue
            }
        }
    }
    
    # Fallback to exact string comparison for non-numeric values
    return $current -eq $ExpectedValue
}

function Test-RegistryCompliance {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule,
        
        [Parameter(Mandatory = $false)]
        [string]$PolicyContent
    )
    
    $result = @{
        RuleId = $Rule.id
        Title = $Rule.title
        CheckType = "Registry"
        Compliant = $false
        CurrentValue = $null
        ExpectedValue = $Rule.expected_value
        Details = ""
        Error = $null
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
        
        # Check compliance with intelligent validation
        if ($result.CurrentValue -ne $null) {
            $result.Compliant = Test-RegistryValueCompliance -CurrentValue $result.CurrentValue -ExpectedValue $result.ExpectedValue
        } else {
            $result.Details = "Registry value not found"
        }
    }
    catch {
        $result.Error = $_.Exception.Message
        $result.Details = "Error: $($result.Error)"
    }
    
    return $result
}

function Get-RegistryValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
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