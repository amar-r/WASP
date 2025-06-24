# Registry Check Module for WASP Scanner
# Handles registry-based CIS compliance checks

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
        
        # Check compliance
        if ($result.CurrentValue -ne $null) {
            $result.Compliant = ($result.CurrentValue -eq $result.ExpectedValue)
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