# Services Check Module for WASP Scanner
# Handles service-based CIS compliance checks

function Test-ServiceCompliance {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule
    )
    
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
        Error = $null
    }
    
    try {
        # Extract service name from audit_procedure field
        $serviceName = $null
        if ($Rule.audit_procedure -and $Rule.audit_procedure.Trim() -ne "") {
            # Look for service name in audit_procedure (e.g., "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler:Start")
            if ($Rule.audit_procedure -match "Services\\(\w+):") {
                $serviceName = $matches[1]
            }
        }
        
        # Validate required fields
        if (-not $serviceName) {
            $result.Error = "Could not extract service name from audit_procedure"
            $result.Details = "Service name not found in audit_procedure: $($Rule.audit_procedure)"
            return $result
        }
        
        $serviceInfo = Get-ServiceStatus -ServiceName $serviceName
        if ($serviceInfo) {
            $result.CurrentStatus = $serviceInfo.Status
            $result.CurrentStartType = $serviceInfo.StartType
            
            # For Windows service rules, we typically check the start type
            # The expected_value usually contains the desired start type (e.g., "Automatic", "Disabled")
            $expectedStartType = $Rule.expected_value
            
            # Map expected values to actual start types
            switch ($expectedStartType) {
                "Automatic" { $expectedStartType = "Automatic" }
                "Manual" { $expectedStartType = "Manual" }
                "Disabled" { $expectedStartType = "Disabled" }
                default { $expectedStartType = $expectedStartType }
            }
            
            # Check if the current start type matches expected
            $result.Compliant = ($result.CurrentStartType -eq $expectedStartType)
            $result.ExpectedStartType = $expectedStartType
            
            $result.Details = "Service found - Status: $($result.CurrentStatus), StartType: $($result.CurrentStartType)"
            
            if (-not $result.Compliant) {
                $result.Details += " - Start type does not match expected ($expectedStartType)"
            }
        } else {
            $result.Details = "Service not found"
            $result.Error = "Service '$serviceName' does not exist or is not accessible"
        }
    }
    catch {
        $result.Error = $_.Exception.Message
        $result.Details = "Error: $($result.Error)"
    }
    
    return $result
}

function Get-ServiceStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )
    
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

function Get-ServiceStatusText {
    param([int]$StatusCode)
    
    switch ($StatusCode) {
        1 { return "Stopped" }
        2 { return "StartPending" }
        3 { return "StopPending" }
        4 { return "Running" }
        5 { return "ContinuePending" }
        6 { return "PausePending" }
        7 { return "Paused" }
        default { return "Unknown" }
    }
}

function Get-ServiceStartTypeText {
    param([int]$StartTypeCode)
    
    switch ($StartTypeCode) {
        0 { return "Boot" }
        1 { return "System" }
        2 { return "Automatic" }
        3 { return "Manual" }
        4 { return "Disabled" }
        default { return "Unknown" }
    }
} 