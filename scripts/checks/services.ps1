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