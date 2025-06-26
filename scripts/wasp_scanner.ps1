$lvl1 = Import-Excel .\baselines\CIS_Microsoft_Windows_Server_2022_Benchmark_v4.0.0.xlsx -WorksheetName "Level 1 - Member Server"

$AuditPolStr = auditpol.exe /get /category:*

$Width = $AuditPolStr[2].IndexOf("Setting")
$AuditPolObj = @{}
ForEach ($Line in $AuditPolStr) {
    If ($Line.Length -gt $Width) {
        $AuditPolObj.Add($Line.SubString(0, $Width).Trim(), $Line.SubString($Width).Trim())
    }
}

$report = foreach ($rule in $lvl1) {
    if ($null -ne $rule.'Recommendation #') {

        $remediation = if ($rule.'Remediation Procedure' -match '\`\`([^\`]+)\`\`') {
            $Matches[1].Trim()
        }

        $expectedValue = if ($rule.Title -match "'.*'([^']+)'.*$") {
            $Matches[1]
        }

        $ruleObj = [PSCustomObject]@{
            id            = $rule.'Recommendation #'
            title         = $rule.Title
            remediation   = $remediation
            expectedValue = $expectedValue
            checkEnabled  = $true
        }

        switch -Regex ($rule.'Audit Procedure') {
            HK.*\\ {
                if ($rule.'Audit Procedure' -match "HK.*\\.*") {
                    $ruleObj | Add-Member -MemberType NoteProperty -Name "registryKey" -Value $Matches[0]
                    $ruleObj | Add-Member -MemberType NoteProperty -Name "type" -Value "registry"
                    $regKey = $Matches[0] -split ":"
                    $regKeyValue = try {((Get-ItemProperty registry::$($regKey[0]) -ErrorAction Stop).($regKey[1]))} catch {"Key not found"}
                    $expectedValue = if ($expectedValue -eq "Enabled") {1} elseif ($expectedValue -eq "Disabled") {0}
                    $passStatus = $regKeyValue -eq $expectedValue
                    $ruleObj | Add-Member -MemberType NoteProperty -Name "currentValue" -Value $regKeyValue 
                    $ruleObj | Add-Member -MemberType NoteProperty -Name "pass" -Value $passStatus
                }
            }
            auditpol {
                if ($rule.Title -match "'Audit ([^']+)'") {
                    $ruleObj | Add-Member -MemberType NoteProperty -Name "auditPolKey" -Value $Matches[1]
                    $ruleObj | Add-Member -MemberType NoteProperty -Name "type" -Value "auditPol"
                    $ruleObj | Add-Member -MemberType NoteProperty -Name "currentValue" -Value $AuditPolObj[$Matches[1]]
                    $ruleObj | Add-Member -MemberType NoteProperty -Name "pass" -Value ($AuditPolObj[$Matches[1]] -eq $expectedValue)
                }                
            }
            default { $ruleObj | Add-Member -MemberType NoteProperty -Name "type" -Value "secPol" }
        }

        $ruleObj
    }
}

$report | ? {$_.type -eq 'registry'} | select -first 5

$totalChecks = $report.Count
$passedChecks = ($report | Where-Object {$_.pass -eq $true}).Count
$failedChecks = ($report | Where-Object {$_.pass -eq $false}).Count
$percentPassed = [math]::Round(($passedChecks / $totalChecks * 100),2)


"Total Checks: $totalChecks`nPassed Checks: $passedChecks`nFailed Checks: $failedChecks`nPercent Passed: $percentPassed%" | Out-File .\reports\report.txt
$report | Out-File .\reports\report.txt -Append