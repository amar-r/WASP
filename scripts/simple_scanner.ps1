# WASP Scanner - Simple Version
# Reads JSON baseline and performs basic checks with detailed results

param(
    [string]$BaselinePath = "baselines\cis-windows-server-2022-member-server.json",
    [string]$OutputPath = "reports\results.txt"
)

# Create output directory
New-Item -ItemType Directory -Path "reports" -Force | Out-Null

Write-Host "WASP Scanner Starting..." -ForegroundColor Green

# Load JSON baseline
try {
    $json = Get-Content $BaselinePath -Raw | ConvertFrom-Json
    $rules = $json.rules
    Write-Host "Loaded $($rules.Count) rules" -ForegroundColor Green
} catch {
    Write-Error "Failed to load baseline: $_"
    exit 1
}

# Get system data once
Write-Host "Getting system data..." -ForegroundColor Yellow
$secpol = secedit /export /cfg "reports\secpol.inf" 2>$null
$auditpol = auditpol /get /category:* 2>$null

function Test-Compliance {
    param($current, $expected)
    
    if ($current -eq $expected) { return $true }
    
    # Handle "X or more"
    if ($expected -match "(\d+) or more") {
        $min = [int]$matches[1]
        if ($current -match "(\d+)") {
            return [int]$matches[1] -ge $min
        }
    }
    
    # Handle "X or fewer"
    if ($expected -match "(\d+) or fewer") {
        $max = [int]$matches[1]
        if ($current -match "(\d+)") {
            $val = [int]$matches[1]
            return $val -le $max -and $val -gt 0
        }
    }
    
    # Handle "but not 0"
    if ($expected -match "but not 0") {
        if ($current -match "(\d+)") {
            return [int]$matches[1] -gt 0
        }
    }
    
    return $false
}

# Process rules
$results = @()
$pass = 0
$fail = 0

foreach ($rule in $rules) {
    if ($rule.skip) { continue }
    
    $status = "FAIL"
    $current = ""
    $location = ""
    
    switch ($rule.check_type) {
        "secpol" {
            $location = "Security Policy"
            if ($secpol -eq 0) {
                $secpolContent = Get-Content "reports\secpol.inf" -Raw -ErrorAction SilentlyContinue
                if ($rule.title -match "Ensure '([^']+)'") {
                    $setting = $matches[1]
                    if ($secpolContent -match "$setting\s*=\s*(.+)") {
                        $current = $matches[1].Trim()
                        if (Test-Compliance -current $current -expected $rule.expected_value) {
                            $status = "PASS"
                        }
                    }
                }
            }
        }
        "registry" {
            if ($rule.audit_procedure -match "(.+):(.+)") {
                $path = $matches[1]
                $name = $matches[2]
                $location = "Registry: $path\$name"
                try {
                    $value = Get-ItemProperty -Path "Registry::$path" -Name $name -ErrorAction SilentlyContinue
                    if ($value) {
                        $current = $value.$name
                        if (Test-Compliance -current $current -expected $rule.expected_value) {
                            $status = "PASS"
                        }
                    }
                } catch { }
            }
        }
        "auditpol" {
            $location = "Audit Policy"
            if ($rule.title -match "Ensure '([^']+)'") {
                $setting = $matches[1]
                if ($auditpol -match "$setting\s+(.+)") {
                    $current = $matches[1].Trim()
                    if (Test-Compliance -current $current -expected $rule.expected_value) {
                        $status = "PASS"
                    }
                }
            }
        }
    }
    
    if ($status -eq "PASS") { $pass++ } else { $fail++ }
    
    $results += [PSCustomObject]@{
        ID = $rule.id
        Title = $rule.title
        Status = $status
        Current = $current
        Expected = $rule.expected_value
        Location = $location
    }
}

# Generate detailed report
$report = "WASP Scanner Report`n$(Get-Date)`n`nPASS: $pass`nFAIL: $fail`n`n"

foreach ($r in $results) {
    $report += "$($r.ID) - $($r.Status) - $($r.Current) vs $($r.Expected)`n"
}

$report | Out-File $OutputPath

Write-Host "PASS: $pass, FAIL: $fail"
Write-Host "Report: $OutputPath" -ForegroundColor Cyan 