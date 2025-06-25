# Debug script to examine security policy
secedit /export /cfg "reports\secpol.inf" 2>$null

Write-Host "=== SECURITY POLICY CONTENTS ===" -ForegroundColor Yellow
Get-Content "reports\secpol.inf" | Select-Object -First 20

Write-Host "`n=== LOOKING FOR PASSWORD SETTINGS ===" -ForegroundColor Yellow
$secpolContent = Get-Content "reports\secpol.inf" -Raw

# Look for password-related settings
$passwordSettings = @(
    "PasswordHistorySize",
    "MaximumPasswordAge", 
    "MinimumPasswordAge",
    "MinimumPasswordLength",
    "PasswordComplexity",
    "ClearTextPassword"
)

foreach ($setting in $passwordSettings) {
    if ($secpolContent -match "$setting\s*=\s*(.+)") {
        Write-Host "$setting = $($matches[1].Trim())" -ForegroundColor Green
    } else {
        Write-Host "$setting = NOT FOUND" -ForegroundColor Red
    }
}

Write-Host "`n=== LOOKING FOR ACCOUNT LOCKOUT SETTINGS ===" -ForegroundColor Yellow
$lockoutSettings = @(
    "LockoutDuration",
    "LockoutBadCount",
    "ResetLockoutCount"
)

foreach ($setting in $lockoutSettings) {
    if ($secpolContent -match "$setting\s*=\s*(.+)") {
        Write-Host "$setting = $($matches[1].Trim())" -ForegroundColor Green
    } else {
        Write-Host "$setting = NOT FOUND" -ForegroundColor Red
    }
} 