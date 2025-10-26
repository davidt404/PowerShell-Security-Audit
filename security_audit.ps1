# Security-Compliance-Audit.ps1
# Windows security baseline compliance checker
# Generates HTML report with pass/fail status for audit documentation

# Set output file
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportFile = "$env:USERPROFILE\Desktop\Security_Audit_Report_$timestamp.html"

# Initialize HTML report
$htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows Security Compliance Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; margin-top: 30px; }
        .pass { color: #27ae60; font-weight: bold; }
        .fail { color: #e74c3c; font-weight: bold; }
        .warn { color: #f39c12; font-weight: bold; }
        .info { background-color: #ecf0f1; padding: 10px; margin: 10px 0; border-radius: 5px; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #bdc3c7; padding: 8px; text-align: left; }
        th { background-color: #34495e; color: white; }
        .summary { background-color: #3498db; color: white; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>Windows Security Compliance Audit Report</h1>
    <div class="info">
        <strong>System:</strong> $env:COMPUTERNAME<br>
        <strong>Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
        <strong>User:</strong> $env:USERNAME<br>
        <strong>OS:</strong> $((Get-CimInstance Win32_OperatingSystem).Caption)
    </div>
"@

$htmlBody = ""
$passCount = 0
$failCount = 0
$warnCount = 0

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Windows Security Compliance Audit" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Function to add result to HTML
function Add-AuditResult {
    param(
        [string]$Category,
        [string]$Check,
        [string]$Status,
        [string]$Details
    )
    
    $statusClass = switch ($Status) {
        "PASS" { "pass"; $script:passCount++; break }
        "FAIL" { "fail"; $script:failCount++; break }
        "WARN" { "warn"; $script:warnCount++; break }
    }
    
    $script:htmlBody += "<tr><td>$Category</td><td>$Check</td><td class='$statusClass'>[$Status]</td><td>$Details</td></tr>`n"
    
    $color = switch ($Status) {
        "PASS" { "Green"; break }
        "FAIL" { "Red"; break }
        "WARN" { "Yellow"; break }
    }
    Write-Host "[$Status] $Check - $Details" -ForegroundColor $color
}

# Start audit checks table
$htmlBody += "<h2>Security Audit Results</h2>`n"
$htmlBody += "<table><tr><th>Category</th><th>Check</th><th>Status</th><th>Details</th></tr>`n"

# 1. Windows Firewall Status
Write-Host "`nChecking Windows Firewall..." -ForegroundColor Cyan
try {
    $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop
    $allEnabled = $true
    foreach ($profile in $firewallProfiles) {
        if ($profile.Enabled -eq $false) {
            $allEnabled = $false
            Add-AuditResult "Firewall" "Firewall Profile: $($profile.Name)" "FAIL" "Firewall is disabled"
        }
    }
    if ($allEnabled) {
        Add-AuditResult "Firewall" "Windows Firewall Status" "PASS" "All firewall profiles enabled"
    }
} catch {
    Add-AuditResult "Firewall" "Windows Firewall Status" "FAIL" "Unable to check firewall status"
}

# 2. Windows Defender Status
Write-Host "`nChecking Windows Defender..." -ForegroundColor Cyan
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    if ($defenderStatus.AntivirusEnabled) {
        Add-AuditResult "Antivirus" "Windows Defender Status" "PASS" "Antivirus is enabled"
    } else {
        Add-AuditResult "Antivirus" "Windows Defender Status" "FAIL" "Antivirus is disabled"
    }
    
    if ($defenderStatus.RealTimeProtectionEnabled) {
        Add-AuditResult "Antivirus" "Real-Time Protection" "PASS" "Real-time protection is enabled"
    } else {
        Add-AuditResult "Antivirus" "Real-Time Protection" "FAIL" "Real-time protection is disabled"
    }
    
    $defAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
    if ($defAge.Days -le 7) {
        Add-AuditResult "Antivirus" "Definition Updates" "PASS" "Definitions updated $($defAge.Days) days ago"
    } else {
        Add-AuditResult "Antivirus" "Definition Updates" "WARN" "Definitions are $($defAge.Days) days old"
    }
} catch {
    Add-AuditResult "Antivirus" "Windows Defender Status" "WARN" "Unable to check Defender status (may not be installed)"
}

# 3. Windows Updates
Write-Host "`nChecking Windows Updates..." -ForegroundColor Cyan
try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $searchResult = $updateSearcher.Search("IsInstalled=0")
    
    if ($searchResult.Updates.Count -eq 0) {
        Add-AuditResult "Updates" "Pending Windows Updates" "PASS" "No pending updates"
    } elseif ($searchResult.Updates.Count -le 5) {
        Add-AuditResult "Updates" "Pending Windows Updates" "WARN" "$($searchResult.Updates.Count) updates pending"
    } else {
        Add-AuditResult "Updates" "Pending Windows Updates" "FAIL" "$($searchResult.Updates.Count) updates pending"
    }
} catch {
    Add-AuditResult "Updates" "Pending Windows Updates" "WARN" "Unable to check for updates"
}

# 4. User Accounts
Write-Host "`nChecking User Accounts..." -ForegroundColor Cyan
try {
    $localUsers = Get-LocalUser | Where-Object {$_.Enabled -eq $true}
    $userCount = ($localUsers | Measure-Object).Count
    
    if ($userCount -le 5) {
        Add-AuditResult "Users" "Enabled Local Users" "PASS" "$userCount enabled user accounts"
    } else {
        Add-AuditResult "Users" "Enabled Local Users" "WARN" "$userCount enabled user accounts (review required)"
    }
    
    # Check for Guest account
    $guestEnabled = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue | Where-Object {$_.Enabled -eq $true}
    if ($guestEnabled) {
        Add-AuditResult "Users" "Guest Account" "FAIL" "Guest account is enabled"
    } else {
        Add-AuditResult "Users" "Guest Account" "PASS" "Guest account is disabled"
    }
} catch {
    Add-AuditResult "Users" "User Account Check" "WARN" "Unable to enumerate user accounts"
}

# 5. Administrator Accounts
Write-Host "`nChecking Administrator Privileges..." -ForegroundColor Cyan
try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    $adminCount = ($admins | Measure-Object).Count
    
    if ($adminCount -le 2) {
        Add-AuditResult "Privileges" "Administrator Accounts" "PASS" "$adminCount accounts with admin privileges"
    } else {
        Add-AuditResult "Privileges" "Administrator Accounts" "WARN" "$adminCount accounts with admin privileges (review required)"
    }
} catch {
    Add-AuditResult "Privileges" "Administrator Accounts" "WARN" "Unable to check administrator group"
}

# 6. Password Policy
Write-Host "`nChecking Password Policy..." -ForegroundColor Cyan
try {
    $secpol = secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet
    $policyContent = Get-Content "$env:TEMP\secpol.cfg"
    
    $minPwdLength = ($policyContent | Select-String "MinimumPasswordLength").ToString().Split("=")[1].Trim()
    if ([int]$minPwdLength -ge 8) {
        Add-AuditResult "Password Policy" "Minimum Password Length" "PASS" "Minimum length is $minPwdLength characters"
    } else {
        Add-AuditResult "Password Policy" "Minimum Password Length" "FAIL" "Minimum length is only $minPwdLength characters (recommend 8+)"
    }
    
    Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue
} catch {
    Add-AuditResult "Password Policy" "Password Policy Check" "WARN" "Unable to retrieve password policy"
}

# 7. BitLocker Status
Write-Host "`nChecking BitLocker Encryption..." -ForegroundColor Cyan
try {
    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction Stop
    $osVolume = $bitlockerVolumes | Where-Object {$_.VolumeType -eq "OperatingSystem"}
    
    if ($osVolume.ProtectionStatus -eq "On") {
        Add-AuditResult "Encryption" "BitLocker Drive Encryption" "PASS" "OS drive is encrypted"
    } else {
        Add-AuditResult "Encryption" "BitLocker Drive Encryption" "FAIL" "OS drive is not encrypted"
    }
} catch {
    Add-AuditResult "Encryption" "BitLocker Drive Encryption" "WARN" "Unable to check BitLocker status (may not be available)"
}

# 8. UAC Status
Write-Host "`nChecking User Account Control..." -ForegroundColor Cyan
try {
    $uacValue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction Stop
    if ($uacValue.EnableLUA -eq 1) {
        Add-AuditResult "System" "User Account Control (UAC)" "PASS" "UAC is enabled"
    } else {
        Add-AuditResult "System" "User Account Control (UAC)" "FAIL" "UAC is disabled"
    }
} catch {
    Add-AuditResult "System" "User Account Control (UAC)" "WARN" "Unable to check UAC status"
}

# Close table
$htmlBody += "</table>`n"

# Add summary
$htmlSummary = @"
<div class="summary">
    <h2>Audit Summary</h2>
    <p><strong>Total Checks:</strong> $($passCount + $failCount + $warnCount)</p>
    <p><span class="pass">PASS:</span> $passCount | <span class="fail">FAIL:</span> $failCount | <span class="warn">WARN:</span> $warnCount</p>
</div>
"@

# Recommendations
$htmlRecommendations = @"
<h2>Recommendations</h2>
<ul>
    <li>Address all <span class="fail">[FAIL]</span> items immediately</li>
    <li>Review and resolve <span class="warn">[WARN]</span> items based on organizational policy</li>
    <li>Ensure Windows updates are applied regularly</li>
    <li>Review user accounts and remove unnecessary administrator privileges</li>
    <li>Enable BitLocker encryption on all drives containing sensitive data</li>
    <li>Keep antivirus definitions up to date</li>
</ul>
"@

# Close HTML
$htmlFooter = @"
<hr>
<p style="color: #7f8c8d; font-size: 12px;">Generated by Security-Compliance-Audit.ps1 on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
</body>
</html>
"@

# Combine all HTML parts
$fullHtml = $htmlHeader + $htmlSummary + $htmlBody + $htmlRecommendations + $htmlFooter

# Write to file
$fullHtml | Out-File -FilePath $reportFile -Encoding UTF8

# Display summary
Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host "Audit Summary" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "PASS: $passCount" -ForegroundColor Green
Write-Host "FAIL: $failCount" -ForegroundColor Red
Write-Host "WARN: $warnCount" -ForegroundColor Yellow
Write-Host "`nReport saved to: $reportFile" -ForegroundColor Cyan
Write-Host "======================================`n" -ForegroundColor Cyan

# Open report in default browser
Start-Process $reportFile
