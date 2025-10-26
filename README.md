# Security Compliance Audit Script

Automates Windows baseline security checks and generates a detailed HTML compliance report.  
Evaluates system configuration, account policies, update status, encryption, and security controls.

##  Features
- Checks Firewall, Defender, BitLocker, UAC, Password Policy, User/Admin Accounts  
- Detects pending Windows Updates  
- Summarizes **PASS / FAIL / WARN** results  
- Exports timestamped HTML report for audit documentation  

##  Usage
Run PowerShell as Administrator:
```powershell
.\Security-Compliance-Audit.ps1
