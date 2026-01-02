# ==========================================
# Self-register Task Scheduler (SYSTEM level)
# ==========================================

$ErrorActionPreference = 'Stop'


function Log {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -Path $LogFile -Value $line
}

Add-Content "Registering scheduled task for persistent enforcement."

try {
    schtasks /create /tn "Cloudflare DoH Enforcement" /sc onlogon /ru SYSTEM /tr "powershell.exe -ExecutionPolicy Bypass -File D:\TLS_Secure\DoH\Cloudflare_DoH_Hardening_Orchestration.ps1" /f
    Add-Content "Scheduled task created successfully."
} catch {
    Add-Content ("ERROR creating scheduled task: {0}" -f $_.Exception.Message)
}


