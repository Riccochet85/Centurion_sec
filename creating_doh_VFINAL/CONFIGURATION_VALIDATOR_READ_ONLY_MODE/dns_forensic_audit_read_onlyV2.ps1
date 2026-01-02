&&&# ============================
# DNS FORENSIC AUDIT (READ-ONLY)
# CORRECTED ENUMERATION
# ============================

$ErrorActionPreference = 'Stop'

$LogRoot = "C:\Users\herbe\OneDrive\Apps\PowerShell\creating_doh_VFINAL\logs"
$LogFile = Join-Path $LogRoot 'audit_corrections.log'

if (-not (Test-Path $LogRoot)) {
    New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
}

function Log {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -Path $LogFile -Value $line
}

Log '=== START DNS FORENSIC AUDIT (READ-ONLY) ==='

# ----------------------------
# OS-LEVEL DNS (CORRECTED)
# ----------------------------
$dnsAll = Get-DnsClient |
    Where-Object { $_.ConnectionState -eq 'Connected' } |
    ForEach-Object {
        Get-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4,IPv6
    } |
    Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 }

$dnsAll | ForEach-Object {
    Log "Adapter [$($_.InterfaceAlias)] DNS: $($_.ServerAddresses -join ', ')"
}

# ----------------------------
# REGISTRY INTERFACE DNS
# ----------------------------
$ifaceRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
Get-ChildItem $ifaceRoot | ForEach-Object {
    $props = Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue
    foreach ($field in 'NameServer','DhcpNameServer') {
        if ($props.$field) {
            $dns = ($props.$field -split '[ ,]+' | Where-Object { $_ -ne '' })
            Log "Interface [$($_.PSChildName)] $field = $($dns -join ', ')"
        }
    }
}

# ----------------------------
# GLOBAL TCP/IP
# ----------------------------
$global = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
foreach ($field in 'NameServer','DhcpNameServer','SearchList') {
    if ($global.$field) {
        $dns = ($global.$field -split '[ ,]+' | Where-Object { $_ -ne '' })
        Log "GLOBAL $field = $($dns -join ', ')"
    }
}

# ----------------------------
# SYSTEM DOH
# ----------------------------
Get-DnsClientDohServerAddress | ForEach-Object {
    Log "DoH: $($_.ServerAddress) Template=$($_.DohTemplate)"
}

Log '=== END DNS FORENSIC AUDIT ==='
