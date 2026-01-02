<#
HEADER: Cloudflare DoH Hardening Orchestration
Service: Local DNS Enforcement Layer
Executable: PowerShell Host (invoked by administrator)
Controller: Enforces Cloudflare-Only DoH Configuration
Privilege: Requires Administrator (network + firewall modification)
Audit: All actions logged to C:\Logs\CloudflareDoH-Hardening.log
Deployment: schtasks /create /tn "Cloudflare DoH Enforcement" /sc onlogon /ru SYSTEM /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\CloudflareDoH-Hardening.ps1"
#>

# =========================
# Initialization and logging
# =========================

$LogPath = 'C:\Logs\CloudflareDoH-Hardening.log'
$LogDir  = Split-Path -Path $LogPath -Parent

if (-not (Test-Path -Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $LogPath -Value ("{0}`t{1}" -f $timestamp, $Message)
}

Write-Log "=== Cloudflare DoH Hardening Script Start ==="

# ======================
# Privilege verification
# ======================

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Administrator privileges are required." -ForegroundColor Red
    Write-Log  "ERROR: Script aborted. Administrator privileges not detected."
    exit 1
}

Write-Log "Privilege check passed: running as Administrator."

# ============================
# Define Cloudflare DoH config
# ============================

$CloudflareDohTemplate = 'https://cloudflare-dns.com/dns-query'

$CloudflareServersIPv4 = @('1.1.1.1','1.0.0.1')
$CloudflareServersIPv6 = @('2606:4700:4700::1111','2606:4700:4700::1001')
$AllCloudflareServers  = $CloudflareServersIPv4 + $CloudflareServersIPv6

Write-Log ("Cloudflare DoH template: {0}" -f $CloudflareDohTemplate)
Write-Log ("Cloudflare IPv4: {0}" -f ($CloudflareServersIPv4 -join ', '))
Write-Log ("Cloudflare IPv6: {0}" -f ($CloudflareServersIPv6 -join ', '))

# ==========================================
# Remove all non-Cloudflare DoH registrations
# ==========================================

Write-Log "Removing all non-Cloudflare DoH entries."

try {
    $existingDoh = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
    if ($existingDoh) {
        $nonCloudflare = $existingDoh | Where-Object { $_.DohTemplate -ne $CloudflareDohTemplate }
        foreach ($entry in $nonCloudflare) {
            Write-Log ("Removing DoH entry: {0} ({1})" -f $entry.ServerAddress, $entry.DohTemplate)
            Remove-DnsClientDohServerAddress -ServerAddress $entry.ServerAddress -ErrorAction SilentlyContinue
        }
    } else {
        Write-Log "No existing DoH entries found."
    }
} catch {
    Write-Log ("ERROR removing non-Cloudflare DoH entries: {0}" -f $_.Exception.Message)
}

# ====================================
# Ensure Cloudflare DoH entries present
# ====================================

Write-Log "Ensuring Cloudflare DoH entries exist."

foreach ($ip in $AllCloudflareServers) {
    try {
        Remove-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue

        Write-Log ("Adding Cloudflare DoH entry for {0}" -f $ip)
        Add-DnsClientDohServerAddress `
            -ServerAddress $ip `
            -DohTemplate $CloudflareDohTemplate `
            -AllowFallbackToUdp $false `
            -AutoUpgrade $true `
            -ErrorAction Stop
    } catch {
        Write-Log ("ERROR adding DoH entry for {0}: {1}" -f $ip, $_.Exception.Message)
    }
}

# ==========================
# Select active network adapter
# ==========================

Write-Log "Selecting active network adapter."

$adapter = Get-DnsClient |
    Where-Object {
        $_.InterfaceAlias -notlike '*Loopback*' -and
        $_.InterfaceOperationalStatus -eq 'Up'
    } |
    Select-Object -First 1

if (-not $adapter) {
    Write-Host "ERROR: No active network adapter found." -ForegroundColor Red
    Write-Log  "ERROR: No active network adapter found."
    exit 1
}

$adapterName = $adapter.InterfaceAlias
Write-Log ("Using adapter: {0}" -f $adapterName)

# =====================================
# Assign Cloudflare as system DNS (IPv4)
# =====================================

try {
    Write-Log ("Setting IPv4 DNS: {0}" -f ($CloudflareServersIPv4 -join ', '))
    Set-DnsClientServerAddress -InterfaceAlias $adapterName -ServerAddresses $CloudflareServersIPv4 -ErrorAction Stop
} catch {
    Write-Log ("ERROR setting IPv4 DNS: {0}" -f $_.Exception.Message)
}

# =====================================
# Assign Cloudflare as system DNS (IPv6)
# =====================================

try {
    Write-Log ("Setting IPv6 DNS: {0}" -f ($CloudflareServersIPv6 -join ', '))
    Set-DnsClientServerAddress -InterfaceAlias $adapterName -ServerAddresses $CloudflareServersIPv6 -ErrorAction Stop
} catch {
    Write-Log ("ERROR setting IPv6 DNS: {0}" -f $_.Exception.Message)
}

# =================================
# Harden firewall: block DNS port 53
# =================================

Write-Log "Blocking outbound DNS port 53 (TCP/UDP)."

$rules = @(
    @{ Name='BLOCK_DNS_TCP_53'; Protocol='TCP'; Port=53 },
    @{ Name='BLOCK_DNS_UDP_53'; Protocol='UDP'; Port=53 }
)

foreach ($rule in $rules) {
    try {
        Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

        Write-Log ("Creating firewall rule: {0}" -f $rule.Name)
        New-NetFirewallRule `
            -DisplayName $rule.Name `
            -Direction Outbound `
            -Protocol $rule.Protocol `
            -RemotePort $rule.Port `
            -Action Block `
            -ErrorAction Stop | Out-Null
    } catch {
        Write-Log ("ERROR creating firewall rule {0}: {1}" -f $rule.Name, $_.Exception.Message)
    }
}

# ===================================
# Verification guidance
# ===================================

Write-Host ""
Write-Host "Verification steps:" -ForegroundColor Cyan
Write-Host "  Get-DnsClientDohServerAddress" -ForegroundColor Yellow
Write-Host "  Resolve-DnsName microsoft.com" -ForegroundColor Yellow
Write-Host "  Get-NetTCPConnection -RemotePort 443 | Where-Object {`$_.State -eq 'Established'}" -ForegroundColor Yellow
Write-Host ""

Write-Log "Cloudflare DoH configuration and firewall hardening completed."
Write-Log "=== Cloudflare DoH Hardening Script End ==="