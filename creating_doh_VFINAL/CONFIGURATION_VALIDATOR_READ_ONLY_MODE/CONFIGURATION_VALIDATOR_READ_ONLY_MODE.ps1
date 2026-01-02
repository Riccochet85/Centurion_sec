<# =====================================================================
   HERBÉ CONFIGURATION VALIDATOR — READ-ONLY MODE
   PURPOSE:
   - Validate DNS servers
   - Validate DoH profiles
   - Validate certificate binding
   - Validate HTTPS listener
   - Validate Neverland Orchestrator presence
   - Validate firewall rules existence
   - Validate adapter status
   - Produce a clean, structured report
   - NO CHANGES ARE MADE TO THE SYSTEM
   ===================================================================== #>

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

Write-Host "=== HERBÉ CONFIGURATION VALIDATION REPORT ===`n"

# -------------------------------
# PATHS
# -------------------------------
$BasePath = "C:\Users\herbe\OneDrive\Apps\PowerShell\creating_doh\Cloudflare_DoH_Hardening_Orchestration_V2"
$NeverlandEngine = Join-Path $BasePath "block_rules.py"
$FirewallRules = Join-Path $BasePath "firewall_rules.txt"
$HostsRules = Join-Path $BasePath "hosts_rules.txt"

Write-Host "Base Path: $BasePath"
Write-Host "Neverland Engine: $NeverlandEngine"
Write-Host "Firewall Rules File: $FirewallRules"
Write-Host "Hosts Rules File: $HostsRules"
Write-Host ""

# -------------------------------
# 1. Validate Network Adapters
# -------------------------------
Write-Host "=== NETWORK ADAPTERS ==="
$adapters = Get-NetAdapter -Physical

if (-not $adapters) {
    Write-Host "❌ No physical adapters found."
} else {
    foreach ($adapter in $adapters) {
        Write-Host "Adapter: $($adapter.Name) — Status: $($adapter.Status)"
    }
}
Write-Host ""

# -------------------------------
# 2. Validate DNS Servers
# -------------------------------
Write-Host "=== DNS SERVERS ==="
$expectedDNS4 = @("1.1.1.1","1.0.0.1")
$expectedDNS6 = @("2606:4700:4700::1111","2606:4700:4700::1001")

foreach ($adapter in $adapters) {
    Write-Host "`nAdapter: $($adapter.Name)"

    $dns = Get-DnsClientServerAddress -InterfaceAlias $adapter.Name

    $current4 = $dns | Where-Object AddressFamily -eq 2 | Select-Object -ExpandProperty ServerAddresses
    $current6 = $dns | Where-Object AddressFamily -eq 23 | Select-Object -ExpandProperty ServerAddresses

    Write-Host "IPv4 DNS: $($current4 -join ', ')"
    Write-Host "IPv6 DNS: $($current6 -join ', ')"

    if ($current4 -eq $expectedDNS4) { Write-Host "✔ IPv4 DNS OK" } else { Write-Host "❌ IPv4 DNS mismatch" }
    if ($current6 -eq $expectedDNS6) { Write-Host "✔ IPv6 DNS OK" } else { Write-Host "❌ IPv6 DNS mismatch" }
}
Write-Host ""

# -------------------------------
# 3. Validate DoH Profiles
# -------------------------------
Write-Host "=== DOH PROFILES ==="
$requiredDoH = $expectedDNS4 + $expectedDNS6
$currentDoH = Get-DnsClientDohServerAddress

if (-not $currentDoH) {
    Write-Host "❌ No DoH profiles found."
} else {
    foreach ($ip in $requiredDoH) {
        if ($currentDoH.ServerAddress -contains $ip) {
            Write-Host "✔ DoH profile exists for $ip"
        } else {
            Write-Host "❌ Missing DoH profile for $ip"
        }
    }
}
Write-Host ""

# -------------------------------
# 4. Validate Certificate Binding
# -------------------------------
Write-Host "=== CERTIFICATE BINDING ==="
$bindings = netsh http show sslcert

if ($bindings -match "0.0.0.0:443") {
    Write-Host "✔ Certificate bound to port 443"
} else {
    Write-Host "❌ No certificate binding found on port 443"
}
Write-Host ""

# -------------------------------
# 5. Validate HTTPS Listener
# -------------------------------
Write-Host "=== HTTPS LISTENER ==="
$listener = netstat -ano | Select-String ":443"

if ($listener) {
    Write-Host "✔ Port 443 listener active"
} else {
    Write-Host "❌ No active listener on port 443"
}
Write-Host ""

# -------------------------------
# 6. Validate Neverland Orchestrator Files
# -------------------------------
Write-Host "=== NEVERLAND ORCHESTRATOR FILES ==="

if (Test-Path $NeverlandEngine) { Write-Host "✔ block_rules.py found" } else { Write-Host "❌ block_rules.py missing" }
if (Test-Path $FirewallRules) { Write-Host "✔ firewall_rules.txt found" } else { Write-Host "❌ firewall_rules.txt missing" }
if (Test-Path $HostsRules) { Write-Host "✔ hosts_rules.txt found" } else { Write-Host "❌ hosts_rules.txt missing" }

Write-Host ""

# -------------------------------
# 7. Validate Firewall Rules (basic presence)
# -------------------------------
Write-Host "=== FIREWALL RULES ==="
$neverlandRules = Get-NetFirewallRule | Where-Object DisplayName -like "Neverland*"

if ($neverlandRules) {
    Write-Host "✔ Neverland firewall rules detected: $($neverlandRules.Count)"
} else {
    Write-Host "❌ No Neverland firewall rules found"
}
Write-Host ""

# -------------------------------
# END REPORT
# -------------------------------
Write-Host "=== VALIDATION COMPLETE ==="
