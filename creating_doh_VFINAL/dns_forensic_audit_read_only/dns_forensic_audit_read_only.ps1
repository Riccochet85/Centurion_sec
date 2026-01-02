<# =====================================================================
   HERBÉ dns_forensic_audit_read_only.ps1
   PURPOSE:
   - Enumerate ALL DNS resolvers from:
       * TCP/IP interface registry
       * Global TCP/IP parameters
       * Active adapter configuration
       * NRPT (Name Resolution Policy Table)
       * System DoH configuration
       * Hosts file
       * Firewall rules related to DNS
   - Highlight anything NOT in the allowed Cloudflare set:
       1.1.1.1
       1.0.0.1
       2606:4700:4700::1111
       2606:4700:4700::1001
   - NO MODIFICATIONS. PURE OBSERVATION.
   ===================================================================== #>

Write-Host "=== HERBÉ DNS FORENSIC AUDIT — READ-ONLY ===`n"

$AllowedV4 = @("1.1.1.1","1.0.0.1")
$AllowedV6 = @("2606:4700:4700::1111","2606:4700:4700::1001")

function Show-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host "=== $Title ==="
}

# -------------------------------
# 1. Active adapter DNS (OS view)
# -------------------------------
Show-Header "ACTIVE ADAPTER DNS (Get-DnsClientServerAddress)"

$dnsAll = Get-DnsClientServerAddress -All

$dnsAll | Select-Object InterfaceAlias, AddressFamily, ServerAddresses | Format-Table -AutoSize

$SuspiciousAdapterDNS = $dnsAll |
    ForEach-Object {
        $fam = $_.AddressFamily
        $srv = $_.ServerAddresses
        if ($srv) {
            $notAllowed = @()
            foreach ($ip in $srv) {
                if ($fam -eq 2 -and $AllowedV4 -notcontains $ip) { $notAllowed += $ip }
                if ($fam -eq 23 -and $AllowedV6 -notcontains $ip) { $notAllowed += $ip }
            }
            if ($notAllowed.Count -gt 0) {
                [PSCustomObject]@{
                    InterfaceAlias = $_.InterfaceAlias
                    AddressFamily  = $fam
                    NotAllowedDNS  = ($notAllowed -join ", ")
                }
            }
        }
    }

if ($SuspiciousAdapterDNS) {
    Write-Host "`n❌ NON-ALLOWED ADAPTER DNS FOUND:"
    $SuspiciousAdapterDNS | Format-Table -AutoSize
} else {
    Write-Host "`n✔ No non-allowed adapter DNS detected (OS-level)."
}

# -------------------------------
# 2. Registry: Interface DNS
# -------------------------------
Show-Header "REGISTRY: INTERFACE-LEVEL DNS (Tcpip Parameters\\Interfaces)"

$ifRoot = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
$ifKeys = Get-ChildItem $ifRoot

$RegInterfaceDNS = foreach ($k in $ifKeys) {
    $ns   = $k.GetValue("NameServer")
    $dhcp = $k.GetValue("DhcpNameServer")
    if ($ns -or $dhcp) {
        [PSCustomObject]@{
            KeyPath        = $k.PSPath
            NameServer     = $ns
            DhcpNameServer = $dhcp
        }
    }
}

if ($RegInterfaceDNS) {
    $RegInterfaceDNS | Format-Table -AutoSize

    $SuspiciousRegDNS = @()

    foreach ($entry in $RegInterfaceDNS) {
        foreach ($field in @("NameServer","DhcpNameServer")) {
            $val = $entry.$field
            if ([string]::IsNullOrWhiteSpace($val)) { continue }
            $ips = $val -split "[ ,;]+" | Where-Object { $_ -ne "" }
            $notAllowed = @()
            foreach ($ip in $ips) {
                if ($ip -match ":") {
                    if ($AllowedV6 -notcontains $ip) { $notAllowed += $ip }
                } else {
                    if ($AllowedV4 -notcontains $ip) { $notAllowed += $ip }
                }
            }
            if ($notAllowed.Count -gt 0) {
                $SuspiciousRegDNS += [PSCustomObject]@{
                    KeyPath    = $entry.KeyPath
                    Field      = $field
                    NotAllowed = ($notAllowed -join ", ")
                }
            }
        }
    }

    if ($SuspiciousRegDNS) {
        Write-Host "`n❌ NON-ALLOWED REGISTRY INTERFACE DNS FOUND:"
        $SuspiciousRegDNS | Format-Table -AutoSize
    } else {
        Write-Host "`n✔ No non-allowed DNS in registry interface keys."
    }
} else {
    Write-Host "No NameServer/DhcpNameServer entries found in interface registry keys."
}

# -------------------------------
# 3. Registry: Global TCP/IP DNS
# -------------------------------
Show-Header "REGISTRY: GLOBAL TCP/IP PARAMETERS"

$tcpGlobal = Get-Item "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

$GlobalNameServer = $tcpGlobal.GetValue("NameServer")
$GlobalDhcpNameServer = $tcpGlobal.GetValue("DhcpNameServer")
$SearchList = $tcpGlobal.GetValue("SearchList")

[PSCustomObject]@{
    NameServer     = $GlobalNameServer
    DhcpNameServer = $GlobalDhcpNameServer
    SearchList     = $SearchList
} | Format-Table -AutoSize

$fieldsToCheck = @{
    "NameServer"     = $GlobalNameServer
    "DhcpNameServer" = $GlobalDhcpNameServer
}

$SuspiciousGlobal = @()

foreach ($kvp in $fieldsToCheck.GetEnumerator()) {
    $field = $kvp.Key
    $val   = $kvp.Value
    if ([string]::IsNullOrWhiteSpace($val)) { continue }
    $ips = $val -split "[ ,;]+" | Where-Object { $_ -ne "" }
    $notAllowed = @()
    foreach ($ip in $ips) {
        if ($ip -match ":") {
            if ($AllowedV6 -notcontains $ip) { $notAllowed += $ip }
        } else {
            if ($AllowedV4 -notcontains $ip) { $notAllowed += $ip }
        }
    }
    if ($notAllowed.Count -gt 0) {
        $SuspiciousGlobal += [PSCustomObject]@{
            Field      = $field
            NotAllowed = ($notAllowed -join ", ")
        }
    }
}

if ($SuspiciousGlobal) {
    Write-Host "`n❌ NON-ALLOWED GLOBAL TCP/IP DNS FOUND:"
    $SuspiciousGlobal | Format-Table -AutoSize
} else {
    Write-Host "`n✔ No non-allowed DNS in global TCP/IP parameters."
}

# -------------------------------
# 4. NRPT (Name Resolution Policy Table)
# -------------------------------
Show-Header "NRPT (Name Resolution Policy Table)"

try {
    $nrpt = Get-DnsClientNrptPolicy -ErrorAction Stop
    if ($nrpt) {
        $nrpt | Select-Object Namespace, NameServers, DirectAccess | Format-Table -AutoSize

        $SuspiciousNRPT = @()
        foreach ($rule in $nrpt) {
            if ($rule.NameServers) {
                $ips = $rule.NameServers -split "[ ,;]+" | Where-Object { $_ -ne "" }
                $notAllowed = @()
                foreach ($ip in $ips) {
                    if ($ip -match ":") {
                        if ($AllowedV6 -notcontains $ip) { $notAllowed += $ip }
                    } else {
                        if ($AllowedV4 -notcontains $ip) { $notAllowed += $ip }
                    }
                }
                if ($notAllowed.Count -gt 0) {
                    $SuspiciousNRPT += [PSCustomObject]@{
                        Namespace  = $rule.Namespace
                        NotAllowed = ($notAllowed -join ", ")
                    }
                }
            }
        }

        if ($SuspiciousNRPT) {
            Write-Host "`n❌ NON-ALLOWED NRPT DNS FOUND:"
            $SuspiciousNRPT | Format-Table -AutoSize
        } else {
            Write-Host "`n✔ No non-allowed DNS in NRPT policies."
        }
    } else {
        Write-Host "No NRPT policies defined."
    }
} catch {
    Write-Host "NRPT not available on this system or access denied."
}

# -------------------------------
# 5. System DoH configuration
# -------------------------------
Show-Header "SYSTEM DOH CONFIGURATION"

$Doh = Get-DnsClientDohServerAddress
if ($Doh) {
    $Doh | Format-Table -AutoSize

    $SuspiciousDoh = @()
    foreach ($entry in $Doh) {
        $ip = $entry.ServerAddress
        if ($ip -match ":") {
            if ($AllowedV6 -notcontains $ip) {
                $SuspiciousDoh += $entry
            }
        } else {
            if ($AllowedV4 -notcontains $ip) {
                $SuspiciousDoh += $entry
            }
        }
    }

    if ($SuspiciousDoh) {
        Write-Host "`n❌ NON-ALLOWED DOH RESOLVERS FOUND:"
        $SuspiciousDoh | Format-Table -AutoSize
    } else {
        Write-Host "`n✔ All DoH resolvers are in allowed Cloudflare set."
    }
} else {
    Write-Host "No DoH configuration found."
}

# -------------------------------
# 6. Hosts file inspection
# -------------------------------
Show-Header "HOSTS FILE"

$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"

if (Test-Path $hostsPath) {
    $hostsLines = Get-Content $hostsPath | Where-Object { -not ($_ -match '^\s*#') -and $_.Trim() -ne "" }
    if ($hostsLines) {
        $hostsLines | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "Hosts file contains no active entries."
    }
} else {
    Write-Host "Hosts file not found at $hostsPath (unexpected)."
}

# -------------------------------
# 7. Firewall rules related to DNS
# -------------------------------
Show-Header "FIREWALL RULES: DNS (PORT 53)"

$fwDNS = Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object {
        ($_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue).RemotePort -contains 53
    }

if ($fwDNS) {
    $fwDNS |
        Select-Object DisplayName, Direction, Action, Enabled, Profile |
        Format-Table -AutoSize

    # Note: deeper inspection of RemoteAddress would require joining with address filter:
    $fwDetailed = foreach ($rule in $fwDNS) {
        $addr = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            DisplayName   = $rule.DisplayName
            Direction     = $rule.Direction
            Action        = $rule.Action
            RemoteAddress = ($addr.RemoteAddress -join ", ")
        }
    }

    Write-Host "`nDNS Firewall Rule Address Detail:"
    $fwDetailed | Format-Table -AutoSize
} else {
    Write-Host "No firewall rules specifically referencing port 53 found."
}

Write-Host "`n=== HERBÉ DNS FORENSIC AUDIT COMPLETE (READ-ONLY) ==="
