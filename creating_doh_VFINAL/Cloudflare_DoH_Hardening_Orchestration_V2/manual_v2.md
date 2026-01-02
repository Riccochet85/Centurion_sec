Absolutely, Herbé — here is the **clean, authoritative, V2‑aligned manual**, rewritten from scratch to match the **final architecture**, including:

- The **standalone task‑creation script behavior**  
- The **self‑registering main script behavior**  
- The **final file paths**  
- The **V2 adapter‑selection logic**  
- The **V2 logging model**  

Everything is explicit, deterministic, and audit‑ready — exactly your style.

---

# 📘 **Cloudflare DoH Hardening Orchestration — V2 Technical Manual**  
**Explicit. Deterministic. Audit‑Ready.**

This manual documents the **final V2 architecture**, including:

- Script location  
- Script behavior  
- Task Scheduler integration  
- Logging  
- Adapter detection  
- Firewall enforcement  
- Verification steps  

This is the authoritative reference for the system.

---

# 1. **SYSTEM ARCHITECTURE OVERVIEW**

The DoH enforcement system consists of:

### **1.1 Main Enforcement Script (V2)**  
Location:

```
D:\TLS_Secure\DoH\Cloudflare_DoH_Hardening_Orchestration.ps1
```

This script performs:

- Cloudflare‑only DoH registration  
- Removal of all non‑Cloudflare DoH entries  
- DNS server assignment (IPv4 + IPv6)  
- Adapter detection (V2 hardened logic)  
- Firewall hardening (block TCP/UDP 53)  
- Logging to `C:\Logs\CloudflareDoH-Hardening.log`  
- **Self‑registration in Task Scheduler**  

### **1.2 Optional Standalone Task Script (V2)**  
If executed separately, it **will create the task**, but **only if Write‑Log is removed or defined**.

---

# 2. **SCRIPT LOCATION AND PERMISSIONS**

### **2.1 Script Path**
The script must reside at:

```
D:\TLS_Secure\DoH\Cloudflare_DoH_Hardening_Orchestration.ps1
```

### **2.2 Required Privileges**
The script must be executed:

- As **Administrator**  
- With **ExecutionPolicy Bypass** (handled automatically by Task Scheduler)

---

# 3. **LOGGING MODEL (V2)**

All actions are logged to:

```
C:\Logs\CloudflareDoH-Hardening.log
```

The script:

- Creates the folder if missing  
- Appends timestamped entries  
- Logs success and failure of each operation  
- Logs task creation status  

Logging is deterministic and never silent.

---

# 4. **CLOUDFLARE DoH CONFIGURATION (V2)**

### **4.1 DoH Template**
```
https://cloudflare-dns.com/dns-query
```

### **4.2 IPv4 Servers**
```
1.1.1.1
1.0.0.1
```

### **4.3 IPv6 Servers**
```
2606:4700:4700::1111
2606:4700:4700::1001
```

### **4.4 Behavior**
The script:

- Removes all existing DoH entries not matching Cloudflare  
- Re‑adds all four Cloudflare entries  
- Enforces `AllowFallbackToUdp = False`  
- Enforces `AutoUpgrade = True`  

---

# 5. **ADAPTER DETECTION (V2)**

The V2 logic is hardened to avoid failures caused by:

- OneDrive virtualization  
- Virtual adapters  
- Loopback interfaces  
- Pseudo‑interfaces  

### **5.1 Primary Selection**
```
Get-DnsClient |
  Where-Object {
      $_.InterfaceAlias -notlike '*Loopback*' -and
      $_.InterfaceAlias -notlike '*Virtual*' -and
      $_.InterfaceAlias -notlike '*Pseudo*' -and
      $_.InterfaceOperationalStatus -eq 'Up'
  } |
  Sort-Object InterfaceIndex |
  Select-Object -First 1
```

### **5.2 Fallback**
If no adapter is detected:

```
Get-DnsClient | Select-Object -First 1
```

This guarantees deterministic adapter selection.

---

# 6. **DNS ASSIGNMENT (V2)**

### **6.1 IPv4**
```
Set-DnsClientServerAddress -InterfaceAlias <adapter> -ServerAddresses 1.1.1.1,1.0.0.1
```

### **6.2 IPv6**
```
Set-DnsClientServerAddress -InterfaceAlias <adapter> -ServerAddresses 2606:4700:4700::1111,2606:4700:4700::1001
```

---

# 7. **FIREWALL HARDENING (V2)**

The script removes any existing rules with the same names, then creates:

### **7.1 Block TCP 53**
```
New-NetFirewallRule -DisplayName "BLOCK_DNS_TCP_53" -Direction Outbound -Protocol TCP -RemotePort 53 -Action Block
```

### **7.2 Block UDP 53**
```
New-NetFirewallRule -DisplayName "BLOCK_DNS_UDP_53" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Block
```

This prevents plaintext DNS leaks.

---

# 8. **TASK SCHEDULER INTEGRATION (V2)**

### **8.1 Self‑Registration**
The main script automatically executes:

```
schtasks /create /tn "Cloudflare DoH Enforcement" /sc onlogon /ru SYSTEM /tr "powershell.exe -ExecutionPolicy Bypass -File D:\TLS_Secure\DoH\Cloudflare_DoH_Hardening_Orchestration.ps1" /f
```

### **8.2 Behavior**
- If run manually → task is created  
- If run as a module → task is created  
- If run from Task Scheduler → task is already present  

### **8.3 Requirements**
- Must be run as Administrator  
- Script path must exist  

---

# 9. **OPTIONAL STANDALONE TASK SCRIPT (V2)**

If you run only the task block:

- It **will create the task**  
- Write‑Log must be removed or defined  

Minimal standalone version:

```
schtasks /create /tn "Cloudflare DoH Enforcement" /sc onlogon /ru SYSTEM /tr "powershell.exe -ExecutionPolicy Bypass -File D:\TLS_Secure\DoH\Cloudflare_DoH_Hardening_Orchestration.ps1" /f
```

---

# 10. **VERIFICATION PROCEDURES**

### **10.1 Verify DoH entries**
```
Get-DnsClientDohServerAddress
```

### **10.2 Verify DNS resolution**
```
Resolve-DnsName microsoft.com
```

### **10.3 Verify HTTPS traffic**
```
Get-NetTCPConnection -RemotePort 443 | Where-Object { $_.State -eq 'Established' }
```

### **10.4 Verify scheduled task**
```
schtasks /query /tn "Cloudflare DoH Enforcement"
```

---

# 11. **SYSTEM STATE AFTER V2 DEPLOYMENT**

Your system now:

- Uses Cloudflare DoH exclusively  
- Blocks plaintext DNS  
- Enforces configuration at every logon  
- Logs all actions  
- Uses hardened adapter detection  
- Has a deterministic, reproducible configuration  

---

