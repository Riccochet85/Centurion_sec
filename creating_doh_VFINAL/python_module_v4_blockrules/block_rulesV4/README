# Cloudflare DoH Hardening Orchestration
Explicit, deterministic, audit‑ready orchestration for enforcing Cloudflare‑only DNS‑over‑HTTPS (DoH) on Windows systems.

This project provides:
- A hardened PowerShell script that removes all non‑Cloudflare DoH providers
- Registers Cloudflare DoH endpoints explicitly (IPv4 + IPv6)
- Assigns Cloudflare DNS servers to the active network adapter
- Blocks plaintext DNS (TCP/UDP port 53)
- Logs all actions to an audit file
- Supports automated deployment via Windows Task Scheduler

---

## Features

### 1. Cloudflare‑Only DoH Enforcement
The script registers the following DoH endpoints:

- **IPv4**
  - `1.1.1.1`
  - `1.0.0.1`

- **IPv6**
  - `2606:4700:4700::1111`
  - `2606:4700:4700::1001`

All mapped to:  Herbé — perfect, I’ll give you three things, clean and aligned with your standards:
- A Task Scheduler command (final, explicit, deterministic)
- A README.md (GitHub‑ready, technical, audit‑oriented)
- A Git commit message (concise, conventional‑commit style)
No fluff. No abstractions. No placeholders. Everything explicit.

🔵 1. TASK SCHEDULER COMMAND (FINAL VERSION)
This creates a SYSTEM‑level scheduled task that runs your DoH hardening script at logon.
Replace the path only if your script lives somewhere else.
schtasks /create /tn "Cloudflare DoH Enforcement" /sc onlogon /ru SYSTEM /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\CloudflareDoH-Hardening.ps1"


This matches the header you approved.

🔵 2. README.md (GITHUB‑READY)
Below is the full README text.
You can paste it directly into README.md in your repository.
# Cloudflare DoH Hardening Orchestration
Explicit, deterministic, audit‑ready orchestration for enforcing Cloudflare‑only DNS‑over‑HTTPS (DoH) on Windows systems.

This project provides:
- A hardened PowerShell script that removes all non‑Cloudflare DoH providers
- Registers Cloudflare DoH endpoints explicitly (IPv4 + IPv6)
- Assigns Cloudflare DNS servers to the active network adapter
- Blocks plaintext DNS (TCP/UDP port 53)
- Logs all actions to an audit file
- Supports automated deployment via Windows Task Scheduler

---

## Features

### 1. Cloudflare‑Only DoH Enforcement
The script registers the following DoH endpoints:

- **IPv4**
  - `1.1.1.1`
  - `1.0.0.1`

- **IPv6**
  - `2606:4700:4700::1111`
  - `2606:4700:4700::1001`

All mapped to:


https://cloudflare-dns.com/dns-query

### 2. Removal of Non‑Cloudflare Providers
The script removes Google, Quad9, and any other DoH templates present on the system.

### 3. DNS Assignment
The active network adapter is configured to use Cloudflare DNS exclusively.

### 4. Firewall Hardening
Outbound DNS on port 53 (TCP/UDP) is blocked to prevent plaintext DNS leaks.

### 5. Logging
All actions are logged to:


C:\Logs\CloudflareDoH-Hardening.log

---

## Deployment

### 1. Place the script
Save the script as:


C:\Scripts\CloudflareDoH-Hardening.ps1

### 2. Create the scheduled task
Run the following command as Administrator:


schtasks /create /tn "Cloudflare DoH Enforcement" /sc onlogon /ru SYSTEM /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\CloudflareDoH-Hardening.ps1"

This ensures the configuration is re‑applied at every logon.

---

## Verification

### Check DoH entries:


Get-DnsClientDohServerAddress

### Test DNS resolution:


Resolve-DnsName microsoft.com

### Confirm HTTPS traffic:


Get-NetTCPConnection -RemotePort 443  Where-Object { $_.State -eq 'Established' }

---

## License
This repository is provided without warranty. Use at your own discretion.



🔵 3. GIT COMMIT MESSAGE (CONVENTIONAL‑COMMITS STYLE)
Here is a clean, professional commit message for adding the script and README:
feat: add Cloudflare DoH hardening orchestration script and documentation

- Added CloudflareDoH-Hardening.ps1 with full enforcement logic
- Implemented Cloudflare-only DoH registration (IPv4 + IPv6)
- Added firewall rules to block plaintext DNS (TCP/UDP 53)
- Added audit logging to C:\Logs\CloudflareDoH-Hardening.log
- Added README.md with deployment instructions and verification steps
- Included Task Scheduler command for automated enforcement


