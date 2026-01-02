Absolutely, Herbé — here is a **clean, disciplined, audit‑ready README** for your orchestrator.  
It is written exactly the way a systems engineer would expect: explicit, structured, and aligned with the v2 engine you now have.

No fluff, no ambiguity — just doctrine.

---

# 📘 Neverland Firewall & Hosts Orchestrator  
### **README — Version 2 (Extended Rule Engine)**  
**Module:** `block_rules.py`  
**Purpose:** Silent, idempotent enforcement of firewall and hosts‑based blocking/allowing rules on Windows.

---

# 1. Overview

The Neverland Orchestrator is a **self‑contained, self‑locating, silent, elevated** automation module that:

### **1. Applies firewall rules**  
- Reads `firewall_rules.txt`  
- Supports **v1 legacy syntax** and **v2 extended syntax**  
- Implements:
  - `block` (concrete)
  - `allow` (concrete)
  - `drop` (stub)
  - `redirect` (stub)
  - `route` (stub)
- Supports:
  - Ports
  - Protocols
  - Profiles
  - Expiration dates
  - Labels (EN/ES)

### **2. Applies hosts rules**  
- Reads `hosts_rules.txt`  
- Adds `0.0.0.0 domain.tld` entries  
- Enforces idempotence  
- Logs all operations  

### **3. Logs everything**  
- `firewall_sumary_rules.csv`  
- `hosts_firewall_rules.csv`  

---

# 2. Execution Model

### **Silent Mode**
All stdout/stderr is redirected to `NUL`.  
The script produces **no console output**.

### **Elevation**
If not running as admin, the script relaunches itself with:

```
runas
```

### **Self‑Located**
All rule files and CSVs live in the same directory as the script.

---

# 3. File Structure

```
/Neverland/
    block_rules.py
    firewall_rules.txt
    hosts_rules.txt
    firewall_sumary_rules.csv
    hosts_firewall_rules.csv
```

---

# 4. Firewall Rules — Syntax & Behavior

The orchestrator supports **two syntaxes**:

---

## 4.1 Legacy v1 Syntax (Backward Compatible)

```
name|direction|ips
```

Example:

```
Neverland_Block_GoogleAnalytics|out|216.58.0.0/16
```

This is interpreted as:

- `action=block`
- `profile=any`
- All ports, all protocols

---

## 4.2 Extended v2 Syntax (Recommended)

```
action=<block|allow|drop|redirect|route> |
name=<rule_name> |
direction=<in|out> |
targets=<ip1,ip2,cidr,...> |
[port=<single_or_range>] |
[protocol=<tcp|udp|any>] |
[redirect_to=<ip:port>] |
[route_via=<gateway_ip>] |
profile=<any|domain|private|public> |
[expires=YYYY-MM-DD] |
[label:en=English label] |
[label:es=Spanish label]
```

### **Required fields**
- `action`
- `name`
- `direction`
- `targets`
- `profile`

### **Optional fields**
- `port`, `ports`
- `protocol`
- `redirect_to`
- `route_via`
- `expires`
- `label:en`, `label:es`

---

# 5. Supported Actions

### ✔ **block** (implemented)
Adds a Windows Firewall rule:

```
netsh advfirewall firewall add rule action=block ...
```

### ✔ **allow** (implemented)
Adds a Windows Firewall rule:

```
netsh advfirewall firewall add rule action=allow ...
```

### ⚠ **drop** (stub)
- Logged as skipped  
- Reserved for future silent‑deny implementation  

### ⚠ **redirect** (stub)
- Logged as skipped  
- Reserved for future transparent proxy/DNS redirection  

### ⚠ **route** (stub)
- Logged as skipped  
- Reserved for future gateway enforcement  

---

# 6. Ports & Protocols

### **Ports**
- `port=443`
- `ports=80,443`
- `port=1000-2000`

Mapped to:

```
remoteport=<value>
```

### **Protocols**
- `protocol=tcp`
- `protocol=udp`
- `protocol=any`

Mapped to:

```
protocol=TCP
protocol=UDP
```

---

# 7. Expiration

Rules may include:

```
expires=YYYY-MM-DD
```

If the date is **in the past**, the rule is **skipped** and logged as:

```
skipped-expired
```

---

# 8. Labels

Optional metadata:

```
label:en=Block Google Analytics
label:es=Bloquear Google Analytics
```

Stored in CSV logs for documentation.

---

# 9. Hosts Rules

### **Syntax**

```
0.0.0.0 domain.tld
```

### **Behavior**
- Validates domain format  
- Ensures idempotence  
- Appends to Windows hosts file  
- Logs `"added"` or `"exists"`  

---

# 10. CSV Logging

### **Firewall CSV**
`firewall_sumary_rules.csv` contains:

- timestamp  
- name  
- action  
- direction  
- targets  
- port  
- protocol  
- profile  
- expires  
- label_en  
- label_es  
- status  
- raw_line  

### **Hosts CSV**
`hosts_firewall_rules.csv` contains:

- timestamp  
- ip  
- domain  
- status  

---

# 11. Common Use Scenarios (Copy‑Paste Ready)

---

## 11.1 Block a service (IP-only)

```
action=block | name=Neverland_Block_GoogleAnalytics | direction=out | targets=216.58.0.0/16 | profile=any | label:en=Google Analytics CIDR
```

---

## 11.2 Allow only HTTPS outbound

```
action=allow | name=Neverland_Allow_HTTPS | direction=out | targets=0.0.0.0/0 | port=443 | protocol=tcp | profile=any | label:en=Allow HTTPS only
```

Drop everything else:

```
action=drop | name=Neverland_Drop_Other_Outgoing | direction=out | targets=0.0.0.0/0 | profile=any | label:en=Drop all non-HTTPS
```

---

## 11.3 Block QUIC (UDP 443)

```
action=block | name=Neverland_Block_QUIC | direction=out | targets=0.0.0.0/0 | port=443 | protocol=udp | profile=any | label:en=Block QUIC outbound
```

---

## 11.4 Redirect DNS to local resolver (future)

```
action=redirect | name=Neverland_Redirect_DNS | direction=out | targets=0.0.0.0/0 | port=53 | protocol=udp | redirect_to=127.0.0.1:5353 | profile=any | label:en=Force DNS to local
```

---

## 11.5 Route internal traffic through VPN (future)

```
action=route | name=Neverland_Route_Internal_VPN | direction=out | targets=10.0.0.0/8 | route_via=10.8.0.1 | profile=any | label:en=Route internal via VPN
```

---

## 11.6 Temporary block with expiration

```
action=block | name=Neverland_Block_bcgame | direction=out | targets=104.21.95.92,172.67.144.19 | profile=any | expires=2026-02-01 | label:en=Temporary bcgame block
```

---

# 12. Backward Compatibility

Any line in the old format:

```
Neverland_Block_X|out|1.2.3.4
```

Is automatically interpreted as:

```
action=block
profile=any
protocol=any
all ports
```

---

# 13. Future Extensions

The v2 engine already includes **hooks** for:

- `drop`
- `redirect`
- `route`
- `expires`
- `label:en`
- `label:es`
- `port`
- `protocol`

Implementing these fully requires only extending the `add_firewall_rule_v2()` function or adding routing/redirect subsystems.

---

# 14. Summary

The Neverland Orchestrator v2 is:

- Silent  
- Elevated  
- Idempotent  
- Backward compatible  
- Forward extensible  
- Fully documented  
- CSV‑audited  

It now supports a **professional‑grade rule schema** suitable for large‑scale, reproducible firewall governance.

---

If you want, I can also generate:

- A **linting tool** to validate rule files  
- A **rule pack** for common services (Google, Cloudflare, Meta, gambling, adult sites, trackers)  
- A **migration tool** to convert v1 → v2 automatically  

Just tell me the direction you want to take.
