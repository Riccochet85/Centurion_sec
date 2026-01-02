# ======================================================
# block_rules.py (v4.1 – TRUE SILENT)
# REQUIREMENTS:
#   - Must run as SYSTEM or Administrator
#   - No self-elevation (by design)
# ======================================================

import os
import re
import sys
import csv
import subprocess
import hashlib
from datetime import datetime, date

# ------------------------------------------------------
# HARD SILENCE (NO ESCAPE)
# ------------------------------------------------------
DEVNULL = open(os.devnull, "w")
sys.stdout = DEVNULL
sys.stderr = DEVNULL

# ------------------------------------------------------
# Paths (self-located)
# ------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

FIREWALL_TXT = os.path.join(BASE_DIR, "firewall_rules.txt")
HOSTS_TXT    = os.path.join(BASE_DIR, "hosts_rules.txt")

FW_CSV    = os.path.join(BASE_DIR, "firewall_sumary_rules.csv")
HOSTS_CSV = os.path.join(BASE_DIR, "hosts_firewall_rules.csv")

HOSTS_PATH = os.path.join(
    os.environ["SystemRoot"], "System32", "drivers", "etc", "hosts"
)

for p in (FW_CSV, HOSTS_CSV):
    if not os.path.exists(p):
        open(p, "w", encoding="utf-8").close()

# ------------------------------------------------------
# Regex
# ------------------------------------------------------
RULE_V1_RE = re.compile(r"^([^|]+)\|(in|out)\|(.+)$", re.IGNORECASE)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)

# ------------------------------------------------------
# Hash
# ------------------------------------------------------
def rule_hash(rule: dict) -> str:
    payload = "|".join([
        rule.get("name", ""),
        rule.get("action", ""),
        rule.get("direction", ""),
        rule.get("targets", ""),
        rule.get("protocol", ""),
        rule.get("port") or rule.get("ports", ""),
        rule.get("profile", "")
    ])
    return hashlib.sha256(payload.encode()).hexdigest()

# ------------------------------------------------------
# Parsing
# ------------------------------------------------------
def parse_rule(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if "action=" in line:
        data = {}
        for seg in line.split("|"):
            if "=" in seg:
                k, v = seg.split("=", 1)
                data[k.strip().lower()] = v.strip()
        if not all(k in data for k in ("action", "name", "direction", "targets")):
            return None
        data["protocol"] = data.get("protocol", "any")
        data["profile"] = data.get("profile", "any")
        data["targets"] = ",".join(t.strip() for t in data["targets"].split(",") if t.strip())
        data["raw_line"] = line
        return data

    m = RULE_V1_RE.match(line)
    if not m:
        return None

    name, direction, ips = m.groups()
    ips = ",".join(i.strip() for i in ips.split(",") if i.strip())
    if not ips:
        return None

    return {
        "action": "block",
        "name": name,
        "direction": direction.lower(),
        "targets": ips,
        "protocol": "any",
        "profile": "any",
        "raw_line": line
    }

# ------------------------------------------------------
# Firewall helpers
# ------------------------------------------------------
def firewall_rule_exists(name, direction):
    r = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True
    )
    return r.returncode == 0

def add_rule(rule):
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule['name']}",
        f"dir={rule['direction']}",
        f"action={rule['action']}",
        f"remoteip={rule['targets']}",
        f"profile={rule['profile']}",
        "enable=yes"
    ]
    return subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ).returncode == 0

def delete_rule(name, direction):
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule",
         f"name={name}", f"dir={direction}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

# ------------------------------------------------------
# Firewall with atomic rollback
# ------------------------------------------------------
def process_firewall():
    results = []
    added = []

    with open(FIREWALL_TXT, encoding="utf-8") as f:
        for line in f:
            rule = parse_rule(line)
            if not rule:
                continue

            rh = rule_hash(rule)

            if firewall_rule_exists(rule["name"], rule["direction"]):
                status = "exists"
            else:
                if not add_rule(rule):
                    for n, d in added:
                        delete_rule(n, d)
                    return results
                added.append((rule["name"], rule["direction"]))
                status = "added"

            results.append({
                "timestamp": datetime.utcnow().isoformat(),
                "name": rule["name"],
                "direction": rule["direction"],
                "action": rule["action"],
                "targets": rule["targets"],
                "rule_hash": rh,
                "status": status
            })

    return results

# ------------------------------------------------------
# Hosts (silent + idempotent)
# ------------------------------------------------------
def process_hosts():
    results = []

    with open(HOSTS_PATH, encoding="utf-8") as f:
        existing = {
            tuple(l.split()[:2])
            for l in f if l.strip() and not l.startswith("#")
        }

    with open(HOSTS_TXT, encoding="utf-8") as f, \
         open(HOSTS_PATH, "a", encoding="utf-8") as out:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            ip, domain = line.split()
            domain = domain.rstrip(".").lower()
            if (ip, domain) in existing:
                continue
            out.write(f"{ip} {domain}\n")
            existing.add((ip, domain))
            results.append({
                "timestamp": datetime.utcnow().isoformat(),
                "ip": ip,
                "domain": domain,
                "status": "added"
            })

    return results

# ------------------------------------------------------
# CSV writer
# ------------------------------------------------------
def write_csv(path, rows):
    if not rows:
        return
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=sorted(rows[0].keys()))
        if f.tell() == 0:
            w.writeheader()
        w.writerows(rows)

# ------------------------------------------------------
# MAIN
# ------------------------------------------------------
def main():
    write_csv(FW_CSV, process_firewall())
    write_csv(HOSTS_CSV, process_hosts())

if __name__ == "__main__":
    main()
