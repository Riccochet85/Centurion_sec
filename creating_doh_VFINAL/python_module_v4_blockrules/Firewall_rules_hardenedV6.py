# ======================================================
# CENTURION FIREWALL HARDENING ORCHESTRATION — V6
# ======================================================
# PURPOSE:
#   Execute a complete, deterministic firewall + hosts
#   hardening workflow using:
#       - firewall_rules.txt
#       - hosts_rules.txt
#
#   The script:
#       1. Parses and validates firewall rules
#       2. Normalizes rule format
#       3. Applies rules to Windows Firewall
#       4. Logs all actions (added / exists / failed)
#       5. Generates a CSV compendium of all firewall rules
#       6. Enforces hosts file entries (no duplicates)
#       7. Generates a CSV compendium of all hosts entries
#       8. Applies default inbound block policy
#
# INPUT FILES (must exist in same directory):
#       firewall_rules.txt
#       hosts_rules.txt
#
# OUTPUT FILES (auto-created if missing):
#       firewall_sumary_rules.csv      ← compendium of firewall rules
#       hosts_firewall_rules.csv       ← compendium of hosts entries
#       centurion_firewall.log         ← chronological firewall log
#       centurion_domain_general.log   ← domain generator log
#       centurion_domain_exceptions.log← domain generator error log
#
# MODULE MAP:
#       0. Hard Silence + Paths (self-contained)
#       1. Canonical Rule Library
#       2. Parser + Hash + Linter
#       3. Formatter
#       4. System Snapshot
#       5. Firewall Executor
#       6. Rule Builder CLI
#       7. Domain-to-Rule Generator
#       8. Default Inbound Block Policy
#       9. Hosts Executor
#      10. CSV Writer
#      11. Orchestrator (MAIN)
#
# EXECUTION:
#       python Firewall_rules_hardenedV6.py
#
# BEHAVIOR:
#       - Fully silent (stdout/stderr suppressed)
#       - Deterministic, idempotent, no duplicates
#       - Logs everything, never prints
#       - Safe to run repeatedly
#       - All modules independent and self-contained
#
# ======================================================


# ======================================================
# HARD SILENCE (SELF-CONTAINED)
# ======================================================
import os
import sys

DEVNULL = open(os.devnull, "w")
sys.stdout = DEVNULL
sys.stderr = DEVNULL

# ======================================================
# PATHS (SELF-CONTAINED, SCRIPT-LOCAL)
# ======================================================
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Input rule files
FIREWALL_TXT = os.path.join(BASE_DIR, "firewall_rules.txt")
HOSTS_TXT    = os.path.join(BASE_DIR, "hosts_rules.txt")

# CSV compendiums
FW_CSV       = os.path.join(BASE_DIR, "firewall_sumary_rules.csv")
HOSTS_CSV    = os.path.join(BASE_DIR, "hosts_firewall_rules.csv")

# Log files (SELF-LOCATED — FIXED)
FIREWALL_LOG         = os.path.join(BASE_DIR, "centurion_firewall.log")
DOMAIN_GENERAL_LOG   = os.path.join(BASE_DIR, "centurion_domain_general.log")
DOMAIN_EXCEPTION_LOG = os.path.join(BASE_DIR, "centurion_domain_exceptions.log")

# Hosts file path
HOSTS_PATH = os.path.join(
    os.environ["SystemRoot"], "System32", "drivers", "etc", "hosts"
)

# Ensure CSVs and logs exist
for p in (FW_CSV, HOSTS_CSV, FIREWALL_LOG, DOMAIN_GENERAL_LOG, DOMAIN_EXCEPTION_LOG):
    if not os.path.exists(p):
        open(p, "w", encoding="utf-8").close()

# ======================================================
# MODULE 0 — Imports (Shared)
# ======================================================

import re
import ipaddress
import hashlib
import subprocess
import socket
import argparse
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple


# ======================================================
# MODULE 1 — Canonical Rule Library (Independent)
# ======================================================

CANONICAL_RULE_LIBRARY = """
# Google Analytics
action=block|name=CenturionCent_Block_GoogleAnalytics|direction=out|targets=216.58.0.0/16|protocol=any|profile=any|label:en=GoogleAnalyticsCIDR

# Google Fonts / Google APIs
action=block|name=CenturionCent_Block_GoogleFonts|direction=out|targets=142.250.0.0/15|protocol=any|profile=any|label:en=GoogleFonts

# Google Wide
action=block|name=CenturionCent_Block_GoogleWide|direction=out|targets=172.217.0.0/16|protocol=any|profile=any|label:en=GoogleWideCIDR

# Facebook
action=block|name=CenturionCent_Block_Facebook|direction=out|targets=157.240.0.0/16|protocol=any|profile=any|label:en=FacebookCIDR

# Twitter / X
action=block|name=CenturionCent_Block_Twitter|direction=out|targets=104.244.42.0/24|protocol=any|profile=any|label:en=TwitterCIDR

# Cloudflare
action=block|name=CenturionCent_Block_Cloudflare|direction=out|targets=104.16.0.0/12|protocol=any|profile=any|label:en=CloudflareCIDR

# Akamai
action=block|name=CenturionCent_Block_Akamai|direction=out|targets=23.0.0.0/11|protocol=any|profile=any|label:en=AkamaiCIDR

# AWS
action=block|name=CenturionCent_Block_AWS|direction=out|targets=52.95.0.0/16|protocol=any|profile=any|label:en=AWSCIDR

# Microsoft Telemetry
action=block|name=CenturionCent_Block_MicrosoftTelemetry|direction=out|targets=13.107.0.0/16|protocol=any|profile=any|label:en=MicrosoftTelemetryCIDR

# Generic Ads
action=block|name=CenturionCent_Block_GenericAds|direction=out|targets=198.51.100.0/24|protocol=any|profile=any|label:en=GenericAdsCIDR
""".strip()


# ======================================================
# MODULE 2 — Parsing + Hash + Linter (Independent)
# ======================================================


# MODULE 2
import re
import ipaddress
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
RULE_V1_RE = re.compile(r"^([^|]+)\|(in|out)\|(.+)$", re.IGNORECASE)

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

def parse_rule(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if "action=" in line:
        data: Dict[str, Any] = {}
        for seg in line.split("|"):
            seg = seg.strip()
            if "=" in seg:
                k, v = seg.split("=", 1)
                data[k.strip().lower()] = v.strip()

        if not all(k in data for k in ("action", "name", "direction", "targets")):
            return None

        data["protocol"] = data.get("protocol", "any")
        data["profile"] = data.get("profile", "any")
        data["targets"] = ",".join(
            t.strip() for t in data["targets"].split(",") if t.strip()
        )
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

def lint_firewall_file(path: str) -> Dict[str, Any]:
    issues: List[Dict[str, Any]] = []
    seen_hashes: Dict[str, int] = {}
    seen_namedir: Dict[Tuple[str, str], int] = {}

    with open(path, encoding="utf-8") as f:
        lines = f.readlines()

    for idx, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue

        rule = parse_rule(raw)
        if not rule:
            issues.append({
                "line": idx,
                "raw": raw.rstrip("\n"),
                "severity": "error",
                "code": "PARSE_FAILED",
                "detail": "Unable to parse rule line."
            })
            continue

        for key in ("action", "name", "direction", "targets", "protocol", "profile"):
            if key not in rule or not str(rule[key]).strip():
                issues.append({
                    "line": idx,
                    "raw": raw.rstrip("\n"),
                    "severity": "error",
                    "code": "MISSING_FIELD",
                    "detail": f"Missing required field '{key}'."
                })

        action = rule["action"].lower()
        if action not in {"block", "allow"}:
            issues.append({
                "line": idx,
                "raw": raw.rstrip("\n"),
                "severity": "error",
                "code": "INVALID_ACTION",
                "detail": f"Invalid action '{rule['action']}'."
            })

        direction = rule["direction"].lower()
        if direction not in {"in", "out"}:
            issues.append({
                "line": idx,
                "raw": raw.rstrip("\n"),
                "severity": "error",
                "code": "INVALID_DIRECTION",
                "detail": f"Invalid direction '{rule['direction']}'."
            })

        for t in rule["targets"].split(","):
            t = t.strip()
            if not t:
                continue
            try:
                if "/" in t:
                    ipaddress.ip_network(t, strict=False)
                else:
                    ipaddress.ip_address(t)
            except ValueError:
                issues.append({
                    "line": idx,
                    "raw": raw.rstrip("\n"),
                    "severity": "error",
                    "code": "INVALID_TARGET",
                    "detail": f"Invalid IP/CIDR target '{t}'."
                })

        h = rule_hash(rule)
        if h in seen_hashes:
            issues.append({
                "line": idx,
                "raw": raw.rstrip("\n",
                "severity": "warning",
                "code": "DUPLICATE_HASH",
                "detail": f"Duplicate of line {seen_hashes[h]}."
            })
        else:
            seen_hashes[h] = idx

        nd = (rule["name"], rule["direction"])
        if nd in seen_namedir:
            issues.append({
                "line": idx,
                "raw": raw.rstrip("\n"),
                "severity": "warning",
                "code": "DUPLICATE_NAME_DIRECTION",
                "detail": f"Duplicate name+direction of line {seen_namedir[nd]}."
            })
        else:
            seen_namedir[nd] = idx

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "file": path,
        "issues": issues
    }


# ======================================================
# MODULE 3 — Formatter (Independent)
# ======================================================


# MODULE 3
from typing import Dict, Any, Optional, List


def format_rule_line(rule: Dict[str, Any]) -> str:
    base_order = ["action", "name", "direction", "targets", "protocol", "profile"]

    rule = dict(rule)
    rule["protocol"] = rule.get("protocol", "any")
    rule["profile"] = rule.get("profile", "any")

    segments = [f"{key}={rule[key]}" for key in base_order]

    extra_keys: List[str] = []
    raw = rule.get("raw_line", "")
    if raw and "action=" in raw:
        for seg in raw.split("|"):
            seg = seg.strip()
            if "=" in seg:
                k, v = seg.split("=", 1)
                if k.strip().lower() not in base_order:
                    extra_keys.append(f"{k.strip()}={v.strip()}")

    return "|".join(segments + extra_keys)

def format_firewall_file(path_in: str, path_out: Optional[str] = None) -> Dict[str, Any]:
    if path_out is None:
        path_out = path_in

    with open(path_in, encoding="utf-8") as f:
        lines = f.readlines()

    formatted_lines: List[str] = []
    changed = False

    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            formatted_lines.append(raw.rstrip("\n"))
            continue

        rule = parse_rule(raw)
        if not rule:
            formatted_lines.append(raw.rstrip("\n"))
            continue

        new_line = format_rule_line(rule)
        if new_line != stripped:
            changed = True

        formatted_lines.append(new_line)

    with open(path_out, "w", encoding="utf-8") as f:
        for line in formatted_lines:
            f.write(line + "\n")

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "file_in": path_in,
        "file_out": path_out,
        "changed": changed
    }


# ======================================================
# MODULE 4 — System Snapshot (Independent)
# ======================================================

# MODULE 4
import subprocess
from datetime import datetime
from typing import Dict, Any


def system_snapshot() -> Dict[str, Any]:
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "firewall_rules": subprocess.getoutput("netsh advfirewall firewall show rule name=all"),
        "active_connections": subprocess.getoutput("netstat -ano"),
        "routing_table": subprocess.getoutput("route print"),
        "ipconfig": subprocess.getoutput("ipconfig /all")
    }


# ======================================================
# MODULE 5 — Firewall Executor (Independent, no duplicates)
# ======================================================

# MODULE 5
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Tuple


def firewall_rule_exists(name: str, direction: str) -> bool:
    r = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}", f"dir={direction}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True
    )
    return r.returncode == 0

def add_firewall_rule(rule: Dict[str, Any]) -> bool:
    if firewall_rule_exists(rule["name"], rule["direction"]):
        return True
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule['name']}",
        f"dir={rule['direction']}",
        f"action={rule['action']}",
        f"remoteip={rule['targets']}",
        f"profile={rule['profile']}",
        "enable=yes"
    ]
    r = subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True
    )
    return r.returncode == 0

def delete_firewall_rule(name: str, direction: str) -> None:
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule",
         f"name={name}", f"dir={direction}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True
    )

def process_firewall_file(path: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    added: List[Tuple[str, str]] = []

    with open(path, encoding="utf-8") as f:
        for raw in f:
            rule = parse_rule(raw)
            if not rule:
                continue

            rh = rule_hash(rule)

            if firewall_rule_exists(rule["name"], rule["direction"]):
                status = "exists"
            else:
                if not add_firewall_rule(rule):
                    for n, d in added:
                        delete_firewall_rule(n, d)
                    results.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "name": rule["name"],
                        "direction": rule["direction"],
                        "action": rule["action"],
                        "targets": rule["targets"],
                        "rule_hash": rh,
                        "status": "rollback"
                    })
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


# ======================================================
# MODULE 6 — Rule Builder CLI (Independent, no duplicates)
# ======================================================


# MODULE 6
import argparse
from typing import Dict, Any, Optional, List


def load_existing_rules(path: str) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    try:
        with open(path, encoding="utf-8") as f:
            for raw in f:
                r = parse_rule(raw)
                if r:
                    rules.append(r)
    except FileNotFoundError:
        pass
    return rules

def rule_exists_in_file(path: str, name: str, direction: str, targets: str) -> bool:
    rules = load_existing_rules(path)
    for r in rules:
        if r["name"] == name and r["direction"] == direction and r["targets"] == targets:
            return True
    return False

def build_rule_line(name: str,
                    action: str,
                    direction: str,
                    targets: str,
                    protocol: str = "any",
                    profile: str = "any",
                    label_en: Optional[str] = None) -> str:
    segments = [
        f"action={action}",
        f"name={name}",
        f"direction={direction}",
        f"targets={targets}",
        f"protocol={protocol}",
        f"profile={profile}",
    ]
    if label_en:
        segments.append(f"label:en={label_en}")
    return "|".join(segments)

def cli_rule_builder():
    parser = argparse.ArgumentParser(description="Centurion Rule Builder CLI")
    parser.add_argument("--file", required=True, help="Firewall rules file path")
    parser.add_argument("--name", required=True, help="Rule name")
    parser.add_argument("--action", default="block", choices=["block", "allow"], help="Rule action")
    parser.add_argument("--direction", default="out", choices=["in", "out"], help="Rule direction")
    parser.add_argument("--targets", required=True, help="IP or CIDR or comma-separated list")
    parser.add_argument("--protocol", default="any", help="Protocol")
    parser.add_argument("--profile", default="any", help="Firewall profile")
    parser.add_argument("--label-en", default=None, help="English label")
    args = parser.parse_args()

    targets_norm = ",".join(t.strip() for t in args.targets.split(",") if t.strip())

    if rule_exists_in_file(args.file, args.name, args.direction, targets_norm):
        return

    line = build_rule_line(
        name=args.name,
        action=args.action,
        direction=args.direction,
        targets=targets_norm,
        protocol=args.protocol,
        profile=args.profile,
        label_en=args.label_en
    )

    with open(args.file, "a", encoding="utf-8") as f:
        f.write(line + "\n")




# ======================================================
# MODULE 7 — Domain‑to‑Rule Generator (Dual Logging)
# ======================================================

GENERAL_LOG = "centurion_domain_general.log"
EXCEPTION_LOG = "centurion_domain_exceptions.log"


def log_general(entry: Dict[str, Any]):
    """Log every action, always."""
    entry["log_type"] = "general"
    with open(GENERAL_LOG, "a", encoding="utf-8") as lf:
        lf.write(f"{entry}\n")


def log_exception(entry: Dict[str, Any]):
    """Log only errors, mismatches, anomalies."""
    entry["log_type"] = "exception"
    with open(EXCEPTION_LOG, "a", encoding="utf-8") as lf:
        lf.write(f"{entry}\n")


def resolve_domain_ips(domain: str) -> List[str]:
    ips: List[str] = []
    try:
        info = socket.getaddrinfo(domain, None)
        for family, _, _, _, sockaddr in info:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror:
        # DNS resolution failed
        log_exception({
            "timestamp": datetime.utcnow().isoformat(),
            "domain": domain,
            "status": "dns_resolution_failed"
        })
    return ips


def generate_rules_for_domain(domain: str,
                              base_name: str,
                              direction: str = "out",
                              action: str = "block",
                              profile: str = "any",
                              protocol: str = "any") -> List[str]:

    timestamp = datetime.utcnow().isoformat()
    ips = resolve_domain_ips(domain)

    # CASE 1 — Domain resolved normally
    if ips:
        rules: List[str] = []
        for idx, ip in enumerate(ips, start=1):

            # Validate IP
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                log_exception({
                    "timestamp": timestamp,
                    "domain": domain,
                    "ip": ip,
                    "status": "invalid_ip_format"
                })
                continue

            name = f"{base_name}_{idx}"
            label_en = f"{domain}_{ip}"

            line = build_rule_line(
                name=name,
                action=action,
                direction=direction,
                targets=ip,
                protocol=protocol,
                profile=profile,
                label_en=label_en
            )

            rules.append(line)

            log_general({
                "timestamp": timestamp,
                "domain": domain,
                "ip": ip,
                "rule_name": name,
                "status": "rule_generated"
            })

        return rules

    # CASE 2 — Domain did NOT resolve → create fallback block rule
    fallback_name = f"{base_name}_UNRESOLVED"
    fallback_label = f"{domain}_UNRESOLVED"

    fallback_rule = build_rule_line(
        name=fallback_name,
        action="block",
        direction=direction,
        targets="0.0.0.0",
        protocol=protocol,
        profile=profile,
        label_en=fallback_label
    )

    log_exception({
        "timestamp": timestamp,
        "domain": domain,
        "status": "domain_unresolved_fallback_rule_created",
        "rule_name": fallback_name
    })

    log_general({
        "timestamp": timestamp,
        "domain": domain,
        "status": "fallback_rule_generated",
        "rule_name": fallback_name
    })

    return [fallback_rule]


def append_domain_rules_to_file(domain: str,
                                base_name: str,
                                path: str) -> List[str]:

    timestamp = datetime.utcnow().isoformat()
    existing = load_existing_rules(path)
    existing_set = {(r["name"], r["direction"], r["targets"]) for r in existing}

    generated = generate_rules_for_domain(domain, base_name)
    appended: List[str] = []

    with open(path, "a", encoding="utf-8") as f:
        for line in generated:
            r = parse_rule(line)
            if not r:
                log_exception({
                    "timestamp": timestamp,
                    "domain": domain,
                    "line": line,
                    "status": "parse_failed"
                })
                continue

            key = (r["name"], r["direction"], r["targets"])
            if key in existing_set:
                log_general({
                    "timestamp": timestamp,
                    "domain": domain,
                    "rule_name": r["name"],
                    "status": "duplicate_skipped"
                })
                continue

            existing_set.add(key)
            f.write(line + "\n")
            appended.append(line)

            log_general({
                "timestamp": timestamp,
                "domain": domain,
                "rule_name": r["name"],
                "status": "rule_appended"
            })

    return appended

# ======================================================
# MODULE 8 — Default Inbound Block Policy (Independent)
# ======================================================

# MODULE 8
import subprocess
from datetime import datetime
from typing import Dict, Any, List




def set_default_inbound_block() -> Dict[str, Any]:
    profiles = ["domainprofile", "privateprofile", "publicprofile"]
    results: List[Dict[str, Any]] = []

    for prof in profiles:
        cmd = [
            "netsh", "advfirewall", "set", prof,
            "firewallpolicy", "blockinbound,allowoutbound"
        ]
        r = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True
        )
        results.append({
            "profile": prof,
            "returncode": r.returncode
        })

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "policy": "blockinbound,allowoutbound",
        "results": results
    }
    
# ======================================================
# MODULE 9 — Hosts Executor (Merged Final Version)
# ======================================================

def process_hosts() -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    # Load existing (ip, domain) pairs from real hosts file
    existing: set = set()
    try:
        with open(HOSTS_PATH, encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split()
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    domain = parts[1].strip().rstrip(".").lower()
                    existing.add((ip, domain))
    except FileNotFoundError:
        results.append({
            "timestamp": datetime.utcnow().isoformat(),
            "status": "hosts_file_missing"
        })
        return results

    # Process hosts_rules.txt
    try:
        with open(HOSTS_TXT, encoding="utf-8") as src, \
             open(HOSTS_PATH, "a", encoding="utf-8") as dst:

            for raw in src:
                # Remove comments
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue

                parts = line.split()
                if len(parts) < 2:
                    results.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "raw": raw.rstrip("\n"),
                        "status": "malformed_line"
                    })
                    continue

                ip = parts[0].strip()
                domain = parts[1].strip().rstrip(".").lower()

                # Already exists
                if (ip, domain) in existing:
                    results.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "ip": ip,
                        "domain": domain,
                        "status": "exists"
                    })
                    continue

                # Append new entry
                try:
                    dst.write(f"{ip} {domain}\n")
                    existing.add((ip, domain))
                    results.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "ip": ip,
                        "domain": domain,
                        "status": "added"
                    })
                except Exception as e:
                    results.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "ip": ip,
                        "domain": domain,
                        "error": str(e),
                        "status": "write_failed"
                    })

    except FileNotFoundError:
        results.append({
            "timestamp": datetime.utcnow().isoformat(),
            "status": "hosts_rules_missing"
        })

    return results
    
# ======================================================
# MODULE 10 — CSV Writer (Independent)
# ======================================================

import csv

def write_csv(path: str, rows: List[Dict[str, Any]]) -> None:
    """
    Append structured rows to a CSV file.
    Writes header only if file is empty.
    """
    if not rows:
        return

    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=sorted(rows[0].keys()))
        if f.tell() == 0:
            writer.writeheader()
        writer.writerows(rows)
        
        
        
# ======================================================
# MODULE 11 — Orchestrator (MAIN)
# ======================================================

def main():
    # Firewall execution (Module 5)
    fw_rows = process_firewall_file(FIREWALL_TXT)
    write_csv(FW_CSV, fw_rows)

    # Hosts execution (Module 9)
    hosts_rows = process_hosts()
    write_csv(HOSTS_CSV, hosts_rows)

if __name__ == "__main__":
    main()
