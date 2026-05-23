#!/usr/bin/env python3
"""
Scan public files for configured private/lab IPs before committing.

Put sensitive values in scripts/own-ips.txt. That file is gitignored.
The scanner fails if any configured exact IP appears in public project files.
CIDR entries are used by runtime scripts, but are intentionally not expanded here.
"""

import ipaddress
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OWN_IPS_FILE = ROOT / "scripts" / "own-ips.txt"
PUBLIC_SUFFIXES = {".md", ".json", ".csv", ".txt", ".yml", ".yaml"}
SKIP_DIRS = {".git", "__pycache__"}


def load_exact_ips():
    ips = set()
    if not OWN_IPS_FILE.exists():
        return ips
    for raw_line in OWN_IPS_FILE.read_text().splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if net.num_addresses == 1:
            ips.add(str(net.network_address))
    return ips


def public_files():
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path == OWN_IPS_FILE:
            continue
        if path.suffix.lower() in PUBLIC_SUFFIXES:
            yield path


def main():
    ips = load_exact_ips()
    if not ips:
        print("privacy-scan: keine exakten eigenen IPs in scripts/own-ips.txt gefunden")
        return 0

    findings = []
    for path in public_files():
        text = path.read_text(errors="ignore")
        for ip in ips:
            if ip in text:
                findings.append((path.relative_to(ROOT), ip))

    if findings:
        print("privacy-scan: sensible IPs in öffentlichen Dateien gefunden:")
        for rel_path, ip in findings:
            print(f"  {rel_path}: {ip}")
        return 1

    print("privacy-scan: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
