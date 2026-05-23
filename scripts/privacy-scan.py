#!/usr/bin/env python3
"""
Scan public files for configured private/lab values before committing.

Put sensitive values in scripts/own-ips.txt. That file is gitignored.
The scanner fails if any configured exact IP appears in public project files.
CIDR entries are used by runtime scripts, but are intentionally not expanded here.

CI can pass additional literal denylist values through PRIVACY_SCAN_PATTERNS.
"""

import ipaddress
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OWN_IPS_FILE = ROOT / "scripts" / "own-ips.txt"
PUBLIC_SUFFIXES = {".md", ".json", ".csv", ".txt", ".yml", ".yaml"}
SKIP_DIRS = {".git", "__pycache__"}


def load_patterns():
    patterns = set()
    if OWN_IPS_FILE.exists():
        for raw_line in OWN_IPS_FILE.read_text().splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                continue
            if net.num_addresses == 1:
                patterns.add(str(net.network_address))

    env_value = os.environ.get("PRIVACY_SCAN_PATTERNS", "")
    for item in env_value.replace(",", "\n").splitlines():
        item = item.strip()
        if item:
            patterns.add(item)

    return patterns


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
    patterns = load_patterns()
    if not patterns:
        print("privacy-scan: keine eigenen IPs oder CI-Pattern konfiguriert")
        return 0

    findings = []
    for path in public_files():
        text = path.read_text(errors="ignore")
        for pattern in patterns:
            if pattern in text:
                findings.append((path.relative_to(ROOT), pattern))

    if findings:
        print("privacy-scan: sensible Werte in öffentlichen Dateien gefunden:")
        for rel_path, pattern in findings:
            print(f"  {rel_path}: {pattern}")
        return 1

    print("privacy-scan: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
