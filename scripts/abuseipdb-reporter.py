#!/usr/bin/env python3
"""
abuseipdb-reporter.py
---------------------
Liest Cowrie-Logs und meldet Angreifer-IPs an AbuseIPDB.
Verhindert Doppel-Meldungen durch eine lokale Cache-Datei.

Use:  python3 abuseipdb-reporter.py
      python3 abuseipdb-reporter.py --hours 24 --dry-run
"""

import argparse
import ipaddress
import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import urllib.request
import urllib.parse

LOG_PATH = Path(os.environ.get("COWRIE_LOG_PATH", str(Path.home() / "cowrie/logs/cowrie.json")))
CACHE_PATH = Path(os.environ.get("ABUSEIPDB_CACHE_PATH", str(Path.home() / ".abuseipdb-reported.json")))
API_URL = "https://api.abuseipdb.com/api/v2/report"


def load_secrets_file():
    """Lade KEY=value Paare aus ~/.secrets falls nicht im Environment."""
    secrets_path = Path.home() / ".secrets"
    if not secrets_path.exists():
        return
    for line in secrets_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:]
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value


load_secrets_file()
API_KEY = os.environ.get("ABUSEIPDB_KEY", "")


def load_cache():
    if CACHE_PATH.exists():
        return json.loads(CACHE_PATH.read_text())
    return {}


def save_cache(cache):
    CACHE_PATH.write_text(json.dumps(cache, indent=2))


def is_reportable_ip(ip):
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def report_ip(ip, comment, dry_run=False):
    if dry_run:
        print(f"  [DRY-RUN] würde melden: {ip}")
        return True

    data = urllib.parse.urlencode({
        "ip": ip,
        "categories": "18,22",  # 18=Brute-Force, 22=SSH
        "comment": comment
    }).encode()

    req = urllib.request.Request(
        API_URL,
        data=data,
        headers={
            "Key": API_KEY,
            "Accept": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            score = result.get("data", {}).get("abuseConfidenceScore", "?")
            print(f"  ✓ {ip} gemeldet — Confidence Score: {score}%")
            return True
    except Exception as e:
        print(f"  ✗ {ip} Fehler: {e}")
        return False


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--log", default=str(LOG_PATH))
    p.add_argument("--dry-run", action="store_true", help="Nichts melden, nur anzeigen")
    args = p.parse_args()

    if not API_KEY and not args.dry_run:
        print("FEHLER: ABUSEIPDB_KEY nicht gesetzt")
        print("Use: export ABUSEIPDB_KEY=dein-key && python3 abuseipdb-reporter.py")
        return

    log_path = Path(args.log)
    if not log_path.exists():
        print(f"FEHLER: {log_path} nicht gefunden")
        return

    since = datetime.now(timezone.utc) - timedelta(hours=args.hours)
    cache = load_cache()
    today = datetime.now().strftime("%Y-%m-%d")

    # IPs aus Cowrie-Log sammeln
    ip_attempts = {}
    with log_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            if ev.get("eventid") not in ("cowrie.login.failed", "cowrie.login.success"):
                continue

            ts_str = ev.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                continue

            if ts < since:
                continue

            ip = ev.get("src_ip", "")
            if not is_reportable_ip(ip):
                continue

            if ip not in ip_attempts:
                ip_attempts[ip] = []
            ip_attempts[ip].append(f"{ev.get('username','?')}/{ev.get('password','?')}")

    print(f"==> AbuseIPDB Reporter — letzte {args.hours}h")
    print(f"    {len(ip_attempts)} einzigartige Angreifer-IPs gefunden")
    print()

    reported = 0
    skipped = 0

    for ip, attempts in ip_attempts.items():
        cache_key = f"{today}:{ip}"

        # Heute schon gemeldet? Überspringen
        if cache_key in cache:
            skipped += 1
            continue

        comment = (
            f"SSH brute-force via Cowrie honeypot. "
            f"{len(attempts)} attempts. "
            f"Sample credentials: {', '.join(attempts[:3])}"
        )

        success = report_ip(ip, comment, dry_run=args.dry_run)

        if success and not args.dry_run:
            cache[cache_key] = datetime.now().isoformat()
            reported += 1
            time.sleep(0.5)  # Rate-Limit respektieren
        elif success:
            reported += 1

    if not args.dry_run:
        save_cache(cache)

    print()
    print(f"==> Fertig: {reported} gemeldet, {skipped} heute bereits gemeldet")


if __name__ == "__main__":
    main()
