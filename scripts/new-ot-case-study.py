#!/usr/bin/env python3
"""
New OT Case Study
-----------------
Creates a deliberately unfinished OT/Conpot case-study template.

Use:
  python3 scripts/new-ot-case-study.py --date 2026-05-23 --protocol Modbus --slug modbus-internet-scan
"""

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CASE_DIR = ROOT / "ot-case-studies"


def parse_args():
    parser = argparse.ArgumentParser(description="Create a new OT/Conpot case-study template.")
    parser.add_argument("--date", required=True, help="Datum im Format YYYY-MM-DD")
    parser.add_argument("--protocol", required=True, help="OT-Protokoll, z.B. Modbus, S7Comm, BACnet")
    parser.add_argument("--slug", required=True, help="Kurzer Dateiname, z.B. modbus-internet-scan")
    parser.add_argument("--title", help="Titel ohne 'OT Case Study:'")
    parser.add_argument("--source-ip", default="TODO", help="Optionale Quell-IP oder Cluster-Bezeichnung")
    return parser.parse_args()


def safe_slug(value):
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9-]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-")
    if not value:
        raise ValueError("Slug ist leer.")
    return value


def build_template(date, protocol, title, source_ip):
    return f"""# OT Case Study: {title}

**Datum:** {date}
**Quelle:** Conpot OT/ICS-Honeypot
**Protokoll:** {protocol}
**Quelle/Cluster:** {source_ip}
**Analyst:** xln777

## 1. Zusammenfassung

TODO: In 3-5 Sätzen erklären, was im OT-Honeypot sichtbar war.

## 2. Beobachtung

TODO: Zahlen aus dem Tagesreport übernehmen: Events, Sessions, Quell-IPs, Protokoll.

## 3. OT-Kontext

TODO: Kurz erklären, wofür {protocol} in Industrieumgebungen typischerweise genutzt wird.

## 4. Pattern

TODO: War es nur ein Internet-Scan, ein gezielter Protokolltest oder wiederholtes Verhalten?

## 5. Hypothese

TODO: Was wollte der Scanner wahrscheinlich erkennen?

## 6. Defensive Lessons

TODO: Was würde man in echter OT daraus ableiten? Segmentierung, keine direkte Internet-Erreichbarkeit, Monitoring, Asset-Inventar.

## 7. IOCs / Hinweise

```text
Protokoll:       {protocol}
Quelle/Cluster:  {source_ip}
Erste Sichtung:  TODO
Letzte Sichtung: TODO
Bewertung:       TODO
```
"""


def main():
    args = parse_args()
    try:
        filename = f"{safe_slug(args.protocol)}-{safe_slug(args.slug)}.md"
    except ValueError as exc:
        sys.exit(f"FEHLER: {exc}")

    title = args.title or args.slug.replace("-", " ").title()
    target_dir = CASE_DIR / args.date
    target = target_dir / filename
    if target.exists():
        sys.exit(f"FEHLER: Datei existiert bereits: {target}")

    target_dir.mkdir(parents=True, exist_ok=True)
    target.write_text(
        build_template(args.date, args.protocol, title, args.source_ip),
        encoding="utf-8",
    )
    print(f"Created {target.relative_to(ROOT)}")
    print("Next:")
    print("  Tagesreport prüfen")
    print("  Protokoll-Kontext ergänzen")
    print("  Defensive Lessons sauber formulieren")


if __name__ == "__main__":
    main()
