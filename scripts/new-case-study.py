#!/usr/bin/env python3
"""
New Case Study
--------------
Erzeugt ein bewusst unfertiges Case-Study-Gerüst. Fakten können mit
case-study-evidence.py und enrich.py vorbereitet werden, die Bewertung bleibt
aber menschliche Analyse.

Use:
  python3 scripts/new-case-study.py 107.189.23.209 --date 2026-05-16 --slug root-wordlist-burst --threat "schneller Root-Credential-Scanner"
"""

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CASE_DIR = ROOT / "case-studies"


def parse_args():
    parser = argparse.ArgumentParser(description="Create a new case-study template.")
    parser.add_argument("ip", help="IP-Adresse der Case Study")
    parser.add_argument("--date", required=True, help="Datum im Format YYYY-MM-DD")
    parser.add_argument("--slug", required=True, help="Kurzer Dateiname, z.B. root-wordlist-burst")
    parser.add_argument("--title", help="Titel ohne 'Case Study:'")
    parser.add_argument("--threat", default="TODO", help="Kurze Bedrohungskategorie für den Index")
    parser.add_argument("--title-en", default="TODO", help="Englischer Titel für den englischen Index")
    parser.add_argument("--threat-en", default="TODO", help="Englische Bedrohungskategorie für den englischen Index")
    return parser.parse_args()


def safe_slug(value):
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9-]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-")
    if not value:
        raise ValueError("Slug ist leer.")
    return value


def ip_slug(ip):
    parts = ip.split(".")
    if len(parts) != 4 or not all(part.isdigit() for part in parts):
        raise ValueError("Bitte eine IPv4-Adresse angeben, z.B. 107.189.23.209")
    return "-".join(parts)


def build_template(ip, date, title, threat, title_en, threat_en):
    return f"""# Case Study: {title}

**Datum:** {date}
**Quelle:** Cowrie SSH-Honeypot
**Analyst:** xln777
**Bedrohung:** {threat}
**English title:** {title_en}
**English threat:** {threat_en}

## 1. Zusammenfassung

TODO: In 3-5 Sätzen erklären, was passiert ist und warum es auffällig war.

## 2. Beobachtung

TODO: Zahlen aus `case-study-evidence.py` übernehmen.

```bash
python3 scripts/case-study-evidence.py {ip} --date {date}
```

## 3. Erste Fragen

TODO: Was ist ungewöhnlich? Volumen, Zeitfenster, Client, Credentials, Befehle, Downloads?

## 4. Pattern

TODO: Muster beschreiben, nicht rohe Listen kopieren. Nur repräsentative Beispiele nutzen.

## 5. Hypothese

TODO: Was wollte der Angreifer wahrscheinlich erreichen?

## 6. OSINT-Verifikation

TODO: Ergebnisse aus `enrich.py` zusammenfassen.

```bash
python3 scripts/enrich.py {ip}
```

### AbuseIPDB

TODO

### GreyNoise

TODO

### Shodan

TODO

### VirusTotal

TODO

### WHOIS

TODO

## 7. Schlussfolgerung

TODO: Passt die Hypothese zur Evidenz?

## 8. Defensive Lessons

TODO: Was würde man auf echten Systemen daraus ableiten?

## 9. IOCs

```text
IP:                  {ip}
Verhalten:           TODO
Erste Sichtung:      TODO
Letzte Sichtung:     TODO
```
"""


def main():
    args = parse_args()
    try:
        filename = f"{ip_slug(args.ip)}-{safe_slug(args.slug)}.md"
    except ValueError as exc:
        sys.exit(f"FEHLER: {exc}")

    title = args.title or args.slug.replace("-", " ").title()
    target_dir = CASE_DIR / args.date
    target = target_dir / filename
    if target.exists():
        sys.exit(f"FEHLER: Datei existiert bereits: {target}")

    target_dir.mkdir(parents=True, exist_ok=True)
    target.write_text(
        build_template(args.ip, args.date, title, args.threat, args.title_en, args.threat_en),
        encoding="utf-8",
    )
    print(f"Created {target.relative_to(ROOT)}")
    print("Next:")
    print(f"  python3 scripts/case-study-evidence.py {args.ip} --date {args.date} -o /tmp/evidence.md")
    print(f"  python3 scripts/enrich.py {args.ip}")
    print("  python3 scripts/update-case-study-index.py")


if __name__ == "__main__":
    main()
