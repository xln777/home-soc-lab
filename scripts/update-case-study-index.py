#!/usr/bin/env python3
"""
Update Case Study Index
-----------------------
Erzeugt die deutschen und englischen Case-Study-Indexdateien aus der
Ordnerstruktur:

  case-studies/YYYY-MM-DD/IP-thema.md

Use:
  python3 scripts/update-case-study-index.py
"""

import re
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CASE_DIR = ROOT / "case-studies"
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
IP_RE = re.compile(r"^(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})-")


@dataclass
class CaseStudy:
    date: str
    ip: str
    title: str
    title_en: str
    threat: str
    threat_en: str
    path: Path


def read_title(text):
    for line in text.splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
            return title.replace("Case Study:", "").strip()
    return "(ohne Titel)"


def read_threat(text):
    for line in text.splitlines():
        if line.startswith("**Bedrohung:**"):
            return line.split("**Bedrohung:**", 1)[1].strip()
    return "siehe Case Study"


def read_meta(text, field, fallback):
    marker = f"**{field}:**"
    for line in text.splitlines():
        if line.startswith(marker):
            value = line.split(marker, 1)[1].strip()
            return value or fallback
    return fallback


def ip_from_filename(path):
    match = IP_RE.match(path.name)
    if not match:
        return "-"
    return ".".join(match.groups())


def collect_case_studies():
    cases = []
    for date_dir in CASE_DIR.iterdir():
        if not date_dir.is_dir() or not DATE_RE.match(date_dir.name):
            continue
        for path in date_dir.glob("*.md"):
            text = path.read_text(encoding="utf-8")
            cases.append(CaseStudy(
                date=date_dir.name,
                ip=ip_from_filename(path),
                title=read_title(text),
                title_en=read_meta(text, "English title", read_title(text)),
                threat=read_threat(text),
                threat_en=read_meta(text, "English threat", read_threat(text)),
                path=path.relative_to(CASE_DIR),
            ))
    return sorted(cases, key=lambda item: (item.date, item.ip), reverse=True)


def table_de(cases):
    rows = [
        "| Datum | IP | Titel | Bedrohung |",
        "|-------|----|-------|-----------|",
    ]
    for item in cases:
        rows.append(
            f"| {item.date} | `{item.ip}` | [{item.title}]({item.path.as_posix()}) | {item.threat} |"
        )
    return "\n".join(rows)


def table_en(cases):
    rows = [
        "| Date | IP | Title | Threat |",
        "|------|----|-------|--------|",
    ]
    for item in cases:
        rows.append(
            f"| {item.date} | `{item.ip}` | [{item.title_en}]({item.path.as_posix()}) | {item.threat_en} |"
        )
    return "\n".join(rows)


def write_readme_de(cases):
    content = f"""# Case Studies

[English version](README.en.md)

Hier liegen ausführlichere Auswertungen von Angriffen, die mir in den Tages-Reports aufgefallen sind. Im Gegensatz zu `reports/` (automatisch generiert) sind das manuelle Schreibarbeiten.

## Index

{table_de(cases)}

## Aufbau

Jede Case Study folgt grob diesen 9 Punkten. Sie sind als Leitfaden gedacht, nicht als Zwangsformat. Wenn ein Punkt für einen konkreten Fall nichts hergibt, kommt er raus.

1. **Zusammenfassung** - kurzer Überblick
2. **Beobachtung** - rohe Zahlen aus den Logs
3. **Erste Fragen** - was ist auffällig
4. **Pattern** - Häufungen, Sortierungen, Cluster
5. **Hypothese** - was will der Angreifer
6. **OSINT-Verifikation** - AbuseIPDB, GreyNoise, Shodan, VirusTotal, WHOIS
7. **Schlussfolgerung** - passt die Hypothese zur Evidenz
8. **Defensive Lessons** - was nehme ich für eigene Systeme mit
9. **IOCs** - Indicators of Compromise für andere

## Workflow

Der genaue Ablauf steht in [`workflow.md`](workflow.md).
"""
    (CASE_DIR / "README.md").write_text(content, encoding="utf-8")


def write_readme_en(cases):
    content = f"""# Case Studies

[Deutsche Version](README.md)

This folder contains deeper writeups for attacks that stood out in the daily reports. Unlike `reports/`, these are manually written analyses.

## Index

{table_en(cases)}

## Structure

Each case study roughly follows these nine points. They are a guide, not a mandatory template. If a point does not add value for a specific incident, it can be skipped.

1. **Summary** - short overview
2. **Observation** - raw numbers from the logs
3. **Initial questions** - what stands out
4. **Pattern** - clusters, sorting, repeated behavior
5. **Hypothesis** - what the attacker likely wanted
6. **OSINT verification** - AbuseIPDB, GreyNoise, Shodan, VirusTotal, WHOIS
7. **Conclusion** - whether the hypothesis fits the evidence
8. **Defensive lessons** - what to take away for real systems
9. **IOCs** - indicators of compromise for others

## Workflow

The detailed process is documented in [`workflow.en.md`](workflow.en.md).
"""
    (CASE_DIR / "README.en.md").write_text(content, encoding="utf-8")


def main():
    cases = collect_case_studies()
    write_readme_de(cases)
    write_readme_en(cases)
    print(f"Updated case-study indexes with {len(cases)} entries.")


if __name__ == "__main__":
    main()
