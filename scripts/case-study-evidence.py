#!/usr/bin/env python3
"""
Case Study Evidence
-------------------
Verdichtet Cowrie-JSON-Logs für eine einzelne IP zu einer strukturierten
Markdown-Übersicht. Ziel: genug Material für eine Case Study, ohne rohe Logs
oder endlose Passwortlisten manuell durchsuchen zu müssen.

Use:
  python3 scripts/case-study-evidence.py 107.189.23.209 --date 2026-05-16
  python3 scripts/case-study-evidence.py 107.189.23.209 --log ~/cowrie/logs/cowrie.json.2026-05-16
  python3 scripts/case-study-evidence.py 107.189.23.209 --date 2026-05-16 -o evidence.md
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


LOGIN_EVENTS = {"cowrie.login.failed", "cowrie.login.success"}


def parse_args():
    parser = argparse.ArgumentParser(description="Build structured Cowrie evidence for one IP.")
    parser.add_argument("ip", help="IP-Adresse, die untersucht werden soll")
    parser.add_argument("--date", help="Datum im Format YYYY-MM-DD, nutzt ~/cowrie/logs/cowrie.json.<date>")
    parser.add_argument("--log", help="Pfad zu einer Cowrie-JSON-Logdatei")
    parser.add_argument("-o", "--output", help="Markdown-Ausgabedatei")
    parser.add_argument("--top", type=int, default=20, help="Maximale Anzahl pro Top-Tabelle")
    parser.add_argument("--examples", type=int, default=12, help="Maximale Anzahl Beispiel-Sessions")
    args = parser.parse_args()

    if not args.date and not args.log:
        parser.error("Bitte --date oder --log angeben.")
    if args.date and args.log:
        parser.error("Bitte nur --date oder --log angeben, nicht beides.")
    return args


def log_path_from_args(args):
    if args.log:
        return Path(args.log).expanduser()
    return Path.home() / "cowrie/logs" / f"cowrie.json.{args.date}"


def parse_timestamp(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def load_events(path, ip):
    events = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("src_ip") != ip:
                continue
            event["_ts"] = parse_timestamp(event.get("timestamp"))
            events.append(event)
    events.sort(key=lambda item: item.get("_ts") or datetime.min)
    return events


def md_table(headers, rows):
    if not rows:
        return "_Keine Daten._"
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(["---"] * len(headers)) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def top_rows(counter, limit):
    return [[key, count] for key, count in counter.most_common(limit)]


def session_summary(events):
    sessions = defaultdict(list)
    for event in events:
        session = event.get("session") or "(none)"
        sessions[session].append(event)

    rows = []
    for session, items in sessions.items():
        timestamps = [item["_ts"] for item in items if item.get("_ts")]
        first = min(timestamps).isoformat().replace("+00:00", "Z") if timestamps else "-"
        last = max(timestamps).isoformat().replace("+00:00", "Z") if timestamps else "-"
        login = next((item for item in items if item.get("eventid") in LOGIN_EVENTS), None)
        version = next((item.get("version") for item in items if item.get("eventid") == "cowrie.client.version"), "-")
        hassh = next((item.get("hassh") for item in items if item.get("hassh")), "-")
        commands = [item.get("input") for item in items if item.get("eventid") == "cowrie.command.input"]
        downloads = [item.get("url") for item in items if item.get("eventid") == "cowrie.session.file_download"]
        rows.append({
            "session": session,
            "first": first,
            "last": last,
            "version": version,
            "hassh": hassh,
            "result": login.get("eventid").replace("cowrie.login.", "") if login else "-",
            "username": login.get("username", "-") if login else "-",
            "password": login.get("password", "-") if login else "-",
            "commands": len(commands),
            "downloads": len(downloads),
        })

    rows.sort(key=lambda item: item["first"])
    return rows


def compact_examples(sessions, limit):
    rows = []
    for item in sessions[:limit]:
        rows.append([
            item["first"],
            item["result"],
            item["username"],
            item["password"],
            item["version"],
            item["commands"],
            item["downloads"],
        ])
    return rows


def build_markdown(ip, log_path, events, limit, example_limit):
    lines = [f"# Evidence: {ip}", ""]
    lines.append(f"**Logdatei:** `{log_path}`")
    lines.append(f"**Events:** {len(events)}")
    lines.append("")

    if not events:
        lines.append("_Keine Events für diese IP gefunden._")
        return "\n".join(lines) + "\n"

    first = events[0].get("timestamp", "-")
    last = events[-1].get("timestamp", "-")
    eventids = Counter(event.get("eventid", "-") for event in events)
    versions = Counter(event.get("version") for event in events if event.get("eventid") == "cowrie.client.version")
    hasshes = Counter(event.get("hassh") for event in events if event.get("hassh"))
    logins = [event for event in events if event.get("eventid") in LOGIN_EVENTS]
    successful = [event for event in logins if event.get("eventid") == "cowrie.login.success"]
    failed = [event for event in logins if event.get("eventid") == "cowrie.login.failed"]
    users = Counter(event.get("username") for event in logins if event.get("username"))
    passwords = Counter(event.get("password") for event in logins if event.get("password"))
    combos = Counter(
        f"{event.get('username')}/{event.get('password')}"
        for event in logins
        if event.get("username") and event.get("password")
    )
    commands = Counter(event.get("input") for event in events if event.get("eventid") == "cowrie.command.input")
    downloads = Counter(event.get("url") for event in events if event.get("eventid") == "cowrie.session.file_download")
    sessions = session_summary(events)

    lines.append("## Überblick")
    lines.append("")
    lines.append(md_table(
        ["Merkmal", "Wert"],
        [
            ["Erste Sichtung", first],
            ["Letzte Sichtung", last],
            ["Sessions", len(sessions)],
            ["Login erfolgreich", len(successful)],
            ["Login fehlgeschlagen", len(failed)],
            ["Befehle", sum(commands.values())],
            ["Downloads", sum(downloads.values())],
            ["Unique Usernames", len(users)],
            ["Unique Passwörter", len(passwords)],
            ["Unique Kombinationen", len(combos)],
        ],
    ))

    lines.append("\n## Event-Typen\n")
    lines.append(md_table(["Event", "Anzahl"], top_rows(eventids, limit)))

    lines.append("\n## Client-Fingerprints\n")
    lines.append("### SSH-/Client-Versionen\n")
    lines.append(md_table(["Version", "Anzahl"], top_rows(versions, limit)))
    lines.append("\n### HASSH\n")
    lines.append(md_table(["HASSH", "Anzahl"], top_rows(hasshes, limit)))

    lines.append("\n## Credentials\n")
    lines.append("### Top Usernames\n")
    lines.append(md_table(["Username", "Versuche"], top_rows(users, limit)))
    lines.append("\n### Top Passwörter\n")
    lines.append(md_table(["Passwort", "Versuche"], top_rows(passwords, limit)))
    lines.append("\n### Top User/Pass-Kombinationen\n")
    lines.append(md_table(["Kombination", "Versuche"], top_rows(combos, limit)))

    lines.append("\n## Beispiel-Sessions\n")
    lines.append(md_table(
        ["Zeit", "Resultat", "Username", "Passwort", "Client", "Befehle", "Downloads"],
        compact_examples(sessions, example_limit),
    ))

    lines.append("\n## Post-Login-Aktivität\n")
    lines.append("### Befehle\n")
    lines.append(md_table(["Befehl", "Anzahl"], top_rows(commands, limit)))
    lines.append("\n### Downloads\n")
    lines.append(md_table(["URL", "Anzahl"], top_rows(downloads, limit)))

    lines.append("\n## Hinweise für die Case Study\n")
    hints = []
    if versions:
        hints.append(f"- Häufigster Client: `{versions.most_common(1)[0][0]}`")
    if len(users) == 1:
        hints.append(f"- Nur ein Username beobachtet: `{next(iter(users))}`")
    if len(passwords) == len(logins) and logins:
        hints.append("- Jedes Passwort wurde nur einmal getestet. Das spricht eher für eine kurze Wortliste als für langes Raten gegen ein einzelnes Ziel.")
    if not commands and not downloads and successful:
        hints.append("- Es gab erfolgreiche Honeypot-Logins, aber keine Befehle oder Downloads. Das passt zu Credential-Validierung oder Treffer-Sammlung.")
    if any(event.get("version", "").startswith("GET ") for event in events):
        hints.append("- Mindestens ein HTTP-Request traf den SSH-Port. Das kann auf generische Port-Erkennung oder unsauberes Scanning hindeuten.")
    lines.extend(hints or ["- Keine automatischen Hinweise."])

    return "\n".join(lines) + "\n"


def main():
    args = parse_args()
    log_path = log_path_from_args(args)
    if not log_path.exists():
        sys.exit(f"FEHLER: Logdatei nicht gefunden: {log_path}")

    events = load_events(log_path, args.ip)
    markdown = build_markdown(args.ip, log_path, events, args.top, args.examples)

    if args.output:
        Path(args.output).write_text(markdown, encoding="utf-8")
    print(markdown)


if __name__ == "__main__":
    main()
