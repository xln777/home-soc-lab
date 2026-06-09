#!/usr/bin/env python3
"""
Cowrie Daily Report
-------------------
Wertet Cowrie- und optional Conpot-Logs aus und schreibt einen Markdown-Bericht.
Eigene IPs (z.B. für Red-Team-Übungen) werden gefiltert.

Eigene IPs in own-ips.txt (eine pro Zeile, CIDR erlaubt, '#' für Kommentare).
Diese Datei wird via .gitignore NICHT mit ins Repo committed.

Use:  python3 cowrie-daily-report.py
      python3 cowrie-daily-report.py --hours 24
      python3 cowrie-daily-report.py --log <path> -o <out.md>
"""

import argparse
import ipaddress
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

OWN_IPS_FILE = Path(__file__).parent / 'own-ips.txt'


def parse_args():
    p = argparse.ArgumentParser()
    default_log = os.environ.get('COWRIE_LOG_PATH') or str(Path.home() / 'cowrie/logs/cowrie.json')
    default_conpot_log = os.environ.get('CONPOT_LOG_PATH') or str(Path.home() / 'conpot/logs/conpot.log')
    p.add_argument('--log', default=default_log)
    p.add_argument('--conpot-log', default=default_conpot_log)
    p.add_argument('--with-conpot', action='store_true', help='Conpot/OT-Abschnitt einbinden (standardmäßig deaktiviert)')
    p.add_argument('--hours', type=int, default=24, help='Zeitraum rückwärts in Stunden')
    p.add_argument('-o', '--output', default=None)
    p.add_argument('--include-own', action='store_true', help='Eigene IPs NICHT filtern (nur für lokale Tests)')
    return p.parse_args()


def load_own_networks():
    nets = []
    if not OWN_IPS_FILE.exists():
        return nets
    for line in OWN_IPS_FILE.read_text().splitlines():
        # inline comments unterstuetzen
        if '#' in line:
            line = line[:line.index('#')]
        line = line.strip()
        if not line:
            continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            print(f'WARN: ungültiger Eintrag in own-ips.txt: {line}', file=sys.stderr)
    return nets


def is_own_ip(ip_str, own_nets):
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in own_nets)
    except ValueError:
        return False


def load_events(log_path: Path, since: datetime, own_nets, include_own):
    events = []
    skipped_own = 0
    with log_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts_str = ev.get('timestamp', '')
            try:
                ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            except ValueError:
                continue
            if ts < since:
                continue
            if not include_own and is_own_ip(ev.get('src_ip'), own_nets):
                skipped_own += 1
                continue
            ev['_ts'] = ts
            events.append(ev)
    return events, skipped_own


def protocol_from_conpot_message(message):
    lower = message.lower()
    checks = [
        ('modbus', 'Modbus'),
        ('s7comm', 'S7Comm'),
        ('snmp', 'SNMP'),
        ('bacnet', 'BACnet'),
        ('tftp', 'TFTP'),
        ('ftp', 'FTP'),
        ('http', 'HTTP'),
        ('ipmi', 'IPMI'),
    ]
    for needle, protocol in checks:
        if needle in lower:
            return protocol
    return 'Other'


def extract_conpot_ip(message):
    patterns = [
        r'\bfrom\s+\(?[\'"]?(\d{1,3}(?:\.\d{1,3}){3})',
        r'\bconnection from\s+(\d{1,3}(?:\.\d{1,3}){3})',
    ]
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            return match.group(1)
    return ''


def is_public_observation_ip(ip_str):
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def load_conpot_events(log_path: Path, since: datetime, own_nets, include_own):
    events = []
    skipped_own = 0
    skipped_internal = 0
    if not log_path.exists():
        return events, skipped_own, skipped_internal

    line_re = re.compile(r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+(?P<message>.*)$')
    with log_path.open(errors='ignore') as f:
        for line in f:
            line = line.strip()
            match = line_re.match(line)
            if not match:
                continue
            try:
                ts = datetime.strptime(match.group('ts'), '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if ts < since:
                continue

            message = match.group('message')
            src_ip = extract_conpot_ip(message)
            if not src_ip:
                continue
            if not include_own and is_own_ip(src_ip, own_nets):
                skipped_own += 1
                continue
            if not include_own and not is_public_observation_ip(src_ip):
                skipped_internal += 1
                continue

            events.append({
                '_ts': ts,
                'src_ip': src_ip,
                'protocol': protocol_from_conpot_message(message),
                'message': message,
            })

    return events, skipped_own, skipped_internal


def top(counter: Counter, n=10):
    return counter.most_common(n)


def md_table(headers, rows):
    out = ['| ' + ' | '.join(headers) + ' |',
           '|' + '|'.join(['---'] * len(headers)) + '|']
    for row in rows:
        out.append('| ' + ' | '.join(str(c) for c in row) + ' |')
    return '\n'.join(out)


def build_conpot_section(events, skipped_own, skipped_internal):
    lines = ['\n## OT / Conpot Übersicht\n']
    if skipped_own or skipped_internal:
        skipped_bits = []
        if skipped_own:
            skipped_bits.append(f'{skipped_own} eigene Events')
        if skipped_internal:
            skipped_bits.append(f'{skipped_internal} interne/private Events')
        lines.append(f'_Hinweis: {", ".join(skipped_bits)} wurden aus dem öffentlichen Report ausgeschlossen._\n')

    if not events:
        lines.append('_Keine öffentlichen Conpot/OT-Events im Zeitraum._')
        return '\n'.join(lines)

    observed = [event for event in events if event.get('src_ip')]
    top_ips = Counter(event['src_ip'] for event in observed)
    protocols = Counter(event['protocol'] for event in events)
    session_events = [event for event in events if 'session' in event['message'].lower() or 'connection from' in event['message'].lower()]

    lines.append(md_table(
        ['Metric', 'Anzahl'],
        [
            ['OT-Logevents', len(events)],
            ['OT-Sessions/Connections', len(session_events)],
            ['Unique öffentliche Quell-IPs', len(top_ips)],
            ['Protokolle gesehen', len(protocols)],
        ],
    ))

    if protocols:
        lines.append('\n### Top OT-Protokolle\n')
        lines.append(md_table(['Protokoll', 'Events'], top(protocols)))

    if top_ips:
        lines.append('\n### Top OT-Quell-IPs\n')
        lines.append(md_table(['IP', 'Events'], top(top_ips)))

    examples = [event for event in events if event.get('src_ip')][:10]
    if examples:
        lines.append('\n### Beispiel-Events\n')
        rows = [
            [
                event['_ts'].strftime('%Y-%m-%d %H:%M:%S'),
                event['protocol'],
                event.get('src_ip') or '-',
                event['message'][:160],
            ]
            for event in examples
        ]
        lines.append(md_table(['Zeit', 'Protokoll', 'Quelle', 'Event'], rows))

    return '\n'.join(lines)


def build_report(events, hours, skipped_own, conpot_events=None, conpot_skipped_own=0, conpot_skipped_internal=0):
    connections = [e for e in events if e.get('eventid') == 'cowrie.session.connect']
    login_failed = [e for e in events if e.get('eventid') == 'cowrie.login.failed']
    login_success = [e for e in events if e.get('eventid') == 'cowrie.login.success']
    commands = [e for e in events if e.get('eventid') == 'cowrie.command.input']
    downloads = [e for e in events if e.get('eventid') == 'cowrie.session.file_download']

    top_ips = Counter(e.get('src_ip') for e in connections if e.get('src_ip'))
    top_users = Counter(e.get('username') for e in login_failed + login_success if e.get('username'))
    top_passwords = Counter(e.get('password') for e in login_failed + login_success if e.get('password'))
    top_combos = Counter(
        f"{e.get('username')}/{e.get('password')}"
        for e in login_failed + login_success
        if e.get('username') and e.get('password')
    )
    top_commands = Counter(e.get('input') for e in commands if e.get('input'))

    lines = []
    lines.append(f'# Home SOC Daily Report — {datetime.now().strftime("%Y-%m-%d")}')
    lines.append(f'_Erstellt: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}_')
    if skipped_own:
        lines.append(f'_Hinweis: {skipped_own} Events von eigenen IPs (Red-Team-Lab) wurden ausgeschlossen._')
    lines.append('')

    lines.append('## Übersicht\n')
    lines.append(md_table(
        ['Metric', 'Anzahl'],
        [
            ['Verbindungen', len(connections)],
            ['Login fehlgeschlagen', len(login_failed)],
            ['Login erfolgreich (Honeypot)', len(login_success)],
            ['Befehle eingegeben', len(commands)],
            ['Datei-Downloads versucht', len(downloads)],
            ['Unique IPs', len(top_ips)],
        ],
    ))

    if top_ips:
        lines.append('\n## Top 10 Angreifer-IPs\n')
        lines.append(md_table(['IP', 'Verbindungen'], top(top_ips)))

    if top_combos:
        lines.append('\n## Top 10 User/Pass-Kombinationen\n')
        lines.append(md_table(['Kombination', 'Versuche'], top(top_combos)))

    if top_users:
        lines.append('\n## Top Usernames\n')
        lines.append(md_table(['Username', 'Versuche'], top(top_users)))

    if top_passwords:
        lines.append('\n## Top Passwörter\n')
        lines.append(md_table(['Passwort', 'Versuche'], top(top_passwords)))

    if top_commands:
        lines.append('\n## Top Befehle nach Login\n')
        lines.append(md_table(['Befehl', 'Anzahl'], top(top_commands)))
    else:
        lines.append('\n## Befehle nach Login\n_Keine — Angreifer waren nur automatisierte Scanner._')

    if downloads:
        lines.append('\n## Datei-Downloads (Malware-Versuche!)\n')
        rows = [[d.get('url', '-'), d.get('outfile', '-')] for d in downloads[:20]]
        lines.append(md_table(['URL', 'Lokale Datei'], rows))

    if conpot_events is not None:
        lines.append(build_conpot_section(conpot_events, conpot_skipped_own, conpot_skipped_internal))

    return '\n'.join(lines), connections, top_ips


def main():
    args = parse_args()
    log_path = Path(args.log)
    if not log_path.exists():
        sys.exit(f'FEHLER: {log_path} existiert nicht')

    own_nets = load_own_networks()
    since = datetime.now(timezone.utc) - timedelta(hours=args.hours)
    events, skipped = load_events(log_path, since, own_nets, args.include_own)
    conpot_events = None
    conpot_skipped_own = 0
    conpot_skipped_internal = 0
    if args.with_conpot:
        conpot_events, conpot_skipped_own, conpot_skipped_internal = load_conpot_events(
            Path(args.conpot_log),
            since,
            own_nets,
            args.include_own,
        )
    report, connections, top_ips = build_report(
        events,
        args.hours,
        skipped,
        conpot_events,
        conpot_skipped_own,
        conpot_skipped_internal,
    )

    if args.output:
        out = Path(args.output)
    else:
        out = Path.home() / 'home-soc-lab/reports' / f'{datetime.now().strftime("%Y-%m-%d")}.md'
        out.parent.mkdir(parents=True, exist_ok=True)

    out.write_text(report)
    print(report)
    print(f'\n-> Bericht gespeichert: {out}')
    if skipped:
        print(f'-> {skipped} Events von eigenen IPs wurden gefiltert.')


if __name__ == "__main__":
    main()
