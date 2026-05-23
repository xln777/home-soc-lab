# home-soc-lab

[English overview](README.en.md)

Ein selbst betriebenes Mini-SOC auf einem Hetzner-VPS. Das Projekt verbindet Cowrie-Honeypot-Daten, Conpot-OT-Telemetrie, Log-Auswertung, Threat-Intelligence-Anreicherung und kurze Incident-Writeups.

Ziel ist nicht ein produktives Enterprise-SOC, sondern ein nachvollziehbares Portfolio-Projekt für Defensive Security: echte Angriffsdaten sammeln, auswerten und sauber dokumentieren.

## Kurz erklärt

Ich betreibe einen SSH-Honeypot und einen OT/ICS-Honeypot, sammle die Logs zentral und werte sie mit eigenen Python-Scripts aus. Aus den Daten entstehen tägliche Reports und einzelne Case Studies. Dabei übe ich typische Blue-Team-Arbeit: Log-Verständnis, IOC-Auswertung, Threat-Intel-Abfragen, saubere Dokumentation und defensive Schlussfolgerungen.

## Was läuft

| Komponente | Zweck |
|------------|-------|
| Cowrie SSH-Honeypot | sammelt reale SSH-Scan- und Login-Versuche |
| Conpot OT/ICS-Honeypot | simuliert industrielle Protokolle wie Modbus, S7Comm, SNMP und BACnet |
| Grafana, Loki, Promtail | Log-Aggregation und Dashboarding |
| CrowdSec | automatische Entscheidungen gegen auffällige IPs |
| AbuseIPDB-Reporting | tägliches Melden neuer Angreifer-IPs |
| Restic + Backblaze B2 | Server-Backups |
| Python-Scripts | Reports, IP-Anreicherung und wiederholbare Analysen |

## Repository-Struktur

| Pfad | Inhalt |
|------|--------|
| `case-studies/` | manuelle Tiefenanalysen einzelner Angriffe, sortiert nach Datum |
| `ot-case-studies/` | manuelle OT/ICS-Auswertungen aus Conpot |
| `reports/` | automatisch erzeugte Tagesreports aus Cowrie-Logs |
| `scripts/` | Python-Tools für Reports, AbuseIPDB und Threat Intelligence |
| `CHEATSHEET.md` | Alltagsbefehle für Betrieb und Analyse |
| `SETUP.md` | generische Setup-Anleitung ohne private Serverdaten |

## Datenfluss

```text
Internet-Scanner
  -> Cowrie SSH-Honeypot + Conpot OT/ICS-Honeypot
  -> JSON- und Text-Logs
  -> Python-Reports
  -> Threat-Intel-Anreicherung
  -> Reports und Case Studies
```

## Reports

`scripts/cowrie-daily-report.py` erzeugt Markdown-Reports mit:

- Top-Angreifer-IPs
- häufige Username/Passwort-Kombinationen
- erfolgreiche Honeypot-Logins
- eingegebene Befehle
- versuchte Malware-Downloads
- OT/Conpot-Abschnitt mit Protokollen, öffentlichen Quell-IPs und Beispiel-Events

Eigene Test-IP-Adressen werden über `scripts/own-ips.txt` gefiltert. Die Datei ist absichtlich gitignored. Vor Commits kann `python3 scripts/privacy-scan.py` prüfen, ob eine dort eingetragene eigene IP versehentlich in öffentliche Reports oder Dashboard-Exports geraten ist.

Für einzelne IPs erzeugt `scripts/case-study-evidence.py` eine strukturierte Evidence-Übersicht mit Zeitfenster, Event-Typen, Client-Fingerprints, User/Pass-Kombinationen und Beispiel-Sessions.

## Threat Intelligence

`scripts/enrich.py <ip>` führt eine kompakte IP-Anreicherung durch:

| Quelle | Ergebnis |
|--------|----------|
| AbuseIPDB | Reputation, Reports, Confidence Score |
| ip-api.com | GeoIP, ASN, Hosting/Proxy-Hinweise |
| WHOIS | Netzregistrierung |
| GreyNoise | Scanner-Klassifikation |
| Shodan | offene Ports |
| VirusTotal | aggregierte Reputation |

## Case Studies

Die Case Studies zeigen den Lern- und Analyseweg: Was war in den Logs sichtbar, welches Muster war auffällig, welche Hypothese entstand daraus und wie wurde sie mit externen Quellen geprüft.

Die Indexe liegen hier:

- Deutsch: [`case-studies/README.md`](case-studies/README.md)
- Englisch: [`case-studies/README.en.md`](case-studies/README.en.md)
- OT/ICS: [`ot-case-studies/README.md`](ot-case-studies/README.md)

Neue Analysen werden dort automatisch gepflegt, damit diese Hauptseite stabil bleibt.

## Sicherheit

Die Dokumentation ist für ein öffentliches Portfolio geschrieben. Beispiele nutzen Platzhalter und generische Pfade, damit das Projekt nachvollziehbar bleibt, ohne private Betriebsdetails offenzulegen.
