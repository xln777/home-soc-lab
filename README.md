# home-soc-lab

Ein selbst betriebenes Mini-SOC auf einem Hetzner-VPS. Das Projekt verbindet Cowrie-Honeypot-Daten, Log-Auswertung, Threat-Intelligence-Anreicherung und kurze Incident-Writeups.

Ziel ist nicht ein produktives Enterprise-SOC, sondern ein nachvollziehbares Portfolio-Projekt für Defensive Security: echte Angriffsdaten sammeln, auswerten und sauber dokumentieren.

## Kurz erklärt

Ich betreibe einen SSH-Honeypot, sammle die Logs zentral und werte sie mit eigenen Python-Scripts aus. Aus den Daten entstehen tägliche Reports und einzelne Case Studies. Dabei übe ich typische Blue-Team-Arbeit: Log-Verständnis, IOC-Auswertung, Threat-Intel-Abfragen, saubere Dokumentation und defensive Schlussfolgerungen.

## Was läuft

| Komponente | Zweck |
|------------|-------|
| Cowrie SSH-Honeypot | sammelt reale SSH-Scan- und Login-Versuche |
| Grafana, Loki, Promtail | Log-Aggregation und Dashboarding |
| CrowdSec | automatische Entscheidungen gegen auffällige IPs |
| AbuseIPDB-Reporting | tägliches Melden neuer Angreifer-IPs |
| Restic + Backblaze B2 | Server-Backups |
| Python-Scripts | Reports, IP-Anreicherung und wiederholbare Analysen |

## Repository-Struktur

| Pfad | Inhalt |
|------|--------|
| `case-studies/` | manuelle Tiefenanalysen einzelner Angriffe |
| `reports/` | automatisch erzeugte Tagesreports aus Cowrie-Logs |
| `scripts/` | Python-Tools für Reports, AbuseIPDB und Threat Intelligence |
| `CHEATSHEET.md` | Alltagsbefehle für Betrieb und Analyse |
| `SETUP.md` | generische Setup-Anleitung ohne private Serverdaten |

## Datenfluss

```text
Internet-Scanner
  -> Cowrie SSH-Honeypot
  -> JSON-Logs
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

Eigene Test-IP-Adressen werden über `scripts/own-ips.txt` gefiltert. Die Datei ist absichtlich gitignored.

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

Aktueller Einstieg:

- [`case-studies/2026-05-17-crypto-validator-scanner.md`](case-studies/2026-05-17-crypto-validator-scanner.md)

## Sicherheit

Die Dokumentation ist für ein öffentliches Portfolio geschrieben. Beispiele nutzen Platzhalter und generische Pfade, damit das Projekt nachvollziehbar bleibt, ohne private Betriebsdetails offenzulegen.
