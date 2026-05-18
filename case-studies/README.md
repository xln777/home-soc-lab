# Case Studies

Hier liegen ausführlichere Auswertungen von Angriffen, die mir in den Tages-Reports aufgefallen sind. Im Gegensatz zu `reports/` (automatisch generiert) sind das manuelle Schreibarbeiten.

## Index

| Datum | Titel | Bedrohung |
|-------|-------|-----------|
| 2026-05-17 | [Crypto-Validator-Scanner aus Rumänien](2026-05-17-crypto-validator-scanner.md) | Credential-Brute-Force gegen Blockchain-Validatoren |
| 2026-05-16 | [Root-Wortlisten-Burst aus einem Cloud-Hosting-Netz](2026-05-16-root-wordlist-burst.md) | schneller Root-Credential-Scanner |

## Aufbau

Jede Case Study folgt grob diesen 9 Punkten. Sie sind als Leitfaden gedacht, nicht als Zwangsformat. Wenn ein Punkt für einen konkreten Fall nichts hergibt, kommt er raus.

1. **Zusammenfassung** – kurzer Überblick
2. **Beobachtung** – rohe Zahlen aus den Logs
3. **Erste Fragen** – was ist auffällig
4. **Pattern** – Häufungen, Sortierungen, Cluster
5. **Hypothese** – was will der Angreifer
6. **OSINT-Verifikation** – AbuseIPDB, GreyNoise, Shodan, VirusTotal, WHOIS
7. **Schlussfolgerung** – passt die Hypothese zur Evidenz
8. **Defensive Lessons** – was nehme ich für eigene Systeme mit
9. **IOCs** – Indicators of Compromise für andere

## Workflow

1. Auffälligen Tag in `reports/` raussuchen
2. `scripts/enrich.py <ip>` für den Threat-Intel-Kontext
3. Die 9 Punkte als Gerüst nehmen und einen Bericht schreiben
4. Committen, pushen, fertig
