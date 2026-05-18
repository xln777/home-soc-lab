# Case-Study-Workflow

Dieser Ablauf hilft dabei, aus einem Tagesreport eine saubere Case Study zu machen, ohne rohe Logs manuell durchsuchen zu müssen.

## 1. Kandidat auswählen

Starte im Ordner `reports/` und suche nach Auffälligkeiten:

- sehr viele Verbindungen von einer IP
- ungewöhnliche Usernames oder Passwörter
- erfolgreiche Honeypot-Logins
- Befehle nach Login
- Datei-Downloads
- kurze, schnelle Bursts
- wiederkehrende IPs über mehrere Tage

Der Tagesreport ist nur der Einstieg. Für eine Case Study reicht er allein meistens nicht aus.

## 2. Cowrie-Evidence erzeugen

Nutze das Evidence-Script für eine einzelne IP:

```bash
python3 ~/home-soc-lab/scripts/case-study-evidence.py 107.189.23.209 \
  --date 2026-05-16 \
  -o /tmp/evidence.md
```

Die Ausgabe enthält:

- erste und letzte Sichtung
- Event-Typen
- Login-Erfolge und Fehlschläge
- Client-Versionen
- HASSH-Fingerprints
- Top-Usernames
- Top-Passwörter
- Top-User/Pass-Kombinationen
- Beispiel-Sessions mit Username, Passwort, Client, Befehlen und Downloads
- automatische Hinweise für die Analyse

Wichtig: Nicht alle Passwörter blind in die Case Study übernehmen. Nur Muster und repräsentative Beispiele nutzen.

## 3. Threat Intelligence ergänzen

Danach die IP anreichern:

```bash
python3 ~/home-soc-lab/scripts/enrich.py 107.189.23.209
```

Prüfe besonders:

- AbuseIPDB Confidence und Anzahl Reporter
- GreyNoise Noise/RIOT
- Shodan offene Ports
- VirusTotal Reputation
- WHOIS, ASN und Netzblock

## 4. Hypothese bilden

Aus Cowrie-Evidence und OSINT entsteht die Arbeitshypothese.

Beispiele:

- Credential-Validation statt direkter Ausnutzung
- branchenspezifischer Scanner
- generischer Root-Bruteforce
- Malware-Dropper
- Internetweiter Portscanner

Die Hypothese muss zu den Logs passen. Wenn keine Befehle oder Downloads vorkamen, nicht so schreiben, als wäre ein echter Post-Exploitation-Angriff passiert.

## 5. Case Study schreiben

Neue Case Studies liegen nach Datum sortiert:

```text
case-studies/YYYY-MM-DD/IP-thema.md
```

Beispiel:

```text
case-studies/2026-05-16/107-189-23-209-root-wordlist-burst.md
```

Ein neues Gerüst kann per Script erzeugt werden:

```bash
python3 scripts/new-case-study.py 107.189.23.209 \
  --date 2026-05-16 \
  --slug root-wordlist-burst \
  --threat "schneller Root-Credential-Scanner" \
  --title-en "Root wordlist burst from a cloud hosting network" \
  --threat-en "fast root credential scanner"
```

## 6. Prüfen

Vor dem Commit prüfen:

- keine privaten Serverdetails
- keine echten Zugangsdaten
- keine lokalen Pfade
- keine unnötig langen Rohlog-Blöcke
- IP, Datum und Zahlen stimmen
- Links im Index funktionieren

## 7. Index aktualisieren

Der Index wird automatisch erzeugt:

```bash
python3 scripts/update-case-study-index.py
```

Das Script aktualisiert `case-studies/README.md` und `case-studies/README.en.md`.
