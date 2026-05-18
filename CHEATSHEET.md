# Cheatsheet - home-soc-lab

Die wichtigsten Befehle für Betrieb, Analyse und Fehlersuche.

## Honeypot

```bash
# Läuft Cowrie?
docker ps | grep cowrie

# Live-Log ansehen
tail -f ~/cowrie/logs/cowrie.json

# Nur fehlgeschlagene Logins anzeigen
tail -f ~/cowrie/logs/cowrie.json | grep --line-buffered login.failed

# Cowrie neu starten
cd ~/cowrie
docker compose restart

# Container-Logs
docker logs cowrie-cowrie-1 --tail 50 --follow
```

## Tagesreports

```bash
# Report für die letzten 24 Stunden
python3 ~/home-soc-lab/scripts/cowrie-daily-report.py

# Größerer Zeitraum
python3 ~/home-soc-lab/scripts/cowrie-daily-report.py --hours 72

# Report aus einer rotierten Log-Datei
python3 ~/home-soc-lab/scripts/cowrie-daily-report.py \
  --log ~/cowrie/logs/cowrie.json.2026-05-15 \
  --hours 999999 \
  -o /tmp/report-2026-05-15.md
```

## IP-Anreicherung

```bash
# Voller Markdown-Bericht
python3 ~/home-soc-lab/scripts/enrich.py 193.32.162.34

# JSON-Ausgabe
python3 ~/home-soc-lab/scripts/enrich.py 193.32.162.34 --json

# In eine Datei schreiben
mkdir -p ~/home-soc-lab/case-studies/snippets
python3 ~/home-soc-lab/scripts/enrich.py 193.32.162.34 \
  > ~/home-soc-lab/case-studies/snippets/enrichment.md

# Mehrere IPs prüfen
for ip in 193.32.162.34 82.223.34.63; do
  python3 ~/home-soc-lab/scripts/enrich.py "$ip"
  echo "---"
done
```

## AbuseIPDB

```bash
# Testlauf ohne echte Meldung
python3 ~/home-soc-lab/scripts/abuseipdb-reporter.py --dry-run

# Letzte 24 Stunden melden
python3 ~/home-soc-lab/scripts/abuseipdb-reporter.py --hours 24

# Anderen Logpfad verwenden
python3 ~/home-soc-lab/scripts/abuseipdb-reporter.py \
  --log ~/cowrie/logs/cowrie.json.2026-05-16 \
  --hours 999999
```

## CrowdSec

```bash
# Aktuelle Entscheidungen
sudo cscli decisions list

# Alerts der letzten Stunde
sudo cscli alerts list --since 1h

# IP manuell für 24 Stunden bannen
sudo cscli decisions add --ip 1.2.3.4 --duration 24h

# IP wieder freigeben
sudo cscli decisions delete --ip 1.2.3.4

# Metriken
sudo cscli metrics
```

## Docker

```bash
docker ps
docker logs cowrie-cowrie-1 --tail 50 --follow
docker stats

# Compose-Stack neu starten
cd ~/monitoring
docker compose restart

# Erst prüfen, wie viel Platz Docker belegt
docker system df

# Nur bewusst nutzen: entfernt ungenutzte Images/Container
docker system prune -af
```

## Backups

```bash
bash ~/bin/restic-backup.sh status
bash ~/bin/restic-backup.sh check
bash ~/bin/restic-backup.sh backup

source ~/.secrets
restic snapshots
```

## Grafana und Loki

```bash
# SSH-Tunnel auf den eigenen Server
ssh -L 3000:localhost:3000 your-server

# Browser
# http://localhost:3000

# Loki direkt per LogQL abfragen
curl -G "http://localhost:3100/loki/api/v1/query_range" \
  --data-urlencode 'query={container="cowrie-cowrie-1"}' \
  --data-urlencode 'limit=10'
```

## System-Wartung

```bash
sudo apt update
sudo apt upgrade -y
df -h /
free -h
htop
who
last | head -20
sudo ufw status verbose
sudo ss -tunap | head -30
```

## Git-Workflow

```bash
cd ~/home-soc-lab

git status
git diff

git add case-studies/2026-05-18-titel.md
git commit -m "case study: kurze beschreibung"
git push origin main

# Auto-Commit-Lauf manuell testen
~/bin/soc-lab-autocommit.sh
```

## Cron-Jobs

```bash
crontab -l

# Cron-Logs der Pipeline
tail -50 ~/logs/report.log
tail -50 ~/logs/autocommit.log
tail -50 ~/logs/abuseipdb.log

# System-Cron-Aktivität
sudo journalctl -u cron --since "1 hour ago"
```

## Schnelle Fehlersuche

```bash
sudo journalctl --since "10 minutes ago"
sudo journalctl -u ssh --since "1 hour ago"
sudo journalctl -u crowdsec --since "1 hour ago"
sudo ss -tlnp
```

## Analyse-Workflow bei auffälliger IP

```bash
IP=193.32.162.34

# 1. Threat-Intel-Anreicherung
python3 ~/home-soc-lab/scripts/enrich.py "$IP"

# 2. Anzahl der Events
grep -c "\"src_ip\": \"$IP\"" ~/cowrie/logs/cowrie.json*

# 3. Username/Passwort-Kombinationen
grep "\"src_ip\": \"$IP\"" ~/cowrie/logs/cowrie.json* \
  | grep login.failed \
  | python3 -c "
import sys, json
for line in sys.stdin:
    payload = line.split(':', 1)[1] if ':' in line else line
    try:
        e = json.loads(payload)
        if e.get('username'):
            print(f\"{e['username']}/{e.get('password','')}\")
    except Exception:
        pass
" | sort | uniq -c | sort -rn | head -20

# 4. AbuseIPDB-Testlauf
python3 ~/home-soc-lab/scripts/abuseipdb-reporter.py --dry-run
```

## Case-Study-Methode

1. Beobachten: Was steht roh in den Logs?
2. Fragen stellen: Was ist auffällig?
3. Gruppieren: Top-N, Counter, Zeitverlauf.
4. Pivot: Eine IP oder ein Muster tiefer verfolgen.
5. Hypothese: Was wollte der Angreifer wahrscheinlich erreichen?
6. Verifikation: AbuseIPDB, GreyNoise, Shodan, VirusTotal, WHOIS.
7. Ergebnis sauber dokumentieren.

## Wichtige Pfade

| Pfad | Inhalt |
|------|--------|
| `~/cowrie/` | Cowrie-Konfiguration und Docker Compose |
| `~/cowrie/logs/` | Cowrie-JSON-Logs |
| `~/home-soc-lab/` | dieses Repo |
| `~/monitoring/` | Grafana, Loki, Promtail |
| `~/logs/` | Cron-Logs |
| `~/bin/` | eigene Hilfsscripte |
| `~/.secrets` | lokale API-Keys, nie committen |
