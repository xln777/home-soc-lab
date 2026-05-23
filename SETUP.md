# Setup-Anleitung

Diese Anleitung beschreibt, wie ein vergleichbares Honeypot-Analyse-Lab auf einem frischen Ubuntu-Server aufgebaut werden kann. Sie ist bewusst generisch gehalten und enthält keine privaten Serverdaten.

## Voraussetzungen

- Ubuntu 24.04 Server, mindestens 4 GB RAM
- Benutzer mit `sudo`-Rechten
- Docker und Docker Compose
- eigene Domain optional, zum Beispiel für Grafana hinter Reverse Proxy oder Tunnel
- API-Keys für die Threat-Intel-Quellen

| Key | Dienst | Zweck | Pflicht? |
|-----|--------|-------|----------|
| `ABUSEIPDB_KEY` | [abuseipdb.com](https://www.abuseipdb.com) | Reputations-Score und Meldungs-Historie | Ja |
| `SHODAN_KEY` | [shodan.io](https://www.shodan.io) | offene Ports auf Angreifer-IPs | Ja |
| `VT_KEY` | [virustotal.com](https://www.virustotal.com) | aggregierte Reputation | Ja |
| `GREYNOISE_KEY` | [greynoise.io](https://www.greynoise.io) | Scanner-Klassifikation | Optional |

`ip-api.com` und WHOIS funktionieren ohne API-Key.

## 1. Basis-Hardening

```bash
sudo apt update
sudo apt upgrade -y

sudo adduser soc
sudo usermod -aG sudo soc
```

SSH-Basics:

```text
PermitRootLogin no
PasswordAuthentication no
Port 22
```

Firewall-Beispiel:

```bash
sudo ufw allow 22/tcp
sudo ufw allow 2222/tcp
sudo ufw allow 80,443/tcp
sudo ufw enable
sudo ufw status verbose
```

Hinweis: Der echte SSH-Zugang bleibt auf Port 22. Cowrie bekommt einen eigenen Honeypot-Port, hier `2222`.

## 2. Docker installieren

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker "$USER"
newgrp docker
docker version
```

## 3. Cowrie SSH-Honeypot

```bash
mkdir -p ~/cowrie/{data,logs}
cd ~/cowrie
```

```bash
cat > docker-compose.yml << 'EOF'
services:
  cowrie:
    image: cowrie/cowrie:latest
    restart: unless-stopped
    ports:
      - "2222:2222"
    volumes:
      - ./data:/cowrie/cowrie-git/var/lib/cowrie
      - ./logs:/cowrie/cowrie-git/var/log/cowrie
EOF
```

```bash
docker compose up -d
docker compose logs -f cowrie
```

Test von einem anderen System:

```bash
ssh root@DEIN-SERVER -p 2222
```

Nimm dafür ein Testpasswort. Cowrie protokolliert den Versuch.

## 4. CrowdSec

```bash
curl -s https://install.crowdsec.net | sudo sh
sudo apt install crowdsec crowdsec-firewall-bouncer-iptables -y
sudo cscli collections install crowdsecurity/sshd
sudo systemctl restart crowdsec
sudo cscli decisions list
```

## 5. Analyse-Repo

```bash
cd ~
git clone https://github.com/xln777/home-soc-lab.git
cd home-soc-lab

sudo apt install whois -y
```

API-Keys lokal ablegen:

```bash
cat > ~/.secrets << 'EOF'
ABUSEIPDB_KEY=DEIN-KEY-HIER
SHODAN_KEY=DEIN-KEY-HIER
VT_KEY=DEIN-KEY-HIER
GREYNOISE_KEY=DEIN-KEY-HIER
EOF

chmod 600 ~/.secrets
```

Eigene IPs für Tests filtern:

```bash
cp scripts/own-ips.txt.example scripts/own-ips.txt
nano scripts/own-ips.txt
python3 scripts/privacy-scan.py
```

Funktionstest:

```bash
python3 scripts/enrich.py 193.32.162.34
python3 scripts/cowrie-daily-report.py --log ~/cowrie/logs/cowrie.json
```

## 6. Cron-Jobs

```bash
mkdir -p ~/logs
crontab -e
```

Beispiel:

```cron
# Cowrie-Tagesbericht 06:30
30 6 * * * python3 ~/home-soc-lab/scripts/cowrie-daily-report.py --log ~/cowrie/logs/cowrie.json -o ~/home-soc-lab/reports/$(date +\%Y-\%m-\%d).md >> ~/logs/report.log 2>&1

# AbuseIPDB-Reporting 07:00
0 7 * * * python3 ~/home-soc-lab/scripts/abuseipdb-reporter.py --log ~/cowrie/logs/cowrie.json >> ~/logs/abuseipdb.log 2>&1

# Auto-Commit der Reports 07:15
15 7 * * * ~/bin/soc-lab-autocommit.sh >> ~/logs/autocommit.log 2>&1
```

## 7. Git-Auto-Commit-Script

```bash
mkdir -p ~/bin
```

```bash
cat > ~/bin/soc-lab-autocommit.sh << 'EOF'
#!/bin/bash
set -euo pipefail

cd "$HOME/home-soc-lab"
git pull --rebase origin main

if [ -n "$(git status --porcelain reports/)" ]; then
    git add reports/
    git commit -m "report: daily honeypot data $(date +%Y-%m-%d)"
    git push origin main
fi
EOF

chmod +x ~/bin/soc-lab-autocommit.sh
```

Empfehlung: Für den Server einen eigenen GitHub-Deploy-Key oder einen separaten SSH-Key mit minimalen Rechten verwenden.

## 8. Restic-Backup

Optional, aber empfohlen:

```bash
sudo apt install restic -y
```

Secrets in `~/.secrets` ergänzen:

```bash
cat >> ~/.secrets << 'EOF'
B2_ACCOUNT_ID=...
B2_ACCOUNT_KEY=...
RESTIC_REPOSITORY=b2:dein-bucket:/restic
RESTIC_PASSWORD=...
EOF
```

Einmalig initialisieren:

```bash
source ~/.secrets
restic init
```

## 9. Verifikation

```bash
tail -f ~/cowrie/logs/cowrie.json
python3 ~/home-soc-lab/scripts/cowrie-daily-report.py --hours 24 -o /tmp/test-report.md
python3 ~/home-soc-lab/scripts/enrich.py 193.32.162.34
python3 ~/home-soc-lab/scripts/abuseipdb-reporter.py --dry-run
crontab -l
~/bin/soc-lab-autocommit.sh
```

## Sicherheitshinweis

Alle Beispiele verwenden Platzhalter. Zugangsdaten und lokale Betriebsdetails bleiben außerhalb der öffentlichen Dokumentation.
