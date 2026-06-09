#!/usr/bin/env bash
# Setup-Script: Suricata NIDS auf Ubuntu 24.04
# Führe dieses Script als root aus: sudo bash setup-suricata.sh
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Als root ausführen: sudo bash $0"

# ── Netzwerk-Interface und eigene IP erkennen ─────────────────────────────────
IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
[[ -z "$IFACE" ]] && error "Konnte kein Netzwerk-Interface ermitteln."
info "Interface: $IFACE"

PUBLIC_IP=$(curl -sf --max-time 5 https://api.ipify.org || true)
if [[ -z "$PUBLIC_IP" ]]; then
    warn "Öffentliche IP nicht ermittelbar – HOME_NET bleibt auf RFC1918-Standardwert."
    HOME_NET="[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
else
    HOME_NET="[$PUBLIC_IP/32]"
    info "Öffentliche IP: $PUBLIC_IP → HOME_NET=$HOME_NET"
fi

# ── Installation ──────────────────────────────────────────────────────────────
info "Installiere Suricata..."
apt-get update -q
apt-get install -y suricata

# ── suricata.yaml konfigurieren ───────────────────────────────────────────────
CONF=/etc/suricata/suricata.yaml
info "Konfiguriere $CONF ..."

# HOME_NET setzen
sed -i "s|HOME_NET:.*|HOME_NET: \"$HOME_NET\"|" "$CONF"

# af-packet Interface setzen (erste Occurrence)
sed -i "0,/interface: .*/s/interface: .*/interface: $IFACE/" "$CONF"

# Sicherstellen dass EVE-Log läuft und wichtige Typen aktiv sind
# Suricata 7.x hat EVE standardmäßig aktiv – prüfen ob aktiviert
if grep -q "enabled: no" "$CONF"; then
    # Nur die EVE-Log-Zeile aktivieren, nicht blind alle
    sed -i '/- eve-log:/{n; s/enabled: no/enabled: yes/}' "$CONF"
fi

info "suricata.yaml konfiguriert."

# ── Regelaktualisierung ───────────────────────────────────────────────────────
info "Lade Suricata-Regeln (suricata-update)..."
suricata-update --no-reload

# ── Dienst aktivieren ─────────────────────────────────────────────────────────
info "Aktiviere und starte Suricata..."
systemctl enable suricata
systemctl restart suricata
sleep 3

if systemctl is-active --quiet suricata; then
    info "Suricata läuft."
else
    error "Suricata nicht gestartet. Prüfe: journalctl -u suricata -n 50"
fi

# ── Log-Pfad prüfen ───────────────────────────────────────────────────────────
EVE_LOG=/var/log/suricata/eve.json
if [[ -f "$EVE_LOG" ]]; then
    info "EVE-Log vorhanden: $EVE_LOG"
else
    warn "EVE-Log noch nicht vorhanden – entsteht beim ersten Event."
fi

# ── Promtail-Snippet ausgeben ─────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  NÄCHSTER SCHRITT: Promtail konfigurieren"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Füge folgenden Block in ~/monitoring/promtail.yml unter 'scrape_configs:' ein:"
echo ""
cat <<'PROMTAIL'
  - job_name: suricata
    static_configs:
      - targets:
          - localhost
        labels:
          job: suricata
          __path__: /var/log/suricata/eve.json
    pipeline_stages:
      - json:
          expressions:
            event_type: event_type
            src_ip: src_ip
            alert_signature: alert.signature
            alert_severity: alert.severity
      - labels:
          event_type:
PROMTAIL
echo ""
echo "Danach Promtail neu starten:"
echo "  cd ~/monitoring && docker compose restart promtail"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Grafana-Dashboard importieren"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  dashboards/suricata-nids.json in Grafana importieren:"
echo "  Grafana → Dashboards → Import → JSON hochladen"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Nützliche Befehle"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  systemctl status suricata"
echo "  tail -f /var/log/suricata/eve.json | jq 'select(.event_type==\"alert\")'"
echo "  suricata-update && systemctl reload suricata   # Regeln aktualisieren"
echo "  suricata -T -c /etc/suricata/suricata.yaml     # Konfiguration testen"
echo ""
info "Setup abgeschlossen."
