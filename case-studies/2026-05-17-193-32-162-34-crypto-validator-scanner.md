# Case Study: Crypto-Validator-Scanner aus Rumänien

**Datum:** 2026-05-17 (Update: 2026-05-18)
**Quelle:** Cowrie SSH-Honeypot auf meinem Hetzner-Server
**Analyst:** xln777

## 1. Zusammenfassung

Eine einzelne IP aus einem rumänischen Bulletproof-Hoster hat ab dem 12. Mai 2026 meinen Honeypot mit Login-Versuchen geflutet. Am ersten Tag waren es noch 1.550 Verbindungen, sechs Tage später schon 17.000. Die Wortliste war keine Standard-Bruteforce, sondern voll mit Crypto-Begriffen: `tron`, `solana`, `eth`, `firedancer`, `validator`, `eigenlayer`. AbuseIPDB gibt der IP 100 von 100 Punkten und 157 Meldungen. Nach jedem erfolgreichen Login passierte nichts: keine Befehle, keine Downloads. Sieht aus wie reines Credential-Sammeln für eine spätere Phase.

## 2. Beobachtung

Verlauf der Verbindungen pro Tag, gefiltert auf 193.32.162.34:

| Tag        | Gesamt | Davon diese IP |
|------------|-------:|---------------:|
| 2026-05-12 |  1.563 |          1.550 |
| 2026-05-13 | 14.831 |         14.809 |
| 2026-05-14 | 15.456 |         15.444 |
| 2026-05-15 | 16.778 |         16.746 |
| 2026-05-16 | 17.171 |         17.101 |
| 2026-05-17 | 15.697 |         15.672 |

Vor dem 12. Mai gab es maximal 34 Verbindungen pro Tag, das war normales Hintergrundrauschen aus zufälligen Scans. Erster Kontakt der neuen IP war 21:22 Uhr UTC. Bis Mitternacht liefen 1.550 Verbindungen durch, also etwa 10 pro Minute. Ab dem nächsten Tag lief das Tool durchgehend mit gleichem Tempo, dadurch die Verzehnfachung.

## 3. Erste Fragen

Was ist auffällig an der Verbindung?

- Bei 17.000 Versuchen pro Tag kann kein Mensch dahinter sitzen.
- Username und Passwort waren in den meisten Fällen identisch (`tron/tron`, `solana/solana`).
- Der SSH-Client meldete sich als `SSH-2.0-Go`. OpenSSH oder PuTTY würde sich anders identifizieren. Das ist ein Tool, das jemand selbst in Go geschrieben hat.
- Nach erfolgreichem Login wurden 0 Befehle abgesetzt. Bei einem manuellen Angreifer würde ich `whoami`, `uname -a` oder ähnliches erwarten.

## 4. Pattern

Top-Credentials aus dem 12.-Mai-Log:

```
tron / tron               18
solana / solana           10
sol / sol                 10
validator / validator     10
firedancer / firedancer   10
node / node               10
bitcoin / bitcoin         10
ubuntu / ubuntu           19
ubuntu / 123456           18
```

Die Crypto-Begriffe sind keine zufällige Auswahl. Das sind alles Default-User-Namen, die in den jeweiligen Installationsanleitungen der Validator-Software vorgeschlagen werden:

| Username | Software |
|----------|----------|
| `heimdall`, `bor` | Polygon-Validator |
| `eigenlayer`, `eigen` | EigenLayer Restaking |
| `firedancer` | Solana-Client von Jump Crypto |
| `bittensor`, `tao` | Bittensor AI |
| `solana`, `sol`, `tron`, `eth`, `bitcoin` | direkte Chain-Nodes |

Ein normaler Bruteforce-Bot probiert `root/root`, `admin/admin` oder die rockyou.txt durch. Diese Liste ist kuratiert. Jemand hat sich hingesetzt und überlegt, welche Service-Accounts es bei Crypto-Setups gibt.

## 5. Hypothese

Vermutlich läuft das so ab: Der Scanner durchsucht das Internet nach SSH-Ports und testet pro Server seine Wortliste. Findet er einen gültigen Login, schreibt er das Ergebnis weg und macht sofort weiter. Ein zweites Tool oder ein menschlicher Operator nutzt diese Liste dann später, um die wirklich interessanten Treffer manuell zu plündern.

Was bei einem echten Validator-Treffer passieren würde, kann ich nur raten:
- Staking-Rewards umleiten
- Hot Wallet leeren, falls Keys lokal liegen
- Slashing provozieren (für Konkurrenz oder aus Spaß)
- Im Zweifel Crypto-Mining draufpacken

Mein Honeypot hat das Tool gestoppt, bevor Phase 2 anlief. Es weiß, dass `tron/tron` funktioniert hat, kann aber damit nichts anfangen, weil keine echte Validator-Software dahintersteckt.

## 6. OSINT-Verifikation

### AbuseIPDB

- Confidence: 100/100
- Meldungen: 157 von 39 verschiedenen Nutzern
- Land: RO
- ISP: UNMANAGED LTD
- Typ: Data Center / Web Hosting / Transit
- Zuletzt gemeldet: 2026-05-18

39 verschiedene Reporter heißt, dass mindestens 39 andere Server diese IP unabhängig gesehen und gemeldet haben.

### GreyNoise

- Klassifikation: unknown (nicht als gutartig markiert)
- Noise: true (breit scannend)
- Riot: false (kein bekannter legitimer Dienst)
- Zuletzt gesehen: 2026-05-18

### VirusTotal

14 Vendoren stufen die IP als bösartig ein, ein weiterer als verdächtig, Reputation -1.

### Shodan

Nicht erfasst. Auf der IP sind keine offenen Ports indexiert, das deckt sich mit dem Verhalten: die Maschine spricht nur ausgehend.

### WHOIS

- Netzblock: 193.32.162.0/24
- Netname: DMZHOST
- ASN: AS47890 UNMANAGED LTD
- Registriert in NL, Server physisch in RO

UNMANAGED LTD ist ein bekannter Bulletproof-Provider. Die Trennung "Registrierung in NL, Hardware in RO" ist typisch: erschwert juristische Zugriffe und Abuse-Beschwerden landen ins Leere.

## 7. Schlussfolgerung

Die Indizien zusammen ergeben für mich folgendes Bild:

- Selbst geschriebenes Tool, nicht von der Stange
- Kuratierte Wortliste, gezielt auf eine Branche zugeschnitten
- Hosting bei einem Anbieter, der nicht kooperiert
- Volumen automatisch hochgefahren, sobald ein Ziel reagiert

Das spricht nicht für einen Hobby-Angreifer. Wer sich diesen Aufwand macht, hat ein finanzielles Motiv. Crypto-Infrastruktur ist da naheliegend, weil die Beute sofort liquide ist.

## 8. Defensive Lessons

Mitnehmen für eigene Setups:

- Validator-Software nie unter dem Default-Account-Namen mit schwachem Passwort laufen lassen. Die Wortlisten sind drauf vorbereitet.
- Wenn echtes Geld an einem SSH-Zugang hängt: kein Passwort-Login, nur Keys. Idealerweise nur erreichbar via VPN oder Port-Knocking.
- CrowdSec kann diese IP automatisch wegblocken, sobald sie auch nur einmal verdächtig auftritt. AbuseIPDB-Integration nutzen.
- Idee für eine Detection-Regel: SSH-Login-Versuch mit Username gleich Crypto-Service-Name (`solana`, `tron`, `eigenlayer`, ...) ist quasi immer feindlich.

## 9. IOCs

```
IP:                193.32.162.34
ASN:               AS47890 (UNMANAGED LTD)
Netzblock:         193.32.162.0/24 (DMZHOST)
Hosting:           Bulletproof, NL-registriert, RO-Hardware
SSH-Client:        SSH-2.0-Go
Credential-Muster: username == crypto-service-name, password == username
Erste Sichtung:    2026-05-12 21:22 UTC
Letzte Sichtung:   2026-05-18
```
