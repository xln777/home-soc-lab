# Case Study: Root-Wortlisten-Burst aus einem Cloud-Hosting-Netz

**Datum:** 2026-05-16
**Quelle:** Cowrie SSH-Honeypot
**Analyst:** xln777

## 1. Zusammenfassung

Am 16. Mai 2026 fiel eine IP auf, die nur für wenige Minuten aktiv war, aber in sehr kurzer Zeit 46 Verbindungen erzeugte. 45 davon waren SSH-Verbindungen mit dem Client-Banner `SSH-2.0-Go`. Alle Login-Versuche nutzten den Benutzer `root`, jedes Passwort wurde nur einmal ausprobiert. Nach erfolgreichen Honeypot-Logins wurden keine Befehle ausgeführt und keine Dateien heruntergeladen.

Das sieht nicht nach manuellem Zugriff aus, sondern nach einem schnellen Credential-Validation-Lauf: Das Tool testet eine kleine Wortliste gegen `root`, speichert mögliche Treffer und zieht direkt weiter.

## 2. Beobachtung

Im Tagesreport vom 16. Mai steht die IP auf Platz 2:

| IP | Verbindungen |
|----|-------------:|
| 193.32.162.34 | 17.101 |
| 107.189.23.209 | 46 |
| 82.223.34.63 | 8 |

Der große Crypto-Scanner dominierte den Tag komplett. Gerade deshalb ist diese zweite IP interessant: Sie ging nicht über Masse, sondern über einen kurzen, schnellen Burst.

Verdichtete Werte aus dem Cowrie-Log:

| Merkmal | Wert |
|---------|------|
| Zeitraum | 2026-05-16 16:49:29 bis 16:54:39 UTC |
| Verbindungen | 46 |
| Login-Erfolge im Honeypot | 45 |
| Fehlgeschlagene Logins | 0 |
| Befehle nach Login | 0 |
| Datei-Downloads | 0 |
| SSH-Client | `SSH-2.0-Go` |
| HASSH | `01ca35584ad5a1b66cf6a9846b5b2821` |

Der eigentliche Login-Burst lief innerhalb von ungefähr 9 Sekunden. Das entspricht rechnerisch rund 300 Verbindungen pro Minute. Eine letzte Session blieb danach 300 Sekunden offen und wurde dann geschlossen.

## 3. Erste Fragen

Mehrere Dinge sind auffällig:

- Der erste Kontakt war kein normaler SSH-Handshake, sondern `GET / HTTP/1.1` auf dem SSH-Port.
- Direkt danach kamen 45 SSH-Verbindungen mit identischem Client-Banner.
- Der Username war immer `root`.
- Die Passwörter wirkten wie eine kleine, kuratierte Wortliste.
- Nach dem Login passierte nichts.

Das passt zu einem Scanner, der zuerst grob prüft, was auf dem Port antwortet, und danach automatisiert SSH-Credentials testet.

## 4. Pattern

Die beobachteten Passwörter waren breit gemischt:

```text
cooler, steelers, compaq, claudia, 123456d, rabbit, bailey1,
crazy1, august, isabella, orange1, october, green1, black1,
samson, aaaa, angelo, boomer, junior1, shorty1, tyler1,
kimberly, guitar1, cowboys, passion, soleil, christ, 111
```

Das ist keine technische Service-Liste wie bei der Crypto-Validator-Case-Study. Es wirkt eher wie eine klassische schwache Passwortliste:

- Vornamen (`claudia`, `isabella`, `kimberly`, `andrey`)
- einfache Wörter (`rabbit`, `orange1`, `green1`, `black1`)
- Sport-/Popkultur-Begriffe (`steelers`, `cowboys`, `metallica1`)
- einfache Varianten mit Zahl am Ende (`bailey1`, `shorty1`, `forever1`)

Jedes Passwort wurde nur einmal getestet. Das spricht gegen einen langen Bruteforce gegen ein einzelnes Ziel. Wahrscheinlicher ist ein Internet-weiter Scan: wenige Versuche pro Host, dafür viele Hosts.

## 5. Hypothese

Meine Hypothese: Die IP war Teil eines schnellen Root-Credential-Scanners.

Der Ablauf dürfte ungefähr so aussehen:

1. Port ansprechen und prüfen, ob etwas reagiert.
2. Wenn SSH erkannt wird, eine kleine Passwortliste gegen `root` testen.
3. Treffer speichern.
4. Keine Befehle ausführen, weil die Auswertung später durch ein anderes Tool oder einen Operator passiert.

Der Honeypot akzeptiert bestimmte Logins bewusst, dadurch sieht der Scanner scheinbar erfolgreiche Treffer. Weil danach keine Befehle kamen, ging es in diesem Schritt vermutlich nur um Validierung, nicht um direkte Ausnutzung.

## 6. OSINT-Verifikation

### AbuseIPDB

- Confidence: 89/100
- Meldungen: 19 von 15 verschiedenen Nutzern
- Land: NL
- ISP: RouterHosting LLC
- Typ: Data Center / Web Hosting / Transit
- Zuletzt gemeldet: 2026-05-18

Die IP ist also nicht nur in meinem Honeypot aufgefallen. Mehrere unabhängige Reporter haben sie ebenfalls gesehen.

### GreyNoise

- Klassifikation: unknown
- Noise: true
- Riot: false
- Zuletzt gesehen: 2026-05-18

`Noise: true` passt zum Verhalten: breit scannend, nicht gezielt gegen ein einzelnes System.

### VirusTotal

- 2 Vendoren bösartig
- 2 Vendoren verdächtig
- Reputation: 0

Das ist schwächer als beim Crypto-Validator-Scanner, aber ausreichend auffällig im Zusammenspiel mit den Honeypot-Daten.

### Shodan

Die IP war nicht in Shodan erfasst. Es waren also keine offenen Dienste indexiert. Das passt zu einem Host, der vor allem ausgehend scannt.

### WHOIS

- Netzblock: 107.189.0.0/19
- Netname: PONYNET-11
- Organisation: FranTech Solutions
- ASN: AS14956 RouterHosting LLC
- Reverse-DNS: `209.23.189.107.static.cloudzy.com`

Der Host liegt in einem Cloud-/Hosting-Umfeld. Für Scanner ist das typisch: günstig, schnell ersetzbar, keine direkte Bindung an ein privates Endgerät.

## 7. Schlussfolgerung

Die IP war kein dominanter Langläufer, sondern ein kurzer, automatisierter Burst. Das macht sie trotzdem interessant, weil sie ein anderes Angreiferprofil zeigt als der große Crypto-Scanner:

- kein branchenspezifisches Credential-Set
- nur `root`
- kurze Wortliste
- hoher Durchsatz
- keine direkte Post-Login-Aktion

Für mich sieht das wie ein Credential-Sammler aus, der viele Hosts oberflächlich prüft. Ein echter kompromittierter Server wäre wahrscheinlich erst später weiterverarbeitet worden.

## 8. Defensive Lessons

Mitnehmen für eigene Systeme:

- Passwort-Login für `root` sollte deaktiviert sein. Diese Scanner testen genau darauf.
- Ein einzelner erfolgreicher Login ohne Befehle ist trotzdem ein Alarm. Es kann nur die Validierungsphase sein.
- `GET / HTTP/1.1` auf einem SSH-Port ist ein gutes Signal für unsaubere Port-Erkennung oder generisches Scanning.
- Kurze Bursts sind leicht zu übersehen, wenn man nur Tagesvolumen betrachtet.
- Für Detection lohnt sich eine Regel auf viele kurze SSH-Sessions mit gleichem HASSH und wechselnden Passwörtern.

## 9. IOCs

```text
IP:                  107.189.23.209
ASN:                 AS14956 (RouterHosting LLC)
Netzblock:           107.189.0.0/19
Netname:             PONYNET-11
Organisation:        FranTech Solutions
Reverse-DNS:         209.23.189.107.static.cloudzy.com
SSH-Client:          SSH-2.0-Go
HASSH:               01ca35584ad5a1b66cf6a9846b5b2821
Username:            root
Verhalten:           kurzer Credential-Validation-Burst
Erste Sichtung:      2026-05-16 16:49:29 UTC
Letzte Sichtung:     2026-05-16 16:54:39 UTC
```
