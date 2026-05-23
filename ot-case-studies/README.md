# OT Case Studies

Hier liegen manuelle Auswertungen aus dem Conpot OT/ICS-Honeypot. Sie sind getrennt von den Cowrie-SSH-Case-Studies, weil OT andere Fragen stellt: Protokoll, Anlagenkontext, Segmentierung, Safety und Verfügbarkeit.

## Index

| Datum | Protokoll | Titel | Bewertung |
|-------|-----------|-------|-----------|
| TODO | TODO | TODO | TODO |

## Aufbau

1. **Zusammenfassung** - was war sichtbar
2. **Beobachtung** - Zahlen aus dem Tagesreport
3. **OT-Kontext** - wofür das Protokoll in Industrieumgebungen genutzt wird
4. **Pattern** - Scan, wiederholtes Verhalten oder gezielter Protokolltest
5. **Hypothese** - was der Scanner wahrscheinlich erkennen wollte
6. **Defensive Lessons** - was echte Betreiber daraus ableiten sollten
7. **IOCs / Hinweise** - technische Indikatoren und Bewertung

Neue Vorlagen:

```bash
python3 scripts/new-ot-case-study.py --date 2026-05-23 --protocol Modbus --slug modbus-internet-scan
```
