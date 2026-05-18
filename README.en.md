# home-soc-lab

A small self-hosted SOC lab built around a Cowrie SSH honeypot. The project combines real-world honeypot logs, Python-based reporting, threat-intelligence enrichment and short incident writeups.

The goal is not to present an enterprise SOC or production-grade security platform. It is a practical learning and portfolio project for defensive security: collecting real attack data, understanding logs, enriching indicators and documenting findings clearly.

## Short version

I run an SSH honeypot, collect the logs and analyze them with Python scripts. The output is daily Markdown reports and selected case studies. The project helps me practice typical blue-team work: log analysis, IOC enrichment, threat-intelligence checks, reporting and defensive conclusions.

## What is included

| Component | Purpose |
|-----------|---------|
| Cowrie SSH honeypot | collects real SSH scan and login attempts |
| Grafana, Loki, Promtail | log aggregation and dashboards |
| CrowdSec | automated decisions against suspicious IPs |
| AbuseIPDB reporting | daily reporting of new attacker IPs |
| Restic + Backblaze B2 | server backups |
| Python scripts | reports, enrichment and repeatable analysis |

## Repository structure

| Path | Content |
|------|---------|
| `case-studies/` | manual deep dives into selected attacks, grouped by date |
| `reports/` | daily reports generated from Cowrie logs |
| `scripts/` | Python tools for reporting, AbuseIPDB and enrichment |
| `CHEATSHEET.md` | operational commands for daily use |
| `SETUP.md` | generic setup guide without private server details |

## Data flow

```text
Internet scanners
  -> Cowrie SSH honeypot
  -> JSON logs
  -> Python reports
  -> threat-intelligence enrichment
  -> reports and case studies
```

## Reports

`scripts/cowrie-daily-report.py` generates Markdown reports with:

- top attacker IPs
- common username/password combinations
- successful honeypot logins
- commands entered after login
- attempted malware downloads

Own test IPs can be filtered through `scripts/own-ips.txt`. The file is intentionally ignored by Git.

For individual IPs, `scripts/case-study-evidence.py` generates a structured evidence overview with time window, event types, client fingerprints, user/password combinations and example sessions.

## Threat intelligence

`scripts/enrich.py <ip>` performs compact IP enrichment:

| Source | Result |
|--------|--------|
| AbuseIPDB | reputation, reports, confidence score |
| ip-api.com | GeoIP, ASN, hosting/proxy hints |
| WHOIS | network registration |
| GreyNoise | scanner classification |
| Shodan | open ports |
| VirusTotal | aggregated reputation |

## Case studies

The case studies show the learning and analysis process: what was visible in the logs, which pattern stood out, what hypothesis came from it and how it was checked with external sources.

The index is available here:

- English: [`case-studies/README.en.md`](case-studies/README.en.md)
- German: [`case-studies/README.md`](case-studies/README.md)

New analyses are maintained there automatically, so this main page stays stable.

## Safety note

The documentation is written for a public portfolio. Examples use placeholders and generic paths so the project remains understandable without exposing private operational details.
