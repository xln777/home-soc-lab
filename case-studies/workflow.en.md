# Case Study Workflow

This workflow turns a daily report into a structured case study without manually digging through raw logs.

## 1. Choose a candidate

Start in the `reports/` folder and look for signals:

- high connection volume from one IP
- unusual usernames or passwords
- successful honeypot logins
- commands after login
- file downloads
- short, fast bursts
- recurring IPs across multiple days

The daily report is only the starting point. It is usually not enough for a full case study.

## 2. Generate Cowrie evidence

Use the evidence script for one IP:

```bash
python3 ~/home-soc-lab/scripts/case-study-evidence.py 107.189.23.209 \
  --date 2026-05-16 \
  -o /tmp/evidence.md
```

The output includes:

- first and last sighting
- event types
- successful and failed logins
- client versions
- HASSH fingerprints
- top usernames
- top passwords
- top username/password combinations
- example sessions with username, password, client, commands and downloads
- automatic analysis hints

Important: Do not copy every password into the case study. Focus on patterns and representative examples.

## 3. Add threat intelligence

Then enrich the IP:

```bash
python3 ~/home-soc-lab/scripts/enrich.py 107.189.23.209
```

Check especially:

- AbuseIPDB confidence and reporter count
- GreyNoise Noise/RIOT
- Shodan open ports
- VirusTotal reputation
- WHOIS, ASN and netblock

## 4. Build a hypothesis

The working hypothesis comes from Cowrie evidence plus OSINT.

Examples:

- credential validation instead of direct exploitation
- industry-specific scanner
- generic root brute force
- malware dropper
- internet-wide port scanner

The hypothesis must fit the logs. If there were no commands or downloads, do not describe it as a real post-exploitation attack.

## 5. Write the case study

Case studies are grouped by date:

```text
case-studies/YYYY-MM-DD/IP-topic.md
```

Example:

```text
case-studies/2026-05-16/107-189-23-209-root-wordlist-burst.md
```

A new draft can be created with:

```bash
python3 scripts/new-case-study.py 107.189.23.209 \
  --date 2026-05-16 \
  --slug root-wordlist-burst \
  --threat "schneller Root-Credential-Scanner" \
  --title-en "Root wordlist burst from a cloud hosting network" \
  --threat-en "fast root credential scanner"
```

## 6. Review before commit

Check before committing:

- no private server details
- no real credentials
- no local machine paths
- no unnecessarily long raw log blocks
- IP, date and numbers are correct
- index links work

## 7. Update the index

The index is generated automatically:

```bash
python3 scripts/update-case-study-index.py
```

The script updates `case-studies/README.md` and `case-studies/README.en.md`.
