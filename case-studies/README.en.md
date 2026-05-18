# Case Studies

[Deutsche Version](README.md)

This folder contains deeper writeups for attacks that stood out in the daily reports. Unlike `reports/`, these are manually written analyses.

## Index

| Date | IP | Title | Threat |
|------|----|-------|--------|
| 2026-05-17 | `193.32.162.34` | [Crypto validator scanner from Romania](2026-05-17/193-32-162-34-crypto-validator-scanner.md) | credential brute force against blockchain validators |
| 2026-05-16 | `107.189.23.209` | [Root wordlist burst from a cloud hosting network](2026-05-16/107-189-23-209-root-wordlist-burst.md) | fast root credential scanner |

## Structure

Each case study roughly follows these nine points. They are a guide, not a mandatory template. If a point does not add value for a specific incident, it can be skipped.

1. **Summary** - short overview
2. **Observation** - raw numbers from the logs
3. **Initial questions** - what stands out
4. **Pattern** - clusters, sorting, repeated behavior
5. **Hypothesis** - what the attacker likely wanted
6. **OSINT verification** - AbuseIPDB, GreyNoise, Shodan, VirusTotal, WHOIS
7. **Conclusion** - whether the hypothesis fits the evidence
8. **Defensive lessons** - what to take away for real systems
9. **IOCs** - indicators of compromise for others

## Workflow

The detailed process is documented in [`workflow.en.md`](workflow.en.md).
