#!/usr/bin/env python3
"""
IP Enrichment Tool
------------------
Reichert eine IP-Adresse mit Daten aus mehreren Threat-Intel-Quellen an.

Quellen:
- AbuseIPDB    (Reputation, braucht ABUSEIPDB_KEY)
- ip-api.com   (GeoIP + ASN, kein Key nötig)
- WHOIS        (Netz-Registrierung, kein Key nötig)
- GreyNoise    (Scanner-Klassifikation, optional GREYNOISE_KEY)
- Shodan       (offene Ports, braucht SHODAN_KEY)
- VirusTotal   (70+ Vendor-Reputation, braucht VT_KEY)

Usage:
  python3 enrich.py 1.2.3.4
  python3 enrich.py 1.2.3.4 --json
  python3 enrich.py 1.2.3.4 > case-studies/iocs.md

API-Keys via Environment-Variablen (z.B. in ~/.secrets):
  export ABUSEIPDB_KEY=...
  export GREYNOISE_KEY=...
  export SHODAN_KEY=...
  export VT_KEY=...
  export NTFY_TOPIC=cowrie-alerts   # optional, fuer Push-Benachrichtigungen
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request
import urllib.error

TIMEOUT = 10


def load_secrets_file():
    """Lade KEY=value Paare aus ~/.secrets falls nicht im Environment."""
    secrets_path = os.path.expanduser('~/.secrets')
    if not os.path.exists(secrets_path):
        return
    try:
        with open(secrets_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('export '):
                    line = line[7:]
                if '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip().strip("'").strip('"')
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass


load_secrets_file()


def http_get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {'_error': 'HTTP ' + str(e.code)}
    except Exception as e:
        return {'_error': str(e)}


def lookup_abuseipdb(ip):
    key = os.environ.get('ABUSEIPDB_KEY')
    if not key:
        return {'_skipped': 'ABUSEIPDB_KEY not set'}
    url = 'https://api.abuseipdb.com/api/v2/check?ipAddress=' + ip + '&maxAgeInDays=90'
    data = http_get(url, {'Accept': 'application/json', 'Key': key})
    if '_error' in data:
        return data
    d = data.get('data', {})
    return {
        'score': d.get('abuseConfidenceScore'),
        'total_reports': d.get('totalReports'),
        'distinct_users': d.get('numDistinctUsers'),
        'country': d.get('countryCode'),
        'isp': d.get('isp'),
        'usage_type': d.get('usageType'),
        'last_reported': d.get('lastReportedAt'),
    }


def lookup_ipapi(ip):
    data = http_get('http://ip-api.com/json/' + ip + '?fields=66846719')
    if '_error' in data or data.get('status') != 'success':
        return {'_error': data.get('message', data.get('_error', 'unknown'))}
    return {
        'country': data.get('country'),
        'region': data.get('regionName'),
        'city': data.get('city'),
        'isp': data.get('isp'),
        'org': data.get('org'),
        'as': data.get('as'),
        'asn': data.get('asname'),
        'reverse': data.get('reverse'),
        'hosting': data.get('hosting'),
        'proxy': data.get('proxy'),
        'mobile': data.get('mobile'),
    }


def lookup_whois(ip):
    try:
        out = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=15)
        result = {}
        keys_of_interest = ['netname', 'orgname', 'country', 'cidr', 'inetnum',
                            'descr', 'origin', 'route', 'orgtechemail']
        for line in out.stdout.splitlines():
            line = line.strip()
            if ':' not in line:
                continue
            k, v = line.split(':', 1)
            k = k.strip().lower()
            v = v.strip()
            if k in keys_of_interest and k not in result and v:
                result[k] = v
        return result if result else {'_error': 'no useful fields'}
    except FileNotFoundError:
        return {'_error': 'whois nicht installiert (apt install whois)'}
    except Exception as e:
        return {'_error': str(e)}


def lookup_greynoise(ip):
    # Community-API geht ohne Key
    data = http_get('https://api.greynoise.io/v3/community/' + ip)
    if '_error' in data:
        return data
    return {
        'classification': data.get('classification'),
        'name': data.get('name'),
        'noise': data.get('noise'),
        'riot': data.get('riot'),
        'last_seen': data.get('last_seen'),
        'link': data.get('link'),
    }


def lookup_shodan(ip):
    key = os.environ.get('SHODAN_KEY')
    if not key:
        return {'_skipped': 'SHODAN_KEY not set'}
    data = http_get('https://api.shodan.io/shodan/host/' + ip + '?key=' + key)
    if '_error' in data:
        return data
    return {
        'ports': data.get('ports', []),
        'hostnames': data.get('hostnames', []),
        'org': data.get('org'),
        'os': data.get('os'),
        'tags': data.get('tags', []),
        'last_update': data.get('last_update'),
    }


def lookup_virustotal(ip):
    key = os.environ.get('VT_KEY')
    if not key:
        return {'_skipped': 'VT_KEY not set'}
    data = http_get('https://www.virustotal.com/api/v3/ip_addresses/' + ip,
                    {'x-apikey': key})
    if '_error' in data:
        return data
    attrs = data.get('data', {}).get('attributes', {})
    stats = attrs.get('last_analysis_stats', {})
    return {
        'malicious': stats.get('malicious'),
        'suspicious': stats.get('suspicious'),
        'harmless': stats.get('harmless'),
        'undetected': stats.get('undetected'),
        'reputation': attrs.get('reputation'),
    }


def render_markdown(ip, results):
    L = []
    L.append('# IP-Anreicherung: ' + ip)
    L.append('')

    abi = results.get('abuseipdb', {})
    if abi and '_skipped' not in abi and '_error' not in abi:
        L.append('## AbuseIPDB')
        L.append('')
        L.append('- **Confidence-Score:** ' + str(abi.get('score')) + '/100')
        L.append('- **Meldungen:** ' + str(abi.get('total_reports')) +
                 ' von ' + str(abi.get('distinct_users')) + ' verschiedenen Nutzern')
        L.append('- **Land:** ' + str(abi.get('country')))
        L.append('- **ISP:** ' + str(abi.get('isp')))
        L.append('- **Typ:** ' + str(abi.get('usage_type')))
        L.append('- **Zuletzt gemeldet:** ' + str(abi.get('last_reported')))
        L.append('')

    geo = results.get('ipapi', {})
    if geo and '_error' not in geo:
        L.append('## Geolokation und Netzwerk')
        L.append('')
        L.append('- **Standort:** ' + str(geo.get('city')) + ', ' +
                 str(geo.get('region')) + ', ' + str(geo.get('country')))
        L.append('- **ISP:** ' + str(geo.get('isp')))
        L.append('- **Organisation:** ' + str(geo.get('org')))
        L.append('- **ASN:** ' + str(geo.get('as')))
        L.append('- **Reverse-DNS:** ' + (geo.get('reverse') or '(keine)'))
        L.append('- **Hosting/Rechenzentrum:** ' + str(geo.get('hosting')))
        L.append('- **Proxy/VPN:** ' + str(geo.get('proxy')))
        L.append('')

    gn = results.get('greynoise', {})
    if gn and '_error' not in gn:
        L.append('## GreyNoise')
        L.append('')
        cls = gn.get('classification') or 'unbekannt / nicht bei GreyNoise erfasst'
        L.append('- **Klassifikation:** ' + str(cls))
        if gn.get('name'):
            L.append('- **Name:** ' + str(gn.get('name')))
        L.append('- **Noise (breit scannend):** ' + str(gn.get('noise')))
        L.append('- **RIOT (gutartiger Dienst):** ' + str(gn.get('riot')))
        L.append('- **Zuletzt gesehen:** ' + str(gn.get('last_seen')))
        if gn.get('link'):
            L.append('- **Mehr:** ' + str(gn.get('link')))
        L.append('')

    sh = results.get('shodan', {})
    if sh and '_skipped' not in sh and sh.get('_error') == 'HTTP 404':
        L.append('## Shodan')
        L.append('')
        L.append('- IP nicht in Shodan erfasst (keine offenen Ports indexiert)')
        L.append('')
    elif sh and '_skipped' not in sh and '_error' not in sh:
        L.append('## Shodan')
        L.append('')
        ports = ', '.join(map(str, sh.get('ports', []))) or '(keine)'
        L.append('- **Offene Ports:** ' + ports)
        hostnames = ', '.join(sh.get('hostnames', []) or ['(keine)'])
        L.append('- **Hostnames:** ' + hostnames)
        L.append('- **OS:** ' + (sh.get('os') or '(unbekannt)'))
        tags = ', '.join(sh.get('tags', []) or ['(keine)'])
        L.append('- **Tags:** ' + tags)
        L.append('- **Letztes Update:** ' + str(sh.get('last_update')))
        L.append('')

    vt = results.get('virustotal', {})
    if vt and '_skipped' not in vt and '_error' not in vt:
        L.append('## VirusTotal')
        L.append('')
        L.append('- **Bösartig:** ' + str(vt.get('malicious')) + ' Vendoren')
        L.append('- **Verdächtig:** ' + str(vt.get('suspicious')) + ' Vendoren')
        L.append('- **Reputation:** ' + str(vt.get('reputation')))
        L.append('')

    wh = results.get('whois', {})
    if wh and '_error' not in wh:
        L.append('## WHOIS')
        L.append('')
        for k, v in wh.items():
            L.append('- **' + k.title() + ':** ' + str(v))
        L.append('')

    # Skipped sources at end
    skipped = [k for k, v in results.items() if isinstance(v, dict) and '_skipped' in v]
    if skipped:
        L.append('---')
        L.append('')
        L.append('_Quellen ohne Key übersprungen: ' + ', '.join(skipped) + '_')

    return '\n'.join(L)


def main():
    p = argparse.ArgumentParser(description='IP threat-intelligence enrichment.')
    p.add_argument('ip', help='IP address to enrich')
    p.add_argument('--json', action='store_true', help='raw JSON output')
    args = p.parse_args()

    print('IP wird angereichert: ' + args.ip, file=sys.stderr)
    results = {
        'abuseipdb': lookup_abuseipdb(args.ip),
        'ipapi': lookup_ipapi(args.ip),
        'greynoise': lookup_greynoise(args.ip),
        'shodan': lookup_shodan(args.ip),
        'virustotal': lookup_virustotal(args.ip),
        'whois': lookup_whois(args.ip),
    }

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(render_markdown(args.ip, results))


if __name__ == '__main__':
    main()
