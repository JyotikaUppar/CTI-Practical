"""Standalone offline CTI classroom practical. Python 3.9+; standard library only."""
import argparse
import csv
import ipaddress
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def events():
    with (ROOT / 'events.jsonl').open(encoding='utf-8') as f:
        return [json.loads(line) for line in f if line.strip()]

def feeds():
    rows = []
    for name in ('feed_alpha.csv', 'feed_beta.csv'):
        with (ROOT / name).open(newline='', encoding='utf-8') as f:
            rows.extend(dict(row, feed=name) for row in csv.DictReader(f))
    return rows

def dt(s):
    return datetime.fromisoformat(s)


def run(args):
    rows=events()
    print('PRACTICAL 11 — SIEM-LIKE LOG QUERY:',args.query)
    if args.query in ('process','all'):
        hits=[e for e in rows if e['type']=='process' and e.get('parent')=='WINWORD.EXE' and e.get('child')=='powershell.exe']
        print('Office -> PowerShell:',[(e['id'],e['host']) for e in hits])
    if args.query in ('network','all'):
        known={r['value'] for r in feeds() if int(r['confidence']) >= args.min_confidence}
        hits=[e for e in rows if e['type']=='network' and (e.get('domain') in known or e.get('dst_ip') in known)]
        print('Feed-enriched network matches:',[(e['id'],e['host'],e.get('domain')) for e in hits])
    print('These are analytic matches, not confirmed incidents.')

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--query', choices=('process','network','all'), default='all')
    parser.add_argument('--min-confidence', type=int, default=70)
    run(parser.parse_args())
