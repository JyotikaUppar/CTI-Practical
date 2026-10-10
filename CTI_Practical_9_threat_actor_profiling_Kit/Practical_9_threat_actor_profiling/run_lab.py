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
    rows = [e for e in events() if e['host']=='WS-25']
    types = Counter(e['type'] for e in rows)
    print('PRACTICAL 9 — PROVISIONAL ACTIVITY PROFILE')
    print('Tracking label: UNATTRIBUTED-01 (not a named threat group)')
    print('Event types:', ', '.join(f'{k}={v}' for k,v in sorted(types.items())))
    print('Observed: Office -> PowerShell:', any(e.get('parent')=='WINWORD.EXE' and e.get('child')=='powershell.exe' for e in rows))
    print('Observed: Run key write:',any(e['type']=='registry' for e in rows))
    print('Observed: repeated network events:',types['network'])
    print('Hypothesis: operator may seek persistent access; objective unverified.')
    print('Confidence: moderate for linked host activity; low for actor identity.')
    print('Do not attribute nationality, name, or motivation from these TTPs.')

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    
    run(parser.parse_args())
