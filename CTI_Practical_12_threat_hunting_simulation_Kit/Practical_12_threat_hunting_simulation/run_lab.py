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
    known={r['value'] for r in feeds() if int(r['confidence']) >= 70}
    print('PRACTICAL 12 — THREAT HUNT')
    print('Hypothesis: Office -> PowerShell followed by feed match within',args.window_minutes,'minute(s).')
    hits=0
    for p in rows:
        if p['type']!='process' or p.get('parent')!='WINWORD.EXE' or p.get('child')!='powershell.exe':continue
        correlated=[n for n in rows if n['type']=='network' and n['host']==p['host']
                    and (n.get('domain') in known or n.get('dst_ip') in known)
                    and 0 <= (dt(n['time'])-dt(p['time'])).total_seconds() <= args.window_minutes*60]
        if correlated:
            hits+=1
            print(p['host'],p['id'],'->',', '.join(n['id'] for n in correlated))
    if not hits:print('No host satisfies the current hypothesis window.')
    print('Validate authorized scripts, feed provenance, and event completeness.')

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--window-minutes', type=int, default=30)
    run(parser.parse_args())
