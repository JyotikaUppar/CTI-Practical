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
    rows = sorted((e for e in events() if e['host'] == args.host), key=lambda e: e['time'])
    print('PRACTICAL 8 — ATTACK PATTERN, HOST', args.host)
    for e in rows:
        print(e['time'][11:19], e['id'], e['type'], e['summary'])
    beacons = [dt(e['time']) for e in rows if e['type']=='network' and e.get('path')=='/status']
    gaps = [int((b-a).total_seconds()/60) for a,b in zip(beacons,beacons[1:])]
    print('Status request gaps in minutes:', gaps)
    posts = [e for e in rows if e['type']=='network' and e.get('method')=='POST']
    print('Outbound POST bytes:',sum(e.get('bytes_out',0) for e in posts))
    if len(gaps)>=2 and posts:
        print('Pattern is suspicious; beaconing and exfiltration remain hypotheses.')
    else:
        print('Insufficient sequence on this host to support that attack pattern.')

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='WS-25')
    run(parser.parse_args())
