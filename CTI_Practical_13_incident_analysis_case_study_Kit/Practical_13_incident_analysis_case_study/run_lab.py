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
    rows=sorted((e for e in events() if e['host']==args.host),key=lambda e:e['time'])
    print('PRACTICAL 13 — INCIDENT CASE:',args.host)
    if not rows:
        print('No events for host');return
    print('Time span:',rows[0]['time'],'to',rows[-1]['time'])
    for e in rows:
        print(e['id'],e['time'],e['summary'])
    process_hit=any(e['type']=='process' and e.get('parent')=='WINWORD.EXE' for e in rows)
    run_hit=any(e['type']=='registry' for e in rows)
    post_hit=any(e['type']=='network' and e.get('method')=='POST' for e in rows)
    print('Evidence flags: Office child process =',process_hit,
          '| Run key =',run_hit,'| POST =',post_hit)
    if process_hit and run_hit:
        print('Assessment: investigate linked activity; theft and actor attribution unconfirmed.')
        print('Next: preserve evidence, inspect endpoint and proxy data, assess isolation.')
    else:
        print('Assessment: insufficient host evidence for this incident chain.')
        print('Next: retain as comparison context and check for additional telemetry if needed.')

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='WS-25')
    run(parser.parse_args())
