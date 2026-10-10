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
    grouped = defaultdict(list)
    for row in feeds():
        grouped[(row['type'], row['value'])].append(row)
    print('PRACTICAL 6 — THREAT FEED COMPARISON')
    print('Minimum score for review:', args.min_confidence)
    for (kind, value), rows in sorted(grouped.items()):
        best = max(int(r['confidence']) for r in rows)
        if kind == 'IPv4' and ipaddress.ip_address(value).is_private and value.startswith('192.168.'):
            decision = 'INTERNAL CONTEXT — verify, do not block as a remote IP'
        elif best >= args.min_confidence:
            decision = 'INVESTIGATE'
        else:
            decision = 'MONITOR / VALIDATE'
        scores = ', '.join(f"{r['feed']}:{r['confidence']}" for r in rows)
        print(f'{kind:6} {value:36} sources={len(rows)} scores={scores} -> {decision}')
    print('A match in two mock feeds does not establish source independence.')

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--min-confidence', type=int, default=70)
    run(parser.parse_args())
