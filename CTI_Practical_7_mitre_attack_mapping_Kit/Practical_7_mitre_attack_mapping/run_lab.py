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
    print('PRACTICAL 7 — EVIDENCE-BASED ATT&CK MAPPING')
    for e in events():
        matches = []
        if e['type'] == 'email' and e.get('attachment'):
            matches.append(('T1566.001', 'candidate', 'Attachment delivery observed; maliciousness unknown'))
        if e['type'] == 'process' and e.get('child','').lower() == 'powershell.exe':
            matches.append(('T1059.001', 'observed', 'PowerShell process in log'))
        if e['type'] == 'registry' and 'Run' in e.get('key',''):
            matches.append(('T1547.001', 'observed', 'Run key write in log'))
        if e['type'] == 'network' and e.get('domain') == 'malware-example.test':
            matches.append(('T1071.001', 'candidate', 'HTTP contact; C2 intent unverified'))
            if e.get('method') == 'POST' and e.get('bytes_out',0) > 1000000:
                matches.append(('T1041', 'hypothesis', 'Large POST; contents unavailable'))
        for tid,status,why in matches:
            print(f"{e['id']} {tid:10} {status:10} {why}")
    print('E10 remains unmapped: generic update traffic is not a C2 technique match.')

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    
    run(parser.parse_args())
