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
    rows=sorted((e for e in events() if e['host']=='WS-25'),key=lambda e:e['time'])
    template=(ROOT/'report_template.md').read_text(encoding='utf-8')
    timeline='\n'.join(f"- {e['time']} {e['id']}: {e['summary']}" for e in rows)
    feed_rows=feeds()
    indicator_lines='\n'.join(f"- {r['type']}: {r['value']} ({r['feed']}, score {r['confidence']})"
                               for r in feed_rows if int(r['confidence'])>=70)
    report=template.replace('{{TIMELINE}}',timeline).replace('{{INDICATORS}}',indicator_lines)
    target=(ROOT/args.output).resolve()
    if target.parent != ROOT:raise ValueError('Output must be a filename in this kit folder')
    target.write_text(report,encoding='utf-8')
    print('PRACTICAL 14 — REPORT STARTER WRITTEN:',target.name)
    print('Review the draft: add your evidence-based conclusion and check all candidate claims.')

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='student_report.md')
    run(parser.parse_args())
