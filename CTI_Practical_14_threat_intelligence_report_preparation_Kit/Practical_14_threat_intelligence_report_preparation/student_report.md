# CTI Report for WS-25

## Executive summary
[Write a two to three sentence assessment with uncertainty.]

## Scope and sources
Synthetic email, endpoint, and network events on 2026-09-23; two mock feeds.

## Evidence timeline
- 2026-09-23T10:00:00 E01: Suspicious email with invoice.docm attachment delivered
- 2026-09-23T10:03:00 E02: WINWORD.EXE launched powershell.exe
- 2026-09-23T10:04:00 E03: Script file observed in Public folder; hash is a fictional exercise value
- 2026-09-23T10:05:00 E04: Run key pointing to Public folder script observed
- 2026-09-23T10:07:00 E05: HTTP GET to simulated destination
- 2026-09-23T10:10:00 E06: Repeated status request 1
- 2026-09-23T10:15:00 E07: Repeated status request 2
- 2026-09-23T10:20:00 E08: Repeated status request 3
- 2026-09-23T10:25:00 E09: Large HTTP POST; content not available

## Candidate indicators and provenance
- IPv4: 203.0.113.45 (feed_alpha.csv, score 75)
- Domain: malware-example.test (feed_alpha.csv, score 85)
- IPv4: 203.0.113.45 (feed_beta.csv, score 80)
- Domain: malware-example.test (feed_beta.csv, score 90)

## ATT&CK mapping
[T1059.001 observed E02; T1547.001 observed E04; distinguish candidates and hypotheses.]

## Confidence, alternatives, and gaps
[Explain why actor identity and exfiltration are unconfirmed.]

## Recommended triage actions
[Preserve logs, review host, investigate POST metadata, validate feed independence.]
