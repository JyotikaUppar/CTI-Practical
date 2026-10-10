     # Student Worksheet — Practical 8 Attack Pattern Analysis

Name: __________  Roll number: __________  Date: __________

## Input observations
Which records or feed rows did you inspect? List IDs or values and their sources.

| Record or value | What is directly observed? | Source | Confidence or limitation |
|---|---|---|---|
| E01 | Suspicious email with invoice.docm attachment delivered from security-alert@example.test | events.jsonl | Direct observation; it shows a phishing lure but not a confirmed malware execution |
| E02, E03, E04 | WINWORD.EXE launched powershell.exe; script was stored in C:\Users\Public\update.ps1; a Run key referenced that script | events.jsonl | Direct observation; suggests persistence but does not prove malicious intent |
| E05-E09 | GET to malware-example.test /update.exe followed by three /status GETs at 10:10, 10:15, and 10:20, then a large POST of 4,200,000 bytes at 10:25 | events.jsonl and run_lab.py output | Direct observation; suspicious pattern is visible, but payload content and destination context are missing |
| Status gaps = [5, 5] minutes | Derived from repeated /status requests: 10:10→10:15 and 10:15→10:20 | run_lab.py output | Direct calculation from log timestamps; it is a pattern indicator, not proof of compromise |

## Interpretation
What does the evidence suggest? What alternative explanation could fit?

The WS-25 chain is suspicious: a phishing email leads to a PowerShell script launched from Word, a persistence entry writes the script to the Public folder, then outbound network traffic shows repeated /status checks and a large POST. This sequence matches a common malware pattern of initial access, execution, persistence, beaconing, and exfiltration in a simplified exercise.

However, the evidence is not enough to prove a real attack. A benign admin script, a lab/test script, or a false positive could produce a similar sequence. The dataset does not include endpoint telemetry, malware hash validation, or actual payload content, and the README explicitly warns that an IoC, ATT&CK label, or timing pattern does not by itself confirm compromise.

## Extension result
Record the command/parameter change, output difference, and reason.

Command changed: `python run_lab.py --host WS-50`

Output difference:
- Status request gaps in minutes: []
- Outbound POST bytes: 0
- Insufficient sequence on this host to support that attack pattern.

Reason: WS-50 has only one network event (E10, a single GET to /patch) and no repeated /status requests or POST traffic. Unlike WS-25, it does not show the beaconing/exfiltration pattern. This demonstrates that the suspicious pattern is host-specific and not a universal behavior in the dataset.

## Conclusion and next evidence
Give a concise conclusion, its confidence, and two checks that would strengthen or disprove it.

Conclusion: WS-25 shows a suspicious infection-style sequence, but the evidence is still a hypothesis rather than proven compromise. Confidence: moderate that the pattern is suspicious; low that it is confirmed malicious activity.

Two checks that would strengthen or disprove it:
1. Review endpoint telemetry on WS-25: process ancestry, PowerShell command line, persistence entries, and whether the script actually executed after startup.
2. Examine network and security logs for the same destination and time window: whether repeated /status traffic was seen elsewhere, whether the destination is malicious or internal, and whether any file transfer activity matches the 4,200,000-byte POST.
   
   