# Student Worksheet — Practical 7 MITRE ATT&CK Mapping

Name: Jyotika Uppar  Roll number: 28  Date: 10/10/26

## Input observations
Which records or feed rows did you inspect? List IDs or values and their sources.

| Record or value | What is directly observed? | Source | Confidence or limitation |
|---|---|---|---|
| E01 | Email with `invoice.docm` attachment delivered to user; suspicious attachment observed | `events.jsonl` entry for E01 | Candidate only: attachment is suspicious, but maliciousness is not directly proven |
| E02 | `WINWORD.EXE` launched `powershell.exe` | `events.jsonl` entry for E02 | Observed: direct process relationship in log |
| E04 | Registry Run key `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater` points to `C:\Users\Public\update.ps1` | `events.jsonl` entry for E04 | Observed: direct persistence artifact in log |
| E05-E09 | Network traffic to `malware-example.test` with repeated GET requests and a large POST upload | `events.jsonl` entries for E05-E09 | Candidate for C2; E09 is a hypothesis because content is unavailable |
| E10 | Generic update traffic from a different host (`WS-50`) to `updates.example.test` | `events.jsonl` entry for E10 | Intentionally excluded from C2 mapping; not associated with the malicious sequence |

## Interpretation
What does the evidence suggest? What alternative explanation could fit?

The evidence suggests a phishing-delivered execution chain on host `WS-25`: an email with a suspicious attachment (E01) led to `powershell.exe` execution (E02), followed by persistence via a Run key (E04). This strongly matches ATT&CK techniques `T1566.001` (phishing attachment), `T1059.001` (PowerShell), and `T1547.001` (Run key persistence).

The repeated HTTP requests to `malware-example.test` (E05-E09) are consistent with possible command-and-control or beaconing behavior, but the lab notes that a domain or network hit alone is not enough to confirm compromise. E09 is especially tentative: the large `POST` could be a data upload or another legitimate file transfer, but because the content is unavailable, it is treated as a hypothesis rather than a direct observation. An alternative explanation could be a legitimate update or backup sync process, which is exactly why E10 is intentionally excluded from the C2 mapping.

## Extension result
Record the command/parameter change, output difference, and reason.

Command run: `python run_lab.py`

Observed output:
- `E01 T1566.001 candidate Attachment delivery observed; maliciousness unknown`
- `E02 T1059.001 observed PowerShell process in log`
- `E04 T1547.001 observed Run key write in log`
- `E09 T1041 hypothesis Large POST; contents unavailable`
- `E10 remains unmapped: generic update traffic is not a C2 technique match.`

Reason: E10 is excluded because it comes from a different host and a different domain (`updates.example.test`), and it is described as generic update traffic rather than malware C2 activity. The alternative explanation for E09 is that it may be a legitimate file upload or software backup sync, not necessarily exfiltration.

## Conclusion and next evidence
Give a concise conclusion, its confidence, and two checks that would strengthen or disprove it.

Conclusion: Host `WS-25` likely suffered a phishing campaign leading to PowerShell execution and persistence, with possible C2 or exfiltration behavior. Confidence is moderate to high for the observed execution/persistence chain (`T1059.001` and `T1547.001`), moderate for `T1566.001`, and low for `T1041` because it remains an inference rather than a confirmed exfiltration event.

Two checks that would strengthen or disprove this conclusion:
1. Inspect the contents and hash of `C:\Users\Public\update.ps1` and validate whether it matches malicious script behavior or is a benign update file.
2. Correlate the network telemetry for `malware-example.test` with endpoint logs and DNS records to confirm whether the repeated requests are malicious beaconing or legitimate traffic.
