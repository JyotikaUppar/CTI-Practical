# Student Worksheet — Practical 6 Threat Feed Analysis

Name: Jyotika Uppar  Roll number: 28  Date: 10/10/26

## Input observations
Which records or feed rows did you inspect? List IDs or values and their sources.

| Record or value | What is directly observed? | Source | Confidence or limitation |
|---|---|---|---|
| 203.0.113.45 | IPv4 indicator appears in both mock feeds and is considered a candidate malicious destination. | feed_alpha.csv and feed_beta.csv | Alpha: 75, Beta: 80; repeated across feeds increases suspicion but does not prove compromise. |
| malware-example.test | Domain indicator appears in both feeds as a possible malicious domain. | feed_alpha.csv and feed_beta.csv | Alpha: 85, Beta: 90; high-confidence signal in both feeds. |
| 192.168.1.25 | Internal IPv4 address marked as analyst review context. | feed_alpha.csv | 20; private address and internal-only context; not a remote block target. |
| security-alert@example.test | Email address appears only once with a low score. | feed_beta.csv | 55; single-source indicator, monitor/validate only. |

## Interpretation
The evidence suggests that 203.0.113.45 and malware-example.test are the strongest indicators because they are present in both feeds and the confidence scores are relatively high. The private IPv4 address 192.168.1.25 is not a suspicious external destination because it is in the 192.168.0.0/16 range and is explicitly labeled as internal context. An alternative explanation is that both feeds may have derived the same indicator from a common source, or the same false-positive feed, so matching values in two feeds does not automatically mean the sources are independent. This is why the practical warns that a feed match is not proof of a real compromise.

## Extension result
Command used: `python run_lab.py --min-confidence 90`

Difference: At the default threshold of 70, 203.0.113.45 was classified as INVESTIGATE. With the threshold raised to 90, it dropped to MONITOR / VALIDATE because the best score was 80 from feed_beta. The domain malware-example.test stayed at INVESTIGATE because its score was 90 from feed_beta. This shows that score alone is not enough; context, source provenance, and the nature of the indicator matter.

## Conclusion and next evidence
My conclusion is that 203.0.113.45 and malware-example.test are suspicious indicators that deserve investigation, while 192.168.1.25 should not be treated as a malicious remote target. The confidence is moderate-to-high for the repeated indicators, but not proof of compromise. Two checks that would strengthen or disprove the conclusion are: (1) review the actual logs or firewall/ DNS records for those indicators and (2) check whether the same indicators appear in other internal sensors or if the feeds share a common origin. This separates observed evidence from analyst inference.
