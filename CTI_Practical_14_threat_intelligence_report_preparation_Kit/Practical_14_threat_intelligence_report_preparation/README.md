# Practical 14 Threat Intelligence Report Preparation

## Aim
Generate a report starter and revise it into an evidence-based final intelligence report.

## Requirements and contents
Python 3.9 or newer; no third-party package, account, SIEM server, internet connection, or live malware. This kit is standalone. Files: run_lab.py, events.jsonl, feed_alpha.csv, feed_beta.csv, report_template.md, sample_output.txt, worksheet.md, instructor_key.md. All data and threat labels are fictional; addresses are reserved documentation examples.

## Run the demonstration
1. Extract this ZIP. Keep the files together in its extracted folder.
2. Open a terminal in that folder. Run `python run_lab.py` (on some systems use `python3 run_lab.py`).
3. Compare the result with `sample_output.txt`. If the Python command is unavailable, verify Python 3.9+ is installed and use its configured command.
4. Open the inputs in a text editor or spreadsheet and trace every claim to the relevant records.
5. Complete `worksheet.md`, then try the extension task below.

## Expected analytical result
The output student_report.md contains the timeline and mock feed values, with sections to complete.

## Extension task
Complete confidence, competing explanations, impact, and recommendations; cite event IDs.

## Submission
Submit the filled worksheet, a terminal transcript or screenshot, the changed parameters and output for the extension, and a short paragraph distinguishing observed evidence from inference.

## Important limitation
This is an offline simulation. An IoC match, ATT&CK label, timing pattern or file hash does not on its own confirm a compromise, malware family, named actor or data theft.
