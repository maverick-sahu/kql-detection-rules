# LSASS Parent Process Validation

## Overview

This detection rule identifies instances where **lsass.exe** is observed with an unexpected parent process. Under normal Windows operation, **wininit.exe** is responsible for launching **lsass.exe** during system startup. If LSASS is initiated by any other process, it may indicate process tampering, masquerading, process injection, or other malicious activity.

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Defense Evasion & Credential Access |
| Technique | T1036 – Masquerading |

## Data Sources

- DeviceProcessEvents

## Detection Logic

The rule performs the following actions:

1. Identifies executions of **lsass.exe**.
2. Confirms the executable is running from the expected location:
   - `C:\Windows\System32\lsass.exe`
3. Verifies that the initiating (parent) process is **not** `wininit.exe`.
4. Returns all matching events for investigation.

## Severity

**High**

## Frequency

Every 30 minutes

## Lookback

1 hour

## Investigation Guidance

When this rule generates an alert:

1. Verify whether the parent process is legitimate.
2. Validate the digital signature of **lsass.exe**.
3. Review the complete process tree.
4. Check for recent process injection or credential dumping activity.
5. Investigate any suspicious child processes or network connections.
6. Review authentication events from the affected endpoint.
7. Isolate the device if malicious activity is confirmed.

## False Positives

Potential legitimate triggers include:

- Endpoint Detection and Response (EDR) products
- Digital forensic or memory acquisition tools
- Windows recovery or repair operations
- Unsupported or customized Windows environments

## Tuning Recommendations

- Exclude known security products if consistently benign.
- Verify Microsoft digital signatures before escalating.
- Combine with file creation and network telemetry to improve confidence.

## References

- MITRE ATT&CK T1036 – Masquerading
- Microsoft Defender XDR Advanced Hunting Documentation

## Author

**Raunak Sahu**
