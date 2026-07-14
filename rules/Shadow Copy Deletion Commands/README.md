# Shadow Copy Deletion Commands

## Overview

This detection rule identifies execution of commands used to delete Windows Volume Shadow Copies and backup catalogs. Threat actors, particularly ransomware operators, commonly remove recovery mechanisms before encrypting files to prevent restoration through backups or system restore points.

The rule detects the use of built-in Windows utilities such as `vssadmin`, `wmic`, and `wbadmin` when executed through command interpreters.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Impact |
| Technique | T1490 – Inhibit System Recovery |

---

## Data Sources

- DeviceProcessEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors execution of:
   - `cmd.exe`
   - `powershell.exe`
   - `pwsh.exe`
2. Detects command-line arguments containing:
   - `vssadmin delete shadows`
   - `wmic shadowcopy delete`
   - `wbadmin delete catalog`
3. Returns execution details for investigation.

---

## Severity

**Critical**

---

## Frequency

Every **30 minutes**

---

## Lookback

**24 hours**

---

## Investigation Guidance

When this rule generates an alert:

1. Determine whether the backup deletion was authorized.
2. Review the full process tree leading to the command execution.
3. Identify the user account and privilege level.
4. Investigate recent file encryption or mass file modification activity.
5. Review service termination events targeting backup or security software.
6. Check for outbound network activity or command-and-control communication.
7. Verify whether additional recovery mechanisms were disabled.
8. Isolate the endpoint immediately if ransomware activity is suspected.

---

## False Positives

Potential legitimate triggers include:

- Backup administration
- Disaster recovery testing
- System maintenance
- Enterprise backup software
- Authorized administrative scripts

---

## Tuning Recommendations

- Exclude approved backup administrators and maintenance accounts.
- Correlate with:
  - Service stop events
  - File encryption activity
  - Mass file renames
  - Ransom note creation
  - Security tool tampering
- Prioritize:
  - Executions outside maintenance windows
  - Interactive user sessions
  - Unsigned parent processes
  - Additional ransomware indicators

---

## Limitations

This rule detects commands associated with deleting recovery mechanisms but does not confirm successful deletion. It should be correlated with additional endpoint telemetry to determine whether recovery features were disabled and whether ransomware activity followed.

---

## References

- MITRE ATT&CK T1490 – Inhibit System Recovery
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft Volume Shadow Copy Service (VSS) Documentation

---

## Author

**Raunak Sahu**
