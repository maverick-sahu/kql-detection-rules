# Suspicious Access to Sensitive Processes

## Overview

This detection rule identifies suspicious access to high-value Windows processes using privileged process access rights or remote thread creation. Attackers frequently target processes such as **LSASS** to dump credentials or inject malicious code into trusted processes to evade detection.

The rule monitors process access events and identifies processes requesting access rights commonly associated with credential dumping, process injection, and other post-exploitation techniques.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Credential Access & Defense Evasion |
| Technique | T1003.001 – OS Credential Dumping: LSASS Memory & T1055 – Process Injection |

---

## Data Sources

- DeviceEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors `ProcessAccessed` and `CreateRemoteThread` events.
2. Extracts the `GrantedAccess` value from the event metadata.
3. Detects access to sensitive Windows processes including:
   - `lsass.exe`
   - `winlogon.exe`
   - `explorer.exe`
   - `mstsc.exe`
   - `services.exe`
   - `lsaiso.exe`
   - `csrss.exe`
4. Identifies high-privilege access masks commonly associated with:
   - Credential dumping
   - Process injection
   - Memory manipulation
5. Excludes known Microsoft security components and trusted system processes.

---

## Severity

**High**

---

## Frequency

Every **30 minutes**

---

## Lookback

**1 hour**

---

## Investigation Guidance

When this rule generates an alert:

1. Verify whether the initiating process is Microsoft-signed.
2. Review the complete process tree.
3. Determine whether the process is expected to access the target process.
4. Check for credential dumping tools such as Mimikatz or ProcDump.
5. Investigate PowerShell, CMD, or LOLBin activity preceding the alert.
6. Review file creation, registry changes, and network connections.
7. Isolate the endpoint if malicious activity is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Microsoft Defender Antivirus
- Microsoft Defender for Endpoint
- EDR products
- Memory acquisition tools
- Digital forensic software
- Debugging utilities

---

## Tuning Recommendations

- Exclude approved security products.
- Exclude known forensic tools.
- Correlate with:
  - LSASS memory dump detections
  - Process injection detections
  - Privilege escalation alerts
  - Unsigned process execution
- Prioritize unsigned or uncommon processes requesting privileged access.

---

## Limitations

This rule detects suspicious process access behavior but does not confirm successful credential dumping or process injection. Alerts should be correlated with additional endpoint telemetry for higher confidence.

---

## References

- MITRE ATT&CK T1003.001 – OS Credential Dumping: LSASS Memory
- MITRE ATT&CK T1055 – Process Injection
- Microsoft Defender XDR Advanced Hunting Documentation

---

## Author

**Raunak Sahu**
