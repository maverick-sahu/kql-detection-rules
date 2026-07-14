# Hidden Scheduled Task via PowerShell

## Overview

This detection rule identifies PowerShell executions that create hidden scheduled tasks while using common defense evasion techniques such as execution policy bypass, encoded commands, hidden windows, or non-interactive execution.

Scheduled tasks are a widely used persistence mechanism. Attackers frequently combine PowerShell with hidden scheduled tasks to maintain long-term access while minimizing user awareness.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Persistence & Execution |
| Technique | T1053.005 – Scheduled Task |

---

## Data Sources

- DeviceProcessEvents

---

## Detection Logic

The rule identifies PowerShell processes that:

1. Execute using suspicious arguments, including:
   - `-ExecutionPolicy Bypass`
   - `-EncodedCommand`
   - `-enc`
   - `-nop`
   - `-w hidden`
   - `-windowstyle hidden`
2. Create scheduled tasks using:
   - `schtasks /create`
   - `Register-ScheduledTask`
   - `New-ScheduledTask`
3. Configure the task as hidden using:
   - `Hidden`
   - `<Hidden>true</Hidden>`
4. Excludes:
   - SYSTEM account activity
   - Common Windows system paths
   - Git Bash installation path

---

## Severity

**High**

---

## Frequency

Every **30 minutes**

---

## Lookback

**24 hours**

---

## Investigation Guidance

When this rule generates an alert:

1. Review the PowerShell command line for obfuscation or encoded content.
2. Identify the scheduled task name and its configured action.
3. Determine whether the task is hidden or configured to run at logon or startup.
4. Review the parent process that launched PowerShell.
5. Decode any Base64-encoded commands.
6. Investigate subsequent persistence, network activity, and child processes.
7. Remove unauthorized scheduled tasks and isolate the endpoint if malicious activity is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Enterprise automation platforms
- Software deployment tools
- Configuration management solutions
- Administrative PowerShell scripts

---

## Tuning Recommendations

- Exclude approved automation scripts and deployment accounts.
- Correlate with:
  - Scheduled task creation events
  - PowerShell Script Block Logging
  - Registry Run key modifications
  - Service installation
  - Network connections
- Prioritize:
  - Encoded PowerShell
  - Unsigned scripts
  - User-writable execution paths
  - Hidden scheduled tasks created outside maintenance windows

---

## Limitations

This rule focuses on scheduled tasks created through PowerShell. Tasks created using other utilities or APIs without PowerShell involvement require separate detections.

---

## References

- MITRE ATT&CK T1053.005 – Scheduled Task
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft PowerShell Security Documentation

---

## Author

**Raunak Sahu**
