# Suspicious AT Job Followed by LOLBin Execution

## Overview

This detection rule identifies legacy scheduled job creation using **AT.exe** or **Win32_ScheduledJob**, followed by execution of commonly abused Living-off-the-Land Binaries (LOLBins) within six hours. Threat actors often use scheduled jobs to delay execution, establish persistence, or evade user observation, while leveraging trusted Windows binaries to execute malicious payloads.

By correlating job creation with subsequent LOLBin execution, this rule provides higher fidelity than monitoring either activity independently.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Persistence & Execution |
| Technique | T1053.002 – Scheduled Task/Job: At & T1218 – System Binary Proxy Execution |

---

## Data Sources

- DeviceProcessEvents

---

## Detection Logic

The rule performs the following actions:

1. Detects scheduled job creation using:
   - `at.exe`
   - `Win32_ScheduledJob`
2. Monitors processes started by:
   - `svchost.exe`
   - `taskeng.exe`
3. Detects execution of high-risk LOLBins, including:
   - `powershell.exe`
   - `pwsh.exe`
   - `cmd.exe`
   - `wscript.exe`
   - `cscript.exe`
   - `mshta.exe`
   - `rundll32.exe`
   - `regsvr32.exe`
   - `certutil.exe`
   - `bitsadmin.exe`
4. Excludes known Windows maintenance tasks and approved internal WebDAV activity.
5. Correlates LOLBin execution occurring within **six hours** of scheduled job creation.

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

1. Review the scheduled job creation command.
2. Determine who created the scheduled job and whether it was authorized.
3. Examine the executed LOLBin and its command line.
4. Review the complete process tree.
5. Investigate outbound network connections initiated by the LOLBin.
6. Check for persistence mechanisms or additional scheduled tasks.
7. Review recent administrative activity on the endpoint.
8. Isolate the endpoint if unauthorized scheduled job execution is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Enterprise software deployment
- Administrative automation
- Patch management solutions
- Approved maintenance scripts
- Scheduled IT operations

---

## Tuning Recommendations

- Maintain exclusions for approved maintenance tasks and enterprise automation.
- Correlate with:
  - DeviceNetworkEvents
  - Scheduled Task creation events
  - Service creation
  - Registry persistence
  - PowerShell logging
- Prioritize:
  - Encoded PowerShell
  - Remote script execution
  - External network connections
  - Unsigned child processes

---

## Limitations

This rule focuses on legacy **AT.exe** and **Win32_ScheduledJob** activity. Modern scheduled tasks created through `schtasks.exe`, PowerShell (`Register-ScheduledTask`), or Task Scheduler APIs are not covered and should be monitored using complementary detections.

---

## References

- MITRE ATT&CK T1053.002 – Scheduled Task/Job: At
- MITRE ATT&CK T1218 – System Binary Proxy Execution
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft Task Scheduler Documentation

---

## Author

**Raunak Sahu**
