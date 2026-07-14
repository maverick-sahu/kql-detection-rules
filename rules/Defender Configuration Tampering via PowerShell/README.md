# Defender Configuration Tampering via PowerShell

## Overview

This detection rule identifies attempts to modify Microsoft Defender Antivirus settings using the PowerShell `Set-MpPreference` cmdlet. Threat actors frequently disable or weaken security controls before deploying malware, ransomware, or other post-exploitation tooling to reduce the likelihood of detection.

The rule detects PowerShell commands that disable real-time protection, behavioral monitoring, script scanning, cloud protection, intrusion prevention, and sample submission features.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Defense Evasion |
| Technique | T1562.001 – Impair Defenses: Disable or Modify Security Tools |

---

## Data Sources

- DeviceProcessEvents

---

## Detection Logic

The rule monitors PowerShell execution for the `Set-MpPreference` cmdlet and identifies attempts to modify Microsoft Defender settings, including:

- `DisableRealtimeMonitoring`
- `DisableBehaviorMonitoring`
- `DisableBlockAtFirstSeen`
- `DisableIOAVProtection`
- `DisableIntrusionPreventionSystem`
- `DisableScriptScanning`
- `MAPSReporting 0`
- `SubmitSamplesConsent 2`

These options are commonly abused to reduce Defender's detection and prevention capabilities.

---

## Severity

**Critical**

---

## Frequency

Every **30 minutes**

---

## Lookback

**1 hour**

---

## Investigation Guidance

When this rule generates an alert:

1. Review the PowerShell command to identify which Defender settings were modified.
2. Determine whether the change was authorized by an administrator or endpoint management solution.
3. Check whether Microsoft Defender protections were successfully disabled.
4. Investigate subsequent process execution, downloads, or ransomware activity.
5. Review the parent process and complete process tree.
6. Examine recent logon activity and privilege escalation events.
7. Restore Microsoft Defender settings if unauthorized changes are confirmed.
8. Isolate the endpoint if malicious activity is identified.

---

## False Positives

Potential legitimate triggers include:

- Endpoint management platforms
- Security hardening or baseline scripts
- Approved administrative maintenance
- Defender configuration testing

---

## Tuning Recommendations

- Allowlist approved management tools and automation accounts.
- Correlate with:
  - DeviceRegistryEvents
  - DeviceEvents
  - Microsoft Defender alerts
  - Service modification events
  - Malware detections
- Prioritize:
  - Multiple Defender settings modified in a single command
  - Encoded PowerShell
  - Non-administrative user execution
  - Additional defense evasion activity

---

## Limitations

This rule detects PowerShell-based Defender configuration changes using `Set-MpPreference`. It does not detect modifications made through Group Policy, Windows Registry, WMI, direct API calls, or third-party management platforms unless those actions invoke the monitored PowerShell cmdlet.

---

## References

- MITRE ATT&CK T1562.001 – Impair Defenses: Disable or Modify Security Tools
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft Defender Antivirus PowerShell Reference

---

## Author

**Raunak Sahu**
