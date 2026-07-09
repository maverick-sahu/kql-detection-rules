# Suspicious PowerShell Credential Prompt

## Overview

This detection rule identifies PowerShell executions that invoke the **Get-Credential** cmdlet or display common credential prompt strings. While **Get-Credential** is a legitimate PowerShell feature, it can also be abused by attackers to present fake authentication prompts and harvest user credentials during phishing or post-exploitation activity.

The rule monitors PowerShell process creation events and highlights command lines indicative of credential collection attempts.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Credential Access |
| Technique | T1056 – Input Capture |

---

## Data Sources

- DeviceProcessEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors execution of:
   - `powershell.exe`
   - `pwsh.exe`
2. Detects command lines containing:
   - `Get-Credential`
   - `Enter your password`
   - `CredentialRequired`
   - `Enter your credential`
3. Returns the execution details for investigation.

---

## Severity

**Medium**

---

## Frequency

Every **30 minutes**

---

## Lookback

**1 hour**

---

## Investigation Guidance

When this rule generates an alert:

1. Verify whether the PowerShell execution was initiated by an authorized administrator or automation.
2. Review the complete PowerShell command line for suspicious parameters.
3. Determine whether the script originated from a trusted location.
4. Check for encoded PowerShell commands or downloaded scripts.
5. Review subsequent authentication events for the affected user.
6. Investigate any related network connections, scheduled tasks, or persistence mechanisms.
7. Isolate the endpoint if malicious credential harvesting is confirmed.

---

## False Positives

Potential legitimate triggers include:

- IT administration scripts
- Helpdesk credential prompts
- PowerShell automation
- System management tools
- Enterprise deployment scripts

---

## Tuning Recommendations

- Exclude approved administrative scripts or automation accounts.
- Correlate with:
  - Encoded PowerShell execution
  - PowerShell Script Block Logging
  - Network authentication events
  - Microsoft Defender for Endpoint alerts
- Prioritize executions launched from Office applications, browsers, or unsigned scripts.

---

## Limitations

This rule detects the use of **Get-Credential** and similar prompt strings but does not confirm credential theft. Legitimate administrative activity may generate alerts and should be validated before escalation.

---

## References

- MITRE ATT&CK T1056 – Input Capture
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft PowerShell Get-Credential Documentation

---

## Author

**Raunak Sahu**
