# Browser-Spawned Encoded PowerShell

## Overview

This detection rule identifies encoded or obfuscated PowerShell execution launched directly or indirectly by a web browser. Modern phishing campaigns, ClickFix attacks, fake software updates, and drive-by downloads frequently rely on browsers to initiate PowerShell with encoded commands that execute malicious payloads entirely in memory.

The rule detects PowerShell instances spawned from supported browsers and searches for common indicators of obfuscation and in-memory execution.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Initial Access & Execution |
| Technique | T1059.001 – Command and Scripting Interpreter: PowerShell |

---

## Data Sources

- DeviceProcessEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors PowerShell processes started by:
   - Chrome
   - Microsoft Edge
   - Firefox
2. Detects command-line indicators including:
   - `-enc`
   - `-EncodedCommand`
   - `FromBase64String`
   - `IEX`
   - `Invoke-Expression`
3. Returns execution details for investigation.

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

1. Review the browser process that launched PowerShell.
2. Decode any Base64-encoded PowerShell commands.
3. Determine whether a downloaded file or webpage initiated execution.
4. Review browser download history and recently accessed URLs.
5. Investigate outbound network connections established by PowerShell.
6. Examine the process tree for additional payload execution.
7. Check for persistence mechanisms created after execution.
8. Isolate the endpoint if malicious PowerShell execution is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Enterprise browser automation
- Administrative PowerShell scripts
- Software deployment portals
- Internal IT management tools

---

## Tuning Recommendations

- Exclude approved browser automation frameworks.
- Correlate with:
  - DeviceNetworkEvents
  - DeviceFileEvents (Downloads folder)
  - Microsoft SmartScreen alerts
  - Office macro execution
  - Browser download activity
- Prioritize:
  - External URLs
  - Unsigned scripts
  - Encoded commands
  - Additional persistence or credential access activity

---

## Limitations

This rule detects encoded PowerShell launched from a browser but does not determine whether the execution originated from a malicious website, downloaded file, or legitimate enterprise application. Additional browser, network, and endpoint telemetry should be reviewed to confirm malicious activity.

---

## References

- MITRE ATT&CK T1059.001 – Command and Scripting Interpreter: PowerShell
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft PowerShell Security Documentation

---

## Author

**Raunak Sahu**
