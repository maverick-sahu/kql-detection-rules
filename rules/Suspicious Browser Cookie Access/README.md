# Suspicious Browser Cookie Access

## Overview

This detection rule identifies attempts to access browser cookie databases by processes other than the associated web browser. It combines Windows file activity and cross-platform process execution telemetry to detect behavior commonly associated with infostealers and malware that steal authenticated web session cookies.

Stolen browser cookies can allow attackers to hijack authenticated sessions, bypass multi-factor authentication (MFA), and gain unauthorized access to cloud services without requiring user credentials.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Credential Access |
| Technique | T1539 – Steal Web Session Cookie |

---

## Data Sources

- DeviceFileEvents
- DeviceProcessEvents

---

## Detection Logic

The rule combines two complementary detections:

### Windows (DeviceFileEvents)

- Monitors browser cookie databases for:
  - Google Chrome
  - Microsoft Edge
  - Chromium
  - Brave
  - Mozilla Firefox
  - Opera
- Detects access by non-browser processes.
- Excludes known browser journal files and approved browser executables.

### Cross-platform (DeviceProcessEvents)

- Detects processes referencing browser cookie databases in their command line.
- Covers browser profile locations for:
  - Chrome
  - Edge
  - Brave
  - Chromium
  - Firefox
  - Opera
  - Safari (macOS)
- Excludes legitimate browser and common application processes.

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

1. Determine whether the initiating process is approved.
2. Review the complete process tree.
3. Verify whether the executable is signed and trusted.
4. Check for archive creation or compression shortly after cookie access.
5. Review outbound network connections.
6. Investigate subsequent cloud authentication events.
7. Check for browser credential store access.
8. Isolate the endpoint if malicious activity is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Endpoint Detection and Response (EDR) products
- Backup software
- Digital forensic tools
- Browser migration utilities
- Enterprise synchronization tools

---

## Tuning Recommendations

- Exclude approved security products and automation.
- Correlate with:
  - Browser credential access
  - Archive creation
  - PowerShell or shell execution
  - Network exfiltration
  - Cloud authentication anomalies
- Prioritize unsigned or recently dropped executables.

---

## Limitations

The rule monitors browser cookie databases in standard profile locations. Organizations using custom browser profiles or portable browsers should update the monitored paths accordingly. Detection of cookie access does not, by itself, confirm successful cookie extraction or exfiltration.

---

## References

- MITRE ATT&CK T1539 – Steal Web Session Cookie
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft Browser Security Documentation

---

## Author

**Raunak Sahu**
