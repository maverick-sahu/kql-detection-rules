# Suspicious Winlogon DLL Load

## Overview

This detection rule identifies DLLs loaded by **winlogon.exe** from locations outside the trusted Windows system directories. The Windows Logon Process (`winlogon.exe`) loads components involved in authentication and user logon. Attackers may abuse this behavior by registering malicious Network Provider DLLs or credential providers to execute code during logon and establish persistence.

To reduce false positives, the rule excludes known legitimate Citrix Single Sign-On (SSO) components (`pnsson.dll` and `ssonstub.dll`).

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Persistence & Credential Access |
| Technique | T1556.008 – Network Provider DLL |

---

## Data Sources

- DeviceImageLoadEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors DLLs loaded by `winlogon.exe`.
2. Excludes DLLs loaded from:
   - `C:\Windows\System32`
3. Excludes known legitimate Citrix SSO DLLs:
   - `pnsson.dll`
   - `ssonstub.dll`
4. Returns image load details for investigation.

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

1. Verify whether the DLL is Microsoft-signed.
2. Determine whether the DLL belongs to an approved credential provider or authentication solution.
3. Review the file creation event for the DLL.
4. Investigate recent registry modifications related to:
   - `NetworkProvider`
   - Credential Providers
5. Review user logon activity following the DLL load.
6. Analyze the DLL using its hash and reputation.
7. Isolate the endpoint if unauthorized persistence is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Citrix Single Sign-On
- Enterprise identity solutions
- Approved credential providers
- Security software

---

## Tuning Recommendations

- Maintain an allowlist of approved authentication DLLs.
- Correlate with:
  - DeviceRegistryEvents
  - DeviceFileEvents
  - DeviceProcessEvents
  - Logon events
- Prioritize:
  - Unsigned DLLs
  - User-writable directories
  - Recently created DLLs
  - Non-Microsoft publishers

---

## Limitations

This rule detects suspicious DLL loading by `winlogon.exe` but does not verify whether the DLL was successfully registered through a Network Provider or Credential Provider mechanism. Correlation with registry modifications significantly improves confidence.

---

## References

- MITRE ATT&CK T1556.008 – Network Provider DLL
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft Windows Winlogon Architecture

---

## Author

**Raunak Sahu**
