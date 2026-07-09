# LSA Notification Package Persistence

## Overview

This detection rule identifies potential persistence through **LSA Authentication Packages** by correlating three related events on the same endpoint:

1. A DLL is created or modified on disk.
2. The **Notification Packages** registry value under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` is modified to reference the DLL.
3. The same DLL is subsequently loaded by **LSASS**.

This technique enables attackers to execute malicious code inside the Local Security Authority Subsystem Service (LSASS) during system startup, providing persistence and potential access to authentication material.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Persistence & Credential Access |
| Technique | T1547.002 – Authentication Package |

---

## Data Sources

- DeviceFileEvents
- DeviceRegistryEvents
- DeviceImageLoadEvents

---

## Detection Logic

The rule correlates the following events occurring on the same device:

1. A DLL is created or modified.
2. The **Notification Packages** registry value is modified to reference that DLL.
3. LSASS subsequently loads the same DLL.
4. All three events occur within defined time windows to reduce false positives.

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

1. Verify whether the DLL is Microsoft-signed or belongs to an approved authentication provider.
2. Review the process responsible for creating the DLL.
3. Inspect the registry modification for unauthorized changes.
4. Analyze the DLL using its SHA256 hash.
5. Review additional LSASS activity, including memory access and credential dumping attempts.
6. Investigate persistence mechanisms, scheduled tasks, services, and newly created users.
7. Isolate the endpoint if malicious activity is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Microsoft authentication packages
- Enterprise identity and authentication solutions
- Security software integrating with LSA
- Approved third-party credential providers

---

## Tuning Recommendations

- Maintain an allowlist of approved LSA authentication packages.
- Exclude Microsoft-signed DLLs where appropriate.
- Correlate with:
  - LSASS memory access
  - Credential dumping
  - Unsigned DLL loading
  - Service installation
  - Privilege escalation
- Prioritize DLLs loaded from user-writable or non-system directories.

---

## Limitations

This rule focuses specifically on persistence through **LSA Authentication Packages**. Other LSASS persistence techniques that do not modify the **Notification Packages** registry value will not be detected.

---

## References

- MITRE ATT&CK T1547.002 – Authentication Package
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft Windows Local Security Authority (LSA) Documentation

---

## Author

**Raunak Sahu**
