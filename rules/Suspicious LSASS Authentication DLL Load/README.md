# Suspicious LSASS Authentication DLL Load

## Overview

This detection rule identifies instances where **LSASS (Local Security Authority Subsystem Service)** loads the authentication-related DLLs **cryptdll.dll** or **samsrv.dll** from locations outside the trusted Windows system directories (`C:\Windows\System32` and `C:\Windows\SysWOW64`).

These DLLs are core components of the Windows authentication infrastructure. Under normal conditions, they are loaded only from protected system directories. Loading them from alternate locations may indicate an attempt to modify the Windows authentication process, establish persistence, or facilitate credential theft.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Persistence & Credential Access |
| Technique | T1556 – Modify Authentication Process |

---

## Data Sources

- DeviceImageLoadEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors DLLs loaded by `lsass.exe`.
2. Detects loads of:
   - `cryptdll.dll`
   - `samsrv.dll`
3. Excludes the trusted directories:
   - `C:\Windows\System32\`
   - `C:\Windows\SysWOW64\`
4. Returns image load details for investigation.

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

1. Verify the DLL's location and confirm whether it resides outside trusted Windows directories.
2. Validate the DLL's digital signature and publisher.
3. Compare the file hash against known-good Microsoft versions.
4. Review recent file creation or modification events for the DLL.
5. Investigate registry modifications related to authentication packages or Network Providers.
6. Review LSASS memory access, credential dumping alerts, and logon activity.
7. Isolate the endpoint if unauthorized DLL loading is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Approved authentication providers
- Enterprise identity solutions
- Security software extending authentication functionality
- Vendor-supported integrations

---

## Tuning Recommendations

- Maintain an allowlist of approved authentication DLLs.
- Correlate with:
  - DeviceFileEvents
  - DeviceRegistryEvents
  - LSASS memory access detections
  - Service installation events
  - Privilege escalation alerts
- Prioritize:
  - Unsigned DLLs
  - Recently created files
  - DLLs loaded from user-writable locations
  - Non-Microsoft publishers

---

## Limitations

This rule focuses specifically on `cryptdll.dll` and `samsrv.dll` loaded by `lsass.exe`. Other authentication-related DLLs or alternative persistence mechanisms require additional detections.

---

## References

- MITRE ATT&CK T1556 – Modify Authentication Process
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft Windows Local Security Authority (LSA) Documentation

---

## Author

**Raunak Sahu**
