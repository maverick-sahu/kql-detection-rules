# Network Provider Registry Modification

## Overview

This detection rule identifies modifications to Windows Network Provider registry settings. Network Providers are loaded by Windows during user logon to enable network authentication and resource access.

Attackers may register a malicious Network Provider DLL to establish persistence, intercept authentication traffic, or capture user credentials. Because Network Providers are loaded automatically during logon, unauthorized registry modifications should be investigated promptly.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Persistence & Credential Access |
| Technique | T1556.008 – Network Provider DLL |

---

## Data Sources

- DeviceRegistryEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors:
   - `RegistryValueSet`
   - `RegistryKeyCreated`
2. Detects changes under:
   - `HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider`
   - `HKLM\SYSTEM\CurrentControlSet\Services`
3. Monitors modifications to:
   - `NetworkProvider`
   - `Order`
4. Returns registry modification details and the initiating process.

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

1. Determine whether the registry modification was authorized.
2. Identify the DLL referenced by the Network Provider configuration.
3. Verify whether the DLL is Microsoft-signed or part of an approved application.
4. Review the initiating process and its parent process.
5. Check for DLL creation events corresponding to the configured provider.
6. Review authentication activity and logon events following the modification.
7. Investigate persistence mechanisms, service creation, and credential access activity.
8. Isolate the endpoint if unauthorized persistence is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Installation of approved network client software
- Enterprise identity solutions
- Endpoint security software
- VPN client installation
- Network file system software

---

## Tuning Recommendations

- Maintain an allowlist of approved Network Provider DLLs.
- Exclude trusted installation processes after validation.
- Correlate with:
  - DeviceFileEvents
  - DeviceProcessEvents
  - DeviceImageLoadEvents
  - Authentication events
  - Service creation events
- Prioritize unsigned DLLs or providers loaded from non-system directories.

---

## Limitations

This rule detects registry modifications but does not verify that the configured Network Provider DLL exists or was successfully loaded. For higher confidence, correlate with DLL creation and image load telemetry.

---

## References

- MITRE ATT&CK T1556.008 – Network Provider DLL
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft Windows Network Provider Architecture Documentation

---

## Author

**Raunak Sahu**
