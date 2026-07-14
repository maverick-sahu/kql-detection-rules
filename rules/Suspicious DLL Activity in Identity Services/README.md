# Suspicious DLL Activity in Identity Services

## Overview

This detection rule identifies suspicious DLL loading and DLL injection targeting Microsoft Entra ID Connect and Active Directory Federation Services (AD FS) components. Identity synchronization services process privileged authentication data and are attractive targets for attackers seeking persistence, credential theft, or identity compromise.

The rule monitors DLLs loaded from temporary or user-writable directories and detects remote thread creation involving critical identity service processes.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Persistence, Credential Access & Defense Evasion |
| Technique | T1574.001 – Hijack Execution Flow: DLL Search Order Hijacking & T1055 – Process Injection |

---

## Data Sources

- DeviceImageLoadEvents
- DeviceEvents

---

## Detection Logic

The rule performs two complementary detections:

### 1. Suspicious DLL Load

- Monitors `ImageLoaded` events.
- Detects DLLs loaded from temporary or user-writable directories.
- Identifies DLLs loaded into:
  - `AzureADConnectAuthenticationAgentService`
  - `Microsoft.IdentityServer.ServiceHost.exe`
  - `miiserver.exe`

### 2. DLL Injection

- Monitors `CreateRemoteThreadApiCall` events.
- Detects DLL-based process injection originating from temporary or user-writable directories.
- Identifies injection targeting the same identity service processes.

The results from both detections are combined into a single output.

---

## Severity

**Critical**

---

## Frequency

Every **30 minutes**

---

## Lookback

**30 days**

---

## Investigation Guidance

When this rule generates an alert:

1. Verify whether the loaded or injected DLL is Microsoft-signed.
2. Review the DLL's origin and determine whether it resides in a user-writable directory.
3. Validate the DLL hash against known-good baselines.
4. Examine the process tree leading to the DLL load or injection.
5. Investigate recent service configuration changes.
6. Review authentication activity involving Entra ID Connect or AD FS.
7. Correlate with credential dumping, privilege escalation, and persistence detections.
8. Isolate the server immediately if malicious code execution is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Microsoft-supported identity service extensions
- Approved third-party identity integrations
- Security or monitoring software
- Vendor-supported troubleshooting tools

---

## Tuning Recommendations

- Maintain an allowlist of approved DLLs and publishers.
- Correlate with:
  - DeviceProcessEvents
  - DeviceRegistryEvents
  - Service installation events
  - Authentication anomalies
  - LSASS access detections
- Prioritize:
  - Unsigned DLLs
  - DLLs in user-writable directories
  - Newly created DLLs
  - Unexpected remote thread creation

---

## Limitations

This rule focuses on DLL activity involving Microsoft Entra ID Connect and AD FS service processes. It does not detect other persistence mechanisms or attacks targeting different identity infrastructure components.

---

## References

- MITRE ATT&CK T1574.001 – Hijack Execution Flow: DLL Search Order Hijacking
- MITRE ATT&CK T1055 – Process Injection
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft Entra Connect Security Documentation

---

## Author

**Raunak Sahu**
