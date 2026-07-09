# LSA Notification Package Registry Modification

## Overview

This detection rule identifies modifications to the **Notification Packages** registry value under the Windows **Local Security Authority (LSA)** configuration. The **Notification Packages** registry value specifies authentication packages that are loaded by the Local Security Authority Subsystem Service (LSASS) during system startup.

Attackers may modify this registry value to register a malicious authentication package, enabling persistence and execution of arbitrary code within the LSASS process. Because this rule detects only the registry modification, it should be considered an early warning and correlated with additional endpoint telemetry.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Persistence |
| Technique | T1547.002 – Authentication Package |

---

## Data Sources

- DeviceRegistryEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors registry modification events.
2. Detects changes to:
   - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
3. Identifies modifications to the:
   - `Notification Packages` registry value.
4. Returns registry modification details for investigation.

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
2. Review the DLL referenced in the `Notification Packages` value.
3. Verify whether the DLL is Microsoft-signed or part of an approved authentication provider.
4. Review the initiating process responsible for the registry modification.
5. Correlate with:
   - DLL creation events
   - LSASS DLL load events
   - Credential dumping detections
   - Privilege escalation activity
6. Analyze the referenced DLL using its hash and reputation.
7. Isolate the endpoint if malicious persistence is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Microsoft authentication package installation
- Enterprise identity and authentication products
- Security software integrating with LSA
- Approved third-party credential providers

---

## Tuning Recommendations

- Maintain an allowlist of approved authentication packages.
- Exclude trusted identity and security software.
- Correlate with:
  - DeviceFileEvents
  - DeviceImageLoadEvents
  - LSASS memory access detections
  - Unsigned DLL loading
- Prioritize modifications introducing previously unseen DLL names.

---

## Limitations

This rule detects only the registry modification and does not confirm that the referenced DLL exists or was successfully loaded by LSASS. For higher confidence, correlate this detection with DLL creation and LSASS image load events.

---

## References

- MITRE ATT&CK T1547.002 – Authentication Package
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft Windows Local Security Authority (LSA) Documentation

---

## Author

**Raunak Sahu**
