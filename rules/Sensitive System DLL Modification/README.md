# Sensitive System DLL Modification

## Overview

This detection rule monitors modifications to **cryptdll.dll** and **samsrv.dll** located in protected Windows system directories. These DLLs play critical roles in cryptographic services and the Security Account Manager (SAM). Unauthorized changes to these files may indicate attempts to tamper with authentication mechanisms, establish persistence, or evade security controls.

Because these files are rarely modified outside of legitimate operating system servicing, changes should be treated as high-priority events and investigated promptly.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Defense Evasion & Persistence |
| Technique | T1574.001 – DLL Search Order Hijacking & T1036 – Masquerading |

---

## Data Sources

- DeviceFileEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors the following files:
   - `cryptdll.dll`
   - `samsrv.dll`
2. Restricts monitoring to:
   - `C:\Windows\System32\`
   - `C:\Windows\SysWOW64\`
3. Detects:
   - File creation
   - File modification
   - File renaming
   - File deletion
4. Returns the initiating process and file metadata for investigation.

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

1. Verify whether the modification was performed during a Windows Update or approved maintenance activity.
2. Validate the digital signature and hash of the affected DLL.
3. Review the initiating process and parent process.
4. Determine whether the file was replaced with an unsigned or unexpected version.
5. Review recent service installations, registry modifications, and scheduled tasks.
6. Investigate for additional indicators of persistence, credential access, or defense evasion.
7. Isolate the endpoint if unauthorized system file modification is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Windows Update
- Component-Based Servicing (CBS)
- DISM
- System File Checker (SFC)
- Trusted software installation
- Enterprise software deployment

---

## Tuning Recommendations

- Exclude trusted Windows servicing processes after validation.
- Correlate with:
  - Windows servicing events
  - Registry modifications
  - Service creation
  - Driver installation
  - Credential dumping detections
- Prioritize unsigned binaries or modifications performed by non-Microsoft processes.

---

## Limitations

This rule detects modifications to two specific system DLLs and does not provide complete coverage for all protected Windows binaries. Organizations requiring broader integrity monitoring should extend the rule to additional security-sensitive files.

---

## References

- MITRE ATT&CK T1574.001 – DLL Search Order Hijacking
- MITRE ATT&CK T1036 – Masquerading
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft Windows File Protection Documentation

---

## Author

**Raunak Sahu**
