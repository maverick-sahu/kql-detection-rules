# HID-Triggered LOLBin Execution

## Overview

This detection rule identifies the execution of Windows Living-off-the-Land Binaries (LOLBins) shortly after a USB Human Interface Device (HID) connection. Programmable HID devices, such as Rubber Ducky, O.MG Cable, and BadUSB implants, emulate legitimate keyboards and rapidly inject keystrokes that launch trusted Windows binaries to execute malicious payloads.

The rule correlates USB/HID connection events with the execution of commonly abused LOLBins within a **30-second** window, providing high-confidence detection of HID-based command injection attacks.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Initial Access & Defense Evasion & Execution |
| Technique | T1674 – Input Injection & T1218 – System Binary Proxy Execution |

---

## Data Sources

- DeviceEvents
- DeviceProcessEvents

---

## Detection Logic

The rule performs the following actions:

1. Detects USB HID connection events:
   - `PnpDeviceConnected`
   - `PnpDeviceAllowed`
2. Filters devices identified as keyboards or HID peripherals.
3. Monitors execution of:
   - `mshta.exe` loading remote or local HTA content
   - `regsvr32.exe` executing `.sct` scriptlets
   - `rundll32.exe` executing JavaScript
4. Correlates LOLBin execution occurring within **30 seconds** of the HID connection.
5. Returns both the HID event and process execution details.

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

1. Identify the connected USB/HID device and verify whether it is approved.
2. Review the LOLBin command line for remote URLs, scriptlets, or JavaScript payloads.
3. Examine the parent process and full process tree.
4. Investigate outbound network connections initiated by the LOLBin.
5. Check for persistence mechanisms created after execution.
6. Review additional script execution or PowerShell activity on the endpoint.
7. Determine whether the HID device remained connected after execution.
8. Isolate the endpoint if HID-based command execution is confirmed.

---

## False Positives

Potential legitimate triggers include:

- USB keyboard testing
- Security assessments
- Administrative automation
- Approved software deployment tools
- Enterprise management solutions

---

## Tuning Recommendations

- Maintain an allowlist of trusted USB HID devices.
- Correlate with:
  - DeviceNetworkEvents
  - PowerShell execution
  - Scheduled task creation
  - Registry modifications
  - Service creation
- Prioritize:
  - Remote URLs
  - Unsigned child processes
  - External network connections
  - Additional LOLBin activity following the initial execution

---

## Limitations

This rule detects LOLBin execution shortly after a USB HID connection but cannot definitively prove that the HID device generated the keystrokes. Attackers who delay execution beyond the correlation window or use alternate execution methods may evade this detection.

---

## References

- MITRE ATT&CK T1674 – Input Injection
- MITRE ATT&CK T1218 – System Binary Proxy Execution
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft LOLBAS Project Documentation

---

## Author

**Raunak Sahu**
