# HID-Triggered Encoded PowerShell

## Overview

This detection rule identifies obfuscated or encoded PowerShell execution occurring shortly after a USB Human Interface Device (HID) connection. Programmable HID devices, such as Rubber Ducky, O.MG Cable, and BadUSB implants, frequently emulate keyboard input to launch hidden PowerShell commands that download payloads, establish persistence, or execute malware.

By correlating HID connection events with suspicious PowerShell activity within a two-minute window, the rule provides high-confidence detection of HID-based command injection attacks.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Initial Access, Execution & Defense Evasion |
| Technique | T1674 – Input Injection & T1059.001 – Command and Scripting Interpreter: PowerShell |

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
3. Monitors PowerShell execution:
   - `powershell.exe`
   - `pwsh.exe`
4. Detects suspicious command-line indicators including:
   - `-enc`
   - `-EncodedCommand`
   - `-nop`
   - `-windowstyle hidden`
   - `-w hidden`
   - `Invoke-Expression`
   - `iex(`
5. Correlates PowerShell execution occurring within **two minutes** of the HID connection.

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

1. Identify the connected USB/HID device and determine whether it is approved.
2. Decode any Base64-encoded PowerShell commands.
3. Review the complete PowerShell command line for download or execution behavior.
4. Examine the parent process and process tree.
5. Investigate outbound network connections initiated by PowerShell.
6. Check for persistence mechanisms created after execution.
7. Review subsequent PowerShell, LOLBin, or scripting activity on the endpoint.
8. Isolate the endpoint if unauthorized HID-based PowerShell execution is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Security assessments
- Administrative automation
- Endpoint provisioning
- Approved PowerShell scripts
- Hardware testing

---

## Tuning Recommendations

- Maintain an allowlist of trusted HID devices and administrative scripts.
- Correlate with:
  - DeviceNetworkEvents
  - PowerShell Script Block Logging
  - Scheduled task creation
  - Registry modifications
  - Service creation
- Prioritize:
  - Encoded commands
  - Hidden execution
  - External network connections
  - Download-and-execute behavior
  - Additional persistence activity

---

## Limitations

This rule detects suspicious PowerShell execution following a USB HID connection but cannot definitively attribute the command execution to the HID device itself. Attackers may evade the detection by delaying execution beyond the two-minute window or by using alternate scripting interpreters.

---

## References

- MITRE ATT&CK T1674 – Input Injection
- MITRE ATT&CK T1059.001 – Command and Scripting Interpreter: PowerShell
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft PowerShell Security Documentation

---

## Author

**Raunak Sahu**
