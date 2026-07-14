# HID-Triggered Script Execution (macOS)

## Overview

This detection rule identifies suspicious script execution occurring within **30 seconds** of a USB Human Interface Device (HID) connection on macOS. Programmable HID devices, such as Rubber Ducky, O.MG Cable, and other BadUSB implants, emulate legitimate keyboards to inject keystrokes that execute commands without requiring user interaction.

The rule correlates USB/HID connection events with the execution of AppleScript, shell, and Python interpreters commonly used during keystroke injection attacks.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Initial Access & Execution |
| Technique | T1674 – Input Injection |

---

## Data Sources

- DeviceInfo
- DeviceEvents
- DeviceProcessEvents

---

## Detection Logic

The rule performs the following actions:

1. Identifies macOS devices.
2. Detects USB/HID connection events, including:
   - `PnpDeviceConnected`
   - `UsbDriveMounted`
3. Filters for keyboard- and HID-related devices.
4. Monitors execution of:
   - `osascript`
   - `python`
   - `python3`
   - `bash`
   - `zsh`
   - `sh`
5. Detects suspicious command-line patterns such as:
   - `curl`
   - `wget`
   - `base64`
   - `chmod +x`
   - `os.system`
   - `subprocess`
   - `exec(`
6. Correlates script execution occurring within **30 seconds** of the HID connection.

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

1. Identify the connected USB/HID device.
2. Determine whether the device is approved.
3. Review the executed command line for download, execution, or persistence behavior.
4. Investigate child processes spawned by the interpreter.
5. Review outbound network connections immediately following execution.
6. Check for persistence mechanisms such as LaunchAgents, LaunchDaemons, or cron jobs.
7. Determine whether the HID device remained connected after execution.
8. Isolate the endpoint if unauthorized HID-based command execution is confirmed.

---

## False Positives

Potential legitimate triggers include:

- USB keyboard testing
- Administrative automation
- Developer scripts
- Enterprise provisioning tools
- Approved USB peripherals

---

## Tuning Recommendations

- Maintain an allowlist of trusted USB devices.
- Correlate with:
  - DeviceNetworkEvents
  - LaunchAgent or LaunchDaemon creation
  - Cron modifications
  - File downloads
  - AppleScript execution
- Prioritize:
  - Encoded commands
  - Download-and-execute behavior
  - Base64 decoding
  - Network connections to external IP addresses

---

## Limitations

This rule detects script execution shortly after a USB/HID connection but does not confirm that the HID device generated the keystrokes. Advanced attackers may delay execution beyond the correlation window or use trusted scripting tools that blend with legitimate administrative activity.

---

## References

- MITRE ATT&CK T1674 – Input Injection
- Microsoft Defender XDR Advanced Hunting Documentation
- Apple Platform Security Documentation

---

## Author

**Raunak Sahu**
