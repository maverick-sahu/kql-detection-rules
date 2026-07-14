# Suspicious AppleScript Credential Prompt

## Overview

This detection rule identifies AppleScript (`osascript`) executions that display dialog boxes requesting authentication credentials or passwords on macOS. AppleScript provides a legitimate mechanism for presenting graphical dialogs, but threat actors frequently abuse it to mimic native macOS authentication prompts and trick users into revealing their credentials.

The rule focuses on AppleScript commands that create dialog boxes containing credential-related keywords while excluding known approved enterprise scripts.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Credential Access |
| Technique | T1056.002 – Input Capture: GUI Input Capture |

---

## Data Sources

- DeviceProcessEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors execution of `/usr/bin/osascript`.
2. Detects AppleScript commands containing:
   - `display dialog`
   - `answer`
3. Searches for credential-related keywords including:
   - `admin`
   - `administrator`
   - `authenticate`
   - `authentication`
   - `credentials`
   - `password`
   - `unlock`
4. Excludes known approved automation scripts such as:
   - `Claude Code — Trino Credential Setup`
5. Returns process execution details for investigation.

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

1. Review the AppleScript command to determine the dialog text presented to the user.
2. Verify whether the script originated from an approved application or administrator.
3. Review the parent process that launched `osascript`.
4. Check for recent file downloads or execution from user-writable directories.
5. Investigate network connections following the prompt.
6. Review Keychain access, LaunchAgent creation, or other persistence mechanisms.
7. Determine whether the user entered credentials into the dialog.
8. Isolate the endpoint if malicious credential harvesting is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Enterprise authentication scripts
- IT support automation
- Approved administrative workflows
- Developer setup scripts

---

## Tuning Recommendations

- Maintain an allowlist of approved AppleScript automation.
- Correlate with:
  - DeviceNetworkEvents
  - Keychain access events
  - LaunchAgent and LaunchDaemon creation
  - File downloads
  - Parent process lineage
- Prioritize:
  - Unsigned parent processes
  - Scripts executed from user-writable directories
  - External network connections following the prompt
  - Multiple credential prompts on the same device

---

## Limitations

This rule detects AppleScript-based credential prompts but cannot determine whether a user entered credentials. Additional telemetry, such as Keychain access, outbound network activity, or subsequent credential use, should be correlated to confirm malicious intent.

---

## References

- MITRE ATT&CK T1056.002 – Input Capture: GUI Input Capture
- Microsoft Defender XDR Advanced Hunting Documentation
- Apple AppleScript Documentation
- Apple Platform Security Guide

---

## Author

**Raunak Sahu**
