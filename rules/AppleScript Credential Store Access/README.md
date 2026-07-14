# AppleScript Credential Store Access

## Overview

This detection rule identifies suspicious AppleScript or shell execution followed by access to browser credential stores or the macOS Keychain. Modern macOS infostealers commonly execute AppleScript or shell commands to access saved passwords, browser cookies, authentication tokens, and Keychain secrets before exfiltrating the collected data.

By correlating process execution with credential store access within a short time window, the rule provides high-confidence detection while reducing false positives.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Credential Access & Collection |
| Technique | T1555 – Credentials from Password Stores & T1059.002 – Command and Scripting Interpreter: AppleScript |

---

## Data Sources

- DeviceProcessEvents
- DeviceFileEvents

---

## Detection Logic

The rule performs the following actions:

### Step 1 – Suspicious Script Execution

Monitors execution of:

- `osascript`
- `bash`
- `zsh`
- `sh`

Detects suspicious command-line indicators including:

- `do shell script`
- `base64`
- `curl`
- `wget`
- `security`
- `keychain`

Looks for references to credential-related data such as:

- `Login Data`
- `Cookies`
- `Web Data`
- `keychain`

Excludes common macOS parent processes:

- Finder
- System Events

---

### Step 2 – Credential Store Access

Monitors access to:

- Google Chrome credential database
- Brave Browser credential database
- Safari data
- macOS Keychain

Excludes legitimate browser processes.

---

### Correlation

Correlates suspicious script execution with credential store access occurring within **five minutes** on the same endpoint.

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

1. Review the AppleScript or shell command for credential harvesting behavior.
2. Identify which browser or Keychain files were accessed.
3. Determine whether the process originated from a downloaded or user-writable location.
4. Review outbound network connections following credential access.
5. Investigate archive creation or compression of collected data.
6. Examine process ancestry and child processes.
7. Review persistence mechanisms such as LaunchAgents or LaunchDaemons.
8. Isolate the endpoint if credential theft is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Browser migration tools
- Enterprise endpoint management
- Approved administrative scripts
- Backup software
- Browser synchronization utilities

---

## Tuning Recommendations

- Maintain an allowlist for approved administrative tools.
- Correlate with:
  - DeviceNetworkEvents
  - Archive creation
  - Keychain access
  - LaunchAgent creation
  - File uploads
- Prioritize:
  - Base64 decoding
  - External network connections
  - Multiple browser profile access
  - Access to both browser stores and Keychain

---

## Limitations

This rule detects suspicious script execution followed by access to credential stores but does not confirm credential exfiltration. Additional telemetry, such as outbound network activity, archive creation, or cloud uploads, should be reviewed to determine whether collected credentials were successfully exfiltrated.

---

## References

- MITRE ATT&CK T1555 – Credentials from Password Stores
- MITRE ATT&CK T1059.002 – Command and Scripting Interpreter: AppleScript
- Microsoft Defender XDR Advanced Hunting Documentation
- Apple Platform Security Guide

---

## Author

**Raunak Sahu**
