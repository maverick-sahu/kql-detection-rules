# Suspicious Shell History Access

## Overview

This detection rule identifies repeated non-interactive access to Bash (`.bash_history`) and Zsh (`.zsh_history`) history files. After gaining access to a system, attackers often review shell history to discover previously executed commands, credentials, SSH usage, cloud administration commands, and other operational details that can facilitate privilege escalation or lateral movement.

The rule focuses on command-line utilities reading shell history files while excluding normal interactive shells and approved developer tooling.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Discovery |
| Technique | T1083 – File and Directory Discovery & T1552.001 – Unsecured Credentials: Credentials in Files |

---

## Data Sources

- DeviceProcessEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors non-root and non-system users.
2. Detects command-line utilities reading:
   - `.bash_history`
   - `.zsh_history`
3. Monitors utilities including:
   - `cat`
   - `tac`
   - `grep`
   - `awk`
   - `sed`
   - `less`
   - `more`
   - `tail`
   - `head`
   - `sort`
   - `strings`
4. Excludes:
   - Interactive shells (`Terminal`, `iTerm2`, `bash`, `zsh`)
   - Cursor sandbox helper activity
   - Known benign shell snapshot locations
   - Sandbox execution
5. Groups events into **15-minute** windows and alerts when the activity occurs **two or more times**.

---

## Severity

**Medium**

---

## Frequency

Every **30 minutes**

---

## Lookback

**24 hours**

---

## Investigation Guidance

When this rule generates an alert:

1. Determine which process accessed the shell history files.
2. Review the parent process and process ancestry.
3. Verify whether the activity originated from approved administrative or forensic tools.
4. Examine recent SSH sessions and interactive logons.
5. Review access to credential files, browser data, and cloud configuration files.
6. Investigate archive creation or outbound network connections following the activity.
7. Check for additional discovery commands executed by the same process.
8. Isolate the endpoint if the activity is determined to be malicious.

---

## False Positives

Potential legitimate triggers include:

- Digital forensic investigations
- Endpoint management tools
- Developer utilities
- Approved security software
- Incident response activities

---

## Tuning Recommendations

- Maintain allowlists for approved developer and forensic tools.
- Correlate with:
  - DeviceFileEvents
  - DeviceNetworkEvents
  - SSH activity
  - Archive creation
  - Credential store access
- Prioritize:
  - Repeated access within a short time window
  - Access followed by data compression or exfiltration
  - Multiple discovery commands from the same process

---

## Limitations

This rule detects repeated reads of shell history files but cannot determine whether the accessed history contained sensitive information such as passwords or authentication tokens. Additional investigation is required to assess the impact and identify any subsequent credential use or data exfiltration.

---

## References

- MITRE ATT&CK T1083 – File and Directory Discovery
- MITRE ATT&CK T1552.001 – Unsecured Credentials: Credentials in Files
- Microsoft Defender XDR Advanced Hunting Documentation

---

## Author

**Raunak Sahu**
