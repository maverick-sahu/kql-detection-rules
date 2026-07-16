# Suspicious Shell History Modification

## Overview

This detection rule identifies modification, deletion, creation, or renaming of shell history files by processes other than interactive shells. Attackers often tamper with shell history after executing commands to conceal evidence, making this behavior a common indicator of defense evasion during post-compromise activity.

The rule focuses on `.bash_history` and `.zsh_history`, which store command histories for Bash and Zsh users.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Defense Evasion |
| Technique | T1070.003 – Indicator Removal on Host: Clear Command History |

---

## Data Sources

- DeviceFileEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors shell history files:
   - `.bash_history`
   - `.zsh_history`
2. Detects the following file operations:
   - `FileModified`
   - `FileDeleted`
   - `FileRenamed`
   - `FileCreated`
3. Excludes common interactive shell processes:
   - `bash`
   - `zsh`
   - `sh`
   - `Terminal`
   - `iTerm2`
4. Returns events for investigation.

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

1. Determine which process modified or deleted the shell history file.
2. Review the process tree and parent process.
3. Verify whether the activity originated from approved administrative software.
4. Review recent SSH logins or interactive sessions for the affected user.
5. Investigate other evidence of defense evasion, such as log deletion or artifact cleanup.
6. Check for credential access, privilege escalation, or persistence activity preceding the event.
7. Review recently executed commands if historical logs are available.
8. Isolate the endpoint if malicious history tampering is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Administrative cleanup scripts
- Shell initialization or profile management
- Endpoint management software
- Backup and synchronization utilities
- Developer tooling

---

## Tuning Recommendations

- Allowlist approved administration and endpoint management tools.
- Correlate with:
  - DeviceProcessEvents
  - SSH authentication logs
  - Privilege escalation detections
  - Credential access activity
  - Log or artifact deletion events
- Prioritize:
  - File deletion or renaming
  - Activity immediately following privileged sessions
  - Multiple history modifications on the same host

---

## Limitations

This rule detects changes to shell history files but cannot determine whether commands were actually removed or altered. Some legitimate shell or maintenance operations may also modify these files, requiring environment-specific tuning.

---

## References

- MITRE ATT&CK T1070.003 – Indicator Removal on Host: Clear Command History
- Microsoft Defender XDR Advanced Hunting Documentation

---

## Author

**Raunak Sahu**
