# Suspicious IIS Web Root File Modification

## Overview

This detection rule identifies file creation, modification, deletion, or renaming within the default Microsoft IIS web root (`C:\inetpub\wwwroot`) performed by non-system accounts. Unauthorized changes to web content are commonly associated with web shell deployment, website defacement, or post-exploitation activity following the compromise of an IIS server.

By excluding common development tools and focusing on modifications performed by non-system users, the rule helps identify suspicious changes requiring further investigation.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Persistence & Defense Evasion |
| Technique | T1505.003 – Web Shell |

---

## Data Sources

- DeviceFileEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors file creation, modification, deletion, and rename events.
2. Focuses on activity within the default IIS web root:
   - `C:\inetpub\wwwroot\`
3. Excludes activity performed by:
   - SYSTEM accounts
   - Service accounts containing `svc`
4. Excludes common development and deployment tools.
5. Returns remaining events for investigation.

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

1. Verify whether the file modification was part of an approved deployment.
2. Determine whether the modified file is:
   - `.aspx`
   - `.ashx`
   - `.asmx`
   - `.php`
   - `.config`
   - `.dll`
3. Review the initiating process and parent process.
4. Inspect IIS logs for requests to newly created or modified files.
5. Analyze the file hash using threat intelligence sources.
6. Review PowerShell, CMD, and scripting activity preceding the modification.
7. Investigate outbound network connections and persistence mechanisms.
8. Isolate the server if a web shell or malicious modification is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Website deployments
- Application updates
- CI/CD pipelines
- Web administrators
- Microsoft Web Deploy
- IIS maintenance
- Developer activity

---

## Tuning Recommendations

- Exclude approved deployment tools and service accounts.
- Exclude known deployment directories if appropriate.
- Correlate with:
  - IIS logs
  - PowerShell execution
  - Web server child processes
  - Network connections
  - Web shell detections
- Prioritize executable web content (`.aspx`, `.ashx`, `.asmx`) over static files.

---

## Limitations

This rule focuses on the default IIS web root. Organizations hosting web applications in custom directories should update the monitored paths accordingly. Legitimate deployments may also generate alerts if appropriate exclusions are not configured.

---

## References

- MITRE ATT&CK T1505.003 – Web Shell
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft IIS Security Best Practices

---

## Author

**Raunak Sahu**
