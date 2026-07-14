# Suspicious Kerberos Cache File Access

## Overview

This detection rule identifies the creation or access of Kerberos credential cache (`ccache`) files on macOS from unexpected locations or by non-standard processes. Kerberos cache files store authentication tickets that can be reused to authenticate to network resources without requiring user credentials.

Attackers frequently target these files to steal valid Kerberos tickets, enabling lateral movement, privilege escalation, and unauthorized access across enterprise environments.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Credential Access |
| Technique | T1558 – Steal or Forge Kerberos Tickets |

---

## Data Sources

- DeviceFileEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors file events involving Kerberos cache files:
   - `krb5cc_<UID>`
   - `*.ccache`
2. Detects:
   - File creation
   - File access
   - File read
3. Excludes:
   - `root` and `system` accounts
   - Standard user cache locations:
     - `/tmp`
     - `/var/folders`
     - `/Users`
   - Approved Python developer tooling
   - Common Kerberos utilities:
     - `kinit`
     - `login`
     - `sudo`
     - `ssh`
4. Returns file and process metadata for investigation.

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

1. Determine whether the Kerberos cache file location is expected.
2. Review the initiating process and verify whether it is trusted.
3. Identify whether the process is Microsoft- or Apple-signed (where applicable).
4. Review recent Kerberos authentication activity.
5. Investigate SSH sessions, remote logons, and lateral movement.
6. Review outbound network connections following cache access.
7. Search for credential dumping or ticket manipulation activity.
8. Isolate the endpoint if unauthorized Kerberos cache access is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Kerberos administration
- Enterprise identity management software
- Approved developer tools
- Authentication troubleshooting
- Security products

---

## Tuning Recommendations

- Exclude approved Kerberos management utilities.
- Correlate with:
  - `kinit` execution
  - SSH activity
  - Ticket renewal events
  - Remote authentication
  - Lateral movement detections
- Prioritize:
  - Unsigned binaries
  - Access outside normal user paths
  - Recently executed processes
  - Repeated access to multiple cache files

---

## Limitations

This rule detects access to Kerberos cache files but does not confirm successful extraction or reuse of Kerberos tickets. Organizations should correlate these events with authentication telemetry and lateral movement activity for higher confidence.

---

## References

- MITRE ATT&CK T1558 – Steal or Forge Kerberos Tickets
- Microsoft Defender XDR Advanced Hunting Documentation
- MIT Kerberos Documentation
- Apple Platform Security Documentation

---

## Author

**Raunak Sahu**
