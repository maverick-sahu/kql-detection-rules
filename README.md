# KQL Detection Rules – Microsoft Defender XDR

![Rules](https://img.shields.io/badge/rules-8-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red)
![Platform](https://img.shields.io/badge/platform-Microsoft%20Defender%20XDR-informational)
![Tables](https://img.shields.io/badge/tables-MDE%20Advanced%20Hunting-blueviolet)
![Maintained](https://img.shields.io/badge/maintained-yes-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

> Production-ready KQL detection rules for **Microsoft Defender XDR Advanced Hunting**. Built from 4.5 years of enterprise detection work at Deloitte USI — written for real SOC environments, not CTF labs.

---

## Platform

All rules in this repo run in:

**Microsoft Defender XDR → Hunting → Advanced Hunting**

No Microsoft Sentinel license required. These queries use native MDE tables available to any organisation with Microsoft Defender for Endpoint Plan 2 or Microsoft 365 Defender.

---

## MDE tables used

| Table | What it covers |
|-------|---------------|
| `DeviceProcessEvents` | Process creation, command lines, parent-child relationships |
| `DeviceFileEvents` | File read, write, create, delete |
| `DeviceNetworkEvents` | Outbound/inbound connections, bytes transferred |
| `DeviceRegistryEvents` | Registry key and value changes |
| `DeviceLogonEvents` | Interactive, remote, and service logons |
| `DeviceImageLoadEvents` | DLL/module loads into processes |
| `IdentityLogonEvents` | Azure AD / Entra ID sign-in events (Defender for Identity) |

---

## Why this repo

Most public detection rule libraries target Sentinel or are written for lab environments. These rules come from production — tuned against real enterprise telemetry across CrowdStrike and MDE stacks, validated with historical log testing, and refined through false positive feedback loops in 24/7 MXDR operations.

Every rule includes:
- **Tuning notes** — what creates false positives and how to suppress them
- **MITRE mapping** — tactic, technique, and sub-technique IDs
- **Risk scoring** — where applicable, rules assign a score rather than a binary alert, reducing noise
- **Alert detail strings** — pre-formatted context for SOC analysts triaging in the MDE incident queue
- **Threat actor references** — real-world groups observed using each technique

---

## Repository structure

```
kql-detection-rules/
├── rules/
│   ├── initial-access/         # T1078, T1566 etc.
│   ├── execution/              # T1059, T1204 etc.
│   ├── persistence/            # T1053, T1547 etc.
│   ├── defense-evasion/        # T1562 etc.
│   ├── credential-access/      # T1539, T1003 etc.
│   ├── lateral-movement/       # T1021 etc.
│   └── exfiltration/           # T1048 etc.
├── playbooks/                  # IR response playbooks linked to rules
└── docs/
    ├── MITRE_COVERAGE.md       # ATT&CK coverage map + Navigator JSON
    └── RULE_TEMPLATE.md        # Standard template for new rules
```

---

## Coverage summary

| Tactic | Rules | Techniques Covered |
|--------|:-----:|--------------------|
| Initial Access | 1 | T1078 |
| Execution | 2 | T1059.001, T1204.002 |
| Persistence | 1 | T1053.005 |
| Defense Evasion | 1 | T1562.001 |
| Credential Access | 2 | T1539, T1003.001 |
| Lateral Movement | 1 | T1021.001 |
| Exfiltration | 1 | T1048.003 |
| **Total** | **9** | **9 techniques across 7 tactics** |

Full ATT&CK Navigator layer → [docs/MITRE_COVERAGE.md](docs/MITRE_COVERAGE.md)

---

## Rule index

### Initial Access
| File | Technique | Severity | MDE Tables |
|------|-----------|:--------:|-----------|
| [impossible-travel.kql](rules/initial-access/impossible-travel.kql) | T1078 – Valid Accounts | High | `IdentityLogonEvents` |

### Execution
| File | Technique | Severity | MDE Tables |
|------|-----------|:--------:|-----------|
| [powershell-encoded-command.kql](rules/execution/powershell-encoded-command.kql) | T1059.001 – PowerShell | High–Critical | `DeviceProcessEvents` |
| [malicious-office-macro.kql](rules/execution/malicious-office-macro.kql) | T1204.002 – Malicious File | High–Critical | `DeviceProcessEvents` |

### Persistence
| File | Technique | Severity | MDE Tables |
|------|-----------|:--------:|-----------|
| [scheduled-task-creation.kql](rules/persistence/scheduled-task-creation.kql) | T1053.005 – Scheduled Task | Medium–High | `DeviceProcessEvents`, `DeviceRegistryEvents` |

### Defense Evasion
| File | Technique | Severity | MDE Tables |
|------|-----------|:--------:|-----------|
| [defender-tampering.kql](rules/defense-evasion/defender-tampering.kql) | T1562.001 – Impair Defenses | High | `DeviceProcessEvents`, `DeviceRegistryEvents` |

### Credential Access
| File | Technique | Severity | MDE Tables |
|------|-----------|:--------:|-----------|
| [web-session-cookie-theft.kql](rules/credential-access/web-session-cookie-theft.kql) | T1539 – Steal Web Session Cookie | High–Critical | `DeviceFileEvents`, `DeviceNetworkEvents` |
| [lsass-access.kql](rules/credential-access/lsass-access.kql) | T1003.001 – LSASS Memory | Critical | `DeviceProcessEvents`, `DeviceFileEvents` |

### Lateral Movement
| File | Technique | Severity | MDE Tables |
|------|-----------|:--------:|-----------|
| [rdp-lateral-movement.kql](rules/lateral-movement/rdp-lateral-movement.kql) | T1021.001 – Remote Desktop Protocol | Medium–High | `DeviceLogonEvents`, `DeviceNetworkEvents` |

### Exfiltration
| File | Technique | Severity | MDE Tables |
|------|-----------|:--------:|-----------|
| [large-upload-to-external.kql](rules/exfiltration/large-upload-to-external.kql) | T1048.003 – Exfiltration Over Alt Protocol | Medium–High | `DeviceNetworkEvents` |

---

## How rules are tested

Every rule goes through this validation process before being published:

**1. Historical log testing** — queries are run against historical MDE Advanced Hunting data to confirm they fire on known-malicious activity and surface false positive sources.

**2. Risk scoring and threshold tuning** — where applicable, rules use a scoring model rather than a binary match. This reduces noise significantly compared to simple string-match rules.

**3. UAT in staging** — rules are peer-reviewed and validated against staging data before production deployment, mirroring the UAT process used in enterprise MXDR operations.

**4. Alert detail review** — the `AlertDetail` field in every rule is written to give a SOC analyst enough context to make a triage decision without opening a second tool.

---

## Rule header format

Every `.kql` file uses this standard header:

```
// Rule Name      : [Descriptive name]
// MITRE Tactic   : [Tactic]
// MITRE Technique: [TID.SubID] – [Name]
// Severity       : Critical / High / Medium / Low
// Data Sources   : [MDE tables used]
// Platform       : Microsoft Defender XDR → Advanced Hunting
// Frequency      : Every X hour(s)
// Lookback       : X hour(s)
// False Positives: [Known FP sources and mitigation]
// Author         : Raunak Sahu
// Last Updated   : [YYYY-MM-DD]
```

---

## How to run in Microsoft Defender XDR

1. Go to **Microsoft Defender XDR → Hunting → Advanced Hunting**
2. Copy the KQL from any `.kql` file in this repo into the query editor
3. Adjust the `ago()` lookback window as needed
4. Review the **tuning notes** in the file header before using in production
5. To schedule as a custom detection: **Create detection rule** → set frequency and action (alert / isolate device / etc.)
6. Map entity fields (DeviceName, AccountName, RemoteIP) for enriched alert cards

---

## Recently added

| Date | Rule | Technique |
|------|------|-----------|
| 2025-06-01 | [lsass-access.kql](rules/credential-access/lsass-access.kql) | T1003.001 – LSASS dump |
| 2025-06-01 | [web-session-cookie-theft.kql](rules/credential-access/web-session-cookie-theft.kql) | T1539 – Cookie theft |
| 2025-06-01 | [large-upload-to-external.kql](rules/exfiltration/large-upload-to-external.kql) | T1048.003 – Exfiltration |
| 2025-06-01 | [rdp-lateral-movement.kql](rules/lateral-movement/rdp-lateral-movement.kql) | T1021.001 – RDP lateral movement |
| 2025-06-01 | [defender-tampering.kql](rules/defense-evasion/defender-tampering.kql) | T1562.001 – Defender disable |
| 2025-06-01 | [powershell-encoded-command.kql](rules/execution/powershell-encoded-command.kql) | T1059.001 – PowerShell |
| 2025-06-01 | [malicious-office-macro.kql](rules/execution/malicious-office-macro.kql) | T1204.002 – Office macro |
| 2025-06-01 | [scheduled-task-creation.kql](rules/persistence/scheduled-task-creation.kql) | T1053.005 – Scheduled task |

---

## Contributing / Roadmap

Planned rules — all targeting MDE Advanced Hunting tables:

- [ ] `credential-access/password-spray.kql` — T1110.003 via `IdentityLogonEvents`
- [ ] `credential-access/kerberoasting.kql` — T1558.003 via `IdentityLogonEvents`
- [ ] `lateral-movement/pass-the-hash.kql` — T1550.002 via `DeviceLogonEvents`
- [ ] `persistence/registry-run-key.kql` — T1547.001 via `DeviceRegistryEvents`
- [ ] `defense-evasion/lolbas-execution.kql` — T1218 via `DeviceProcessEvents`
- [ ] `defense-evasion/log-clearing.kql` — T1070.004 via `DeviceProcessEvents`
- [ ] `exfiltration/staging-compression.kql` — T1560.001 via `DeviceProcessEvents` + `DeviceFileEvents`

To contribute, use the template at [docs/RULE_TEMPLATE.md](docs/RULE_TEMPLATE.md) and open a pull request. Please include tuning notes, known false positive sources, and the specific MDE tables your rule uses.

---

## Related resources

- [MDE Advanced Hunting schema reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-schema-tables)
- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — import JSON from [docs/MITRE_COVERAGE.md](docs/MITRE_COVERAGE.md)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — emulate TTPs to validate rules
- [MDE Custom Detection Docs](https://learn.microsoft.com/en-us/microsoft-365/security/defender/custom-detection-rules)

---

## Author

**Raunak Sahu**
Detection Engineer | Blue Team | 4.5 years at Deloitte USI

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin)](https://linkedin.com/in/raunak-sahu-95a10b171)

Open to Detection Engineer and Threat Hunter roles — US remote or relocation.

---

## License

MIT — free to use, adapt, and share. Attribution appreciated.
