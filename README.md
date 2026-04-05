# KQL Detection Rules Library

![Rules](https://img.shields.io/badge/rules-17-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red)
![Platform](https://img.shields.io/badge/platform-Microsoft%20Sentinel%20%7C%20QRadar%20%7C%20Defender-informational)
![Maintained](https://img.shields.io/badge/maintained-yes-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

> Production-ready KQL detection rules for Microsoft Sentinel, mapped to MITRE ATT&CK. Built from 4.5 years of enterprise detection work at Deloitte USI — written for real SOC environments, not CTF labs.

---

## Why this repo

Most public detection rule libraries are written for lab environments. These rules come from production — tuned against real enterprise telemetry, validated with historical log testing, and refined through false positive feedback in 24/7 MXDR operations.

Every rule in this library includes:
- **Tuning notes** — what creates false positives and how to suppress them
- **MITRE mapping** — tactic, technique, and sub-technique IDs
- **Alert detail strings** — pre-formatted context for SOC analysts triaging the alert
- **Response guidance** — linked IR playbook where applicable

---

## Platform compatibility

| Rule | Sentinel (KQL) | QRadar (AQL) | Splunk (SPL) | Defender (MDE) |
|------|:-:|:-:|:-:|:-:|
| Impossible travel | ✅ | Adaptable | Adaptable | — |
| Password spray | ✅ | Adaptable | Adaptable | — |
| Web session cookie theft | ✅ | — | — | ✅ |
| PowerShell encoded command | ✅ | — | Adaptable | ✅ |
| Defender tampering | ✅ | — | — | ✅ |
| DNS tunneling | ✅ | Adaptable | Adaptable | — |

> Rules marked "Adaptable" use standard log fields that translate across platforms with minor syntax changes. AQL and SPL variants are on the roadmap — see [Contributing](#contributing--roadmap).

---

## Repository structure

```
kql-detection-rules/
├── rules/
│   ├── initial-access/         # T1078, T1566 etc.
│   ├── execution/              # T1059, T1204 etc.
│   ├── persistence/            # T1053, T1547 etc.
│   ├── defense-evasion/        # T1070, T1218, T1562 etc.
│   ├── credential-access/      # T1539, T1110, T1003 etc.
│   ├── lateral-movement/       # T1021, T1550 etc.
│   └── exfiltration/           # T1041, T1048 etc.
├── playbooks/                  # IR playbooks linked to rules
└── docs/
    ├── MITRE_COVERAGE.md       # ATT&CK coverage map + Navigator JSON
    └── RULE_TEMPLATE.md        # Template for new rules
```

---

## Coverage summary

| Tactic | Rules | Key Techniques |
|--------|:-----:|----------------|
| Initial Access | 3 | T1078, T1566.001 |
| Execution | 2 | T1059.001, T1204.002 |
| Persistence | 2 | T1053.005, T1547.001 |
| Defense Evasion | 3 | T1070.004, T1218.011, T1562.001 |
| Credential Access | 3 | T1539, T1110.003, T1003.001 |
| Lateral Movement | 2 | T1021.001, T1550.002 |
| Exfiltration | 2 | T1041, T1048.003 |
| **Total** | **17** | **16 techniques across 7 tactics** |

Full ATT&CK Navigator layer (importable JSON) → [docs/MITRE_COVERAGE.md](docs/MITRE_COVERAGE.md)

---

## Rule index

### Initial Access
| File | Technique | Description |
|------|-----------|-------------|
| [impossible-travel.kql](rules/initial-access/impossible-travel.kql) | T1078 – Valid Accounts | Logins from geographically impossible locations within a rolling window |
| [phishing-attachment-execution.kql](rules/initial-access/phishing-attachment-execution.kql) | T1566.001 – Spearphishing Attachment | Office application spawning shells or scripting engines |
| [successful-login-after-bruteforce.kql](rules/initial-access/successful-login-after-bruteforce.kql) | T1078 – Valid Accounts | Successful authentication following repeated failures from same source |

### Execution
| File | Technique | Description |
|------|-----------|-------------|
| [powershell-encoded-command.kql](rules/execution/powershell-encoded-command.kql) | T1059.001 – PowerShell | Encoded, obfuscated, or AMSI-bypass PowerShell — scored by risk level |
| [malicious-office-macro.kql](rules/execution/malicious-office-macro.kql) | T1204.002 – Malicious File | Office apps spawning suspicious child processes |

### Persistence
| File | Technique | Description |
|------|-----------|-------------|
| [scheduled-task-creation.kql](rules/persistence/scheduled-task-creation.kql) | T1053.005 – Scheduled Task | Suspicious scheduled task creation via command line |
| [registry-run-key-modification.kql](rules/persistence/registry-run-key-modification.kql) | T1547.001 – Registry Run Keys | Autorun registry key modification by non-system processes |

### Defense Evasion
| File | Technique | Description |
|------|-----------|-------------|
| [log-clearing.kql](rules/defense-evasion/log-clearing.kql) | T1070.004 – File Deletion | Windows event log clearing — pre-ransomware indicator |
| [lolbas-execution.kql](rules/defense-evasion/lolbas-execution.kql) | T1218.011 – Rundll32 | Living-off-the-land binary abuse for proxy execution |
| [defender-tampering.kql](rules/defense-evasion/defender-tampering.kql) | T1562.001 – Impair Defenses | Microsoft Defender disabling via PowerShell, sc.exe, or registry |

### Credential Access
| File | Technique | Description |
|------|-----------|-------------|
| [web-session-cookie-theft.kql](rules/credential-access/web-session-cookie-theft.kql) | T1539 – Steal Web Session Cookie | Non-browser processes accessing browser cookie stores |
| [password-spray.kql](rules/credential-access/password-spray.kql) | T1110.003 – Password Spraying | Low-and-slow spray pattern — one IP, many accounts, few attempts each |
| [lsass-access.kql](rules/credential-access/lsass-access.kql) | T1003.001 – LSASS Memory | Credential dumping via LSASS process access |

### Lateral Movement
| File | Technique | Description |
|------|-----------|-------------|
| [rdp-lateral-movement.kql](rules/lateral-movement/rdp-lateral-movement.kql) | T1021.001 – Remote Desktop Protocol | Unusual RDP connections between internal endpoints |
| [pass-the-hash.kql](rules/lateral-movement/pass-the-hash.kql) | T1550.002 – Pass the Hash | NTLM lateral movement pattern detection |

### Exfiltration
| File | Technique | Description |
|------|-----------|-------------|
| [large-upload-to-external.kql](rules/exfiltration/large-upload-to-external.kql) | T1048.003 – Exfiltration Over Unencrypted Protocol | Unusual large outbound data transfers to external destinations |
| [dns-tunneling.kql](rules/exfiltration/dns-tunneling.kql) | T1041 – Exfiltration Over C2 Channel | Long subdomains, high query volume, and TCP DNS as tunneling indicators |

---

## How rules are tested

Every rule goes through the following validation steps before being published:

**1. Historical log testing** — rules are run against historical SIEM data to validate they fire on known-malicious activity and surface false positive sources before tuning begins.

**2. Threshold and logic tuning** — suppression logic, parameter refinement, and layered conditions are applied to reduce operational noise. Target false positive rate is documented in each rule's tuning notes.

**3. UAT in staging** — rules are validated in a staging environment with peer review before promotion to production, mirroring the UAT process used in enterprise MXDR operations.

**4. Alert detail review** — the `AlertDetail` field in every rule is reviewed to ensure a SOC analyst has enough context to triage without opening a second tool.

---

## Rule header format

Every rule file uses this standard header so you know exactly what you're deploying:

```
// Rule Name      : [Descriptive name]
// MITRE Tactic   : [Tactic]
// MITRE Technique: [TID.SubID] – [Name]
// Severity       : Critical / High / Medium / Low
// Data Sources   : [Tables used]
// Frequency      : Every X hour(s)
// Lookback       : X hour(s)
// False Positives: [Known FP sources and mitigation]
// Author         : Raunak Sahu
// Last Updated   : [YYYY-MM-DD]
```

---

## How to deploy in Microsoft Sentinel

1. Go to **Microsoft Sentinel → Analytics → Create → Scheduled query rule**
2. Copy the KQL from any `.kql` file in this repo
3. Set the **rule frequency** and **lookback window** as specified in the rule header
4. Review the **tuning notes** before deploying to production
5. Set **entity mapping** fields (AccountName, DeviceName, IPAddress) for alert enrichment
6. Enable **alert grouping** to reduce ticket noise on high-frequency rules

---

## Recently added

| Date | Rule | Technique |
|------|------|-----------|
| 2025-06-01 | [dns-tunneling.kql](rules/exfiltration/dns-tunneling.kql) | T1041 – DNS exfiltration |
| 2025-06-01 | [defender-tampering.kql](rules/defense-evasion/defender-tampering.kql) | T1562.001 – Impair defenses |
| 2025-06-01 | [web-session-cookie-theft.kql](rules/credential-access/web-session-cookie-theft.kql) | T1539 – Cookie theft |
| 2025-06-01 | [password-spray.kql](rules/credential-access/password-spray.kql) | T1110.003 – Password spray |
| 2025-06-01 | [powershell-encoded-command.kql](rules/execution/powershell-encoded-command.kql) | T1059.001 – PowerShell |
| 2025-06-01 | [impossible-travel.kql](rules/initial-access/impossible-travel.kql) | T1078 – Valid accounts |

---

## Contributing / Roadmap

Planned rules — contributions welcome:

- [ ] `credential-access/kerberoasting.kql` — T1558.003
- [ ] `lateral-movement/smb-admin-shares.kql` — T1021.002
- [ ] `persistence/account-creation.kql` — T1136.001
- [ ] `execution/windows-command-shell.kql` — T1059.003
- [ ] `defense-evasion/masquerading.kql` — T1036
- [ ] AQL variants for QRadar
- [ ] SPL variants for Splunk

To contribute, use the template at [docs/RULE_TEMPLATE.md](docs/RULE_TEMPLATE.md) and open a pull request. Please include tuning notes and at least one known false positive source.

---

## Related resources

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — import the JSON from [docs/MITRE_COVERAGE.md](docs/MITRE_COVERAGE.md)
- [Sigma Rules Project](https://github.com/SigmaHQ/sigma) — platform-agnostic detection rules
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — adversary emulation for rule validation
- [KQL Reference](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/) — Microsoft KQL documentation

---

## Author

**Raunak Sahu**
Detection Engineer | Blue Team | 4.5 years at Deloitte USI

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin)](https://linkedin.com/in/raunak-sahu-95a10b171)

Open to Detection Engineer and Threat Hunter roles — US remote or relocation.

---

## License

MIT — free to use, adapt, and share. Attribution appreciated.
