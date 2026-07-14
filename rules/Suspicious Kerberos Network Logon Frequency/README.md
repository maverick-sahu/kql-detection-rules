# Suspicious Kerberos Network Logon Frequency

## Overview

This detection rule identifies user accounts generating an unusually high number of Kerberos network logons within a short period. While frequent Kerberos authentication can occur during legitimate operations, excessive or unexpected activity may indicate abuse of forged Kerberos service tickets (Silver Tickets), lateral movement, or automated authentication attempts.

This rule is intended as an anomaly detection and should be correlated with additional Kerberos telemetry before confirming malicious activity.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Lateral Movement & Credential Access |
| Technique | T1558.002 – Steal or Forge Kerberos Tickets: Silver Ticket |

---

## Data Sources

- DeviceLogonEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors network logons using the Kerberos protocol.
2. Excludes:
   - Computer accounts ending in `$`
   - Service accounts following the `s-` naming convention
3. Counts Kerberos network logons per user and device.
4. Generates an alert when more than **five** logons occur within the monitoring period.

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

1. Verify whether the account normally authenticates to the affected device at this frequency.
2. Review the services being accessed and determine whether they are expected.
3. Investigate concurrent Kerberos authentication events from the same account.
4. Review recent privilege escalation or credential access activity.
5. Correlate with:
   - Ticket creation events
   - Service ticket requests
   - Lateral movement detections
   - Remote service execution
6. Investigate additional authentication anomalies or suspicious network activity.
7. Isolate affected systems if unauthorized ticket usage is confirmed.

---

## False Positives

Potential legitimate triggers include:

- File servers
- Application servers
- Jump servers
- Backup systems
- Enterprise automation
- Management platforms

---

## Tuning Recommendations

- Increase the threshold on high-traffic servers.
- Exclude approved service and automation accounts.
- Correlate with:
  - Event ID 4769 (Kerberos Service Ticket)
  - Event ID 4624 (Network Logon)
  - Abnormal SPN usage
  - Service ticket lifetime anomalies
  - Unusual authentication patterns
- Prioritize user accounts that do not normally perform frequent network authentication.

---

## Limitations

This rule detects anomalous Kerberos authentication frequency but **does not directly identify forged Silver Tickets**. Legitimate high-volume authentication activity can generate alerts. Additional telemetry, such as Kerberos ticket issuance, service ticket validation, SPN analysis, and endpoint activity, is required to confidently attribute the behavior to a Silver Ticket attack.

---

## References

- MITRE ATT&CK T1558.002 – Steal or Forge Kerberos Tickets: Silver Ticket
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft Kerberos Authentication Documentation

---

## Author

**Raunak Sahu**
