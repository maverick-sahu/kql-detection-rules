# Suspicious Deletion of Okta Emails

## Overview

This detection rule identifies Okta-generated emails that are deleted from Microsoft Exchange Online shortly after delivery. Security notifications such as MFA prompts, password reset confirmations, and sign-in alerts are often targeted by attackers attempting to conceal evidence of account compromise from end users.

By correlating email delivery with subsequent mailbox deletion events, the rule provides high-confidence detection of suspicious mailbox tampering.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Defense Evasion & Credential Access |
| Technique | T1070.008 – Indicator Removal on Host: Clear Mailbox Data |

---

## Data Sources

- EmailEvents
- CloudAppEvents

---

## Detection Logic

The rule performs the following actions:

1. Identifies emails sent from the `okta.com` domain.
2. Monitors Exchange Online mailbox actions:
   - `SoftDelete`
   - `HardDelete`
   - `MoveToDeletedItems`
3. Extracts the `NetworkMessageId` from Exchange audit telemetry.
4. Correlates deletion events with the original email.
5. Alerts when the deletion occurs within **30 minutes** of email delivery.

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

1. Confirm whether the recipient intentionally deleted the email.
2. Review recent Okta authentication activity for the affected account.
3. Check for password resets, MFA enrollment changes, or new device registrations.
4. Review Exchange mailbox rules for suspicious forwarding or deletion behavior.
5. Investigate the IP address and user agent associated with the mailbox action.
6. Examine additional mailbox deletions involving security-related messages.
7. Review sign-ins from unfamiliar locations or devices.
8. Reset credentials and invalidate active sessions if account compromise is suspected.

---

## False Positives

Potential legitimate triggers include:

- User-initiated mailbox cleanup
- Automated retention policies
- Approved mailbox management solutions
- Help desk testing
- Security awareness exercises

---

## Tuning Recommendations

- Exclude approved mailbox automation and retention processes.
- Correlate with:
  - Okta authentication logs
  - Exchange mailbox rule creation
  - Inbox forwarding rules
  - Impossible travel detections
  - MFA enrollment changes
- Prioritize:
  - Immediate deletion after delivery
  - Multiple deleted Okta notifications
  - Deletions from unfamiliar IP addresses
  - Concurrent suspicious sign-in activity

---

## Limitations

This rule detects deletion of Okta-generated emails in Exchange Online but does not determine whether the deletion was malicious or user initiated. Organizations using automated retention or mailbox management workflows should validate and tune exclusions to minimize false positives.

---

## References

- MITRE ATT&CK T1070.008 – Indicator Removal on Host: Clear Mailbox Data
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft Exchange Online Audit Logging Documentation
- Okta Security Documentation

---

## Author

**Raunak Sahu**
