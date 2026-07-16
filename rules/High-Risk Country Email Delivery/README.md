# High-Risk Country Email Delivery

## Overview

This detection rule identifies inbound emails delivered from sender IP addresses geolocated to a predefined list of high-risk countries. Although the sender's geographic location does not by itself indicate malicious activity, emails originating from high-risk regions may warrant additional investigation, particularly when associated with phishing campaigns, malware delivery, or other suspicious indicators.

The rule focuses on emails that were delivered to recipients and not quarantined by email security controls.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Initial Access |
| Technique | T1566 – Phishing |

---

## Data Sources

- EmailEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors inbound email messages.
2. Determines the sender's country using IP geolocation.
3. Excludes emails quarantined by security controls.
4. Filters emails originating from a predefined list of high-risk countries:
   - Iran
   - Ukraine
   - Cuba
   - North Korea
   - Russia
   - Syria
   - Sudan
   - Venezuela
   - Belarus
   - Myanmar
   - Nicaragua
5. Summarizes matching events for investigation.

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

1. Review the sender's reputation and historical communication patterns.
2. Examine the email subject, body, attachments, and embedded URLs.
3. Verify whether the sender is expected or trusted.
4. Determine whether Microsoft identified any phishing or malware indicators.
5. Check whether multiple recipients received similar messages.
6. Review user interaction with the email, including URL clicks or attachment access.
7. Correlate with email authentication results (SPF, DKIM, DMARC) if available.
8. Quarantine or remove the message if confirmed malicious.

---

## False Positives

Potential legitimate triggers include:

- International business communications
- Customers or partners in listed countries
- Security testing
- Cloud-hosted email infrastructure

---

## Tuning Recommendations

- Tailor the monitored country list to your organization's threat model and business operations.
- Correlate with:
  - Safe Links and Safe Attachments alerts
  - Email authentication failures
  - Threat intelligence
  - User click telemetry
  - Attachment detonation results
- Prioritize:
  - Known malicious senders
  - Multiple recipients
  - Credential harvesting content
  - Malware attachments

---

## Limitations

Geolocation is an indicator rather than proof of malicious intent. Attackers may relay email through infrastructure in other countries, while legitimate organizations may use cloud providers or mail gateways located in regions included in the monitored list. This rule should therefore be used alongside additional email security signals.

---

## References

- MITRE ATT&CK T1566 – Phishing
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft Defender for Office 365 Documentation

---

## Author

**Raunak Sahu**
