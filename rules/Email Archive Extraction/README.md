# Email Archive Extraction

## Overview

This detection rule identifies ZIP and RAR email attachments that were successfully delivered to a user and subsequently accessed on an endpoint through common archive extraction utilities. By correlating email telemetry with endpoint file activity, the rule helps identify phishing campaigns that use compressed attachments to deliver malware or other malicious payloads.

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Initial Access |
| Technique | T1566.001 – Spearphishing Attachment |

## Data Sources

- EmailAttachmentInfo
- EmailEvents
- DeviceFileEvents

## Detection Logic

The rule performs the following actions:

1. Identifies email attachments with a **ZIP** or **RAR** file type.
2. Filters for emails that were successfully delivered (not blocked).
3. Correlates the attachment SHA256 hash with endpoint file activity.
4. Confirms that the file was processed by a common archive extraction utility such as:
   - 7z.exe
   - 7za.exe
   - 7zfm.exe
   - WinRAR (winrar.exe)
   - WinZip (winzip64.exe)
   - unzip.exe

## Severity

**Medium**

## Frequency

Every 30 minutes

## Lookback

1 hour

## Investigation Guidance

When the rule generates an alert:

1. Verify whether the sender is trusted.
2. Review the email subject and message context.
3. Inspect the extracted archive contents.
4. Determine whether any executable or script files were extracted.
5. Review process creation events immediately following the extraction.
6. Investigate any subsequent network connections or persistence activity.
7. Isolate the endpoint if malicious activity is confirmed.

## False Positives

The following activities may legitimately trigger this detection:

- Internal users exchanging ZIP or RAR files
- Software or driver packages delivered through email
- Password-protected archives shared for business purposes
- Automated software distribution or IT operations

## Tuning Recommendations

- Exclude trusted internal senders where appropriate.
- Exclude approved software distribution mailboxes.
- Correlate with child process execution from the extracted directory.
- Increase fidelity by alerting only when extracted files include executable content such as:
  - `.exe`
  - `.dll`
  - `.ps1`
  - `.js`
  - `.vbs`
  - `.bat`
  - `.cmd`
  - `.scr`
  - `.lnk`
  - `.iso`

## References

- MITRE ATT&CK T1566.001 – Spearphishing Attachment
- Microsoft Defender XDR Advanced Hunting Documentation
- Microsoft Defender for Office 365 Email Telemetry Documentation

## Author

**Raunak Sahu**
