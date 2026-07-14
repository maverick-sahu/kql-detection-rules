# Suspicious Python Script Execution from Downloads

## Overview

This detection rule identifies Python scripts executed directly from the user's **Downloads** directory. It focuses on scenarios where the Python interpreter is launched after a file is obtained through a web browser, Microsoft Outlook, or Microsoft Office application and executed through a command shell or scripting engine.

Attackers frequently distribute Python-based malware as downloaded scripts that users execute manually or through social engineering. Executing Python code from user-writable directories is uncommon in most enterprise environments and should be investigated.

---

## MITRE ATT&CK

| Category | Mapping |
|----------|---------|
| Tactic | Execution |
| Technique | T1059.006 – Command and Scripting Interpreter: Python |

---

## Data Sources

- DeviceProcessEvents

---

## Detection Logic

The rule performs the following actions:

1. Monitors execution of Python interpreters.
2. Detects command lines referencing:
   - `.py`
   - `.pyc`
3. Restricts execution to scripts located in the user's **Downloads** directory.
4. Requires the initiating process to be:
   - Google Chrome
   - Microsoft Edge
   - Mozilla Firefox
   - Microsoft Outlook
   - Microsoft Word
   - Microsoft Excel
5. Requires the parent process to be:
   - `cmd.exe`
   - `powershell.exe`
   - `wscript.exe`
   - `csscript.exe`
6. Returns execution details for investigation.

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

## Expected Output

The query returns:

- Timestamp
- Device Name
- Device ID
- Account Name
- Python Executable
- Folder Path
- Process Command Line
- Initiating Process
- Parent Process
- SHA256
- Report ID

---

## Investigation Guidance

When this rule generates an alert:

1. Determine whether the Python script was expected.
2. Review the downloaded file and its origin.
3. Inspect the complete process tree.
4. Verify whether the Python executable is trusted.
5. Analyze the executed script using threat intelligence and sandboxing.
6. Review outbound network connections following execution.
7. Check for persistence mechanisms or additional payload downloads.
8. Isolate the endpoint if malicious activity is confirmed.

---

## False Positives

Potential legitimate triggers include:

- Software developers
- Data science and automation environments
- Internal Python applications
- Approved administrative scripts
- Enterprise automation tools

---

## Tuning Recommendations

- Exclude developer workstations and approved automation environments.
- Correlate with:
  - Browser download events
  - File creation in Downloads
  - PowerShell or CMD activity
  - Network connections
  - Persistence detections
- Prioritize:
  - Unsigned Python executables
  - Scripts downloaded from the Internet
  - Recently created files
  - User-writable execution paths

---

## Limitations

This rule focuses on Python scripts executed from the **Downloads** directory. It does not detect Python scripts executed from other user-writable locations or embedded Python interpreters within packaged applications.

---

## References

- MITRE ATT&CK T1059.006 – Command and Scripting Interpreter: Python
- Microsoft Defender XDR Advanced Hunting Documentation
- Python Security Best Practices

---

## Author

**Raunak Sahu**
