# Suspicious Process Detection

## Detection Overview

This detection identifies execution of commonly abused Windows utilities (LOLBins) that attackers frequently use to execute malicious code while blending into legitimate system activity.

---

# Detection Name

Suspicious Process Execution

---

# Severity

**High**

Increase to **Critical** if:

- Executed with High/System integrity
- Spawned from Microsoft Office applications
- Initiates external network connections
- Modifies registry keys
- Launches additional suspicious processes

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---------|-----------|----|
| Defense Evasion | System Binary Proxy Execution | T1218 |
| Execution | Command and Scripting Interpreter | T1059 |

---

# Data Source

- Microsoft Sysmon
- Event ID 1

---

# SPL Detection Logic

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
(Image="*powershell.exe" OR Image="*cmd.exe" OR Image="*rundll32.exe" OR Image="*regsvr32.exe" OR Image="*mshta.exe" OR Image="*certutil.exe" OR Image="*wmic.exe")
| table _time User Image ParentImage CommandLine
| sort -_time
```

---

# Why This Detection Matters

Attackers frequently abuse trusted Windows binaries to:

- Execute malicious code
- Bypass application controls
- Download payloads
- Maintain persistence
- Evade detection

---

# Investigation Steps

1. Identify the executed binary.
2. Review the parent process.
3. Inspect command-line arguments.
4. Check for network activity.
5. Review registry modifications.
6. Investigate child processes.

---

# Possible False Positives

- System administrators
- IT automation scripts
- Software deployment tools
- Enterprise management software

---

# Analyst Response

- Validate business justification.
- Review related Sysmon events.
- Escalate if malicious behavior is confirmed.

---

# Related Dashboard Panel

Suspicious Process Detection
