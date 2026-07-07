# PowerShell Execution Detection

## Detection Overview

This detection monitors PowerShell process execution using Sysmon Event ID 1. PowerShell is a legitimate administrative tool but is frequently abused by attackers for malware execution, reconnaissance, persistence, privilege escalation, and lateral movement.

---

# Detection Name

PowerShell Process Execution

---

# Severity

**Medium**

Increase to **High** if:

- Encoded commands are used
- Executed with High/System integrity
- Spawned from Microsoft Office applications
- Connects to external IP addresses
- Launches additional suspicious processes

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---------|-----------|----|
| Execution | PowerShell | T1059.001 |

---

# Data Source

- Microsoft Sysmon
- Event ID 1

---

# SPL Detection Logic

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 Image="*powershell.exe"
| table _time User ParentImage CommandLine IntegrityLevel
| sort -_time
```

---

# Why This Detection Matters

PowerShell is commonly abused by threat actors because it is:

- Installed by default
- Trusted by Windows
- Capable of downloading malware
- Able to execute scripts in memory
- Frequently used in fileless attacks

---

# Investigation Steps

1. Identify the user.
2. Review the parent process.
3. Inspect the full command line.
4. Check integrity level.
5. Review network activity.
6. Investigate child processes.

---

# Possible False Positives

- System administrators
- IT automation
- PowerShell maintenance scripts
- Software deployment tools

---

# Analyst Response

- Validate business justification.
- Review command-line arguments.
- Investigate related Sysmon events.
- Escalate if malicious behavior is confirmed.

---

# Related Dashboard Panel

PowerShell Execution Monitoring
