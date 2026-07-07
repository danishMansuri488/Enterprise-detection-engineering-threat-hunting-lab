# High Integrity Process Monitoring

## Overview

High Integrity processes execute with elevated privileges and have greater access to system resources. Monitoring these processes helps identify administrative activity, privilege escalation, and potentially malicious execution with elevated permissions.

---

# Detection Objective

Monitor processes running with elevated integrity levels to identify:

- Administrator activity
- Privilege escalation
- Elevated PowerShell execution
- Elevated Command Prompt execution
- Unauthorized administrative tools
- High-risk process execution

---

# Data Source

| Source | Value |
|---------|-------|
| Event Source | Microsoft-Windows-Sysmon |
| Event ID | 1 |
| Log Source | XmlWinEventLog:Microsoft-Windows-Sysmon/Operational |

---

# SPL Query

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 IntegrityLevel=High OR IntegrityLevel=System
| table _time User IntegrityLevel Image ParentImage CommandLine
| sort -_time
```

---

# Query Explanation

| Field | Description |
|---------|-------------|
| _time | Event timestamp |
| User | User executing the process |
| IntegrityLevel | Privilege level |
| Image | Executed process |
| ParentImage | Parent process |
| CommandLine | Full command-line arguments |

---

# Security Use Cases

- Detect elevated PowerShell sessions
- Detect elevated Command Prompt usage
- Monitor administrative activity
- Investigate privilege escalation
- Identify suspicious elevated tools

---

# Example Detections

Legitimate

```
Administrator
 └── powershell.exe
```

```
Administrator
 └── cmd.exe
```

Suspicious

```
User
 └── powershell.exe (High)
```

```
Unknown User
 └── rundll32.exe (System)
```

```
Normal User
 └── reg.exe (High)
```

---

# MITRE ATT&CK Mapping

| Technique | ID |
|------------|----|
| Abuse Elevation Control Mechanism | T1548 |
| Command and Scripting Interpreter | T1059 |
| Privilege Escalation | TA0004 |

---

# Investigation Tips

During investigation, verify:

- Was elevated execution expected?
- Which parent process launched it?
- Which user executed it?
- Did the process create network connections?
- Did it modify the registry?
- Did additional suspicious child processes appear?

---

# Dashboard Panel

This query powers the following dashboard panel:

- High Integrity Process Monitoring
