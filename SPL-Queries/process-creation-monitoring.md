# Process Creation Monitoring (Sysmon Event ID 1)

## Overview

Sysmon Event ID 1 records every new process created on the monitored endpoint. This event is one of the most valuable telemetry sources for threat hunting, malware analysis, and incident response because almost every attack begins by launching a process.

---

# Detection Objective

Monitor all newly created processes and identify:

- Suspicious executables
- Administrative tools
- Living-off-the-Land Binaries (LOLBins)
- PowerShell execution
- Command Prompt activity
- Parent-child process relationships
- Privilege level of executed processes

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
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| table _time Image ParentImage CommandLine User ProcessId IntegrityLevel
| sort -_time
```

---

# Query Explanation

| Field | Description |
|---------|-------------|
| _time | Event timestamp |
| Image | Executed process |
| ParentImage | Parent process that launched it |
| CommandLine | Full command-line arguments |
| User | User who executed the process |
| ProcessId | Process identifier |
| IntegrityLevel | Process privilege level |

---

# Security Use Cases

- Detect malware execution
- Monitor PowerShell usage
- Detect Command Prompt execution
- Investigate parent-child relationships
- Detect privilege escalation
- Identify unauthorized tools

---

# Example Detections

Legitimate

```
explorer.exe
 └── notepad.exe
```

Suspicious

```
winword.exe
 └── powershell.exe
```

```
excel.exe
 └── cmd.exe
```

```
outlook.exe
 └── rundll32.exe
```

---

# MITRE ATT&CK Mapping

| Technique | ID |
|------------|----|
| Command and Scripting Interpreter | T1059 |
| PowerShell | T1059.001 |
| Windows Command Shell | T1059.003 |
| System Binary Proxy Execution | T1218 |

---

# Investigation Tips

During investigation, verify:

- Who executed the process?
- What launched the process?
- Was the command line expected?
- Was the integrity level elevated?
- Did the process establish network connections?
- Did it modify the registry?

---

# Dashboard Panel

This query powers the following dashboard panels:

- Total Processes Created
- Process Creation Timeline
- Suspicious Process Detection
- High Integrity Process Monitoring
- PowerShell Activity
- Command Prompt Activity
