# Registry Modification Monitoring (Sysmon Event ID 13)

## Overview

Sysmon Event ID 13 records registry value modifications on the endpoint. Registry monitoring is essential for detecting persistence mechanisms, malware configuration changes, unauthorized system modifications, and privilege escalation techniques.

---

# Detection Objective

Monitor registry value modifications to identify:

- Persistence mechanisms
- Startup registry changes
- Malware registry activity
- Unauthorized configuration changes
- Suspicious registry modifications

---

# Data Source

| Source | Value |
|---------|-------|
| Event Source | Microsoft-Windows-Sysmon |
| Event ID | 13 |
| Log Source | XmlWinEventLog:Microsoft-Windows-Sysmon/Operational |

---

# SPL Query

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=13
| table _time Image TargetObject User Details
| sort -_time
```

---

# Query Explanation

| Field | Description |
|---------|-------------|
| _time | Event timestamp |
| Image | Process modifying the registry |
| TargetObject | Registry path being modified |
| User | User performing the action |
| Details | Value written into the registry |

---

# Security Use Cases

- Detect persistence mechanisms
- Monitor autorun registry keys
- Detect malware configuration changes
- Investigate suspicious registry modifications
- Identify privilege abuse

---

# Example Detections

Legitimate

```
svchost.exe
 └── Windows Update Registry
```

```
Explorer.exe
 └── User Preference Update
```

Suspicious

```
powershell.exe
 └── Run Key Modification
```

```
cmd.exe
 └── Startup Registry Entry
```

```
reg.exe
 └── Security Configuration Change
```

---

# MITRE ATT&CK Mapping

| Technique | ID |
|------------|----|
| Boot or Logon Autostart Execution | T1547 |
| Modify Registry | T1112 |
| Persistence | TA0003 |

---

# Investigation Tips

During investigation, verify:

- Which process modified the registry?
- Which registry key was changed?
- Is the registry path commonly abused?
- What value was written?
- Did the process establish network connections?
- Was the process executed with elevated privileges?

---

# Dashboard Panel

This query powers the following dashboard panel:

- Registry Modification Monitoring
