# PowerShell Execution Monitoring

## Purpose

Monitor PowerShell execution to identify administrative activity, scripting, automation, and potentially malicious PowerShell usage.

---

## SPL Query

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 Image="*powershell.exe"
| table _time User ParentImage CommandLine IntegrityLevel
| sort -_time
```

---

## Security Use Cases

- Detect PowerShell execution
- Investigate malicious scripts
- Detect encoded commands
- Threat Hunting
- Incident Investigation

---

## MITRE ATT&CK

- T1059.001 – PowerShell

---

## Dashboard Panel

- PowerShell Execution Monitoring
