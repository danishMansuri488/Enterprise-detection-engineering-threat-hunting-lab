# Command Prompt Execution Monitoring

## Purpose

Monitor Command Prompt execution for suspicious administrative or attacker activity.

---

## SPL Query

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 Image="*cmd.exe"
| table _time User ParentImage CommandLine IntegrityLevel
| sort -_time
```

---

## MITRE ATT&CK

- T1059.003 – Windows Command Shell

---

## Dashboard Panel

- Command Prompt Execution Monitoring
