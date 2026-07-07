# Top Parent Processes

## Purpose

Identify parent processes that launch the highest number of child processes.

---

## SPL Query

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| top limit=10 ParentImage
```

---

## Dashboard Panel

- Top Parent Processes
