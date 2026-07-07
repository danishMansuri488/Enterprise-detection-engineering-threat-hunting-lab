# Top Executed Processes

## Purpose

Identify the most frequently executed applications on the monitored endpoint.

---

## SPL Query

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| top limit=10 Image
```

---

## Dashboard Panel

- Top 10 Executed Processes
