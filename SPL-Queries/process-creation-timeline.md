# Process Creation Timeline

## Purpose

Visualize process creation activity over time to identify spikes and abnormal behavior.

---

## SPL Query

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| timechart count
```

---

## Dashboard Panel

- Process Creation Timeline
