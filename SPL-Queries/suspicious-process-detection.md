# Suspicious Process Detection

## Purpose

Detect execution of commonly abused Windows binaries (LOLBins).

---

## SPL Query

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
(Image="*powershell.exe" OR Image="*cmd.exe" OR Image="*rundll32.exe" OR Image="*regsvr32.exe" OR Image="*mshta.exe" OR Image="*certutil.exe" OR Image="*wmic.exe")
| table _time User Image ParentImage CommandLine
| sort -_time
```

---

## MITRE ATT&CK

- T1218
- T1059

---

## Dashboard Panel

- Suspicious Process Detection
