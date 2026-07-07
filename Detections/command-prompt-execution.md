# Command Prompt Execution Detection

## Detection Overview

This detection monitors Command Prompt execution using Sysmon Event ID 1. Attackers frequently use cmd.exe to execute scripts, enumerate systems, run batch files, and launch additional tools during post-exploitation.

---

# Detection Name

Command Prompt Execution

---

# Severity

Medium

Increase to High if:

- Spawned from Office applications
- Executes suspicious commands
- Launches PowerShell
- Creates outbound network connections

---

# MITRE ATT&CK

| Tactic | Technique | ID |
|---------|-----------|----|
| Execution | Windows Command Shell | T1059.003 |

---

# SPL Detection Logic

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 Image="*cmd.exe"
| table _time User ParentImage CommandLine IntegrityLevel
| sort -_time
```

---

# Investigation

- Identify user
- Review parent process
- Inspect command line
- Check child processes
- Review related network activity

---

# False Positives

- IT administrators
- Software installers
- Login scripts

---

# Dashboard Panel

Command Prompt Execution Monitoring
