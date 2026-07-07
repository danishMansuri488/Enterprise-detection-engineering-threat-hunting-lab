# Registry Modification Detection

## Detection Overview

This detection monitors Windows Registry modifications using Sysmon Event ID 13. Registry changes are commonly used by attackers to establish persistence, modify system configurations, or disable security controls.

---

# Detection Name

Registry Modification Monitoring

---

# Severity

**Medium**

Increase to **High** if:

- Startup registry keys are modified
- Security-related registry keys are changed
- Changes are performed by suspicious processes
- Registry modifications are followed by network activity

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---------|-----------|----|
| Persistence | Boot or Logon Autostart Execution | T1547 |
| Defense Evasion | Modify Registry | T1112 |

---

# Data Source

- Microsoft Sysmon
- Event ID 13

---

# SPL Detection Logic

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=13
| table _time Image TargetObject User Details
| sort -_time
```

---

# Why This Detection Matters

Registry modifications may indicate:

- Malware persistence
- Startup modifications
- Configuration tampering
- Security bypass attempts

---

# Investigation Steps

1. Review the modified registry path.
2. Identify the process responsible.
3. Verify the user account.
4. Correlate with process creation events.
5. Check for persistence mechanisms.

---

# Possible False Positives

- Windows Update
- Software installation
- Legitimate application configuration
- Enterprise management tools

---

# Analyst Response

- Validate the registry change.
- Review associated process activity.
- Escalate if unauthorized persistence is detected.

---

# Related Dashboard Panel

Registry Modification Monitoring
