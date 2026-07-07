# High Integrity Process Detection

## Detection Overview

This detection monitors processes executing with **High** or **System** integrity levels using Sysmon Event ID 1. Elevated processes have greater privileges and can perform sensitive operations, making them a valuable source for detecting privilege escalation and unauthorized administrative activity.

---

# Detection Name

High Integrity Process Execution

---

# Severity

**High**

Increase to **Critical** if:

- Spawned by an unexpected parent process
- Launched by a standard user
- Followed by registry modifications
- Initiates suspicious network connections

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---------|-----------|----|
| Privilege Escalation | Abuse Elevation Control Mechanism | T1548 |

---

# Data Source

- Microsoft Sysmon
- Event ID 1

---

# SPL Detection Logic

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 IntegrityLevel=High OR IntegrityLevel=System
| table _time User IntegrityLevel Image ParentImage CommandLine
| sort -_time
```

---

# Why This Detection Matters

Processes running with elevated privileges can:

- Modify critical system settings
- Install persistence mechanisms
- Disable security controls
- Execute administrative actions
- Access sensitive resources

Monitoring these processes helps identify both legitimate administrative activity and potential attacker behavior.

---

# Investigation Steps

1. Verify the user account.
2. Review the parent process.
3. Examine the command line.
4. Check for registry modifications.
5. Review related network connections.
6. Identify any spawned child processes.

---

# Possible False Positives

- System administrators
- Windows Update
- Enterprise management tools
- Security software

---

# Analyst Response

- Confirm legitimate administrative activity.
- Review process lineage.
- Correlate with additional Sysmon events.
- Escalate if privilege escalation is suspected.

---

# Related Dashboard Panel

High Integrity Process Monitoring
