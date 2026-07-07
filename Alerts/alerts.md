# Splunk Alert Configuration

## Overview

This document describes the alerting use cases implemented for the Sysmon Threat Detection & Process Monitoring Dashboard.

The alerts are designed to notify SOC analysts when suspicious endpoint activities are detected.

---

# Alert 1 – PowerShell Execution

## Severity

Medium

## Trigger

PowerShell process execution detected.

## SPL

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 Image="*powershell.exe"
```

## Analyst Action

- Review command line.
- Verify parent process.
- Check user account.
- Investigate related activity.

---

# Alert 2 – Command Prompt Execution

## Severity

Medium

## SPL

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 Image="*cmd.exe"
```

---

# Alert 3 – High Integrity Process

## Severity

High

## SPL

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 IntegrityLevel=High OR IntegrityLevel=System
```

---

# Alert 4 – Suspicious Process

## Severity

High

## SPL

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
(Image="*powershell.exe" OR Image="*cmd.exe" OR Image="*rundll32.exe" OR Image="*regsvr32.exe" OR Image="*mshta.exe" OR Image="*certutil.exe" OR Image="*wmic.exe")
```

---

# Alert 5 – Registry Modification

## Severity

Medium

## SPL

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=13
```

---

# Alert 6 – Network Connection

## Severity

Medium

## SPL

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=3
```

---

# Alert Response Workflow

1. Alert Triggered
2. Validate Detection
3. Investigate Process
4. Review Related Events
5. Determine Severity
6. Contain if Required
7. Document Findings
8. Close or Escalate Incident
