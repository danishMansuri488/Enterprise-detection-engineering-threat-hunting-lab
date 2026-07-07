# Threat Hunting Playbook

## Overview

This document contains proactive threat hunting queries and methodologies used to identify suspicious behavior within Windows endpoints using Sysmon telemetry and Splunk Enterprise.

Unlike alerts, threat hunting focuses on discovering suspicious activities that may not trigger predefined detection rules.

---

# Hunt 1 – PowerShell Activity

## Objective

Identify all PowerShell executions.

## SPL Query

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 Image="*powershell.exe"
| table _time User ParentImage CommandLine IntegrityLevel
| sort -_time
```

## Hunt Goal

- Encoded commands
- Unexpected parent processes
- Elevated PowerShell sessions

---

# Hunt 2 – Command Prompt Activity

## SPL Query

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 Image="*cmd.exe"
| table _time User ParentImage CommandLine
| sort -_time
```

## Hunt Goal

- Unexpected CMD execution
- Office spawning CMD
- Batch script abuse

---

# Hunt 3 – Suspicious Parent-Child Processes

## SPL Query

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| table _time ParentImage Image CommandLine User
| sort -_time
```

## Hunt Goal

Look for unusual combinations such as:

- winword.exe → powershell.exe
- excel.exe → cmd.exe
- outlook.exe → rundll32.exe

---

# Hunt 4 – High Integrity Processes

## SPL Query

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 IntegrityLevel=High OR IntegrityLevel=System
| table _time User Image ParentImage IntegrityLevel
```

## Hunt Goal

- Unexpected administrative activity
- Privilege escalation
- Elevated scripting

---

# Hunt 5 – Network Connections

## SPL Query

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=3
| table _time Image DestinationIp DestinationHostname DestinationPort User
```

## Hunt Goal

- Unknown destination IPs
- Rare outbound ports
- PowerShell network traffic

---

# Hunt 6 – Registry Modifications

## SPL Query

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=13
| table _time Image TargetObject User Details
```

## Hunt Goal

- Startup registry keys
- Persistence
- Unauthorized registry changes

---

# Hunt 7 – LOLBins

## SPL Query

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
(Image="*powershell.exe" OR Image="*cmd.exe" OR Image="*rundll32.exe" OR Image="*regsvr32.exe" OR Image="*certutil.exe" OR Image="*mshta.exe" OR Image="*wmic.exe")
| table _time User Image ParentImage CommandLine
```

## Hunt Goal

Identify Living-off-the-Land Binary (LOLBin) abuse.

---

# Threat Hunting Methodology

1. Define the hunting objective.
2. Collect relevant endpoint telemetry.
3. Execute SPL hunting queries.
4. Review suspicious events.
5. Correlate multiple event types.
6. Validate findings.
7. Document results.
8. Create new detections if required.

---

# Outcome

The hunting queries documented in this playbook provide proactive visibility into endpoint activity and help identify suspicious behavior that may bypass traditional signature-based detection methods.
