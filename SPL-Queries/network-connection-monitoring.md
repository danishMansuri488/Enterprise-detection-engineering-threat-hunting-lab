# Network Connection Monitoring (Sysmon Event ID 3)

## Overview

Sysmon Event ID 3 records outbound network connections initiated by processes running on the endpoint. This event helps detect suspicious communications, malware command-and-control (C2) traffic, lateral movement, and unexpected external connections.

---

# Detection Objective

Monitor network connections initiated by processes and identify:

- Suspicious outbound connections
- Connections to unknown IP addresses
- Potential Command-and-Control (C2) communication
- Malware beaconing
- Unusual application network activity

---

# Data Source

| Source | Value |
|---------|-------|
| Event Source | Microsoft-Windows-Sysmon |
| Event ID | 3 |
| Log Source | XmlWinEventLog:Microsoft-Windows-Sysmon/Operational |

---

# SPL Query

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=3
| table _time Image DestinationIp DestinationHostname DestinationPort Protocol User
| sort -_time
```

---

# Query Explanation

| Field | Description |
|---------|-------------|
| _time | Event timestamp |
| Image | Process initiating the connection |
| DestinationIp | Remote IP address |
| DestinationHostname | Remote hostname |
| DestinationPort | Remote port |
| Protocol | Network protocol |
| User | User context |

---

# Security Use Cases

- Detect malware communicating with external servers
- Monitor PowerShell network activity
- Detect suspicious outbound connections
- Investigate lateral movement
- Identify unauthorized internet access

---

# Example Detections

Legitimate

```
chrome.exe
 └── https://google.com
```

```
MpDefenderCoreService.exe
 └── Microsoft Update
```

Suspicious

```
powershell.exe
 └── Unknown Public IP
```

```
cmd.exe
 └── External Server
```

```
rundll32.exe
 └── Random Internet Host
```

---

# MITRE ATT&CK Mapping

| Technique | ID |
|------------|----|
| Application Layer Protocol | T1071 |
| Command and Control | TA0011 |
| Remote Services | T1021 |

---

# Investigation Tips

During investigation, verify:

- Which process created the connection?
- Is the destination IP trusted?
- Is the destination port expected?
- Is the hostname legitimate?
- Did the process execute recently?
- Was the connection followed by registry or process activity?

---

# Dashboard Panel

This query powers the following dashboard panel:

- Network Connection Monitoring
