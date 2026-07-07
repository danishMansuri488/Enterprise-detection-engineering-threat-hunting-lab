# Network Connection Detection

## Detection Overview

This detection monitors outbound network connections using Sysmon Event ID 3. It helps identify suspicious communications, malware beaconing, command-and-control traffic, and unauthorized external connections.

---

# Detection Name

Outbound Network Connection Monitoring

---

# Severity

Medium

Increase to High if:

- Destination IP is untrusted
- Connection originates from PowerShell or CMD
- Multiple repeated outbound connections occur
- Destination uses uncommon ports

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---------|-----------|----|
| Command and Control | Application Layer Protocol | T1071 |

---

# SPL Detection Logic

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=3
| table _time Image DestinationIp DestinationHostname DestinationPort Protocol User
| sort -_time
```

---

# Investigation

- Verify destination IP.
- Check destination hostname.
- Review process initiating the connection.
- Correlate with process creation events.
- Investigate repeated communication patterns.

---

# Possible False Positives

- Web browsers
- Windows Update
- Microsoft Defender
- Enterprise applications

---

# Analyst Response

- Validate the destination.
- Investigate unknown IP addresses.
- Escalate persistent suspicious communications.

---

# Related Dashboard Panel

Network Connection Monitoring
