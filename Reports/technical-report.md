# Technical Report

## Architecture

Windows 10 VM → Sysmon → Splunk Universal Forwarder → Splunk Enterprise → SPL Detections → Dashboard

---

# Data Sources

- Sysmon Event ID 1
- Sysmon Event ID 3
- Sysmon Event ID 13

---

# Detection Rules

- Process Creation
- PowerShell Execution
- Command Prompt Execution
- Network Connections
- Registry Modification
- High Integrity Processes
- Suspicious Processes

---

# Dashboard Panels

- Total Processes Created
- Top Executed Processes
- Top Parent Processes
- PowerShell Execution Monitoring
- Command Prompt Execution Monitoring
- Network Connection Monitoring
- Registry Modification Monitoring
- High Integrity Process Monitoring
- Suspicious Process Detection
- Process Creation Timeline

---

# Skills Demonstrated

- Splunk Administration
- Detection Engineering
- SPL Query Development
- Threat Hunting
- Incident Response
- Windows Endpoint Monitoring
- MITRE ATT&CK Mapping

---

# Conclusion

This project demonstrates the implementation of a production-inspired endpoint monitoring and detection environment using Splunk Enterprise and Sysmon. It showcases the complete lifecycle of log collection, detection development, investigation, and dashboard visualization.
