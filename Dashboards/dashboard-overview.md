# Sysmon Threat Detection & Process Monitoring Dashboard

## Overview

The Sysmon Threat Detection & Process Monitoring Dashboard was developed in Splunk Enterprise to provide real-time visibility into Windows endpoint activity using Sysmon telemetry.

The dashboard centralizes endpoint monitoring by visualizing process execution, PowerShell activity, Command Prompt execution, registry modifications, network connections, high integrity processes, and suspicious process activity.

The objective is to assist SOC analysts in rapidly identifying abnormal behavior, investigating security events, and supporting threat hunting activities.

---

# Dashboard Features

- Total Processes Created
- Top 10 Executed Processes
- Top Parent Processes
- PowerShell Execution Monitoring
- Command Prompt Execution Monitoring
- Network Connection Monitoring
- Registry Modification Monitoring
- High Integrity Process Monitoring
- Suspicious Process Detection
- Process Creation Timeline

---

# Dashboard Purpose

The dashboard enables analysts to:

- Monitor endpoint activity
- Detect suspicious process execution
- Investigate parent-child relationships
- Identify elevated processes
- Observe registry modifications
- Review outbound network connections
- Support threat hunting investigations

---

# Data Source

- Microsoft Sysmon
- Splunk Universal Forwarder
- Splunk Enterprise

---

# Dashboard Refresh

- Auto Refresh: 5 Minutes
- Default Time Range: Last 24 Hours

---

# Technologies

- Splunk Enterprise
- Sysmon
- Windows 10
- SPL
