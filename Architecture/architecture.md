# Enterprise Detection Engineering & Threat Hunting Lab Architecture

## Overview

This lab simulates an enterprise Security Operations Center (SOC) environment for collecting, forwarding, analyzing, and investigating Windows endpoint telemetry.

The architecture uses Sysmon to generate detailed endpoint events, Splunk Universal Forwarder to securely transmit logs, and Splunk Enterprise to index, search, correlate, and visualize security events through a custom SOC dashboard.

---

# Architecture Components

## Windows 10 Virtual Machine

The Windows 10 virtual machine acts as the monitored endpoint where user activity and security events are generated.

Activities performed on the endpoint include:

- Process Creation
- PowerShell Execution
- Command Prompt Execution
- Network Connections
- Registry Modifications
- Privileged Process Execution

These activities are captured by Sysmon.

---

## Sysmon

Sysmon (System Monitor) is installed on the Windows endpoint to generate detailed endpoint telemetry.

The project primarily uses the following Sysmon Event IDs:

| Event ID | Description |
|----------|-------------|
| 1 | Process Creation |
| 3 | Network Connection |
| 7 | Image Loaded |
| 13 | Registry Value Set |

Sysmon provides significantly richer telemetry than native Windows Event Logs, enabling advanced threat detection and investigation.

---

## Splunk Universal Forwarder

Splunk Universal Forwarder collects Sysmon Operational logs from the Windows endpoint and securely forwards them to Splunk Enterprise.

Responsibilities include:

- Continuous log forwarding
- Reliable event delivery
- Lightweight endpoint collection

---

## Splunk Enterprise

Splunk Enterprise serves as the Security Information and Event Management (SIEM) platform.

Primary responsibilities:

- Event Indexing
- Log Searching
- SPL Query Execution
- Dashboard Visualization
- Threat Detection
- Security Investigation

---

## Detection Engineering

Detection logic is implemented using Splunk Search Processing Language (SPL).

Custom SPL queries detect:

- Process Creation
- PowerShell Execution
- Command Prompt Execution
- Network Connections
- Registry Modifications
- High Integrity Processes
- Suspicious Process Execution

---

## Threat Hunting Dashboard

The dashboard provides analysts with real-time visibility into endpoint activities.

Implemented dashboard panels include:

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

# Architecture Workflow

1. User performs activity on the Windows 10 endpoint.
2. Sysmon captures endpoint telemetry.
3. Splunk Universal Forwarder forwards the events.
4. Splunk Enterprise indexes the incoming logs.
5. SPL detection rules analyze the collected events.
6. Dashboard panels visualize security events.
7. SOC analysts investigate suspicious activities.

---

# Security Monitoring Workflow

```
Windows Endpoint
        │
        ▼
      Sysmon
        │
        ▼
Universal Forwarder
        │
        ▼
Splunk Enterprise
        │
        ▼
Detection Rules (SPL)
        │
        ▼
SOC Dashboard
        │
        ▼
Security Investigation
```

---

# Project Objectives

- Build a production-inspired Detection Engineering lab
- Collect Windows endpoint telemetry
- Develop custom SPL detections
- Monitor endpoint activities
- Perform threat hunting
- Visualize security events
- Simulate SOC investigations

---

# Skills Demonstrated

- Detection Engineering
- Splunk Enterprise
- SPL Query Development
- Windows Endpoint Monitoring
- Sysmon
- Threat Hunting
- Security Operations
- Incident Investigation
- Dashboard Development
- Log Analysis
