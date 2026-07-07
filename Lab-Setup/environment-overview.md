# Environment Overview

## Lab Components

The detection lab consists of the following components:

- Windows 10 Virtual Machine
- Sysmon
- Splunk Universal Forwarder
- Splunk Enterprise
- VMware Workstation

## Log Flow

Windows 10
↓
Sysmon
↓
Universal Forwarder
↓
Splunk Enterprise
↓
SPL Queries
↓
Dashboard
↓
Threat Hunting

## Purpose

The environment simulates a Windows endpoint monitored by a Security Operations Center (SOC), enabling real-time process monitoring, detection engineering, and threat hunting.
