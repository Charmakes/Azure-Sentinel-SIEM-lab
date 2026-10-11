# Azure-Sentinel-SIEM-lab

## Overview
In this lab, I configured Microsoft Sentinel (SIEM) in Azure and connected it to a exposed Windows Virtual Machine (`MIA-EAST-1`) to observe live RDP Brute Force attacks originating globally. Using custom PowerShell logging, IP geolocation lookup watchlists, and KQL queries, incoming attack telemetry was mapped to physical coordinates and visualized on a Sentinel attack map.

---

## Environment Architecture & Setup

### Azure Resources Deployed
* Resource Group: `SIEM-LAB`
* Virtual Machine: `MIA-EAST-1` (Windows 10)
* Public IP Address: `MIA-EAST-1-ip`
* Network Security Group: `MIA-EAST-1-nsg`
* Virtual Network: `VNET-SIEM-LAB`
* Network Interface: `mia-east-1877_z1`
* Log Analytics Workspace: `LAW-SIEM-LAB-0000`

---

## Configuration Details

### 1. Network & System Exposure
* Network Security Group (NSG): Configured an inbound security rule allowing RDP (Port 3389) traffic from any source IP (`*`).
* OS Firewall: Disabled Windows Defender Firewall on `MIA-EAST-1` to permit uninhibited connection attempts.

### 2. Telemetry Ingestion & Geolocation Mapping
* Data Connector: Configured Windows Security Events via AMA inside Microsoft Sentinel to stream `Event ID 4625` (Failed Logon) logs into the Log Analytics Workspace `LAW-SIEM-LAB-0000`.
![CSV](https://github.com/Charmakes/azure-ms-sentinel-siem/blob/main/images/tongiht%203.png?raw=true)

* Geolocation Watchlist: Imported a custom CSV geolocation lookup file (`query_data.csv`) under the Sentinel Watchlist alias `geoip`, keyed on the `network` field.
![CSV](https://github.com/Charmakes/azure-ms-sentinel-siem/blob/main/images/image%283%29.png?raw=true)
* PowerShell Tracking: Executed a background script on `MIA-EAST-1` to extract failed logon events and resolve IP details in real time.


---
## Live World Attack Map Results

After leaving MIA-EAST-1 exposed to the public internet for 48 hours, thousands of automated brute-force logon attempts were captured globally. Automated port scanners discovered the public IP address MIA-EAST-1-ip within minutes of exposure. High-volume automated dictionary attacks immediately targeted standard administrator account names across multiple IP ranges. Incoming attack vectors were mapped geographically via custom Microsoft Sentinel Workbooks using latitude and longitude coordinates enriched by KQL queries.

![Windows VM Attack Map](https://github.com/Charmakes/azure-ms-sentinel-siem/blob/main/images/Map_Result.png?raw=true)
