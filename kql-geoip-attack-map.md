# Azure Custom Log Query: GeoIP Enrichment & Failed Logons

**Project Scope:** Real-time threat visualization in Microsoft Sentinel by cross-referencing raw Windows Event logs with custom GeoIP geolocation watchlist data.

---

## Description

This document details the KQL query and JSON configuration used to deploy an interactive attack map inside Microsoft Sentinel.

The query targets Windows Security Event logs (`SecurityEvent`) specifically filtering for failed logon attempts (`Event ID 4625`), which indicate brute-force or unauthorized access attempts via RDP/SMB. Because raw Windows security logs do not contain geographic coordinates, the KQL query leverages the `ipv4_lookup` operator to match source attacker IP addresses against a custom uploaded Sentinel watchlist (`geoip`).

Once enriched with geographical metrics (latitude, longitude, city, and country), failure counts are aggregated by location. The resulting dataset is rendered as an interactive, color-coded heatmap using an Azure Workbook map visualization.

---

## Technical Overview

* **Log Collection**: Security events are pulled from Windows Event logs (`SecurityEvent`).
* **GeoIP Enrichment**: Source IP addresses are cross-referenced with a custom Sentinel watchlist (`geoip`) containing subnet ranges, coordinates, and city/country mappings.
* **Aggregation**: Logon failure totals are summarized by IP address and coordinates to isolate high-volume attack sources.
* **Visualization**: Rendered as a dynamic heatmap on a world map using Azure Workbooks.

---

## Deployment Instructions

1. **Upload Watchlist**: Ensure the `geoip` CSV file is uploaded as a watchlist named `geoip` in Microsoft Sentinel under **Configuration** > **Watchlists**.
2. **Create Workbook**: Navigate to **Microsoft Sentinel** > **Threat management** > **Workbooks** and click **+ Add workbook**.
3. **Configure Advanced Editor**: Click **Edit**, remove default template widgets, click **Add** > **Add query**, and select the **Advanced Editor** (`</>`) icon.
4. **Apply Configuration**: Paste the JSON payload provided below into the Advanced Editor and select **Done Editing**.
5. **Save**: Save the workbook as `Windows VM Attack Map` within your primary Resource Group.

---
## Sentinel Workbook GeoIP Attack Map KQL Query

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent;
WindowsEvents | where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,
friendly_location = strcat(cityname, " (", countryname, ")");

```

## Workbook JSON Configuration

```json
{
    "type": 3,
    "content": {
        "version": "KqlItem/1.0",
        "query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet WindowsEvents = SecurityEvent;\nWindowsEvents | where EventID == 4625\n| order by TimeGenerated desc\n| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname\n| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,\nfriendly_location = strcat(cityname, \" (\", countryname, \")\");",
        "size": 3,
        "timeContext": {
            "durationMs": 2592000000
        },
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "map",
        "mapSettings": {
            "locInfo": "LatLong",
            "locInfoColumn": "countryname",
            "latitude": "latitude",
            "longitude": "longitude",
            "sizeSettings": "FailureCount",
            "sizeAggregation": "Sum",
            "opacity": 0.8,
            "labelSettings": "friendly_location",
            "legendMetric": "FailureCount",
            "legendAggregation": "Sum",
            "itemColorSettings": {
                "nodeColorField": "FailureCount",
                "colorAggregation": "Sum",
                "type": "heatmap",
                "heatmapPalette": "greenRed"
            }
        }
    },
    "name": "Windows VM Attack Map"
}
kql-geoip-attack-map.md
