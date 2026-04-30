# Multi-Source EDR Visualizer (Ultimate Edition v3.6)

A professional-grade security analysis and digital forensics (DFIR) tool that reconstructs disparate Windows event logs into a hierarchical, EDR-style process tree. Version 3.6 introduces a native **Log Type Classification Engine**, allowing analysts to instantly filter and sort between Sysmon, Firewall, Defender, Security, and PowerShell data sources.

## 🚀 Key Features

### 🗂️ Log Type Classification Engine (New)
* **Unified Telemetry:** Raw event log providers (e.g., `Microsoft-Windows-Sysmon/Operational`, `pfirewall.log`) are automatically converted into a clean, human-readable **Log Type** column (`Sysmon`, `Firewall`, `PowerShell`, `Security`, `Defender`).
* **Source Filtering:** A dedicated "Log Type" UI filter allows you to isolate entire categories of logs (e.g., viewing *only* PowerShell scripts or *only* Firewall drops) with a single word.

### 🖥️ PowerShell Forensics & Script Auditing
* **Script Block Extraction:** Automatically parses `Microsoft-Windows-PowerShell/Operational` logs (Event ID 4104) to expose raw, in-memory PowerShell script blocks and payloads.
* **Pipeline Execution Tracking:** Captures Pipeline Execution details (Event ID 4103) and maps them cleanly into the timeline for tracking obfuscated commands and lateral movement.

### 🛠️ Noise Reduction & "Exclude N/A" Engine
* **Instant De-Clutter:** Use the UI checkboxes to instantly strip out logs with empty data. Filter out events missing **Usernames**, **File Hashes**, **Destination IPs**, or **DNS Queries** to focus only on actionable intelligence.
* **Dynamic Refinement:** Apply exclusions on top of existing keyword filters to isolate high-fidelity process executions and network beacons.

### 🛡️ Advanced Firewall & Network Forensics
* **WFP Deep Parsing:** Decodes Windows Filtering Platform (WFP) connection events (IDs 5152–5159) from the Security log to reveal "Allow," "Drop," and "Block" network decisions.
* **Firewall Rule Evaluation:** Parses Advanced Security XML exports (IDs 2004, 2010, 2052, 2097). Automatically identifies `Direction` (Inbound/Outbound) and `Action` (Permit/Block) from raw rule data.
* **W3C Log Ingestion:** Support for importing raw `pfirewall.log` text files, integrating flat log data directly into the visual tree.

### ⚡ Performance & GUI
* **Standard UI Framework:** A clean, standard Windows-native interface that prioritizes speed and legibility.
* **UI Virtualization Engine:** Optimized to handle 100,000+ rows with zero lag by dynamically rendering only visible rows.
* **Process Pivot:** Right-click any process to "Pivot." This isolates the specific execution chain (via PGUID), showing every child process and network connection associated with that specific instance.
* **Process Tree Lineage:** Correlates Parent/Child relationships with visual indentation (`┗━━`) and oldest-to-newest chronological sorting.

### 🔍 Threat Intelligence & Reporting
* **Multi-Vector VirusTotal Integration:** Right-click context menus for instant lookups of **File Hashes**, **Destination IPs**, and **DNS Queries**.
* **Structured Data Exports:** Save findings to **CSV**, **JSON**, or professional **CSS-Styled HTML Reports** for SIEM ingestion or case documentation. The new `LogType` property is mapped to all exports.

## 📋 Requirements
* **OS:** Windows 10/11 or Windows Server 2016+.
* **PowerShell:** Version 5.1 or 7.x.
* **Permissions:** Administrator privileges are required only for **Live Log** access.

## 🛠️ How It Works

### 1. Ingestion
Choose to pull **Live Logs** (last 24 hours) or manually import forensic files:
* **.evtx / .xml:** Standard Windows Event Logs.
* **.log:** W3C Standard Firewall Logs.

### 2. Multi-Source Correlation
The engine automatically maps properties across:
* **Sysmon:** IDs 1 (Process), 3 (Network), and 22 (DNS).
* **Windows Defender:** Malware detections and path parsing.
* **Windows Firewall:** Advanced Security rule changes, profile updates, and WFP connection drops.
* **PowerShell:** Script Blocks (4104) and Pipeline Execution (4103).
* **Windows Security:** Logons (4624), Process Auditing (4688), and Credential Reads (5379).

### 3. The Hunting Dashboard
* **Filters:** Hunt by Log Type, User, ID, Hash, IP, DNS, Firewall Action, or Port.
* **Exclusions:** Check "Exclude N/A" boxes to see only events with usable indicators.
* **Pivot:** Right-click a suspicious entry to strip away noise and follow the "story" of a specific process.

## 📥 Installation & Usage
1. Download `Security_logs_analyzer.ps1`.
2. (Optional) Insert your **VirusTotal API Key** in the `$script:VT_API_KEY` variable.
3. Open PowerShell as Administrator.
4. Execute:
   ```powershell
   .\Security_logs_analyzer.ps1Multi-Source EDR Visualizer (Ultimate Edition v3.4.1)

A professional-grade security analysis and digital forensics (DFIR) tool that reconstructs disparate Windows event logs into a hierarchical, EDR-style process tree. Version 3.4.1 introduces a high-performance Noise Reduction Engine and expanded support for Advanced Firewall Telemetry, making it one of the most comprehensive open-source log visualizers for incident responders.
🚀 Key Features
🛠️ Noise Reduction & "Exclude N/A" Engine (New)

    Instant De-Clutter: Use the new UI checkboxes to instantly strip out logs with empty data. Filter out events missing Usernames, File Hashes, Destination IPs, or DNS Queries to focus only on actionable intelligence.

    Dynamic Refinement: Apply exclusions on top of existing keyword filters to isolate high-fidelity process executions and network beacons.

🛡️ Advanced Firewall & Network Forensics (New)

    WFP Deep Parsing: Decodes Windows Filtering Platform (WFP) connection events (IDs 5152–5159) from the Security log to reveal "Allow," "Drop," and "Block" actions.

    Firewall Rule Evaluation: Specifically updated to parse Advanced Security XML exports (IDs 2004, 2010, 2052, 2097).

    Attribute Extraction: Automatically identifies ModifyingApplication, Direction (Inbound/Outbound), and Action (Permit/Block) from raw rule evaluation data.

    W3C Log Ingestion: Support for importing raw pfirewall.log text files, integrating flat log data into the hierarchical process tree.

⚡ Performance & Forensics

    UI Virtualization Engine: Optimized to handle 100,000+ rows with zero lag by dynamically rendering only visible rows.

    Process Pivot / Execution Isolation: Right-click any process to "Pivot." This isolates the specific process execution chain (via PGUID), showing every child process and network connection associated with that specific instance.

    Process Tree Lineage: Correlates Parent/Child relationships with visual indentation (┗━━) and oldest-to-newest chronological sorting.

🔍 Threat Intelligence & Reporting

    Multi-Vector VirusTotal Integration: Right-click context menus for instant lookups of File Hashes, Destination IPs, and DNS Queries.

    Structured Data Exports: Save findings to CSV, JSON, or professional CSS-Styled HTML Reports for SIEM ingestion or case documentation.

📋 Requirements

    OS: Windows 10/11 or Windows Server 2016+.

    PowerShell: Version 5.1 or 7.x.

    Permissions: Administrator privileges are required only for Live Log access.

🛠️ How It Works
1. Ingestion

Choose to pull Live Logs (last 24 hours) or manually import forensic files:

    .evtx / .xml: Standard Windows Event Logs.

    .log: W3C Standard Firewall Logs.

2. Multi-Source Correlation

The engine automatically maps properties across:

    Sysmon: IDs 1 (Process), 3 (Network), and 22 (DNS).

    Windows Defender: Malware detections and path parsing.

    Windows Firewall: Advanced Security rule changes and WFP connection drops.

    Windows Security: Logons (4624), Process Auditing (4688), and Credential Reads (5379).

3. The Hunting Dashboard

    Filters: Hunt by User, ID, Hash, IP, DNS, Firewall Action, or Port.

    Exclusions: Check "Exclude N/A" boxes to see only events with usable indicators.

    Pivot: Right-click a suspicious entry to strip away noise and follow the "story" of a specific process.

📥 Installation & Usage

    Download Security_logs_analyzer.ps1.

    (Optional) Insert your VirusTotal API Key in the $script:VT_API_KEY variable.

    Open PowerShell as Administrator.

    Execute:
    PowerShell

    .\Security_logs_analyzer.ps1
