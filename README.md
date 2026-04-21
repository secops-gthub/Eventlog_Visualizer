Multi-Source EDR Visualizer (Ultimate Edition v3.4.1)

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
