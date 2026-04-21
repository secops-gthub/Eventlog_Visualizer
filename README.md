Multi-Source EDR Visualizer (Ultimate Edition v3.3)

A professional-grade security analysis and digital forensics (DFIR) tool that reconstructs disparate Windows event logs into a hierarchical, EDR-style process tree. This version features an advanced Lineage Engine, high-performance UI Virtualization, and a newly expanded Network & Firewall Forensic Suite for deep traffic investigation.
🚀 Key Features
🛡️ Enhanced Firewall & Network Suite (New)

    Deep WFP Parsing: Natively decodes Windows Filtering Platform (WFP) connection events (IDs 5152–5159) from the Security log, revealing hidden "Allow," "Drop," and "Block" actions.

    Advanced Security Log Support: Automatically parses Firewall Rule modifications, Profile changes, and Rule Evaluations (IDs 2004, 2010, 2097) from the Advanced Security log.

    Raw W3C Log Ingestion: Support for importing raw pfirewall.log text files. The script automatically converts these flat logs into structured objects for the Process Tree.

    Specialized Networking Filters: Dedicated UI fields for FW Action (Allow/Block) and Filter Port to isolate specific lateral movement or C2 beacons.

⚡ Performance & Forensics

    UI Virtualization Engine: Handles massive forensic datasets (100k+ rows) with zero lag by dynamically rendering only the rows currently visible on screen.

    Process Pivot / Execution Isolation: Right-click any process to instantly isolate its entire execution chain (using its unique PGUID), revealing every child process, network connection, and DNS query associated with that specific execution path.

    Process Tree Lineage: Automatically correlates Parent/Child processes with visual indentation (┗━━) and chronological sorting.

🔍 Threat Intelligence & Exports

    Multi-Vector VirusTotal Integration: Smart context menus allow for instant intelligence lookups of File Hashes, Destination IPs, and DNS Queries.

    Structured Data Exports: Export your filtered investigation findings to CSV, JSON, or CSS-Styled HTML Reports for SIEM ingestion (Splunk, Sentinel) or peer review.

    Universal Property Mapping: Uses XML-based parsing to extract "Named" properties (TargetUserName, IpAddress, CommandLine) that are often missing in standard Windows Event Viewer.

📋 Requirements

    OS: Windows 10/11 or Windows Server 2016+.

    PowerShell: Version 5.1 or 7.x.

    Permissions: Administrator privileges (required for live log access; not required for manual file analysis).

🛠️ How It Works
1. Source Selection

Upon launch, choose to pull Live Logs (last 24 hours) from the local machine or proceed to the dashboard for Manual Import of forensic .evtx, .xml, or .log files.
2. Multi-Source Ingestion

    Sysmon: Process behavior (ID 1), network telemetry (ID 3), and DNS queries (ID 22).

    Windows Defender: Malware detections and remediation history with high-fidelity path parsing.

    Windows Firewall: Connection blocks, rule modifications, and profile changes.

    Windows Security: Decoded Logons (4624), Process Auditing (4688), Group Enumeration (4798), and Credential Reads (5379).

3. Threat Hunting & Reporting

    Enhanced Filtering: Hunt using Usernames, Event IDs, Hashes, IPs, DNS Queries, Firewall Actions, Ports, or Date Ranges.

    Smart Context Menu: Perform targeted VirusTotal lookups based on the selected cell's data.

    Reporting: Generate a portable, styled HTML report for documentation and case filing.

📥 Installation & Usage

    Download Security_logs_analyzer.ps1.

    (Optional) Edit the script to add your VirusTotal API Key in the $script:VT_API_KEY field.

    Open PowerShell as Administrator.

    Run the script:
    PowerShell

    .\Security_logs_analyzer.ps1
