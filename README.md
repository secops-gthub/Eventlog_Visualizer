Multi-Source EDR Visualizer (Sysmon, Defender, & Security)

A high-fidelity security analysis tool that reconstructs Windows event logs into a hierarchical, EDR-style process tree. This version features an enhanced Universal Parsing Engine that correctly decodes complex Windows Security attributes and supports cumulative loading to merge live logs and forensic files into a single unified timeline.
🚀 Key Features

    Universal Property Mapping (New): Uses advanced XML-based parsing to correctly extract "Named" properties (like TargetUserName, IpAddress, and CommandLine) that are often blank or incorrectly parsed in standard Security and Sysmon logs.

    Multi-Source Ingestion: Combines data from:

        Sysmon: Detailed process behavior (ID 1), network connections (ID 3), and DNS queries (ID 22).

        Windows Defender: Malware detections and automated remediation actions.

        Windows Security: Enhanced decoding for Logons (ID 4624), Failures (4625), Group Enumeration (4798), and Credential Reads (5379).

    Selection Hub: A pre-launch dashboard to toggle specific live log sources for a 24-hour lookback.

    Cumulative Loading: Merge multiple .evtx or .xml files without wiping existing data—perfect for tracking lateral movement across different machines.

    Persistent Investigation (Fixed): Applying a filter that yields no results no longer wipes your data. Simply clear the filter fields and click Apply to restore the full original log set.

    EDR-Style Visualization: Maps parent-child relationships with specialized icons and a clean "Activity Tree" layout.

📋 Requirements

    OS: Windows 10/11 or Windows Server 2016+.

    PowerShell: Version 5.1 or 7.x (Optimized for modern XAML handling).

    Permissions: Must be run as Administrator to access the Windows Security and Sysmon log streams.

    Dependencies: Sysinternals Sysmon is recommended for deep process and network visibility.

🛠️ How It Works
1. Source Selection

Upon launch, a Selection Hub appears:

    Live Load: Check the logs you wish to pull from the local machine (Last 24 hours).

    Manual Import: Skip live logs to go directly to the dashboard for forensic file analysis.

2. The Dashboard

    Add Log: Import external logs. These are appended to your current view, allowing for cross-machine correlation.

    Universal Filter: Narrows down the tree by User, Event ID, Date Range, or Activity keywords.

    Data Restoration: If a search returns no results, clearing the filter boxes and clicking Apply immediately restores your full investigation data.

3. Reporting

    Open HTML: Generates a temporary, interactive report in your default browser.

    Save HTML: Exports a standalone report for evidence or peer review.

📥 Installation

    Clone the repository or download Sysmon_Visualizer.ps1.

    Open PowerShell as Administrator.

    Execute the script:
    PowerShell

    .\Sysmon_Visualizer.ps1
