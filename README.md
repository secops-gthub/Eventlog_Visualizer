Multi-Source EDR Visualizer (Sysmon, Defender, & Security)

A high-fidelity security analysis tool that reconstructs Windows event logs into a hierarchical, EDR-style process tree. This version features an enhanced Universal Parsing Engine that correctly decodes complex Windows Security attributes and supports cumulative loading to merge live logs and forensic files into a single unified timeline.
🚀 Key Features

    Universal Property Mapping: Uses advanced XML-based parsing to correctly extract "Named" properties (like TargetUserName, IpAddress, and CommandLine) that are often blank or incorrectly parsed in standard Security and Sysmon log views.

    Performance-Optimized HTML Export (New): High-speed report generation engine using StringBuilder to prevent the application from becoming non-responsive when exporting or opening large datasets in the browser.

    Full Date Range Filtering (New): Ability to filter merged datasets by specific start and end dates—essential when manually adding older .evtx or .xml logs that fall outside the initial 24-hour live lookback.

    Multi-Source Ingestion: Combines data from:

        Sysmon: Detailed process behavior (ID 1), network connections (ID 3), and DNS queries (ID 22).

        Windows Defender: Malware detections and automated remediation actions.

        Windows Security: Enhanced decoding for Logons (ID 4624), Failures (4625), Group Enumeration (4798), and Credential Reads (5379).

    Cumulative Loading: Merge multiple .evtx or .xml files without wiping existing data—perfect for tracking lateral movement across different machines.

    Persistent Investigation: Applying a filter that yields no results no longer wipes your session. Simply clear the filter fields and click Apply to restore the full original dataset.

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

    Add Log: Import external forensic logs. These are appended to your current view, allowing for timeline correlation across multiple files or hosts.

    Universal Filter: Narrows down the activity tree by User, Event ID, Date Range, or Activity keywords (Image names, IPs, etc.).

    Status Bar: Real-time feedback on log counts and export progress.

3. Reporting

    Open HTML: Generates a temporary, CSS-styled interactive report and launches it in your default browser immediately.

    Save HTML: Exports a standalone, portable report for evidence or peer review. Optimized to handle thousands of rows without freezing the UI.

📥 Installation

    Download Sysmon_Visualizer.ps1.

    Open PowerShell as Administrator.

    Execute the script:
    PowerShell

    .\Sysmon_Visualizer.ps1
