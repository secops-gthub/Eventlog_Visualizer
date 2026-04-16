Multi-Source EDR Visualizer (Sysmon, Defender, & Security)

A high-fidelity security analysis tool that reconstructs Windows event logs into a hierarchical, EDR-style process tree. This version features an enhanced Universal Parsing Engine, dedicated SHA256 extraction, and a Performance-Optimized HTML Engine.
🚀 Key Features

    Universal Property Mapping: Uses advanced XML-based parsing to correctly extract "Named" properties (like TargetUserName, IpAddress, and CommandLine) from Security and Sysmon logs that typically appear blank in standard viewers.

    SHA256 Hash Visibility (New): Automatically isolates the SHA256 hash from Sysmon events. Long hashes are truncated in the view for cleanliness but are viewable via Tooltip hover.

    GUI Cell Copying (New): Select any cell (Hash, Timestamp, ID) and press Ctrl+C to copy the data directly to your clipboard for use in threat intelligence lookups.

    Performance-Optimized HTML Export: Utilizes StringBuilder logic and background UI management to generate massive investigation reports instantly without application hanging.

    Full Date Range Filtering: Dedicated DatePickers allow for filtering merged datasets—essential for investigations involving manual imports of older forensic .evtx files.

    Multi-Source Ingestion:

        Sysmon: Process behavior (ID 1), network telemetry (ID 3), and DNS queries (ID 22).

        Windows Defender: Malware detection and remediation history.

        Windows Security: Decoded Logons (4624), Process Auditing (4688), Group Enumeration (4798), and Credential Reads (5379).

    Cumulative Loading: Append multiple log files to a single session to track lateral movement across different machines and timeframes.

    Persistent Investigation: Filter logic is non-destructive. If a search yields no results, clearing the filters and clicking Apply restores your full original log set.

📋 Requirements

    OS: Windows 10/11 or Windows Server 2016+.

    PowerShell: 7.x.

    Permissions: Administrator privileges are required to access live local log streams.

🛠️ How It Works
1. Source Selection

Upon launch, choose to pull Live Logs (last 24 hours) from the local machine or proceed to the dashboard for Manual Import of forensic files.
2. The Dashboard

    Add Log: Merge new .evtx logs into your current timeline.

    Clear Logs: Resets the current investigation and wipes the session memory.

    Universal Filter: Filter by User, Event ID, SHA256 Hash, Date Range, or activity keywords.

    Status Bar: Provides real-time feedback on log counts and processing status.

3. Reporting

    Open HTML: Generates a temporary, CSS-styled report and launches it in your default browser.

    Save HTML: Saves a standalone, portable report for evidence. The engine is optimized to prevent UI freezing during large exports.

📥 Installation

    Download Sysmon_Visualizer.ps1.

    Open PowerShell as Administrator.

    Run the script: .\Sysmon_Visualizer.ps1Multi-Source EDR Visualizer (Sysmon, Defender, & Security)

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

    PowerShell: Version 7.x (Optimized for modern XAML handling).

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
