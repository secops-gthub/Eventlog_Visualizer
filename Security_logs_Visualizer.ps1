<#
    Advanced EDR Multi-Source Visualizer - ULTIMATE EDITION v2
    - ADDED: UI Virtualization (Handles 100k+ rows with zero lag)
    - ADDED: Process Pivot (Right-click to isolate a process execution chain)
    - ADDED: Export to CSV and JSON for SIEM/Spreadsheet ingestion
    - KEEPS: VirusTotal Context Menu, Tree Lineage, HTML Export, Exit Button
#>

# --- CONFIGURATION: Put your VirusTotal API Key here ---
$script:VT_API_KEY = "YOUR_API_KEY_HERE"

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

# ------------------------------
# CORE: UNIVERSAL PARSING ENGINE
# ------------------------------
function Get-CombinedEDREvents {
    param([string]$Path = $null, [string[]]$LiveLogs = @())
    $events = @()
    $lookbackTime = (Get-Date).AddDays(-1) 

    try {
        if ($Path) {
            if ($Path.EndsWith(".xml")) {
                [xml]$xmlFile = Get-Content $Path -Raw
                $events = $xmlFile.SelectNodes("//*[local-name()='Event']")
            } else {
                $events = Get-WinEvent -Path $Path -Oldest 
            }
        } elseif ($LiveLogs.Count -gt 0) {
            foreach ($log in $LiveLogs) { 
                $events += Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$lookbackTime} -ErrorAction SilentlyContinue 
            }
        }
    } catch { return @() }

    $parsedData = foreach ($e in $events) {
        $xmlDoc = $null
        try {
            if ($e.ToXml) { $xmlDoc = [xml]$e.ToXml() } 
            elseif ($e -is [System.Xml.XmlElement]) {
                $xmlDoc = New-Object System.Xml.XmlDocument
                $xmlDoc.AppendChild($xmlDoc.ImportNode($e, $true)) | Out-Null
            } else { $xmlDoc = [xml]$e }
        } catch { continue }

        $eventNode = $xmlDoc.Event ?? $xmlDoc.SelectNodes("//*[local-name()='Event']")[0]
        $id = [int]($eventNode.System.EventID.'#text' ?? $eventNode.System.EventID ?? 0)
        $provider = $eventNode.System.Provider.Name
        $rawTime = $eventNode.System.TimeCreated.SystemTime ?? $eventNode.System.TimeCreated
        $timeCreated = if ($rawTime) { [datetime]$rawTime } else { Get-Date }

        $data = @{}
        $dataNodes = $eventNode.EventData.Data
        if ($dataNodes) {
            foreach ($node in $dataNodes) {
                if ($node.Name) { $data[$node.Name] = $node.'#text' }
                else { $data["Param_$($data.Count)"] = $node.InnerText }
            }
        }
        
        $detectedUser = $data.TargetUserName ?? $data.SubjectUserName ?? $data.User ?? "N/A"
        $imagePath = $data.NewProcessName ?? $data.Image ?? $data.ProcessName ?? "System/EDR"
        
        # --- PROCESS LINEAGE EXTRACTION ---
        $pGuid  = $data.ProcessGuid ?? $data.NewProcessId ?? $data.ProcessId
        $ppGuid = $data.ParentProcessGuid ?? $data.CreatorProcessId ?? $data.ParentProcessId

        # SHA256 Extraction
        $sha256 = "N/A"
        if ($data.Hashes -match 'SHA256=([A-Fa-f0-9]{64})') { $sha256 = $Matches[1] }

        # --- NETWORK/DNS EXTRACTION ---
        $destIp = "N/A"
        $dnsQuery = "N/A"

        $details = ""
        if ($provider -like "*Windows Defender*") {
            $threat = $data.'Threat Name' ?? $data.ThreatName ?? "Unknown Threat"
            $action = $data.'Action Name' ?? $data.ActionName ?? "Action Taken"
            $path = $data.Path ?? $data.'Resource Path' ?? "Unknown Path"
            $details = "⚠️ DEFENDER: $action on $threat | Path: $path"
            if ($data.'Process Name') { $imagePath = $data.'Process Name' }
        } elseif ($provider -like "*Security-Auditing*") {
            switch($id) {
                4624 { 
                    $destIp = $data.IpAddress ?? "Local"
                    $details = "🔑 LOGON: Type $($data.LogonType) - Target: $($data.TargetUserName) - IP: $destIp" 
                }
                4688 { $details = "🚀 PROCESS: $($data.NewProcessName)" }
                4798 { $details = "🔍 GROUP: Enumerate groups for $($data.TargetUserName)" }
                5379 { $details = "📂 CRED: Read by $($data.SubjectUserName) for $($data.TargetUserName)" }
                default { $details = "Security ID $id" }
            }
        } elseif ($provider -like "*Sysmon*") {
            switch($id) {
                1  { $details = "PROCESS: $($data.CommandLine)" }
                3  { 
                    $destIp = $data.DestinationIp
                    $details = "NETWORK: $($data.SourceIp) -> $($data.DestinationIp):$($data.DestinationPort)" 
                }
                22 { 
                    $dnsQuery = $data.QueryName
                    $details = "DNS: $($data.QueryName)" 
                }
                default { $details = "Sysmon ID $id" }
            }
        }

        if ([string]::IsNullOrWhiteSpace($details) -or $details -match "ID \d+") {
            $details = ($data.GetEnumerator() | Select-Object -First 3 | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join " | "
        }

        [PSCustomObject]@{
            TimeCreated = $timeCreated
            EventID     = [string]$id
            Provider    = $provider
            Image       = $imagePath
            User        = $detectedUser
            Hash        = $sha256
            DestIP      = $destIp
            DNSQuery    = $dnsQuery
            Details     = $details
            PGUID       = $pGuid
            PPGUID      = $ppGuid
        }
    }
    return $parsedData
}

# ------------------------------
# LINEAGE & TREE ENGINE
# ------------------------------
function Get-EDRTreeView {
    param([object[]]$Events)
    if ($null -eq $Events) { return @() }

    # Map all events by their unique Process ID
    $ProcessMap = @{}
    foreach ($e in $Events) {
        if ($e.PGUID) { $ProcessMap[$e.PGUID] = $e }
    }

    # Sort ASCENDING (Oldest first) so time flows downwards. 
    $results = foreach ($item in ($Events | Sort-Object TimeCreated)) {
        $depth = 0
        $current = $item
        
        while ($current.PPGUID -and $ProcessMap.ContainsKey($current.PPGUID) -and $depth -lt 10) {
            $depth++
            $current = $ProcessMap[$current.PPGUID]
        }

        $indent = "    " * $depth
        $treeMarker = if ($depth -gt 0) { "┗━━ " } else { "■ " }

        [PSCustomObject]@{
            Time         = $item.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff")
            User         = $item.User
            EventID      = $item.EventID
            Hash         = $item.Hash
            DestIP       = $item.DestIP
            DNSQuery     = $item.DNSQuery
            ActivityTree = "$indent$treeMarker ID:$($item.EventID) | $($item.Image)`n$indent    ┗━━ $($item.Details)"
            RawDate      = $item.TimeCreated
            # Hidden fields for pivoting
            PGUID        = $item.PGUID
            PPGUID       = $item.PPGUID
        }
    }
    return $results
}

# ------------------------------
# OPTIMIZED HTML ENGINE
# ------------------------------
function ConvertTo-HtmlReport {
    param($DataItems)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<html><head><style>
    body { font-family: 'Segoe UI', sans-serif; margin: 30px; background-color: #f8f9fa; }
    h2 { color: #0078D4; border-bottom: 2px solid #0078D4; padding-bottom: 10px; }
    table { width: 100%; border-collapse: collapse; background: white; margin-top: 20px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
    th { background-color: #0078D4; color: white; padding: 12px; text-align: left; }
    td { padding: 10px; border-bottom: 1px solid #dee2e6; font-family: 'Consolas', monospace; font-size: 11px; vertical-align: top; }
    tr:nth-child(even) { background-color: #f2f2f2; }
    .tree { white-space: pre-wrap; color: #333; }
</style></head>
<body>
    <h2>EDR Investigation Activity Report</h2>
    <table><tr><th>Time</th><th>User</th><th>ID</th><th>SHA256 Hash</th><th>Dest IP</th><th>DNS Query</th><th>Activity / Details</th></tr>
"@)
    foreach ($row in $DataItems) {
        $cleanTree = [System.Net.WebUtility]::HtmlEncode($row.ActivityTree)
        [void]$sb.Append("<tr><td>$($row.Time)</td><td>$($row.User)</td><td>$($row.EventID)</td><td>$($row.Hash)</td><td>$($row.DestIP)</td><td>$($row.DNSQuery)</td><td class='tree'>$cleanTree</td></tr>")
    }
    [void]$sb.Append("</table></body></html>")
    return $sb.ToString()
}

# ------------------------------
# UI: SOURCE SELECTOR
# ------------------------------
$selectorXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Source Selection" Height="260" Width="360" WindowStartupLocation="CenterScreen" Topmost="True">
    <StackPanel Margin="20">
        <TextBlock Text="Select Live Logs (Last 24h):" FontWeight="Bold" FontSize="14" Margin="0,0,0,10"/>
        <CheckBox x:Name="ChkSecurity" Content="Windows Security Logs" IsChecked="False" Margin="0,5"/>
        <CheckBox x:Name="ChkDefender" Content="Windows Defender Logs" IsChecked="False" Margin="0,5"/>
        <CheckBox x:Name="ChkSysmon" Content="Sysmon Logs" IsChecked="False" Margin="0,5"/>
        <UniformGrid Columns="2" Margin="0,15,0,0">
            <Button x:Name="BtnLive" Content="⚡ Load Selected" Height="35" Margin="0,0,5,0" Background="#0078D4" Foreground="White"/>
            <Button x:Name="BtnManual" Content="📂 Manual Import" Height="35"/>
        </UniformGrid>
    </StackPanel>
</Window>
"@

$reader = [System.Xml.XmlNodeReader]::new(([xml]$selectorXaml))
$selector = [Windows.Markup.XamlReader]::Load($reader)
$script:selectedLogs = @()

$selector.FindName('BtnLive').Add_Click({
    if ($selector.FindName('ChkSecurity').IsChecked) { $script:selectedLogs += "Security" }
    if ($selector.FindName('ChkDefender').IsChecked) { $script:selectedLogs += "Microsoft-Windows-Windows Defender/Operational" }
    if ($selector.FindName('ChkSysmon').IsChecked)   { $script:selectedLogs += "Microsoft-Windows-Sysmon/Operational" }
    $selector.Close()
})
$selector.FindName('BtnManual').Add_Click({ $selector.Close() })
$selector.ShowDialog() | Out-Null

# ------------------------------
# UI: MAIN EDR DASHBOARD
# ------------------------------
$mainXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="EDR Visualizer - Ultimate Edition v2" Height="900" Width="1580">
    <Grid Margin="10">
        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
        
        <Grid Grid.Row="0" Margin="0,0,0,10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            
            <StackPanel Grid.Column="0" Orientation="Horizontal">
                <Button x:Name="BtnLoad" Content="📂 Add Log" Width="90" Height="30" Margin="0,0,10,0"/>
                <Button x:Name="BtnClear" Content="🗑️ Clear Logs" Width="100" Height="30" Background="#FFC5C5" Margin="0,0,10,0"/>
                <Button x:Name="BtnHtmlSave" Content="💾 Save HTML" Width="100" Height="30" Background="#6c757d" Foreground="White" Margin="0,0,5,0"/>
                <Button x:Name="BtnSaveCSV" Content="💾 Save CSV" Width="90" Height="30" Background="#17A2B8" Foreground="White" Margin="0,0,5,0"/>
                <Button x:Name="BtnSaveJSON" Content="💾 Save JSON" Width="90" Height="30" Background="#FFC107" Foreground="Black" Margin="0,0,5,0"/>
                <Button x:Name="BtnHtmlOpen" Content="🌐 Open HTML" Width="100" Height="30" Background="#28A745" Foreground="White"/>
            </StackPanel>
            
            <Button x:Name="BtnExit" Grid.Column="1" Content="❌ Exit" Width="80" Height="30" Background="#DC3545" Foreground="White" FontWeight="Bold"/>
        </Grid>

        <Border Grid.Row="1" Background="#E9ECEF" Padding="10" CornerRadius="5" Margin="0,0,0,10">
            <WrapPanel>
                <StackPanel Margin="0,0,10,0"><TextBlock Text="Filter User:" FontSize="10"/><TextBox x:Name="TbUserFilt" Width="90" Height="25"/></StackPanel>
                <StackPanel Margin="0,0,10,0"><TextBlock Text="Event ID:" FontSize="10"/><TextBox x:Name="TbIdFilt" Width="50" Height="25"/></StackPanel>
                <StackPanel Margin="0,0,10,0"><TextBlock Text="Hash Search:" FontSize="10"/><TextBox x:Name="TbHashFilt" Width="130" Height="25"/></StackPanel>
                <StackPanel Margin="0,0,10,0"><TextBlock Text="Filter IP:" FontSize="10"/><TextBox x:Name="TbIpFilt" Width="100" Height="25"/></StackPanel>
                <StackPanel Margin="0,0,10,0"><TextBlock Text="Filter DNS:" FontSize="10"/><TextBox x:Name="TbDnsFilt" Width="120" Height="25"/></StackPanel>
                <StackPanel Margin="0,0,10,0">
                    <TextBlock Text="Date Range:" FontSize="10"/>
                    <StackPanel Orientation="Horizontal">
                        <DatePicker x:Name="DpStart" Width="110"/>
                        <DatePicker x:Name="DpEnd" Width="110" Margin="5,0,0,0"/>
                    </StackPanel>
                </StackPanel>
                <StackPanel Margin="0,0,10,0"><TextBlock Text="Activity Search:" FontSize="10"/><TextBox x:Name="TbTreeFilt" Width="160" Height="25"/></StackPanel>
                
                <StackPanel Orientation="Horizontal" VerticalAlignment="Bottom">
                    <Button x:Name="BtnApply" Content="⚡ Apply" Width="70" Height="35" Background="#0078D4" Foreground="White"/>
                    <Button x:Name="BtnClearFilter" Content="🔄 Clear Filter" Width="85" Height="35" Margin="5,0,0,0" Background="#6c757d" Foreground="White"/>
                </StackPanel>
            </WrapPanel>
        </Border>

        <DataGrid x:Name="GridEvents" Grid.Row="2" AutoGenerateColumns="False" 
                  IsReadOnly="True" SelectionUnit="Cell" SelectionMode="Extended"
                  FontFamily="Consolas" ClipboardCopyMode="ExcludeHeader"
                  EnableRowVirtualization="True" EnableColumnVirtualization="True"
                  VirtualizingPanel.IsVirtualizing="True" VirtualizingPanel.VirtualizationMode="Recycling">
            <DataGrid.ContextMenu>
                <ContextMenu>
                    <MenuItem x:Name="MiPivot" Header="Pivot on this Process (PGUID)" />
                    <Separator />
                    <MenuItem x:Name="MiVT_Hash" Header="Search Hash on VirusTotal" />
                    <MenuItem x:Name="MiVT_IP" Header="Search Destination IP on VirusTotal" />
                    <MenuItem x:Name="MiVT_DNS" Header="Search DNS Query on VirusTotal" />
                </ContextMenu>
            </DataGrid.ContextMenu>
            <DataGrid.Columns>
                <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="170" SortMemberPath="RawDate"/>
                <DataGridTextColumn Header="User" Binding="{Binding User}" Width="120"/>
                <DataGridTextColumn Header="ID" Binding="{Binding EventID}" Width="50"/>
                <DataGridTextColumn Header="SHA256 Hash" Binding="{Binding Hash}" Width="150">
                    <DataGridTextColumn.ElementStyle>
                        <Style TargetType="TextBlock"><Setter Property="TextTrimming" Value="CharacterEllipsis"/><Setter Property="ToolTip" Value="{Binding Hash}"/></Style>
                    </DataGridTextColumn.ElementStyle>
                </DataGridTextColumn>
                <DataGridTextColumn Header="Dest IP" Binding="{Binding DestIP}" Width="110"/>
                <DataGridTextColumn Header="DNS Query" Binding="{Binding DNSQuery}" Width="160">
                    <DataGridTextColumn.ElementStyle>
                        <Style TargetType="TextBlock"><Setter Property="TextTrimming" Value="CharacterEllipsis"/><Setter Property="ToolTip" Value="{Binding DNSQuery}"/></Style>
                    </DataGridTextColumn.ElementStyle>
                </DataGridTextColumn>
                <DataGridTextColumn Header="Activity Tree" Binding="{Binding ActivityTree}" Width="*"/>
            </DataGrid.Columns>
        </DataGrid>
        
        <StatusBar Grid.Row="3" Background="#F0F0F0">
            <StatusBarItem><TextBlock x:Name="TxtStatus" Text="Ready"/></StatusBarItem>
        </StatusBar>
    </Grid>
</Window>
"@

$reader = [System.Xml.XmlNodeReader]::new(([xml]$mainXaml))
$window = [Windows.Markup.XamlReader]::Load($reader)
$grid = $window.FindName('GridEvents')
$txtStatus = $window.FindName('TxtStatus')
$script:RawData = @()

if ($script:selectedLogs.Count -gt 0) {
    $script:RawData = Get-CombinedEDREvents -LiveLogs $script:selectedLogs
    $grid.ItemsSource = Get-EDRTreeView -Events $script:RawData
}

# --- CONTEXT MENU LOGIC (PIVOT & VIRUSTOTAL) ---

$window.FindName('MiPivot').Add_Click({
    $selected = $grid.CurrentItem
    if ($null -eq $selected -and $grid.SelectedCells.Count -gt 0) { $selected = $grid.SelectedCells[0].Item }
    
    if ($null -ne $selected -and $selected.PGUID -and $selected.PGUID -ne "N/A") {
        $targetPGUID = $selected.PGUID
        $filtered = $script:RawData | Where-Object { $_.PGUID -eq $targetPGUID -or $_.PPGUID -eq $targetPGUID }
        $grid.ItemsSource = Get-EDRTreeView -Events $filtered
        $txtStatus.Text = "Pivoted on Process ID. Click 'Clear Filter' to reset."
    } else {
        [System.Windows.MessageBox]::Show("No Process ID available for this event to pivot.", "Pivot Search", 0, 48)
    }
})

$window.FindName('MiVT_Hash').Add_Click({
    $selected = $grid.CurrentItem
    if ($null -eq $selected -and $grid.SelectedCells.Count -gt 0) { $selected = $grid.SelectedCells[0].Item }
    
    if ($null -ne $selected -and $selected.Hash -ne "N/A" -and ![string]::IsNullOrWhiteSpace($selected.Hash)) {
        Start-Process "https://www.virustotal.com/gui/file/$($selected.Hash)"
        $txtStatus.Text = "Opening VirusTotal for hash: $($selected.Hash)"
    } else { [System.Windows.MessageBox]::Show("No valid SHA256 Hash found for this event.", "VirusTotal Lookup", 0, 48) }
})

$window.FindName('MiVT_IP').Add_Click({
    $selected = $grid.CurrentItem
    if ($null -eq $selected -and $grid.SelectedCells.Count -gt 0) { $selected = $grid.SelectedCells[0].Item }
    
    if ($null -ne $selected -and $selected.DestIP -ne "N/A" -and $selected.DestIP -ne "Local" -and ![string]::IsNullOrWhiteSpace($selected.DestIP)) {
        Start-Process "https://www.virustotal.com/gui/ip-address/$($selected.DestIP)"
        $txtStatus.Text = "Opening VirusTotal for IP: $($selected.DestIP)"
    } else { [System.Windows.MessageBox]::Show("No valid Destination IP found for this event.", "VirusTotal Lookup", 0, 48) }
})

$window.FindName('MiVT_DNS').Add_Click({
    $selected = $grid.CurrentItem
    if ($null -eq $selected -and $grid.SelectedCells.Count -gt 0) { $selected = $grid.SelectedCells[0].Item }
    
    if ($null -ne $selected -and $selected.DNSQuery -ne "N/A" -and ![string]::IsNullOrWhiteSpace($selected.DNSQuery)) {
        Start-Process "https://www.virustotal.com/gui/domain/$($selected.DNSQuery)"
        $txtStatus.Text = "Opening VirusTotal for DNS: $($selected.DNSQuery)"
    } else { [System.Windows.MessageBox]::Show("No valid DNS Query found for this event.", "VirusTotal Lookup", 0, 48) }
})

# --- EXIT BUTTON LOGIC ---
$window.FindName('BtnExit').Add_Click({ $window.Close() })

# --- EXPORT LOGIC ---
$window.FindName('BtnSaveCSV').Add_Click({
    if ($null -eq $grid.ItemsSource) { return }
    $dlg = [Microsoft.Win32.SaveFileDialog]::new()
    $dlg.Filter = "CSV Files (*.csv)|*.csv"
    if ($dlg.ShowDialog()) {
        $grid.ItemsSource | Select-Object Time, User, EventID, Hash, DestIP, DNSQuery, ActivityTree | Export-Csv -Path $dlg.FileName -NoTypeInformation
        $txtStatus.Text = "Exported to CSV successfully."
    }
})

$window.FindName('BtnSaveJSON').Add_Click({
    if ($null -eq $grid.ItemsSource) { return }
    $dlg = [Microsoft.Win32.SaveFileDialog]::new()
    $dlg.Filter = "JSON Files (*.json)|*.json"
    if ($dlg.ShowDialog()) {
        $grid.ItemsSource | Select-Object Time, User, EventID, Hash, DestIP, DNSQuery, ActivityTree | ConvertTo-Json -Depth 3 | Set-Content -Path $dlg.FileName
        $txtStatus.Text = "Exported to JSON successfully."
    }
})

$window.FindName('BtnLoad').Add_Click({
    $dlg = [Microsoft.Win32.OpenFileDialog]::new()
    if ($dlg.ShowDialog()) {
        $newData = Get-CombinedEDREvents -Path $dlg.FileName
        $script:RawData += $newData
        $grid.ItemsSource = Get-EDRTreeView -Events $script:RawData
        $txtStatus.Text = "Added $($newData.Count) events. Total: $($script:RawData.Count)"
    }
})

$window.FindName('BtnApply').Add_Click({
    $uFilt = $window.FindName('TbUserFilt').Text
    $iFilt = $window.FindName('TbIdFilt').Text
    $hFilt = $window.FindName('TbHashFilt').Text
    $ipFilt = $window.FindName('TbIpFilt').Text
    $dnsFilt = $window.FindName('TbDnsFilt').Text
    $tFilt = $window.FindName('TbTreeFilt').Text
    $start = $window.FindName('DpStart').SelectedDate
    $end   = $window.FindName('DpEnd').SelectedDate

    # Reset if all filters are empty
    if ([string]::IsNullOrWhiteSpace($uFilt) -and [string]::IsNullOrWhiteSpace($iFilt) -and 
        [string]::IsNullOrWhiteSpace($tFilt) -and [string]::IsNullOrWhiteSpace($hFilt) -and 
        [string]::IsNullOrWhiteSpace($ipFilt) -and [string]::IsNullOrWhiteSpace($dnsFilt) -and 
        $null -eq $start -and $null -eq $end) {
        $grid.ItemsSource = Get-EDRTreeView -Events $script:RawData
        return
    }

    $filtered = $script:RawData | Where-Object {
        ([string]::IsNullOrWhiteSpace($uFilt) -or $_.User -like "*$uFilt*") -and
        ([string]::IsNullOrWhiteSpace($iFilt) -or $_.EventID -eq $iFilt) -and
        ([string]::IsNullOrWhiteSpace($hFilt) -or $_.Hash -like "*$hFilt*") -and
        ([string]::IsNullOrWhiteSpace($ipFilt) -or $_.DestIP -like "*$ipFilt*") -and
        ([string]::IsNullOrWhiteSpace($dnsFilt) -or $_.DNSQuery -like "*$dnsFilt*") -and
        ($null -eq $start -or $_.TimeCreated -ge $start) -and
        ($null -eq $end -or $_.TimeCreated -le $end.AddDays(1)) -and
        ([string]::IsNullOrWhiteSpace($tFilt) -or $_.Details -like "*$tFilt*" -or $_.Image -like "*$tFilt*")
    }
    $grid.ItemsSource = Get-EDRTreeView -Events $filtered
})

$window.FindName('BtnClearFilter').Add_Click({
    $window.FindName('TbUserFilt').Text = ""
    $window.FindName('TbIdFilt').Text = ""
    $window.FindName('TbHashFilt').Text = ""
    $window.FindName('TbIpFilt').Text = ""
    $window.FindName('TbDnsFilt').Text = ""
    $window.FindName('TbTreeFilt').Text = ""
    $window.FindName('DpStart').SelectedDate = $null
    $window.FindName('DpEnd').SelectedDate = $null
    $grid.ItemsSource = Get-EDRTreeView -Events $script:RawData
    $txtStatus.Text = "Filters cleared."
})

$window.FindName('BtnHtmlOpen').Add_Click({
    if ($null -eq $grid.ItemsSource) { return }
    $txtStatus.Text = "Building Report..."
    [System.Windows.Forms.Application]::DoEvents()
    $tempPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "EDR_Report_$(Get-Date -Format 'HHmm').html")
    $html = ConvertTo-HtmlReport -DataItems $grid.ItemsSource
    Set-Content -Path $tempPath -Value $html
    Start-Process $tempPath
    $txtStatus.Text = "Report opened."
})

$window.FindName('BtnHtmlSave').Add_Click({
    if ($null -eq $grid.ItemsSource) { return }
    $dlg = [Microsoft.Win32.SaveFileDialog]::new()
    $dlg.Filter = "HTML Files (*.html)|*.html"
    if ($dlg.ShowDialog()) {
        $html = ConvertTo-HtmlReport -DataItems $grid.ItemsSource
        Set-Content -Path $dlg.FileName -Value $html
        $txtStatus.Text = "Exported successfully."
    }
})

$window.FindName('BtnClear').Add_Click({
    $script:RawData = @()
    $grid.ItemsSource = $null
    $txtStatus.Text = "Logs Cleared."
})

$window.ShowDialog() | Out-Null
