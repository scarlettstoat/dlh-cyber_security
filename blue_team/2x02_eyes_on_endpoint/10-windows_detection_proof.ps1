# Name: 10-windows_detection_proof.ps1
# Purpose: Match Task 9 ground truth against Windows Security, Sysmon and PowerShell events.
# Author: Suraya
# Project: MedDefense - Eyes on the Endpoint (2x02), Task 10
# Run: On the Windows endpoint used for Task 9, in an elevated PowerShell terminal.

param(
    [string]$GroundTruthPath = (Join-Path $PSScriptRoot 'windows_attack_log.json'),
    [string]$OutputPath = (Join-Path $PSScriptRoot 'windows_detection_matrix.json'),
    [ValidateRange(1, 300)]
    [int]$WindowSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Identifiers from our Task 9 simulation; change only if Task 9 was customised.
$SimulatedUser = 'support_update'
$SimulatedTask = 'DLH_EyesOnEndpoint_Sim'
$StartupFileName = 'DLH_endpoint_simulation.txt'
$DestinationIP = '1.1.1.1'
$DestinationPort = '443'
$HarmlessPayload = 'Write-Host "C2 beacon"'
$EncodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($HarmlessPayload))

$Channels = [ordered]@{
    Security   = @{ Name = 'Security'; IDs = @(4720, 4732, 4688, 4698, 4663) }
    Sysmon     = @{ Name = 'Microsoft-Windows-Sysmon/Operational'; IDs = @(1, 3, 11) }
    PowerShell = @{ Name = 'Microsoft-Windows-PowerShell/Operational'; IDs = @(4104) }
}

function Get-EventFields {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Record)

    $fields = @{}
    [xml]$xml = $Record.ToXml()
    $nodes = $xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")
    foreach ($node in $nodes) {
        $name = $node.GetAttribute('Name')
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $fields[$name] = $node.InnerText
        }
    }
    return $fields
}

function Field-IsPresent {
    param([hashtable]$Fields, [string]$Name)
    return ($Fields.ContainsKey($Name) -and
        -not [string]::IsNullOrWhiteSpace([string]$Fields[$Name]) -and
        [string]$Fields[$Name] -ne '-')
}

function Get-KeyFields {
    param([hashtable]$Fields, [string[]]$Names)

    $result = [ordered]@{}
    foreach ($name in $Names) {
        if (Field-IsPresent -Fields $Fields -Name $name) {
            $result[$name] = [string]$Fields[$name]
        }
    }
    return $result
}

function Get-DetectionMatch {
    param(
        [int]$ActionNumber,
        [string]$Source,
        [System.Diagnostics.Eventing.Reader.EventRecord]$Record,
        [hashtable]$Data,
        [string]$CreatedUserSid,
        [datetime]$ActionTime
    )

    # A matched event must contain simulation-specific evidence, not just a matching ID.
    $match = $false
    $full = $false
    $names = @()
    $id = [int]$Record.Id

    switch ($ActionNumber) {
        1 {
            if ($Source -eq 'Security' -and $id -eq 4720 -and
                $Data['TargetUserName'] -eq $SimulatedUser) {
                $match = $true
                $names = @('TargetUserName', 'TargetDomainName', 'TargetSid', 'SubjectUserName')
                $full = (Field-IsPresent $Data 'TargetSid') -and
                        (Field-IsPresent $Data 'SubjectUserName')
            }
        }
        2 {
            if ($Source -eq 'Security' -and $id -eq 4732 -and
                ($Data['TargetSid'] -eq 'S-1-5-32-544' -or
                 $Data['TargetUserName'] -eq 'Administrators')) {
                $names = @('MemberName', 'MemberSid', 'TargetUserName', 'TargetSid',
                    'SubjectUserName')
                $memberName = [string]$Data['MemberName']
                $memberSid = [string]$Data['MemberSid']
                $linkedBySid = (-not [string]::IsNullOrEmpty($CreatedUserSid) -and
                    $memberSid -eq $CreatedUserSid)
                $linkedByName = ($memberName -eq $SimulatedUser -or
                    $memberName.EndsWith("\$SimulatedUser", [StringComparison]::OrdinalIgnoreCase))

                if ($linkedBySid -or $linkedByName) {
                    $match = $true
                    $full = (Field-IsPresent $Data 'TargetSid') -and
                            (Field-IsPresent $Data 'MemberSid')
                }
                elseif ([math]::Abs(($Record.TimeCreated.ToUniversalTime() -
                            $ActionTime).TotalSeconds) -le 5) {
                    # Local group membership events often show MemberName as '-'.
                    # A close timestamp and Administrators SID are weaker evidence.
                    $match = $true
                    $full = $false
                }
            }
        }
        3 {
            if ($Source -eq 'PowerShell' -and $id -eq 4104) {
                $text = [string]$Data['ScriptBlockText']
                if ($text.Trim() -eq $HarmlessPayload) {
                    $match = $true
                    $names = @('ScriptBlockText', 'ScriptBlockId', 'MessageNumber', 'MessageTotal')
                    $full = (Field-IsPresent $Data 'ScriptBlockId')
                }
            }
            elseif ($Source -eq 'Sysmon' -and $id -eq 1) {
                $image = [string]$Data['Image']
                $command = [string]$Data['CommandLine']
                if ($image -match '(?i)\\(powershell|pwsh)\.exe$' -and
                    ($command.Contains($EncodedPayload) -or
                     $command -match '(?i)-(encodedcommand|enc)\b')) {
                    $match = $true
                    $names = @('Image', 'CommandLine', 'ParentImage', 'ProcessGuid', 'User')
                    $full = (Field-IsPresent $Data 'CommandLine') -and
                            (Field-IsPresent $Data 'ParentImage')
                }
            }
            elseif ($Source -eq 'Security' -and $id -eq 4688) {
                $image = [string]$Data['NewProcessName']
                $command = [string]$Data['CommandLine']
                if ($image -match '(?i)\\(powershell|pwsh)\.exe$' -and
                    ($command.Contains($EncodedPayload) -or
                     $command -match '(?i)-(encodedcommand|enc)\b')) {
                    $match = $true
                    $names = @('NewProcessName', 'CommandLine', 'SubjectUserName',
                        'NewProcessId', 'ParentProcessName')
                    $full = (Field-IsPresent $Data 'CommandLine') -and
                            (Field-IsPresent $Data 'SubjectUserName')
                }
            }
        }
        4 {
            if ($Source -eq 'Sysmon' -and $id -eq 1) {
                $image = [string]$Data['Image']
                $command = [string]$Data['CommandLine']
                if ($image -match '(?i)\\schtasks\.exe$' -and
                    $command -match '(?i)/create\b' -and
                    $command.Contains($SimulatedTask)) {
                    $match = $true
                    $names = @('Image', 'CommandLine', 'ParentImage', 'ProcessGuid')
                    $full = (Field-IsPresent $Data 'CommandLine') -and
                            (Field-IsPresent $Data 'ParentImage')
                }
            }
            elseif ($Source -eq 'Security' -and $id -eq 4698 -and
                ([string]$Data['TaskName']).Contains($SimulatedTask)) {
                $match = $true
                $names = @('TaskName', 'SubjectUserName', 'TaskContent')
                $full = (Field-IsPresent $Data 'TaskName') -and
                        (Field-IsPresent $Data 'SubjectUserName')
            }
            elseif ($Source -eq 'Security' -and $id -eq 4688) {
                $image = [string]$Data['NewProcessName']
                $command = [string]$Data['CommandLine']
                if ($image -match '(?i)\\schtasks\.exe$' -and
                    $command -match '(?i)/create\b' -and
                    $command.Contains($SimulatedTask)) {
                    $match = $true
                    $names = @('NewProcessName', 'CommandLine', 'SubjectUserName')
                    $full = (Field-IsPresent $Data 'CommandLine') -and
                            (Field-IsPresent $Data 'SubjectUserName')
                }
            }
        }
        5 {
            if ($Source -eq 'Sysmon' -and $id -eq 3 -and
                $Data['DestinationIp'] -eq $DestinationIP -and
                [string]$Data['DestinationPort'] -eq $DestinationPort -and
                [string]$Data['Image'] -match '(?i)\\(powershell|pwsh)\.exe$') {
                $match = $true
                $names = @('Image', 'DestinationIp', 'DestinationPort', 'SourceIp',
                    'SourcePort', 'Protocol', 'Initiated', 'ProcessGuid')
                $full = (Field-IsPresent $Data 'SourceIp') -and
                        (Field-IsPresent $Data 'Image')
            }
        }
        6 {
            if ($Source -eq 'Sysmon' -and $id -eq 11 -and
                ([string]$Data['TargetFilename']).EndsWith(
                    "\$StartupFileName", [StringComparison]::OrdinalIgnoreCase) -and
                ([string]$Data['TargetFilename']) -match '(?i)\\StartUp\\') {
                $match = $true
                $names = @('TargetFilename', 'Image', 'ProcessGuid', 'User')
                $full = (Field-IsPresent $Data 'TargetFilename') -and
                        (Field-IsPresent $Data 'Image')
            }
            elseif ($Source -eq 'Security' -and $id -eq 4663 -and
                ([string]$Data['ObjectName']).EndsWith(
                    "\$StartupFileName", [StringComparison]::OrdinalIgnoreCase) -and
                ([string]$Data['ObjectName']) -match '(?i)\\StartUp\\') {
                $match = $true
                $names = @('ObjectName', 'ProcessName', 'Accesses', 'SubjectUserName')
                $full = (Field-IsPresent $Data 'ProcessName') -and
                        (Field-IsPresent $Data 'Accesses')
            }
        }
    }

    if (-not $match) { return $null }

    $level = if ($full) { 'full' } else { 'partial' }
    return [pscustomobject]@{
        source             = if ($Source -eq 'PowerShell') { 'PS ScriptBlock' } else { $Source }
        channel            = $Record.LogName
        event_id           = $id
        event_timestamp    = $Record.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        record_id          = $Record.RecordId
        detail_level       = $level
        key_fields_present = Get-KeyFields -Fields $Data -Names $names
    }
}

if (-not $env:WINDIR) {
    throw 'Run this script on the Windows machine that produced the Task 9 events.'
}
if (-not (Test-Path -LiteralPath $GroundTruthPath -PathType Leaf)) {
    throw "Ground truth not found: $GroundTruthPath. Run Task 9 first."
}

$groundTruth = @(Get-Content -LiteralPath $GroundTruthPath -Raw -Encoding UTF8 |
    ConvertFrom-Json)
if ($groundTruth.Count -eq 0) { throw 'The ground truth JSON has no actions.' }

# Accept either a plain Task 9 array or an object with an actions array.
if ($groundTruth.Count -eq 1 -and $null -ne $groundTruth[0].PSObject.Properties['actions']) {
    $groundTruth = @($groundTruth[0].actions)
}

$actionTimes = @{}
$endTimes = @{}
foreach ($action in $groundTruth) {
    $number = [int]$action.action_number
    $actionTimes[$number] = [DateTimeOffset]::Parse([string]$action.timestamp).UtcDateTime
    $end = $actionTimes[$number]
    if ($null -ne $action.PSObject.Properties['completed_at_utc'] -and
        -not [string]::IsNullOrWhiteSpace([string]$action.completed_at_utc)) {
        $end = [DateTimeOffset]::Parse([string]$action.completed_at_utc).UtcDateTime
    }
    $endTimes[$number] = $end
    if ($null -ne $action.PSObject.Properties['hostname'] -and $action.hostname -and
        $action.hostname -ne $env:COMPUTERNAME) {
        Write-Warning "Task 9 ran on '$($action.hostname)' but this is '$env:COMPUTERNAME'."
    }
}

$first = @($actionTimes.Values | Sort-Object)[0]
$last = @($endTimes.Values | Sort-Object -Descending)[0]
$from = ([datetime]$first).AddSeconds(-$WindowSeconds)
$until = ([datetime]$last).AddSeconds($WindowSeconds)

Write-Host ('[*] Loading ground truth ({0} actions)...' -f $groundTruth.Count)
Write-Host '[*] Searching Security, Sysmon and PowerShell logs...'

$events = @{}
foreach ($source in $Channels.Keys) {
    $channel = $Channels[$source]
    $events[$source] = @()
    try {
        $null = Get-WinEvent -ListLog $channel.Name -ErrorAction Stop
        $events[$source] = @(Get-WinEvent -FilterHashtable @{
            LogName   = $channel.Name
            ID        = $channel.IDs
            StartTime = $from.ToLocalTime()
            EndTime   = $until.ToLocalTime()
        } -ErrorAction Stop)
    }
    catch {
        if ($_.Exception.Message -notmatch 'No events were found|NoMatchingEventsFound') {
            Write-Warning ("Cannot read {0}: {1}" -f $source, $_.Exception.Message)
        }
    }
}

# Local group event 4732 may contain only a SID, not the new user's name.
# Link that SID to Security 4720 when possible.
$createdUserSid = ''
foreach ($eventRecord in $events['Security']) {
    if ($eventRecord.Id -ne 4720) { continue }
    $data = Get-EventFields -Record $eventRecord
    if ($data['TargetUserName'] -eq $SimulatedUser -and
        (Field-IsPresent $data 'TargetSid')) {
        $createdUserSid = [string]$data['TargetSid']
        break
    }
}

$matrix = [System.Collections.Generic.List[object]]::new()
$capturedCount = 0
$multiSourceCount = 0

foreach ($action in ($groundTruth | Sort-Object { [int]$_.action_number })) {
    $number = [int]$action.action_number
    $start = $actionTimes[$number].AddSeconds(-$WindowSeconds)
    $end = $endTimes[$number].AddSeconds($WindowSeconds)
    $detectionsForAction = [System.Collections.Generic.List[object]]::new()

    foreach ($source in $Channels.Keys) {
        foreach ($eventRecord in $events[$source]) {
            if ($null -eq $eventRecord.TimeCreated -or
                $eventRecord.TimeCreated.ToUniversalTime() -lt $start -or
                $eventRecord.TimeCreated.ToUniversalTime() -gt $end) { continue }

            $data = Get-EventFields -Record $eventRecord
            $found = Get-DetectionMatch -ActionNumber $number -Source $source `
                -Record $eventRecord -Data $data -CreatedUserSid $createdUserSid `
                -ActionTime $actionTimes[$number]
            if ($null -ne $found) { $detectionsForAction.Add($found) }
        }
    }

    # One best record per source/Event ID, with preference for full detail.
    $bestMatches = @($detectionsForAction | Sort-Object `
        @{ Expression = { if ($_.detail_level -eq 'full') { 0 } else { 1 } } },
        @{ Expression = { [math]::Abs((([DateTimeOffset]::Parse($_.event_timestamp)).UtcDateTime -
                    $actionTimes[$number]).TotalSeconds) } } |
        Group-Object { "$($_.source)|$($_.event_id)" } |
        ForEach-Object { $_.Group | Select-Object -First 1 })

    $captured = $bestMatches.Count -gt 0
    $detail = if (-not $captured) { 'missed' }
              elseif (@($bestMatches | Where-Object { $_.detail_level -eq 'full' }).Count -gt 0) { 'full' }
              else { 'partial' }
    $sources = @($bestMatches | ForEach-Object { $_.source } | Select-Object -Unique)
    if ($captured) { $capturedCount++ }
    if ($sources.Count -gt 1) { $multiSourceCount++ }

    $matrix.Add([pscustomobject]@{
        action_number         = $number
        description           = [string]$action.description
        timestamp             = [string]$action.timestamp
        ground_truth_status   = [string]$action.status
        mitre_attack_id       = [string]$action.mitre_attack_id
        window_start_utc      = $start.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        window_end_utc        = $end.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        status                = if ($captured) { 'CAPTURED' } else { 'MISSED' }
        detail_level          = $detail
        captured_by           = $sources
        event_ids             = @($bestMatches | ForEach-Object { $_.event_id } | Select-Object -Unique)
        key_fields_present    = @($bestMatches | ForEach-Object { $_.key_fields_present })
        detections            = @($bestMatches)
    })
}

Write-Host ''
Write-Host ('{0,-26} {1,-16} {2,-9} {3,-8} {4}' -f 'Action', 'Source', 'Event ID', 'Detail', 'Status')
Write-Host ('-' * 81)
foreach ($entry in $matrix) {
    if ($entry.detections.Count -eq 0) {
        Write-Host ('{0,-26} {1,-16} {2,-9} {3,-8} {4}' -f `
            $entry.description, '-', '-', 'Missed', '[MISSED]')
    }
    else {
        $firstLine = $true
        foreach ($detection in $entry.detections) {
            $label = if ($firstLine) { $entry.description } else { '' }
            Write-Host ('{0,-26} {1,-16} {2,-9} {3,-8} {4}' -f `
                $label, $detection.source, $detection.event_id,
                $detection.detail_level, '[CAPTURED]')
            $firstLine = $false
        }
    }
}

$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$parent = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $parent)) {
    New-Item -Path $parent -ItemType Directory -Force | Out-Null
}
$json = ConvertTo-Json -InputObject @($matrix.ToArray()) -Depth 12
[System.IO.File]::WriteAllText($OutputPath, $json + [Environment]::NewLine,
    ([System.Text.UTF8Encoding]::new($false)))

$percent = [math]::Round(($capturedCount / $groundTruth.Count) * 100)
Write-Host ''
Write-Host ('Actions: {0} | Captured: {1}/{0} ({2}%) | Multi-source: {3}' -f `
    $groundTruth.Count, $capturedCount, $percent, $multiSourceCount)
Write-Host ('Report saved to: {0}' -f $OutputPath)
