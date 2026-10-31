# Name: 3-windows_telemetry_export.ps1
# Purpose: Export and normalise Windows Security, Sysmon and PowerShell events as JSON.
# Author: Suraya

param(
    [ValidateRange(1, 8760)]
    [int]$Hours = 24,
    [string]$OutputPath = (Join-Path $PSScriptRoot 'windows_events_export.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Extract named fields from an event's XML. These are more reliable than
# splitting the human-readable event message.
function Get-EventFields {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord)

    $fields = @{}
    [xml]$eventXml = $EventRecord.ToXml()
    $nodes = $eventXml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")

    foreach ($node in $nodes) {
        $name = $node.GetAttribute('Name')
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $fields[$name] = $node.InnerText
        }
    }
    return $fields
}

# Give every event the same core fields and enrich the important event types.
function Convert-EventRecord {
    param(
        [System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord,
        [string]$SourceType
    )

    $data = Get-EventFields -EventRecord $EventRecord
    $message = $null
    try { $message = $EventRecord.Message } catch { $message = $null }

    $record = [ordered]@{
        timestamp      = $EventRecord.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        hostname       = $env:COMPUTERNAME
        platform       = 'Windows'
        source_type    = $SourceType
        channel        = $EventRecord.LogName
        event_id       = [int]$EventRecord.Id
        event_category = 'other'
        provider       = $EventRecord.ProviderName
        raw_message    = $message
    }

    switch ("$SourceType/$($EventRecord.Id)") {
        'Security/4624' {
            $record['event_category'] = 'successful_logon'
            $record['target_user'] = $data['TargetUserName']
            $record['logon_type'] = $data['LogonType']
            $record['source_ip'] = $data['IpAddress']
            $record['workstation'] = $data['WorkstationName']
        }
        'Security/4625' {
            $record['event_category'] = 'failed_logon'
            $record['target_user'] = $data['TargetUserName']
            $record['failure_reason'] = $data['FailureReason']
            $record['source_ip'] = $data['IpAddress']
            $record['status'] = $data['Status']
            $record['sub_status'] = $data['SubStatus']
        }
        'Security/4672' {
            $record['event_category'] = 'special_privileges_assigned'
            $record['privileged_account'] = $data['SubjectUserName']
            $record['privileges'] = $data['PrivilegeList']
        }
        'Security/4688' {
            $record['event_category'] = 'process_creation'
            $record['process_name'] = $data['NewProcessName']
            $record['command_line'] = $data['CommandLine']
            if ($data['ParentProcessName']) {
                $record['parent_process'] = $data['ParentProcessName']
            } elseif ($data['CreatorProcessName']) {
                $record['parent_process'] = $data['CreatorProcessName']
            }
        }
        'PowerShell/4104' {
            $record['event_category'] = 'script_block_logging'
            $record['script_block_text'] = $data['ScriptBlockText']
        }
        'Sysmon/1' {
            $record['event_category'] = 'process_creation'
            $record['image'] = $data['Image']
            $record['command_line'] = $data['CommandLine']
            $record['parent_image'] = $data['ParentImage']
            $record['hashes'] = $data['Hashes']
        }
        'Sysmon/3' {
            $record['event_category'] = 'network_connection'
            $record['destination_ip'] = $data['DestinationIp']
            $record['destination_port'] = $data['DestinationPort']
            $record['process'] = $data['Image']
        }
        'Sysmon/11' {
            $record['event_category'] = 'file_creation'
            $record['target_filename'] = $data['TargetFilename']
            $record['creating_process'] = $data['Image']
        }
        'Sysmon/13' {
            $record['event_category'] = 'registry_modification'
            $target = $data['TargetObject']
            $record['registry_key'] = $target
            $record['value_name'] = $null
            if ($target) {
                $lastSlash = $target.LastIndexOf('\')
                if ($lastSlash -ge 0) {
                    $record['registry_key'] = $target.Substring(0, $lastSlash)
                    $record['value_name'] = $target.Substring($lastSlash + 1)
                }
            }
            $record['registry_value'] = $data['Details']
        }
        'Sysmon/22' {
            $record['event_category'] = 'dns_query'
            $record['query_name'] = $data['QueryName']
            $record['query_results'] = $data['QueryResults']
        }
        default {
            $record['event_category'] = "${SourceType}_event".ToLowerInvariant()
        }
    }

    return [pscustomobject]$record
}

$startTime = (Get-Date).AddHours(-$Hours)
$logs = [ordered]@{
    Security   = 'Security'
    Sysmon     = 'Microsoft-Windows-Sysmon/Operational'
    PowerShell = 'Microsoft-Windows-PowerShell/Operational'
}
$channelCounts = @{}
$idCounts = @{}
$total = 0
$failedLogs = @()

$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$parentFolder = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $parentFolder)) {
    New-Item -ItemType Directory -Path $parentFolder -Force | Out-Null
}

Write-Host "[*] Exporting Windows telemetry from last $Hours hours..."

# Stream events directly to disk, so large Security logs do not fill memory.
$encoding = New-Object System.Text.UTF8Encoding($false)
$writer = New-Object System.IO.StreamWriter($OutputPath, $false, $encoding)
try {
    $writer.WriteLine('[')

    foreach ($sourceType in $logs.Keys) {
        $channelCounts[$sourceType] = 0
        $logName = $logs[$sourceType]

        try {
            Get-WinEvent -FilterHashtable @{
                LogName = $logName
                StartTime = $startTime
            } -ErrorAction Stop | ForEach-Object {
                $eventRecord = $_
                try {
                    $record = Convert-EventRecord -EventRecord $eventRecord -SourceType $sourceType
                    $json = ConvertTo-Json -InputObject $record -Depth 6 -Compress

                    if ($total -gt 0) { $writer.WriteLine(',') }
                    $writer.Write($json)

                    $total++
                    $channelCounts[$sourceType]++
                    $label = if ($sourceType -eq 'Sysmon') {
                        "Sysmon-$($eventRecord.Id)"
                    } elseif ($sourceType -eq 'PowerShell') {
                        "PowerShell-$($eventRecord.Id)"
                    } else {
                        [string]$eventRecord.Id
                    }
                    if (-not $idCounts.ContainsKey($label)) { $idCounts[$label] = 0 }
                    $idCounts[$label]++
                } catch {
                    Write-Warning "Skipped event $($eventRecord.Id) from ${sourceType}: $($_.Exception.Message)"
                }
            }
        } catch {
            # Get-WinEvent throws when a log has no matching events.
            if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') {
                Write-Warning "Could not read ${logName}: $($_.Exception.Message)"
                $failedLogs += $logName
            }
        }
    }

    $writer.WriteLine()
    $writer.WriteLine(']')
} finally {
    $writer.Dispose()
}

Write-Host "Security events: $($channelCounts['Security'])"
Write-Host "Sysmon events: $($channelCounts['Sysmon'])"
Write-Host "PowerShell events: $($channelCounts['PowerShell'])"
Write-Host "Total events: $total"

$topIds = @($idCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 5)
$topText = if ($topIds.Count -gt 0) { ($topIds | ForEach-Object { $_.Key }) -join ', ' } else { 'none' }
Write-Host "Top Event IDs: $topText"
Write-Host "Output: $OutputPath"

if ($failedLogs.Count -gt 0) {
    Write-Warning "Export is incomplete. Check permissions or availability of: $($failedLogs -join ', ')"
    exit 1
}
