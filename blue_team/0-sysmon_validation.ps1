# Name: 0-sysmon_validation.ps1
# Purpose: Validate five Sysmon event types using controlled endpoint actions.
# Author: Suraya

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$logName = 'Microsoft-Windows-Sysmon/Operational'
$runId = [guid]::NewGuid().ToString('N').Substring(0, 8)
$testFile = "C:\Windows\Temp\SysmonTest_$runId.txt"
$registryKey = "HKCU:\Software\SysmonTest_$runId"
$registryValue = 'Validation'
$destinationIp = '1.1.1.1'
$destinationPort = 443
$domain = 'example.com'
$captured = 0

# Read the named fields from an event instead of searching formatted messages.
function Get-SysmonFields {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord)

    $fields = @{}
    [xml]$eventXml = $EventRecord.ToXml()
    foreach ($item in $eventXml.Event.EventData.Data) {
        $fields[$item.GetAttribute('Name')] = $item.InnerText
    }
    return $fields
}

# Allow a few seconds for Sysmon to write its event to the log.
function Find-SysmonEvent {
    param(
        [int]$EventId,
        [datetime]$StartTime,
        [hashtable]$Expected,
        [scriptblock]$Check
    )

    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName = $logName
            Id = $EventId
            StartTime = $StartTime.AddSeconds(-1)
        } -ErrorAction SilentlyContinue)

        foreach ($event in $events) {
            $fields = Get-SysmonFields -EventRecord $event
            if (& $Check $fields $Expected) {
                return $event
            }
        }

        if ($attempt -lt 5) {
            Start-Sleep -Seconds 1
        }
    }
    return $null
}

function Show-TestResult {
    param(
        [int]$Number,
        [string]$Description,
        [int]$EventId,
        [datetime]$Started,
        [object]$FoundEvent,
        [string]$SuccessMessage
    )

    Write-Host "[$Number/5] $Description (Event ID $EventId)..."
    Write-Host ("    Started: {0}" -f $Started.ToString('o'))

    if ($null -ne $FoundEvent) {
        $script:captured++
        Write-Host "    $SuccessMessage [PASS]" -ForegroundColor Green
        Write-Host ("    Captured: {0}" -f $FoundEvent.TimeCreated.ToString('o'))
    }
    else {
        Write-Host '    Matching event or required details not found [FAIL]' -ForegroundColor Red
    }
}

try {
    Get-WinEvent -ListLog $logName -ErrorAction Stop | Out-Null
}
catch {
    Write-Host "Cannot access the Sysmon Operational log: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host '[*] Running Sysmon telemetry validation...'
Write-Host "[*] Test run: $runId"

try {
    # 1. Process creation: Sysmon should include cmd.exe and its arguments.
    $started = Get-Date
    try {
        cmd.exe /c whoami | Out-Null
    }
    catch {
        Write-Warning "Process test failed: $($_.Exception.Message)"
    }
    $found = Find-SysmonEvent -EventId 1 -StartTime $started -Expected @{} -Check {
        param($data, $expected)
        $data['Image'] -like '*\cmd.exe' -and
        $data['CommandLine'] -match '(?i)/c\s+whoami'
    }
    Show-TestResult -Number 1 -Description 'Process creation' -EventId 1 `
        -Started $started -FoundEvent $found `
        -SuccessMessage 'cmd.exe /c whoami -> command line present'

    # 2. Network connection: check the destination and originating process.
    $started = Get-Date
    try {
        Test-NetConnection -ComputerName $destinationIp -Port $destinationPort `
            -InformationLevel Quiet -WarningAction SilentlyContinue | Out-Null
    }
    catch {
        Write-Warning "Network test failed: $($_.Exception.Message)"
    }
    $found = Find-SysmonEvent -EventId 3 -StartTime $started `
        -Expected @{ Ip = $destinationIp; Port = [string]$destinationPort } -Check {
        param($data, $expected)
        $data['DestinationIp'] -eq $expected.Ip -and
        $data['DestinationPort'] -eq $expected.Port -and
        -not [string]::IsNullOrWhiteSpace($data['Image']) -and
        $data['Initiated'] -eq 'true'
    }
    Show-TestResult -Number 2 -Description 'Network connection' -EventId 3 `
        -Started $started -FoundEvent $found `
        -SuccessMessage 'Outbound TCP -> destination IP/port and process present'

    # 3. File creation: use a unique file so older events cannot match.
    $started = Get-Date
    try {
        Set-Content -Path $testFile -Value "Sysmon validation $runId" -ErrorAction Stop
    }
    catch {
        Write-Warning "File test failed: $($_.Exception.Message)"
    }
    $found = Find-SysmonEvent -EventId 11 -StartTime $started `
        -Expected @{ Path = $testFile } -Check {
        param($data, $expected)
        $data['TargetFilename'] -eq $expected.Path -and
        -not [string]::IsNullOrWhiteSpace($data['Image'])
    }
    Show-TestResult -Number 3 -Description 'File creation' -EventId 11 `
        -Started $started -FoundEvent $found `
        -SuccessMessage "$testFile -> target filename and process present"

    # 4. Registry modification: verify the path, value, and SetValue action.
    $started = Get-Date
    try {
        New-Item -Path $registryKey -Force | Out-Null
        New-ItemProperty -Path $registryKey -Name $registryValue `
            -Value "test_$runId" -PropertyType String -Force | Out-Null
    }
    catch {
        Write-Warning "Registry test failed: $($_.Exception.Message)"
    }
    $found = Find-SysmonEvent -EventId 13 -StartTime $started `
        -Expected @{ Key = "SysmonTest_$runId"; Value = $registryValue } -Check {
        param($data, $expected)
        $data['TargetObject'] -like "*\$($expected.Key)\$($expected.Value)" -and
        $data['EventType'] -eq 'SetValue'
    }
    Show-TestResult -Number 4 -Description 'Registry modification' -EventId 13 `
        -Started $started -FoundEvent $found `
        -SuccessMessage 'HKCU\...\SysmonTest -> registry path, value and SetValue present'

    # 5. DNS query: verify both the query name and its recorded result.
    $started = Get-Date
    try {
        nslookup.exe $domain | Out-Null
    }
    catch {
        Write-Warning "DNS test failed: $($_.Exception.Message)"
    }
    $found = Find-SysmonEvent -EventId 22 -StartTime $started `
        -Expected @{ Domain = $domain } -Check {
        param($data, $expected)
        $data['QueryName'] -eq $expected.Domain -and
        -not [string]::IsNullOrWhiteSpace($data['QueryResults']) -and
        $data['QueryResults'] -ne '-'
    }
    Show-TestResult -Number 5 -Description 'DNS query' -EventId 22 `
        -Started $started -FoundEvent $found `
        -SuccessMessage "nslookup $domain -> query and results present"
}
finally {
    Write-Host '[*] Cleanup: removing test artifacts...'
    Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $registryKey -Recurse -Force -ErrorAction SilentlyContinue
}

$missed = 5 - $captured
Write-Host "Actions tested: 5 | Captured: $captured | Missed: $missed"
