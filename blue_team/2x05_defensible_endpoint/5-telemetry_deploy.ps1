# Exit codes: 0 all actions verified, 1 verification failed, 2 missing prerequisite.
param(
    [string]$SysmonConfig = (Join-Path $PSScriptRoot '../2x01_windows_fortress/sysmonconfig.xml')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-TelemetryError {
    param([int]$Code, [string]$Message)
    [Console]::Error.WriteLine($Message)
    exit $Code
}

function Get-EventData {
    param($Record)
    [xml]$xml = $Record.ToXml()
    $fields = @{}
    foreach ($node in $xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) {
        $fields[$node.GetAttribute('Name')] = $node.InnerText
    }
    return $fields
}

function Find-ProbeRecord {
    param([string]$Channel, [int]$Id, [datetime]$Since, [scriptblock]$MatchesProbe)
    for ($attempt = 0; $attempt -lt 16; $attempt++) {
        $cutoff = (Get-Date).AddMinutes(-10)
        if ($Since -gt $cutoff) { $cutoff = $Since }
        $filter = @{ LogName = $Channel; Id = $Id; StartTime = $cutoff }
        try {
            foreach ($record in (Get-WinEvent -FilterHashtable $filter)) {
                if (& $MatchesProbe (Get-EventData -Record $record)) {
                    return [string]$record.RecordId
                }
            }
        }
        catch {
            if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') { throw }
        }
        Start-Sleep -Milliseconds 500
    }
}

function Invoke-RecordedAction {
    param(
        [string]$Name, [string]$Channel, [int]$Id,
        [scriptblock]$Operation, [scriptblock]$MatchesProbe
    )
    $since = Get-Date
    $evidence = @()
    $failure = $null
    try {
        $null = & $Operation
        $search = @{ Channel = $Channel; Id = $Id; Since = $since; MatchesProbe = $MatchesProbe }
        $evidence = @(Find-ProbeRecord @search)
        if ($evidence.Count -eq 0) { $failure = 'No matching event from this run.' }
    }
    catch { $failure = $_.Exception.Message }
    return [ordered]@{
        action = $Name
        source = $Channel
        expected = "Event ID $Id"
        passed = ($evidence.Count -gt 0)
        evidence = $evidence
        error = $failure
    }
}

function Invoke-ServiceProbe {
    param([ValidateSet('start', 'stop')][string]$Verb)
    if (-not $testService) { throw 'No stopped, enabled lab test service was available.' }
    if ($Verb -eq 'start') {
        $testService.Refresh()
        if ($testService.Status -ne 'Stopped') { throw 'The test service was already running.' }
    }
    elseif (-not $script:restoreService) { throw 'The test did not start the fixture service.' }

    $sc = Join-Path $env:SystemRoot 'System32/sc.exe'
    $process = Start-Process -FilePath $sc -ArgumentList @($Verb, $testService.Name) -PassThru -Wait -NoNewWindow
    if ($process.ExitCode -ne 0) { throw "Service action $Verb returned exit code $($process.ExitCode)." }
    if ($Verb -eq 'start') { $script:restoreService = $true }
    $script:probePid = $process.Id
    $goal = if ($Verb -eq 'start') { 'Running' } else { 'Stopped' }
    $testService.WaitForStatus($goal, [timespan]::FromSeconds(10))
    if ($Verb -eq 'stop') { $script:restoreService = $false }
}

if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) {
    Write-TelemetryError -Code 2 -Message 'Run this script in 64-bit PowerShell on the Windows lab VM.'
}
$computer = ([Net.Dns]::GetHostName() -split '\.')[0]
if ($computer -notin @('hawthorne-adm-01', 'hawthorne-adm-0')) {
    Write-TelemetryError -Code 2 -Message "Expected hawthorne-adm-01. Current host: $computer"
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-TelemetryError -Code 2 -Message 'Open PowerShell as Administrator.'
}

$sysmonLog = 'Microsoft-Windows-Sysmon/Operational'
$psLog = 'Microsoft-Windows-PowerShell/Operational'
$securityLog = 'Security'
$engine = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$exporter = Join-Path $PSScriptRoot '../2x02_eyes_on_endpoint/3-windows_telemetry_export.ps1'
$targetPath = Join-Path $PSScriptRoot 'capstone/target_state.json'
try {
    foreach ($path in @($engine, $exporter, $targetPath, $SysmonConfig)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing input: $path" }
    }
    $target = Get-Content -LiteralPath $targetPath -Raw | ConvertFrom-Json
    $controlIds = @($target.controls.id | Sort-Object -Unique)
    if ($target.schema_version -ne 'capstone-target-v1' -or $controlIds.Count -lt 29) {
        throw 'Invalid capstone target state.'
    }
    $null = [datetimeoffset]$target.generated_at

    $running = Get-Service -Name Sysmon, Sysmon64, Sysmon64a -ErrorAction SilentlyContinue |
        Where-Object Status -eq Running | Select-Object -First 1
    if (-not $running) { throw 'Sysmon must be installed and running. Run Task 4 on the Windows VM.' }
    foreach ($channel in @($sysmonLog, $psLog, $securityLog)) {
        $eventLog = Get-WinEvent -ListLog $channel
        if (-not $eventLog.IsEnabled) { throw "The $channel event channel is disabled." }
    }

    $configHash = (Get-FileHash -LiteralPath $SysmonConfig -Algorithm SHA256).Hash
    $configEvent = Get-WinEvent -FilterHashtable @{ LogName = $sysmonLog; Id = 16 } -MaxEvents 1
    $loadedHash = (Get-EventData -Record $configEvent)['ConfigurationFileHash']
    if ($loadedHash -notmatch "\bSHA256=$configHash\b") {
        throw 'The latest Sysmon configuration event does not identify the MedDefense XML.'
    }
    $policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if ((Get-ItemPropertyValue -LiteralPath $policy -Name EnableScriptBlockLogging) -ne 1) {
        throw 'PowerShell Script Block Logging is disabled. Run Task 4 on the Windows VM.'
    }
}
catch { Write-TelemetryError -Code 2 -Message $_.Exception.Message }

$output = Join-Path $PSScriptRoot 'capstone/telemetry'
$token = 'mdt-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$stage = Join-Path $output ".$token"
$lockFile = Join-Path $output '.windows_telemetry.lock'
[void][IO.Directory]::CreateDirectory($output)
try {
    $runLock = [IO.File]::Open($lockFile, 'OpenOrCreate', 'Write', 'None')
}
catch { Write-TelemetryError -Code 1 -Message 'Cannot acquire the Windows telemetry lock.' }

try {
    [void][IO.Directory]::CreateDirectory($stage)
    if ((Get-LocalUser -Name $token -ErrorAction SilentlyContinue) -or
        (Get-ScheduledTask -TaskName $token -TaskPath '\' -ErrorAction SilentlyContinue)) {
        throw 'The generated fixture name is already in use.'
    }
    $testService = Get-Service -Name WiaRpc, SCardSvr -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Stopped' -and $_.StartType -ne 'Disabled' } |
        Select-Object -First 1

    $ownsUser = $false
    $ownsTask = $false
    $script:restoreService = $false
    $script:probePid = 0
    $cleanupOk = $true
    try {
        # The account is disabled at creation and receives no privileged memberships.
        $userCheck = @{
            Name = 'create_user'; Channel = $securityLog; Id = 4720
            Operation = {
                $password = [Security.SecureString]::new()
                try {
                    foreach ($character in ([guid]::NewGuid().ToString('N') + 'Q9!a').ToCharArray()) {
                        $password.AppendChar($character)
                    }
                    New-LocalUser -Name $token -Password $password -Disabled -Description 'Hawthorne telemetry fixture'
                }
                finally { $password.Dispose() }
            }
            MatchesProbe = { param($fields) $fields['TargetUserName'] -eq $token }
        }
        $ownsUser = $true
        $userResult = Invoke-RecordedAction @userCheck

        # A triggerless task runs the fixed test marker once as LocalService.
        $taskCheck = @{
            Name = 'create_and_run_scheduled_task'; Channel = $sysmonLog; Id = 1
            Operation = {
                $cmd = Join-Path $env:SystemRoot 'System32/cmd.exe'
                $action = New-ScheduledTaskAction -Execute $cmd -Argument "/d /c echo $token-task"
                $account = New-ScheduledTaskPrincipal -UserId 'S-1-5-19' -LogonType ServiceAccount -RunLevel Limited
                $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([timespan]::FromSeconds(30))
                $task = @{
                    TaskName = $token; Action = $action; Principal = $account
                    Settings = $settings; TaskPath = '\'
                }
                Register-ScheduledTask @task | Out-Null
                Start-ScheduledTask -TaskName $token -TaskPath '\'
            }
            MatchesProbe = {
                param($fields)
                $fields['Image'] -like '*\cmd.exe' -and $fields['CommandLine'] -like "*echo $token-task*"
            }
        }
        $ownsTask = $true
        $taskResult = Invoke-RecordedAction @taskCheck

        $serviceCheck = @{
            Name = 'start_service'; Channel = $sysmonLog; Id = 1
            Operation = { Invoke-ServiceProbe -Verb start }
            MatchesProbe = {
                param($fields)
                $fields['Image'] -like '*\sc.exe' -and $fields['ProcessId'] -eq [string]$script:probePid
            }
        }
        $startResult = Invoke-RecordedAction @serviceCheck
        $serviceCheck.Name = 'stop_service'
        $serviceCheck.Operation = { Invoke-ServiceProbe -Verb stop }
        $stopResult = Invoke-RecordedAction @serviceCheck

        $psCheck = @{
            Name = 'powershell_command'; Channel = $psLog; Id = 4104
            Operation = {
                & $engine -NoLogo -NoProfile -NonInteractive -Command "Write-Output '$token-ps'" | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'The PowerShell test command failed.' }
            }
            MatchesProbe = { param($fields) $fields['ScriptBlockText'] -like "*Write-Output '$token-ps'*" }
        }
        $psResult = Invoke-RecordedAction @psCheck
        $results = @($userResult, $taskResult, $startResult, $stopResult, $psResult)
    }
    finally {
        if ($ownsTask) {
            try {
                if (Get-ScheduledTask -TaskName $token -TaskPath '\' -ErrorAction SilentlyContinue) {
                    Unregister-ScheduledTask -TaskName $token -TaskPath '\' -Confirm:$false
                }
            }
            catch { $cleanupOk = $false; Write-Warning $_.Exception.Message }
        }
        if ($ownsUser) {
            try {
                if (Get-LocalUser -Name $token -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $token }
            }
            catch { $cleanupOk = $false; Write-Warning $_.Exception.Message }
        }
        if ($script:restoreService) {
            try {
                Stop-Service -Name $testService.Name
                $testService.WaitForStatus('Stopped', [timespan]::FromSeconds(10))
            }
            catch { $cleanupOk = $false; Write-Warning $_.Exception.Message }
        }
    }

    $ended = [datetimeoffset]::UtcNow
    $start = $ended.AddMinutes(-30)
    $encoding = [Text.UTF8Encoding]::new($false)
    $exportOk = $false
    try {
        $rawPath = Join-Path $stage 'legacy_events.json'
        & $engine -NoLogo -NoProfile -NonInteractive -File $exporter -Hours 1 -OutputPath $rawPath
        if ($LASTEXITCODE -ne 0) { throw 'The Windows telemetry exporter failed.' }
        $rawEvents = Get-Content -LiteralPath $rawPath -Raw | ConvertFrom-Json
        $events = @(
            foreach ($entry in $rawEvents) {
                if ($entry.source_type -notin @('Sysmon', 'PowerShell')) { continue }
                $when = if ($entry.timestamp -is [datetime]) {
                    [datetimeoffset]$entry.timestamp
                }
                else { [datetimeoffset]::Parse($entry.timestamp, [cultureinfo]::InvariantCulture) }
                if ($when -ge $start -and $when -le $ended) { $entry }
            }
        )
        $sources = @($events | ForEach-Object source_type)
        if ('Sysmon' -notin $sources -or 'PowerShell' -notin $sources) {
            throw 'Expected Sysmon and PowerShell records in the 30-minute export.'
        }
        $eventPath = Join-Path $stage 'windows_events.json'
        [IO.File]::WriteAllText($eventPath, (ConvertTo-Json -InputObject $events -Depth 10) + [Environment]::NewLine, $encoding)
        Move-Item -LiteralPath $eventPath -Destination (Join-Path $output 'windows_events.json') -Force
        $exportOk = $true
    }
    catch { Write-Warning $_.Exception.Message }

    $allPassed = $exportOk -and $cleanupOk -and @($results | Where-Object { -not $_.passed }).Count -eq 0
    $coverage = [ordered]@{
        timestamp = $ended.ToString('o')
        hostname = $computer
        platform = 'windows'
        actions = $results
        export_ok = $exportOk
        cleanup_ok = $cleanupOk
        all_passed = $allPassed
    }
    $coveragePath = Join-Path $stage 'windows_coverage.json'
    [IO.File]::WriteAllText($coveragePath, (ConvertTo-Json -InputObject $coverage -Depth 8) + [Environment]::NewLine, $encoding)
    Move-Item -LiteralPath $coveragePath -Destination (Join-Path $output 'windows_coverage.json') -Force
    if ($allPassed) { exit 0 }
    Write-TelemetryError -Code 1 -Message 'Coverage failed. See capstone/telemetry/windows_coverage.json.'
}
catch { Write-TelemetryError -Code 1 -Message $_.Exception.Message }
finally {
    $runLock.Dispose()
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
