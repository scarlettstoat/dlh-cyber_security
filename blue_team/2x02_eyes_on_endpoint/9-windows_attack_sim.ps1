# Name: 9-windows_attack_sim.ps1
# Purpose: Simulate six harmless attacker-like actions and record ground truth for SOC validation.
# Author: DLH Cybersecurity Academy student
# Project: MedDefense - Eyes on the Endpoint (2x02), Task 9
# Run: Open Windows PowerShell as Administrator on a dedicated Windows lab endpoint.
# Note: This script creates temporary local artifacts and removes them after recording.

#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$UserName = 'support_update'
$TaskName = 'DLH_EyesOnEndpoint_Sim'
$StartupDirectory = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
$StartupFile = Join-Path $StartupDirectory 'DLH_endpoint_simulation.txt'
$OutputFile = Join-Path $PSScriptRoot 'windows_attack_log.json'
$ExternalIP = '1.1.1.1'  # Public DNS service; only a TCP connection test, no data transfer.
$ExternalPort = 443

$script:GroundTruth = [System.Collections.Generic.List[object]]::new()
$script:CreatedUser = $false
$script:CreatedTask = $false
$script:CreatedFile = $false
$script:ConnectionReachable = $null

function Get-UtcTimestamp {
    return [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
}

function Save-GroundTruth {
    # -InputObject preserves the outer JSON array, including when zero or one item exists.
    $json = ConvertTo-Json -InputObject @($script:GroundTruth.ToArray()) -Depth 6
    [System.IO.File]::WriteAllText($OutputFile, $json + [Environment]::NewLine,
        ([System.Text.UTF8Encoding]::new($false)))
}

function Invoke-SimulatedAction {
    param(
        [int]$Number,
        [string]$Description,
        [string[]]$DetectionSources,
        [string]$MitreId,
        [string]$MitreTechnique,
        [scriptblock]$Action
    )

    $start = Get-UtcTimestamp
    Write-Host ('    [{0}/6] {1}... {2}' -f $Number, $Description, $start)
    $status = 'SUCCESS'
    $errorMessage = $null

    try {
        & $Action
    }
    catch {
        $status = 'FAILED'
        $errorMessage = $_.Exception.Message
        Write-Warning ('Action {0} failed: {1}' -f $Number, $errorMessage)
    }

    $script:GroundTruth.Add([pscustomobject]@{
        action_number              = $Number
        description                = $Description
        timestamp                  = $start
        completed_at_utc           = Get-UtcTimestamp
        hostname                   = $env:COMPUTERNAME
        status                     = $status
        expected_detection_source  = $DetectionSources
        mitre_attack_id            = $MitreId
        mitre_attack_technique     = $MitreTechnique
        error                      = $errorMessage
    })

    # Save each entry in case the lab session closes before the cleanup stage.
    Save-GroundTruth
}

function Confirm-LabEnvironment {
    if (-not $env:WINDIR) {
        throw 'This simulation must run on Windows, not Ubuntu or Kali.'
    }

    foreach ($command in @('New-LocalUser', 'Add-LocalGroupMember', 'Get-LocalUser',
                           'Remove-LocalUser', 'Get-LocalGroup', 'Test-NetConnection')) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "Required Windows command is unavailable: $command"
        }
    }

    # Domain controllers do not maintain normal local user accounts.
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($computer.DomainRole -ge 4) {
        throw 'This machine is a domain controller. Run on a Windows lab workstation/member server; do not create domain accounts.'
    }

    # Refuse to overwrite or delete anything that existed before this test.
    if (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue) {
        throw "Local user '$UserName' already exists. No changes were made."
    }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        throw "Scheduled task '$TaskName' already exists. No changes were made."
    }
    if (Test-Path -LiteralPath $StartupFile) {
        throw "Startup file '$StartupFile' already exists. No changes were made."
    }
}

function Remove-SimulationArtifacts {
    Write-Host '[*] Cleaning up artifacts...'

    # Check for our artifacts even if the creation command reported an error afterward.
    try {
        if ($script:CreatedFile -or (Test-Path -LiteralPath $StartupFile)) {
            Remove-Item -LiteralPath $StartupFile -Force -ErrorAction Stop
        }
        Write-Host '    Startup file removed or not created.'
    }
    catch { Write-Warning "Startup file cleanup failed: $($_.Exception.Message)" }

    try {
        if ($script:CreatedTask -or (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
            & schtasks.exe /Delete /TN $TaskName /F | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'schtasks /delete returned an error.' }
        }
        Write-Host '    Scheduled task removed or not created.'
    }
    catch { Write-Warning "Scheduled task cleanup failed: $($_.Exception.Message)" }

    try {
        if ($script:CreatedUser -or (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)) {
            Remove-LocalUser -Name $UserName -ErrorAction Stop
        }
        Write-Host '    Temporary user removed or not created.'
    }
    catch { Write-Warning "Local user cleanup failed: $($_.Exception.Message)" }
}

Write-Host '[*] Running Windows attacker simulation...'
Confirm-LabEnvironment

try {
    Invoke-SimulatedAction -Number 1 -Description "Creating local user '$UserName'" `
        -DetectionSources @('Security Event ID 4720') `
        -MitreId 'T1136.001' -MitreTechnique 'Create Account: Local Account' -Action {
            # The account is disabled and has a unique strong password; it cannot be used to log in.
            $bytes = New-Object byte[] 24
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
            $passwordText = 'Aa1!' + [Convert]::ToBase64String($bytes)
            $password = ConvertTo-SecureString $passwordText -AsPlainText -Force
            New-LocalUser -Name $UserName -Password $password -Disabled `
                -Description 'Temporary DLH endpoint detection simulation' -ErrorAction Stop | Out-Null
            $script:CreatedUser = $true
        }

    Invoke-SimulatedAction -Number 2 -Description 'Adding user to Administrators group' `
        -DetectionSources @('Security Event ID 4732') `
        -MitreId 'T1098.007' -MitreTechnique 'Account Manipulation: Additional Local or Domain Groups' -Action {
            if (-not $script:CreatedUser) { throw 'The temporary local user was not created.' }
            # The built-in Administrators SID works on non-English Windows installations too.
            $adminSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
            $adminGroup = Get-LocalGroup -SID $adminSid -ErrorAction Stop
            Add-LocalGroupMember -Group $adminGroup.Name -Member $UserName -ErrorAction Stop
        }

    Invoke-SimulatedAction -Number 3 -Description 'Running encoded PowerShell' `
        -DetectionSources @('Sysmon Event ID 1', 'Security Event ID 4688', 'PowerShell Event ID 4104') `
        -MitreId 'T1059.001' -MitreTechnique 'Command and Scripting Interpreter: PowerShell' -Action {
            $payload = 'Write-Host "C2 beacon"'   # Harmless demonstration; no actual beaconing.
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
            $powershellExe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $process = Start-Process -FilePath $powershellExe `
                -ArgumentList "-NoProfile -NonInteractive -EncodedCommand $encoded" `
                -PassThru -Wait -WindowStyle Hidden -ErrorAction Stop
            if ($process.ExitCode -ne 0) { throw "PowerShell exited with code $($process.ExitCode)." }
        }

    Invoke-SimulatedAction -Number 4 -Description 'Creating scheduled task' `
        -DetectionSources @('Security Event ID 4698', 'TaskScheduler Event ID 106', 'Sysmon Event ID 1') `
        -MitreId 'T1053.005' -MitreTechnique 'Scheduled Task/Job: Scheduled Task' -Action {
            # On-logon trigger is never deliberately started; the task command only exits.
            & schtasks.exe /Create /TN $TaskName /SC ONLOGON /TR 'cmd.exe /c exit 0' /RU SYSTEM | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'schtasks /create returned an error.' }
            $script:CreatedTask = $true
        }

    Invoke-SimulatedAction -Number 5 -Description 'Initiating outbound network connection' `
        -DetectionSources @('Sysmon Event ID 3') `
        -MitreId 'T1095' -MitreTechnique 'Non-Application Layer Protocol (TCP connection test only)' -Action {
            # Network reachability may fail in an isolated lab; the attempted test is still recorded.
            $script:ConnectionReachable = [bool](Test-NetConnection -ComputerName $ExternalIP `
                -Port $ExternalPort -InformationLevel Quiet -WarningAction SilentlyContinue)
            Write-Host "        TCP reachable: $script:ConnectionReachable"
        }

    Invoke-SimulatedAction -Number 6 -Description 'Dropping file in Startup directory' `
        -DetectionSources @('Sysmon Event ID 11', 'Security Event ID 4663 if file auditing is enabled') `
        -MitreId 'T1547.001' -MitreTechnique 'Boot or Logon Autostart Execution: Startup Folder' -Action {
            if (-not (Test-Path -LiteralPath $StartupDirectory -PathType Container)) {
                throw "Startup directory not found: $StartupDirectory"
            }
            # A .txt marker creates a file event but cannot run as a startup program.
            Set-Content -LiteralPath $StartupFile -Value 'DLH test marker - safe to delete.' `
                -Encoding UTF8 -ErrorAction Stop
            $script:CreatedFile = $true
        }
}
finally {
    # Save the log before cleanup so Task 10 can match the six action timestamps.
    Save-GroundTruth
    Remove-SimulationArtifacts
}

$successful = @($script:GroundTruth | Where-Object { $_.status -eq 'SUCCESS' }).Count
Write-Host ('Actions executed: {0}/6' -f $successful)
Write-Host ('Ground truth saved to: {0}' -f $OutputFile)
if ($successful -ne 6) {
    Write-Warning 'Some actions failed; review the statuses in windows_attack_log.json.'
    exit 1
}
