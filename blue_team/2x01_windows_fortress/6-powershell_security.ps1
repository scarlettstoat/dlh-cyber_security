#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    6-powershell_security.ps1 - PowerShell Security GPO
.PURPOSE
    Enable script block logging, module logging and transcription through
    Group Policy, check AMSI in the running host, and prove that an encoded
    PowerShell test command is recorded in decoded form as Event ID 4104.
.AUTHOR
    MedDefense Security Lab
.DATE
    2026-10-19
.NOTES
    Intended for the authorized DC01 lab in meddefense.local only.
    This script changes a domain-wide GPO. It does not disable PowerShell,
    bypass AMSI, or change execution policy.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedDomain = 'meddefense.local'
$gpoName = 'MedDefense - PowerShell Security'
$transcriptFolder = 'C:\PSTranscripts'
$operationalLog = 'Microsoft-Windows-PowerShell/Operational'
$policyBase = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell'

function Set-LoggingPolicy {
    param(
        [Parameter(Mandatory)][guid]$GpoId,
        [Parameter(Mandatory)][string]$DomainName,
        [Parameter(Mandatory)][string]$DomainController,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$ValueName,
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][Microsoft.Win32.RegistryValueKind]$Type
    )

    $parameters = @{
        Guid      = $GpoId
        Domain    = $DomainName
        Server    = $DomainController
        Key       = $Key
        ValueName = $ValueName
        Value     = $Value
        Type      = $Type
    }
    Set-GPRegistryValue @parameters | Out-Null

    # Read the value back from the GPO, not merely from the local machine.
    $saved = Get-GPRegistryValue -Guid $GpoId -Domain $DomainName `
        -Server $DomainController -Key $Key -ValueName $ValueName
    if ($null -eq $saved -or [string]$saved.Value -cne [string]$Value) {
        throw "The GPO did not retain $Key\$ValueName."
    }
}

function Assert-LocalPolicy {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ValueName,
        [Parameter(Mandatory)][object]$ExpectedValue
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "The effective policy key is missing: $Path"
    }
    # Read the literal registry value name (the module wildcard is named "*").
    $registryKey = Get-Item -LiteralPath $Path -ErrorAction Stop
    $actual = $registryKey.GetValue($ValueName, $null)
    if ([string]$actual -cne [string]$ExpectedValue) {
        throw "Effective policy mismatch: $Path\$ValueName is '$actual'; expected '$ExpectedValue'."
    }
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop

    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($computer.DomainRole -lt 4) {
        throw 'Run this script directly on the authorized MedDefense domain controller.'
    }

    $domain = Get-ADDomain -ErrorAction Stop
    if ($domain.DNSRoot -ine $expectedDomain) {
        throw "Unexpected domain: $($domain.DNSRoot). Expected $expectedDomain."
    }
    $dc = $domain.PDCEmulator
    $domainRoot = $domain.DistinguishedName
    Write-Host "[*] Domain verified: $expectedDomain" -ForegroundColor Cyan

    # Re-use an existing named GPO so re-running does not create duplicates.
    $gpo = Get-GPO -All -Domain $expectedDomain -Server $dc |
        Where-Object { $_.DisplayName -eq $gpoName } |
        Select-Object -First 1

    if ($null -eq $gpo) {
        $gpo = New-GPO -Name $gpoName -Domain $expectedDomain -Server $dc
        Write-Host "[*] Creating GPO: '$gpoName'... CREATED" -ForegroundColor Green
    } else {
        $backupLocation = Join-Path $env:ProgramData (
            'MedDefense\GPO-Backups\PowerShell-' + (Get-Date -Format 'yyyyMMdd_HHmmss')
        )
        New-Item -Path $backupLocation -ItemType Directory -Force | Out-Null
        Backup-GPO -Guid $gpo.Id -Domain $expectedDomain -Server $dc `
            -Path $backupLocation | Out-Null
        Write-Host "[*] Reusing GPO (backup: $backupLocation)" -ForegroundColor Yellow
    }

    $scriptBlockKey = "$policyBase\ScriptBlockLogging"
    $moduleKey = "$policyBase\ModuleLogging"
    $moduleNamesKey = "$moduleKey\ModuleNames"
    $transcriptionKey = "$policyBase\Transcription"

    # GPO machine-side Administrative Template settings, not ad-hoc local tweaks.
    Set-LoggingPolicy -GpoId $gpo.Id -DomainName $expectedDomain -DomainController $dc `
        -Key $scriptBlockKey -ValueName 'EnableScriptBlockLogging' -Value 1 -Type DWord
    Write-Host '[*] Script Block Logging: EnableScriptBlockLogging = 1  [SET]'
    Write-Host '    Event ID 4104 records the script content.'

    Set-LoggingPolicy -GpoId $gpo.Id -DomainName $expectedDomain -DomainController $dc `
        -Key $moduleKey -ValueName 'EnableModuleLogging' -Value 1 -Type DWord
    Set-LoggingPolicy -GpoId $gpo.Id -DomainName $expectedDomain -DomainController $dc `
        -Key $moduleNamesKey -ValueName '*' -Value '*' -Type String
    Write-Host '[*] Module Logging: EnableModuleLogging = 1; ModuleNames = *  [SET]'
    Write-Host '    Event ID 4103 records module pipeline activity.'

    Set-LoggingPolicy -GpoId $gpo.Id -DomainName $expectedDomain -DomainController $dc `
        -Key $transcriptionKey -ValueName 'EnableTranscripting' -Value 1 -Type DWord
    Set-LoggingPolicy -GpoId $gpo.Id -DomainName $expectedDomain -DomainController $dc `
        -Key $transcriptionKey -ValueName 'OutputDirectory' -Value $transcriptFolder -Type String
    Set-LoggingPolicy -GpoId $gpo.Id -DomainName $expectedDomain -DomainController $dc `
        -Key $transcriptionKey -ValueName 'EnableInvocationHeader' -Value 1 -Type DWord

    # Create the local output location on DC01; domain computers also need
    # this directory to be available with permissions suitable for transcripts.
    if (-not (Test-Path -LiteralPath $transcriptFolder)) {
        New-Item -Path $transcriptFolder -ItemType Directory -Force | Out-Null
    }
    Write-Host "[*] Transcription: OutputDirectory = $transcriptFolder  [SET]"

    # Domain-root link ensures computers can receive these machine policies.
    $links = @( (Get-GPInheritance -Target $domainRoot -Domain $expectedDomain -Server $dc).GpoLinks )
    $existingLink = $links | Where-Object { $_.DisplayName -eq $gpoName } |
        Select-Object -First 1
    if ($null -eq $existingLink) {
        New-GPLink -Guid $gpo.Id -Target $domainRoot -Domain $expectedDomain `
            -Server $dc -LinkEnabled Yes | Out-Null
        Write-Host '[*] Linked PowerShell Security GPO to the domain root.  [LINKED]'
    } elseif (-not $existingLink.Enabled) {
        Set-GPLink -Guid $gpo.Id -Target $domainRoot -Domain $expectedDomain `
            -Server $dc -LinkEnabled Yes | Out-Null
        Write-Host '[*] Re-enabled existing domain-root GPO link.  [LINKED]'
    } else {
        Write-Host '[*] Domain-root GPO link already enabled.  [OK]'
    }

    Write-Host '[*] Forcing computer Group Policy update...'
    & gpupdate.exe /target:computer /force
    if ($LASTEXITCODE -ne 0) {
        throw "gpupdate failed with exit code $LASTEXITCODE."
    }
    Write-Host '    Group Policy refresh completed.  [OK]'

    # Confirm that DC01 actually received the registry-backed settings.
    $localBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    Assert-LocalPolicy -Path "$localBase\ScriptBlockLogging" `
        -ValueName 'EnableScriptBlockLogging' -ExpectedValue 1
    Assert-LocalPolicy -Path "$localBase\ModuleLogging" `
        -ValueName 'EnableModuleLogging' -ExpectedValue 1
    Assert-LocalPolicy -Path "$localBase\ModuleLogging\ModuleNames" `
        -ValueName '*' -ExpectedValue '*'
    Assert-LocalPolicy -Path "$localBase\Transcription" `
        -ValueName 'EnableTranscripting' -ExpectedValue 1
    Assert-LocalPolicy -Path "$localBase\Transcription" `
        -ValueName 'OutputDirectory' -ExpectedValue $transcriptFolder
    Write-Host '[*] Effective DC01 PowerShell logging policy... VERIFIED' -ForegroundColor Green

    # Inspect the current PowerShell process for the AMSI integration DLL.
    # A loaded DLL indicates the integration is present; it does not prove
    # antivirus provider health or resistance to runtime tampering.
    $amsiModule = @(Get-Process -Id $PID -Module -ErrorAction Stop |
        Where-Object { $_.ModuleName -ieq 'amsi.dll' })
    if ($amsiModule.Count -gt 0) {
        Write-Host '[*] AMSI integration: amsi.dll loaded in current PowerShell process.  [OK]'
    } else {
        Write-Warning 'AMSI integration not confirmed: amsi.dll not loaded in this PowerShell process.'
    }

    # -EncodedCommand requires UTF-16LE. A unique marker distinguishes this
    # test from old events, and a new process picks up the applied policy.
    $marker = 'MedDefense-4104-' + [guid]::NewGuid().ToString('N')
    $testCommand = 'Write-Host "' + $marker + '"'
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($testCommand))
    $testStarted = (Get-Date).AddSeconds(-2)

    Write-Host '[*] Testing encoded PowerShell command...'
    Write-Host "    Decoded test content: $testCommand"
    $windowsPowerShell = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $testProcess = Start-Process -FilePath $windowsPowerShell `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) `
        -PassThru -Wait -NoNewWindow
    if ($testProcess.ExitCode -ne 0) {
        throw "Encoded test process failed with exit code $($testProcess.ExitCode)."
    }

    # Event delivery can lag a few seconds; never report VERIFIED without
    # finding the marker in an actual 4104 event from the Operational log.
    $matchedEvent = $null
    for ($attempt = 1; $attempt -le 8 -and $null -eq $matchedEvent; $attempt++) {
        try {
            $events = @(Get-WinEvent -FilterHashtable @{
                LogName   = $operationalLog
                Id        = 4104
                StartTime = $testStarted
            } -MaxEvents 500 -ErrorAction Stop)
            $matchedEvent = $events | Where-Object {
                $_.Message -like "*$marker*" -and $_.Message -like '*Write-Host*'
            } | Select-Object -First 1
        } catch [System.Exception] {
            # No matching event has arrived yet; try again before failing.
            $matchedEvent = $null
        }
        if ($null -eq $matchedEvent -and $attempt -lt 8) {
            Start-Sleep -Seconds 2
        }
    }

    if ($null -eq $matchedEvent) {
        throw 'Event 4104 verification failed: decoded marker not found in the PowerShell Operational log.'
    }

    Write-Host ('    Event ID 4104: decoded command found at {0}.  [VERIFIED]' -f
        $matchedEvent.TimeCreated) -ForegroundColor Green
    Write-Host '[+] MedDefense PowerShell Security GPO configured and locally verified.' `
        -ForegroundColor Green
    Write-Host '[!] Review GPO application and transcript-folder permissions on other domain machines.' `
        -ForegroundColor Yellow
} catch {
    Write-Host "[ERROR] PowerShell security configuration failed: $($_.Exception.Message)" `
        -ForegroundColor Red
    exit 1
}
