#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    9-sysmon_deploy.ps1 - Install and verify Sysmon on MedDefense DC01.
.PURPOSE
    Download the Microsoft Sysinternals Sysmon package and SwiftOnSecurity
    reference baseline, deploy the attributed SwiftOnSecurity-based sysmonconfig.xml,
    verify the service/driver and event generation, and test Event ID 11.
    Supports verified offline binaries and the bundled baseline if downloads fail.
.AUTHOR
    MedDefense Blue Team
.DATE
    2026-10-20
.NOTES
    Authorized MedDefense DC01 Windows Server 2022 lab only.
    Run from the folder containing sysmonconfig.xml in elevated Windows
    PowerShell 5.1. This script does not deploy to remote domain endpoints.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sysmonUrl = 'https://download.sysinternals.com/files/Sysmon.zip'
$baselineUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml'
$logName = 'Microsoft-Windows-Sysmon/Operational'
$gpoFolder = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $gpoFolder 'sysmonconfig.xml'
$cacheFolder = Join-Path $env:TEMP 'MedDefense-Sysmon'
$zipPath = Join-Path $cacheFolder 'Sysmon.zip'
$unpackedPath = Join-Path $cacheFolder 'Microsoft-Sysmon'
$baselinePath = Join-Path $cacheFolder 'SwiftOnSecurity-sysmonconfig-export.xml'

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Get-RecentSysmonEvents {
    param(
        [Parameter(Mandatory = $true)][datetime]$StartTime,
        [int]$Id = 0,
        [int]$MaxEvents = 300
    )

    $query = @{
        LogName = $logName
        StartTime = $StartTime
    }
    if ($Id -ne 0) { $query.Id = $Id }

    try {
        return @(Get-WinEvent -FilterHashtable $query -MaxEvents $MaxEvents -ErrorAction Stop)
    }
    catch [System.Exception] {
        # Get-WinEvent also raises an exception if a query has no matches.
        if ($_.Exception.Message -match 'No events were found') {
            return @()
        }
        throw
    }
}

try {
    Write-Step 'Checking the lab environment...'
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($computer.Domain -ine 'meddefense.local') {
        throw "Unexpected domain '$($computer.Domain)'. Expected meddefense.local; no installation attempted."
    }
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw "Missing separate deliverable: $configPath"
    }

    # Confirm valid XML and an inclusion that covers the required file test.
    [xml]$configuration = Get-Content -LiteralPath $configPath -Raw
    if ($configuration.DocumentElement.LocalName -ne 'Sysmon') {
        throw 'sysmonconfig.xml is not a Sysmon configuration.'
    }
    $testCovered = $false
    foreach ($rule in $configuration.SelectNodes('//FileCreate[@onmatch="include"]/TargetFilename')) {
        if ($rule.InnerText -like 'C:\Windows\Temp\sysmon_test*') {
            $testCovered = $true
            break
        }
    }
    if (-not $testCovered) {
        throw 'The XML does not include the C:\Windows\Temp\sysmon_test file-creation test.'
    }
    $expectedCategories = @('ProcessCreate','NetworkConnect','FileCreate','RegistryEvent','DnsQuery','WmiEvent','PipeEvent')
    foreach ($category in $expectedCategories) {
        if (@($configuration.SelectNodes("//EventFiltering//$category")).Count -eq 0) {
            throw "The bundled Sysmon configuration is missing event filter: $category"
        }
    }

    New-Item -Path $cacheFolder -ItemType Directory -Force | Out-Null

    Write-Step 'Downloading Sysmon from Microsoft Sysinternals...'
    $sysmonBinary = $null
    try {
        Invoke-WebRequest -Uri $sysmonUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
        if ((Get-Item -LiteralPath $zipPath).Length -lt 100000) {
            throw 'The Sysmon download is unexpectedly small.'
        }
        Expand-Archive -LiteralPath $zipPath -DestinationPath $unpackedPath -Force
        $sysmonBinary = Get-ChildItem -Path $unpackedPath -Filter 'Sysmon64.exe' -Recurse -File |
            Select-Object -First 1
        if ($null -eq $sysmonBinary) {
            throw 'The Microsoft archive did not contain Sysmon64.exe.'
        }
        Write-Host '    Sysmon download: [OK]' -ForegroundColor Green
    }
    catch {
        Write-Warning "Microsoft download unavailable: $($_.Exception.Message)"
        # An offline lab may supply the signed binary alongside the script.
        # Existing installed binary is also sufficient for reconfiguration.
        $candidates = @(
            (Join-Path $gpoFolder 'Sysmon64.exe'),
            (Join-Path $env:windir 'Sysmon64.exe')
        )
        foreach ($candidate in $candidates) {
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                $sysmonBinary = Get-Item -LiteralPath $candidate
                Write-Host "    Using signed local binary: $candidate" -ForegroundColor Yellow
                break
            }
        }
        if ($null -eq $sysmonBinary) {
            throw 'Sysmon download failed and no local Sysmon64.exe was found.'
        }
    }

    # Check the publisher before running downloaded executables as administrator.
    $signature = Get-AuthenticodeSignature -LiteralPath $sysmonBinary.FullName
    if ($signature.Status -ne 'Valid' -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
        throw "Sysmon64.exe failed Microsoft code-signature verification: $($signature.Status)"
    }
    Write-Host '    Microsoft-signed Sysmon64.exe: [OK]' -ForegroundColor Green

    Write-Step 'Downloading SwiftOnSecurity reference configuration...'
    try {
        Invoke-WebRequest -Uri $baselineUrl -OutFile $baselinePath -UseBasicParsing -ErrorAction Stop
        [xml]$referenceConfig = Get-Content -LiteralPath $baselinePath -Raw
        if ($referenceConfig.DocumentElement.LocalName -ne 'Sysmon') {
            throw 'Downloaded SwiftOnSecurity baseline is not valid Sysmon XML.'
        }
        Write-Host '    SwiftOnSecurity reference downloaded: [OK]' -ForegroundColor Green
        Write-Host "    Upstream reference: $baselinePath"
    }
    catch {
        # The submitted XML is a documented SwiftOnSecurity-derived baseline;
        # it can be installed without network access to GitHub.
        Write-Warning "Reference download unavailable; using bundled SwiftOnSecurity-derived XML: $($_.Exception.Message)"
    }
    Write-Host "    Active deployment config: $configPath"

    $installedService = @(Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue)
    if ($installedService.Count -eq 0) {
        Write-Step 'Installing Sysmon with sysmonconfig.xml...'
        & $sysmonBinary.FullName -accepteula -i $configPath
    }
    else {
        Write-Step 'Sysmon is already installed; updating its configuration...'
        & $sysmonBinary.FullName -c $configPath
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Sysmon installation/configuration failed with exit code $LASTEXITCODE."
    }

    Write-Step 'Checking the Sysmon service and kernel driver...'
    $service = @(Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Running' }) | Select-Object -First 1
    if ($null -eq $service) {
        throw 'Sysmon service is not running.'
    }
    Write-Host "    Service: $($service.Name) - Running [OK]" -ForegroundColor Green

    $driver = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='SysmonDrv'"
    if ($null -eq $driver -or $driver.State -ne 'Running') {
        throw 'SysmonDrv kernel driver is not loaded.'
    }
    Write-Host '    Driver: SysmonDrv - Loaded [OK]' -ForegroundColor Green

    $eventLog = Get-WinEvent -ListLog $logName -ErrorAction Stop
    if (-not $eventLog.IsEnabled) {
        throw "Sysmon event channel is not enabled: $logName"
    }

    Write-Step 'Checking Sysmon event generation...'
    # Execute a benign command to produce fresh Event ID 1 telemetry.
    & "$env:windir\System32\whoami.exe" | Out-Null
    Start-Sleep -Seconds 2
    $events = @(Get-RecentSysmonEvents -StartTime (Get-Date).AddSeconds(-60))
    Write-Host "    Events in last 60 seconds: $($events.Count)"
    if ($events.Count -eq 0) {
        throw 'No recent Sysmon events were found.'
    }
    Write-Host '    Sysmon event generation: [OK]' -ForegroundColor Green

    Write-Step 'Testing FileCreate detection (Event ID 11)...'
    $tempDirectory = Join-Path $env:windir 'Temp'
    $testPath = Join-Path $tempDirectory 'sysmon_test.txt'
    if (Test-Path -LiteralPath $testPath) {
        # Avoid replacing someone else's file, but stay inside the XML prefix rule.
        $suffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
        $testPath = Join-Path $tempDirectory "sysmon_test_$suffix.txt"
    }
    $testStart = (Get-Date).AddSeconds(-2)
    Set-Content -LiteralPath $testPath -Value 'MedDefense Sysmon FileCreate verification' -Encoding ASCII
    Write-Host "    Created: $testPath"

    $match = $null
    for ($attempt = 1; $attempt -le 12 -and $null -eq $match; $attempt++) {
        Start-Sleep -Seconds 1
        $fileEvents = @(Get-RecentSysmonEvents -StartTime $testStart -Id 11 -MaxEvents 300)
        foreach ($entry in $fileEvents) {
            [xml]$eventXml = $entry.ToXml()
            $fields = @{}
            foreach ($node in @($eventXml.Event.EventData.Data)) {
                $fields[$node.GetAttribute('Name')] = $node.InnerText
            }
            if ($fields.ContainsKey('TargetFilename') -and
                $fields['TargetFilename'] -ieq $testPath) {
                $match = $entry
                break
            }
        }
    }
    if ($null -eq $match) {
        throw "FileCreate Event ID 11 was not found for '$testPath'. Check the active Sysmon configuration."
    }

    Write-Host "    Event ID 11 captured: Record $($match.RecordId) [VERIFIED]" -ForegroundColor Green
    Write-Host '    Sysmon deployment and FileCreate validation completed.' -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
