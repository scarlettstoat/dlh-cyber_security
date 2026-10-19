<#
.SYNOPSIS
    4-password_policy.ps1 - MedDefense password and account lockout hardening.
.PURPOSE
    Create or update a domain-root GPO that sets the required password and
    account lockout security policy, refresh Group Policy, and verify results.
.AUTHOR
    MedDefense Blue Team
.DATE
    2026-10-19
.NOTES
    Authorized MedDefense Windows Server 2022 lab only. Run elevated on DC01.
    The GroupPolicy module does not expose a cmdlet for Account Policies.
    This script edits the GPO security template and updates its AD metadata.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$policyName = 'MedDefense - Password and Lockout Policy'
$expectedDomain = 'meddefense.local'
$securityExtension = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'

# The INF keys below represent Computer Configuration > Windows Settings >
# Security Settings > Account Policies, not registry-backed GP preferences.
$settings = [ordered]@{
    MinimumPasswordLength = '14'
    PasswordComplexity    = '1'
    PasswordHistorySize   = '24'
    MaximumPasswordAge    = '0'
    MinimumPasswordAge    = '1'
    LockoutBadCount       = '5'
    LockoutDuration       = '15'
    ResetLockoutCount     = '15'
}

function Write-ProgressLine {
    param([string]$Message)
    Write-Host "[*] $Message"
}

function Set-AccountPolicyTemplate {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Entries
    )

    # Retain any unrelated security-template sections and settings when rerun.
    if (Test-Path -LiteralPath $Path) {
        $source = @(Get-Content -LiteralPath $Path -Encoding Unicode)
    } else {
        $source = @('[Unicode]', 'Unicode=yes', '')
    }

    $result = New-Object 'System.Collections.Generic.List[string]'
    $present = @{}
    $inAccountSection = $false
    $foundAccountSection = $false
    $foundVersionSection = $false

    foreach ($line in $source) {
        if ($line -match '^\s*\[([^\]]+)\]\s*$') {
            if ($inAccountSection) {
                foreach ($key in $Entries.Keys) {
                    if (-not $present.ContainsKey($key)) {
                        $result.Add("$key = $($Entries[$key])")
                    }
                }
                $inAccountSection = $false
            }
            if ($Matches[1] -eq 'System Access') {
                $inAccountSection = $true
                $foundAccountSection = $true
            }
            if ($Matches[1] -eq 'Version') {
                $foundVersionSection = $true
            }
        }

        if ($inAccountSection -and $line -match '^\s*([A-Za-z][A-Za-z0-9]*)\s*=') {
            $key = $Matches[1]
            if ($Entries.Contains($key)) {
                $result.Add("$key = $($Entries[$key])")
                $present[$key] = $true
                continue
            }
        }
        $result.Add($line)
    }

    if ($inAccountSection) {
        foreach ($key in $Entries.Keys) {
            if (-not $present.ContainsKey($key)) {
                $result.Add("$key = $($Entries[$key])")
            }
        }
    }
    if (-not $foundAccountSection) {
        $result.Add('')
        $result.Add('[System Access]')
        foreach ($key in $Entries.Keys) {
            $result.Add("$key = $($Entries[$key])")
        }
    }
    if (-not $foundVersionSection) {
        $result.Add('')
        $result.Add('[Version]')
        $result.Add('signature="$CHICAGO$"')
        $result.Add('Revision=1')
    }

    $directory = Split-Path -Path $Path -Parent
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    # Security templates use UTF-16LE (Unicode) with a BOM.
    Set-Content -LiteralPath $Path -Value $result.ToArray() -Encoding Unicode
}

function Set-GptFileVersion {
    param([string]$Path, [uint64]$Version)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "GPO version file missing: $Path"
    }
    $lines = @(Get-Content -LiteralPath $Path)
    $found = $false
    $updated = @(
        foreach ($line in $lines) {
            if ($line -match '^\s*Version\s*=') {
                $found = $true
                "Version=$Version"
            } else {
                $line
            }
        }
    )
    if (-not $found) {
        $updated += "Version=$Version"
    }
    Set-Content -LiteralPath $Path -Value $updated -Encoding ASCII
}

function Test-EffectivePolicy {
    param($Policy)
    return (
        $Policy.MinPasswordLength -eq 14 -and
        $Policy.ComplexityEnabled -eq $true -and
        $Policy.PasswordHistoryCount -eq 24 -and
        $Policy.MaxPasswordAge -eq [timespan]::Zero -and
        $Policy.MinPasswordAge -eq [timespan]::FromDays(1) -and
        $Policy.LockoutThreshold -eq 5 -and
        $Policy.LockoutDuration -eq [timespan]::FromMinutes(15) -and
        $Policy.LockoutObservationWindow -eq [timespan]::FromMinutes(15)
    )
}

try {
    Import-Module ActiveDirectory
    Import-Module GroupPolicy

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run an elevated Windows PowerShell session on DC01.'
    }

    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($computer.DomainRole -lt 4) {
        throw 'This script must run on a domain controller, not on a workstation.'
    }

    $domain = Get-ADDomain
    if ($domain.DNSRoot -ne $expectedDomain) {
        throw "Refusing to change domain '$($domain.DNSRoot)'; expected '$expectedDomain'."
    }

    # Use the same DC for the AD container and the corresponding SYSVOL files.
    $server = "$($env:COMPUTERNAME).$($domain.DNSRoot)"
    $existing = Get-GPO -Name $policyName -Domain $domain.DNSRoot -Server $server -ErrorAction SilentlyContinue

    if ($null -eq $existing) {
        Write-ProgressLine "Creating GPO: $policyName"
        $gpo = New-GPO -Name $policyName -Comment 'MedDefense account password and lockout baseline.' -Domain $domain.DNSRoot -Server $server
        Write-Host '    CREATED'
    } else {
        $gpo = $existing
        $backupPath = Join-Path $env:TEMP ('MedDefense-GPO-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
        New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
        Backup-GPO -Guid $gpo.Id -Path $backupPath -Domain $domain.DNSRoot -Server $server | Out-Null
        Write-ProgressLine "Existing GPO reused; backup saved to $backupPath"
    }

    $guidWithBraces = '{' + $gpo.Id.ToString().ToUpperInvariant() + '}'
    $policyFolder = "\\$server\SYSVOL\$($domain.DNSRoot)\Policies\$guidWithBraces"
    if (-not (Test-Path -LiteralPath $policyFolder)) {
        throw "GPO SYSVOL folder not found: $policyFolder"
    }

    $templatePath = Join-Path $policyFolder 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
    $gptIniPath = Join-Path $policyFolder 'GPT.INI'
    $gpoDn = "CN=$guidWithBraces,CN=Policies,CN=System,$($domain.DistinguishedName)"
    $gpoAd = Get-ADObject -Identity $gpoDn -Server $server -Properties gPCMachineExtensionNames, versionNumber

    Write-ProgressLine 'Configuring password and account lockout policy in GptTmpl.inf...'
    Set-AccountPolicyTemplate -Path $templatePath -Entries $settings
    Write-Host '    Minimum Length: 14            [SET]'
    Write-Host '    Complexity: Enabled           [SET]'
    Write-Host '    History: 24                   [SET]'
    Write-Host '    Maximum Age: 0 days           [SET]'
    Write-Host '    Minimum Age: 1 day            [SET]'
    Write-Host '    Threshold: 5 attempts         [SET]'
    Write-Host '    Duration: 15 minutes          [SET]'
    Write-Host '    Reset Counter: 15 minutes     [SET]'

    # Security settings require the security client-side extension registered
    # in AD, and matching machine version counters in AD and GPT.INI.
    $extensions = [string]$gpoAd.gPCMachineExtensionNames
    if ($extensions -notmatch [regex]::Escape($securityExtension)) {
        $extensions = $extensions + $securityExtension
    }
    $oldVersion = [uint64]$gpoAd.versionNumber
    $userVersion = [math]::Floor($oldVersion / 65536)
    $machineVersion = ($oldVersion % 65536 + 1) % 65536
    $newVersion = [uint64]($userVersion * 65536 + $machineVersion)

    # Persist SYSVOL first, then publish its corresponding AD version.
    Set-GptFileVersion -Path $gptIniPath -Version $newVersion
    Set-ADObject -Identity $gpoDn -Server $server -Replace @{
        gPCMachineExtensionNames = $extensions
        versionNumber           = [int64]$newVersion
    }

    Write-ProgressLine 'Linking GPO to the domain root...'
    $inheritance = Get-GPInheritance -Target $domain.DistinguishedName -Domain $domain.DNSRoot -Server $server
    $linked = @($inheritance.GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id })
    if ($linked.Count -eq 0) {
        New-GPLink -Guid $gpo.Id -Target $domain.DistinguishedName -Domain $domain.DNSRoot -Server $server -LinkEnabled Yes -Order 1 | Out-Null
    } else {
        Set-GPLink -Guid $gpo.Id -Target $domain.DistinguishedName -Domain $domain.DNSRoot -Server $server -LinkEnabled Yes -Order 1 | Out-Null
    }
    Write-Host '    LINKED (highest precedence at domain root)'

    Write-ProgressLine 'Forcing Group Policy update on this DC...'
    & gpupdate.exe /force
    if ($LASTEXITCODE -ne 0) {
        throw "gpupdate failed with exit code $LASTEXITCODE."
    }
    Write-Host '    COMPLETE'

    Write-ProgressLine 'Verifying effective domain account policy...'
    $effective = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -Server $server
    $verified = Test-EffectivePolicy -Policy $effective

    Write-Host ("    Minimum Length:       {0}" -f $effective.MinPasswordLength)
    Write-Host ("    Complexity Enabled:   {0}" -f $effective.ComplexityEnabled)
    Write-Host ("    Password History:     {0}" -f $effective.PasswordHistoryCount)
    Write-Host ("    Maximum Age (days):   {0}" -f $effective.MaxPasswordAge.TotalDays)
    Write-Host ("    Minimum Age (days):   {0}" -f $effective.MinPasswordAge.TotalDays)
    Write-Host ("    Lockout Threshold:    {0}" -f $effective.LockoutThreshold)
    Write-Host ("    Lockout Duration:     {0} minutes" -f $effective.LockoutDuration.TotalMinutes)
    Write-Host ("    Reset Counter:        {0} minutes" -f $effective.LockoutObservationWindow.TotalMinutes)

    if (-not $verified) {
        throw 'GPO saved, but the effective domain policy does not match yet. Check DC policy processing, replication and conflicting domain-root GPOs; do not report success.'
    }

    Write-Host '[PASS] All eight effective password and lockout values match the requirements.' -ForegroundColor Green
} catch {
    Write-Error "Password policy configuration or verification failed: $($_.Exception.Message)"
    exit 1
}
