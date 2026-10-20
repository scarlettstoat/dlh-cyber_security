#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    15-master_validation.ps1 - MedDefense Windows domain compliance dashboard.
.PURPOSE
    Verify the effective DC01 security baseline without changing policies,
    Active Directory accounts, firewall rules, services, or applications.
    Return 0 when every critical check passes, or 1 if any critical check fails.
.AUTHOR
    MedDefense Blue Team
.DATE
    2026-10-20
.NOTES
    Read-only assessment for the authorized meddefense.local Windows Server 2022
    domain controller. A temporary secedit export is deleted after inspection.
    DC01 results are not proof that every workstation or DC is compliant.
#>

[CmdletBinding()]
param(
    [ValidateRange(1,3650)]
    [int]$ServicePasswordAgeLimit = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedDomain = 'meddefense.local'
$report = New-Object 'System.Collections.Generic.List[object]'
$domain = $null

function Write-Section {
    param([Parameter(Mandatory)][string]$Title)
    Write-Host "`n--- $Title ---" -ForegroundColor Cyan
}

function Add-Check {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('PASS','WARN','FAIL')][string]$Status,
        [Parameter(Mandatory)][string]$Detail,
        [bool]$Critical = $false
    )
    [void]$script:report.Add([pscustomobject]@{
        Check = $Name
        Status = $Status
        Detail = $Detail
        Critical = $Critical
    })
    $shade = switch ($Status) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
    }
    Write-Host ('[{0}] {1}: {2}' -f $Status, $Name, $Detail) -ForegroundColor $shade
}

function Invoke-Check {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Probe,
        [bool]$Critical = $false
    )
    try {
        # Every probe returns an object with Compliant and Detail properties.
        $answer = & $Probe
        if ($null -eq $answer) { throw 'No result was returned.' }
        $state = if ([bool]$answer.Compliant) { 'PASS' }
                 elseif ($Critical) { 'FAIL' }
                 else { 'WARN' }
        Add-Check -Name $Name -Status $state -Detail ([string]$answer.Detail) -Critical $Critical
    }
    catch {
        $state = if ($Critical) { 'FAIL' } else { 'WARN' }
        Add-Check -Name $Name -Status $state -Detail "Could not verify: $($_.Exception.Message)" -Critical $Critical
    }
}

function Result {
    param([bool]$Ok, [string]$Detail)
    return [pscustomobject]@{ Compliant = $Ok; Detail = $Detail }
}

function Read-RegistryValue {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    return $key.GetValue($Name, $null)
}

function Check-Dword {
    param([string]$Path, [string]$Name, [int]$Expected, [string]$Description)
    $actual = Read-RegistryValue -Path $Path -Name $Name
    $display = if ($null -eq $actual) { 'not configured' } else { [string]$actual }
    return Result -Ok ($null -ne $actual -and [int]$actual -eq $Expected) `
        -Detail ("{0} (expected {1}; found {2})" -f $Description, $Expected, $display)
}

function Get-LocalRights {
    # secedit /export reads the EFFECTIVE security database. It does not apply
    # a template. Remove the export so this weekly check leaves no evidence files.
    $tempFile = Join-Path $env:TEMP ("MedDefense-rights-{0}.inf" -f [guid]::NewGuid().ToString('N'))
    try {
        & secedit.exe /export /cfg $tempFile /areas USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tempFile)) {
            throw "secedit /export failed (exit $LASTEXITCODE)."
        }
        $rights = @{}
        foreach ($line in (Get-Content -LiteralPath $tempFile -Encoding Unicode)) {
            if ($line -match '^\s*(Se\w+Right)\s*=\s*(.*)$') {
                $rights[$Matches[1]] = @($Matches[2] -split ',' | ForEach-Object {
                    $_.Trim().TrimStart('*')
                } | Where-Object { $_ })
            }
        }
        return $rights
    }
    finally {
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }
}

function Normalize-Protocol {
    param([object]$Protocol)
    switch ([string]$Protocol) {
        '6'   { return 'TCP' }
        '17'  { return 'UDP' }
        default { return ([string]$Protocol).ToUpperInvariant() }
    }
}

function Test-MedDefFirewallRule {
    param([hashtable]$Definition)
    $rule = @(Get-NetFirewallRule -Name $Definition.Name -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Where-Object { [string]$_.Enabled -eq 'True' -and [string]$_.Direction -eq 'Inbound' -and
                       [string]$_.Action -eq 'Allow' } | Select-Object -First 1)
    if ($rule.Count -ne 1) { return $false }
    $ports = $rule[0] | Get-NetFirewallPortFilter -ErrorAction Stop
    $addresses = $rule[0] | Get-NetFirewallAddressFilter -ErrorAction Stop
    $wanted = @($Definition.Ports | ForEach-Object { [string]$_ })
    $actual = @($ports.LocalPort | ForEach-Object { [string]$_ })
    $scopes = @($addresses.RemoteAddress | ForEach-Object { [string]$_ })
    return ((Normalize-Protocol $ports.Protocol) -eq $Definition.Protocol -and
        @(Compare-Object -ReferenceObject $wanted -DifferenceObject $actual).Count -eq 0 -and
        $scopes.Count -eq 1 -and $scopes[0] -eq $Definition.Subnet)
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'An elevated PowerShell console is needed to inspect all settings.'
    }
    $computer = Get-CimInstance Win32_ComputerSystem
    if ($computer.DomainRole -lt 4) { throw 'Run on DC01, not on an ordinary Windows workstation.' }
    $domain = Get-ADDomain -ErrorAction Stop
    if ($domain.DNSRoot -ine $expectedDomain) {
        throw "Connected to $($domain.DNSRoot), not $expectedDomain."
    }
    Write-Host ("MedDefense weekly Windows compliance | {0} | {1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor White
}
catch {
    Add-Check -Name 'Authorized DC01 context' -Status FAIL -Critical $true `
        -Detail $_.Exception.Message
    Write-Host '[FAIL] Compliance assessment could not start; exit code 1.' -ForegroundColor Red
    exit 1
}

Write-Section 'Password & Lockout'
$pwd = $null
$pwdError = $null
try { $pwd = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop }
catch { $pwdError = $_.Exception.Message }

$accountPolicy = @(
    @{ Name='Minimum length';  Want='14'; Display='14 characters'; Get={ [int]$pwd.MinPasswordLength } },
    @{ Name='Complexity';      Want='True'; Display='Enabled'; Get={ [bool]$pwd.ComplexityEnabled } },
    @{ Name='Password history'; Want='24'; Display='24 passwords'; Get={ [int]$pwd.PasswordHistoryCount } },
    @{ Name='Maximum age';    Want='0'; Display='0 days (no scheduled expiry)'; Get={ [int]$pwd.MaxPasswordAge.TotalDays } },
    @{ Name='Minimum age';    Want='1'; Display='1 day'; Get={ [int]$pwd.MinPasswordAge.TotalDays } },
    @{ Name='Lockout threshold'; Want='5'; Display='5 attempts'; Get={ [int]$pwd.LockoutThreshold } },
    @{ Name='Lockout duration'; Want='15'; Display='15 minutes'; Get={ [int]$pwd.LockoutDuration.TotalMinutes } },
    @{ Name='Reset lockout counter'; Want='15'; Display='15 minutes'; Get={ [int]$pwd.LockoutObservationWindow.TotalMinutes } }
)
foreach ($item in $accountPolicy) {
    $policyItem = $item
    Invoke-Check -Name $policyItem.Name -Critical $true -Probe {
        if ($null -ne $pwdError) { throw $pwdError }
        $observed = & $policyItem.Get
        Result -Ok ([string]$observed -eq $policyItem.Want) -Detail ("{0}; actual: {1}" -f $policyItem.Display, $observed)
    }
}

Write-Section 'Advanced Audit Policy'
$auditEntries = @(
    @{ Name='Credential Validation';       Guid='0CCE923F-69AE-11D9-BED3-505054503030'; Mask=3 },
    @{ Name='Kerberos Authentication';     Guid='0CCE9242-69AE-11D9-BED3-505054503030'; Mask=3 },
    @{ Name='Logon';                       Guid='0CCE9215-69AE-11D9-BED3-505054503030'; Mask=3 },
    @{ Name='Logoff';                      Guid='0CCE9216-69AE-11D9-BED3-505054503030'; Mask=1 },
    @{ Name='Special Logon';               Guid='0CCE921B-69AE-11D9-BED3-505054503030'; Mask=1 },
    @{ Name='User Account Management';     Guid='0CCE9235-69AE-11D9-BED3-505054503030'; Mask=3 },
    @{ Name='Sensitive Privilege Use';     Guid='0CCE9228-69AE-11D9-BED3-505054503030'; Mask=3 },
    @{ Name='File System';                 Guid='0CCE921D-69AE-11D9-BED3-505054503030'; Mask=3 },
    @{ Name='Registry';                    Guid='0CCE921E-69AE-11D9-BED3-505054503030'; Mask=3 },
    @{ Name='Process Creation';            Guid='0CCE922B-69AE-11D9-BED3-505054503030'; Mask=1 }
)
$auditMap = @{}
$auditError = $null
try {
    $auditText = & auditpol.exe /get '/category:*' /r 2>&1
    if ($LASTEXITCODE -ne 0) { throw "auditpol returned $LASTEXITCODE" }
    foreach ($line in @($auditText | ConvertFrom-Csv)) {
        $id = ([string]$line.'Subcategory GUID').Trim('{}').ToUpperInvariant()
        if ($id) { $auditMap[$id] = $line }
    }
}
catch { $auditError = $_.Exception.Message }
foreach ($entry in $auditEntries) {
    $auditItem = $entry
    $isCriticalAudit = $auditItem.Name -in @('Process Creation', 'Logon', 'User Account Management')
    Invoke-Check -Name $auditItem.Name -Critical $isCriticalAudit -Probe {
        if ($null -ne $auditError) { throw $auditError }
        if (-not $auditMap.ContainsKey($auditItem.Guid)) { throw 'Audit subcategory was not returned.' }
        $record = $auditMap[$auditItem.Guid]
        $label = [string]$record.'Inclusion Setting'
        # The numeric setting is less dependent on the displayed category name.
        $valueText = [string]$record.'Setting Value'
        $actualMask = 0
        if ($valueText -match '^\s*[0-3]\s*$') {
            $actualMask = [int]$valueText.Trim()
        } else {
            if ($label -match 'Success') { $actualMask = $actualMask -bor 1 }
            if ($label -match 'Failure') { $actualMask = $actualMask -bor 2 }
        }
        $want = if ($auditItem.Mask -eq 3) { 'Success and Failure' } else { 'Success' }
        Result -Ok (($actualMask -band $auditItem.Mask) -eq $auditItem.Mask) `
            -Detail ("Expected {0}; actual: {1}" -f $want, $label)
    }
}
$auditRegistry = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
Invoke-Check -Name 'Process command-line logging' -Critical $true -Probe {
    Check-Dword -Path $auditRegistry -Name 'ProcessCreationIncludeCmdLine_Enabled' -Expected 1 -Description 'Included in Event 4688'
}
Invoke-Check -Name 'Advanced audit overrides legacy' -Probe {
    Check-Dword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' `
        -Expected 1 -Description 'Advanced subcategories take precedence'
}
$localRights = $null
$rightsError = $null
try { $localRights = Get-LocalRights }
catch { $rightsError = $_.Exception.Message }
Invoke-Check -Name 'Security log clearing user right' -Critical $true -Probe {
    if ($null -ne $rightsError) { throw $rightsError }
    $authorized = @('S-1-5-18', ('{0}-512' -f $domain.DomainSID.Value))
    $assigned = @($localRights['SeSecurityPrivilege'])
    $other = @($assigned | Where-Object { $authorized -notcontains $_ })
    Result -Ok ($assigned -contains $authorized[1] -and $other.Count -eq 0) `
        -Detail ("Manage auditing and security log right: {0}" -f ($assigned -join ', '))
}
Invoke-Check -Name 'Security log channel ACL' -Probe {
    $sddl = [string](Read-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' 'ChannelAccess')
    $daSid = '{0}-512' -f $domain.DomainSID.Value
    Result -Ok ($sddl -match [regex]::Escape($daSid)) `
        -Detail $(if ($sddl) { 'Domain Admins SID appears in Security channel ACL (review effective access separately)' } else { 'Security channel ACL policy not found' })
}
Invoke-Check -Name 'Security log size' -Critical $true -Probe {
    $log = Get-WinEvent -ListLog Security -ErrorAction Stop
    $size = [long]$log.MaximumSizeInBytes
    Result -Ok ($size -ge 1073741824) -Detail ("{0:N0} bytes (minimum: 1 GiB)" -f $size)
}

Write-Section 'PowerShell Logging'
$powerShellBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
Invoke-Check -Name 'Script Block Logging' -Critical $true -Probe {
    Check-Dword -Path "$powerShellBase\ScriptBlockLogging" -Name EnableScriptBlockLogging -Expected 1 -Description 'Event 4104'
}
Invoke-Check -Name 'Module Logging' -Probe {
    $enabled = Read-RegistryValue "$powerShellBase\ModuleLogging" 'EnableModuleLogging'
    $wildcard = Read-RegistryValue "$powerShellBase\ModuleLogging\ModuleNames" '*'
    Result -Ok ($enabled -eq 1 -and $wildcard -eq '*') `
        -Detail ("Enabled={0}; ModuleNames={1}" -f $enabled, $wildcard)
}
Invoke-Check -Name 'Transcription' -Critical $true -Probe {
    $enabled = Read-RegistryValue "$powerShellBase\Transcription" 'EnableTranscripting'
    $folder = [string](Read-RegistryValue "$powerShellBase\Transcription" 'OutputDirectory')
    $expected = 'C:\PSTranscripts'
    Result -Ok ($enabled -eq 1 -and $folder.TrimEnd('\') -ieq $expected) `
        -Detail ("Enabled={0}; Directory={1}" -f $enabled, $folder)
}
Invoke-Check -Name 'PowerShell transcript directory' -Probe {
    Result -Ok (Test-Path -LiteralPath 'C:\PSTranscripts' -PathType Container) -Detail 'C:\PSTranscripts'
}

Write-Section 'Sysmon Endpoint Telemetry'
Invoke-Check -Name 'Sysmon service' -Critical $true -Probe {
    $services = @(Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue)
    $running = @($services | Where-Object { $_.Status -eq 'Running' })
    Result -Ok ($running.Count -gt 0) -Detail ("Running: {0}" -f (($running | ForEach-Object { $_.Name }) -join ', '))
}
Invoke-Check -Name 'Sysmon driver' -Critical $true -Probe {
    $drivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop |
        Where-Object { $_.Name -match '^SysmonDrv$|^SysmonDrv\d*$' })
    $active = @($drivers | Where-Object { $_.State -eq 'Running' -or $_.Started })
    Result -Ok ($active.Count -gt 0) -Detail ("Running drivers: {0}" -f (($active | ForEach-Object { $_.Name }) -join ', '))
}
Invoke-Check -Name 'Sysmon Operational log' -Critical $true -Probe {
    $log = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
    Result -Ok ([bool]$log.IsEnabled) -Detail ("Enabled={0}" -f $log.IsEnabled)
}
Invoke-Check -Name 'Sysmon recent telemetry' -Probe {
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=(Get-Date).AddHours(-24)
    } -MaxEvents 1 -ErrorAction SilentlyContinue)
    Result -Ok ($events.Count -gt 0) -Detail 'At least one event observed in the last 24 hours'
}
Invoke-Check -Name 'Sysmon custom detection rules' -Probe {
    # `Sysmon64.exe -c` with no filename READS the installed configuration.
    # Local source XML is useful for troubleshooting but is not deployed proof.
    $candidateBinaries = @(
        (Join-Path $env:windir 'Sysmon64.exe'),
        (Join-Path $env:windir 'Sysmon.exe')
    )
    $foundCommand = Get-Command 'Sysmon64.exe' -ErrorAction SilentlyContinue
    if ($null -ne $foundCommand) { $candidateBinaries += $foundCommand.Source }
    $binary = @($candidateBinaries | Where-Object { Test-Path -LiteralPath $_ } |
        Select-Object -First 1)
    if ($binary.Count -gt 0) {
        $raw = @(& $binary[0] -c 2>&1)
        if ($LASTEXITCODE -eq 0) {
            $content = $raw -join "`n"
            $names = @('ProcessCreate','NetworkConnect','FileCreate','RegistryEvent',
                'DnsQuery','WmiEvent','PipeEvent')
            $active = @($names | Where-Object { $content -match [regex]::Escape($_) })
            if ($active.Count -ge 5) {
                return Result -Ok $true -Detail ("{0} active categories reported by Sysmon -c: {1}" -f $active.Count, ($active -join ', '))
            }
        }
    }
    $config = Join-Path $PSScriptRoot 'sysmonconfig.xml'
    if (-not (Test-Path -LiteralPath $config)) {
        throw 'Could not verify active Sysmon rules, and sysmonconfig.xml is missing.'
    }
    [xml]$xml = Get-Content -LiteralPath $config -Raw -ErrorAction Stop
    $sourceTypes = @($xml.SelectNodes('//EventFiltering//ProcessCreate | //EventFiltering//NetworkConnect | //EventFiltering//FileCreate | //EventFiltering//RegistryEvent | //EventFiltering//DnsQuery | //EventFiltering//WmiEvent | //EventFiltering//PipeEvent'))
    return Result -Ok $false -Detail ("{0} rule sections in source XML; active driver rules could not be confirmed" -f $sourceTypes.Count)
}

Write-Section 'Kerberos & Authentication'
$kerberosKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
Invoke-Check -Name 'DES disabled' -Critical $true -Probe {
    $mask = Read-RegistryValue $kerberosKey 'SupportedEncryptionTypes'
    Result -Ok ($null -ne $mask -and (([int]$mask -band 3) -eq 0) -and (([int]$mask -band 24) -eq 24)) `
        -Detail ("Encryption mask={0}; expected AES128/AES256 (0x18)" -f $(if ($null -eq $mask) { 'unset' } else { '0x{0:X}' -f [int]$mask }))
}
Invoke-Check -Name 'RC4 disabled' -Critical $true -Probe {
    $mask = Read-RegistryValue $kerberosKey 'SupportedEncryptionTypes'
    Result -Ok ($null -ne $mask -and (([int]$mask -band 4) -eq 0) -and (([int]$mask -band 24) -eq 24)) `
        -Detail ("Encryption mask={0}; RC4 bit must be off" -f $(if ($null -eq $mask) { 'unset' } else { '0x{0:X}' -f [int]$mask }))
}
Invoke-Check -Name 'KDC fallback encryption' -Probe {
    $mask = Read-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' 'DefaultDomainSupportedEncTypes'
    Result -Ok ($null -ne $mask -and (([int]$mask -band 7) -eq 0) -and (([int]$mask -band 24) -eq 24)) `
        -Detail ("KDC fallback mask={0}; expected 0x18" -f $(if ($null -eq $mask) { 'unset' } else { '0x{0:X}' -f [int]$mask }))
}
Invoke-Check -Name 'NTLMv1 disabled' -Critical $true -Probe {
    Check-Dword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Expected 5 -Description 'NTLMv2-only fallback'
}
Invoke-Check -Name 'DES-only user accounts' -Probe {
    $old = @(Get-ADUser -Filter * -Properties UseDESKeyOnly |
        Where-Object { $_.UseDESKeyOnly -eq $true })
    Result -Ok ($old.Count -eq 0) -Detail ("{0} accounts still require DES" -f $old.Count)
}

Write-Section 'SMB Protection'
$smb = $null
$smbError = $null
try { $smb = Get-SmbServerConfiguration -ErrorAction Stop }
catch { $smbError = $_.Exception.Message }
Invoke-Check -Name 'SMBv1 disabled' -Critical $true -Probe {
    if ($null -ne $smbError) { throw $smbError }
    Result -Ok (-not [bool]$smb.EnableSMB1Protocol) -Detail ("EnableSMB1Protocol={0}" -f $smb.EnableSMB1Protocol)
}
Invoke-Check -Name 'SMB signing required' -Critical $true -Probe {
    if ($null -ne $smbError) { throw $smbError }
    Result -Ok ([bool]$smb.RequireSecuritySignature) -Detail ("RequireSecuritySignature={0}" -f $smb.RequireSecuritySignature)
}

Write-Section 'Windows Firewall'
Invoke-Check -Name 'All firewall profiles' -Critical $true -Probe {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    $valid = $profiles.Count -eq 3 -and @($profiles | Where-Object {
        [string]$_.Enabled -ne 'True' -or [string]$_.DefaultInboundAction -ne 'Block'
    }).Count -eq 0
    $detail = ($profiles | ForEach-Object { '{0}={1}/{2}' -f $_.Name, $_.Enabled, $_.DefaultInboundAction }) -join '; '
    Result -Ok $valid -Detail $detail
}
Invoke-Check -Name 'Dropped packet logging' -Probe {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    $bad = @($profiles | Where-Object { [string]$_.LogBlocked -ne 'True' })
    Result -Ok ($profiles.Count -eq 3 -and $bad.Count -eq 0) -Detail ("{0} profiles logging blocked traffic" -f ($profiles.Count - $bad.Count))
}
$expectedRules = @(
    @{ Name='MedDef-RDP-Mgmt'; Protocol='TCP'; Ports=@('3389'); Subnet='10.10.3.0/24' },
    @{ Name='MedDef-DNS-TCP'; Protocol='TCP'; Ports=@('53'); Subnet='Any' },
    @{ Name='MedDef-DNS-UDP'; Protocol='UDP'; Ports=@('53'); Subnet='Any' },
    @{ Name='MedDef-LDAP'; Protocol='TCP'; Ports=@('389'); Subnet='Any' },
    @{ Name='MedDef-Kerberos-TCP'; Protocol='TCP'; Ports=@('88'); Subnet='Any' },
    @{ Name='MedDef-Kerberos-UDP'; Protocol='UDP'; Ports=@('88'); Subnet='Any' },
    @{ Name='MedDef-SMB'; Protocol='TCP'; Ports=@('445'); Subnet='10.10.1.0/24' },
    @{ Name='MedDef-WinRM'; Protocol='TCP'; Ports=@('5985','5986'); Subnet='10.10.3.0/24' }
)
Invoke-Check -Name 'Service allow rules & subnet limits' -Critical $true -Probe {
    $incorrect = @()
    foreach ($expected in $expectedRules) {
        if (-not (Test-MedDefFirewallRule -Definition $expected)) { $incorrect += $expected.Name }
    }
    Result -Ok ($incorrect.Count -eq 0) -Detail ("{0}/8 matching; issues: {1}" -f (8-$incorrect.Count), $(if ($incorrect.Count) { $incorrect -join ', ' } else { 'none' }))
}

Write-Section 'RDP & Remote Access'
$rdpPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$rdpListener = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$rdpSettings = @(
    @{ Label='NLA required'; Name='UserAuthentication'; Value=1; Critical=$true },
    @{ Label='TLS security layer'; Name='SecurityLayer'; Value=2; Critical=$false },
    @{ Label='High encryption'; Name='MinEncryptionLevel'; Value=3; Critical=$false },
    @{ Label='Idle timeout'; Name='MaxIdleTime'; Value=900000; Critical=$false },
    @{ Label='Maximum session'; Name='MaxConnectionTime'; Value=28800000; Critical=$false },
    @{ Label='Clipboard redirection disabled'; Name='fDisableClip'; Value=1; Critical=$false },
    @{ Label='Drive redirection disabled'; Name='fDisableCdm'; Value=1; Critical=$false },
    @{ Label='Remote Assistance disabled'; Name='fAllowToGetHelp'; Value=0; Critical=$false },
    @{ Label='Unsolicited Assistance disabled'; Name='fAllowUnsolicited'; Value=0; Critical=$false }
)
foreach ($entry in $rdpSettings) {
    $rdpItem = $entry
    Invoke-Check -Name $rdpItem.Label -Critical $rdpItem.Critical -Probe {
        Check-Dword -Path $rdpPolicy -Name $rdpItem.Name -Expected $rdpItem.Value -Description 'Policy value'
    }
}
Invoke-Check -Name 'NLA on RDP listener' -Critical $true -Probe {
    Check-Dword -Path $rdpListener -Name 'UserAuthentication' -Expected 1 -Description 'RDP listener'
}
$authorizedAdmin = $null
$adminError = $null
try { $authorizedAdmin = Get-ADGroup -Identity 'G_IT_Admins' -ErrorAction Stop }
catch { $adminError = $_.Exception.Message }
Invoke-Check -Name 'G_IT_Admins RDP logon right' -Critical $true -Probe {
    if ($null -ne $rightsError) { throw $rightsError }
    if ($null -ne $adminError) { throw $adminError }
    $allowed = @($localRights['SeRemoteInteractiveLogonRight'])
    $required = $authorizedAdmin.SID.Value
    Result -Ok ($allowed.Count -eq 1 -and $allowed[0] -eq $required) -Detail ("Allowed SIDs: {0}" -f ($allowed -join ', '))
}
Invoke-Check -Name 'Remote Desktop Users membership' -Critical $true -Probe {
    if ($null -ne $adminError) { throw $adminError }
    $members = @(Get-ADGroupMember -Identity 'S-1-5-32-555' -ErrorAction Stop)
    $names = @($members | ForEach-Object { $_.SamAccountName })
    Result -Ok ($members.Count -eq 1 -and $members[0].DistinguishedName -eq $authorizedAdmin.DistinguishedName) `
        -Detail ("Direct members: {0}" -f ($names -join ', '))
}

Write-Section 'Service Accounts'
$services = @()
$servicesError = $null
try {
    $standard = @(Get-ADUser -Filter * -Properties AccountNotDelegated,TrustedForDelegation,
        TrustedToAuthForDelegation,PasswordLastSet,Name,DistinguishedName | Where-Object {
            $_.SamAccountName -match 'svc' -or $_.Name -match 'svc' -or
            $_.DistinguishedName -match '(?i)OU=Service Accounts,'
        })
    $managed = @(Get-ADServiceAccount -Filter * -Properties AccountNotDelegated,TrustedForDelegation,
        TrustedToAuthForDelegation,PasswordLastSet,DistinguishedName)
    $services = @($standard) + @($managed)
    if ($services.Count -eq 0) { throw 'No service identities were found.' }
}
catch { $servicesError = $_.Exception.Message }
Invoke-Check -Name 'Delegation restricted' -Critical $true -Probe {
    if ($null -ne $servicesError) { throw $servicesError }
    $unsafe = @($services | Where-Object {
        -not $_.AccountNotDelegated -or $_.TrustedForDelegation -or $_.TrustedToAuthForDelegation
    })
    Result -Ok ($unsafe.Count -eq 0) -Detail ("{0}/{1} service identities protected; unsafe: {2}" -f ($services.Count-$unsafe.Count), $services.Count, (($unsafe | ForEach-Object { $_.SamAccountName }) -join ', '))
}
Invoke-Check -Name 'Service accounts denied console/RDP' -Critical $true -Probe {
    if ($null -ne $servicesError) { throw $servicesError }
    if ($null -ne $rightsError) { throw $rightsError }
    $guard = Get-ADGroup -Identity 'GG_ServiceAccounts_NoInteractive' -ErrorAction Stop
    $members = @(Get-ADGroupMember -Identity $guard -ErrorAction Stop)
    $missing = @($services | Where-Object { $members.DistinguishedName -notcontains $_.DistinguishedName })
    $guardSid = $guard.SID.Value
    $console = @($localRights['SeDenyInteractiveLogonRight']) -contains $guardSid
    $remote = @($localRights['SeDenyRemoteInteractiveLogonRight']) -contains $guardSid
    Result -Ok ($missing.Count -eq 0 -and $console -and $remote) `
        -Detail ("Guard group: {0}/{1} accounts; console deny={2}; RDP deny={3}" -f ($services.Count-$missing.Count), $services.Count, $console, $remote)
}
Invoke-Check -Name 'Privileged service account membership' -Critical $true -Probe {
    if ($null -ne $servicesError) { throw $servicesError }
    $domainSid = $domain.DomainSID.Value
    $privilegedIds = @("${domainSid}-512", "${domainSid}-518", "${domainSid}-519", "${domainSid}-520",
        'S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550')
    $targets = @($services | ForEach-Object { $_.DistinguishedName })
    $violations = @()
    foreach ($id in $privilegedIds) {
        $group = Get-ADGroup -Identity $id -ErrorAction SilentlyContinue
        if ($null -eq $group) { continue }
        $members = @(Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop)
        foreach ($member in $members) {
            if ($targets -contains $member.DistinguishedName) {
                $violations += ('{0} in {1}' -f $member.Name, $group.Name)
            }
        }
    }
    Result -Ok ($violations.Count -eq 0) -Detail ("Excessive memberships: {0}" -f $(if ($violations.Count) { $violations -join '; ' } else { 'none detected' }))
}
foreach ($service in $services) {
    $account = $service
    Invoke-Check -Name ("{0} password age" -f $account.SamAccountName) -Probe {
        if ($null -eq $account.PasswordLastSet) { throw 'PasswordLastSet is unavailable.' }
        $days = [int][Math]::Floor(((Get-Date) - $account.PasswordLastSet).TotalDays)
        Result -Ok ($days -le $ServicePasswordAgeLimit) -Detail ("{0} days (review threshold: {1} days)" -f $days, $ServicePasswordAgeLimit)
    }
}

Write-Section 'Compliance Summary'
$passed = @($report | Where-Object Status -eq 'PASS').Count
$warned = @($report | Where-Object Status -eq 'WARN').Count
$failed = @($report | Where-Object Status -eq 'FAIL').Count
$criticalFailed = @($report | Where-Object { $_.Critical -and $_.Status -ne 'PASS' }).Count
Write-Host ("Checks: {0} | PASS: {1} | WARN: {2} | FAIL: {3}" -f $report.Count, $passed, $warned, $failed)
if ($criticalFailed -gt 0) {
    Write-Host "[FAIL] $criticalFailed critical control(s) failed or could not be verified. Exit code: 1" -ForegroundColor Red
    exit 1
}
Write-Host '[PASS] All critical controls verified. Exit code: 0' -ForegroundColor Green
if ($warned -gt 0) { Write-Host '[WARN] Review advisory checks and domain-wide coverage separately.' -ForegroundColor Yellow }
exit 0
