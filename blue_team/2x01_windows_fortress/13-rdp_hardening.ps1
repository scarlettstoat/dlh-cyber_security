<#
.SYNOPSIS
    13-rdp_hardening.ps1 - MedDefense RDP and Remote Assistance hardening.
.PURPOSE
    Restrict interactive remote access to G_IT_Admins, enforce NLA and TLS,
    limit RDP session time, block clipboard/drive redirection, disable Remote
    Assistance, and verify the resulting settings on the lab domain controller.
.AUTHOR
    MedDefense Security Team
.DATE
    2026-10-20
.NOTES
    Run from an elevated Windows PowerShell 5.1 session on DC01 only.
    Changing remote logon rights may prevent existing administrators from
    connecting by RDP. A console login or other recovery path is required.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

$authorizedGroupName = 'G_IT_Admins'
$rdpUsersSid = 'S-1-5-32-555'  # Builtin Remote Desktop Users group
$listenerKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$assistanceKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
$backupRoot = Join-Path $env:ProgramData 'MedDefense\RDPBackups'
$backupDir = Join-Path $backupRoot (Get-Date -Format 'yyyyMMdd_HHmmss_fff')
$checks = [System.Collections.Generic.List[object]]::new()

function Write-Stage {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host "[*] $Text" -ForegroundColor Cyan
}

function Set-PolicyDword {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Value
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force |
        Out-Null
}

function Assert-RegistryValue {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Expected
    )
    $actual = [int](Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop)
    $passed = ($actual -eq $Expected)
    $script:checks.Add([pscustomobject]@{
        Setting = $Label
        Expected = $Expected
        Actual = $actual
        Verified = $passed
    })
    $status = if ($passed) { '[VERIFIED]' } else { '[FAILED]' }
    Write-Host ('    {0,-30} {1}' -f $Label, $status)
}

function Invoke-SecurityTool {
    param([Parameter(Mandatory)][string[]]$Arguments)
    & secedit.exe @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "secedit.exe returned exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
    }
}

function Get-AssignedSids {
    param(
        [Parameter(Mandatory)][string]$InfPath,
        [Parameter(Mandatory)][string]$Right
    )
    $line = Get-Content -Path $InfPath -Encoding Unicode |
        Where-Object { $_ -match "^\s*$([regex]::Escape($Right))\s*=" } |
        Select-Object -First 1
    if ($null -eq $line) { return @() }
    $value = ($line -split '=', 2)[1]
    return @($value -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

# Preflight: fail BEFORE making changes if the machine or AD groups are wrong.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script in an elevated PowerShell session.'
}
$os = Get-CimInstance -ClassName Win32_OperatingSystem
if ($os.ProductType -ne 2) {
    throw 'This script is intended for a domain controller (DC01), not a personal PC.'
}
$domain = Get-ADDomain
if ($domain.DNSRoot -ne 'meddefense.local') {
    throw "Unexpected domain $($domain.DNSRoot); refusing to modify RDP access."
}
$adminGroup = Get-ADGroup -Identity $authorizedGroupName -ErrorAction Stop
$remoteDesktopGroup = Get-ADGroup -Identity $rdpUsersSid -ErrorAction Stop
$adminMembers = @(Get-ADGroupMember -Identity $adminGroup -Recursive)
if ($adminMembers.Count -eq 0) {
    throw "$authorizedGroupName has no resolvable members. RDP access would be locked out."
}
$operatorAuthorized = @($adminMembers | Where-Object { $_.SID.Value -eq $identity.User.Value }).Count -gt 0
if (-not $operatorAuthorized) {
    Write-Warning 'The account running this script is not in G_IT_Admins. It may lose RDP access. Ensure console recovery is available.'
}

New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
$priorMembers = @(Get-ADGroupMember -Identity $remoteDesktopGroup)
$priorMembers | Select-Object Name, SamAccountName, DistinguishedName, SID |
    ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $backupDir 'rdp_group_before.json') -Encoding UTF8

Write-Stage 'Backing up current RDP policy and logon rights...'
$oldRights = Join-Path $backupDir 'user_rights_before.inf'
Invoke-SecurityTool -Arguments @('/export', '/cfg', $oldRights, '/areas', 'USER_RIGHTS', '/quiet')
$priorDenySids = @(Get-AssignedSids -InfPath $oldRights -Right 'SeDenyRemoteInteractiveLogonRight')
if ($priorDenySids -contains $adminGroup.SID.Value) {
    throw "$authorizedGroupName is explicitly denied RDP logon. Remove the conflicting deny assignment through the governing policy first."
}

$regBackupTargets = @(
    @{ Registry = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; PsPath = $listenerKey; File = 'listener_before.reg' },
    @{ Registry = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; PsPath = $policyKey; File = 'policy_before.reg' },
    @{ Registry = 'HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance'; PsPath = $assistanceKey; File = 'assistance_before.reg' }
)
foreach ($item in $regBackupTargets) {
    if (Test-Path -LiteralPath $item.PsPath) {
        $null = & reg.exe export $item.Registry (Join-Path $backupDir $item.File) /y
        if ($LASTEXITCODE -ne 0) { throw "Registry backup failed for $($item.Registry)." }
    }
}
Write-Host "    Recovery files: $backupDir" -ForegroundColor DarkGray

# Machine and policy-layer values. Windows stores the session limits in ms.
$settings = @(
    @{ Label='NLA - listener';       Path=$listenerKey;   Name='UserAuthentication'; Value=1 },
    @{ Label='NLA - policy';         Path=$policyKey;     Name='UserAuthentication'; Value=1 },
    @{ Label='TLS - listener';       Path=$listenerKey;   Name='SecurityLayer';       Value=2 },
    @{ Label='High - listener';      Path=$listenerKey;   Name='MinEncryptionLevel';  Value=3 },
    @{ Label='TLS security layer';   Path=$policyKey;     Name='SecurityLayer';       Value=2 },
    @{ Label='High encryption';      Path=$policyKey;     Name='MinEncryptionLevel';  Value=3 },
    @{ Label='Idle limit (15 min)';  Path=$policyKey;     Name='MaxIdleTime';        Value=900000 },
    @{ Label='Max session (8 hr)';  Path=$policyKey;     Name='MaxConnectionTime';  Value=28800000 },
    @{ Label='Clipboard disabled';  Path=$policyKey;     Name='fDisableClip';       Value=1 },
    @{ Label='Drive access blocked';Path=$policyKey;     Name='fDisableCdm';        Value=1 },
    @{ Label='Solicited RA off';    Path=$policyKey;     Name='fAllowToGetHelp';    Value=0 },
    @{ Label='Unsolicited RA off';  Path=$policyKey;     Name='fAllowUnsolicited';  Value=0 },
    @{ Label='Remote Assistance off';Path=$assistanceKey;Name='fAllowToGetHelp';    Value=0 }
)

Write-Stage 'Applying RDP authentication, session, and redirection controls...'
foreach ($setting in $settings) {
    Set-PolicyDword -Path $setting.Path -Name $setting.Name -Value $setting.Value
}
Write-Host '    NLA: required; encryption: high with TLS                  [SET]'
Write-Host '    Idle: 15 minutes; maximum session: 8 hours                [SET]'
Write-Host '    Clipboard, drives, Remote Assistance: disabled           [SET]'

# Configure the builtin group as a single entry point for approved RDP users.
Write-Stage "Restricting Remote Desktop Users to $authorizedGroupName..."
$alreadyPresent = @($priorMembers | Where-Object { $_.DistinguishedName -eq $adminGroup.DistinguishedName }).Count -gt 0
if (-not $alreadyPresent) {
    Add-ADGroupMember -Identity $remoteDesktopGroup -Members $adminGroup -ErrorAction Stop
    Write-Host "    Added: $authorizedGroupName                                [SET]"
}
foreach ($member in $priorMembers) {
    if ($member.DistinguishedName -ne $adminGroup.DistinguishedName) {
        Remove-ADGroupMember -Identity $remoteDesktopGroup -Members $member -Confirm:$false -ErrorAction Stop
        Write-Host "    Removed: $($member.Name)"
    }
}

# Merely changing group membership is insufficient on a DC: Administrators
# have SeRemoteInteractiveLogonRight by default. Replace the local allow-right
# with the authorized group's SID so other admins do not bypass the restriction.
Write-Stage 'Updating the RDP logon user right...'
$policyInf = Join-Path $backupDir 'rdp_logon_right.inf'
$policyDb = Join-Path $backupDir 'rdp_logon_right.sdb'
$policyLog = Join-Path $backupDir 'secedit_apply.log'
$template = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeRemoteInteractiveLogonRight = *$($adminGroup.SID.Value)
"@
Set-Content -Path $policyInf -Value $template -Encoding Unicode
Invoke-SecurityTool -Arguments @('/configure', '/db', $policyDb, '/cfg', $policyInf,
    '/overwrite', '/areas', 'USER_RIGHTS', '/log', $policyLog, '/quiet')
Write-Host "    Allow log on through RDS: $authorizedGroupName only       [SET]"

Write-Stage 'Verifying registry settings, AD membership, and logon rights...'
foreach ($setting in $settings) {
    Assert-RegistryValue -Label $setting.Label -Path $setting.Path -Name $setting.Name -Expected $setting.Value
}

$newMembers = @(Get-ADGroupMember -Identity $remoteDesktopGroup)
$groupPass = ($newMembers.Count -eq 1 -and
    $newMembers[0].DistinguishedName -eq $adminGroup.DistinguishedName)
$checks.Add([pscustomobject]@{
    Setting = 'Remote Desktop Users membership'
    Expected = $authorizedGroupName
    Actual = @($newMembers | ForEach-Object { $_.Name }) -join ', '
    Verified = $groupPass
})
Write-Host "    G_IT_Admins is sole RDP group member: $(if ($groupPass) { '[VERIFIED]' } else { '[FAILED]' })"

$afterRights = Join-Path $backupDir 'user_rights_after.inf'
Invoke-SecurityTool -Arguments @('/export', '/cfg', $afterRights, '/areas', 'USER_RIGHTS', '/quiet')
$allowedSids = @(Get-AssignedSids -InfPath $afterRights -Right 'SeRemoteInteractiveLogonRight')
$rightsPass = ($allowedSids.Count -eq 1 -and $allowedSids[0] -eq $adminGroup.SID.Value)
$checks.Add([pscustomobject]@{
    Setting = 'RDP logon right'
    Expected = $adminGroup.SID.Value
    Actual = $allowedSids -join ','
    Verified = $rightsPass
})
Write-Host "    RDP logon rights: $authorizedGroupName only               $(if ($rightsPass) { '[VERIFIED]' } else { '[FAILED]' })"

$failedChecks = @($checks | Where-Object { -not $_.Verified })
$report = [pscustomobject]@{
    Computer = $env:COMPUTERNAME
    Domain = $domain.DNSRoot
    AssessmentDate = (Get-Date).ToString('o')
    AuthorizedGroup = $authorizedGroupName
    BackupDirectory = $backupDir
    Checks = $checks.ToArray()
    AllChecksPassed = ($failedChecks.Count -eq 0)
    Caveat = 'Local configuration only; domain GPOs can overwrite registry or logon rights.'
}
$reportPath = Join-Path $backupDir 'rdp_verification.json'
$report | ConvertTo-Json -Depth 5 | Set-Content -Path $reportPath -Encoding UTF8
Write-Host "    Verification report: $reportPath" -ForegroundColor DarkGray
if ($failedChecks.Count -gt 0) {
    throw "$($failedChecks.Count) RDP hardening verification check(s) failed. See $reportPath."
}
Write-Host '[OK] RDP hardening settings verified on this domain controller.' -ForegroundColor Green
Write-Warning 'Changes to a domain builtin group can affect other domain systems. Group Policy may override local rights; validate resultant policy and test an authorized RDP login separately.'
