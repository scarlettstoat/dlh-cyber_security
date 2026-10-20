<#
.SYNOPSIS
    11-firewall_hardening.ps1 - MedDefense Windows Firewall lockdown.
.PURPOSE
    Record and back up DC01's firewall configuration, enable all three profiles
    with a default-deny inbound policy, add least-privilege service rules,
    disable conflicting legacy local inbound rules, enable drop logging,
    and verify the effective configuration.
.AUTHOR
    MedDefense Security Team
.DATE
    2026-10-20
.NOTES
    Authorized MedDefense Windows Server 2022 lab only. Run locally on DC01
    in an elevated Windows PowerShell session. Do NOT deploy the six-service
    rule set to a production domain controller without reviewing additional
    Active Directory ports (RPC, replication, SYSVOL, etc.).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module NetSecurity -ErrorAction Stop

$managementSubnet = '10.10.3.0/24'
$serverSubnet = '10.10.1.0/24'
$ruleGroup = 'MedDefense-Windows-Fortress'
$profiles = @('Domain', 'Private', 'Public')
$logFile = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
$backupRoot = Join-Path $env:ProgramData 'MedDefense\FirewallBackups'
$backupPath = Join-Path $backupRoot (Get-Date -Format 'yyyyMMdd_HHmmss_fff')

function Write-Stage {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Test-PortIncluded {
    param(
        [Parameter(Mandatory)][string[]]$ConfiguredPorts,
        [Parameter(Mandatory)][int]$TargetPort
    )

    foreach ($item in $ConfiguredPorts) {
        foreach ($token in ($item -split ',')) {
            $port = $token.Trim()
            if ($port -eq [string]$TargetPort) { return $true }
            if ($port -match '^(\d+)-(\d+)$') {
                if ($TargetPort -ge [int]$Matches[1] -and $TargetPort -le [int]$Matches[2]) {
                    return $true
                }
            }
        }
    }
    return $false
}

function Test-RuleConfiguration {
    param([Parameter(Mandatory)][hashtable]$Definition)

    $rule = Get-NetFirewallRule -Name $Definition.Name -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Where-Object { $_.Group -eq $ruleGroup -and $_.Enabled -eq 'True' -and
                       $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' } |
        Select-Object -First 1

    if ($null -eq $rule) { return $false }

    $portFilter = $rule | Get-NetFirewallPortFilter
    $addressFilter = $rule | Get-NetFirewallAddressFilter
    $actualPorts = @($portFilter.LocalPort | ForEach-Object { [string]$_ })
    $wantedPorts = @($Definition.Ports | ForEach-Object { [string]$_ })
    $actualScope = @($addressFilter.RemoteAddress | ForEach-Object { [string]$_ })

    # Both ports and remote scope must match the intended allow rule.
    if ([string]$portFilter.Protocol -ne $Definition.Protocol) { return $false }
    if (@(Compare-Object $wantedPorts $actualPorts).Count -gt 0) { return $false }
    if ($actualScope.Count -ne 1 -or $actualScope[0] -ne $Definition.RemoteAddress) {
        return $false
    }
    return $true
}

# Six required service categories translate to eight protocol-specific rules.
$allowRules = @(
    @{ Name='MedDef-RDP-Mgmt';     Label='RDP';      Protocol='TCP'; Ports=@('3389');        RemoteAddress=$managementSubnet },
    @{ Name='MedDef-DNS-TCP';      Label='DNS';      Protocol='TCP'; Ports=@('53');          RemoteAddress='Any' },
    @{ Name='MedDef-DNS-UDP';      Label='DNS';      Protocol='UDP'; Ports=@('53');          RemoteAddress='Any' },
    @{ Name='MedDef-LDAP';         Label='LDAP';     Protocol='TCP'; Ports=@('389');         RemoteAddress='Any' },
    @{ Name='MedDef-Kerberos-TCP'; Label='Kerberos'; Protocol='TCP'; Ports=@('88');          RemoteAddress='Any' },
    @{ Name='MedDef-Kerberos-UDP'; Label='Kerberos'; Protocol='UDP'; Ports=@('88');          RemoteAddress='Any' },
    @{ Name='MedDef-SMB';  Label='SMB';      Protocol='TCP'; Ports=@('445');         RemoteAddress=$serverSubnet },
    @{ Name='MedDef-WinRM';   Label='WinRM';    Protocol='TCP'; Ports=@('5985','5986'); RemoteAddress=$managementSubnet }
)

# These ports must not remain open to other networks through old local rules.
$restrictedSources = @{
    3389 = $managementSubnet
    445  = $serverSubnet
    5985 = $managementSubnet
    5986 = $managementSubnet
}

$disabledLegacyNames = New-Object 'System.Collections.Generic.List[string]'
$reviewRuleNames = New-Object 'System.Collections.Generic.List[string]'

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator privileges are required. Open Windows PowerShell as Administrator on DC01.'
    }

    Write-Stage 'Capturing current firewall state...'
    $before = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Sort-Object Name)
    foreach ($profile in $before) {
        $state = if ([string]$profile.Enabled -eq 'True') { 'ON' } else { 'OFF' }
        Write-Host ("    {0}: {1}, DefaultInbound: {2}" -f $profile.Name, $state, $profile.DefaultInboundAction)
    }

    # netsh .wfw exports all firewall rules and profile settings, making recovery possible.
    New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
    $backupFile = Join-Path $backupPath 'before_firewall.wfw'
    & netsh.exe advfirewall export $backupFile | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $backupFile)) {
        throw 'Firewall backup failed. No configuration changes were made.'
    }
    $before | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogBlocked |
        ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $backupPath 'before_profiles.json') -Encoding UTF8
    Write-Host "    Recovery backup: $backupFile" -ForegroundColor Gray

    # Create narrowly scoped inbound exceptions BEFORE enabling default-deny.
    Write-Stage 'Creating MedDefense inbound allow rules...'
    foreach ($entry in $allowRules) {
        $existing = @(Get-NetFirewallRule -Name $entry.Name -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
        foreach ($oldRule in $existing) {
            if ($oldRule.Group -ne $ruleGroup) {
                throw "The name '$($entry.Name)' belongs to another firewall rule. Not overwriting it."
            }
            $oldRule | Remove-NetFirewallRule -ErrorAction Stop
        }

        $ruleParams = @{
            Name          = $entry.Name
            DisplayName   = $entry.Name
            Description   = ("MedDefense Task 11 - {0}: {1} {2} from {3}" -f $entry.Label, $entry.Protocol, ($entry.Ports -join ","), $entry.RemoteAddress)
            Group         = $ruleGroup
            PolicyStore   = 'PersistentStore'
            Profile       = 'Any'
            Enabled       = 'True'
            Direction     = 'Inbound'
            Action        = 'Allow'
            Protocol      = $entry.Protocol
            LocalPort     = $entry.Ports
            RemoteAddress = $entry.RemoteAddress
        }
        New-NetFirewallRule @ruleParams | Out-Null
        Write-Host ("    {0}: {1} {2} from {3} [CREATED]" -f
            $entry.Name, $entry.Protocol, ($entry.Ports -join ','), $entry.RemoteAddress) -ForegroundColor Green
    }

    Write-Stage 'Identifying and disabling conflicting legacy local allow rules...'
    $legacyRules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Inbound -Action Allow -Enabled True |
        Where-Object { $_.Group -ne $ruleGroup })

    foreach ($legacy in $legacyRules) {
        $portInfo = $legacy | Get-NetFirewallPortFilter
        $addressInfo = $legacy | Get-NetFirewallAddressFilter
        $ports = @($portInfo.LocalPort | ForEach-Object { [string]$_ })
        $addresses = @($addressInfo.RemoteAddress | ForEach-Object { [string]$_ })

        # Catch-all and application-based rules require service-aware review;
        # disabling them blindly could stop core domain-controller functions.
        if ($ports -contains 'Any') {
            # Disable only a genuine allow-everything rule. Rules limited to a
            # specific executable/service may be necessary for AD operation.
            $appInfo = $legacy | Get-NetFirewallApplicationFilter
            $serviceInfo = $legacy | Get-NetFirewallServiceFilter
            $isUnrestricted = (
                [string]$portInfo.Protocol -in @('Any','256') -and
                $addresses.Count -eq 1 -and $addresses[0] -eq 'Any' -and
                [string]$appInfo.Program -eq 'Any' -and
                [string]$serviceInfo.Service -eq 'Any'
            )
            if ($isUnrestricted) {
                $legacy | Disable-NetFirewallRule -ErrorAction Stop
                $disabledLegacyNames.Add($legacy.Name)
                Write-Host "    Disabled unrestricted legacy rule: $($legacy.DisplayName)" -ForegroundColor Yellow
            } else {
                $reviewRuleNames.Add($legacy.Name)
            }
            continue
        }

        $isTcpCompatible = [string]$portInfo.Protocol -in @('TCP','6','Any','256')
        if (-not $isTcpCompatible) { continue }

        $conflicts = $false
        foreach ($target in @(3389,445,5985,5986)) {
            if (-not (Test-PortIncluded -ConfiguredPorts $ports -TargetPort $target)) { continue }
            $expectedScope = [string]$restrictedSources[$target]
            if ($addresses.Count -ne 1 -or $addresses[0] -ne $expectedScope) {
                $conflicts = $true
                break
            }
        }

        if ($conflicts) {
            $legacy | Disable-NetFirewallRule -ErrorAction Stop
            $disabledLegacyNames.Add($legacy.Name)
            Write-Host "    Disabled legacy rule: $($legacy.DisplayName)" -ForegroundColor Yellow
        }
    }
    Write-Host "    Conflicting local rules disabled: $($disabledLegacyNames.Count)"
    if ($reviewRuleNames.Count -gt 0) {
        Write-Warning "$($reviewRuleNames.Count) rules with 'Any' local port need manual review; they were not blindly disabled."
    }

    Write-Stage 'Enabling Domain, Private, and Public profiles with default-deny inbound...'
    Set-NetFirewallProfile -Name $profiles -PolicyStore PersistentStore -Enabled True `
        -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
    Write-Host '    Domain, Private, Public: ON; DefaultInbound: Block [SET]' -ForegroundColor Green

    Write-Stage 'Enabling dropped-packet logging...'
    Set-NetFirewallProfile -Name $profiles -PolicyStore PersistentStore -LogBlocked True `
        -LogFileName $logFile -LogMaxSizeKilobytes 32767 -ErrorAction Stop
    Write-Host "    Log: $logFile [SET]" -ForegroundColor Green

    Write-Stage 'Verifying effective firewall profiles and service rules...'
    $effective = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    foreach ($name in $profiles) {
        $profile = $effective | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if ($null -eq $profile -or [string]$profile.Enabled -ne 'True' -or
            [string]$profile.DefaultInboundAction -ne 'Block' -or
            [string]$profile.LogBlocked -ne 'True') {
            throw "Effective $name firewall profile does not match the required lockdown settings. Check GPO overrides."
        }
        Write-Host "    $name`: ON / Block inbound / Log dropped [VERIFIED]" -ForegroundColor Green
    }

    foreach ($entry in $allowRules) {
        if (-not (Test-RuleConfiguration -Definition $entry)) {
            throw "Firewall rule verification failed: $($entry.Name)."
        }
    }
    Write-Host "    Service categories: 6; protocol-specific rules: $($allowRules.Count) [VERIFIED]" -ForegroundColor Green

    $result = [PSCustomObject]@{
        CheckedAt              = (Get-Date).ToString('o')
        Computer               = $env:COMPUTERNAME
        ManagementSubnet       = $managementSubnet
        ServerSubnet           = $serverSubnet
        BaselineBackup         = $backupFile
        Profiles               = @($effective | Select-Object Name,Enabled,DefaultInboundAction,LogBlocked)
        CustomRuleNames        = @($allowRules | ForEach-Object { $_.Name })
        DisabledLegacyRuleNames = @($disabledLegacyNames.ToArray())
        ManualReviewRuleNames  = @($reviewRuleNames.ToArray())
        Note                   = 'Local policy only; DC functionality requires AD port and GPO assessment.'
    }
    $reportFile = Join-Path $backupPath 'firewall_result.json'
    $result | ConvertTo-Json -Depth 6 | Set-Content -Path $reportFile -Encoding UTF8

    Write-Host ''
    Write-Host '[SUCCESS] Local Windows Firewall lockdown configured and verified.' -ForegroundColor Green
    Write-Host "    Evidence: $reportFile"
    if ($reviewRuleNames.Count -gt 0) {
        Write-Warning 'Some broad inbound rules remain. Do not claim full least-privilege enforcement until reviewed.'
    }
    Write-Warning 'Additional DC services (RPC, SYSVOL, replication, LDAP SSL, GC, NTP) may require scoped exceptions.'
}
catch {
    Write-Host "[ERROR] Firewall hardening stopped: $($_.Exception.Message)" -ForegroundColor Red
    if ($null -ne $backupPath -and (Test-Path -LiteralPath (Join-Path $backupPath 'before_firewall.wfw'))) {
        Write-Warning "Recovery backup available: $(Join-Path $backupPath 'before_firewall.wfw')"
        Write-Warning 'For an authorized rollback, use: netsh advfirewall import <path-to-before_firewall.wfw>'
    }
    exit 1
}
