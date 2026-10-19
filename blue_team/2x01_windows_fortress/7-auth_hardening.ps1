#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    7-auth_hardening.ps1 - MedDefense Kerberos and authentication hardening.
.PURPOSE
    Inventory Kerberos encryption, DES-only accounts and service SPNs; remove
    account-level DES restrictions; deploy AES-only Kerberos and NTLMv2-only
    fallback through Group Policy; assess Credential Guard; verify settings.
.AUTHOR
    MedDefense Blue Team
.DATE
    2026-10-19
.NOTES
    Authorized DC01 / meddefense.local lab only. Changes domain authentication.
    Production rollout needs RC4/NTLMv1 dependency testing and maintenance.
    Credential Guard is inspected, not enabled on a domain controller.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedDomain = 'meddefense.local'
$gpoName = 'MedDefense - Authentication Hardening'
$aesMask = 0x18 # 0x08 AES128 + 0x10 AES256; excludes DES (0x01, 0x02) and RC4 (0x04)
$policyKerberosKey = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
$kdcKey = 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc'
$lsaKey = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'

function Show-EncryptionTypes {
    param([AllowNull()][object]$Mask)
    if ($null -eq $Mask) { return 'Not explicitly configured (OS/KDC defaults apply)' }
    $value = [int]$Mask
    $types = @()
    if ($value -band 0x01) { $types += 'DES-CBC-CRC' }
    if ($value -band 0x02) { $types += 'DES-CBC-MD5' }
    if ($value -band 0x04) { $types += 'RC4-HMAC' }
    if ($value -band 0x08) { $types += 'AES128' }
    if ($value -band 0x10) { $types += 'AES256' }
    if ($types.Count -eq 0) { return ('No known encryption bits in 0x{0:X}' -f $value) }
    return ($types -join ', ')
}

function Read-Dword {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    $value = $key.GetValue($Name, $null)
    if ($null -eq $value) { return $null }
    return [int]$value
}

function Set-AndCheckGpoValue {
    param(
        [Parameter(Mandatory)][guid]$GpoId,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$ValueName,
        [Parameter(Mandatory)][int]$Value
    )
    Set-GPRegistryValue -Guid $GpoId -Domain $Domain -Server $Server `
        -Key $Key -ValueName $ValueName -Value $Value -Type DWord | Out-Null
    $saved = Get-GPRegistryValue -Guid $GpoId -Domain $Domain -Server $Server `
        -Key $Key -ValueName $ValueName
    if ($null -eq $saved -or [int]$saved.Value -ne $Value) {
        throw "GPO verification failed for $Key\$ValueName."
    }
    Write-Host ("    {0} = {1}  [SET IN GPO]" -f $ValueName, $Value)
}

function Test-LocalValue {
    param([string]$Path, [string]$Name, [int]$Expected)
    $actual = Read-Dword -Path $Path -Name $Name
    if ($null -eq $actual) {
        Write-Warning "Effective local value not present yet: $Path\$Name (refresh/restart may be required)."
        return $false
    }
    if ($actual -ne $Expected) {
        Write-Warning "Effective local $Name is $actual, expected $Expected; inspect resultant GPO and restart."
        return $false
    }
    Write-Host "    $Name = $actual  [VERIFIED ON DC01]" -ForegroundColor Green
    return $true
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop

    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($computer.DomainRole -lt 4) {
        throw 'This script must run on the authorized Windows Server domain controller.'
    }
    $domain = Get-ADDomain
    if ($domain.DNSRoot -ine $expectedDomain) {
        throw "Unexpected domain $($domain.DNSRoot); expected $expectedDomain."
    }
    $server = "$($env:COMPUTERNAME).$expectedDomain"
    Write-Host "[*] Domain: $expectedDomain; current DC: $server" -ForegroundColor Cyan

    # 1. Inventory. Domain msDS-SupportedEncryptionTypes is not an authoritative
    # domain-wide cipher switch; check machine Kerberos policy and KDC defaults.
    Write-Host '[*] Current Kerberos configuration:'
    $policyMask = Read-Dword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'SupportedEncryptionTypes'
    $kdcMask = Read-Dword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'DefaultDomainSupportedEncTypes'
    Write-Host "    DC allowed types: $(Show-EncryptionTypes -Mask $policyMask)"
    Write-Host "    KDC default for unmarked accounts: $(Show-EncryptionTypes -Mask $kdcMask)"
    if ($null -ne $policyMask -and ($policyMask -band 0x07)) {
        Write-Warning 'Current DC Kerberos policy explicitly includes DES and/or RC4.'
    }
    $dcList = @(Get-ADDomainController -Filter *)
    Write-Host "    Domain controllers discovered: $($dcList.Count)"
    foreach ($dc in $dcList) { Write-Host "      $($dc.HostName)" }

    # 2-3. Identify service identities by name/OU or SPN and inspect DES flag.
    $allUsers = @(Get-ADUser -Filter * -Properties UseDESKeyOnly,ServicePrincipalName, `
        'msDS-SupportedEncryptionTypes',PasswordLastSet,DistinguishedName)
    $userServices = @($allUsers | Where-Object {
        $_.SamAccountName -like '*svc*' -or
        $_.DistinguishedName -match '(?i)OU=Service Accounts,' -or
        ($null -ne $_.ServicePrincipalName -and @($_.ServicePrincipalName).Count -gt 0)
    })

    $managedServices = @()
    try {
        $managedServices = @(Get-ADServiceAccount -Filter * -Properties UseDESKeyOnly, `
            ServicePrincipalName,'msDS-SupportedEncryptionTypes' -ErrorAction Stop)
    } catch {
        Write-Warning "Managed service account inventory could not be completed: $($_.Exception.Message)"
    }
    $serviceAccounts = @($userServices) + @($managedServices)
    $desUsers = @($allUsers | Where-Object { $_.UseDESKeyOnly -eq $true })
    $desManaged = @($managedServices | Where-Object { $_.UseDESKeyOnly -eq $true })

    Write-Host "[*] Service identities found: $($serviceAccounts.Count)"
    Write-Host '[*] Service principal names (SPNs):'
    foreach ($account in ($serviceAccounts | Sort-Object SamAccountName)) {
        $spns = @($account.ServicePrincipalName | Where-Object { $null -ne $_ -and $_ -ne '' })
        $accountMask = $account.'msDS-SupportedEncryptionTypes'
        $encryption = Show-EncryptionTypes -Mask $accountMask
        Write-Host "    $($account.SamAccountName): $(if ($spns.Count -gt 0) { $spns -join ', ' } else { '(none)' })"
        Write-Host "      UseDESKeyOnly=$($account.UseDESKeyOnly); encryption=$encryption"
        if ($spns.Count -gt 0 -and $account.ObjectClass -eq 'user') {
            Write-Warning "SPN-bearing user $($account.SamAccountName) is a potential Kerberoasting target; audit password strength and tickets."
        }
        if ($null -ne $accountMask) {
            $m = [int]$accountMask
            if (($m -band 0x18) -eq 0 -and ($m -band 0x07) -ne 0) {
                Write-Warning "$($account.SamAccountName) advertises only weak Kerberos types; verify AES keys and rotate service password before rollout."
            } elseif ($m -band 0x07) {
                Write-Warning "$($account.SamAccountName) explicitly advertises DES/RC4; plan an AES-only account update after compatibility testing."
            }
        }
    }

    # 4. Clear DES-only flag on all AD users carrying it, including services.
    Write-Host "[*] Accounts with UseDESKeyOnly enabled: $($desUsers.Count + $desManaged.Count)"
    foreach ($account in (@($desUsers) + @($desManaged))) {
        Write-Host "    $($account.SamAccountName): UseDESKeyOnly=True  [FOUND]"
        Set-ADAccountControl -Identity $account.DistinguishedName -UseDESKeyOnly $false -ErrorAction Stop
        $check = Get-ADObject -Identity $account.DistinguishedName -Properties userAccountControl
        if (([int]$check.userAccountControl -band 0x200000) -ne 0) {
            throw "Could not clear the DES-only flag on $($account.SamAccountName)."
        }
        Write-Host "    $($account.SamAccountName): DES-only flag cleared  [VERIFIED]" -ForegroundColor Green
    }

    # 5-6. Deploy domain-root machine configuration using GPO registry policy.
    # A new GPO avoids changing baseline GPOs; existing one is backed up.
    $gpo = Get-GPO -All -Domain $expectedDomain -Server $server |
        Where-Object { $_.DisplayName -eq $gpoName } | Select-Object -First 1
    if ($null -eq $gpo) {
        $gpo = New-GPO -Name $gpoName -Domain $expectedDomain -Server $server `
            -Comment 'MedDefense AES-only Kerberos and NTLMv2-only fallback'
        Write-Host "[*] Created GPO: $gpoName"
    } else {
        $backupFolder = Join-Path $env:ProgramData ('MedDefense\GPO-Backups\Auth-' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
        New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
        Backup-GPO -Guid $gpo.Id -Path $backupFolder -Domain $expectedDomain -Server $server | Out-Null
        Write-Host "[*] Reusing GPO; backup: $backupFolder"
    }

    Write-Host '[*] Enforcing AES128 + AES256 (0x18) through domain GPO:'
    Set-AndCheckGpoValue -GpoId $gpo.Id -Domain $expectedDomain -Server $server `
        -Key $policyKerberosKey -ValueName 'SupportedEncryptionTypes' -Value $aesMask
    # KDC fallback affects accounts without explicitly defined encryption masks.
    Set-AndCheckGpoValue -GpoId $gpo.Id -Domain $expectedDomain -Server $server `
        -Key $kdcKey -ValueName 'DefaultDomainSupportedEncTypes' -Value $aesMask
    Write-Host '[*] Refusing NTLMv1 and LM, allowing NTLMv2 fallback:'
    Set-AndCheckGpoValue -GpoId $gpo.Id -Domain $expectedDomain -Server $server `
        -Key $lsaKey -ValueName 'LmCompatibilityLevel' -Value 5

    $links = @((Get-GPInheritance -Target $domain.DistinguishedName `
        -Domain $expectedDomain -Server $server).GpoLinks)
    $link = $links | Where-Object { $_.DisplayName -eq $gpoName } | Select-Object -First 1
    if ($null -eq $link) {
        New-GPLink -Guid $gpo.Id -Target $domain.DistinguishedName -Domain $expectedDomain `
            -Server $server -LinkEnabled Yes | Out-Null
        Write-Host '[*] Linked authentication GPO to domain root. [LINKED]'
    } elseif (-not $link.Enabled) {
        Set-GPLink -Guid $gpo.Id -Target $domain.DistinguishedName -Domain $expectedDomain `
            -Server $server -LinkEnabled Yes | Out-Null
        Write-Host '[*] Re-enabled authentication GPO link. [LINKED]'
    } else {
        Write-Host '[*] Authentication GPO already linked. [OK]'
    }

    # 7. Credential Guard awareness: do not enable it on DC01. Check status
    # so that it can be planned for supported member servers/workstations.
    Write-Host '[*] Credential Guard awareness:'
    try {
        $guard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
            -ClassName Win32_DeviceGuard -ErrorAction Stop
        $running = @($guard.SecurityServicesRunning) -contains 1
        Write-Host "    Credential Guard running on DC01: $running"
        Write-Host "    VBS status: $($guard.VirtualizationBasedSecurityStatus)"
    } catch {
        Write-Warning "Credential Guard status unavailable on DC01: $($_.Exception.Message)"
    }
    Write-Host '    DC guidance: do NOT deploy Credential Guard here; assess and enable on compatible endpoints separately.'

    Write-Host '[*] Forcing computer Group Policy update on DC01...'
    & gpupdate.exe /target:computer /force
    if ($LASTEXITCODE -ne 0) { throw "gpupdate returned exit code $LASTEXITCODE." }
    Write-Host '    Group Policy refresh [COMPLETE]'

    # 8. Check actual state. A populated GPO is not the same as an applied GPO.
    Write-Host '[*] Verifying effective DC01 authentication configuration:'
    $policyOK = Test-LocalValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
        -Name 'SupportedEncryptionTypes' -Expected $aesMask
    $kdcOK = Test-LocalValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
        -Name 'DefaultDomainSupportedEncTypes' -Expected $aesMask
    $ntlmOK = Test-LocalValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'LmCompatibilityLevel' -Expected 5

    if ($policyOK -and $kdcOK -and $ntlmOK) {
        Write-Host '[+] DC01 configured: AES128/AES256 only, NTLMv2 fallback only. [VERIFIED]' -ForegroundColor Green
    } else {
        Write-Warning 'GPO values were written and read back, but some DC01 effective values are still pending or overridden.'
    }
    if ($dcList.Count -gt 1) {
        Write-Warning 'Only DC01 was refreshed/verified. Check replication, gpresult and effective settings on every other DC.'
    }
    Write-Warning 'AES key availability and actual ticket types require service testing and Event 4769 review; reboots may be required.'
    Write-Host '[+] Task 7 script finished; review all warnings before claiming domain-wide enforcement.'
} catch {
    Write-Host "[ERROR] Authentication hardening failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
