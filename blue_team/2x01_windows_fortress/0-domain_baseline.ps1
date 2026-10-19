<#
.SYNOPSIS
    0-domain_baseline.ps1 - MedDefense Active Directory security inventory.
.DESCRIPTION
    Read-only collection of the domain, users, groups, service accounts, GPO
    links, authentication policies, Kerberos settings, and privileged users.
    Saves the full inventory and security observations as JSON.
.NOTES
    Script: 0-domain_baseline.ps1
    Purpose: Establish the pre-hardening security baseline for meddefense.local.
    Author: MedDefense Security Analyst
    Date: 2026-10-19
#>

param(
    [string]$OutputPath = (".\DomainBaseline_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

$findings = [System.Collections.Generic.List[object]]::new()
$collectionIssues = [System.Collections.Generic.List[string]]::new()

function Add-Finding {
    param(
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium')][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Description
    )
    $findings.Add([pscustomobject]@{
        Severity = $Severity
        Category = $Category
        Description = $Description
    })
}

function Get-EncryptionNames {
    param([int]$Mask)

    # AD's msDS-SupportedEncryptionTypes low-order flags (not a guarantee of
    # which encryption type was negotiated for any particular ticket).
    $names = [System.Collections.Generic.List[string]]::new()
    if ($Mask -band 0x01) { $names.Add('DES-CBC-CRC') }
    if ($Mask -band 0x02) { $names.Add('DES-CBC-MD5') }
    if ($Mask -band 0x04) { $names.Add('RC4-HMAC') }
    if ($Mask -band 0x08) { $names.Add('AES128-CTS-HMAC-SHA1') }
    if ($Mask -band 0x10) { $names.Add('AES256-CTS-HMAC-SHA1') }
    if ($names.Count -eq 0) { $names.Add('No named encryption flags in low 5 bits') }
    return $names.ToArray()
}

function Get-GroupUsers {
    param([Parameter(Mandatory)][string]$GroupName)
    try {
        return @(Get-ADGroupMember -Identity $GroupName -Recursive |
            Where-Object { $_.objectClass -eq 'user' } |
            Select-Object -ExpandProperty SamAccountName)
    }
    catch {
        $collectionIssues.Add("Unable to resolve privileged group '$GroupName': $($_.Exception.Message)")
        return @()
    }
}

Write-Host '[1/10] Domain and domain controllers' -ForegroundColor Cyan
$domain = Get-ADDomain
$forest = Get-ADForest
$dcs = @(Get-ADDomainController -Filter *)

Write-Host '[2/10] User accounts' -ForegroundColor Cyan
$rawUsers = @(Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalName, 'msDS-SupportedEncryptionTypes')
$users = @($rawUsers | ForEach-Object {
    $encryptionMask = $_.'msDS-SupportedEncryptionTypes'
    [pscustomobject]@{
        Name                         = $_.Name
        SamAccountName               = $_.SamAccountName
        DistinguishedName            = $_.DistinguishedName
        Enabled                      = [bool]$_.Enabled
        LastLogonDate                = $_.LastLogonDate # Approximate, replicated value
        PasswordLastSet              = $_.PasswordLastSet
        PasswordNeverExpires         = [bool]$_.PasswordNeverExpires
        TrustedForDelegation         = [bool]$_.TrustedForDelegation
        TrustedToAuthForDelegation   = [bool]$_.TrustedToAuthForDelegation
        ServicePrincipalNames        = @($_.ServicePrincipalName)
        KerberosEncryptionMask       = $encryptionMask
        KerberosEncryptionTypes      = if ($null -eq $encryptionMask) { @('Not explicitly set') } else { @(Get-EncryptionNames -Mask ([int]$encryptionMask)) }
    }
})
$neverExpires = @($users | Where-Object { $_.PasswordNeverExpires })
$stale = @($users | Where-Object {
    $_.Enabled -and $null -ne $_.LastLogonDate -and
    $_.LastLogonDate -lt (Get-Date).AddDays(-90)
})
if ($neverExpires.Count -gt 0) {
    Add-Finding -Severity High -Category 'Account hygiene' -Description "$($neverExpires.Count) accounts have passwords set to never expire; review exceptions and account purpose."
}
if ($stale.Count -gt 0) {
    Add-Finding -Severity Medium -Category 'Account hygiene' -Description "$($stale.Count) enabled accounts have an approximate last logon older than 90 days."
}

Write-Host '[3/10] Groups and members' -ForegroundColor Cyan
$rawGroups = @(Get-ADGroup -Filter * -Properties GroupCategory, GroupScope)
$groups = @($rawGroups | ForEach-Object {
    $group = $_
    $members = @()
    $memberStatus = 'Complete'
    try {
        $members = @(Get-ADGroupMember -Identity $group.DistinguishedName |
            ForEach-Object {
                [pscustomobject]@{
                    Name = $_.Name
                    SamAccountName = $_.SamAccountName
                    ObjectClass = $_.objectClass
                    DistinguishedName = $_.DistinguishedName
                }
            })
    }
    catch {
        $memberStatus = 'Incomplete'
        $collectionIssues.Add("Cannot list members of '$($group.Name)': $($_.Exception.Message)")
    }
    [pscustomobject]@{
        Name = $group.Name
        DistinguishedName = $group.DistinguishedName
        GroupCategory = [string]$group.GroupCategory
        GroupScope = [string]$group.GroupScope
        MemberCount = $members.Count
        MembershipStatus = $memberStatus
        Members = $members
    }
})

Write-Host '[4/10] Service accounts and delegation' -ForegroundColor Cyan
$serviceAccounts = @($users | Where-Object {
    $_.SamAccountName -match 'svc' -or
    $_.DistinguishedName -match '(?i)OU=Service Accounts,'
})
# TrustedForDelegation is UNCONSTRAINED delegation. The similarly named
# TrustedToAuthForDelegation flag refers to protocol transition, not the same thing.
$unconstrained = @($serviceAccounts | Where-Object { $_.TrustedForDelegation })
if ($unconstrained.Count -gt 0) {
    Add-Finding -Severity Critical -Category 'Kerberos delegation' -Description "$($unconstrained.Count) identified service accounts allow unconstrained delegation."
}

Write-Host '[5/10] GPO inventory and links' -ForegroundColor Cyan
$rawGpos = @(Get-GPO -All)
$gpos = @($rawGpos | ForEach-Object {
    [pscustomobject]@{
        Name = $_.DisplayName
        Id = [string]$_.Id
        Status = [string]$_.GpoStatus
        Created = $_.CreationTime
        Modified = $_.ModificationTime
        Owner = [string]$_.Owner
    }
})
$gpoLinks = [System.Collections.Generic.List[object]]::new()
$containers = @($domain.DistinguishedName) +
    @(Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName)
foreach ($container in $containers) {
    try {
        $inheritance = Get-GPInheritance -Target $container
        $directLinks = @($inheritance.GpoLinks | ForEach-Object {
            [pscustomobject]@{
                Name = $_.DisplayName
                GpoId = [string]$_.GpoId
                Enabled = $_.Enabled
                Enforced = $_.Enforced
                Order = $_.Order
            }
        })
        $gpoLinks.Add([pscustomobject]@{
            Target = $container
            InheritanceBlocked = [string]$inheritance.GpoInheritanceBlocked
            DirectLinks = $directLinks
        })
    }
    catch {
        $collectionIssues.Add("Cannot inspect GPO links for '$container': $($_.Exception.Message)")
    }
}
$customGpos = @($gpos | Where-Object {
    $_.Name -notin @('Default Domain Policy', 'Default Domain Controllers Policy')
})
if ($customGpos.Count -eq 0) {
    Add-Finding -Severity Medium -Category 'Group Policy' -Description 'No non-default GPOs were found; review whether dedicated security policies are missing.'
}

Write-Host '[6/10] Domain password policy' -ForegroundColor Cyan
$pwd = Get-ADDefaultDomainPasswordPolicy
$passwordPolicy = [pscustomobject]@{
    MinPasswordLength = $pwd.MinPasswordLength
    ComplexityEnabled = $pwd.ComplexityEnabled
    PasswordHistoryCount = $pwd.PasswordHistoryCount
    MaxPasswordAgeDays = $pwd.MaxPasswordAge.TotalDays
    MinPasswordAgeDays = $pwd.MinPasswordAge.TotalDays
}
if ($pwd.MinPasswordLength -lt 12) {
    Add-Finding -Severity High -Category 'Password policy' -Description "Minimum password length is $($pwd.MinPasswordLength), below this assessment's 12-character threshold."
}
if (-not $pwd.ComplexityEnabled) {
    Add-Finding -Severity High -Category 'Password policy' -Description 'Password complexity is disabled; assess together with minimum length and password screening.'
}
if ($pwd.PasswordHistoryCount -lt 5) {
    Add-Finding -Severity Medium -Category 'Password policy' -Description "Password history is $($pwd.PasswordHistoryCount), below this assessment's baseline of 5."
}

Write-Host '[7/10] Account lockout policy' -ForegroundColor Cyan
$lockoutPolicy = [pscustomobject]@{
    Threshold = $pwd.LockoutThreshold
    DurationMinutes = $pwd.LockoutDuration.TotalMinutes
    ObservationWindowMinutes = $pwd.LockoutObservationWindow.TotalMinutes
    Status = if ($pwd.LockoutThreshold -eq 0) { 'NOT CONFIGURED' } else { 'Configured' }
}
if ($pwd.LockoutThreshold -eq 0) {
    Add-Finding -Severity High -Category 'Account lockout' -Description 'Account lockout threshold is zero; no account lockout is enforced by the default domain policy.'
}

Write-Host '[8/10] Kerberos encryption configuration' -ForegroundColor Cyan
# The KDC default applies when an account has no explicit msDS-SupportedEncryptionTypes.
# It is NOT equivalent to all encryption types that might appear in tickets.
$kdcRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\KDC'
$kdcMask = $null
try {
    $kdcMask = (Get-ItemProperty -Path $kdcRegistryPath -Name 'DefaultDomainSupportedEncTypes' -ErrorAction Stop).DefaultDomainSupportedEncTypes
}
catch {
    $collectionIssues.Add('KDC DefaultDomainSupportedEncTypes is not explicitly set or could not be read; no effective default is inferred.')
}
# The policy registry value records the Kerberos encryption types allowed on DC01.
$kerberosPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
$policyMask = $null
try {
    $policyMask = (Get-ItemProperty -Path $kerberosPolicyPath -Name 'SupportedEncryptionTypes' -ErrorAction Stop).SupportedEncryptionTypes
}
catch {
    $collectionIssues.Add('DC01 Kerberos allowed-encryption policy is not explicitly set or could not be read.')
}
$kerberos = [pscustomobject]@{
    Dc01PolicyRegistryValue = $policyMask
    Dc01AllowedEncryptionTypes = if ($null -eq $policyMask) { @('Not explicitly set / not established') } else { @(Get-EncryptionNames -Mask ([int]$policyMask)) }
    KdcDefaultRegistryValue = $kdcMask
    KdcDefaultEncryptionTypes = if ($null -eq $kdcMask) { @('Not explicitly set / not established') } else { @(Get-EncryptionNames -Mask ([int]$kdcMask)) }
    AccountsWithExplicitMask = @($users | Where-Object { $null -ne $_.KerberosEncryptionMask } | Select-Object -ExpandProperty SamAccountName)
    AccountEncryptionConfiguration = @($users | Select-Object SamAccountName, KerberosEncryptionMask, KerberosEncryptionTypes)
    Note = 'Policy is collected only from DC01. Inspect all DCs and Security events 4768/4769 to determine negotiated ticket encryption; unset masks do not prove AES is disabled.'
}
$explicitWeak = @($users | Where-Object {
    $null -ne $_.KerberosEncryptionMask -and
    (([int]$_.KerberosEncryptionMask -band 0x07) -ne 0)
})
if ($explicitWeak.Count -gt 0) {
    Add-Finding -Severity High -Category 'Kerberos encryption' -Description "$($explicitWeak.Count) user accounts explicitly permit DES or RC4 in their Kerberos encryption flags."
}
if ($null -ne $kdcMask -and (([int]$kdcMask -band 0x07) -ne 0)) {
    Add-Finding -Severity High -Category 'Kerberos encryption' -Description 'The DC KDC fallback encryption configuration includes DES or RC4 flags; verify effective policy and usage.'
}
if ($null -ne $policyMask -and (([int]$policyMask -band 0x07) -ne 0)) {
    Add-Finding -Severity High -Category 'Kerberos encryption' -Description 'The DC01 local/effective Kerberos encryption policy permits DES or RC4; inspect the source GPO.'
}

Write-Host '[9/10] Privileged group membership' -ForegroundColor Cyan
$privileged = [pscustomobject]@{
    DomainAdmins = @(Get-GroupUsers -GroupName 'Domain Admins')
    EnterpriseAdmins = @(Get-GroupUsers -GroupName 'Enterprise Admins')
    SchemaAdmins = @(Get-GroupUsers -GroupName 'Schema Admins')
}
$uniqueAdmins = @($privileged.DomainAdmins + $privileged.EnterpriseAdmins + $privileged.SchemaAdmins |
    Sort-Object -Unique)
if ($uniqueAdmins.Count -gt 5) {
    Add-Finding -Severity High -Category 'Privileged access' -Description "$($uniqueAdmins.Count) distinct users hold Domain, Enterprise or Schema Admin membership; review least privilege."
}

Write-Host '[10/10] Report and security findings' -ForegroundColor Cyan
$criticalCount = @($findings | Where-Object Severity -eq Critical).Count
$highCount = @($findings | Where-Object Severity -eq High).Count
$mediumCount = @($findings | Where-Object Severity -eq Medium).Count
$summary = [pscustomobject]@{
    UserAccounts = $users.Count
    PasswordNeverExpires = $neverExpires.Count
    ServiceAccounts = $serviceAccounts.Count
    UnconstrainedServiceAccounts = $unconstrained.Count
    Gpos = $gpos.Count
    Findings = $findings.Count
    Critical = $criticalCount
    High = $highCount
    Medium = $mediumCount
    CollectionIssues = $collectionIssues.Count
}
$report = [pscustomobject]@{
    GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    DomainInformation = [pscustomobject]@{
        Name = $domain.DNSRoot
        DomainLevel = [string]$domain.DomainMode
        ForestLevel = [string]$forest.ForestMode
        DomainControllers = @($dcs | ForEach-Object {
            [pscustomobject]@{ HostName = $_.HostName; Site = $_.Site; IPv4Address = $_.IPv4Address }
        })
    }
    Users = $users
    Groups = $groups
    ServiceAccounts = $serviceAccounts
    Gpos = $gpos
    GpoLinks = $gpoLinks.ToArray()
    PasswordPolicy = $passwordPolicy
    LockoutPolicy = $lockoutPolicy
    Kerberos = $kerberos
    PrivilegedMembership = $privileged
    Summary = $summary
    Findings = $findings.ToArray()
    CollectionIssues = $collectionIssues.ToArray()
}

$report | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $OutputPath -Encoding UTF8 -Force

Write-Host ''
Write-Host '--- MEDDEFENSE DOMAIN BASELINE ---' -ForegroundColor Green
Write-Host "Domain: $($domain.DNSRoot)"
Write-Host "Domain Controllers: $($dcs.HostName -join ', ')"
Write-Host "User Accounts: $($users.Count) (Password Never Expires: $($neverExpires.Count))"
Write-Host "Service Accounts: $($serviceAccounts.Count) (Unconstrained Delegation: $($unconstrained.Count))"
Write-Host "GPOs: $($gpos.Count) | Domain/OU link targets: $($gpoLinks.Count)"
Write-Host "Password Minimum Length: $($pwd.MinPasswordLength) | Complexity: $($pwd.ComplexityEnabled)"
Write-Host "Lockout Threshold: $(if ($pwd.LockoutThreshold -eq 0) { 'NOT CONFIGURED (0)' } else { $pwd.LockoutThreshold })"
Write-Host "DC01 Kerberos Allowed: $($kerberos.Dc01AllowedEncryptionTypes -join ', ')"
Write-Host "KDC Kerberos Default: $($kerberos.KdcDefaultEncryptionTypes -join ', ')"
Write-Host "Domain Admins: $($privileged.DomainAdmins -join ', ')"
Write-Host "Enterprise Admins: $($privileged.EnterpriseAdmins -join ', ')"
Write-Host "Findings: $($summary.Findings) (Critical: $criticalCount, High: $highCount, Medium: $mediumCount)"
if ($collectionIssues.Count -gt 0) {
    Write-Warning "$($collectionIssues.Count) collection limitations recorded in the JSON; check before treating this as a complete baseline."
}
Write-Host "Full JSON report: $OutputPath" -ForegroundColor Green
