#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    14-service_accounts.ps1 - MedDefense service-account assessment and remediation.
.PURPOSE
    Inventory user and managed service accounts, identify risky privileges,
    credentials and delegation, prevent credential delegation, restrict
    interactive/RDP logon by domain GPO, and remove inappropriate admin roles.
.AUTHOR
    MedDefense Security Team
.DATE
    2026-10-20
.NOTES
    Run in elevated Windows PowerShell on authorized DC01 (meddefense.local).
    Defaults to remediation; -AuditOnly inventories without changing the domain.
    Passwords are NOT rotated automatically. GPO enforcement on other computers
    requires their own policy refresh. Preserve the report for rollback/review.
#>

[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [ValidateRange(1, 3650)]
    [int]$OldPasswordDays = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedDomain = 'meddefense.local'
$restrictedGroupName = 'GG_ServiceAccounts_NoInteractive'
$policyName = 'MedDefense - Service Account Logon Restrictions'
$workRoot = Join-Path $env:ProgramData 'MedDefense\ServiceAccountReviews'
$runFolder = Join-Path $workRoot (Get-Date -Format 'yyyyMMdd_HHmmss_fff')
$observations = [System.Collections.Generic.List[object]]::new()
$changes = [System.Collections.Generic.List[object]]::new()

function Write-Stage {
    param([string]$Title)
    Write-Host ("`n[*] " + $Title) -ForegroundColor Cyan
}

function Add-Observation {
    param([string]$Account, [string]$Severity, [string]$Issue)
    $script:observations.Add([pscustomobject]@{
        Account = $Account; Severity = $Severity; Finding = $Issue
    })
    Write-Host ("    [{0}] {1}: {2}" -f $Severity, $Account, $Issue) -ForegroundColor Yellow
}

function Record-Change {
    param([string]$Account, [string]$Action, [string]$Result)
    $script:changes.Add([pscustomobject]@{
        Account = $Account; Action = $Action; Result = $Result
    })
}

function Get-DirectGroups {
    param([Parameter(Mandatory)]$Principal)
    return @(Get-ADPrincipalGroupMembership -Identity $Principal.DistinguishedName -Server $script:pdc -ErrorAction Stop)
}

function Set-DenyRightsInTemplate {
    param([string]$TemplatePath, [string]$Sid)
    $folder = Split-Path -Path $TemplatePath -Parent
    New-Item -Path $folder -ItemType Directory -Force | Out-Null
    if (Test-Path -LiteralPath $TemplatePath) {
        $lines = @(Get-Content -LiteralPath $TemplatePath -Encoding Unicode)
    } else {
        $lines = @('[Unicode]', 'Unicode=yes', '', '[Version]', 'signature="$CHICAGO$"', 'Revision=1')
    }

    $targets = @('SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight')
    $merged = @{}
    foreach ($right in $targets) {
        $current = @($lines | Where-Object { $_ -match "^\s*$right\s*=" } | Select-Object -First 1)
        $members = @()
        if ($current.Count -gt 0) {
            $members = @(($current[0] -split '=', 2)[1] -split ',' |
                ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }
        if ($members -notcontains ('*' + $Sid)) { $members += ('*' + $Sid) }
        $merged[$right] = "$right = $($members -join ',')"
    }

    $result = [System.Collections.Generic.List[string]]::new()
    $inRights = $false
    $foundRights = $false
    $added = $false
    foreach ($line in $lines) {
        if ($line -match '^\s*\[([^\]]+)\]\s*$') {
            if ($inRights -and -not $added) {
                foreach ($right in $targets) { $result.Add($merged[$right]) }
                $added = $true
            }
            $inRights = ($Matches[1] -ieq 'Privilege Rights')
            if ($inRights) { $foundRights = $true }
        }
        if ($inRights -and ($line -match '^\s*(SeDenyInteractiveLogonRight|SeDenyRemoteInteractiveLogonRight)\s*=')) {
            continue  # Reinsert the merged values once, retaining other rights.
        }
        $result.Add($line)
    }
    if (-not $foundRights) {
        $result.Add('')
        $result.Add('[Privilege Rights]')
    }
    if (-not $added) {
        foreach ($right in $targets) { $result.Add($merged[$right]) }
    }
    $utf16 = [System.Text.UnicodeEncoding]::new($false, $true)
    [IO.File]::WriteAllText($TemplatePath, (($result.ToArray() -join "`r`n") + "`r`n"), $utf16)
}

function Register-SecurityPolicyExtension {
    param([string]$GpoDn, [string]$Server)
    # Security Settings client-side extension and its management-tool extension.
    $entry = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    $object = Get-ADObject -Identity $GpoDn -Server $Server -Properties gPCMachineExtensionNames
    $existing = [string]$object.gPCMachineExtensionNames
    if ($existing.IndexOf($entry, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        Set-ADObject -Identity $GpoDn -Server $Server -Replace @{
            gPCMachineExtensionNames = ($existing + $entry)
        }
    }
}

function Advance-ComputerGpoVersion {
    param([string]$GpoDn, [string]$GptIni, [string]$Server)
    # The upper 16 bits of the GPO version number track computer settings.
    $object = Get-ADObject -Identity $GpoDn -Server $Server -Properties versionNumber
    $previous = [long]$object.versionNumber
    $machine = (($previous -shr 16) + 1) -band 0xffff
    $user = $previous -band 0xffff
    $nextVersion = [long](($machine -shl 16) -bor $user)
    $content = if (Test-Path -LiteralPath $GptIni) {
        @(Get-Content -LiteralPath $GptIni)
    } else { @('[General]') }
    $content = @($content | Where-Object { $_ -notmatch '^\s*Version\s*=' })
    $content += "Version=$nextVersion"
    [IO.File]::WriteAllText($GptIni, (($content -join "`r`n") + "`r`n"), [Text.Encoding]::ASCII)
    Set-ADObject -Identity $GpoDn -Server $Server -Replace @{ versionNumber = [int]$nextVersion }
}

function Get-LocalDenyRightSids {
    param([string]$Right, [string]$ExportPath)
    $output = & secedit.exe /export /cfg $ExportPath /areas USER_RIGHTS /quiet 2>&1
    if ($LASTEXITCODE -ne 0) { throw "secedit export failed: $($output -join ' ')" }
    $entry = @(Get-Content -LiteralPath $ExportPath -Encoding Unicode |
        Where-Object { $_ -match ('^\s*' + [regex]::Escape($Right) + '\s*=') } |
        Select-Object -First 1)
    if ($entry.Count -eq 0) { return @() }
    return @(($entry[0] -split '=', 2)[1] -split ',' |
        ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ })
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop
    $computer = Get-CimInstance Win32_ComputerSystem
    if ($computer.DomainRole -lt 4) { throw 'Use the authorized DC01 domain controller, not your personal Windows machine.' }
    $domain = Get-ADDomain
    if ($domain.DNSRoot -ine $expectedDomain) { throw "Unexpected AD domain: $($domain.DNSRoot)." }
    $pdc = $domain.PDCEmulator
    New-Item -Path $runFolder -ItemType Directory -Force | Out-Null

    Write-Stage 'Discovering MedDefense service identities...'
    # Name/OU discovery is deliberately broader than an exact svc_ prefix.
    $userCandidates = @(Get-ADUser -Server $pdc -Filter * -Properties PasswordLastSet, LastLogonDate,
        Enabled, PasswordNeverExpires, AccountNotDelegated, TrustedForDelegation,
        TrustedToAuthForDelegation, ServicePrincipalName, UseDESKeyOnly)
    $serviceUsers = @($userCandidates | Where-Object {
        $_.SamAccountName -match 'svc' -or $_.Name -match 'svc' -or
        $_.DistinguishedName -match '(?i)OU=Service Accounts,'
    })
    # Include gMSAs/sMSAs as service identities, not ordinary user accounts.
    $managedAccounts = @(Get-ADServiceAccount -Server $pdc -Filter * -Properties PasswordLastSet,
        LastLogonDate, AccountNotDelegated, TrustedForDelegation,
        TrustedToAuthForDelegation, ServicePrincipalName, UseDESKeyOnly)
    $accounts = @($serviceUsers) + @($managedAccounts)
    if ($accounts.Count -eq 0) { throw 'No service accounts discovered; no changes made.' }

    # Resolve exact privileged groups by SID to avoid confusing similarly named groups.
    $domainSid = $domain.DomainSID.Value
    $privilegedSids = @(
        "${domainSid}-512", "${domainSid}-518", "${domainSid}-519", "${domainSid}-520",
        'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550'
    )
    $resolvedPrivileged = @{}
    foreach ($sid in $privilegedSids) {
        $g = Get-ADGroup -Identity $sid -Server $pdc -ErrorAction SilentlyContinue
        if ($null -ne $g) { $resolvedPrivileged[$g.SID.Value] = $g }
    }
    # Privileged DNS administration group is optional in some AD deployments.
    $dnsAdmins = Get-ADGroup -Identity 'DnsAdmins' -Server $pdc -ErrorAction SilentlyContinue
    if ($null -ne $dnsAdmins) { $resolvedPrivileged[$dnsAdmins.SID.Value] = $dnsAdmins }
    $backupOperators = Get-ADGroup -Identity 'S-1-5-32-551' -Server $pdc -ErrorAction SilentlyContinue

    $now = Get-Date
    $inventory = [System.Collections.Generic.List[object]]::new()
    foreach ($account in $accounts) {
        $name = $account.SamAccountName
        $memberships = @(Get-DirectGroups -Principal $account)
        $elevated = @($memberships | Where-Object { $resolvedPrivileged.ContainsKey($_.SID.Value) })
        $backupRole = @($memberships | Where-Object {
            $null -ne $backupOperators -and $_.SID.Value -eq $backupOperators.SID.Value
        })
        $passwordAge = if ($null -ne $account.PasswordLastSet) {
            [int][Math]::Floor(($now - $account.PasswordLastSet).TotalDays)
        } else { $null }
        $spns = @($account.ServicePrincipalName | Where-Object { $_ })
        $kind = if ($account.ObjectClass -eq 'user') { 'Standard service user' } else { 'Managed service account' }
        $item = [pscustomobject]@{
            Name                     = $name
            Type                     = $kind
            DistinguishedName        = $account.DistinguishedName
            Enabled                  = $account.Enabled
            PasswordAgeDays          = $passwordAge
            PasswordNeverExpires     = if ($account.ObjectClass -eq 'user') { $account.PasswordNeverExpires } else { $null }
            LastLogon                = $account.LastLogonDate
            Groups                   = @($memberships | ForEach-Object { $_.Name })
            ExcessiveGroups          = @($elevated | ForEach-Object { $_.Name })
            BackupOperatorsReview    = ($backupRole.Count -gt 0)
            AccountNotDelegated      = [bool]$account.AccountNotDelegated
            UnconstrainedDelegation  = [bool]$account.TrustedForDelegation
            ProtocolTransition       = [bool]$account.TrustedToAuthForDelegation
            UseDESKeyOnly            = [bool]$account.UseDESKeyOnly
            SPNs                     = $spns
        }
        $inventory.Add($item)
        Write-Host ("    {0} ({1})" -f $name, $kind) -ForegroundColor White
        Write-Host ("      Password age: {0}; Last logon: {1}" -f $passwordAge, $account.LastLogonDate)
        Write-Host ("      Groups: {0}" -f ($item.Groups -join ', '))
        Write-Host ("      SPNs: {0}" -f ($spns -join ', '))
        Write-Host ("      Delegation: unconstrained={0}; sensitive={1}" -f $account.TrustedForDelegation, $account.AccountNotDelegated)

        if ($null -eq $passwordAge) {
            Add-Observation $name 'Medium' 'Password age unavailable; review credential lifecycle.'
        } elseif ($passwordAge -gt $OldPasswordDays) {
            Add-Observation $name 'High' "Password has not been rotated in $passwordAge days."
        }
        if ($account.TrustedForDelegation) { Add-Observation $name 'Critical' 'Unconstrained Kerberos delegation enabled.' }
        if ($account.TrustedToAuthForDelegation) { Add-Observation $name 'High' 'Protocol-transition delegation enabled; check dependencies.' }
        if (-not $account.AccountNotDelegated) { Add-Observation $name 'High' 'Account is not marked sensitive/cannot-be-delegated.' }
        if ($account.UseDESKeyOnly) { Add-Observation $name 'High' 'Account is restricted to weak DES encryption.' }
        if ($elevated.Count -gt 0) { Add-Observation $name 'Critical' ("Excessive admin roles: " + ($item.ExcessiveGroups -join ', ')) }
        if ($backupRole.Count -gt 0) { Add-Observation $name 'High' 'Backup Operators membership needs service-owner approval.' }
        if ($spns.Count -gt 0) { Add-Observation $name 'Medium' "SPNs present ($($spns.Count)); assess Kerberoasting exposure." }
        if ($null -ne $account.LastLogonDate -and $account.LastLogonDate.Hour -ge 0 -and $account.LastLogonDate.Hour -lt 5) {
            Add-Observation $name 'Medium' 'Last recorded logon was overnight; investigate if unexpected (not proof of compromise).'
        }
    }

    $beforePath = Join-Path $runFolder 'accounts_before.json'
    @($inventory) | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $beforePath -Encoding UTF8
    Write-Host "`n[*] Initial inventory saved: $beforePath"

    if ($AuditOnly) {
        Write-Host '[*] Audit-only mode: no Active Directory or GPO changes made.' -ForegroundColor Green
    } else {
        # A dedicated deny group is safer to maintain than enumerating many SIDs
        # directly in every workstation's local user-right assignment.
        Write-Stage 'Preparing a dedicated interactive-logon-deny security group...'
        $guard = Get-ADGroup -Identity $restrictedGroupName -Server $pdc -ErrorAction SilentlyContinue
        if ($null -eq $guard) {
            $guard = New-ADGroup -Name $restrictedGroupName -SamAccountName $restrictedGroupName `
                -GroupCategory Security -GroupScope Global -Path $domain.UsersContainer -Server $pdc -PassThru
            Write-Host "    $restrictedGroupName [CREATED]"
        }
        $guard = Get-ADGroup -Identity $restrictedGroupName -Server $pdc -ErrorAction Stop
        $validAccounts = @($accounts | ForEach-Object { $_.DistinguishedName })
        $present = @(Get-ADGroupMember -Identity $guard -Server $pdc -ErrorAction Stop)
        $unrecognized = @($present | Where-Object { $validAccounts -notcontains $_.DistinguishedName })
        if ($unrecognized.Count -gt 0) {
            throw "The existing $restrictedGroupName group contains unrecognized members. Refusing to create potentially unsafe logon denies."
        }

        Write-Stage 'Removing incompatible delegation settings and inappropriate admin roles...'
        foreach ($account in $accounts) {
            $name = $account.SamAccountName
            Set-ADAccountControl -Identity $account.DistinguishedName -AccountNotDelegated $true `
                -TrustedForDelegation $false -TrustedToAuthForDelegation $false -Server $pdc -ErrorAction Stop
            Record-Change $name 'Protect credentials; disable delegation and protocol transition' 'SET'
            Write-Host ("    {0}: cannot be delegated [SET]" -f $name)

            $direct = @(Get-DirectGroups -Principal $account)
            foreach ($membership in $direct) {
                if ($resolvedPrivileged.ContainsKey($membership.SID.Value)) {
                    Remove-ADGroupMember -Identity $membership.DistinguishedName -Members $account.DistinguishedName `
                        -Confirm:$false -Server $pdc -ErrorAction Stop
                    Record-Change $name ("Remove privileged membership: " + $membership.Name) 'REMOVED'
                    Write-Host ("    {0}: removed from {1}" -f $name, $membership.Name)
                }
            }
            $currentDenyMembers = @(Get-ADGroupMember -Identity $guard -Server $pdc)
            if (@($currentDenyMembers | Where-Object { $_.DistinguishedName -eq $account.DistinguishedName }).Count -eq 0) {
                Add-ADGroupMember -Identity $guard -Members $account.DistinguishedName -Server $pdc -ErrorAction Stop
                Record-Change $name "Add to $restrictedGroupName" 'ADDED'
            }
        }

        Write-Stage 'Creating domain-wide Group Policy interactive-logon restrictions...'
        $gpo = @(Get-GPO -All -Domain $expectedDomain -Server $pdc |
            Where-Object { $_.DisplayName -eq $policyName } | Select-Object -First 1)
        if ($gpo.Count -eq 0) {
            $gpoObject = New-GPO -Name $policyName -Domain $expectedDomain -Server $pdc
            Write-Host "    GPO: $policyName [CREATED]"
        } else {
            $gpoObject = $gpo[0]
            $backupPath = Join-Path $runFolder 'previous_gpo'
            New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
            Backup-GPO -Guid $gpoObject.Id -Domain $expectedDomain -Server $pdc -Path $backupPath | Out-Null
            Write-Host "    Existing GPO backed up: $backupPath"
        }

        $guid = '{' + $gpoObject.Id.ToString().ToUpperInvariant() + '}'
        $policyFolder = "\\$pdc\SYSVOL\$expectedDomain\Policies\$guid"
        if (-not (Test-Path -LiteralPath $policyFolder)) { throw "Cannot access SYSVOL policy folder: $policyFolder" }
        $template = Join-Path $policyFolder 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
        $gpoDn = "CN=$guid,CN=Policies,CN=System,$($domain.DistinguishedName)"
        Set-DenyRightsInTemplate -TemplatePath $template -Sid $guard.SID.Value
        Register-SecurityPolicyExtension -GpoDn $gpoDn -Server $pdc
        Advance-ComputerGpoVersion -GpoDn $gpoDn -GptIni (Join-Path $policyFolder 'GPT.INI') -Server $pdc

        $linked = @((Get-GPInheritance -Target $domain.DistinguishedName -Domain $expectedDomain -Server $pdc).GpoLinks |
            Where-Object { [string]$_.GpoId -eq [string]$gpoObject.Id })
        if ($linked.Count -eq 0) {
            New-GPLink -Guid $gpoObject.Id -Domain $expectedDomain -Server $pdc `
                -Target $domain.DistinguishedName -LinkEnabled Yes | Out-Null
        }
        Record-Change '(domain)' 'Link service-account interactive logon deny GPO' 'LINKED'
        Write-Host "    Deny console and RDP logon: $restrictedGroupName [SET]"

        Write-Stage 'Refreshing computer policy on DC01...'
        $gpOutput = & gpupdate.exe '/target:computer' '/force' '/wait:60' 2>&1
        if ($LASTEXITCODE -ne 0) { throw "gpupdate failed: $($gpOutput -join ' ')" }
        Write-Host '    gpupdate [COMPLETE]'

        Write-Stage 'Verifying AD settings, group memberships and effective local logon denies...'
        foreach ($account in $accounts) {
            $actual = if ($account.ObjectClass -eq 'user') {
                Get-ADUser -Identity $account.DistinguishedName -Server $pdc -Properties AccountNotDelegated, TrustedForDelegation, TrustedToAuthForDelegation
            } else {
                Get-ADServiceAccount -Identity $account.DistinguishedName -Server $pdc -Properties AccountNotDelegated, TrustedForDelegation, TrustedToAuthForDelegation
            }
            if (-not $actual.AccountNotDelegated -or $actual.TrustedForDelegation -or $actual.TrustedToAuthForDelegation) {
                throw "Delegation settings not verified for $($account.SamAccountName)."
            }
            $remaining = @(Get-DirectGroups -Principal $actual |
                Where-Object { $resolvedPrivileged.ContainsKey($_.SID.Value) })
            if ($remaining.Count -gt 0) { throw "Privileged direct memberships remain for $($account.SamAccountName)." }
            $guardMembers = @(Get-ADGroupMember -Identity $guard -Server $pdc)
            if (@($guardMembers | Where-Object { $_.DistinguishedName -eq $account.DistinguishedName }).Count -eq 0) {
                throw "Missing deny-group membership for $($account.SamAccountName)."
            }
            Write-Host ("    {0}: delegation and group checks [VERIFIED]" -f $account.SamAccountName)
        }

        $rightsPath = Join-Path $runFolder 'effective_rights.inf'
        foreach ($right in @('SeDenyInteractiveLogonRight','SeDenyRemoteInteractiveLogonRight')) {
            $sids = @(Get-LocalDenyRightSids -Right $right -ExportPath $rightsPath)
            if ($sids -notcontains $guard.SID.Value) {
                throw "Effective local $right does not contain $restrictedGroupName. GPO precedence or refresh may be blocking it."
            }
            Write-Host ("    {0}: guard group SID present [VERIFIED]" -f $right)
        }
    }

    $summary = [pscustomobject]@{
        Timestamp         = (Get-Date).ToString('o')
        Domain            = $domain.DNSRoot
        Mode              = if ($AuditOnly) { 'AuditOnly' } else { 'Remediation' }
        TotalAccounts     = $accounts.Count
        Findings          = @($observations)
        Changes           = @($changes)
        InitialInventory  = @($inventory)
        ReportFolder      = $runFolder
    }
    $reportPath = Join-Path $runFolder 'service_account_report.json'
    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8
    Write-Host "`n[*] Service accounts assessed: $($accounts.Count)"
    Write-Host "[*] Findings: $($observations.Count)"
    Write-Host "[*] Changes recorded: $($changes.Count)"
    Write-Host "[*] Report: $reportPath" -ForegroundColor Green
    Write-Host '[!] Review stale credentials, service-specific privilege needs and unexpected logons before rotating passwords.' -ForegroundColor Yellow
    Write-Host '[!] Verify nested privileged memberships and delegated OU permissions separately.' -ForegroundColor Yellow
}
catch {
    if (Test-Path -LiteralPath $runFolder) {
        [pscustomobject]@{
            Time = (Get-Date).ToString('o')
            Error = $_.Exception.Message
            ChangesBeforeFailure = @($changes)
        } | ConvertTo-Json -Depth 5 |
            Set-Content -Path (Join-Path $runFolder 'partial_failure.json') -Encoding UTF8
    }
    Write-Error "Service account assessment/hardening failed: $($_.Exception.Message)"
    exit 1
}
