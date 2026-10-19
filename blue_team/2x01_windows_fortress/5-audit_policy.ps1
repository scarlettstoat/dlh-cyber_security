#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    5-audit_policy.ps1 - MedDefense Advanced Audit Policy
.PURPOSE
    Create and link a domain GPO that enables granular Windows auditing,
    process command-line capture, and stronger Security log protection.
.AUTHOR
    MedDefense Security Lab
.DATE
    2026-10-19
.NOTES
    Run only on the authorized meddefense.local domain controller.
    Changes are made through Group Policy and affect domain computers.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$policyName = 'MedDefense - Advanced Audit Policy'
$expectedDomain = 'meddefense.local'
$securityLogSizeKB = 1048576  # 1 GiB in KB
$securityLogSizeBytes = 1073741824

# GUIDs are used instead of translated subcategory names so that checks work
# even when the Windows display language is not English.
$auditSettings = @(
    [pscustomobject]@{ Category='Account Logon';      Name='Credential Validation';          Guid='0CCE923F-69AE-11D9-BED3-505054503030'; Value=3 }
    [pscustomobject]@{ Category='Account Logon';      Name='Kerberos Authentication Service'; Guid='0CCE9242-69AE-11D9-BED3-505054503030'; Value=3 }
    [pscustomobject]@{ Category='Logon/Logoff';       Name='Logon';                          Guid='0CCE9215-69AE-11D9-BED3-505054503030'; Value=3 }
    [pscustomobject]@{ Category='Logon/Logoff';       Name='Logoff';                         Guid='0CCE9216-69AE-11D9-BED3-505054503030'; Value=1 }
    [pscustomobject]@{ Category='Logon/Logoff';       Name='Special Logon';                  Guid='0CCE921B-69AE-11D9-BED3-505054503030'; Value=1 }
    [pscustomobject]@{ Category='Account Management'; Name='User Account Management';        Guid='0CCE9235-69AE-11D9-BED3-505054503030'; Value=3 }
    [pscustomobject]@{ Category='Privilege Use';      Name='Sensitive Privilege Use';        Guid='0CCE9228-69AE-11D9-BED3-505054503030'; Value=3 }
    [pscustomobject]@{ Category='Object Access';      Name='File System';                    Guid='0CCE921D-69AE-11D9-BED3-505054503030'; Value=3 }
    [pscustomobject]@{ Category='Object Access';      Name='Registry';                       Guid='0CCE921E-69AE-11D9-BED3-505054503030'; Value=3 }
    [pscustomobject]@{ Category='Process Tracking';   Name='Process Creation';               Guid='0CCE922B-69AE-11D9-BED3-505054503030'; Value=1 }
)

function Set-AuditCsv {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object[]]$Settings
    )

    $folder = Split-Path -Parent $Path
    New-Item -Path $folder -ItemType Directory -Force | Out-Null
    $header = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
    $lines = New-Object 'System.Collections.Generic.List[string]'
    [void]$lines.Add($header)
    $targetGuids = @($Settings | ForEach-Object { $_.Guid.ToUpperInvariant() })

    # Retain unrelated audit subcategories if this GPO already has settings.
    if (Test-Path -LiteralPath $Path) {
        $previousLines = @(Get-Content -LiteralPath $Path | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        foreach ($line in @($previousLines | Select-Object -Skip 1)) {
            if ($line -match '\{([0-9A-Fa-f-]{36})\}') {
                if ($targetGuids -contains $Matches[1].ToUpperInvariant()) { continue }
            }
            [void]$lines.Add($line)
        }
    }

    foreach ($setting in $Settings) {
        $mode = if ($setting.Value -eq 3) { 'Success and Failure' } else { 'Success' }
        [void]$lines.Add((',System,{0},{{{1}}},{2},,{3}' -f $setting.Name, $setting.Guid, $mode, $setting.Value))
    }

    # The Advanced Audit CSE consumes UTF-8 CSV with Windows CRLF newlines.
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, (($lines.ToArray() -join "`r`n") + "`r`n"), $utf8)
}

function Set-SecurityLogRight {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$DomainAdminSid
    )

    $folder = Split-Path -Parent $Path
    New-Item -Path $folder -ItemType Directory -Force | Out-Null

    # SeSecurityPrivilege controls the ability to manage/clear the Security log.
    # SYSTEM is retained for normal Windows operation; all human administrators
    # who require this right must be members of Domain Admins.
    $assignment = 'SeSecurityPrivilege = *S-1-5-18,*' + $DomainAdminSid
    if (Test-Path -LiteralPath $Path) {
        $source = @(Get-Content -LiteralPath $Path)
    } else {
        $source = @('[Unicode]', 'Unicode=yes', '', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '')
    }

    $output = New-Object 'System.Collections.Generic.List[string]'
    $insideRights = $false
    $rightsSectionFound = $false
    $assignmentWritten = $false

    foreach ($line in $source) {
        if ($line -match '^\s*\[([^]]+)\]\s*$') {
            if ($insideRights -and -not $assignmentWritten) {
                [void]$output.Add($assignment)
                $assignmentWritten = $true
            }
            $insideRights = ($Matches[1] -ieq 'Privilege Rights')
            if ($insideRights) { $rightsSectionFound = $true }
        }
        if ($insideRights -and $line -match '^\s*SeSecurityPrivilege\s*=') {
            if (-not $assignmentWritten) {
                [void]$output.Add($assignment)
                $assignmentWritten = $true
            }
            continue
        }
        [void]$output.Add($line)
    }

    if (-not $rightsSectionFound) {
        [void]$output.Add('')
        [void]$output.Add('[Privilege Rights]')
    }
    if (-not $assignmentWritten) { [void]$output.Add($assignment) }

    # Security templates use UTF-16 LE; preserve any unrelated settings.
    $unicode = [System.Text.UnicodeEncoding]::new($false, $true)
    [System.IO.File]::WriteAllText($Path, (($output.ToArray() -join "`r`n") + "`r`n"), $unicode)
}

function Register-MachineExtension {
    param(
        [Parameter(Mandatory)][string]$GpoDn,
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$CseGuid,
        [Parameter(Mandatory)][string]$ToolGuid
    )

    $adGpo = Get-ADObject -Identity $GpoDn -Server $Server -Properties gPCMachineExtensionNames
    $current = [string]$adGpo.gPCMachineExtensionNames
    $entry = '[{' + $CseGuid.ToUpperInvariant() + '}{' + $ToolGuid.ToUpperInvariant() + '}]'
    if ($current.IndexOf($entry, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        Set-ADObject -Identity $GpoDn -Server $Server -Replace @{
            gPCMachineExtensionNames = ($current + $entry)
        }
    }
}

function Write-PolicyRegistryValue {
    param(
        [Parameter(Mandatory)][guid]$GpoId,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Type
    )
    Set-GPRegistryValue -Guid $GpoId -Domain $Domain -Server $Server `
        -Key $Key -ValueName $Name -Value $Value -Type $Type | Out-Null
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop

    $system = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($system.DomainRole -lt 4) {
        throw 'This script must run directly on an authorized domain controller, not a workstation.'
    }

    $domain = Get-ADDomain
    if ($domain.DNSRoot -ine $expectedDomain) {
        throw "Wrong domain: $($domain.DNSRoot). Expected $expectedDomain."
    }
    $server = $domain.PDCEmulator
    $domainDn = $domain.DistinguishedName
    $adminSid = "{0}-512" -f $domain.DomainSID.Value
    Write-Host "[*] Domain confirmed: $expectedDomain" -ForegroundColor Cyan

    # Re-running the script is safe: use the named GPO rather than duplicating it.
    $gpo = Get-GPO -All -Domain $expectedDomain -Server $server |
        Where-Object { $_.DisplayName -eq $policyName } |
        Select-Object -First 1

    if ($null -eq $gpo) {
        $gpo = New-GPO -Name $policyName -Domain $expectedDomain -Server $server
        Write-Host "[*] Creating GPO: '$policyName'... CREATED" -ForegroundColor Green
    } else {
        $backupDir = Join-Path $env:ProgramData ('MedDefense\GPO-Backups\' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
        Backup-GPO -Guid $gpo.Id -Domain $expectedDomain -Server $server -Path $backupDir | Out-Null
        Write-Host "[*] GPO exists; backup saved to: $backupDir" -ForegroundColor Yellow
    }

    $gpoGuid = '{' + $gpo.Id.ToString().ToUpperInvariant() + '}'
    # Use one DC consistently for SYSVOL and GPO administration.
    $policyDir = "\\$server\SYSVOL\$expectedDomain\Policies\$gpoGuid"
    $auditCsvPath = Join-Path $policyDir 'Machine\Microsoft\Windows NT\Audit\audit.csv'
    $securityTemplatePath = Join-Path $policyDir 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
    if (-not (Test-Path -LiteralPath $policyDir)) { throw "GPO SYSVOL path unavailable: $policyDir" }

    Write-Host '[*] Configuring advanced audit subcategories...' -ForegroundColor Cyan
    Set-AuditCsv -Path $auditCsvPath -Settings $auditSettings
    foreach ($setting in $auditSettings) {
        $mode = if ($setting.Value -eq 3) { 'Success, Failure' } else { 'Success' }
        Write-Host ('    {0,-34} {1,-17} [SET]' -f $setting.Name, $mode)
    }

    # Restrict the user right as well as the channel ACL. Without the user right
    # change, a built-in administrator may still manage the Security log.
    Set-SecurityLogRight -Path $securityTemplatePath -DomainAdminSid $adminSid
    $logSddl = "O:BAG:SYD:(A;;0xF0007;;;SY)(A;;0x3;;;BA)(A;;0x7;;;$adminSid)(A;;0x1;;;S-1-5-32-573)"
    # Check SDDL syntax before placing the value into Group Policy.
    [void]([System.Security.AccessControl.CommonSecurityDescriptor]::new($false, $false, $logSddl))

    $gpoDn = "CN=$gpoGuid,CN=Policies,CN=System,$domainDn"
    # Register BOTH relevant client-side extensions. Just writing audit.csv and
    # GptTmpl.inf is not sufficient to have the client apply those files.
    Register-MachineExtension -GpoDn $gpoDn -Server $server `
        -CseGuid 'F3CCC681-B74C-4060-9F26-CD84525DCA2A' `
        -ToolGuid '0F3F3735-573D-9804-99E4-AB2A69BA5FD4'
    Register-MachineExtension -GpoDn $gpoDn -Server $server `
        -CseGuid '827D319E-6EAC-11D2-A4EA-00C04F79F83A' `
        -ToolGuid '803E14A0-B4FB-11D0-A0D0-00A0C90F574B'

    # Registry-backed GPO settings also increment its computer policy version,
    # prompting clients to process the new audit and security templates.
    $registrySettings = @(
        @{ Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name='ProcessCreationIncludeCmdLine_Enabled'; Value=1; Type='DWord' }
        @{ Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Name='SCENoApplyLegacyAuditPolicy'; Value=1; Type='DWord' }
        @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name='MaxSize'; Value=$securityLogSizeKB; Type='DWord' }
        @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name='ChannelAccess'; Value=$logSddl; Type='String' }
    )
    foreach ($item in $registrySettings) {
        Write-PolicyRegistryValue -GpoId $gpo.Id -Domain $expectedDomain -Server $server `
            -Key $item.Key -Name $item.Name -Value $item.Value -Type $item.Type
    }
    Write-Host '[*] Process creation command-line logging... [SET]'
    Write-Host '[*] Security log clearing rights: Domain Admins (+SYSTEM)... [SET]'
    Write-Host '[*] Security log maximum: 1 GiB... [SET]'

    $links = @( (Get-GPInheritance -Target $domainDn -Domain $expectedDomain -Server $server).GpoLinks )
    if (@($links | Where-Object { [string]$_.GpoId -eq [string]$gpo.Id }).Count -eq 0) {
        New-GPLink -Guid $gpo.Id -Domain $expectedDomain -Server $server `
            -Target $domainDn -LinkEnabled Yes | Out-Null
        Write-Host '[*] Domain-root GPO link... LINKED' -ForegroundColor Green
    } else {
        Write-Host '[*] Domain-root GPO link... ALREADY PRESENT' -ForegroundColor Green
    }

    Write-Host '[*] Applying Computer Group Policy on this DC...' -ForegroundColor Cyan
    $gpMessage = & gpupdate.exe '/target:computer' '/force' '/wait:60' 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ('gpupdate failed: ' + ($gpMessage -join ' '))
    }
    Write-Host '[*] Group Policy update... COMPLETE' -ForegroundColor Green

    Write-Host "`n[*] Effective audit policy (auditpol /get /category:*):" -ForegroundColor Cyan
    $auditOutput = & auditpol.exe '/get' '/category:*' 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('auditpol failed: ' + ($auditOutput -join ' ')) }
    $auditOutput | ForEach-Object { Write-Host $_ }

    # Verify by GUID, independently of translated Windows audit subcategory names.
    $rawCsv = & auditpol.exe '/get' '/category:*' '/r' 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('auditpol CSV verification failed: ' + ($rawCsv -join ' ')) }
    $records = @($rawCsv | ConvertFrom-Csv)
    $mismatches = New-Object 'System.Collections.Generic.List[string]'
    foreach ($setting in $auditSettings) {
        $target = '{' + $setting.Guid + '}'
        $record = @($records | Where-Object { $_.'Subcategory GUID' -ieq $target } | Select-Object -First 1)
        if ($record.Count -eq 0) {
            [void]$mismatches.Add("$($setting.Name): not returned by auditpol")
            continue
        }
        $actual = [string]$record[0].'Inclusion Setting'
        $expected = if ($setting.Value -eq 3) { 'Success and Failure' } else { 'Success' }
        if ($actual -ne $expected) {
            [void]$mismatches.Add("$($setting.Name): expected $expected; received $actual")
        }
    }

    $cmdLineValue = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
        -Name 'ProcessCreationIncludeCmdLine_Enabled').ProcessCreationIncludeCmdLine_Enabled
    if ($cmdLineValue -ne 1) { [void]$mismatches.Add('Process creation command-line logging not effective on DC01') }

    $logPolicy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' `
        -Name 'ChannelAccess', 'MaxSize'
    if ([string]$logPolicy.ChannelAccess -ne $logSddl) {
        [void]$mismatches.Add('Security log channel permissions not applied on DC01')
    }
    if ([long]$logPolicy.MaxSize -ne $securityLogSizeKB) {
        [void]$mismatches.Add('Security log size GPO is not effective on DC01')
    }

    $sizeOutput = & wevtutil.exe 'gl' 'Security' 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('wevtutil failed: ' + ($sizeOutput -join ' ')) }
    $sizeLine = @($sizeOutput | Where-Object { $_ -match '^\s*maxSize:\s*(\d+)' } | Select-Object -First 1)
    if ($sizeLine.Count -eq 0) {
        [void]$mismatches.Add('Unable to read the effective Security log maximum size')
    } elseif ([long](($sizeLine[0] -split ':',2)[1].Trim()) -ne $securityLogSizeBytes) {
        [void]$mismatches.Add('Security log maximum size is not 1 GiB on DC01')
    }

    if ($mismatches.Count -gt 0) {
        foreach ($issue in $mismatches) { Write-Warning "Verification: $issue" }
        throw "$($mismatches.Count) effective-setting check(s) failed. Check GP precedence, replication, and GP processing."
    }

    Write-Host "`n[+] Verified: all $($auditSettings.Count) audit subcategories, command-line logging and 1 GiB Security log size on this DC." -ForegroundColor Green
    Write-Host '[!] Security log rights also require checking effective user-right assignment and the channel ACL on each endpoint.' -ForegroundColor Yellow
    Write-Host '[!] File and registry access events also require appropriate object SACLs.' -ForegroundColor Yellow
    Write-Host '[!] Additional DCs/workstations apply the linked GPO on their own refresh cycles.' -ForegroundColor Yellow
}
catch {
    Write-Error "Advanced Audit Policy configuration failed: $($_.Exception.Message)"
    exit 1
}
