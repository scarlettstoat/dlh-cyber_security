#requires -Version 5.1
<#
.SYNOPSIS
Align local Windows inbound firewall rules with the Task 2 contract.
.DESCRIPTION
Run on the Windows lab host as Administrator. Measures local and effective
policy in JSON before changing profiles or replacing MedDefense-* rules.
Keeps named-host selectors and creates only rules terminating on local IPs.

Task 6 covers inbound allows and profile defaults. It does not translate the
Linux forward chain or the contract's outbound restrictions. Existing rules
outside MedDefense-* are preserved and reported; whole-firewall equivalence
and successful packet delivery are not inferred from rule installation.
.EXAMPLE
.\6-windows_firewall.ps1 -Preview -HostAddress 10.10.2.10
Render a labelled plan without needing Windows or changing a firewall.
.EXAMPLE
.\6-windows_firewall.ps1
Apply on Windows, verify the effective managed rules, and export JSON.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$PolicyPath = (Join-Path -Path $PSScriptRoot -ChildPath 'segmentation_rules.json'),
    [string]$OutputDirectory = $PSScriptRoot,
    [switch]$Preview,
    [string[]]$HostAddress
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-OptionalField {
    param([object]$InputObject, [string]$Name)
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) { $property.Value }
}

function ConvertTo-IPv4Number {
    param([string]$Address)
    $parsed = [System.Net.IPAddress]::Parse($Address)
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Only IPv4 addresses are supported by this contract: $Address"
    }
    $bytes = $parsed.GetAddressBytes()
    [uint64]$bytes[0] * 16777216 + [uint64]$bytes[1] * 65536 +
        [uint64]$bytes[2] * 256 + [uint64]$bytes[3]
}

function Get-CidrRange {
    param([string]$Cidr)
    $parts = $Cidr.Split('/')
    if ($parts.Count -ne 2 -or $parts[1] -notmatch '^\d{1,2}$') {
        throw "Expected an IPv4 CIDR: $Cidr"
    }
    $prefix = [int]$parts[1]
    if ($prefix -gt 32) { throw "Invalid prefix: $Cidr" }
    $number = ConvertTo-IPv4Number -Address $parts[0]
    $size = [uint64][math]::Pow(2, 32 - $prefix)
    $start = [uint64]([math]::Floor($number / $size) * $size)
    if ($number -ne $start) { throw "CIDR must use its network address: $Cidr" }
    [pscustomobject]@{ Start = $start; End = $start + $size - 1 }
}

function Test-AddressInCidr {
    param([string]$Address, [string]$Cidr)
    $number = ConvertTo-IPv4Number -Address $Address
    $range = Get-CidrRange -Cidr $Cidr
    $number -ge $range.Start -and $number -le $range.End
}

function Read-SegmentationPolicy {
    param([string]$Path)
    $policy = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $zoneNames = @('DMZ', 'INTERNAL', 'MGMT', 'MEDDEV')
    if (@($policy.zones).Count -ne 4 -or
        @(Compare-Object -ReferenceObject $zoneNames -DifferenceObject @($policy.zones.name)).Count) {
        throw 'Expected exactly DMZ, INTERNAL, MGMT and MEDDEV zones.'
    }
    $zones = @{}
    foreach ($zone in $policy.zones) {
        if ($zone.default_inbound -ne 'drop' -or $zone.default_outbound -ne 'accept') {
            throw 'Zone defaults must be inbound drop and outbound accept.'
        }
        $range = Get-CidrRange -Cidr $zone.cidr
        foreach ($existing in $zones.Values) {
            $other = Get-CidrRange -Cidr $existing.cidr
            if ($range.Start -le $other.End -and $other.Start -le $range.End) {
                throw 'Zone CIDRs must not overlap.'
            }
        }
        $zones[$zone.name] = $zone
    }
    $identifiers = @{}
    $terminalSeen = $false
    foreach ($flow in $policy.flows) {
        if ($flow.id -notmatch '^[A-Za-z][A-Za-z0-9_]*$' -or $identifiers.ContainsKey($flow.id)) {
            throw 'Every flow needs a unique, safe ID.'
        }
        $identifiers[$flow.id] = $true
        if ($flow.action -eq 'deny_all') {
            $terminalSeen = $true
            if ($flow.proto -ne 'all' -or $null -ne $flow.dport) {
                throw "$($flow.id): deny_all must cover all protocols and ports."
            }
        }
        elseif ($flow.action -eq 'allow') {
            if ($terminalSeen -or $flow.proto -notin @('tcp', 'udp') -or
                ($flow.dport -isnot [int] -and $flow.dport -isnot [long]) -or
                $flow.dport -lt 1 -or $flow.dport -gt 65535) {
                throw "$($flow.id): invalid port/protocol or allow after terminal deny."
            }
        }
        else { throw "$($flow.id): unsupported action." }
        foreach ($side in @('src', 'dst')) {
            $zoneName = [string](Get-OptionalField -InputObject $flow -Name ($side + '_zone'))
            $allowedNames = if ($side -eq 'src') { $zoneNames + 'ALL' } else { $zoneNames + 'INTERNET' }
            if ($zoneName -notin $allowedNames) { throw "Unknown zone: $zoneName" }
            $selectors = @(Get-OptionalField -InputObject $flow -Name ($side + '_cidrs'))
            if ($selectors.Count -eq 0) { throw "$($flow.id): missing address selectors." }
            foreach ($selector in $selectors) {
                $range = Get-CidrRange -Cidr $selector
                if ($zoneName -eq 'INTERNET') {
                    foreach ($zone in $policy.zones) {
                        $other = Get-CidrRange -Cidr $zone.cidr
                        if ($range.Start -le $other.End -and $other.Start -le $range.End) {
                            throw "$($flow.id): INTERNET selector overlaps a modelled zone."
                        }
                    }
                }
                else {
                    $bounds = if ($zoneName -eq 'ALL') { @($policy.zones.cidr) } else { @($zones[$zoneName].cidr) }
                    $contained = @($bounds | Where-Object {
                        $bound = Get-CidrRange -Cidr $_
                        $range.Start -ge $bound.Start -and $range.End -le $bound.End
                    }).Count -gt 0
                    if (-not $contained) { throw "$($flow.id): selector exceeds its zone." }
                }
            }
            $hostNames = @(Get-OptionalField -InputObject $flow -Name ($side + '_hosts'))
            if ($hostNames.Count) {
                if (-not $zones.ContainsKey($zoneName)) { throw 'Named hosts require one concrete zone.' }
                $expected = @(foreach ($hostName in $hostNames) {
                    $found = @($zones[$zoneName].hosts | Where-Object { $_.name -eq $hostName })
                    if ($found.Count -ne 1) { throw "Unknown/duplicate named host: $hostName" }
                    if (-not (Test-AddressInCidr -Address $found[0].address -Cidr $zones[$zoneName].cidr)) {
                        throw "Named host is outside its zone: $hostName"
                    }
                    $found[0].address + '/32'
                })
                if (@(Compare-Object -ReferenceObject @($expected | Sort-Object -Unique) `
                            -DifferenceObject @($selectors | Sort-Object -Unique)).Count) {
                    throw "$($flow.id): selectors must match its named hosts exactly."
                }
            }
        }
    }
    $policy
}

function Get-InboundPlan {
    param([object]$Policy, [string[]]$Addresses)
    foreach ($address in $Addresses) {
        if (-not @($Policy.zones | Where-Object { Test-AddressInCidr -Address $address -Cidr $_.cidr }).Count) {
            throw "Host address $address is outside the four planned zones; no firewall changes made."
        }
    }
    foreach ($flow in $Policy.flows) {
        if ($flow.action -ne 'allow') { continue }
        $local = @($Addresses | Where-Object {
            $address = $_
            @($flow.dst_cidrs | Where-Object { Test-AddressInCidr -Address $address -Cidr $_ }).Count -gt 0
        } | Sort-Object -Unique | ForEach-Object { $_ + '/32' })
        if ($local.Count -eq 0) { continue }
        [pscustomobject][ordered]@{
            name = 'MedDefense-' + $flow.id
            display_name = "MedDefense-$($flow.src_zone)-$($flow.proto.ToUpperInvariant())-$($flow.dport)"
            flow_id = $flow.id
            src_zone = $flow.src_zone
            dst_zone = $flow.dst_zone
            proto = $flow.proto.ToLowerInvariant()
            dport = [int]$flow.dport
            local_address = $local
            remote_address = @($flow.src_cidrs | Sort-Object -Unique)
            direction = 'Inbound'
            action = 'Allow'
            profile = 'Any'
            justification = $flow.justification
            exception_for = Get-OptionalField -InputObject $flow -Name 'exception_for'
        }
    }
}

function Write-JsonEvidence {
    param([string]$Path, [object]$Value)
    $temporary = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $json = ConvertTo-Json -InputObject $Value -Depth 20
        [System.IO.File]::WriteAllText($temporary, $json + "`n", [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $Path -Force -WhatIf:$false
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -WhatIf:$false }
    }
}

function Test-WindowsHost {
    [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

function Test-Administrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-HostFirewallAddress {
    $connected = @(Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected |
        Select-Object -ExpandProperty InterfaceIndex)
    @(Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred | Where-Object {
        $_.InterfaceIndex -in $connected -and $_.IPAddress -notmatch '^(127\.|169\.254\.)'
    } | Select-Object -ExpandProperty IPAddress -Unique)
}

function ConvertTo-AddressSelector {
    param([string[]]$Addresses)
    @($Addresses | ForEach-Object {
        $parsed = $null
        if ([System.Net.IPAddress]::TryParse($_, [ref]$parsed) -and
            $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            $parsed.ToString() + '/32'
        }
        else { $_.ToLowerInvariant() }
    } | Sort-Object -Unique)
}

function Get-FirewallSnapshot {
    param([string]$Store)
    $profiles = @(Get-NetFirewallProfile -PolicyStore $Store | ForEach-Object {
        [pscustomobject]@{
            name = [string]$_.Name; enabled = [string]$_.Enabled
            default_inbound = [string]$_.DefaultInboundAction
            default_outbound = [string]$_.DefaultOutboundAction
            log_blocked = [string]$_.LogBlocked; log_file = [string]$_.LogFileName
            allow_local_rules = [string]$_.AllowLocalFirewallRules
            allow_inbound_rules = [string]$_.AllowInboundRules
        }
    })
    $allRules = @(Get-NetFirewallRule -PolicyStore $Store)
    $managed = @($allRules | Where-Object { $_.DisplayName -like 'MedDefense-*' } | ForEach-Object {
        $rule = $_
        $address = $rule | Get-NetFirewallAddressFilter
        $port = $rule | Get-NetFirewallPortFilter
        $protocol = switch ([string]$port.Protocol) {
            '6' { 'tcp' }; '17' { 'udp' }; default { ([string]$port.Protocol).ToLowerInvariant() }
        }
        [pscustomobject]@{
            name = [string]$rule.Name; display_name = [string]$rule.DisplayName
            direction = [string]$rule.Direction; action = [string]$rule.Action
            enabled = [string]$rule.Enabled; profile = [string]$rule.Profile
            proto = $protocol; local_port = @($port.LocalPort); remote_port = @($port.RemotePort)
            local_address = @(ConvertTo-AddressSelector -Addresses $address.LocalAddress)
            remote_address = @(ConvertTo-AddressSelector -Addresses $address.RemoteAddress)
            description = [string]$rule.Description
            policy_store_source = [string]$rule.PolicyStoreSource
            policy_store_source_type = [string]$rule.PolicyStoreSourceType
        }
    } | Sort-Object -Property name)
    $otherInbound = @($allRules | Where-Object {
        $_.DisplayName -notlike 'MedDefense-*' -and [string]$_.Enabled -eq 'True' -and
        [string]$_.Direction -eq 'Inbound'
    } | Select-Object -Property Name, DisplayName, Action, Profile, PolicyStoreSource, PolicyStoreSourceType)
    [pscustomobject]@{
        captured_at = [datetime]::UtcNow.ToString('o'); policy_store = $Store
        profiles = $profiles; rules = $managed; total_rule_count = $allRules.Count
        other_enabled_inbound_rules = $otherInbound
    }
}

function Test-ProfileAlignment {
    param([object]$FirewallProfile)
    $path = [System.Environment]::ExpandEnvironmentVariables($FirewallProfile.log_file)
    $expected = [System.Environment]::ExpandEnvironmentVariables('%systemroot%\system32\LogFiles\Firewall\meddefense.log')
    $FirewallProfile.enabled -eq 'True' -and $FirewallProfile.default_inbound -eq 'Block' -and
        $FirewallProfile.default_outbound -eq 'Allow' -and $FirewallProfile.log_blocked -eq 'True' -and $path -eq $expected
}

function Test-ManagedRuleAlignment {
    param([object[]]$Plan, [object]$EffectiveState)
    $issues = @()
    if ($EffectiveState.rules.Count -ne $Plan.Count) { $issues += 'Effective managed rule count differs from plan.' }
    foreach ($expected in $Plan) {
        $found = @($EffectiveState.rules | Where-Object { $_.name -eq $expected.name })
        if ($found.Count -ne 1) { $issues += "Missing/duplicate effective rule: $($expected.name)"; continue }
        $actual = $found[0]
        if ($actual.display_name -ne $expected.display_name -or $actual.proto -ne $expected.proto -or
            $actual.direction -ne 'Inbound' -or $actual.action -ne 'Allow' -or
            $actual.enabled -ne 'True' -or $actual.profile -ne 'Any') {
            $issues += "Wrong effective rule properties: $($expected.name)"
        }
        foreach ($field in @('local_address', 'remote_address', 'local_port', 'remote_port')) {
            $wanted = switch ($field) {
                'local_port' { [string]$expected.dport }
                'remote_port' { 'Any' }
                default { $expected.$field }
            }
            if (@(Compare-Object -ReferenceObject @($wanted) -DifferenceObject @($actual.$field)).Count) {
                $issues += "Wrong $field filter: $($expected.name)"
            }
        }
    }
    foreach ($name in @('Domain', 'Private', 'Public')) {
        $found = @($EffectiveState.profiles | Where-Object { $_.name -eq $name })
        if ($found.Count -ne 1 -or -not (Test-ProfileAlignment -FirewallProfile $found[0])) {
            $issues += "Effective profile defaults/logging do not match: $name"
        }
        elseif ($found[0].allow_local_rules -eq 'False' -or $found[0].allow_inbound_rules -eq 'False') {
            $issues += "Effective profile suppresses local inbound allow rules: $name"
        }
    }
    [pscustomobject]@{ passed = ($issues.Count -eq 0); issues = $issues; actual_rule_count = $EffectiveState.rules.Count }
}

function Invoke-FirewallBackup {
    param([ValidateSet('export', 'import')][string]$Operation, [string]$Path)
    $netsh = Join-Path -Path $env:SystemRoot -ChildPath 'System32\netsh.exe'
    $messages = & $netsh advfirewall $Operation $Path 2>&1
    if ($LASTEXITCODE -ne 0) { throw "netsh $Operation failed: $($messages -join ' ')" }
    if ($Operation -eq 'export' -and -not (Test-Path -LiteralPath $Path)) {
        throw 'The firewall backup file was not created.'
    }
}

function Invoke-MedDefenseFirewall {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$PolicyPath, [string]$OutputDirectory, [switch]$Preview, [string[]]$HostAddress)

    $dryRun = $Preview -or $WhatIfPreference
    $reportName = if ($dryRun) { 'windows_firewall_plan.json' } else { 'windows_firewall_rules.json' }
    $reportPath = Join-Path -Path $OutputDirectory -ChildPath $reportName
    $report = [ordered]@{
        generated_at = [datetime]::UtcNow.ToString('o'); hostname = [System.Net.Dns]::GetHostName()
        status = 'started'; applied = $false; preview = [bool]$dryRun
        policy_path = [System.IO.Path]::GetFullPath($PolicyPath)
        scope = 'Local host inbound allows and all three profile defaults (Task 6)'
        coverage = [ordered]@{
            forwarding = $false; outbound_restrictions = $false
            whole_firewall_equivalence_asserted = $false; connection_tests_performed = $false
            other_rules = 'Preserved; effective unmanaged inbound rules are included in the snapshots'
        }
    }
    $changed = $false
    $mutex = $null
    $locked = $false
    $backupPath = $null
    try {
        if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) { throw 'Output directory must exist.' }
        Write-Information -MessageData '[*] Reading segmentation_rules.json...' -InformationAction Continue
        $policy = Read-SegmentationPolicy -Path $PolicyPath
        $report.policy_sha256 = (Get-FileHash -LiteralPath $PolicyPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($HostAddress -and -not $dryRun) { throw '-HostAddress is for previews only; apply discovers real local addresses.' }
        if ($HostAddress) { $addresses = @($HostAddress | Sort-Object -Unique) }
        else {
            if (-not (Test-WindowsHost)) { throw 'Apply/discovery needs Windows. For a plan use -Preview -HostAddress <planned-IPv4>.' }
            Import-Module -Name NetSecurity -ErrorAction Stop
            $addresses = @(Get-HostFirewallAddress)
        }
        if ($addresses.Count -eq 0) { throw 'No connected, preferred IPv4 address was found.' }
        $report.host_addresses = $addresses
        $report.address_source = if ($HostAddress) { 'Explicit preview input' } else { 'Discovered Windows interfaces' }
        $plan = @(Get-InboundPlan -Policy $policy -Addresses $addresses)
        $report.plan = $plan
        $report.summary = [ordered]@{
            planned_inbound_allow_count = $plan.Count
            deny_all_handling = 'DefaultInboundAction Block; no conflicting blanket inbound block rules'
            outbound_restriction_flow_ids = @($policy.flows | Where-Object { $_.action -eq 'deny_all' } | ForEach-Object { $_.id })
        }
        if ($dryRun) {
            $report.status = 'planned'
            Write-JsonEvidence -Path $reportPath -Value $report
            Write-Information -MessageData "Planned $($plan.Count) host-specific inbound rule(s). No firewall changes made. Saved $reportName" -InformationAction Continue
            return
        }
        if (-not (Test-WindowsHost) -or -not (Test-Administrator)) { throw 'Run this script in Windows PowerShell as Administrator.' }
        Import-Module -Name NetSecurity -ErrorAction Stop
        $mutex = [System.Threading.Mutex]::new($false, 'Global\MedDefenseFirewallAlignment')
        try { $locked = $mutex.WaitOne(0) }
        catch [System.Threading.AbandonedMutexException] { $locked = $true }
        if (-not $locked) { throw 'Another MedDefense firewall update is running.' }
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem
        $report.domain_joined = [bool]$computer.PartOfDomain
        $report.domain = [string]$computer.Domain
        $report.pre_state = [ordered]@{
            persistent = Get-FirewallSnapshot -Store PersistentStore
            effective = Get-FirewallSnapshot -Store ActiveStore
        }
        $report.status = 'measured'
        Write-JsonEvidence -Path $reportPath -Value $report
        foreach ($profileState in $report.pre_state.effective.profiles) {
            if ($profileState.allow_local_rules -eq 'False' -or $profileState.allow_inbound_rules -eq 'False') {
                throw "Effective $($profileState.name) policy suppresses local inbound rules; resolve the domain policy first."
            }
        }
        if (-not $PSCmdlet.ShouldProcess('Local Windows Firewall', 'Replace MedDefense-* inbound rules and align all profiles')) {
            $report.status = 'not_applied'
            Write-JsonEvidence -Path $reportPath -Value $report
            return
        }
        $backupDirectory = Join-Path -Path $env:ProgramData -ChildPath 'MedDefense\FirewallBackups'
        $null = New-Item -ItemType Directory -Path $backupDirectory -Force
        $backupPath = Join-Path -Path $backupDirectory -ChildPath ('firewall-' + [datetime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') + '.wfw')
        Invoke-FirewallBackup -Operation export -Path $backupPath
        $report.rollback = [ordered]@{
            backup = $backupPath
            command = 'netsh advfirewall import "' + $backupPath + '"'
            restores = 'The exported local firewall configuration; domain GPO policy remains authoritative'
        }
        Write-JsonEvidence -Path $reportPath -Value $report
        Write-Information -MessageData '[*] Setting profile defaults...' -InformationAction Continue
        $changed = $true
        foreach ($name in @('Domain', 'Private', 'Public')) {
            $current = @($report.pre_state.persistent.profiles | Where-Object { $_.name -eq $name })
            if ($current.Count -ne 1) { throw "Missing local profile: $name" }
            if (-not (Test-ProfileAlignment -FirewallProfile $current[0])) {
                Set-NetFirewallProfile -Name $name -PolicyStore PersistentStore -Enabled True `
                    -DefaultInboundAction Block -DefaultOutboundAction Allow -LogBlocked True `
                    -LogFileName '%systemroot%\system32\LogFiles\Firewall\meddefense.log'
            }
            Write-Information -MessageData "  ${name}: DefaultInboundAction=Block DefaultOutboundAction=Allow LogBlocked=True [SET]" -InformationAction Continue
        }
        $previous = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.DisplayName -like 'MedDefense-*' })
        foreach ($rule in $previous) { Remove-NetFirewallRule -Name $rule.Name -PolicyStore PersistentStore }
        Write-Information -MessageData "[*] Clearing previous MedDefense-* rules... [$($previous.Count) removed]" -InformationAction Continue
        foreach ($rule in $plan) {
            $arguments = @{
                Name = $rule.name; DisplayName = $rule.display_name; Group = 'MedDefense'
                Description = "$($rule.flow_id): $($rule.justification)"
                Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any'
                Protocol = $rule.proto.ToUpperInvariant(); LocalPort = $rule.dport
                LocalAddress = $rule.local_address; RemoteAddress = $rule.remote_address
                PolicyStore = 'PersistentStore'; ErrorAction = 'Stop'
            }
            $null = New-NetFirewallRule @arguments
            Write-Information -MessageData "  $($rule.display_name) Inbound Allow $($rule.proto) $($rule.dport) [CREATED]" -InformationAction Continue
        }
        $report.post_state = [ordered]@{
            persistent = Get-FirewallSnapshot -Store PersistentStore
            effective = Get-FirewallSnapshot -Store ActiveStore
        }
        $report.verification = Test-ManagedRuleAlignment -Plan $plan -EffectiveState $report.post_state.effective
        if (-not $report.verification.passed) { throw ($report.verification.issues -join '; ') }
        $report.rules = $report.post_state.effective.rules
        $report.profiles = $report.post_state.effective.profiles
        $report.summary.other_enabled_inbound_rule_count = $report.post_state.effective.other_enabled_inbound_rules.Count
        $report.status = 'applied'
        $report.applied = $true
        Write-JsonEvidence -Path $reportPath -Value $report
        Write-Information -MessageData "Verified $($plan.Count) managed inbound rule(s). Saved $reportName" -InformationAction Continue
    }
    catch {
        $report.status = 'failed'
        $report.applied = $false
        $report.error = $_.Exception.Message
        if ($changed -and $backupPath) {
            try {
                Invoke-FirewallBackup -Operation import -Path $backupPath
                $report.status = 'rolled_back'
            }
            catch { $report.status = 'rollback_failed'; $report.rollback_error = $_.Exception.Message }
        }
        if (Test-Path -LiteralPath $OutputDirectory -PathType Container) { Write-JsonEvidence -Path $reportPath -Value $report }
        throw
    }
    finally {
        if ($locked) { $mutex.ReleaseMutex() }
        if ($null -ne $mutex) { $mutex.Dispose() }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-MedDefenseFirewall -PolicyPath $PolicyPath -OutputDirectory $OutputDirectory `
        -Preview:$Preview -HostAddress $HostAddress -WhatIf:$WhatIfPreference
}

