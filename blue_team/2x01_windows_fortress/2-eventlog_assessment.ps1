<#
.SYNOPSIS
    2-eventlog_assessment.ps1 - Windows Security Event Log assessment.
.PURPOSE
    Read DC01's effective audit policy and check whether nine critical Security
    Event IDs were recorded in the past 24 hours. Reports missing audit
    coverage separately from events that simply have not occurred.
.AUTHOR
    MedDefense Security Analyst
.DATE
    2026-10-19
.NOTES
    Read-only: does not enable auditing, clear logs, or modify domain policy.
    Run in an elevated Windows PowerShell session on DC01.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 168)]
    [int]$Hours = 24,

    [string]$ReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Microsoft audit subcategory GUIDs are stable across Windows display languages.
# RequiredBit: 1 = audit successes; 2 = audit failures.
# Event 1102 is an automatic Windows Event Log service event: it does not depend
# on enabling a Security audit subcategory.
$eventChecks = @(
    [pscustomobject]@{ Id = 4624; Description = 'Successful Logon';      Subcategory = 'Logon';                     Guid = '0cce9215-69ae-11d9-bed3-505054503030'; RequiredBit = 1 }
    [pscustomobject]@{ Id = 4625; Description = 'Failed Logon';          Subcategory = 'Logon';                     Guid = '0cce9215-69ae-11d9-bed3-505054503030'; RequiredBit = 2 }
    [pscustomobject]@{ Id = 4648; Description = 'Explicit Credentials';  Subcategory = 'Logon';                     Guid = '0cce9215-69ae-11d9-bed3-505054503030'; RequiredBit = 1 }
    [pscustomobject]@{ Id = 4688; Description = 'Process Creation';      Subcategory = 'Process Creation';          Guid = '0cce922b-69ae-11d9-bed3-505054503030'; RequiredBit = 1 }
    [pscustomobject]@{ Id = 4720; Description = 'Account Created';       Subcategory = 'User Account Management';   Guid = '0cce9235-69ae-11d9-bed3-505054503030'; RequiredBit = 1 }
    [pscustomobject]@{ Id = 4726; Description = 'Account Deleted';       Subcategory = 'User Account Management';   Guid = '0cce9235-69ae-11d9-bed3-505054503030'; RequiredBit = 1 }
    [pscustomobject]@{ Id = 4732; Description = 'Member Added to Group'; Subcategory = 'Security Group Management'; Guid = '0cce9237-69ae-11d9-bed3-505054503030'; RequiredBit = 1 }
    [pscustomobject]@{ Id = 4672; Description = 'Special Logon';         Subcategory = 'Special Logon';             Guid = '0cce921b-69ae-11d9-bed3-505054503030'; RequiredBit = 1 }
    [pscustomobject]@{ Id = 1102; Description = 'Audit Log Cleared';     Subcategory = 'Automatic (Other Events)'; Guid = $null; RequiredBit = 0 }
)

function Get-AuditModeLabel {
    param([int]$Value)
    switch ($Value -band 3) {
        0 { return 'No Auditing' }
        1 { return 'Success' }
        2 { return 'Failure' }
        3 { return 'Success and Failure' }
    }
}

function Test-RecentSecurityEvent {
    param(
        [Parameter(Mandatory = $true)][int]$EventId,
        [Parameter(Mandatory = $true)][datetime]$Since
    )

    try {
        # One record is enough to establish that an Event ID was generated.
        # Avoid loading all logon records from a busy domain controller.
        $eventRecord = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = $EventId
            StartTime = $Since
        } -MaxEvents 1 -ErrorAction Stop

        return [pscustomobject]@{
            Present  = $true
            LastSeen = $eventRecord.TimeCreated
        }
    }
    catch {
        # A genuinely empty result is not a query failure. Other failures,
        # including access denied, must not be reported as 'no events'.
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            return [pscustomobject]@{
                Present  = $false
                LastSeen = $null
            }
        }
        throw
    }
}

$backupPath = Join-Path -Path $env:TEMP -ChildPath (
    'meddefense_auditpolicy_{0}.csv' -f [guid]::NewGuid().ToString('N')
)

try {
    $since = (Get-Date).AddHours(-$Hours)
    Write-Host ('Windows Event Log Assessment | {0} | Previous {1} hours' -f $env:COMPUTERNAME, $Hours)
    Write-Host 'Reading effective audit policy (no settings will be changed)...'

    # Required task command: obtain the complete, human-readable policy.
    $auditPolicyText = @(& auditpol.exe /get '/category:*' 2>&1 | ForEach-Object { $_.ToString() })
    if ($LASTEXITCODE -ne 0) {
        throw 'auditpol /get /category:* failed. Run PowerShell as administrator on DC01.'
    }

    # /backup produces stable numeric Setting Value fields (0-3) and GUIDs.
    # Unlike localized English-language strings, these can be checked reliably.
    $null = & auditpol.exe /backup "/file:$backupPath" 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $backupPath)) {
        throw 'Could not obtain the machine-readable audit policy snapshot.'
    }

    $csvLines = @(Get-Content -LiteralPath $backupPath)
    if ($csvLines.Count -lt 2) {
        throw 'The audit policy snapshot did not contain any subcategory data.'
    }

    # auditpol /backup exports columns in a stable order. The headers can be
    # localized, so skip that line and supply our own names.
    $columnNames = @('Computer', 'Target', 'Subcategory', 'Guid', 'Inclusion', 'Exclusion', 'Value')
    $csvRows = @($csvLines | Select-Object -Skip 1 | ConvertFrom-Csv -Header $columnNames)
    $policyByGuid = @{}

    foreach ($row in $csvRows) {
        if ($row.Target -ne 'System') { continue }
        $guid = ([string]$row.Guid).Trim().Trim([char[]]'{}').ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($guid)) { continue }

        $policyByGuid[$guid] = [pscustomobject]@{
            Subcategory   = [string]$row.Subcategory
            SettingValue  = [int]$row.Value
            SettingLabel  = Get-AuditModeLabel -Value ([int]$row.Value)
        }
    }

    if ($policyByGuid.Count -eq 0) {
        throw 'No system audit subcategories could be read from the audit policy snapshot.'
    }

    # Make sure Security log access works before interpreting individual IDs.
    $securityLog = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
    if (-not $securityLog.IsEnabled) {
        throw 'The Security event log is disabled. Cannot assess event generation.'
    }

    Write-Host 'Checking the Security log for each required Event ID...'
    $results = @(
        foreach ($check in $eventChecks) {
            $recent = Test-RecentSecurityEvent -EventId $check.Id -Since $since
            $automatic = ($check.RequiredBit -eq 0)
            $policyEnabled = $null
            $auditSetting = 'Automatic'

            if (-not $automatic) {
                if (-not $policyByGuid.ContainsKey($check.Guid)) {
                    throw ('Required audit subcategory was absent: {0} ({1})' -f $check.Subcategory, $check.Guid)
                }
                $auditEntry = $policyByGuid[$check.Guid]
                $auditSetting = $auditEntry.SettingLabel
                $policyEnabled = (($auditEntry.SettingValue -band $check.RequiredBit) -ne 0)
            }

            if ($automatic) {
                $status = if ($recent.Present) { 'GENERATING - REVIEW' } else { 'NOT SEEN (NORMAL)' }
            }
            elseif (-not $policyEnabled) {
                $status = if ($recent.Present) { 'FOUND / POLICY OFF' } else { 'NOT CONFIGURED' }
            }
            elseif ($recent.Present) {
                $status = 'GENERATING'
            }
            else {
                $status = 'ENABLED / NO EVENTS'
            }

            [pscustomobject]@{
                EventId         = $check.Id
                Description     = $check.Description
                AuditSubcategory = $check.Subcategory
                AuditGuid       = $check.Guid
                AuditRequirement = if ($automatic) { 'Automatic' } elseif ($check.RequiredBit -eq 1) { 'Success' } else { 'Failure' }
                AuditSetting    = $auditSetting
                PolicyEnabled   = $policyEnabled
                SeenInWindow    = $recent.Present
                LastSeen        = if ($null -ne $recent.LastSeen) { $recent.LastSeen.ToString('o') } else { $null }
                VisibilityGap   = (-not $automatic -and -not $policyEnabled)
                Status          = $status
            }
        }
    )

    Write-Host ''
    Write-Host ('{0,-6} {1,-23} {2,-26} {3,-19} {4}' -f 'ID', 'Description', 'Audit Subcategory', 'Audit Setting', 'Status')
    Write-Host ('-' * 106)
    foreach ($result in $results) {
        Write-Host ('{0,-6} {1,-23} {2,-26} {3,-19} [{4}]' -f `
            $result.EventId, $result.Description, $result.AuditSubcategory, $result.AuditSetting, $result.Status)
    }

    $gaps = @($results | Where-Object { $_.VisibilityGap })
    $observed = @($results | Where-Object { $_.SeenInWindow })
    $enabledButNotObserved = @($results | Where-Object {
        $_.PolicyEnabled -eq $true -and -not $_.SeenInWindow
    })
    $logCleared = @($results | Where-Object { $_.EventId -eq 1102 -and $_.SeenInWindow }).Count -gt 0

    Write-Host ''
    Write-Host ('Observed Event IDs: {0}/{1}' -f $observed.Count, $results.Count)
    Write-Host ('Audit-policy gaps: {0}' -f $gaps.Count)
    Write-Host ('Enabled but not observed: {0}' -f $enabledButNotObserved.Count)
    if ($logCleared) {
        Write-Warning 'Event 1102 was recorded: investigate why the Security log was cleared.'
    }
    Write-Host 'Note: no event in 24 hours does not prove that auditing is disabled.'
    Write-Host 'Note: results describe this DC only, not every domain workstation.'

    $report = [pscustomobject]@{
        Hostname        = $env:COMPUTERNAME
        AssessedAtUtc   = (Get-Date).ToUniversalTime().ToString('o')
        WindowStartUtc  = $since.ToUniversalTime().ToString('o')
        WindowHours     = $Hours
        SecurityLog     = [pscustomobject]@{
            IsEnabled          = $securityLog.IsEnabled
            RecordCount        = $securityLog.RecordCount
            MaximumSizeInBytes = $securityLog.MaximumSizeInBytes
            LogMode            = [string]$securityLog.LogMode
        }
        AuditpolOutput  = $auditPolicyText
        AuditPolicy     = @($policyByGuid.GetEnumerator() | Sort-Object Key | ForEach-Object {
            [pscustomobject]@{
                Guid     = $_.Key
                Name     = $_.Value.Subcategory
                Setting  = $_.Value.SettingLabel
                Value    = $_.Value.SettingValue
            }
        })
        Events          = $results
        Summary         = [pscustomobject]@{
            CheckedIds                = $results.Count
            ObservedIds               = $observed.Count
            PolicyGaps                = $gaps.Count
            EnabledButUnobservedIds   = $enabledButNotObserved.Count
            SecurityLogCleared        = $logCleared
        }
    }

    if ([string]::IsNullOrWhiteSpace($ReportPath)) {
        $ReportPath = Join-Path -Path $env:TEMP -ChildPath (
            'MedDefense_EventLog_Assessment_{0}.json' -f (Get-Date -Format 'yyyyMMdd_HHmmss')
        )
    }
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReportPath)
    $directory = Split-Path -Path $fullPath -Parent
    if (-not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $fullPath -Encoding UTF8
    Write-Host ('JSON report: {0}' -f $fullPath)
}
catch {
    Write-Host ('Event log assessment failed: {0}' -f $_.Exception.Message) -ForegroundColor Red
    exit 1
}
finally {
    if (Test-Path -LiteralPath $backupPath) {
        Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
    }
}
