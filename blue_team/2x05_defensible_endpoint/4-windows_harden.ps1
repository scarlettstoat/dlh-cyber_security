# Exit codes: 0 success, 1 hardening or audit failure, 2 environment or input error.
param(
    [string]$AuditHelper = '/home/analyst/MedDefense_Lab/capstone/win_audit.ps1',
    [string]$SysmonConfig = (Join-Path $PSScriptRoot '../2x01_windows_fortress/sysmonconfig.xml'),
    [string]$Step,
    [string]$WorkDirectory
)

$ErrorActionPreference = 'Stop'

function Write-TaskError {
    param([int]$Code, [string]$Message)
    [Console]::Error.WriteLine($Message)
    exit $Code
}

if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) {
    Write-TaskError 2 'Use 64-bit Windows PowerShell on hawthorne-adm-01.'
}
$computer = (([Net.Dns]::GetHostName() -split '\.')[0]).ToLowerInvariant()
$labNames = @('hawthorne-adm-01', 'hawthorne-adm-0')
if ($computer -notin $labNames) {
    Write-TaskError 2 "Expected hawthorne-adm-01. Current host: $computer"
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-TaskError 2 'Open Windows PowerShell as Administrator.'
}

function Invoke-ExternalTool {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Executable exited with code $LASTEXITCODE."
    }
}

function Register-StepChange {
    param([string]$Id)
    $script:StepChanged = $true
    if ($Id) { $script:StepControls.Add($Id) }
}

function Write-LocalDword {
    param([string]$Path, [string]$Name, [int]$Value, [string]$Id)
    if (-not (Test-Path -LiteralPath $Path)) {
        $null = New-Item -Path $Path -Force
        Register-StepChange $Id
    }
    $key = Get-Item -LiteralPath $Path
    if ($key.GetValue($Name) -eq $Value -and $key.GetValueKind($Name) -eq 'DWord') {
        return
    }
    $null = New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force
    Register-StepChange $Id
}

function Get-AccountGap {
    param([System.Collections.IDictionary]$Policy)
    $currentPath = Join-Path $WorkDirectory 'account-current.inf'
    Invoke-ExternalTool 'secedit.exe' @('/export', '/cfg', $currentPath, '/areas', 'SECURITYPOLICY', '/quiet') | Out-Null
    $current = Get-Content -LiteralPath $currentPath -Raw
    foreach ($name in $Policy.Keys) {
        if ($current -notmatch "(?m)^\s*$name\s*=\s*$($Policy[$name])\s*$") {
            $name
        }
    }
}

function Get-AuditSetting {
    $rows = Invoke-ExternalTool 'auditpol.exe' @('/get', '/category:*', '/r') | ConvertFrom-Csv
    $settings = @{}
    foreach ($row in $rows) {
        $guid = ([string]$row.'Subcategory GUID').Trim('{}')
        if ($guid) { $settings[$guid] = [string]$row.'Inclusion Setting' }
    }
    if ($settings.Count -eq 0) { throw 'Could not read audit subcategories.' }
    return $settings
}

function Get-FirewallGap {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if ($profiles.Count -ne 3) { throw 'Expected all three Windows Firewall profiles.' }
    $profiles | Where-Object {
        $_.Enabled -ne 'True' -or $_.DefaultInboundAction -ne 'Block' -or $_.LogBlocked -ne 'True'
    }
}

$actions = [ordered]@{
    account_policy = {
        $policy = [ordered]@{
            MinimumPasswordLength = 14; PasswordComplexity = 1; PasswordHistorySize = 24
            MaximumPasswordAge = 0; MinimumPasswordAge = 1; LockoutBadCount = 5
            LockoutDuration = 15; ResetLockoutCount = 15
        }
        if (@(Get-AccountGap $policy).Count -gt 0) {
            $template = Join-Path $WorkDirectory 'account-policy.inf'
            $database = Join-Path $WorkDirectory 'account-policy.sdb'
            $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"',
                       'Revision=1', '[System Access]')
            $lines += @($policy.Keys | ForEach-Object { "$_ = $($policy[$_])" })
            [IO.File]::WriteAllLines($template, [string[]]$lines, [Text.Encoding]::Unicode)
            Invoke-ExternalTool 'secedit.exe' @('/configure', '/db', $database, '/cfg', $template,
                '/areas', 'SECURITYPOLICY', '/quiet')
            Register-StepChange
            if (@(Get-AccountGap $policy).Count -gt 0) {
                throw 'The effective local account policy does not match the template.'
            }
        }
        Write-Output 'Local password and lockout policy verified.'
    }
    audit_policy = {
        # MedDefense workstation subcategories and required success/failure bits.
        $policy = [ordered]@{
            '0CCE923F' = 3; '0CCE9215' = 3; '0CCE9216' = 1; '0CCE921B' = 1
            '0CCE9235' = 3; '0CCE9228' = 3; '0CCE921D' = 3; '0CCE921E' = 3
            '0CCE922B' = 1
        }
        $current = Get-AuditSetting
        $bits = @{ 'Success' = 1; 'Failure' = 2; 'Success and Failure' = 3 }
        foreach ($prefix in $policy.Keys) {
            $id = "$prefix-69AE-11D9-BED3-505054503030"
            $actual = [int]$bits[[string]$current[$id]]
            if (($actual -band $policy[$prefix]) -eq $policy[$prefix]) { continue }
            $arguments = @('/set', "/subcategory:{$id}", '/success:enable')
            if ($policy[$prefix] -eq 3) { $arguments += '/failure:enable' }
            Invoke-ExternalTool 'auditpol.exe' $arguments
            Register-StepChange 'WIN-AUD-01'
        }
        Write-LocalDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Id 'WIN-AUD-01'
        $current = Get-AuditSetting
        foreach ($prefix in $policy.Keys) {
            $id = "$prefix-69AE-11D9-BED3-505054503030"
            if (([int]$bits[[string]$current[$id]] -band $policy[$prefix]) -ne $policy[$prefix]) {
                throw "The effective audit setting for $id does not match."
            }
        }
        Write-Output 'Local audit subcategories verified.'
    }
    firewall_baseline = {
        foreach ($networkProfile in @(Get-FirewallGap)) {
            $settings = @{
                Name = $networkProfile.Name; PolicyStore = 'PersistentStore'; Enabled = 'True'
                DefaultInboundAction = 'Block'; LogBlocked = 'True'
            }
            Set-NetFirewallProfile @settings
            Register-StepChange 'WIN-FW-01'
        }
        if (@(Get-FirewallGap).Count -gt 0) { throw 'The effective firewall policy is still incomplete.' }
        Write-Output 'Default-deny inbound verified for Domain, Private and Public.'
    }
    sysmon_installation = {
        [xml]$config = Get-Content -LiteralPath $SysmonConfig -Raw
        if ($config.DocumentElement.LocalName -ne 'Sysmon') { throw 'Invalid MedDefense Sysmon XML.' }
        $configHash = (Get-FileHash -LiteralPath $SysmonConfig -Algorithm SHA256).Hash
        $sysmonNames = @('Sysmon64', 'Sysmon', 'Sysmon64a')
        $service = Get-Service -Name $sysmonNames -ErrorAction SilentlyContinue | Select-Object -First 1
        $channel = 'Microsoft-Windows-Sysmon/Operational'
        $history = @{ LogName = $channel; Id = 16 }
        $recentConfig = Get-WinEvent -FilterHashtable $history -MaxEvents 1 -ErrorAction SilentlyContinue
        $matchesConfig = $recentConfig -and $recentConfig.ToXml() -match [regex]::Escape($configHash)
        if (-not $service -or -not $matchesConfig) {
            $exeName = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'Sysmon64a.exe' } else { 'Sysmon64.exe' }
            $candidates = @(
                (Join-Path $env:SystemRoot $exeName),
                (Join-Path $env:SystemRoot "System32\$exeName"),
                (Join-Path (Split-Path -Parent $SysmonConfig) $exeName)
            )
            if ($service.Name -eq 'Sysmon') {
                $candidates = @((Join-Path $env:SystemRoot 'System32\Sysmon.exe')) + $candidates
            }
            $binary = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
            if (-not $binary) {
                $archive = Join-Path $WorkDirectory 'Sysmon.zip'
                $folder = Join-Path $WorkDirectory 'Sysmon'
                Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $archive -UseBasicParsing
                Expand-Archive -LiteralPath $archive -DestinationPath $folder -Force
                $binary = Join-Path $folder $exeName
            }
            $signature = Get-AuthenticodeSignature -LiteralPath $binary
            if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
                throw 'Sysmon binary failed Microsoft signature verification.'
            }
            $mode = if ($service) { '-c' } else { '-i' }
            Invoke-ExternalTool $binary @('-accepteula', $mode, $SysmonConfig)
            Register-StepChange 'WIN-SYS-01'
        }
        $service = Get-Service -Name $sysmonNames -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $service) { throw 'Sysmon service was not found after deployment.' }
        if ($service.Status -ne 'Running') {
            Start-Service -Name $service.Name
            Register-StepChange 'WIN-SYS-01'
        }
        $eventLog = Get-WinEvent -ListLog $channel
        if (-not $eventLog.IsEnabled) {
            $eventLog.IsEnabled = $true
            $eventLog.SaveChanges()
            Register-StepChange 'WIN-SYS-01'
        }
        Write-Output "Sysmon and the MedDefense configuration verified: $configHash"
    }
    script_block_logging = {
        $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        Write-LocalDword -Path $key -Name 'EnableScriptBlockLogging' -Value 1 -Id 'WIN-PWR-01'
        $channel = Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational'
        if (-not $channel.IsEnabled) {
            $channel.IsEnabled = $true
            $channel.SaveChanges()
            Register-StepChange 'WIN-SYS-03'
        }
        Write-Output 'Script Block Logging and its Operational channel are enabled.'
    }
    applocker_baseline = {
        [xml]$effective = Get-AppLockerPolicy -Effective -Xml
        $identityService = Get-Service -Name AppIDSvc
        if ($identityService.Status -ne 'Running' -and
            $effective.SelectSingleNode('/AppLockerPolicy/RuleCollection[@EnforcementMode="Enabled"]/*')) {
            throw 'Review existing enforced AppLocker rules before starting Application Identity.'
        }
        $exeRules = $effective.SelectSingleNode('/AppLockerPolicy/RuleCollection[@Type="Exe"]')
        if ($null -eq $exeRules -or $exeRules.ChildNodes.Count -eq 0) {
            if ($null -ne $exeRules -and $exeRules.EnforcementMode -eq 'Enabled') {
                throw 'Existing AppLocker enforcement must be reviewed before adding audit rules.'
            }
            $policyPath = Join-Path $WorkDirectory 'applocker-audit.xml'
            [IO.File]::WriteAllText($policyPath, @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="0420aa01-76cb-4b7d-bcb2-05a510000001" Name="Hawthorne Windows" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="0420aa01-76cb-4b7d-bcb2-05a510000002" Name="Hawthorne Program Files" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="0420aa01-76cb-4b7d-bcb2-05a510000003" Name="Hawthorne Administrators" Description="" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@)
            Set-AppLockerPolicy -XmlPolicy $policyPath -Merge
            Register-StepChange
        }
        if ($identityService.StartType -ne 'Automatic') {
            Invoke-ExternalTool 'sc.exe' @('config', 'AppIDSvc', 'start=auto')
            Register-StepChange
        }
        if ($identityService.Status -ne 'Running') {
            Start-Service -Name AppIDSvc
            Register-StepChange
        }
        Write-Output 'AppLocker executable baseline and Application Identity service are present.'
    }
    service_minimization = {
        $optional = @('RemoteRegistry', 'Fax', 'RetailDemo', 'XblAuthManager', 'XblGameSave', 'XboxNetApiSvc')
        foreach ($service in @(Get-Service -Name $optional -ErrorAction SilentlyContinue)) {
            if ($service.Status -ne 'Stopped') {
                Stop-Service -Name $service.Name
                Register-StepChange
            }
            if ($service.StartType -ne 'Disabled') {
                Set-Service -Name $service.Name -StartupType Disabled
                Register-StepChange
            }
            Write-Output "$($service.Name): stopped and disabled."
        }
    }
}

# Run each control in its own child process so failures retain their exit code.
if ($Step) {
    if (-not $actions.Contains($Step) -or -not [IO.Directory]::Exists($WorkDirectory)) {
        Write-TaskError 2 'Invalid hardening step or work directory.'
    }
    $script:StepChanged = $false
    $script:StepControls = [Collections.Generic.List[string]]::new()
    $exitCode = 0
    try { & $actions[$Step] }
    catch {
        [Console]::Error.WriteLine($_.Exception.Message)
        $exitCode = 1
    }
    Write-Output "changed=$($script:StepChanged.ToString().ToLowerInvariant())"
    $script:StepControls | Sort-Object -Unique | ForEach-Object { Write-Output "control=$_" }
    exit $exitCode
}

$engine = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$targetPath = Join-Path $PSScriptRoot 'capstone/target_state.json'
$baselinePath = Join-Path $PSScriptRoot 'capstone/baseline/baseline_windows.json'
if (-not $PSBoundParameters.ContainsKey('AuditHelper') -and -not (Test-Path -LiteralPath $AuditHelper -PathType Leaf)) {
    $AuditHelper = Join-Path $PSScriptRoot 'capstone/win_audit.ps1'
}
foreach ($path in @($engine, $targetPath, $baselinePath, $AuditHelper, $SysmonConfig)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Write-TaskError 2 "Missing input: $path" }
}
try {
    $target = Get-Content -LiteralPath $targetPath -Raw | ConvertFrom-Json
    $baseline = Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json
    $requiredRate = $target.windows.pass_rate
    $beforeRate = $baseline.pass_rate_percent
    if ($target.schema_version -ne 'capstone-target-v1' -or @($target.controls.id).Count -lt 29 -or
        $null -eq $requiredRate -or $requiredRate -is [string] -or $requiredRate -is [bool] -or
        [double]$requiredRate -lt 0 -or [double]$requiredRate -gt 100) {
        throw 'Invalid target-state contract or Windows threshold.'
    }
    if (([string]$baseline.hostname -split '\.')[0] -notin $labNames -or $null -eq $beforeRate -or
        $beforeRate -is [string] -or $beforeRate -is [bool] -or [double]$beforeRate -lt 0 -or [double]$beforeRate -gt 100) {
        throw 'Use a valid baseline snapshot collected on hawthorne-adm-01.'
    }
    $SysmonConfig = (Resolve-Path -LiteralPath $SysmonConfig).Path
    $AuditHelper = (Resolve-Path -LiteralPath $AuditHelper).Path
}
catch { Write-TaskError 2 $_.Exception.Message }

function Invoke-LoggedScript {
    param([string]$Name, [string]$Path, [string[]]$Extra = @())
    $stdoutPath = Join-Path $staging "$Name.stdout"
    $stderrPath = Join-Path $staging "$Name.stderr"
    [IO.File]::AppendAllLines($log, [string[]]@('', "[$Name] script=$Path"))
    $clock = [Diagnostics.Stopwatch]::StartNew()
    try {
        $parameters = @{
            FilePath = $engine
            WorkingDirectory = Split-Path -Parent $Path
            ArgumentList = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', ('"{0}"' -f $Path)) + $Extra
            RedirectStandardOutput = $stdoutPath
            RedirectStandardError = $stderrPath
        }
        $process = Start-Process @parameters -Wait -PassThru
        $code = $process.ExitCode
        $lines = @(Get-Content -LiteralPath $stdoutPath) + @(Get-Content -LiteralPath $stderrPath)
    }
    catch {
        $code = 1
        $lines = @($_.Exception.Message)
    }
    $duration = [Math]::Round($clock.Elapsed.TotalSeconds, 3)
    $changed = $lines -contains 'changed=true'
    $touched = @(
        $lines | Where-Object { $_ -match '^control=' } | ForEach-Object { $_.Substring(8) } |
            Where-Object { $target.controls.id -contains $_ } | Sort-Object -Unique
    )
    [IO.File]::AppendAllLines($log, [string[]]($lines + "[$Name] exit_code=$code duration_seconds=$duration changed=$changed"))
    [pscustomobject]@{
        name = $Name; script_path = $Path; exit_code = $code; duration_seconds = $duration
        changed = $changed; controls_touched = $touched; output = $lines
    }
}

function Get-PostPassRate {
    param([string[]]$Lines)
    $counts = @{ PASS = 0; FAIL = 0; NOT_APPLICABLE = 0 }
    foreach ($line in $Lines) {
        $plain = $line -replace '\x1b\[[0-9;]*m', ''
        $tokens = [regex]::Matches($plain, '\b(?:NOT_APPLICABLE|PASS|FAIL)\b')
        if ($tokens.Count -eq 1) { $counts[$tokens[0].Value]++ }
    }
    $applicable = $counts.PASS + $counts.FAIL
    if ($applicable + $counts.NOT_APPLICABLE -eq 0) { return $null }
    if ($applicable -eq 0) { return 0 }
    [Math]::Round(100.0 * $counts.PASS / $applicable, 2)
}

$outputDirectory = Join-Path $PSScriptRoot 'capstone/exec'
$staging = $null
$lock = $null
$resultCode = 1
try {
    $null = New-Item -ItemType Directory -Path $outputDirectory -Force
    $lock = [IO.File]::Open((Join-Path $outputDirectory '.windows_harden.lock'), 'OpenOrCreate', 'Write', 'None')
    $staging = Join-Path $outputDirectory ('.windows-' + [Guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $staging
    $log = Join-Path $staging 'windows_harden.log'
    $timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $steps = @(
        foreach ($name in $actions.Keys) {
            $extra = @('-Step', $name, '-WorkDirectory', ('"{0}"' -f $staging),
                       '-SysmonConfig', ('"{0}"' -f $SysmonConfig))
            Invoke-LoggedScript -Name $name -Path $PSCommandPath -Extra $extra |
                Select-Object name, script_path, exit_code, duration_seconds, changed, controls_touched
        }
    )

    $audit = Invoke-LoggedScript -Name 'post_cis_audit' -Path $AuditHelper
    $postPassRate = if ($audit.exit_code -eq 0) { Get-PostPassRate $audit.output } else { $null }
    $passed = $null -ne $postPassRate -and $postPassRate -ge $requiredRate -and
        @($steps | Where-Object exit_code -ne 0).Count -eq 0
    $report = [ordered]@{
        timestamp = $timestamp
        hostname = $computer
        steps = $steps
        lynis_before = $null
        lynis_after = $null
        cis_before = $beforeRate
        cis_after = $postPassRate
        post_pass_rate = $postPassRate
        index_delta = if ($null -eq $postPassRate) { $null } else { [Math]::Round($postPassRate - $beforeRate, 2) }
        controls_touched = @($steps | ForEach-Object { $_.controls_touched } | Sort-Object -Unique)
        passed = $passed
    }
    [IO.File]::AppendAllLines($log, [string[]]@("CIS before=$beforeRate after=$postPassRate target=$requiredRate"))
    $json = Join-Path $staging 'windows_harden.json'
    [IO.File]::WriteAllText($json, ($report | ConvertTo-Json -Depth 6) + [Environment]::NewLine)
    Move-Item -LiteralPath $log, $json -Destination $outputDirectory -Force

    if ($passed) {
        Write-Output "Windows hardening met the CIS target of $requiredRate percent."
        $resultCode = 0
    }
    else { [Console]::Error.WriteLine('A step or the post-hardening audit failed. See capstone/exec/.') }
}
catch { [Console]::Error.WriteLine("Windows hardening failed: $($_.Exception.Message)") }
finally {
    if ($staging) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue }
    if ($lock) { $lock.Dispose() }
}
exit $resultCode
