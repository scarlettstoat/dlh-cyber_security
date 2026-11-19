# Exit codes: 0 success, 1 collection failed, 2 environment error.
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT' -or
    ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess)) {
    [Console]::Error.WriteLine('Run this in native Windows PowerShell on the target.')
    exit 2
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    [Console]::Error.WriteLine('Open Windows PowerShell as Administrator.')
    exit 2
}

$requiredCommands = @(
    'Get-CimInstance', 'Get-HotFix', 'Get-Service', 'Get-LocalUser',
    'Get-NetFirewallProfile', 'Get-WinEvent', 'auditpol.exe', 'net.exe'
)
foreach ($commandName in $requiredCommands) {
    if (-not (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
        [Console]::Error.WriteLine("Missing dependency: $commandName")
        exit 2
    }
}

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $hotfixIds = @(Get-HotFix | Select-Object -ExpandProperty HotFixID | Sort-Object -Unique)

    if ($os.ProductType -eq 1) {
        $featureCommand = 'Get-WindowsOptionalFeature'
    }
    else {
        $featureCommand = 'Get-WindowsFeature'
    }

    if (-not (Get-Command -Name $featureCommand -ErrorAction SilentlyContinue)) {
        [Console]::Error.WriteLine("Missing dependency: $featureCommand")
        exit 2
    }

    if ($os.ProductType -eq 1) {
        $features = @(Get-WindowsOptionalFeature -Online | Where-Object State -eq 'Enabled')
    }
    else {
        $features = @(Get-WindowsFeature | Where-Object Installed)
    }

    $services = @(Get-Service | Sort-Object Name)
    $runningServices = @(
        $services | Where-Object Status -eq 'Running' | ForEach-Object {
            [ordered]@{ name = $_.Name; display_name = $_.DisplayName }
        }
    )
    $localUsers = @(
        Get-LocalUser | Sort-Object Name | ForEach-Object {
            [ordered]@{ name = $_.Name; enabled = $_.Enabled; sid = [string]$_.SID }
        }
    )
    $firewallProfiles = @(
        Get-NetFirewallProfile -PolicyStore ActiveStore | Sort-Object Name | ForEach-Object {
            [ordered]@{
                name = $_.Name
                enabled = [string]$_.Enabled
                default_inbound_action = [string]$_.DefaultInboundAction
                default_outbound_action = [string]$_.DefaultOutboundAction
            }
        }
    )

    $auditCsv = @(& auditpol.exe /get '/category:*' /r)
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol failed with exit code $LASTEXITCODE."
    }
    $auditPolicy = @($auditCsv | ConvertFrom-Csv)
    if ($auditPolicy.Count -eq 0) {
        throw 'auditpol returned no policy rows.'
    }

    $accountPolicy = @(& net.exe accounts)
    if ($LASTEXITCODE -ne 0) {
        throw "net accounts failed with exit code $LASTEXITCODE."
    }

    $sysmonService = $services |
        Where-Object { $_.Name -in @('Sysmon', 'Sysmon64') } |
        Select-Object -First 1
    $sysmon = [ordered]@{
        present = ($null -ne $sysmonService)
        service_name = $null
        service_status = $null
        version = $null
        channel_present = $false
        channel_maximum_size_bytes = $null
    }

    if ($sysmonService) {
        $sysmon.service_name = $sysmonService.Name
        $sysmon.service_status = [string]$sysmonService.Status
        $serviceFilter = "Name='$($sysmonService.Name)'"
        $serviceInfo = Get-CimInstance -ClassName Win32_Service -Filter $serviceFilter
        if ($serviceInfo.PathName -match '^\s*"([^"]+)"|^\s*([^"].*?\.exe)(?:\s|$)') {
            $exePath = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
            $exePath = [Environment]::ExpandEnvironmentVariables($exePath)
            $sysmon.version = (Get-Item -LiteralPath $exePath).VersionInfo.FileVersion
        }
        else {
            throw "Could not resolve the executable for $($sysmonService.Name)."
        }
    }

    try {
        $sysmonLog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'
        $sysmon.channel_present = $true
        $sysmon.channel_maximum_size_bytes = $sysmonLog.MaximumSizeInBytes
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingLogsFound*') {
            throw
        }
    }

    $loggingKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $loggingValue = $null
    if (Test-Path -LiteralPath $loggingKey) {
        $loggingPolicy = Get-ItemProperty -LiteralPath $loggingKey
        $loggingValue = $loggingPolicy.EnableScriptBlockLogging
    }

    $loggingState = switch ($loggingValue) {
        1 { 'enabled' }
        0 { 'disabled' }
        $null { 'not_configured' }
        default { 'unexpected_value' }
    }

    $baseline = [ordered]@{
        hostname = $env:COMPUTERNAME
        os = [ordered]@{
            caption = $os.Caption
            version = $os.Version
            build_number = $os.BuildNumber
            update_build_revision = $currentVersion.UBR
            installed_hotfix_ids = $hotfixIds
        }
        installed_feature_count = $features.Count
        running_services = $runningServices
        local_users = $localUsers
        firewall_profiles = $firewallProfiles
        audit_policy = $auditPolicy
        sysmon = $sysmon
        powershell_script_block_logging = [ordered]@{
            registry_path = $loggingKey
            registry_value = $loggingValue
            state = $loggingState
        }
        account_policy = $accountPolicy
    }

    $baseline | ConvertTo-Json -Depth 8
    exit 0
}
catch {
    [Console]::Error.WriteLine("Windows intake failed: $($_.Exception.Message)")
    exit 1
}
