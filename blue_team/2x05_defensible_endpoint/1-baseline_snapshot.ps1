# Exit codes: 0 success, 1 audit or report failure, 2 environment error.
param(
    [string]$AuditHelper = '/home/analyst/MedDefense_Lab/capstone/win_audit.ps1'
)

$ErrorActionPreference = 'Stop'
$staging = $null
try {
    if (-not (Test-Path -LiteralPath $AuditHelper -PathType Leaf)) {
        [Console]::Error.WriteLine("Missing audit helper: $AuditHelper")
        exit 2
    }

    $helperPath = (Get-Item -LiteralPath $AuditHelper).FullName
    $engine = (Get-Process -Id $PID).Path
    $auditLog = @(
        & $engine -NoProfile -NonInteractive -File $helperPath 2>&1 |
            ForEach-Object { [string]$_ }
    )
    if ($LASTEXITCODE -ne 0) {
        throw "Audit helper exited with code $LASTEXITCODE."
    }

    $counts = @{ PASS = 0; FAIL = 0; NOT_APPLICABLE = 0 }
    foreach ($line in $auditLog) {
        $plainLine = $line -replace '\x1b\[[0-9;]*m', ''
        $statuses = [regex]::Matches($plainLine, '\b(?:NOT_APPLICABLE|PASS|FAIL)\b')
        if ($statuses.Count -eq 1) {
            $counts[$statuses[0].Value]++
        }
    }

    $applicableCount = $counts.PASS + $counts.FAIL
    $controlsTotal = $applicableCount + $counts.NOT_APPLICABLE
    if ($controlsTotal -eq 0) {
        throw 'No recognised control results in the audit output.'
    }
    $passRate = 0
    if ($applicableCount -gt 0) {
        $passRate = [Math]::Round(100.0 * $counts.PASS / $applicableCount, 2)
    }

    $baseline = [ordered]@{
        timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        hostname = [System.Net.Dns]::GetHostName()
        controls_total = $controlsTotal
        pass_count = $counts.PASS
        fail_count = $counts.FAIL
        na_count = $counts.NOT_APPLICABLE
        pass_rate_percent = $passRate
        log_path = 'capstone/baseline/windows_baseline.log'
    }

    $outputDirectory = Join-Path $PSScriptRoot 'capstone/baseline'
    $staging = Join-Path $outputDirectory ('.windows-' + [Guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $staging -Force
    $logFile = Join-Path $staging 'windows_baseline.log'
    $jsonFile = Join-Path $staging 'baseline_windows.json'
    [IO.File]::WriteAllLines($logFile, [string[]]$auditLog)
    [IO.File]::WriteAllText($jsonFile, ($baseline | ConvertTo-Json) + [Environment]::NewLine)
    Move-Item -LiteralPath $logFile, $jsonFile -Destination $outputDirectory -Force
}
catch {
    [Console]::Error.WriteLine("Windows baseline failed: $($_.Exception.Message)")
    exit 1
}
finally {
    if ($staging) {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}
exit 0
