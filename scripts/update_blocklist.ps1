# Blocklist refresh, run daily by the "AdBlocker blocklist update" scheduled task.
# Skips the run while the unit's list is under 6.5 days old, so the list is rebuilt
# about weekly; -Force rebuilds now. Rebuilds blocklist.bin from StevenBlack plus
# lists/, uploads it to the unit and keeps the last update's output in
# %LOCALAPPDATA%\AdBlocker\blocklist-update.log, with one line per skipped run after it.
# Written for Windows PowerShell 5.1, whose path does not change between versions.
param([switch]$Force)

$unit = 'http://192.168.1.53'
$maxAgeDays = 6.5
$repo = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $env:LOCALAPPDATA 'AdBlocker'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir 'blocklist-update.log'

if (-not $Force) {
    try {
        $stats = Invoke-RestMethod -Uri "$unit/stats" -TimeoutSec 10
        $built = [DateTimeOffset]::FromUnixTimeSeconds([long]$stats.build_time).UtcDateTime
        $age = ((Get-Date).ToUniversalTime() - $built).TotalDays
        if ($stats.blocklist_loaded -and $age -lt $maxAgeDays) {
            "$(Get-Date -Format s) list is $([math]::Round($age, 1)) days old, skipping" |
                Out-File -FilePath $log -Append -Encoding utf8
            exit 0
        }
    } catch {
        # Unit unreachable: run the update anyway so the upload error lands in the log.
        $note = "could not read $unit/stats: $($_.Exception.Message)"
    }
}

# The task may start with an environment from before the password was set.
if (-not $env:ADBLOCK_ADMIN_PASSWORD) {
    $env:ADBLOCK_ADMIN_PASSWORD = [Environment]::GetEnvironmentVariable('ADBLOCK_ADMIN_PASSWORD', 'User')
}

"$(Get-Date -Format s) start in $repo" | Out-File -FilePath $log -Encoding utf8
if ($note) { $note | Out-File -FilePath $log -Append -Encoding utf8 }
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    "python not found on PATH" | Out-File -FilePath $log -Append -Encoding utf8
    exit 1
}
Set-Location $repo
& $python.Source -I scripts/build_blocklist.py --upload "$unit/upload" 2>&1 |
    ForEach-Object { "$_" } | Out-File -FilePath $log -Append -Encoding utf8
$code = $LASTEXITCODE
"$(Get-Date -Format s) exit $code" | Out-File -FilePath $log -Append -Encoding utf8
exit $code
