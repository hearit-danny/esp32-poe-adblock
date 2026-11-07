# Weekly blocklist refresh, run by the "AdBlocker blocklist update" scheduled task.
# Rebuilds blocklist.bin from StevenBlack plus lists/, uploads it to the unit and
# keeps the last run's output in %LOCALAPPDATA%\AdBlocker\blocklist-update.log.
# Written for Windows PowerShell 5.1, whose path does not change between versions.

$repo = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $env:LOCALAPPDATA 'AdBlocker'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir 'blocklist-update.log'

# The task may start with an environment from before the password was set.
if (-not $env:ADBLOCK_ADMIN_PASSWORD) {
    $env:ADBLOCK_ADMIN_PASSWORD = [Environment]::GetEnvironmentVariable('ADBLOCK_ADMIN_PASSWORD', 'User')
}

"$(Get-Date -Format s) start in $repo" | Out-File -FilePath $log -Encoding utf8
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    "python not found on PATH" | Out-File -FilePath $log -Append -Encoding utf8
    exit 1
}
Set-Location $repo
& $python.Source -I scripts/build_blocklist.py --upload http://192.168.1.53/upload 2>&1 |
    ForEach-Object { "$_" } | Out-File -FilePath $log -Append -Encoding utf8
$code = $LASTEXITCODE
"$(Get-Date -Format s) exit $code" | Out-File -FilePath $log -Append -Encoding utf8
exit $code
