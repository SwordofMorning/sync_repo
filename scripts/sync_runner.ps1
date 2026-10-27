<#
.SYNOPSIS
    Windows PowerShell Synchronization Service Runner.
.DESCRIPTION
    Runs sync_tool.py in either Batch mode (single execution for Windows Task Scheduler)
    or Daemon mode (continuous loop).
.PARAMETER Mode
    "Batch" (default) or "Daemon"
.PARAMETER DryRun
    Simulates synchronization without pushing to remote.
#>

param (
    [ValidateSet("Batch", "Daemon")]
    [string]$Mode = "Batch",
    [switch]$DryRun = $false
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source

if (-not $PythonExe) {
    Write-Error "Python executable not found in PATH."
    exit 1
}

$SyncTool = Join-Path $ProjectDir "sync_tool.py"
$LogFile = Join-Path $ProjectDir "sync.log"

function Run-SingleSync {
    $Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzzz"
    $ArgsList = @($SyncTool, "sync")
    if ($DryRun) {
        $ArgsList += "--dry-run"
    }

    Write-Output "[$Timestamp] Starting synchronization run..." | Out-File -FilePath $LogFile -Append -Encoding utf8
    & $PythonExe $ArgsList *>> $LogFile
    $ExitCode = $LASTEXITCODE
    $EndTimestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzzz"
    Write-Output "[$EndTimestamp] Synchronization finished with exit code $ExitCode" | Out-File -FilePath $LogFile -Append -Encoding utf8
    return $ExitCode
}

if ($Mode -eq "Batch") {
    $ExitCode = Run-SingleSync
    exit $ExitCode
}
elseif ($Mode -eq "Daemon") {
    $IntervalSec = 900
    Write-Output "[+] Daemon mode started. Interval: $IntervalSec seconds. Press Ctrl+C to stop."
    while ($true) {
        Run-SingleSync
        Start-Sleep -Seconds $IntervalSec
    }
}
