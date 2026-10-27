<#
.SYNOPSIS
    Registers Windows Task Scheduler job for sync_runner.ps1.
#>

param (
    [string]$TaskName = "SmartRepoSyncService",
    [int]$IntervalMinutes = 15
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RunnerScript = Join-Path $ScriptDir "sync_runner.ps1"

if (-not (Test-Path $RunnerScript)) {
    Write-Error "Cannot find runner script at $RunnerScript"
    exit 1
}

$Action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$RunnerScript`""

$Trigger = New-ScheduledTaskTrigger `
    -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
    -RepetitionDuration ([TimeSpan]::MaxValue)

$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -Description "Automated background sync service between smart and smart_encrypted repos" `
    -Force

Write-Output "[+] Scheduled Task '$TaskName' registered successfully (Interval: $IntervalMinutes mins)."
