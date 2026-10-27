# Out-of-tree physical file operations. Paths are data, never PowerShell source.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ManifestPath,
    [Parameter(Mandatory = $true)][string]$ResultPath,
    [int]$ParentPid = 0,
    [int64]$ParentCreateTimeFt = 0,
    [string]$LeaseFile = "",
    [string]$ReleaseFlagFile = ""
)

$ErrorActionPreference = 'Stop'
$parentProc = $null
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Write-DurableUtf8([string]$Path, [string]$Text) {
    $bytes = $utf8.GetBytes($Text)
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

# Bind the parent's kernel process object BEFORE reading a manifest or mutating
# any worktree file. Accessing Handle forces Process to retain the fixed object.
if ($ParentPid -gt 0) {
    try {
        $parentProc = [System.Diagnostics.Process]::GetProcessById($ParentPid)
        $null = $parentProc.Handle
        if ($parentProc.HasExited -or
            $parentProc.StartTime.ToFileTimeUtc() -ne $ParentCreateTimeFt) { exit 99 }
        if (-not $LeaseFile -or -not $ReleaseFlagFile -or
            -not [System.IO.File]::Exists($LeaseFile)) { exit 99 }
        $registration = @{
            worker_pid = $PID
            worker_create_time_ft = [System.Diagnostics.Process]::GetCurrentProcess().StartTime.ToFileTimeUtc()
        }
        Write-DurableUtf8 ($LeaseFile + '.worker.tmp') ($registration | ConvertTo-Json -Compress)
        [System.IO.File]::Move(($LeaseFile + '.worker.tmp'), ($LeaseFile + '.worker'))
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while (-not [System.IO.File]::Exists($ReleaseFlagFile)) {
            if ($parentProc.HasExited -or -not [System.IO.File]::Exists($LeaseFile) -or
                [DateTime]::UtcNow -ge $deadline) { exit 99 }
            Start-Sleep -Milliseconds 100
        }
        if ($parentProc.HasExited -or -not [System.IO.File]::Exists($LeaseFile)) { exit 99 }
    }
    catch { exit 99 }
}

function Assert-ParentAlive {
    if ($null -ne $parentProc) {
        if ($parentProc.HasExited -or -not [System.IO.File]::Exists($LeaseFile)) { exit 99 }
    }
}

function Test-TsdHeader([byte[]]$Bytes) {
    $magic = [System.Text.Encoding]::ASCII.GetBytes('%TSD-Header-###%')
    if ($Bytes.Length -lt $magic.Length) { return $false }
    for ($i = 0; $i -lt $magic.Length; $i++) {
        if ($Bytes[$i] -ne $magic[$i]) { return $false }
    }
    return $true
}

function Get-Sha256([byte[]]$Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-Attestation([byte[]]$Bytes) {
    $length = [Math]::Min(16, $Bytes.Length)
    $head = New-Object byte[] $length
    [Array]::Copy($Bytes, $head, $length)
    return @{
        physical_size = $Bytes.LongLength
        physical_sha256 = (Get-Sha256 $Bytes)
        physical_header_hex = ([BitConverter]::ToString($head)).Replace('-', '').ToLowerInvariant()
        has_tsd_header = (Test-TsdHeader $Bytes)
    }
}

function Assert-PlainBytes([byte[]]$Bytes, $Item) {
    if ($Bytes.LongLength -ne [int64]$Item.expected_size) { throw 'Physical size mismatch' }
    if ((Get-Sha256 $Bytes) -ne $Item.expected_sha256) { throw 'Physical SHA-256 mismatch' }
    if (Test-TsdHeader $Bytes) { throw 'Unexpected physical TSD cipher header' }
}

$manifest = $null
$result = [ordered]@{
    tx_id = $null; nonce = $null; overall_status = 'PASS'
    failed_index = $null; error = $null; items = @()
}
$index = -1
try {
    Assert-ParentAlive
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $result.tx_id = $manifest.tx_id
    $result.nonce = $manifest.nonce
    # MoveFileExW gives atomic, overwrite-existing rename semantics on Windows
    # PowerShell 5.1, whose System.IO.File.Move has no overwrite overload.
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SyncPhysicalMove {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool MoveFileEx(string oldPath, string newPath, int flags);
}
'@
    $index = 0
    foreach ($item in $manifest.items) {
        Assert-ParentAlive
        $observed = [ordered]@{
            index = $index; mode = $item.mode
            target_abs_path = $item.target_abs_path; status = 'PASS'
        }
        try {
            $target = [string]$item.target_abs_path
            switch ([string]$item.mode) {
                'REPLACE_UNENCRYPTED' {
                    $bytes = [System.IO.File]::ReadAllBytes([string]$item.stage_old_path)
                    Assert-PlainBytes $bytes $item
                    $null = [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($target))
                    Assert-ParentAlive
                    if (-not [SyncPhysicalMove]::MoveFileEx([string]$item.stage_old_path, $target, 9)) {
                        throw (New-Object ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
                    }
                    $after = [System.IO.File]::ReadAllBytes($target)
                    Assert-PlainBytes $after $item
                    $attest = Get-Attestation $after
                    foreach ($key in $attest.Keys) { $observed[$key] = $attest[$key] }
                }
                'DELETE_FILE' {
                    if ([System.IO.Directory]::Exists($target)) { throw 'Directory blocks DELETE_FILE' }
                    if ([System.IO.File]::Exists($target)) { [System.IO.File]::Delete($target) }
                    if ([System.IO.File]::Exists($target)) { throw 'File still exists after deletion' }
                    $observed.exists = $false
                }
                'PROBE_PHYSICAL_HEADER' {
                    $bytes = [System.IO.File]::ReadAllBytes($target)
                    $attest = Get-Attestation $bytes
                    foreach ($key in $attest.Keys) { $observed[$key] = $attest[$key] }
                    if ($item.include_bytes) {
                        $observed.physical_bytes_base64 = [Convert]::ToBase64String($bytes)
                    }
                }
                default { throw ('Unsupported worker operation: ' + $item.mode) }
            }
        }
        catch {
            $observed.status = 'FAIL'
            $observed.error = $_.Exception.Message
            $result.overall_status = 'FAIL'
            $result.failed_index = $index
            $result.error = $_.Exception.Message
        }
        $result.items += $observed
        if ($result.overall_status -eq 'FAIL') { break }
        $index++
    }
}
catch {
    $result.overall_status = 'FAIL'
    $result.failed_index = $index
    $result.error = $_.Exception.Message
}

Assert-ParentAlive
Write-DurableUtf8 ($ResultPath + '.tmp') ($result | ConvertTo-Json -Depth 20 -Compress)
if ([System.IO.File]::Exists($ResultPath)) { [System.IO.File]::Delete($ResultPath) }
[System.IO.File]::Move(($ResultPath + '.tmp'), $ResultPath)
if ($null -ne $parentProc) { $parentProc.Dispose() }
if ($result.overall_status -eq 'FAIL') { exit 1 }
exit 0
