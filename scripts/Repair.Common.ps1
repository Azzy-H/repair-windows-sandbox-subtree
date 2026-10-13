Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This script requires Windows.' }
if (-not ('DshSubtreeRepair.Security' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'SubtreeSecurity.cs')
}

function Get-LocalPath([string]$Value) {
    if ($Value -notmatch '^[A-Za-z]:[\\/]') { throw "Use an absolute local drive path: $Value" }
    $full = [System.IO.Path]::GetFullPath($Value).TrimEnd('\')
    if ($full.Substring(2).Contains(':')) { throw "Alternate data streams are not supported: $Value" }
    return $full
}

function Test-Inside([string]$Root, [string]$Candidate) {
    return $Candidate.StartsWith($Root.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

# The Win32 code inside a wrapped exception, so a caller can separate "another process holds
# the object open" from a missing right. Non-Win32 failures report 0 and stay fatal.
function Get-Win32Code($Exception) {
    $base = $Exception.GetBaseException()
    if ($base -is [System.ComponentModel.Win32Exception]) { return [int]$base.NativeErrorCode }
    return 0
}

# Check every component without following a reparse leaf. Callers also compare
# canonical paths and file identities. Concurrent filesystem writers must be stopped.
function Open-PathChain([string]$FullPath, $Handles, [switch]$Writable) {
    $full = Get-LocalPath $FullPath
    $parts = $full.Substring(3).Split('\', [System.StringSplitOptions]::RemoveEmptyEntries)
    $current = $full.Substring(0, 3)
    $entry = [DshSubtreeRepair.Entry]::Inspect($current)
    $Handles.Add($entry)
    if ($entry.IsReparse) { throw "Reparse ancestor: $current" }
    for ($partIndex = 0; $partIndex -lt $parts.Count; $partIndex++) {
        $part = $parts[$partIndex]
        $current = Join-Path $current $part
        $entry = if ($Writable -and $partIndex -eq $parts.Count - 1) {
            [DshSubtreeRepair.Entry]::Open($current)
        } else { [DshSubtreeRepair.Entry]::Inspect($current) }
        $Handles.Add($entry)
        if ($entry.IsReparse) { throw "Reparse ancestor: $current" }
    }
    if ($entry.Path -ine $full) { throw "Path resolved through an alias: $full" }
    return $entry
}

function Write-DurableJson([string]$File, $Value) {
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 12) + "`n")
    $stream = [System.IO.FileStream]::new($File, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}

function Get-Facts([string]$Sddl, [string]$Sid, [bool]$Directory) {
    return [pscustomobject]@{
        capability = [DshSubtreeRepair.Security]::HasGrant($Sddl, $Sid, [DshSubtreeRepair.Security]::GrantMask, $Directory)
        lowLabel = [DshSubtreeRepair.Security]::HasLowLabel($Sddl, $Directory)
    }
}
