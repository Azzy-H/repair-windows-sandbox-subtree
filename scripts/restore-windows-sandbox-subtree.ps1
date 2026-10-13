<# Restores one repair's DACLs and integrity labels. Refuses changed or replaced objects. #>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param([Parameter(Mandatory = $true)][string]$Backup)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$handles = [System.Collections.Generic.List[object]]::new()
$restored = 0
$unchanged = 0
$exitCode = 1
$inUse = [System.Collections.Generic.List[string]]::new()
try {
    . (Join-Path $PSScriptRoot 'Repair.Common.ps1')
    if ([DshSubtreeRepair.Security]::IsElevated()) { throw 'Do not run recovery elevated.' }
    if (-not $WhatIfPreference -and [DshSubtreeRepair.Security]::IsRestricted()) { throw 'Recovery requires an authorized unconfined invocation.' }
    $data = [System.IO.File]::ReadAllText((Get-LocalPath $Backup)) | ConvertFrom-Json
    if ($data.schema -ne 1) { throw 'Unsupported backup schema.' }
    $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($data.userSid -ne $userSid) { throw 'Use the same signed-in account that made this backup.' }
    $root = Open-PathChain (Get-LocalPath $data.root) $handles
    if ($root.Identity -ne $data.rootIdentity) { throw 'The workspace root was replaced.' }
    $rootBefore = $root.Read()
    $work = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    # Validate every target before the first restore; writes retain the checked object handle.
    foreach ($row in $data.objects) {
        $path = Get-LocalPath $row.path
        if (-not (Test-Inside $root.Path $path) -or -not $seen.Add($path)) { throw "Invalid or duplicate backup path: $path" }
        $entry = $null
        try { $entry = Open-PathChain $path $handles -Writable }
        catch {
            $code = Get-Win32Code $_.Exception
            if (-not [DshSubtreeRepair.Entry]::IsTransient($code)) { throw }
            # Held open by another process, or gone: it cannot be written now, and that is not a
            # reason to leave the remaining objects unrestored.
            $inUse.Add($path)
            Write-Output ("SKIPPED_IN_USE $path (win32 $code)")
            continue
        }
        if ($entry.Identity -ne $row.identity -or $entry.IsDirectory -ne $row.directory -or
            (-not $entry.IsDirectory -and $entry.Links -gt 1)) { throw "Object was replaced or hard-linked: $path" }
        # The allowed after-state must be exactly the plan this tool could have made.
        $expected = [DshSubtreeRepair.Security]::Plan($row.before, $data.workspaceSid, $userSid, $entry.IsDirectory)
        if (-not [DshSubtreeRepair.Security]::Same($expected, $row.after)) { throw "Invalid repair plan in backup: $path" }
        $current = $entry.Read()
        # The current state may legitimately differ from the recorded plan: Windows re-applies the
        # parent's inheritable entries when an unprotected DACL is written. Accept the recorded
        # before state exactly, the DACL-only state, or the completed repair, all by intent.
        $daclOnly = [DshSubtreeRepair.Security]::VerifyDaclIntent($row.before, $row.after, $current, $data.workspaceSid, $userSid, $entry.IsDirectory) -and
            [DshSubtreeRepair.Security]::SameLabel($current, $row.before)
        $repaired = [DshSubtreeRepair.Security]::VerifyIntent($row.before, $row.after, $current, $data.workspaceSid, $userSid, $entry.IsDirectory)
        if (-not [DshSubtreeRepair.Security]::Same($current, $row.before) -and -not $daclOnly -and -not $repaired) {
            throw "Permissions changed after the repair; refusing to overwrite them: $path"
        }
        $work.Add([pscustomobject]@{ entry = $entry; row = $row; current = $current })
    }
    if ($PSCmdlet.ShouldProcess("$($work.Count) backed-up objects", 'restore and verify DACLs and integrity labels')) {
        for ($i = $work.Count - 1; $i -ge 0; $i--) {
            $item = $work[$i]
            if (-not [DshSubtreeRepair.Security]::Same($item.entry.Read(), $item.current)) { throw "Concurrent permission change: $($item.row.path)" }
            if ([DshSubtreeRepair.Security]::Same($item.current, $item.row.before)) { $unchanged++; continue }
            # Keep the repair's WRITE_OWNER grant until the original label is restored.
            if (-not [DshSubtreeRepair.Security]::SameLabel($item.current, $item.row.before)) { $item.entry.SetLabel($item.row.before) }
            $item.entry.SetDacl($item.row.before)
            if (-not [DshSubtreeRepair.Security]::VerifyRestoredIntent($item.row.before, $item.entry.Read())) { throw "Restore verification failed: $($item.row.path)" }
            $restored++
            Write-Output ('RESTORED ' + $item.row.path)
        }
        if (-not [DshSubtreeRepair.Security]::Same($root.Read(), $rootBefore)) { throw 'The workspace root changed during recovery.' }
    }
    if ($inUse.Count -gt 0) {
        Write-Output ('RESTORE_PARTIAL ' + $inUse.Count + ' object(s) are held open by another process and were not restored.')
        $exitCode = 1
    } else { $exitCode = 0 }
} catch {
    Write-Output ('RESTORE_FAILED ' + $_.Exception.Message)
} finally {
    for ($i = $handles.Count - 1; $i -ge 0; $i--) { $handles[$i].Dispose() }
    Write-Output ('RESTORE_RECAP ' + (@{ restored = $restored; unchanged = $unchanged; skippedInUse = $inUse.Count; exitCode = $exitCode; preview = [bool]$WhatIfPreference } | ConvertTo-Json -Compress))
}
exit $exitCode
