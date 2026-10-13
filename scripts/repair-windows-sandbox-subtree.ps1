<#
.SYNOPSIS
Repairs missing DSH sandbox grants and integrity labels strictly below a workspace root.
.DESCRIPTION
Reads every bounded, non-reparse descendant; backs up each planned change and creates
standalone recovery files before changing permissions. Uses numeric Win32 security data.
No recursive permission command is used. Stop writers before repair or rollback.
.PARAMETER Path
The actual workspace root, never an arbitrarily chosen deeper directory.
.PARAMETER Out
Persistent existing recovery directory outside the workspace and skill directories.
.PARAMETER WorkspaceSid
Optional exact SID from this session's DSH diagnostics. Otherwise derived from the
canonical workspace path using the current DSH workspaceWriteSid algorithm.
.PARAMETER Limit
Maximum descendants visited. Exceeding it refuses the whole repair before mutation.
.PARAMETER Sample
Maximum example paths in the recap. Every file and directory is inspected and verified.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Out,
    [ValidatePattern('^S-1-4-\d+-\d+$')][string]$WorkspaceSid,
    [ValidateRange(1, 1000000)][int]$Limit = 20000,
    [ValidateRange(0, 1000)][int]$Sample = 40,
    [string]$User
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$runId = [guid]::NewGuid().ToString('n')
$handles = [System.Collections.Generic.List[object]]::new()
$script:reportPath = $null
$script:refusals = [System.Collections.Generic.List[string]]::new()
$script:verdict = 'REFUSED'
$script:next = 'stop'
$rollback = $null
$backupPath = $null
$exitCode = 2
$mutationStarted = $false
$scan = [ordered]@{ objects = 0; directories = 0; files = 0; reparse = 0; truncated = $false; skipped = 0 }
$observed = [ordered]@{ missingCapability = 0; missingLabel = 0; examples = @() }
$actions = [ordered]@{ planned = 0; attempted = 0; verified = 0; failed = 0; skipped = 0; partial = 0 }
$verification = [ordered]@{ performed = $false; rootUnchanged = $false; checked = 0 }
# Objects another process holds open, or that disappeared mid-walk. They are neither a
# permission problem nor a reason to abandon the objects that can be repaired. A path claimed
# after its DACL write is tracked separately: that object is half-repaired, not skipped.
$skippedPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$skippedExamples = [System.Collections.Generic.List[string]]::new()
$partialPaths = [System.Collections.Generic.List[string]]::new()

function Write-Record([string]$Kind, $Data) {
    $json = [pscustomobject]@{ run = $runId; record = $Kind; data = $Data } | ConvertTo-Json -Compress -Depth 12
    if ($script:reportPath) { [System.IO.File]::AppendAllText($script:reportPath, $json + "`n") }
    # Records must never become function return values.
    Write-Information ($Kind.ToUpperInvariant() + ' ' + $json) -InformationAction Continue
}

try {
    . (Join-Path $PSScriptRoot 'Repair.Common.ps1')
    if ([DshSubtreeRepair.Security]::IsElevated()) { throw 'Do not run this repair elevated.' }
    if (-not $WhatIfPreference -and [DshSubtreeRepair.Security]::IsRestricted()) { throw 'Repair requires an authorized unconfined invocation; the token is restricted.' }
    $rootInput = Get-LocalPath $Path
    if ($rootInput -match '^[A-Za-z]:$') { throw 'A volume root is not a workspace repair target.' }
    foreach ($forbidden in @($env:USERPROFILE, $env:WINDIR)) {
        if ($forbidden -and $rootInput -ieq (Get-LocalPath $forbidden)) { throw "Refusing protected root: $rootInput" }
    }
    if ($env:WINDIR -and (Test-Inside (Get-LocalPath $env:WINDIR) $rootInput)) { throw 'The Windows directory is not a repair target.' }
    $rootEntry = Open-PathChain $rootInput $handles
    if (-not $rootEntry.IsDirectory) { throw 'Path must be a directory.' }
    $root = $rootEntry.Path
    if ([System.IO.DriveInfo]::new($root.Substring(0,3)).DriveFormat -ne 'NTFS') { throw 'This repair supports local NTFS workspaces only.' }
    $outEntry = Open-PathChain (Get-LocalPath $Out) $handles
    if (-not $outEntry.IsDirectory) { throw 'Out must be an existing directory.' }
    $outRoot = $outEntry.Path
    $skillRoot = Get-LocalPath (Split-Path -Parent $PSScriptRoot)
    if ($outRoot -ieq $root -or (Test-Inside $root $outRoot) -or $outRoot -ieq $skillRoot -or (Test-Inside $skillRoot $outRoot)) {
        throw 'Out must be outside the workspace and skill directories.'
    }
    $script:reportPath = Join-Path $outRoot "acl-report-$runId.jsonl"
    if (-not $WorkspaceSid) { $WorkspaceSid = [DshSubtreeRepair.Security]::WorkspaceSid($root) }
    $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ([System.Security.AccessControl.RawSecurityDescriptor]::new($outEntry.Read()).Owner.Value -ne $userSid) {
        throw 'Out must be owned by the signed-in user.'
    }
    if ($User) {
        $selected = [System.Security.Principal.NTAccount]::new($User).Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($selected -ne $userSid) { throw 'User must be the current signed-in account.' }
    }
    $rootBefore = $rootEntry.Read()
    # The root's own label structure decides what every future child inherits, and the root is not
    # among the inspected entries, so it is validated here: an entry that stops propagating, or one
    # that covers only files or only containers, would leave directories created later unlabelled
    # while this run reported success.
    try {
        [DshSubtreeRepair.Security]::ValidateLabelStructure($rootBefore, $true)
    } catch {
        $script:verdict = 'ROOT_NOT_PROVISIONED'
        throw ('The workspace root label structure is unsupported: ' + $_.Exception.GetBaseException().Message)
    }
    $rootFacts = Get-Facts $rootBefore $WorkspaceSid $true
    Write-Record 'observe-root' @{ path = $root; workspaceSid = $WorkspaceSid; facts = $rootFacts }
    if (-not $rootFacts.capability -or -not $rootFacts.lowLabel) {
        $script:verdict = 'ROOT_NOT_PROVISIONED'
        throw 'The root lacks the exact inheritable workspace grant or Low label. Diagnose provisioning first.'
    }

    $entries = [System.Collections.Generic.List[object]]::new()
    $pending = [System.Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        # Lazy, one-directory enumeration stops at Limit instead of collecting the entire tree.
        foreach ($child in [System.IO.Directory]::EnumerateFileSystemEntries($directory)) {
            if ($scan.objects -ge $Limit) { $scan.truncated = $true; $script:verdict = 'SCAN_LIMIT'; throw "Scan exceeds Limit=$Limit; nothing was changed." }
            $scan.objects++
            $entry = $null; $openError = 0
            if (-not [DshSubtreeRepair.Entry]::TryInspect($child, [ref]$entry, [ref]$openError)) {
                if (-not [DshSubtreeRepair.Entry]::IsTransient($openError)) {
                    throw (New-Object System.ComponentModel.Win32Exception($openError, "inspect: $child"))
                }
                $scan.skipped++
                if ($skippedExamples.Count -lt $Sample) { $skippedExamples.Add($child) }
                Write-Record 'skip-unreadable' @{ path = $child; win32 = $openError; inUse = [DshSubtreeRepair.Entry]::IsInUse($openError) }
                continue
            }
            $handles.Add($entry)
            if ($entry.IsReparse) { $scan.reparse++; Write-Record 'skip-reparse' @{ path = $child }; continue }
            if (-not (Test-Inside $root $entry.Path)) { throw "Object resolved outside the workspace: $child" }
            if (-not $entry.IsDirectory -and $entry.Links -gt 1) { throw "Hard-linked file requires separate diagnosis: $child" }
            $entries.Add($entry)
            if ($entry.IsDirectory) { $scan.directories++; $pending.Enqueue($entry.Path) } else { $scan.files++ }
        }
    }
    Write-Record 'scan' $scan
    $plans = [System.Collections.Generic.List[object]]::new()
    $states = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $entries) {
        $before = $entry.Read()
        # Every inspected object is validated, not only the ones that need a rebuild: with a valid
        # Low entry present the repair would plan nothing and report a healthy object while the
        # subtree stays unwritable. A refusal here precedes every permission write.
        [DshSubtreeRepair.Security]::ValidateLabelStructure($before, $entry.IsDirectory)
        $facts = Get-Facts $before $WorkspaceSid $entry.IsDirectory
        if (-not $facts.capability) { $observed.missingCapability++ }
        if (-not $facts.lowLabel) { $observed.missingLabel++ }
        $after = $before
        if (-not $facts.capability -or -not $facts.lowLabel) {
            if ($observed.examples.Count -lt $Sample) { $observed.examples += $entry.Path }
            $after = [DshSubtreeRepair.Security]::Plan($before, $WorkspaceSid, $userSid, $entry.IsDirectory)
            $plans.Add([pscustomobject]@{ path = $entry.Path; identity = $entry.Identity; directory = $entry.IsDirectory; before = $before; after = $after })
            Write-Record 'plan' @{ path = $entry.Path; missingCapability = -not $facts.capability; missingLabel = -not $facts.lowLabel }
        }
        $states.Add([pscustomobject]@{ entry = $entry; before = $before; after = $after })
    }
    $actions.planned = $plans.Count
    Write-Record 'observe' $observed
    if ($plans.Count -eq 0) {
        if ($scan.skipped -gt 0) {
            # A skipped object may be exactly where the gap is, and a skipped directory hides its
            # whole subtree, so an incomplete scan cannot conclude that there is no gap.
            $script:verdict = 'SCAN_INCOMPLETE'; $exitCode = 2
            Write-Record 'note' @{ verdict = 'SCAN_INCOMPLETE'; scanSkipped = $scan.skipped
                                   hint = 'stop the processes holding these paths, then run again' }
        } else {
            $script:verdict = 'NO_GAP_FOUND'; $exitCode = 0
        }
    } elseif (-not $PSCmdlet.ShouldProcess("$($plans.Count) objects strictly inside $root", 'back up, add user/workspace permissions and set missing Low labels')) {
        $script:verdict = 'PREVIEW'; $exitCode = 0
    } else {
        $recovery = Join-Path $outRoot "acl-recovery-$runId"
        [void][System.IO.Directory]::CreateDirectory($recovery)
        foreach ($name in @('SubtreeSecurity.cs','Repair.Common.ps1','restore-windows-sandbox-subtree.ps1')) {
            [System.IO.File]::Copy((Join-Path $PSScriptRoot $name), (Join-Path $recovery $name), $false)
        }
        $backupPath = Join-Path $recovery 'backup.json'
        Write-DurableJson $backupPath ([ordered]@{ schema = 1; run = $runId; root = $root; rootIdentity = $rootEntry.Identity; workspaceSid = $WorkspaceSid; userSid = $userSid; objects = @($plans.ToArray()) })
        $restoreFile = (Join-Path $recovery 'restore-windows-sandbox-subtree.ps1').Replace("'", "''")
        $backupArg = $backupPath.Replace("'", "''")
        $rollback = "& '$restoreFile' -Backup '$backupArg'"
        Write-Record 'recovery' @{ backup = $backupPath; rollback = $rollback }
        foreach ($state in $states) {
            if ([DshSubtreeRepair.Security]::Same($state.before, $state.after)) { continue }
            $entry = $state.entry
            # A writable handle needs write-class access on this object, which fails while another
            # process holds it open. That is not a permission problem and does not predict the
            # other objects, so skip this one and keep repairing.
            $currentEntry = $null
            try { $currentEntry = Open-PathChain $entry.Path $handles -Writable }
            catch {
                $code = Get-Win32Code $_.Exception
                if (-not [DshSubtreeRepair.Entry]::IsTransient($code)) { throw }
                [void]$skippedPaths.Add($entry.Path)
                $actions.skipped++
                if ($skippedExamples.Count -lt $Sample) { $skippedExamples.Add($entry.Path) }
                Write-Record 'skip-in-use' @{ path = $entry.Path; win32 = $code; inUse = [DshSubtreeRepair.Entry]::IsInUse($code) }
                continue
            }
            if ($currentEntry.Identity -ne $entry.Identity) { throw "Object changed since inspection: $($entry.Path)" }
            $entry = $currentEntry
            if (-not [DshSubtreeRepair.Security]::Same($entry.Read(), $state.before)) { throw "Permissions changed since inspection: $($entry.Path)" }
            $actions.attempted++; $mutationStarted = $true
            Write-Record 'attempt' @{ path = $entry.Path }
            $daclWritten = $false
            try {
                $entry.SetDacl($state.after)
                $daclWritten = $true
                # Reopen after the user grant so the new handle can acquire WRITE_OWNER.
                $labelEntry = [DshSubtreeRepair.Entry]::Open($entry.Path)
                try {
                    if ($labelEntry.Identity -ne $entry.Identity -or $labelEntry.IsReparse) { throw 'Object identity changed.' }
                    # Windows re-applies the parent's inheritable entries when an unprotected DACL is
                    # written, so the result can hold inherited entries the plan did not predict.
                    # Verify the intent rather than equality with the planned descriptor.
                    if (-not [DshSubtreeRepair.Security]::VerifyDaclIntent($state.before, $state.after, $labelEntry.Read(), $WorkspaceSid, $userSid, $entry.IsDirectory)) { throw "DACL verification failed: $($entry.Path)" }
                    if (-not [DshSubtreeRepair.Security]::SameLabel($state.before, $state.after)) { $labelEntry.SetLabel($state.after) }
                    if (-not [DshSubtreeRepair.Security]::VerifyIntent($state.before, $state.after, $labelEntry.Read(), $WorkspaceSid, $userSid, $entry.IsDirectory)) { throw "Repair verification failed: $($entry.Path)" }
                } finally { $labelEntry.Dispose() }
            } catch {
                # The object was claimed by another process. Before the DACL write nothing on it
                # changed; after that write the object is half-repaired, and a half-repaired object
                # is a partial result this run must report as such rather than as a plain skip.
                $code = Get-Win32Code $_.Exception
                if (-not [DshSubtreeRepair.Entry]::IsTransient($code)) { throw }
                [void]$skippedPaths.Add($entry.Path)
                if ($skippedExamples.Count -lt $Sample) { $skippedExamples.Add($entry.Path) }
                if ($daclWritten) {
                    $actions.partial++
                    $partialPaths.Add($entry.Path)
                    Write-Record 'partial' @{ path = $entry.Path; win32 = $code; wroteDacl = $true; wroteLabel = $false }
                } else {
                    $actions.skipped++
                    Write-Record 'skip-in-use' @{ path = $entry.Path; win32 = $code; inUse = [DshSubtreeRepair.Entry]::IsInUse($code) }
                }
                continue
            }
            $actions.verified++
            Write-Record 'verified' @{ path = $entry.Path }
        }
        if ($actions.attempted -eq 0 -and $actions.skipped -gt 0) {
            $script:verdict = 'REFUSED'; $exitCode = 2
            throw "Every planned object is held open by another process; no permission was changed. Stop the workspace writers and run again."
        }
        $verification.performed = $true
        foreach ($state in $states) {
            if ($skippedPaths.Contains($state.entry.Path)) { continue }
            $actual = $state.entry.Read()
            $facts = Get-Facts $actual $WorkspaceSid $state.entry.IsDirectory
            # Same intent check as the per-object verification. Windows re-applies a parent's
            # inheritable entries when an unprotected DACL is written, so comparing a healthy object
            # with the planned descriptor byte for byte fails on the inherited entry it now carries.
            if (-not [DshSubtreeRepair.Security]::VerifyIntent($state.before, $state.after, $actual, $WorkspaceSid, $userSid, $state.entry.IsDirectory) -or -not $facts.capability -or -not $facts.lowLabel) {
                throw "Final verification failed: $($state.entry.Path)"
            }
            $verification.checked++
        }
        $verification.rootUnchanged = [DshSubtreeRepair.Security]::Same($rootEntry.Read(), $rootBefore)
        if (-not $verification.rootUnchanged) { throw 'The workspace root changed during the run.' }
        if ($actions.partial -gt 0) {
            # Half-repaired objects are neither a failure of the whole run nor a success: every
            # other object was still repaired, and these paths need recovery or a second run.
            $script:verdict = 'REPAIR_PARTIAL'; $script:next = 'stop'; $exitCode = 1
            Write-Record 'note' @{ verdict = 'REPAIR_PARTIAL'; partial = $actions.partial
                                   hint = 'these objects were claimed mid-mutation; inspect details.partiallyWritten and the recovery command' }
        } elseif ($scan.skipped -gt 0 -or $actions.skipped -gt 0) {
            # Everything inspected is repaired, but coverage was incomplete, so the result is not
            # a clean repair.
            $script:verdict = 'REPAIR_PARTIAL'; $script:next = 'stop'; $exitCode = 1
            Write-Record 'note' @{ verdict = 'REPAIR_PARTIAL'; scanSkipped = $scan.skipped; skipped = $actions.skipped
                                   hint = 'these paths were not inspected or not claimed; stop the processes holding them and run again' }
        } else {
            $script:verdict = 'REPAIRED'; $script:next = 'verify_original_confined_operation'; $exitCode = 0
        }
    }
} catch {
    $message = $_.Exception.Message
    $script:refusals.Add($message)
    $script:next = 'stop'
    if ($mutationStarted) { $script:verdict = 'REPAIR_FAILED'; $actions.failed++; $exitCode = 1 }
    try { Write-Record 'refusal' @{ verdict = $script:verdict; reason = $message } } catch { Write-Warning "Report write failed: $($_.Exception.Message)" }
} finally {
    for ($i = $handles.Count - 1; $i -ge 0; $i--) { $handles[$i].Dispose() }
    $recap = [ordered]@{ run = $runId; verdict = $script:verdict; scan = $scan; observed = $observed; actions = $actions; verification = $verification; refusals = @($script:refusals.ToArray()); details = @{ nextAction = $script:next; report = $script:reportPath; backup = $backupPath; rollback = $rollback; skipped = @($skippedExamples.ToArray()); partiallyWritten = @($partialPaths.ToArray()) } }
    $json = $recap | ConvertTo-Json -Compress -Depth 12
    if ($script:reportPath) {
        try { [System.IO.File]::AppendAllText($script:reportPath, $json + "`n") } catch {
            $recap.verdict = 'REPORT_FAILED'; $recap.details.nextAction = 'stop'; $exitCode = 1
            $recap.refusals += "Final report write failed: $($_.Exception.Message)"
            $json = $recap | ConvertTo-Json -Compress -Depth 12
        }
    }
    Write-Output ('RECAP ' + $json)
}
exit $exitCode
