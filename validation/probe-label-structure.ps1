# Structure validation probe. The repair refuses label structures it cannot carry to descendants.
# A valid Low entry in the same ACL hides such a structure from the "does this object need a label
# rebuild" question, so the repair validates every inspected directory instead of only the ones it
# plans to change. This probe shows both halves: Plan alone accepts the structure, the dedicated
# validation refuses it.
#   pwsh -NoProfile -File probe-label-structure.ps1 -SecuritySource <path to SubtreeSecurity.cs>
param([Parameter(Mandatory = $true)][string]$SecuritySource)
$ErrorActionPreference = 'Stop'
Add-Type -Path $SecuritySource
$userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$workspaceSid = 'S-1-4-354330715-528748462'
$dacl = 'O:' + $userSid + 'G:' + $userSid + 'D:AI(A;OICI;FA;;;' + $userSid + ')'

$hidden = @(
    'S:(ML;OIIO;NWNRNX;;;LW)(ML;OICI;NW;;;LW)',          # one-sided inherit-only entry, already Low
    'S:(ML;OICINPIO;NWNRNX;;;LW)(ML;OICI;NW;;;LW)'       # stops propagating, already Low
)
$supported = @(
    'S:(ML;;NW;;;LW)',                                    # effective only
    'S:(ML;OICIIO;NWNRNX;;;LW)(ML;OICI;NW;;;LW)'          # inherit-only plus effective, both Low
)

$problems = 0
'--- structures a valid Low entry would hide ---'
foreach ($labels in $hidden) {
    $sd = $dacl + $labels
    $planOutcome = 'planned'
    try { [void][DshSubtreeRepair.Security]::Plan($sd, $workspaceSid, $userSid, $true) }
    catch { $planOutcome = 'refused' }
    $checkOutcome = 'MISSED'
    try { [DshSubtreeRepair.Security]::ValidateLabelStructure($sd, $true) }
    catch { $checkOutcome = 'refused: ' + $_.Exception.GetBaseException().Message }
    if ($checkOutcome -eq 'MISSED') { $problems++ }
    if ($planOutcome -ne 'planned') { '   note: Plan refused this structure too' }
    "  $labels"
    "     Plan alone: $planOutcome    ValidateLabelStructure: $checkOutcome"
}
'--- supported structures stay accepted ---'
foreach ($labels in $supported) {
    $sd = $dacl + $labels
    $checkOutcome = 'accepted'
    try { [DshSubtreeRepair.Security]::ValidateLabelStructure($sd, $true) }
    catch { $checkOutcome = 'REFUSED: ' + $_.Exception.GetBaseException().Message; $problems++ }
    "  $labels   -> $checkOutcome"
}
'--- a file is not validated: it has no descendants ---'
try { [DshSubtreeRepair.Security]::ValidateLabelStructure(($dacl + $hidden[0]), $false); '  file -> accepted' }
catch { '  file -> REFUSED (unexpected)'; $problems++ }
"PROBLEM CASES: $problems"
