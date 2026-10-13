# Label-planning probe. For each input descriptor it prints the label before and after
# Security.Plan, and whether the policy bits (NO_WRITE_UP | NO_READ_UP | NO_EXECUTE_UP) and the
# inheritance flags survived. Usage:
#   pwsh -NoProfile -File probe-label.ps1 -SecuritySource <path to SubtreeSecurity.cs>
param([Parameter(Mandatory = $true)][string]$SecuritySource)
$ErrorActionPreference = 'Stop'
Add-Type -Path $SecuritySource
$userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$workspaceSid = 'S-1-4-354330715-528748462'
$dacl = 'O:' + $userSid + 'G:' + $userSid + 'D:AI(A;OICI;FA;;;' + $userSid + ')'

function Get-Label([string]$sddl) {
    if ($sddl -match 'S:(\(ML;[^)]*\))+') { return $Matches[0] }
    return '(none)'
}
function Get-Policy([string]$label) {
    $bits = 0
    if ($label -match 'NW') { $bits = $bits -bor 1 }
    if ($label -match 'NR') { $bits = $bits -bor 2 }
    if ($label -match 'NX') { $bits = $bits -bor 4 }
    return $bits
}
function Get-LabelCount([string]$label) { return ([regex]::Matches($label, '\(ML;')).Count }

$cases = [ordered]@{
    'file, no label'                    = @{ dir = $false; label = '' }
    'file, Medium NW+NR+NX'             = @{ dir = $false; label = 'S:(ML;;NWNRNX;;;ME)' }
    'dir, Medium NW+NR+NX'              = @{ dir = $true;  label = 'S:(ML;;NWNRNX;;;ME)' }
    'dir, inherit-only Medium NW+NR+NX' = @{ dir = $true;  label = 'S:(ML;OICIIO;NWNRNX;;;ME)' }
    'dir, effective + inherit-only'     = @{ dir = $true;  label = 'S:(ML;;NW;;;ME)(ML;OICIIO;NWNRNX;;;ME)' }
    'dir, already Low NW'               = @{ dir = $true;  label = 'S:(ML;OICI;NW;;;LW)' }
    # Structures the repair refuses: an entry that stops propagating, or that lands on only one
    # kind of child, keeps the appended Low label out of the next generation (measured with the
    # reviewer's native two-generation probe).
    'dir, files-only (OI) - refused'              = @{ dir = $true; label = 'S:(ML;OI;NWNRNX;;;ME)'; refused = $true }
    'dir, no-propagate (NP) - refused'            = @{ dir = $true; label = 'S:(ML;OICINP;NWNRNX;;;ME)'; refused = $true }
    'dir, NP + inherit-only - refused'            = @{ dir = $true; label = 'S:(ML;OICINPIO;NWNRNX;;;ME)'; refused = $true }
    'dir, two one-sided inherit-only - refused'   = @{ dir = $true; label = 'S:(ML;OIIO;NR;;;ME)(ML;CIIO;NX;;;ME)'; refused = $true }
}

$problems = 0
foreach ($name in $cases.Keys) {
    $case = $cases[$name]
    $before = $dacl + $case.label
    $labelBefore = Get-Label $before
    $result = $null
    $errorText = $null
    try { $result = [DshSubtreeRepair.Security]::Plan($before, $workspaceSid, $userSid, [bool]$case.dir) }
    catch { $errorText = $_.Exception.Message }
    if ($errorText) {
        "== $name"
        "   REFUSED: $errorText"
        if (-not $case.refused) { $problems++ }
        continue
    }
    if ($case.refused) {
        "== $name"
        "   EXPECTED A REFUSAL BUT PLANNED: $result"
        $problems++
        continue
    }
    $labelAfter = Get-Label $result
    $policyBefore = Get-Policy $labelBefore
    $policyAfter = Get-Policy $labelAfter
    $lost = $policyBefore -band (-bnot $policyAfter)
    $kept = if ($lost -eq 0) { 'policy kept' } else { "POLICY LOST ($lost)" }
    if ($lost -ne 0) { $problems++ }
    "== $name"
    "   before: $labelBefore   (policy $policyBefore, labelAces $(Get-LabelCount $labelBefore))"
    "   after : $labelAfter   (policy $policyAfter, labelAces $(Get-LabelCount $labelAfter))"
    "   $kept"
}
"PROBLEM CASES: $problems"
