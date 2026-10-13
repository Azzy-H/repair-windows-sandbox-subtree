# Label-policy regression probe: does Plan() keep the object's existing no-read-up /
# no-execute-up bits when it lowers the level to Low? Usage:
#   powershell -File probe-label.ps1 -SecuritySource <path to SubtreeSecurity.cs>
param([Parameter(Mandatory = $true)][string]$SecuritySource)
$ErrorActionPreference = 'Stop'
Add-Type -Path $SecuritySource
$userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$workspaceSid = 'S-1-4-354330715-528748462'   # any syntactically valid workspace SID
# Owner + canonical DACL + a Medium label carrying NO_WRITE_UP|NO_READ_UP|NO_EXECUTE_UP (mask 7)
$before = 'O:' + $userSid + 'G:' + $userSid + 'D:AI(A;OICI;FA;;;' + $userSid + ')S:(ML;;NWNRNX;;;ME)'
$labelBefore = if ($before -match 'S:\(ML;[^)]*\)') { $Matches[0] } else { '(none)' }
$after = [DshSubtreeRepair.Security]::Plan($before, $workspaceSid, $userSid, $false)
$labelAfter = if ($after -match 'S:\(ML;[^)]*\)') { $Matches[0] } else { '(none)' }
$policyBefore = 0
if ($labelBefore -match 'NW') { $policyBefore = $policyBefore -bor 1 }
if ($labelBefore -match 'NR') { $policyBefore = $policyBefore -bor 2 }
if ($labelBefore -match 'NX') { $policyBefore = $policyBefore -bor 4 }
$policyAfter = 0
if ($labelAfter -match 'NW') { $policyAfter = $policyAfter -bor 1 }
if ($labelAfter -match 'NR') { $policyAfter = $policyAfter -bor 2 }
if ($labelAfter -match 'NX') { $policyAfter = $policyAfter -bor 4 }
$verdict = if ($policyAfter -eq $policyBefore) { 'PRESERVED' } else { 'DROPPED' }
"before: $labelBefore   policy=$policyBefore"
"after : $labelAfter   policy=$policyAfter"
"result: $verdict"
