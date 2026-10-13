# Poisoned-label probe. A directory can carry an effective Low entry AND an inherit-only entry whose
# level is higher; the old health check saw only the effective entry, reported the directory as
# healthy, and every descendant then inherited the higher level. This probe measures the inherited
# descriptors natively — before and after planning — in memory only.
#   pwsh -NoProfile -File probe-poisoned-labels.ps1 -SecuritySource <path to SubtreeSecurity.cs>
param([Parameter(Mandatory = $true)][string]$SecuritySource)
$ErrorActionPreference = 'Stop'
Add-Type -Path $SecuritySource
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
public static class MemoryInheritanceProbe {
    [StructLayout(LayoutKind.Sequential)] struct Mapping { public uint Read,Write,Execute,All; }
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool CreatePrivateObjectSecurityEx(byte[] parent, IntPtr creator, out IntPtr result,
        IntPtr objectType, [MarshalAs(UnmanagedType.Bool)] bool directory, uint flags,
        SafeAccessTokenHandle token, ref Mapping mapping);
    [DllImport("advapi32.dll")] [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool DestroyPrivateObjectSecurity(ref IntPtr descriptor);
    [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    public static byte[] Inherit(string parent, bool directory) {
        var sd=new RawSecurityDescriptor(parent);
        var input=new byte[sd.BinaryLength]; sd.GetBinaryForm(input,0);
        var mapping=new Mapping {Read=0x120089,Write=0x120116,Execute=0x1200A0,All=0x1f01ff};
        IntPtr result;
        using (var id=WindowsIdentity.GetCurrent()) {
            if (!CreatePrivateObjectSecurityEx(input,IntPtr.Zero,out result,IntPtr.Zero,directory,3,id.AccessToken,ref mapping))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        try {
            var bytes=new byte[GetSecurityDescriptorLength(result)];
            Marshal.Copy(result,bytes,0,bytes.Length); return bytes;
        } finally { DestroyPrivateObjectSecurity(ref result); }
    }
}
'@
$userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$workspaceSid = 'S-1-4-354330715-528748462'
$dacl = 'O:' + $userSid + 'G:' + $userSid + 'D:AI(A;OICI;FA;;;' + $userSid + ')'

function Get-Label([string]$Sddl) {
    # A planned descriptor renders as S:(ML;...) and an inherited one as S:AI(ML;...), so match the
    # label entries themselves rather than the section prefix.
    if ($Sddl -match '(\(ML;[^)]*\))+') { return $Matches[0] }
    return '(none)'
}
# Returns the whole inherited descriptor, so it can be inherited from in turn.
function Get-ChildDescriptor([string]$Parent, [bool]$Directory) {
    try {
        $bytes = [MemoryInheritanceProbe]::Inherit($Parent, $Directory)
        return [DshSubtreeRepair.Security]::Serialize([System.Security.AccessControl.RawSecurityDescriptor]::new($bytes, 0))
    } catch { return 'UNAVAILABLE: ' + $_.Exception.GetBaseException().Message }
}

$problems = 0
foreach ($labels in @(
    'S:(ML;OICIIO;NW;;;ME)(ML;OICI;NW;;;LW)',
    'S:(ML;OICIIO;NWNRNX;;;ME)(ML;OICI;NW;;;LW)'
)) {
    $parent = $dacl + $labels
    "== $labels"
    "   health check on the parent (directory) : " + [DshSubtreeRepair.Security]::HasLowLabel($parent, $true)
    $beforeChild = Get-ChildDescriptor $parent $true
    "   child before repair                    : " + (Get-Label $beforeChild)
    $planned = $null
    $planError = $null
    try { $planned = [DshSubtreeRepair.Security]::Plan($parent, $workspaceSid, $userSid, $true) } catch { $planError = $_.Exception.GetBaseException().Message }
    if ($planError) { "   planning REFUSED: $planError"; $problems++; continue }
    "   health check on the planned result     : " + [DshSubtreeRepair.Security]::HasLowLabel($planned, $true)
    "   planned label                          : " + (Get-Label $planned)
    $child = Get-ChildDescriptor $planned $true
    $childFile = Get-ChildDescriptor $planned $false
    $grandchild = if ($child -like 'UNAVAILABLE*') { $child } else { Get-ChildDescriptor $child $true }
    "   child directory after repair           : " + (Get-Label $child)
    "   child file after repair                : " + (Get-Label $childFile)
    "   grandchild directory after repair      : " + (Get-Label $grandchild)
    $ok = ($child -match ';;;LW\)') -and ($childFile -match ';;;LW\)') -and ($grandchild -match ';;;LW\)')
    if ($ok) { '   -> descendants are Low after repair' } else { '   -> DESCENDANTS NOT LOW AFTER REPAIR'; $problems++ }
}
"PROBLEM CASES: $problems"
