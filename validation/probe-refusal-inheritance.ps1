param([Parameter(Mandatory=$true)][string]$SecuritySource)
$ErrorActionPreference='Stop'
Add-Type -Path $SecuritySource
# This probe allocates security descriptors in process memory only. It does not
# create filesystem objects, set their security, or modify token privileges.
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
$user=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$base="O:${user}G:SYD:(A;OICI;FA;;;$user)"
function Get-EffectivePolicy([string]$Sddl) {
    foreach ($ace in ([System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)).SystemAcl) {
        $bytes=[byte[]]::new($ace.BinaryLength)
        $ace.GetBinaryForm($bytes,0)
        if ($bytes[0] -eq 0x11 -and ($bytes[1] -band 8) -eq 0) { return [BitConverter]::ToInt32($bytes,4) }
    }
    return $null
}
function Inherit-Sddl([string]$Parent,[bool]$Directory) {
    $bytes=[MemoryInheritanceProbe]::Inherit($Parent,$Directory)
    return [DshSubtreeRepair.Security]::Serialize([System.Security.AccessControl.RawSecurityDescriptor]::new($bytes,0))
}
$cases=@(
    @{labels='S:(ML;OICI;NWNRNX;;;ME)';refuse=$false},
    @{labels='S:(ML;;NW;;;ME)(ML;OICIIO;NWNRNX;;;ME)';refuse=$false},
    @{labels='S:(ML;OICINP;NWNRNX;;;ME)';refuse=$true},
    @{labels='S:(ML;OICINPIO;NWNRNX;;;ME)';refuse=$true},
    @{labels='S:(ML;OI;NWNRNX;;;ME)';refuse=$true},
    @{labels='S:(ML;OIIO;NR;;;ME)(ML;CIIO;NX;;;ME)';refuse=$true},
    @{labels='S:(ML;OIIO;NWNRNX;;;LW)(ML;OICI;NW;;;LW)';refuse=$true},
    @{labels='S:(ML;OICINPIO;NWNRNX;;;LW)(ML;OICI;NW;;;LW)';refuse=$true}
)
$results=foreach($case in $cases) {
    $planningError=$null; $planned=$null
    try {$planned=[DshSubtreeRepair.Security]::Plan(($base+$case.labels),'S-1-4-4242-11',$user,$true)}
    catch {$planningError=$_.Exception.GetBaseException().Message}
    if($planningError) {
        [pscustomobject]@{input=$case.labels; expectedRefusal=$case.refuse; refused=$true; reason=$planningError; passed=($case.refuse -and $planningError -like 'A mandatory label*requires separate diagnosis.')}
        continue
    }
    try {
        $child=Inherit-Sddl $planned $true
        $grandFile=Inherit-Sddl $child $false
        $grandDir=Inherit-Sddl $child $true
        $childEffectiveLow=[DshSubtreeRepair.Security]::HasLowLabel($child,$false)
        $childPropagatesLow=[DshSubtreeRepair.Security]::HasLowLabel($child,$true)
        $grandFileLow=[DshSubtreeRepair.Security]::HasLowLabel($grandFile,$false)
        $grandDirLow=[DshSubtreeRepair.Security]::HasLowLabel($grandDir,$true)
        [pscustomobject]@{input=$case.labels; expectedRefusal=$case.refuse; refused=$false; parent=$planned; child=$child; grandFile=$grandFile; grandDir=$grandDir; childEffectiveLow=$childEffectiveLow; childPropagatesLow=$childPropagatesLow; grandFileLow=$grandFileLow; grandDirLow=$grandDirLow; passed=(-not $case.refuse -and $childEffectiveLow -and $childPropagatesLow -and $grandFileLow -and $grandDirLow)}
    } catch {[pscustomobject]@{input=$case.labels; expectedRefusal=$case.refuse; refused=$false; nativeError=$_.Exception.GetBaseException().Message; passed=$false}}
}
[pscustomobject]@{scope='Native memory-only inheritance with expected planning refusals; no filesystem ACL or token privilege changes.'; passed=@($results | Where-Object {$_.passed}).Count; failed=@($results | Where-Object {-not $_.passed}).Count; results=@($results)} | ConvertTo-Json -Depth 7