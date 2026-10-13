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
$rows=foreach($labels in @('S:(ML;OICIIO;NW;;;ME)(ML;OICI;NW;;;LW)','S:(ML;OICIIO;NWNRNX;;;ME)(ML;OICI;NW;;;LW)')) {
    $parent=$base+$labels
    $refusal=$null
    try {[DshSubtreeRepair.Security]::ValidateLabelStructure($parent,$true)}
    catch {$refusal=$_.Exception.GetBaseException().Message}
    $childBytes=[MemoryInheritanceProbe]::Inherit($parent,$true)
    $child=[DshSubtreeRepair.Security]::Serialize([System.Security.AccessControl.RawSecurityDescriptor]::new($childBytes,0))
    $grandBytes=[MemoryInheritanceProbe]::Inherit($child,$true)
    $grand=[DshSubtreeRepair.Security]::Serialize([System.Security.AccessControl.RawSecurityDescriptor]::new($grandBytes,0))
    [pscustomobject]@{input=$labels; currentRootLowCheck=[DshSubtreeRepair.Security]::HasLowLabel($parent,$true); independentValidationRefusal=$refusal; child=$child; childEffectiveLow=[DshSubtreeRepair.Security]::HasLowLabel($child,$false); childPropagatesLow=[DshSubtreeRepair.Security]::HasLowLabel($child,$true); grandchild=$grand; grandchildEffectiveLow=[DshSubtreeRepair.Security]::HasLowLabel($grand,$false)}
}
[pscustomobject]@{scope='Read-only descriptor analysis plus native memory inheritance; no filesystem ACL or token privilege changes.'; cases=@($rows)} | ConvertTo-Json -Depth 6