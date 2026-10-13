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
$results=foreach ($labels in @(
    'S:(ML;OICI;NWNRNX;;;ME)',
    'S:(ML;;NW;;;ME)(ML;OICIIO;NWNRNX;;;ME)',
    'S:(ML;OICINP;NWNRNX;;;ME)',
    'S:(ML;OICINPIO;NWNRNX;;;ME)',
    'S:(ML;OI;NWNRNX;;;ME)',
    'S:(ML;OIIO;NR;;;ME)(ML;CIIO;NX;;;ME)'
)) {
    try {
        $planned=[DshSubtreeRepair.Security]::Plan(($base+$labels),'S-1-4-4242-11',$user,$true)
        $child=Inherit-Sddl $planned $true
        $grandchildFile=Inherit-Sddl $child $false
        $grandchildDirectory=Inherit-Sddl $child $true
        [pscustomobject]@{
            input=$labels
            plannedParent=$planned
            parentPassesFinalCheck=[DshSubtreeRepair.Security]::HasLowLabel($planned,$true)
            childDirectory=$child
            childEffectiveLow=[DshSubtreeRepair.Security]::HasLowLabel($child,$false)
            childPassesSameCheck=[DshSubtreeRepair.Security]::HasLowLabel($child,$true)
            grandchildFile=$grandchildFile
            grandchildFileLow=[DshSubtreeRepair.Security]::HasLowLabel($grandchildFile,$false)
            grandchildDirectory=$grandchildDirectory
            grandchildDirectoryLow=[DshSubtreeRepair.Security]::HasLowLabel($grandchildDirectory,$true)
            error=$null
        }
    } catch { [pscustomobject]@{input=$labels; error=$_.Exception.GetBaseException().Message} }
}
$checks=foreach ($row in $results) {
    [pscustomobject]@{input=$row.input; passed=($null -eq $row.error -and $row.parentPassesFinalCheck -and $row.childPassesSameCheck -and $row.grandchildFileLow -and $row.grandchildDirectoryLow)}
}
[pscustomobject]@{scope='Native Windows descriptor inheritance in memory, two generations; no filesystem ACL writes or token privilege changes.'; passed=@($checks | Where-Object {$_.passed}).Count; failed=@($checks | Where-Object {-not $_.passed}).Count; checks=@($checks); results=@($results)} | ConvertTo-Json -Depth 6