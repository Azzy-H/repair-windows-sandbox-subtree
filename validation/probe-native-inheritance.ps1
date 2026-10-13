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
$rows=foreach ($labels in @('S:(ML;OICIIO;NWNRNX;;;ME)','S:(ML;;NW;;;ME)(ML;OICIIO;NWNRNX;;;ME)')) {
    $before=$base+$labels
    $after=[DshSubtreeRepair.Security]::Plan($before,'S-1-4-4242-11',$user,$true)
    # A diagnostic control, not a proposed production fix: retain all generated
    # ACE data but put inherit-only entries first to isolate the ordering effect.
    $controlSd=[System.Security.AccessControl.RawSecurityDescriptor]::new($after)
    $controlAcl=[System.Security.AccessControl.RawAcl]::new(2,$controlSd.SystemAcl.Count)
    $labelAces=@($controlSd.SystemAcl)
    foreach ($inheritOnly in @($true,$false)) {
        foreach ($ace in $labelAces) {
            if ((([int]$ace.AceFlags -band 8) -ne 0) -eq $inheritOnly) { $controlAcl.InsertAce($controlAcl.Count,$ace) }
        }
    }
    $controlSd.SystemAcl=$controlAcl
    $control=[DshSubtreeRepair.Security]::Serialize($controlSd)
    foreach ($directory in @($false,$true)) {
        foreach ($phase in @('before','after','reordered-control')) {
            $parent=if ($phase -eq 'before') {$before} elseif ($phase -eq 'after') {$after} else {$control}
            try {
                $bytes=[MemoryInheritanceProbe]::Inherit($parent,$directory)
                $child=[DshSubtreeRepair.Security]::Serialize([System.Security.AccessControl.RawSecurityDescriptor]::new($bytes,0))
                [pscustomobject]@{input=$labels; phase=$phase; childDirectory=$directory; parentSddl=$parent; childSddl=$child; effectivePolicy=(Get-EffectivePolicy $child); error=$null}
            } catch {
                [pscustomobject]@{input=$labels; phase=$phase; childDirectory=$directory; parentSddl=$parent; childSddl=$null; effectivePolicy=$null; error=$_.Exception.GetBaseException().Message}
            }
        }
    }
}
$checks=foreach ($beforeRow in @($rows | Where-Object {$_.phase -eq 'before'})) {
    $afterRow=$rows | Where-Object {$_.input -eq $beforeRow.input -and $_.childDirectory -eq $beforeRow.childDirectory -and $_.phase -eq 'after'}
    $controlRow=$rows | Where-Object {$_.input -eq $beforeRow.input -and $_.childDirectory -eq $beforeRow.childDirectory -and $_.phase -eq 'reordered-control'}
    [pscustomobject]@{input=$beforeRow.input; childDirectory=$beforeRow.childDirectory; beforePolicy=$beforeRow.effectivePolicy; afterPolicy=$afterRow.effectivePolicy; controlPolicy=$controlRow.effectivePolicy; passed=($null -ne $beforeRow.effectivePolicy -and $null -ne $afterRow.effectivePolicy -and ($beforeRow.effectivePolicy -band $afterRow.effectivePolicy) -eq $beforeRow.effectivePolicy)}
}
[pscustomobject]@{scope='Native Windows CreatePrivateObjectSecurityEx allocates descriptors in memory; no filesystem ACL or token privilege mutations. Reordered output is an isolation control, not a general fix.'; passed=@($checks | Where-Object {$_.passed}).Count; failed=@($checks | Where-Object {-not $_.passed}).Count; checks=@($checks); observations=@($rows)} | ConvertTo-Json -Depth 7
