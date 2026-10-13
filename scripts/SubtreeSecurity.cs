using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace DshSubtreeRepair {
    // Every write uses a MAXIMUM_ALLOWED handle. SetSecurityInfo then does not
    // propagate inheritable ACEs to existing children; traversal belongs to the caller.
    // https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
    public sealed class Entry : IDisposable {
        public string Path { get; private set; }
        public string Identity { get; private set; }
        public bool IsDirectory { get; private set; }
        public bool IsReparse { get; private set; }
        public uint Links { get; private set; }
        private SafeFileHandle handle;
        private bool writable;
        private Entry(SafeFileHandle value, bool maximumAllowed) { handle = value; writable = maximumAllowed; }

        public static Entry Open(string path) { return OpenPath(path, true); }
        public static Entry Inspect(string path) { return OpenPath(path, false); }
        private static Entry OpenPath(string path, bool maximumAllowed) {
            var h = Native.CreateFileW(path, maximumAllowed ? 0x02000000u : 0x00020080u, 7, IntPtr.Zero, 3,
                0x02200000, IntPtr.Zero); // BACKUP_SEMANTICS + OPEN_REPARSE_POINT
            if (h.IsInvalid) { var error = Native.Error("open", path); h.Dispose(); throw error; }
            var item = new Entry(h, maximumAllowed);
            try {
                Native.FileInfo info;
                if (!Native.GetFileInformationByHandle(h, out info)) throw Native.Error("identity", path);
                var text = new StringBuilder(32768);
                uint size = Native.GetFinalPathNameByHandleW(h, text, (uint)text.Capacity, 0);
                if (size == 0 || size >= text.Capacity) throw Native.Error("canonical path", path);
                string final = text.ToString();
                if (!final.StartsWith(@"\\?\", StringComparison.Ordinal) || final.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Only local drive paths are supported: " + path);
                item.Path = final.Substring(4).TrimEnd('\\');
                item.Identity = info.Volume.ToString("X8") + ":" + info.IndexHigh.ToString("X8") + info.IndexLow.ToString("X8");
                item.IsDirectory = (info.Attributes & 0x10) != 0;
                item.IsReparse = (info.Attributes & 0x400) != 0;
                item.Links = info.Links;
                return item;
            } catch { item.Dispose(); throw; }
        }

        public string Read() {
            IntPtr owner, group, dacl, sacl, descriptor;
            uint status = Native.GetSecurityInfo(handle, 1, 0x17, out owner, out group, out dacl, out sacl, out descriptor);
            Native.Check(status, "read security", Path);
            try {
                int size = checked((int)Native.GetSecurityDescriptorLength(descriptor));
                var bytes = new byte[size];
                Marshal.Copy(descriptor, bytes, 0, size);
                return Security.Serialize(new RawSecurityDescriptor(bytes, 0));
            } finally { Native.LocalFree(descriptor); }
        }

        public void SetDacl(string sddl) {
            CheckTarget();
            var sd = new RawSecurityDescriptor(sddl);
            if (sd.DiscretionaryAcl == null) throw new IOException("Refusing a null DACL: " + Path);
            Native.Check(Native.SetSecurityInfo(handle, 1, 4, IntPtr.Zero, IntPtr.Zero,
                Security.AclBytes(sd.DiscretionaryAcl), null), "write DACL", Path);
        }

        public void SetLabel(string sddl) {
            CheckTarget();
            var sd = new RawSecurityDescriptor(sddl);
            // An empty label ACL removes a label added to an originally unlabeled object.
            byte[] label = Security.AclBytes(sd.SystemAcl ?? new RawAcl(2, 0));
            Native.Check(Native.SetSecurityInfo(handle, 1, 0x10, IntPtr.Zero, IntPtr.Zero,
                null, label), "write label", Path);
        }

        private void CheckTarget() {
            if (!writable) throw new IOException("An inspection handle cannot modify permissions.");
            Native.FileInfo info;
            if (!Native.GetFileInformationByHandle(handle, out info)) throw Native.Error("check identity", Path);
            if ((info.Attributes & 0x400) != 0 || (!IsDirectory && info.Links > 1))
                throw new IOException("Object became a reparse point or acquired another hard link: " + Path);
            var text = new StringBuilder(32768);
            uint count = Native.GetFinalPathNameByHandleW(handle, text, (uint)text.Capacity, 0);
            if (count == 0 || count >= text.Capacity || !String.Equals(text.ToString(), @"\\?\" + Path, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Object moved since inspection: " + Path);
        }

        // Inspection opens read-class; a maximum-allowed handle is opened only when the object is
        // about to be changed. Requesting write-class access on every object fails with a sharing
        // violation wherever another process holds the object open, which is not a permission
        // problem. Errors are returned so the caller can separate that case from a missing right.
        public static bool TryInspect(string path, out Entry entry, out int error) {
            try { entry = Inspect(path); error = 0; return true; }
            catch (Win32Exception failure) { entry = null; error = failure.NativeErrorCode; return false; }
        }
        public static bool TryOpen(string path, out Entry entry, out int error) {
            try { entry = Open(path); error = 0; return true; }
            catch (Win32Exception failure) { entry = null; error = failure.NativeErrorCode; return false; }
        }
        /** ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION: another process holds the object open. */
        public static bool IsInUse(int error) { return error == 32 || error == 33; }
        /** In use, or gone between enumeration and inspection: not repairable in this run. */
        public static bool IsTransient(int error) { return IsInUse(error) || error == 2 || error == 3; }

        public void Dispose() { if (handle != null) { handle.Dispose(); handle = null; } }
    }

    public static class Security {
        public const int GrantMask = 0x00110156; // DSH win32-abi.ts GRANT_MASK
        public const int FullControl = 0x001F01FF;
        public const int ManagementMask = 0x000C0000; // WRITE_DAC | WRITE_OWNER, never DELETE_CHILD
        public static byte[] AclBytes(GenericAcl acl) {
            var bytes = new byte[acl.BinaryLength]; acl.GetBinaryForm(bytes, 0); return bytes;
        }
        public static string Serialize(RawSecurityDescriptor sd) {
            var bytes = new byte[sd.BinaryLength]; sd.GetBinaryForm(bytes, 0);
            IntPtr text; uint length;
            // .NET GetSddlForm(All) asks for SACL_SECURITY_INFORMATION, which omits
            // mandatory labels. Request LABEL_SECURITY_INFORMATION explicitly.
            if (!Native.ConvertSecurityDescriptorToStringSecurityDescriptorW(bytes, 1, 0x17, out text, out length))
                throw Native.Error("serialize security", "descriptor");
            try { return Marshal.PtrToStringUni(text); } finally { Native.LocalFree(text); }
        }
        public static string WorkspaceSid(string canonicalRoot) {
            using (var sha = SHA256.Create()) {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(canonicalRoot));
                return "S-1-4-" + ((BitConverter.ToUInt32(hash, 0) % 1073741823u) + 1u) + "-" +
                    ((BitConverter.ToUInt32(hash, 4) % 1073741823u) + 1u);
            }
        }
        private static int ExpandMask(int mask) {
            uint bits = unchecked((uint)mask);
            int result = mask & 0x0FFFFFFF;
            if ((bits & 0x10000000) != 0) result |= FullControl;
            if ((bits & 0x40000000) != 0) result |= 0x120116;
            if ((bits & 0x80000000) != 0) result |= 0x120089;
            if ((bits & 0x20000000) != 0) result |= 0x1200A0;
            return result;
        }
        public static bool HasGrant(string sddl, string sid, int required, bool inheritable) {
            var acl = new RawSecurityDescriptor(sddl).DiscretionaryAcl;
            if (acl == null) return false;
            int allowed = 0;
            foreach (GenericAce raw in acl) {
                var ace = raw as CommonAce;
                if (ace == null || ace.IsCallback || ace.SecurityIdentifier.Value != sid ||
                    (ace.AceFlags & AceFlags.InheritOnly) != 0) continue;
                if (inheritable && ((ace.AceFlags & (AceFlags.ObjectInherit | AceFlags.ContainerInherit)) !=
                    (AceFlags.ObjectInherit | AceFlags.ContainerInherit) || (ace.AceFlags & AceFlags.NoPropagateInherit) != 0)) continue;
                if (ace.AceQualifier == AceQualifier.AccessAllowed) allowed |= ExpandMask(ace.AccessMask);
            }
            return (allowed & required) == required;
        }
        // For a directory (inheritable: true) this answers what the repair actually needs: will this
        // object AND the entries it passes on both stay Low? One effective Low entry is not enough,
        // because another entry can carry a higher level to the descendants that inherit it, so every
        // entry that reaches descendants must be Low with NO_WRITE_UP as well. Files pass nothing on.
        public static bool HasLowLabel(string sddl, bool inheritable) {
            var acl = new RawSecurityDescriptor(sddl).SystemAcl;
            if (acl == null) return false;
            bool found = false;
            foreach (GenericAce ace in acl) {
                byte[] bytes = new byte[ace.BinaryLength]; ace.GetBinaryForm(bytes, 0);
                if (bytes[0] != 0x11 || (bytes[1] & 8) != 0) continue;
                string sid = new SecurityIdentifier(bytes, 8).Value;
                if (!sid.StartsWith("S-1-16-", StringComparison.Ordinal)) return false;
                uint level = uint.Parse(sid.Substring(7), System.Globalization.CultureInfo.InvariantCulture);
                if (level > 4096 || (BitConverter.ToInt32(bytes, 4) & 1) == 0) return false;
                if (inheritable && ((bytes[1] & 3) != 3 || (bytes[1] & 4) != 0)) continue;
                found = true;
            }
            if (!found || !inheritable) return found;
            foreach (GenericAce ace in acl) {
                byte[] bytes = new byte[ace.BinaryLength]; ace.GetBinaryForm(bytes, 0);
                if (bytes[0] != 0x11 || (bytes[1] & 3) == 0) continue;
                string sid = new SecurityIdentifier(bytes, 8).Value;
                if (!sid.StartsWith("S-1-16-", StringComparison.Ordinal)) return false;
                uint level = uint.Parse(sid.Substring(7), System.Globalization.CultureInfo.InvariantCulture);
                if (level > 4096 || (BitConverter.ToInt32(bytes, 4) & 1) == 0) return false;
            }
            return true;
        }
        private static void AddAllow(RawSecurityDescriptor sd, string sid, int mask, bool directory) {
            if (sd.DiscretionaryAcl == null) throw new IOException("Refusing to replace a null DACL.");
            if (HasGrant(Serialize(sd), sid, mask, directory)) return;
            int index = 0;
            while (index < sd.DiscretionaryAcl.Count && (sd.DiscretionaryAcl[index].AceFlags & AceFlags.Inherited) == 0) index++;
            sd.DiscretionaryAcl.InsertAce(index, new CommonAce(directory ? AceFlags.ObjectInherit | AceFlags.ContainerInherit : AceFlags.None,
                AceQualifier.AccessAllowed, mask, new SecurityIdentifier(sid), false, null));
        }
        // A label carries the integrity level and the no-read-up / no-execute-up policy bits.
        // A label ACL can carry more than one mandatory-label ACE: an inherit-only entry applies to
        // the descendants that inherit it, an effective one applies to this object. Lowering the
        // level must keep every entry's policy bits and inheritance flags, and must leave this
        // object with an effective Low label of its own, so the entries are rebuilt one by one
        // rather than collapsed into a single ACE.
        // Windows gives a child the first label entry that lands there and drops the rest, so an
        // entry that stops propagating, or that covers only files or only containers, either blocks
        // an appended Low label or leaves the next generation unlabelled. Those structures are
        // refused before any permission is written: carrying them would need per-case verification
        // across two generations. Callers validate every inspected directory, not only the ones that
        // need a label rebuilt, because a valid Low entry would otherwise hide the structure.
        public static void ValidateLabelStructure(string before, bool directory) {
            if (!directory) return;
            var acl = new RawSecurityDescriptor(before).SystemAcl;
            if (acl == null) return;
            foreach (GenericAce raw in acl) {
                byte[] bytes = new byte[raw.BinaryLength]; raw.GetBinaryForm(bytes, 0);
                if (bytes[0] != 0x11) continue;
                if ((bytes[1] & 4) != 0) {
                    throw new IOException("A mandatory label that stops propagating (NP) requires separate diagnosis.");
                }
                if (((bytes[1] & 1) != 0) != ((bytes[1] & 2) != 0)) {
                    throw new IOException("A mandatory label that covers only files or only containers requires separate diagnosis.");
                }
            }
        }
        private static string LabelSddl(string before, bool directory) {
            ValidateLabelStructure(before, directory);
            var parts = new List<string>();
            bool effective = false;
            bool effectiveInheritable = false;
            var acl = new RawSecurityDescriptor(before).SystemAcl;
            if (acl != null) {
                foreach (GenericAce raw in acl) {
                    byte[] bytes = new byte[raw.BinaryLength]; raw.GetBinaryForm(bytes, 0);
                    if (bytes[0] != 0x11) continue;
                    bool inheritOnly = (bytes[1] & 8) != 0;
                    if (!inheritOnly) {
                        if (effective) throw new IOException("Multiple mandatory labels require separate diagnosis.");
                        effective = true;
                        effectiveInheritable = (bytes[1] & 3) == 3 && (bytes[1] & 4) == 0;
                    }
                    // Every entry keeps its own inheritance flags and policy bits; only the level
                    // changes. Widening an entry in place would be a change of inheritance range.
                    parts.Add("(ML;" + AceFlagsText(bytes[1]) + (inheritOnly ? "IO" : "") + ";" +
                        MaskText((BitConverter.ToInt32(bytes, 4) & 7) | 1) + ";;;LW)");
                }
            }
            // Windows resolves a child's effective label from the first inherited label entry, so an
            // entry widened in place would shadow the policy an inherit-only entry carries to
            // descendants. When this object still needs an inheritable Low label of its own, it is
            // appended after every existing entry, where it cannot change what is already inherited.
            if (!effective) parts.Add("(ML;" + (directory ? "OICI" : "") + ";NW;;;LW)");
            else if (directory && !effectiveInheritable) parts.Add("(ML;OICI;NW;;;LW)");
            return "S:" + string.Join("", parts);
        }
        private static string MaskText(int policy) {
            var mask = new StringBuilder();
            if ((policy & 1) != 0) mask.Append("NW");
            if ((policy & 2) != 0) mask.Append("NR");
            if ((policy & 4) != 0) mask.Append("NX");
            return mask.ToString();
        }
        private static string AceFlagsText(byte aceFlags) {
            var flags = new StringBuilder();
            if ((aceFlags & 1) != 0) flags.Append("OI");
            if ((aceFlags & 2) != 0) flags.Append("CI");
            if ((aceFlags & 4) != 0) flags.Append("NP");
            return flags.ToString();
        }
        public static string Plan(string before, string workspaceSid, string userSid, bool directory) {
            var sd = new RawSecurityDescriptor(before);
            // Validated here as well as per object by the repair, so a caller that plans a single
            // object cannot skip the structure check just because a valid Low entry is present.
            ValidateLabelStructure(before, directory);
            if (sd.Owner == null || sd.Owner.Value != userSid) throw new IOException("The object is not owned by the signed-in user.");
            if (sd.DiscretionaryAcl == null) throw new IOException("Null DACL requires separate diagnosis.");
            var common = new CommonSecurityDescriptor(directory, false, sd);
            if (!common.IsDiscretionaryAclCanonical) throw new IOException("Noncanonical DACL requires separate diagnosis.");
            // An explicit FullControl user ACE could outrank the inherited Everyone
            // DELETE_CHILD deny used by DSH. Add only the rights this repair needs.
            AddAllow(sd, userSid, ManagementMask, false);
            AddAllow(sd, workspaceSid, GrantMask, directory);
            if (!HasLowLabel(before, directory)) {
                sd.SystemAcl = new RawSecurityDescriptor(LabelSddl(before, directory)).SystemAcl;
                sd.SetFlags(sd.ControlFlags | ControlFlags.SystemAclPresent);
            }
            return Serialize(sd);
        }
        public static string WithDacl(string labelsFrom, string daclFrom) {
            var sd = new RawSecurityDescriptor(labelsFrom);
            sd.DiscretionaryAcl = new RawSecurityDescriptor(daclFrom).DiscretionaryAcl;
            return Serialize(sd);
        }
        // Compare the sections this tool can modify, plus owner/group and protection.
        // AUTO_INHERITED bookkeeping bits are not permissions and can be normalized by Windows.
        public static bool Same(string left, string right) {
            var a = new RawSecurityDescriptor(left); var b = new RawSecurityDescriptor(right);
            return String.Equals(a.Owner == null ? null : a.Owner.Value, b.Owner == null ? null : b.Owner.Value, StringComparison.Ordinal) &&
                String.Equals(a.Group == null ? null : a.Group.Value, b.Group == null ? null : b.Group.Value, StringComparison.Ordinal) &&
                ((a.ControlFlags ^ b.ControlFlags) & (ControlFlags.DiscretionaryAclProtected | ControlFlags.SystemAclProtected)) == 0 &&
                EqualAcl(a.DiscretionaryAcl, b.DiscretionaryAcl, false) && EqualAcl(a.SystemAcl, b.SystemAcl, true);
        }
        public static bool SameLabel(string left, string right) {
            return EqualAcl(new RawSecurityDescriptor(left).SystemAcl, new RawSecurityDescriptor(right).SystemAcl, true);
        }
        // Windows re-applies a parent's inheritable entries to an object whose DACL is written while
        // unprotected, so the written result can hold inherited entries the plan did not predict.
        // Observed on the first real directory: an inherited workspace grant and an inherited deny
        // appeared that the planned descriptor did not contain, and equality with the plan failed the
        // run. Verification therefore checks the intent: the entries this repair adds must be present,
        // no entry that existed before may be lost, no protection flag may change, and every entry
        // that was in neither the before state nor the plan must be inherited or a deny.
        public static bool VerifyDaclIntent(string before, string planned, string actual, string workspaceSid, string userSid, bool directory) {
            var b = new RawSecurityDescriptor(before);
            var p = new RawSecurityDescriptor(planned);
            var a = new RawSecurityDescriptor(actual);
            if (b.Owner == null || a.Owner == null || b.Owner.Value != a.Owner.Value) return false;
            if (!String.Equals(b.Group == null ? null : b.Group.Value, a.Group == null ? null : a.Group.Value, StringComparison.Ordinal)) return false;
            if (((a.ControlFlags ^ p.ControlFlags) & (ControlFlags.DiscretionaryAclProtected | ControlFlags.SystemAclProtected)) != 0) return false;
            if (!HasGrant(actual, workspaceSid, GrantMask, directory)) return false;
            if (!HasGrant(actual, userSid, ManagementMask, false)) return false;
            var actualAces = Aces(a.DiscretionaryAcl);
            var beforeAces = Aces(b.DiscretionaryAcl);
            foreach (var ace in beforeAces) if (!ContainsAce(actualAces, ace)) return false;
            var plannedAces = Aces(p.DiscretionaryAcl);
            foreach (var ace in actualAces) {
                if (ContainsAce(beforeAces, ace) || ContainsAce(plannedAces, ace)) continue;
                if ((ace.AceFlags & AceFlags.Inherited) == 0 && ace.AceType != AceType.AccessDenied) return false;
            }
            return true;
        }
        // The post-condition the repair promises for an object: the DACL intent above, plus the label
        // the confined child needs. HasLowLabel is the predicate every caller uses, so a directory is
        // accepted only when its descendants stay Low as well.
        public static bool VerifyIntent(string before, string planned, string actual, string workspaceSid, string userSid, bool directory) {
            return VerifyDaclIntent(before, planned, actual, workspaceSid, userSid, directory) && HasLowLabel(actual, directory);
        }
        // Recovery writes the recorded before state back, and that write can be re-applied with the
        // parent's inheritable entries as well. The restored object is accepted when every recorded
        // entry is present, the label matches the record, and the only extra entries are inherited or
        // deny entries — the same bookkeeping Windows adds on any unprotected DACL write.
        public static bool VerifyRestoredIntent(string before, string actual) {
            var b = new RawSecurityDescriptor(before);
            var a = new RawSecurityDescriptor(actual);
            if (b.Owner == null || a.Owner == null || b.Owner.Value != a.Owner.Value) return false;
            if (!String.Equals(b.Group == null ? null : b.Group.Value, a.Group == null ? null : a.Group.Value, StringComparison.Ordinal)) return false;
            if (!SameLabel(before, actual)) return false;
            var actualAces = Aces(a.DiscretionaryAcl);
            var beforeAces = Aces(b.DiscretionaryAcl);
            foreach (var ace in beforeAces) if (!ContainsAce(actualAces, ace)) return false;
            foreach (var ace in actualAces) {
                if (ContainsAce(beforeAces, ace)) continue;
                if ((ace.AceFlags & AceFlags.Inherited) == 0 && ace.AceType != AceType.AccessDenied) return false;
            }
            return true;
        }
        private static List<GenericAce> Aces(RawAcl acl) {
            var list = new List<GenericAce>();
            if (acl == null) return list;
            foreach (GenericAce ace in acl) list.Add(ace);
            return list;
        }        // INHERITED_ACE is bookkeeping Windows rewrites while re-applying inheritance; the ACE type,
        // the inheritance flags and the access mask are the permission. Compare those, and the SID.
        private static bool ContainsAce(List<GenericAce> aces, GenericAce candidate) {
            var common = candidate as CommonAce;
            var wantFlags = candidate.AceFlags & ~AceFlags.Inherited;
            foreach (var ace in aces) {
                if (ace.AceType != candidate.AceType || (ace.AceFlags & ~AceFlags.Inherited) != wantFlags) continue;
                if (common == null) return true;
                var other = ace as CommonAce;
                if (other != null && other.AccessMask == common.AccessMask &&
                    other.SecurityIdentifier.Value == common.SecurityIdentifier.Value) return true;
            }
            return false;
        }
        private static bool EqualAcl(RawAcl a, RawAcl b, bool emptyEqualsNull) {
            if (emptyEqualsNull && (a == null || a.Count == 0) && (b == null || b.Count == 0)) return true;
            if (a == null || b == null) return a == b;
            return Convert.ToBase64String(AclBytes(a)) == Convert.ToBase64String(AclBytes(b));
        }
        public static bool IsElevated() {
            using (var id = WindowsIdentity.GetCurrent()) return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        public static bool IsRestricted() {
            using (var id = WindowsIdentity.GetCurrent()) return Native.IsTokenRestricted(id.AccessToken);
        }
    }

    internal static class Native {
        [StructLayout(LayoutKind.Sequential)] internal struct FileInfo {
            internal uint Attributes;
            internal System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
            internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        internal static Exception Error(string action, string path) { return new Win32Exception(Marshal.GetLastWin32Error(), action + ": " + path); }
        internal static void Check(uint status, string action, string path) { if (status != 0) throw new Win32Exception((int)status, action + ": " + path); }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
        [DllImport("advapi32.dll")] internal static extern uint GetSecurityInfo(SafeFileHandle handle, int type, uint flags, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll")] internal static extern uint SetSecurityInfo(SafeFileHandle handle, int type, uint flags, IntPtr owner, IntPtr group, byte[] dacl, byte[] sacl);
        [DllImport("advapi32.dll")] internal static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(byte[] descriptor, uint revision, uint flags, out IntPtr text, out uint length);
        [DllImport("advapi32.dll")] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool IsTokenRestricted(SafeAccessTokenHandle token);
        [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr memory);
    }
}
