# repair-windows-sandbox-subtree

A skill for Windows agents whose writes fail on **pre-existing** files and directories inside a DSH
workspace, while a write directly in the workspace root still succeeds.

The usual cause is not the DACL alone. A confined child runs at Low integrity, so it needs the object
to carry a Low integrity label as well as the workspace grant. DSH provisions the workspace root;
descendants that already existed when the root was granted keep neither the label nor, sometimes, the
grant. This skill repairs that gap per object, with a backup and a recovery path.

## What it does

- Scans every ordinary file and directory under a workspace root (bounded, default 20000 objects,
  reparse points reported and not followed).
- Plans first, then writes per object: the exact workspace allow entry, a non-inheritable
  permission-management entry (`WRITE_DAC | WRITE_OWNER`) for the signed-in account, and the Low
  no-write-up label the confined child needs.
- Verifies **intent**, not byte equality: Windows re-applies a parent's inheritable entries when an
  unprotected DACL is written, so a written object can legitimately carry inherited entries no plan
  predicted. Verification checks that the intended entries are present, that nothing that existed
  before was lost, and that anything extra is an inherited or deny entry.
- Refuses, before any write, label structures it cannot carry to descendants, and a root that is not
  provisioned.
- Saves full before/after descriptors, copies the recovery script beside the backup, and never
  modifies the workspace root's own entries.

## Requirements

- Windows, local NTFS.
- An **authorized unconfined** command: writing an integrity label needs `WRITE_OWNER`, which a
  confined token does not have. The script refuses a restricted or elevated token.
- A persistent, user-owned recovery directory **outside** the workspace and outside this skill. It
  must exist before the script runs.
- The workspace root must already carry the exact workspace grant and a Low label (this skill repairs
  descendants, not root provisioning; a root that cannot be granted needs separate diagnosis).

## Install

Copy this directory into a skill location your client scans. For DSH:

```powershell
git clone https://github.com/Azzy-H/repair-windows-sandbox-subtree.git "$env:USERPROFILE\.dsh\skills\repair-windows-sandbox-subtree"
```

## Use

```powershell
& "$env:USERPROFILE\.dsh\skills\repair-windows-sandbox-subtree\scripts\repair-windows-sandbox-subtree.ps1" `
    -Path '<workspace-root>' -Out '<existing-recovery-directory>'
exit $LASTEXITCODE
```

`-WhatIf` inspects, plans and writes a report without changing permissions. Read the final `RECAP`
first; `SKILL.md` maps every verdict to the next action.

## The trade-off you inherit

The Low label is what makes an existing object writable for the confined child, and the same label
makes the Shell treat the file as an untrusted source: opening it from Explorer can raise the
Internet-security prompt, and files created inside a labelled directory inherit the label. To open one
file normally, raise just that file back:

```powershell
icacls "<file>" /setintegritylevel Medium
```

The confined child then cannot write that file. Directories stay labelled so newly created paths
remain writable.

## Scope

- Repairs descendants of an already provisioned workspace. Root provisioning failures (for example
  `SetNamedSecurityInfoW failed (Win32 5): grantWrite(<root>)`) are a different problem: the sandbox
  could not write the root's Low label because the root had no explicit entry for the account.
- Does not remove denies, change ownership, widen permissions beyond the exact workspace entry, or
  touch anything outside the given root.
- `CHANGELOG.md` is a development record of the revisions this skill went through; `validation/`
  holds the probes that were used to review it, with their provenance in `validation/README.md`.