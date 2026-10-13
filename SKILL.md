---
name: repair-windows-sandbox-subtree
description: Diagnose and repair missing Windows sandbox permissions on pre-existing files and directories inside a DSH workspace when the root is writable under workspace-write but descendants are denied. Requires an authorized unconfined command and creates persistent recovery files before modifying permissions.
whenToUse: A DSH workspace-write operation fails on an existing descendant while a write directly in the workspace root succeeds.
---

# Repair Windows sandbox subtree permissions

Use this skill only for unexpected denials inside an already provisioned DSH workspace on local NTFS. Writes outside the workspace, read-only sessions, and an unwritable workspace root require separate diagnosis. Repeat the original failed operation once in confinement to confirm the symptom.

## Run one bounded repair

Stop processes that create, move, delete, or change permissions in the workspace while repairing or restoring. Determine the actual workspace root from the failing session. Never substitute a deeper directory, a volume root, the user profile root, the Windows directory, or a broader ancestor.

Create a persistent, user-owned recovery directory outside both the workspace and this skill's resource directory. It must already exist when the script starts. Keep it until the user no longer needs rollback.

```powershell
& '<skill-directory>\scripts\repair-windows-sandbox-subtree.ps1' -Path '<workspace-root>' -Out '<existing-recovery-directory>'
exit $LASTEXITCODE
```

Use full quoted paths. Run the repair as the signed-in user through the host's supported approval mechanism for one unconfined command. Do not elevate through UAC, runas, or administrator credentials. If that execution permission is unavailable or refused, stop and report the limitation. Do not automatically switch the whole session to full access.

Write any required approval request in the user's language. State the exact workspace, the recovery directory, the permissions being added, and the limitations of recovery. For example:

> 这条命令会检查 `<工作区>` 内已有的文件和子文件夹，给缺少权限的对象补上当前工作区的写入授权、你账号更改权限和标记所需的权限，以及沙箱需要的低完整性标记。它不修改工作区根目录、文件内容或所有者，也不删除拒绝项。首次修改前会把备份和恢复脚本保存到 `<恢复目录>`；恢复时会检查对象和权限是否被后续操作改变，发现冲突就停止。文件多时可能要几分钟。

Existing authorization can cover this invocation; do not ask for redundant confirmation. Never execute a permission change merely to review this skill.

## Scope and checks

- Every discovered ordinary file and directory is inspected. `-Limit` defaults to 20000 descendants; exceeding it refuses the entire repair before any permission changes. `-Sample` limits example paths in the recap, not inspection or verification.
- Reparse points are reported and not followed. Reparse ancestors, hard-linked files, unsupported filesystems, noncanonical DACLs on repair candidates, and repair candidates owned by another user cause a refusal before mutation.
- Inspection opens every object read-class; a write-class handle is requested only for an object about to be changed. An object another process holds open, or one that disappears during the run, is reported and skipped instead of ending the run: it is neither a permission problem nor a predictor for the other objects. A target claimed *after* its DACL write is a partial result, not a skip: the run continues, then reports `REPAIR_PARTIAL` and exits nonzero. When every planned object was skipped before any write, nothing changed and the run reports `REFUSED`.
- Coverage decides the verdict. `NO_GAP_FOUND` is reported only when nothing was skipped, because an uninspected object — and a skipped directory with its whole subtree — may be exactly where the gap is; a scan with skips changes nothing and reports `SCAN_INCOMPLETE`. A repair that leaves anything uninspected, unclaimed, or half-written reports `REPAIR_PARTIAL` and exits nonzero.
- The expected workspace SID is derived from the canonical root using DSH's `workspaceWriteSid` algorithm. `-WorkspaceSid` may supply the exact SID recorded by the current session's DSH diagnostics. Never choose an arbitrary existing `S-1-4-*` entry. An unmatched or incomplete root grant, and a root label structure this repair refuses (see below), produce `ROOT_NOT_PROVISIONED` before any permission is written; the root's own entries are never modified.
- A candidate receives a missing non-inheritable user permission-management entry (`WRITE_DAC | WRITE_OWNER`), the exact workspace allow entry, and a Low label where required. Do not add user FullControl: that explicit entry could outrank DSH's inherited Everyone delete-child deny. Existing denies, unrelated entries, ownership, and inheritance protection stay intact. Directory workspace grants and labels can be inherited by future children. Native writes deliberately do not propagate to existing children; each existing object is handled separately. A label structure that cannot carry a Low label to both kinds of child and on to the next generation — an entry that stops propagating, or one that covers only files or only containers — is refused while planning, before any permission is written; the run reports `REFUSED` and the reason.
- Full before/after descriptors for the DACL and integrity label, including an absent label, are saved before the first mutation. Recovery code is copied beside the backup so it survives skill unloading.
- A failed write on an object that is not merely in use, a changed object, changed permissions, or failed verification stops further repair and returns a nonzero exit code. Partial changes, including the DACL of an object that was claimed mid-mutation, are reported and left available for deliberate recovery.
- Windows re-applies a parent's inheritable entries to an object whose DACL is written while unprotected, so a written object can carry inherited entries no plan predicted. Verification therefore checks the intent — the entries this repair adds are present, no entry that existed before is lost, and every extra entry is inherited or a deny — instead of comparing the written descriptor with the planned one byte for byte. Recovery accepts the same inherited bookkeeping when it validates a recorded state.
- A confined child runs at Low integrity, so the Low label — not the workspace grant — is what makes an existing object writable there: an object whose DACL already grants the workspace still refuses that child while it carries no label. The same label makes the Shell treat the file as an untrusted source, so opening a labelled file from Explorer can raise the Internet-security prompt, and any file created inside a labelled directory inherits the label. Tell the user this trade-off; when a specific file must open normally, `icacls "<file>" /setintegritylevel Medium` restores it, and the confined child can no longer write that file.

`-WhatIf` performs inspection and planning and writes a report, but makes no permission changes and creates no recovery backup. It may run confined if reads are allowed; a refusal is not proof that the host account lacks access. Real repair refuses a restricted or elevated token.

## Interpret the result

Read the final `RECAP` first. Details are retained in the JSONL report. Console records use the information stream so they cannot contaminate function return values.

| Result | Next step |
|---|---|
| `REPAIRED`, exit 0, `nextAction=verify_original_confined_operation` | Every inspected object carries the entries now, and nothing was skipped. Repeat the original operation in confinement. |
| `NO_GAP_FOUND`, exit 0 | The inspected objects have the expected entries and nothing was skipped. Diagnose another cause; do not widen permissions. |
| `PREVIEW`, exit 0 | A plan only; `verification.performed` is false. |
| `SCAN_INCOMPLETE`, exit 2 | Nothing was changed: objects could not be inspected, so the absence of gaps among the inspected ones proves nothing. Name the skipped paths in `details.skipped` and let the user stop the processes holding them. |
| `ROOT_NOT_PROVISIONED`, `SCAN_LIMIT`, or `REFUSED`, exit 2 | No permission change was started. Explain the recorded reason. |
| `REPAIR_PARTIAL`, exit 1 | Everything inspected is repaired, but some objects were uninspected, unclaimed, or half-written. Report `actions.partial`, `details.partiallyWritten` and `details.skipped`, name the recovery command, and do not describe the run as a clean repair. |
| `REPAIR_FAILED`, exit 1 | Partial changes may remain. Stop and report the affected paths and recovery command. |
| `REPORT_FAILED`, exit 1 | The final report could not be saved. Use the console recap and stop. |

Verification checks the exact workspace SID, applicable write mask, integrity label, intended descriptor, and unchanged root for all inspected objects. It does not emulate the confined token or prove that an unrelated deny entry cannot block the original operation. Only repeating that operation tests the actual outcome.

Stop after any failed or refused repair or failed verification. Do not repeat it automatically, repair a broader path, remove a sandbox entry or deny, change ownership, or reset permissions. A scan-limit refusal may be reconsidered with a deliberately chosen larger bound on the same workspace; it must not become an automatic retry loop.

**A stopped run still owes the user a decision.** Name the object and the entry it lacks, what changed and what was left unchanged, the recovery command, and the report path. Prefer one approved unconfined command over widening the session; only when nothing else can unblock the run, ask the user to switch this session to **full access** (Chinese UI: 完全权限) temporarily, and say what that opens: keep working under it, or have you keep investigating this file-permission problem from the report. Then ask them to send this session as feedback, quoting the report records that matter, so the unhandled scenario reaches us — only what reaches this conversation travels with it. For example:

> 这个工作区被 Windows 文件权限挡住了：`<对象>` 上 `<缺哪个条目 / 被哪个进程占用>`。你可以把本会话切到「完全权限」(full access) 临时继续工作；切完之后既能直接干活，也可以让我继续排查这个文件权限问题（报告里已经有机制和证据）。也麻烦把这个会话作为反馈发出去，好让我们补上这个场景。
>
> This workspace is blocked by Windows file permissions: `<object>` `<missing entry / process holding it>`. Switch this session to full access (完全权限) to keep working meanwhile; then either continue your work or have me keep investigating this file-permission problem from the report. Please also send this session as feedback so we can cover the case.

## Recovery and reporting

The recap includes the persistent report, `backup.json`, and the exact recovery command. Recovery validates file identities and known pre-repair, partial, or completed permission states before writing anything. It restores integrity labels before removing the user grant, restores the original DACL, and re-reads both. An originally absent label is cleared. A replacement object or later permission change causes a conflict instead of overwriting unrelated changes. An object another process holds open is reported as `SKIPPED_IN_USE` and left for a later run, which reports `RESTORE_PARTIAL` and exits nonzero. Keep the entire recovery directory, including its helper files.

Run recovery only when requested or covered by existing authorization, with the same account and an authorized unconfined, non-elevated command. `-WhatIf` previews it. A failed original operation is not by itself a reason to undo a verified repair.

Report in the user's language: workspace, evidence, changed and skipped objects, verification limits, exit status, report path, recovery command, and next diagnostic step. If reporting a problem for feedback, quote the relevant records in the conversation and let the user decide whether to send it.
