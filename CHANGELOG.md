# V10.1 变更日志（基于已复审的 v10）

对象：`repair-windows-sandbox-subtree-v10.1`
基线：`repair-windows-sandbox-subtree-v10`（哈希见 `review-v10/manifest.json`）
变更文件：`scripts/SubtreeSecurity.cs`、`scripts/repair-windows-sandbox-subtree.ps1`、`scripts/restore-windows-sandbox-subtree.ps1`、`SKILL.md`

## [P1] 真实落盘运行在第一个对象上中止：写入后校验要求与计划值完全相等

### 现象（真实工作区首次实跑，6027 个对象）

报告 `acl-report-bc83bf3fc5ff41e4a1c72882661ed865.jsonl`：

- `.git` 只有 `plan` → `attempt` → `refusal{DACL verification failed}`；`attempted 1 / verified 0`；最终 `REPAIR_FAILED`、exit 1、停手。
- 备份里的计划值有 10 条 DACL 条目，磁盘实际 12 条，多出的两条都是**继承**条目（带 `ID`）：
  - `(D;CIID;DT;;;WD)`
  - `(A;OICIID;0x110156;;;S-1-4-<workspace>)`

### 机制

`SetSecurityInfo` 在写入一个**未受保护**的 DACL 时，会把父对象的可继承条目重新合并进这个对象。该工作区 5310/6027 个对象的 DACL 与父对象不同步（根目录的授权项是后加的），因此第一次写入就产生了计划没有预测到的差异，而旧校验要求与计划值**逐字节相等** → 失败 → 停手。

**影响**：v10 在真实工作区上修不完任何对象——它会在第一个“DACL 与父对象不同步”的对象上停下，而这类对象在本工作区占绝大多数。

**为什么九轮内存审查没发现**：模拟的 ACL 存储不做继承合并；原生探针只分析描述符语义，从不经过“写入后读回”。这是只能靠落盘暴露的缺陷。

### 修复

新增三个语义判定（`scripts/SubtreeSecurity.cs`），修复与恢复入口改用它们：

| 判定 | 用在 | 规则 |
|---|---|---|
| `VerifyDaclIntent(before, planned, actual, workspaceSid, userSid, directory)` | 写完 DACL 之后 | 所有者/组不变；保护标志与计划一致；工作区 capability ACE 与用户管理 ACE 都在（按掩码 + SID 判定）；`before` 中的条目一条都不能丢；`actual` 中多出来的条目**必须带 `ID`（继承）或是拒绝项** |
| `VerifyIntent(...)` | 写完标签之后 | 上面全部 + `HasLowLabel(actual, directory)`（与所有调用点同一个谓词） |
| `VerifyRestoredIntent(before, actual)` | 恢复写入之后 | `before` 中的条目一条都不能丢；标签与记录一致；多出来的条目同样必须带 `ID` 或是拒绝项 |

ACE 比较忽略 `INHERITED_ACE`（Windows 会重写这个书签位），比较的是 ACE 类型、继承标志、访问掩码与 SID。

**未改动**：`Plan`、标签策略、扫描/备份/写入顺序、状态词表与退出码、备份文件格式。`after` 字段保留原名——它的语义是**意图**而不是磁盘结果；改名会破坏恢复兼容与既有测试。

## 验证记录

### 真实落盘复现（本机 NTFS，工作区内临时目录，运行后已清理）

复现方式：创建 `P\C` → 让 `P` 在 `C` 已存在**之后**才获得一条可继承条目（与工作区根的真实时序一致）→ 对 `C` 执行与工具完全相同的“未受保护 DACL 写入”。

| 检查 | 结果 |
|---|---|
| 实际多出的条目 | `(A;OICIID;FR;;;WD)` —— 继承条目，计划未预测 |
| 计划 / 实际 ACE 数 | 11 / 12 |
| 丢失的条目 | 无 |
| 旧判定 `Same(actual, planned)` | **False**（v10 就是在这里停手） |
| 新判定 `VerifyDaclIntent` | **True** |
| 恢复后旧判定 `Same(restored, before)` | **False** |
| 恢复后新判定 `VerifyRestoredIntent` | **True** |

### 真实工作区数据（只读，不写盘）

用 `.git` 的真实 `before`、备份里的计划值、以及它当前的描述符：

| 检查 | v10 | v10.1 |
|---|---|---|
| `Same(actual, planned)` | False | False（客观事实不变） |
| `VerifyDaclIntent` | 不存在 | **True** |
| `VerifyIntent` | 不存在 | False，**仅因为标签尚未写入** |

即：新版不会再在 `.git` 上停手，而是继续把标签写上；`VerifyIntent` 为 False 正是“标签还没写”这一中间状态应有的结果。

### 回归与闸门

- GPT 的 v10 基线套件（65 项验收断言；仅给其 mock 补了 2 行新方法转发）：**65 通过 / 0 失败**。
- 3 个 PowerShell 文件在 Windows PowerShell 5.1 下 parse OK；`SubtreeSecurity.cs` 在 5.1 下编译通过。

## [P1-2] 追加修复：最终全量复核仍在用逐字节相等（同一次真实运行暴露的第二处）

同一次真实运行（报告 `acl-report-1c0af9cfaa77455c8b32645a5fc087c3.jsonl`）暴露了同一类缺陷的第二处：

- 6027 个对象**全部写入并逐对象验证通过**（`attempted=6027 / verified=6027`），原始失败的 `dotnet build` 恢复成功（exit 0），受限子进程对原先被拒的目录（构建输出目录、`.git`、素材目录）实测可写 ✓；
- 但**最终全量复核**在根目录文件 `.gitignore` 上判失败 → `REPAIR_FAILED`、exit 1、`nextAction=stop`。

定位（该次运行的备份 + 该文件当前描述符逐项核对）：

| 检查 | 结果 |
|---|---|
| `Same(actual, planned)` | **False** ← 最终复核当时用的正是它 |
| `SameLabel(actual, planned)` | True |
| `VerifyDaclIntent(before, planned)` | True |
| `VerifyIntent(before, planned)` | True |
| `facts.capability` / `facts.lowLabel` | True / True |
| 计划 / 实际 ACE 数 | 6 / 7；多出的条目 `(A;ID;0x110156;;;S-1-4-<workspace>)`（**继承**条目，计划未预测） |

即与 `.git` 上那个缺陷**完全同类**：Windows 把父对象的可继承条目重新应用到被写入的对象上。

**修复**：最终全量复核改用 `VerifyIntent`（与逐对象检查同一套意图判定）。至此“写入时两处校验 + 最终全量复核 + 恢复路径”四处使用同一语义。

**教训（写进日志）**：上一版只改了“写入时”的两处校验，漏了“最终全量复核”——**同一个语义必须覆盖全部调用点**，这正是 GPT 第 9 轮反复强调的“统一判定”。

## 完整规模的端到端实跑（已在真实工作区完成）

由另一个会话在真实工作区 `<workspace>`（6027 个对象）上以一次非受限命令执行：

| 项目 | 结果 |
|---|---|
| 逐对象动作 | 计划 6027 / **尝试 6027 / 逐对象验证通过 6027** / 半写 0 |
| 原始失败操作 | 部署构建 `<project> -> <build output>\<assembly>.dll`，**0 错误、exit 0** |
| 受限子进程实测 | 原先全部被拒的位置（构建输出目录、`.git`、素材目录）**WRITE OK** |
| 判定 | 被 `[P1-2]` 那处最终复核误判为 `REPAIR_FAILED`（该处已修） |

即：**本轮修复已在真实 NTFS 上完成端到端验证**。`[P1-2]` 修好后按新条件重算全部 6027 个对象：`.gitignore` 通过 ✓，仅剩的两个失败对象是**修复之后被构建覆盖**的 `<assembly>.dll` / `<assembly>.pdb`（`identitySame=False`，能力与标签均正常），重跑会给出干净判定。

## 机制复核：Low 标签是不是必需的（实测结论：是）

同一台机器、同一个 DSH shell（`whoami /groups` → `Mandatory Label\Low Mandatory Level S-1-16-4096`）实测：

| 对象 | capability ACE | 标签 | 该 shell 的写入 |
|---|---|---|---|
| `.agents` / `packages` / `docs`（既有目录） | 有（继承） | 无 | **拒绝访问** |
| `AGENTS.md`（既有文件，就地重写） | 有（继承） | 无 | **拒绝访问** |
| 本次会话新建的 `<local scratch>` 及其子项 | 有（继承） | `(ML;OICIID;NW;;;LW)` | 可写 ✓ |

结论：**DACL 里的 workspace 授权是必要但不充分的；低完整性标签才是让受限 shell 能写的条件。** 因此给对象打 Low 标签不是可选项，而它的副作用（Shell 把 Low 文件当不可信来源 → 双击打开弹安全提示；在被标记目录中新建的文件继承该标签）是同一机制的另一面，必须在 SKILL 里向用户说明。

## 附带发现：全新工作区只有 capability、没有标签

`D:\mcp-video-frames`（全新工作区，DSH 从零在其内部工作）实测：根目录与全部子项**无标签**、无 `Everyone @DELETE` 拒绝项、无用户完全控制项，只有可继承的 workspace capability ACE。对照两个被修复过的工作区，三者齐备。

结合最初那次 `SetNamedSecurityInfoW failed (Win32 5): grantWrite(工作区根目录)`（写标签需要 `WRITE_OWNER`，所有者并不隐式持有该权限），最可能的解释是：**根目录 provisioning 的"标签"那一步失败后没有落地，工作区以"有授权、没有标签"的半配置状态出生**——于是 DSH 的 shell 在该工作区写不了任何既有对象（本次已在本会话对象上复现同样的拒绝）。这比"后代被拒"更接近根因，值得作为上游反馈的一部分。

## 给用户的取舍说明（同一次修复的另一面）

| 状态 | 受限 shell 能否写入既有对象 | 从资源管理器打开文件 |
|---|---|---|
| 打 Low 标签（本修复、以及那两个被修过的工作区） | 能 ✓ | 可能弹"Internet 安全设置阻止打开"提示 |
| 不打标签（全新工作区） | **不能** | 正常 ✓ |

出口：从应用（编辑器/看图工具）里打开不受影响；需要正常双击的文件用 `icacls "<文件>" /setintegritylevel Medium` 单独恢复，代价是受限 shell 不能再写该文件。

## 实测补充：根目录授权失败的真实原因（DSH 0.2.0-rc.2 起）

某工作区（在旧版本上创建并使用）实测到的指纹：

| 检查 | 该工作区 | 两个后授权的工作区 |
|---|---|---|
| 根 DACL 有 workspace capability ACE（掩码 `0x110156`） | **有** | 有 |
| 根 DACL 有**该用户账户的显式授权项** | **没有** | 有（完全控制 `F`） |
| 根与文件的 Low 标签 | **无** | 有 |

在该工作区以受限模式运行 shell 时，失败发生在**任何命令执行之前**：

```
SetNamedSecurityInfoW failed (Win32 5): grantWrite(<root>)
```

**原因（读 DSH 源码可查，不是工作区配置错）**：提交 `d5ad3baeb5`（2026-09-19，"confine Windows deletes with a Low integrity label"）把**受限令牌降到 Low 完整性**，并在**同一个 `SetNamedSecurityInfoW` 调用里**给被授权目录加 Low no-write-up 标签（`acl.ts:257`）；同一簇的 `3d5ba3b83f` 把幂等跳过收紧为"**ACE 与标签都精确匹配**才跳过"（`acl.ts:363`）。写标签需要 `WRITE_OWNER`，而"所有者"身份不隐式包含它（所有者隐式只有 `READ_CONTROL` + `WRITE_DAC`）——**用户新建的目录默认没有本账户的显式条目**，因此该调用被拒 → 整个 `grantWrite` 失败 → 受限 shell 起不来，且因为是"ACE 在、标签不在"的残局，**每次重试都失败，无法自愈**。

**升级前（≤09-19）是 DACL-only**：`acl.ts` 的历史逐版本扫描显示，`d5ad3baeb5` 之前的全部版本只有 `DACL_SECURITY_INFORMATION`、没有 `LABEL`，令牌也不降级。所以旧版本授权过的目录**有 capability ACE、没有任何标签**——这正是上表中间那一列的来源，**不是"provisioning 半配置"**（此前的推断已撤回）。

**与这个 skill 的边界**：根目录 provisioning 失败属于**内置诊断 skill 的职责**（它检查路径与全部上级，并在同一次运行内给根目录补上账户的显式授权），不是本 skill 的范围——本 skill 只处理"已 provision 好的工作区内、既有后代缺少标签/授权"这一半。本文件记录它，是为了说明"为什么同一个工作区在升级前后表现不同"，不作为本 skill 的动作指引。

## 仍需完成

- 与本次修复无关的后续项：v11（单 ACE 收窄）提案、以及按 GPT 路线做验证脚本整合与说明压缩。
- **恢复路径尚未在真实工作区上实跑过**。现有两次修复的备份，若需回滚按“新 → 旧”顺序执行。
