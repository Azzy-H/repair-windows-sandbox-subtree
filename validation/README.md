# Provenance

These probes were used while reviewing this skill. They are included unchanged so results can be
reproduced; run each in a fresh PowerShell process so loaded C# types do not leak between revisions.

- `probe-label.ps1`, `probe-label-cases.ps1`, `probe-label-structure.ps1`, `probe-poisoned-labels.ps1`
  — written by the skill author.
- `probe-native-inheritance.ps1`, `probe-two-generations.ps1`, `probe-refusal-inheritance.ps1`,
  `probe-root-inheritance.ps1`, `probe-supported-labels.ps1` — written by the independent reviewer of
  revisions v4-v10, included unchanged.

The probes read descriptors only; they mutate no ACL. `probe-poisoned-labels.ps1` measures inherited
descriptors in memory through `CreatePrivateObjectSecurityEx`.