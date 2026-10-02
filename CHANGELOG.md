# Changelog

Releases follow semantic versioning. Each release is archived on Zenodo with its own DOI.

## 1.0.0 (2026-10-02)

First archival release. The concepts were first shared publicly on 10 August 2026. Publication preflight also updated the AMD SEV-SNP specification citation to revision 1.59, corrected the repository citation metadata structure, completed all five TLC reproduction commands, and clarified the MIT license scope for the formal specification artifacts. Relative to that version: reachability uses reflexive-transitive closure; sealed objects have an explicit labeling rule; SafeOpen is evaluated on the post-commit configuration; the safety theorem is proved from two local obligations, including one covering relabeling; a projection-soundness assumption connects the finite model to the graph invariant; key derivation uses a per-epoch seed and an injective encoding; the noninterference theorem derives the gated-output step from the MECI invariant; the finite model is specified in TLA+ and checked by TLC and an independent reference checker with exactly matching counts; citations were corrected and figures redrawn.
