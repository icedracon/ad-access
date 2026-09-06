# Changelog

All notable changes to `ad-access` are documented here. Follows
[Keep a Changelog](https://keepachangelog.com); uses SemVer.

## [0.1.0-beta.1] — unreleased

Initial release. Unstable API (0.x + beta) — expect small breaks before 0.1.0.

### Added
- Windows effective-access core: `access_check(sd, token, desired, mapping)`.
- Ordered DACL evaluation with deny-before-allow.
- NULL vs empty DACL semantics.
- Owner implicit `READ_CONTROL` + `WRITE_DAC`.
- Generic → specific right mapping (`GenericMapping::map`) + a `FILE` preset.
- Group SIDs in the token, not just the user SID.
- Minimal privilege model: `SeBackup` / `SeRestore` / `SeTakeOwnership`.
- Conditional (callback) ACE evaluator: `Condition` AST with `Member_of`,
  `Member_of_Any`, claim equality/presence, and `!` / `&&` / `||`.
- Mandatory integrity `no-write-up` check via `SecurityDescriptor::with_label`
  + `AccessToken::with_integrity`.
- Zero-desired-access returns denied to match Windows' `ERROR_ACCESS_DENIED`
  semantics.
- Zero dependencies (pure logic over already-parsed structures).

### Validated
- 13 unit tests cover deny-before-allow, group ACEs, NULL/empty DACL,
  owner rights, generic mapping, `SeBackup`, conditional gates,
  claim + boolean combinators, and the no-write-up rule.
- **30/30 conformance vs Windows `AuthzAccessCheck`** on a live Windows
  host, baked into `tests/conformance.rs` for offline regression. Building
  the corpus caught a real bug in the evaluator (zero-desired-access was
  trivially allowed; now returns denied per Windows semantics).

### Not included (deliberately, for later)
- Parsing the SDDL conditional-expression string into `Condition` — the
  evaluator is here, the tokenizer belongs with the SD parser.
- RESTRICTED / filtered tokens (the restricting-SID second pass).
- Inheritance / auto-inherit merge — this evaluator takes an already-merged DACL.
- Object-type ACEs (AD property-set / control-access-right GUIDs).
