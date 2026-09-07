# Changelog

All notable changes to `ad-access` are documented here. Follows
[Keep a Changelog](https://keepachangelog.com); uses SemVer.

## [0.1.0] — 2026-09-06

First stable release of the Windows effective-access / token evaluator.

### Features

- Ordered DACL evaluation with **deny-before-allow** (canonical ACL order).
- NULL DACL → full access; empty DACL → no access.
- Owner implicit rights (`READ_CONTROL` + `WRITE_DAC`).
- Generic → specific right mapping (`GenericMapping`) + a `FILE` preset.
- Group SIDs in the token, not just the user SID.
- Minimal privilege model (`SeBackup` / `SeRestore` / `SeTakeOwnership`).
- **Conditional (callback) ACEs** — a `Condition` AST with `Member_of`,
  `Member_of_Any`, claim equality/presence, and `!` / `&&` / `||`.
- **Mandatory integrity** — `no-write-up` via `SecurityDescriptor::with_label`
  + `AccessToken::with_integrity`.
- **Inheritance flags** (`ace_flags`) — `INHERIT_ONLY` ACEs do not apply to the
  object itself.
- **Object-type ACEs** — `Guid` + `Ace::with_object_type` + `access_check_object`
  for AD property-set / extended-right / control-access matching (DCSync,
  per-attribute writes). A plain `access_check` does not fire an object ACE
  (matches Windows); an object-typed check matches the requested GUID.
- Zero-desired-access returns denied, matching Windows `ERROR_ACCESS_DENIED`.
- Zero dependencies (pure logic over already-parsed structures).

### Validated

- **42/42 conformance vs Windows `AuthzAccessCheck` / `AuthzAccessCheckByType`**
  on a live Windows Server host, baked into `tests/conformance.rs` for offline
  regression. Building the corpus caught two real bugs before release:
  zero-desired-access was trivially allowed, and a plain check wrongly fired
  object ACEs.

### Non-goals (documented, not gaps)

- SDDL conditional-expression *string* parsing (the AST + evaluator are here;
  tokenizing belongs with the SD parser, `windows-sddl`).
- RESTRICTED / filtered tokens (the restricting-SID second pass).
- Hierarchical object-type lists (property set → member properties).

### Pre-release history

- `0.1.0-beta.1` — initial publish (core evaluator, 30/30 conformance).
- `0.1.0-beta.2` — add `repository` field.
- `0.1.0-beta.3` — CI fix (broken intra-doc link).
