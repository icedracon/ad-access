# ad-access

A **Windows effective-access / token evaluator** for Rust — given a security
descriptor and a token, compute the *resultant* access a principal actually
has. This is the primitive audit and attack-path tools approximate (and often
get wrong): it answers "who can **actually** write this object", not "who has
an ACE mentioning it".

**Zero dependencies** — pure logic over already-parsed structures. SDDL/token
parsing is a caller concern.

## Windows conformance

The evaluator is validated **1:1 against Windows' `AuthzAccessCheck` and
`AuthzAccessCheckByType`** on a live Windows Server host: **42/42 cases
matched** — allow, deny-before-allow, group-SID via token membership,
empty-DACL owner rights, non-canonical ACE ordering, partial vs full grant,
deny-superset / disjoint-deny, multi-ACE accumulation, all-rights, zero
desired-access (Windows' `ERROR_ACCESS_DENIED`), mandatory-integrity
no-write-up, `INHERIT_ONLY` skipping, and object-type ACE matching (a plain
check does not fire an object ACE; an object-typed check matches the GUID).
The corpus is baked into `tests/conformance.rs` so it runs offline forever.
Building it against Windows caught two real bugs before release
(zero-desired-access was trivially allowed; a plain check wrongly fired
object ACEs).

## Implemented

- Ordered DACL: deny-before-allow, NULL vs empty DACL semantics.
- Owner implicit `READ_CONTROL` + `WRITE_DAC`.
- Generic → specific right mapping.
- Group SIDs in the token, not just the user SID.
- Minimal privilege hook (`SeBackup` / `SeRestore` / `SeTakeOwnership`).
- **Conditional (callback) ACEs** — an AST with `Member_of`, `Member_of_Any`,
  claim equality/presence, `!` / `&&` / `||`, evaluated against token claims.
- **Mandatory integrity** — a `no-write-up` check.
- **Inheritance flags** — `INHERIT_ONLY` ACEs skipped for the object itself.
- **Object-type ACEs** — `access_check_object` matches AD property-set /
  extended-right GUIDs (DCSync, per-attribute writes, control-access rights).

## Explicit non-goals (documented, not gaps)

- Parsing the SDDL conditional-expression *string* into the AST — the evaluator
  is done; string tokenizing belongs with the SD parser (`windows-sddl`).
- RESTRICTED / filtered tokens (the restricting-SID second pass) — rare; not modeled.
- Hierarchical object-type lists (property set → member properties) — the flat
  single-type check covers the common AD queries.

## License

MIT.
