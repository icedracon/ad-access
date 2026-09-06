# ad-access

A **Windows effective-access / token evaluator** for Rust — given a security
descriptor and a token, compute the *resultant* access a principal actually
has. This is the primitive audit and attack-path tools approximate (and often
get wrong): it answers "who can **actually** write this object", not "who has
an ACE mentioning it".

**Zero dependencies** — pure logic over already-parsed structures. SDDL/token
parsing is a caller concern.

> **Status: early scaffold.** The core is correct; the hard parts are not done
> yet — see below. Do not treat its results as authoritative until the TODO
> surface is closed and validated against Windows `AuthzAccessCheck`.

## Implemented (correct today)

- Ordered DACL evaluation with **deny-before-allow**.
- NULL DACL → full access; empty DACL → no access.
- Owner implicit rights (`READ_CONTROL` + `WRITE_DAC`).
- Generic → specific right mapping.
- Group SIDs, not just the user SID.
- A minimal privilege hook (`SeBackup` / `SeRestore` / `SeTakeOwnership`).

## Windows conformance

The core evaluator has been validated **1:1 against Windows'
`AuthzAccessCheck`** on a live Windows Server host: **30/30 cases matched** —
allow, deny-before-allow, group-SID via token membership, empty-DACL owner
rights, non-canonical ACE ordering, partial vs full grant, mixed
group-allow / user-deny, deny-superset blocking a subset request,
disjoint-deny not blocking, multi-ACE bit accumulation, all-rights
(`0x001F01FF`), zero-desired-access (Windows' `ERROR_ACCESS_DENIED`
semantics), and more. The regression corpus is baked into
`tests/conformance.rs` so the check runs offline forever. Building it
against Windows caught and fixed a real bug (zero-desired-access was
trivially allowed).

## Implemented on top of that

- Ordered DACL: deny-before-allow, NULL vs empty DACL semantics.
- Owner implicit `READ_CONTROL` + `WRITE_DAC`.
- Generic → specific right mapping.
- Group SIDs in the token, not just the user SID.
- Minimal privilege hook (`SeBackup` / `SeRestore` / `SeTakeOwnership`).
- **Conditional (callback) ACEs** — an AST with `Member_of`, `Member_of_Any`,
  claim equality/presence, `!` / `&&` / `||`, evaluated against token claims.
- **Mandatory integrity** — a `no-write-up` check: subjects below the object's
  label cannot obtain write-class rights, regardless of the DACL.

## Still TODO

- Parsing the SDDL conditional-expression *string* into the AST (the evaluator
  is done; the tokenizer belongs with the SD parser).
- RESTRICTED / filtered tokens (the restricting-SID second pass).
- Inheritance / auto-inherit merge (this evaluator takes an already-merged DACL).
- Object-type ACEs (AD property-set / control-access-right GUIDs).
- A larger Windows corpus covering the four above.

## License

MIT.
