//! `ad-access` — a Windows effective-access / token evaluator.
//!
//! Given a [`SecurityDescriptor`] and an [`AccessToken`], compute the
//! *resultant* access a principal actually has — the answer graph-based
//! attack-path tools approximate and get wrong. It answers "who can
//! *actually* write this object", not "who has an ACE that mentions it".
//!
//! ## Implemented
//!
//! - Ordered DACL evaluation with **deny-before-allow** (canonical ACL order).
//! - NULL DACL → full access; empty DACL → no access.
//! - Owner implicit rights (`READ_CONTROL` + `WRITE_DAC`).
//! - Generic → specific right mapping ([`GenericMapping`]).
//! - Group SIDs in the token, not just the user SID.
//! - A minimal privilege hook (`SeBackup`/`SeRestore`/`SeTakeOwnership`).
//! - **Conditional (callback) ACEs** — a [`Condition`] AST with `Member_of`,
//!   `Member_of_Any`, claim equality/presence, and `!`/`&&`/`||`, evaluated
//!   against the token's groups and claims.
//! - **Mandatory integrity** — a `no-write-up` check: a subject whose
//!   integrity is below the object's mandatory label cannot obtain write-class
//!   rights.
//!
//! ## Still TODO (validation-gated)
//!
//! - Parsing an SDDL conditional-expression *string* into a [`Condition`] (the
//!   AST + evaluator are here; the string tokenizer belongs to the SD parser).
//! - RESTRICTED / filtered tokens (the restricting-SID second pass).
//! - Inheritance / auto-inherit merge (this evaluator takes an already-merged DACL).
//! - Object-type ACEs (AD property-set / control-access-right GUIDs).
//! - A conformance corpus validated against Windows `AuthzAccessCheck`.
//!
//! ```
//! use ad_access::*;
//! let sd = SecurityDescriptor::new(
//!     "S-1-5-21-X-500",
//!     Acl::Entries(vec![Ace::allow("S-1-5-21-X-1001", rights::FILE_READ_DATA)]),
//! );
//! let token = AccessToken::new("S-1-5-21-X-1001", &[]);
//! let d = access_check(&sd, &token, rights::FILE_READ_DATA, &GenericMapping::FILE);
//! assert!(d.allowed);
//! ```
#![deny(missing_docs)]

/// A security identifier, in SDDL string form (`S-1-5-...`).
pub type Sid = String;

/// Windows access-right bits (a representative subset).
pub mod rights {
    /// `FILE_READ_DATA` — read the contents of a file.
    pub const FILE_READ_DATA: u32 = 0x0000_0001;
    /// `FILE_WRITE_DATA` — write bytes into a file, overwriting existing data.
    pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
    /// `FILE_APPEND_DATA` — append bytes to a file.
    pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
    /// `FILE_EXECUTE` — execute the file / traverse the directory.
    pub const FILE_EXECUTE: u32 = 0x0000_0020;
    /// Standard `DELETE` right.
    pub const DELETE: u32 = 0x0001_0000;
    /// Standard `READ_CONTROL` right (read the security descriptor).
    pub const READ_CONTROL: u32 = 0x0002_0000;
    /// Standard `WRITE_DAC` right (change the DACL).
    pub const WRITE_DAC: u32 = 0x0004_0000;
    /// Standard `WRITE_OWNER` right (change the owner).
    pub const WRITE_OWNER: u32 = 0x0008_0000;
    /// Standard `SYNCHRONIZE` right (use the object for wait operations).
    pub const SYNCHRONIZE: u32 = 0x0010_0000;

    /// `GENERIC_ALL` — resolves to `mapping.all` via [`crate::GenericMapping::map`].
    pub const GENERIC_ALL: u32 = 0x1000_0000;
    /// `GENERIC_EXECUTE` — resolves to `mapping.execute`.
    pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
    /// `GENERIC_WRITE` — resolves to `mapping.write`.
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    /// `GENERIC_READ` — resolves to `mapping.read`.
    pub const GENERIC_READ: u32 = 0x8000_0000;
    /// Mask covering all four generic bits, useful for stripping them.
    pub const GENERIC_MASK: u32 = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL;

    /// Write-class rights subject to the mandatory-integrity no-write-up rule.
    pub const WRITE_CLASS: u32 =
        FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER;
}

/// Mandatory integrity levels, ordered low → high.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegrityLevel {
    /// Lowest integrity — sandboxed processes.
    Untrusted,
    /// Low integrity — the AppContainer / protected-mode browser tier.
    Low,
    /// Medium integrity — the default interactive-user tier.
    Medium,
    /// High integrity — elevated / administrator tier.
    High,
    /// System integrity — kernel / `SYSTEM` tier.
    System,
}

/// Maps the four generic rights onto object-specific right sets, as Windows
/// `MapGenericMask` does before an access check.
#[derive(Clone, Debug)]
pub struct GenericMapping {
    /// Right bits that `GENERIC_READ` maps to.
    pub read: u32,
    /// Right bits that `GENERIC_WRITE` maps to.
    pub write: u32,
    /// Right bits that `GENERIC_EXECUTE` maps to.
    pub execute: u32,
    /// Right bits that `GENERIC_ALL` maps to.
    pub all: u32,
}

impl GenericMapping {
    /// A file-like mapping, for examples and tests.
    pub const FILE: GenericMapping = GenericMapping {
        read: rights::FILE_READ_DATA | rights::READ_CONTROL | rights::SYNCHRONIZE,
        write: rights::FILE_WRITE_DATA | rights::FILE_APPEND_DATA | rights::READ_CONTROL,
        execute: rights::FILE_EXECUTE | rights::READ_CONTROL | rights::SYNCHRONIZE,
        all: rights::FILE_READ_DATA
            | rights::FILE_WRITE_DATA
            | rights::FILE_APPEND_DATA
            | rights::FILE_EXECUTE
            | rights::DELETE
            | rights::READ_CONTROL
            | rights::WRITE_DAC
            | rights::WRITE_OWNER
            | rights::SYNCHRONIZE,
    };

    /// Resolve the generic bits in `mask` into specific bits.
    pub fn map(&self, mask: u32) -> u32 {
        let mut out = mask & !rights::GENERIC_MASK;
        if mask & rights::GENERIC_READ != 0 {
            out |= self.read;
        }
        if mask & rights::GENERIC_WRITE != 0 {
            out |= self.write;
        }
        if mask & rights::GENERIC_EXECUTE != 0 {
            out |= self.execute;
        }
        if mask & rights::GENERIC_ALL != 0 {
            out |= self.all;
        }
        out
    }
}

/// A claim value carried by a token (simplified: string or integer).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimValue {
    /// String-valued claim.
    Str(String),
    /// Integer-valued claim.
    Int(i64),
}

/// A conditional-ACE expression, evaluated against a token's groups and claims.
/// This is the semantic core; parsing the SDDL condition string into this AST
/// is a separate (SD-parser) concern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Condition {
    /// Unconditional (a plain ACCESS_ALLOWED / ACCESS_DENIED ACE).
    Always,
    /// `Member_of {SIDs}` — the token must contain **all** listed SIDs.
    MemberOfAll(Vec<Sid>),
    /// `Member_of_Any {SIDs}` — the token must contain **any** listed SID.
    MemberOfAny(Vec<Sid>),
    /// A named claim equals a value.
    ClaimEq(String, ClaimValue),
    /// A named claim is present.
    ClaimPresent(String),
    /// Logical negation of the inner condition.
    Not(Box<Condition>),
    /// Logical AND of all inner conditions.
    And(Vec<Condition>),
    /// Logical OR of any inner condition.
    Or(Vec<Condition>),
}

impl Condition {
    /// Evaluate the condition against `token`. Unknown claims evaluate to
    /// `false` (a missing claim never satisfies a comparison).
    pub fn eval(&self, token: &AccessToken) -> bool {
        match self {
            Condition::Always => true,
            Condition::MemberOfAll(sids) => sids.iter().all(|s| token.contains_sid(s)),
            Condition::MemberOfAny(sids) => sids.iter().any(|s| token.contains_sid(s)),
            Condition::ClaimEq(name, val) => token.claim(name) == Some(val),
            Condition::ClaimPresent(name) => token.claim(name).is_some(),
            Condition::Not(inner) => !inner.eval(token),
            Condition::And(parts) => parts.iter().all(|c| c.eval(token)),
            Condition::Or(parts) => parts.iter().any(|c| c.eval(token)),
        }
    }
}

/// Whether an ACE grants access (ALLOW) or denies it (DENY).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AceKind {
    /// `ACCESS_ALLOWED` — grants the mask bits.
    Allowed,
    /// `ACCESS_DENIED` — denies the mask bits (checked before Allowed in canonical order).
    Denied,
}

/// One access-control entry (inheritance flags assumed already resolved).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ace {
    /// ALLOW or DENY.
    pub kind: AceKind,
    /// Trustee SID.
    pub sid: Sid,
    /// Access-rights mask this ACE grants or denies.
    pub mask: u32,
    /// Conditional guard (`Condition::Always` for a plain ACE).
    pub condition: Condition,
}

impl Ace {
    /// Shorthand for a plain `ACCESS_ALLOWED` ACE with no condition.
    pub fn allow(sid: &str, mask: u32) -> Ace {
        Ace::new(AceKind::Allowed, sid, mask, Condition::Always)
    }

    /// Shorthand for a plain `ACCESS_DENIED` ACE with no condition.
    pub fn deny(sid: &str, mask: u32) -> Ace {
        Ace::new(AceKind::Denied, sid, mask, Condition::Always)
    }

    /// Build an ACE from all four fields.
    pub fn new(kind: AceKind, sid: &str, mask: u32, condition: Condition) -> Ace {
        Ace {
            kind,
            sid: sid.into(),
            mask,
            condition,
        }
    }

    /// Does this ACE apply to `token` — trustee SID present AND condition met?
    fn applies(&self, token: &AccessToken) -> bool {
        token.contains_sid(&self.sid) && self.condition.eval(token)
    }
}

/// A discretionary ACL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Acl {
    /// No DACL present — grants everyone full access (Windows semantics).
    Null,
    /// A concrete list of ACEs (assumed already merged from inheritance).
    Entries(Vec<Ace>),
}

/// A security descriptor: owner + group + DACL + optional mandatory-integrity label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityDescriptor {
    /// Owner SID — gets `READ_CONTROL` + `WRITE_DAC` implicitly.
    pub owner: Sid,
    /// Group SID (informational; not used by the current evaluator).
    pub group: Sid,
    /// Discretionary access-control list.
    pub dacl: Acl,
    /// The object's mandatory integrity label, if any (from the SACL).
    pub mandatory_label: Option<IntegrityLevel>,
}

impl SecurityDescriptor {
    /// A descriptor with the given owner and DACL, a default group, and no
    /// mandatory label.
    pub fn new(owner: &str, dacl: Acl) -> SecurityDescriptor {
        SecurityDescriptor {
            owner: owner.into(),
            group: "S-1-5-21-X-513".into(),
            dacl,
            mandatory_label: None,
        }
    }

    /// Attach a mandatory-integrity label to the descriptor.
    pub fn with_label(mut self, label: IntegrityLevel) -> SecurityDescriptor {
        self.mandatory_label = Some(label);
        self
    }
}

/// Token privileges that override or short-circuit the DACL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Privilege {
    /// `SeBackupPrivilege` — grants read-class rights regardless of DACL.
    SeBackup,
    /// `SeRestorePrivilege` — grants write-class rights + WRITE_DAC + WRITE_OWNER.
    SeRestore,
    /// `SeTakeOwnershipPrivilege` — grants WRITE_OWNER.
    SeTakeOwnership,
}

/// A subject access token: user SID, group memberships, privileges,
/// integrity level, and named claims.
#[derive(Clone, Debug)]
pub struct AccessToken {
    /// User SID.
    pub user: Sid,
    /// Group SIDs the token holds (including built-ins like Authenticated Users).
    pub groups: Vec<Sid>,
    /// Enabled privileges.
    pub privileges: Vec<Privilege>,
    /// Token's mandatory integrity level.
    pub integrity: IntegrityLevel,
    /// Named claims (for conditional-ACE evaluation).
    pub claims: Vec<(String, ClaimValue)>,
}

impl AccessToken {
    /// A Medium-integrity token with no privileges or claims.
    pub fn new(user: &str, groups: &[&str]) -> AccessToken {
        AccessToken {
            user: user.into(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            privileges: Vec::new(),
            integrity: IntegrityLevel::Medium,
            claims: Vec::new(),
        }
    }

    /// Grant the token a set of privileges.
    pub fn with_privileges(mut self, privs: &[Privilege]) -> AccessToken {
        self.privileges = privs.to_vec();
        self
    }

    /// Set the token's mandatory integrity level.
    pub fn with_integrity(mut self, level: IntegrityLevel) -> AccessToken {
        self.integrity = level;
        self
    }

    /// Attach a named claim to the token (for conditional-ACE evaluation).
    pub fn with_claim(mut self, name: &str, value: ClaimValue) -> AccessToken {
        self.claims.push((name.into(), value));
        self
    }

    fn contains_sid(&self, sid: &str) -> bool {
        self.user == sid || self.groups.iter().any(|g| g == sid)
    }

    fn owns(&self, owner: &str) -> bool {
        self.contains_sid(owner)
    }

    fn has(&self, p: Privilege) -> bool {
        self.privileges.contains(&p)
    }

    fn claim(&self, name: &str) -> Option<&ClaimValue> {
        self.claims.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }
}

/// The result of an access check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    /// Every desired bit was granted.
    pub allowed: bool,
    /// The bits actually granted.
    pub granted: u32,
    /// Desired bits that were denied or never granted (including bits blocked
    /// by the mandatory-integrity rule).
    pub still_denied: u32,
}

/// Compute resultant access for `desired` rights. `desired` may contain generic
/// bits; they are mapped through `mapping` first.
pub fn access_check(
    sd: &SecurityDescriptor,
    token: &AccessToken,
    desired: u32,
    mapping: &GenericMapping,
) -> Decision {
    let desired = mapping.map(desired);
    // Windows `AccessCheck` returns `ERROR_ACCESS_DENIED` when `DesiredAccess`
    // is 0 — a zero mask is not a valid request. Match that behavior.
    if desired == 0 {
        return Decision {
            allowed: false,
            granted: 0,
            still_denied: 0,
        };
    }
    let mut remaining = desired;
    let mut granted = 0u32;

    // Mandatory integrity (no-write-up): a subject below the object's label
    // cannot obtain write-class rights. Set those aside up front.
    let mut blocked = 0u32;
    if let Some(label) = sd.mandatory_label {
        if token.integrity < label {
            blocked = remaining & rights::WRITE_CLASS;
            remaining &= !blocked;
        }
    }

    let grant = |bits: u32, remaining: &mut u32, granted: &mut u32| {
        let hit = bits & *remaining;
        *granted |= hit;
        *remaining &= !hit;
    };

    // Owner gets READ_CONTROL + WRITE_DAC implicitly.
    if token.owns(&sd.owner) {
        grant(
            rights::READ_CONTROL | rights::WRITE_DAC,
            &mut remaining,
            &mut granted,
        );
    }
    // Minimal privilege model (simplified vs. the real open-intent semantics).
    if token.has(Privilege::SeTakeOwnership) {
        grant(rights::WRITE_OWNER, &mut remaining, &mut granted);
    }
    if token.has(Privilege::SeBackup) {
        grant(
            mapping.read | rights::READ_CONTROL,
            &mut remaining,
            &mut granted,
        );
    }
    if token.has(Privilege::SeRestore) {
        grant(
            mapping.write | rights::WRITE_DAC | rights::WRITE_OWNER,
            &mut remaining,
            &mut granted,
        );
    }

    match &sd.dacl {
        Acl::Null => {
            grant(remaining, &mut remaining, &mut granted);
        }
        Acl::Entries(aces) => {
            for ace in aces {
                if remaining == 0 {
                    break;
                }
                if !ace.applies(token) {
                    continue;
                }
                match ace.kind {
                    AceKind::Denied => {
                        let hit = ace.mask & remaining;
                        if hit != 0 {
                            return Decision {
                                allowed: false,
                                granted,
                                still_denied: hit | blocked,
                            };
                        }
                    }
                    AceKind::Allowed => {
                        grant(ace.mask, &mut remaining, &mut granted);
                    }
                }
            }
        }
    }

    Decision {
        allowed: remaining == 0 && blocked == 0,
        granted,
        still_denied: remaining | blocked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rights::*;

    const U: &str = "S-1-5-21-X-1001";

    #[test]
    fn allow_ace_grants() {
        let s = SecurityDescriptor::new(
            "S-1-5-21-X-500",
            Acl::Entries(vec![Ace::allow(U, FILE_READ_DATA)]),
        );
        let d = access_check(
            &s,
            &AccessToken::new(U, &[]),
            FILE_READ_DATA,
            &GenericMapping::FILE,
        );
        assert!(d.allowed);
        assert_eq!(d.granted, FILE_READ_DATA);
    }

    #[test]
    fn deny_before_allow_wins() {
        let s = SecurityDescriptor::new(
            "S-1-5-21-X-500",
            Acl::Entries(vec![
                Ace::deny(U, FILE_WRITE_DATA),
                Ace::allow(U, FILE_WRITE_DATA),
            ]),
        );
        let d = access_check(
            &s,
            &AccessToken::new(U, &[]),
            FILE_WRITE_DATA,
            &GenericMapping::FILE,
        );
        assert!(!d.allowed);
        assert_eq!(d.still_denied, FILE_WRITE_DATA);
    }

    #[test]
    fn group_sid_matches() {
        let s = SecurityDescriptor::new(
            "S-1-5-21-X-500",
            Acl::Entries(vec![Ace::allow("S-1-5-32-544", FILE_READ_DATA)]),
        );
        let t = AccessToken::new(U, &["S-1-5-32-544"]);
        assert!(access_check(&s, &t, FILE_READ_DATA, &GenericMapping::FILE).allowed);
    }

    #[test]
    fn null_dacl_grants_all() {
        let s = SecurityDescriptor::new("S-1-5-21-X-500", Acl::Null);
        assert!(
            access_check(
                &s,
                &AccessToken::new(U, &[]),
                GENERIC_ALL,
                &GenericMapping::FILE
            )
            .allowed
        );
    }

    #[test]
    fn empty_dacl_denies() {
        let s = SecurityDescriptor::new("S-1-5-21-X-500", Acl::Entries(vec![]));
        let d = access_check(
            &s,
            &AccessToken::new(U, &[]),
            FILE_READ_DATA,
            &GenericMapping::FILE,
        );
        assert!(!d.allowed && d.granted == 0);
    }

    #[test]
    fn owner_gets_read_control_and_write_dac() {
        let s = SecurityDescriptor::new(U, Acl::Entries(vec![])); // token IS the owner
        let d = access_check(
            &s,
            &AccessToken::new(U, &[]),
            READ_CONTROL | WRITE_DAC,
            &GenericMapping::FILE,
        );
        assert!(d.allowed);
    }

    #[test]
    fn generic_all_is_mapped() {
        let mapped = GenericMapping::FILE.map(GENERIC_ALL);
        assert!(mapped & FILE_READ_DATA != 0 && mapped & FILE_WRITE_DATA != 0);
        assert_eq!(mapped & GENERIC_MASK, 0);
    }

    #[test]
    fn se_backup_grants_read() {
        let s = SecurityDescriptor::new("S-1-5-21-X-500", Acl::Entries(vec![]));
        let t = AccessToken::new(U, &[]).with_privileges(&[Privilege::SeBackup]);
        assert!(access_check(&s, &t, FILE_READ_DATA, &GenericMapping::FILE).allowed);
    }

    // ---- conditional ACEs (#9) ----

    #[test]
    fn member_of_condition_gates_the_ace() {
        // Allow READ only if the token is a member of the "Tier0" group.
        let ace = Ace::new(
            AceKind::Allowed,
            U,
            FILE_READ_DATA,
            Condition::MemberOfAll(vec!["S-1-5-21-X-Tier0".into()]),
        );
        let s = SecurityDescriptor::new("S-1-5-21-X-500", Acl::Entries(vec![ace]));
        // Without the group → denied.
        assert!(
            !access_check(
                &s,
                &AccessToken::new(U, &[]),
                FILE_READ_DATA,
                &GenericMapping::FILE
            )
            .allowed
        );
        // With the group → allowed.
        let t = AccessToken::new(U, &["S-1-5-21-X-Tier0"]);
        assert!(access_check(&s, &t, FILE_READ_DATA, &GenericMapping::FILE).allowed);
    }

    #[test]
    fn claim_and_boolean_conditions() {
        // Allow if department == "IT" AND NOT member of "Contractors".
        let cond = Condition::And(vec![
            Condition::ClaimEq("department".into(), ClaimValue::Str("IT".into())),
            Condition::Not(Box::new(Condition::MemberOfAny(vec![
                "S-1-5-21-X-Contractors".into(),
            ]))),
        ]);
        let s = SecurityDescriptor::new(
            "S-1-5-21-X-500",
            Acl::Entries(vec![Ace::new(AceKind::Allowed, U, FILE_WRITE_DATA, cond)]),
        );
        let ok = AccessToken::new(U, &[]).with_claim("department", ClaimValue::Str("IT".into()));
        assert!(access_check(&s, &ok, FILE_WRITE_DATA, &GenericMapping::FILE).allowed);
        let contractor = AccessToken::new(U, &["S-1-5-21-X-Contractors"])
            .with_claim("department", ClaimValue::Str("IT".into()));
        assert!(!access_check(&s, &contractor, FILE_WRITE_DATA, &GenericMapping::FILE).allowed);
    }

    // ---- mandatory integrity ----

    #[test]
    fn no_write_up_blocks_write_but_not_read() {
        // High-integrity object, Medium-integrity subject with a full-control ACE.
        let s = SecurityDescriptor::new(
            "S-1-5-21-X-500",
            Acl::Entries(vec![Ace::allow(U, FILE_READ_DATA | FILE_WRITE_DATA)]),
        )
        .with_label(IntegrityLevel::High);
        let t = AccessToken::new(U, &[]).with_integrity(IntegrityLevel::Medium);
        // Read is granted; write is blocked by the label regardless of the ACE.
        let d = access_check(
            &s,
            &t,
            FILE_READ_DATA | FILE_WRITE_DATA,
            &GenericMapping::FILE,
        );
        assert!(!d.allowed);
        assert_eq!(d.granted, FILE_READ_DATA);
        assert_eq!(d.still_denied, FILE_WRITE_DATA);
        // A High-integrity subject writes fine.
        let hi = AccessToken::new(U, &[]).with_integrity(IntegrityLevel::High);
        assert!(access_check(&s, &hi, FILE_WRITE_DATA, &GenericMapping::FILE).allowed);
    }
}
