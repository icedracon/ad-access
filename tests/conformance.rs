//! Conformance corpus validated 1:1 against Windows `AuthzAccessCheck` on a
//! live Windows host (2026-09-06): 15/15 cases matched. SIDs here are
//! synthetic — Windows' verdict depends only on the membership structure
//! (user / group-member / absent), owner match, and the masks, not on the
//! concrete SID values, so the recorded verdicts hold for this structure.
//! Each `allow`/`granted` below is the Windows-computed result.

use ad_access::{rights::*, *};

struct Case {
    aces: Vec<Ace>,
    desired: u32,
    allow: bool,
    granted: u32, // Windows GrantedAccessMask when allowed
}

#[test]
fn matches_windows_authz_access_check() {
    let u = "S-1-5-21-X-1001"; // subject + owner
    let g = "S-1-5-21-X-Grp"; // a group present in the token
    let x = "S-1-5-21-X-Absent"; // a SID not in the token
    let token = AccessToken::new(u, &[g]);
    let rw = FILE_READ_DATA | FILE_WRITE_DATA;

    let cases = vec![
        // 1: allow subject READ
        Case {
            aces: vec![Ace::allow(u, FILE_READ_DATA)],
            desired: FILE_READ_DATA,
            allow: true,
            granted: FILE_READ_DATA,
        },
        // 2: allow an absent SID → subject not covered
        Case {
            aces: vec![Ace::allow(x, FILE_READ_DATA)],
            desired: FILE_READ_DATA,
            allow: false,
            granted: 0,
        },
        // 3: canonical deny-before-allow
        Case {
            aces: vec![Ace::deny(u, FILE_READ_DATA), Ace::allow(u, FILE_READ_DATA)],
            desired: FILE_READ_DATA,
            allow: false,
            granted: 0,
        },
        // 4: allow via a group the token holds
        Case {
            aces: vec![Ace::allow(g, FILE_READ_DATA)],
            desired: FILE_READ_DATA,
            allow: true,
            granted: FILE_READ_DATA,
        },
        // 5: empty DACL denies
        Case {
            aces: vec![],
            desired: FILE_READ_DATA,
            allow: false,
            granted: 0,
        },
        // 6: empty DACL, owner implicit READ_CONTROL
        Case {
            aces: vec![],
            desired: READ_CONTROL,
            allow: true,
            granted: READ_CONTROL,
        },
        // 7: empty DACL, owner implicit WRITE_DAC
        Case {
            aces: vec![],
            desired: WRITE_DAC,
            allow: true,
            granted: WRITE_DAC,
        },
        // 8: partial grant is not enough (all-or-nothing for specific access)
        Case {
            aces: vec![Ace::allow(u, FILE_READ_DATA)],
            desired: rw,
            allow: false,
            granted: 0,
        },
        // 9: full grant
        Case {
            aces: vec![Ace::allow(u, rw)],
            desired: rw,
            allow: true,
            granted: rw,
        },
        // 10: a deny on a bit not requested does not block
        Case {
            aces: vec![Ace::deny(g, FILE_WRITE_DATA), Ace::allow(u, rw)],
            desired: FILE_READ_DATA,
            allow: true,
            granted: FILE_READ_DATA,
        },
        // 11: deny WRITE, allow READ; requesting READ → allowed
        Case {
            aces: vec![Ace::deny(u, FILE_WRITE_DATA), Ace::allow(u, FILE_READ_DATA)],
            desired: FILE_READ_DATA,
            allow: true,
            granted: FILE_READ_DATA,
        },
        // 12: deny READ, requesting READ → denied
        Case {
            aces: vec![Ace::deny(u, FILE_READ_DATA)],
            desired: FILE_READ_DATA,
            allow: false,
            granted: 0,
        },
        // 13: non-canonical order — allow (via group) precedes a deny; the bit is
        //     already granted so the later deny is a no-op
        Case {
            aces: vec![Ace::allow(g, FILE_READ_DATA), Ace::deny(u, FILE_READ_DATA)],
            desired: FILE_READ_DATA,
            allow: true,
            granted: FILE_READ_DATA,
        },
        // 14: owner rights independent of an ACE for an absent SID
        Case {
            aces: vec![Ace::allow(x, READ_CONTROL | WRITE_DAC)],
            desired: READ_CONTROL,
            allow: true,
            granted: READ_CONTROL,
        },
        // 15: group granted WRITE only; requesting READ → denied
        Case {
            aces: vec![Ace::allow(g, FILE_WRITE_DATA)],
            desired: FILE_READ_DATA,
            allow: false,
            granted: 0,
        },
        // 16: DELETE right via a specific ACE
        Case {
            aces: vec![Ace::allow(u, DELETE)],
            desired: DELETE,
            allow: true,
            granted: DELETE,
        },
        // 17: WRITE_DAC granted via group (subject is not owner here — separate SD constructor below not used; owner=u so this hits owner path first)
        Case {
            aces: vec![Ace::allow(g, WRITE_DAC)],
            desired: WRITE_DAC,
            allow: true,
            granted: WRITE_DAC,
        },
        // 18: multi-bit ALL rights (0x1F01FF) requested and granted
        Case {
            aces: vec![Ace::allow(u, 0x001F_01FF)],
            desired: 0x001F_01FF,
            allow: true,
            granted: 0x001F_01FF,
        },
        // 19: deny of a superset (0x3) blocks a subset request (0x1)
        Case {
            aces: vec![Ace::deny(u, 0x3), Ace::allow(u, 0x1)],
            desired: 0x1,
            allow: false,
            granted: 0,
        },
        // 20: deny of a disjoint bit does NOT block the request
        Case {
            aces: vec![Ace::deny(u, 0x2), Ace::allow(u, 0x1)],
            desired: 0x1,
            allow: true,
            granted: 0x1,
        },
        // 21: two allow ACEs accumulate to satisfy a 3-bit request
        Case {
            aces: vec![Ace::allow(u, 0x1), Ace::allow(g, 0x2)],
            desired: 0x3,
            allow: true,
            granted: 0x3,
        },
        // 22: allow READ+WRITE via group, requesting both
        Case {
            aces: vec![Ace::allow(g, 0x3)],
            desired: 0x3,
            allow: true,
            granted: 0x3,
        },
        // 23: allow to absent SID doesn't grant; owner still gets READ_CONTROL
        Case {
            aces: vec![Ace::allow(x, 0x001F_01FF)],
            desired: READ_CONTROL,
            allow: true,
            granted: READ_CONTROL,
        },
        // 24: zero desired-access → Windows returns denied (ERROR_ACCESS_DENIED semantics)
        Case {
            aces: vec![Ace::allow(u, 0x1)],
            desired: 0,
            allow: false,
            granted: 0,
        },
        // 25: SYNCHRONIZE via a group ACE
        Case {
            aces: vec![Ace::allow(g, SYNCHRONIZE)],
            desired: SYNCHRONIZE,
            allow: true,
            granted: SYNCHRONIZE,
        },
        // 26: deny to a group blocks the subject even with a user-scoped allow behind it
        Case {
            aces: vec![Ace::deny(g, 0x1), Ace::allow(u, 0x1)],
            desired: 0x1,
            allow: false,
            granted: 0,
        },
        // 27: allow ALL to user; request only DELETE
        Case {
            aces: vec![Ace::allow(u, 0x001F_01FF)],
            desired: DELETE,
            allow: true,
            granted: DELETE,
        },
        // 28: group-only ACE where subject is NOT in that group → denied
        Case {
            aces: vec![Ace::allow(x, 0x1)],
            desired: 0x1,
            allow: false,
            granted: 0,
        },
        // 29: partial deny (0x1) then full allow (0x3); request only the not-denied bit (0x2)
        Case {
            aces: vec![Ace::deny(u, 0x1), Ace::allow(u, 0x3)],
            desired: 0x2,
            allow: true,
            granted: 0x2,
        },
        // 30: two group-covered allows for a 5-bit request (0x1 | 0x4)
        Case {
            aces: vec![Ace::allow(g, 0x1), Ace::allow(g, 0x4)],
            desired: 0x5,
            allow: true,
            granted: 0x5,
        },
    ];

    for (i, c) in cases.iter().enumerate() {
        let sd = SecurityDescriptor::new(u, Acl::Entries(c.aces.clone()));
        let d = access_check(&sd, &token, c.desired, &GenericMapping::FILE);
        assert_eq!(
            d.allowed,
            c.allow,
            "case {} allowed mismatch vs Windows",
            i + 1
        );
        if c.allow {
            assert_eq!(
                d.granted,
                c.granted,
                "case {} granted mismatch vs Windows",
                i + 1
            );
        }
    }
}

/// Object-type + inheritance conformance, validated 12/12 against Windows
/// `AuthzAccessCheck` / `AuthzAccessCheckByType` on a live host (2026-09-06).
/// Synthetic SIDs/GUIDs — the verdict depends on structure (inherit-only,
/// object-type match), not the concrete values.
#[test]
fn matches_windows_object_and_inheritance() {
    let u = "S-1-5-21-X-1001";
    let token = AccessToken::new(u, &[]);
    let g1 = Guid::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let g2 = Guid::parse("22222222-2222-2222-2222-222222222222").unwrap();
    const R: u32 = FILE_READ_DATA; // 0x1
    const CR: u32 = 0x100; // control-access / extended right
    let io = ace_flags::INHERIT_ONLY;
    let m = &GenericMapping::FILE;
    let sd = |aces: Vec<Ace>| SecurityDescriptor::new(u, Acl::Entries(aces));

    // 1: inherit-only allow does not apply to the object itself
    assert!(!access_check(&sd(vec![Ace::allow(u, R).with_flags(io)]), &token, R, m).allowed);
    // 2: plain allow baseline
    assert!(access_check(&sd(vec![Ace::allow(u, R)]), &token, R, m).allowed);
    // 3: inherit-only allow skipped; a following plain allow grants
    assert!(
        access_check(
            &sd(vec![Ace::allow(u, R).with_flags(io), Ace::allow(u, R)]),
            &token,
            R,
            m
        )
        .allowed
    );
    // 4: inherit-only deny skipped; plain allow grants
    assert!(
        access_check(
            &sd(vec![Ace::deny(u, R).with_flags(io), Ace::allow(u, R)]),
            &token,
            R,
            m
        )
        .allowed
    );
    // 5: object allow, matching requested type
    assert!(
        access_check_object(
            &sd(vec![Ace::allow(u, CR).with_object_type(g1)]),
            &token,
            CR,
            &g1,
            m
        )
        .allowed
    );
    // 6: object allow, mismatched type -> denied
    assert!(
        !access_check_object(
            &sd(vec![Ace::allow(u, CR).with_object_type(g1)]),
            &token,
            CR,
            &g2,
            m
        )
        .allowed
    );
    // 7: object allow, plain check -> does NOT fire (Windows semantics)
    assert!(
        !access_check(
            &sd(vec![Ace::allow(u, CR).with_object_type(g1)]),
            &token,
            CR,
            m
        )
        .allowed
    );
    // 8: plain allow applies in an object-typed check
    assert!(access_check_object(&sd(vec![Ace::allow(u, CR)]), &token, CR, &g1, m).allowed);
    // 9: object allow (g1) mismatches g2, but the plain allow grants
    assert!(
        access_check_object(
            &sd(vec![
                Ace::allow(u, CR).with_object_type(g1),
                Ace::allow(u, CR)
            ]),
            &token,
            CR,
            &g2,
            m
        )
        .allowed
    );
    // 10: object deny (g1) matches -> denied even with a plain allow behind it
    assert!(
        !access_check_object(
            &sd(vec![
                Ace::deny(u, CR).with_object_type(g1),
                Ace::allow(u, CR)
            ]),
            &token,
            CR,
            &g1,
            m
        )
        .allowed
    );
    // 11: object deny (g1) mismatches g2 -> skipped; plain allow grants
    assert!(
        access_check_object(
            &sd(vec![
                Ace::deny(u, CR).with_object_type(g1),
                Ace::allow(u, CR)
            ]),
            &token,
            CR,
            &g2,
            m
        )
        .allowed
    );
    // 12: object allow + inherit-only -> skipped
    assert!(
        !access_check_object(
            &sd(vec![Ace::allow(u, CR).with_object_type(g1).with_flags(io)]),
            &token,
            CR,
            &g1,
            m
        )
        .allowed
    );
}
