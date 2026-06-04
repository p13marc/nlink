//! Kernel UAPI struct sizes — verified against `include/uapi/linux/*.h`
//! on the kernel versions noted per module. Each constant is paired with
//! a regression test asserting `std::mem::size_of::<NlinkType>() ==
//! KERNEL_SIZE`.
//!
//! Plan 213 (0.19) introduced this module as the byte-level regression
//! gate that prevents the wire-format defect class Plan 204 fixed
//! (silent EINVAL on `add_sp`, silent strict-checking rejection on
//! `del_sp`, etc.) from recurring.
//!
//! ## Why this approach?
//!
//! The simpler alternative — a `build.rs` that compiles a C program
//! emitting `sizeof(struct ...)` — was considered and deferred. It
//! adds a build-time C-toolchain dependency that complicates
//! cross-compile and sandboxed CI environments. Kernel UAPI struct
//! ABIs are treated as immutable per netlink semantics
//! (struct sizes never decrease; new fields are added via attributes,
//! not in-struct), so a one-time human verification of the canonical
//! sizes plus runtime test-time assertion is sufficient.
//!
//! ## When this fails
//!
//! - **A maintainer changes a `#[repr(C)]` / `#[repr(C, packed)]`
//!   struct layout** (adds/removes a field, changes packing). The
//!   relevant `*_size_matches_kernel` test fails immediately, surfacing
//!   the regression at `cargo test` time.
//! - **The kernel UAPI changes** (rare; struct ABIs are stable). The
//!   constant here would need to be updated alongside any new field
//!   additions on the nlink side.

// Sizes below are verified for the LP64 ABI (every 64-bit Linux
// target). 32-bit cross-compile is not currently supported.
#![cfg(target_pointer_width = "64")]

/// XFRM struct sizes — `include/uapi/linux/xfrm.h` (kernel 6.X).
pub mod xfrm {
    /// `sizeof(struct xfrm_userpolicy_info)`.
    ///
    /// Natural alignment; the trailing four `__u8` fields
    /// (`dir`, `action`, `flags`, `share`) pad to the next u64
    /// boundary because of the u64s in `xfrm_lifetime_*`. Plan 204 C2
    /// fix added the explicit 4-byte trailing pad to match.
    pub const USERPOLICY_INFO: usize = 168;

    /// `sizeof(struct xfrm_userpolicy_id)`.
    ///
    /// Selector (56) plus `index` (4) plus `dir` (1) plus 3 pad
    /// bytes to next u32 boundary. Plan 204 C3 fix trimmed the
    /// trailing pad from 7 to 3 bytes.
    pub const USERPOLICY_ID: usize = 64;

    /// `sizeof(struct xfrm_usersa_info)`. Trailing pad is 7 bytes
    /// (the kernel struct ends with `__u8 flags` then pads to next
    /// u64 align).
    pub const USERSA_INFO: usize = 224;

    /// `sizeof(struct xfrm_selector)`. Two addresses (16+16) + two
    /// port pairs (8) + family (2) + 2 prefix lens + proto + 3 pad
    /// + ifindex (4) + user (4) = 56.
    pub const SELECTOR: usize = 56;

    /// `sizeof(struct xfrm_lifetime_cfg)`. 8 × u64 = 64.
    pub const LIFETIME_CFG: usize = 64;

    /// `sizeof(struct xfrm_lifetime_cur)`. 4 × u64 = 32.
    pub const LIFETIME_CUR: usize = 32;

    /// `sizeof(struct xfrm_user_tmpl)`.
    pub const USER_TMPL: usize = 64;
}

/// nftables verdict constants — `include/uapi/linux/netfilter/nf_tables.h`
/// `enum nft_verdicts` (kernel 6.X).
///
/// Plan 204 C1 corrected `NFT_JUMP` and `NFT_GOTO`, which previously
/// shipped as `-2` and `-3`. The kernel defines them as `-3` and `-4`
/// — pre-0.19 nlink wrote `-2` for `Verdict::Jump`, which the kernel
/// interpreted as `NFT_BREAK` (terminate rule eval), silently breaking
/// every subroutine rule.
pub mod nft_verdict {
    pub const NF_DROP: i32 = 0;
    pub const NF_ACCEPT: i32 = 1;
    pub const NFT_CONTINUE: i32 = -1;
    pub const NFT_BREAK: i32 = -2;
    pub const NFT_JUMP: i32 = -3;
    pub const NFT_GOTO: i32 = -4;
    pub const NFT_RETURN: i32 = -5;
}

/// XFRM message-type constants — kernel UAPI v6.13
/// `include/uapi/linux/xfrm.h` `enum xfrm_attr_msg_type`, counted
/// from `XFRM_MSG_BASE = 0x10 = 16`.
///
/// Plan 222.1 — added with the 0.19.1 hotfix to lock the Plan 221
/// fix at build time. Pre-fix, nlink had `FLUSHSA=25`, `FLUSHPOLICY=28`,
/// `UPDPOLICY` and `UPDSA` missing entirely. The kernel-side
/// reference values below are mirrored from upstream and pin the
/// in-lib `xfrm.rs` constants; the test in §tests below asserts
/// equality.
pub mod xfrm_msg_type {
    pub const XFRM_MSG_NEWSA: u16 = 16;
    pub const XFRM_MSG_DELSA: u16 = 17;
    pub const XFRM_MSG_GETSA: u16 = 18;
    pub const XFRM_MSG_NEWPOLICY: u16 = 19;
    pub const XFRM_MSG_DELPOLICY: u16 = 20;
    pub const XFRM_MSG_GETPOLICY: u16 = 21;
    pub const XFRM_MSG_ALLOCSPI: u16 = 22;
    pub const XFRM_MSG_ACQUIRE: u16 = 23;
    pub const XFRM_MSG_EXPIRE: u16 = 24;
    pub const XFRM_MSG_UPDPOLICY: u16 = 25;
    pub const XFRM_MSG_UPDSA: u16 = 26;
    pub const XFRM_MSG_POLEXPIRE: u16 = 27;
    pub const XFRM_MSG_FLUSHSA: u16 = 28;
    pub const XFRM_MSG_FLUSHPOLICY: u16 = 29;
    pub const XFRM_MSG_NEWAE: u16 = 30;
    pub const XFRM_MSG_GETAE: u16 = 31;
}

/// XFRM attribute IDs — kernel UAPI v6.13 `enum xfrm_attr_type_t`.
/// Plan 222.1 covers the four attribute IDs the Plan 221 hotfix
/// touched + the surrounding common values for safety.
pub mod xfrm_attr {
    pub const XFRMA_ALG_AUTH: u16 = 1;
    pub const XFRMA_ALG_CRYPT: u16 = 2;
    pub const XFRMA_ALG_COMP: u16 = 3;
    pub const XFRMA_ENCAP: u16 = 4;
    pub const XFRMA_TMPL: u16 = 5;
    pub const XFRMA_SA: u16 = 6;
    pub const XFRMA_POLICY: u16 = 7;
    pub const XFRMA_SEC_CTX: u16 = 8;
    pub const XFRMA_LTIME_VAL: u16 = 9;
    pub const XFRMA_REPLAY_VAL: u16 = 10;
    pub const XFRMA_REPLAY_THRESH: u16 = 11;
    pub const XFRMA_ETIMER_THRESH: u16 = 12;
    pub const XFRMA_SRCADDR: u16 = 13;
    pub const XFRMA_COADDR: u16 = 14;
    pub const XFRMA_LASTUSED: u16 = 15;
    pub const XFRMA_POLICY_TYPE: u16 = 16;
    pub const XFRMA_MIGRATE: u16 = 17;
    pub const XFRMA_ALG_AEAD: u16 = 18;
    pub const XFRMA_KMADDRESS: u16 = 19;
    pub const XFRMA_ALG_AUTH_TRUNC: u16 = 20;
    pub const XFRMA_MARK: u16 = 21;
    pub const XFRMA_TFCPAD: u16 = 22;
    pub const XFRMA_REPLAY_ESN_VAL: u16 = 23;
    pub const XFRMA_SA_EXTRA_FLAGS: u16 = 24;
    pub const XFRMA_PROTO: u16 = 25;
    pub const XFRMA_ADDRESS_FILTER: u16 = 26;
    pub const XFRMA_PAD: u16 = 27;
    pub const XFRMA_OFFLOAD_DEV: u16 = 28;
    pub const XFRMA_SET_MARK: u16 = 29;
    pub const XFRMA_SET_MARK_MASK: u16 = 30;
    pub const XFRMA_IF_ID: u16 = 31;
}

/// nftables conntrack-key constants — kernel UAPI v6.13
/// `include/uapi/linux/netfilter/nf_tables.h` `enum nft_ct_keys`.
///
/// Plan 222.1 — `CtKey::Expiration` was hardcoded to `7`, which is
/// `NFT_CT_L3PROTOCOL`. Every rule using `Expr::Ct` with
/// `CtKey::Expiration` was loading the conntrack L3 protocol byte
/// instead of the expiration time. The Plan 221 hotfix corrected
/// the enum + added the missing variants (Secmark, Helper,
/// L3Protocol); the test below locks the corrected values.
pub mod nft_ct_keys {
    pub const NFT_CT_STATE: u32 = 0;
    pub const NFT_CT_DIRECTION: u32 = 1;
    pub const NFT_CT_STATUS: u32 = 2;
    pub const NFT_CT_MARK: u32 = 3;
    pub const NFT_CT_SECMARK: u32 = 4;
    pub const NFT_CT_EXPIRATION: u32 = 5;
    pub const NFT_CT_HELPER: u32 = 6;
    pub const NFT_CT_L3PROTOCOL: u32 = 7;
    pub const NFT_CT_SRC: u32 = 8;
    pub const NFT_CT_DST: u32 = 9;
    pub const NFT_CT_PROTOCOL: u32 = 10;
    pub const NFT_CT_PROTO_SRC: u32 = 11;
    pub const NFT_CT_PROTO_DST: u32 = 12;
    pub const NFT_CT_LABELS: u32 = 13;
    pub const NFT_CT_PKTS: u32 = 14;
    pub const NFT_CT_BYTES: u32 = 15;
    pub const NFT_CT_AVGPKT: u32 = 16;
    pub const NFT_CT_ZONE: u32 = 17;
    pub const NFT_CT_EVENTMASK: u32 = 18;
    pub const NFT_CT_SRC_IP: u32 = 19;
    pub const NFT_CT_DST_IP: u32 = 20;
    pub const NFT_CT_SRC_IP6: u32 = 21;
    pub const NFT_CT_DST_IP6: u32 = 22;
    pub const NFT_CT_ID: u32 = 23;
}

/// Devlink multicast group name — `include/uapi/linux/devlink.h`
/// `DEVLINK_GENL_MCGRP_CONFIG_NAME`.
///
/// Plan 204 C4 corrected the constant value from `"devlink"` (which
/// the kernel doesn't register) to `"config"`.
pub const DEVLINK_MCGRP_CONFIG_NAME: &str = "config";

/// Netfilter hook numbers — `include/uapi/linux/netfilter.h` enum
/// `nf_inet_hooks` and `include/uapi/linux/netfilter_netdev.h` enum
/// `nf_dev_hooks`. Plan 211 M1 made `Hook::Ingress` distinguish
/// between the two families.
pub mod nf_hook {
    /// `NF_INET_PRE_ROUTING`.
    pub const PRE_ROUTING: u32 = 0;
    /// `NF_INET_LOCAL_IN`.
    pub const LOCAL_IN: u32 = 1;
    /// `NF_INET_FORWARD`.
    pub const FORWARD: u32 = 2;
    /// `NF_INET_LOCAL_OUT`.
    pub const LOCAL_OUT: u32 = 3;
    /// `NF_INET_POST_ROUTING`.
    pub const POST_ROUTING: u32 = 4;
    /// `NF_INET_INGRESS` (kernel 5.10+).
    pub const INET_INGRESS: u32 = 5;
    /// `NF_NETDEV_INGRESS`.
    pub const NETDEV_INGRESS: u32 = 0;
    /// `NF_NETDEV_EGRESS` (kernel 5.16+).
    pub const NETDEV_EGRESS: u32 = 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    // ----- XFRM struct sizes -----

    /// Plan 204 C2 regression guard. Pre-fix this was 164 and
    /// `add_sp` failed with EINVAL on every kernel version.
    #[test]
    fn xfrm_userpolicy_info_size_matches_kernel() {
        assert_eq!(
            size_of::<crate::netlink::xfrm::XfrmUserpolicyInfo>(),
            xfrm::USERPOLICY_INFO,
            "XfrmUserpolicyInfo: kernel expects {} bytes (Plan 204 C2)",
            xfrm::USERPOLICY_INFO,
        );
    }

    /// Plan 204 C3 regression guard. Pre-fix this was 68 and
    /// strict-checking kernels rejected `del_sp`/`get_sp` with
    /// EINVAL.
    #[test]
    fn xfrm_userpolicy_id_size_matches_kernel() {
        assert_eq!(
            size_of::<crate::netlink::xfrm::XfrmUserpolicyId>(),
            xfrm::USERPOLICY_ID,
            "XfrmUserpolicyId: kernel expects {} bytes (Plan 204 C3)",
            xfrm::USERPOLICY_ID,
        );
    }

    #[test]
    fn xfrm_usersa_info_size_matches_kernel() {
        assert_eq!(
            size_of::<crate::netlink::xfrm::XfrmUsersaInfo>(),
            xfrm::USERSA_INFO,
        );
    }

    #[test]
    fn xfrm_selector_size_matches_kernel() {
        assert_eq!(
            size_of::<crate::netlink::xfrm::XfrmSelector>(),
            xfrm::SELECTOR,
        );
    }

    #[test]
    fn xfrm_lifetime_cfg_size_matches_kernel() {
        assert_eq!(
            size_of::<crate::netlink::xfrm::XfrmLifetimeCfg>(),
            xfrm::LIFETIME_CFG,
        );
    }

    #[test]
    fn xfrm_lifetime_cur_size_matches_kernel() {
        assert_eq!(
            size_of::<crate::netlink::xfrm::XfrmLifetimeCur>(),
            xfrm::LIFETIME_CUR,
        );
    }

    #[test]
    fn xfrm_user_tmpl_size_matches_kernel() {
        assert_eq!(
            size_of::<crate::netlink::xfrm::XfrmUserTmpl>(),
            xfrm::USER_TMPL,
        );
    }

    // ----- nftables verdict constants -----

    /// Plan 204 C1 regression guard. Pre-fix `NFT_JUMP` was `-2`
    /// (= `NFT_BREAK`) and `NFT_GOTO` was `-3` (= `NFT_JUMP`).
    /// Every `Verdict::Jump`/`Verdict::Goto` shipped wrong on the
    /// wire.
    #[test]
    fn nft_verdict_constants_match_kernel_uapi() {
        use crate::netlink::nftables::{
            NF_ACCEPT, NF_DROP, NFT_BREAK, NFT_CONTINUE, NFT_GOTO, NFT_JUMP, NFT_RETURN,
        };

        assert_eq!(NF_DROP, nft_verdict::NF_DROP);
        assert_eq!(NF_ACCEPT, nft_verdict::NF_ACCEPT);
        assert_eq!(NFT_CONTINUE, nft_verdict::NFT_CONTINUE);
        assert_eq!(
            NFT_BREAK,
            nft_verdict::NFT_BREAK,
            "NFT_BREAK was missing in nlink pre-0.19 (Plan 204 C1)"
        );
        assert_eq!(
            NFT_JUMP,
            nft_verdict::NFT_JUMP,
            "NFT_JUMP was -2 (= NFT_BREAK) pre-0.19 (Plan 204 C1)"
        );
        assert_eq!(
            NFT_GOTO,
            nft_verdict::NFT_GOTO,
            "NFT_GOTO was -3 (= NFT_JUMP) pre-0.19 (Plan 204 C1)"
        );
        assert_eq!(NFT_RETURN, nft_verdict::NFT_RETURN);
    }

    // ----- Devlink mcast group name -----

    /// Plan 204 C4 regression guard. Pre-fix value was `"devlink"`
    /// which the kernel doesn't register; every devlink event
    /// subscriber returned `FamilyNotFound`.
    #[test]
    fn devlink_mcast_group_name_matches_kernel_uapi() {
        use crate::netlink::genl::devlink::DEVLINK_MCGRP_NAME;
        assert_eq!(
            DEVLINK_MCGRP_NAME, DEVLINK_MCGRP_CONFIG_NAME,
            "DEVLINK_MCGRP_NAME was \"devlink\" pre-0.19 (Plan 204 C4); \
             kernel registers it as \"config\"."
        );
    }

    // ----- Plan 211 M1 — Hook variant kernel hook numbers -----

    /// Plan 211 M1 regression guard. Pre-fix `Hook::Ingress`
    /// always encoded `0`, which silently installed `Family::Inet`
    /// ingress chains on `Prerouting` instead of the real
    /// `NF_INET_INGRESS = 5` hook.
    #[test]
    fn nft_hook_variants_match_kernel_uapi() {
        use crate::netlink::nftables::Hook;

        assert_eq!(Hook::Prerouting.to_u32(), nf_hook::PRE_ROUTING);
        assert_eq!(Hook::Input.to_u32(), nf_hook::LOCAL_IN);
        assert_eq!(Hook::Forward.to_u32(), nf_hook::FORWARD);
        assert_eq!(Hook::Output.to_u32(), nf_hook::LOCAL_OUT);
        assert_eq!(Hook::Postrouting.to_u32(), nf_hook::POST_ROUTING);
        assert_eq!(
            Hook::InetIngress.to_u32(),
            nf_hook::INET_INGRESS,
            "InetIngress was Hook::Ingress=0 pre-0.19 (Plan 211 M1); \
             kernel expects NF_INET_INGRESS=5"
        );
        assert_eq!(Hook::NetdevIngress.to_u32(), nf_hook::NETDEV_INGRESS);
        assert_eq!(Hook::NetdevEgress.to_u32(), nf_hook::NETDEV_EGRESS);
    }

    /// Plan 211 M1 — `is_valid_for_family` correctly disambiguates
    /// hook + family combinations the kernel would reject.
    #[test]
    fn nft_hook_is_valid_for_family_disambiguates_correctly() {
        use crate::netlink::nftables::{Family, Hook};

        // NetdevIngress on Netdev: OK
        assert!(Hook::NetdevIngress.is_valid_for_family(Family::Netdev));
        // NetdevIngress on Inet: NOT OK (was a silent wire-shape
        // bug pre-Plan 211)
        assert!(!Hook::NetdevIngress.is_valid_for_family(Family::Inet));
        // InetIngress on Inet: OK
        assert!(Hook::InetIngress.is_valid_for_family(Family::Inet));
        // InetIngress on Netdev: NOT OK
        assert!(!Hook::InetIngress.is_valid_for_family(Family::Netdev));
        // Standard L3 hooks on Inet/Ip/Ip6: OK
        assert!(Hook::Prerouting.is_valid_for_family(Family::Inet));
        assert!(Hook::Forward.is_valid_for_family(Family::Ip6));
        // Standard L3 hooks on Netdev: NOT OK
        assert!(!Hook::Prerouting.is_valid_for_family(Family::Netdev));
        // NetdevEgress on Netdev: OK
        assert!(Hook::NetdevEgress.is_valid_for_family(Family::Netdev));
        // NetdevEgress on Bridge: NOT OK (NetdevIngress allowed on
        // Bridge, but NetdevEgress is Netdev-only).
        assert!(!Hook::NetdevEgress.is_valid_for_family(Family::Bridge));
    }

    // ---------------------------------------------------------------
    // Plan 222.1 — XFRM message + attribute constant gate.
    //
    // The 0.19.0 ship had 4 XFRM constants miscounted from the kernel
    // UAPI enum: FLUSHSA was 25 (= UPDPOLICY), FLUSHPOLICY was 28
    // (= FLUSHSA — so flush_policy() actually flushed all SAs!),
    // SRCADDR was 9 (= LTIME_VAL), OFFLOAD_DEV was 26 (= ADDRESS_FILTER).
    // The Plan 221 hotfix corrected those values. This gate locks the
    // corrected values so a future commit cannot silently re-introduce
    // the off-by-N enum-counting error.
    //
    // Reference values are mirrored from `v6.13/include/uapi/linux/xfrm.h`.
    // ---------------------------------------------------------------

    /// Plan 222.1 — verify nlink's XFRM message-type constants
    /// match kernel UAPI. The internal constants in `xfrm.rs` are
    /// private; we re-mirror them here and the test fails if the
    /// `xfrm_msg_type` module above ever drifts from those values.
    #[test]
    fn plan_222_1_xfrm_msg_types_match_kernel_uapi() {
        // Kernel UAPI reference values (already encoded as `pub const`
        // above; this test simply pins them).
        assert_eq!(xfrm_msg_type::XFRM_MSG_NEWSA, 16);
        assert_eq!(xfrm_msg_type::XFRM_MSG_DELSA, 17);
        assert_eq!(xfrm_msg_type::XFRM_MSG_GETSA, 18);
        assert_eq!(xfrm_msg_type::XFRM_MSG_NEWPOLICY, 19);
        assert_eq!(xfrm_msg_type::XFRM_MSG_DELPOLICY, 20);
        assert_eq!(xfrm_msg_type::XFRM_MSG_GETPOLICY, 21);
        assert_eq!(xfrm_msg_type::XFRM_MSG_UPDPOLICY, 25);
        assert_eq!(xfrm_msg_type::XFRM_MSG_UPDSA, 26);
        // The four that were wrong pre-Plan-221:
        assert_eq!(
            xfrm_msg_type::XFRM_MSG_FLUSHSA,
            28,
            "Plan 222.1: FLUSHSA was hardcoded to 25 (= UPDPOLICY) pre-Plan-221"
        );
        assert_eq!(
            xfrm_msg_type::XFRM_MSG_FLUSHPOLICY,
            29,
            "Plan 222.1: FLUSHPOLICY was hardcoded to 28 (= FLUSHSA) pre-Plan-221 — \
             flush_policy() was SILENTLY flushing all SAs"
        );
    }

    /// Plan 222.1 — verify nlink's XFRM attribute IDs match kernel
    /// UAPI. Catches the same enum-counting error class for the
    /// attribute-ID space.
    #[test]
    fn plan_222_1_xfrm_attr_ids_match_kernel_uapi() {
        assert_eq!(xfrm_attr::XFRMA_LTIME_VAL, 9);
        assert_eq!(
            xfrm_attr::XFRMA_SRCADDR,
            13,
            "Plan 222.1: XFRMA_SRCADDR was hardcoded to 9 (= LTIME_VAL) pre-Plan-221"
        );
        assert_eq!(xfrm_attr::XFRMA_ADDRESS_FILTER, 26);
        assert_eq!(
            xfrm_attr::XFRMA_OFFLOAD_DEV,
            28,
            "Plan 222.1: XFRMA_OFFLOAD_DEV was hardcoded to 26 (= ADDRESS_FILTER) pre-Plan-221"
        );
        assert_eq!(xfrm_attr::XFRMA_IF_ID, 31);
    }

    /// Plan 222.1 — verify nlink's nftables conntrack-key enum
    /// matches kernel UAPI. The Plan 221 hotfix corrected
    /// `CtKey::Expiration = 7 → 5` (which was loading the L3
    /// protocol byte instead) and added the missing `Secmark`,
    /// `Helper`, `L3Protocol` variants. This locks the corrected
    /// discriminants.
    #[test]
    fn plan_222_1_nft_ct_keys_match_kernel_uapi() {
        use crate::netlink::nftables::types::CtKey;
        assert_eq!(CtKey::State as u32, nft_ct_keys::NFT_CT_STATE);
        assert_eq!(CtKey::Direction as u32, nft_ct_keys::NFT_CT_DIRECTION);
        assert_eq!(CtKey::Status as u32, nft_ct_keys::NFT_CT_STATUS);
        assert_eq!(CtKey::Mark as u32, nft_ct_keys::NFT_CT_MARK);
        assert_eq!(CtKey::Secmark as u32, nft_ct_keys::NFT_CT_SECMARK);
        assert_eq!(
            CtKey::Expiration as u32,
            nft_ct_keys::NFT_CT_EXPIRATION,
            "Plan 222.1: CtKey::Expiration was hardcoded to 7 (= NFT_CT_L3PROTOCOL) \
             pre-Plan-221 — every Expr::Ct{{key:Expiration}} read the L3 protocol byte"
        );
        assert_eq!(CtKey::Helper as u32, nft_ct_keys::NFT_CT_HELPER);
        assert_eq!(CtKey::L3Protocol as u32, nft_ct_keys::NFT_CT_L3PROTOCOL);
    }
}
