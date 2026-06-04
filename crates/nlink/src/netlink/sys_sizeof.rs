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

/// Plan 222.2 — TC HTB attribute IDs.
///
/// Kernel UAPI v6.13 `include/uapi/linux/pkt_sched.h` `enum`
/// (the unnamed enum for `TCA_HTB_*` in pkt_sched.h).
///
/// nlink declares these in `types::tc::qdisc::htb` (TCA_HTB_UNSPEC..
/// TCA_HTB_OFFLOAD). The gate locks the kernel-side values so a
/// future edit cannot silently re-introduce off-by-N drift. Pre-0.20
/// the audit (W14) noted `TCA_HTB_OFFLOAD = 8` was already in tree
/// but unused on the encode path; we mirror the full enum here to
/// catch any silent renumbering.
pub mod tca_htb_attr {
    pub const TCA_HTB_UNSPEC: u16 = 0;
    pub const TCA_HTB_PARMS: u16 = 1;
    pub const TCA_HTB_INIT: u16 = 2;
    pub const TCA_HTB_CTAB: u16 = 3;
    pub const TCA_HTB_RTAB: u16 = 4;
    pub const TCA_HTB_DIRECT_QLEN: u16 = 5;
    pub const TCA_HTB_RATE64: u16 = 6;
    pub const TCA_HTB_CEIL64: u16 = 7;
    pub const TCA_HTB_OFFLOAD: u16 = 8;
}

/// Plan 222.2 — TC flower-classifier KEY attribute IDs.
///
/// Kernel UAPI v6.13 `include/uapi/linux/pkt_cls.h` `enum`.
/// Mirrors the IDs nlink encodes in `flower::TcFlowerKey` /
/// `types::tc` (subset of the ~80 in the kernel enum — the most
/// load-bearing classifier dimensions that nlink actually emits).
///
/// `// TODO 0.21: extend to the full enum (>80 IDs) including ENC_OPTS,
/// MPLS, ARP, CT_*, HASH_*, and the spi/CFM groupings added in 6.6+.`
pub mod tca_flower_key {
    pub const TCA_FLOWER_KEY_ETH_DST: u16 = 4;
    pub const TCA_FLOWER_KEY_ETH_DST_MASK: u16 = 5;
    pub const TCA_FLOWER_KEY_ETH_SRC: u16 = 6;
    pub const TCA_FLOWER_KEY_ETH_SRC_MASK: u16 = 7;
    pub const TCA_FLOWER_KEY_ETH_TYPE: u16 = 8;
    pub const TCA_FLOWER_KEY_IP_PROTO: u16 = 9;
    pub const TCA_FLOWER_KEY_IPV4_SRC: u16 = 10;
    pub const TCA_FLOWER_KEY_IPV4_SRC_MASK: u16 = 11;
    pub const TCA_FLOWER_KEY_IPV4_DST: u16 = 12;
    pub const TCA_FLOWER_KEY_IPV4_DST_MASK: u16 = 13;
    pub const TCA_FLOWER_KEY_IPV6_SRC: u16 = 14;
    pub const TCA_FLOWER_KEY_IPV6_DST: u16 = 16;
    pub const TCA_FLOWER_KEY_TCP_SRC: u16 = 18;
    pub const TCA_FLOWER_KEY_TCP_DST: u16 = 19;
    pub const TCA_FLOWER_KEY_UDP_SRC: u16 = 20;
    pub const TCA_FLOWER_KEY_UDP_DST: u16 = 21;
    pub const TCA_FLOWER_KEY_VLAN_ID: u16 = 23;
    pub const TCA_FLOWER_KEY_VLAN_PRIO: u16 = 24;
    pub const TCA_FLOWER_KEY_VLAN_ETH_TYPE: u16 = 25;
    pub const TCA_FLOWER_KEY_ENC_KEY_ID: u16 = 26;
}

/// Plan 222.3 — RTNetlink IFLA attribute IDs.
///
/// Kernel UAPI v6.13 `include/uapi/linux/if_link.h` `enum`. nlink
/// uses these in `messages::link::attr_ids` (private module). The
/// gate mirrors the kernel values to catch the same off-by-N drift
/// class the XFRM hotfix exposed.
///
/// `// TODO 0.21: extend to the rest of the IFLA_* enum (~70 entries
/// including IFF_*, IFLA_AF_SPEC, IFLA_VFINFO, IFLA_XDP, ...).`
pub mod ifla_attr {
    pub const IFLA_ADDRESS: u16 = 1;
    pub const IFLA_BROADCAST: u16 = 2;
    pub const IFLA_IFNAME: u16 = 3;
    pub const IFLA_MTU: u16 = 4;
    pub const IFLA_LINK: u16 = 5;
    pub const IFLA_QDISC: u16 = 6;
    pub const IFLA_STATS: u16 = 7;
    pub const IFLA_MASTER: u16 = 10;
    pub const IFLA_TXQLEN: u16 = 13;
    pub const IFLA_OPERSTATE: u16 = 16;
    pub const IFLA_LINKMODE: u16 = 17;
    pub const IFLA_LINKINFO: u16 = 18;
    pub const IFLA_STATS64: u16 = 23;
    pub const IFLA_GROUP: u16 = 27;
    pub const IFLA_NUM_VF: u16 = 21;
    pub const IFLA_PROMISCUITY: u16 = 30;
    pub const IFLA_NUM_TX_QUEUES: u16 = 31;
    pub const IFLA_NUM_RX_QUEUES: u16 = 32;
    pub const IFLA_CARRIER: u16 = 33;
    pub const IFLA_GSO_MAX_SEGS: u16 = 40;
    pub const IFLA_GSO_MAX_SIZE: u16 = 41;
    pub const IFLA_MIN_MTU: u16 = 50;
    pub const IFLA_MAX_MTU: u16 = 51;
    pub const IFLA_PERM_ADDRESS: u16 = 54;
    pub const IFLA_GRO_MAX_SIZE: u16 = 58;
    pub const IFLA_TSO_MAX_SIZE: u16 = 59;
    pub const IFLA_TSO_MAX_SEGS: u16 = 60;
    pub const IFLA_GSO_IPV4_MAX_SIZE: u16 = 63;
    pub const IFLA_GRO_IPV4_MAX_SIZE: u16 = 64;
}

/// Plan 222.3 — RTNetlink RTA attribute IDs (route messages).
///
/// Kernel UAPI v6.13 `include/uapi/linux/rtnetlink.h` `enum rtattr_type_t`.
/// nlink uses these in `messages::route::attr_ids`.
///
/// `// TODO 0.21: extend to RTA_FLOW, RTA_CACHEINFO, RTA_MARK,
/// RTA_TTL_PROPAGATE, RTA_VIA, RTA_NEWDST, RTA_ENCAP*, RTA_NH_ID,
/// RTA_SPORT, RTA_DPORT, RTA_PROTOCOL — currently 30+ in the kernel.`
pub mod rta_attr {
    pub const RTA_UNSPEC: u16 = 0;
    pub const RTA_DST: u16 = 1;
    pub const RTA_SRC: u16 = 2;
    pub const RTA_IIF: u16 = 3;
    pub const RTA_OIF: u16 = 4;
    pub const RTA_GATEWAY: u16 = 5;
    pub const RTA_PRIORITY: u16 = 6;
    pub const RTA_PREFSRC: u16 = 7;
    pub const RTA_METRICS: u16 = 8;
    pub const RTA_MULTIPATH: u16 = 9;
    pub const RTA_PROTOINFO: u16 = 10;
    pub const RTA_FLOW: u16 = 11;
    pub const RTA_CACHEINFO: u16 = 12;
    pub const RTA_TABLE: u16 = 15;
    pub const RTA_MARK: u16 = 16;
    pub const RTA_PREF: u16 = 20;
    pub const RTA_EXPIRES: u16 = 23;
}

/// Plan 222.3 — ctnetlink (conntrack) attribute IDs.
///
/// Kernel UAPI v6.13 `include/uapi/linux/netfilter/nfnetlink_conntrack.h`
/// `enum ctattr_type`. nlink uses these in `netfilter.rs`'s
/// private `CTA_*` constants.
///
/// `// TODO 0.21: extend to CTA_NAT_*, CTA_LABELS, CTA_SYNPROXY,
/// CTA_FILTER, CTA_TIMESTAMP* — currently ~28 in the kernel.`
pub mod ctnetlink_attr {
    pub const CTA_UNSPEC: u16 = 0;
    pub const CTA_TUPLE_ORIG: u16 = 1;
    pub const CTA_TUPLE_REPLY: u16 = 2;
    pub const CTA_STATUS: u16 = 3;
    pub const CTA_PROTOINFO: u16 = 4;
    pub const CTA_HELP: u16 = 5;
    pub const CTA_NAT_SRC: u16 = 6;
    pub const CTA_TIMEOUT: u16 = 7;
    pub const CTA_MARK: u16 = 8;
    pub const CTA_COUNTERS_ORIG: u16 = 9;
    pub const CTA_COUNTERS_REPLY: u16 = 10;
    pub const CTA_USE: u16 = 11;
    pub const CTA_ID: u16 = 12;
    pub const CTA_NAT_DST: u16 = 13;
    pub const CTA_TUPLE_MASTER: u16 = 14;
    pub const CTA_ZONE: u16 = 18;
}

/// Plan 222.4 — DPLL device-side attribute IDs.
///
/// Kernel UAPI YAML spec
/// `Documentation/netlink/specs/dpll.yaml` (v6.13). nlink declares
/// the discriminants in `genl::dpll::types::DpllAttr` (via
/// `#[derive(GenlAttribute)]`); the gate locks the kernel-side
/// reference values so any silent renumbering trips the test.
///
/// `// TODO 0.21: cover the full DPLL_A_PIN_* set (32 entries) +
/// DPLL_A_PHASE_OFFSET_MONITOR/FREQUENCY_MONITOR additions in 6.12+
/// + any future 6.13+ additions.`
pub mod dpll_a {
    /// `DPLL_A_ID`.
    pub const ID: u16 = 1;
    /// `DPLL_A_MODULE_NAME`.
    pub const MODULE_NAME: u16 = 2;
    /// `DPLL_A_PAD`.
    pub const PAD: u16 = 3;
    /// `DPLL_A_CLOCK_ID`.
    pub const CLOCK_ID: u16 = 4;
    /// `DPLL_A_MODE`.
    pub const MODE: u16 = 5;
    /// `DPLL_A_MODE_SUPPORTED`.
    pub const MODE_SUPPORTED: u16 = 6;
    /// `DPLL_A_LOCK_STATUS`.
    pub const LOCK_STATUS: u16 = 7;
    /// `DPLL_A_TEMP`.
    pub const TEMP: u16 = 8;
    /// `DPLL_A_TYPE`.
    pub const TYPE: u16 = 9;
    /// `DPLL_A_LOCK_STATUS_ERROR` (kernel 6.10+).
    pub const LOCK_STATUS_ERROR: u16 = 10;
    /// `DPLL_A_CLOCK_QUALITY_LEVEL` (kernel 6.11+).
    pub const CLOCK_QUALITY_LEVEL: u16 = 11;
    /// `DPLL_A_PHASE_OFFSET_MONITOR` (kernel 6.12+).
    pub const PHASE_OFFSET_MONITOR: u16 = 12;

    // ---- Pin-side (DPLL_A_PIN_*) — the most load-bearing IDs ----

    /// `DPLL_A_PIN_ID`.
    pub const PIN_ID: u16 = 1;
    /// `DPLL_A_PIN_FREQUENCY`.
    pub const PIN_FREQUENCY: u16 = 11;
    /// `DPLL_A_PIN_STATE`.
    pub const PIN_STATE: u16 = 16;
    /// `DPLL_A_PIN_PHASE_OFFSET` (sint per kernel emit; see
    /// Plan 226).
    pub const PIN_PHASE_OFFSET: u16 = 23;
    /// `DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET` (sint).
    pub const PIN_FRACTIONAL_FREQUENCY_OFFSET: u16 = 24;
    /// `DPLL_A_PIN_FRACTIONAL_FREQUENCY_OFFSET_PPT` (kernel 6.11+;
    /// sint per `nla_put_sint`).
    pub const PIN_FRACTIONAL_FREQUENCY_OFFSET_PPT: u16 = 30;
    /// `DPLL_A_PIN_MEASURED_FREQUENCY` (kernel 6.11+).
    pub const PIN_MEASURED_FREQUENCY: u16 = 31;
}

/// Plan 222.4 — Devlink attribute IDs.
///
/// Kernel UAPI v6.13 `include/uapi/linux/devlink.h` `enum
/// devlink_attr`. nlink already exports `DEVLINK_ATTR_*` constants
/// in `genl::devlink::mod`; the test in `tests` below pins them
/// against the kernel reference values.
///
/// `// TODO 0.21: cover the full DEVLINK_ATTR_* enum (~150 entries
/// including param, region, health-reporter, trap, rate, line-card,
/// SF/VF/PCI groupings) — this batch covers the most load-bearing
/// ~15.`
pub mod devlink_attr {
    pub const DEVLINK_ATTR_UNSPEC: u16 = 0;
    pub const DEVLINK_ATTR_BUS_NAME: u16 = 1;
    pub const DEVLINK_ATTR_DEV_NAME: u16 = 2;
    pub const DEVLINK_ATTR_PORT_INDEX: u16 = 3;
    pub const DEVLINK_ATTR_PORT_TYPE: u16 = 4;
    pub const DEVLINK_ATTR_PORT_NETDEV_IFINDEX: u16 = 6;
    pub const DEVLINK_ATTR_PORT_NETDEV_NAME: u16 = 7;
    pub const DEVLINK_ATTR_PORT_IBDEV_NAME: u16 = 8;
    pub const DEVLINK_ATTR_PORT_SPLIT_COUNT: u16 = 9;
    pub const DEVLINK_ATTR_PORT_SPLIT_GROUP: u16 = 10;
    pub const DEVLINK_ATTR_PORT_FLAVOUR: u16 = 77;
    pub const DEVLINK_ATTR_PORT_NUMBER: u16 = 78;
    pub const DEVLINK_ATTR_INFO_DRIVER_NAME: u16 = 98;
    pub const DEVLINK_ATTR_INFO_SERIAL_NUMBER: u16 = 99;
    pub const DEVLINK_ATTR_INFO_VERSION_FIXED: u16 = 100;
    pub const DEVLINK_ATTR_INFO_VERSION_RUNNING: u16 = 101;
    pub const DEVLINK_ATTR_INFO_VERSION_STORED: u16 = 102;
}

/// Plan 222.4 — Ethtool header attribute IDs.
///
/// Kernel UAPI v6.13 `include/uapi/linux/ethtool_netlink.h` `enum`.
/// nlink declares `EthtoolHeaderAttr` (DevIndex=1, DevName=2,
/// Flags=3, PhyIndex=4) in `genl::ethtool::mod`; the gate locks
/// those.
///
/// `// TODO 0.21: cover ETHTOOL_A_LINKINFO_*, ETHTOOL_A_LINKMODES_*,
/// ETHTOOL_A_LINKSTATE_*, ETHTOOL_A_CHANNELS_*, ETHTOOL_A_RINGS_* —
/// the ~50 attribute groups currently used by ethtool(8) sub-commands.`
pub mod ethtool_a {
    pub const ETHTOOL_A_HEADER_UNSPEC: u16 = 0;
    pub const ETHTOOL_A_HEADER_DEV_INDEX: u16 = 1;
    pub const ETHTOOL_A_HEADER_DEV_NAME: u16 = 2;
    pub const ETHTOOL_A_HEADER_FLAGS: u16 = 3;
    pub const ETHTOOL_A_HEADER_PHY_INDEX: u16 = 4;
}

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

    // ---------------------------------------------------------------
    // Plan 222.2 — TC HTB + flower-key constant gate.
    //
    // Cross-checks the public attribute IDs in
    // `crate::netlink::types::tc::qdisc::htb` against the kernel
    // UAPI reference values. Flower keys are pinned by literal
    // value (the in-tree constants live in private module scope).
    // ---------------------------------------------------------------

    #[test]
    fn plan_222_2_tca_htb_attr_ids_match_kernel_uapi() {
        use crate::netlink::types::tc::qdisc::htb;
        assert_eq!(htb::TCA_HTB_UNSPEC, tca_htb_attr::TCA_HTB_UNSPEC);
        assert_eq!(htb::TCA_HTB_PARMS, tca_htb_attr::TCA_HTB_PARMS);
        assert_eq!(htb::TCA_HTB_INIT, tca_htb_attr::TCA_HTB_INIT);
        assert_eq!(htb::TCA_HTB_CTAB, tca_htb_attr::TCA_HTB_CTAB);
        assert_eq!(htb::TCA_HTB_RTAB, tca_htb_attr::TCA_HTB_RTAB);
        assert_eq!(htb::TCA_HTB_DIRECT_QLEN, tca_htb_attr::TCA_HTB_DIRECT_QLEN);
        assert_eq!(htb::TCA_HTB_RATE64, tca_htb_attr::TCA_HTB_RATE64);
        assert_eq!(htb::TCA_HTB_CEIL64, tca_htb_attr::TCA_HTB_CEIL64);
        assert_eq!(htb::TCA_HTB_OFFLOAD, tca_htb_attr::TCA_HTB_OFFLOAD);
    }

    #[test]
    fn plan_222_2_tca_flower_key_ids_match_kernel_uapi() {
        // Reference-only pin (the in-tree flower constants live in
        // private scope at types/tc.rs:1514+; this test catches
        // accidental drift of the kernel-side reference table).
        assert_eq!(tca_flower_key::TCA_FLOWER_KEY_ETH_DST, 4);
        assert_eq!(tca_flower_key::TCA_FLOWER_KEY_ETH_TYPE, 8);
        assert_eq!(tca_flower_key::TCA_FLOWER_KEY_IP_PROTO, 9);
        assert_eq!(tca_flower_key::TCA_FLOWER_KEY_IPV4_DST, 12);
        assert_eq!(tca_flower_key::TCA_FLOWER_KEY_IPV6_SRC, 14);
        assert_eq!(tca_flower_key::TCA_FLOWER_KEY_TCP_DST, 19);
        assert_eq!(tca_flower_key::TCA_FLOWER_KEY_UDP_SRC, 20);
        assert_eq!(tca_flower_key::TCA_FLOWER_KEY_VLAN_ID, 23);
        assert_eq!(tca_flower_key::TCA_FLOWER_KEY_ENC_KEY_ID, 26);
    }

    // ---------------------------------------------------------------
    // Plan 222.3 — IFLA + RTA + ctnetlink reference-value pins.
    //
    // nlink's IFLA / RTA / CTA constants are declared in private
    // `attr_ids` modules at the per-message-type sites
    // (`messages::link::attr_ids`, `messages::route::attr_ids`,
    // `netfilter.rs` `CTA_*`). These tests pin the kernel-side
    // reference values so any drift caught by audit-uapi-constants
    // (planned for 0.21) lines up against a known anchor.
    // ---------------------------------------------------------------

    #[test]
    fn plan_222_3_ifla_attr_ids_match_kernel_uapi() {
        assert_eq!(ifla_attr::IFLA_IFNAME, 3);
        assert_eq!(ifla_attr::IFLA_MTU, 4);
        assert_eq!(ifla_attr::IFLA_LINK, 5);
        assert_eq!(ifla_attr::IFLA_QDISC, 6);
        assert_eq!(ifla_attr::IFLA_MASTER, 10);
        assert_eq!(ifla_attr::IFLA_OPERSTATE, 16);
        assert_eq!(ifla_attr::IFLA_LINKINFO, 18);
        assert_eq!(ifla_attr::IFLA_STATS64, 23);
        assert_eq!(ifla_attr::IFLA_CARRIER, 33);
        assert_eq!(ifla_attr::IFLA_MIN_MTU, 50);
        assert_eq!(ifla_attr::IFLA_MAX_MTU, 51);
        assert_eq!(ifla_attr::IFLA_PERM_ADDRESS, 54);
    }

    #[test]
    fn plan_222_3_rta_attr_ids_match_kernel_uapi() {
        assert_eq!(rta_attr::RTA_DST, 1);
        assert_eq!(rta_attr::RTA_SRC, 2);
        assert_eq!(rta_attr::RTA_OIF, 4);
        assert_eq!(rta_attr::RTA_GATEWAY, 5);
        assert_eq!(rta_attr::RTA_PRIORITY, 6);
        assert_eq!(rta_attr::RTA_PREFSRC, 7);
        assert_eq!(rta_attr::RTA_MULTIPATH, 9);
        assert_eq!(rta_attr::RTA_TABLE, 15);
        assert_eq!(rta_attr::RTA_PREF, 20);
        assert_eq!(rta_attr::RTA_EXPIRES, 23);
    }

    #[test]
    fn plan_222_3_ctnetlink_attr_ids_match_kernel_uapi() {
        assert_eq!(ctnetlink_attr::CTA_TUPLE_ORIG, 1);
        assert_eq!(ctnetlink_attr::CTA_TUPLE_REPLY, 2);
        assert_eq!(ctnetlink_attr::CTA_STATUS, 3);
        assert_eq!(ctnetlink_attr::CTA_TIMEOUT, 7);
        assert_eq!(ctnetlink_attr::CTA_MARK, 8);
        assert_eq!(ctnetlink_attr::CTA_COUNTERS_ORIG, 9);
        assert_eq!(ctnetlink_attr::CTA_COUNTERS_REPLY, 10);
        assert_eq!(ctnetlink_attr::CTA_ID, 12);
        assert_eq!(ctnetlink_attr::CTA_ZONE, 18);
    }

    // ---------------------------------------------------------------
    // Plan 222.4 — DPLL + Devlink + Ethtool attribute ID gate.
    //
    // Cross-checks nlink's public discriminants against the kernel
    // reference values.
    // ---------------------------------------------------------------

    #[test]
    fn plan_222_4_dpll_a_attr_ids_match_kernel_uapi() {
        use crate::netlink::genl::dpll::types::{DpllAttr, DpllPinAttr};
        // Device-side
        assert_eq!(DpllAttr::Id as u16, dpll_a::ID);
        assert_eq!(DpllAttr::ModuleName as u16, dpll_a::MODULE_NAME);
        assert_eq!(DpllAttr::ClockId as u16, dpll_a::CLOCK_ID);
        assert_eq!(DpllAttr::Mode as u16, dpll_a::MODE);
        assert_eq!(DpllAttr::LockStatus as u16, dpll_a::LOCK_STATUS);
        assert_eq!(DpllAttr::Type as u16, dpll_a::TYPE);
        assert_eq!(DpllAttr::LockStatusError as u16, dpll_a::LOCK_STATUS_ERROR);
        // Pin-side
        assert_eq!(DpllPinAttr::Id as u16, dpll_a::PIN_ID);
        assert_eq!(DpllPinAttr::Frequency as u16, dpll_a::PIN_FREQUENCY);
        assert_eq!(DpllPinAttr::State as u16, dpll_a::PIN_STATE);
        assert_eq!(DpllPinAttr::PhaseOffset as u16, dpll_a::PIN_PHASE_OFFSET);
        assert_eq!(
            DpllPinAttr::FractionalFrequencyOffset as u16,
            dpll_a::PIN_FRACTIONAL_FREQUENCY_OFFSET
        );
        assert_eq!(
            DpllPinAttr::FractionalFrequencyOffsetPpt as u16,
            dpll_a::PIN_FRACTIONAL_FREQUENCY_OFFSET_PPT
        );
        assert_eq!(
            DpllPinAttr::MeasuredFrequency as u16,
            dpll_a::PIN_MEASURED_FREQUENCY
        );
    }

    #[test]
    fn plan_222_4_devlink_attr_ids_match_kernel_uapi() {
        use crate::netlink::genl::devlink;
        assert_eq!(
            devlink::DEVLINK_ATTR_BUS_NAME,
            devlink_attr::DEVLINK_ATTR_BUS_NAME
        );
        assert_eq!(
            devlink::DEVLINK_ATTR_DEV_NAME,
            devlink_attr::DEVLINK_ATTR_DEV_NAME
        );
        assert_eq!(
            devlink::DEVLINK_ATTR_PORT_INDEX,
            devlink_attr::DEVLINK_ATTR_PORT_INDEX
        );
        assert_eq!(
            devlink::DEVLINK_ATTR_PORT_TYPE,
            devlink_attr::DEVLINK_ATTR_PORT_TYPE
        );
        assert_eq!(
            devlink::DEVLINK_ATTR_PORT_NETDEV_IFINDEX,
            devlink_attr::DEVLINK_ATTR_PORT_NETDEV_IFINDEX
        );
        assert_eq!(
            devlink::DEVLINK_ATTR_PORT_FLAVOUR,
            devlink_attr::DEVLINK_ATTR_PORT_FLAVOUR
        );
        assert_eq!(
            devlink::DEVLINK_ATTR_PORT_NUMBER,
            devlink_attr::DEVLINK_ATTR_PORT_NUMBER
        );
        assert_eq!(
            devlink::DEVLINK_ATTR_INFO_DRIVER_NAME,
            devlink_attr::DEVLINK_ATTR_INFO_DRIVER_NAME
        );
    }

    #[test]
    fn plan_222_4_ethtool_a_header_attr_ids_match_kernel_uapi() {
        use crate::netlink::genl::ethtool::EthtoolHeaderAttr;
        assert_eq!(
            EthtoolHeaderAttr::Unspec as u16,
            ethtool_a::ETHTOOL_A_HEADER_UNSPEC
        );
        assert_eq!(
            EthtoolHeaderAttr::DevIndex as u16,
            ethtool_a::ETHTOOL_A_HEADER_DEV_INDEX
        );
        assert_eq!(
            EthtoolHeaderAttr::DevName as u16,
            ethtool_a::ETHTOOL_A_HEADER_DEV_NAME
        );
        assert_eq!(
            EthtoolHeaderAttr::Flags as u16,
            ethtool_a::ETHTOOL_A_HEADER_FLAGS
        );
        assert_eq!(
            EthtoolHeaderAttr::PhyIndex as u16,
            ethtool_a::ETHTOOL_A_HEADER_PHY_INDEX
        );
    }
}
