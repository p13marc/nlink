# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.19.0] - 2026-05-31

### Breaking changes

- **`ApplyOptions::with_purge` removed; `ConfigDiff::*_to_remove`
  collections removed** (Plan 205 Option B). The feature was
  silently non-functional in 0.18 — the diff phase never
  populated the `*_to_remove` collections, so the apply path's
  `if options.purge { ... }` branches were dead code that lied
  about what they did. Pre-0.19 callers passing
  `.with_purge(true)` thought kernel state was being reconciled;
  it wasn't. Rather than continue shipping the silent lie, the
  knob is now gone. Migration: for the "remove undeclared
  resources" use case, use the imperative API
  (`Connection::del_link` / `del_address` / `del_route` /
  `del_qdisc`). A correctly-wired purge with a kernel-managed-
  resource exclusion list (IPv6 link-local, multicast, `lo`,
  link-local prefix routes) is queued for 0.20.

- **`DpllPin::phase_offset` field type: `Option<i32>` →
  `Option<i64>`** (Plan 206 H1). The kernel field is declared
  `s64` per `Documentation/netlink/specs/dpll.yaml` (atto-
  seconds × 1000). Pre-0.19 nlink routed the attribute through
  `parse_i32_attr` which reads only the low 4 bytes of the 8-
  byte payload, silently truncating high bits on LE platforms.
  Telco/PTP/SyncE values routinely exceed `i32::MAX` (a 1 ns
  offset = 1e9 in those units), producing nonsense readings.
  Now correctly typed as `i64` and parsed via a new
  `__rt::parse_i64_attr` / `emit_i64_attr` helper pair; the
  `GenlMessage` derive recognizes `i64` field types. Migration:
  callers reading `.phase_offset` explicitly need to update the
  type annotation; `.phase_offset_ns()` accessor unchanged
  (still `Option<i64>`). 1 new regression test
  (`pin_phase_offset_round_trips_value_above_i32_max`) pins
  the high-bit round-trip.

- **`Hook::Ingress` split into `Hook::NetdevIngress` and
  `Hook::InetIngress`; `Hook::NetdevEgress` added** (Plan 211 M1).
  Pre-0.19 `Hook::Ingress` always encoded `0`, which was correct
  only for `Family::Netdev` / `Family::Bridge`. On `Family::Inet`,
  ingress is `NF_INET_INGRESS = 5`, so the old encoding silently
  installed the chain on `Prerouting` (also hook 0) — every
  `Family::Inet` ingress chain was attached to the wrong hook.
  Migration: pick the variant matching the chain family.
  `Hook::is_valid_for_family(Family)` validates at build time.
  Verified against `include/uapi/linux/netfilter.h` and
  `include/uapi/linux/netfilter_netdev.h`. New `nft_hook` module
  in `sys_sizeof` pins the kernel hook numbers.

- **nftables verdict constants `NFT_JUMP` / `NFT_GOTO` corrected
  to match kernel UAPI** (Plan 204 C1). Pre-0.19 nlink shipped
  `NFT_JUMP = -2` and `NFT_GOTO = -3`. The kernel's
  `enum nft_verdicts` defines them as `-3` and `-4` respectively;
  `-2` is `NFT_BREAK` (terminate rule evaluation). Code building
  `Verdict::Jump(chain)` previously wrote `-2` on the wire, which
  the kernel interpreted as "terminate", silently breaking every
  subroutine rule. The new `NFT_BREAK = -2` constant is added for
  completeness. Source-level no-op for users of `Verdict::Jump` /
  `Verdict::Goto`; runtime behavior changes from silently broken
  to kernel-correct. Verified against kernel
  `include/uapi/linux/netfilter/nf_tables.h`.

### Added

- **`nlink::netlink::sys_sizeof` module + 9 wire-format byte-exact
  regression tests** (Plan 213). Hosts the kernel UAPI struct
  sizes (`XfrmUserpolicyInfo` = 168 bytes, `XfrmUserpolicyId` =
  64 bytes, etc.) and the nft verdict constants, with a test
  per type asserting `size_of::<NlinkType>() == KERNEL_SIZE`.
  Catches the Plan 204 class of silent wire-format defects at
  `cargo test` time; future struct field changes that drift from
  the kernel layout fail the test immediately. The test pass
  surfaced an additional latent bug: `XfrmUserTmpl` was 62
  bytes (kernel: 64) — fixed by adding a 2-byte explicit pad
  between `family` and `saddr` to match kernel natural
  alignment.

### Fixed

- **`NatExpr.addr` re-typed from `Option<Ipv4Addr>` to the
  `NatAddr` enum (PR #6, @avionix-g)** — `NatAddr` has three
  variants: `None` (port-only NAT), `V4(Ipv4Addr)` (IPv4
  address recorded), and `Reg` (a non-v4 address — e.g. v6 —
  loaded into `R0` with no `Ipv4Addr` to record). Before this
  change, the encoder emitted `NFTA_NAT_REG_ADDR_MIN` only
  when `addr.is_some()`, so a v6 NAT (16-byte address in
  `R0`, no `Ipv4Addr` to carry) silently dropped the address
  register. The enum models "register in use" and "the IPv4
  value to record" as one value so the illegal
  `(addr recorded, register unused)` state is
  unrepresentable. Breaking for code constructing `NatExpr`
  as a struct literal or matching on `addr`. The
  `NatExpr::{snat,dnat}` + `.addr()` and
  `Rule::{snat,dnat,snat_v6,dnat_v6}` builders are
  unaffected. v4 wire output is byte-identical.

- **`ApplyOptions` is now `#[non_exhaustive]` + builder-shaped
  (Plan 188 §2.2)** — struct-literal construction no longer
  compiles. Build via `with_*` setters instead:
  ```rust
  // Before
  ApplyOptions { dry_run: true, ..Default::default() }
  // 0.19+
  ApplyOptions::default().with_dry_run(true)
  ```
  Mirrors `ReconcileOptions` (Plan 163). The lockdown enables
  growing the option set in future minors without semver
  breakage.

- **`Error::from_errno*` factories now normalize via `.abs()`
  (Plan 187 §2.1)** — passing positive or negative errno
  produces the same stored POSIX value. Before 0.19 the
  factory silently negated the input — `from_errno_ext_ack(1, ..)`
  produced stored `-1`, surfaced as a footgun in nlink-lab's
  unit tests. The fix is purely additive for the kernel-side
  call sites that always passed the kernel's signed-negative
  errno; only direct test/mock callers asserting `Some(-N)`
  break — update to `Some(N)`.

### Added

- **`Error::DumpInterrupted` variant + `is_dump_interrupted()`
  predicate (post-cycle bug-hunt)** — the kernel sets the
  `NLM_F_DUMP_INTR` flag on a dump message when the snapshot
  iterator's underlying data structure was mutated between
  frames, signaling that the returned set is inconsistent. Pre-
  0.19 nlink silently accepted the partial dump; the user had no
  way to know the data was stale. Now `Connection::send_dump`
  (and every typed dump wrapper that goes through it —
  `get_links`, `get_routes`, `get_neighbors`, `get_addrs`,
  `get_rules`, `get_qdiscs`, `get_classes`, `get_filters`,
  `get_nexthops`, `get_actions`) returns
  `Error::DumpInterrupted`. Callers can retry with their own
  bound — Cilium uses 30 attempts, vishvananda/netlink uses 24,
  `iproute2` warns once and accepts the partial. The new
  `NlMsgHdr::is_dump_interrupted()` accessor also lets stream
  consumers detect interruption on individual frames.
  References: kernel docs/userspace-api/netlink/intro.html,
  `vishvananda/netlink#1163`, `pyroute2#874`, Cilium safenetlink.

### Fixed

- **`XfrmUserpolicyInfo` body was 4 bytes shorter than kernel
  expected — `add_sp` rejected with EINVAL on every kernel
  version** (Plan 204 C2). The kernel's
  `struct xfrm_userpolicy_info` uses natural alignment (not
  packed); after the four trailing `__u8` fields the struct
  pads to the next u64 boundary for a total of 168 bytes.
  nlink used `#[repr(C, packed)]` with no trailing pad,
  emitting 164 bytes. Kernel `xfrm_add_policy()` calls
  `nlmsg_parse_deprecated(nlh, sizeof(*p), ...)` requiring
  `nlmsg_len >= NLMSG_HDRLEN + 168`. The `add_sp` API has been
  silently non-functional since the XFRM family shipped. Fix
  adds explicit `_pad: [u8; 4]` and a `sys_sizeof` regression
  test.

- **`XfrmUserpolicyId` body was 4 bytes longer than kernel
  expected — `del_sp` / `get_sp` brittle on strict-checking
  kernels** (Plan 204 C3). nlink's `_pad: [u8; 7]` produced a
  68-byte body; the kernel struct is 64 bytes (selector + u32
  index + u8 dir + 3 pad). On lenient kernels the extra 4
  bytes were parsed as a malformed trailing nlattr and silently
  skipped. On strict-checking kernels (≥5.0 with
  `NETLINK_GET_STRICT_CHK`, enableable via Plan 155.2), the
  kernel rejected with EINVAL. Fix trims `_pad` to `[u8; 3]`.

- **`XfrmUserTmpl` was 62 bytes (kernel: 64) — discovered by
  Plan 213 sizeof test** (Plan 204 hidden sibling of C2/C3).
  The kernel struct uses natural alignment (not packed); the
  2-byte gap between `family` (u16 at offset 24) and `saddr`
  (xfrm_address_t, align 4) was missing from nlink's packed
  representation. Fix adds explicit `_pad_saddr: [u8; 2]`
  between the two fields.

- **Devlink multicast subscription was broken — group name
  mismatch** (Plan 204 C4). nlink looked up `"devlink"` in the
  kernel's CTRL_ATTR_MCAST_GROUPS table; the kernel registers
  the group as `"config"` (per `DEVLINK_GENL_MCGRP_CONFIG_NAME`
  in `include/uapi/linux/devlink.h`). Every
  `Connection::<Devlink>::subscribe()` call returned
  `Error::FamilyNotFound`. Fix changes the constant to
  `"config"` plus the `sys_sizeof` regression test.

- **`Error::is_not_found` now matches `Error::Io(ENOENT)` and
  `Error::Io(ENODEV)`** (Plan 212 M9). Brings the predicate
  into symmetry with `is_busy`, `is_permission_denied`,
  `is_already_exists` which Plan 187 §2.5 already routed
  through `errno()`. Code calling `e.is_not_found()` on an
  `Error::Io` carrying ENOENT/ENODEV now correctly returns
  `true`. 3 new regression tests.

- **`Connection::send_ack_inner` surfaces explicit error on
  unexpected matching-seq data response** (Plan 212 M16) instead
  of silently looping for the next frame (which would hit the
  30s timeout). Defense-in-depth against kernel behavior
  divergence.

- **`Connection::cache` RwLock poison handling** (Plan 212
  M17): previously `read/write().unwrap()` would panic on
  poisoning; now recovers via `unwrap_or_else(into_inner)`.
  Hardens against future panics inside the locked region
  (currently unreachable; defense-in-depth).

- **WireGuard `PublicKey` accepts unpadded base64** (Plan 215
  M12). Pre-0.19 the decoder required exactly 44 chars + the
  trailing `=`; some YAML/JSON serializers strip optional
  base64 padding (RFC 4648 §3.2). Now both 43-char and 44-char
  forms decode correctly. 1 new regression test.

- **nl80211 SSID parser walks the IE chain** (Plan 215 M13)
  instead of assuming element-id 0 is the first IE.
  Vendor-specific IEs (id=221) sometimes precede the SSID;
  pre-fix those BSSes returned `None`. New `parse_ssid_from_ies`
  helper + 6 unit tests covering well-formed, vendor-prepended,
  missing, truncated, non-UTF-8, and empty IE chains.

- **`bins/nft` rejects unknown `--type` and `--policy` tokens**
  (Plan 209 H5 — security UX). Pre-0.19 a typo on `--policy`
  silently fell through to ACCEPT (`--policy drpo` for `drop`
  produced an accept-everything firewall). Same hazard for
  `--type` chain type. Now both error explicitly:
  `unknown policy `drpo` — expected `drop` or `accept``.

- **`bins/wg set --private-key /path` propagates file read
  errors** (Plan 209 H6 — security UX). Pre-0.19 a missing
  private-key file or base64-decode failure silently dropped the
  key set; `wg set wg0 --private-key /typo` exited 0 and the
  user believed the new key was installed. Now the read error
  surfaces immediately via `?`.

- **`bins/tc action` parses TC action attributes via zerocopy
  `ref_from_prefix` instead of raw-pointer casts** (Plan 209
  H11). Pre-0.19 the code did
  `unsafe { &*(attr_data.as_ptr() as *const TcGact) }` which is
  UB on strict-alignment architectures (some ARM, MIPS) — `Vec<u8>`'s
  data pointer has no alignment guarantee. Now uses zerocopy's
  alignment-checked parser, eliminating the UB. Three sites
  updated (`gact`, `mirred`, `police` parameter blocks, both
  JSON and text formatters).

- **NetworkConfig correctness pass: 6 silent reconcile-divergence
  bugs fixed** (Plan 207).

  - **H2 — link `master` change detection** (`config/diff.rs`).
    Pre-0.19 the diff compared `Option<String>` (declared) vs
    `Option<u32>` (kernel ifindex) treating any (Some, Some)
    pair as equal. Bridge-port reassignment (`master: "br0"` vs
    kernel `master: ifindex(br1)`) silently no-op'd. Now resolves
    `existing.master()` ifindex → name via the diff's name map
    and compares strings.

  - **H3 — route gateway / dev / metric change detection**
    (`config/diff.rs`). Pre-0.19 the diff identity tuple was
    `(dst, prefix, table)` only; changing the gateway on the
    same route produced an empty diff. Now compares the full
    route key (including gateway/oif/metric); any mismatch
    queues a route for re-emission. `add_route` uses
    `NLM_F_REPLACE` so the kernel atomically swaps the existing
    route — no del+add window. Most common reconcile op in
    multi-router topologies.

  - **H4 — `apply_reconcile` recomputes diff per retry**
    (`config/mod.rs`). Pre-0.19, on EBUSY the reconcile loop
    re-ran the full original apply against changed kernel state,
    producing EEXIST that masked the original EBUSY. Now each
    retry computes a fresh diff against current state and
    targets only what's still missing. `change_count` becomes
    the cumulative sum across attempts. Empty diff at retry
    start short-circuits as success.

  - **M3 — `remove_route` forwards table identity**
    (`config/apply.rs`). Pre-0.19 the `_table` parameter was
    discarded; routes in non-default tables (table ≠ 254)
    could never be purged — kernel returned ESRCH which
    `is_not_found()` swallowed silently.

  - **M5 — topo-sort handles VXLAN underlay + master deps**
    (`config/diff.rs`). Pre-0.19 only `Vlan { parent }` and
    `Macvlan { parent }` were modeled. Declaring
    `vxlan42.underlay_dev("eth0")` before `eth0`, or
    `dummy0.master("br0")` before `br0`, in the same batch
    silently failed at apply (same shape as Plan 186 §3c).

  - **M10 — `LinkState::Down` uses IFF_UP flag, not OperState**
    (`config/diff.rs`). Pre-0.19 the comparison read
    `IFLA_OPERSTATE` (RFC 2863 operational state, carrier-
    dependent). Dummy/veth interfaces with no carrier stayed
    non-`Up` operationally even when admin-up, so
    `LinkState::Down` declared on a no-carrier admin-up
    interface silently no-op'd. Now reads `ifi_flags & IFF_UP`
    (admin state).

  - **M18 — atomic `replace_qdisc` via NLM_F_REPLACE**
    (`config/apply.rs`). Pre-0.19 del+add sequence left a
    transient `pfifo_fast`/`mq` window between the delete and
    the new add; if the add failed the interface kept the
    kernel-default qdisc not the previous declared one. Now
    uses `Connection::replace_qdisc*` (atomic
    `RTM_NEWQDISC + NLM_F_REPLACE`). Falls back to del+add for
    `Ingress`/`Clsact` pseudo-qdiscs (kernel rejects REPLACE
    on those).

  2 new unit tests pin the topo-sort dep extensions
  (`topo_sort_promotes_vxlan_underlay_before_vxlan`,
  `topo_sort_promotes_master_before_slave`). Integration
  verification for the diff/apply changes lands via the
  existing `network_config_apply.rs` integration suite under
  the privileged-CI gate.

- **10 protocol recv-loops wrapped in `with_timeout` + seq
  filter + `NLM_F_DUMP_INTR` detection** (Plan 208 Phase 1+2):
  `xfrm.rs::{get_security_associations, get_security_policies}`,
  `netfilter.rs::get_conntrack_family`,
  `fib_lookup.rs::lookup_with_options`,
  `sockdiag.rs::{query_inet_family, query_unix_typed,
  query_netlink_typed}`,
  `Connection::<Generic>::{query_family, command, dump_command}`.
  Pre-0.19 each could hang indefinitely if the kernel dropped a
  response, and dump variants would silently use an
  interrupted-dump snapshot. Now surface as `Error::Timeout`
  after the configured budget and `Error::DumpInterrupted` per
  the Plan 208 contract. `wg_command` stale-frame race deferred
  pending GENL command unification (Plan 208 Phase 3+4 — bigger
  refactor).

### Documentation

- **`Connection<P>` doc-comment now describes the concurrent-
  use caveat** (Plan 212 M15). The type implements `Sync` but
  concurrent `.await`-ed calls on a shared connection race on
  recv and can produce dual `Error::Timeout`. Recommended
  pattern: one `Connection<P>` per task, or use
  `ConnectionPool<P>` for fan-out. Architectural NlRouter-style
  dispatch fix tracked for 0.20.

- **README.md updated to 0.19 install lines** + `tuntap-async`
  and `serde` features added to the features table.

- **lib.rs landing-page doc-comment updated** (Plan 214):
  the stale "`_by_name` reads `/sys/class/net/`" claim removed
  (Plan 192 D4 made both lookups netlink-correct); `addr.address`
  doctest reference updated to `addr.address()` accessor.

- **`Error::is_dump_interrupted` doctest type fix** (Plan 214):
  was `Vec<nlink::Link>` (doesn't exist), now
  `Vec<nlink::netlink::LinkMessage>`.

- **`nftables-declarative-config.md` recipe uses `Display`
  instead of deprecated `.summary()`** (Plan 214).

### Earlier post-cycle fixes (`5ef0808`)

- **`Batch::send_chunk` could hang indefinitely on dropped
  per-op ACK (post-cycle bug-hunt)** — the nftables/route batch
  send-chunk recv loop did NOT run under `Connection::with_timeout`,
  so a kernel that lost the ACK for any single batched op would
  leave the call waiting forever. Plan 171's 30s default
  Connection timeout was supposed to catch every recv-loop;
  Plan 172 missed wiring it here. Now the recv loop is wrapped
  in `with_timeout`, so a dropped ACK surfaces as `Error::Timeout`
  after the configured budget instead of an indefinite hang.

- **`audit.rs::{get_status, get_tty_status, get_features}` had
  no timeout + no seq filter (post-cycle bug-hunt)** — the three
  Audit RPCs raw-`recv_msg()`-looped without `with_timeout`, so
  a kernel that dropped the response hung forever; they also
  matched on `nlmsg_type` only and would have accepted a stale
  frame from a prior request on the same socket. Both now match
  `nlmsg_seq` first and run under the connection timeout. Same
  hazard class as Plan 172 but on a non-rtnetlink protocol that
  the original audit missed.

- **`sockdiag.rs::destroy_tcp_socket` bypassed
  `Error::from_errno*` factory + had no seq filter / timeout
  (post-cycle bug-hunt)** — constructed `Error::Kernel { errno: -errno, ... }`
  by hand instead of routing through
  `Error::from_errno_with_context_ext_ack`, so the stored errno
  shape diverged from the Plan 187 sign-normalization invariant
  and ext-ack info was dropped. Now uses the factory + seq filter
  + 30s timeout wrap.

- **`MessageBuilder::nest_end` + `NlAttr::new` silently
  truncated `nla_len` to `u16` on > 65 KB payloads (post-cycle
  bug-hunt)** — the kernel's `nla_len` field is a `u16`, so a
  caller building a >64 KB nested attribute would have its
  header silently wrap to a tiny value, producing a malformed
  message the kernel would either reject (best case) or
  misinterpret the wrapped length and skip past the real payload
  bytes (worst case). No caller hit this today — the bug was
  latent waiting for a future caller — but the silent-corruption
  shape was identical to PR #7's `tcm_info` packing footgun
  (where transposed bytes silently broke every TC filter add).
  Now: `debug_assert!` panic with a clear "exceeds u16::MAX wire
  limit" message in debug builds, saturating cast in release so
  the kernel rejects the message rather than misinterpreting a
  wrapped length. 2 new boundary tests
  (`nest_end_just_under_u16_max_boundary_succeeds`,
  `nest_end_over_u16_max_panics_in_debug`) pin the contract.

- **`AttrIter` parser-robustness contract was unverified (post-
  cycle bug-hunt)** — `AttrIter` is the equivalent of `MessageIter`
  for nested attribute walking; every parser in the lib uses it
  (hundreds of call sites). Plan 193 §2.3 added robustness tests
  for `MessageIter` (found a real infinite-loop bug in the
  process), but the matching `AttrIter` had **zero tests** —
  future refactors could silently turn the safe `return None`
  paths into panics or infinite loops. 13 new tests pin the
  three CLAUDE.md `## Parser robustness` rules on `AttrIter`:
  zero-length attribute terminates iteration without loop;
  truncated `len > buffer` terminates; under-min `len < NLA_HDRLEN`
  terminates; accept-larger-than-expected payload is forward-
  compatible; `NLA_F_NESTED` / `NLA_F_NET_BYTEORDER` flag bits
  are masked from `kind()` (preventing the vishvananda/netlink
  #1104 bug class). Same bug-by-test-writing pattern as Plan 193
  §2.3.

- **TC filter `tcm_info` packing — kernel-EINVAL on every
  `add_filter*` call with explicit protocol+priority (PR #7,
  @nuclearcat)** — `add_filter_by_index_full` (and the
  sibling `replace`/`change`/`delete` paths in `filter.rs`,
  plus the ratelimit ingress filter) packed `tcm_info` as
  `(protocol << 16) | priority` with no `htons`. The kernel
  uses `TC_H_MAKE(prio << 16, htons(proto))` — priority in
  the upper 16 bits, ethernet protocol in the lower 16 bits
  in network byte order. With the halves transposed the
  kernel read e.g. protocol=0x0800/prio=200 as
  protocol=200/prio=2048 and returned EINVAL; every TC
  filter add with an explicit ethernet protocol failed. The
  ratelimit ingress filter was silently installed under the
  wrong ethertype. Fix routes every pack site through a
  single `TcMsg::with_filter_info(protocol, priority)`
  chokepoint, restores accessor symmetry on
  `TcMessage::protocol()` / `priority()` (which were
  self-inconsistently broken — matched the buggy pack while
  the unused `filter_protocol()` / `filter_priority()`
  matched the kernel). 4 new unit tests pin iproute2's
  exact wire layout + add the
  `pre_fix_layout_was_transposed` regression guard
  documenting what the kernel parsed pre-fix. 1 new
  root-gated integration test
  (`test_filter_add_explicit_protocol_priority`) asserts a
  real filter add accepts. **Runtime semantic break** for
  `TcMessage::protocol()` / `priority()` accessor return
  values — they now return the kernel-correct values
  instead of the transposed garbage; signature unchanged so
  `cargo-semver-checks` doesn't flag it, but document the
  shift. Verified on kernel 6.17.

- **IPv6 NAT silently dropped the address register
  (PR #6, @avionix-g)** — see the `### Breaking changes`
  entry on `NatExpr.addr` → `NatAddr` for the type-level
  fix. New `Rule::dnat_v6(Ipv6Addr, Option<u16>)` and
  `Rule::snat_v6(Ipv6Addr, Option<u16>)` builders emit
  `Family::Ip6` in the NAT expr (matching the address
  family, not the chain's `Family::Inet`), load the 16-byte
  address into `R0` + optional port into `R1`. 3 new unit
  tests + 2 root-gated diff-idempotency integration tests
  (`dnat_v6_rule_round_trips`, `snat_v6_rule_round_trips`)
  on separate hooks (postrouting/`SrcNat` vs
  prerouting/`DstNat`) prove the kernel stored exactly the
  expr bytes nlink rendered.

- **`Error::is_busy`, `is_already_exists`, `is_permission_denied`
  catch `Error::Io` variants (Plan 187 §2.5)** — these three
  predicates matched on `Self::Kernel*` variant directly,
  missing the `Error::Io(io_err)` case carrying the same
  errno via `raw_os_error()`. Same bug class as Plan 185's
  `is_no_buffer_space` fix. Single-point fix: `Error::errno()`
  now unwraps `Error::Io` via `raw_os_error()`, so every
  predicate that goes through `errno()` inherits the right
  shape. `is_busy` and `is_try_again` are used by
  `NftablesConfig::apply_reconcile` retry classification —
  a raw `EBUSY`/`EAGAIN` from the socket layer no longer
  bypasses the retry budget. Plan 185's defensive branch in
  `is_no_buffer_space` is now redundant and removed. New
  `predicate_io_shape_sweep` test pins the contract for 10
  predicates; future additions inherit it.

- **`MessageIter` infinite loop on truncated / malformed
  netlink frames (Plan 193 §2.3 + CLAUDE.md §"Parser
  robustness" rule 2)** — surfaced while writing the
  parse-events skip regression tests this cycle:
  `MessageIter::next` returned `Some(Err(...))` on both
  the `NlMsgHdr::from_bytes` failure and the
  `msg_len < HDRLEN || msg_len > data.len()` guard, but
  forgot to advance `self.data` past the malformed
  bytes. Subsequent `next()` calls returned the same
  `Err` indefinitely, hanging the long-lived multicast
  subscribers Plans 185 + 191 introduced. Fix: in both
  error branches, set `self.data = &[]` before
  returning so the next poll yields `None`. Bug class
  matches neli #305 (whole-batch abort on one malformed
  message) — same shape, different surface. 4 new
  `stream.rs` tests pin the contract: empty buffer,
  unknown msg-type, garbage payload on known msg-type,
  truncated frame.

### Deprecated

- **`ConfigDiff::summary()` + `NftablesDiff::summary()`
  (Plan 188 §2.6)** — Plan 183 (0.18) made the `Display` impl
  on both diff types share the same renderer; the two methods
  produce byte-for-byte identical output. Pick the Rust idiom
  (`Display`); remove the legacy method in 0.20.
  Update call sites from `diff.summary()` to `diff.to_string()`
  or use the `{}` placeholder in `format!`/`println!`.

### Added

- **`Rule::dnat_v6(Ipv6Addr, Option<u16>)` + `Rule::snat_v6(Ipv6Addr,
  Option<u16>)` (PR #6, @avionix-g)** — IPv6 NAT helpers, the
  counterparts to `dnat` / `snat`. Each loads the 16-byte address
  into `R0` (and the optional port into `R1`) and emits `Family::Ip6`
  in the NAT expr to match the address family (not the chain's
  `Family::Inet`). Use on `ip6` or `inet` NAT chains. Closes a silent
  encoder bug where `addr.is_some()` was used as the proxy for
  "register in use" — see the breaking-change entry on `NatExpr.addr`.

- **Post-cycle audit backfill** — closes gaps surfaced by
  the 0.19 plan-by-plan audit:
  - **Plan 196**: `PublicKey` newtype with `FromStr` (base64)
    + `Display` round-trip, `Debug` via `Display`. Inline
    32-byte base64 codec (no new crate dep). 6 new unit
    tests pin `fE/wpxQ6/M6OmF5j4dvbY3FbCEXc3KlBL2QqAYjE0WI=`
    test vector + zero/max boundary cases + invalid-input
    rejection.
  - **Plan 196**: `Display` impl on `WireguardConfigDiff`
    rendering `+ peer`, `~ peer (endpoint, allowed_ips)`,
    `- peer` per change. Empty diff renders "no changes".
  - **Plan 196**: `WireguardConfig::apply_reconcile(conn,
    opts)` mirroring `NetworkConfig::apply_reconcile` —
    bounded EBUSY/EAGAIN retry with exponential backoff,
    reuses the shared `ReconcileOptions` shape.
  - **Plan 192 §2.7**: CLAUDE.md `## util::ifname sysfs reads`
    sub-section under the existing namespace-safety section.
    New `scripts/audit-sysfs-in-lib.sh` + CI gate in
    `.github/workflows/rust.yml`. Fails the build if any
    `/sys/class/net/` or `/proc/sys/` read appears in
    `crates/nlink/src/netlink/` outside `sysctl.rs`. Skips
    rustdoc comments via in-script prefix filter.
  - **Integration test backfill** (`tests/integration/
    cycle_0_19_backfill.rs`, 6 root-gated tests):
    - Plan 188 §2.1 `ConfigDiff::apply` round-trip
    - Plan 188 §2.4 `NetworkConfig::apply_reconcile` happy path
    - Plan 188 §2.7 `del_table_if_exists` idempotence
      (cold/warm/cold-again triplet)
    - Plan 202 §2.3 multipath route round-trip — the
      headline test the parser plan was named to fix
    - Plan 200 §2.1 facade `apply::network_in_namespace`
      composition + diff symmetry
    - Plan 200 §2.4 `Stack` orchestration + re-apply no-op
    Plus Plan 196 + Plan 199 module-gated tests
    (`require_module!("wireguard")`) covering full GENL
    round-trip + watcher polling.

- **High-level facade APIs (Plan 200)** — three thin
  compositional wrappers + a unified `Stack` type that
  collapse the typed surface's 5–15-line boilerplate into
  one-liners.
  - `nlink::facade::apply::network(cfg).await?` — opens a
    fresh `Connection<Route>` + calls `apply`.
    Same shape for `nftables(...)` (computes diff +
    applies), `wireguard(...)` (uses the async GENL
    family-resolution path). `*_in_namespace(ns, cfg)`
    siblings for each.
  - `nlink::facade::diff::*` — symmetric drift-detection
    wrappers (NetworkConfig → ConfigDiff, NftablesConfig →
    NftablesDiff, WireguardConfig → WireguardConfigDiff).
  - `nlink::facade::watch::route_changes()` —
    one-line resync-wrapped event stream for RTNETLINK
    (mirrors Plan 191's `into_events_with_resync` with the
    factory closure built for you). `nftables_changes()`
    same for Plan 185. `wireguard_changes(opts).await?`
    returns a `WireguardWatcher` for the polling path
    (Plan 199 — kernel has no multicast).
  - `nlink::facade::Stack` — bundles `NetworkConfig` +
    `NftablesConfig` + `WireguardConfig` with optional
    layers. `Stack::apply` calls them in dependency order
    (RTNETLINK → nftables → WireGuard), returning a
    `StackApplyReport` with per-layer counters.
    `Stack::diff` aggregates per-layer diffs into
    `StackDiff::is_empty()` for fast "is anything dirty"
    checks.
  - ovpn intentionally absent — the kernel ovpn family is
    bleeding-edge (6.16+) and nlink ships only the link
    half (Plan 190 §2.3b). Plan 197 (GENL-side ovpn
    declarative) needs the imperative ovpn GENL family
    implemented first; deferred to a future cycle for
    kernel-ABI stability.
  3 unit tests on the `StackDiff` / `StackApplyReport`
  no-op semantics.

- **Declarative WireGuard configuration (Plan 196)** —
  the GENL-family twin of `NetworkConfig` / `NftablesConfig`.
  `WireguardConfig::new().device("wg0", |d| ...)` builder
  shape with `.private_key`, `.listen_port`, `.fwmark`,
  and `.peer(public_key, |p| ...)` accepting `.endpoint`,
  `.persistent_keepalive`, `.preshared_key`, `.allowed_ip`.
  `cfg.diff(&conn).await` computes the symmetric diff
  against current kernel state; `cfg.apply(&conn).await`
  dispatches the kernel mutations.
  - `WireguardConfigDiff` / `DeviceChanges` / `PeerChanges`
    public diff types. `change_count` counts kernel
    calls, not dirty fields (a single SET_DEVICE collapses
    all device-level changes into one write).
  - `allowed_ips` diff is order-independent — declaring
    in one order vs the kernel reporting in another
    doesn't churn.
  - `WireguardApplyResult` reports `device_writes` +
    `peer_writes` + `peer_removals` separately.
  - **Privacy-key caveat**: the kernel never returns
    `private_key` / `preshared_key` on `GET_DEVICE`. When
    declared in the config, they're ALWAYS written
    (idempotent at the WG protocol layer — no handshake
    storm — but costs one extra SET call per re-apply).
    Omit them after first apply for zero-op re-applies.
  - Apply uses `replace_allowed_ips()` for in-config peers
    so the declarative model is "this is the full set",
    not "merge."
  13 new unit tests on the pure diff logic: builder
  round-trips, private-key dirty semantics, listen_port
  match/mismatch, peer add/remove/modify, endpoint
  change, allowed_ips set difference, allowed_ips
  order-independent comparison, change_count
  aggregation.

- **WireGuard polling watcher (Plan 199, redesigned)** —
  the kernel `wireguard` GENL family declares
  `n_mcgrps = 0`; verified 2026-05-31 via
  `drivers/net/wireguard/netlink.c` upstream. There is no
  native event-subscription surface — every WG monitoring
  tool polls `GET_DEVICE` on a cadence. nlink now ships a
  typed poll-and-diff primitive so consumers don't
  re-implement that machinery per app.
  - `WireguardEvent` enum: `PeerAdded`, `PeerRemoved`,
    `PeerEndpointChanged`, `PeerHandshakeRefreshed`,
    `PeerAllowedIpsChanged`. First poll emits `PeerAdded`
    for every existing peer (initial-inventory semantics,
    matching Plan 185 / 191 snapshot shape).
  - `WireguardWatchOptions` builder: `.interval(d)` +
    `.interface(name)`. Default cadence 1 s. The watcher
    does NOT auto-enumerate WG-kind interfaces — caller
    specifies the set explicitly.
  - `WireguardWatcher::new(conn, opts)` returns `Result`
    (validates non-empty interfaces);
    `next_events().await -> Result<Vec<WireguardEvent>>`
    sleeps then polls + diffs. `connection()` /
    `into_connection()` give callers their socket back.
  - `diff_device_states(ifname, prev, curr)` pure
    function exposed for callers wiring custom polling
    cadences.
  - If the kernel grows multicast support (Linus Lotz's
    2021 patch is "Awaiting Upstream" — never merged),
    this watcher will be replaced with a multicast
    subscriber and the polling path will become a
    compatibility shim. The `WireguardEvent` enum shape
    stays the same either way.
  11 new unit tests on the pure-function diff. Closes
  what Plan 191 §8 punted to a separate plan.

- **`SetKeyType::InetProto` + `Concat(Vec<_>)` (Plan 198
  §2.1, scoped subset)** — extends the nftables set key
  taxonomy with the two real-world variants the
  research-agent audit flagged: `InetProto` (single u8
  protocol — `tcp`/`udp`/`icmp`) and `Concat(Vec<_>)`
  (composite key used in rules like `ip saddr . tcp
  dport`). `type_id()` for `Concat` packs each
  component's 6-bit type ID into sequential slots,
  matching the kernel's `nft_set_ext_concat`
  layout. `len()` returns the per-component sum after
  4-byte alignment padding. **Note**: `SetKeyType` lost
  `Copy` (the `Concat` variant carries a `Vec`); the
  enum is `#[non_exhaustive]` so this is mitigated, but
  any downstream `let k: SetKeyType = ...;` that
  expected `Copy` semantics needs a `.clone()`. The
  imperative `Set` builder + downstream wire-emit code
  in the lib was unaffected.
  The fuller Plan 198 — `DeclaredSet` declarative type,
  `SetFlags` bitflags, element diff, `DeclaredTableBuilder::set`
  — stays as a 0.20 follow-up; this commit ships the
  imperative taxonomy extension so future declarative
  work has the right wire types. 5 new unit tests pin
  `InetProto` wire constants + `Concat` length/packing
  on 1/2/3-component shapes.

- **`#[must_use]` on the diff + result + report types
  (Plan 201 §2.1, scoped subset)** — `ConfigDiff`,
  `NftablesDiff`, `ApplyResult`, both `ReconcileReport`s
  (TC recipe + nftables) gain `#[must_use]` with a
  specific message pointing the caller at the right
  accessor (`.apply()`, `.is_success()`, `.is_noop()`).
  Catches the easy-to-forget shape "build a diff,
  forget to call apply()." Three in-tree integration
  test sites that intentionally discarded a
  `ReconcileReport` were updated to `let _ = ...` to
  silence the new lint. Plan 201's broader sweep
  (every `*Builder`, `From`/`Into`, `Display`,
  `#[inline]`) remains as a polish backlog; this commit
  ships the highest-leverage subset matching the cycle's
  existing diff/apply API surface.

- **`RouteMessage::multipath()` accessor + `ParsedNextHop`
  + `RTA_MULTIPATH` parser (Plan 202)** — closes a gap
  surfaced by Plan 193 §2.2's audit: nlink could WRITE
  multipath routes (`write_multipath_v4` / `_v6`) but
  didn't PARSE them back. Multipath routes round-tripped
  through `Connection<Route>::get_routes()` lost their
  nexthop list. The drift-detection consequence: any
  `NetworkConfig` carrying a multipath route would see
  "kernel has no nexthops; config wants 2" forever, even
  though the kernel ACK'd the write.
  Adds:
  - `parse_multipath(data, family)` walker — defensive
    guards per Plan 193 §2.2 + CLAUDE.md §"Parser
    robustness" rule 2 (rtnh_len < HDRLEN aborts;
    rtnh_len > remaining bytes aborts; rtnh_len == 0
    aborts; `offset.max(HDRLEN)` advance prevents stall).
  - `ParsedNextHop` struct: `ifindex` + `weight` (1-based,
    matching `ip route` + imperative `NextHop::weight`) +
    `flags` + `gateway: Option<IpAddr>`.
  - `RouteMessage::multipath()` accessor returning
    `Option<&[ParsedNextHop]>`.
  - `RTA_MULTIPATH = 9` const in attr_ids.
  6 unit tests pin the contract: normal walk, empty
  buffer, zero-length rtnh, undersized rtnh header,
  truncated chain, garbage nested attrs. The zero-
  length + truncated tests guard against the
  netlink-packet-route #152 infinite-loop shape.

- **Concurrent-stress regression tests (Plan 194)** —
  two new root-gated integration tests preempting
  bug-shapes the `rtnetlink` Rust crate hit recently:
  - `concurrent_dumps_on_shared_connection_route_correctly`
    spawns 16 concurrent `get_links()` calls on a shared
    `Arc<Connection>` and asserts every dump sees the
    pre-created `dummy0`. Pins nlink's seq-routing
    correctness against the kind of bug rtnetlink #131
    surfaced (replies routed to the wrong receiver).
  - `concurrent_namespaces_dont_corrupt_each_other` spawns
    16 concurrent `LabNamespace::new` calls, each with a
    uniquely-named dummy interface; verifies each
    namespace's dump returns only its own dummy. Pins
    the namespace creation path against rtnetlink #132's
    race-shape.
  Both tests are expected to GO GREEN — Plan 170's seq-
  filter + Plan 172's recv-loop audit defenses are
  already in place. If either turns red on the
  privileged-CI gate, a follow-up fix lands per Plan 194
  §3.2 / §3.3.

- **`ResyncStreamExt` combinators on resync streams
  (Plan 195 §2.1 + §2.3)** — kube-rs-style composable
  adapters over `Connection<{Route,Nftables}>::into_events_with_resync`'s
  output. The trait blanket-impls over any
  `Stream<Item = Result<ResyncedEvent<T>>> + Unpin`, so it
  applies to both watchers without per-protocol
  duplication.
  Adapters shipped:
  - `predicate_filter(key_fn)` — drops consecutive
    `Event(T)` / `Resynced(T)` items whose key matches the
    previously-emitted item's key; `Marker` items always
    pass through (they're state-machine signals).
  - `map_event(f)` — projects the inner `T` to a
    domain-specific type via the closure; `Marker` items
    pass through unchanged.
  `default_backoff()` + `StreamBackoff` (Plan 195 §2.2)
  deferred — most consumers handle restart backoff at the
  spawn-loop level via `tokio::time::sleep`; in-stream
  backoff would need `tokio::time::Sleep` Pin gymnastics
  that don't justify the LOC without a current consumer
  ask. 4 new unit tests pin the dedup + map + marker
  passthrough + error propagation contracts.

- **Documentation + tracing-span audit (Plan 192 D4 + W7)** —
  - **D4**: `link.rs` rewrote 10 "namespace-safe variant that
    avoids reading from /sys/class/net/" docstrings to remove
    the misleading claim. The name-based and index-based
    constructors are both netlink-correct; the difference is
    purely ergonomic. Plan 186 §1's audit confirmed
    `resolve_interface` is netlink-based end-to-end.
  - **W7**: Audit + backfill `#[tracing::instrument]` on
    `Connection<P>` public methods that grew without spans:
    `enable_strict_checking`, `set_ext_ack`, `for_namespace`,
    `subscribe_all`, `dump_typed`, and the 7 streaming-dump
    wrappers (`stream_links`, `stream_routes`,
    `stream_neighbors`, `stream_addresses`, `stream_qdiscs`,
    `stream_classes`, `stream_filters`). Trivial accessors
    (`socket`, `state`, `timeout`, etc.) deliberately stay
    bare per CLAUDE.md observability guidance. Closes the
    "every Connection method, every netlink request/ack/dump
    cycle" contract from CLAUDE.md §Observability.
  - D1 / D5 / D6 / D2-D3 already shipped in Plans 186 §3c,
    188 §2.2, 188 §2.6, 187 respectively (per the 0.19
    consolidation-pass cross-references).

- **`Connection<Route>::into_events_with_resync` +
  `subscribe_all_with_resync` + `rtnetlink_snapshot`
  (Plan 191 §2.5 + §2.6)** — RTNETLINK twin of Plan 185's
  nftables resync wrappers. The infra (`ConnectionFactory<P>`
  + `events_with_resync` from Plan 185 + `impl EventSource
  for Route` + `RtnetlinkGroup` enum from 0.17) was already
  in place; this commit ships the Route-specific layer:
  `rtnetlink_snapshot()` walks the current state via the
  existing `get_links` / `get_addresses` / `get_routes` /
  `get_neighbors` methods, returning a `Vec<NetworkEvent>`
  of `New*` variants in the kernel's natural emit order.
  `Connection<Route>::into_events_with_resync(factory)` is
  the spawn-friendly owned form; `subscribe_all_with_resync`
  borrows for caller-held queries. Both subscribe to every
  rtnetlink multicast group before returning the stream.
  Closes nlink-feedback §15 + W2 (lab Plan 158d's polling
  fallback can now become subscribe-based watch).

- **`serde` feature flag — opt-in `Serialize` derives on every
  public diff/result/report type (Plan 189)** — gated by a new
  top-level `serde` feature (opt-in only; included in `full`).
  JSON shape conventions: structs use `rename_all = "kebab-case"`
  (`links-to-add`, not `links_to_add`); enums use
  `rename_all = "snake_case"` so unit variants emit bare strings
  (`"inet"`, not `{"Inet": null}`).
  Types gaining `Serialize` (in this commit):
  `ConfigDiff`, `NftablesDiff`, `LinkChanges`, `DeclaredLink`,
  `DeclaredLinkType`, `DeclaredAddress`, `DeclaredRoute`,
  `DeclaredRouteType`, `DeclaredQdisc`, `DeclaredQdiscType`,
  `QdiscParent`, `LinkState`, `MacvlanMode`, `BondMode`,
  `VlanProtocol`, `NetkitMode`, `NetkitPolicy`, `NetkitScrub`,
  `AdSelect`, `LacpRate`, `Family`, `Hook`, `ChainType`,
  `Priority`, `Policy`, `DeclaredTable`, `DeclaredChain`,
  `DeclaredRule` (`body` field skipped), `DeclaredFlowtable`,
  `RuleHandle`, `ApplyResult`, `ApplyError` (`error` field
  serialized as the `Display` string), `ReconcileOptions`
  (tc recipe + nftables — both shapes), `ReconcileReport`
  (tc recipe + nftables), `StaleObject`, `UnmanagedObject`,
  `TcHandle`, `FilterPriority`.
  Use case: `apply --check --json` envelopes for CI gates and
  IaC tooling. The kebab-case shape matches nlink-lab's
  existing schema convention. `Deserialize` is **not** derived
  this commit — the diff types are not user-constructible
  (they're products of `compute_diff`), so round-trip
  deserialization adds no consumer value. Closes
  nlink-feedback §9 + W4.
  5 new JSON-shape unit tests in `crate::serde_tests` (gated
  on `feature = "serde"`).

- **`ConfigDiff::apply` inherent method (Plan 188 §2.1)** —
  matches `NftablesDiff::apply`'s shape from Plan 157.
  ```rust
  let diff = cfg.diff(&conn).await?;
  println!("{diff}");
  diff.apply(&conn, ApplyOptions::default()).await?;
  ```
  More efficient than `NetworkConfig::apply` when you already
  hold a diff — saves one re-dump round-trip.

- **`RouteBuilder::default_v4()` + `default_v6()`
  (Plan 188 §2.3)** — declarative-side mirror of
  `Ipv4Route::default_route()` / `Ipv6Route::default_route()`
  (Plan 184). Self-documenting:
  ```rust
  RouteBuilder::default_v4().via("192.0.2.1")
  ```

- **GSO/GRO/TSO cap parsing on `LinkMessage` (Plan 190
  §2.3c)** — 7 new u32 accessors: `gso_max_segs`,
  `gso_max_size`, `gro_max_size`, `tso_max_size`,
  `tso_max_segs`, `gso_ipv4_max_size`,
  `gro_ipv4_max_size`. The 4 legacy caps were already
  defined in the `IflaAttr` enum but not extracted by the
  message parser; this commit adds the parsing AND the
  two new IPv4-specific caps from kernel 6.6+
  (`IFLA_GSO_IPV4_MAX_SIZE=63`,
  `IFLA_GRO_IPV4_MAX_SIZE=64`). All 7 accept-larger-than-
  expected on attribute length per CLAUDE.md
  §"Parser robustness" rule 1. Useful for throughput
  tuning on heterogeneous NICs (mixed v4/v6 workloads on
  the same box). 3 new unit tests: parses all 7 caps,
  absent-attrs-stay-None, IflaAttr enum numeric pinning.

- **ovpn link half (kernel 6.16+) — `OvpnLink` +
  `LinkBuilder::ovpn` + `DeclaredLinkType::Ovpn`
  (Plan 190 §2.3b)** — minimal in-kernel OpenVPN
  data-channel-offload link. Imperative `OvpnLink` ~50 LOC
  (matching the `IfbLink` shape). Declarative path: zero-arg
  `LinkBuilder::ovpn()` plus the `Ovpn` enum variant.
  Useful for inventory tools that need to detect ovpn
  interfaces. Peer / cipher config stays in the GENL `ovpn`
  family — deferred to Plan 197 in 0.20 as a parallel
  declarative track alongside WireGuard's peer config.
  2 new unit tests.

- **netkit declarative path (kernel 6.7+) — `LinkBuilder::netkit`
  + `DeclaredLinkType::Netkit` (Plan 190 §2.3a)** —
  BPF-programmable veth pair. Imperative `NetkitLink` +
  `NetkitMode` + `NetkitPolicy` + `NetkitScrub` already
  shipped in 0.16; this lifts them to `NetworkConfig`. Five
  setters: `netkit_mode` (L2/L3), `netkit_primary_policy` /
  `netkit_peer_policy` (Forward/Blackhole),
  `netkit_scrub` / `netkit_peer_scrub` (kernel 6.10+).
  Enums re-exported via `nlink::netlink::config::types`.
  Use case: Cilium-style no-bridge service-mesh data plane.
  3 new unit tests.

- **Bond options gap-fill: `bond_ad_select`, `bond_lacp_rate`,
  `bond_downdelay`, `bond_updelay`, `bond_resend_igmp`
  (Plan 190 §8)** — 5 new declarative-path setters on
  `LinkBuilder` covering the previously-imperative-only bond
  knobs. `DeclaredLinkType::Bond` grew matching
  `Option<...>` fields. The imperative `BondLink` already
  exposes all of these; the apply-path arm forwards them.
  Existing `AdSelect` + `LacpRate` enums re-exported via the
  config types module as `BondAdSelect` / `BondLacpRate` (no
  new types — single source of truth). Closes the
  consolidation-pass §8 expansion. 3 new unit tests.

- **`LinkBuilder::vxlan_local` / `vxlan_port` /
  `vxlan_underlay_dev` (Plan 190 §2.1)** — declarative-path
  coverage for the three VXLAN knobs nlink-lab §10 flagged.
  `DeclaredLinkType::Vxlan` grew `local: Option<IpAddr>`,
  `port: Option<u16>`, `underlay_dev: Option<String>`. The
  imperative VxlanLink already exposes `.local(Ipv4Addr)` /
  `.port(u16)` / `.dev(name)`; the apply-path arm forwards
  all three (IPv6 `local` values silently dropped today —
  the imperative layer is IPv4-only for tunnel-source IPs,
  matching the existing `remote` handling). 3 new unit
  tests + 1 root-gated integration test reproducing the
  nlink-lab 158e Slice 4 case. Note: idempotent re-apply
  coverage (Plan 190 §2.1 ¶"Idempotence implication") is
  deferred — VXLAN `compute_diff` parity against the
  kernel's IFLA_VXLAN_* attribute dump would need an
  IFLA_INFO_DATA parser; for now re-apply replays the
  create. **Note**: `DeclaredLinkType::Vxlan` widening
  (already `#[non_exhaustive]`) requires `..` rest-pattern
  in downstream matches.

- **`LinkBuilder::vlan_protocol(p)` + `VlanProtocol` enum
  (Plan 190 §2.2)** — declarative-path VLAN protocol selector.
  The imperative `VlanLink` gains a typed `.protocol(VlanProtocol)`
  setter alongside the existing `.qinq()` shortcut.
  `DeclaredLinkType::Vlan` grew a `protocol: Option<VlanProtocol>`
  field; `None` == kernel default (802.1Q). Use
  `VlanProtocol::Dot1ad` for Q-in-Q. `VlanProtocol` is
  `#[non_exhaustive]`. Closes nlink-feedback §12. **Note**:
  widens `DeclaredLinkType::Vlan` — downstream pattern matches
  must use `..` rest-pattern (the in-tree integration test
  config.rs:136 was updated to demonstrate).
  4 new unit tests.

- **`LinkBuilder::vrf(table)` + `DeclaredLinkType::Vrf`
  (Plan 190 §2.3)** — declarative-path VRF coverage. The
  imperative `VrfLink` shipped already; this lifts it to
  `NetworkConfig`. Members enslave via the existing
  `LinkBuilder::master` chain. The Plan 186 §3c topo-sort
  makes VRF declared after its members still apply
  correctly. Three new unit tests + two new root-gated
  integration tests (gated by `require_module!("vrf")`).
  Closes nlink-feedback §13 VRF half (WG half deferred to
  Plan 196 for 0.20). **Note**: this widens the
  `DeclaredLinkType` enum (already `#[non_exhaustive]`);
  downstream pattern matches without `..` rest-pattern would
  break, see migration guide §"Plan 190".

- **Topo-sort `links_to_add` so parent-before-child holds
  regardless of declared order (Plan 186 §3c)** —
  `NetworkConfig::apply` now stable-sorts the new-links list
  so a VLAN whose parent dummy is in the same apply lands
  AFTER the parent. Independent links keep their declared
  order (the sort is stable). Lifts the "declare parent
  first" footgun that the nlink-lab 158e Slice 3 case hit
  — `NetworkConfig` constructed from a `HashMap` (where the
  child happens to iterate first) now works. The
  `NetworkConfig::link` docstring documents the new
  order-independence guarantee. 7 new unit tests pin the
  sort behavior.

- **Integration repro for the VLAN parent ifindex race
  (Plan 186 phase 1)** — three new root-gated tests in
  `tests/integration/network_config_apply.rs`:
  `vlan_parent_dummy_in_same_apply_succeeds` (headline),
  `vlan_parent_dummy_declared_in_either_order` (hash-defeating
  order; tolerantly records pre-topo-sort behavior),
  `vlan_parent_already_exists_in_kernel` (control). Plan 186's
  audit found nlink's `resolve_interface` is netlink-based
  end-to-end (no cache, no sysfs) — the maintainer's
  hypotheses were wrong. The integration repro ships as a
  permanent regression guard; if green, the symptom may not be
  reproducible in our harness and the topo-sort + ordering
  docstring still ship as defensive additions.

- **`NetworkConfig::apply_reconcile` (Plan 188 §2.4)** —
  bounded-retry sibling of `NetworkConfig::apply`, mirroring
  `NftablesDiff::apply_reconcile` (Plan 157, 0.16). Retries
  on `Error::is_busy()` / `is_try_again()` up to
  `opts.max_retries` times with exponential backoff. For
  RTNETLINK the transient surface is smaller than nftables —
  no batch-end races — but VRF table allocation + neighbor
  cache pressure still benefit. Uses the nftables-side
  `ReconcileOptions` (the retry-budget shape), NOT the
  crate-root `ReconcileOptions` (the TC recipe shape with
  `fallback_to_apply` / `dry_run`). Plan 187's `errno()`
  Io-shape fix means raw socket-layer `EBUSY`/`EAGAIN`
  classifies correctly now.

- **`LinkChanges::Display` (Plan 188 §2.5)** — `ConfigDiff::Display`
  can render `links_to_modify` rows compactly:
  `~ link eth0 (mtu=9000, up)`. Wraps the existing `summary()`
  (which may itself be deprecated in 0.20).

- **`Connection<Nftables>::del_{table,chain,rule}_if_exists`
  (Plan 188 §2.7 / feedback W8)** — idempotent siblings of the
  existing `del_*` methods. Return `Ok(true)` when the resource
  was deleted, `Ok(false)` when it didn't exist (kernel ENOENT).
  Replaces the universal `let _ = conn.del_table(...).await;`
  ignore pattern.

- **`Error::chain_walk` + `root_cause` + `contexts` (Plan 187 §2.2)** —
  iterator over the source chain that transparently unwraps
  `Box<nlink::Error>` (the trap the maintainer hit in their 158b
  work). Plus two convenience shortcuts: `root_cause()` returns
  the deepest `nlink::Error` in the chain, `contexts()` collects
  every layer outer-to-inner. New named `ChainWalk` iterator
  struct exposed at the crate root. Rustdoc on `Error::Kernel`
  warns about the boxed-source trap + points consumers at
  `chain_walk` as the escape hatch.

- **Parser robustness policy + CI gate (Plan 193 — Phase 1)** —
  CLAUDE.md gains a new §"Parser robustness" section
  documenting the three defensive-parsing rules used across
  the lib (accept-larger-than-expected on fixed-size structs,
  pathological-length input guards on header-driven chain
  walks, recoverable per-message parse failures in event
  parsers). New `scripts/audit-recv-loop-error-handling.sh`
  CI gate fails on a `?` operator inside a `MessageIter::new`
  walking loop in `stream.rs`. Preempts the bug classes
  tracked by netlink-packet-route #232, #152, and neli #305.
  No consumer action required — the lib already follows the
  rules; the policy + gate prevent future drift.

### Post-cycle audit batch (closes F1 + N1-N9 + Findings A-D)

A four-agent adversarial audit run after the main 0.19 cycle
work surfaced one more architectural bug, twelve correctness
bugs, and four test-coverage gaps. All eleven verified findings
shipped; Finding E was refuted (false-positive). Tracked
internally as Plan 194 closeout + the post-audit batch.

#### Breaking changes (post-cycle batch)

- **`Connection<P>::events()` / `into_events()` are now `async`
  (Finding B).** Acquires the connection's request lock for the
  stream's lifetime so concurrent streams on a shared
  `Arc<Connection>` no longer race on `poll_recv`. Same change
  cascades through:
  - `Connection<Route>::into_events_with_resync` / `subscribe_all_with_resync` → `async fn`
  - `Connection<Nftables>::into_events_with_resync` / `subscribe_all_with_resync` → `async fn`
  - `nlink::facade::watch::{route_changes,route_changes_in_namespace,nftables_changes,nftables_changes_in_namespace}` → `async fn`

  Migration: add `.await` at every call site. ~30 line changes
  across nlink's own bins/examples; downstream consumers will
  see a wave of "future used without await" errors during the
  bump.

- **`Connection<P>::subscribe()` / `subscribe_all()` /
  `subscribe_group()` flipped `&mut self` → `&self`
  (Finding A).** The underlying syscall is
  `setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP)` which is
  fd-level; the `&mut` was a stale artefact of routing through
  `AsyncFd::get_mut`. Same fix on:
  - `Connection<Nftables>::subscribe` / `subscribe_all` / `subscribe_all_with_resync`
  - `Connection<Netfilter>::subscribe` / `subscribe_all`
  - `Connection<Wireguard|Macsec|Mptcp|Ethtool|Nl80211|Devlink>::subscribe`
  - `Connection<Route>::subscribe_all_with_resync`
  - GENL macro-generated `subscribe_group` on macro-defined families
  - Internal `NetlinkSocket::add_membership` / `drop_membership`

  Migration: remove `mut` from `Connection<P>` bindings if it
  was only there for `subscribe*`. ConnectionPool's
  `PooledConnection` now supports `pool.acquire().await?.subscribe_all()?`
  — concurrent subscribe from multiple tasks sharing
  `Arc<Connection>` is also a legitimate pattern now.

- **`Connection::socket_mut()` removed.** Was the last
  `&mut self` accessor on Connection; obsolete now that
  `add_membership` is `&self`. Internal API (`pub(crate)`);
  the lib's own callers refactored to `self.socket().add_membership(group)`.

- **`Connection<P>::request_lock` field type:
  `Mutex<()>` → `Arc<Mutex<()>>` (Finding B prerequisite).**
  Required so streams can hold an `OwnedMutexGuard` whose
  lifetime is independent of the parent's borrow scope.
  `#[non_exhaustive]` struct so this is source-compatible for
  downstream code that never constructed a Connection literal,
  which is all of them (the constructor is `Connection::<P>::new()`).

#### Concurrency: F1 closed across all protocols

- **F1 — `Connection<P>` request lock** closes the rtnetlink
  #131 shape: two tasks sharing `Arc<Connection<P>>` would race
  on the recv side, with task A's recv loop consuming task B's
  response from the socket buffer and discarding it via the
  seq filter. Both tasks then blocked indefinitely (or surfaced
  `Error::Timeout` after Plan 171's 30s default). Added
  `tokio::sync::Mutex` on `Connection<P>`, acquired at every
  send+recv-loop method via a new `pub(crate) lock_request()`
  helper.

  Coverage swept across the central methods in `connection.rs`
  (send_request_inner, send_ack_inner, send_dump_inner) plus
  every protocol-specific send+recv-loop in
  `genl/{wireguard,macsec,mptcp,ethtool,nl80211,devlink}/connection.rs`,
  `nftables/connection.rs`, `sockdiag.rs`, `xfrm.rs`, `audit.rs`,
  `netfilter.rs`, `fib_lookup.rs`, `batch.rs`, plus the public
  GENL escape hatches `Connection<P>::command()` /
  `dump_command()` (initially missed in the lock sweep — closed
  in a follow-up commit). 42+ acquire sites across 14 files.

  Regression coverage: Plan 194's
  `concurrent_dumps_on_shared_connection_route_correctly` test
  (originally `#[ignore]`'d when this bug was discovered) is
  now green on CI. A second
  `concurrent_ack_requests_on_shared_connection_succeed` test
  added for ACK-style coverage.

  Trade-off: concurrent ops on a shared `Arc<Connection>` now
  serialize cleanly (the kernel processes a single socket FIFO
  anyway). For true parallel throughput use
  `ConnectionPool<P>` — each task gets its own connection.

- **Finding B — `DumpStream` + `EventSubscription` lifetime
  lock.** Stream-shape APIs were the remaining concurrency
  hole: two `DumpStream`s on a shared connection would both
  call `socket.poll_recv` and steal each other's frames.
  Closed by storing an `OwnedMutexGuard<()>` inside each stream
  struct; acquired in the async constructor, released on stream
  drop. See breaking-change entries above for the API-shape
  fallout.

#### Verified bugs (post-cycle audit)

- **N1 (CRITICAL) — `namespace::create` thread-bleed.**
  `unshare(CLONE_NEWNET)` is scoped to the calling *thread*,
  not the process. When called from a tokio worker thread
  (`LabNamespace::new` in tests, app code that creates netns
  via tokio runtime), every other tokio task scheduled on that
  worker temporarily observed the new empty namespace until the
  matching `setns()` restored it — including any `Connection<P>`
  they constructed, which silently bound to the wrong netns.
  Fix: isolate the unshare+mount+setns sequence on a freshly
  `std::thread::spawn`'d worker so the bleed is bounded to a
  dedicated thread that does nothing else.

- **N2 (HIGH) — Malformed multicast frame killed unrelated
  request.** When a `Connection<P>` was both subscribed
  (multicast) and performing requests, the recv loop saw both
  unicast replies AND multicast frames through the same
  `recv_msg().await`. A `?` propagation on `MessageIter` parse
  errors fired BEFORE the seq filter could discard the frame,
  killing the request. Fixed: skip parse failures silently in
  the per-frame loop (extends Plan 193 §2.3 rule 3 to
  subscribed-connection request paths). 3 recv loops in
  connection.rs touched.

- **N3 (HIGH) — `xfrm.rs` `from_le_bytes` on host-order fields.**
  4 sites used `u16::from_le_bytes` / `u32::from_le_bytes` for
  netlink attribute headers and XFRM algo fields, which the
  kernel emits in host byte order. Silently broken on big-endian
  platforms (s390x, sparc64, PowerPC-BE). Fixed to
  `from_ne_bytes`. On LE hosts `to_le_bytes` and `to_ne_bytes`
  coincide so this regressed silently; the audit caught it via
  kernel-source cross-check.

- **N4 (HIGH) — `RouteMessage::write_to` dropped 5 fields.**
  `source`, `iif`, `pref`, `expires`, `multipath` (the Plan 202
  ECMP nexthop chain) were parsed but never written, silently
  dropping them on `get → mutate → set` round-trips. Added 5
  builder setters (`.source(addr, prefix_len)`, `.iif(ifindex)`,
  `.pref(p)`, `.expires(secs)`, `.multipath(Vec<ParsedNextHop>)`)
  + 5 emit branches + a `write_attr_multipath` helper that
  mirrors `parse_multipath` (rtnexthop chain with nested
  RTA_GATEWAY). ECMP route replay through the typed API works
  now. Roundtrip regression test added.

- **N5 (HIGH) — `NeighborMessage::write_to` dropped 6 fields.**
  `probes`, `port` (BIG-endian — VXLAN UDP port), `vni`,
  `ifindex_attr`, `master`, `cache_info` were parsed but never
  written. Blocked typed VXLAN FDB programming via
  `NeighborMessageBuilder` — users had to drop to raw
  `MessageBuilder`. Added 6 builder setters + 6 emit branches +
  `write_attr_u16_be` (for NDA_PORT) + `write_attr_cache_info`.
  Roundtrip regression test added.

- **N6 (HIGH) — `WireguardWatcher::next_events` first-failure
  killed whole watcher.** Plan 199's per-interface loop used
  `?` to propagate `get_device_by_name` errors. Deleting one
  watched interface out-of-band aborted the entire poll cycle —
  all other interfaces' updates silently dropped, watcher
  stuck. Fixed: `match` on each per-iface result, log
  `tracing::warn!` on error, emit `PeerRemoved` for tracked
  peers on the failed iface, drop it from `self.previous`,
  continue.

- **N7 (HIGH) — `Stack::apply` had no pre-flight validation.**
  Failure in the WireGuard layer after network + nftables
  succeeded left the host in a partial state (interfaces +
  firewall up, no VPN). Fixed: call `self.diff().await?` first
  to validate every set layer against current kernel state
  before any mutation. Catches the high-value failure modes
  (missing kernel module, invalid key, family-resolution
  failure, permission, missing netns). Residual race window
  documented in the rustdoc.

- **N8 (MEDIUM) — `parse_af_spec_vlans` / `_tunnels` dropped
  orphan RANGE_BEGIN.** Consecutive RANGE_BEGIN markers (no
  intervening RANGE_END) silently overwrote the prior
  `range_start` and dropped the entire prior range. Trailing
  RANGE_BEGIN at end of chain also dropped. Plan 193 rule 2
  ("pathological-length input guards") requires defensive
  handling. Fixed: emit prior `range_start` as a single
  VLAN/tunnel with a `tracing::warn!`, then start the new
  range. Symmetric fix for the VLAN + tunnel parsers.

- **N9 (MEDIUM) — 6 sibling parsers used `le_u16` for
  host-order `nla_len`/`nla_type` + wrong mask in `rule.rs`.**
  `messages/{rule,address,link,neighbor,route,tc}.rs` all
  parsed `struct nlattr` headers as little-endian. Also
  `rule.rs` masked `0x7fff` instead of canonical
  `NLA_TYPE_MASK = 0x3fff`, so any future kernel attr shipped
  with `NLA_F_NET_BYTEORDER` would silently miss every match
  arm. Fixed all 6 to `take(2)` + `from_ne_bytes` (winnow has
  no `ne_u16`); rule.rs uses `NLA_TYPE_MASK`.

- **Finding A (HIGH) — subscribe blocked through ConnectionPool.**
  See breaking changes above.

- **Finding C (MEDIUM) — `Pool::invalidate` capacity decay.**
  `PooledConnection::invalidate` dropped the broken connection
  without replacing it. After N invalidates a size-N pool's
  `acquire()` would block indefinitely. Fixed: added a
  `Factory<P>` trait on `PoolInner` capturing the namespace +
  sync/async build mode. `invalidate` now `tokio::spawn`s a
  task that calls `factory.build().await` and `try_send`s the
  replacement into the pool's mpsc. Capacity recovers.
  Integration test
  (`pool_invalidate_replenishes_capacity`) asserts the
  replenish lands.

- **Finding D (LOW) — `Connector::send_proc_control` missed F1
  lock.** Send-only path didn't acquire `request_lock`,
  violating the doc invariant. Fixed: acquire the lock for the
  send. Also corrected misleading comment "NLMSG_DONE" → the
  actual value (0) is NLMSG_NOOP. No ACK to drain
  (`NLM_F_ACK` is not set; cn_proc doesn't emit one).

- **Finding E — `Batch::send_chunk` stale-seq window: REFUTED.**
  Original audit agent claimed the recv loop's seq matching
  accepted stale frames from earlier requests via a `> end_seq`
  window check. Re-read: the code uses per-op exact seq
  matching (`ops.iter().position(|op| op.seq == header.nlmsg_seq)`),
  not a window. Agent hallucinated the check. No fix needed;
  documented for future audit cycles.

#### Test backfill

- **Plan 204 C1 — Verdict::Jump + Verdict::Goto kernel
  round-trip.** Asserts the rule survives the kernel commit
  AND the raw `NFTA_RULE_EXPRESSIONS` bytes contain the
  big-endian encoding of the correct verdict constants
  (`NFT_JUMP = -3`, `NFT_GOTO = -4`) and NOT the pre-fix wrong
  constant (`NFT_BREAK = -2`). CI surfaced that
  `NFTA_VERDICT_CODE` is actually `__be32` on the wire — the
  test correctly uses `to_be_bytes()` to assert the
  protocol-correct encoding.

- **Plan 211 M1 — `Hook::InetIngress` kernel acceptance.**
  Installs a Prerouting chain AND an InetIngress chain at the
  same priority on the same Inet family table. Pre-fix the
  second chain would EEXIST (both aliased to hook 0); post-fix
  InetIngress = NF_INET_INGRESS (5) so they coexist. Skips
  gracefully on kernels < 5.10.

- **Plan 191 — Route `subscribe_all_with_resync` live events.**
  Asserts that a live multicast event (a dummy link addition)
  arrives wrapped in `ResyncedEvent::Event(NewLink)` through the
  resync stream. The Route-side glue is a separate code path
  from the Nftables side; this guards against a silent
  regression that would drop the wrapper.

- **F1 sweep gap — `concurrent_ack_requests_on_shared_connection_succeed`.**
  Extends Plan 194's regression coverage to ACK-style ops.
  16 concurrent `add_link` calls on a shared
  `Arc<Connection<Route>>`; all must succeed and the final
  dump must see all 16 dummies.

## [0.18.0] - 2026-05-29

### Added

- **`DeclaredChainBuilder::chain_type(ChainType)` (Plan 180)**
  — closes the parity gap between the imperative
  `Chain::chain_type` and declarative `DeclaredChain` paths.
  Required for declarative NAT chain reconcile via
  `NftablesConfig::diff().apply()`: a chain hooking
  `prerouting`/`postrouting` without `chain_type(ChainType::Nat)`
  defaults to `ChainType::Filter`, and any `masquerade`/
  `snat`/`dnat` verdict refuses to load with `EOPNOTSUPP`.
  Unblocks downstream consumers (e.g. nlink-lab) migrating
  to the declarative path. Mirrors the imperative builder's
  rustdoc + invariants.

- **`Chain::device(name)` + `DeclaredChainBuilder::device(name)`
  (Plan 180, adjacent gap)** — bind a netdev base chain to a
  specific interface (`type filter hook ingress device eth0
  priority -150`). Wires `NFTA_HOOK_DEV` (constant 3 inside
  the `NFTA_CHAIN_HOOK` nest). Required for `Family::Netdev`
  base chains; ignored on other families. Both imperative and
  declarative paths gained the setter. `ChainInfo` now exposes
  `device: Option<String>` populated from dump responses, and
  is now `#[non_exhaustive]` (only construction site is
  internal `parse_chain` — no breaking change for downstream).

- **`list_tables_in(family)` / `list_chains_in(table, family)`
  / `list_flowtables_in(table, family)` /
  `list_sets_in(table, family)` (Plan 181)** — server-side
  filtered dump methods on `Connection<Nftables>`. Mirror the
  existing `list_rules(table, family)` shape: each new method
  emits the corresponding `NFTA_*_TABLE` attribute +
  `nfgen_family` so the kernel returns only matching entities.
  More efficient than `list_*().filter(...)` on hosts with
  many tables. The unfiltered counterparts keep working
  unchanged. Integration test
  `list_in_filters_match_only_target_table` exercises all
  four `_in` shapes against a two-table fixture.

- **`Error::ext_ack() -> Option<&str>` +
  `Error::ext_ack_offset() -> Option<u32>` (Plan 182)** —
  inherent accessors over the `Kernel` / `KernelWithContext`
  variants' fields. Saves consumers from writing a 5-line
  `match | _ =>` ceremony at every site (forced by the
  `#[non_exhaustive]` attribute on those variants). Matches
  the existing `errno() -> Option<i32>` shape.

- **`impl Display for NftablesDiff` + `impl Display for
  ConfigDiff` (Plan 183)** — `println!("{diff}")` now works
  directly. Wraps the existing `summary()` methods, so the
  rendered output is unchanged from `diff.summary()`.

- **`Ipv4Route::default_route()` /
  `Ipv6Route::default_route()` (Plan 184)** — self-documenting
  zero-arg constructors for `0.0.0.0/0` and `::/0`.
  Equivalent to the iproute2-muscle-memory
  `Ipv4Route::new("0.0.0.0", 0)` form; pick whichever reads
  better in context.

- **`Connection<Nftables>::into_events_with_resync(factory)` +
  `subscribe_all_with_resync(factory)` (Plan 185)** —
  ENOBUFS-resilient nftables event watching. Mirrors
  `kube_rs::watcher(api, cfg) -> Stream`: hand in a factory
  closure that opens a fresh `Connection<Nftables>` on demand,
  receive a `Stream<Item = Result<ResyncedEvent<NftablesEvent>>>`.
  When the kernel drops events under pressure (`-ENOBUFS`),
  the wrapper re-dumps the ruleset via a fresh connection and
  emits the snapshot as `Resynced(...)` items between
  `ResyncMarker::ResyncStart` / `ResyncEnd` markers. The owned
  form (`into_events_with_resync`) returns a `'static + Send`
  stream that's `tokio::spawn`-friendly; the borrowed form
  (`subscribe_all_with_resync`) keeps `&mut self` around for
  ad-hoc queries on the same connection. New module
  `nftables::resync` exports `nftables_snapshot`,
  `ConnectionFactory`, `ConnectionFuture`, and the
  `OwnedResyncStream` / `BorrowedResyncStream<'_>` type aliases.
  Recipe: `docs/recipes/nftables-watch-with-resync.md`.
  Closes nlink-lab Wishlist item 5.

- **`NftablesEvent::NewSet(SetInfo)` +
  `DelSet(SetInfo)` (Plan 185, bundled)** — bundled with
  the resync wrapper because the snapshot enumerates sets, so
  drift-detection consumers need to see set creates/deletes.
  Wires `NFT_MSG_NEWSET` / `NFT_MSG_DELSET` through
  `parse_nftables_event` using the existing `parse_set` parser.
  Set elements (`NFT_MSG_NEWSETELEM`) remain unwired; open an
  issue if you need them. `NftablesEvent` carries
  `#[non_exhaustive]` already, so this is non-breaking.

### Audit fixes

- **`ConnectionFactory<P>` + `ConnectionFuture<P>` are now
  generic + live at the crate root (Plan 185 audit)** — Plan 185
  spec called for `ConnectionFactory<P>` at the crate root; the
  first cut shipped a non-generic `nftables::resync::ConnectionFactory`
  pinned to `Nftables`. Aligned now: both types live in
  `nlink::netlink::resync` (re-exported as `nlink::ConnectionFactory<P>`
  / `nlink::ConnectionFuture<P>`). Existing call sites add the
  `<Nftables>` turbofish, matching the established
  `Connection<P>::new()` pattern. Future protocol watchers can
  reuse the same alias without redefining it.

- **Plan 181 wire-shape unit tests landed** — 4 tests covering
  `build_list_tables_request` / `build_list_chains_request` /
  `build_list_flowtables_request` / `build_list_sets_request`,
  matching Plan 181 §5 acceptance. Extracted the request-builder
  bodies into free `pub(crate)` functions so the tests can
  inspect the on-wire bytes without socket I/O. No behavioral
  change to the public `list_*_in` methods.

- **Plan 185 ENOBUFS-recovery integration test landed** — new
  `into_events_with_resync_recovers_from_enobufs` (root-gated)
  drives the wrapper end-to-end through a real kernel overflow:
  shrinks the multicast subscriber's `SO_RCVBUF` to 256 bytes,
  spawns a 2k-iteration rule-add flood from a second connection,
  drains the resync stream slowly, asserts the
  `ResyncStart → Resynced(...) → ResyncEnd` marker sequence.
  Needed a new `NetlinkSocket::set_rcvbuf(bytes)` helper
  (`SO_RCVBUFFORCE` — requires `CAP_NET_ADMIN`, matches the
  existing root-gated test scope).

- **`ChainInfo.chain_type` is now `Option<ChainType>` (was
  `Option<String>`) (Plan 180 audit)** — Plan 180 spec called
  for a typed enum on the dump-side field; the first cut
  shipped a raw string for parser convenience. Aligned now:
  `parse_chain` maps the kernel's `"filter"`/`"nat"`/`"route"`
  string into the typed `ChainType` variant; unrecognised
  values (kernel can grow new chain types) yield `None`.
  Added `ChainType::from_kernel_string(&str) -> Option<Self>`
  as the canonical mapping. Affects only downstream code that
  read `ChainInfo.chain_type` directly — typed match arms keep
  working, stringly comparisons (`== Some("nat".into())`) need
  to become `== Some(ChainType::Nat)`.

### Breaking changes (lib internals)

- **`events_with_resync` is now lifetime-generic (Plan 185)** —
  the snapshot-future bound went from `Send + 'static` to
  `Send + 'a`. Existing call sites that handed in `'static`
  closures keep working unchanged (the `'a` parameter defaults
  via lifetime elision to whatever satisfies the caller). The
  refactor unlocks the borrowed `subscribe_all_with_resync`
  variant whose snapshot future doesn't need to outlive the
  caller's stack frame.

## [0.17.0] - 2026-05-26

### Breaking changes

- **`Register` discriminants changed (Plan 178)** — switched
  from `NFT_REG32_xx` (`8..=11`, 4-byte register aliases) to the
  canonical `NFT_REG_x` form (`1..=4`, 16-byte registers).
  Downstream code that cast `Register::R0 as u32` and stored
  the literal value `8` will see `1` instead. The lib's
  wire-format behavior is unchanged from the kernel's
  perspective — the kernel canonicalizes both forms to
  `NFT_REG_1` internally — but anyone matching the raw integer
  needs an audit. Enum now carries `#[repr(u32)]`, locking the
  memory layout so the `as u32` cast is well-defined.

- **`NftablesDiff::rules_to_delete` tuple shape**: changed
  from `Vec<(String, Family, RuleHandle)>` to
  `Vec<(String, Family, String, RuleHandle)>` — the chain name
  is now carried explicitly. The kernel rejects a `DELRULE`
  with an empty `NFTA_RULE_CHAIN` even when
  `NFTA_RULE_HANDLE` pins the rule, contrary to an earlier
  assumption. Plan 178 closeout.

### Fixed

- **`Connection::send_request` / `send_ack` no longer error
  when the socket is also subscribed to multicast groups** —
  both recv paths did a single `recv_msg()` and bailed if the
  returned frame happened to carry only multicast events
  (`seq=0`) instead of the unicast ACK to the just-sent
  request. They now loop on `recv_msg()` until a frame with a
  matching seq arrives, ignoring unrelated multicast events
  along the way. Same canonical shape Plan 172 enforced on the
  dump-loops; the 30s default operation timeout (Plan 171)
  bounds the loop. Affected the rare pattern of issuing
  unicast requests on a `Connection` that's also `subscribe`'d
  to a group the request mutates (e.g. an event-monitor
  connection that also creates the interface it's about to
  observe).

- **`Connection::<Nftables>::send_batch` no longer hangs on a
  missing batch-end ACK (Plan 170)** — the recv-loop didn't
  filter by `nlmsg_seq` and terminated on the first per-op ACK
  rather than the BATCH_END's ACK. A sequence-skew on the GHA
  `rust:bookworm` container surfaced this as a 22-minute hang
  on the 0.16 cut CI. Fix: seq-filter + end-seq termination +
  `NLM_F_ACK` on `NFNL_MSG_BATCH_END`. The canonical
  recv-loop shape is now documented in CLAUDE.md and audited
  across all 9 lib recv-loops (see Plan 172 under "Changed").
  Un-ignored 4 of the 7 `nftables_reconcile::*` tests this
  blocked; the remaining 3 became Plan 178.

- **`NftablesConfig::diff` body-bytes false-positive (Plan 178)**
  — keyed rules were flagged as `to_replace` on every idempotent
  re-diff, churning kernel state on every reapply for any caller
  of the declarative-config reconcile loop. Three coordinated
  fixes (see "Breaking changes" above for the two API-level
  ones; the third is the diff-path internal):
  - **`normalize_tlv` in the diff path**: walks both sides of
    the comparison as TLV trees, strips `NLA_F_NESTED` (`0x8000`)
    and `NLA_F_NET_BYTEORDER` (`0x4000`) hint bits, and sorts
    sibling attributes by type at every depth. Closes the
    writer-vs-kernel divergence on the NESTED bit (writer set
    it on every nest; kernel doesn't on its outgoing
    serialization) and intra-nest attribute ordering (writer
    emits in source order; kernel in canonical numeric order).
  - Un-ignored 3 `nftables_reconcile::*` tests (idempotent
    reapply, replace, delete) that were `#[ignore]`'d under
    Plan 178 tracking. They now exercise the full diff +
    apply + re-diff cycle including delete-by-handle.

### Added

- **`Bottleneck::score: f64` normalized severity (Plan 169 Phase 3)**
  — `Diagnostics::find_bottleneck()` now returns a `Bottleneck`
  with a `score: f64` field (range 0.0..=1.0) computed from
  `drop_rate × 0.6 + backlog_pressure × 0.3 + error_rate × 0.1`,
  saturating at 1.0. Backlog and error components are gated on
  the bottleneck's `BottleneckType` (only counted when
  applicable), so a pure hardware-error bottleneck scores on
  the error component alone. Useful for sorting multiple
  bottlenecks by severity in a controller dashboard. 6 unit
  tests cover empty input, pure-component scores, composite
  scores, saturation, and type-gating.

- **`From<AddressParseError>` + `From<RouteParseError>` for
  `nlink::Error` (Plan 173)** — removes the
  `.map_err(|e| nlink::Error::InvalidMessage(e.to_string()))?`
  ceremony in `NetworkConfig` caller chains. The two parse-
  error types are now `#[from]` variants on `nlink::Error`, so
  `?` propagates them cleanly:

  ```rust
  // before
  let addr: Address = "10.0.0.1/24"
      .parse()
      .map_err(|e: AddressParseError| nlink::Error::InvalidMessage(e.to_string()))?;
  // after
  let addr: Address = "10.0.0.1/24".parse()?;
  ```

  `examples/config/declarative.rs` updated accordingly.

- **`docs/release-validation-manual.md` (Plan 176)** — pre-cut
  hardware-validation checklist for the lib paths no CI can
  exercise (XFRM IPsec offload, Devlink rate, Devlink port
  function state, `net_shaper` caps). Documents per-feature
  expected outcome + failure-mode triage. The cut script
  (`scripts/cut-release.sh`) points at this file before the
  irreversible publish step. Introduces the
  `> ⚠ No CI coverage — manually validated YYYY-MM-DD against
  > <hardware>` CHANGELOG annotation convention for future
  hardware-only feature entries. Self-hosted-runner +
  vendor-cloud-lab paths sketched as future plans for the day
  a real downstream needs CI coverage on these paths.

- **`scripts/cut-release.sh` (Plan 175)** — one-shot orchestrator
  for an nlink release cut. Walks the Plan 167 sequence end-to-
  end with confirmation prompts at the irreversible steps
  (publish, merge, tag-push). Bakes in the three friction points
  hit during the 0.16 cut:
  - skips `cargo publish -p nlink --dry-run` (known false
    negative — `nlink-macros` isn't on crates.io yet at that
    point);
  - automates the `## [Unreleased]` → `## [X.Y.Z] - YYYY-MM-DD`
    CHANGELOG promotion;
  - detects when the CHANGELOG section exceeds GitHub's 125000-
    char release-body limit and falls back to a "highlights +
    link to the full file" template;
  - replaces the manual `sleep 30` after `cargo publish -p nlink-
    macros` with a poll loop on `cargo search` (5-min cap).

  Pre-flight checks: clean tree, on the cycle branch, Cargo.toml
  version matches the arg, cargo + gh auth present.

### Changed

- **`Connection<P>` operations now time out after 30 s by
  default (Plan 171)** — every `Connection<P>` method that
  performs a netlink round-trip (every getter, setter, dump,
  batch commit) now wraps the underlying `recv` loop in a
  30-second `tokio::time::timeout`. Before 0.17.0, the timeout
  was opt-in via `Connection::timeout(Duration)` and the
  default was `None` — a kernel that never responded would hang
  the call indefinitely. Driven by the 0.16 cut's evidence (a
  22-minute GHA hang that should have been a clean
  `Error::Timeout`). Override per-Connection with
  `.timeout(Duration)`; opt out with `.no_timeout()`.

  Callers whose ops legitimately take > 30 s should bump the
  timeout explicitly via `.timeout(...)` or stream the dump in
  chunks via the `dump_stream*` APIs (which apply the timeout
  per-chunk, not over the whole dump).

- **All 9 recv-loops in the lib routed through
  `self.with_timeout` (Plan 172)** — the Plan 170 hang pattern
  (no seq filter + indefinite block on missing DONE marker)
  was audited across every lib recv-loop; 8 of 9 were already
  structurally defensive but lacked the Plan 171 timeout
  wrap. Sites updated: `nftables::{send_batch, nft_dump}`,
  `genl/{wireguard, macsec, mptcp, ethtool}` dump-collection,
  `genl/devlink` (3 loops), `genl/nl80211`
  (`collect_dump_responses`, `wait_ack`). The canonical recv-
  loop shape is documented in CLAUDE.md "Recv-loop shape
  (canonical)" — required for any new loop added to the lib.

- **CI observability (Plan 174)** — three related improvements
  so the next hidden hang takes 1 CI iteration to diagnose
  instead of 3:
  - `nlink::lab::init_test_tracing()` (lab-feature only) wires a
    libtest-friendly `tracing-subscriber` honoring `RUST_LOG`.
    Auto-invoked by `nlink::require_root!()` /
    `require_root_void!()` so every integration test path emits
    the lib's `#[tracing::instrument]` spans without per-test
    boilerplate. The integration CI job sets
    `RUST_LOG=nlink=debug,nlink::netlink::nftables=trace` so a
    hang surfaces which method was in flight at the failure
    point.
  - `.github/workflows/integration-tests.yml` modprobes
    `nf_tables` + `nf_flow_table` explicitly (previously relied
    on kernel auto-load; documents intent + survives locked-down
    containers).
  - `crates/nlink/tests/integration/IGNORED.md` catalogs every
    `#[ignore]`'d test (13 total — 12 diagnostics.rs migration
    candidates tracked by Plan 179 + 1 kernel-build-dependent
    conntrack test) with reason category + tracking plan;
    `scripts/audit-ignored-tests.sh` (wired into rust.yml as
    `audit-ignored-tests`) fails on any new ignore missing a
    catalog entry.

## [0.16.0] - 2026-05-25

> See [`docs/migration_guide/0.15.1-to-0.16.0.md`](docs/migration_guide/0.15.1-to-0.16.0.md)
> for the full upgrade walkthrough (breaking changes, behavior
> changes, and adoption guide for new features).

### Added

- **`events_with_resync` + `ResyncStream` re-exported at the
  crate root** so callers can write
  `use nlink::{events_with_resync, ResyncStream};` to match the
  existing pattern (`ResyncedEvent` / `ResyncMarker` /
  `DumpStream` already lived at the crate root).

- **`events_with_resync(stream, snapshot_fn) -> ResyncStream<...>`
  (Plan 151 closeout)** — pre-baked `Stream` wrapper that turns
  any `Stream<Item = Result<T>>` into a `Stream<Item =
  Result<ResyncedEvent<T>>>`. On `ENOBUFS` it transparently runs
  the caller-supplied snapshot future, emits `Marker(ResyncStart)`,
  replays every snapshot frame as `Resynced(T)`, emits
  `Marker(ResyncEnd)`, and returns to forwarding live events.
  Non-ENOBUFS errors fuse the stream. Hand-rolled `poll_next`
  state machine — no `async_stream` dependency. 6 unit tests
  cover pass-through, replay, empty-snapshot markers, error
  fusing, snapshot failure, multiple consecutive recoveries.

  Replaces the documented hand-rolled loop pattern in
  `docs/recipes/multi-namespace-events.md` — that pattern still
  works (and is still recommended when you want full control of
  the snapshot lifecycle), but the wrapper saves boilerplate for
  the common case. Closes Plan 151.

- **20 root-gated integration tests across 6 new files
  (Plan 166 closeout — pulled into 0.16)**:
  `tests/integration/ergonomics.rs` (Plan 148 — 3 tests),
  `streaming.rs` (Plan 149 — 2 tests),
  `flowtable.rs` (Plan 150 — 2 tests),
  `nftables_reconcile.rs` (Plan 157 — 7 tests),
  `syscall_batch.rs` (Plan 158 — 1 test),
  `pool.rs` (Plan 159 + Plan 162 guard — 5 tests). All gated
  with `nlink::require_root!()` + `nlink::require_modules!()`
  so they ship in 0.16 and early-exit cleanly when run as a
  regular user; runs under the Plan 140 privileged-CI workflow
  already in tree since 0.15.0
  (`.github/workflows/integration-tests.yml`) — activates the
  moment 0.16 merges to master.
  Hardware-only scenarios (XFRM offload, devlink rate,
  net_shaper caps round-trip) explicitly out of scope.

- **Plan 150 §9.1 formally closed — flowtable per-flow counters
  via the existing `stream_conntrack` API** (no new code; the
  original design's kernel-UAPI premise was wrong). Research
  against `include/uapi/linux/netfilter/nf_tables.h` confirmed
  `NFT_MSG_GETFLOWTABLE` returns only the flowtable's
  configuration (hooks, devices, flags) — there is no per-flow
  tuple or counter attribute. Per-flow counters live in the
  underlying conntrack entries (kept in sync by the offload
  fastpath when `flags counter` is set), surfaced via
  `CTA_COUNTERS_ORIG` / `_REPLY` on the standard
  `IPCTNL_MSG_CT_GET` dump. The `IPS_OFFLOAD_BIT` /
  `IPS_HW_OFFLOAD_BIT` status bits identify which entries were
  flowtable-offloaded.

  No new API needed — Plan 149's `Connection::<Netfilter>::stream_conntrack`
  + `ConntrackStatus::OFFLOAD` / `::HW_OFFLOAD` + the existing
  `ConntrackEntry::counters_orig` / `counters_reply` fields
  already cover the use case. `docs/recipes/nftables-stateful-fw.md`
  gains a new "Per-flow counters for offloaded flows" section
  documenting the pattern. See
  [Plan 150 §9.1 closeout](plans/150-0.16-nftables-flowtable-plan.md#91-flowtable-counter-introspection--closed-without-new-api-surface)
  for the kernel-source-cited rationale.

  Closes Plan 150.

- **Per-rule USERDATA-keyed reconciliation for `NftablesConfig`**
  (Plan 157b v2 — closes Plan 157 §4.3 with a different design
  than the original).

  `DeclaredRule::handle_key` now does real work: it's encoded as
  `NFTA_RULE_USERDATA` (libnftnl-compatible TLV — shows up as
  `comment "nlink:<key>"` in `nft list ruleset` output) on apply,
  parsed back on dump, and used as the per-rule identity field
  for the diff. Matches the existing `NetworkConfig` per-object
  reconciliation pattern (where each link/route/address is
  individually diffable by name/destination).

  ```rust
  let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| {
      t.chain("input", |c| c.hook(Hook::Input).policy(Policy::Drop))
          .rule_keyed("input", "ssh-allow", |r| r.match_tcp_dport(22).accept())
          .rule_keyed("input", "icmp-allow", |r| r.match_l4proto(1 /* IPPROTO_ICMP */).accept())
  });

  cfg.diff(&conn).await?.apply(&conn).await?;     // first time: 2 adds
  cfg.diff(&conn).await?.apply(&conn).await?;     // re-apply: 0 ops (idempotent)

  // Change one rule's body, keep the key.
  let updated = NftablesConfig::new().table("filter", Family::Inet, |t| {
      t.chain("input", |c| c.hook(Hook::Input).policy(Policy::Drop))
          .rule_keyed("input", "ssh-allow", |r| r.match_tcp_dport(2222).accept())
          .rule_keyed("input", "icmp-allow", |r| r.match_l4proto(1 /* IPPROTO_ICMP */).accept())
  });
  updated.diff(&conn).await?.apply(&conn).await?; // 1 op (replace_rule by handle)
  ```

  Diff algorithm:
  - Declared keyed rule with kernel-side `nlink:<key>` match
    → compare expression bytes; differ → `rules_to_replace`
    (in-place atomic update via `NFT_MSG_NEWRULE + NLM_F_REPLACE
    + handle`); same → no-op.
  - Declared keyed rule with no kernel match → `rules_to_add`.
  - Kernel rule with `nlink:<key>` comment NOT in declared →
    `rules_to_delete` (it's ours; it shouldn't be there).
  - Kernel rule without an `nlink:` prefix → left alone (foreign
    rule from `iptables-nft`, hand-edited via `nft -f`, etc.).
  - Declared rule without `handle_key` → always-add + `tracing::warn`
    (anonymous; no idempotency — pathological, same as a
    `LinkConfig` without a name).

  **Why this design (research-validated):** the original Plan
  157 §4.3 called for typed-Match canonicalization + reverse-
  lowering of kernel-dumped expressions. Research turned up
  that no production tool implements this — kube-proxy's
  nftables mode (KEP-3866, GA in K8s 1.33) uses chain-as-unit
  regeneration, Google's `nftables` Go library uses USERDATA
  comment-tagging, libnftnl has no equivalence API. The
  USERDATA-tagging approach is the documented production
  pattern, robust against `NFTA_RULE_COMPAT` and future kernel
  attribute additions, and aligns with `NetworkConfig`'s
  per-object identity model. See
  [`plans/157b-rule-reconciliation-design.md`](plans/157b-rule-reconciliation-design.md)
  for the full design rationale.

  New API surface:
  - `Rule::comment(comment: &str)` — attach a comment that
    round-trips through `NFTA_RULE_USERDATA`.
  - `Rule::comment_ref()` — read it back.
  - `Transaction::replace_rule(rule, handle)` — emit
    `NFT_MSG_NEWRULE | NLM_F_REPLACE | NFTA_RULE_HANDLE` inside
    the atomic batch.
  - `RuleInfo` gains `comment: Option<String>` (parsed nlink-key,
    if any), `userdata_raw: Option<Vec<u8>>` (preserves foreign
    comments), `expression_bytes: Vec<u8>` (raw payload for the
    body-equivalence check).
  - `NftablesDiff::rules_to_replace: Vec<(table, family, chain,
    handle, declared)>` — populated by the new diff branch.
  - `nftables::userdata` module (crate-private) ships the TLV
    encode/decode helpers; 8 unit tests cover round-trip,
    over-long key rejection, foreign-prefix skip, unknown-TLV
    skip, malformed input.

  Implementation:
  - `crates/nlink/src/netlink/nftables/userdata.rs` — new module.
  - `crates/nlink/src/netlink/nftables/types.rs` — `Rule.comment`
    + `RuleInfo` field additions.
  - `crates/nlink/src/netlink/nftables/connection.rs` — wire
    USERDATA into `Connection::add_rule` + `Transaction::add_rule`
    + new `Transaction::replace_rule`; extend `parse_rule` to
    extract `NFTA_RULE_USERDATA` + `NFTA_RULE_EXPRESSIONS`.
  - `crates/nlink/src/netlink/nftables/config/diff.rs` — replace
    the "always re-add" stub with per-rule identity diff.
  - `crates/nlink/src/netlink/nftables/config/apply.rs` — handle
    `rules_to_replace` in the atomic batch; auto-wire
    `handle_key` → `body.comment` at apply boundary.

  Test count: 960 lib tests (was 953 + 7 new — 3 wire-roundtrip,
  4 diff). End-to-end wire format validated via parse-back round
  trip; idempotent-reapply + replace + cascade-delete scenarios
  shipped via Plan 166 (`tests/integration/nftables_reconcile.rs`,
  7 root-gated scenarios) and run under the Plan 140
  privileged-CI workflow.

- **`NftablesDiff::apply_reconcile` + declarative-config recipe**
  (Plan 157 §4.5 + §6). Bounded retry-on-conflict variant of
  `apply` for concurrent-mutator scenarios (e.g. operator pod +
  `systemd-resolved` racing on `nft -f`):

  ```rust
  use nlink::netlink::nftables::config::ReconcileOptions;
  use std::time::Duration;

  let diff = cfg.diff(&conn).await?;
  let report = diff
      .apply_reconcile(&conn, ReconcileOptions::default())
      .await?;
  if report.attempts > 1 {
      tracing::warn!(retries = report.attempts - 1, "transient conflict");
  }
  ```

  Default options: 3 retries, 100ms initial backoff (exponential
  to `backoff × 2^10`). Predicate is
  `Error::is_busy() || Error::is_try_again()`; non-transient
  errors surface immediately. Plus a new
  [`docs/recipes/nftables-declarative-config.md`](docs/recipes/nftables-declarative-config.md)
  walking through the `diff + apply + reconcile` pattern,
  including the documented "flush before reapply" workaround for
  the rule-identity caveat.

  **Plan 157 rule canonicalization (§4.3) deferred to 0.17** —
  needs a refactor of the `Rule` type. Current `Rule` stores
  `Vec<Expr>` already-lowered; Plan §4.3's canonicalization
  design requires sorting at the typed `Vec<Match>` layer
  *before* lowering. The match-vs-expression layering is the
  prerequisite, and it's a substantial enough change to warrant
  its own focused pass.

- **Conntrack + nft-rules streaming dump** (Plan 149 closeout —
  closes Plan 149). `Connection<Netfilter>::stream_conntrack` /
  `stream_conntrack_v4` / `stream_conntrack_v6` and
  `Connection<Nftables>::stream_rules(table, family)` return
  `DumpStream` for O(1)-memory iteration. The use case that
  motivated the streaming-dump foundation in the first place:
  busy NAT gateways with millions of conntrack entries, CDN
  edges with thousands of per-tenant nft rules.

  ```rust
  use nlink::netlink::{Connection, Netfilter};
  use tokio_stream::StreamExt;

  let conn = Connection::<Netfilter>::new()?;
  let mut stream = conn.stream_conntrack(libc::AF_INET as u8).await?;
  while let Some(entry) = stream.next().await {
      let entry = entry?;
      // ... process one entry, bounded memory
  }
  ```

  Required a small extension to the `DumpStream` foundation:
  new `Connection::dump_stream_with_body<T>(msg_type, body: &[u8])`
  bypasses `T::write_dump_header` so callers can pass a
  runtime-parameterized body — conntrack needs `nfgenmsg.family`
  (varies v4/v6/AF_UNSPEC), nft-rules needs `nfgenmsg + NFTA_RULE_TABLE`
  filter attribute. The existing `dump_stream` is unchanged and
  forwards through the same internal `send_with_body_bytes`
  helper.

  Plus `FromNetlink` impls on `ConntrackEntry` + `RuleInfo`
  delegating to the existing `parse_conntrack_body` and
  `parse_rule` (one parser per kind shared with the eager /
  multicast-event paths). 5 new unit tests (942 lib tests
  total). End-to-end validated on this kernel — conntrack
  stream correctly delivered EPERM through the stream item
  channel (same wire-shape as the eager `get_conntrack` would
  produce).

- **XFRM streaming dump** (Plan 149 follow-up).
  `Connection<Xfrm>::stream_sas` and `stream_sps` return
  `DumpStream<'_, Xfrm, SecurityAssociation>` /
  `DumpStream<'_, Xfrm, SecurityPolicy>` — O(1)-memory iteration
  preferred over the eager `get_security_associations` /
  `get_security_policies` on hosts running scale-out IPsec
  (cloud gateways, telco aggregation routers with thousands of
  active SAs).

  ```rust
  use nlink::netlink::{Connection, Xfrm};
  use tokio_stream::StreamExt;

  let conn = Connection::<Xfrm>::new()?;
  let mut stream = conn.stream_sas().await?;
  while let Some(sa) = stream.next().await {
      let sa = sa?;
      tracing::info!(spi = %format!("{:x}", sa.spi), dst = ?sa.dst_addr, "SA");
  }
  ```

  Internally: refactored the existing `parse_sa_msg` /
  `parse_policy_msg` into payload-only `parse_sa_payload` /
  `parse_sp_payload` helpers (the nlmsghdr-stripped form
  `DumpStream` needs), then implemented `FromNetlink` for
  `SecurityAssociation` + `SecurityPolicy` against those
  helpers. `write_dump_header` pushes the kernel's required
  `xfrm_usersa_info` / `xfrm_userpolicy_info` body prefix
  zeroed = "match all." No public API churn — the existing
  eager methods keep working unchanged. 6 new unit tests
  (937 lib tests total).

  Conntrack + nft-rules streaming still deferred — they need
  the dump-stream API to learn how to pass a body prefix
  parameterized by caller (conntrack needs nfgenmsg.family).

- **`net_shaper` Generic Netlink family** (Plan 153 §4.3 — closes
  Plan 153). TX hardware shaping (per-NIC, per-queue, or
  intermediate-node bandwidth/burst/priority/weight) via the
  kernel-6.13 `net-shaper` family. Surface:

  ```rust
  use nlink::netlink::{
      Connection,
      genl::net_shaper::{
          NetShaper, NetShaperHandle, NetShaperMetric, NetShaperScope, NetShaperSetRequest,
      },
  };

  let conn = Connection::<NetShaper>::new_async().await?;

  // Always check caps before set — drivers vary widely.
  let caps = conn.get_caps(ifindex, NetShaperScope::Queue).await?;
  if caps.support_bw_max && caps.support_burst {
      conn.set_shaper(
          NetShaperSetRequest::new(ifindex, NetShaperHandle::queue(0))
              .metric(NetShaperMetric::Bps)
              .bw_max(1_000_000_000)
              .burst(1 << 16),
      ).await?;
  }
  ```

  Connection methods: `get_shaper` / `dump_shapers` /
  `set_shaper` / `del_shaper` / `get_caps` / `dump_caps`. The
  `group` command (NET_SHAPER_CMD_GROUP — hierarchical
  reparenting) is deferred: it needs `Vec<NetlinkAttrs>` support
  in the macro stack which doesn't ship yet (Plan 154
  follow-up).

  **Second in-tree dogfood of `nlink-macros`** (after DPLL — Plan
  156). The full family — 5 commands, 10 outer attrs, 10 caps
  attrs, 2 handle attrs, 2 enums — declares in ~200 lines of
  macro-derived Rust. The one hand-written piece is
  `NetShaperCapsReply::from_bytes`, parsing the kernel's
  presence-flag attributes (`NET_SHAPER_A_CAPS_SUPPORT_*`) into
  `bool` fields — the macros don't yet model zero-payload flag
  attributes. 15 new unit tests; 931 lib tests pass total. End-
  to-end validated on kernel 6.13+ (kernel correctly parses our
  requests, returns EOPNOTSUPP on loopback as expected). Recipe
  at [`docs/recipes/tx-hw-shaping.md`](docs/recipes/tx-hw-shaping.md);
  runnable example at
  [`crates/nlink/examples/genl/net_shaper.rs`](crates/nlink/examples/genl/net_shaper.rs).

- **DPLL multicast monitor + shared GENL group-resolution infra**
  (Plan 156 Phase 5 — closes Plan 156). The `Connection<Dpll>`
  API now exposes a typed push-based event stream:

  ```rust
  use nlink::netlink::{Connection, genl::dpll::{Dpll, DpllEvent}};
  use tokio_stream::StreamExt;

  let mut conn = Connection::<Dpll>::new_async().await?;
  conn.subscribe_monitor()?;            // resolves "monitor" group → kernel ID
  let mut events = conn.events();
  while let Some(evt) = events.next().await {
      match evt? {
          DpllEvent::DeviceChanged(dev) => println!("device {} → {:?}", dev.id, dev.lock_status),
          DpllEvent::PinChanged(pin)    => println!("pin {} → {:?}", pin.id, pin.state),
          DpllEvent::DeviceDeleted { id } | DpllEvent::PinDeleted { id } => {
              println!("removed: {id}");
          }
          _ => {}
      }
  }
  ```

  Sub-millisecond latency on lock-status changes — supersedes the
  2-second polling pattern previously documented in the recipe
  (the polling shape stays valid for cross-kernel-version
  compatibility).

  ### Shared infrastructure

  The work needed new infra that's reusable by every GENL family:

  - **`__rt::resolve_genl_family_with_groups(socket, name)`** —
    extends the existing family resolver to also parse
    `CTRL_ATTR_MCAST_GROUPS` from the `CTRL_CMD_GETFAMILY`
    response, returning `(family_id, HashMap<String, u32>)`. One
    additional kernel round-trip — none. The old
    `resolve_genl_family` (id-only) is kept for back-compat.
  - **`GenlFamily::mcast_group(name) -> Option<u32>`** new trait
    method (default-impl returns `None`) — hand-written families
    that don't carry a group map keep working unchanged.
  - **`#[genl_family]` macro** now emits a `mcast_groups: HashMap<String, u32>`
    field on every macro-generated marker struct + populates it
    at construction time + overrides `mcast_group()` with a real
    HashMap lookup.
  - **`Connection<F: GenlFamily>::subscribe_group(name)`** generic
    helper — looks up the named group via the family marker and
    calls `socket.add_membership(...)`. Returns
    `Error::FamilyNotFound { name: "<family>::<group>" }` when
    the kernel doesn't ship the group.
  - **`Connection<Dpll>::subscribe_monitor()`** family-specific
    convenience wrapping `subscribe_group("monitor")`.
  - **`DpllEvent`** enum (6 variants: device/pin × create/delete/change)
    + parser dispatching on the GENL `cmd` byte.
  - **`impl EventSource for Dpll`** wires `Connection::events()` /
    `into_events()` to yield `DpllEvent` items (matches the existing
    Netfilter/SELinux/Devlink/Nl80211/Ethtool pattern).

  5 new unit tests cover device-change parsing, device-delete
  ID-only extraction, pin-change parsing, non-notification command
  rejection, and truncated-payload rejection. 880 lib tests pass
  (was 875 + 5). Clippy clean across `--all-features`.

  ### Follow-up: existing families now use the shared infra

  Devlink, Nl80211, and Ethtool previously hand-rolled their own
  per-family multicast-group resolution in `resolve_*_family()`
  helpers (each ~100 lines of duplicated
  `CTRL_ATTR_MCAST_GROUPS`-parsing). All three now route through
  `__rt::resolve_genl_family_with_groups` and implement
  `GenlFamily` (with a `mcast_group(name) -> Option<u32>` lookup
  into the parsed map). **Net −254 lines** of duplicated wire
  parsing across the three connection.rs files. The bespoke
  `Connection::<F>::subscribe()` methods are preserved as thin
  wrappers over the generic `subscribe_group(name)`, so calling
  code is unaffected. The `Ethtool::monitor_group_id()` accessor
  now delegates to the map lookup. No API change.

- **DPLL Generic Netlink family** (Plan 156, Phases 1-4 + 6
  partial) — the kernel's clock-synchronization family (SyncE,
  PTP, GNSS-disciplined oscillators) is now a first-class
  `Connection<Dpll>` API. **First in-tree user of `nlink-macros`**
  — every type in `nlink::netlink::genl::dpll::*` is declared
  via the macro stack: ~430 lines of declarative Rust for the
  full family (12 commands, 14 device attrs, 31 pin attrs, 8
  value enums, 1 bitflags newtype, 2 nested attribute groups,
  3 message structs each for device + pin sides). Compare with
  the hand-written `wireguard` / `macsec` / `devlink` modules
  in the same `genl/` directory: 600+ lines each for comparable
  surface.

  Public surface:

  ```rust
  use nlink::netlink::{genl::dpll::{Dpll, DpllMode}, Connection};
  use tokio_stream::StreamExt;

  let conn = Connection::<Dpll>::new_async().await?;
  let mut devices = conn.dump_devices().await?;
  while let Some(dev) = devices.next().await {
      let dev = dev?;
      println!("device {}: {:?}", dev.id, dev.lock_status);
  }
  conn.set_device_mode(0, DpllMode::Automatic).await?;
  conn.set_pin_priority(pin_id, 0).await?;
  ```

  Version-gated kernel fields surface as `Option<…>`:
  - kernel 6.10+: `lock_status_error` + `clock_quality_level`
  - kernel 6.11+: pin `measured_frequency` + `phase_adjust_gran`
  - kernel 6.12+: device `phase_offset_monitor` +
    `frequency_monitor` + `phase_offset_avg_factor`

  Scaling helpers apply the kernel's dividers transparently:
  `DpllDeviceReply::temp_celsius()`,
  `DpllPinReply::phase_offset_ns()`,
  `DpllPinReply::measured_frequency_hz()`. Raw fields stay
  accessible for high-resolution callers.

  Recipe: [`docs/recipes/dpll-monitor.md`](docs/recipes/dpll-monitor.md).
  Runnable example:
  [`crates/nlink/examples/genl/dpll.rs`](crates/nlink/examples/genl/dpll.rs).

  **Multicast monitor (Phase 5) deferred** — the
  `DPLL_CMD_*_CHANGE_NTF` push-notification path needs new
  GENL multicast-group-ID resolution infrastructure that didn't
  fit this commit. Polling pattern in the recipe is the 0.16
  shape; push semantics land in a follow-up.

- **`#[derive(NetlinkAttrs)]` for nested attribute groups + the
  `nested` field hint** (Plan 154 Phase 8.5 — closes out the
  Phase 8 macro-extension batch). The final downstream-unblocker
  piece. Nested attribute groups (kernel encodes a sub-struct as
  the contents of a single `NLA_F_NESTED` attribute) now declare
  via two coordinated derives:

  ```rust
  #[derive(NetlinkAttrs, Debug, Default)]
  pub struct ParentDeviceBlock {
      #[genl_attr(1u16)] pub device_id: u32,
      #[genl_attr(2u16)] pub label: String,
  }

  #[derive(GenlMessage, Debug, Default)]
  #[genl_message(cmd = DpllCmd::PinGet)]
  pub struct DpllPinReply {
      #[genl_attr(DpllPinAttr::Id)] pub id: u32,
      #[genl_attr(DpllPinAttr::ParentDevice, nested)]
      pub parent_device: Option<ParentDeviceBlock>,
  }
  ```

  - `#[derive(NetlinkAttrs)]` emits `impl NetlinkAttrs for T {
    write_attrs, read_attrs }` — same field-type-mapping table as
    `GenlMessage` (primitives + `Option<T>` + `Vec<u8>` +
    `Vec<GenlEnum>` + bitflags + `Option<GenlEnum>`), minus the
    `CMD` const.
  - `#[genl_attr(MyAttr::Foo, nested)]` on a `GenlMessage` field
    routes through the nested type's `write_attrs` / `read_attrs`,
    wrapping the output in an `NLA_F_NESTED` attribute on the wire.
  - Like `Option<MyEnum>`, the nested field must be wrapped in
    `Option<T>` (kernel either emits the group or doesn't; no
    sensible Default).

  With this, **Plan 156 (DPLL) is fully unblocked** — every DPLL
  field shape now expressible via the macros. Plan 153.3
  (`net_shaper`) is similarly clear. Phase 8 complete.

  3 new tests: round-trip a nested group, missing-attr → None,
  on-wire `NLA_F_NESTED` flag check.

- **`bitflags`-newtype field support in `#[derive(GenlMessage)]`**
  (Plan 154 Phase 8.4). Bitmask fields (DPLL `pin_capabilities`,
  devlink port flags, etc.) now declare cleanly via the existing
  `bitflags::bitflags!` macro:

  ```rust
  bitflags::bitflags! {
      pub struct DpllPinCapabilities: u32 {
          const DIRECTION_CAN_CHANGE = 1;
          const PRIORITY_CAN_CHANGE  = 2;
          const STATE_CAN_CHANGE     = 4;
      }
  }

  #[derive(GenlMessage, Debug, Clone)]
  #[genl_message(cmd = DpllCmd::PinGet)]
  pub struct DpllPinReply {
      #[genl_attr(DpllPinAttr::Id)] pub id: u32,
      #[genl_attr(DpllPinAttr::Capabilities, bitflags = "u32")]
      pub caps: DpllPinCapabilities,
  }
  ```

  Emit writes `.bits()` directly through `emit_uN_attr`. Parse
  uses `Type::from_bits_retain(raw)` so unknown kernel-side bits
  are preserved verbatim — a newer kernel emitting flags this
  binary doesn't recognize round-trips through `parse → emit`
  unchanged instead of silently dropping bits.

  No `Option<>` wrapper needed (unlike `Option<MyEnum>`): a
  bitflags newtype is self-empty-able via `from_bits_retain(0)`,
  so missing-attribute defaults to `Type::empty()`. Allowed both
  at top-level and inside `Option<>` if the caller wants to
  distinguish "attr absent" from "attr present with no bits set".

  Added `bitflags = "2"` as a workspace dep + nlink dev-dep
  (downstream consumers bring their own version). 3 new tests:
  combined-bits round-trip, missing-attr → empty flags,
  unknown-bit preservation.

- **`Vec<MyEnum>` repeated-attribute support in
  `#[derive(GenlMessage)]`** (Plan 154 Phase 8.3). When the kernel
  emits the same attribute type multiple times for list-valued
  fields (DPLL's `mode_supported`, devlink rate-limit's list
  fields, etc.), declare the Rust side as
  `Vec<MyGenlEnum>` and tag the field with the existing
  `repr = "..."` hint:

  ```rust
  #[genl_attr(DpllAttr::ModeSupported, repr = "u32")]
  pub modes_supported: Vec<DpllMode>,
  ```

  Emit writes one attribute per element; parse accumulates each
  matching attr into the Vec in arrival order. Empty Vec emits
  zero attrs (no trailing presence indicator needed).

  `Vec<u8>` keeps its existing meaning ("the whole payload of a
  single attribute is a byte string") — only `Vec<MyEnum>` with a
  repr hint produces the repeated shape. Other `Vec<T>` shapes
  without a hint produce a compile error pointing at the supported
  forms.

  2 new tests: round-trip a 2-element Vec, empty-Vec emits no
  attrs of that type.

- **`Option<MyEnum>` field support in `#[derive(GenlMessage)]`**
  (Plan 154 Phase 8.2 — **the macro-stack headline unblocker**).
  `#[genl_attr(...)]` now accepts an optional `repr = "u8"|"u16"|"u32"`
  hint telling the derive a field is a `#[derive(GenlEnum)]`-typed
  value:

  ```rust
  #[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
  #[genl_enum(repr = "u32")]
  enum DpllMode { Manual = 1, Automatic = 2 }

  #[derive(GenlMessage, Debug, Default)]
  #[genl_message(cmd = DpllCmd::DeviceGet)]
  pub struct DpllDeviceReply {
      #[genl_attr(DpllAttr::Id)] pub id: u32,
      #[genl_attr(DpllAttr::Mode, repr = "u32")] pub mode: Option<DpllMode>,
  }
  ```

  Emit routes through `<Repr as From<MyEnum>>::from(field)` (the
  `GenlEnum` derive ships `From<MyEnum> for Repr`); parse routes
  through `<MyEnum as TryFrom<Repr>>::try_from(raw)`. Unknown
  wire values surface as `Error::InvalidMessage` carrying the
  generated `MyEnumUnknownValue(repr)` Display text.

  **Why `Option<MyEnum>` and not bare `MyEnum`?** Kernel UAPI
  enums are typically 1-based with no sensible "zero" variant,
  so `Default` doesn't exist. Wrapping in `Option<T>` makes
  missing-attribute semantics map cleanly to `None`. The derive
  emits a compile error pointing at the fix if a bare enum is
  used.

  Unblocks Plan 156 (DPLL) and Plan 153.3 (`net_shaper`) on
  scalar-enum fields. Repeated-enum (`Vec<MyEnum>`), bitflags
  newtypes, and nested attribute groups remain as the rest of
  Phase 8.

  3 new tests: round-trip `Some(MyEnum)`, missing-attr → `None`,
  unknown-value → typed error.

- **`i32` field support in `#[derive(GenlMessage)]`** (Plan 154
  Phase 8.1). The first of the five Phase 8 macro extensions —
  smallest mechanical piece. Adds `WireKind::I32` to the
  field-type-mapping table and `emit_i32_attr` / `parse_i32_attr`
  to `nlink::macros::__rt`. Unblocks DPLL's `temp_mdeg: Option<i32>`
  and any other signed-int kernel attribute. 2 new tests cover
  the positive + negative + Option<i32> round-trips.

- **`Transaction::{add_table_with_flags, del_chain, del_rule,
  add_flowtable, del_flowtable}`** on the nftables batch type
  (Plan 150 §9.4 / Plan 157 coordination follow-up). The batch
  now mirrors the imperative `Connection::<Nftables>` mutation
  surface end-to-end; no operation needs to escape the atomic
  batch.

- **`NftablesDiff::apply` flips to atomic** (Plan 157 §4.4
  closeout). With the four new `Transaction` methods above in
  place, `apply` now bundles every diff operation into one
  `NFNL_MSG_BATCH_BEGIN ... BATCH_END` round-trip — the kernel
  either accepts the whole diff (full set visible to other
  readers in one step) or rolls back the entire batch. No
  half-applied intermediate state is observable. Operators
  running long-lived `NftablesConfig` reconcilers no longer
  have to design around the partial-apply window.

  The 0.16-era non-atomic imperative path is gone — every
  table/chain/rule/flowtable mutation in a diff (including
  flagged tables) commits in one batch.

- **TC streaming dump wrappers** (Plan 149 follow-up):
  `Connection::<Route>::stream_qdiscs()` / `stream_classes()` /
  `stream_filters()` return `DumpStream<'_, Route, TcMessage>`
  for O(1)-memory iteration over kernel TC tables. Same shape as
  the existing `stream_links` / `stream_routes` /
  `stream_neighbors` / `stream_addresses`. Right answer on hosts
  with TC-heavy interfaces (per-pod CNI, per-BGP-peer route
  shaping, telecom DPDK fanout) where the existing eager
  `get_qdiscs()` / `get_classes()` / `get_filters()` would
  materialize tens of MB of intermediate buffers.

- **Nftables multicast events** (Plan 150 §9.2): subscribe to
  `NFNLGRP_NFTABLES` (7) and consume a typed
  `Stream<Item = Result<NftablesEvent>>`. Mirrors the existing
  `Connection::<Netfilter>::subscribe` /
  `Connection::<Netfilter>::events` shape that conntrack consumers
  already use.

  ```rust
  use nlink::netlink::{Connection, Nftables};
  use nlink::netlink::nftables::{NftablesEvent, NftablesGroup};
  use tokio_stream::StreamExt;

  let mut nft = Connection::<Nftables>::new()?;
  nft.subscribe(&[NftablesGroup::All])?;
  let mut events = nft.events();
  while let Some(evt) = events.next().await {
      match evt? {
          NftablesEvent::NewTable(t) => println!("+ table {}", t.name),
          NftablesEvent::DelRule(r)  => println!("- rule  on {}/{}", r.table, r.chain),
          _ => {}
      }
  }
  ```

  Eight typed variants: `NewTable`/`DelTable`, `NewChain`/`DelChain`,
  `NewRule`/`DelRule`, `NewFlowtable`/`DelFlowtable`. Sets +
  setelem + gen messages aren't parsed today (silently dropped from
  the stream — wire when a consumer asks). Bonus surface for
  Plan 157's reconcile mode: the declarative `NftablesConfig` can
  subscribe to these to drive convergent reapply on external drift.

  4 new unit tests cover group→kernel-id mapping, wrong-subsystem
  rejection, truncated-body rejection, and unknown-msg-type skip.

- **nlink-macros polish + publish-order docs** (Plan 154 Phase 7,
  closes out the macro cycle):
  - `crates/nlink-macros/README.md` — crates.io landing page
    with the headline taste, the "don't depend on this crate
    directly" note, and the **publish-order requirement** (the
    matching `nlink-macros X.Y.Z` must be on crates.io before
    `cargo publish -p nlink`).
  - `crates/nlink-macros/src/lib.rs` module docstring refreshed
    to reflect the full Phase 1–6 shipped surface (was stuck on
    Phases 1+2 narrative since Phase 3a landed).
  - Workspace `Cargo.toml` `nlink-macros` dep now carries
    `version = "..."` alongside the path dep — required for
    `cargo publish -p nlink` to resolve the dependency on
    crates.io. Documented inline.

  Plan 154 is now feature-complete for the 0.16 cycle. The
  `#[derive(NetlinkAttrs)]` derive for nested attribute groups
  remains as a documented follow-up (the trait is in tree, only
  the derive's automation is deferred).

- **Worked example + recipe for the macro stack** (Plan 154
  Phase 6):
  - [`crates/nlink/examples/macros/define_taskstats.rs`](crates/nlink/examples/macros/define_taskstats.rs)
    — full kernel taskstats family declared end-to-end in ~30 lines
    via the macros. Runs the canonical
    `Connection::<Taskstats>::new_async()` + `conn.send_typed(req)`
    cycle against a real kernel family.
  - [`docs/recipes/define-your-own-genl-family.md`](docs/recipes/define-your-own-genl-family.md)
    — narrative recipe walking through the four macros
    (`#[genl_family]` + `GenlCommand` + `GenlAttribute` +
    `GenlMessage`) and the generic dispatch that closes the loop.

- **Generic `Connection::<P: AsyncConstructible>::new_async()`**
  consolidation. The six in-tree GENL families
  (`Wireguard`, `Macsec`, `Mptcp`, `Devlink`, `Nl80211`, `Ethtool`)
  used to each carry a hand-rolled inherent `new_async()`
  duplicating the same socket-create + `resolve_async` glue.
  Replaced with a single generic
  `impl<P: AsyncConstructible + AsyncProtocolInit> Connection<P>`
  constructor. This is also what makes macro-defined families
  (`#[genl_family(...)]`) plug into the canonical API for free:
  the macro emits the `AsyncProtocolInit` impl and the generic
  constructor does the rest.

  Public API unchanged — `Connection::<Wireguard>::new_async().await?`
  still works, just routes through the generic impl now.

- **`Connection::<F: GenlFamily>::send_typed<M, R>`** +
  **`dump_typed_stream<M, R>`** (Plan 154 Phase 5) — the generic
  send-side dispatch that closes the Plan 154 loop: with
  `#[genl_family(...)]` + `#[derive(GenlMessage)]`, downstream
  code now writes one fully-typed round-trip in a single line:

  ```rust
  let reply: GetReply = conn.send_typed(GetRequest { id: 0 }).await?;
  ```

  - `send_typed` is the single-request / single-response shape
    (`NLM_F_REQUEST | NLM_F_ACK`). Missing attributes leave the
    response fields at their `Default` values — matches the
    `#[derive(GenlMessage)]` `from_bytes` semantics.
  - `dump_typed_stream` returns a
    `GenlTypedDumpStream<'_, F, R>` that implements
    [`tokio_stream::Stream<Item = Result<R>>`], mirroring the
    byte-level [`DumpStream`](crate::netlink::dump_stream::DumpStream)
    state machine with a per-frame
    `R::from_bytes(payload[GENL_HDRLEN..])` parse step. Honors
    the `syscall_batch` feature on the recv path.

  The dispatch is gated on a new public **`GenlFamily`** trait
  (the send-time contract, distinct from the construction-time
  `AsyncProtocolInit`) that `#[genl_family(...)]` now emits
  automatically alongside the existing trait impls. Hand-written
  families can implement `GenlFamily` directly when the macro
  doesn't fit — see the trait's docstring for the shape.

  6 new tests cover `parse_first_genl_reply` against synthetic
  frames (typed reply, NLMSG_DONE, pure ACK, ACK-then-reply,
  kernel-error propagation) and the on-wire header layout that
  `build_genl_request` emits.

- **`#[genl_family(name = "...", version = N)]`** attribute macro
  (Plan 154 Phase 4) — rewrites a unit-struct declaration into a
  complete GENL family marker type with all four trait impls
  (`ProtocolState` + `AsyncProtocolInit` + the sealed-trait pair
  `__macro_seal::ProtocolStateSeal` +
  `__macro_seal::AsyncConstructibleSeal`) plus the `family_id`
  field, the `NAME`/`VERSION` const accessors, and the
  `family_id()` getter.

  ```rust
  use nlink::macros::genl_family;

  #[genl_family(name = "my_family", version = 1)]
  pub struct MyFamily;

  // Now usable as any in-tree GENL family marker:
  let conn = Connection::<MyFamily>::new_async().await?;
  ```

  The `AsyncProtocolInit::resolve_async` impl calls a new
  `nlink::macros::__rt::resolve_genl_family(socket, name)`
  helper (matches the body of the existing per-family
  `resolve_wireguard_family` / `resolve_macsec_family` / etc.
  helpers, parametrized on family name — a future cleanup pass
  can rewire those copies through this resolver to eliminate the
  duplication). The sealed-trait impls go through new
  `nlink::netlink::__macro_seal` re-exports — `#[doc(hidden)]`
  paths the macro is the only authorized emitter of; downstream
  code should not name them directly.

  6 new tests: `NAME`/`VERSION` const generation, default
  construction with `family_id = 0`, `Debug` impl format,
  `ProtocolState::PROTOCOL == Protocol::Generic` compile-time
  check, `AsyncConstructible` + `AsyncProtocolInit` trait-bound
  satisfaction (proves a macro-defined family plugs into
  `Connection::<F>::new_async()` exactly like the in-tree
  hand-written ones), and two macro-defined families coexisting.

- **`#[derive(GenlMessage)]`** (Plan 154 Phase 3b) — the big
  derive that turns a struct annotation into a complete
  `GenlMessage` impl. Pairs with the typed-enum codec derives to
  let downstream authors define a GENL message body in ~10 lines:

  ```rust
  use nlink::macros::*;

  #[derive(GenlCommand, Debug, Clone, Copy)]
  #[genl_command(repr = "u8")]
  enum MyCmd { Get = 2 }

  #[derive(GenlAttribute, Debug, Clone, Copy)]
  #[genl_attribute(repr = "u16")]
  enum MyAttr { Id = 1, Name = 2, Description = 3 }

  #[derive(GenlMessage, Debug)]
  #[genl_message(cmd = MyCmd::Get)]
  struct GetRequest {
      #[genl_attr(MyAttr::Id)]      id: u32,
      #[genl_attr(MyAttr::Name)]    name: String,
      #[genl_attr(MyAttr::Description)] description: Option<String>,
  }
  ```

  Supported field types (0.16 Phase 3b):
  - `u8` / `u16` / `u32` / `u64`
  - `String`
  - `Vec<u8>`
  - `Option<T>` for any of the above — omitted on `None`,
    present-when-`Some`, `Some(parsed)` if the kernel returns it.

  Unsupported types (`i32`, nested attribute groups, `IpAddr`,
  `bool`) produce a compile-time error naming the field +
  pointing at the supported-types list. Nested-group support
  via `#[derive(NetlinkAttrs)]` lands in a follow-up phase.

  `from_bytes` semantics: missing attributes produce default
  values (zero for ints, empty for strings/bytes, `None` for
  `Option<T>`). Unknown attribute types are silently skipped —
  forward-compatibility with newer kernels emitting attrs older
  consumers don't understand.

  Generated locals use a `__` prefix (`__payload`, `__ty`,
  `__attr_payload`) so they can't collide with user field names
  — a field named `payload` no longer shadows the function
  parameter.

  Required for the in-tree derive tests: `extern crate self as
  nlink;` was added to `lib.rs` so the macro-generated
  `::nlink::macros::__rt::*` paths resolve uniformly from inside
  the `nlink` crate itself + from any downstream crate.

  7 new runtime tests (in addition to the 4 substrate tests
  shipped in Phase 3a): simple round-trip, `Option<T>` omitted-
  on-None + round-trip-Some, typed-enum composition (CMD comes
  from `MyCmd::Get as u8`), `Vec<u8>` round-trip, default-fill
  on empty payload, unknown-attribute skip.

- **`nlink::macros` module** — substrate for the proc-macro
  derives (Plan 154 Phase 3a). nlink now depends on `nlink-macros`;
  downstream code writes `use nlink::macros::*;` to pull in the
  derives + the supporting traits in one shot, no need to depend
  on `nlink-macros` directly.

  Surface added:
  - `nlink::macros::GenlCommand` / `GenlAttribute` / `GenlEnum` —
    the three typed-enum codec derives re-exported from
    `nlink-macros`.
  - `nlink::macros::GenlMessage` trait — wire-protocol contract
    for a GENL message (CMD constant + `to_bytes` + `from_bytes`).
    Implemented automatically by `#[derive(GenlMessage)]` (Phase 3b);
    can be hand-implemented today against the `__rt` helpers below.
  - `nlink::macros::NetlinkAttrs` trait — same shape for nested
    attribute groups (no CMD, just `write_attrs` / `read_attrs`).
  - `nlink::macros::__rt` — `#[doc(hidden)]` runtime module the
    macros emit calls into: `emit_{u8,u16,u32,u64}_attr`,
    `parse_{u8,u16,u32,u64}_attr`, `emit_str_attr`/`parse_str_attr`,
    `emit_bytes_attr`/`parse_bytes_attr`, `emit_flag_attr`, and
    big-endian variants (`*_be_attr`) for nftables-style
    attributes. Plus an `attr_iter` re-export.

  4 new unit tests cover: a hand-rolled `GenlMessage` impl
  round-tripping through the runtime helpers, truncated-payload
  rejection (`u8` / `u32` / `u64`), NUL-termination + lossy-UTF8
  string parsing, big-endian round-trip.

- **New `nlink-macros` crate** (Plan 154 Phases 1 + 2). Proc-macro
  crate that downstream consumers will use to define new GENL
  families in ~20 lines of declarative code (matching neli's
  `#[neli_enum]` ergonomics on top of nlink's typed
  `Connection<P>` machinery).

  Phases 1 + 2 ship the three typed-enum codec derives. They
  share one expansion path (`codec::expand_codec`); each derive
  differs only in attribute name + accepted repr widths +
  pointer-at-the-right-derive error hints. The remaining derives
  (`GenlMessage`, `NetlinkAttrs`) and the `#[genl_family]`
  attribute macro land in subsequent phases.

  - `#[derive(GenlCommand)]` + `#[genl_command(repr = "u8"|"u16")]`
    — typed GENL command enum.
  - `#[derive(GenlAttribute)]` + `#[genl_attribute(repr = "u8"|"u16")]`
    — typed attribute-kind enum (the u16 attribute-type field
    on each `nlattr`). Caller manages `NLA_F_NESTED` / `NLA_F_NET_BYTEORDER`
    flag bits.
  - `#[derive(GenlEnum)]` + `#[genl_enum(repr = "u8"|"u16"|"u32")]`
    — typed value enum encoded *inside* an attribute payload.
    Used for `DPLL_LOCK_STATUS_*`, `DEVLINK_RATE_TYPE_*`, etc.
    No constraint on 1-based-vs-0-based discriminants (kernel
    UAPI has both — e.g. `DPLL_FEATURE_STATE_DISABLE = 0`).

  All three generate:
  - `impl From<EnumType> for ReprType` (infallible — every
    variant has a known discriminant).
  - `impl TryFrom<ReprType> for EnumType` returning
    `EnumTypeUnknownValue(repr)` on unknown wire values.
  - `EnumTypeUnknownValue` carries the raw bad value + impls
    `Debug + Display + std::error::Error`.

  Variants must have explicit discriminants (e.g. `Get = 1`) —
  kernel ABI requires stable wire values; anonymous
  discriminants are a compile error.

  Test surface: 14 runtime tests across the three derives
  (round-trips / sparse discriminants / u16+u32 reprs / 0-based
  outlier / Display contains enum name + bad value /
  std::error::Error impl) + 5 trybuild compile-fail cases
  (missing attribute, struct/union target, missing
  discriminants, invalid repr value, discriminant overflow) +
  1 compile-pass case. Trybuild baselines committed; re-bless
  via `TRYBUILD=overwrite cargo test -p nlink-macros --test
  trybuild` after stable-Rust message-text drift.

  The crate is standalone in 0.16 — `nlink` does not yet depend
  on it. Wiring lands in Plan 154 Phase 7 once `GenlMessage` +
  `NetlinkAttrs` + `#[genl_family]` ship.

- **Declarative `NftablesConfig`** — mirror of `NetworkConfig`
  for the nftables subsystem. `NftablesConfig::new()` →
  `.table(name, family, |t| ...)` → `.chain(name, |c| ...)` →
  `.rule(chain, |r| ...)` → `.flowtable(name, |f| ...)`, with
  closure-style nesting that matches the visual shape of
  `nft list ruleset`.

  ```ignore
  let cfg = NftablesConfig::new()
      .table("filter", Family::Inet, |t| t
          .persist(true)
          .chain("input", |c| c
              .hook(Hook::Input).priority(Priority::Filter).policy(Policy::Drop))
          .rule("input", |r| r.match_iif("lo").accept())
          .rule_keyed("input", "allow-icmp", |r| r.match_l4proto(1 /* IPPROTO_ICMP */).accept())
          .flowtable("ft", |f| f.device("eth0").hw_offload(true)));
  let diff = cfg.diff(&conn).await?;
  println!("{}", diff.summary());
  diff.apply(&conn).await?;
  ```

  Surface added:
  - `NftablesConfig` builder + `DeclaredTable` / `DeclaredChain` /
    `DeclaredRule` / `DeclaredFlowtable` value types
  - `NftablesDiff` per-object change collections + `summary()` /
    `change_count()` / `is_empty()`
  - `NftablesConfig::diff(&conn)` async method
  - `NftablesDiff::apply(&conn)` async method
  - `RuleHandle(u64)` newtype for kernel-assigned rule handles
  - All re-exported at the crate root

  **0.16 scope caveats** (documented in module rustdoc):
  - Rule identity: name-based via caller-supplied `handle_key`
    (`rule_keyed`); rules without a key are re-applied on every
    diff (harmless churn). Full canonicalization-based diff
    deferred — needs typed `Match` collection refactor that's
    not in tree yet.
  - Apply is **not atomic** (the existing `Transaction` doesn't
    yet cover `del_chain` / `del_rule` / flowtable ops — Plan
    150 §9.4 coordination point). Operations execute in
    dependency-correct order so partial failure recovery is
    converge-on-next-apply. Atomic apply flips on when
    Transaction grows full coverage post-0.16.
  - Sets and maps deferred — separate dimension of nftables
    state warranting its own design pass.

  See Plan 157.

- **Devlink rate + port-function-state**
  (`Connection::<Devlink>::{add_rate, set_rate, del_rate,
  set_port_function_state}`). Cloud + SmartNIC users use these to
  rate-limit SR-IOV VFs at the kernel/firmware boundary (vs in
  the guest's TC stack) and to activate/deactivate VFs without
  tearing them down.

  Public surface:
  - `DevlinkRate` typed builder (bus + device + node_name +
    optional parent_node + tx_share + tx_max + rate_type) — takes
    `nlink::Rate` for the bandwidth fields so the bytes/sec
    convention is enforced by the type system rather than
    documentation.
  - `DevlinkRateType::{Leaf, Node}` for terminal-VF vs
    scheduler-node semantics.
  - `DevlinkPortFunctionState::{Inactive, Active}` for port-function
    activation.
  - `DEVLINK_CMD_RATE_{NEW, SET, DEL, GET}` (74/75/76/77),
    `DEVLINK_CMD_PORT_FUNCTION_SET` (68),
    `DEVLINK_ATTR_RATE_*` + `DEVLINK_ATTR_PORT_FUNCTION_STATE`
    constants — all pinned to kernel UAPI values by unit tests.

  On NICs without rate support (most non-SmartNIC hardware), the
  kernel returns `EOPNOTSUPP` — callers dispatch via
  `Error::is_not_supported()`. See Plan 153 §4.2.

- **XFRM IPsec hardware offload** — `XfrmSaBuilder::offload(ifindex,
  flags)` requests kernel push the SA's crypto / packet path onto a
  NIC (mlx5, hns3, etc.). `XfrmOffloadFlag` bitwise-newtype with
  `IPV6` / `INBOUND` / `PACKET` (last needs kernel 6.0+).
  Wire-encoded as `XFRMA_OFFLOAD_DEV` (= 26) carrying
  `struct xfrm_user_offload` (4 byte ifindex + 1 byte flags + 3 byte
  pad). If the NIC doesn't support the requested shape the kernel
  returns `EOPNOTSUPP` on the add — callers can dispatch via
  `Error::is_not_supported()` and retry without offload. Unit
  tests pin the constants against the kernel UAPI. See Plan 153 §4.1.

- **`syscall_batch` feature** — opt-in `recvmmsg(2)` /
  `sendmmsg(2)` syscall batching. New
  `NetlinkSocket::recv_batch(&mut Vec<Vec<u8>>, max)` and
  `NetlinkSocket::send_batch(&[&[u8]])` (both async, AsyncFd-
  integrated). Batches up to 32 frames per syscall — expected
  2-5× reduction in syscall count + ~1.5× wall-clock speedup on
  dump-heavy workloads (BGP route tables, conntrack tables, nft
  rulesets) per the prior-art measurements in quinn-udp. `MSG_TRUNC`
  on any slot is promoted to `Error::InvalidMessage` instead of
  silent truncation. Per-socket recv-buffer pool is thread-local
  + lazy (~1 MiB on first batched recv per thread). Constants
  exposed: `NL_BATCH_SIZE` (32), `NL_BUF_SIZE` (32 KiB). Behind
  the `syscall_batch` feature flag for one release of soak;
  default-on planned for 0.17. Dump-path wiring (the per-callsite
  `cfg`-gate that swaps `recv_msg` for `recv_batch`) lands when
  the bench infrastructure (Plan 158 §5) is in place to measure
  the speedup. See Plan 158.

- **ENOBUFS resync types** — `ResyncedEvent<T>` sum type
  (`Event(T)` / `Resynced(T)` / `Marker(...)`) + `ResyncMarker`
  (`ResyncStart` / `ResyncEnd`) for consumers that want to handle
  multicast-overflow recovery explicitly. The canonical loop
  pattern (poll events, on `is_no_buffer_space()` invalidate
  local state + redump via a separate dump connection + resume)
  is documented in `docs/recipes/events-with-resync.md`. Pairs
  naturally with the connection pool from Plan 159 for the dump
  connection. The pre-baked Stream wrapper that drives this
  state machine internally (Plan 151 §4.2) is a follow-up — the
  design needs more soak before locking in. Re-exported at the
  crate root: `nlink::{ResyncMarker, ResyncedEvent}`. See
  Plan 151.

- **nftables flowtable support** — `Connection::<Nftables>::add_flowtable`,
  `del_flowtable`, `list_flowtables`. New `Flowtable` builder
  (`Flowtable::new(family, table, name).device(d).priority(p).hw_offload(true).counter(true)`).
  Pairs with the new `Expr::FlowOffload { table }` rule expression
  for the `flow add @<ft>` rule clause that populates the
  flowtable from a rule path. Kernel UAPI constants exposed:
  `NFT_MSG_NEWFLOWTABLE` (= 22), `NFT_MSG_GETFLOWTABLE` (= 23),
  `NFT_MSG_DELFLOWTABLE` (= 24), `NFTA_FLOWTABLE_*` attribute IDs,
  `NF_NETDEV_INGRESS` (= 0), `NFT_FLOWTABLE_HW_OFFLOAD` (= 0x1),
  `NFT_FLOWTABLE_COUNTER` (= 0x2). Unit tests pin the constants
  against the kernel UAPI header. See Plan 150.

- **Streaming dump API** — `Connection::<P>::dump_stream<T>(msg_type)
  -> DumpStream<'_, P, T>` plus four typed wrappers on
  `Connection<Route>`: `stream_links`, `stream_routes`,
  `stream_neighbors`, `stream_addresses`. Yields parsed messages
  one at a time as the kernel returns them, instead of buffering
  the full response into a `Vec<T>` like the eager `get_*`
  counterparts. O(1) memory in number of messages — the cliff fix
  for BGP-scale route tables, container-host link counts,
  busy-gateway conntrack tables.

  Hand-rolled `Stream` impl (no `async-stream` dep) following the
  same pattern as the multicast `EventSubscription`. The
  per-message parse failures keep the stream iterating
  (kernel sometimes ships partially-parseable frames on long
  dumps); `NLMSG_ERROR` and socket-level errors terminate after
  yielding the error. The existing `get_links` docstring gains a
  scale note pointing at `stream_links`. See Plan 149.

- **`ConnectionPool<P>` + `PooledConnection<'p, P>`** — bounded
  mpsc-channel-backed pool for high-fanout consumers. RAII
  `PooledConnection` derefs to `&Connection<P>`, returns the
  connection to the pool on drop (or invalidates it on demand).
  `ConnectionPoolBuilder::<P>::new().size(N).build()` for sync
  protocols; `.build_async()` for GENL families — split via the
  Plan 148 §4.5 sealed `SyncConstructible` / `AsyncConstructible`
  traits. `ConnectionPool::<P>::for_namespace(ns, size)`
  convenience for per-namespace pools (the canonical CNI / multi-
  tenant shape). Two new error variants — `Error::PoolExhausted
  { size, timeout }` and `Error::PoolClosed` — both with
  `is_X()` predicates. Re-exported at the crate root as
  `nlink::{ConnectionPool, ConnectionPoolBuilder, PooledConnection}`.
  Recipe at `docs/recipes/connection-pool.md`. Partial alternative
  to the deferred-to-0.17 NlRouter-style multiplexing (see
  master plan §4 item 6). See Plan 159.

- **`netkit` integration test** — `tests/integration/link.rs`
  gains `test_create_netkit_pair` covering primary + peer
  creation, kind verification, and symmetric pair-removal-on-del.
  Closes the test gap CODE_ANALYSIS.md §4.1 flagged: the
  `NetkitLink` type has shipped since 0.13 but never had a CI
  regression test. Gated `require_root!()` + `require_module!("netkit")`.
  See Plan 148 §4.7.

- **`Connection::<P>::wait_link_up(iface, timeout)`** — polls for
  `IFF_UP` with exponential backoff (10ms → 100ms cap) until
  observed or the deadline elapses. `Err(Timeout)` on deadline,
  `Err(InterfaceNotFound)` if the interface is removed during the
  wait. Namespace-correct via the existing `resolve_interface`
  pipeline. See Plan 148 §4.1.

- **Sealed GENL constructor traits** — `Connection::<P>::new()`
  is now bounded `where P: SyncConstructible`, and the GENL
  protocol markers (`Wireguard`, `Macsec`, `Mptcp`, `Ethtool`,
  `Nl80211`, `Devlink`) are excluded from that bound. This turns
  the silent runtime bug
  (`Connection::<Wireguard>::new()` returning a connection with
  `family_id = 0` that fails confusingly on first use) into a
  **compile error** that points the user at `new_async().await`.
  GENL constructors are bounded `where P: AsyncConstructible`
  (added to namespace.rs's `connection_for_async` family).
  Both marker traits live in `nlink::netlink::protocol::construction`
  and are sealed via the same `private::Sealed` supertrait as
  `ProtocolState`. **Breaking-shaped but bug-fix in intent**:
  any code that compiled with `Connection::<Wireguard>::new()`
  was already broken at runtime; this surface change just moves
  the failure to compile time. See Plan 148 §4.5.

- **`docs/recipes/error-handling-patterns.md`** — new cookbook
  recipe covering `is_*()` predicate dispatch, bounded retry on
  EAGAIN/ENOBUFS, idempotent `NLM_F_EXCL` create/delete, XFRM
  SA/SP `update_sa` vs delete-then-add, namespace cleanup on
  error paths, cross-fork pitfalls, and cancellation safety in
  async. Linked from `docs/recipes/README.md`. See Plan 148 §4.6.

- **Crate-root re-exports** for route / address / rule builders and
  the extension traits. Previously reachable only via deep
  `nlink::netlink::route::Ipv4Route`-style paths; now also surfaced
  as `nlink::Ipv4Route`, `nlink::Ipv6Route`, `nlink::NextHop`,
  `nlink::RouteMetrics`, `nlink::RouteConfig`, `nlink::Ipv4Address`,
  `nlink::Ipv6Address`, `nlink::AddressConfig`, `nlink::RuleBuilder`,
  `nlink::LinkConfig`, `nlink::NeighborConfig`. Pure additive.
  See Plan 148 §4.3.

- **`Connection::<Route>::get_link_stats(iface)`** convenience
  wrapper that returns the kernel-reported per-link `LinkStats`
  for a named or indexed interface. `Err(InterfaceNotFound)` if no
  match; `Err(InvalidMessage)` if the kernel response didn't
  include a stats attribute (rare). See Plan 148 §4.2.

- **`NFT_TABLE_F_PERSIST` (kernel 6.9+) and related table-flag
  constants** + `Connection::<Nftables>::add_table_with_flags(name,
  family, flags)` connection method. Lets users create tables that
  survive `nft flush ruleset` operations issued against the same
  family. Also exposes `NFT_TABLE_F_DORMANT` and
  `NFT_TABLE_F_OWNER` (the latter from kernel 5.13+). Existing
  `add_table(name, family)` is unchanged (defaults to flags = 0).
  Unit tests pin the constants against the kernel UAPI header
  values. See Plan 148 §4.8.

- **Namespace-safety doc story** — added a "Namespace safety —
  `_by_index` vs `_by_name`" section to `lib.rs`'s rustdoc landing
  page and to `CLAUDE.md` ("Namespace-safe APIs" subsection of
  "Connections & namespaces"). Documents the existing `_by_index`
  design as a deliberate distinguishing-feature choice vs neli +
  vishvananda/netlink (which both leave namespace handling to the
  caller — the documented Cilium-issue-#40280 footgun). Also added
  a "Connection diagnostics + sockopts" subsection covering the new
  `enable_strict_checking` + `set_ext_ack` methods. See Plan 155 §4.4.

- **`Connection::<P>::enable_strict_checking(on: bool)`** — toggles
  the `NETLINK_GET_STRICT_CHK` sockopt (kernel 5.0+). When enabled,
  the kernel validates dump request filters strictly and returns an
  error if they reference unknown attributes — useful for catching
  client/kernel-version mismatches early. Off by default. Silently
  a no-op on pre-5.0 kernels (`ENOPROTOOPT` → `Ok(())`). See
  Plan 155 §4.2.

- **`Connection::<P>::set_ext_ack(on: bool)`** — toggles the
  `NETLINK_EXT_ACK` sockopt (kernel 4.12+). Enabled by default
  during socket construction; exposed for parity with neli's API
  and for callers wanting to explicitly suppress the trailing
  TLVs in error responses. Silently a no-op on pre-4.12 kernels.
  See Plan 155 §4.3.

- **Extended-ack TLV parsing from kernel error responses**. The
  kernel populates `NLMSGERR_ATTR_MSG` (human-readable error
  string) and `NLMSGERR_ATTR_OFFS` (offset into the offending
  request) when `NETLINK_EXT_ACK` is enabled (on by default in
  nlink). Previously these TLVs sat unparsed at the bottom of
  every error response and the user saw `errno = 22` with no
  context. Now `Error::Kernel` / `Error::KernelWithContext`
  carry `ext_ack: Option<String>` and `ext_ack_offset:
  Option<u32>` fields, and the `Display` output stitches the
  ext-ack message in when present. Example output:
  `"add_link(veth0): Invalid argument (errno 22): attribute
  IFLA_MTU rejected: value 0 out of range (at request offset 24)"`.
  See Plan 155 §4.1.

  New surface:
  - `Error::Kernel { errno, message, ext_ack, ext_ack_offset }`
  - `Error::KernelWithContext { operation, errno, message, ext_ack, ext_ack_offset }`
  - Both variants now `#[non_exhaustive]` so future field
    additions are non-breaking
  - `Error::from_errno_ext_ack(errno, ext_ack, ext_ack_offset)`
    constructor (plus context variant)
  - `nlink::netlink::message::ParsedExtAck { message, offset }`
  - `nlink::netlink::message::NlMsgError::parsed_ext_ack(&self, payload)
    -> ParsedExtAck`
  - `nlink::netlink::message::NlMsgError::into_error(&self, payload)
    -> Error` — convenience for the "early return on non-ACK" pattern
  - `nlink::netlink::message::nlmsgerr_attr::{MSG, OFFS, COOKIE,
    POLICY, MISS_TYPE, MISS_NEST}` constants

- **`Error::NamespaceRestoreFailed { source }`** variant +
  `Error::is_namespace_restore_failed()` predicate. Surfaces the
  previously-swallowed `setns()` restore failure in
  `NetlinkSocket::new_in_namespace` — the socket was created in the
  target netns but the calling thread couldn't be restored. Prior
  behavior (≤ 0.15.1) was to log to stderr and return the socket
  anyway, leaving the thread silently stuck in the target ns. This
  was a real footgun in tokio multi-thread runtimes where another
  task scheduled on the corrupted thread would read
  `/sys/class/net/` from the wrong namespace. See Plan 147 §4.1.
  Variant is additive under `#[non_exhaustive]`.

- **`Rule::match_saddr_v6` / `match_daddr_v6` / `match_saddr_v6_not`
  / `match_daddr_v6_not`** on the nftables rule builder, alongside
  the existing v4 helpers. Same `(addr, prefix)` signature; `/128`
  uses the exact-match fast-path (no bitwise mask), shorter
  prefixes emit `Payload + Bitwise + Cmp` with the masked
  address. Unblocks single-stack IPv6 nftables rule construction.
  New helper `prefix_to_mask_v6` mirrors the existing
  `prefix_to_mask_v4`. Inline unit tests cover the exact-match
  path, prefix path, destination offset (24 vs 8), `_not`
  variants, and the prefix-to-mask byte-boundary case.

### Fixed

- **`EthtoolBitset::write_to` no longer clones each bitset name on
  encode** (`genl/ethtool/bitset.rs:283`). Switched
  `sort_by_key(|(_, name)| (*name).clone())` to
  `sort_unstable_by_key(|(_, name)| name.as_str())` — one fewer
  `String` allocation per name per `set_features` call. The
  earlier clippy-suggested form had picked a key shape that
  allocated; the borrow form is strictly cheaper. Stable-vs-unstable
  ordering is immaterial here (names are unique within a bitset).

- **`NamespaceGuard::drop` now emits `tracing::error!` instead of
  `eprintln!`** on restore failure (`netlink/namespace.rs:442`).
  Same class of bug as the `socket.rs` Phase 1 fix in this release
  — unstructured stderr output didn't surface in subscribers,
  hiding the "thread stuck in foreign netns" hazard. Drop can't
  return errors, so the structured event is the right escape.
  Callers that need explicit detection should restore the
  namespace via an explicit method call before the guard drops.

- **`util/parse.rs` octal parser uses byte indexing instead of
  `chars().nth(1).unwrap()`** (line 65). The previous form walked
  the UTF-8 iterator just to peek at byte 1, which is guaranteed
  to be ASCII by the surrounding `len() > 1` + `starts_with('0')`
  guards. Cosmetic; no behavior change.

- **SAFETY comment added on `libc::geteuid()` in `lab::is_root`**
  (`lab/mod.rs:297`). `geteuid` is POSIX-mandated infallible
  and has no preconditions — documented for the reader.

- **`route.rs` `write_delete_with_interfaces` carries a kernel-source
  citation explaining why `RTA_METRICS` is deliberately omitted
  on delete** (Plan 147 §4.2). `fib_table_delete` (IPv4) and
  `ip6_route_del` (IPv6) match on the route's discriminating-key
  fields; metrics live in the shared `fib_info` / `fib6_info` and
  are never part of the match key. The asymmetry with `write_add`
  (which DOES write metrics) is intentional. Documentation-only;
  no behavior change.

- **`NetworkConfig::diff` now detects same-kind / different-params
  qdisc changes** (`config/diff.rs:434`). Previously, changing an
  HTB's `default_class` from `0x10` to `0x20` (or any other
  parameter on any qdisc kind) produced an empty diff — the diff
  loop only compared the `kind` string. Now `diff_qdiscs` renders
  the declared `DeclaredQdiscType` through `QdiscConfig::write_options`
  and byte-compares against the kernel's `TCA_OPTIONS` blob.
  Differences (including known false positives from kernel-side
  default attributes) push to `qdiscs_to_replace` and trigger
  idempotent re-apply via the normal `apply` path. See Plan 147 §4.4.

- **`NetlinkSocket::new_in_namespace` no longer silently corrupts
  thread state on `setns()` restore failure** (`socket.rs:138`).
  Previously the function used `eprintln!` to warn and returned
  the (successful) socket regardless. Now it returns
  `Error::NamespaceRestoreFailed`, drops the socket, and emits a
  structured `tracing::error!` event. The calling thread is still
  in the target netns when the error returns — the documented
  recovery is to abort the affected task or pin subsequent work to
  a different thread. See Plan 147 §4.1.

- **`Neighbor::write_delete` now propagates `ndm_flags`** so the
  kernel can match flag-keyed entries on delete. The user-visible
  symptom was deleting a proxy NDP entry through the high-level
  API returning `ENOENT`: the kernel's pneigh lookup keys on
  `(family, ifindex, NDA_DST, ndm_flags)`, and the flags field
  was being dropped. The fix also lines `write_delete` up with
  `NTF_ROUTER` / `NTF_EXT_LEARNED`, though in practice the
  kernel's unicast delete only matches on
  `(family, ifindex, NDA_DST)`, so only the proxy case was
  user-broken. `ndm_state` deliberately stays unset on delete;
  the kernel doesn't match on state. The regression test is
  `test_delete_proxy_ndp_entry_round_trip` in
  `tests/integration/neigh.rs` (requires the `lab` feature);
  guards for the unicast and `NTF_EXT_LEARNED` paths land
  alongside it. `nlink::netlink::neigh::ntf` is now re-exported
  so callers decoding `NeighborMessage::flags()` don't have to
  redefine kernel constants.

### Changed — semver lockdown (Plan 163, pre-cut)

- **11 new-in-0.16 pub structs gain `#[non_exhaustive]`**:
  `RuleInfo`, `NftablesDiff`, `ReconcileOptions`, `ReconcileReport`,
  `DpllDeviceReply`, `DpllPinReply`, `NetShaperReply`,
  `NetShaperCapsReply`, `ConnectionPool`, `ConnectionPoolBuilder`,
  `PooledConnection`, `DumpStream`, `ResyncStream`,
  `GenlTypedDumpStream`. Re-applying the attribute after publish
  would itself be breaking, so it landed in the pre-cut audit
  window. (`ResyncStream` + `GenlTypedDumpStream` caught by a
  post-batch `cargo public-api diff` sweep — see Plan 163.)

  **Caller-visible impact**: `ReconcileOptions` can no longer
  be constructed with a struct literal. Use the builder pattern:
  ```rust
  let opts = ReconcileOptions::default()
      .max_retries(5)
      .backoff(Duration::from_millis(50));
  ```
  Field access and `Default::default()` continue to work
  unchanged. All other types in the list are constructed by
  nlink internals, not user code.

### Changed — Plan 162 `PooledConnection::invalidate` consume-self

- **`PooledConnection::invalidate` now takes `self` by value
  (consume-self) instead of `&mut self`** (`pool/pooled.rs`).
  Closes a panic-on-misuse footgun: previously,
  `p.invalidate(); &*p` would panic at runtime because
  `invalidate` left `conn: None` and `Deref` unwrapped it. The
  new shape makes the bug a compile error
  (E0382: use of moved value). A `compile_fail` rustdoc test
  on `invalidate()` guards the contract against future
  regressions.

  **Source-compatible** for the "invalidate then drop" use case
  (`p.invalidate();` still works — the guard is gone after the
  call either way). Only breaks the bug-shape.

### Added — diagnostics layer gaps closed (Plan 169)

The Plan 168 orphan-example closeout (above) surfaced
*evidence* — each phantom symbol in a broken example was a
record of "an author wanted this and didn't find it". Most
were rename drift (already-fixed bugs); four were real
lib-side coverage gaps where the lower-level type carried the
data but the higher-level diagnostics wrapper dropped it on
the way through. Plan 169 closes those gaps:

- **`RouteInfo` gains `source: Option<IpAddr>` (RTA_PREFSRC) +
  `dev_name: Option<String>` (resolved output-interface name)**
  and is now `#[non_exhaustive]`. The diagnostics scan already
  fetched both data points internally; they're now stored on
  RouteInfo for direct access (no longer just a function-return
  side channel). `#[non_exhaustive]` is added in the same
  commit so future RTA_* propagation doesn't break callers.
- **`InterfaceDiag` gains `is_up() -> bool`, `has_carrier() -> bool`,
  and `is_operational() -> bool`** convenience predicates,
  mirroring the same-named methods on the lower-level
  `LinkMessage`. Callers no longer need to bit-test `flags`
  against `IFF_UP` / `IFF_RUNNING` manually or remember to
  compare `state` against `OperState::Up`. `is_operational()`
  combines both checks ("ready to carry traffic right now?").
- **`Srv6LocalRoute::table() -> Option<u32>`** convenience
  getter. The kernel UAPI puts the routing-table attribute
  inside the action's nested encap block, so the lib's parser
  embeds it in the action variant (`EndT { table }`,
  `EndDT4 { table }`, etc.). Asking "what table is this SID
  in?" used to require enumerating all four table-carrying
  variants; the new getter encapsulates that match.

Four new unit tests cover the new methods (3 for InterfaceDiag,
1 for Srv6LocalRoute). 970 lib tests (was 966).

### Examples — Plan 160 orphan catalog closed (Plan 168)

- **All 9 orphan example files catalogued by Plan 160 closed.**
  Five fixed in place + registered: `bridge/vlan.rs`,
  `bridge/fdb.rs`, `route/mpls.rs`, `route/nexthop.rs`,
  `route/srv6.rs` (each was either a rename — `.link_kind()` →
  `.kind()`, `route.gateway` → `route.via`, `nh.is_blackhole()` →
  `nh.blackhole`, `Srv6LocalRoute::table` → `.protocol`,
  `FdbEntry::is_local()` → `is_self`/`is_master`/`is_extern_learn` —
  or a format-string fix where `r#"..."#` literals had unescaped
  `{}` placeholders the outer `println!` tried to consume).
- **Three diagnostics demos deleted, one comprehensive replacement
  written**: `bottleneck.rs` + `connectivity.rs` + `scan.rs` were
  `println!`-of-doc-string walkthroughs against fields that never
  existed. Replaced by `diagnostics/health_check.rs` — a single
  end-to-end demo that runs `Diagnostics::scan()` + prints the
  full report + calls `find_bottleneck()`. Uses canonical field
  names verified against `diagnostics.rs`.
- **`config/declarative.rs` rewritten** to mirror
  `examples/nftables/declarative.rs`. The old file imported a
  struct-based API (`LinkConfig`, `AddressConfig`, `RouteConfig`,
  `QdiscConfig`) that never existed; the actual `NetworkConfig`
  API is closure-based
  (`.link(name, |b| b.dummy().up()).address(...).route(...)`).
  New file demos diff → apply → re-diff (idempotent) → mutate →
  re-apply → teardown via `apply_with_options(purge=true)`.
- **`scripts/audit-example-registration.allowlist` deleted** —
  empty after Phase 3 (script gracefully no-ops when absent per
  Plan 160 §"Acceptance criteria"). The
  `audit-example-registration` CI gate now enforces zero
  orphans from a clean slate; any future bit-rot fails CI loudly
  with a copy-paste fix block.

### Performance — Plan 164 NftablesConfig::diff hoist

- **`NftablesConfig::diff` no longer issues `list_chains()` +
  `list_flowtables()` once per declared table.** The two dump
  calls are hoisted to a single call each at the top of
  `diff()`, then indexed by `(Family, table_name)` into
  `HashMap<_, Vec<&_>>` for O(1) per-table lookup. Wire
  round-trips drop from O(N²+N·R) to O(N+R) for N declared
  tables and R kernel rules. No public-API change.

## [0.15.1] - 2026-04-26

Patch release. Fixes a regression that prevented `cargo test
--workspace` from compiling with default features, fixes a
shipped bug where `Connection::<Ethtool>::set_features` was a
silent no-op, and lands quality wins from the 0.16 strategic
analysis that fit a patch (no public-API changes;
`cargo-semver-checks` + `cargo public-api diff` verify a clean
diff against 0.15.0).

### Fixed

- **`examples/xfrm/ipsec_monitor.rs` — `[[example]]` entry now
  declares `required-features = ["lab"]`** (Plan 143 Phase 0).
  The example was promoted to a full lifecycle runner using
  `nlink::lab::with_namespace` during the 0.15.0 post-cut tail
  (commit `5634f1a`), but the Cargo.toml gating wasn't added,
  so `cargo test --workspace` (default features) failed to
  compile the example. Pure metadata fix; library code is
  unchanged.
- **`Connection::<Ethtool>::set_features` now actually sends the
  request** (was a silent no-op since the `Features` API
  shipped). The closure that should encode the `EthtoolBitset`
  into the `ETHTOOL_A_FEATURES_WANTED` attribute had `let _ =
  wanted; let _ = builder;` placeholder code with a `// TODO:
  Properly encode bitset` marker. Implemented the bit-by-bit
  encoder as `EthtoolBitset::write_to(&mut MessageBuilder,
  attr_type)` (matches the kernel ethtool-netlink format the
  parser already understands) and wired it into
  `apply_features`. Roundtrip unit test
  (`bitset::tests::write_to_roundtrips_through_parse`) covers
  encode → parse symmetry; live-kernel validation requires
  ethtool-capable hardware (skip-if-no-hw).
- The `parse_bits` parser now also accepts name-only entries
  (without an `Index` attribute), needed because SET requests
  send only `Name` while GET responses send both. Behavior
  for kernel GET responses is unchanged.
- **`cargo doc -p nlink --no-deps` now emits zero warnings**
  (Plan 145). Seven unresolved intra-doc cross-references
  fixed:
  - `DEFAULT_ASSUMED_LINK_RATE_BPS` typo in `impair.rs`
    module docs (correct name: `DEFAULT_ASSUMED_LINK_RATE`).
  - Two `[\`ReconcileOptions::with_fallback_to_apply(true)\`]`
    occurrences in `impair.rs` and `ratelimit.rs` —
    rustdoc doesn't accept function-call argument lists in
    link paths; the `(true)` now lives outside the link as
    inline code.
  - Four bare `[\`TcHandle\`]` references in `messages/tc.rs`
    — `TcHandle` is re-exported at the crate root but not in
    scope at the use site; now use `[\`TcHandle\`](crate::TcHandle)`
    so the link resolves while keeping the rendered text.
- **CHANGELOG `## [0.15.0]` preamble typo** corrected: said
  "41 typed configs in `nlink::ParseParams` (18 qdisc + 4
  class + 9 filter + 14 action)" — the breakdown sums to 45
  (which is correct as of the 0.15.0 pre-publish class-side
  surgery in commit `c43de7f`). Now reads "45".

### Changed — CI safety nets (Plan 144)

- **`.github/workflows/rust.yml` rewritten as 7 named jobs**
  (was: a single `cargo build && cargo test` step):
  `build-and-test-default-features`, `build-and-test-all-features`,
  `clippy`, `doc`, `semver-checks`, `audit-examples`, `machete`.
  Each gate has a clear "what failed" signal in the GitHub UI.
- **`build-and-test-default-features`** runs `cargo test
  --workspace` with no features, catching the
  `xfrm_ipsec_monitor`-class regression (a feature-gated
  example that imports a feature-gated module without
  declaring `required-features`).
- **`doc` job** runs `cargo doc -p nlink --no-deps --all-features`
  with `RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D
  rustdoc::redundant_explicit_links"`. Matches the docs.rs
  build configuration.
- **`semver-checks` job** uses
  `obi1kenobi/cargo-semver-checks-action@v2` against the
  latest published version on crates.io. Catches accidental
  semver violations (per [Predrag Gruevski's research](https://predr.ag/blog/semver-in-rust-tooling-breakage-and-edge-cases/),
  ~1 in 6 crates accidentally violate semver). Would have
  caught the `add_class_config` rename / stringly-typed
  holdover that pre-publish surgery surfaced in 0.15.0.
- **`public-api-diff` job** runs `cargo public-api -p nlink
  diff <latest-tag>..HEAD --deny=all` on every PR. Patch
  releases require an empty diff; minor releases drop
  `--deny=all` and use the diff informationally. Verified
  empty between `0.15.0` tag and the 0.15.1 candidate.
- **`msrv` job** runs `cargo-msrv verify --path crates/nlink`
  to enforce the declared `rust-version = "1.95"` in
  `[workspace.package]`. Catches accidental usage of features
  stabilized after the floor.
- **Every Rust-using job in `rust.yml` now pins
  `dtolnay/rust-toolchain@stable` + `Swatinem/rust-cache@v2`.**
  The previous workflow had no toolchain step, so each job
  silently used whatever Rust ubuntu-latest shipped
  pre-installed (typically 2-4 months behind current stable).
  That produced spurious clippy warnings against new lints,
  rustdoc warnings against new diagnostics, and tool-install
  failures when `cargo install --locked` wanted a newer Rust
  than the runner had. With the explicit toolchain step,
  every job uses current stable; the rust-cache action keeps
  CI fast across runs.
- **`integration-tests.yml` container bumped from
  `rust:1.85-bookworm` to `rust:bookworm`** (latest stable
  Debian + Rust). The 1.85 pin lagged current stable by ~10
  versions, producing the same kind of warning churn. The
  floating `bookworm` tag tracks current stable; in exchange
  for the very occasional CI flakiness when a new Rust release
  lands, we catch new diagnostics early.
- **`audit-examples` job** runs `scripts/audit-example-features.sh`,
  a new bash diagnostic that maps every `[[example]]` entry
  to its `required-features` declaration, cross-references
  against feature-gated module imports (`nlink::lab`,
  `nlink::sockdiag`, `nlink::tuntap`, `nlink::output`,
  `nlink::namespace_watcher`), and exits non-zero on any
  mismatch. Belt-and-suspenders alongside the
  `build-and-test-default-features` enforcement layer.
- **`machete` job** now runs without `|| true` suppression
  (see "Removed" below). Same change applied to
  `.github/workflows/integration-tests.yml`.

### Removed — pre-existing dead deps in `bins/{ss,bridge}` (Plan 144 Phase 4 Option A)

`cargo machete` previously flagged five unused dependencies
that the CI workflow suppressed with `|| true`. All five are
deleted; both bins still build cleanly. (Both bins are
`publish = false` POCs; this change has no effect on the
published `nlink` crate.)

- **`bins/ss/Cargo.toml`** — removed `libc` (no `use libc`
  anywhere in `src/`) and `atty` (no caller). Verified by
  `cargo build -p nlink-ss`.
- **`bins/bridge/Cargo.toml`** — removed `tokio-stream`,
  `tracing`, and `tracing-subscriber` (no callers; `bridge`
  uses `clap` + `serde_json` + `atty` only). Verified by
  `cargo build -p nlink-bridge`.

### Added — MSRV declaration

- `[workspace.package]` now declares `rust-version = "1.95"`.
  Tracks current stable: the project is happy to require
  contributors and downstream consumers stay on a recent
  toolchain in exchange for using modern language features
  (`if let && Y` chains, etc.) without contortion. Every
  package crate (`crates/nlink/Cargo.toml` + 11 bins) inherits
  via `rust-version.workspace = true` so `cargo-msrv` can
  verify it without resolving workspace inheritance. Cadence
  policy: advance in lockstep with stable; called out in
  CHANGELOG when it bumps.

### Documentation

- New `scripts/audit-example-features.sh` (~110 LOC bash) —
  the diagnostic powering the `audit-examples` CI job. Can
  be run manually before opening a PR. Tested to catch the
  exact regression class that produced the `xfrm_ipsec_monitor`
  bug.
- New `crates/nlink/public-api.txt` placeholder reserves the
  path for the eventual full-snapshot convention. The full
  output of `cargo public-api -p nlink -sss` is ~14k lines,
  too noisy as a checked-in baseline; 0.16 will decide whether
  to commit the full snapshot, a curated stable-surface
  subset (per `STRATEGIC_ANALYSIS.md` §4.1), or stay with the
  CI diff-vs-tag mechanism alone. The placeholder file
  documents the trade-off.
- Plan documents 143/144/145 (deleted post-cut per the
  project's plan-document convention) described the design and
  acceptance criteria for the 0.15.1 surgery. Substance lives
  in this CHANGELOG section.

### Out of scope (genuinely 0.16+)

Per `STRATEGIC_ANALYSIS.md`, the following require new public
API surface, semver-major scope, or substantial design work
that doesn't fit a patch release:

- **Streaming dump API** (`get_routes()` etc. iterator form).
  Adds new public methods.
- **Observability feature** (structured spans + optional
  `metrics` integration). Adds a new feature flag.
- **Fuzzing infrastructure** (`fuzz/` tree + corpora).
  Substantial new infrastructure with ongoing maintenance
  commitment.
- **All new kernel features** (`netkit` link kind, `tcx` BPF
  attach hooks, nftables flowtable, XFRM IPsec offload,
  devlink rate, nl80211 MLO). Each adds new public types.
- **All new library features** (`MultiConnection`,
  `NetworkStatPoller`, `TcDebugger`, `#[derive(Builder)]`).
  New public surface.
- **YNL codegen bet** (proof-of-concept and possibly full
  rollout). Multi-week project.
- **README rewrite** ("lead with the moat"). Cosmetic but
  worth the dedicated cycle.
- **1.0 stability tier declaration**. Needs API freeze
  decision and `nlink_unstable` cfg reservation.

## [0.15.0] - 2026-04-26

The typed-API completion arc — what would have been 0.14.0 +
0.15.0 in the original release plan merged into one ship. 45
typed configs in `nlink::ParseParams` (18 qdisc + 4 class + 9
filter + 14 action). Legacy `tc::builders::*` and `tc::options/*` modules
deleted. Lib tests grew from 593 (post-0.13.0) to 749 (+156).
Full upgrade walkthrough:
[`docs/migration_guide/0.14.0-to-0.15.0.md`](docs/migration_guide/0.14.0-to-0.15.0.md).
Highlights below — see the per-PR sections that follow for the
detail.

### Changed — class side closes the typed-API completion arc (pre-publish surgery)

A pre-publish deep audit caught that the **class side** of the TC
API still carried legacy holdovers Plan 142 Phase 4 had missed:

- `Connection::add_class("eth0", parent, classid, "htb",
  &["rate", "100mbit"])` (and `change_class` / `replace_class`,
  with `*_by_index` variants) — six stringly-typed mutation
  methods that bypassed the typed-config dispatch.
- `add_class_options(builder, kind, &params)` — a per-kind
  dispatcher whose non-HTB arm read `_ => { /* ignore */ }` —
  the exact silent-skipping anti-pattern the typed `parse_params`
  contract exists to kill. HFSC / DRR / QFQ class params went
  straight into the void.
- `bins/tc class add|change|replace` was still routed through the
  stringly-typed methods, so the bin's class command inherited
  the silent-skip behaviour.

Surgery (zero downstream callers in the workspace before this
commit, so it's a clean break inside the 0.15.0 release window):

- **Added `parse_params` to all 4 class configs**:
  `HtbClassConfig`, `HfscClassConfig`, `DrrClassConfig`,
  `QfqClassConfig`. Strict-rejection contract identical to the
  18 qdisc + 9 filter + 14 action parsers (kind-prefixed errors,
  unknown-token rejection, alias support). 16 new unit tests.
- **Wired the 4 class configs into the sealed `ParseParams`
  trait** (`crates/nlink/src/netlink/parse_params.rs`). The
  total typed config count grows from 41 to **45** (18 qdisc +
  4 class + 9 filter + 14 action).
- **Deleted the 6 stringly-typed class methods** from
  `Connection<Route>` and the `add_class_options` /
  `add_htb_class_options` helpers (~250 LOC).
- **Renamed `add_class_config` / `change_class_config` /
  `replace_class_config`** (and `*_by_index` variants) to drop
  the `_config` suffix. The typed surface is now uniform:
  `add_qdisc<C: QdiscConfig>` / `add_class<C: ClassConfig>` /
  `add_filter<C: FilterConfig>` / `add_action<A: ActionConfig>`.
- **Migrated `bins/tc/src/commands/class.rs` to the typed
  `dispatch!` macro pattern** mirroring `qdisc.rs` — unknown
  class kinds error with a recognised-kinds list (`htb, hfsc,
  drr, qfq`) instead of silently dropping params on the floor.

Net source-tree effect: zero stringly-typed `Connection`
mutation methods remain. Every TC mutation goes through a typed
config that implements `ParseParams`. Lib tests grew 749 → 765
(+16 net, all green). `cargo clippy --workspace --all-targets
--all-features -- --deny warnings` clean. `cargo machete` clean
(only the same two pre-existing nlink-ss / nlink-bridge entries
unrelated to this work).

### Added — recipes + CI tail items (post-cut, pre-publish)

The remaining sudo-gated tail items from Plan 142's open list
all landed before the publish:

- **`docs/recipes/xfrm-ipsec-tunnel.md`** — two-namespace IPsec
  tunnel walkthrough using the typed `XfrmSaBuilder` /
  `XfrmSpBuilder` from Plan 141 PRs A+B. Covers SA install,
  SP setup, key rotation via `update_sa`, and NAT-T encap.
  Plan 135 PR B closes at 7/7.
- **`docs/recipes/cgroup-classification.md`** — per-cgroup
  HTB shaping via `net_cls` cgroup v1 + the typed
  `CgroupFilter`. Plus an ematch-combination snippet for
  L4-aware steering using `BasicFilter`.
- **`examples/xfrm/ipsec_monitor.rs --apply`** — promoted from
  dump-only to full lifecycle (install → verify → rotate → tear
  down) inside a `LabNamespace`. Mirrors the conntrack `--apply`
  runner shape. Sudo-gated for end-to-end validation.
- **`crates/nlink/tests/integration/conntrack.rs`** — Plan 137
  integration tests un-park: 6 `#[tokio::test]` functions
  covering inject/query, update-in-place, del-by-id, flush, and
  multicast NEW + DESTROY event subscription. Each test gates
  with `nlink::require_root!()` + `nlink::require_module!(...)`
  so the suite skips cleanly on non-root runs and bit-rots no
  more.
- **`.github/workflows/integration-tests.yml`** — Plan 140 tail:
  privileged GHA runner runs the integration tests on every
  push to master (and PR). `--test-threads=1` mandatory for
  namespace-naming reasons; `modprobe nf_conntrack` best-effort
  with autoload fallback. Same job runs lib tests + clippy +
  cargo machete to keep one CI gate authoritative.

Lib code: tiny additive change — `Xfrm` protocol state now
derives `Default` so `LabNamespace::connection_for::<Xfrm>()`
works (consistent with `Route` / `Netfilter` / `Generic` etc.).
The hand-rolled `Connection<Xfrm>::new()` was removed — the
generic `Connection::<P>::new()` covers it now that `Xfrm:
Default`.

Pre-publish source-tree cleanup: the long-standing
`#[deprecated] pub mod nlink::netlink::link::bond_mode { ... }`
constants module (replaced by the `BondMode` enum since 0.13.0
and unreferenced anywhere in the workspace) was deleted. With
this, the source tree carries **zero `#[deprecated]` attributes
and zero `#[allow(deprecated)]` overrides**, satisfying Plan 142
§6's "zero deprecations in source" gate.

Active plans table cleared: every row from `128b-roadmap-overview.md`
that was open at cut-pending time has shipped. 0.16.0 opens
fresh (other-bins typed-units rollout per the Backlog).

### Removed — legacy `tc::builders` + `tc::options` modules (Plan 139 PR C, **0.15.0 release-cut**)

This is the **legacy-deletion milestone** that closes Plan 142
Phase 4 and the 0.15.0 typed-API completion arc. The
`#[deprecated]` markers introduced in 0.14.0 have been redeemed:
the modules they pointed at are gone.

**Deleted entirely** (~3500 LOC):

- `nlink::tc::builders::class` — replaced by
  `Connection<Route>::add_class(...)` taking
  `HtbClassConfig` / `HfscClassConfig` / `DrrClassConfig` /
  `QfqClassConfig`. (The `add_class_config` name briefly used
  during the migration was renamed back to `add_class` once the
  legacy stringly-typed `add_class("htb", &["rate", ...])` was
  deleted, restoring uniformity with `add_qdisc` / `add_filter` /
  `add_action`.)
- `nlink::tc::builders::qdisc` — replaced by
  `Connection<Route>::add_qdisc_full(...)` taking the typed
  qdisc config (18 kinds: `HtbQdiscConfig`, `NetemConfig`,
  `CakeConfig`, ...).
- `nlink::tc::builders::filter` — replaced by
  `Connection<Route>::add_filter_full(...)` taking the typed
  filter config (9 kinds: `FlowerFilter`, `U32Filter`, ...).
- `nlink::tc::builders::action` — replaced by
  `Connection<Route>::{add,del,get,dump}_action(...)` shipped
  in Plan 139 PR A, plus the typed action configs (14 kinds).
- `nlink::tc::options::{cake,codel,fq_codel,fq,htb,netem,prio,sfq,tbf}` —
  replaced by their typed `*Config::parse_params(&[&str])`
  methods (38 typed `parse_params` methods total in the
  `nlink::ParseParams` trait impl list).
- `nlink::tc::handle` (incl. `parse_handle` / `format_handle` /
  `Handle`) — internal helper of the deprecated tree, was only
  used by `tc::options::htb`. The unrelated
  `nlink::TcHandle` typed handle (with `from_str` and `Display`)
  is the canonical replacement.
- The `tc` Cargo feature flag — its only purpose was to gate
  the deleted modules. `nlink::TcHandle` and the typed configs
  live in always-built modules.

**Migration table for downstream consumers:**

| Removed call | Typed replacement |
|---|---|
| `tc::builders::class::add(conn, dev, parent, classid, "htb", &["rate", "100mbit"])` | `conn.add_class(dev, parent, classid, HtbClassConfig::parse_params(&["rate", "100mbit"])?)` |
| `tc::builders::qdisc::add(conn, dev, parent, handle, "htb", &params)` | `conn.add_qdisc_full(dev, parent, handle, HtbQdiscConfig::parse_params(&params)?)` |
| `tc::builders::filter::add(conn, dev, parent, "ip", prio, "flower", &params)` | `conn.add_filter_full(dev, parent, handle, "ip" → u16, prio, FlowerFilter::parse_params(&params)?)` |
| `tc::builders::filter::parse_protocol("ip")` | inline (~10-line lookup; see `bins/tc/src/commands/filter.rs::parse_protocol_u16`) |
| `tc::builders::action::add(conn, "gact", &params)` | `conn.add_action(GactAction::parse_params(&params)?)` |
| `tc::handle::parse_handle("1:a")` | `"1:a".parse::<nlink::TcHandle>()?` |
| `tc::options::netem::build(...)` | `NetemConfig::parse_params(&params)?` |

The typed parsers are **stricter** than the legacy code they
replace — unknown tokens, missing values, and unparseable
inner values now return `Error::InvalidMessage("kind: ...")`
instead of being silently swallowed. That's the point of the
typed surface; downstream code that relied on silent skips will
need to fix the input.

**`bins/tc` migration** — completed across PR C slices 1+2
(commits `b2370fd`, `0d095ae`):

- `bins/tc/src/commands/action.rs` — typed dispatch via
  `add_typed_action` macro mapping kind → `parse_params` →
  `conn.add_action`. 14 action kinds wired. Unknown kinds error
  cleanly with a recognised-kinds list.
- `bins/tc/src/commands/qdisc.rs` — `try_typed_qdisc`
  (`Option<Result<()>>`) restructured as `dispatch_qdisc`
  (`Result<()>`); legacy fallback removed. Unknown kinds error
  with a recognised-kinds list.
- `bins/tc/src/commands/filter.rs` — same restructure;
  `parse_protocol_u16` and `format_protocol` inlined (10-line
  helpers; no need to keep them in a separate module).
- All `#[allow(deprecated)]` directives in `bins/tc/` are gone
  (`grep -r "allow(deprecated)" bins/tc/` returns empty).

**Behavior changes** (documented for users upgrading from
0.14.0):

- `tc qdisc add DEV TYPE` for an unknown TYPE now errors
  immediately instead of silently emitting an empty options
  payload (which the kernel would reject with EINVAL anyway).
  The new error message lists every recognised kind.
- `tc filter add DEV TYPE` similarly errors on unknown TYPE.
- `tc filter del DEV` now requires `--protocol` and `--prio`
  (the typed `del_filter` takes the full lookup tuple). The
  partial-spec "delete-all-on-DEV" path is gone — users who
  need it should `tc filter show DEV` to enumerate, then delete
  by tuple. (Or open an issue if a typed flush-by-partial-spec
  helper is wanted.)
- `tc action del KIND` now requires `--index` (the typed
  `del_action` takes a concrete index).

**Plan 142 §6 acceptance criteria — all met:**

- [x] `crates/nlink/src/tc/builders/` directory does not exist
- [x] `crates/nlink/src/tc/options/` directory does not exist
- [x] `crates/nlink/src/tc/` directory does not exist (the whole
      legacy subtree is gone, including the unused `handle.rs`
      that only `tc::options::htb` referenced)
- [x] `bins/tc/src/commands/{class,qdisc,filter,action}.rs`
      contains zero `#[allow(deprecated)]` directives
- [x] No `use nlink::tc::builders::` anywhere in the workspace
- [x] No `nlink::tc::options::` references anywhere
- [x] No `tc::handle::parse_handle` references
- [x] `cargo clippy --workspace --all-targets --all-features
      -- --deny warnings` passes
- [x] `cargo machete` reports no NEW unused dependencies (the
      pre-existing `nlink-ss` / `nlink-bridge` warnings are
      unrelated to this PR)
- [x] `cargo test -p nlink --lib` passes (749 tests)
- [x] `cargo test -p nlink-tc` passes (35 tests)

**Net diff:** -3940 LOC deleted, +53 LOC inlined =
~3887 LOC removed from the source tree. The typed surface
that replaces the deletion was already shipped over Phases
0–3 and bumped lib tests from 593 → 749 (+156 net new) — the
typed code is more strictly tested AND smaller than the legacy
it replaces.

**Plan 142 closes here. Phase 4 done. 0.15.0 ready to cut.**

For the full upgrade walkthrough (every removed symbol, every
behaviour change, before/after diffs, worked HTB-tree example),
see [`docs/migration_guide/0.14.0-to-0.15.0.md`](docs/migration_guide/0.14.0-to-0.15.0.md).

Remaining open items (out of scope for the 0.15.0 release-cut):
- Plan 141 PR C — `xfrm-ipsec-tunnel` recipe + `examples/xfrm/
  ipsec_monitor.rs --apply` promotion (needs sudo for golden-
  frame validation).
- Plan 137 integration tests un-parking + the GHA workflow
  (needs an in-tree test that uses `require_module!`).

### Added — `parse_params` on the last 3 action kinds (Plan 139 PR B closes; sub-slice 3)

Plan 139 PR B closes here. **All 14 action kinds typed-first**
(13 fully parsed + 1 stub for `pedit`). Total
`nlink::ParseParams` impls now **41** (18 qdisc + 9 filter + 14
action). The bin's `bins/tc/src/commands/action.rs` migration
(PR C) can now dispatch typed for every kind it supports.

- **`PoliceAction::parse_params`** — large token surface mapping
  to typed `Rate` (`rate`, `peakrate`, `avrate`) and
  tc-byte-syntax sizes (`burst`/`buffer`/`maxburst`, `mtu`).
  `conform-exceed <conform>/<exceed>` parses the slash-separated
  verdict pair (e.g. `pass/drop`); the alternative
  `conform <verdict>` and `exceed <verdict>` individual tokens
  also work. Verdict parsing reuses `parse_gact_verdict` with
  `gact:` → `police:` error-prefix rebrand.
- **`CtAction::parse_params`** — operation (`commit` / `clear`,
  default "restore state"), `force` flag, `zone <0–65535>`,
  `mark <value> <mask>` (two values for clarity), and
  `nat src|dst <addr>` / `nat src|dst <min>-<max>` for
  single-address or range NAT (parsed via the new
  `parse_ipv4_range_or_single` helper).
- **`PeditAction::parse_params`** — explicit rejection stub.
  `tc(8)`'s pedit DSL (`munge ip src set 1.2.3.4`, etc.) is
  genuinely complex; per Plan 139 §10 it's "punt-eligible until
  a downstream user asks". The stub keeps `PeditAction`
  discoverable in the `ParseParams` trait list and surfaces a
  clean error pointing at the typed builder
  (`PeditAction::set_ipv4_src` etc.) for users who run
  `tc action add pedit ...`.

15 new unit tests cover: police rate/burst/conform-exceed combos
(slash form + individual form), invalid-rate / missing-slash /
unknown-verdict-rebrand error paths; ct commit+zone+mark,
clear+force, nat src single-addr, nat dst range, zone
out-of-range / mark missing-mask / nat unknown-direction
errors; pedit stub-always-rejects.

749 lib tests total (was 734). Workspace clippy with
--all-features --deny warnings is clean.

**Plan 139 PR C** is the **legacy-deletion milestone** for
Plan 142 Phase 4 — it migrates `bins/tc/src/commands/action.rs`
to dispatch typed (using these 14 parse_params), drops the
last `#[allow(deprecated)]` on `bins/tc`, and **deletes
`tc::builders::*` and `tc::options/*` entirely**. That PR closes
the 0.15.0 cycle.

### Added — `parse_params` on 6 more typed action kinds (Plan 139 PR B sub-slice 2)

Eleven of ~14 action kinds now typed-first. The remaining three
(`PoliceAction`, `CtAction`, `PeditAction`) are the larger /
trickier parsers; they ship in sub-slice 3.

- **`CsumAction::parse_params`** — accumulates checksum-kind
  flags (`iph`/`icmp`/`igmp`/`tcp`/`udp`/`udplite`/`sctp`).
  Order-independent, idempotent (bitmask OR).
- **`SampleAction::parse_params`** — required `rate <N>` +
  `group <G>` plus optional `trunc <bytes>`.
- **`TunnelKeyAction::parse_params`** — `set` / `release`
  operation, plus set-only modifiers `src`/`dst`/`src6`/`dst6`
  for outer addresses, `id <vni>`, `dst_port <port>`,
  `tos`/`ttl <0–255>`, and the `no_csum` / `no_frag` flag
  tokens. Set-only modifiers under `release` are explicitly
  rejected.
- **`NatAction::parse_params`** — positional
  `<ingress|egress> <oldaddr[/prefix]> <newaddr>` mirroring
  `tc(8)`. `egress` → SNAT, `ingress` → DNAT. Bare addresses
  default to /32.
- **`SimpleAction::parse_params`** — required `sdata <text>`
  (single token; multi-word tags need the typed builder per
  Plan 139 §8.4) plus optional `verdict <kw>`.
- **`BpfAction::parse_params`** — required program source
  (`pinned <path>` for filesystem-pinned programs, or
  `fd <n>` for raw file descriptors — mutually exclusive),
  optional `name <text>` and `verdict <kw>`.

Three of these (`BpfAction`, `SimpleAction`) reuse
`parse_gact_verdict` for their `verdict <kw>` token — the
`gact:` error prefix gets rebranded to the action's own kind
on the way out, so users see `simple: unknown verdict ...`
rather than the misleading `gact: ...`.

29 new unit tests cover: each parser's wire equivalence to the
typed builder via `write_options` byte comparison,
token-order independence (where applicable), all reject paths
(missing required tokens, out-of-range values, wrong-direction
modifiers, mutex violations, unknown tokens), error-prefix
rebranding for shared-helper paths.

Six new `nlink::ParseParams` trait impls — total now **38 typed
configs** (18 qdisc + 9 filter + 11 action). Three action kinds
remain (police/ct/pedit).

734 lib tests total (was 705). Workspace clippy with
--all-features --deny warnings is clean.

### Added — `parse_params` on 5 typed action kinds (Plan 139 PR B sub-slice 1)

First batch of per-kind action parsers — the bulk of the bin
migration work for `bins/tc/src/commands/action.rs`. Five of
~14 action kinds typed-first:

- **`GactAction::parse_params`** — verdict keywords (`pass`/`ok`,
  `drop`/`shot`, `pipe`, `reclassify`, `stolen`, `continue`),
  `goto_chain <n>`, and `random determ|netrand <verdict> <val>`
  for probabilistic alternates.
- **`MirredAction::parse_params`** — `egress`/`ingress` direction +
  `redirect`/`mirror` operation + `dev <ifname>` (sysfs lookup
  via `nlink::util::get_ifindex`) or `ifindex <n>`
  (namespace-safe). `dev` and `ifindex` are mutually exclusive.
- **`VlanAction::parse_params`** — operation (`pop`,
  `push <id>`, `modify <id>`) plus optional `priority <p>` and
  `protocol 802.1q|802.1ad` modifiers. VLAN ID range-checked
  to 0–4095, priority to 0–7.
- **`SkbeditAction::parse_params`** — `priority`, `mark`,
  `mask` (combined with `mark` if both present), and
  `queue_mapping`. Tokens are any-order; `mask` without `mark`
  is rejected.
- **`ConnmarkAction::parse_params`** — `zone <0–65535>`.

Stricter than the legacy `tc::builders::action::*` parsers
(which silently dropped unknown tokens via `_ => i += 1`):
unknown tokens, missing values, and out-of-range values all
return `Error::InvalidMessage("<kind>: ...")`.

Module-scope helpers added: `action_need_value`,
`action_parse_u32`, `parse_gact_verdict` (mirrors the
`filter::need_value` / `parse_u32_int` / etc. pattern from the
qdisc + filter rollouts; reused by the remaining action parsers
in subsequent sub-slices).

Five new `nlink::ParseParams` trait impls — total now 32 typed
configs (18 qdisc + 9 filter + 5 action).

30 new unit tests cover: each shortcut/keyword's wire equivalence
to the direct typed setter (via `write_options` byte comparison),
token-order independence where applicable, all named verdicts /
protocols / mutex error cases, plus 13 strict-error scenarios
across the five parsers.

705 lib tests total (was 677). Workspace clippy with
--all-features --deny warnings is clean.

Plan 139 PR B sub-slices 2+ ship the remaining ~9 action kinds
(`PoliceAction`, `NatAction`, `TunnelKeyAction`, `CsumAction`,
`SampleAction`, `CtAction`, `PeditAction`, `BpfAction`,
`SimpleAction`). PR C is the legacy-deletion milestone for
Plan 142 Phase 4.

### Added — typed standalone-action CRUD on `Connection<Route>` (Plan 139 PR A, Plan 142 Phase 3)

Today nlink has two coexisting action surfaces: filter-attached
actions (typed end-to-end since 0.13.0) and standalone shared
actions (the `tc action add ...` flavour). Standalone actions
were previously only reachable via the deprecated
`nlink::tc::builders::action::*` free functions. PR A adds the
typed equivalent on `Connection<Route>` using the existing
`ActionConfig` trait — same trait the filter-attached actions
already use.

New public API in `nlink::netlink::action`:

- `ActionMessage { kind, index, options_raw }` — parsed dump
  entry. Per-kind decoders for `options_raw` are intentionally
  deferred (Plan 139 §3.2): the raw payload is the honest
  baseline.
- `Connection<Route>::add_action<A: ActionConfig>(action)` —
  `RTM_NEWACTION` + `NLM_F_CREATE`. Kernel assigns the index
  (returning the assigned value requires `NLM_F_ECHO` plumbing,
  deferred per Plan 139 §8).
- `Connection<Route>::del_action(kind, index)` —
  `RTM_DELACTION`. Index goes alongside `TCA_ACT_KIND` at the
  slot level (modern lookup path).
- `Connection<Route>::get_action(kind, index)` — single-result
  fetch via `send_request`. Returns `Ok(Some(am))` /
  `Ok(None)` / `Err`.
- `Connection<Route>::dump_actions(kind)` — dump all actions of
  a kind (or pass `""` for every kind).

Wire shape mirrors `tc(8)`'s standalone-action protocol:
`tcamsg + TCA_ACT_TAB { [1] { TCA_ACT_KIND + TCA_ACT_OPTIONS { ... } } }`.
The typed methods reuse the existing `ActionConfig::write_options`
to emit each kind's bits — no per-kind code in the new methods.

Internal:
- `parse_action_messages(msg) -> Vec<ActionMessage>` — walks
  `TCA_ACT_TAB` slots, extracts kind + index + raw options.
  Falls back to extracting index from the first sub-attribute's
  PARMS struct payload (older kernel encoding) when the modern
  slot-level `TCA_ACT_INDEX` is absent.
- `next_nla(input)` — small TLV walker that masks
  `NLA_F_NESTED` / `NLA_F_NET_BYTEORDER` flags through
  `NLA_TYPE_MASK` so the dispatch sees only the bare type.

8 new unit tests round-trip builder output through the new
parser:
- `add_action_gact_drop_roundtrips_through_parser`
- `add_action_mirred_roundtrips`
- `add_action_police_roundtrips`
- `add_action_vlan_pop_roundtrips`
- `add_action_skbedit_roundtrips`
- `del_action_emits_kind_plus_index_at_slot_level`
- `get_action_request_uses_request_only_flags`
- `parse_action_messages_handles_two_slots` /
  `parse_action_messages_skips_truncated_input`

677 lib tests total (was 668). Workspace clippy with
--all-features --deny warnings is clean.

**Plan 139 PR B** is the bulk of the per-kind work — `parse_params`
on every typed action kind (~14 kinds) so `bins/tc/src/commands/
action.rs` can dispatch typed instead of falling through to the
deprecated `tc::builders::action::*` path. PR C is the
**legacy-deletion milestone** for Plan 142 Phase 4: deletes
`tc::builders::*` and `tc::options/*` entirely.

### Added — `XfrmSpBuilder` + Security Policy CRUD (Plan 141 PR B)

`Connection<Xfrm>` already shipped Security Association CRUD in
PR A. PR B adds the matching write path for Security Policies —
SPs are what steer traffic into the IPsec subsystem in the first
place (without an SP, an SA never sees a packet).

New public types in `nlink::netlink::xfrm`:

- `XfrmSpBuilder { sel, direction, action, priority, index,
  flags, share, tmpls, mark, if_id }` — `must_use` builder.
- `XfrmUserTmpl` — zero-copy struct mirroring the kernel's
  `xfrm_user_tmpl` (one entry in an SP's `XFRMA_TMPL` array).
  Tells the kernel which SA to look up to satisfy the policy.
- `XfrmUserpolicyId` — zero-copy struct for `XFRM_MSG_DELPOLICY`
  / `GETPOLICY` request bodies (selector + index + dir byte).
- `PolicyDirection::number()` / `PolicyAction::number()` —
  inverse of the existing `from_u8` parsers (mirrors
  `IpsecProtocol::number` / `XfrmMode::number` from PR A).

Builder API (chained):
- `XfrmSpBuilder::new(sel, dir)` — entry point. Defaults to
  `Allow` action, priority 0, kernel-assigned index, no
  templates.
- `.allow()` / `.block()` — set action.
- `.priority(u32)` — order of evaluation (lower = first).
- `.index(u32)` — pre-pin a policy index (default 0 → kernel
  assigns).
- `.template(XfrmUserTmpl)` — append a template; multiple calls
  accumulate in order (relevant for nested ESP+AH).
- `.mark(mark, mask)` — filter which policies apply by skb mark.
- `.if_id(id)` — XFRM interface ID.

`XfrmUserTmpl::match_any(src, dst, proto, mode, reqid)` —
convenience constructor for the common "match any algorithm
combination" template (algorithm bitmasks default to `u32::MAX`).

New `Connection<Xfrm>` methods:
- `add_sp(sp)` — `XFRM_MSG_NEWPOLICY` with `CREATE | EXCL`.
- `update_sp(sp)` — `XFRM_MSG_NEWPOLICY` with `CREATE | REPLACE`,
  matches on `(selector, dir)` to update in place.
- `del_sp(sel, dir)` — `XFRM_MSG_DELPOLICY` with
  `XfrmUserpolicyId` body.
- `flush_sp()` — `XFRM_MSG_FLUSHPOLICY`. No body — wipes all
  policies in the kernel's database.
- `get_sp(sel, dir)` — single-result fetch via `send_request`.
  Returns `Ok(Some(sp))` on hit, `Ok(None)` on ENOENT.

Internal: `parse_policy_msg` extracted as an associated function
on `Connection<Xfrm>` (mirrors `parse_sa_msg` from PR A) so unit
tests can call it without a live socket. The `&self` `parse_policy`
method delegates.

8 new unit tests:
- `xfrm_sp_out_with_one_tmpl_roundtrips` — typical
  outbound-encrypt SP with one template via `match_any`.
- `xfrm_sp_in_with_two_tmpls_packs_array` — inbound chain
  (ESP outer + AH inner); asserts `XFRMA_TMPL` carries
  `2 * sizeof(XfrmUserTmpl)` bytes packed back-to-back (the
  kernel reads it as a packed array, not nested attrs).
- `xfrm_sp_block_action_no_templates` — `Block` action emits
  no templates.
- `xfrm_del_sp_emits_selector_plus_dir` — direction byte at
  the documented offset (16 + sel_size + 4) carries
  `XFRM_POLICY_OUT`.
- `xfrm_get_sp_request_uses_request_only_flags` — flags must
  be `REQUEST` only (no DUMP, no ACK).
- `xfrm_flush_sp_has_no_body` — frame is exactly the 16-byte
  nlmsghdr.
- `xfrm_user_tmpl_sets_default_algo_bitmasks_to_max` — locks
  in the "match any algorithm" default.
- `policy_direction_to_u8_round_trips` — `from_u8(number())`
  preserves all 3 named variants.

Plus 1 new constant `XFRMA_POLICY_TYPE` is in place but currently
`#[allow(dead_code)]` for the future "main vs sub" policy-type
slice.

668 lib tests total (was 660). Workspace clippy with
--all-features --deny warnings is clean.

Plan 141 PR B closes here. Plan 141 PR C (the
`xfrm-ipsec-tunnel` recipe + `examples/xfrm/ipsec_monitor.rs`
`--apply` promotion) is the last slice; it bumps Plan 135 PR B
to 7/7 once shipped.

### Added — XFRM SA write-path slice 2: `update_sa`, `flush_sa_proto`, `get_sa` (Plan 141 PR A complete)

Closes Plan 141 PR A's full DoD. Three small methods, all
mirrored from Plan 137 PR A's pattern for `Connection<Netfilter>`:

- `Connection<Xfrm>::update_sa(sa)` — same wire shape as
  `add_sa` but with `NLM_F_CREATE | NLM_F_REPLACE` (no
  `NLM_F_EXCL`). The kernel matches on the
  (`daddr`, `spi`, `proto`, `family`) tuple from the body and
  updates in place. Useful for rotating keys without a
  delete-then-add (which would briefly leave traffic
  unprotected).
- `Connection<Xfrm>::flush_sa_proto(proto: IpsecProtocol)` —
  variant of `flush_sa()` that flushes only one IPsec
  protocol (e.g. ESP only, leaving AH SAs in place).
  Internally just calls `flush_sa_inner(proto.number())`.
- `Connection<Xfrm>::get_sa(src, dst, spi, proto)` — single-result
  fetch. Returns `Ok(Some(sa))` on hit, `Ok(None)` on
  ENOENT (kernel says no such SA), `Err(e)` on other failures.
  Uses `send_request` (not `send_dump`) for the one-message
  response. Sends `XFRM_MSG_GETSA` with `NLM_F_REQUEST` only
  (no DUMP, no ACK) and an `XfrmUsersaId` body, with optional
  `XFRMA_SRCADDR` for the source-address hint.

`NLM_F_REPLACE` constant lost its `#[allow(dead_code)]` gate.

4 new unit tests:
- `xfrm_update_sa_uses_create_and_replace_flags_not_excl` —
  asserts the nlmsghdr.flags carry `CREATE|REPLACE` but NOT
  `EXCL`.
- `xfrm_update_sa_body_round_trips_like_add_sa` — the body is
  identical to `add_sa`, so existing `parse_sa_msg` round-trips
  it.
- `xfrm_flush_sa_proto_writes_specific_proto_byte` — checks the
  proto byte at the expected offset and that padding stays zero.
- `xfrm_get_sa_request_carries_lookup_tuple` — asserts
  `nlmsg_type=GETSA`, flags=`REQUEST` only, and the
  `XfrmUsersaId` lookup body decodes correctly.

660 lib tests total (was 656). Workspace clippy with
--all-features --deny warnings is clean.

Plan 141 PR A is now complete per §9 DoD: builder + all 6
methods (`add`/`update`/`del`/`flush`/`flush_proto`/`get`) +
8 round-trip wire-format tests. Plan 141 PR B (Security Policy
CRUD with `XfrmSpBuilder`) is the next slice; PR C bundles the
recipe and `--apply` example promotion.

### Added — `XfrmSaBuilder` + SA CRUD on `Connection<Xfrm>` (Plan 141 PR A, Plan 142 Phase 2)

`Connection<Xfrm>` was dump-only — `get_security_associations`
and `get_security_policies`, nothing else. PR A adds the typed
write path for Security Associations using the same builder
pattern Plan 137 PR A established for `Connection<Netfilter>`.

New public types in `nlink::netlink::xfrm`:

- `XfrmSaBuilder { src, dst, spi, proto, mode, reqid, ... }` —
  `must_use` builder with fluent setters.
- `XfrmAlgoAuth { name, key }`, `XfrmAlgoEncr { name, key }`,
  `XfrmAlgoAead { name, key, icv_truncbits }` — algorithm specs.
- `XfrmUsersaId` (24 bytes) and `XfrmUsersaFlush` (8 bytes) —
  zero-copy structs for `XFRM_MSG_DELSA` / `FLUSHSA` bodies.

Builder API (chained):
- `XfrmSaBuilder::new(src, dst, spi, proto)` — entry point;
  defaults to transport mode, reqid 0, replay window 32 (kernel
  default of 0 disables replay protection — surprising footgun;
  builder picks the iproute2-default 32 packets).
- `.mode(XfrmMode)`, `.reqid(u32)`, `.replay_window(u8)`.
- `.auth(name, key)` and `.auth_hmac_sha256(key)` for auth algos.
- `.encr(name, key)` and `.encr_aes_cbc(key)` for encrypt algos.
- `.aead(name, key, icv_truncbits)` and `.aead_aes_gcm(key, icv)`
  for AEAD (combined auth+encrypt with ICV).
- `.nat_t_udp_encap(sport, dport)` — picks
  `UDP_ENCAP_ESPINUDP` (2) for dport=4500, `_NON_IKE` (1)
  otherwise.
- `.mark(mark, mask)` and `.if_id(id)` for filtering attributes.

New `Connection<Xfrm>` methods:
- `add_sa(sa)` — sends `XFRM_MSG_NEWSA` with
  `NLM_F_CREATE | NLM_F_EXCL`. Returns `EEXIST` if SA tuple
  already exists.
- `del_sa(src, dst, spi, proto)` — sends `XFRM_MSG_DELSA` with
  `XfrmUsersaId` body + optional `XFRMA_SRCADDR` attribute.
- `flush_sa()` — sends `XFRM_MSG_FLUSHSA` with proto=0
  (IPSEC_PROTO_ANY → all protocols).

Wire-format encoding helpers:
- `encode_xfrm_algo(name, key)` — packs the kernel `xfrm_algo`
  layout: 64-byte zero-padded name + 4-byte key_len_bits + key.
- `encode_xfrm_algo_aead(name, key, icv_truncbits)` — adds the
  4-byte icv_truncbits field between key_len and key.
- `family_for_pair(src, dst)` — returns `AF_INET`/`AF_INET6` (or
  0 for mismatched families; kernel rejects).
- `ip_to_xfrm_addr(IpAddr)` — wraps the existing
  `XfrmAddress::from_v4` / `from_v6` constructors.

Eight new unit tests round-trip builder output through the
existing `parse_sa_msg` (extracted from the impl as an associated
function so tests can call it without a live socket):
- `xfrm_sa_v4_esp_separate_auth_encr_roundtrips_through_parse_sa`
- `xfrm_sa_v4_esp_aead_aes_gcm_roundtrips`
- `xfrm_sa_v6_separate_auth_encr_roundtrips`
- `xfrm_sa_nat_t_udp_encap_roundtrips`
- `xfrm_del_sa_emits_correct_tuple` (24-byte XfrmUsersaId
  verified field-by-field)
- `xfrm_flush_sa_proto_zero_means_all`
- `xfrm_sa_default_replay_window_is_32` (locks in the iproute2
  default to prevent regressions to the kernel's 0 default)
- Plus updated `zerocopy_sizes` with the new struct sizes.

656 lib tests total (was 649). Workspace clippy with
--all-features --deny warnings is clean.

**Deferred to a follow-up slice** (Plan §9 PR A DoD):
- `update_sa` (NLM_F_REPLACE wire shape) — `NLM_F_REPLACE`
  constant is in place but unused, gated with
  `#[allow(dead_code)]`.
- `flush_sa_proto(proto)` — variant of flush_sa that flushes
  only one protocol.
- `get_sa(src, dst, spi, proto)` — single-result equivalent of
  `get_security_associations`; needs a parser refactor for
  single-message reads.

These three slot into a quick follow-up commit. Plan 141 PR B
(SP CRUD) is the next major slice; PR C is the recipe + example
promotion.

### Added — `BasicFilter` ematch tree typed support (Plan 133 PR C, Plan 142 Phase 1)

Closes the filter side at **9 of 9 typed-first**. The `cls_basic`
classifier was a stub (just `classid` + `chain`); it now grows
ematch tree support via typed Rust newtypes that mirror the
kernel's `tcf_ematch_*` wire structs.

New public types in `nlink::netlink::filter`:

- `Ematch { kind, op, negate }` — one entry in the tree.
- `EmatchKind::{Cmp, U32}` — `non_exhaustive` enum so `Meta` can
  ship later without breaking matches.
- `EmatchCmp { layer, align, offset, mask, value, op, trans }` —
  compare a packet field against a constant.
- `EmatchU32 { mask, value, offset }` — same selector primitive
  as `cls_u32`'s key, embedded in a `cls_basic` ematch tree.
- `EmatchOp::{And, Or}` — relation joining adjacent matches.
- `CmpOp::{Eq, Gt, Lt}`, `CmpLayer::{Link, Network, Transport}`,
  `CmpAlign::{U8, U16, U32}` — all `non_exhaustive`.

Builder additions to `BasicFilter`:

- `ematch(Ematch)` — append a match (multiple calls accumulate).
- `ip_proto_eq(u8)` — convenience shortcut for a single `cmp`
  match on the IP protocol byte at offset 9 of the network header.
- `Ematch::cmp(EmatchCmp) -> Ematch` and `Ematch::u32(EmatchU32)`
  constructors with default `And` relation and no negation.
- `.or()` and `.negate()` chainable modifiers on `Ematch`.

Wire format — new `nlink::netlink::types::tc::filter::ematch`
module exposes the kernel constants and zero-copy structs
(`TcfEmatchTreeHdr`, `TcfEmatchHdr`, `TcfEmCmp`, `TcfEmU32`).
`TcfEmCmp` is 16 bytes (14 declared + 2 explicit alignment slot
matching the kernel's `sizeof`-rounded struct). The bit-packed
`align:4 / flags:4` and `layer:4 / opnd:4` fields are exposed
as plain `u8`s at module level; the encoder packs them as
`(high << 4) | (low & 0x0F)`. `BasicFilter::write_options` builds
the full nest (`TCA_BASIC_EMATCHES → TCA_EMATCH_TREE_HDR +
TCA_EMATCH_TREE_LIST → per-match attrs`).

`BasicFilter::parse_params` recognises:
- `classid <handle>` / `flowid <handle>` — target class.
- `chain <n>` — TC chain index.
- `ip_proto_eq <name|number>` — convenience for the IP-proto-byte
  cmp match. Accepts the same protocol names as `U32Filter`'s
  `match ip protocol` shortcut (tcp/udp/icmp/icmpv6/sctp/ah/esp/gre).

The full ematch DSL (`match cmp(...) and cmp(...)` with paren
grouping) is intentionally not parsed — `tc(8)`'s ematch syntax
relies on shell-quoted expressions that don't tokenise cleanly
through `bins/tc`'s flat `&[String]` interface. Use the typed
builder for non-trivial trees.

`bins/tc/src/commands/filter.rs` `matches!` guard grew `basic`;
new `dispatch!(BasicFilter)` arm. The bin's import-level
`#[allow(deprecated)]` for `filter_builder` stays for now — it
covers the legacy `add/del/replace/change` fallback paths
(reached only for kinds not in the typed list) plus
`parse_protocol`/`format_protocol` wrappers. Full removal lands
in Plan 142 Phase 4 alongside the legacy module deletion.

`BasicFilter` joined the `nlink::ParseParams` trait impl list
(was 26 impls; now 27 — full filter side + 18 qdiscs typed-first).

12 unit tests cover: single-match `cmp` from `ip_proto_eq`,
two-match tree (relation flags), `negate()` setting `TCF_EM_INVERT`,
`or()` setting the relation flag (and last match's op being
ignored), `cmp` byte layout matching the kernel struct exactly
(via `as_bytes()` comparison), `parse_params` empty/classid/
flowid/chain/ip_proto_eq named/numeric, unknown-token error,
and the `u32:` → `basic:` error-prefix rebrand for shared helper
errors. **`Meta` ematch kind deferred** — its wire format is more
complex and benefits from golden-hex captures the maintainer
needs sudo for.

Plan 133 closes (all 4 PRs shipped). Filter side at 9 of 9
typed-first means **Plan 142 Phase 1 is substantively complete**
(only Plan 137 integration tests un-parking + the bin's deprecated
import drop remain as Phase 1 cleanup; the latter slots into
Phase 4 anyway).

### Added — `U32Filter::parse_params` Phase 3 hash-table grammar (Plan 138 PR C)

- Closes Plan 138. `U32Filter::parse_params` now recognises every
  hash-table token typical `tc(8) u32` filters need:
  - `divisor <n>` — divisor for bucket count when this filter
    creates a hash table. Combine with no keys for the
    table-create case (no `TCA_U32_SEL` is emitted then).
  - `ht <handle>` — hash table this filter belongs to,
    encoded as `TCA_U32_HASH`. Handle uses tc(8) notation
    (`100:` → 0x01000000 via `TcHandle::as_raw`).
  - `link <handle>` — next-hop hash table to chase on match
    (`TCA_U32_LINK`). Same handle notation. (Setter existed since
    0.12; only the parser token is new.)
  - `hashkey mask <hex> at <offset>` — bytes of the packet header
    used to compute the hash bucket index. `mask` packs into
    `sel.hmask` (big-endian on the wire); `offset` packs into
    `sel.hoff` (i16 range, range-checked at parse time).
- New `U32Filter::ht(u32)` and `U32Filter::hashkey(u32, i16)`
  setters. New `ht: Option<u32>` and `hashkey: Option<(u32, i16)>`
  fields. `write_options` emits `TCA_U32_HASH` when `ht` is set
  and writes `sel.hdr.hmask` / `sel.hdr.hoff` when `hashkey` is
  set, requiring the selector emit even with zero keys.
- `order <n>` is **explicitly rejected** with a clear error:
  modifying the filter's own handle requires bin-side support
  that isn't wired through `parse_params`. Documented as future
  work; the error message points there.
- 10 new unit tests cover: divisor-only filter (no keys, no
  link/ht/hashkey), `ht <handle>` encoding via `TcHandle`,
  ht+link+match+classid combo (typical hashed-chain shape),
  link via tc(8) notation, hashkey packing into `sel`,
  hashkey i16 range check, missing-`mask`-keyword error,
  `order` rejection, divisor-not-int error, ht-bad-handle error.
- Doc-string on `parse_params` grew a "Phase 3 surface" section
  and a "Not yet typed-modelled" callout for `order`,
  `match icmp type|code`, and IPv6 named-matches.

`U32Filter::parse_params` now recognises **every Phase 1+2+3
token** Plan 138 specified. 41 unit tests cover the full grammar
(16 raw + 15 named + 10 hash-table). Filter side stays at 8 of 9
typed-first (the `u32` kind is feature-complete; `basic` is the
only legacy kind remaining, gated on Plan 133 PR C).

Plan 138 closes here. Phase 1 of Plan 142 still needs Plan 133 PR C
(`BasicFilter` ematch) before the bin's `#[allow(deprecated)]` on
`filter_builder` can come off.

### Added — `U32Filter::parse_params` Phase 2 named-match shortcuts (Plan 138 PR B)

- `U32Filter::parse_params` grew the four-token named-match
  shortcuts that desugar to the existing typed setters
  (`match_src_ipv4` / `match_dst_ipv4` / `match_ip_proto` /
  `match_src_port` / `match_dst_port`). Wire output is identical
  to direct setter calls — port matches use `nexthdr`-relative
  offsets via `with_nexthdr`, which is IP-options-tolerant.
- Recognised shortcuts:
  - `match ip src <addr>[/<prefix>]` — IPv4 source. Bare addr → /32.
  - `match ip dst <addr>[/<prefix>]` — IPv4 destination.
  - `match ip protocol <name|number>` — IP protocol. Names accepted:
    `tcp` (6), `udp` (17), `icmp` (1), `icmpv6` (58), `sctp` (132),
    `ah` (51), `esp` (50), `gre` (47). Numeric: 0–255.
  - `match ip sport <port>` / `match ip dport <port>` — L4 ports.
  - `match tcp sport|dport <port>` and `match udp sport|dport <port>`
    — alias for `match ip sport|dport`. The wire is identical;
    the `tcp`/`udp` prefix is `tc(8)` syntax sugar.
- New private helpers (`apply_named_match`,
  `parse_u32_ipv4_with_prefix`, `parse_ip_proto_name_or_num`,
  `parse_port`) factored at module scope. The flower filter has
  its own `parse_ipv4_with_prefix` with a `flower:` error prefix;
  the u32 helper is renamed to disambiguate.
- 15 new unit tests cover: each shortcut's wire equivalence to
  the direct setter, /32 default, all 8 named protocols, port
  aliases (ip vs tcp vs udp produce identical bytes), shortcut
  combination with `classid`, plus 6 strict-error cases (invalid
  prefix, invalid addr, unknown field, unknown proto, port out
  of range, missing value).
- `parse_u32_raw_match` (renamed from `parse_u32_match`) now takes
  `width: &str` from the caller's already-validated dispatch.
  No behaviour change.

Per the plan, golden-hex fixtures from `tc(8)` are deferred until
the privileged GHA runner ships (the workflow file lands in a
follow-up alongside the first integration test that uses
`require_module!`). Until then, setter equivalence via shared
helpers is the strongest local check.

Phase 3 (hash-table grammar: `divisor`, `ht`, `link`, `order`,
`hashkey`) follows in the next PR. The filter side stays at 8 of 9
typed-first; `basic` (Plan 133 PR C) is the last remaining kind.

### Added — `U32Filter::parse_params` Phase 1 (Plan 138 PR A, Plan 142 Phase 1)

- New `U32Filter::parse_params(&[&str])` parses the raw-match-triple
  flavour of `tc(8)`'s `u32` filter grammar:
  - `match u32 <hex-value> <hex-mask> at <offset>` — append a
    32-bit-wide selector key. Hex accepts `0x`-prefixed or bare
    digits; offset accepts decimal or hex.
  - `match u16 <hex-value> <hex-mask> at <offset>` — narrower
    width, packed into the right half of a 32-bit-sized key
    based on offset alignment (offset & 3).
  - `match u8 <hex-value> <hex-mask> at <offset>` — same idea,
    one of four byte slots in the 32-bit key.
  - `classid <handle>` / `flowid <handle>` — target class.
  - `chain <n>` — TC chain index.
  - `skip_hw` / `skip_sw` — flag tokens setting
    `TCA_CLS_FLAGS_SKIP_HW` / `SKIP_SW`.
- New `U32Filter::skip_hw()` / `skip_sw()` setters and the
  underlying `flags: u32` field, written via `TCA_U32_FLAGS` in
  `write_options`. The bin's `skip_hw` / `skip_sw` token paths
  go through these.
- Stricter than the legacy `add_u32_options` parser (which silently
  swallowed unknown tokens via `_ => i += 1`): unknown tokens
  return `Error::InvalidMessage("u32: unknown token \`...\`...")`,
  bad hex returns `"u32: invalid VAL \`...\` (expected hex value)"`,
  short matches return `"u32: \`match\` requires \`WIDTH VAL MASK
  at OFFSET\` (missing ...)"`, etc. Every error message
  kind-prefixes with `"u32: "`.
- Width-overflow rejections: `match u8 0xDEAD ...` returns
  `"u32: u8 match VAL/MASK must fit in 8 bits"`. Same for `u16`.
- 16 unit tests cover: empty params, raw u32/u16/u8 triples,
  multiple-match append order, classid/flowid alias, chain +
  skip flags combo, and 7 error-shape cases (unknown token,
  invalid hex, unknown width, short match, missing `at`
  keyword, value-out-of-range, missing required value).
- `bins/tc/src/commands/filter.rs` typed-dispatch `matches!`
  guard grew `u32`; new `dispatch!(U32Filter)` arm. Filter side
  now 8 of 9 typed-first (only `basic` remains, gated on
  Plan 133 PR C).
- `U32Filter` joins the `nlink::ParseParams` trait impl list
  (was 25 impls; now 26).

Phase 2 (named-match shortcuts: `match ip src ADDR/PREFIX`,
`match tcp dport`, etc.) and Phase 3 (hash-table grammar:
`divisor`, `ht`, `link`, `order`, `hashkey`) ship in subsequent
PRs of Plan 138. The `#[allow(deprecated)]` on the bin's
`filter_builder` import stays until Plan 133 PR C also lands
(`basic` is the last remaining legacy caller).

### Added — sealed `ParseParams` trait (Plan 142 Phase 0, slice 2)

- New `nlink::ParseParams` trait formalizes the `parse_params`
  contract every typed TC config has implemented since 0.14.0.
  Sealed via a private supertrait; third-party crates can use the
  trait but cannot implement it (the contract is intentionally
  narrow — strict rejection, kind-prefixed error messages —
  and extending it across foreign types invites drift).
- 25 forwarding impls cover every shipped typed config: 18 qdisc
  (`HtbQdiscConfig`, `NetemConfig`, `CakeConfig`, `TbfConfig`,
  `SfqConfig`, `PrioConfig`, `FqCodelConfig`, `RedConfig`,
  `PieConfig`, `HfscConfig`, `DrrConfig`, `QfqConfig`,
  `IngressConfig`, `ClsactConfig`, `PlugConfig`, `MqprioConfig`,
  `EtfConfig`, `TaprioConfig`) and 7 filter
  (`BpfFilter`, `CgroupFilter`, `FlowFilter`, `FlowerFilter`,
  `FwFilter`, `MatchallFilter`, `RouteFilter`). Each impl
  forwards to the inherent method; existing direct callers
  (every test, every recipe) keep working unchanged.
- `bins/tc` qdisc + filter dispatch macros now bind through
  `<$Cfg as nlink::ParseParams>::parse_params(...)` so the
  dispatcher's contract is type-checked rather than just
  convention. No behaviour change.
- New module `nlink::netlink::parse_params` (the trait's home).
  Top-level re-export at `nlink::ParseParams` for convenience.
- 3 unit tests cover: trait dispatch matches inherent dispatch,
  strict error rejection propagates, generic dispatch
  (`fn run<C: ParseParams>(...)`) compiles and works.

This closes Plan 142 Phase 0 alongside slice 1's `require_module!`
helper. Phase 1 (filter side completion: Plan 138 + Plan 133 PR C)
unblocks next.

### Added — `nlink::lab::has_module` + `require_module!` macros (Plan 142 Phase 0, slice 1)

- New `nlink::lab::has_module(name) -> bool` checks whether a
  named kernel feature is loaded as a module or compiled into
  the kernel. Reads `/sys/module/<name>` (which sysfs exposes
  for both loaded loadable modules and built-in features) so it
  doesn't false-negative on distros that build common bits like
  `nf_conntrack` directly into the kernel image.
- New `nlink::require_module!("nf_conntrack")` macro pairs with
  `nlink::require_root!()` for integration tests that depend on
  optional kernel features. Returns early with `Ok(())` when the
  module is missing — produces a clean skip message rather than
  a cryptic `is_not_supported()` error deep in the test body.
  Also `require_module_void!` for non-`Result` test signatures.
- `has_module` rejects names containing `/` or `\0` (defense in
  depth — those aren't legal kernel module names, and `Path::join`
  would silently resolve outside `/sys/module` for an absolute
  name).
- `CLAUDE.md` "Integration tests" section gained one sentence
  documenting the new macro.

This is the first of two Phase 0 deliverables for Plan 142
(slice 2 will be the sealed `ParseParams` trait + 25 forwarding
impls). The GHA workflow itself ships separately once an
integration test that needs root validation lands — there's no
test in-tree that uses `require_module!` yet, so the workflow
would be a no-op.

### Docs — Plan 142 consolidates the 0.15.0 typed-API completion arc

- New master plan `142-zero-legacy-typed-api-plan.md` (deleted
  post-0.15.0; substance lives in this CHANGELOG section)
  consolidated Plans 133 PR C / 138 / 139 / 140 / 141 into a
  single 0.15.0 milestone. Defined the end-state typed API,
  formalized the `parse_params` / fluent-builder / typed-dispatch
  patterns that emerged from the 0.14.0 typed-units rollout, and
  made the **legacy-removal milestone** unambiguous:
  `tc::builders::{class,qdisc,filter,action}` and
  `tc::options/*` are deleted from the source tree as Phase 4
  of the plan, with concrete acceptance criteria a PR must hit.
- New top-level `CLAUDE.md` section "TC API conventions"
  documents the patterns: typed config builder shape,
  `parse_params` strictness contract, the `ParseParams` trait
  (lands in Plan 142 Phase 0), the `try_typed_X` dispatch
  shape, the deliberate "no clap `value_parser` until Phase 4"
  rationale, and the typed-error policy.
- The roadmap, plus Plans 133/135/137/138/139/140/141, all gain
  cross-references to Plan 142 in their status headers — Plan
  142 is the entry point; the others are phase-level details.
- One new public API previewed: `pub trait ParseParams: Sized`
  (sealed). Lands in Plan 142 Phase 0 alongside Plan 140; one
  impl per shipped typed config (~25 impls forwarding to the
  existing inherent methods). Additive, no breaking change.

No code changes in this commit. Implementation lands in the
phases of Plan 142 across the 0.15.0 cycle.

### Added — `TaprioConfig::parse_params` + bin wiring (slice 15)

- New `TaprioConfig::parse_params` parses the time-aware shaper's
  full grammar:
  - `num_tc` (with 1-16 range check), `map` (16 values).
  - `clockid` (named `CLOCK_TAI` / `CLOCK_REALTIME` / etc., or bare
    integer — reuses the `parse_etf_clockid` helper).
  - `base-time`, `cycle-time`, `cycle-time-extension` (i64 ns).
  - `txtime-delay` (u32 ns).
  - `txtime-assist` / `notxtime-assist` and `full-offload` /
    `nofull-offload` flag pairs, plus a raw `flags <hex>` token for
    advanced use.
  - **`sched-entry <CMD> <gate-mask-hex> <interval-ns>`** —
    structured triple grammar. CMD accepts the long names
    (`SET_AND_HOLD`), short names (`HOLD`), and single-letter
    aliases (`H`); also lowercase variants. Multiple `sched-entry`
    tokens append to the schedule.
  - `queues <count@offset>` is rejected with the same "not parsed
    yet" message as `MqprioConfig` — pair grammar deferred.
- `bins/tc/src/commands/qdisc.rs` known-kinds list grew from 17 to
  18 (+ taprio). **The qdisc side is now 100% typed-first** — every
  kind that has a typed `QdiscConfig` is also dispatched through
  the typed parser path.
- 8 new unit tests cover empty / typical (multi-entry schedule) /
  cmd aliases (SET/S/HOLD/H/RELEASE/R) / short sched-entry / flag
  pairs vs raw `flags` / queues rejection / unknown tokens /
  invalid sched-entry cmd. Lib went 585 → 593; clippy clean.
- Verified interactively: a full taprio config with two
  sched-entry triples reaches the netlink layer; `sched-entry
  BOGUS 0x1 100` fails with `taprio: invalid sched-entry cmd
  "BOGUS" (expected SET / HOLD / RELEASE)`.
- **Net new CLI capability**: the legacy qdisc dispatcher silently
  swallowed `taprio`.

### Added — five more parsers + bin wiring (slice 14)

- New `parse_params` methods on five more typed configs:
  - **Qdisc**:
    - `PlugConfig::parse_params` — `limit <bytes>`.
    - `MqprioConfig::parse_params` — `num_tc`, `map` (16 values),
      `hw`/`nohw`. The `queues <count@offset>` token is rejected
      with a "not parsed yet" message — that grammar would need its
      own pair-parser.
    - `EtfConfig::parse_params` — `delta`, `clockid` (named
      constants like `CLOCK_TAI` or bare integer), and three flag
      pairs (`deadline_mode`, `offload`, `skip_sock_check`).
  - **Filter**:
    - `CgroupFilter::parse_params` — `chain <n>` only. A bare
      `cgroup` filter without ematch matches every cgrouped
      packet, which is rarely useful; the interesting
      `cgroup CGRP_ID` matches need ematch (Plan 133 PR C).
    - `FlowFilter::parse_params` — `keys <csv>` (comma-separated
      `FlowKey` names like `src,dst,proto`), `hash`/`map` mode,
      `baseclass`, `divisor`, `perturb`, `rshift`, `addend`,
      `mask`/`xor` (hex-or-decimal), `chain`.
- `bins/tc/src/commands/qdisc.rs` known-kinds list grew from 14 to
  17 (+ plug, mqprio, etf). All long-tail qdisc kinds except taprio
  now route through typed dispatch.
- `bins/tc/src/commands/filter.rs` known-kinds list grew from 5 to
  7 (+ cgroup, flow). All long-tail filter kinds except u32 and
  basic now route through typed dispatch.
- 22 new unit tests across the five (3 plug + 5 mqprio + 5 etf +
  3 cgroup + 6 flow). Lib went 563 → 585; clippy clean
  workspace-wide.
- Verified interactively: `tc qdisc add dummy0 ... plug limit 10k`,
  `etf delta 300000 clockid CLOCK_TAI offload`, `tc filter add ...
  flow keys src,dst hash baseclass 1:1`, `cgroup chain 5` all reach
  the netlink layer through the typed dispatchers.
- **Net new CLI capability** for plug/mqprio/etf/cgroup/flow — the
  legacy CLI silently swallowed all of them (qdisc dispatcher's
  `_ =>` arm had no case for plug/mqprio/etf; filter dispatcher's
  `_ =>` arm had no case for cgroup/flow).

### Added — `BpfFilter::parse_params` + bin wiring (slice 13)

- New `BpfFilter::parse_params` recognises `fd <n>` (raw program
  fd), `pinned <path>` (alias `object-pinned`; opens the pinned
  program file and uses its fd; mutually exclusive with `fd`),
  `name <s>` (alias `section`), `direct-action` (alias `da`),
  `classid` / `flowid`, and `chain <n>`.
- **Required**: either `fd` or `pinned` must appear in the params,
  since the kernel won't accept a BPF filter without a program
  reference. The parser returns a clear "program reference
  required" error when neither is present (better than the legacy
  parser, which silently constructed a half-built filter that the
  kernel then rejected with EINVAL).
- `skip_hw` / `skip_sw` are explicitly rejected with a "not
  modelled" message — `BpfFilter` doesn't expose a flags field.
- `bins/tc/src/commands/filter.rs` known-kinds list grew from 4 to
  5 (+ `bpf`).
- 8 new unit tests cover the program-ref-required guard, fd, full
  set, name/section + flowid + direct-action aliases, mutex check,
  pinned-open-failure surfacing, skip-flags rejection, and unknown
  tokens. Lib went 555 → 563; clippy clean workspace-wide.
- Verified interactively: `tc filter add dummy0 --parent 1:
  --protocol ip --prio 100 bpf` fails with the program-ref-required
  error; `bpf fd 99 da` reaches the netlink layer.

### Added — `RouteFilter::parse_params` + bin wiring (slice 12)

- New `RouteFilter::parse_params` recognises `classid` / `flowid`,
  `to <realm>`, `from <realm>`, `iif <dev>`, and `chain <n>`.
  Action attachment isn't parsed (use the typed builder's
  `with_action` for that).
- `bins/tc/src/commands/filter.rs` known-kinds list grew from 3 to
  4 (+ `route`).
- **Net new CLI capability**: the legacy filter dispatcher's
  `_ => i += 1` arm silently swallowed `route`, so the CLI
  couldn't configure route-filter rules at all before this slice.
- 6 new unit tests cover empty / typical / chain+flowid alias /
  unknown-token / missing-value / invalid-realm. Lib suite went
  549 → 555; clippy clean workspace-wide.
- Verified interactively: `tc filter add dummy0 --parent 1:
  --protocol ip --prio 100 route to 10 from 5 classid 1:10` reaches
  the netlink layer; `route nonsense` fails typed-parser-clean.

### Added — five small qdisc parsers + bin wiring (slice 11)

- New `parse_params` methods on five more typed qdisc configs:
  - `HfscConfig::parse_params` — `default <hex>` only (the per-class
    service-curve work lives on `HfscClassConfig`).
  - `IngressConfig::parse_params` / `ClsactConfig::parse_params` —
    take no parameters; empty slice succeeds, anything else returns
    a clear "takes no parameters" error. Useful for symmetry: the
    bin's typed dispatch can now route ingress / clsact through the
    typed path uniformly.
  - `DrrConfig::parse_params` / `QfqConfig::parse_params` — same
    "no qdisc-level params" shape, but the error message points at
    the per-class config (`DrrClassConfig::quantum`,
    `QfqClassConfig::weight`/`lmax`) so a user trying to put those
    on the qdisc gets a helpful nudge.
- `bins/tc/src/commands/qdisc.rs` known-kinds list grew from 9 to
  14 (+ `hfsc, drr, qfq, ingress, clsact`). The dispatch macro now
  has a typed arm for every classful AQM and the two
  filter-attachment qdiscs.
- 8 new unit tests across the five (4 hfsc + 2 ingress/clsact + 2
  drr/qfq). Lib suite went 541 → 549; clippy clean workspace-wide.
- Verified interactively: `tc qdisc add dummy0 --parent root
  --handle 1: hfsc default 30` and `tc qdisc add dummy0 ingress`
  both reach the netlink layer; `tc qdisc add dummy0 ingress
  garbage` fails with `ingress: takes no parameters (got
  "garbage")`.

### Added — `RedConfig` + `PieConfig` parse_params + bin wiring (slice 10)

- New `parse_params` methods on two more typed AQM qdisc configs:
  - `RedConfig::parse_params` — `limit` / `min` / `max` (tc-style
    sizes), `probability` (0-100% mapped to the kernel's 0-255
    scale), and three flag pairs: `ecn`/`noecn`, `harddrop`/
    `noharddrop`, `adaptive`/`noadaptive`. The classic
    `avpkt`/`burst`/`bandwidth` tokens are rejected with a "not
    modelled" error since `RedConfig` doesn't carry those.
  - `PieConfig::parse_params` — `target`/`tupdate` (tc-style
    times), `limit`/`alpha`/`beta` (integers), and the
    `ecn`/`noecn`, `bytemode`/`nobytemode` flag pairs.
- **Net new CLI capability**: the legacy parser silently swallowed
  unknown qdisc kinds (its `add_qdisc_options` match arm has no
  case for `red` or `pie`), so the CLI couldn't use these at all
  before. The typed dispatch now routes them through
  `Connection::add_qdisc_full` with the typed config.
- `bins/tc/src/commands/qdisc.rs` known-kinds list grew from 7 to
  9 (htb, netem, cake, tbf, sfq, prio, fq_codel, **red, pie**).
- 11 new unit tests (6 red + 5 pie) covering empty-yields-default,
  thresholds-with-size-suffixes (red), probability mapping, all
  three flag pairs (red), typical-set (pie), flag pairs (pie),
  unsupported-features-rejected (red avpkt/burst/bandwidth),
  unknown tokens, and invalid time/probability values. Lib suite
  went 530 → 541; clippy clean workspace-wide.
- Verified interactively: `tc qdisc add dummy0 --parent root
  --handle 1: red limit 100k min 10k max 30k probability 50 ecn`
  and `tc qdisc add dummy0 --parent root --handle 1: pie target
  15ms ecn` both reach the netlink layer (and fail at the
  interface lookup as expected for a non-existent `dummy0`).

### Added — `MatchallFilter` + `FwFilter` parse_params + bin wiring (slice 9)

- New `parse_params` methods on two more typed filter configs:
  - `MatchallFilter::parse_params` — `classid` / `flowid`,
    `chain`, `goto_chain`, `skip_hw` / `skip_sw`. Stricter than the
    legacy parser (which only recognised classid / flowid and
    silently dropped everything else).
  - `FwFilter::parse_params` — `classid` / `flowid`, `mask` (0x-prefix
    means hex, otherwise decimal — matches `parse_hex_or_dec`'s
    semantics, avoids the bare-hex-vs-decimal ambiguity that would
    silently flip "255" to 0x255), `chain`.
- `bins/tc/src/commands/filter.rs` `try_typed_filter` now dispatches
  via the same `dispatch!` macro pattern as the qdisc side. Known
  filter kinds grew from 1 to 3: flower, matchall, fw. Long-tail
  kinds (u32, basic, bpf, cgroup, route, flow) still fall through
  to the legacy `filter_builder::*` path. New helper
  `run_typed_filter` factors the verb dispatch out of the macro
  body for clarity.
- 13 new unit tests (7 matchall + 6 fw) covering empty / classid /
  flowid alias / chain+goto_chain / skip flags / unknown-token /
  missing-value / mask-hex / mask-decimal / invalid-mask. Lib
  suite went 517 → 530; clippy clean workspace-wide.
- Verified interactively: `matchall garbage_token` → `matchall:
  unknown token "garbage_token"`; valid matchall/fw params reach
  the netlink layer.

### Added — three more typed qdisc parsers + bin wiring (slice 8)

- New `parse_params` methods on three more typed qdisc configs:
  - `SfqConfig::parse_params` — `quantum`, `perturb`, `limit`. The
    legacy `divisor` token is rejected ("not modelled by SfqConfig")
    until the typed config grows that field.
  - `PrioConfig::parse_params` — `bands`, `priomap` (exactly 16
    values; the legacy parser silently ignored short maps, the typed
    one returns a clear "requires exactly 16 values, got N" error).
  - `FqCodelConfig::parse_params` — `limit`, `target`, `interval`,
    `flows`, `quantum`, `ce_threshold`, `memory_limit`, plus the
    `ecn` / `noecn` flag pair.
- `bins/tc/src/commands/qdisc.rs` `try_typed_qdisc` now dispatches
  these three new kinds via the same `dispatch!` macro as before.
  The known-kinds list grew from 4 to 7: htb, netem, cake, tbf, sfq,
  prio, fq_codel. Long-tail kinds (ingress, clsact, red, pie, hfsc,
  drr, qfq, mqprio, taprio, etf, plug, etc.) still fall through to
  the legacy `qdisc_builder::*`.
- 17 new unit tests across the three configs (6 sfq + 5 prio + 6
  fq_codel) covering empty-yields-default, typical-set,
  unknown-token, missing-value, invalid-value, plus per-config
  specifics (sfq's quantum-with-size-suffix and divisor rejection;
  prio's full-priomap and short-priomap-error; fq_codel's
  ecn/noecn toggle and ce_threshold). Lib suite went 500 → 517;
  clippy clean workspace-wide.
- Verified interactively: `tc qdisc add dummy0 --parent root --handle
  1: sfq nonsense_token foo` now fails with `sfq: unknown token
  "nonsense_token"`; valid params reach the netlink layer.

### Changed — `bins/tc` filter subcommand: typed dispatch for `flower` (slice 7)

- `bins/tc/src/commands/filter.rs` now dispatches typed for the
  `flower` filter kind, calling `Connection::add_filter_full` /
  `del_filter` / `replace_filter_full` / `change_filter_full`
  directly with typed `TcHandle` parents and a typed
  `FlowerFilter`. Long-tail kinds (u32, matchall, basic, fw, bpf,
  cgroup, route, flow) still fall through to the deprecated
  `filter_builder::*` legacy path.
- New private helpers in `filter.rs`:
  - `try_typed_filter(verb)` — checks `kind == "flower"`, parses
    parent + protocol, builds `FlowerFilter::parse_params`, calls
    the right `Connection` verb. Returns `None` for non-flower
    kinds, `Some(Err)` if the typed parser rejects params on a
    flower call (the error surfaces rather than getting masked by
    the legacy fallback). `Del` mirrors the same fallback shape:
    if either protocol or prio is missing, the legacy
    `filter_builder::del` (which knows how to handle the holes)
    runs instead.
  - `parse_protocol_u16(s)` — wraps the deprecated
    `filter_builder::parse_protocol` (the protocol-name table
    we'd otherwise duplicate) and surfaces the result via
    `nlink::Error`.
- **Typo-on-flower surfaces cleanly**: `tc filter add dummy0
  --parent 1: --protocol ip --prio 100 flower nonsense_token foo`
  now fails with `flower: unknown token "nonsense_token"` instead
  of being silently swallowed. **Long-tail kinds (e.g. u32) still
  work unchanged** via the legacy fallback (verified
  interactively — `u32` reaches the netlink layer as expected).
- `#[allow(deprecated)]` on `filter_builder` import stays — comment
  updated to "only used as the long-tail fallback" so the next
  contributor sees that flower took the load.

### Changed — `bins/tc` qdisc subcommand: typed dispatch for known kinds (slice 6)

- `bins/tc/src/commands/qdisc.rs` now dispatches typed for the four
  qdisc kinds with `parse_params` (htb, netem, cake, tbf), calling
  `Connection::add_qdisc_full` / `del_qdisc_full` / `replace_qdisc_full`
  / `change_qdisc_full` directly with typed `TcHandle` parents and
  the appropriate typed config. Long-tail kinds (sfq, prio, fq_codel,
  ingress, etc.) still fall through to the deprecated
  `qdisc_builder::*` legacy path.
- New private helpers in `qdisc.rs`:
  - `parse_qdisc_handles(parent, handle)` — typed handle parsing
    with clear-error wrapping. Returns `Err` cleanly so the caller
    can fall back to the legacy path on failure (which has its own
    handle parser).
  - `try_typed_qdisc(verb)` — checks the kind against the four
    known names; if known, parses handles + the typed config, then
    runs the verb via `run_typed_qdisc`. Returns `None` for
    unknown kinds (caller falls back to legacy).
  - `run_typed_qdisc(cfg, verb)` — generic-over-`QdiscConfig`
    helper that picks the right `Connection::*_qdisc_full` method
    by `QdiscVerb` tag.
- **Typo-on-known-kind surfaces cleanly**: `tc qdisc add dummy0
  --parent root --handle 1: htb default_class 0x10` now fails with
  `htb: unknown token "default_class" (expected default, r2q, or
  direct_qlen)` instead of being silently ignored as the legacy
  parser used to do. **Long-tail kinds (e.g. sfq) still work
  unchanged** via the legacy fallback.
- `#[allow(deprecated)]` on `qdisc_builder` import stays — comment
  updated to "only used as the long-tail fallback" so the next
  contributor knows the typed path took the load.

### Added — `TbfConfig::parse_params` (typed-units rollout, slice 5)

- New method `TbfConfig::parse_params(&[&str]) -> Result<Self>` parses
  a tc-style tbf params slice directly into the typed config.
  Recognises every token the typed config can model: `rate <rate>`
  (uses `Rate::parse` for correct units, no bits/bytes confusion),
  `peakrate <rate>`, `burst <bytes>` (aliases `buffer`, `maxburst`),
  `limit <bytes>`, `mtu <bytes>` (alias `minburst`).
- **Honest scope-mismatch error** for the `latency` token —
  `tc(8)` accepts it as a derived form (`limit ≈ rate * latency`),
  but `TbfConfig` only stores the raw `limit`. The parser rejects
  `latency` with a clear message pointing at
  `tc::options::tbf::build` or telling callers to compute the limit
  themselves.
- `mtu`/`minburst` overflow is also caught: tc-style sizes are u64
  but `TbfConfig::mtu` is u32, so values >4 GB return a clear error
  rather than silently truncating.
- 9 new unit tests cover empty / typical-set (rate+burst+limit) /
  burst aliases / mtu alias / peakrate / latency-rejected /
  unknown-token / missing-value / invalid-rate. Lib suite hit a
  round 500.

### Added — `CakeConfig::parse_params` (typed-units rollout, slice 4)

- New method `CakeConfig::parse_params(&[&str]) -> Result<Self>`
  parses a tc-style cake params slice directly into the typed
  config. Recognises every token the typed config can model:
  `bandwidth` / `unlimited`, `rtt`, `target`, `overhead` (signed
  i32), `mpu`, `memlimit`, `fwmark` (hex), the 5 diffserv flag
  tokens (`diffserv3`/`4`/`8`, `besteffort`, `precedence`), the 8
  flow-isolation tokens (`flowblind`, `srchost`, `dsthost`,
  `hosts`, `flows`, `dual-srchost`, `dual-dsthost`,
  `triple-isolate`), the 3 ATM tokens (`noatm`, `atm`, `ptm`), the
  3 ACK-filter tokens (`ack-filter`, `ack-filter-aggressive`,
  `no-ack-filter`), and the boolean flag pairs (`raw`,
  `nat`/`nonat`, `wash`/`nowash`, `ingress`/`egress`,
  `split-gso`/`no-split-gso`, `autorate-ingress`).
- Stricter than `tc::options::cake::build`: unknown tokens (e.g.
  `dual_srchost` typo'd with underscore instead of hyphen),
  missing values, and unparseable rate / time / size / integer
  values all return `Error::InvalidMessage` rather than being
  silently skipped.
- 15 new unit tests cover empty / bandwidth+rtt / unlimited / each
  diffserv mode / each flow mode / each atm mode / each ack-filter
  variant / boolean flags with negations / signed overhead /
  memlimit size / fwmark hex (with and without `0x` prefix) /
  realistic combo / unknown-token (including the underscore typo) /
  missing values / invalid values.

### Fixed — units bug in `NetemConfig::parse_params` `rate` token

- `NetemConfig::parse_params(["rate", "100mbit"])` was returning a
  `Rate` of 100 MB/sec (= 800 Mbit) instead of 12.5 MB/sec
  (= 100 Mbit) because it routed the legacy `get_rate` (which
  returns bits) through `Rate::bytes_per_sec`. Caught while
  writing `CakeConfig::parse_params` against the same pattern.
  Both now use `Rate::parse` (the typed parser that handles the
  unit conversion correctly), and the netem test asserts the exact
  bytes/sec round-trip so future regressions trip the test.

### Added — `FlowerFilter::parse_params` (typed-units rollout, slice 3)

- New method `FlowerFilter::parse_params(&[&str]) -> Result<Self>`
  parses a tc-style flower params slice directly into the typed
  filter. Recognises every match the typed filter can model:
  `classid` / `flowid`, `ip_proto` (named or numeric),
  `src_ip` / `dst_ip` (v4 or v6, with optional prefix; sets
  `eth_type` implicitly), `src_port` / `dst_port`,
  `src_mac` / `dst_mac`, `eth_type` (named or hex),
  `vlan_id` / `vlan_prio` (with range validation),
  `ip_tos` / `ip_ttl` (val[/mask]), `tcp_flags` (val[/mask]),
  `skip_hw` / `skip_sw`.
- **Honest scope-mismatch errors** for syntax `FlowerFilter` doesn't
  yet model: `ct_state`, `ct_zone`, `ct_mark`, `enc_key_id`,
  `enc_dst_ip`, `enc_src_ip`, `enc_dst_port`, `indev`. Each
  rejection points at `tc::builders::filter` so callers know the
  fallback path.
- Six new private helpers (`parse_flower_ip_proto`,
  `parse_flower_eth_type`, `parse_ipv4_with_prefix`,
  `parse_ipv6_with_prefix`, `parse_mac`, `parse_value_mask_u8`,
  `parse_value_mask_u16_hex`) handle the per-field parsing with
  context-bearing error messages.
- 22 new unit tests cover the empty, classid, flowid alias, ip_proto
  by name and numeric, ports, IPv4/IPv6 with-and-without prefix,
  MAC, eth_type by name and hex, vlan_id+prio (with out-of-range
  error), ip_tos with-mask and bare-implies-mask-ff, skip_hw/sw,
  unknown tokens, all 8 unsupported features, missing values,
  invalid MACs, and out-of-range prefixes. Lib suite went 454 →
  476; workspace clippy clean; all unit-testable as a regular user.

### Added — `NetemConfig::parse_params` (typed-units rollout, slice 2)

- New method `NetemConfig::parse_params(&[&str]) -> Result<Self>`
  parses a tc-style netem params slice directly into the typed
  config. Recognises every token the typed config can model:
  `delay <time> [<jitter> [<corr>]]` (alias `latency`), `loss
  [random] <pct> [<corr>]` (alias `drop`), `duplicate <pct>
  [<corr>]`, `corrupt <pct> [<corr>]`, `reorder <pct> [<corr>]`,
  `gap <n>`, `rate <rate>`, `limit <packets>`.
- **Honest scope-mismatch errors** for syntax the typed config
  doesn't yet model. `NetemConfig` lacks fields for `slot`, `ecn`,
  `distribution`, the 4-state `loss state` Markov model, the
  `loss gemodel` form, and the positional `rate` extras
  (`packet_overhead` / `cell_size` / `cell_overhead`) — the parser
  rejects each with a clear message pointing at
  `tc::options::netem::build` (the legacy stringly-typed parser
  that does cover them) so callers know exactly where the line is.
- Stricter than the legacy parser otherwise: unknown keywords,
  missing values, and unparseable time/rate/percent/integer values
  all return `Error::InvalidMessage`.
- 14 new unit tests. Lib suite 440 → 454; clippy clean
  workspace-wide; all unit-testable as a regular user.

### Added — `HtbQdiscConfig::parse_params` (typed-units rollout, slice 1)

- New method `HtbQdiscConfig::parse_params(&[&str]) -> Result<Self>`
  parses a tc-style params slice (`["default", "1:10", "r2q", "5",
  "direct_qlen", "1000"]`) directly into a typed config. Recognises
  the same `default` / `r2q` / `direct_qlen` tokens as the legacy
  `nlink::tc::options::htb::build`, and accepts both forms of the
  `default` value (tc handle `1:10` or bare hex `10`, matching
  `tc(8)`).
- **Stricter error model than the legacy parser:** unknown tokens,
  keys missing their value, and unparseable numbers all return
  `Error::InvalidMessage` with a clear context-bearing message. The
  legacy `tc::options::htb::build` silently swallowed unknown tokens
  (so a typo like `default_class` for `default` did nothing
  visible) — the typed parser rejects it.
- 8 new unit tests cover the empty / handle / bare-hex / all-three /
  unknown-token / missing-value / invalid-number / invalid-default
  cases. Lib suite: 440 pass; clippy clean workspace-wide.

This is the first slice of the design path captured in commit
`8013d3a`: per the roadmap, `bins/tc/src/commands/qdisc.rs` will
later dispatch on `kind` and call `HtbQdiscConfig::parse_params`
(plus equivalents on `NetemConfig`, `CakeConfig`, etc. as they're
written) to construct typed configs and call
`Connection::add_qdisc_full` directly — replacing the deprecated
`tc::builders::qdisc::add` path entirely. No bin changes in this
commit; the parser is in place for the next slice to consume.

### Changed — `bins/tc`: `class` subcommand off the deprecated legacy path

- `bins/tc/src/commands/class.rs` no longer imports
  `nlink::tc::builders::class`. `add` / `del` / `change` / `replace`
  now call `Connection::{add,del,change,replace}_class` directly,
  which take typed `TcHandle` for `parent` / `classid` (parsed at CLI
  time via `TcHandle::from_str`) and pass `&[&str]` params through
  to the same kernel-encoder the legacy builder used. Net effects:
  - Invalid handles are caught at CLI parse time with a typed error
    (`Error: InvalidMessage("invalid parent `garbage`: ...")`)
    instead of failing deep in the legacy string-splitter.
  - The `#[allow(deprecated)]` scope on `impl ClassCmd` is gone — the
    file is clippy-clean under `--deny warnings` without suppression.
  - No behaviour change: the per-kind options parser
    (`add_class_options`, same codepath the legacy builder called) is
    reused verbatim.
- New local helper `parse_handles(parent, classid)` centralises the
  two-handle parse with clear-error wrapping; it's the shape the
  other three command files (`qdisc`, `filter`, `action`) will
  borrow when they migrate.
- Plan 137-family roadmap row for "Workspace-wide typed-units rollout"
  advances from "deprecation added" to "class migrated; qdisc +
  filter unblocked; action still blocked on typed standalone-action
  CRUD".

### Deprecated — legacy `tc::builders::{class, qdisc, filter, action}`

- `nlink::tc::builders::class` / `qdisc` / `filter` / `action` are now
  annotated `#[deprecated(since = "0.14.0", ...)]`. These are the
  original string-args TC builders (take `&str` parent/classid and
  `&[String]` params, re-split inside). Typed replacements are:
  - `Connection::add_class_config` + `HtbClassConfig` / etc.
  - `Connection::add_qdisc(_full)` + `HtbQdiscConfig` / `CakeConfig` /
    `NetemConfig` / `FqPieConfig` / `TbfConfig` / ...
  - `Connection::add_filter` + `FlowerFilter` / `U32Filter` / ...
  - For filter-attached actions: `FilterConfig::actions(...)` +
    `GactAction` / `MirredAction` / ... Standalone shared-action CRUD
    on `Connection` is not yet typed — the `action` module stays until
    that API is designed.
- Audit is clean: zero library / test / example usage. The only
  consumer is `bins/tc/`, whose four command files now carry scoped
  `#[allow(deprecated)]` on the use statements + the `impl Cmd`
  blocks, each with a `TODO(0.15+)` comment pointing at the typed
  replacement. Workspace-wide `cargo clippy --all-targets -- --deny
  warnings` stays green.
- Module-level docs on `tc::builders::mod` now include the migration
  table so readers landing there from the deprecation note can find
  the typed equivalent immediately.

### Changed — `conntrack-programmatic` recipe gains an Events section

- `docs/recipes/conntrack-programmatic.md` extended with a
  "Subscribing to events" section showing the `subscribe` →
  `events()` → `StreamExt::next` loop, plus four sub-sections that
  capture the gotchas the example surfaced: `subscribe_all` vs
  targeted groups, the `New` covers updates caveat, the
  mutation-and-subscription-on-the-same-connection trap (use two
  connections), and the kernel multicast buffer overrun behaviour.
- The recipe's "Don't use it when" block no longer warns that events
  aren't supported (PR B has shipped); it now points readers at the
  new section for live monitoring.
- See-also gains pointers to `ConntrackEvent` / `ConntrackGroup` and
  both `--apply` example binaries.

### Added — Plan 137 PR B: `netfilter_conntrack_events` example

- New example `netfilter_conntrack_events` exercises the multicast
  subscribe + EventSource wire path end-to-end. Modes:
  - default → usage + code skeleton + the New-vs-Update caveat.
  - `watch` → root-gated host subscription, prints events forever.
  - `--apply` → in a temp namespace, opens two `Connection<Netfilter>`
    (one subscribed, one for mutation), injects a TCP entry, deletes
    it by ID, asserts at least 1 NEW + 1 DESTROY event arrived in a
    3-second window. Validated against Linux 6.19: same kernel-
    assigned ID round-trips through both the inject ACK and the
    multicast NEW notification, confirming the parser handles
    back-to-back multicast frames.

### Added — Plan 137 PR B: ctnetlink event subscription

- `nlink::netlink::netfilter::ConntrackEvent` — `#[non_exhaustive]`
  enum with `New(ConntrackEntry)` and `Destroy(ConntrackEntry)`
  variants. Update notifications come through as `New` because the
  kernel uses `IPCTNL_MSG_CT_NEW` for both creation and update wire
  shapes; subscribe to only `ConntrackGroup::Update` if you need
  update isolation.
- `nlink::netlink::netfilter::ConntrackGroup` — typed enum for the
  conntrack multicast groups (`New=1`, `Update=2`, `Destroy=3`,
  `ExpNew=4`, `ExpDestroy=6`). `to_kernel_group()` exposes the raw
  group ID for advanced callers. The `ExpNew` / `ExpDestroy`
  variants are present so `subscribe()` can be called with them, but
  the parser ignores expectation messages until Plan 137 PR C lands
  the `ct_expect` shape.
- `Connection<Netfilter>::subscribe(&[ConntrackGroup])` and
  `subscribe_all()` — wire `add_membership` calls with the right
  kernel group IDs. `subscribe_all` covers `New + Update + Destroy`
  (skips the expectation groups).
- `EventSource for Netfilter` — implements the existing trait so
  `Connection<Netfilter>::events()` and `into_events()` return
  `Stream<Item = Result<ConntrackEvent>>`. Reuses the dump-side
  parser that already handles every `ConntrackEntry` field.
- 6 new unit tests under `netlink::netfilter::tests`:
  `conntrack_group_kernel_ids`, `parse_event_new_classifies_as_new`,
  `parse_event_delete_classifies_as_destroy`,
  `parse_event_ignores_unknown_subsystem`,
  `parse_event_ignores_unknown_ctnetlink_msg`,
  `parse_event_back_to_back_frames` (the multicast-coalesced case).
- Internal refactor: split the conntrack parser body into a
  `pub(crate) fn parse_conntrack_body(body)` so both the dump path
  and the multicast event path share the attribute parsing without
  re-implementing the nfgenmsg-skip dance.

Integration tests, an `examples/netfilter/conntrack_events.rs`
binary, and a recipe entry are deferred to follow-up commits — they
need the same `lab` plumbing as Plan 137 PR A's integration-test
slice, so they should land together.

### Added — Plan 137 PR A (slice 3): netfilter_conntrack example promotion

- `examples/netfilter/conntrack.rs` rewritten from a query-only dump
  formatter into a Plan 136 §1-shaped lifecycle demo. New modes:
  - default → prints usage + a copy-pasteable code skeleton.
  - `show` → keeps the old dump display (still requires
    `CAP_NET_ADMIN` for unprivileged hosts).
  - `--apply` → root-gated lifecycle inside a temporary namespace:
    inject TCP/ESTABLISHED, dump and verify by tuple, update mark +
    timeout in place, delete by ID, inject UDP, delete by tuple,
    inject 2 more, flush. Each step is asserted so the binary
    doubles as a wire-format smoke test.

### Changed — `Netfilter` derives `Default`

- `nlink::netlink::Netfilter` now derives `Default` (it's a ZST, no
  semantic change). This unblocks the generic
  `Connection::<Netfilter>::new()` constructor (already worked) *and*
  the `namespace::connection_for::<Netfilter>(name)` /
  `LabNamespace::connection_for::<Netfilter>()` paths, neither of
  which compiled before. The previous custom `Connection::<Netfilter>::new()`
  inherent method has been removed in favour of the now-applicable
  generic — same wire result, no caller-visible breakage.

### Added — Plan 137 PR A (slice 2): conntrack-programmatic recipe

- `docs/recipes/conntrack-programmatic.md` — end-to-end walkthrough of
  the new ctnetlink write API: inject a synthetic TCP/ESTABLISHED
  entry, dump it back, update mark + timeout in place, delete by ID,
  delete by tuple, flush. Covers asymmetric/NAT'd flows (explicit
  reply tuple + `SRC_NAT` flags) and per-zone scoping. Caveats cover
  `nf_conntrack` autoload, the `CONFIRMED` mandatory flag, and the
  `EEXIST`/`ENOENT` semantics of `add` / `del`.
- Recipe index updated with a Firewalling entry.

### Added — Plan 137 PR A (slice 1): ctnetlink mutation API

- `nlink::netlink::netfilter::ConntrackBuilder` — typed builder for
  injecting / replacing / deleting conntrack entries. `new_v4` /
  `new_v6` constructors lock the address family at the type-state
  level. Supports `orig` / `reply` tuples, `status`, `timeout`,
  `mark`, `tcp_state`, `id`, and `zone`. If `reply` is unset on
  `add_conntrack`, the orig tuple is auto-mirrored (correct for
  symmetric flows without NAT).
- `nlink::netlink::netfilter::ConntrackStatus` — bitflags-style flags
  for the `IPS_*` enum (`CONFIRMED`, `SEEN_REPLY`, `ASSURED`,
  `SRC_NAT`, etc.) with `bitor` and `contains`. The kernel rejects
  injections without `CONFIRMED`.
- `ConntrackTuple::v4` / `v6` / `ports` / `icmp` / `mirror` —
  ergonomic constructors so callers don't have to populate the
  field-by-field struct literal.
- `TcpConntrackState::to_u8` (private) — wire encoding for
  `CTA_PROTOINFO_TCP_STATE`.
- New `Connection<Netfilter>` methods:
  - `add_conntrack(ConntrackBuilder)` — `IPCTNL_MSG_CT_NEW` with
    `NLM_F_CREATE | NLM_F_EXCL`, returns `Error::AlreadyExists` if
    the tuple is taken.
  - `update_conntrack(ConntrackBuilder)` — same wire shape with
    `NLM_F_CREATE | NLM_F_REPLACE`, for in-place timeout / mark /
    state nudges.
  - `del_conntrack(ConntrackBuilder)` — `IPCTNL_MSG_CT_DELETE` by
    tuple. Status / timeout / mark / protoinfo are intentionally
    elided since the kernel ignores them on the delete path.
  - `del_conntrack_by_id(u32)` — delete by the kernel-assigned ID
    returned in `ConntrackEntry::id`.
  - `flush_conntrack()` / `flush_conntrack_v6()` — flush the entire
    family table (matches `conntrack -F`).
- 9 new unit tests under `netlink::netfilter::tests` covering wire
  format round-trips (v4 TCP with auto-mirrored reply, v6 UDP, the
  delete-elides-status invariant), `ConntrackStatus` bitor / contains,
  `TcpConntrackState::to_u8` round-trip, `ConntrackTuple::mirror`
  symmetry, and the `(subsystem << 8) | msg` packing of `ctnl_msg_type`.

Integration tests, the `examples/netfilter/conntrack.rs` example
promotion, and the `docs/recipes/conntrack-programmatic.md` recipe
are deferred to follow-up commits in this PR — they need `lab`-feature
plumbing + `nf_conntrack` autoload that's out of scope for the
wire-format slice.

### Added — Plan 135 PR B: `nftables-stateful-fw` recipe

- `docs/recipes/nftables-stateful-fw.md` — drop-by-default `inet` table
  with stateful `ct state established,related` shortcut, per-service
  allows (SSH/HTTPS/ICMP-rate-limited), set-backed blocklist, plus a
  3-namespace WAN/router/LAN lab demo that asserts the asymmetric
  ping result. Uses `Transaction::commit` for atomic install and
  `Connection::<Netfilter>::get_conntrack` for state verification.
  Caveats cover `nf_conntrack` autoload, `Family::Inet` vs `Family::Ip`
  for NAT, and the partial-rollback-on-error contract of transactions.
- Recipe index updated; the `nftables-stateful-fw` entry moves out of
  the "Wanted" list.

### Added — `MacsecLink` rtnetlink builder

- `nlink::netlink::link::MacsecLink` — typed rtnetlink builder for
  creating IEEE 802.1AE MACsec interfaces on top of a parent Ethernet
  device. Exposes `sci`, `port`, `encrypt`, `protect`, `include_sci`,
  `end_station`, `scb`, `replay_protect`, `replay_window`, and
  `encoding_sa`; with a `with_parent_index` namespace-safe variant.
  Key material + SA lifecycle remain on the GENL
  `Connection::<Macsec>` API — this builder only creates the
  interface, matching the split used by WireGuard.
- `examples/genl/macsec.rs` now uses `MacsecLink` directly instead of
  shelling out to `ip link add ... type macsec`; the `--apply` flow
  is fully nlink-native. Closes the follow-up captured when the
  example first landed.

### Added — Plan 135 PR B: cookbook recipes

- `docs/recipes/multi-namespace-events.md` — fan-in link/addr/route/TC
  events across N namespaces with `tokio_stream::StreamMap`.
- `docs/recipes/bridge-vlan.md` — VLAN-aware bridge, trunk vs. access
  port shape, VLAN-1-default gotcha, VLAN↔VNI mapping for VXLAN.
- `docs/recipes/bidirectional-rate-limit.md` — HTB egress + IFB ingress
  via `RateLimiter`, with the hand-rolled IFB / mirred / HTB sequence
  for custom filter predicates.
- `docs/recipes/wireguard-mesh.md` — 3-node WireGuard full-mesh in
  `nlink::lab` namespaces using the `Connection::<Wireguard>`
  write-path.
- `docs/recipes/README.md` — index of all recipes + recipe-shape
  template + "wanted" list for contributors.
- `README.md` + `CLAUDE.md` link the recipe index.

Deferred recipes from Plan 135:

- `xfrm-ipsec-tunnel.md` — tracked in the recipes index "Wanted"
  section; skipped in this drop to stay within a reasonable review
  chunk.
- `nftables-stateful-fw.md` — same rationale.
- `cgroup-classification.md` — blocked on Plan 133 PR C (`BasicFilter`
  ematch).

### Added — Plan 135 PR A: public `nlink::lab` module + builders

- New `LabBridge<'a>` builder (`nlink::lab::LabBridge`) that chains
  `create` → `add_port` → `up` with one rtnetlink op per step —
  wraps our `BridgeLink` + `Connection::enslave` /
  `Connection::set_link_up` into a test-friendly fluent interface
  scoped to a `LabNamespace`.
- New `LabVeth<'a>` builder (`nlink::lab::LabVeth`) that creates a
  veth pair with the peer optionally placed in another
  `LabNamespace` — a thin layer over `VethLink::peer_netns()` that
  keeps both interface names around for later use.
- New `examples/lab/three_namespace.rs` — builds an hq/alpha/beta
  topology with a bridge on hq connected to each client via veth.
  Default mode prints the topology diagram; `--apply` runs the real
  setup inside three transient namespaces. Registered in Cargo.toml
  with `required-features = ["lab"]`.

### Added — Plan 135 PR A: public `nlink::lab` module

- New `nlink::lab` module, gated behind a `lab` feature flag. Promotes
  the `TestNamespace` helper (previously private in
  `crates/nlink/tests/common/mod.rs`) to a public, reusable API:
  - `LabNamespace::new(prefix)` creates an ephemeral namespace with a
    PID-suffixed unique name; deletes it on `Drop`. Cleanup failure
    WARNs via `tracing` rather than silently leaking.
  - `LabNamespace::named(name)` for a user-chosen name (errors if it
    already exists).
  - `LabNamespace::connection()` / `connection_for::<P>()` /
    `connection_for_async::<P>()` open netlink sockets scoped to the
    namespace — the generic variants accept `ProtocolState` and
    `AsyncProtocolInit` bounds, both of which are now re-exported at
    `nlink::netlink`.
  - `spawn` / `spawn_output` for running a `std::process::Command`
    inside the namespace via `setns()`.
  - Convenience: `exec`, `exec_ignore`, `connect_to`, `add_dummy`,
    `link_up`, `add_addr`.
- `nlink::lab::with_namespace(prefix, closure)` — async scope-guard
  idiom: create a namespace, run the closure, delete it regardless of
  error/panic.
- `nlink::lab::is_root()` + `nlink::require_root!` /
  `nlink::require_root_void!` macros for skip-if-not-root test
  gating.
- `crates/nlink/tests/common/mod.rs` is now a thin shim that re-exports
  `LabNamespace as TestNamespace` — existing integration tests keep
  their `crate::common::TestNamespace` imports unchanged. The
  `integration` test target now has `required-features = ["lab"]` so
  the binary only builds when the feature is enabled.
- `full` feature set picks up `lab`.

### Changed — Plan 136: `ethtool_rings`, `genl_nl80211`, `genl_devlink` promoted

- `ethtool_rings` gains `--set-rx <N>` / `--set-tx <N>` that snapshot
  the current ring sizes, apply the requested size via `set_rings()`,
  re-query to verify (warning if the driver clamped or rejected),
  then restore the original values. Requires CAP_NET_ADMIN and a
  driver that honors `ETHTOOL_SRINGPARAM`. Mirrors the shape of the
  existing `ethtool_features --toggle` promote.
- `genl_nl80211` gains `--scan <iface>` that triggers an active scan,
  waits up to 15s on the multicast group for `Nl80211Event::ScanComplete`,
  then dumps BSSes (`bssid`, frequency, signal dBm, SSID, privacy
  flag). Inventory mode (default) unchanged.
- `genl_devlink` gains `--reload <bus/device>` that parses the
  devlink path (e.g., `pci/0000:03:00.0`), snapshots the device's
  pre-reload state (info, ports, health reporters), calls
  `reload(ReloadAction::DriverReinit)`, and re-queries to confirm
  the device reappeared. Inventory mode (default) unchanged.

### Changed — Plan 136: `genl_macsec` + `genl_mptcp` examples promoted

- `examples/genl/mptcp.rs` gains a `--apply` mode that creates a
  dummy interface with an IPv4 address in a temporary namespace,
  opens an MPTCP PM GENL connection, adds two endpoints bound to
  the dummy (signal+subflow, signal+backup), sets `subflows` /
  `add_addr_accepted` limits, dumps, flips endpoint #1's flags via
  `set_endpoint_flags`, deletes it, and flushes. `show` subcommand
  retained for read-only probing.
- `examples/genl/macsec.rs` gains a `--apply` mode that creates a
  dummy parent, shells out to `ip link add macsec0 link dummy0
  type macsec` (no `MacsecLink` rtnetlink helper yet — tracked as
  a follow-up), opens a MACsec GENL connection, adds a TX SA, adds
  an RX SC + RX SA for a peer SCI, dumps the device state, and
  cleans up. `show` subcommand lists existing macsec interfaces
  on the host.
- Both examples are now registered in `crates/nlink/Cargo.toml`
  under `[[example]]` — previously they were orphans and couldn't
  be `cargo run`-ed.

### Changed — Plan 136: `genl_wireguard` example promoted to full lifecycle

- `examples/genl/wireguard.rs` gains a `--apply` mode that creates
  `wg0` inside a temporary namespace via rtnetlink (`WireguardLink`),
  configures it through the GENL API (private key + listen port),
  adds a peer (public key + endpoint + allowed-ip + persistent
  keepalive), dumps the device to verify the round-trip, removes the
  peer via `del_peer`, then deletes the namespace. The existing
  read-only probe was kept behind a `show` subcommand. Dropped the
  in-file custom base64 encoder in favor of a short hex preview
  (`abcdef…`) — a demo needs a visual identifier, not a correct
  wg-tool serialization.

### Changed — Plan 136: `route_tc_htb` example promoted to full TC pipeline

- `examples/route/tc/htb.rs` gains a `--apply` mode that builds a 3-class
  HTB tree with two flower filters (UDP/5060 → voice, TCP/1935 → video)
  inside a temporary namespace on a dummy interface, dumps the resulting
  qdisc/class/filter tree, deletes the root qdisc to demonstrate
  cascading cleanup, and removes the namespace. Default-args mode now
  prints the topology diagram + idiomatic code snippet; the existing
  `show <dev>` / `classes <dev>` query subcommands are retained for
  inspecting real devices. Rate formatting uses `Rate::bytes_per_sec(..)`
  's `Display` impl instead of a local helper — one less place that
  could silently confuse units.

### Added — Plan 133 (PR A): typed `CakeConfig` + `CakeOptions` parser

- `CakeConfig` typed qdisc builder for `sch_cake`, the modern
  self-tuning AQM (OpenWrt's default and the `bufferbloat.net`
  recommended setup). Brings cake to typed-builder parity with the
  rest of the qdisc lineup; the legacy string-args interface in
  `tc/options/cake.rs` keeps working for `Connection::add_qdisc("eth0",
  "cake", &["bandwidth", ...])` callers.
- Typed mode enums: `CakeDiffserv` (Diffserv3 / Diffserv4 / Diffserv8
  / Besteffort / Precedence), `CakeFlowMode` (Flowblind / Srchost /
  Dsthost / Hosts / Flows / DualSrchost / DualDsthost / Triple),
  `CakeAtmMode` (None / Atm / Ptm), `CakeAckFilter` (Disabled /
  Filter / Aggressive). All `#[non_exhaustive]`.
- `QdiscOptions::Cake(CakeOptions)` parser variant for dump-side
  inspection, with `bandwidth() -> Option<Rate>`, `rtt() ->
  Option<Duration>`, `target() -> Option<Duration>` accessors. Per-tin
  stats (the cake selling point) are scoped for a follow-up — they
  arrive via `xstats` and need a separate parser.
- `unlimited()` shorthand for the no-shaping mode (encoded as
  bandwidth=0 on the wire).

### Added — Plan 133 (PR D): `BpfAction` + `SimpleAction`

- `BpfAction` — companion to `BpfFilter`. Runs an eBPF program as a
  TC action (vs as a classifier), wrapping a program loaded by
  `aya` / `libbpf-rs` (`from_fd`) or pinned at a filesystem path
  (`from_pinned`). Configurable verdict (`pipe()` / `ok()` / `drop()`
  / `verdict(int)`); default is `TC_ACT_PIPE` so the action chain
  continues after BPF runs.
- `SimpleAction` — `act_simple` debugging action that writes a tagged
  string to the kernel log on every match. Useful for tracing filter
  chains during debugging (watch via `dmesg -w`). Same verdict
  helpers; default `TC_ACT_PIPE`.
- New constant modules `netlink::types::tc::action::{bpf_act,
  simple_act}` carrying the `TCA_ACT_BPF_*` and `TCA_DEF_*`
  attribute sets respectively.

### Added — Plan 133 (PR B): `FqPieConfig`

- `FqPieConfig` typed qdisc builder for `sch_fq_pie` (mainline since
  Linux 5.6). Combines `fq_codel`'s per-flow hashing with PIE's
  proportional-integral AQM — each flow gets its own queue and PIE
  controls per-queue drop probability based on queueing delay.
  Better than `pie` on shared links where elephant flows would
  otherwise crowd out interactive ones.
- `QdiscOptions::FqPie(FqPieOptions)` parser variant in
  `tc_options.rs`, exposing all 12 `TCA_FQ_PIE_*` attributes plus
  ergonomic accessors (`target() -> Option<Duration>`, `tupdate() ->
  Option<Duration>`, `ecn_prob() -> Option<Percent>`).
- Constants module `netlink::types::tc::qdisc::fq_pie` with the full
  `TCA_FQ_PIE_*` attribute set.

### Added — Plan 131: reconcile pattern

- `PerPeerImpairer::reconcile` and `PerHostLimiter::reconcile` —
  non-destructive convergence to the desired TC tree. Dumps the live
  qdiscs / classes / filters on the target interface, diffs against
  the tree the helper would build, and emits the minimum
  `add_*` / `change_*` / `replace_*` / `del_*` operations to
  converge. Calling `reconcile()` twice in a row with no other
  changes makes **zero** kernel calls on the second invocation
  (`ReconcileReport::is_noop()` returns `true`).
- `reconcile_dry_run()` for previewing the change set without
  mutating kernel state, and `reconcile_with_options()` accepting a
  `ReconcileOptions { fallback_to_apply, dry_run }` for finer
  control. By default a wrong-kind root qdisc returns an error;
  `with_fallback_to_apply(true)` opts in to a destructive rebuild
  via `apply()`.
- `ReconcileReport` (re-exported at the crate root) carries
  `changes_made`, `rules_added` / `rules_modified` / `rules_removed`,
  `default_modified`, `root_modified`, `dry_run`, and the
  drift-detection lists `stale_removed: Vec<StaleObject>` and
  `unmanaged: Vec<UnmanagedObject>`. Stale = objects in the helper's
  deterministic handle range that the desired tree no longer
  references (removed). Unmanaged = objects outside that range
  (left alone, surfaced for audit).
- New module `nlink::netlink::tc_recipe` (public types) and
  `tc_recipe_internals` (internal scaffolding: `LiveTree` dump,
  `netem_matches`, `fq_codel_target_matches`,
  `htb_class_rates_match`, `flower_classid`).

`apply()` keeps its destructive contract — recommend new code use
`reconcile()` for repeated calls (k8s operators, lab controllers,
config-tick loops). See `docs/recipes/per-peer-impairment.md` and
the reconcile-loop snippet in `CLAUDE.md`.

## [0.14.0] — skipped

0.14.0 was never published as its own release. Its work
(additive: typed-units rollout, reconcile pattern, ctnetlink
mutation, `MacsecLink`, recipes, `tc::builders::*` deprecation)
shipped together with the 0.15.0 deletion work as a single
release. Upgrading from 0.13.0? Read both
[`docs/migration_guide/0.13.0-to-0.14.0.md`](docs/migration_guide/0.13.0-to-0.14.0.md)
(additive surface) and
[`docs/migration_guide/0.14.0-to-0.15.0.md`](docs/migration_guide/0.14.0-to-0.15.0.md)
(deletion) in order.

## [0.13.0] - 2026-04-19

The 0.13.0 release lands the four foundation plans from the 1.0
roadmap (`128b-roadmap-overview.md`): typed units (Rate / Bytes /
Percent), typed TC handles (TcHandle / FilterPriority), API cleanup
(class-builder wrapper removal + 95-enum non_exhaustive lockdown),
and tracing instrumentation across the whole public surface.

### Added — Plan 134: tracing instrumentation

- nlink now emits `tracing` spans on its high-value entry points:
  `Connection::new` / `new_in_namespace` / `new_in_namespace_path`
  (INFO), `Connection::subscribe` (INFO with the subscribed groups),
  the netlink request/ack/dump inner loops (TRACE with sequence
  numbers + dump response counts + kernel `errno` on failure), and
  the recipe helpers `RateLimiter::{apply,remove}`,
  `PerHostLimiter::{apply,remove}`, `PerPeerImpairer::{apply,clear}`
  (INFO with the device, rule count, and clear-vs-apply intent).
  Wire up a `tracing-subscriber` to see the events:
  `tracing_subscriber::fmt().with_env_filter("nlink=debug").init()`.
  Spans cost a single relaxed atomic load when no subscriber is
  attached (the `tracing` library guarantee).
- A follow-up pass extended instrumentation to the long tail: every
  `pub async fn` on `Connection<Route>`, `Connection<Generic>`, and
  the GENL protocol-specific `Connection<*>` types now carries an
  `#[instrument(level = "debug", skip_all, fields(method = "..."))]`
  (~318 spans total). Filterable via tracing-subscriber's env-filter:
  `RUST_LOG="nlink[method=add_qdisc]=debug"`. Plus INFO span on
  `Connection::<Generic>::get_family` (with `cached` boolean), DEBUG
  span on `Batch::execute` (with `ops` count), and TRACE event on
  every multicast batch parsed by `EventSubscription` /
  `OwnedEventStream`. See `docs/observability.md` for the full
  level conventions and common queries.

### Changed (BC break) — Plan 132: API cleanup

- **`*Built` wrapper types are gone from class builders.**
  `HtbClassConfig::build()`, `HfscClassConfig::build()`,
  `DrrClassConfig::build()`, and `QfqClassConfig::build()` now return
  `Self` instead of a distinct `*Built(Self)` newtype. The
  `HtbClassBuilt`, `HfscClassBuilt`, `DrrClassBuilt`, and
  `QfqClassBuilt` types are removed entirely. Code that named these
  types explicitly needs to use the underlying `*Config` type. Code
  that just chained `.build()` and passed the result to
  `add_class_config(...)` continues to work unchanged.

- **95 public enums are now `#[non_exhaustive]`.** All kernel-defined
  attribute enums (`*Attr`), state enums (`NeighborState`,
  `BondSlaveState`, etc.), type enums (`RouteType`, `RouteScope`,
  `RouteProtocol`, `Family`, `IpProtocol`, `XfrmMode`, etc.), GENL
  command/attribute enums (WireGuard, MACsec, MPTCP, ethtool, nl80211,
  devlink), and nftables enums (`Hook`, `ChainType`, `Priority`,
  `Policy`, `MetaKey`, `CtKey`, etc.) are now non-exhaustive. This
  locks down the API for 1.0: future kernel additions can become new
  variants without breaking downstream code, but exhaustive `match`es
  on these enums now require a wildcard `_ => ...` arm. Adding
  `#[non_exhaustive]` post-1.0 is itself a breaking change, so 1.0 is
  the right moment to err on the side of marking.

### Changed (BC break) — Plan 130: typed TC handles

- **TC handles and parents are now strongly typed via `nlink::TcHandle`
  throughout the public API.** Connection methods, filter builders, and
  `TcMessage` accessors no longer take or return `&str`/`u32` for the
  `(major, minor)` packed values the kernel uses to identify qdiscs,
  classes, and filters. The wire-format integer remains accessible via
  `TcHandle::as_raw()` and `TcMessage::handle_raw()` /
  `TcMessage::parent_raw()` for cases like `HashMap` keys.

  | Old                                                         | New                                                         |
  |---|---|
  | `conn.add_qdisc_full("eth0", "root", Some("1:"), x)`        | `conn.add_qdisc_full("eth0", TcHandle::ROOT, Some(TcHandle::major_only(1)), x)` |
  | `conn.add_class_config("eth0", "1:0", "1:1", x)`            | `conn.add_class_config("eth0", TcHandle::major_only(1), TcHandle::new(1, 1), x)` |
  | `conn.add_filter("eth0", "1:", x)` / `"ingress"` / `"egress"` | `conn.add_filter("eth0", TcHandle::major_only(1), x)` / `TcHandle::INGRESS` / `TcHandle::from_raw(0xFFFF_FFF3)` |
  | `conn.del_qdisc("eth0", "root")`                            | `conn.del_qdisc("eth0", TcHandle::ROOT)`                    |
  | `conn.add_tc_chain("eth0", "ingress", N)`                   | `conn.add_tc_chain("eth0", TcHandle::INGRESS, N)`           |
  | `conn.get_filters_by_parent(iface, "1:")`                   | `conn.get_filters_by_parent(iface, TcHandle::major_only(1))` |
  | `conn.get_qdisc_by_handle("eth0", "1:")`                    | `conn.get_qdisc_by_handle("eth0", TcHandle::major_only(1))` |
  | `U32Filter::new().classid("1:10")` / `.classid_raw(0x10010)` | `.classid(TcHandle::new(1, 0x10))` / `.classid(TcHandle::from_raw(0x10010))` |
  | `FlowerFilter::new().classid(...)` / `MatchallFilter` / `FwFilter` / `BpfFilter` / `BasicFilter` / `RouteFilter` | same — all `.classid(TcHandle)` now, no `.classid_raw()` variant |
  | `FlowFilter::new().baseclass("1:10")` / `.baseclass_id(u32)` | `.baseclass(TcHandle::new(1, 0x10))` (single setter)        |
  | `qdisc.handle() -> u32` (and same for `parent()`)           | `-> TcHandle`. Use `handle_raw()` / `parent_raw()` for the `u32`. |
  | Comparing `c.parent() == 0xffffffff`                        | `c.parent().is_root()` (similarly `is_ingress()`, `is_clsact()`, `is_unspec()`) |

- **The vestigial `.parent(impl Into<String>)` and `.handle(impl
  Into<String>)` setters were removed from all 17 qdisc config
  builders** (`NetemConfig`, `FqCodelConfig`, `TbfConfig`,
  `HtbQdiscConfig`, `PrioConfig`, `SfqConfig`, `RedConfig`, `PieConfig`,
  `PfifoConfig`, `BfifoConfig`, `DrrConfig`, `QfqConfig`, `PlugConfig`,
  `MqprioConfig`, `TaprioConfig`, `HfscConfig`, `EtfConfig`). These
  setters stored values that nothing read — the actual parent and handle
  reach the kernel through the explicit `add_qdisc_full(dev, parent,
  handle, config)` arguments. Old code calling `.handle("1:")` was a
  silent no-op; now it's a compile error pointing you at
  `add_qdisc_full`.

- **`Connection::resolve_parent` is gone** — parsing happens at the call
  site via `TcHandle::from_str` (or the `TcHandle::ROOT` / `INGRESS` /
  `CLSACT` constants), with errors surfaced at parse time instead of as
  generic `Error::InvalidMessage` deep inside the connection plumbing.

- **Bug fix as a side effect of typing:** the BPF clsact attach path
  used to call `tc_handle::parse("egress")`, which returned `None`, so
  egress BPF programs attached at the wrong handle. `BpfDirection::Egress`
  now uses `TcHandle::from_raw(0xFFFF_FFF3)` (the kernel's
  `TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS)`) directly.

### Added — Plan 130

- `nlink::TcHandle` — typed `(major, minor)` packed handle. Constructors
  `new(major, minor)`, `major_only(major)`, `from_raw(u32)`. Constants
  `ROOT`, `INGRESS`, `CLSACT`, `UNSPEC`. Inspectors `major()`, `minor()`,
  `as_raw()`, `is_root()`, `is_ingress()`, `is_clsact()`, `is_unspec()`.
  `FromStr` accepts `"root"`, `"ingress"`, `"clsact"`, `"none"`, `"1:"`,
  `"1:a"`. `Display` round-trips. Re-exported at crate root and from
  `prelude`.
- `nlink::FilterPriority` — typed `u16` filter priority with documented
  bands (operator: 1..=49, recipe: 100..=199, app: 200..=999, system:
  1000..). Helpers in this crate (`PerPeerImpairer`, `PerHostLimiter`)
  install in the recipe band so they don't fight with operator filters.
- `TcMessage::handle_raw()` / `TcMessage::parent_raw()` — escape-hatch
  accessors that return the raw `u32` for callers that genuinely need
  the integer (e.g. as a `HashMap` key).

### Changed (BC break) — Plan 129: typed units

- **TC rates, byte counts, and percentages are now strongly typed via
  `nlink::Rate`, `nlink::Bytes`, and `nlink::Percent` newtypes.** This
  replaces a mix of `u64` (sometimes bits/sec, sometimes bytes/sec),
  `u32` (sometimes packets, sometimes bytes), and `f64` (clamped 0..=100)
  with three concrete types whose constructors are explicit about units
  and whose accessors don't lie. The 8× HTB rate bug fixed in 0.12.x is
  now a compile error.

  | Old                                                | New                                                |
  |---|---|
  | `HtbClassConfig::from_bps(12_500_000)`             | `HtbClassConfig::new(Rate::mbit(100))`             |
  | `HtbClassConfig::new("100mbit")?`                  | `HtbClassConfig::new("100mbit".parse()?)` or `Rate::mbit(100)` |
  | `HtbClassConfig::ceil_bps(u64)` / `.ceil("...")?`  | `.ceil(Rate)`                                      |
  | `HtbClassConfig::burst_bytes(u32)` / `.burst("...")?` | `.burst(Bytes)`                                 |
  | `NetemConfig::rate(bytes_per_sec)` / `rate_bps(bits_per_sec)` / `rate_kbps(_)` / `rate_mbps(_)` / `rate_gbps(_)` | `.rate(Rate)` |
  | `NetemConfig::loss(f64)` / `.duplicate(f64)` / `.corrupt(f64)` / `.reorder(f64)` and the four `*_correlation` methods | `.loss(Percent)` etc. |
  | `RateLimit::new(u64)` / `parse(&str)?`             | `RateLimit::new(Rate)` (parse via `Rate::parse`/`FromStr`) |
  | `RateLimit::ceil(u64)` / `.burst(u32)`             | `.ceil(Rate)` / `.burst(Bytes)`                    |
  | `RateLimiter::egress(&str)?` / `egress_bps(u64)` and the same shape for `ingress` / `burst_to` / `burst_size` | `.egress(Rate)` / `.ingress(Rate)` / `.burst_to(Rate)` / `.burst_size(Bytes)` |
  | `PerHostLimiter::new(dev, &str)?` / `new_bps(dev, u64)` | `PerHostLimiter::new(dev, Rate)` (infallible) |
  | `PerHostLimiter::limit_*(..., &str)?`              | `.limit_*(..., Rate)` — most variants now infallible (only `*_subnet` keep `Result` for subnet parse) |
  | `PerPeerImpairer::assumed_link_rate_bps(u64)`      | `.assumed_link_rate(Rate)`                         |
  | `DEFAULT_ASSUMED_LINK_RATE_BPS: u64`               | `DEFAULT_ASSUMED_LINK_RATE: Rate`                  |
  | `PeerImpairment::rate_cap_bps(u64)` / `.rate_cap(&str)?` | `.rate_cap(Rate)`                             |
  | `PeerImpairment::cap_bps()`                        | `.cap()`                                           |
  | `TbfConfig::rate(u64)` / `rate_bps(u64)` / `peakrate(u64)` | `.rate(Rate)` / `.peakrate(Rate)`         |
  | `TbfConfig::burst(u32)` / `limit(u32)`             | `.burst(Bytes)` / `.limit(Bytes)`                  |
  | `HfscClassConfig::{rt_rate,ls_rate,ul_rate}(u32)`  | `…(Rate)` (saturating-cast to u32 for HFSC's 32-bit kernel field) |
  | `DrrClassConfig::quantum(u32)`                     | `.quantum(Bytes)` (saturating-cast)                |
  | `QfqClassConfig::lmax(u32)`                        | `.lmax(Bytes)` (saturating-cast)                   |

  All `*Built` wrapper types (e.g., `HtbClassBuilt`) are unchanged in
  this round — see Plan 132 (API cleanup) for the wrapper removal.

  `nlink::util::parse::get_rate` and `get_size` remain as the underlying
  parsers and as the public API for the legacy raw-string TC interface
  (`Connection::add_class("eth0", parent, classid, "htb", &["rate",
  "100mbit", ...])`). Their docs now recommend `Rate::parse` /
  `Bytes::parse` for new code.

### Added — Plan 129

- `nlink::Rate` — typed bandwidth (internally bytes/sec). Constructors
  `bytes_per_sec`, `bits_per_sec`, `kbit`, `mbit`, `gbit`, `kibit`,
  `mibit`, `gibit`, `kib_per_sec`, `mib_per_sec`. `Rate::parse` and
  `FromStr` accept tc-style strings (`"100mbit"`, `"1.5gibit"`).
  `Display` round-trips. Saturating arithmetic. `Rate * Duration ->
  Bytes`, `Bytes / Duration -> Rate`. `as_u32_bytes_per_sec_saturating`
  for kernel u32 fields.
- `nlink::Bytes` — typed byte count. `kb`/`mb`/`gb` (decimal),
  `kib`/`mib`/`gib` (binary). `Bytes::parse` / `FromStr` for tc-style
  strings. `as_u32_saturating` for kernel u32 fields.
- `nlink::Percent` — clamped 0..=100 percentage. Construction clamps;
  arithmetic saturates. `as_kernel_probability()` returns `u32` for
  netem qopt fields. `FromStr` accepts `"50%"` / `"50"` / `"0.5"`.
- All three types re-exported at crate root and from `nlink::prelude`.

### Fixed (behavior change)

- **HTB rates from string parsing were 8× too high.** `HtbClassConfig::new(rate)`,
  `HtbClassConfig::ceil(rate)`, `RateLimit::parse(rate)`, `RateLimiter::{egress,
  ingress, burst_to}(rate)`, and `PerHostLimiter::{new, limit_*}(rate)` parsed
  values like `"100mbit"` as bits/sec but stored them in fields the kernel reads
  as bytes/sec — so a "100mbit" rate actually shaped at ~800 Mbps. All affected
  call sites now divide by 8 to convert to bytes/sec, matching the kernel's
  `tc_ratespec.rate` semantics. **Callers who relied on the buggy 8× rate must
  multiply their input by 8 to keep the same wire behavior.**
- **`PerHostLimiter` IPv6 / port-match filters were never matched.** The flower
  filter for `HostMatch::Ip(IpAddr::V6(_))`, `HostMatch::SrcIp(IpAddr::V6(_))`,
  `HostMatch::SrcSubnet(IpAddr::V6(_), _)`, and the L4 port matchers were added
  with `tcm_info` etherproto = `ETH_P_IP` (0x0800) regardless of the address
  family. The kernel dispatches filters per protocol bucket *before* consulting
  flower's own `KEY_ETH_TYPE` attribute, so IPv6 packets never reached IPv6
  filters. Now passes `ETH_P_IPV6` for v6 and `ETH_P_IP` for v4 / L4 port
  filters explicitly via `add_filter_full`.

### Added

- `nlink::netlink::impair` — new module exposing `PerPeerImpairer`,
  `PeerImpairment`, `PeerMatch`, and `DEFAULT_ASSUMED_LINK_RATE_BPS`. Per-peer
  netem impairment helper for shared L2 segments (bridges, multipoint radio
  fabrics). Builds an HTB + flower + netem leaf tree under the device's root
  qdisc, with optional per-rule rate caps and a configurable default catch-all.
  Supports destination and source matching by IP, subnet, and MAC.
- `Connection<Route>::get_filters_by_parent(iface, parent)` and
  `get_filters_by_parent_index(ifindex, parent)` — client-side filter dump
  variants that filter by parent handle. Useful for reconcile-style consumers
  doing targeted teardown.
- `docs/recipes/per-peer-impairment.md` — recipe documentation, including a
  hand-rolled equivalent for users who need a custom topology.
- `examples/impair/per_peer.rs` (`cargo run -p nlink --example impair_per_peer`)
  — runnable demo. Default mode prints the topology + usage patterns; with
  `--apply` (root) it creates a temporary namespace, applies a 3-peer
  impairment with mixed configs (delay/loss, per-rule rate cap, subnet match,
  default), dumps the resulting tree, then cleans up.

## [0.12.2] - 2026-04-04

### Fixed

- **DNAT/SNAT rules fail with EAFNOSUPPORT in inet family tables** — `Rule::dnat()` and
  `Rule::snat()` passed the table's `Family::Inet` (value 1) to the kernel's `NFTA_NAT_FAMILY`
  attribute, but the kernel NAT expression only accepts `Family::Ip` (2) or `Family::Ip6` (10).
  Now always uses `Family::Ip` since these methods accept `Ipv4Addr`. Added `debug_assert!` in
  expression encoding to catch future misuse.

### Added

- `Connection<Route>::set_link_netns(iface, ns_name)` — move an interface to a named network
  namespace without manual FD management (convenience wrapper over `set_link_netns_fd`)
- `Connection<Route>::set_link_netns_by_index(ifindex, ns_name)` — index-based variant for
  namespace-safe operations
- `VethLink::peer_netns(ns_name)` — move the peer interface to a named namespace at creation
  time (returns `Result<Self>` since opening the namespace can fail)

### Improved

- Documented sync vs async `Connection::new()` construction — `Connection` struct doc, `new()`
  method doc, and all six GENL protocol type docs (`Wireguard`, `Macsec`, `Mptcp`, `Ethtool`,
  `Nl80211`, `Devlink`) now clearly state that `new_async().await` is required
- Added doc warnings on `NatExpr::snat()` and `NatExpr::dnat()` that `Family::Inet` is invalid

## [0.12.1] - 2026-03-30

### Added

- `Connection<Nl80211>::set_wiphy_netns(wiphy, fd)` — move a wireless PHY to a different
  network namespace by file descriptor (equivalent to `iw phy <name> set netns name <ns>`)
- `Connection<Nl80211>::set_wiphy_netns_pid(wiphy, pid)` — move by process PID
- `Ipv4Route` and `Ipv6Route` added to `nlink::prelude`

### Fixed

- All 5 rustdoc link warnings resolved (zero remaining)

## [0.12.0] - 2026-03-30

### Added

#### Mount Namespace Support in Spawn Functions
- `spawn_with_etc()` / `spawn_output_with_etc()` — spawn processes with `/etc/netns/<name>/`
  file overlays and `/sys` remount, mirroring `ip netns exec` behavior
- `spawn_path_with_etc()` / `spawn_output_path_with_etc()` — path-based variants
- `NamespaceSpec::spawn_with_etc()` / `spawn_output_with_etc()` — integrated methods
- Pre-computes all bind mount paths before `fork()` to ensure async-signal-safety
  (no allocations in `pre_exec()`, safe under tokio multi-thread runtime)
- Uses `MS_SLAVE | MS_REC` for mount propagation to match iproute2
- Skips overlay silently if `/etc/netns/<name>/` doesn't exist (no-op)

## [0.11.4] - 2026-03-30

### Fixed

- Correct `NFNL_MSG_BATCH_BEGIN`/`NFNL_MSG_BATCH_END` constants from `0x10 << 8` (4096) to
  `0x10` (16). These are raw `nlmsg_type` values (`NLMSG_MIN_TYPE`), not subsystem-shifted
  message types. The wrong values caused the kernel to not recognize batch delimiters.

## [0.11.3] - 2026-03-30

### Fixed

- Wrap all nftables mutation operations (`add_table`, `add_chain`, `add_rule`, `del_*`,
  `flush_table`) in `NFNL_MSG_BATCH_BEGIN`/`NFNL_MSG_BATCH_END` messages. Since Linux 4.6,
  the kernel requires batch wrapping for nftables mutations; standalone messages failed with
  `EINVAL`. The `Transaction` API was not affected.

## [0.11.2] - 2026-03-30

### Fixed

- Use `/proc/thread-self/ns/net` instead of `/proc/self/ns/net` in all namespace operations.
  `/proc/self` resolves to the thread group leader (main thread), not the calling thread. After
  `unshare(CLONE_NEWNET)` on a non-main thread, this caused `namespace::create()` to bind-mount
  the wrong namespace, silently targeting the root namespace instead. Affects `create()`,
  `enter_path()`, and `new_in_namespace()`. Requires Linux 3.17+.

## [0.11.1] - 2026-03-29

### Fixed

- `namespace::create()` now restores the calling thread's network namespace after creating a new
  one. Previously, `unshare(CLONE_NEWNET)` permanently changed the thread's namespace, causing
  subsequent operations (`connection_for()`, `setns()`, veth creation) to silently operate in the
  wrong namespace context. This caused `EEXIST` on veth creation in loops and `EPERM` on SELinux
  systems.

## [0.11.0] - 2026-03-28

### Breaking Changes

- **Interface parameter unification**: ~56 methods now accept `impl Into<InterfaceRef>` instead
  of `&str` for interface names. Existing `&str` callers continue to work via `From<&str>`.
  Affected: TC operations, address operations, FDB, bridge VLAN, neighbor, filter methods.
- **Renamed `remove_*` to `del_*`**: `remove_netem` → `del_netem`, `remove_netem_by_index` →
  `del_netem_by_index`, `remove_peer` → `del_peer`, `remove_peer_by_name` → `del_peer_by_name`,
  `remove_addr` → `del_addr`
- **LinkStats fields now public**: All 10 fields changed from `pub(crate)` to `pub`
- **Send + Sync bounds on config traits**: `LinkConfig`, `AddressConfig`, `RouteConfig`,
  `NeighborConfig` now require `Send + Sync`
- **`#[non_exhaustive]` on 43 API enums**: `NetworkEvent`, `Error`, `OperState`, and 40 others.
  Match expressions must include a wildcard arm.

### Added

#### Convenience API (Plan A)
Based on nlink-lab feedback report:

- `OperState`: `Display` impl and `display_name()` for lowercase output ("up", "down", etc.)
- `add_address_by_name()` / `replace_address_by_name()` — resolve interface name internally,
  eliminating the resolve-then-act pattern for address operations
- `enslave()` / `enslave_by_index()` — handle the down/master/up sequence for bond and bridge
  enslavement in a single call

#### Defensive Validation (Plan B)
- Interface name validation in `add_link()` and `set_link_name()` — validates names before
  sending to kernel, preventing cryptic EINVAL from invalid names (too long, contains `/`, etc.)
- `peer_name()` on `LinkConfig` trait — VethLink and NetkitLink now expose peer names for validation
- Promote kernel ENOENT to typed errors: `del_link` → `InterfaceNotFound`,
  `del_qdisc`/`change_qdisc` → `QdiscNotFound`, `set_link_up/down` → `InterfaceNotFound`
- `KernelWithContext` enrichment for `add_link`, `del_link`, `set_link_state`, `del_qdisc`,
  `change_qdisc` — errors now include the operation name and target

#### nftables Match Expressions (Plan D)
New match methods on `Rule`:
- `match_l4proto(proto)` — generic L4 protocol matching (TCP/UDP/ICMP/etc.)
- `match_tcp_sport(port)` / `match_udp_sport(port)` — source port matching
- `match_icmp_type(type)` / `match_icmpv6_type(type)` — ICMP type matching
- `match_mark(mark)` — packet mark/fwmark matching

Negation variants:
- `match_saddr_v4_not()` / `match_daddr_v4_not()` — negated IP address matching
- `match_tcp_dport_not()` / `match_udp_dport_not()` — negated port matching

#### Async GENL Namespace Connections (Plan C)
- `AsyncProtocolInit` trait for protocols requiring async initialization (GENL family resolution)
- Implemented for all 6 GENL protocols: Wireguard, Macsec, Mptcp, Ethtool, Nl80211, Devlink
- `namespace::connection_for_async()` — create GENL connections in foreign namespaces
- `namespace::connection_for_path_async()` / `connection_for_pid_async()` — path and PID variants

#### API Hardening
- `#[must_use]` on all 62 builder structs to catch unused builders at compile time
- Error context on all 46 mutation operations via `KernelWithContext`
- `nlink::prelude` module for convenient imports

## [0.10.0] - 2026-03-22

### Added

#### Sysctl Management
Namespace-aware sysctl read/write support via `/proc/sys/` filesystem operations:

- `sysctl::get()`, `sysctl::set()`, `sysctl::set_many()` for current namespace
- `namespace::get_sysctl()`, `namespace::set_sysctl()`, `namespace::set_sysctls()` for named namespaces
- Path-based variants: `namespace::get_sysctl_path()`, `namespace::set_sysctl_path()`, `namespace::set_sysctls_path()`
- Path traversal validation: rejects keys containing `..`, `/`, or null bytes

#### Namespace Process Spawning
Spawn child processes inside network namespaces without shelling out to `ip netns exec`:

- `namespace::spawn(name, cmd)` — spawn via `pre_exec` + `setns` (parent unaffected)
- `namespace::spawn_output(name, cmd)` — spawn and collect stdout/stderr
- `namespace::spawn_path(path, cmd)` / `namespace::spawn_output_path(path, cmd)` — path-based variants
- `NamespaceSpec::spawn()` / `NamespaceSpec::spawn_output()` — unified API across Named/Path/Pid

#### API Improvements
- `CtState::empty()` const fn and `Default` impl for ergonomic flag building
- Re-export `Nftables` and `Wireguard` protocol types at crate root (alongside `Route` and `Generic`)

## [0.9.0] - 2026-03-15

### Added

#### nftables Support (Plan 033)
Complete nftables firewall management via `NETLINK_NETFILTER`:

- `Connection<Nftables>` protocol type with `NfGenMsg` header
- Table CRUD: `add_table()`, `list_tables()`, `del_table()`, `flush_table()`
- Chain management with hook, priority, type, policy configuration
- Rule builder with expression auto-generation
  - `match_tcp_dport()`, `match_udp_dport()` for port matching
  - `match_saddr_v4()`, `match_daddr_v4()` for address matching
  - `match_iif()`, `match_oif()` for interface matching
  - `match_ct_state()` with `CtState` bitflags
  - `accept()`, `drop()`, `jump()`, `counter()` terminations
- NAT expressions: `masquerade()`, snat, dnat, redirect
- `Log` expression with prefix and group
- `Limit` expression with rate, unit, burst
- Set support: `add_set()`, `del_set()`, `add_set_elements()`, `Lookup` expression
- Batch transactions: `transaction()`, `commit()`, `flush_ruleset()`

#### nl80211 WiFi Support (Plan 036)
WiFi configuration via Generic Netlink:

- `Connection<Nl80211>` with GENL family resolution and multicast group subscription
- Read-only queries: `get_interfaces()`, `get_wiphy()`, `get_stations()`, `scan_results()`
- Station mode: `connect()`, `disconnect()`, `set_power_save()`
- Trigger/abort scans: `trigger_scan()`, `abort_scan()`
- Event monitoring via `EventSource` trait with `Nl80211Event` enum
  - `ScanComplete`, `ScanAborted`, `Connect`, `Disconnect`, `NewInterface`, `DelInterface`, `RegChange`
- Types: `WiphyInfo`, `InterfaceInfo`, `StationInfo`, `ScanResult`, `InterfaceType`, `Band`, `BssInfo`

#### Devlink Support (Plan 037)
Hardware device management via Generic Netlink:

- `Connection<Devlink>` with GENL family resolution
- Device queries: `get_devices()`, `get_device_info()`, `get_ports()`, `get_health_reporters()`, `get_params()`
- Management: `reload()`, `flash()`, `set_param()`
- Event monitoring via `EventSource` trait with `DevlinkEvent` enum
  - `NewDevice`, `DelDevice`, `NewPort`, `DelPort`, `HealthEvent`
- Types: `DevlinkDevice`, `DevlinkInfo`, `DevlinkPort`, `HealthReporter`, `DevlinkParam`, `VersionInfo`
- Port types, flavours, health states, config modes as typed enums

#### Bond Support (Plan 031)
Complete bond/team interface management:

- `BondLink` builder with mode, primary, slaves, and advanced options
- Bond modes: `balance-rr`, `active-backup`, `balance-xor`, `broadcast`, `802.3ad`, `balance-tlb`, `balance-alb`
- `conn.add_link(BondLink::new("bond0").mode(BondMode::ActiveBackup))` API
- Slave management: `conn.set_link_master()`, `conn.set_link_nomaster()`

#### Tunnel Link Types (Plan 028)
Additional tunnel interface types:

- `VtiLink`, `Vti6Link` for route-based IPsec tunnels
- `Ip6GreLink`, `Ip6GretapLink` for IPv6 GRE tunnels
- Builder pattern with local/remote/ttl/key configuration

#### Operation Timeouts (Plan 032)
Configurable timeouts for netlink operations:

- `Connection::with_timeout()` builder for setting default timeout
- Per-operation timeout overrides
- `Error::is_timeout()` semantic check

#### Netlink Batching (Plan 030)
Bulk operations via batched sendmsg:

- `conn.batch()` for grouping multiple operations
- Per-operation result tracking
- Reduced syscall overhead for bulk configuration

#### BPF/TC Attachment (Plan 034)
BPF program attachment to TC hooks:

- `BpfFilter` for attaching BPF programs to TC
- `conn.add_filter("eth0", "ingress", bpf_filter)` API
- BPF info parsing from TC filter responses

#### ss Improvements (Plan 026)
Socket statistics enhancements:

- **Summary mode** (`-s`): `SocketSummary` type, `conn.socket_summary()` API
- **Kill mode** (`-K`): `conn.destroy_tcp_socket()`, `conn.destroy_matching()` with `DestroyResult`
- **Netlink socket listing** (`--netlink`): `query_netlink()` via `SOCK_DIAG_BY_FAMILY` with `AF_NETLINK`
- **Expression filters**: `FilterExpr::parse()` with winnow parser
  - Port comparisons: `sport = :22`, `dport != :80`, `sport > :1024`
  - Address/prefix matching: `src 192.168.0.0/16`, `dst 10.0.0.1`
  - State matching: `state established`, `state listening`
  - Boolean operators: `and`, `or`, `not`, parenthesized grouping
  - Trailing filter argument in `ss` binary

#### Ethtool Event Monitoring
- `Connection<Ethtool>::subscribe()` for joining monitor multicast group
- `EthtoolEvent` variants: `LinkStateChanged`, `LinkModesChanged`, `FeaturesChanged`, `CoalesceChanged`, `PauseChanged`

#### New Binaries
- `nlink-nft` — nftables firewall management CLI
- `nlink-wifi` — WiFi interface management CLI with monitor mode
- `nlink-devlink` — Hardware device management CLI with monitor mode

#### Binary Improvements
- `ip link show`: display bond info (mode, miimon, xmit_hash_policy, min_links) and slave info (state, mii_status, link_failure_count, queue_id)
- `tc filter show`: display BPF program info (name, tag, id, run_count, jited)
- `nlink-config example --example bond`: new bond (LACP) example configuration
- `nlink-wifi monitor`: real-time WiFi event monitoring
- `nlink-devlink monitor`: real-time devlink event monitoring

#### Declarative Config Enhancements
- Extended `DeclaredLinkType::Bond` with `miimon`, `xmit_hash_policy`, `min_links` fields
- Bond mode conversion in declarative config apply

#### Library Additions
- `FlashProgress` type with `percent()` helper for devlink firmware flash progress tracking
- `BatchResults::iter()`, `errors()`, `success_count()`, `error_count()`, `all_ok()` API

### Fixed
- Bond mode conversion in declarative config apply now correctly maps `BondMode` to link builder

### Tests
- Unit tests for `BatchResults` API (empty, all success, mixed, all errors, iteration)
- Unit tests for `BondMode::try_from()` and `XmitHashPolicy::try_from()` conversions
- Unit tests for `BpfFilter` builder, defaults, and `from_pinned()` validation
- Unit tests for `SocketSummary` display formatting and default values

#### Code Quality (Plan 035)
- SAFETY comments on all unsafe blocks
- Optional serde_json dependency cleanup
- Unwrap elimination in library code

## [0.8.0] - 2026-01-17

### Breaking Changes

#### API Naming Consistency: `*_for()` → `*_by_name()`
All interface query methods have been renamed for consistency with the `*_by_index()` pattern:

| Old Name | New Name |
|----------|----------|
| `get_addresses_for(name)` | `get_addresses_by_name(name)` |
| `get_neighbors_for(name)` | `get_neighbors_by_name(name)` |
| `get_qdiscs_for(name)` | `get_qdiscs_by_name(name)` |
| `get_classes_for(name)` | `get_classes_by_name(name)` |
| `get_filters_for(name, parent)` | `get_filters_by_name(name, parent)` |
| `get_root_qdisc_for(name)` | `get_root_qdisc_by_name(name)` |
| `get_netem_for(name)` | `get_netem_by_name(name)` |

#### Link Management Methods Now Accept `InterfaceRef`
The following methods now accept `impl Into<InterfaceRef>` instead of `&str`, allowing both name and index:

- `set_link_up(iface)` / `set_link_down(iface)`
- `set_link_state(iface, up)`
- `set_link_mtu(iface, mtu)`
- `set_link_txqlen(iface, txqlen)`
- `del_link(iface)`

```rust
// Both work now:
conn.set_link_up("eth0").await?;
conn.set_link_up(InterfaceRef::Index(2)).await?;
```

### Added

#### New `*_by_index()` Variants for Namespace-Safe Operations
Added index-based query and mutation methods that don't require interface name resolution:

**TC Operations:**
- `get_qdiscs_by_index(ifindex)` - Query qdiscs by interface index
- `get_classes_by_index(ifindex)` - Query TC classes by interface index
- `get_filters_by_index(ifindex)` - Query TC filters by interface index

**Address Operations:**
- `add_address_by_index(ifindex, address, prefix_len)` - Add IP address by index
- `replace_address_by_index(ifindex, address, prefix_len)` - Replace IP address by index

**Neighbor Operations:**
- `add_neighbor_v4_by_index(ifindex, dest, lladdr)` - Add IPv4 neighbor by index
- `add_neighbor_v6_by_index(ifindex, dest, lladdr)` - Add IPv6 neighbor by index
- `replace_neighbor_v4_by_index(ifindex, dest, lladdr)` - Replace IPv4 neighbor by index
- `replace_neighbor_v6_by_index(ifindex, dest, lladdr)` - Replace IPv6 neighbor by index

These methods are essential for namespace operations where sysfs-based name resolution would read from the wrong namespace.

#### Additional Link Methods Now Accept `InterfaceRef`
Extended `InterfaceRef` support to more link modification methods:

- `set_link_master(iface, master)` - Both interface and master accept name or index
- `set_link_nomaster(iface)`
- `set_link_name(iface, new_name)`
- `set_link_address(iface, mac)`
- `set_link_netns_pid(iface, pid)`
- `set_link_netns_fd(iface, fd)`

#### InterfaceRef Support in GENL Modules
WireGuard, MACsec, and Ethtool connection methods now accept `impl Into<InterfaceRef>`:

- `Connection<Wireguard>::get_device(iface)` - accepts name or index
- `Connection<Macsec>::get_device(iface)` - accepts name or index  
- `Connection<Ethtool>::get_link_state(iface)` - accepts name or index
- All other ethtool query/set methods similarly updated

### Migration Guide

To migrate from 0.7.x to 0.8.0:

1. **Rename method calls**: Use find-and-replace to update method names:
   ```
   get_addresses_for  →  get_addresses_by_name
   get_neighbors_for  →  get_neighbors_by_name
   get_qdiscs_for     →  get_qdiscs_by_name
   get_classes_for    →  get_classes_by_name
   get_filters_for    →  get_filters_by_name
   ```

2. **No changes needed** for `set_link_*` methods - existing `&str` arguments work unchanged due to `impl Into<InterfaceRef>`.

3. **For namespace operations**, consider using the new `*_by_index()` methods to avoid sysfs reads from the wrong namespace.

---

## [0.7.0] - 2026-01-05

### Added

#### Ethtool Configuration via Generic Netlink (Linux 5.6+)
Complete ethtool netlink interface for querying and configuring network device settings:

- `Connection<Ethtool>` for ethtool operations
  - `Connection::<Ethtool>::new_async()` constructor with GENL family resolution
  - `conn.family_id()` to access resolved GENL family ID
  - `conn.monitor_group_id()` to access monitor multicast group ID

- **Link State** (`get_link_state()`)
  - Carrier detection status
  - Signal Quality Index (SQI) for automotive Ethernet
  - Extended link state information

- **Link Info** (`get_link_info()`)
  - Port type (TP, AUI, MII, FIBRE, BNC, etc.)
  - PHY address
  - MDI-X status and control
  - Transceiver type

- **Link Modes** (`get_link_modes()`, `set_link_modes()`)
  - Speed, duplex, autonegotiation
  - Supported/advertised/peer link modes
  - Lane count and master/slave configuration
  - `LinkModesBuilder` for configuration

- **Features** (`get_features()`, `set_features()`)
  - Query hardware, wanted, active, and nochange feature sets
  - Bitset parsing for feature names
  - `FeaturesBuilder` for enabling/disabling features

- **Ring Buffers** (`get_rings()`, `set_rings()`)
  - RX/TX ring sizes and maximums
  - RX mini/jumbo ring support
  - Buffer length and CQE size
  - TX/RX push mode
  - `RingsBuilder` for configuration

- **Channels** (`get_channels()`, `set_channels()`)
  - RX/TX/combined/other queue counts
  - Maximum values for each type
  - `ChannelsBuilder` for configuration

- **Coalesce** (`get_coalesce()`, `set_coalesce()`)
  - Interrupt coalescing parameters (rx/tx usecs, max frames)
  - Adaptive coalescing settings
  - Packet rate thresholds
  - `CoalesceBuilder` for configuration

- **Pause** (`get_pause()`, `set_pause()`)
  - Flow control autonegotiation
  - RX/TX pause frame settings
  - `PauseBuilder` for configuration

- **Event Monitoring** (implements `EventSource` trait)
  - `conn.subscribe()` to join monitor multicast group
  - `conn.events()` / `conn.into_events()` for Stream-based monitoring
  - `EthtoolEvent` enum with variants for all setting types
  - Compatible with `tokio_stream::StreamExt` and `StreamMap`

- **Types and Enums**
  - `LinkState`, `LinkInfo`, `LinkModes`, `Features`, `Rings`, `Channels`, `Coalesce`, `Pause`
  - `Duplex` (Half, Full, Unknown)
  - `Port` (TP, AUI, MII, FIBRE, BNC, DA, None, Other)
  - `Transceiver` (Internal, External, Unknown)
  - `MdiX` (Auto, On, Off, Unknown)
  - `LinkExtState` for extended link down reasons
  - `EthtoolEvent` for event monitoring

- **Bitset Support**
  - `EthtoolBitset` for parsing ethtool bitsets
  - Compact and verbose bitset format support
  - Named bit lookup for features and link modes

#### New Binary: nlink-ethtool
Proof-of-concept ethtool utility demonstrating the library:

- `nlink-ethtool <interface>` - Show all settings (like `ethtool`)
- `nlink-ethtool features <interface>` - Show device features
- `nlink-ethtool rings <interface>` - Show ring buffer sizes
- `nlink-ethtool channels <interface>` - Show channel counts
- `nlink-ethtool coalesce <interface>` - Show coalescing parameters
- `nlink-ethtool pause <interface>` - Show pause settings
- `nlink-ethtool monitor` - Monitor ethtool events

#### New Examples
- `ethtool_link_state` - Query link state and carrier detection
- `ethtool_features` - List device features (offloads)
- `ethtool_rings` - Query ring buffer configuration
- `ethtool_monitor` - Monitor ethtool events in real-time

### Changed

- `Ethtool` protocol now implements `EventSource` trait for consistent event monitoring API
- Event monitoring uses `subscribe()` + `events()` pattern (consistent with Route, KobjectUevent, etc.)

#### Consistent InterfaceRef Support Across GENL Modules
All Generic Netlink modules now accept `impl Into<InterfaceRef>` for interface specification,
allowing both interface names (`"eth0"`) and indices (`5u32`):

- **WireGuard** (`Connection<Wireguard>`)
  - `get_device()`, `set_device()`, `set_peer()`, `remove_peer()` accept `impl Into<InterfaceRef>`
  - Added `*_by_name` variants for efficiency when name is already known

- **MACsec** (`Connection<Macsec>`)
  - `get_device()`, `add_tx_sa()`, `update_tx_sa()`, `del_tx_sa()`, `add_rx_sc()`,
    `del_rx_sc()`, `add_rx_sa()`, `update_rx_sa()`, `del_rx_sa()` accept `impl Into<InterfaceRef>`
  - `*_by_index` variants remain for efficiency when index is already known

- **Ethtool** (`Connection<Ethtool>`)
  - All methods now accept `impl Into<InterfaceRef>`:
    `get_link_state()`, `get_link_info()`, `get_link_modes()`, `set_link_modes()`,
    `get_features()`, `set_features()`, `get_rings()`, `set_rings()`,
    `get_channels()`, `set_channels()`, `get_coalesce()`, `set_coalesce()`,
    `get_pause()`, `set_pause()`
  - Added `*_by_name` variants for all methods

This enables namespace-safe operations when working with interface indices obtained
from netlink queries, avoiding sysfs reads that would access the host namespace.

## [0.6.0] - 2026-01-04

### Added

#### Network Diagnostics Module (Plan 014)
High-level diagnostic tools for network troubleshooting:

- `NetworkScanner` - Discover active hosts on a subnet
  - `scan()` for full subnet scanning with configurable concurrency
  - `scan_range()` for scanning IP ranges
  - Hostname resolution, latency measurement, and port checking
  - `ScanResult` with host details and optional port scan results

- `ConnectivityChecker` - Multi-path connectivity testing
  - `check()` for checking connectivity to a destination
  - Supports multiple methods: ICMP ping, TCP connect, HTTP(S) GET
  - `ConnectivityResult` with latency, hops, and detailed status
  - Configurable timeout and retry behavior

- `BottleneckDetector` - Identify network bottlenecks
  - `detect()` for analyzing a network path
  - Identifies issues: congestion, packet loss, high latency, MTU problems
  - `BottleneckReport` with severity levels and recommendations
  - Path analysis with per-hop metrics

#### Rate Limiting DSL (Plan 013)
Declarative rate limiting configuration:

- `RateLimiter` builder for interface-level rate limiting
  - `ingress()`, `egress()` for directional limits
  - `rate()`, `burst()` for traffic parameters
  - `with_netem()` for adding delay/loss simulation

- `PerHostLimiter` for per-source/destination rate limiting
  - `per_source()`, `per_destination()` modes
  - HTB-based implementation with flower filters
  - Automatic class and filter management

- `RateLimit` type with human-readable parsing
  - Supports units: `bps`, `kbps`, `mbps`, `gbps`, `bit`, `kbit`, `mbit`, `gbit`
  - `RateLimit::parse("100mbit")` for string parsing

#### Declarative Network Configuration (Plan 012)
Infrastructure-as-code for network configuration:

- `NetworkConfig` - Full network state representation
  - Links, addresses, routes, rules, qdiscs, classes, filters
  - YAML/JSON serialization via serde

- `NetworkConfig::capture()` - Snapshot current network state
- `NetworkConfig::diff()` - Compare configurations
- `NetworkConfig::apply()` - Apply configuration changes
- `ConfigDiff` with add/remove/modify operations
- Dry-run support for previewing changes

#### Integration Test Infrastructure (Plan 011)
Comprehensive test framework for netlink operations:

- `TestNamespace` - Isolated network namespace for testing
- Tests for all link types: dummy, veth, bridge, vlan, macvlan, vxlan, etc.
- Tests for addresses, routes, neighbors, TC qdiscs/classes/filters
- Tests for FDB, VLAN filtering, routing rules

#### TC Filter Chains (Plan 010)
Linux 4.1+ TC chain support:

- `conn.add_tc_chain()` - Create filter chain
- `conn.del_tc_chain()` - Delete filter chain
- `conn.get_tc_chains()` - List chains for a qdisc
- `FlowerFilter::chain()` - Assign filter to chain
- `FlowerFilter::goto_chain()` - Jump to another chain
- `GactAction::goto_chain()` - Action-based chain jumping

#### MPTCP Path Manager (Plan 009)
Multipath TCP endpoint configuration via Generic Netlink:

- `Connection<Mptcp>` for MPTCP operations
- `MptcpEndpointBuilder` for creating endpoints
  - `subflow()`, `signal()`, `backup()`, `fullmesh()` flags
  - `dev()` for binding to specific interface
- `conn.get_endpoints()`, `add_endpoint()`, `del_endpoint()`
- `conn.get_limits()`, `set_limits()` for connection limits
- `conn.flush_endpoints()` for bulk deletion

#### MACsec Configuration (Plan 008)
IEEE 802.1AE MACsec via Generic Netlink:

- `Connection<Macsec>` for MACsec operations
- `conn.get_device()` - Get device configuration
- `MacsecSaBuilder` for Security Associations
- TX SA management: `add_tx_sa()`, `update_tx_sa()`, `del_tx_sa()`
- RX SC management: `add_rx_sc()`, `del_rx_sc()`
- RX SA management: `add_rx_sa()`, `update_rx_sa()`, `del_rx_sa()`
- Cipher suite support: GCM-AES-128, GCM-AES-256, GCM-AES-XPN-128, GCM-AES-XPN-256

#### SRv6 Segment Routing (Plan 007)
Segment Routing over IPv6 support:

- `Srv6Encap` for SRv6 encapsulation
  - `encap()`, `inline()` modes
  - `segment()`, `segments()` for SID list
- `Srv6LocalBuilder` for local SID behaviors
  - `end()`, `end_x()`, `end_dx4()`, `end_dx6()`
  - `end_dt4()`, `end_dt6()`, `end_dt46()`
  - `end_b6()`, `end_b6_encaps()`
- `conn.add_srv6_local()`, `del_srv6_local()`
- `conn.get_srv6_local_routes()`

#### MPLS Routes (Plan 006)
Multi-Protocol Label Switching support:

- `MplsEncap` for MPLS encapsulation on IP routes
  - `label()`, `labels()` for label stack
  - `ttl()` for TTL value
- `MplsRouteBuilder` for MPLS forwarding
  - `pop()` - Pop label and deliver to local stack
  - `swap()` - Swap to new label
  - `swap_stack()` - Swap to label stack
- `conn.add_mpls_route()`, `del_mpls_route()`
- `conn.get_mpls_routes()`
- `MplsLabel` constants: `IMPLICIT_NULL`, `EXPLICIT_NULL_V4`, `EXPLICIT_NULL_V6`

#### Nexthop Objects (Plan 005)
Linux 5.3+ nexthop object support:

- `NexthopBuilder` for individual nexthops
  - `gateway()`, `dev()` for next hop specification
  - `blackhole()`, `onlink()` flags
- `NexthopGroupBuilder` for ECMP groups
  - `member(id, weight)` for weighted members
  - `resilient()` for resilient hashing
  - `buckets()`, `idle_timer()` for resilient params
- `conn.add_nexthop()`, `replace_nexthop()`, `del_nexthop()`
- `conn.add_nexthop_group()`, `del_nexthop_group()`
- `conn.get_nexthops()`, `get_nexthop_groups()`, `get_nexthop(id)`
- `Ipv4Route::nexthop_group()` for using groups in routes

#### HTB Class Builder (Plan 004)
Typed HTB class configuration:

- `HtbClassConfig` builder for HTB classes
  - `new(rate)` with human-readable rate parsing
  - `from_bps(rate)` for programmatic values
  - `ceil()`, `ceil_bps()` for ceiling rate
  - `burst_bytes()`, `cburst_bytes()` for burst sizes
  - `prio()`, `quantum()`, `mtu()` for tuning
- `conn.add_class_config()`, `change_class_config()`, `replace_class_config()`
- `*_by_index()` variants for namespace-aware operations

#### Bridge VLAN Filtering (Plan 003)
IEEE 802.1Q VLAN support for bridges:

- `BridgeVlanBuilder` for VLAN configuration
  - `pvid()`, `untagged()` flags
  - `range()` for VLAN ranges
- `conn.get_bridge_vlans()` - Query VLANs for a port
- `conn.get_bridge_vlans_all()` - Query all VLANs on a bridge
- `conn.add_bridge_vlan()`, `del_bridge_vlan()`
- `conn.add_bridge_vlan_tagged()`, `add_bridge_vlan_range()`
- `conn.set_bridge_pvid()` - Set native VLAN
- `*_by_index()` variants for all operations

#### Bridge FDB Management (Plan 002)
Forwarding Database operations:

- `FdbEntryBuilder` for FDB entries
  - `permanent()`, `static_entry()`, `dynamic()` states
  - `vlan()` for VLAN-aware bridges
  - `dst()` for VXLAN remote VTEP
- `conn.get_fdb()` - Query FDB for a bridge
- `conn.get_fdb_for_port()` - Query FDB for specific port
- `conn.add_fdb()`, `replace_fdb()`, `del_fdb()`
- `conn.flush_fdb()` - Flush dynamic entries
- `*_by_index()` variants for namespace operations

#### TC Class API (Plan 001)
General TC class management:

- `conn.add_class()`, `change_class()`, `replace_class()`, `del_class()`
- `conn.get_classes()`, `get_classes_for()`
- Support for HTB, DRR, QFQ, HFSC class types
- `*_by_index()` variants for namespace-aware operations

#### HFSC/DRR/QFQ Class Builders
Typed class configuration for additional classful qdiscs:

- `HfscClassConfig` for HFSC classes
  - `new()` with service curve configuration
  - `realtime()`, `linkshare()`, `upperlimit()` service curves
  - Each curve takes `(m1, d, m2)` parameters
- `DrrClassConfig` for DRR classes
  - `new()` with optional quantum
  - `quantum()` for deficit quantum setting
- `QfqClassConfig` for QFQ classes
  - `new()` with weight and maxpkt
  - `weight()`, `maxpkt()` configuration

#### FDB Event Monitoring
Bridge FDB events now included in NetworkEvent:

- `NetworkEvent::NewFdb(FdbEntry)` - New FDB entry added
- `NetworkEvent::DelFdb(FdbEntry)` - FDB entry removed
- Events include MAC address, VLAN, ifindex, and state
- Automatically received when subscribing to `RtnetlinkGroup::Neigh`

#### Bridge VLAN Tunneling
VLAN-to-VNI mapping for VXLAN bridges:

- `BridgeVlanTunnelEntry` for parsed tunnel mappings
  - `vid`, `tunnel_id`, `flags` fields
- `BridgeVlanTunnelBuilder` for creating mappings
  - `new(vid, tunnel_id)` constructor
  - `dev()` for specifying bridge port
  - `range(vid_end, tunnel_id_end)` for ranges
- `conn.get_vlan_tunnels()` - Query tunnel mappings
- `conn.add_vlan_tunnel()`, `del_vlan_tunnel()` - Modify mappings
- `*_by_index()` variants for namespace operations

#### MPTCP Per-Connection Management
Subflow and address management for active MPTCP connections:

- `MptcpAddress` for IP address with optional port
- `MptcpSubflowBuilder` for creating/destroying subflows
  - `new(token)` with connection token
  - `local_addr()`, `remote_addr()` endpoints
  - `local_id()`, `remote_id()` address IDs
  - `dev()` for interface binding
  - `backup()` for backup path marking
- `MptcpAnnounceBuilder` for address announcements
  - `new(token)` with connection token
  - `addr_id()`, `address()` configuration
- `conn.create_subflow()`, `destroy_subflow()` - Subflow lifecycle
- `conn.announce_addr()`, `remove_addr()` - Address announcements

### Changed

- All new examples organized into subdirectories by feature area
- Updated `crates/nlink/examples/README.md` with comprehensive documentation

### Fixed

- Rate parsing in tests now correctly expects bits/sec (not bytes/sec)
- Integration tests requiring root now have `#[ignore]` attribute for CI compatibility

## [0.5.1] - 2026-01-03

### Fixed

- Fixed race condition in `NamespaceWatcher` when the first namespace is created on a system
  where `/var/run/netns` doesn't exist. The watcher now scans the directory after switching
  watches to catch namespaces created during the transition.

### Documentation

- Fixed outdated API references in documentation:
  - Updated `Connection::new(Protocol::Route)` to `Connection::<Route>::new()`
  - Updated `conn.subscribe()` to `conn.events()` in stream module docs
  - Updated `EventStream::builder()` to new subscribe/events API
  - Fixed `RuleBuilder` doc link to use full path

## [0.5.0] - 2026-01-03

### Breaking Changes

#### `NetemOptions` Fields Now Private
All `NetemOptions` fields are now `pub(crate)` with public accessor methods. This completes
the accessor pattern for type safety and future flexibility.

```rust
// Before (direct field access)
if netem.loss_percent > 0.0 {
    println!("loss: {}%", netem.loss_percent);
}

// After (use accessor methods)
if let Some(loss) = netem.loss() {
    println!("loss: {:.2}%", loss);
}
```

New accessor methods added:
- `delay_ns()`, `jitter_ns()` - Raw nanosecond values
- `loss_percent()`, `duplicate_percent()`, `reorder_percent()`, `corrupt_percent()` - Raw percentages
- `packet_overhead()`, `cell_size()`, `cell_overhead()` - Rate limiting overhead values

#### Renamed `into_event_stream()` to `into_events()`
For consistency with Rust naming conventions (`iter()`/`into_iter()` pattern).

```rust
// Before
let mut stream = conn.into_event_stream();

// After
let mut stream = conn.into_events();
```

### Added

#### NetemOptions Accessors
- `delay_correlation()`, `loss_correlation()`, `duplicate_correlation()`, 
  `reorder_correlation()`, `corrupt_correlation()` - Correlation percentages
- `ecn()` - Check if ECN marking is enabled
- `gap()` - Get the reorder gap value
- `limit()` - Get the queue limit in packets
- `slot()` - Get slot-based transmission configuration
- `loss_model()` - Get loss model configuration (Gilbert-Intuitive or Gilbert-Elliot)
- `packet_overhead()`, `cell_size()`, `cell_overhead()` - Rate limiting overhead values
- `delay_ns()`, `jitter_ns()` - Raw delay/jitter values in nanoseconds
- `loss_percent()`, `duplicate_percent()`, `reorder_percent()`, `corrupt_percent()` - Raw percentages

#### FqCodelOptions Accessors
- `target()` - Get target delay as Duration
- `interval()` - Get interval as Duration
- `limit()` - Get queue limit in packets
- `flows()` - Get number of flows
- `quantum()` - Get quantum (bytes per round)
- `ecn()` - Check if ECN is enabled
- `ce_threshold()` - Get CE threshold as Duration
- `memory_limit()` - Get memory limit in bytes
- `drop_batch_size()` - Get drop batch size

#### HtbOptions Accessors
- `default_class()` - Get default class ID
- `rate2quantum()` - Get rate to quantum divisor
- `direct_qlen()` - Get direct queue length
- `version()` - Get HTB version

#### TbfOptions Accessors
- `rate()` - Get rate in bytes/sec
- `peakrate()` - Get peak rate in bytes/sec
- `burst()` - Get bucket size (burst) in bytes
- `mtu()` - Get MTU in bytes
- `limit()` - Get queue limit in bytes

#### TcMessage Convenience Methods
- `is_class()` - Check if this is a TC class
- `is_filter()` - Check if this is a TC filter
- `filter_protocol()` - Get filter protocol (ETH_P_* value)
- `filter_priority()` - Get filter priority
- `handle_str()` - Get handle as human-readable string (e.g., "1:0")
- `parent_str()` - Get parent as human-readable string (e.g., "root")

#### LinkMessage Statistics Helpers
Convenience methods that delegate to `stats()`:
- `total_bytes()`, `total_packets()`, `total_errors()`, `total_dropped()`
- `rx_bytes()`, `tx_bytes()`, `rx_packets()`, `tx_packets()`
- `rx_errors()`, `tx_errors()`, `rx_dropped()`, `tx_dropped()`

#### Additional Error Checks
- `is_address_in_use()` - EADDRINUSE
- `is_name_too_long()` - ENAMETOOLONG
- `is_try_again()` - EAGAIN
- `is_no_buffer_space()` - ENOBUFS
- `is_connection_refused()` - ECONNREFUSED
- `is_host_unreachable()` - EHOSTUNREACH
- `is_message_too_long()` - EMSGSIZE
- `is_too_many_open_files()` - EMFILE
- `is_read_only()` - EROFS

### Fixed

- Fixed Connector not receiving events even as root (missing multicast group join)

### Documentation

- Updated CLAUDE.md and docs/library.md with new accessor patterns

## [0.4.0] - 2026-01-03

### Breaking Changes

#### Message Struct Fields Now Private
All message struct fields are now `pub(crate)` with public accessor methods. This enables future
internal changes without breaking the public API.

Affected types:
- `LinkMessage` - use `ifindex()`, `name()`, `flags()`, `mtu()`, `operstate()`, `link_info()`, `stats()`, etc.
- `AddressMessage` - use `ifindex()`, `family()`, `prefix_len()`, `address()`, `local()`, `label()`, etc.
- `RouteMessage` - use `family()`, `dst_len()`, `destination()`, `gateway()`, `oif()`, `table_id()`, etc.
- `NeighborMessage` - use `ifindex()`, `family()`, `destination()`, `lladdr()`, `state()`, etc.
- `TcMessage` - use `ifindex()`, `handle()`, `parent()`, `kind()`, `options()`, etc.
- `LinkInfo` - use `kind()`, `slave_kind()`, `data()`, `slave_data()`
- `LinkStats` - use `rx_packets()`, `tx_packets()`, `rx_bytes()`, `tx_bytes()`, `total_packets()`, `total_bytes()`

```rust
// Before
let name = link.name.as_deref().unwrap_or("?");
let mtu = link.mtu.unwrap_or(0);

// After
let name = link.name_or("?");
let mtu = link.mtu().unwrap_or(0);
```

#### Qdisc Options API Simplified
- Removed `netem_options()` convenience method
- Renamed `options()` (raw bytes) to `raw_options()`
- New `options()` method returns parsed `QdiscOptions` enum

```rust
// Before
if let Some(netem) = qdisc.netem_options() {
    println!("delay: {:?}", netem.delay());
}

// After
use nlink::netlink::tc_options::QdiscOptions;
if let Some(QdiscOptions::Netem(netem)) = qdisc.options() {
    println!("delay: {:?}", netem.delay());
}
```

#### Renamed `RouteGroup` to `RtnetlinkGroup`
The enum for multicast group subscription was renamed to better reflect that it covers
all rtnetlink groups (links, addresses, routes, neighbors, TC), not just routes.

```rust
// Before
conn.subscribe(&[RouteGroup::Link, RouteGroup::Tc])?;

// After
conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Tc])?;
```

#### Removed Deprecated Type Aliases
- Removed `WireguardConnection` (use `Connection<Wireguard>` instead)

#### `NetemOptions` Methods Return `Option<T>`
The `NetemOptions` methods now return `Option<Duration>` or `Option<f64>` instead of
raw values that required checking for zero. This is more idiomatic Rust.

```rust
// Before
if netem.delay().as_micros() > 0 {
    println!("delay: {:?}", netem.delay());
}

// After
if let Some(delay) = netem.delay() {
    println!("delay: {:?}", delay);
}
```

Changed methods:
- `delay()` → `Option<Duration>` (was `Duration`)
- `jitter()` → `Option<Duration>` (was `Duration`)
- `loss()` → `Option<f64>` (new, replaces checking `loss_percent`)
- `duplicate()` → `Option<f64>` (new, replaces checking `duplicate_percent`)
- `reorder()` → `Option<f64>` (new, replaces checking `reorder_percent` or `gap`)
- `corrupt()` → `Option<f64>` (new, replaces checking `corrupt_percent`)
- `rate_bps()` → `Option<u64>` (new, replaces checking `rate`)

### Documentation
- Updated `CLAUDE.md` with new accessor patterns and API examples
- Updated all examples to use accessor methods

## [0.3.2] - 2026-01-03

### Added

#### Strongly-Typed Event Subscription
- `RtnetlinkGroup` enum for type-safe multicast group subscription
  - `Link`, `Ipv4Addr`, `Ipv6Addr`, `Ipv4Route`, `Ipv6Route`, `Neigh`, `Tc`, `NsId`, `Ipv4Rule`, `Ipv6Rule`
- `Connection<Route>::subscribe(&[RtnetlinkGroup])` - Subscribe to specific groups
- `Connection<Route>::subscribe_all()` - Subscribe to all common groups (Link, Ipv4Addr, Ipv6Addr, Ipv4Route, Ipv6Route, Neigh, Tc)

### Changed

- Event monitoring now uses `Connection::events()` and `into_events()` from `EventSource` trait
- Multi-namespace monitoring now uses `tokio_stream::StreamMap` directly instead of wrapper type

### Removed

- `EventStream` and `EventStreamBuilder` - Use `Connection<Route>::subscribe()` + `events()` instead
- `MultiNamespaceEventStream` and `NamespacedEvent` - Use `StreamMap` directly
- `run_monitor_loop` from output module - Incompatible with new Stream API

### Documentation

- Updated `CLAUDE.md` with new event monitoring patterns
- Added `docs/EVENT_API_CONSOLIDATION_REPORT.md` documenting the API changes

### Migration Guide

Before:
```rust
let mut stream = EventStream::builder()
    .links(true)
    .tc(true)
    .namespace("myns")
    .build()?;

while let Some(event) = stream.try_next().await? {
    // handle event
}
```

After:
```rust
let mut conn = Connection::<Route>::new_in_namespace("myns")?;
conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Tc])?;
let mut events = conn.events();

while let Some(result) = events.next().await {
    let event = result?;
    // handle event
}
```

## [0.3.1] - 2026-01-03

### Added

#### Routing Rules API
- `RuleBuilder` for creating routing rules programmatically
- `conn.get_rules()` - Get all routing rules
- `conn.get_rules_for_family(family)` - Get rules for specific address family
- `conn.add_rule(builder)` - Add a routing rule
- `conn.del_rule(builder)` - Delete a routing rule
- `conn.flush_rules(family)` - Flush all rules for a family

#### SockDiag Refactoring
- `Connection<SockDiag>` now follows the typed connection pattern
- `Connection::<SockDiag>::new()` constructor
- `conn.tcp_sockets()`, `conn.udp_sockets()`, `conn.unix_sockets()` query methods
- `TcpSocketsQuery`, `UdpSocketsQuery`, `UnixSocketsQuery` builders for filtering
- Added sockdiag examples: `list_sockets`, `tcp_connections`, `unix_sockets`

#### WireGuard Refactoring
- `Connection<Wireguard>` now follows the typed connection pattern
- `Connection::<Wireguard>::new_async()` for async initialization with GENL family resolution
- `conn.get_device()`, `conn.set_device()`, `conn.set_peer()`, `conn.remove_peer()` methods
- `conn.family_id()` to access resolved GENL family ID
- Added genl example: `wireguard`

#### New Protocol Implementations
- `Connection<KobjectUevent>` for device hotplug events (udev-style)
  - `Connection::<KobjectUevent>::new()` constructor with multicast subscription
  - `conn.recv()` to receive `Uevent` with action, devpath, subsystem, env
  - Helper methods: `is_add()`, `is_remove()`, `devname()`, `driver()`, etc.
  - Added example: `uevent_device_monitor`

- `Connection<Connector>` for process lifecycle events
  - `Connection::<Connector>::new()` async constructor with registration
  - `conn.recv()` to receive `ProcEvent` (Fork, Exec, Exit, Uid, Gid, Sid, Comm, Ptrace, Coredump)
  - `conn.unregister()` to stop receiving events
  - Added example: `connector_process_monitor`

- `Connection<Netfilter>` for connection tracking
  - `Connection::<Netfilter>::new()` constructor
  - `conn.get_conntrack()` for IPv4 entries
  - `conn.get_conntrack_v6()` for IPv6 entries
  - Types: `ConntrackEntry`, `ConntrackTuple`, `IpProtocol`, `TcpConntrackState`
  - Added example: `netfilter_conntrack`

- `Connection<Xfrm>` for IPsec SA/SP management
  - `Connection::<Xfrm>::new()` constructor
  - `conn.get_security_associations()` for listing SAs
  - `conn.get_security_policies()` for listing SPs
  - Types: `SecurityAssociation`, `SecurityPolicy`, `XfrmSelector`, `IpsecProtocol`, `XfrmMode`
  - Added example: `xfrm_ipsec_monitor`

- `Connection<FibLookup>` for FIB route lookups
  - `Connection::<FibLookup>::new()` constructor
  - `conn.lookup(addr)` for route lookups
  - `conn.lookup_in_table(addr, table)` for table-specific lookups
  - `conn.lookup_with_mark(addr, mark)` for fwmark-aware lookups
  - `conn.lookup_with_options(addr, table, mark)` for full control
  - Types: `FibResult`, `RouteType`, `RouteScope`
  - Added example: `fib_lookup_route_lookup`

- `Connection<Audit>` for Linux Audit subsystem
  - `Connection::<Audit>::new()` constructor
  - `conn.get_status()` for audit daemon status
  - `conn.get_tty_status()` for TTY auditing status
  - `conn.get_features()` for kernel audit features
  - Types: `AuditStatus`, `AuditTtyStatus`, `AuditFeatures`, `AuditFailureMode`, `AuditEventType`
  - Added example: `audit_status`

- `Connection<SELinux>` for SELinux event notifications
  - `Connection::<SELinux>::new()` constructor with multicast subscription
  - `conn.recv()` for receiving SELinux events
  - `SELinux::is_available()` to check if SELinux is present
  - `SELinux::get_enforce()` to read current enforcement mode
  - Types: `SELinuxEvent` (SetEnforce, PolicyLoad)
  - Added example: `selinux_monitor`

### Changed

#### API Cleanup
- Made `send_request()`, `send_ack()`, `send_dump()` methods `pub(crate)` (internal only)
- Removed `RouteConnection` and `GenlConnection` type aliases (use `Connection<Route>` and `Connection<Generic>` directly)
- Reorganized examples into protocol-based subdirectories (`route/`, `events/`, `namespace/`, `sockdiag/`, `genl/`)
- Moved TC type aliases (`QdiscMessage`, `ClassMessage`, `FilterMessage`) before test module

#### Binary Refactoring
- All binary commands now use high-level APIs instead of low-level `send_*` methods
- Refactored: `address.rs`, `link.rs`, `link_add.rs`, `neighbor.rs`, `route.rs`, `rule.rs`, `tunnel.rs`, `vrf.rs`

### Deprecated

- `SockDiag` struct (use `Connection<SockDiag>` instead)
- `WireguardConnection` type alias (use `Connection<Wireguard>` instead)

### Fixed

- Clippy warnings (collapsible if statements, redundant closures, unnecessary casts)
- IpvlanLink no longer attempts to set MAC address (inherits from parent)

### Documentation

- Added `docs/API_CLEANUP_REPORT.md` with refactoring details and recommendations

## [0.3.0] - 2026-01-02

### Added

#### EventStream API Improvements
- `EventType` enum for convenient event type subscription
- `EventStreamBuilder::event_types(&[EventType])` method for bulk subscription
- `EventStreamBuilder::event_type(EventType)` method for single subscription
- `NetworkEvent::action()` returns "new" or "del" based on event type
- `NetworkEvent::as_link()`, `as_address()`, `as_route()`, `as_neighbor()`, `as_tc()` accessor methods
- `NetworkEvent::into_link()`, `into_address()`, `into_route()`, `into_neighbor()`, `into_tc()` consuming accessors

#### TcMessage Improvements
- `TcMessage::name` field for caching interface name
- `TcMessage::name()`, `name_or()` accessor methods
- `TcMessage::with_name()` builder method
- `TcMessage::resolve_name()`, `resolve_name_mut()` for interface name resolution

#### Error Constructor Helpers
- `Error::invalid_message()` for invalid message errors
- `Error::invalid_attribute()` for invalid attribute errors
- `Error::not_supported()` for unsupported operation errors
- `Error::interface_not_found()` for missing interface errors
- `Error::namespace_not_found()` for missing namespace errors
- `Error::qdisc_not_found()` for missing qdisc errors
- `Error::family_not_found()` for missing GENL family errors

#### TC Convenience Methods
- `apply_netem()` now includes fallback logic (tries replace, falls back to add)
- `apply_netem_by_index()` with same fallback behavior

### Changed

- `ip monitor` uses new `EventType` enum and accessor methods for cleaner code
- `tc monitor` uses `TcMessage` name helpers for interface resolution
- `tc_netem` example uses error constructor helpers

### Breaking Changes

- `TcMessage` struct now has a `name: Option<String>` field. Code constructing `TcMessage` with struct literals must add `name: None`

## [0.2.0] - 2026-01-02

### Added

#### API Improvements
- `LinkMessage::name_or(default)` helper method for cleaner interface name access
- `Connection::get_interface_names()` returns `HashMap<u32, String>` for resolving ifindex to names
- Unified all public `ifindex` types to `u32` (was mixed `i32`/`u32`)

#### New Link Types (Phase 8)
- `BareudpLink` - Bare UDP tunneling for MPLS
- `NetkitLink` - BPF-optimized virtual ethernet
- `NlmonLink` - Netlink monitor for debugging
- `VirtWifiLink` - Virtual WiFi for testing
- `VtiLink` / `Vti6Link` - Virtual Tunnel Interface for IPsec
- `Ip6GreLink` / `Ip6GretapLink` - IPv6 GRE tunnels

#### Generic Netlink Support (Phase 7)
- `GenlConnection` for Generic Netlink protocol
- WireGuard configuration via `WireguardConnection`
- `WgDevice` and `WgPeer` builders for WireGuard setup

#### Traffic Control
- **New Qdiscs**: `DrrConfig`, `QfqConfig`, `PlugConfig`, `MqprioConfig`, `TaprioConfig`, `EtfConfig`, `HfscConfig`
- **New Filters**: `CgroupFilter`, `RouteFilter`, `FlowFilter`
- **New Actions**: `ConnmarkAction`, `CsumAction`, `SampleAction`, `CtAction`, `PeditAction`
- Total: 19 qdisc types, 9 filter types, 12 action types

#### Validation
- `Validatable` trait for pre-send validation of configurations
- `ValidationResult` with errors and warnings

#### Examples
- 15 comprehensive examples in `crates/nlink/examples/`
- Examples README with usage documentation

### Changed

- Migrated to `zerocopy` crate for safe byte serialization (no unsafe code in types module)
- Improved error handling with `ValidationErrorInfo` for structured errors
- Split documentation into `docs/library.md` and `docs/cli.md`
- Updated all documentation to use `nlink` crate name

### Fixed

- Clippy warnings across the codebase
- Rustdoc HTML tag warnings
- Type consistency for `ifindex` across all message types

## [0.1.2] - 2024-12-XX

- Initial public release
- Core netlink socket and connection handling
- Link, address, route, neighbor operations
- Event monitoring (link, address, route, neighbor, TC)
- Network namespace support
- Basic TC qdisc operations
