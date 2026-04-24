# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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
