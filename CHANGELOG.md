# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Breaking Changes

- **The early half of the API cleanup (#532).** The workspace is 0.32.0;
  see `docs/migration_guide/0.31.0-to-0.32.0.md`.
  - **Removed:** `Error::SequenceMismatch`, `Error::NamespaceRestoreFailed`
    and `is_namespace_restore_failed()`. Nothing constructed them.
  - **`full` no longer includes `lab`.** `lab` is test code: namespace
    helpers, `require_root!` and a `tracing-subscriber`. Enable it in
    `[dev-dependencies]`.
  - **tokio.** nlink no longer turns on tokio's `full`. It asks for `rt`,
    `net`, `sync`, `time` and `macros`, which is what it uses.
  - **MSRV 1.88** (it was 1.98), checked by CI's `msrv` job. The project
    still builds with the fleet's 1.98.
  - **Deprecated:** `Connection::get_timeout()`, renamed
    `operation_timeout()`, and `namespace_events`
    (`NamespaceEventSubscriber`, `NamespaceNetlinkEvent`), which
    duplicates `NetworkEvent::{NewNsId, DelNsId}`.
  - **`Display`:** `WireguardConfigDiff`'s no longer ends with a newline,
    like the other diffs'. The `nlink-config` and `nlink-nft` diff output
    ends with one again: they printed with `print!`.

- **Typed recreate blockers, and a report of what was recreated (#513,
  part 1).**
  - `LinkRecreate::blocked_by` is a `Vec<Blocker>`. `Blocker` is an enum
    with one variant per thing a recreate would destroy that the config
    does not declare: an address, route, qdisc, class, filter, FDB entry,
    neighbour, proxy neighbour or nexthop, a stacked link, a port, or a
    peer in another namespace. `Unsupported` covers a link that cannot be
    recreated at all. Each variant's `Display` is the text the list held
    before. In JSON a blocker is tagged by `kind`.
  - `ApplyResult::recreated` lists the links the apply deleted and created
    again; a dry run lists the ones it would.
  - `LinkRecreate::resets` says what each recreated link lost that the
    config does not declare: its alias, and a MAC address the kernel
    picks again.
  - `TcHandle` derives `JsonSchema` under `schemars`.

- **A config can own its routes by protocol (#512, part 3).**
  - `NetworkConfig::route_protocol(p)` installs the declared routes with
    `rtm_protocol` `p`. The default, `boot`, is what `ip route add` uses.
    With a number of its own, the config owns exactly its routes. A purge
    removes only routes with that protocol, and never another tool's
    `boot`/`static` route. A declared route never replaces a different
    route of another protocol in its place: the diff refuses it in
    `routes_refused`. An identical route already carries the declaration.
  - `RouteProtocol::Other(u8)` keeps the numbers nlink has no name for,
    which read back as `Unspec`. It comes with `number()`,
    `From<RouteProtocol> for u8`, and a `Display` that prints the name,
    or the number for `Other`. `as u8` no longer compiles.

- **`NetemConfig` is `#[non_exhaustive]` (#515).** It gained seven fields.
  Build one with `NetemConfig::new()` and its setters, not a struct
  literal.

- **`FqPieOptions::ecn_prob_permille` is `ecn_prob_percent` (#631).** It
  holds the whole percentage the kernel reports. The old field held that
  value too, under a name that said per-mille, and `ecn_prob()` divided
  it by 10.

- **One `LinkStats` and one `LinkRates` (#525).**
  - `stats::LinkStats` is the message-level `LinkStats`, with accessors
    in place of public fields. A snapshot keeps link names in
    `StatsSnapshot::names`.
  - `stats::LinkRates` has no `name`.
  - `diagnostics::LinkRates`, which `nlink::LinkRates` re-exported, is
    now the stats one: `f64` bytes and packets per second, with
    `rx_packets_per_sec` in place of `rx_pps` and no
    `sample_duration_ms`.
  - `StatsSnapshot` is `#[non_exhaustive]` and gains `taken_at`, `netns`
    and `names`.
  - `StatsSnapshot::rates(&previous)` takes no duration. It measures the
    time between the two snapshots' `taken_at`, and so does
    `StatsTracker::update`. The tracker used to time its own calls, so a
    snapshot handed over late gave a rate over the wrong interval.

- **TC footguns removed (#515, part 4a).**
  - **A classful qdisc at the root defaults to handle `1:`.** This covers
    htb, prio, hfsc, drr, qfq, ets, multiq, mq, mqprio, taprio, atm and
    dsmark, so their classes can name the qdisc; the kernel picked
    `8001:`. `QdiscConfig::default_handle` returns `Option<TcHandle>`,
    and this is the first use of it. Before, it was declared, returned
    `None` for every kind, and nothing read it. A replace that changes or
    recreates a live qdisc keeps that qdisc's handle, and an explicit
    handle always wins.
  - **Byte quantities take `Bytes`:**
    - `RedConfig::{limit, min, max}`;
    - `GredConfig::limit`, `BfifoConfig::limit` and `PlugConfig::limit`;
    - `FqCodelConfig::memory_limit` and `Connection::plug_set_limit`.

    `limit(u32)` meant packets for some kinds and bytes for others. The
    packet limits stay `u32`. `ChokeConfig`'s limit and thresholds are
    documented as packets, which is what `sch_choke` counts; they were
    documented as bytes.
  - **`PoliceAction` takes `Rate` and `Bytes`:** `rate`, `peakrate` and
    `avrate` take a `Rate`, and `burst` and `mtu` take `Bytes`. `rate`
    used to take bytes per second as a bare `u64`, next to a `rate_bps`
    for bits. `rate_bps` is gone.

- **The filter API is typed: `EthProto` and `FilterPriority` (#515, part
  4b).** These take a protocol as `EthProto` and a priority as
  `FilterPriority`, where they took a bare `u16`:
  - every `Connection` filter method (`add_filter_full`, `del_filter`,
    `replace_filter_full`, `change_filter*`, and the `_by_index`
    variants);
  - the filter builders' `.protocol()` and `.priority()`;
  - the `FilterConfig` trait.

  `TcMessage::protocol()`/`priority()` and `filter_protocol()`/
  `filter_priority()` return the typed values. Both types compare equal
  to a `u16`, so `f.priority() == 100` still compiles.
  `DEFAULT_FILTER_PROTOCOL` is an `EthProto`.

- **`DeclaredQdiscType` is `QdiscSpec`, and it holds the imperative
  configs (#515, part 4c).**
  - A declared netem is `QdiscSpec::Netem(NetemConfig)`, a TBF
    `QdiscSpec::Tbf(TbfConfig)`, and so on. The declarative and
    imperative paths share one type per kind: the same defaults, the same
    comparison, the same fixes. Before, the declarative side had its own
    fields in raw units, its own lowering per kind, and its own
    comparison.
  - `DeclaredQdiscType` remains as a deprecated alias. Its struct-like
    variants are gone.
  - **The JSON and YAML form is written in human units:**
    `{"netem": {"delay": "10ms", "loss": "1%", "rate": "100mbit"}}`.
    A 0.31 document still reads. Its raw-unit fields are accepted in
    their old units: `delay_us`, `loss_percent`, `rate_bps` (bytes per
    second), `burst_bytes`, `limit_bytes`, `perturb_secs`, `target_us`
    and the rest.
  - A document is refused when it:
    - sets a value both ways;
    - has a percentage outside 0–100;
    - gives a rate without its unit;
    - misspells a field.
  - A TBF declared without a limit now fails validation, so
    `from_json_str` refuses it. Before, only the apply did.
  - An undeclared sfq `perturb` now means the kernel's 0, and is compared.

- **One reconcile vocabulary, and plan options apart from execution
  (#532, #519 part 1).**
  - **Reconcile types.** `nlink::reconcile::{ReconcileOptions,
    ReconcileReport}` replace two unrelated pairs of the same names: the
    recipes' at the crate root, and the nftables pair the network and
    WireGuard layers borrowed. Every old path names the new types.
    - The options are `max_retries`, `backoff`, `dry_run` and
      `fallback_to_apply`, set with `with_*` setters.
    - The report is `attempts` and `changes_made` (the layers'
      `change_count` is renamed), plus a recipe's per-rule counts.
    - `dry_run` is now honoured by every layer's `apply_reconcile`: the
      network, nftables (both reconciles) and WireGuard. It used to commit
      anyway.
    - The recipes retry `EBUSY`, `EAGAIN` and interrupted dumps, re-reading
      the tree each attempt, and report their attempts.
  - **Plan and execution.** `DiffOptions` is `PlanOptions` (a deprecated
    alias stays). `ApplyOptions` is `{ plan: PlanOptions, exec:
    ExecOptions }`, with the same setters.
    - `ConfigDiff::apply` takes `impl Into<ExecOptions>`, because a
      computed diff can only be executed. It used to take `ApplyOptions`
      and silently ignore its plan half.
    - Its `verify` now works: the diff keeps the config and plan it came
      from and diffs again with them. Before, it was ignored.
    - `ExecOptions` (`dry_run`, `continue_on_error`, `verify`) is the one
      the `Stack` plan/apply (#519 part 2) shares across layers.
  - **Tests:**
    - a stale precomputed diff applied with `verify` fails `NotConverged`
      with the drift;
    - a purging network reconcile with `dry_run` counts the removal and
      leaves the address;
    - both nftables reconciles with `dry_run` commit nothing.

    The first and second fail on the code before their fixes.

- **`Stack` plans once and applies that plan (#519, parts 2 and 3).**
  `Stack::plan_in(ns, PlanOptions) -> StackPlan` diffs every set layer
  once. `StackPlan` prints as the dry run and serializes.
  `StackPlan::apply(ns, ExecOptions) -> StackReport` applies exactly it, in
  this order: WireGuard links, network, firewall, then WireGuard keys and
  peers.
  - **One diff.** `Stack::apply*` used to run a pre-flight diff of every
    layer, throw it away, and let each layer diff again as it applied: a
    second full dump, and a window for the kernel to change in between.
  - **Re-planning.** A layer planned while a WireGuard link it names did
    not exist is planned again once step 0 has created it. Before, a
    network declaration on the tunnel, such as its MTU, could take a
    second apply.
  - **Verify.** `exec.verify` plans every layer again and fails with
    `Error::StackNotConverged`.
  - **Retry.** `Stack::apply_reconcile_in` plans and applies again on
    `EBUSY`, `EAGAIN`, an interrupted dump, or an nftables commit refused
    because the ruleset moved since the plan.
  - **`WireguardConfigDiff::apply`** is new, like the other layers' diff
    applies.
  - **Renames:**
    - `StackDiff` is now `StackPlan` and `StackApplyReport` is now
      `StackReport` (deprecated aliases);
    - the `diff*` methods are deprecated for `plan*`;
    - `nftables_change_count` is now `nftables`;
    - a dry run's plan is in `planned`;
    - `Stack` is `#[non_exhaustive]`.
  - **`NftablesConfig::absent_table(name, family)`.** A table declared
    absent is deleted, with its contents, whenever the kernel has it. An
    owner no longer special-cases "I own this table and want it gone".
    Declaring a table both present and absent fails validation.

  Root tests:
  - a plan applied as planned converges under `verify`;
  - an address added after a purging plan is not swept up by that plan,
    and `verify` finds it;
  - a stale firewall plan is refused with `ERESTART` while the stack
    reconcile goes through;
  - a WireGuard link's MTU, declared in the network layer, lands in the
    same apply (host root only);
  - an absent table goes and stays gone, and other tables are untouched.

  The WireGuard test fails without the re-plan.

- **File descriptors are `impl AsFd` (#532).** Every public parameter that
  took one as `RawFd` or `i32` now takes `impl AsFd`, so the compiler
  checks that it is open. The guide has the list.
  - **Where:** `get_nsid`, `set_nsid`, `set_link_netns_fd{,_by_index}`,
    `Connection::new_in_namespace`, `NetlinkSocket::new_in_namespace`,
    `set_wiphy_netns`, `Connection::<Ovpn>::attach_socket{,_in_netns}`,
    `VethLink::peer_netns_fd`, `BpfFilter::new` and
    `BpfAction::from_fd`. `NetlinkSocket::send_with_fds` takes
    `&[BorrowedFd]`.
  - **Builders.** `VethLink`, `BpfFilter` and `BpfAction` hold a
    duplicate until the request is sent, so the caller's fd may close at
    once. They used to keep the bare number.
  - **New impls.** `TunTap` and `NetlinkSocket` implement `AsFd`.
  - **Deprecated:** the two `new_in_namespace_fd` twins.
  - **Fixed in passing:** the `ns_fd` field of
    `Connection::new_in_namespace`'s span is now recorded.
    `docs/observability.md` had always said it was.

- **One way into a namespace (#532).** `Connection::<P>::new_in(ns)` and
  `new_in_async(ns)` replace seven spellings:
  - `namespace::connection_for{,_path,_pid}{,_async}`;
  - `Connection::for_namespace`;
  - `Connection::new_in_namespace{,_path,_fd}`;
  - `NamespaceSpec::connection{,_async}`.

  The old spellings are deprecated.
  - **`ns` is anything `Into<NetnsTarget>`** (new): an `ip netns` name, an
    open `&Netns` or `&LabNamespace`, a `NetnsRef`, a path, a
    `NamespaceSpec` or a `BorrowedFd`. A name with a `/` is refused, not
    taken as a path.
  - **The facade takes the same:**
    - `facade::{apply, diff}::*_in` and every `Stack` `*_in` method;
    - `StackPlan::apply`;
    - `MultiNsWatch::add`;
    - the new `facade::watch::*_changes_in`;
    - the new `ConnectionPool::new_in`, and
      `ConnectionPoolBuilder::namespace`.

    Their `_in_namespace(&str)` forms and `ConnectionPool::for_namespace`
    are deprecated.
  - **Breaking:**
    - `Netns::connection{,_async}` (new this cycle) are gone; use
      `Connection::new_in(&netns)`.
    - `ConnectionPoolBuilder::namespace` takes `impl Into<NetnsTarget>`.
  - **Test.** A root test reaches one namespace through each kind of
    target, by its id and a link only it has. It also checks a GENL
    family, the facade and the pool.

- **`Error` is a struct, one pointer wide (#526).** The old variants are
  `ErrorDetail`, reached through `e.detail()`.
  - **Every error carries its context.** `e.context()` lists what was being
    done, outermost first. `with_context` and `ResultExt::context` used to
    keep a context only on a kernel error, and returned an I/O error, a
    refused batch, a validation failure or a parse unchanged.
  - **Kernel errors.** `KernelWithContext` is folded into
    `ErrorDetail::Kernel` plus `context()`. Kernel errors read as before.
  - **Construction.** Every `Error::InvalidMessage(…)` and similar variant
    constructor (about 1,200 sites) now goes through a helper:
    `invalid_message`, `invalid_attribute`, `not_supported`, `validation`,
    `truncated`, `timeout`, `dump_interrupted`, `pool_closed`,
    `Error::from(io::Error)`.
  - **`nlink-macros`'** generated code uses the helpers too.
  - **Unchanged:** `kind()`, `errno()`, `ext_ack()`, the `is_*`
    predicates and `source()`.
  - **Size.** A `Result<T>` used to carry an error of several words; it now
    carries one pointer.
  - **Test.** A unit test keeps a context on an I/O error, a validation
    failure and an invalid message, and pins the kernel error formats. With
    `with_context` back to the kernel-only rule it fails: the I/O error's
    context is empty. A second test pins the size.

- **`sys_sizeof`'s attribute tables are removed (#167).** The modules
  `xfrm_msg_type`, `xfrm_attr`, `nft_ct_keys`, `tca_htb_attr`,
  `tca_flower_key`, `ifla_attr`, `rta_attr`, `ctnetlink_attr`, `dpll_a`,
  `devlink_attr` and `ethtool_a` were hand-copied kernel values, tested
  against literals or against the nlink constants they were copied
  alongside. #265 found `TCA_HTB_OFFLOAD` wrong in both a table and the
  constant it checked. The UAPI audit checks those constants against the
  headers and the YNL specs now. Struct sizes, `nft_verdict`, `nf_hook`
  and `DEVLINK_MCGRP_CONFIG_NAME` stay.

- **One not-found detail (#718).** `ErrorDetail::InterfaceNotFound`,
  `NamespaceNotFound`, `QdiscNotFound` and `FamilyNotFound` are now one
  detail, `NotFound { object: ErrorObject }`. An `IfError::NotFound` converts
  to it as well. `ErrorObject` gains `GenlFamily`. The messages read as they
  did, `is_not_found()` and `kind()` are unchanged, and `Error::object()`
  returns what was missing. `Error::not_found(object)` joins the existing
  `interface_not_found`, `namespace_not_found`, `qdisc_not_found` and
  `family_not_found`. A missing qdisc found by `change_qdisc`,
  `del_qdisc_kind_by_index` or the verbs says its parent too.
  `ErrorObject::Qdisc::parent` is an `Option`. `ErrorDetail::Kernel` no
  longer stores `message`, the `strerror` text of its errno: `Display`
  computes it.

- **Packet counts take `Packets` (#643).** `nlink::Packets(u32)` is to
  packet limits what `Bytes` is to byte limits. Each packet-counted setter
  takes it:
  - the `limit` of netem, fq_codel, codel, fq, sfq, choke, pie, fq_pie,
    pfifo, skbprio, sfb and hhf;
  - choke's `min` and `max`, and fq's `flow_limit`;
  - HTB's `direct_qlen`, and netem's slot `packets`;
  - the declarative `QdiscBuilder::limit`.

  The matching public fields take it too, so a byte count passed where the
  kernel counts packets, or the other way round, is a compile error.
  `Packets` displays as tc(8) writes it (`1000p`), parses with or without
  the `p`, converts from `u32`, and serializes as a plain number, so
  declarative documents read and write as before. The tc(8) parse is
  unchanged. The parsed `tc_options` views stay raw, as their byte and rate
  fields do, and the `flows` counts stay `u32`, since they count queues.

### Fixed

- **`NetworkConfig::validate()` refuses what the apply would fail on
  (#518).** It runs before every diff and apply, so these are refused
  before anything changes. Before, each failed mid-apply, after earlier
  links were created, or never converged:
  - a kind setter called on another kind, which did nothing, such as
    `.miimon()` on a dummy. `LinkBuilder` now records it, as
    `QdiscBuilder` does since #476;
  - a VNI past 24 bits;
  - an IPv4 route with host bits set (`10.0.0.1/24`), which the kernel
    refuses with `EINVAL`. IPv6 masks them, as before;
  - route table 0, which the kernel reads as main while the diff
    compared it as 0 forever;
  - a cycle of masters;
  - a VLAN declared up on a lower device declared down, and a MAC
    address on an ovpn or L3 netkit link. Both checks used to run later,
    in the diff and the apply.

  The diff also reports a parent (VLAN, macvlan, VXLAN underlay) or master
  that a declared link names, when the config does not declare it and it
  does not exist, in `links_missing`. So the apply refuses before creating
  anything.

- **Connections know their namespace, and a pool or watch never moves
  to a namespace recreated under its name (#520, part 2).**
  - **`Connection::netns()`** gives the namespace a connection's socket
    lives in. It is exact for one made in a namespace. For one made with
    `new()` it asks the kernel (`SIOCGSKNS`), or without the privilege
    gives the caller's namespace.
  - **`sibling::<Q>()` and `sibling_async::<Q>()`** make a connection of
    another protocol in the same namespace.
  - **A connection from a `Netns`** (`Connection::new_in(&netns)`, under
    Breaking Changes, #532) makes its sockets on one worker thread per
    handle; `new_in_namespace` spawns and joins a thread per socket.
    Those sockets carry the namespace's marker, so a stream on them ends
    with `NamespaceDeleted` when the name is deleted, like a path-opened
    one. `Netns::from_fd` and `is_live()` are new.
  - **`ConnectionPool` and the `*_changes_in_namespace` watches** open the
    namespace once and make every connection there. A replacement or a
    resync used to look the name up again, so after the namespace was
    deleted and a new one created under the same name, it silently
    joined the new one. Now it fails with `NamespaceDeleted`. A root
    test recreates a pool's namespace and fails without the fix.

- **fq_pie's `ecn_prob` is a percentage (#631).** `FqPieConfig::ecn_prob`
  sent `TCA_FQ_PIE_ECN_PROB` per-mille, so `ecn_prob 20` installed 200.
  That is above the kernel's maximum probability, so ECN marking applied
  at any drop probability. The reader divided by 10, so nlink's own round
  trip agreed with itself. As a result, the kernel's default of 10 read
  back as 1 %. A fractional percentage, which the kernel can't hold, is
  now refused by `write_options` and `parse_params`.

- **Netem percentages are rounded the way tc rounds them (#633).**
  `Percent::as_kernel_probability` truncated where tc(8) rounds to
  nearest. For `loss 1%`, nlink put 42949672 in the kernel and tc
  42949673. The bigger problem was the read-back comparison, which
  truncated as well. For about 8 % of probabilities the read back came
  out one unit short, and those include everyday values such as 0.3,
  1.2, 2.4, 5.2, 9.9 and 20.1 %. A `PerPeerImpairer` or `NetworkConfig`
  netem with one of them never matched its own echo, so it was replaced
  on every reconcile. Both conversions now round, and so does
  `percent_to_prob`. A root test installs the same netem through `tc`
  and through nlink and compares the kernel's dumps byte for byte.

- **cake agrees with tc and the kernel (#635).** Each of these was found
  by installing cake through `tc` and through nlink and comparing the
  kernel's state.
  - A replace turns a flag off. `CakeConfig` sent `nat`, `wash`,
    `ingress` and autorate only when they were on, and `cake_change`
    keeps any attribute it isn't sent. Once set, those flags stayed on.
  - `no-split-gso` reaches the kernel. `split_gso` defaulted to false
    while the kernel's default is on, and false was never sent, so every
    nlink cake split GSO segments.
  - `rtt` sets the target as tc does: tc sends a twentieth of the RTT as
    the target. `rtt 50ms` used to leave the kernel's 5 ms target in
    place.
  - `CakeOptions::raw` reads raw mode from the attribute's presence.
    `cake_dump` sends it with the value 0, so it always read false.

- **A default sfq has 128 flows, as tc's does (#637).** `SfqConfig::new()`
  always sent `limit 127`. A limit caps sfq's flows (`sfq_change`), so an
  nlink sfq had 127 flows. The default limit is now 0, which leaves the
  kernel's, as tc does.

- **A recipe removes only its own tree (#515).** `PerHostLimiter::remove`
  and `PerPeerImpairer::clear` deleted whatever root qdisc the device
  had: a user's TBF, or the other recipe's tree. `remove` also swallowed
  every error. Each now deletes the root only when it is the tree it
  builds: the HTB `1:` with its default class, with fq_codel leaves for
  the limiter or netem leaves for the impairer. Errors other than
  "already gone" are returned.
- **`Batch::add_qdisc` puts a qdisc where `add_qdisc` does (#515).** An
  ingress or clsact goes to its hook, and a classful kind to `1:`. It
  used to send every qdisc to the root, where the kernel refuses an
  ingress.

- **Ethertypes parse in tc's number bases (#515).** Flower's `eth_type`
  read a bare number as hex, so `2048` meant 0x2048 rather than IPv4.
  The ethertypes of the mpls, skbmod and ife actions took no octal.
  All four now go through `EthProto`, which reads numbers the way
  `strtoul(s, NULL, 0)` does.

- **`nlink-tc`: `filter show` lists filters, and `qdisc add DEV clsact`
  works.** `filter show` sent a filter dump that named no device and no
  hook, which the kernel answers with nothing, so it never printed a
  filter. It now uses the library's per-device dumps, which sweep the
  root and the ingress/clsact hooks. `qdisc add` sent `ingress` and
  `clsact` to its default `--parent root`, which the kernel refuses; it
  now sends them to their hook, as `tc qdisc add dev X clsact` does.

- **Deleting an IPv4 address removes the one it names (#516).** The
  delete sent only `IFA_LOCAL`, and `inet_rtm_deladdr` then deletes the
  first address with that local, whatever its prefix or peer. Removing
  `10.7.0.1/16` took `10.7.0.1/24` when both were there; so did a purge or
  a `previous` removal. It now sends `IFA_ADDRESS` too: the peer, or the
  address. A root test deletes one of two prefixes and one of two peers.
  It fails without the fix.

- **`get_bridge_vlans` and `get_bridge_vlans_all` return the ports'
  VLANs (#516).**
  - `get_bridge_vlans(port)` sent a single-link `RTM_GETLINK`. The kernel
    answers that with the generic handler, whose reply carries no VLANs,
    so it returned nothing for every port.
  - `get_bridge_vlans_all(bridge)` dropped every entry but the bridge's
    own before matching ports by master, so no port's VLANs came back.

  Both now read the `AF_BRIDGE` dump. A root test adds a VLAN to a port
  and finds it through both. It fails without the fix.

- **GRE keys and tunnel underlay devices reach the kernel (#516).**
  - **Keys.** `GreLink` and `GretapLink` wrote the key and its `GRE_KEY`
    flag native-endian, while the kernel reads them big-endian. The flag
    read as no key, and `.key(100)` made a tunnel without one.
  - **Underlay.** `GreLink`, `GretapLink`, `IpipLink`, `SitLink`,
    `VtiLink` and `Vti6Link` sent their `.link(dev)` as the top-level
    `IFLA_LINK`, but a tunnel binds through its own link attribute
    (`IFLA_GRE_LINK`, `IFLA_IPTUN_LINK`, `IFLA_VTI_LINK`). The tunnel was
    never bound. `Ip6GreLink` already did it right.

  The GRE root test now checks both through `ip -d -j link`. It fails
  without each fix.

- **A Geneve flow label is sent big-endian (#516).** `GeneveLink::label`
  wrote it native-endian, while the kernel reads it with `nla_get_be32`.
  A label set on a little-endian host was a different one: `0x12345` was
  stored as `0x30100`. A root test checks it through `ip -d -j link`, and
  fails without the fix.

- **MACsec SCIs and ports are big-endian, as the kernel and `ip macsec`
  have them (#516).** `MacsecLink::sci` and `port` were sent
  native-endian. An SCI of `0x0200000000010001` (MAC
  02:00:00:00:00:01, port 1) became `0100010000000002`, and a port of 7
  was another port. The MACsec Generic Netlink API read and wrote SCIs
  the same way: consistent with itself, byte-reversed against everything
  else. Both now use big-endian. A root test checks both through
  `ip -d -j link` and `ip macsec show`, and fails without the fix.

- **`flush_fdb` keeps static entries (#663).** It promised to flush only
  dynamic entries, and it deleted static ones too.
  - The cause: `FdbEntry::is_dynamic()` was `!is_permanent()`, and a
    static entry (`NUD_NOARP`, `bridge fdb add … static`) is not
    permanent, so it counted as dynamic.
  - `FdbEntry::is_static()` is new, and `is_dynamic()` now means neither
    static nor permanent.
  - The `nlink-bridge` bin shows static entries as `static`.
  - A root test adds a static, a permanent and a dynamic entry with
    `bridge fdb`, then flushes. It fails without the fix.
- **`FdbEntryBuilder` documented a local entry as a static one (#663).**
  - **`permanent()` is a local entry on a bridge.** `permanent()`, the
    default, sends `NUD_PERMANENT`. On a bridge that is a *local* entry:
    the MAC is the bridge's own, and frames for it go up the bridge's
    stack, not out of the port. It is what `bridge fdb add` makes too.
    The docs called it static, and so did the module, builder,
    `docs/library.md` and example code.
  - **`static_()` is new.** `FdbEntryBuilder::static_()` sends
    `NUD_NOARP`: a forwarding entry that never ages. `nlink-bridge fdb
    add --static` uses it.
  - **The VXLAN remote examples failed.** They had no `.self_()`, and a
    VXLAN device that is not a bridge port fails that with `EOPNOTSUPP`.
    A root test pins it.

- **`del_rule_by_priority` and `flush_rules` delete any rule, not only
  main-table lookups (#667).**
  - **The cause.** `RuleBuilder` defaulted to action `lookup` and table
    254, and its delete sent both. The kernel's `rule_find` matches a
    delete's action and table when they are set. So
    `del_rule_by_priority` found only a rule that looked up the main
    table. Any other rule was `ENOENT`: another table, a blackhole, a
    prohibit.
  - **The flush.** `flush_rules` ignored that error and left those rules
    in place. It now returns any error other than "already gone".
  - **The fix.** A delete now sends only the action and table that were
    set. An add looks the main table up by default, as before.
  - **Drop rules.** A drop rule is now added with no table, as `ip rule`
    adds it, where it used to be sent table 254.
  - **Tests.** Root tests cover each case, and fail without the fix.

- **`get_nsid`, `get_nsid_for_pid` and `set_nsid` work (#669).**
  - **They failed on every call.** Each appended the one-byte `rtgenmsg`
    with `append`, which pads it to four bytes, then padded it by three
    more. The `NETNSA_*` attribute sat four bytes past where the kernel
    reads it, so every call failed with "Peer netns reference is missing"
    (`EINVAL`).
  - **`nlink-ip netns` too.** Its nsid lookups failed the same way.
  - **Test.** A root test sets an id and reads it back by fd and by the
    pid of a process inside the namespace. It fails without the fix.

- **Nexthop group weights are the ones `ip nexthop` uses (#672).**
  - **The wire value.** `struct nexthop_grp` carries each member's
    weight minus one.
  - **Writing.** `NexthopGroupBuilder::member(id, weight)` sent the
    weight as given, so `member(2, 3)` made a member the kernel weighs 4.
    `.member(1, 1).member(2, 3)` was a 1:2 split, not 1:3. Equal weights
    hid it.
  - **Reading.** `NexthopGroupMember::weight()` returned the wire value,
    so `ip nexthop`'s `1/2,3` read back as 0 and 2.
  - **The fix.** Both now use the real weight, as a `u16`. A weight over
    256 goes through `weight_high` (kernel 6.12).
  - **Tests.** A root test checks both directions against iproute2, and
    fails without the fix.

- **A blackhole nexthop, or one with a device alone, can be made (#673).**
  - **The bug.** `NexthopBuilder` sent `AF_UNSPEC` when there was no
    gateway. The kernel takes that only for a group, so both kinds
    failed with "Invalid address family".
  - **The fix.** Without a gateway the builder now sends `AF_INET`, as
    `ip nexthop` does. `NexthopBuilder::ipv6()` makes an IPv6 one.
  - **Test.** A root test creates both, and fails without the fix.

- **MPLS routes can be added and deleted (#678).** Every MPLS request
  nlink made failed.
  - **Label entries carried a TTL.** `MplsEncap` put one in the bottom
    label entry (255, or what `.ttl()` set), and so did a swap route's
    `RTA_NEWDST` stack. The kernel takes label entries only with TTL 0:
    "TTL in label must be 0". The encapsulation's TTL is
    `MPLS_IPTUNNEL_TTL`'s, which nlink already sends separately.
  - **Table and type were unset.** `MplsRouteBuilder` and
    `del_mpls_route` left `rtm_table` at 0, where the kernel takes only
    main ("MPLS only supports the main route table"). The delete also
    left `rtm_type` at 0, where only unicast is accepted.
  - **Tests.** Root tests add an encapsulated route, checking its TTL,
    and add and delete a swap route. They fail without the fix.

- **`BpfFilter::from_pinned` and `BpfAction::from_pinned` failed on every
  real pin (#710).** They opened the pin with `open(2)`, which bpffs
  refuses (`EIO`): a pinned program's inode has no usable `open`.
  - Both now open it with `bpf(BPF_OBJ_GET)`.
  - The fd is held so that clones share it, and it is closed with the
    last clone. Both used to leak it.
  - `BpfAction`'s open failure is an io error now, not `InvalidMessage`,
    so a missing pin answers `is_not_found()`.
  - `BpfFilter::parse_params` had a third copy of the `open(2)` path, for
    `pinned`/`object-pinned`. It goes through the same opener now. So do
    `nlink-tc filter … bpf pinned <path>`, `nlink-tc action … bpf pinned
    <path>` and `examples/route/tc/bpf.rs`.
  - **Test.** A root test loads and pins a program of each type, then
    attaches them as a filter and as an action. It needs `CAP_BPF` in the
    initial user namespace, so it skips in the rootless CI lane.
    `cls_bpf` and `act_bpf` join the CI module lists.

- **I/O and batch failures keep their errno (#526).**
  - **Namespaces.** The namespace code reported a failed file operation
    as an "invalid message" with the I/O error printed inside it, so
    `is_busy()`, `is_permission_denied()` and the rest answered false for
    it. The affected operations:
    - removing a namespace file or a stale marker;
    - saving, opening or restoring the current namespace;
    - creating a namespace file, its directory or an owner tag;
    - writing a spawned command's cgroup.

    Each is now the I/O error, with what was being done as its context:
    `remove namespace file /var/run/netns/red: I/O error: Device or resource
    busy`.
  - **Batches.** `Batch::execute_all` returned a string of the first
    failed operation's error. It now returns that error, with `batch
    operation N` as its context, so `is_already_exists()` and the rest
    answer.
  - **Worker threads.** A namespace worker thread that panicked or went
    away was also an "invalid message". It is `ErrorDetail::Internal` now,
    kind `Other`.
  - **Test.** A root test adds an existing link through `execute_all` and
    checks `is_already_exists()`. Before, the error was `invalid message:
    batch operation failed: kernel error: File exists (errno 17)`, and the
    test failed.

- **`is_not_found()` missed a delete's "not there" (#526).** The kernel
  answers a route delete that matches nothing with `ESRCH`, and an address
  delete with `EADDRNOTAVAIL`. `kind()` read the errno alone, so neither
  was `NotFound`. Three `del_*_if_exists` methods special-cased one errno
  each, and every other caller had to as well.
  - A kernel error now records the `nlmsg_type` of the request it refused
    (`ErrorDetail::Kernel::request_type`, `Error::request_type()`).
  - `kind()` reads the errno against the request type, and
    `is_not_found()` follows it.
  - The special cases are gone.
  - **Test.** A unit test builds the kernel's refusals from `NLMSG_ERROR`
    payloads: `ESRCH` to `RTM_DELROUTE` and `EADDRNOTAVAIL` to
    `RTM_DELADDR` are not-found, and `ESRCH` to `RTM_NEWROUTE` is not.
    With the errno read alone, the test fails.

- **`kind()` read a request type without its protocol (#722).** #719
  classifies `ESRCH` to a route delete and `EADDRNOTAVAIL` to an address
  delete as `NotFound`, keyed on the refused request's `nlmsg_type`. Type
  numbers mean something only within a protocol: 25 is also
  `XFRM_MSG_UPDPOLICY`, 21 is `XFRM_MSG_GETPOLICY`, and a generic-netlink
  family can have either id. Any of those refusals answered
  `is_not_found()`.
  - A kernel error now records the protocol it came back on
    (`ErrorDetail::Kernel::protocol`, `Error::protocol()`). The
    connection's request, ACK and dump paths and `Batch` fill it in.
  - The two pairs apply on rtnetlink only.
  - **Test.** A unit test refuses type 25 with `ESRCH` and type 21 with
    `EADDRNOTAVAIL` over xfrm and generic netlink; neither is
    `NotFound`. Without the protocol check, the test fails.

- **TC docs gave wrong handles and units (#723).**
  - `RateLimiter`'s docs said its leaf class is `1:10` with default `0x10`.
    The minor is decimal 10, so it is `1:a`, default `0xa`, leaf `a:` in
    tc(8)'s hex notation.
  - `ChokeConfig`'s fields and example called its limits bytes. `sch_choke`
    counts packets, as its setters already said.

  The installed trees are unchanged.

- **nftables: a declared change between two values could be missed
  (#721).** The diff compares rules by normalized expression bytes, and the
  normalizer guessed which attributes were nests: it recursed into any
  payload that parsed as attributes and dropped empty ones. A 4-byte value
  such as `04 00 05 00` parses as one empty attribute. That covers `ip daddr
  4.0.5.0`, and on a little-endian host every mark with `0x0004` in its low
  half. The value was dropped, so `4.0.5.0` and `4.0.6.0` compared equal and
  a change between them diffed empty and was never applied. Unkeyed rules
  hash their derived key through the same normalization, so two such rules
  could also collide.
  - The normalizer follows the kernel's schema now. It walks `NFTA_LIST_ELEM`
    into name and data, and recurses only into the attributes each
    expression declares as nested:
    - `cmp` and `immediate` data;
    - `range` bounds;
    - `bitwise` mask, xor and data;
    - `dynset` expressions.

    Within those, a value is a leaf and a verdict a nest of leaves.
  - **Derived keys.** A kernel rule's derived `~` key is computed again
    from its own canonical body rather than read from its userdata. So rules
    an earlier nlink installed still match their declarations, and upgrading
    replaces none of them.
  - **Tests.**
    - Unit tests: two addresses and two marks that look like attributes
      still differ, and so do their derived keys. A kernel rule with a stale
      `~` key is re-keyed to its declaration, ordinals included.
    - A root transition changes a keyed `ip daddr` from `4.0.5.0` to
      `4.0.6.0` and reads the result back with `nft`.

- **An enum value newer than nlink no longer fails a whole GENL message
  (#727).** `#[derive(GenlMessage)]` and `#[derive(NetlinkAttrs)]` returned
  `InvalidMessage` when an enum-typed field carried a value its `GenlEnum`
  had no variant for. Every other attribute in the frame was lost with it.
  The YNL spec gate (#167) showed the case: v7.x adds `DPLL_TYPE_GENERIC`.
  On a kernel with such a device, `get_devices` failed, and the DPLL event
  stream dropped that device's notifications. An unknown value now reads as
  an absent attribute: an `Option<E>` stays `None`, and a `Vec<E>` skips the
  element. This is how the derives already treat unknown attributes and
  unknown flag bits. It affects every enum field in dpll, ovpn and
  net_shaper.

- **Errors that wrapped an OS error as a message keep the error (#718).**
  Each of these was an `InvalidMessage` string, so `errno()` was `None` and
  `kind()` said `Invalid`, whatever had happened:
  - opening a pinned BPF program from `BpfFilter`/`BpfAction::parse_params`;
  - a failed duplicate of a BPF program fd;
  - `Netns` refusing a file that isn't a namespace (`ENOTTY`);
  - `NetworkConfig::{from_json_str, to_json_string, to_json_string_pretty}`,
    whose detail is `ErrorDetail::Json` now, with serde's line and column;
  - `nlink-ip vrf exec` and `vrf identify`.

  Each now keeps its source under a context. Mirred's `dev` lookup in
  `parse_params` is `InterfaceNotFound` (`is_not_found()`), not a parse
  error. `get_bond_info` reports a missing interface as not found. A
  panicked lab helper is `ErrorDetail::Internal`.

- **`--features serde` without `output` compiles again (#741).**
  `ErrorDetail::Json` and its `From<serde_json::Error>` were gated on
  `output` alone, so the JSON helpers' error (#718) didn't compile under
  `serde` or `schemars` by themselves. CI now checks both features on their
  own, and the integration lane builds with `serde`.

- **A mirred `dev <name>` is looked up in the right namespace (#645).**
  `MirredAction::parse_params` used to read `/sys/class/net` in the calling
  process's namespace. For a connection in another namespace, that found the
  wrong device or none at all. The name is now resolved by the connection
  that installs the action.
- **`RouteFilter::from_if(name)` can be installed (#645).** Nothing resolved
  the name, so every install failed.

- **`is_goto_chain(TC_ACT_UNSPEC)` is false (#645).** The goto test checked a
  single bit, and `continue` (-1) has every bit set, so it read as a goto to
  chain 16777215. It now compares the opcode nibble, as the kernel's
  `TC_ACT_EXT_CMP` does. `tc_act_goto_chain` and `tc_act_chain` keep 28 bits of
  chain (`TC_ACT_EXT_VAL_MASK`), where they used to cut it to 24.
- **A gate's `base-time` in whole nanoseconds is read exactly (#645).** Before,
  an absolute time lost precision through a float.
- **An ife `use tcindex` over 65535 is refused (#645).** It used to be truncated
  to 16 bits.

- **police's `conform-exceed` is read exceed first, as tc(8) reads it
  (#751).** tc-police(8)'s form is `conform-exceed EXCEEDACT[/NOTEXCEEDACT]`.
  nlink took the first value as the conform action. So `conform-exceed
  drop/pipe` dropped the traffic that conformed and piped the traffic that
  exceeded, with no error, in `PoliceAction::parse_params` and in `nlink-tc`.
  The conform half is now optional, as in tc(8).
- **A gate's bare times are nanoseconds (#751).** tc-gate(8) reads a bare
  `base-time`, `cycle-time` or `sched-entry` interval as nanoseconds. nlink
  read it as microseconds, a thousand times too long. A bare decimal is now
  refused.
- **A gate interval past `u32` nanoseconds is refused (#751).** That's about
  4.29 s. `GateAction::sched_entry` used to wrap it; writing the action now
  says so.
- **ct reads tc(8)'s `nat` (#751).** `nat src|dst addr <range>` was refused,
  because the `addr` keyword wasn't read. A bare `nat`, which NATs as the
  conntrack entry says, was refused too. The old form without `addr` still
  reads. `CtAction::nat()` is new.

### Added

- **`Netns`, an owned network namespace handle (#520).**
  `nlink::netlink::namespace::Netns` owns an fd to a namespace, so what
  it names cannot change under it. A namespace deleted and recreated
  under the same name is a different one, with a different `NetnsId`
  (the nsfs device and inode).
  - **Opening:** `open(name)`, `from_path`, `from_pid`, `from_pidfd` (the
    pidfd ioctl on 6.11+, a reuse-safe fdinfo fallback before),
    `current()` and `init()`. `create(name)` makes one and opens it.
  - **Deleting:** `delete()` deletes the `ip netns` name only while it
    still names this namespace.
  - **Working inside it:** `run(f)` runs a closure, which may borrow, on
    a thread of its own inside the namespace. `socket(domain, ty,
    protocol)` makes a socket there, for capture or TCP probes.
    `connection::<P>()` and `connection_async::<P>()` connect there.
  - **`NetnsRef`** (`Default`, `Named`, `Path`, `Pid`) is the owned,
    `Clone + Eq + Hash`, serde-able description for configs and state
    files. `open()` turns it into a `Netns`.

  `namespace.rs` became the `namespace/` module; the existing API is
  unchanged.

- **`ErrorKind`, and context that stacks (#526, first part).**
  - `Error::kind()` classifies every error, kernel or not, in one answer:
    `NotFound`, `AlreadyExists`, `Busy`, `PermissionDenied`,
    `NotSupported`, `InvalidArgument`, `TryAgain`, `Restart`,
    `DumpInterrupted`, `Overrun`, `Timeout`, `Validation`, `Invalid`, and
    more. It comes with `ErrorKind::from_errno` and `is_retryable()`, and
    serializes under `serde`. The `is_*` predicates stay and agree with
    it.
  - A second `with_context` on a kernel error keeps both, as
    `"outer: inner"`. It used to drop the second one.
  - `ResultExt::context` adds context to a `Result`'s error, so a call
    site no longer needs `map_err`.

- **A config diff against a snapshot, and an apply that verifies (#518,
  part 2).**
  - `Snapshot::read(&conn)` reads what a diff needs, including what a
    recreate would destroy. `NetworkConfig::diff_snapshot(&snapshot,
    opts)` diffs against it with no kernel read, so a plan, its dry run
    and a comparison of two candidate configs can see one state.
    `compute_diff_with_options` is now a snapshot read and a pure diff.
  - `ApplyOptions::with_verify(true)` diffs again after the apply and
    fails with `Error::NotConverged { remaining }` if anything is left:
    a change the kernel did not take as expected, or a concurrent
    change. `ErrorKind::NotConverged` goes with it.

- **Purge by the previous config (#512, part 1).**
  `DiffOptions::previous(cfg)` and `ApplyOptions::with_previous(cfg)`
  take the config applied before. The diff then removes exactly what
  that config declared and this one does not, while the kernel still
  has it, and nothing undeclared:
  - its addresses;
  - its routes, in whatever table they were. A route moved from table
    100 to table 200 no longer leaves its old copy, which `purge` could
    not reach once nothing declared into table 100;
  - its root and ingress qdiscs, through the new
    `ConfigDiff::qdiscs_to_remove`. The apply deletes them, and the
    kernel puts its default back.

  It works with or without `purge`; with both, the diff removes the
  union. Deleting links the previous config declared is part 2.

- **The previous config's links are deleted when this one drops them
  (#512, part 2).** With `DiffOptions::previous` /
  `ApplyOptions::with_previous`, a link the previous config created and
  this one does not declare goes in the new `ConfigDiff::links_to_remove`
  (`LinkRemoval`), with the links the kernel deletes along with it. It is
  deleted before anything is created, since a replacement can conflict
  with it (the same VLAN id on the same parent).
  - **Only a link the config created.** It must have been declared with a
    kind, and must still be in the kernel with that kind. A physical or
    kindless device the previous config only configured is never
    deleted, and neither is a link of the same name another actor made
    with another kind.
  - **Refusals.** Deleting a link also destroys what it carries. What no
    config declared there refuses the removal, before anything changes,
    as it refuses a recreate: an address, a route, a qdisc or class, an
    FDB entry or neighbour, a port. This is the recreate's logic, shared.
    nlink-lab asked for this (its #159): a VLAN removed from a running lab
    stayed in the kernel.

- **A recreate policy, and state the caller owns (#513, part 2).**
  - `DiffOptions::recreate_policy` / `ApplyOptions::with_recreate_policy`
    take a `RecreatePolicy`. `Refuse` is the default and refuses as
    before. `Allow` lets every recreate and removal through.
    `AllowDestroying(BlockerFilter)` lets one through when every blocker
    passes the filter: "routes a routing daemon re-learns", say, which is
    why `Blocker::Route` now carries its `protocol`. A link kind that
    cannot be recreated at all still refuses under any policy.
  - `caller_owned([Owned::RootQdisc { dev }, Owned::IngressQdisc { dev },
    Owned::RouteTable { table }])` names state the caller manages itself.
    It never refuses a recreate or removal, and is never purged. Owning
    a device's root or ingress qdisc means owning its TC tree.
  - What a recreate or removal destroys under either rule is in its
    `destroys`, and `ApplyResult::destroyed` collects it: what the caller
    puts back. nlink-lab took its TC and VRF routes off before an apply
    and put them back after, and declared fake qdiscs for `--check`, to
    get the same effect.

- **Offline recreate prediction (#513, part 3).**
  `NetworkConfig::diff_against(&previous)` predicts, with no kernel,
  which links going from `previous` to this config recreates:
  `OfflineDiff { recreates: [OfflineRecreate { name, reason, certainty }] }`.
  It runs the comparison a live diff runs, against the link the kernel
  would hold for `previous`: the declaration encoded as the apply sends it
  and parsed back as a dump. So it cannot drift from the apply.
  - A parameter `previous` left to a module parameter's default (the
    VXLAN port, a bond's `lacp_rate` or `ad_select`) makes the recreate
    `Certainty::IfKernelDefaultDiffers`.
  - What is stacked on a recreated link is recreated with it.
  - What the live state would block cannot be known offline. The live
    diff's `links_to_recreate` says that.

  A root test checks it against the kernel over nine transitions: every
  certain prediction is recreated live, and nothing live goes
  unpredicted. nlink-lab can drop its 342-line mirror of `kind.rs`. The
  per-kind link builders are now built by one `link_config`, and
  `Box<dyn LinkConfig>` is a `LinkConfig`.

- **An owner tag finds a config's links again (#512, part 4).**
  `NetworkConfig::owner(tag)` writes `tag` as the alias (`IFLA_IFALIAS`)
  of every link the apply creates. With `purge`, a link that carries the
  tag and that the config no longer declares is removed, through the same
  path as a link the previous config declared. Everything on a tagged link
  goes with it. What the kernel would destroy with it that cannot be
  declared refuses the removal: an untagged link stacked on it, FDB
  entries, neighbours. This is how a caller finds its links again with no
  record of the config it applied before, after a crash for instance.

- **Qdisc handles, and the kernel's root on demand (#514, part 1).**
  - `QdiscBuilder::handle(TcHandle)` installs a declared qdisc at that
    handle. A classful kind (HTB, prio) defaults to `1:`, so its classes
    and filters can name it; the others get the kernel's choice. The diff
    replaces a qdisc whose live handle differs. In JSON it is `"handle":
    "1:"`, tc(8)'s notation. A declared prio used to land at an automatic
    handle (`8001:`); it is replaced once.
  - `QdiscBuilder::kernel_default()` declares the kernel's own root qdisc:
    the diff removes whatever root is installed (`qdiscs_to_remove`), and
    the kernel puts its default back.

- **`block`/`unblock`, and boxed qdisc configs (#515, part 1).**
  - `Connection::block(dev, Direction)` drops everything a device
    receives or sends. It adds a clsact if the device has none, then a
    `matchall` + `gact drop` filter at priority 1 on that side. The root
    qdisc and its tree are left alone. Replacing the root with a 100 %-loss
    netem, nlink-lab's way to partition a lab, destroyed a prio, TBF or
    HTB setup. `unblock` deletes that filter, and `is_blocked` reports it.
    A plain `ingress` qdisc refuses, since blocking would replace it.
  - `QdiscConfig` is implemented for `Box<T>` and `&T`, so
    `conn.replace_qdisc(dev, Box<dyn QdiscConfig>)` works. nlink-lab
    carried an enum of every config type to get that.

- **netem: slot, ECN, a PRNG seed, rate overheads and delay
  distributions (#515, part 2).**
  - `NetemConfig` gains `ecn`, `slot(NetemSlot)`, `seed(u64)`,
    `distribution(NetemDistribution)` and `rate_overhead(packet, cell_size,
    cell)`. `parse_params` accepts their tc(8) tokens instead of
    refusing them: `ecn`, `slot MIN [MAX] [packets N] [bytes N]`,
    `seed N`, `distribution NAME` and `rate R [OVERHEAD [CELLSIZE
    [CELLOVERHEAD]]]`. The same tokens through `tc` and through
    `parse_params` give the same `tc -d qdisc show` line.
  - A seed makes loss repeatable: the same seed drops the same
    packets of the same traffic, run after run (Linux 6.3+). The kernel
    keeps a seed across a change that does not send one.
    `NetemOptions::seed()` reads it back.
  - `NetemDistribution::named("normal")` reads iproute2's `.dist` tables
    from where tc(8) looks: `$TC_LIB_DIR`, `/usr/lib/tc`, `/usr/lib64/tc`,
    `/usr/lib/<triplet>/tc`. `from_file` and `from_table` take your own.
    The kernel never dumps a table, so a reconcile cannot see one.
  - `PerPeerImpairer`'s comparison covers the new fields.
  - The docs now say that jitter without a rate reorders packets
    (netem's queue is sorted by send time).

- **Qdisc options print in tc(8) syntax, and a netem converts back into
  a config (#515, part 3).**
  - `QdiscOptions` and each kind's options implement `Display`. The text
    is the parameters as they follow the kind on a `tc qdisc add` line,
    for example `limit 1000 delay 10ms 2ms loss 1.2%`.
  - The text also works as input. Given to tc, or to the kind's
    `parse_params`, it installs a qdisc the kernel reports exactly as the
    original. A root test checks this for netem, fq_codel, fq_pie, TBF,
    HTB, prio, sfq and cake.
  - Where the kernel quantises a value, the text holds the smallest
    value it reports the same way. A 20 ms fq_codel target, which reads
    back as 19999 µs, prints as `20ms`. A TBF bucket, which the kernel
    keeps only as a transmission time, prints as the smallest size that
    takes as long.
  - Some values can't be set by the typed config: sfq's `depth`,
    `divisor` and `flows`, and fq_codel's `drop_batch`. These print only
    when they differ from the kernel's default, and `parse_params` then
    refuses the text.
  - `NetemConfig::from(&NetemOptions)` turns the netem the kernel reports
    into a config that installs it again. It keeps the seed. It can't
    keep a delay distribution, because the kernel never reports one.
  - `nlink-tc qdisc show` now prints the options.

- **Bulk, namespace-aware statistics (#525).**
  - `Connection::get_stats64_all()` reads every link's counters in one
    `RTM_GETSTATS` dump (Linux 4.7+), as a map from ifindex to counters.
    It replaces a link dump, or the four dumps of a diagnostics scan, for
    a collector that only wants counters.
  - `StatsSnapshot::capture(&conn)` takes that dump and records when the
    counters were read and in which namespace.
  - `RateSampler` gives link rates across many namespaces. It keys each
    link by namespace and ifindex, so `lo` in one namespace isn't `lo` in
    another. A link renamed at its ifindex, or whose counters went
    backwards, gets no rate for that interval.
  - `Diagnostics::scan_since(&previous)` takes its rates against a report
    the caller kept. A fresh `Diagnostics` used to have no previous sample,
    so its rates were always 0.

- **`del_ingress` and `del_clsact` (#515).** These delete only the kind
  they name, plus `_by_index` variants. The ingress and clsact qdiscs
  share one slot, and `TcHandle::INGRESS == TcHandle::CLSACT`, so
  `del_qdisc` at it deletes whichever is there; a clsact goes with its
  BPF programs. The new methods send the kind, and the kernel refuses
  the other one. When it does, the error names what is in the slot, and
  an empty slot is `QdiscNotFound`.
- **`MirredAction::{redirect_to_egress, redirect_to_ingress,
  mirror_to_egress, mirror_to_ingress}` (#515).** The direction is in
  the name, and the docs say an IFB needs `redirect_to_egress`. The
  `*_by_index` constructors are deprecated.

- **`EthProto` (#515).** An ethertype type with tc(8)'s names (`all`,
  `ip`, `ipv6`, `arp`, `802.1Q`, `802.1ad`, `mpls_uc`, …). It parses
  like iproute2's `ll_proto_a2n`: a name, case-insensitively, or a
  number in any base `strtoul` reads. `Display` prints the name, or
  `0x` and four hex digits. It replaces the `ETH_P_*` constants
  duplicated in five modules, and `nlink-tc`'s own protocol table.

- **One qdisc spec for both paths (#515).**
  - `QdiscSpec` implements `QdiscConfig`, so `conn.replace_qdisc(dev,
    spec)` works.
  - `spec.matches(&live)` is the declarative diff's comparison, in the
    kernel's units and quantisation.
  - `spec.validate()` checks a spec without a kernel.
  - `From<NetemConfig>` and the other configs convert into a spec.
  - `QdiscBuilder::spec(config)` declares a whole config, including what
    the builder has no setter for: netem's slot, seed, ECN and rate
    overheads.
  - With `serde`, `Rate`, `Bytes` and `Percent` serialize in tc(8)'s
    units (`"100mbit"`, `"32kib"`, `"1.5%"`), and
    `util::serde_units::{duration, option_duration}` does the same for a
    `Duration` (`"10ms"`). All of them have JSON schemas.

- **TC verbs: `conn.tc(dev).qdisc(parent)…` (#515).**
  - `create`, `change`, `replace`, `apply`, `delete`, `delete_kind` and
    `get` each have defined semantics, tabled in `tc_verbs`.
  - `create` refuses an occupied slot.
  - `change` changes the live qdisc in place. It refuses another kind,
    and one that only a recreate can change; `replace` does those.
  - `apply` does nothing when the live qdisc already matches the spec,
    and replaces it otherwise. It reports whether anything changed.
  - `delete_kind` deletes only the named kind.
  - `Parent::{Root, Ingress, ClsactIngress, ClsactEgress, Class}` names
    the places that `TcHandle`'s constants mixed up.
  - `Connection::del_qdisc_kind_by_index` is the kind-checked delete
    underneath.

- **Declared TC trees: classes, leaves, filters and the IFB redirect
  (#514).** `NetworkConfig::tc(dev, |t| …)` declares what hangs under a
  device's qdiscs:
  - HTB classes (`class(parent, id, HtbClassConfig)`);
  - the leaf qdisc in a class (`leaf(class, handle, spec)`, any
    `QdiscSpec`);
  - filters with their actions: flower, matchall, fw or u32, named by
    parent, priority and protocol;
  - `redirect_ingress_to(ifb)`: everything the device receives, sent out
    of an IFB by name, so the IFB's root qdisc shapes inbound traffic. The
    target is resolved again at every apply, so a recreated IFB is followed.

  The tree is owned. Under a qdisc it declares classes for, and at a
  parent it hangs filters off, what it does not declare is removed. With
  `previous`, a tree the previous config declared and this one drops is
  removed too. A filter is compared against its dump attribute by
  attribute, and its actions by what they do (mirred target, gact verdict,
  police rate), so a filter that differs is replaced and one that matches
  is left alone.

  `ConfigDiff::tc` lists the changes per device and `Display` prints
  them. The apply diffs each tree again after the qdisc step, since a
  root qdisc replaced or a link recreated takes its tree with it. Classes
  and filters a tree declares no longer block a recreate: the apply puts
  them back. `validate()` reports:
  - a class declared twice;
  - a parent class or a leaf's class that is not declared;
  - a class under another qdisc's major;
  - two filters with one name;
  - a redirect on a device with no ingress or clsact qdisc.

  Root tests cover:
  - a tree changed A→B in place and then cut down, with every step
    converging and checked through `tc -j`;
  - an IFB redirect into a 100% netem loss, which drops every datagram and
    goes away with `previous`;
  - a VLAN recreated for an id change, which gets its tree back.

  Both the recreate test (without the blocker change) and the transition
  test (without the `TC_H_ROOT` parent of a top HTB class) fail against
  the code without their fixes. Trees are not in the JSON/YAML form yet: a
  filter's actions have no document shape.

- **The apply is a plan of steps, with a journal that undoes it (#518).**
  `ConfigDiff::plan() -> Plan { steps: Vec<Step> }` lists every kernel call
  an apply makes, in the order it makes them.
  - **Hidden steps are explicit now:**
    - an MTU raised before a link stacked on it is created;
    - a bridge MTU pinned again after its ports moved it;
    - a VLAN held down after its lower device came up;
    - an IPv6 address's old prefix removed right before the new one is
      added;
    - refusals (a missing link, a route someone else owns, a recreate or
      removal that would destroy undeclared state).
  - **What runs is what prints.** `Plan::apply` runs the steps in order,
    and `ConfigDiff::apply` is now `plan().apply()`, so the printed plan
    and the executed one cannot drift apart. `Display` numbers each step,
    with its reason where the plan knows one.
  - **Replaces are changes.** A route that replaces one in its place is
    `Step::ReplaceRoute { before, after }`. The diff prints it as
    `~ route … (replacing …)` instead of `+`.
  - **Journal and undo.** `ApplyResult::journal` records each step that
    changed something, with `Step::inverse()` where one can be known:
    addresses and routes added or removed, links created, a link's state,
    MTU, master and MAC, and qdiscs the previous config declared.
    `ApplyResult::undo()` is the plan that puts those back, last first;
    `irreversible()` lists what it cannot.
  - **Tests.**
    - Unit tests pin the step order (the hidden steps included), the
      rendering and the inverses.
    - A root test applies B over A (an MTU, a new address, a route's
      gateway), runs B's undo, and finds A's diff empty again. It fails
      when the replaced route is not recorded: the step then prints as `+`
      and its undo deletes the route instead of restoring it.
    - The whole root suite runs through the new executor.

- **Declared addresses carry their attributes (#516, row 1).**
  `NetworkConfig::address_with(dev, cidr, |a| …)` declares a peer, an IPv4
  label, a metric (`IFA_RT_PRIORITY`), the flags `nodad`, `optimistic`,
  `noprefixroute`, `home` and `mngtmpaddr`, and valid and preferred
  lifetimes. Each is also a field of the JSON form (`peer`, `label`,
  `metric`, `flags: [..]`, `valid-lft`, `preferred-lft`). A setter the
  family has no use for is a validation error, as is a label not starting
  with the device name, or a preferred lifetime longer than the valid one.
  - **In-place changes.** An IPv4 metric or lifetime, or an IPv6 flag,
    metric or lifetime, is changed with `NLM_F_REPLACE`
    (`ConfigDiff::addresses_to_change`, `Step::ChangeAddress`).
  - **Recreates.** An IPv4 label or flag, which a replace leaves as it
    was, and an IPv6 metric going back to none, which `inet6_addr_modify`
    skips, are a delete right before the add.
  - **Peers.** For IPv4, a different peer is another address, as in the
    kernel.
  - **Not compared.** A lifetime counts down, so it is compared as
    finite-or-forever only. `optimistic` is cleared when DAD ends, so it
    is not compared.
  - **Purge.** A purge still leaves lifetime'd addresses alone, because it
    can't tell them from a DHCP lease. A declared one that the config
    drops goes through `previous`.
  - **New accessors.** `AddressMessage::metric()` and `peer()`.
  - **Test.** A transition test changes every attribute A→B→none,
    converging at each step and checked through `ip -j addr`. It fails
    with a label change made in place, and with an IPv6 metric reset in
    place.

- **Declared routes carry a source, a scope, `onlink` and metrics (#516,
  row 2).** `RouteBuilder` gains `src`, `scope`, `onlink`, `mtu`,
  `advmss`, `window`, `initcwnd`, `initrwnd` and `hoplimit`. The JSON form
  has the same fields (`scope` by name).
  - **Comparison.** The diff compares each attribute. A replace drops what
    it isn't sent, so an attribute left out of the declaration is one the
    route must not have. The scope is compared only when declared, because
    the kernel otherwise picks link for a route without a gateway and
    global for one with.
  - **Imperative side.** `RouteMessage` now parses `RTA_METRICS`
    (`metrics()`) and exposes `flags()` and `is_onlink()`. `Ipv4Route` and
    `Ipv6Route` gain `onlink()`, which only `NextHop` had.
  - **Undo.** The route a replace overwrites is recorded with its
    attributes, so an undo restores them.
  - **Validation.** `onlink` without a device is a validation error (the
    kernel's "Nexthop device required for onlink"), and so is a `src` of
    the other family.
  - **Not here.** A protocol per route stays config-wide
    (`NetworkConfig::routes_protocol`, #512), because ownership is decided
    by it.
  - **Test.** A transition test takes an IPv4 and an IPv6 route A→B→none.
    Every step converges, `ip -j -d route` shows exactly the declared
    source, flags and metrics, and it passes on iproute2 6.1. Without the
    attribute comparison, step 2 never applies.

- **Declared links carry their queue length, alias, group, GSO/GRO
  limits, promiscuous mode, protodown and alternative names (#516, row
  3).**
  - **Builder.** `LinkBuilder` gains `txqlen`, `alias`, `group`,
    `gso_max_size`, `gso_max_segs`, `gro_max_size`, `promisc`, `protodown`
    and `altname`. The JSON form has the same fields at the top level of
    the link.
  - **Diff and apply.** Each declared attribute is compared and changed in
    place (`LinkChanges::set_*`, `add_altnames`/`del_altnames`), and a link
    created by the apply gets them before it comes up. An attribute not
    declared is left alone. Declared altnames are the link's: one it has
    and nothing declares is taken off.
  - **Validation.** These are validation errors:
    - an alias in a config with an `owner` tag, which is written as the
      alias;
    - an alias over 255 bytes;
    - an altname the kernel would refuse.
  - **New imperative calls.** `set_link_group`, `set_link_gso_max_size`,
    `set_link_gso_max_segs`, `set_link_gro_max_size`,
    `set_link_promisc`, `set_link_protodown` and
    `add`/`del_link_altname` (`RTM_NEWLINKPROP`/`RTM_DELLINKPROP`), all
    `_by_index`. `LinkMessage` reads `IFLA_PROTO_DOWN` (`proto_down()`)
    and `IFLA_PROP_LIST` (`altnames()`).
  - **Test.** A transition test changes every one of them A→B on a dummy,
    with protodown on a vxlan (dummy and veth refuse it). Every step
    converges, as checked through `ip -j -d link` on iproute2 6.15 and
    6.1. It fails with the attributes unset.

- **Per-link IPv4 devconf, IPv6 address generation mode and token,
  declared and set over netlink (#516, row 4).**
  - **Builder.** `LinkBuilder::ipv4_conf(Ipv4Devconf, value)` sets
    `/proc/sys/net/ipv4/conf/<dev>/<name>` through `RTM_SETLINK`
    (`IFLA_AF_SPEC`/`AF_INET`/`IFLA_INET_CONF`). `addr_gen_mode` and
    `ipv6_token` are the IPv6 ones the kernel takes over netlink. All
    three go in before the link comes up, where `addrgenmode` needs them;
    nlink-lab's per-interface sysctl on a declared VLAN used to fail,
    running before the link existed.
  - **JSON form.** `"ipv4-conf": {"rp_filter": 2}`, `"addr-gen-mode":
    "none"`, `"ipv6-token": "::1:2"`.
  - **Validation.** An unknown setting name and a token whose upper 64
    bits aren't zero are validation errors.
  - **New module.** `nlink::netlink::devconf` has `Ipv4Devconf` (all 33
    `IPV4_DEVCONF_*`, by sysctl name) and `AddrGenMode`. Both are checked
    by the UAPI audit.
  - **Reading back.** `LinkMessage` reads `IFLA_AF_SPEC`'s inet parts:
    `ipv4_devconf(..)`, `ipv6_devconf_raw(id)`, `addr_gen_mode()` and
    `ipv6_token()`.
  - **Setters.** `set_ipv4_devconf_by_index`, `set_addr_gen_mode_by_index`
    and `set_ipv6_token_by_index`.
  - **Undo.** A link change's inverse restores the old values; `::`
    clears a token.
  - **Test.** A transition test changes `rp_filter`, `forwarding`,
    `arp_ignore`, the mode and the token A→B on a veth. It is read back
    from `/proc/sys`, `ip -d link` and `ip token`, on iproute2 6.15 and
    6.1, and fails with the devconf never written.

- **Per-link IPv6 devconf (#516, row 5).**
  `LinkBuilder::ipv6_conf(Ipv6Devconf, value)` declares
  `/proc/sys/net/ipv6/conf/<dev>/<name>`: `accept_dad`, `disable_ipv6`,
  `accept_ra`, `forwarding`, `hop_limit`, `keep_addr_on_down` and 41
  more integer settings. The JSON form is `"ipv6-conf": {"accept_dad":
  0}`.
  - **Writes.** The kernel takes these only through `/proc/sys`. The apply
    writes them from a thread inside the connection's namespace
    (`Connection::netns()` → `Netns::run`), before the link comes up.
  - **Reads.** The diff reads them back from the link dump
    (`IFLA_INET6_CONF`, `LinkMessage::ipv6_devconf`).
  - **Left out.** `Ipv6Devconf` leaves out:
    - the intervals, which the dump reports in milliseconds while `/proc`
      takes seconds;
    - `stable_secret`, which is an address;
    - the read-only `mc_forwarding`;
    - `addr_gen_mode`, set over netlink in row 4.

    It is checked by the UAPI audit.
  - **Containers.** In a container whose `/proc/sys` is read-only, as the
    privileged CI lane's are, the apply fails with that error. The root
    test therefore skips there.
  - **Test.** It changes five settings A→B on a veth the first step
    creates. It reads them back from `/proc/sys`, and fails with the
    write skipped.

- **Declared bridge and bridge-port options (#516, row 6, first part).**
  A link's `bridge` section (`LinkBuilder::bridge_options`) declares:
  - VLAN filtering and the default PVID;
  - STP and the bridge priority;
  - the ageing time, forward delay, hello time and max age.

  It is a separate section, so `"link-type": "bridge"` stays a bare
  string. A link's `port` section (`port_options`) declares, for a bridge
  port:
  - learning;
  - unicast, multicast and broadcast flooding;
  - isolation and `neigh_suppress`;
  - hairpin, proxy ARP, BPDU guard and root block;
  - cost and priority.

  How they apply:
  - **Bridge options** go in at create. On a live bridge they are compared
    with the dump's `IFLA_INFO_DATA` and changed in place with
    `changelink`, the timers in the kernel's 1/100 s.
  - **Port options** are read from the dump's slave data and set with
    `set_bridge_port` after the link joins its bridge, at create or later.
  - **Validation.** Bridge options on a link that isn't a bridge, and port
    options on a link with no master or one that isn't a bridge, are
    validation errors. A misspelled option in a document is refused.
  - **Test.** A transition test changes both sides A→B, reads them back
    through `ip -d -j link` on iproute2 6.15 and 6.1, and fails when they
    aren't compared.
  - **Still to do.** Port VLANs are the second part of row 6.

- **Declared bridge-port VLANs (#516, row 6, second part).**
  `PortOptions::pvid(vid)`, `untagged(vid)`, `vlan(vid)` and `vlan_with`
  declare a port's VLANs as its exact set. The JSON form is `"vlans":
  [{"vid": 10, "pvid": true, "untagged": true}, {"vid": 20}]`.
  - **Diff.** It reads every port's VLANs from one `AF_BRIDGE` dump in the
    snapshot.
  - **Apply.** It makes the port's VLANs the declared ones against a fresh
    read: adds first (which also moves the PVID), then the undeclared ones
    go. That includes the default PVID a port gets when it joins, which no
    diff made before the join could see.
  - **Validation.** A VID outside 1–4094 or declared twice, and two PVIDs,
    are validation errors.
  - **Test.** A transition test moves an access VLAN, untags a trunk VLAN,
    drops one and adds another, checked through `bridge -j vlan` on
    iproute2 6.15 and 6.1. It fails when the undeclared VLANs aren't
    removed.

- **Declared ipvlan and macvtap links (#516, row 7, first batch).**
  - **Builders.** `LinkBuilder::ipvlan(parent)` with `ipvlan_mode` (l2,
    l3, l3s) and `ipvlan_isolation` (bridge, private, vepa), and
    `macvtap(parent)` with `macvtap_mode`.
  - **Changes.** Modes and isolation change in place (`changelink`).
    Another parent is a recreate. Passthru in or out is a recreate for
    macvtap, as it is for macvlan.
  - **Validation.** A MAC declared on an ipvlan, which shares its
    parent's, is a validation error.
  - **CI.** `macvtap` is now in CI's module guard and strict list.
  - **Test.** A transition test takes both through three values, checked
    through `ip -d -j link` on iproute2 6.15 and 6.1, and fails with the
    ipvlan mode uncompared.

- **Declared IPv4 tunnels: gre, gretap, ipip, sit and vti (#516, row 7,
  second batch).**
  - **Builders.** `LinkBuilder::gre()` (and `gretap`, `ipip`, `sit`,
    `vti`) with `tunnel_local`, `tunnel_remote`, `tunnel_ttl`,
    `tunnel_key` and `tunnel_underlay_dev`, as each kind has them. The
    JSON form is `{"gre": {"local": .., "remote": .., "key": 7}}`.
  - **Changes.** Every parameter changes in place. A tunnel's
    `changelink` rebuilds its configuration from the request, zeroing
    what it isn't sent, so any difference sends the whole declared set.
  - **TTL.** An unset TTL is the kernel's (inherit, or 64 for sit) and
    isn't compared.
  - **Validation.** These are validation errors:
    - a MAC on an L3 tunnel;
    - a setter the kind lacks (a key on ipip, a TTL on vti);
    - a tunnel named after the kernel's fallback device (`gre0`, `tunl0`,
      `sit0`, `ip_vti0`, …), which every namespace has and nothing can
      configure.
  - **CI.** `ip_vti` joins CI's module lists.
  - **Test.** A transition test takes all five A→B and checks every
    parameter through `ip -d -j link`, on iproute2 6.15 and 6.1.

- **Declared Geneve and bare UDP tunnels (#516, row 7, third batch).**
  - **Geneve.** `LinkBuilder::geneve(vni)` with `geneve_remote` (IPv4 or
    IPv6), `geneve_ttl`, `geneve_tos` and `geneve_port`.
    `geneve_changelink` refuses a VNI, port or address-family change, and
    those recreate. The remote, TTL and TOS change in place.
  - **Bare UDP.** `bareudp(port, ethertype)` with `bareudp_srcport_min`
    and `bareudp_multiproto`. It has no `changelink`, so any change
    recreates. Bare UDP is **unverified on a live kernel**: the one this
    was written on doesn't build it. Unit fixtures pin its encoding
    through the offline recreate prediction.
  - **`GeneveLink`** gains `address()`, so a declared MAC lands at
    create.
  - **CI.** `geneve` joins CI's module lists.
  - **Test.** A root test changes a Geneve tunnel's remote and TTL in
    place (same ifindex), then its VNI (recreated), checked through
    `ip -d -j link` on iproute2 6.15 and 6.1. It fails with the VNI
    uncompared.

- **Declared MACsec links (#516, row 7, fourth batch).**
  - **Builder.** `LinkBuilder::macsec(parent)` with `macsec_sci`,
    `macsec_port`, `macsec_encrypt`, `macsec_protect`,
    `macsec_include_sci` and `macsec_replay_window`.
  - **Changes.** `macsec_changelink` refuses the SCI and port, so those
    recreate. The rest change in place.
  - **Validation.** `macsec_include_sci(false)` is a validation error:
    the kernel needs end-station or SCB mode for it, which a declaration
    doesn't carry.
  - **Keys and SAs** stay with the MACsec Generic Netlink API.
  - **CI.** `macsec` joins CI's module lists.
  - **Test.** A root test changes encryption and the window in place
    (same ifindex), then the SCI (recreated), checked through
    `ip -d -j link` on iproute2 6.15 and 6.1. It fails with the SCI
    uncompared.

- **`Ip6tnlLink` and `XfrmLink`, and declared ip6tnl and xfrm links
  (#516, row 7, last batch).**
  - **Imperative builders.**
    - `Ip6tnlLink` carries IPv6 or IPv4 over IPv6. It takes the ends,
      `hoplimit`, `encap_limit` and an `Ip6tnlMode` (`any` by default,
      as in `ip link`).
    - `XfrmLink` is an IPsec interface with an `if_id`.
    - Each is bound to its underlay through its own link attribute.
  - **Builder.** `LinkBuilder::ip6tnl()` with `ip6tnl_local`,
    `ip6tnl_remote`, `ip6tnl_hoplimit`, `ip6tnl_encap_limit` and
    `ip6tnl_mode`, and `LinkBuilder::xfrm(if_id)`. Both take
    `tunnel_underlay_dev`.
  - **Changes.**
    - Any ip6tnl difference sends the whole declared set, since
      `ip6_tnl_changelink` rebuilds the configuration from the request.
    - An xfrm interface's if_id changes in place. A new underlay, which
      `xfrmi_changelink` refuses, recreates it.
  - **Validation errors:**
    - an ip6tnl with no ends and no underlay, which is the fallback
      `ip6tnl0`'s tunnel, so the kernel refuses it with `EEXIST`;
    - a link named `ip6tnl0`;
    - an `if_id` of 0;
    - two xfrm interfaces with one `if_id`.
  - **CI.** `ip6_tunnel` and `xfrm_interface` join CI's module lists.
  - **Tests.**
    - A root test checks every builder parameter through `ip -d -j link`.
    - A transition test changes every ip6tnl parameter and the if_id in
      place (same ifindexes), then the xfrm underlay (recreated). It
      passes on iproute2 6.15 and 6.1.
    - It fails if the ip6tnl change sends only the mode (`EEXIST`), or
      if the xfrm change leaves out the underlay (`EINVAL`).

- **Declared neighbours (#516, row 8, first half).**
  - **Builder.** `NetworkConfig::neighbour(dev, ip, lladdr)` declares a
    permanent ARP or ND entry. `proxy_neighbour(dev, ip)` declares a
    proxy entry.
  - **Diff.** Each is installed with `NLM_F_REPLACE`: when it is missing,
    not permanent, or has another link-layer address.
    - `ConfigDiff::neighbours_to_set` and `neighbours_to_remove` hold
      them, and the JSON schema gains both keys.
    - The plan holds them as `Step::SetNeighbour { before, after }` and
      `Step::DeleteNeighbour`, which invert for `ApplyResult::undo`.
  - **Flushes.** The kernel flushes every neighbour on a device that goes
    down, moves to or from an L3 master, changes its MAC or is recreated.
    That includes permanent and proxy entries, in both families. An apply
    that does any of those puts the declared ones back in the same apply,
    and a recreate no longer counts them among what it would destroy.
  - **Removal.** A neighbour leaves through `PlanOptions::previous`.
    `purge` never removes a neighbour.
  - **Validation errors:**
    - a proxy entry with a link-layer address;
    - a neighbour without one;
    - an unspecified or multicast address;
    - an entry declared twice.
  - **Tests.**
    - A transition test changes the link-layer addresses, recreates the
      VLAN they are on, and takes it down, checking `ip -j neigh` at each
      step. It passes on iproute2 6.15 and 6.1.
    - It fails if declared neighbours are counted as blockers (the
      recreate is refused), or if a downed link's entries are taken as
      present (the apply does not converge).
    - A root test removes the previous config's entries under a purge,
      and keeps one that nothing declared. It also checks that a MAC
      change puts the declared entry back, and fails without that.

- **Declared FDB entries (#516, row 8, second half).**
  - **Builder.** `NetworkConfig::fdb(dev, mac, |e| …)` declares an
    entry:
    - by default, a static entry in the bridge `dev` is a port of
      (`bridge fdb replace … master static`);
    - with `.local()`, the bridge's own MAC (`permanent`);
    - with `.dst(ip)`, a VXLAN remote in the device's own table;
    - with `.vlan(id)`, the entry for that VLAN.
  - **Diff and plan.** The diff sets an entry that is missing, learned,
    or in the other state.
    - `ConfigDiff::fdb_to_set` and `fdb_to_remove` hold the entries, and
      the JSON schema gains both keys.
    - The plan holds them as `Step::SetFdb { before, after }` and
      `Step::DeleteFdb`, which invert for `undo`.
    - An all-zeros or multicast MAC takes any number of remotes, added
      with `NLM_F_APPEND`; a replace there is `EOPNOTSUPP`. A unicast MAC
      has one remote, replaced.
  - **Flushes.** A port that leaves or changes its bridge loses its
    entries, and a recreated device loses all of them. The apply puts
    the declared ones back, and a recreate no longer counts them among
    what it would destroy.
  - **Removal.** An entry leaves through `PlanOptions::previous`.
    - Only that remote goes, not the flood entry.
    - A bridge entry declared on another port of the same bridge is
      moved, not removed.
    - `purge` never removes an FDB entry.
  - **Validation errors:**
    - a VLAN outside 1–4094;
    - a remote with a VLAN, or a local remote;
    - a non-unicast bridge MAC (`fdb_add_entry` refuses it);
    - an entry declared twice;
    - two remotes for a unicast MAC;
    - one MAC and VLAN on two ports of one declared bridge.
  - **Imperative.** `Connection::append_fdb` (`bridge fdb append`).
    `Connection::del_fdb_entry` deletes exactly the entry it is given:
    the bridge's or the device's own, with its VLAN, and with `dst` only
    that remote, where `del_fdb` deletes them all.
  - **Tests.**
    - A transition test runs these steps, checked through
      `bridge -j fdb` at each one:
      - moves a static entry to another port, makes another local, and
        replaces a unicast remote;
      - recreates the VXLAN device;
      - moves a port to another bridge.
    - It passes on iproute2 6.15 and 6.1. It fails with declared entries
      counted as blockers (the recreate is refused), with a moved port's
      entries taken as present, and with flood remotes replaced rather
      than appended.
    - A root test removes the previous config's entries under a purge.
      It keeps a stranger's entry and a flood entry's other remote, and
      fails if the delete drops the remote's `dst`.

- **Declared policy routing rules (#516, row 9).**
  - **Builder.** `NetworkConfig::rule(priority, |r| …)` declares a rule.
    - **Selectors:** `from`, `to`, `iif`, `oif`, `fwmark` or
      `fwmark_masked`, `ipproto`, `sport`, `dport`, `invert` (`not`),
      `suppress_prefixlen`, and `ipv6()` for a rule with no address.
    - **Actions:** a table lookup (main by default), `blackhole`,
      `unreachable` or `prohibit`.
  - **Ownership.** A declared rule carries the config's `route_protocol`
    (`boot` by default), and only a rule with it is the config's.
    - The kernel keeps an identical rule with another protocol as a
      separate rule. `ip rule add` leaves the protocol `unspec`.
    - A delete that names the protocol removes only that rule.
    - So a config neither takes another tool's identical rule for its own
      nor removes it.
  - **Diff and plan.**
    - `ConfigDiff::rules_to_add` and `rules_to_remove` hold the rules,
      and the JSON schema gains both keys.
    - The plan holds them as `Step::AddRule` and `Step::DeleteRule`,
      which invert. A rule is added after the routes of the table it
      looks up.
    - Rules name their devices, so a recreated link keeps its rules.
  - **Removal.** A rule leaves through `PlanOptions::previous`; `purge`
    never removes a rule.
  - **Validation errors:**
    - a prefix longer than its family's;
    - addresses of two families;
    - table 0;
    - a mark mask without a mark;
    - a backwards port range;
    - a rule declared twice.
  - **Imperative.** `RuleBuilder::protocol`, `invert` (`ip rule … not`) and
    `suppress_prefixlen`, and `RuleMessage::is_invert`.
  - **Test harness.** `assert_transition_with_previous` applies each step
    with the step before as its previous config.
  - **Tests.**
    - A transition test changes a rule's table and another's prefix,
      drops one, adds an IPv6 rule with a masked mark, then recreates the
      device a rule names. It checks `ip -j -d rule` at each step, with
      another tool's identical rule ahead of the config's the whole time.
      It passes on iproute2 6.15 and 6.1.
    - It fails if the delete leaves out the protocol (the other tool's
      rule goes), and if live rules are matched without it (the config's
      rule is never added).

- **A veth peer in another namespace (#516, row 10).**
  - **Builder.** `LinkBuilder::veth_peer_netns(NetnsRef)` declares the
    namespace a veth's peer lives in. The apply creates the peer there.
    One found elsewhere, here included, is recreated in it.
    `NetnsRef::Default` is this namespace.
  - **Unset stays unmanaged.** Without it, the peer is created here and
    left wherever it is moved: a CNI moving it into a container is not
    undone.
  - **Diff.** It compares the live peer's `IFLA_LINK_NETNSID` with the
    declared namespace's id here (`RTM_GETNSID`). `Snapshot::read`
    resolves every named namespace; `NetworkConfig::diff` resolves the
    ones the config names.
  - **Recreates.** A recreate that puts the peer back in its declared
    namespace no longer counts it as a foreign-namespace blocker.
  - **Tests.**
    - A transition test creates the peer in namespace B, moves it to C,
      then brings it here. Each move is a recreate.
    - The peer is then moved to B by hand, and the undeclared step 4
      leaves it there.
    - It fails with the foreign-peer blocker kept (step 2 is refused),
      and with the namespace uncompared (the peer stays in B).

- **Declared nexthop objects, and routes through them (#516, row 11,
  first part).**
  - **Builder.**
    - `NetworkConfig::nexthop(id, |n| …)` declares a nexthop object:
      `via` and `dev` (with `onlink`), a `blackhole`, or a `group` of
      `(id, weight)`.
    - `RouteBuilder::nhid(id)` routes through one, in place of a gateway
      and device.
  - **Ownership.** A nexthop carries the config's `route_protocol`. A
    live nexthop with the id and another protocol is another tool's.
    - The apply refuses it rather than replacing it:
      `ConfigDiff::nexthops_refused`, `Step::RefuseNexthop`.
    - So is a change between a single nexthop and a group, which the
      kernel will not make.
  - **Diff and plan.** `ConfigDiff::nexthops_to_set` and
    `nexthops_to_remove` hold the changes, and the JSON schema gains all
    three keys.
    - The plan holds them as `Step::SetNexthop { before, after }` and
      `Step::DeleteNexthop`, which invert.
    - Nexthops are set after the addresses, since a gateway has to be
      reachable, and before the routes. Single nexthops come before the
      groups made of them.
    - On removal, groups come before their members.
  - **Flushes.** The kernel deletes the nexthops on a link that goes
    down or is deleted, then a group whose members are all gone, then
    every route through any of them.
    - Those count as absent, so the apply puts them back, routes
      included.
    - A recreate no longer counts declared nexthops among what it would
      destroy.
  - **How routes through a nexthop compare.** They compare by `nhid`
    alone: the kernel dumps the object's gateway, device and type with
    the route, so a route through a blackhole nexthop is a blackhole
    route.
  - **Removal.** A nexthop leaves through `PlanOptions::previous`;
    `purge` never removes one.
  - **Validation errors:**
    - id 0, or a duplicate id;
    - none or more than one of via, blackhole and group;
    - a gateway without its device;
    - `onlink` without a gateway and device;
    - an undeclared, nested or zero-weight group member;
    - a route through a nexthop that names its own gateway or device, or
      a type;
    - a family mismatch.
  - **Test harness.** `assert_transition_with_previous` drives the test.
  - **Tests.**
    - A transition test changes a nexthop's gateway and its group's
      weights in place, then recreates the VLAN they are on: the nexthops
      on it, the group and all three routes come back. It then drops the
      group, the blackhole and their routes.
    - It passes on iproute2 6.15 and 6.1.
    - It fails with declared nexthops counted as blockers (the recreate
      is refused), and with the routes through lost nexthops taken as
      present (it does not converge).

- **Declared multipath routes (#516, row 11, second part).**
  - **Builder.** `RouteBuilder::nexthop(|h| h.via(..).dev(..).weight(..).onlink())`
    adds a next hop. A route takes two or more, in place of a gateway
    and device. The kernel keeps them in the order given, and the diff
    compares them in that order.
  - **Comparison.** A hop declared without a device takes the one the
    kernel picks.
  - **Lost with a link.** The kernel deletes an IPv4 multipath route
    with any hop's link, and an IPv6 route's hop with its link. A
    multipath route with a hop on a link the apply deletes, or with
    every hop on links it flushes, counts as absent. The apply puts it
    back whole.
  - **Validation errors:**
    - one hop only (the kernel dumps it as a plain route, which would
      never match);
    - a gateway, device or nhid beside the hops;
    - a hop with neither gateway nor device;
    - a gateway of the other family;
    - `onlink` without both;
    - a non-unicast type.
  - **Tests.**
    - A transition test changes the hops' weights in place, recreates
      the link one hop is on, then returns to single-gateway routes,
      checked through `ip -j route` for IPv4 and IPv6. It passes on
      iproute2 6.15 and 6.1.
    - It fails with the hops uncompared (the weights stay), and with a
      route whose hop's link is recreated taken as present (it does not
      converge).

- **Declared routes via an IPv6 gateway, and with an MPLS encapsulation
  (#516, row 11, last part).**
  - **IPv6 gateways.** An IPv4 route may now name an IPv6 gateway
    (RFC 5549). It goes out as `RTA_VIA` (kernel 5.2+) and compares
    against it.
    - Until now this was a validation error, "nlink does not model
      `RTA_VIA`".
    - An IPv6 route with an IPv4 gateway is still refused.
    - `Ipv4Route::gateway_v6` is the imperative form.
  - **MPLS encapsulation.** `RouteBuilder::encap_mpls(&[labels])` pushes
    a label stack (`encap mpls`, the `mpls_iptunnel` module), compared
    against the route's.
  - **Parsing.** `RouteMessage::via()`, `encap_type()` and
    `mpls_encap_labels()` read `RTA_VIA`, `RTA_ENCAP_TYPE` and an MPLS
    `RTA_ENCAP`, which nlink did not parse before. `write_to` writes
    them back.
  - **Validation errors:**
    - a label past 1048575;
    - an encapsulation without a gateway or device.
  - **Tests.**
    - A transition test moves an IPv6 gateway and changes the labels in
      place, then makes both plain routes, checked through `ip route`. It
      passes on iproute2 6.15 and 6.1.
    - It fails with `RTA_VIA` uncompared (no convergence), and with the
      labels uncompared (they stay).

- **Declared ip6gre and ip6gretap links (#516, row 7, completed).**
  - **Builder.** `LinkBuilder::ip6gre()` and `ip6gretap()` take the
    `ip6tnl_*` setters (ends, hop limit, encapsulation limit),
    `tunnel_key` and `tunnel_underlay_dev`. `Ip6tnlParams` gains `key`.
  - **Changes.** Any difference sends the whole declared set, because
    `ip6gre_netlink_parms` rebuilds the configuration from the request.
  - **Imperative.** `Ip6GreLink` and `Ip6GretapLink` gain `key` (sent
    big-endian, with `GRE_KEY`) and `mtu`.
  - **Validation errors:**
    - an ip6gre with no end, underlay or key, which is the fallback
      `ip6gre0`'s tunnel;
    - a link named `ip6gre0`;
    - a key on an ip6tnl;
    - a mode on a GRE tunnel.
  - **CI.** `ip6_gre` joins CI's module lists.
  - **Test.** A transition test changes every parameter in place (same
    ifindexes), checked through `ip -d -j link`. It passes on iproute2
    6.15 and 6.1. It fails if the change sends only one attribute.

- **Namespace creation options: an owner tag, and stale-marker reclaim
  (#522).**
  - **`create_with`.** `namespace::create_with(name, CreateOptions)` and
    `Netns::create_with` create a named namespace as `create` does,
    with two options.
    - **`owner(tag)`** writes the owner to a sidecar under
      `namespace::OWNER_TAG_DIR` (`/run/nlink/netns-owners`), before the
      namespace is made. A crash in between leaves a tag with no
      namespace, never an untagged namespace. A failed create removes the
      tag.
    - **`reclaim_stale(true)`** removes a stale marker in the name's
      place: a `/run/netns` file nothing is mounted on. `create` refuses
      such a marker. A live namespace is never reclaimed.
  - **Reading and removing tags.** `namespace::owner_of(name)` reads a
    tag, and `list_owned(owner)` lists the names tagged with an owner,
    including those whose create was cut short. `remove_owner_tag(name)`
    removes a tag.
  - **Deleting.** `delete`, and so `Netns::delete`, removes the tag with
    the namespace.
  - **Tests.** Root tests cover the tag's life, and a stale marker
    reclaimed next to a live namespace left alone.

- **`nlink::blocking::Connection<P>`, for code that cannot `.await`
  (#533).**
  - **How it works.** A worker thread owns a current-thread runtime and
    the async connection. Each call sends its work there and waits on a
    channel.
  - **Where it is safe.** It never starts a runtime on the calling
    thread, so it is safe in plain synchronous code, and in a `Drop` that
    runs inside a tokio runtime, where `Runtime::block_on` panics.
  - **API.**
    - `new()`, and `in_netns(NetnsRef)` for a namespace.
    - `run(|conn| Box::pin(async move { … }))` for any async work.
    - Methods of its own for the common Route dumps (links, addresses,
      routes, qdiscs) and the `del_*_if_exists` deletes (link, address,
      qdisc, route).
    - For nftables: `list_tables`, `list_rules` (with their counters)
      and `del_table_if_exists`.
  - **Tests.** Root tests cover a link deleted from a `Drop` inside a
    tokio runtime, calls with no runtime at all, and the nftables
    helpers.

- **`NetnsCommand`, a process-spawn builder for namespaces (#521, first
  part).**
  - **Entry points.** `NetnsCommand::new(name, cmd)`,
    `NetnsCommand::path(path, cmd)` and `Netns::command(cmd)` spawn a
    process in a namespace.
  - **`etc_overlay(Overlay)`** sets the `/etc/netns/<name>/` policy:
    - `Off`, the default, gives the host's `/etc` and `/sys`, as `spawn`
      does.
    - `Strict` follows `spawn_with_etc`'s rules: the overlay, or a
      failure.
    - `BestEffort` gives what the environment allows. A refused private
      mount namespace or `MS_SLAVE` remount leaves the host's `/etc`,
      never bound into a tree that propagates. A refused bind is left
      out. The namespace's sysfs goes on top of `/sys` rather than in its
      place, so a refused mount leaves the old one, never none.
  - **`user(SpawnUser)`** drops privileges once inside the namespace.
  - **`cgroup(dir)`** joins a cgroup v2 before entering the namespace, so
    nothing the process starts escapes it. Writing the pid after the
    spawn let early children escape.
  - **`pdeathsig(signal)`** sets the parent-death signal.
  - **`spawn()` and `output()`** run it.
  - **`namespace::etc_overlay_supported()`** probes once, in a child,
    whether `Strict` can work here. It checks the private mount
    namespace, its remount, a fresh sysfs, and a bind over `/etc`. A
    rootless container's user namespace refuses the fresh sysfs once the
    old one is detached.
  - **Tests.** Root tests cover each policy, and a bind the kernel
    refuses: strict fails, best effort leaves it out. They also cover a
    process starting in its cgroup (host root) and the parent-death
    signal. They pass as root and in the rootless lane, where the probe
    says strict cannot work and best effort still gives the overlay.

- **Detached and tokio spawns for `NetnsCommand` (#521, second part).**
  - **`spawn_detached()`** runs the process as no child of the caller's,
    through an async-signal-safe double fork, and returns its pid.
    Everything after the fork works on data built before it: argv, envp,
    and the program, found on `PATH` in the parent. Its stdio is
    `/dev/null`. A failed start (the namespace, the overlay, the cgroup,
    the user, the exec) comes back as the error.
  - **`exit_status_file(path)`** keeps a monitor process as the
    command's parent. The monitor writes the exit code to `path` when the
    command ends, or `128 + n` for a death by signal `n`.
  - **`spawn_tokio()` and `output_async()`** spawn the process as a tokio
    child, to wait on without blocking the runtime. They sit behind the
    new `process` feature (`tokio/process`), which joins `full` and the
    integration lane's feature list.
  - **Internal.** The child-side setup is one `Prepared` step list shared
    by `pre_exec` and the double fork.
  - **Tests.** Root tests cover a detached process: its parent, its
    namespace, its exit code, and a failed start. They also cover a tokio
    child's output and status. They pass as root and in the rootless
    lane.

- **Netconf: sysctl drift as events, and `Family` names (#523, first
  part).**
  - **Events.** `NetworkEvent::NewNetconf` and `DelNetconf` carry a
    `netconf::NetconfMessage`: one interface's IP configuration, or
    `all`'s, or `default`'s (`NetconfDevice`). It holds `forwarding`,
    `rp_filter`, `mc_forwarding`, `proxy_neigh`,
    `ignore_routes_with_linkdown`, `input` and `bc_forwarding`. The
    kernel sends one when these change, through `/proc/sys` too.
  - **Groups.** `RtnetlinkGroup::Ipv4Netconf` and `Ipv6Netconf` subscribe
    to them, and `subscribe_all` now joins both.
  - **Dump.** `Connection::get_netconf(family)` dumps the current
    values. `rtnetlink_snapshot`, and so a resync stream's snapshot,
    includes them.
  - **`Family` names.** `nftables::Family` gains `Display`, `FromStr` and
    `name()`, with `nft`'s names: `ip`, `ip6`, `inet`, `arp`, `bridge`,
    `netdev`.
  - **Tests.**
    - A root test flips an interface's forwarding through `sysctl` and
      expects the event. It also checks that the dump has `all`,
      `default` and the interface.
    - Unit tests cover the parser and `Family`'s names.

- **Event metadata: who caused a change (#523, second part).**
  - **`with_meta()`.** `EventSubscription::with_meta()` and
    `OwnedEventStream::with_meta()` yield each event with an `EventMeta`
    from its notification's header: `portid`, `seq` and `kind` (the
    message type).
  - **Telling changes apart.**
    - A change a request caused carries the requester's port id and
      sequence number. That can be this process (`conn.socket().pid()`),
      `ip`, or `nft`.
    - A change the kernel originated carries port id 0
      (`EventMeta::is_kernel()`).
    - So a watcher can skip its own changes, and tell drift from kernel
      noise.
    - Not every notification names its requester: a new link is reported
      with port id 0 whoever made it.
  - **Parsing.** The streams parse a datagram one message at a time,
    through a new default `EventSource::parse_events_with_meta`. Uevents,
    which have no netlink header, parse whole.
  - **Tests.**
    - A root test checks an address's port id and sequence number, and a
      kernel-reported carrier change (port id 0).
    - A unit test checks two messages in one datagram, each with its own
      metadata.

- **An event stream that restarts instead of ending (#523, third part;
  the backoff half of #257).**
  - **The call.** `Connection::<P>::events_restarting(factory, backoff)`
    returns a `RestartingStream<P>`, for `Route` and `Nftables` (the
    sealed `resync::Restartable`). It runs every group of the protocol,
    resynced after an overflow as `into_events_with_resync` is, on a
    connection from `factory`. `.rcvbuf(bytes)` sizes each run's event
    socket.
  - **When it ends or fails.**
    - The error is yielded, and the stream starts again after the wait.
    - Each restart begins with an initial snapshot (`InitialSyncStart` …
      `ResyncEnd`), so a `Store` rebuilds itself.
    - A failing factory is retried the same way.
  - **When it stops.**
    - The namespace is deleted (`NamespaceDeleted`), or the factory cannot
      find it (`NamespaceNotFound`): no restart brings it back.
    - It has failed `max_attempts` restarts in a row without delivering
      an event.
  - **`resync::Backoff`.**
    - The wait starts at `initial` (100 ms by default) and doubles up to
      `max` (30 s), with an optional `max_attempts`.
    - A run that delivered an event starts the count again.
    - No new dependency: the waits are tokio sleeps.
  - **Tests.**
    - A root test runs a factory that fails twice and then starts, and
      checks the two errors, the initial snapshot and a live event.
    - A second root test deletes the namespace under the stream, which
      must then end. It fails if the deletion check is removed: the
      stream restarts and reports `NamespaceNotFound` instead.
    - Unit tests cover the backoff sequence and giving up after
      `max_attempts`.

- **Gap deltas: what a resync found gone (#523, fourth part).**
  - **The gap.** A resync replays the state as it is. That says what
    exists, not what went away: an object deleted while the socket
    overflowed, or while a restarting stream was down, is simply absent
    from the snapshot. Nothing reported its removal.
  - **`ResyncStreamExt::with_gap_deltas(key)`.**
    - The adapter remembers every object the stream reports, keyed by
      `key`.
    - When a snapshot ends without one, it yields that object's removal
      as a `Resynced(Del*)`, in key order, just before the closing
      `ResyncEnd`.
    - So a consumer that applies events as they come stays equal to the
      kernel without clearing anything at `ResyncStart`.
  - **New types.**
    - **`GapDelta`** says how an event's removal is reported. It is
      implemented for `NetworkEvent` and `NftablesEvent`.
    - **`ObjectKey`** is what an event is about, as a kind and an
      identity.
    - **`NetworkEvent::object_key`** keys links by ifindex, addresses by
      device and prefix, and routes by table, prefixes, TOS and metric.
      It covers the rest too, but not actions.
    - **`NftablesEvent::object_key`** keys tables, chains, sets,
      flowtables and objects by family, table and name, and rules by
      handle. It does not cover set elements or generations.
  - **Tests.**
    - Two root tests overflow a subscriber and then delete what the
      stream had reported: a link through rtnetlink, a table through
      nftables. The rtnetlink test also checks that a mirror that never
      clears ends equal to a fresh dump.
    - Both tests fail when the adapter yields no removals.
    - Unit tests cover the order of the output and a snapshot cut short
      by an error.

- **`MultiNsWatch`: many namespaces in one stream (#523, fifth part).**
  - **Why.** nlink-lab's `watch` ran two sockets, two resync factories
    and two tasks per lab node.
  - **The type.** `nlink::facade::watch::MultiNsWatch<K>` is one
    `Stream<Item = (K, NsEvent)>`:
    - `MultiNsWatch::new(Families::ROUTE | Families::NFTABLES)` starts
      it, configured with `.backoff(..)`, `.rcvbuf(..)` and
      `.gap_deltas(true)`;
    - `add(key, &netns)` and `remove(&key)` change what it watches.
  - **Per namespace.**
    - Each family runs on a restarting stream, from an initial snapshot.
    - `NsEvent::Route`/`Nftables` carry its events, snapshot items and
      markers.
    - `NsEvent::Error` reports a failure the family restarts after.
  - **When a namespace goes.**
    - A deleted namespace yields `NsEvent::Gone` and leaves the watch
      while the others go on. So does one whose families all gave up
      after `max_attempts`.
    - The watch holds its own handle to each namespace, and every
      reconnect checks that the name still names it.
  - **Test.** A root test watches two namespaces and both families. It
    checks a link under one key and a table under the other. It then
    deletes one namespace and checks its `Gone`, that its key was
    dropped, and that the other namespace still delivers. It fails if a
    deleted namespace is treated as an ordinary error: the watch then
    reports giving up rather than the deletion.

- **Event metadata: the group and the namespace (#523, sixth part).**
  - **New fields.** `EventMeta` gains `group` and `nsid`, from the
    datagram's control messages.
    - `group` is the multicast group the notification was sent to
      (`NETLINK_PKTINFO`, which `with_meta()` turns on). It includes
      groups past 32, which the socket address cannot name.
    - `nsid` is the id of the namespace the change happened in.
  - **`Connection::listen_all_nsid(true)`** (`NETLINK_LISTEN_ALL_NSID`,
    kernel 4.6+) receives the events of every namespace that has an id in
    the connection's own.
    - One socket can then watch many namespaces.
    - `EventMeta::nsid` says which namespace an event came from, by the
      id the listener's namespace gave it. It is absent for the
      listener's own namespace.
  - **The receive path.** An event stream's receive now uses `recvmsg`
    with a control buffer. It still peeks each datagram whole first, as
    before (#505). In dispatcher mode, events carry neither field.
  - **Test.** A root test runs a listener in one namespace with an id
    for a second, and checks each field:
    - its own link: group 1 (`RTNLGRP_LINK`), no nsid;
    - the second namespace's link: group 1, nsid 42;
    - the second namespace's address: group 5 (`RTNLGRP_IPV4_IFADDR`),
      nsid 42.

    It fails without the control-message metadata.

- **`events::view`: a serializable projection of every event (#523,
  seventh part; feature `serde`).**
  - **`EventView`** is one shape for both families. It is tagged
    `"object"` (`link`, `address`, `route`, …, `nft_table`, `nft_rule`,
    …), with an `"action"` (`new`/`del`) and the fields that identify
    and describe the object. Optional fields are left out when absent.
  - **Names are stable.**
    - Families are written `inet`, `inet6`, `bridge`, as `ip` and `nft`
      name them.
    - States, scopes, protocols and route types use their `name()`.
    - Prefixes are written as CIDR, and a route with no destination as
      `default`.
  - **Conversions.** `From<&NetworkEvent>` and `From<&NftablesEvent>`
    build a view, and so do their owned forms.
  - **Serde on more types.** `ResyncedEvent`, `ResyncMarker` and
    `EventMeta` now implement `Serialize` and `Deserialize` too. So
    `.map_event(|e| EventView::from(&e))` turns a resync stream into
    JSON lines.
  - **Why.** nlink-lab mirrored every event type into its own
    serializable enum.
  - **Tests.** Unit tests pin the JSON of a link, a route (and the
    `default` destination), an nftables table, the resync items and the
    metadata. Each view is built from the kernel's message bytes and
    round-trips through `Deserialize`.

- **`Netns`: sysctls, the processes inside, and a deletion that waits
  (#520, third part).**
  - **`Netns::sysctl()`** returns a `Sysctl` with `get`, `set` and
    `set_many`. They read and write `/proc/sys` on the handle's worker
    thread, inside the namespace, with the keys and errors of
    `sysctl::get`.
  - **`Netns::pids()`** lists the processes with a thread in the
    namespace. A thread that entered it counts, so a `run` inside lists
    this process.
  - **`Netns::delete_and_wait(timeout)`** deletes the name and waits for
    the `RTM_DELNSID` the kernel sends as it starts destroying the
    namespace. If the namespace has no id in the caller's namespace, it
    gets one first.
    - Past that point nothing can bring the namespace back.
    - The namespace's interfaces go in the same kernel work, just after.
      `RTM_DELNSID` comes before the devices are destroyed (`cleanup_net`
      unhashes the nsid first), so a veth's far end can outlive the
      return by a moment. The rustdoc says so.
    - If something still holds the namespace, it fails with `is_timeout()`
      and logs the holding pids.
  - **Tests.**
    - The first test flips a namespace's sysctl and checks that the
      host's value is unchanged. It also checks `set_many`, and that a
      missing key is `is_not_found()`.
    - The second test checks `pids()` with a child process, with this
      process inside through `run`, and after the child exits.
    - The third test checks `delete_and_wait` on a namespace held by a
      socket (timeout, its veth still there) and on a free one (returns;
      its veth's far end follows). It fails if the call does not wait:
      the held namespace then returns `Ok`.

- **`LabNamespace` is built on `Netns` (#520, fourth part).**
  - **The handle.** It holds a `Netns` to the namespace it created, and
    `netns()` returns it.
    - Connections, spawned processes and `exec` go there through the
      handle's fd, without looking the name up again.
    - All of its connections share the handle's one worker thread.
    - `Drop` deletes the name only while it still names that namespace.
      A namespace recreated under the name since is someone else's.
  - **Netlink helpers.** `add_dummy`, `link_up`, `add_addr` and
    `connect_to` are now netlink calls rather than `ip` commands. They
    run on a thread of their own, so they are still callable from inside
    a runtime. Only `exec` needs a program in `PATH` now.
  - **Behaviour change.** Like any handle, a `LabNamespace` holds its
    namespace open. A namespace whose name is deleted elsewhere lives on,
    unnamed, until the `LabNamespace` drops. One test relied on the old
    behaviour, and now drops its handle first.
  - **Test.** A root test builds a namespace with the helpers, then
    deletes its name and recreates the name as another namespace:
    - the lab's connection still reaches its own `d0`;
    - dropping the lab leaves the new namespace alone.

    It fails with the by-name `Drop` this replaces: the new namespace is
    deleted.
  - **Coverage.** The whole root suite runs on `LabNamespace`, as
    `TestNamespace`, and the 68 helper calls in it go through the new
    paths.

- **Typed decoders for rule statements (#528, first part).**
  `RuleInfo::expressions()` decodes these statements, which used to come
  back as `RuleExpr::Unknown`:
  - **`Limit(LimitExpr)`**, a packet-rate limit;
  - **`Log(LogExpr)`**, to syslog at the default level or to an `nflog`
    group;
  - **`Reject { reject_type, icmp_code }`**;
  - **`Masq`, `Nat` and `Redir`**, which give the registers of the
    address and port ranges, and the range flags as a new `NatFlags`
    (`random`, `fully-random`, `persistent`, `netmap`, …). For `Nat`
    they also give the type and family.
  - **`FlowOffload { flowtable }`**.

  Other details:
  - **Still `Unknown`.** A shape these types cannot carry stays
    `Unknown`, as before: a byte-rate limit, a log level or flags, an
    nflog snaplen. #528's later parts add those.
  - **Shared parsing.** One limit parser serves rules and limit objects.
  - **Flowtable references.** The flowtable-in-use check that keeps a
    referenced flowtable from being purged reads `FlowOffload`.
  - **Test.** A root test writes every one of these in `nft`'s own
    syntax: limit with burst, log with prefix and group, a bare log, the
    ICMPX reject and the TCP reset, `flow add`, `masquerade random`,
    masquerade to a port range, snat to an address range `fully-random`,
    dnat to an address and port, and redirect to a port. It installs them
    with `nft -f`, reads them back through nlink and asserts that none
    is `Unknown` and that each has its expected shape. It fails without
    the decoders. Unit tests cover what nlink writes and what must stay
    `Unknown`.

- **NAT ranges and flags (#528, second part).**
  - **`NatStatement` and `Rule::nat`** write NAT statements as `nft` does:
    - `snat`/`dnat` to an address, `.to(last)` for an address range,
      and `.port(p)`/`.ports(lo, hi)` for a port range;
    - port-only `dnat_to_port(family, p)` and `snat_to_port`;
    - `masquerade()` and `redirect()` with ports;
    - the flags `random()`, `fully_random()`, `persistent()` and
      `netmap()`.
  - **Before, these were missing:** NAT was one address and one port,
    every NAT loaded an address, and masquerade took no options.
  - **Registers.** The ranges go into the next free registers. The
    statement is a new `Expr::NatRegs`, written with the flags the
    kernel derives (`MAP_IPS`, `PROTO_SPECIFIED`) already set, so it
    matches its echo. A single value is the same bytes as the older
    `snat`/`dnat`/`redirect`/`masquerade` builders, which stay.
  - **Errors.** A statement the kernel would refuse makes adding the rule
    fail, naming it: an address on a masquerade, a range that mixes
    families or runs backwards, a family other than `ip`/`ip6`, a
    netmap without a range.
  - **Tests.**
    - **Convergence and parity.** Seven rules (ranges, flags, IPv6,
      netmap, a port-only dnat, a masquerade and a redirect with port
      ranges) reconcile after an apply. `nft list` shows each as written,
      for example `snat ip to 10.0.0.1-10.0.0.9:40000-40010`, `dnat ip to
      :8080`, `masquerade to :1024-2048 random`.
    - **Traffic.** A traffic test sends through each statement between
      two namespaces:
      - snat sources land in the address and port range;
      - masquerade sources land in the port range;
      - a port-only dnat and a redirect reach their new port.
    - **Red run.** Both fail if the implied `PROTO_SPECIFIED` is not
      sent: the diff keeps four changes, and the masquerade's source port
      falls outside its range.
    - **Unit tests.** Unit tests check the register loads and decode, the
      byte equality with the older builders, and every refusal.

- **Byte-rate limits and named ICMPX reject codes (#528, third part).**
  - **Byte-rate limits.**
    - `LimitExpr::bytes(Bytes, LimitUnit)` is nft's `limit rate 10
      mbytes/second`, with a burst in bytes.
    - `Rule::limit_bytes` is the shorthand.
    - The new `LimitExpr::kind` (`LimitKind::{Packets, Bytes}`) says which
      a limit counts.
    - Byte limits work in rules, with `over`, and as named limit objects.
      They now decode, as rule expressions and as objects, where they used
      to be `Unknown` and `ObjectState::Other`.
  - **ICMPX codes.** `IcmpxCode` names the family-independent reject
    codes: `NoRoute`, `PortUnreachable`, `HostUnreachable` and
    `AdminProhibited`. `Rule::reject_icmpx(code)` writes `reject with icmpx
    <code>`. nlink-lab used to define these codes itself.
  - **UAPI audit.** Both enums are mapped in the UAPI audit.
  - **Tests.**
    - **Convergence and parity.** A declared table reconciles, and `nft`
      lists every item as written (`limit rate 10 mbytes/second`, `limit
      rate over 1 kbytes/minute burst 4 kbytes`, `host-unreachable`). It
      holds a byte-limit rule, an `over` one, a byte-limit object and three
      ICMPX rejects.
    - **Traffic.** A packet limit of 100/s with burst 100 passes all 50
      datagrams. A byte limit of the same numbers passes only a handful.
    - **Red run.** Both tests fail if the limit's type is always sent as
      packets: the diff keeps three changes, and all 50 datagrams pass.

- **Ranges, and the `!=` and `IpAddr` matchers (#528, fourth part).**
  - **`Rule::match_range(field, first, last)` and `match_range_not`.**
    - They write nft's `range` expression: `tcp dport 1000-2000`, `ip
      saddr 10.0.0.1-10.0.0.9`, `meta mark != 0x10-0x20`. nlink-lab used
      to hand-roll these as `Cmp Gte` + `Cmp Lte`.
    - The match goes behind the field's protocol guard, as
      `match_in_set` is.
    - A host-order field (a mark, an interface index) goes through a
      `byteorder` to network order first, as nft does. Without that, a
      mark range compared the wrong bytes.
    - `RangeValue` takes a port, an address, a `u32` or a `u8`. A value
      of the wrong kind, or a range that runs backwards, makes adding the
      rule fail.
    - The new `Expr::Range` and `RuleExpr::Range`, with `RangeOp`, encode
      and decode it. `RangeOp` is mapped in the UAPI audit.
  - **New matchers.**
    - `match_saddr`, `match_daddr`, `match_saddr_not` and
      `match_daddr_not` take an `IpAddr`, v4 or v6.
    - `match_tcp_sport_not`, `match_udp_sport_not`, `match_mark_not` and
      `match_l4proto_not` fill in the `!=` forms that were missing.
  - **Tests.**
    - **Convergence and parity.** Every form reconciles, and `nft list`
      shows it as nft writes it. Ranges that `nft` itself installs decode
      as `RuleExpr::Range`.
    - **Traffic.** A port range and a negated one drop what they should.
      A mark range in an output chain drops a datagram an earlier rule
      marked inside it, and passes one marked outside.
    - **Red run.** Without the byteorder step both fail: nft lists the
      mark range differently, and the in-range mark gets through.

- **`fib`, `meta pkttype`, `notrack` and the rest of the meta keys (#528,
  fifth part).**
  - **`fib`.**
    - `Rule::match_fib_missing(FibFlags::SADDR | FibFlags::IIF)` is
      nft's `fib saddr . iif oif missing`, the reverse-path check that
      nlink-lab wants for anti-spoofing.
    - `match_fib_type(flags, RouteType)` is `fib daddr type local`.
    - `Expr::Fib` and `RuleExpr::Fib` encode and decode it, with
      `FibResult` and `FibFlags`.
  - **`meta pkttype`.** `match_pkttype(PktType)` and its `_not` form,
    with `PktType::{Host, Broadcast, Multicast, OtherHost}`.
  - **`notrack`.** `Rule::notrack()` leaves a flow out of connection
    tracking. Its expression has no `dump`, so it is written, and echoed,
    with no data nest.
  - **`MetaKey`** gains every key the kernel has that it lacked:
    `iiftype`/`oiftype`, `nftrace`, `rtclassid`, `secmark`, the bridge
    names, `pkttype`, `cpu`, the interface groups and kinds, `random`,
    `ipsec`, the bridge PVID and VLAN protocol, `time`/`day`/`hour`,
    `sdif`/`sdifname` and `broute`.
  - **Audit and CI.** `PktType`, `FibResult` and the new meta keys are
    mapped in the UAPI audit. `nft_fib_inet` joins the CI module guard
    and the strict list.
  - **Tests.**
    - **Parity with nft.** The rules nlink builds for `fib … missing`,
      `fib daddr type local`, `meta pkttype` (`==` and `!=`) and
      `notrack` decode to the same expressions as the ones `nft` installs
      from the same statements. They also reconcile. This comparison
      caught `fib … missing` comparing one byte where nft compares four;
      one byte reads the wrong end of the kernel's u32 on a big-endian
      host.
    - **Decoding.** Keys nlink had no name for (`cpu`, `iifgroup`,
      `iifkind`, `day`) decode typed.
    - **Traffic, fib.** `a`'s traffic is snat'ed to an address `b` has
      no route to. It arrives without the fib rule, and is dropped with
      it, while `a`'s own source passes.
    - **Traffic, notrack.** `notrack` makes `ct state untracked` count
      exactly that flow's packets. With `notrack` a no-op, both tests
      fail.

- **Conntrack keys: status, direction, tuples, zone, labels, count, and
  `ct … set` (#528, sixth part).**
  - **`CtKey`** gains every kernel key: the tuple's addresses and ports,
    `protocol`, `labels`, `packets`/`bytes`/`avgpkt`, `zone`, `event`
    and `id`. The new `CtDirection` (`original`/`reply`) goes with the
    directional ones.
    - A directional load decodes as the new `RuleExpr::CtDirectional`,
      where it used to be `Unknown`.
    - `Expr::CtDirectional` writes one.
  - **Builders.**
    - `match_ct_status(CtStatus)`: `ct status dnat`, with `CtStatus` as
      bitflags of the `IPS_*` bits.
    - `match_ct_direction(CtDirection)`.
    - `match_ct_zone` and `set_ct_zone`.
    - `match_ct_addr(direction, source, IpAddr)`: `ct original ip saddr
      …`.
    - `match_ct_port(direction, source, port)`: `ct reply proto-dst 22`.
    - `match_ct_label(bit)` and `set_ct_label(bit)`. The mask is laid out
      as the kernel's `unsigned long` bitmap is on the host.
    - `match_ct_count` and `match_ct_count_over`: `ct count over 3`, the
      `connlimit` expression. Its flags attribute is written only for
      `over`, as the kernel dumps it.
  - **Audit and CI.** `CtDirection` and the new keys are mapped in the
    UAPI audit. `nft_connlimit` joins the CI module guard and the strict
    list.
  - **Tests.**
    - **Parity with nft.** Every builder decodes to the same expressions
      as `nft` installs from the same statement, labels included, and the
      rules reconcile. With the label mask written big-endian, the
      comparison fails; the traffic test alone would not catch it, because
      setting and matching would agree with each other.
    - **Traffic.** All of these act as nft's do:
      - a zone set in raw is the zone input sees;
      - a dnat'ed flow has `ct status dnat`;
      - a label one rule sets, the next one reads;
      - the original tuple's destination is `b`;
      - `ct count over 1` passes the first flow and drops the second.

- **Comments on tables, chains, sets, set elements and objects (#528,
  seventh part).** Rules had comments; now everything `nft list` can show
  a comment for has one.
  - **Writing.**
    - Imperative: `Chain::comment`, `Set::comment`, `Object::comment`,
      `SetElement::with_comment`, and `add_table_with_comment` on the
      connection and the transaction.
    - Declarative: `comment` on the table, chain and set builders.
  - **Reading.** `Table`, `ChainInfo`, `SetInfo` and `ObjectInfo` gain
    `comment`, and `SetElement::comment()` returns an element's. Comments
    are read from the libnftnl userdata TLVs, so the ones `nft` writes
    read back too.
  - **Encoding.**
    - Each comment is the TLV libnftnl writes: type 0, or 7 for a set,
      whose comment follows six other TLV types.
    - It goes on a range's start element.
    - One with a NUL, or longer than libnftnl's 127 bytes, fails the add
      or the commit, naming its length.
  - **Changing one later.** A comment is fixed when the kernel creates the
    object, and the diff does not compare comments. A changed comment
    takes recreating the object, which the docs say.
  - **Tests.**
    - A root test declares a commented table, chain, set and element and
      adds a commented object. It reconciles, `nft list` shows every
      comment, and each reads back through nlink.
    - The table and chain comments `nft` writes read back.
    - A 128-byte comment fails.
    - With the comment writer a no-op, the test fails at `nft list`.

- **An NFLOG reader: `Connection<Nflog>` (#528, eighth part).**
  - **Why.** A syslog `log` writes nothing in any namespace but the
    initial one unless the host sets `nf_log_all_netns`. An NFLOG group has
    no such limit, so it is how a lab sees what its firewall logged.
  - **Use.**
    - `Connection::<Nflog>::new()` (or `Connection::<Nflog>::new_in(ns)`),
      then `bind_group(group, copy_range)`.
    - `events()` then yields an `NflogPacket` for each packet a `log
      group N` rule (or `-j NFLOG`) sends. It carries the family and
      group, the ethertype and hook, the rule's prefix, the mark, the
      timestamp, the input and output interfaces (bridge ports included),
      the hardware address, the sending socket's uid and gid, and the
      packet from its network header.
    - `unbind_group` stops it.
  - **Audit and CI.** The `nfnetlink_log` constants are named as in the
    kernel header, so the UAPI audit checks every one. `nfnetlink_log`
    joins the CI module guard and the strict list.
  - **Tests.**
    - A root test installs a `log group 5 prefix "lab: "` rule and binds
      group 5 in that namespace. It sends one datagram and reads it back:
      the prefix, the family, the group and the input interface, then
      the IPv4 header and UDP port in the payload. It fails with no
      packet when the bind is skipped.
    - Unit tests decode a packet laid out as the kernel builds one, and
      check the bind's `res_id`.

- **The nftables diff runs offline: `RulesetSnapshot` and a pure diff
  (#527, first part).**
  - **Why.** `NftablesConfig::diff` read the kernel as it went. nlink-lab
    could not diff an old topology against a new one without root, and
    could not unit-test a planner built on the diff.
  - **The snapshot.** The reads are now a value, `RulesetSnapshot`:
    - every table, chain and flowtable;
    - the objects, sets and rules of the declared tables;
    - the elements of the declared sets.
  - **The new calls.**
    - `NftablesConfig::snapshot(conn)` reads one between two reads of the
      generation, and reads again if a commit landed between them.
    - `diff_snapshot(&snapshot, options)` is the diff as a pure function
      of it. `diff()` is now `snapshot` followed by `diff_snapshot`.
    - `RulesetSnapshot::from_config(&cfg)` simulates the state applying
      `cfg` leaves, as the kernel would report it.
    - `cfg.diff_against(&previous, options)` therefore says what going
      from one config to another would change, with no kernel and no
      generation to hold.
  - **Unread elements.** A snapshot that did not read a set's elements
    makes the diff fail, rather than taking the set for empty.
  - **Tests.**
    - **Online equals offline.** A root test applies one config, then
      checks that the kernel diff of a second config has the same shape as
      the second config's `diff_against` the first. The second config edits,
      removes and inserts rules, changes a policy, moves set elements both
      ways, changes a quota, and drops a set and a chain.
    - **Round trips.** Each config diffs empty against its own simulated
      echo. The kernel's snapshot diffs as `diff()` does.
    - **Unit.** The same checks run with no kernel, plus the unread-elements
      error.
    - **Red run.** With the rule keys left out of the simulation, all of
      them fail.

- **A rule's key has its own userdata TLV (#527, second part).**
  - **The change.** A declared rule's key used to be stored as `comment
    "nlink:<key> <comment>"`, which `nft list` showed and which shared
    libnftnl's 127 comment bytes with the user's text.
    - It now has a TLV of its own, type `0xF0`. libnftnl uses 0 and 1, and
      nft skips types it does not know.
    - The comment TLV holds the user's comment alone, and each of the two
      gets 127 bytes.
  - **Compatibility.** Rules an older nlink wrote are still read by their
    `nlink:` comment, so an upgrade neither re-adds nor replaces them. The
    reader reads the key TLV first. A comment that sits beside a key TLV is
    taken whole, even if it starts with `nlink:`.
  - **A test it fixed.** #697's NAT test listed `"netmap"` as something
    `nft list` shows. That only passed because the rule's key, `netmap`,
    sat in its comment. nft writes the flag as `snat ip prefix to …`, and
    the test now says so. Every other `nft list` check in these tests
    passed once keys were out of comments.
  - **Tests.**
    - A keyed rule's `nft list` line shows the user's comment and no
      `nlink:`.
    - A rule written the old way (`nlink:k allow the thing`) diffs empty
      against its declaration.
    - Unit tests cover the 127 bytes each, the old form, and a
      `nlink:`-looking comment beside a key.
    - With the old encoding restored, the first test fails.

- **`TableMode::{Owned, Shared}`: tables nlink shares with other tools
  (#527, third part).**
  - **Owned (the default).** A declared table is owned as before: a chain,
    set, object or flowtable the config does not declare is deleted.
  - **Shared.** `DeclaredTableBuilder::mode(TableMode::Shared)` is for a
    table other tools put things in too. Of the undeclared chains, sets
    and objects, the diff deletes only the ones nlink's apply made, and it
    deletes no undeclared flowtable (a flowtable has no userdata to tag).
  - **The ownership tag.** The declarative apply now tags every chain, set
    and object it creates with an ownership TLV in its userdata, in either
    mode. `nft` does not show it.
    - `ChainInfo`, `SetInfo` and `ObjectInfo` gain `managed`, read from the
      tag.
    - `RulesetSnapshot::from_config` marks everything managed.
  - **Tests.**
    - **Root.** A shared table's diff deletes nlink's own chain, set and
      counter when the config stops declaring them, and keeps the ones
      `nft` added. The tag reads back as `managed`, `nft list` shows no
      trace of it, the second diff is empty, and an owned table deletes
      what `nft` added.
    - **Offline.** The same holds against a simulated snapshot.
    - **Red run.** With the mode ignored, the shared diff deletes `nft`'s
      items and the test fails.

- **WireGuard: per-prefix allowed-IP removal and a roaming endpoint policy
  (#529).**
  - **Only what changed.** An allowed-IP edit used to replace a peer's
    whole list (`WGPEER_F_REPLACE_ALLOWEDIPS`), which briefly drops traffic
    to the prefixes that did not change.
    - `PeerChanges` now names `allowed_ips_added` and
      `allowed_ips_removed`.
    - With nothing to remove, the update adds only the new prefixes.
    - With something to remove, it removes each one alone
      (`WgPeerBuilder::remove_allowed_ip`, `WGALLOWEDIP_F_REMOVE_ME`) on a
      kernel that supports that, 6.16 and later.
    - On an older kernel it replaces the list, as before.
  - **The probe.** `Connection::<Wireguard>::allowed_ip_removal_supported`
    asks once per connection, with a message that changes nothing either
    way. It removes, update-only, a prefix the peer does not hold.
    - A kernel without the flag refuses it (`EINVAL`), because its strict
      parse of the allowed-IP nest knows no attribute 4. That was checked
      on 6.12.
    - **Unverified:** the 6.16 path, where the probe succeeds and single
      removals are sent, has not run on a live kernel. Unit tests pin its
      bytes.
  - **Roaming.** `EndpointPolicy::InitialOnly`, set through the peer
    builder's `endpoint_policy`, sets a peer's endpoint when it is added
    and then leaves a peer that roamed where it went. `Enforce`, the
    default, puts it back.
  - **Tests.**
    - **Probe and edits.** On 6.12 a root test checks that the probe says
      no and changes nothing. An edit that drops one prefix and adds
      another ends as declared. An addition-only edit sends only the
      addition.
    - **Roaming.** A second root test roams a peer by hand: `InitialOnly`
      leaves it there, and `Enforce` wants it back.
    - **Unit.** Unit tests cover the diff, the builder in each mode, and
      the remove flag's encoding.
    - **CI.** These tests create WireGuard devices, so they need host root
      and skip in the rootless lane.

- **Simulated Wi-Fi radios and mesh, over netlink (#530).** **Unverified
  on a live kernel:** the machine this was written on has no wireless
  stack. Unit tests pin every command and attribute byte against the
  kernel's headers and the driver's.
  - **`Connection<Hwsim>`** (`genl::hwsim`), for the `MAC80211_HWSIM`
    family, creates and deletes radios at run time instead of fixing the
    host's count with `modprobe mac80211_hwsim radios=N`.
    - `new_radio(NewRadio)` returns the radio's id. Setters: name,
      channels, regulatory hint, permanent address, `no_vif`,
      `use_chanctx`, `destroy_on_close`, P2P device.
    - `del_radio`, `del_radio_by_name`, `get_radio` and `get_radios`.
    - A radio belongs to the namespace of the socket that made it. Its
      wiphy carries its name: `Connection::<Nl80211>::get_phy_by_name`,
      also new, finds it.
    - The driver's header is not in the UAPI, so the UAPI audit cannot
      check these numbers; a unit test pins them.
  - **An ACK can carry a value.** `NEW_RADIO` answers with the radio's id
    in the ACK's error field, where an ACK has 0. nlink read any nonzero
    value there as an errno, so radio 3 would have come back as `ESRCH`.
    The new path reads only a negative value as an error. No existing
    request is affected.
  - **nl80211 interfaces and mesh:**
    - `set_interface_type`;
    - `new_interface(wiphy, name, type)`, which returns the new ifindex;
    - `del_interface`;
    - `join_mesh(iface, mesh_id, freq_mhz)` and `leave_mesh`.

    Each takes an interface name, and each has a `_by_index` variant.

- **Errors name what failed (#526).** `Error::object()` returns an
  `ErrorObject`: the link, address, route, neighbour, FDB entry, rule,
  nexthop, qdisc, TC tree, WireGuard device or peer, sysctl or namespace
  the failed operation was done to.
  - **A `NetworkConfig` apply** names the object of the step that failed.
    A propagated error also gets the step's operation as context: `add
    route 10.9.0.0/24: replace_route: Network is unreachable …`, where the
    message used to name no route.
  - **A WireGuard apply** names the device or peer, with `add/update/remove
    peer <key> on <dev>` as context.
  - **A sysctl, interface-not-found or namespace error** names its object
    by itself.
  - **`with_object`** adds one; the innermost object is kept.
  - **`ApplyError`'s JSON** gains `kind`, `errno`, `ext-ack`, `context`
    and `object` beside `operation` and `error`, so a consumer no longer
    parses the errno out of a string.
  - **Test.** A root test declares a route through an unreachable gateway.
    The propagated error, and the `continue_on_error` one with its JSON,
    must name the route. Before, `object()` was `None` and the message
    named no route.

- **The UAPI audit checks nlink against the kernel's YNL specs too (#167).**
  The kernel describes its netlink families in YAML specs, and its header
  generator names every constant in them by fixed rules. 16 of those specs,
  from v7.2, are vendored in `third_party/ynl-specs/` with a `SOURCE` of
  per-file sha256s. `scripts/audit-uapi-constants.sh` derives their constants
  by the generator's rules and merges them with the host's headers:
  - **A spec reaches past the host's headers.** That covers families newer than
    the build host, such as ovpn (6.16) and net_shaper (6.13) on a 6.12 host,
    and every constant added after the host's kernel. It covers 734 constants
    the 6.12 headers do not define.
  - **A spec that disagrees with a header fails the build.** Either the
    derivation or the spec is wrong for that case. The one known spec quirk
    (nlctrl lists `NL_POLICY_TYPE_ATTR_MASK` before `_PAD`) is listed by name,
    with its reason, in `audit-uapi-constants.ynl-quirks`.
  - **A spec edited by hand fails.** A spec can change only through
    `scripts/vendor-ynl-specs.sh <tag>`, in a reviewed commit.

  The audit also reads enums declared through the GENL derives
  (`#[genl_attribute/command/enum(repr = "uN")]`). That form had gone
  unchecked, which left out all of ovpn, net_shaper and dpll: 26 enums and
  178 values. They all match. Three constants the specs now vouch for left
  `audit-uapi-constants.newer`. The audit needs PyYAML, and fails without it
  instead of skipping. Its self-test reconstructs:
  - a drift that only a spec can see;
  - a spec that disagrees with a header;
  - a spec edited by hand;
  - an unclassified GENL enum;
  - a missing PyYAML.

  The nftables and conntrack specs are not vendored. They give no values and
  omit pad attributes, so their implicit numbering drifts from the headers,
  which every supported host has anyway.

- **The UAPI audit reads private constants, and reports coverage (#167).**
  The plain-constant pass read only `pub const`, which left 269
  kernel-named constants unchecked. All of the XFRM message types and
  attributes were among them, including those fixed by the 0.19.1 hotfix.
  It now reads every visibility, and they all match. The MPTCP path-manager
  modules name their constants by suffix, so they are mapped in
  `audit-uapi-constants.modmap`; 44 of their constants are checked, and all
  match. `python3 scripts/audit_uapi_constants.py --coverage` prints how
  much of each vendored spec nlink mirrors, per attribute set, enum and op
  list. Over the 16 specs it is 42%; netdev and the MPTCP events are at 0%.

- **An error says which namespace its connection was in (#718).**
  `Error::netns()` returns the label of the `Netns` a connection was made
  in: an `ip netns` name, a path, `pid 42`, and so on. `Display` puts it
  last: `add_route: Network is unreachable (errno 101) [netns red]`, and
  `ApplyError` serializes it as `netns`. A caller with one connection per
  namespace, such as a lab with a node in each, can tell which one failed
  without wrapping every call. The label is carried by:
  - the kernel's refusals, on every request path: rtnetlink requests,
    dumps and batches, GENL families, nftables batches, sockdiag, xfrm,
    conntrack, audit and `fib_lookup`;
  - the socket's own I/O errors and timeouts;
  - dump and event streams;
  - GENL family lookups;
  - the lookups a connection does by name (`InterfaceNotFound`).

  A connection made through `Connection::new_in`, `Netns::connection` or
  `sibling` has a label; one in the calling thread's namespace has none.
  Errors from checking arguments before anything is sent carry no label.

- **nftables errors name their table, chain, rule, set, object or
  flowtable (#718).** `ErrorObject` gains `NftTable`, `NftChain`, `NftRule`
  (its chain, and its key where it has one), `NftSet`, `NftObject` and
  `NftFlowtable`. Each `NftBatchFailure` carries the object its operation was
  done to, read from the message nlink sent, in a new `object` field. A
  refused batch's `Error::object()` is the first one's. The declarative
  apply's own refusals name theirs too: a table flag the kernel won't
  change on a live table, a chain recreate that would delete rules nlink
  did not write, and a set update the kernel kept. Imperative and
  declarative paths alike can say which rule failed without parsing a
  message.

- **TC errors name their qdisc, class or filter (#718).** `ErrorObject`
  gains `TcClass` (its id) and `TcFilter` (its parent, priority and
  protocol, which is how the kernel tells filters apart). `Qdisc` gains its
  `parent`, and its `kind` is an `Option`, for a delete that doesn't know
  the kind. A declared tree's step names the class, filter or leaf it was
  installing or removing, where it used to name only the tree's device. The
  qdisc verbs (`conn.tc(dev).qdisc(parent).create(..)` and the rest) name
  their slot.

- **`del_*_if_exists` for neighbours, rules, nexthops and xfrm SAs and SPs
  (#718).** `del_neighbor_if_exists`, `del_rule_if_exists`,
  `del_nexthop_if_exists`, `Connection::<Xfrm>::del_sa_if_exists` and
  `del_sp_if_exists` answer `Ok(true)` when they deleted something and
  `Ok(false)` when there was nothing to delete, like the route, address,
  link and TC ones. The kernel reports a missing neighbour, rule, nexthop
  or policy as `ENOENT`, and a missing SA as `ESRCH`. `is_not_found()` now
  reads `ESRCH` as not found for an xfrm SA delete, get or update, and only
  on xfrm: on rtnetlink those message types are link requests.

- **Declared vti6, erspan and ip6erspan links, and ERSPAN tunnels (#680).**
  - **Imperative.** `ErspanLink` and `Ip6ErspanLink` take a session id
    (the GRE key, 10 bits), ends, TTL or hop limit, an underlay device, and
    an `ErspanVersion`: type II with an index, or type III with an
    `ErspanDirection` and a hardware id. They send the `GRE_SEQ | GRE_KEY`
    flags that `erspan_validate` requires, and the `IFLA_GRE_ERSPAN_*`
    attributes nlink had not written before. `Vti6Link` gains `mtu`.
  - **Declarative.** `LinkBuilder::vti6()` takes the `ip6tnl_*` ends,
    `tunnel_key` and `tunnel_underlay_dev`. `erspan(session)` and
    `ip6erspan(session)` take the `erspan_*` setters and
    `tunnel_underlay_dev`. Each kind's parms rebuild the configuration
    from the request, so any difference sends the whole declared set.
  - **Validation:**
    - a vti6 with no end, underlay device or key, which is the fallback
      `ip6_vti0`'s tunnel;
    - a link named `ip6_vti0`;
    - a vti6 hop limit, encapsulation limit or mode;
    - ERSPAN ends of the other family;
    - a session id, index or hardware id past its width.
  - **CI.** `ip6_vti` joins CI's module lists.
  - **Test.** A transition test changes every parameter of all three in
    place, the ERSPAN headers between type II and type III, and checks
    each step through `ip -d -j link`.

- **A veth peer's MAC, MTU and state, in its namespace (#680).**
  `LinkBuilder::veth_peer_address`, `veth_peer_mtu` and
  `veth_peer_up`/`veth_peer_down` set the peer that `veth_peer_netns` puts
  in another namespace, where no declaration in the config can name it.
  The create sets the MAC and MTU in the peer's message (`VethLink` gains
  `peer_mtu`), and brings the peer up there once the pair exists. After
  that the diff reads the peer through a connection in its namespace:
  `Snapshot` reads the links of each such namespace. Any change is a
  `ConfigDiff::veth_peers_to_modify` entry, and a `Step::ModifyVethPeer`
  that the apply runs there and the plan can invert. A peer in this
  namespace is a link of its own, so validation refuses peer settings
  without a peer namespace and says to declare the peer.

- **VRF strict mode (#680).** `NetworkConfig::vrf_strict_mode(bool)`
  declares the namespace's `net.vrf.strict_mode`. In strict mode a routing
  table belongs to one VRF at most. The diff reads the sysctl in the
  connection's namespace (unreadable means the `vrf` module isn't loaded,
  so it is off), and a difference is `ConfigDiff::vrf_strict_mode` and a
  `Step::SetVrfStrictMode`. The apply turns strict mode off before it
  creates links and on after, since the kernel refuses a VRF on a table
  another VRF has while strict mode is on. Validation refuses a config that
  turns it on with two VRFs on one table.

- **A plan says why it re-adds (#649).** An address or route that is there
  now, and that a link change in the same apply flushes, is re-added (#409,
  #427, #436). Its step now says why: `Step::AddAddress { address, reason }`
  and `Step::ReplaceRoute { .., reason }`, read through `Step::reason()`,
  for example `re-add: flushed when d0 changes master`. The diff records
  the cause for each flushed link: it goes down, it changes master, it
  leaves a recreated master, or the lower device under its VLAN goes down.
  `Step::AddAddress` was a tuple variant; `Plan` and `Step` are new in this
  release.

- **A plan reads back from its serialized form (#649).** `Plan` and `Step`
  implement `Deserialize`, so a plan can be reviewed as JSON or YAML and
  applied later, or by another process. A plan read back applies as the plan
  would. What an apply and an undo need is in the serialized form:
  - a link change's kind attributes, by their `IFLA_INFO_DATA` ids;
  - its bridge-port options and VLANs;
  - what the link had before;
  - the reasons;
  - the plan's owner tag and route protocol.

  `TcHandle`, `BridgePortConfig` and the devconf names deserialize too. A
  `Step::TcTree` is refused on read for now, because a TC tree has no
  serialized form yet (#645). It is not read back empty.

- **An undo puts back kind parameters, replaced qdiscs and TC trees (#649).**
  `ApplyResult::undo()` used to report these as irreversible.
  - **Kind parameters.** An in-place change records the live attributes it
    replaces: for most kinds, the ones it sends. For the tunnels, whose
    parms rebuild the configuration from the request, it records the whole
    live set. The inverse sends them back.
  - **Replaced qdiscs.** `Step::ReplaceQdisc { before, after }` carries the
    live qdisc as a declaration (netem, fq_codel, HTB, TBF, sfq, prio,
    ingress, clsact). The inverse replaces it back, or deletes the declared
    qdisc where the kernel's default was there. A root removed for a
    kernel-default declaration records the live qdisc too, so its undo adds
    it again. One whose kind doesn't read back is now irreversible. It
    used to claim an inverse that restored nothing.
  - **TC trees.** A tree applied against the previous config's tree inverts
    to that one.

- **TC trees take HFSC, DRR and QFQ classes and roots (#645).** Before this, a
  declared tree could hold only HTB classes.
  - **Classes.** `ClassSpec` gains `Hfsc`, `Drr` and `Qfq`, built from
    `HfscClassConfig`, `DrrClassConfig` and `QfqClassConfig`.
  - **Roots.** `QdiscSpec` gains `Hfsc`, `Drr` and `Qfq`, with
    `QdiscBuilder::{hfsc, drr, qfq}`. `default_class` now sets HFSC's
    default too, and HFSC's changes in place.
  - **Comparison.** Each class is compared with what the kernel reports for
    it. Some unset values aren't compared, because the kernel chooses them:
    a DRR quantum, and a QFQ `lmax`, which are the device's MTU. A QFQ
    weight left unset is compared as 1, because that's what the kernel
    applies when a change doesn't send one.
  - **Recreates.** A change can't drop an HFSC curve; the kernel keeps
    every curve it isn't sent. So a class that drops one is deleted and
    added again. A class that moved already was, and both now also take
    along the classes under them, the leaf in them and their qdisc's
    filters. Without that, a moved class with children was refused, and
    its leaf didn't come back.
  - **Validation.** It refuses:
    - an HFSC class with neither a real-time nor a link-sharing curve;
    - a DRR or QFQ class hung under another class;
    - classes of two kinds under one qdisc;
    - a class whose qdisc is declared as another kind.
  - `ClassSpec` implements `ClassConfig`, as `QdiscSpec` implements
    `QdiscConfig`.
  - An undo puts a replaced HFSC, DRR or QFQ root back, since
    `QdiscSpec::from_live` reads them.

- **A mirred action can name its target (#645).** `MirredAction::to_dev(name)`
  sends to the device by name. The connection that installs the filter or
  action resolves the name in its own namespace, at every install. So a
  declared tree's filter finds its target again after the target is deleted
  and created with another ifindex. Before, that worked only for
  `TcBuilder::redirect_ingress_to`.
  - `ActionConfig` and `FilterConfig` gain `device_names()` and
    `resolve_devices()`, with defaults. Flower, matchall, cgroup, route,
    rsvp and flow filters pass them through to their actions.
  - A route filter also resolves its `from_if`.

- **TC trees in JSON and YAML (#645).** `NetworkConfig.tc`, `ConfigDiff.tc` and
  a plan's `Step::TcTree` serialize and read back. Each class, filter and action
  is written as its kind plus the tc(8) words its `parse_params` reads:
  `{"kind": "flower", "params": "ip_proto tcp dst_port 22 classid 1:10",
  "actions": [{"kind": "mirred", "params": "egress mirror dev ifb0"}]}`. The IFB
  redirect is written `{"redirect-to": "ifb0"}`. Handles and protocols are
  written as tc(8) writes them.
  - **`to_params` writers.** `to_params()` is the inverse of `parse_params`:
    parsed back, its tokens give the same request. It's new on
    `FlowerFilter`, `MatchallFilter`, `FwFilter`, `U32Filter`,
    `HtbClassConfig`, `HfscClassConfig`, `DrrClassConfig` and
    `QfqClassConfig`. `ActionConfig` gains it as a provided method, and all 19
    action kinds implement it.
  - **Values a grammar can't express** are an error, not dropped. Examples:
    a bpf action held by file descriptor, a goto verdict on an action other
    than gact.
  - **Grammars that grew so every builder value has a word:**
    - HFSC curves take `[m1 <rate> d <time>] m2 <rate>`, and `sc` for real-time
      and link-sharing together. Before, they took only `rt|ls|ul rate <rate>`.
    - u32 takes `match mark VAL MASK` and `at nexthdr+N`.
    - flower takes `chain` and `goto_chain`.
    - mirred, and the vlan, mpls, skbmod, skbedit, tunnel_key, connmark, ctinfo,
      ife, gate, csum, sample, ct and nat actions, take a verdict (`pipe`,
      `drop`, …).
    - ct takes `label`, `port`, `helper <family>-<proto>-<name>` and IPv6 NAT
      addresses.
    - A bpf action opened with `from_pinned` is written `pinned <path>`.

- **The TC recipes as declarations (#645).** `RateLimiter`, `PerHostLimiter`
  and `PerPeerImpairer` each gain `declare(config)` and `to_config()`. Each
  returns what its `apply` installs, as part of a `NetworkConfig`, with the
  same handles, priorities, classes, leaves and filters. So a recipe can be
  diffed and applied with the rest of a config, not beside it.
  - Installed imperatively, the declaration diffs empty against it.
  - Applied from the declaration, the recipe's `reconcile` has nothing to do.
  - `RateLimiter`'s ingress half declares its tagged IFB and the redirect on
    the device's hook. That's the clsact or ingress qdisc the config already
    declares, or an ingress qdisc if it declares none.
  - A `PerPeerImpairer` made with `new_by_index` can't be declared, since a
    declaration names its device.

## [0.31.0] - 2026-10-11

> **The nlink-lab release: 53 bugs fixed, and tests in the shapes that
> missed them.**
>
> nlink-lab adopted 0.30.0, reviewed nlink from its side and filed 76
> issues (#534). This release fixes the 53 bugs among them and a docs
> issue. It also adds four small features they asked for:
> - link options at creation: `master`, `up`, `alias` and `netns` (#517);
> - `wait_link` and a DAD-aware `wait_addresses_settled` (#524);
> - a WireGuard `PrivateKey` type (#529);
> - `PartialEq`, `is_empty()` and JSON Schemas on the declarative configs
>   and diffs (#531).
>
> The redesigns it filed move to 0.32.0.
>
> Those bugs sat behind a green suite of about 2400 tests, because no test
> had their shape:
> - a declared value changed in place;
> - a removal of something still referenced;
> - traffic through ingress or between namespaces;
> - an event that never came.
>
> The helpers in `tests/common/` now cover those shapes, and every fix here
> came with a test that failed without it. A closing sweep found three more
> bugs (#596–#598). It changed every declared field in place and read it
> back with `ip`, `tc` or `nft`, probed the edge values, and installed 13
> flower lines through both `tc` and nlink. Planning the next cycle found
> five more (#600–#604). One of them meant CI could pass without running 22
> module-gated tests.
>
> The compile breaks are small and mechanical. The behaviour changes are
> many: read the behaviour section of the
> [migration guide](docs/migration_guide/0.30.0-to-0.31.0.md) before
> upgrading.

### Breaking Changes

- **Bond `xmit_hash_policy` is typed in `NetworkConfig` (#476).**
  `LinkBuilder::xmit_hash_policy` takes a `BondXmitHashPolicy` (the
  link module's `XmitHashPolicy`, re-exported), and
  `DeclaredLinkType::Bond { xmit_hash_policy }` is
  `Option<BondXmitHashPolicy>`. JSON names the policy (`"layer34"`,
  `"vlan_src_mac"`) instead of a number. See the migration guide.

- **`DiagnosticsConfig` gains `warn_no_default_route` (#509).** Struct
  literals need it, or `..Default::default()`.

- **`StackApplyReport` gains `dry_run: Option<StackDiff>` (#501).** A
  struct literal must add the field, or build the report with
  `..Default::default()`.

- **`TcStatsRateEst` is 64-bit, and `TcMessage::{bps, pps}` return `u64`
  (#489).** `TCA_STATS_RATE_EST` caps the byte rate at `u32::MAX` (about
  34 Gbit/s), and the kernel sends the real value in
  `TCA_STATS_RATE_EST64` only then. nlink now reads it. Drop any `as u64`
  at the call site.

- **A link declaration that does not mention a master leaves it alone
  (#462).** Use `LinkBuilder::nomaster()` to release a link from its
  master; a declaration without `master()` or `nomaster()` no longer does.
  `NetworkConfig::link` called twice for one name updates the first
  declaration, and `DeclaredLink::master_spec()`/`MasterSpec` expose the
  three states. See the migration guide.

- **`DeclaredQdiscType::Prio` gains `priomap` and `#[non_exhaustive]`
  (#487).** Construct it with `QdiscBuilder::prio()`; match it with `..`.

- **`FqCodelConfig::ecn` is `Option<bool>` (#488).** `None` sends nothing,
  and the kernel's default is ECN **on**. `.ecn(false)` now really turns
  it off. See the migration guide.

- **`ParsedExtAck` gains fields and `#[non_exhaustive]` (#507).** The
  workspace moves to 0.31.0 with it. See
  [`docs/migration_guide/0.30.0-to-0.31.0.md`](docs/migration_guide/0.30.0-to-0.31.0.md).

### Fixed

- **A WireGuard keepalive under a second turned keepalive off (#529).**
  `persistent_keepalive(Duration::from_millis(500))` was truncated to 0
  seconds, which WireGuard reads as "off", with no warning. A fraction of
  a second now rounds up. More than 65535 s fails `validate()`.

- **Documentation that contradicted the code (#511).** About 35
  statements, each checked against the source. Those that later fixes in
  this cycle had made true, or had already rewritten, are left as they
  are. The rest are corrected, among them:
  - the `NetworkConfig` supported-resources list and its purge
    descriptions;
  - the nftables event docs, which said sets, elements, objects and
    `NewGen` were dropped;
  - rule identity without a key (#389);
  - `list_set_elements` decoding;
  - `NFTA_SET_ID`, `InetProto`'s length, and `apply()`'s one
    non-atomic batch;
  - chain devices on non-netdev hooks;
  - `wait_link_up`;
  - the mutex-mode stream lock;
  - `execute_in` and `/proc/thread-self/net`;
  - the reflector example, which printed an empty cache;
  - which namespaces get non-net uevents;
  - examples that stopped at the first `ENOBUFS`;
  - the WireGuard key-readback docs and `WgPeerFlags::UpdateOnly`.

  Newly documented: what a `log` statement needs in a network namespace
  (`nf_log_all_netns`, `nf_log_syslog`).

- **`RateLimiter` touched what it did not own, and its ceiling was out of
  reach (#490).**
  - **`remove()`** deleted whatever root and ingress qdiscs were there,
    such as another recipe's tree or a clsact with its BPF programs, and
    discarded every error. It now removes only what the limiter built:
    - the root qdisc, if it is the HTB `1:` with the limiter's default
      class;
    - its redirect;
    - the `ingress` qdisc, once nothing else is on it (never a clsact);
    - its IFB.

    It returns real errors (something already gone is not one). The new
    `remove_egress()` and `remove_ingress()` take one half.
  - **Clsact:** the ingress half deleted whatever sat at `ffff:` first.
    That includes a clsact, and with it its programs. It now hangs its
    redirect off the clsact's ingress hook.
  - **Undeclared halves:** a direction that left the declaration was never
    taken down by `reconcile`. It is now.
  - **IFB ownership:** the IFB was reused if anything had its name. It
    must now be an IFB carrying the limiter's alias tag
    (`nlink:ratelimit:<dev>`; untagged ones from before 0.31 are adopted).
    New: `LinkMessage::alias()` and `Connection::set_link_alias{,_by_index}`.
  - **Drift:** reconcile ignored the burst, and accepted any AQM target
    when none was declared. A burst or latency dropped from the
    declaration now resets to the default, which is sent explicitly,
    because a replace keeps what it is not sent. `PerHostLimiter`'s leaves
    get the same.
  - **Ceiling:** with `burst_to`, class `1:1` sat under the qdisc at `rate`
    and so could never pass it. Measured: 1.1 Mbit/s through a
    `1mbit`-to-`8mbit` limiter. `1:1` now takes the ceiling as its rate,
    and the limiter reaches it.

- **The tc recipes could not shrink past 100 rules, and "fixed" a wrong
  HTB default with an operation HTB does not have (#491).**
  - `PerPeerImpairer` puts rule `i` at priority `100 + i`, so rules 100
    and up sit above the recipe band. Reconcile told its filters by the
    band, so when the rules shrank it left those filters behind, still
    bound to the classes it was deleting (`EBUSY`, "HTB class in use").
    It now tells its filters by the class they send to, as
    `PerHostLimiter` does.
  - When the live HTB `1:` had another default class, `PerPeerImpairer`
    and `PerHostLimiter` reconciles sent a change, which HTB does not
    support (always `EINVAL`), and `fallback_to_apply` was ignored. That
    happens on a pre-0.26 tree, or where another recipe built the HTB.
    It is now handled like a wrong root: rebuilt under
    `fallback_to_apply`, otherwise an error that names the default class.
  - `RateLimiter` never checked the default class, so it added its
    classes into another recipe's tree. It now checks it the same way.
  - CI's module lists gain `sch_fq_codel`.

- **nftables set and object edge cases that failed every apply, or
  dropped what was declared (#483).**
  - A rule using an object map (`counter name ip daddr map @m`) was not
    seen as bound to it, so recreating the map was `EBUSY`. It now moves
    out of the way like a `lookup` does.
  - A recreated object that an object map's element names (a limit whose
    rate changed) was `EBUSY`. Those elements now let go before the delete
    and come back after the add.
  - An interval set's declared ranges were rebuilt without their own
    timeouts, so a range with a timeout never timed out. Ranges now keep
    them; touching ranges with different timeouts stay separate.
  - In ensure mode, a declared range that overlapped one added at runtime
    was refused by the kernel on every apply. It now goes in as the parts
    not already covered.
  - In exact mode, an element of a timeout set that expired between the
    diff and the apply failed the whole batch with `ENOENT`. On 6.3+ the
    removal is `NFT_MSG_DESTROYSETELEM` (new
    `Transaction::destroy_set_elements`, and `kernel_has_destroy()`).
  - Element changes to a constant set a rule is bound to were `EBUSY`.
    The set is recreated instead, with its rules moved.

- **A flowtable with a device could not be created, and table-flag and
  flowtable changes never applied (#479).**
  - **Flowtable devices:** each device was wrapped in an `NFTA_LIST_ELEM`
    nest, whose bytes the kernel took for the name, so any flowtable with
    a device failed with `ENOENT`. The reader expected the same nest and
    read no devices from a real dump. No test had used a device. Devices
    are now bare `NFTA_DEVICE_NAME`s, both ways.
  - **Table flags:** a flag change went out as an add with `NLM_F_EXCL`
    (`EEXIST`), and without `NFTA_TABLE_FLAGS` when it was 0, which the
    kernel ignores. The new `Transaction::update_table` sends the update
    with its flags. A persist or owner change, which the kernel refuses
    on a live table, is listed in the new `NftablesDiff::tables_refused`,
    and the apply fails with `NotSupported` before it changes anything.
  - **Flowtables:** every change went to `flowtables_to_add` (`EEXIST`).
    Now:
    - devices and the counter flag change in place, through the new
      `flowtables_to_update` (`FlowtableUpdate`) and the new
      `Transaction::update_flowtable` / `del_flowtable_devices`;
    - devices are compared as a set (the kernel lists added ones first);
    - a priority or hardware-offload change recreates the flowtable, with
      the rules that offload to it moved out of the way
      (`MoveReason::BoundToRecreatedFlowtable`).
  - CI's module lists gain `nf_flow_table` and `nft_flow_offload`, so the
    flowtable tests cannot skip there.

- **nftables: hooks per family, multi-device chains, PAD attributes,
  interface names, and `validate()` (#484).**
  - **ARP hooks:** `Hook` encoded inet hook numbers for every family, but
    ARP numbers its own (`NF_ARP_IN = 0`, `NF_ARP_OUT = 1`). An `arp`
    input chain therefore filtered outgoing ARP, and an output chain was
    refused. Chains now go out with `Hook::number(family)`.
    `Hook::to_u32` is deprecated.
  - **Hook validity:** `is_valid_for_family` no longer accepts forward,
    prerouting or postrouting for `arp`, nor `NetdevIngress` for `bridge`,
    which has no ingress hook and read it as prerouting.
  - **Multi-device chains:** a netdev chain on several devices dumps
    `NFTA_HOOK_DEVS` and no `NFTA_HOOK_DEV`. That list is now parsed into
    the new `ChainInfo::devices`. A device change recreates the chain (as
    in #478) rather than adding to the list.
  - **PAD attributes:** the rule normalizer drops zero-length attributes.
    These are the `*_PAD` that `nla_put_64bit` adds on architectures
    without efficient unaligned access. They made every counter, limit,
    quota and dynset rule there be replaced, counters reset, on every
    apply.
  - **Interface names:** `match_iif`/`match_oif` cut a name over 15 bytes
    to 15, so the rule matched nothing. Adding such a rule is now an
    error, and `validate()` reports it. New `match_iif_not`/`match_oif_not`
    (`!=`) and `match_iif_prefix`/`match_oif_prefix` (nft's `"eth*"`).
  - **`validate()`** now refuses:
    - a rule in a chain the table does not declare (the diff deleted that
      chain);
    - a policy on a regular chain;
    - a hook the family does not have;
    - a netdev or inet-ingress chain without a device;
    - a `route` chain off the output hook;
    - a `nat` chain at priority -200 or below.

- **A chain's hook, priority or type could not be changed, and a base
  chain declared as a regular one stayed a base chain (#478).** The diff
  sent these as an update. `nf_tables_updchain` refuses those on a live
  chain (`EOPNOTSUPP` on 6.12, `EEXIST` on older kernels), so the apply
  failed every time. A chain declared without a hook was "no claim", so a
  base chain of that name kept filtering behind an empty diff.
  - **The fix is a recreate.** The chain goes in the new
    `NftablesDiff::chains_to_recreate` as a `ChainRecreate`
    (`-/+ chain … (recreate: priority 0 -> -10)`). The apply deletes its
    rules and the chain, creates it again, and puts the declared rules
    back in declared order (`MoveReason::ChainRecreated`).
  - **Rules nlink did not write** refuse the recreate, because it could
    not put them back. An `exclusive` chain deletes them instead.
  - A policy change alone is still an update in place, and the
    `~ chain` line now shows the type and device too.

- **A link recreate destroyed TC trees silently (#472).** The recreate
  check matched a declared root or ingress qdisc against the qdisc slot
  alone. It never read classes, leaf qdiscs or filters. A declared `htb`
  on a link carrying a `RateLimiter` (or an `ingress` with a redirect
  filter) let the recreate go ahead, and only the bare qdisc came back.
  When a recreate is planned, classes and filters are now read for every
  link that has a qdisc of its own. User-made classes (htb, hfsc, drr,
  qfq, cbq), qdiscs under a class, and every filter now block the
  recreate. The kernel's own (prio bands, mq queues, fq_codel flows) do
  not.

- **A link recreate was refused over what the same purge deleted, and was
  not refused when it would delete a veth's peer in another namespace
  (#471, items 1 and 3).**
  - With purge on, an undeclared address on the link or a static route
    through it held the recreate back, even though the same apply was
    about to delete it. So changing a VLAN id and dropping one of its
    addresses took two applies. What the purge removes no longer blocks;
    the diff and the plan share the purge predicates.
  - A veth's or vxcan's peer in another namespace is not part of the
    recreate closure (nothing here can declare it), so a kind change on
    the live link deleted the peer silently. That is now a blocker.

  Item 2 (per-link settings such as devconf, an undeclared MAC, MTU,
  txqlen or alias, which a recreate resets silently) moves to #513.

- **Link changes ran in declaration order, so the kernel refused valid
  configs (#473).** Only creates were sorted.
  - **Raising a parent's and a VLAN's MTU together** failed with `ERANGE`
    when the VLAN came first.
  - **Creating a VLAN or macvlan at an MTU its parent was about to get**
    failed with `EINVAL`, because creates ran before every modification.
  - **Bringing a VLAN up before its parent** failed with `ENETDOWN`.

  Modifications now go lower device first. The MTU of a lower device
  under a new link is set before the creates. Within one link, the MAC is
  set while the link is down (after a `down`, before an `up`), because
  most hardware refuses a MAC change while up with `EBUSY`. The CI
  module lists gain `bridge`.

- **A declared link that did not exist was skipped without a word
  (#475).** A link declared without a kind is not created, and when it
  was missing, its declaration was dropped from the diff.
  - **The peer of a veth or netkit pair created in the same apply** got
    its declared state, MTU and master only on the next apply, so after
    the first apply the pair had no carrier. These settings now go in as
    modifications, which run after every create.
  - **Anything else, such as a typo or a device that is not there yet,**
    is listed in the new `ConfigDiff::links_missing`
    (`! link X (missing: …)`). The apply fails with
    `Error::InterfaceNotFound` before it changes anything.
  - `Stack` does not count its own WireGuard devices as missing, because
    an apply creates those first.

- **A declared route could silently replace the kernel's connected route
  (#469).** Declared routes are added with `NLM_F_REPLACE`, and the kernel
  replaces the first route at the same destination, table and metric,
  whoever owns it. So `10.0.0.0/24 via 10.0.0.254` on a link holding
  `10.0.0.1/24` took the place of the `proto kernel` prefix route. Every
  gateway on that segment then failed with `ENETUNREACH`, and the next
  diff called the config converged. A declared route whose place holds a
  route of a protocol nlink does not add (anything but `static`/`boot`:
  kernel, RA, DHCP, a routing daemon) is now listed in the new
  `ConfigDiff::routes_refused` (`! route … (refused: …)`), and the apply
  fails with `Error::NotSupported` before it changes anything. At
  another metric the route is added next to the connected one.

- **The address purge missed a link with no declared address left, and
  removed addresses the kernel hands out (#470).**
  - A purge only managed the interfaces that still had a declared
    address, so when a link's last address left the config, the address
    stayed on the link. It now reaches every declared link as well, and
    `DiffOptions::purge_address_devs` / `ApplyOptions::with_purge_address_devs`
    add interfaces a caller owned before and declares nothing on now.
  - It removed SLAAC, privacy and DHCP-leased addresses. The next RA or
    renewal brought them back, so a purging diff never converged where
    an RA source or DHCP client ran. An address without
    `IFA_F_PERMANENT` is now left alone unless declared.

- **Four `NetworkConfig` builder mistakes became a different config
  instead of an error (#476).**
  - `route(.., |r| r.via("10.0.0.1x"))` dropped the gateway it could not
    parse and declared an on-link route. `route()` now returns the parse
    error.
  - A gateway of the other family (`10.0.0.0/8 via fd00::1`) was dropped
    at apply while the diff still compared it, so the route was installed
    without a gateway and replaced on every apply. `route()` refuses it,
    and `validate()` refuses it from JSON. (RFC 5549 `RTA_VIA` is not
    modelled.)
  - A `qdisc()` declaration that chose no kind built an fq_codel, which
    an apply put in place of whatever root was there. It is now a
    validation error.
  - A `QdiscBuilder` setter that does not fit the chosen kind did
    nothing: `q.delay_ms(10).netem()` lost the delay, and
    `q.htb(..).delay_ms(10)` was ignored. Both are validation errors
    naming the setter and the kinds it fits.
  - The bond `xmit_hash_policy` was filtered through `XmitHashPolicy` on
    create but sent raw by the in-place update, so an invalid value was
    dropped on the first apply and failed `EINVAL` on every apply after.
    It is typed end to end now.

  A builder that cannot return an error records it, and
  `NetworkConfig::validate()` (which `diff` and `apply` run) reports it
  under the declaration's path, e.g. `qdiscs.eth0`.

- **The namespace watcher reported `Created` before the namespace existed,
  constructors that return `Result` panicked, and `get_route_v4/v6` were
  not what their docs said (#510, items 1, 2 and 4; item 3 shipped
  earlier).**
  - `NamespaceWatcher` fired `Created` on the marker's `IN_CREATE`. Both
    `ip netns add` and nlink's `create` make the marker and mount the
    namespace on it afterwards, and a mount raises no inotify event. So a
    `connection_for(name)` in response raced into `NamespaceNotFound`,
    and a marker nobody mounted got a `Created` at all. `Created` now
    waits, up to 2 s, for the mount.
  - `IN_Q_OVERFLOW` is the new `NamespaceEvent::Overflow` rather than
    ignored.
  - Events queued during a directory switch come out in order.
  - `list_and_watch` lists live namespaces only.
  - `NamespaceEventStream` implements `Stream`.
  - `thread::spawn`, which panics when no thread can be made, is replaced
    by `thread::Builder` in the namespace socket, create and sysctl
    workers.
  - A netlink socket made outside a tokio runtime is an error, not an
    `AsyncFd::new` panic.
  - `get_route_v4/v6` are deprecated in favour of `lookup_route`. They
    were always a FIB lookup of the address. Their `prefix_len` became the
    request's `dst_len`, which strict checking refuses unless it is 32 or
    128; it is ignored now. `nlink-ip route get` uses `lookup_route`.

  A root test checks that a stale marker is neither listed nor
  `Created`, and that a real namespace's `Created` arrives through the
  `Stream` once `connection_for` works. On master the stale marker was
  listed. A unit test checks the socket outside a runtime; on master it
  panicked.

- **Diagnostics: `check_connectivity` picked the first route that contained
  the destination, and four heuristics misreported (#509).**
  - `check_connectivity` searched a dump of every table with `find` and
    called that "longest prefix match". The default route won for every
    destination, policy rules were ignored, and a blackhole counted as
    reachable. It now asks the kernel, as `ip route get` does, through the
    new `Connection::lookup_route(dest)`. A lookup that ends in an
    unreachable, prohibit or blackhole route, or in none, is a `NoRoute`
    issue that says which.
  - Loss and error rates used lifetime counters even with a previous
    sample, so one old burst flagged an interface forever. They are the
    interval's now; a counter that went backwards falls back to lifetime.
  - The qdisc drop rate was `drops / packets`; it is out of
    `packets + drops`.
  - netem's drops, which are its configured loss, were a "dropping X%"
    warning. They are an Info issue that says so, and `find_bottleneck`
    skips netem.
  - A failed route dump was swallowed into an empty list, which then
    raised a spurious "no default route". It is an error now, and the
    warning can be turned off (`warn_no_default_route`).

  A root test checks that a /16 beats the default route and that a
  blackhole is reported as one; on master the default route won. Another
  turns the warning off. Unit tests cover the drop maths, netem, and
  rates since the previous sample.

- **WireGuard `SET_DEVICE` put every peer in one nest, which overflowed the
  u16 `nla_len` (#500).** Around 400 peers, or about 1,600 IPv6
  allowed-ips on one peer, hit `nest_end`'s `debug_assert!` in debug
  builds; release builds clamped the length and sent a malformed message.
  The set is now split the way `wg(8)` splits it, into messages of at most
  32 KiB. The device's own settings and `WGDEVICE_F_REPLACE_PEERS` go in
  the first message. A peer continued into the next message repeats only
  its public key and the rest of its allowed-ips, without
  `WGPEER_F_REPLACE_ALLOWEDIPS`. `MessageBuilder::nest_end` no longer
  panics; it records the oversize (`oversized_nest()`), and the send
  paths and nftables transactions refuse such a message in every build.
  A root test sets 500 peers and one with 2,000 IPv6 allowed-ips, and
  reads all of them back; on master it panicked at 80,004 bytes. Unit
  tests cover the plan, and the refusal of an 80 KB nest.

- **GENL interface lookups and `Diagnostics::watch()` used the process's
  namespace, not the connection's (#497).** The WireGuard, ethtool and
  MACsec connections resolved an ifindex, or a name, with a new
  `Connection::<Route>::new()`, which is in the *process's* namespace. So
  in a lab the host's ifindex 2 named the host's `eth0`. `Diagnostics::
  watch()` subscribed on a new host connection, so
  `Diagnostics::new(lab_conn).watch()` watched the host. It also named a
  removed address's interface through the host's `/sys/class/net`.
  - All of these now use a Route connection in the namespace the
    connection's own socket is in (`ioctl(SIOCGSKNS)`). If that ioctl is
    refused for lack of `CAP_NET_ADMIN`, they use the process's namespace
    only when the two namespaces' `SO_NETNS_COOKIE`s match.
  - `IssueStream` names interfaces from the link events it already
    receives.
  - `TcMessage::resolve_name` is documented as host-only.

  Root tests query ethtool by index inside a lab namespace; on master that
  gave `InterfaceNotFound { name: "ifindex 10" }`. They also watch a lab
  `Diagnostics` and expect the address removal there, named `w0`; on
  master nothing arrived. A unit test checks the cookie fallback.

- **nftables: diffs and applies were not generation-checked, and
  `apply_reconcile` retried deterministic failures (#482).** A diff took
  3 + 2N dumps with no generation check across them. An apply then
  committed against whatever the ruleset had become, so another `nft` run
  in between left the kernel not as declared, or failed with ENOENT. And
  `NftablesDiff::apply_reconcile` retried the same diff on EBUSY and
  EAGAIN, which in nf_tables are not transient: EBUSY is "object in use",
  module loads are replayed in the kernel, and writers serialize on the
  nfnl mutex.
  - A diff is now taken between two reads of the ruleset generation, and
    taken again if a commit landed in between. It records the generation
    in the new `NftablesDiff::generation`.
  - `apply` sends it as `NFNL_BATCH_GENID`, so the kernel refuses a stale
    batch with ERESTART (the new `Error::is_restart()`). After a set
    update commits in its own batch, the rest expects the next generation.
  - The new `NftablesConfig::apply_reconcile` diffs again on ERESTART.
    `facade::apply::nftables_in` uses it. The diff-level `apply_reconcile`
    no longer retries EBUSY or EAGAIN.
  - `Transaction::expect_generation` exposes the check.

  Root tests:
  - A diff overtaken by an `nft add table` is refused, and nothing of it
    lands; the config-level reconcile then converges. On master the stale
    diff applied.
  - One commit moves the generation by exactly one, and a set-growing
    two-batch apply lands.

- **A `Stack` dry run created the WireGuard links, committed the firewall
  and configured the tunnels (#501).** `apply_in_with` passed `ApplyOptions`
  to the network layer only. It always bootstrapped the WireGuard links
  first, and always applied the nftables and WireGuard layers. With
  `dry_run` it now touches nothing and returns the `StackDiff` in the
  report's new `dry_run` field; `is_noop()` and `change_count()` read it.
  The pre-flight diff also gets `purge_tables` now, which it dropped. And
  the WireGuard links are no longer bootstrapped twice. A root test dry
  runs a stack with a dummy link, an nftables table and a WireGuard
  device, then finds none of them; on master `wgd0` existed afterwards.
  Reusing the pre-flight diff for the apply, rather than diffing each
  layer again, is #519.

- **The rate and impairment recipes could not share a device with an
  ingress or clsact qdisc (#485).** `PerHostLimiter` always, and
  `PerPeerImpairer` with a default impairment, put the default class's leaf
  at `ffff:`. That is the ingress/clsact qdisc's handle, which
  `qdisc_alloc_handle` never hands out. With an ingress qdisc present the
  recipe failed with "Cannot move an existing qdisc to a different
  parent", and the other way round the ingress qdisc could not be added.
  That ruled out `RateLimiter`'s own ingress half and any BPF program on
  clsact. The leaf is now at `8000:`, a major the kernel's auto-allocation
  (`8001:`–`fffe:`) never reaches. `reconcile()` deletes a default leaf at
  any other handle and re-adds it there, so a tree from 0.30 converges.
  The new `TcHandle::is_reserved_major()` reports `ffff:`, and nlink
  refuses to add a qdisc there anywhere but at the ingress hook. Root
  tests apply both recipes next to an ingress and a clsact qdisc, and add
  an ingress qdisc after one; on master that failed as above. Another
  root test moves a 0.30 `ffff:` leaf with one reconcile, after which the
  next reconcile is a no-op.

- **nftables `reject()` in an `ip` or `ip6` table dropped silently, and a TCP
  reset had no protocol guard (#480).** `reject()` always sent
  `NFT_REJECT_ICMPX_UNREACH`. The `ip` and `ip6` reject expressions handle
  only ICMP and TCP-reset, so ICMPX fell to their `default:`, a plain
  drop, and clients hung until their timeout: the bug #205 set out to
  fix. An ICMPX reject in an `ip`/`ip6` rule is now sent as the
  family's ICMP code, with the mapping the kernel itself uses (port
  unreachable is 3 / 4). The diff renders it the same way, so a declared
  `reject()` converges.
  - `reject_with(NFT_REJECT_TCP_RST, _)` and the new `reject_tcp_reset()`
    prepend `meta l4proto tcp` unless the rule has it, as `nft` does.
    Without it, every non-TCP packet the rule matched was dropped.
  - The new `reject_icmp(code)` / `reject_icmpv6(code)` carry a `meta
    nfproto` guard, so an `inet` rule's ICMP code is not sent to IPv6
    packets.
  - The ICMPX codes are named (`NFT_REJECT_ICMPX_*`).

  Root traffic tests send UDP into `ip`, `ip6` and `inet` tables with a
  `reject()` rule and get "connection refused". On master the `ip` case
  timed out. They also check that a reset refuses a TCP connect across a
  veth while UDP to the same host still gets its port unreachable; on
  master the UDP was dropped. An echo test applies every reject form in
  the three families and asserts the diff is empty. `nft_reject_ipv4`,
  `_ipv6` and `_inet` join CI's strict module list.

- **A namespaced spawn could not run as another user (#502).** Every
  spawn path enters the namespace (and makes the `/etc/netns` mounts) in a
  `pre_exec` closure. std applies `CommandExt::uid`/`gid`/`groups` before
  any closure, so `spawn(ns, cmd.uid(1000))` ran `setns` unprivileged and
  failed with `EPERM`. The new `namespace::spawn_as` and
  `spawn_with_etc_as` take a `SpawnUser { uid, gid, groups }` and drop to
  it in nlink's own closure, after `setns` and the mounts, in std's order
  (`setgroups`, `setgid`, `setuid`). The other spawn functions now warn
  against `CommandExt::uid`. Root tests check uid, gid, groups and the
  netns inode of a child run as 1:1, check that the `uid()` route still
  fails with `EPERM`, and check that the `/etc` overlay applies before the
  drop. The full spawn builder is #521.

- **`Debug` printed private, preshared, cipher, SA and MACsec keys (#499,
  #567).** The WireGuard types (`WgDevice`, `WgPeer`, their builders,
  `DeclaredWgDevice`/`DeclaredWgPeer` and theirs, so `WireguardConfig` too),
  `OvpnKeydir` (and with it `OvpnKeyConfig`, `OvpnConfig` and the key
  messages), the XFRM algorithm specs and dumps (`XfrmAlgoAuth/Encr/Aead`,
  `XfrmAlgorithm*`) and `MacsecSaBuilder` all derived `Debug`. Any
  `?config` in a `tracing` field, any `dbg!`, or a panic message holding
  one printed every key byte. nlink-lab formats WireGuard plans with
  `{:?}` on every apply. Their `Debug` is now written by hand and shows
  each key as `<N bytes redacted>`. A unit test formats one of each with
  a marker byte and checks it never appears. On master `WgDevice` printed
  `private_key: Some([167, 167, …`. Zeroize-on-drop and key newtypes are
  left for #529's key type.

- **`get_link_by_name`/`get_link_by_index` dumped every link to find one,
  and never found an alternative name (#495).** Both called `get_links()`
  and searched the result. They sit behind `resolve_interface`, which
  about 116 name-taking methods use (`set_link_up(name)`,
  `add_address(name, …)`, `replace_qdisc(name, …)`, `wait_link_up`'s
  poll). So nlink-lab's deploys did thousands of full dumps, and each
  could fail with `DumpInterrupted` because of an unrelated link change.
  Each lookup is now one `RTM_GETLINK`, by `ifi_index` or by name.
  ENODEV means `None`. A name is sent as `IFLA_IFNAME`, which the kernel
  also matches against alternative names, or as `IFLA_ALT_IFNAME` when it
  is longer than 15 bytes. A unit test fetches `lo` both ways and gets
  `None` for absent names and indexes. A root test finds a dummy by a
  short and a 34-byte altname and brings it up by the long one; on master
  `alt0` was `None`.

- **stats: a counter that went backwards read as a 64-bit wrap, about
  1.8e19 bytes/s (#506).** `StatsSnapshot::rates` took any decrease for a
  wrap. A 64-bit wrap never happens in practice; a reset happens all the
  time in labs: a recreated link, a qdisc replaced by another kind, or a
  reused ifindex. Rates are now computed by the new stateless
  `LinkRates::between` and `TcRates::between`. They return `None`, and
  `rates()` leaves the object out for that interval, when a 64-bit counter
  went backwards, or when the link's name or the qdisc's/class's kind
  changed under the same key. The kernel's 32-bit drops, overlimits and
  requeues still count one wrap when bytes and packets moved forward.
  Unit tests cover a reset link and qdisc, a renamed link, a changed
  kind, and a 32-bit drop wrap. On master the reset link reported
  1.8446744073709548e19 B/s.

- **nl80211: 2484 MHz read as channel 15, and nothing turned a channel back
  into a frequency (#508).** `Interface::channel()` and
  `Frequency::channel()` computed `(f - 2407) / 5` across the 2.4 GHz band,
  which makes Japan's channel 14 (2484 MHz) 15, and they ignored 4.9 GHz,
  the lower 5 GHz channels, 6 GHz channel 2 and 60 GHz. Both now go
  through `freq_to_channel`, which mirrors the kernel's
  `ieee80211_freq_khz_to_channel`. The new `channel_to_freq(channel,
  WifiBand)` and `channel_to_freq_khz` mirror
  `ieee80211_channel_to_freq_khz`. `WifiBand` is `enum nl80211_band`,
  checked by the UAPI audit. `Interface::channel()` is `None`, not
  `Some(0)`, for a frequency in no band. Unit tests check channel 14, the
  kernel's values per band, and a round trip over every channel of
  2.4/5/6/60 GHz.

- **u32: port matches never matched a port, and `ht`/`link` named the
  wrong hash table (#492, #562).**
  - `match_src_port`/`match_dst_port` were next-header keys
    (`with_nexthdr`) with their value and mask in host order. On
    little-endian, `match_dst_port(443)` compared the first 16 bits with
    `0xBB01`. And with no linking `offset`, "next header" is the IP header
    itself. They are now tc's `match ip sport|dport`: bytes 20–21 and 22–23
    of an option-less IPv4 header.
  - `TcU32Key::with_nexthdr` packs big-endian like `pack_key*`.
  - New `match_nexthdr_src_port`/`match_nexthdr_dst_port` (tc's
    `match tcp|udp src|dst`) and `offset_at`/`offset_plus`/`eat` (tc's
    `offset at … mask … shift … [eat]`) build the two-level next-header
    form.
  - The parser takes tc's port and protocol masks
    (`match ip dport 80 0xffff`, `match ip protocol 6 0xff`), and
    `match tcp|udp src|dst` and `offset …` too.
  - `ht`/`link` were parsed as qdisc handles, so `2:` was `0x00020000`;
    u32 handles are `htid << 20 | bucket << 12 | node` (`0x00200000`).
    They now parse as u32 handles, and `U32Filter::handle(htid, bucket,
    node)` builds one.
  - The old test compared the parser's keys with the setter's, which
    were wrong the same way. The new tests:
    - unit tests pin the key bytes iproute2 writes;
    - a root test sends UDP through a `match_dst_port` filter on HTB and
      counts the class (on master, port 5001 never reached 1:10);
    - another builds the linked next-header form from tc's own lines;
    - a third installs five u32 lines through `tc` and through nlink's
      parser and compares `tc filter show`.

- **tc readback: a netem rate of 4 GB/s or more read as 4294967295, a
  netem replace kept a slot and ECN set by `tc`, `qopt` latency was in the
  wrong unit, and `is_ingress()`/`is_clsact()` were both true (#493).**
  - `netem_dump` puts `TCA_NETEM_RATE64` *before* `TCA_NETEM_RATE`, whose
    u32 then carries `~0U`. Parsed in order, the cap won. RATE64 now wins
    wherever it comes.
  - `NetemConfig` does not model ECN or a slot, so nothing was sent for
    them. A replace (`netem_change`) keeps whatever it is not sent, so ones
    set by `tc` survived every nlink replace, and `netem_matches` did not
    look at them. `write_options` now sends ECN 0 and a zero slot (the
    kernel's "none"), and the comparison treats a live ECN or slot as a
    difference. A delay distribution table cannot be cleared that way:
    `netem_change` keeps it and `netem_dump` never shows it. Only a delete
    and add resets one.
  - `tc_netem_qopt.latency`/`jitter` are psched ticks (64 ns), and nlink
    wrote and read them as µs. `LATENCY64`/`JITTER64` hid this on 4.15+.
    Below that, a delay was 15.6 times too short.
  - An `ingress` and a `clsact` qdisc both sit at parent `TC_H_INGRESS`,
    and both predicates compared the parent. They now compare the kind.
    Code that means "at the ingress hook" uses `parent().is_ingress()`,
    as the config diff and capture now do.

  Unit tests cover each item. A root test sets `slot 1ms 2ms ecn` with
  `tc`, replaces the qdisc through nlink with a 5 GB/s rate, and checks
  nlink's readback and `tc qdisc show`. On master, ECN survived the
  replace, and the other five tests failed as described.

- **tc stats: `requeues()` was always 0, and packet counts wrapped at 2^32
  (#489).** `tc_fill_qdisc`/`tc_fill_tclass` dump `TCA_STATS2` and then,
  through `gnet_stats_finish_copy`, the legacy `TCA_STATS` block as a
  compat copy. The copy has 32-bit packets and no requeues field. nlink
  parsed both, and the copy, arriving second, overwrote the real
  counters. The legacy block is now used only when there is no
  `TCA_STATS2`, and `TCA_STATS_RATE_EST64` is parsed. A unit test parses a
  dump in the kernel's order. On master it read `requeues() == 0` where
  the queue stats said 7.

- **An event stream kept a deleted namespace alive and idled forever
  (#504).** A socket holds a reference on its network namespace.
  `namespace::delete` unmounts the marker, but the namespace lives on for
  as long as a stream's socket does, with its interfaces, including the
  far ends of veths into it. And the stream got no event: the namespace is
  not destroyed, so there is no `RTM_DELNSID`. nlink-lab's `events
  --follow` held a lab's namespaces this way after the lab was destroyed.
  A socket opened through a namespace path (`namespace::connection_for`,
  `new_in_namespace_path`, `LabNamespace::connection`,
  `Connection::<KobjectUevent>::in_namespace`) now records the marker's
  device and inode. Its event streams check them once a second, and when
  the marker is gone or names another namespace, a stream yields the new
  `Error::NamespaceDeleted { path }` and ends. The resync wrappers pass
  that on and end too. A root test deletes one end of an `NsPair` under a
  live stream. The far veth end outlives the deletion, `NamespaceDeleted`
  arrives, and once the stream is dropped the far end goes. On master no
  error came within 5 s. Sockets opened from a file descriptor or a
  `/proc/<pid>` path are not watched; that needs the `Netns` handle
  (#520).

- **`NetdevLifecycle` could not take a resync stream, so its device set
  was only as good as a stream that never overflows (#510, item 3).** It
  required `Stream<Item = Result<NetworkEvent>>`. An overflow therefore
  lost whatever link events it dropped, a lost `DelLink` among them, and
  the device stayed in the join and its store for good. The docs said
  the store "cannot be missing devices", which was not true. And a device
  that existed before the join subscribed was never announced. The link
  side now also takes `ResyncedEvent<NetworkEvent>`, through the sealed
  `LinkSourceItem`. Each snapshot's links are `Added`, or `Changed` if
  known. When a snapshot ends, every device the join knew that the
  snapshot did not list is `Removed`. The `netdev-lifecycle` recipe and
  example feed it a link-only resync stream that opens with a snapshot.
  A unit test drives an initial snapshot, a live add, and a resync that
  drops two devices and adds one; it checks the events and the store. A
  root test checks that a device created before the join is in the store.

- **GENL: `command()` and family lookups read one datagram, so the next
  call read a stale ACK; family resolution had no timeout (#496).** A
  `doit` reply and its ACK are two datagrams: `genlmsg_reply` unicasts
  the reply, then `netlink_rcv_skb` sends the ACK.
  - `Connection<Generic>::command()` returned the first datagram that
    arrived. From the second call on, that was the previous call's ACK,
    returned as the result while the real reply waited for the call
    after.
  - `get_family` (`query_family`) read the socket directly. It took no
    request lock in mutex mode and raced the driver in dispatcher mode.
    It left the same ACK behind, so a second lookup reported
    `FamilyNotFound` for a family that exists.
  - `resolve_genl_family{,_with_groups}`, which every `new_async()` GENL
    connection and `#[genl_family]` type resolves through, left the ACK
    queued too, and could wait forever for a reply.

  All of them now read through the request's own ACK. `command()` and
  `get_family` go through the request session, so they lock in mutex
  mode and register with the driver in dispatcher mode. The resolvers
  run under the 30 s operation timeout. Unit tests send each request
  three times: on master, call 1 of `command()` returned no reply, lookup
  1 said `FamilyNotFound`, a dispatcher-mode lookup lost its reply to the
  driver, and a resolved socket still held the ACK.

- **Event streams: a large frame was lost and ended the stream, parse
  failures left no trace, and a request beside a mutex-mode stream hung
  (#505).**
  - Every receive read into a 32 KiB buffer with `MSG_TRUNC`. That
    consumed a larger datagram while measuring it. `recv_msg` then read
    the *next* datagram into the grown buffer, so the large one was lost
    without a word. `poll_recv`, under every event stream and
    `dump_stream`, returned `FrameTruncated` and the stream fused. Each
    receive now peeks the datagram's size first, as iproute2 does, and
    reads it whole. A datagram past the 1 MiB cap is still dropped. An
    event stream now reports that as an overrun (an `ENOBUFS` error, so a
    resync wrapper re-dumps) and keeps going. The dispatcher driver
    treats it the same way.
  - The rtnetlink event parser skipped malformed frames and unparseable
    messages silently. It still skips them, so one bad frame cannot end a
    subscription, but it now logs each at `debug`. An nftables event in an
    address family nlink does not know was reported as `inet`; it is
    dropped with a `debug` record instead.
  - In mutex mode an event stream holds the connection's request lock
    until it is dropped. A request on that connection meanwhile waited
    out the 30 s operation timeout. A dump with its own receive loop
    (nftables, conntrack) took the lock outside the timeout, so it waited
    forever. Both fail at once now with the new
    `Error::EventStreamActive`, including a request already queued when
    the stream claims the lock. The docs that said a borrowed stream
    leaves the connection "usable for queries" now say what is true:
    that holds in dispatcher mode only.

  Unit tests queue datagrams between two `NETLINK_USERSOCK` sockets, so
  no kernel subsystem has to produce a large frame. Before the fix,
  `recv_msg_from` returned the 64-byte datagram queued behind a 40 KiB
  one. Two more check that a request beside a live stream, and one queued
  behind its claim, fail within 2 s rather than time out.

- **Resync snapshots covered only part of what the stream subscribes to,
  and there was no initial snapshot (#503).**
  - `rtnetlink_snapshot` dumped links, addresses, routes and neighbours,
    while `subscribe_all` also joins qdiscs, rules, nexthops and MDB.
  - `nftables_snapshot` left out named objects and set elements, though
    the live stream reports both.

  At `ResyncEnd` the reflector replaces its store with the snapshot, so
  one overflow emptied a mirror of any of these, for good. And without an
  initial snapshot a fresh mirror held nothing until the first overflow.

  - The rtnetlink snapshot now dumps everything it can: links,
    addresses, nexthops (before the routes that use them), routes,
    rules, neighbours, qdiscs, classes, filters and bridge MDB.
    Network-namespace ids have no dump.
  - The nftables snapshot adds objects and set elements. It is taken
    between two reads of the ruleset generation (new
    `Connection<Nftables>::generation()`) and taken again if a commit
    landed in between.
  - `ResyncStream::initial_snapshot(bool)` begins the stream with the
    current state, marked by the new `ResyncMarker::InitialSyncStart` …
    `ResyncEnd`, which the reflector stages like a resync. The
    rtnetlink and nftables `*_with_resync` constructors turn it on.

  Root tests check that the initial rtnetlink snapshot includes a netem
  qdisc, a rule and a nexthop, and the nftables one a named counter and
  a set's two elements.

- **After an overflow, the resync stream replayed pre-overflow events on
  top of its snapshot (#464).** On ENOBUFS, `ResyncStream` took the
  snapshot at once. The kernel reports the overflow before it dequeues
  anything, so every frame queued before the overflow was still in the
  socket, and was delivered *after* `ResyncEnd`. A `NewLink` whose
  `DelLink` the overflow had dropped therefore came after a snapshot that
  correctly lacked the link, and a watch-cache kept it forever. The
  stream now drains the inner stream until it has nothing queued, then
  takes the snapshot. That also empties the socket, which the kernel
  requires before it delivers broadcasts again (`netlink_rcv_wake`). A
  root test gives a resync stream a 1 KiB buffer and a 300-link burst
  that starts with a link that is deleted again, then compares the
  mirrored link set with a fresh dump. Before the fix the mirror kept
  the deleted `t1`. A unit test pins the drain.

- **Dispatcher mode lost overflows, buffered without bound, and raced its
  own driver (#466).**
  - An ENOBUFS reached only the typed subscriber surface nothing reads,
    so a `with_dispatcher()` `events()` stream, and the resync wrappers
    built on it, never heard of an overflow.
  - The listener channels were unbounded. A slow consumer turned the
    kernel's bounded buffer, which would have raised ENOBUFS, into
    unbounded memory.
  - About 30 request paths took the request lock and read the socket
    themselves, racing the driver's `recv`: nftables, sockdiag,
    devlink, nl80211, audit, FIB lookup, connector. Beside a running
    driver their replies were stolen and they timed out.

  The fixes:
  - Event listeners now get a bounded channel (1024 datagrams). A
    listener that falls behind, or a kernel ENOBUFS, marks it overrun.
    The stream then drops what it had queued, which predates the loss,
    and yields ENOBUFS as a mutex-mode socket would, so
    `into_events_with_resync` re-dumps in dispatcher mode too.
  - Every one of those request paths goes through `RecvSession`. It
    serializes in mutex mode and registers the seq with the driver in
    dispatcher mode. The nftables batch registers all of its seqs and
    maps a failure back to its operation by seq.

  Root tests: a dispatcher consumer that does not read during 1400 link
  notifications must get ENOBUFS first; it got the first event instead.
  And 40 nftables add/list rounds on a dispatcher connection with a live
  driver on a multi-threaded runtime must complete; they timed out.

- **Multicast was recognised by `nlmsg_seq == 0`, so notifications caused
  by other processes were dropped, and a subscribed connection read its
  own as a reply (#465).** The kernel stamps a notification caused by a
  request with that request's seq and portid (`rtmsg_ifa(…, nlh,
  portid)`, `rtmsg_fib`). Only changes the kernel originates carry seq 0.
  Link changes do, via the netdev notifier, which is why tests that only
  added links never noticed. The effects:
  - A dispatcher-mode `events()` stream silently dropped every address
    or route change made by `ip`, `nft` or another process, as an
    "unregistered seq".
  - A connection subscribed to a group read the notification of its own
    request first. In mutex mode that made `add_address` fail with
    "kernel returned data on an ack-only request". In dispatcher mode the
    notification went to the request and was lost to `events()`.

  `NetlinkSocket` gains `recv_msg_from()`, which also says whether the
  datagram was a multicast copy (`nl_groups` in `msg_name`, the only place
  the kernel records it), plus `recv_unicast()`/`try_recv_unicast()`. The
  dispatcher routes on that tag. Every request/reply loop (rtnetlink,
  GENL, nftables, sockdiag, devlink, nl80211, audit, FIB lookup) skips
  multicast copies, as do batched dump receives (which now record
  `msg_name`). Root tests cover both cases. Before the fix, a
  dispatcher stream never saw an address `ip` added, and a subscribed
  mutex-mode `add_address` failed with "data on an ack-only request".

- **Namespace names were not validated, so `delete("")` detached
  `/var/run/netns` and every named namespace with it (#463).** Every
  by-name function joined the name onto `NETNS_RUN_DIR` unchecked, and
  `delete_path` lazily unmounts what it is given, as root:
  - `delete("")` detached `/var/run/netns` itself (a self-bind mount
    wherever `ip netns add` has run), and every namespace mounted under
    it;
  - `delete("..")` detached `/run`;
  - an absolute name replaced the base directory, so `delete("/some/file")`
    unlinked that file and `exists("/etc/passwd")` was `true`;
  - `create("a/b")` made nested directories.

  The new `namespace::validate_name` checks a name the way `ip netns`
  does: non-empty, no `/`, not `.` or `..`, at most 255 bytes, no NUL.
  `create`, `delete`, `open`, `enter`, `connection_for*`, the sysctl
  helpers, `spawn*` and `/etc/netns` binds all go through it, and
  `exists`/`is_namespace` answer `false` for an invalid name.
  `delete_path` refuses anything that is not a regular file before it
  unmounts. Unit tests cover every entry point with `""`, `.`, `..`,
  `a/b`, an absolute path, NUL and an overlong name, and a directory
  passed to `delete_path`. The destructive cases were not run against
  the old code on purpose; `exists("/etc/passwd")` showed the escape.

- **A dump torn by a concurrent change failed the caller, and left its
  remaining frames in the socket (#494).** The kernel marks a multi-part
  dump `NLM_F_DUMP_INTR` when the table changes under it. nlink returned
  `DumpInterrupted` on the first flagged frame and left the rest of the
  dump unread. No reconcile retried it: `NetworkConfig::apply_reconcile`
  diffed outside its retry loop, and every retry predicate was "busy or
  try again". So any concurrent change in the namespace aborted a whole
  reconcile: a routing daemon installing routes, DAD finishing, a link
  flapping. Now the rtnetlink dumps (`send_dump`, both modes) and the
  nftables dumps read an interrupted dump to its `NLMSG_DONE`, which can
  carry the flag itself (`dump_frame::ends_dump`), then send it again,
  up to 10 times. The reconcile loops of `NetworkConfig`,
  `NftablesDiff` and `WireguardConfig` also retry `is_dump_interrupted()`,
  and `NetworkConfig`'s retries its diff. A root test dumps 400 links 60
  times on a multi-threaded runtime while another connection adds and
  deletes links. Before the fix it failed with `DumpInterrupted`; it has
  now passed 25 runs in a row.

- **sysctl: an interface name with a dot could not be addressed, a missing
  key was `InvalidMessage`, and I/O errors lost the key (#477).** Every
  `.` in a key became a path separator, so `net.ipv4.conf.eth0.100.rp_filter`
  pointed nowhere. The `/`-separated form that `sysctl(8)` accepts for
  this was converted too. A key is now taken verbatim when it contains
  `/`, and `sysctl::ipv4_conf_key(dev, setting)` / `ipv6_conf_key` build
  that form. Every failure is the new `Error::Sysctl { key, source }`:
  `is_not_found()` holds for a missing key and `is_permission_denied()`
  for a refused write, and the message names the key. A root test sets
  `rp_filter` on a dummy named `d0.100` and reads a missing key. Before
  the fix the first gave `InvalidMessage("sysctl key not found:
  net/ipv4/conf/d0.100/rp_filter")`.

- **One allowed-IP prefix on two WireGuard peers never converged (#498).**
  The kernel keeps a device's allowed IPs in one trie, so a prefix belongs
  to at most one peer. Writing it on peer B silently takes it from peer A.
  The diff compared each peer on its own, so a hub that declared every
  spoke with the tunnel /24 rewrote every peer on every apply, and only
  the last one written routed the prefix. The new
  `WireguardConfig::validate()`, run by `diff` and so by `apply`, refuses
  such a prefix before anything is written. It names the masked prefix and
  both peers. It also refuses a device declared twice, which was diffed
  twice in the same way. A root test applies a two-peer /24 hub. Before
  the fix the apply wrote both peers; now it is refused with nothing
  written.

- **A bridge created with an MTU gave it up to its ports (#474).** The
  kernel treats a bridge MTU as the user's (`BROPT_MTU_SET_BY_USER`) only
  after `br_change_mtu`, an `RTM_SETLINK` that changes it. The `IFLA_MTU`
  a bridge is created with does not count. So a port joining
  (`br_add_if`) or a port's MTU change (`NETDEV_CHANGEMTU`) moved the
  bridge to its smallest port's MTU. #407 re-asserted a declared bridge's
  MTU only when its port set changed in the same apply. That missed
  imperative bridges, port MTU changes, and creation itself.
  `Connection::add_link` now pins the MTU of a `BridgeLink` created with
  one, through the new provided `LinkConfig::pinned_mtu`. For bridges
  that already exist, `Connection::pin_bridge_mtu{,_by_index}` sets the
  MTU through a neighbouring value when it is already right, since a
  no-op set does not count. The declarative apply also re-asserts a
  bridge's MTU when a port's MTU changes. Root tests: an imperative
  bridge created at 9000 with a 1500 port; an unpinned bridge pinned
  with `pin_bridge_mtu`; and an echo case where a port drops from 9000
  to 1500. Before the fix the first ended at 1500 and the echo case left
  `~ link br0 (mtu=9000)` after the apply.

- **A partial or duplicate link declaration released the link from its
  master, and two declarations flipped it on every apply (#462).** A
  declaration's `master: None` meant "no master", unlike MTU and MAC,
  where unset means "don't care". So `.link("eth0", |l| l.mtu(9000))`
  released eth0 from a bridge someone else manages. `NetworkConfig::link`
  always pushed, so a link declared twice was diffed twice. Take a VLAN
  declared once by kind and once with `.master("red")`: each apply undid
  the last, and every VRF enslave or release flushed the link's IPv6
  addresses and routes.

  The master is now a `MasterSpec`: `Unmanaged` (the default), `None`
  (set with `nomaster()`), or `Name`. `link()` for a name already
  declared updates that declaration. `NetworkConfig::validate()` refuses
  a link, a route (same destination, table and metric) or a qdisc (same
  device and parent) declared twice. It runs before every diff and on
  JSON input. In JSON, an absent `master` is unmanaged, `null` is no
  master, and a string names one. Echo cases for an MTU-only declaration
  of a bridge port, a VRF member declared in two parts, and `nomaster()`
  check the result through `ip -j`. Before the fix the port was released
  and the two-part declaration never converged.

- **Changing an IPv6 address's prefix length removed the address (purge)
  or never converged (#461).** The address diff keys on `(dev, address,
  prefix)`, but the kernel knows an IPv6 address by the address alone.
  The add of `fd00:1::1/56` over `/64` was `EEXIST`, which the apply
  swallowed as "already present". With purge, the old `/64` was then
  deleted after it, leaving no global address at all. Without purge, the
  add was listed on every diff while the apply reported no change. A
  re-prefixed IPv6 address is now listed as removed at the old prefix
  and added at the new one, and the apply deletes the old prefix right
  before the add, purge or not. An `EEXIST` on an add counts as "already
  present" only if re-reading the device finds the declared prefix. IPv4
  needs none of this: the kernel keys IPv4 addresses on address and
  mask. Echo cases for `/64` → `/56`, with and without purge, check
  through `ip -j` that one address is left at `/56` and that a route
  through it stays. Before the fix both cases listed `+ address
  fd00:61::1/56` forever.

- **Route purge could not delete a `proto static` route or a
  blackhole/unreachable/prohibit route, and reported it deleted (#467).**
  The purge rebuilt each route through the add builder. Its defaults,
  unicast and `proto boot`, went into the delete, and the kernel matches
  type and protocol whenever they are set. So the delete missed with
  ESRCH, was counted "already absent", and the next diff listed the
  route again, forever. Deletes are now sent the way `ip route del` sends
  them: type 0, scope `NOWHERE`, protocol 0, plus metric, device,
  gateway and table. Purge is limited to IPv4/IPv6 routes.
- **Changing a declared route's metric added a second route and kept the
  old one, even with purge (#468).** The add is a replace, and
  `NLM_F_REPLACE` only replaces a route of the same metric (IPv4 matches
  tos and priority, IPv6 the metric). So metric 100 → 200 left both
  installed, with the old one winning. The purge then spared the old
  route, because it keyed "is it declared" on `(dst, prefix, table)`.
  Now, with or without purge, a route that differs from a declared one
  only in its metric is removed as superseded. The purge compares the
  full identity: gateway, device, metric and type. So an undeclared
  static route that shares a declared destination is purged too. Root
  tests cover these: metric 100 → 200 in both families, with and
  without purge, must leave exactly one route at 200 per `ip -j route`.
  A purge must also remove hand-added `proto static`, blackhole,
  unreachable and prohibit routes, IPv4 and IPv6. Before the fix both
  routes stayed, and the purge's diff never emptied.

- **`RateLimiter` ingress shaping dropped every ingress packet (#458).**
  The redirect to the IFB was a mirred *ingress* redirect. That hands the
  packet to the IFB's receive path, so it never reaches the IFB's
  transmit and its root HTB. The IFB is `IFF_NOARP`, so ARP died there
  and nothing got through: the interface was blackholed, live since
  0.26.0. The filter was also a hand-rolled u32 at priority 1, in the
  operator band, and `reconcile()` checked only that *some* filter
  existed.

  The redirect is now a matchall with `MirredAction::redirect_by_index`
  (an egress redirect, `TC_ACT_STOLEN`) at the first recipe-band
  priority. `reconcile()` reads each ingress filter's mirred parameters.
  It deletes and replaces anything else that redirects to the IFB,
  including the legacy u32 ingress redirect.
  `MirredAction::ingress_redirect_by_index` now says it is not for IFB
  shaping.

  A root traffic test applies an ingress limiter across a namespace
  pair. 20 of 20 datagrams arrive and the IFB's HTB counts them; before
  the fix, 0 of 20 arrived. The test then installs the legacy u32 filter
  with `tc` and checks that `reconcile()` restores delivery and that a
  second reconcile changes nothing. CI now requires `cls_matchall`.

- **`replace_qdisc` failed with `EINVAL` in three common cases, and
  `add_qdisc` quietly changed a live qdisc (#486).** All of these checks
  were made on Linux 6.12.
  - **An fq_codel with `flows`:** `fq_codel_change` refuses the attribute
    on a live qdisc even when the value is unchanged, so replacing it
    with any other knob changed was `EINVAL`.
  - **sfq and htb:** neither has a change operation.
  - **A different kind at the live qdisc's own handle**, such as `prio`
    over a recipe's HTB at `1:`: the kernel answered "Invalid qdisc name".

  The fallbacks existed only in the declarative applier. `replace_qdisc`
  now looks at the slot. A same kind is changed in place, with the
  options in change mode. A kind that cannot change, a different
  `flows`, or a kind change at a fixed handle gets a new qdisc grafted
  over the live one, through a free temporary handle, so the slot is
  never bare. A same-kind qdisc that has classes is refused rather than
  emptied. `change_qdisc` sends change mode too.

  `add_qdisc` now sends `NLM_F_EXCL`, as `tc qdisc add` does. An add
  over a live qdisc of the same kind, or at a handle in use, is
  `EEXIST`. The declarative applier's sfq fallback is gone, and so is
  `apply_netem`'s ENOENT fallback, which could never run.

  Two root tests cover this:
  - fq_codel with `flows` replaced twice, and a different `flows`;
  - sfq, then htb `1:` → prio `1:`, then EEXIST on an add over a live
    qdisc, and an htb with a class whose same-kind replace is refused
    and keeps the class.

  Before the fix they failed with
  `Invalid argument: Change operation not supported by specified qdisc`.

- **A prio qdisc with fewer than three bands always failed with `EINVAL`
  (#487).** `PrioConfig::bands(n)` kept the three-band default priomap,
  which names band 2, and `prio_tune` refuses a priomap entry past the
  last band. So `bands(2)`, imperative or declarative, could never be
  installed. The default map is now fitted to fewer bands: each entry is
  capped at the last band, through `PrioConfig::effective_priomap()`,
  which the diff compares too. A custom map that names a missing band, or
  `bands` outside 2..=16, is refused with a message that says so. The
  declarative form gains `QdiscBuilder::priomap()`. The echo cases
  `prio-bands-2` and a custom priomap converge. Before the fix the first
  one failed with `add_qdisc: Invalid argument`.

- **fq_codel ECN could not be turned off, and pie/fq_pie flags could not
  be turned off by a replace (#488).** `FqCodelConfig` wrote
  `TCA_FQ_CODEL_ECN` only when true. The kernel turns ECN on when it creates
  an fq_codel, and keeps it when a change does not carry the attribute, so
  ECN was always on. The declarative docs said the default was off, and a
  declared `ecn(false)` sat in the replace list on every apply. pie's and
  fq_pie's `ecn`, `bytemode` and `dq_rate_estimator` had the same shape:
  once on, a replace could never turn them off. fq_codel's ECN is now
  `Option<bool>`, and `Some(false)` writes 0. The pie/fq_pie flags are
  written every time. Two echo cases, `ecn(false)` and on → off, are
  checked through `tc -j`. A root test replaces a pie and an fq_pie with
  every flag on by ones with every flag off. Each failed before the fix:
  pie's dump still said `"ecn":true,"bytemode":true`.

- **A refused nftables batch said one errno and a bare byte offset (#481).**
  `send_batch` returned on the first error as `kernel error: Device or
  resource busy (os error 16) (errno 16) (at request offset 36)`, whatever
  failed. It did not say which operation that was, the offset was into a
  message the caller never saw, the errno was printed twice, and every
  failure after the first was discarded, although `nfnetlink` reports each
  one. A refused batch is now `Error::NftBatch { failures }`: one
  `NftBatchFailure` per refused operation, in batch order. Each names
  the operation as `op #1 add rule ip t/nochain [key]`. It also gives
  the errno, the ext-ack text, and the attribute or expression the
  offset points at, e.g. `expression #4 (log)`. Where nlink can tell,
  it adds a hint, e.g. "is its module available?" on an unknown
  expression, or "something still uses it" on a refused delete. The
  `is_*` predicates answer for the first failure, so retry loops keep
  working. Kernel errors print their errno once (`Device or resource
  busy (errno 16)`). A root test commits a batch with a rule for a
  missing chain and a delete of a set a rule uses, and checks that both
  are named and that the table the batch also added was not committed.
  Before the fix the error was `No such file or directory (os error 2)
  (errno 2) (at request offset 28)`.

- **Extended-ack: TLVs read at the wrong place, missing attributes and
  policies ignored, warnings on success dropped (#507).** The error's
  TLVs were read at a fixed offset, which is right only when the kernel
  caps the echoed request; with `set_cap_ack(false)` the request's own
  bytes were parsed as ext-ack. `NLMSGERR_ATTR_MISS_TYPE`/`MISS_NEST`
  and `POLICY` were ignored, so a generic netlink family's missing
  attribute — which comes with no message — was a bare `EINVAL`. And a
  successful ACK's warning (`sch_htb: quantum of class 10002 is big.
  Consider r2q change.`, which `tc(8)` prints) was dropped. The TLVs are
  now found by the header's `NLM_F_ACK_TLVS`/`NLM_F_CAPPED`; a missing
  attribute and the policy's bounds are part of the error text; and an
  ACK's warning is logged as a `tracing` WARN. Unit tests cover capped,
  uncapped, flagless, missing-attribute, policy and warning payloads; a
  root run of the tc tests now logs the HTB quantum warnings it used to
  swallow.

- **A rule added by hand to a declared table made every apply fail with
  `EBUSY` (#459).** The rule planner leaves rules nlink did not write
  alone, but the diff deleted every chain, set, flowtable and object the
  config did not declare — including what those rules use. An inline set
  (`tcp dport { 4001, 4002 }`) is an anonymous set `__set0` that `nft`
  never lists and the kernel frees with its rule; a `jump dbg` holds chain
  `dbg`; `counter name x` holds `x`. Each delete was refused, the batch
  with it, on every apply until someone removed the rule by hand.

  Anonymous sets are no longer read into the diff at all. An undeclared
  chain, set, flowtable or object that a staying rule uses is left in
  place and listed in the new `NftablesDiff::kept_in_use` (shown as
  `! … kept` in the rendered diff; not a change, so `is_empty()` ignores
  it). An undeclared chain nothing uses is still deleted. Leaving
  undeclared items alone altogether (an owned/shared table mode) belongs
  to #527. A root test adds the three rules with `nft` and checks the
  diff keeps what they use and applies cleanly; before the fix it
  scheduled `__set0`, `dbg` and the counter for deletion. The CI image
  now installs `nftables` for it.

- **Removing a set, named object or chain that a rule used failed with
  `EBUSY` on every apply (#460).** `NftablesDiff::apply` sent set, object
  and chain deletes before the rule replaces, but the kernel releases what
  a rule uses only when it processes the message that deletes or replaces
  that rule. So renaming a named counter or set, dropping a chain whose
  rule used a counter, or retargeting a jump away from a chain the config
  drops each aborted the batch: `Device or resource busy (at request
  offset 28)`, every time, with the firewall stuck on the old ruleset. The
  rules of a deleted chain were not deleted explicitly either: they went
  with DELCHAIN, after the deletes of what they used.

  The batch now runs in four phases. First release: rule deletes,
  including every rule of a chain being deleted, then element removes,
  then deletes of sets and objects recreated under the same name. Then
  every add, then the rule inserts and replaces, and last the deletes of
  sets, objects, chains, flowtables and tables that nothing uses any more.
  A diff that drops a chain now lists that chain's rules in
  `rules_to_delete`. A root test runs all four edits as A→B transitions;
  each failed with `EBUSY` before the fix.

- **A declared chain policy change failed with `EEXIST` (#456).** #200
  (0.25) made the nftables diff report a chain whose policy drifted
  (`chains_to_modify`), but `NftablesDiff::apply` sent it through
  `Transaction::add_chain`, which always sets `NLM_F_EXCL`, and
  `nf_tables_newchain` refuses that for an existing chain. So flipping a
  declared firewall from `policy(Drop)` to `policy(Accept)` showed in the
  diff and aborted the whole batch on apply. The comment there said the
  kernel would treat the message as an update; it does only without
  `NLM_F_EXCL`. No test applied a `chains_to_modify` entry, so nobody saw
  it. The update now goes as `NFT_MSG_NEWCHAIN` with `NLM_F_CREATE` only,
  and the chain keeps its rules. A root test flips a live chain's policy,
  checks a second diff is empty and that the chain's rule kept its
  handle; sending it the old way fails the test with `EEXIST`.

  Not fixed: the kernel also refuses to change a live base chain's hook,
  priority or type, and the diff reports those as `chains_to_modify` too.
  Converging them needs the chain deleted and recreated with its rules
  moved, as sets got in #377.

- **CI could pass without running the tests that need 22 kernel modules
  (#600).** The integration tests gate on modules such as `sch_sfq`,
  `sch_tbf`, `bonding`, `vxlan`, `nft_nat` and `netkit`. The workflow's
  guard step and `NLINK_TEST_STRICT_MODULES` named none of them, so on a
  runner without one, its tests skipped and reported `ok`. Among them was
  the qdisc transition test from #599. All 22, plus `vrf`, which was
  only in the guard step, are in both lists now. A local root run with
  the full strict list passes all 548 tests.

- **A declared fq_codel `flows` change never reached the kernel (#596).**
  The diff skipped `flows` because a change could not act on it (#361),
  and the declarative replace stripped it. Since #486, `replace_qdisc`
  recreates an fq_codel whose live table is a different size, so the diff
  now compares `flows`, and the apply sends it. A `flows` change replaces
  the qdisc, which drops its queue and resets its statistics, as `tc
  qdisc replace` does.

  That recreate path also refused to replace a busy fq_codel or sfq.
  Their `walk` reports every flow with packets queued as a class, and a
  same-kind recreate refuses to drop classes, so as not to take an HTB
  tree down with it. A `flows` change, or any change to an sfq (which can
  only be recreated), failed with "would delete its N class(es)" whenever
  traffic was queued. Those two kinds are exempt now. A root test queues a
  burst behind an 8 kbit HTB class and changes both leaves under it; the
  transition test reads `flows` back with `tc`.

- **A sub-second sfq `perturb` turned perturbation off (#597).**
  `QdiscBuilder::perturb(Duration)` stored whole seconds by truncation.
  Since sfq reads a period of 0 as "never rehash", 500 ms installed no
  perturbation at all, and the diff converged on that. A fraction now
  rounds up, as WireGuard's keepalive does since #529: 500 ms installs
  1 s, and 1500 ms installs 2 s. `Duration::ZERO` is still off. A period
  past `i32::MAX` seconds, the kernel field's range, is a `build()` error
  from the builder and a `validate()` error from JSON, where it used to
  saturate silently.

- **Changing a live WireGuard peer's keepalive to under a second still
  sent 0 (#602).** #529 rounded a sub-second `persistent_keepalive` up to
  1 s on the path that adds a peer. The path that updates one still
  truncated, so a change to 500 ms turned keepalive off. The diff
  compared against the rounded value, so it was never empty again. The
  update now rounds the same way. So does the JSON diff, which printed
  0. A root transition test changes a peer from 25 s to 500 ms and reads
  1 back with `wg`.

- **A conntrack timeout under one second expired the entry at once
  (#603).** `ConntrackBuilder::timeout(Duration)` sent `CTA_TIMEOUT` as
  whole seconds by truncation. The kernel expires an entry whose timeout
  is 0 immediately, so `timeout(Duration::from_millis(500))` added an
  entry that was gone before the next dump, with no error. A fraction now
  rounds up, as sfq's `perturb` (#597) and WireGuard's keepalive (#529,
  #602) do. A root test adds a 500 ms UDP entry and finds it in the dump.

- **Interface names, VLAN ids and NaN percentages got past nlink's checks
  (#598).** Each failed late, after earlier links were created, or
  changed something silently:
  - **Interface names.** `util::ifname::validate`, which `add_link`
    calls, now matches the kernel's `dev_valid_name` byte for byte. It
    refuses `.`, `..` and `:`, and every byte the kernel's `isspace`
    takes, 0xA0 included. So `à` (UTF-8 `C3 A0`) is refused. A Unicode
    space with no such byte, such as U+2003, is now accepted, as the
    kernel and `ip link` accept it. All of this was checked live on 6.12.
  - **`NetworkConfig::validate()`** checks every declared link name and
    veth/netkit peer name. Before, a bad name failed mid-apply.
  - **VLAN ids past 4094** fail `validate()`, and `VlanLink` refuses them
    before sending, instead of the kernel's `ERANGE`.
  - **Netem percentages** (the probabilities, the correlations and the
    loss-model values) fail `validate()` when they are NaN or outside
    `0..=100`. A JSON or YAML document can carry those values.
  - **`Percent::new(f64::NAN)` is 0 %.** `clamp` used to keep NaN, which
    wrote as 0 % but compared unequal to itself, so the declaration did
    too.
  - **A reversed `BridgeVlanTunnelBuilder` range** (`range(end)` below
    the start) is an error. It underflowed a `u16`: a panic in a debug
    build, a wrapped tunnel id in a release one.

  The `boundaries` transition test no longer leaves these out.
  `ext_ack_survives_a_request_long_enough_to_matter` now provokes its
  kernel error with a VLAN on loopback, since VLAN id 4095 no longer
  reaches the kernel.

- **`purge_address_devs` was dropped by the reconcile loop and by `Stack`
  (#601).** `ApplyOptions::purge_address_devs` (#470) took effect only
  through `apply_with_options`. `NetworkConfig::apply_reconcile_with_options`
  and `Stack`'s pre-flight and dry-run diff built their `DiffOptions` by
  hand and left it out. So a stray address on a listed, undeclared link
  stayed, and a dry run did not show its removal. All three paths now go
  through the new `ApplyOptions::diff_options()`, so a future purge
  option cannot be dropped the same way. A root test runs a `Stack` dry
  run and a reconcile with the option set.

- **`set_wiphy_netns` never moved the wiphy (#604).** It and
  `set_wiphy_netns_pid` sent `NL80211_CMD_SET_WIPHY` (2) with the
  namespace attributes. `nl80211_set_wiphy` does not read those, so as
  the kernel source reads, the request was acked and the wiphy stayed
  where it was. Both now send `NL80211_CMD_SET_WIPHY_NETNS` (49), as
  `iw phy <phy> set netns` does. A unit test pins the command and
  attributes against the header. This is **unverified on a live kernel**:
  neither the test kernel nor CI has a Wi-Fi stack or `mac80211_hwsim`.

  Also, the rustdoc for `Connection::new_in_namespace(RawFd)` sat on
  `new_in_namespace_fd`, so the `RawFd` constructor had none. Each now
  has its own.

### Added

- **Every link builder can set master, up, alias and namespace as it
  creates the link (#517).** `LinkCreateExt` (implemented for every
  `LinkConfig`) adds `.master()`, `.up()`, `.alias()` and
  `.netns(impl AsFd)`. `add_link` sends `IFLA_MASTER`, `IFF_UP` and
  `IFLA_NET_NS_FD` in the one request, so there are no follow-up
  `set_link_master`/`set_link_up` round trips. A link created in another
  namespace is never in the host's one first, and its master is looked up
  where it lands.
  - The alias is set right after the create, in the link's namespace,
    because the kernel ignores `IFLA_IFALIAS` on a create.
  - A veth peer cannot be created up: the kernel configures it before the
    pair is linked (`ENOTCONN`).

- **Waiting for a link, and for IPv6 duplicate address detection (#524).**
  - `Connection::wait_link(iface, LinkCond, timeout)` waits for
    `AdminUp`, `Running`, `OperUp` or `Carrier` and returns the link.
    `wait_link_up` is `wait_link(.., AdminUp, ..)`. It waits for `IFF_UP`,
    which `set_link_up` sets before it returns, and its doc no longer
    claims it waits for the operstate.
  - `Connection::wait_addresses_settled(iface_or_all, timeout)` waits
    until no IPv6 address is tentative. It fails with the new
    `Error::DadFailed { addresses }` (`is_dad_failed()`) when DAD finds an
    address in use.
  - New: `AddressMessage::{is_dad_failed, is_optimistic}`.

- **Declarative configs compare, say when they are empty, and the diffs
  have JSON Schemas (#531).**
  - `NetworkConfig`, `NftablesConfig` and `WireguardConfig` and the
    `Declared*` types inside them derive `PartialEq`. Every type but those
    holding netem's `f64` loss percentage also derives `Eq`, and so do
    `Rule` and `Expr`. Compare a plan by value instead of by its `Debug`
    text, which printed WireGuard keys.
  - `NetworkConfig::is_empty()` and `WireguardConfig::is_empty()` join
    `NftablesConfig`'s.
  - Under `schemars`, `ConfigDiff`, `NftablesDiff` and
    `WireguardConfigDiff` derive `JsonSchema` (with every type they
    reach) and have `json_schema()` / `json_schema_value()` (draft 7, like
    `NetworkConfig`'s). A test pins each diff's top-level keys, so a
    change to its JSON shape is deliberate and shows in its schema.

- **`genl::wireguard::PrivateKey`** (#529): a private key, clamped, that
  reads and writes the base64 `wg genkey` prints and never appears in
  `Debug`. With the new `wireguard-keys` feature, `PrivateKey::generate()`
  and `.public_key()` do what `wg genkey` and `wg pubkey` do (X25519 via
  `x25519-dalek`), so a consumer no longer needs a crypto crate of its own
  for key pairs. Pass a key where a raw one is taken with `.into()`.

- **`RateLimiter::{remove_egress, remove_ingress}`, `LinkMessage::alias()`
  and `Connection::set_link_alias{,_by_index}`** (#490).

- **`Transaction::{update_table, update_flowtable, del_flowtable_devices}`,
  `NftablesDiff::{tables_refused, flowtables_to_update}` and
  `FlowtableUpdate`** (#479).

- **`Hook::number(family)`, `ChainInfo::devices`, and
  `Rule::{match_iif_not, match_oif_not, match_iif_prefix,
  match_oif_prefix}`** (#484).

- **`ConfigDiff::links_missing`** (#475): declared links that do not
  exist and that nothing in the apply creates.

- **`ConfigDiff::routes_refused` and `RouteConflict`** (#469): declared
  routes the apply will not install over a route the config does not
  own.

- **`DiffOptions::purge_address_devs` and
  `ApplyOptions::with_purge_address_devs`** (#470): interfaces to purge
  addresses from that the config no longer declares.

- **`Connection::lookup_route(dest)`**: the kernel's route for a
  destination, `ip route get` semantics (#509).

- **`MessageBuilder::oversized_nest()`** (#500).

- **`NftablesConfig::apply_reconcile`, `NftablesDiff::generation`,
  `Transaction::expect_generation`, `Error::is_restart()`,
  `NFNL_BATCH_GENID`** (#482).

- **`TcHandle::is_reserved_major()`** (#485).

- **`Rule::{reject_tcp_reset, reject_icmp, reject_icmpv6}`** and
  `NFT_REJECT_ICMPX_{NO_ROUTE, PORT_UNREACH, HOST_UNREACH,
  ADMIN_PROHIBITED}` (#480).

- **`namespace::{spawn_as, spawn_with_etc_as, SpawnUser}`** (#502).

- **`LinkRates::between`, `TcRates::between`**: rates from two samples the
  caller keeps (#506).

- **`nl80211::{WifiBand, freq_to_channel, channel_to_freq,
  channel_to_freq_khz}`** (#508).

- **`U32Filter::{handle, match_nexthdr_src_port, match_nexthdr_dst_port,
  offset_at, offset_plus, eat}`** and `u32::pack_key16_nexthdr` (#492).

- **`Error::NamespaceDeleted` and `Error::is_namespace_deleted()`** (#504).

- **`netdev::LinkSourceItem`**: what `NetdevLifecycle` takes from its
  link source, `NetworkEvent` or `ResyncedEvent<NetworkEvent>` (#510).

- **`Error::EventStreamActive` and `Error::is_event_stream_active()`**
  (#505).

- **`ResyncMarker::InitialSyncStart`, `ResyncStream::initial_snapshot`,
  `ResyncedEvent::is_initial_sync_start`, `Connection<Nftables>::generation`**
  (#503).

- **`NetlinkSocket::{recv_msg_from, recv_unicast, try_recv_unicast}`**
  (#465).

- **`namespace::validate_name`** (#463).

- **`Error::Sysctl`, `sysctl::{ipv4_conf_key, ipv6_conf_key}`** (#477).

- **`WireguardConfig::validate()`** (#498).

- **`Connection::pin_bridge_mtu{,_by_index}` and the provided
  `LinkConfig::pinned_mtu`** (#474).

- **`NetworkConfig::validate()`, `LinkBuilder::nomaster()`, `MasterSpec`,
  `DeclaredLink::master_spec()`** (#462).

- **`QdiscConfig::{in_place, write_change_options}` and `InPlace`**
  (#486). These are provided methods, so existing implementations keep
  compiling. They tell `replace_qdisc` how a live qdisc of a kind takes a
  change.

- **`Error::NftBatch` and `NftBatchFailure`** — a refused nftables batch,
  one entry per refused operation (#481).

- **`NlMsgError::{ext_ack, ext_ack_attrs, to_error}`** read the
  extended-ack TLVs where the header's flags say they are, and
  `ParsedExtAck::{missing_type, missing_nest, policy, describe,
  is_empty}` (#507). `NLM_F_CAPPED` and `NLM_F_ACK_TLVS` are exported.

- **`NftablesDiff::kept_in_use` and `KeptInUse`**: what the diff would
  delete but leaves because a rule nlink does not manage uses it (#459).

- **`Transaction::update_chain`**: `nft add chain` semantics. It changes
  an existing chain (its policy) in place, or creates it.
  `Transaction::add_chain` stays a create that fails if the chain
  exists.

## [0.30.0] - 2026-10-09

> **The ipset release, and every declarative layer converges.**
>
> nftables gains what ipset users need: lookups by any packet field and
> `!= @set`, interval sets (prefixes and ranges), concatenated keys, set
> timeouts and rules that fill sets (`dynset`), maps and verdict maps, and
> named counters, quotas and limits with object maps. Each is imperative and
> declarative, and each was tested on traffic through a namespace. The
> [ipset → nftables](docs/recipes/ipset-to-nftables.md) recipe maps one onto
> the other.
>
> To make room, the public nftables types are reshaped once. This is a
> breaking change, but a mechanical one:
> - the growing `Expr` variants carry payload structs;
> - `RuleExpr` variants, `SetInfo`, `Table` and `Flowtable` are
>   `#[non_exhaustive]`;
> - `SetElement` has private fields, and the element calls take the `Set`;
> - set flags are `SetFlags`;
> - `RuleInfo::comment` splits into `key` and `comment_text`;
> - the `NftablesDiff` collections are typed.
>
> Every declarative layer was then checked by applying twice and asserting
> the second apply does nothing. That found 33 bugs outside nftables
> (#398–#418, #424–#428, #431–#433, #436–#439, #447) — TBF never converged at most rates, bond
> ports could not be applied, WireGuard keys were rewritten on every run, a
> changed VNI or VLAN id never reached the kernel, a link recreate could
> destroy FDB and neighbour state, flower filters installed as match-alls,
> among others — and a dozen inside it (#374–#377, #387–#390, #395, #396). Several runtime
> behaviours change; read
> [`docs/migration_guide/0.29.0-to-0.30.0.md`](docs/migration_guide/0.29.0-to-0.30.0.md).

### Added

- **`FlowerFilter::actions(ActionList)` (#450).** A flower filter could only
  jump chains: it wrote `TCA_FLOWER_ACT` for `goto_chain` alone, so tc(8)'s
  `flower … action drop` or `… action mirred …` had no equivalent. On an
  ingress or clsact hook, where a classid means nothing, a flower filter
  could not act at all. The action list shares the nest with `goto_chain`,
  which runs after it, as matchall's does (#313). `parse_params` still does
  not model `action` tokens, and now says so and names the builder method.

- **Interval sets: ranges and prefixes (ipset `hash:net`).**
  `Set::interval()` / `DeclaredSetBuilder::interval()`, and
  `SetElement::{range, ipv4_prefix, ipv6_prefix, ipv4_range, ipv6_range,
  port_range}`. A range `[a, b]` is written the way the kernel's rbtree
  stores it: `a`, then `b + 1` flagged `NFT_SET_ELEM_INTERVAL_END` (no end
  element for a range that runs to the maximum value); a single key in an
  interval set is the range `[k, k]`. `list_set_elements` pairs an interval
  set's wire elements back into ranges, in whatever order the kernel dumps
  them. The declarative diff compares ranges merged where they overlap or
  touch — so `10.0.0.0/25` + `10.0.0.128/25` is one `/24` and converges —
  and changes one range by removing and adding only that range. Host-order
  keys (mark, ifindex) on interval sets are refused rather than ordered
  wrongly. `nlink-nft` sets take `flags interval`, and elements take
  `10.0.0.0/24` and `1000-2000`.

  Tested on traffic: `udp dport @r` with `r = 1000-2000` matches 1000 and
  2000 and not 999 or 2001 (mutation-checked: an end element of `2000`
  instead of `2001` loses port 2000); a `/30` matches its addresses and not
  its neighbours; a single address matches only itself. Until this, nlink
  wrote an interval-set element as a bare start — which the kernel reads as
  a range to the top of the key space — and 0.30 refused interval elements
  outright.

- **Recipes: [nftables sets, maps and objects](docs/recipes/nftables-sets-maps.md)
  and [ipset → nftables](docs/recipes/ipset-to-nftables.md)**, plus the
  example `nftables_sets_maps`. Run it as root with `-- --apply`: it
  applies one declared ruleset with every set kind, sends traffic through
  it in a throwaway namespace, and shows a second apply doing nothing.
  The recipes' code compiles as doctests. Stale docs are fixed: the
  declarative recipe no longer calls maps and objects imperative-only, and
  no longer says unkeyed rules are re-added every time or that dynamic
  sets churn; the stateful-firewall recipe no longer points at a
  `match_saddr_v6_in_set` that never existed.

- **Named stateful objects: counters, quotas and limits, and object maps.**
  - `Object::{counter, quota, limit}` with `ObjectConfig`, `ObjectType`
    (`NFT_OBJECT_*`, audit-mapped), and `ObjectInfo` / `ObjectState` read
    back.
  - `Connection::{add_object, del_object, list_objects, list_objects_in,
    reset_object}`. `reset_object` is `NFT_MSG_GETOBJ_RESET`: it reads the
    object and zeroes it in one step, so no packet is lost between the read
    and the reset.
  - `Transaction::{add_object, update_object, del_object}`.
    `update_object` changes a quota in place and keeps its consumption. For
    a counter or a limit the kernel accepts the update and changes nothing
    (they have no update operation), and the method says so.
  - `Expr::Quota(QuotaExpr)` and `Expr::Objref(ObjrefExpr::{Named, Map})`.
    `Rule::{counter_named, quota_named, limit_named, objref,
    objref_from_map, quota_until, quota_over}`.
  - `SetDataType::Object(ObjectType)` and `SetElement::object(name)` for
    object maps (`NFT_SET_OBJECT` with `NFTA_SET_OBJ_TYPE`; `MAP | OBJECT`
    is `EOPNOTSUPP`).
  - `RuleExpr::{Quota, Objref}` decode typed.
  - `NftablesEvent::{NewObject, DelObject}`.
  - Declaratively, `DeclaredTableBuilder::object(name, ObjectConfig)`.
    Only configuration is compared, so a counter keeps counting and a quota
    keeps what it has used across applies. A changed quota is updated in
    place. A changed limit is deleted and recreated, and the rules using it
    are moved out of its way and back to their places
    (`MoveReason::BoundToRecreatedObject`). A limit declared with burst 0 is
    compared as the 5 the kernel stores.
  - A rule's own quota echoes its consumption (`nft_quota_do_dump` always
    emits it), so the echo form carries a zero one and the diff zeroes the
    live value. A request never sends it, because the quota would start
    there.

  Tested on traffic:
  - a named counter counts 4 packets, `reset_object` returns 4 and leaves 0,
    and the object is notified;
  - an object map counts each destination in its own counter;
  - with 33-byte datagrams, `quota until 100 bytes` matches 3,
    `quota over` the other 7, and a named quota reports itself used up at
    100;
  - declared objects converge and keep their state through a quota update
    and a limit recreate, with rule order unchanged.

  Mutation-checked: comparing a limit's burst unnormalized, not moving the
  rules of a recreated object, a quota echo without its consumption, and
  adding objects after the map elements that name them each fail a test.
  `nft_quota` and `nft_limit` join the privileged lane's strict modules.

- **Maps and verdict maps (`vmap`).**
  - `Set::map(SetDataType)` and `Set::vmap()`, plus the same on
    `DeclaredSetBuilder`. `SetDataType::{Verdict, Value(SetKeyType)}`, and
    the new `SetKeyType::ClassId`. A map is written with `NFT_SET_MAP` and
    its `NFTA_SET_DATA_TYPE`, which is `NFT_DATA_VERDICT` for a verdict map.
    A value map also gets `NFTA_SET_DATA_LEN`; the kernel sizes a verdict
    itself. `SetInfo::{data_type, data_len}` read them back.
  - `SetElement::value(SetElement)` and `SetElement::verdict(Verdict)`, plus
    `SetElement::classid(TcHandle)`. An element's data is checked against
    the map's type and length before anything is sent. It is written in
    `NFTA_SET_ELEM_DATA`, an object reference as `NFTA_SET_ELEM_OBJREF`. In
    an interval map the data goes on the range's start, the only place the
    kernel accepts it, and reads back on the range. A delete names the key
    alone.
  - `Rule::{vmap, vmap_concat, set_mark_from_map, set_priority_from_map}`
    (`ip daddr vmap @vm`, `meta mark set ip daddr map @m`, `meta priority
    set ... map @p`).
  - Declaratively, a changed data type recreates the map. An element whose
    data changed is removed and added in the same batch, in either element
    mode. An interval map's touching ranges are never merged, since they
    may map to different values.

  Tested on traffic:
  - a verdict map jumps each destination to its own chain (3 and 5
    packets counted), and reads back with its verdicts;
  - a value map marks each destination, and the rules after it count by
    mark;
  - declared verdict, value and interval maps converge, and changing one
    element's data replaces just that element.

  Mutation-checked: comparing elements without their data, merging an
  interval map's ranges, and dropping a range's data on readback each fail
  a test.

- **Set timeouts and `dynset`: rules that add to, refresh and delete from a
  set (ipset `timeout`, `SET --add-set`/`--del-set`).**
  - `Set::{dynamic, timeout, per_element_timeouts, gc_interval}` (and the
    same on `DeclaredSetBuilder`), and `SetElement::with_timeout`.
    `SetInfo::{timeout, gc_interval}` and `SetElement::{timeout,
    expiration}` read them back. As the kernel reports it, an element's
    timeout appears only when it differs from the set's default.
  - `Expr::Dynset(DynsetExpr)` with `DynsetOp::{Add, Update, Delete}`, and
    `Rule::{add_to_set, update_in_set, delete_from_set}`. These load a
    `PacketField` and write it to the set, for example `update @seen { ip
    daddr timeout 60s }`. `RuleExpr::Dynset` decodes them; one carrying
    per-element expressions stays `Unknown`.
  - `DeclaredSetBuilder::element_mode(SetElementMode::{Exact, Ensure})`.
    `Ensure` adds the declared elements and leaves the rest. It is the
    default for a dynamic or timeout set, whose elements come from the
    packet path (see Fixed, #395).
  - A declared set's default timeout and GC interval are changed in place,
    like its size. The timeout is compared in 20 ms steps: the kernel keeps
    it in jiffies, rounding down both ways, and 20 ms is a whole number of
    jiffies at every `HZ`. A dynset's timeout is compared the same way, and
    a dynset without one is compared against the zero the kernel echoes. A
    request carrying that zero would be `EOPNOTSUPP` on a set without
    timeouts.

  Tested on traffic: `update @seen { ip daddr timeout 60s }` records each
  destination with 60 s to run, `delete @s { ip daddr }` removes it, and
  elements expire after the set's default timeout or their own. A declared
  dynamic set keeps what its rule put there, and its 1001 ms dynset
  timeout, which the kernel reads back as 1000 ms, converges. A changed
  default timeout keeps the set, its elements and the rule's handle.
  Mutation-checked: the old exact element mode, an update without the
  kernel's timers, comparing timeouts unrounded, and a missing echoed zero
  timeout each fail a test.

- **Sets of concatenated keys (ipset `hash:ip,port`, `hash:net,port`).**
  `SetKeyType::Concat` could declare such a set, but nothing could fill
  one or match against it. Now:
  - `SetElement::concat([..])` builds an element from one element per
    field, each padded to a 4-byte register word; in an interval set a field
    can be a range or prefix of its own (`10.0.0.0/24 . 1000-2000`).
  - `Rule::match_concat_in_set(&[PacketField], set)` and
    `match_concat_not_in_set` load the fields word after word, behind their
    guards (each once, ahead of the loads), as `nft` lays out
    `ip daddr . udp dport @s`.
  - An interval set of concatenated keys is created with `NFT_SET_CONCAT`
    and its field lengths (`NFTA_SET_DESC_CONCAT`), so the kernel selects
    `pipapo`, and stores each range as one element with its inclusive end
    (`NFTA_SET_ELEM_KEY_END`) rather than an end-plus-one element.
    `list_set_elements` reads it back that way, and the declarative diff
    compares those elements one by one, since pipapo neither merges nor
    accepts overlapping ones. A range end before its start is checked field
    by field.
  - `Register::Reg32_00..=Reg32_15`, the 32-bit registers
    (`NFT_REG32_*`). `Register::word(n)` gives the register for word `n` in
    the form the kernel dumps, and the writer always uses that form
    (`Register::wire`): `Reg32_04` is written as `NFT_REG_2`. So a rule
    built with either name converges. Rules that use 32-bit registers now
    decode typed instead of as `Unknown`.

  `NFTA_SET_FIELD_LEN` is a length in **bytes**: the UAPI header documents
  it as bits, but `nft_set_desc_concat_parse` reads bytes. Tested on
  traffic: in a hash set, `ip daddr . udp dport` matches its pairs and not
  their crossings, and `!= @s` counts exactly the others. In a pipapo set,
  `127.0.0.0/30 . 1000-2000` matches only inside both ranges. A declared
  IPv6 concatenation, whose port sits in word 4, converges, and so does a
  declared interval concatenation, one element at a time. Mutation-checked:
  dropping `KEY_END`, pairing the readback, packing one word per field, and
  writing the non-canonical register name each fail a test. The `nlink-nft`
  DSL does not parse concatenations yet.

- **Set lookups by packet field, and an escape hatch.**
  - `Rule::match_in_set(PacketField, set)` and `match_not_in_set` (`!= @set`,
    iptables `! --match-set`) for IPv4 and IPv6 addresses, TCP/UDP ports,
    the mark, `iif`/`oif` and `l4proto` — each behind the guard `nft` puts in
    front of it. `PacketField::key_type()` names the set key type it needs.
    `match_saddr_in_set` / `match_daddr_in_set` are now shorthands for it.
  - `Expr::Raw(RawExpr)` writes an expression nlink does not model (`fib`,
    `socket`, `notrack`, …) from its name and attribute bytes, with an
    optional `echo` for the declarative diff and `RawExpr::without_data`
    for expressions dumped with no data nest. `Transaction::raw(RawMessage)`
    does the same for whole messages.
  - `NftablesEvent::{NewSetElements, DelSetElements, NewGen}`: element
    changes and committed generations, which used to be dropped.
  - `nlink-nft` rules take `ip|ip6 saddr|daddr [!=] @set` and
    `tcp|udp sport|dport [!=] @set`.

  Tested on traffic: an IPv6 set matches `::1` and not IPv4, a port set
  counts member ports only, `!= @set` counts only non-members, and a raw
  `notrack` really untracks — and its declared rule converges.

- **nftables write statements: `meta mark set`, TCP MSS clamping, set
  size.** Three things `nft` does that nlink could not express, so a
  firewall needing them still had to shell out to `nft`/`iptables`:

  - `Expr::MetaSet { key, sreg }` (`meta <key> set ...`) and the
    `Rule::set_mark(mark)` helper — the mark `tc` `fw` filters and
    `ip rule fwmark` act on.
  - `Expr::Exthdr` / `Expr::ExthdrSet` with the new `ExthdrOp` enum
    (IPv6 extension headers, TCP/IPv4/SCTP/DCCP options), and the
    `Rule::clamp_tcp_mss(mss)` helper: `tcp option maxseg size set <mss>`,
    the same bytecode `nft` emits. The MSS is only ever lowered — the
    kernel refuses to raise it, as iptables `TCPMSS --set-mss` does — and
    the clamp is a statement, so the rest of the rule still runs for every
    TCP packet. `Rule::match_tcp_flags(flags, mask)` with the `TcpFlags`
    newtype (`TcpFlags::SYN | TcpFlags::RST`, …) expresses the usual
    `tcp flags syn / syn,rst` guard. A newtype rather than `TCP_FLAG_*`
    constants, because `linux/tcp.h` already uses those names for
    big-endian masks with different values.
  - `Set::size(n)`, written as `NFTA_SET_DESC`/`NFTA_SET_DESC_SIZE` by
    both `Connection::add_set` and `Transaction::add_set`.

  The decoder follows: `RuleExpr::MetaSet`, `RuleExpr::Exthdr` and
  `RuleExpr::ExthdrSet` replace the `Unknown` these used to dump as — code
  matching `RuleExpr::Unknown { name: "meta" | "exthdr", .. }` for them
  stops matching. An exthdr carrying `NFT_EXTHDR_F_PRESENT` still decodes
  as `Unknown`. `ExthdrOp` is `#[repr(u32)]` and checked by the UAPI audit.

  One wire asymmetry handled: `nft_exthdr_tcp_set_init()` rejects
  `NFTA_EXTHDR_FLAGS` with `EINVAL`, yet the dump always carries it. The
  request omits it; the declarative diff lowers the declared rule with
  it, so a declared MSS clamp reconciles to an empty diff instead of a
  replace on every run (same class as #362).

- **nftables → TC classification, connmark and path-MTU clamping.** The
  statements a firewall uses to hand packets to a shaper, each tested by
  sending traffic through a netns and reading rule counters and HTB class
  statistics:

  - `Rule::set_priority(TcHandle)` — `meta priority set 1:10`. HTB sends
    the packet straight to leaf class `1:10` with no `tc` filter
    (`htb_classify` reads `skb->priority` first); `prio` picks a band.
    New `MetaKey::Priority`.
  - `Rule::set_mark_masked(value, mask)` / `match_mark_masked(value,
    mask)` — iptables `MARK --set-mark v/m`: only the bits under `mask`
    change, so kube-proxy's, a CNI's or a VPN's mark bits survive. Pairs
    with `FwFilter::mask`. `set_mark` now says it replaces all 32 bits.
  - Connmark: `Expr::CtSet` (`ct <key> set`), `Rule::set_ct_mark`,
    `match_ct_mark`, `save_mark_to_ct` (`CONNMARK --save-mark`) and
    `restore_mark_from_ct` (`--restore-mark`).
  - `Rule::clamp_tcp_mss_to_pmtu()` — `tcp option maxseg size set rt mtu`
    (`TCPMSS --clamp-mss-to-pmtu`), with the new `Expr::Rt` + `RtKey` and
    `Expr::Byteorder` + `ByteorderOp`, linearized exactly as `nft` does
    (`rt load tcpmss`, `byteorder hton`, `exthdr write`).
  - The decoder: `RuleExpr::{Ct, CtSet, Rt, Byteorder, Bitwise, Lookup}`
    replace the `Unknown` these dumped as (directional `ct`, inverted or
    map lookups and the shift / register forms of `bitwise` stay
    `Unknown` rather than guess).
  - New recipe [`nft-mark-tc-classification`](docs/recipes/nft-mark-tc-classification.md).
  - `nlink-nft` rule specs accept `ip saddr|daddr @set`, `mark V[/M]`,
    `meta mark set V[/M]|ct mark`, `meta priority set X:Y`,
    `ct mark [set] V|mark`, `tcp flags F / M` and
    `tcp option maxseg size set N|rt mtu`.

  `MetaKey`, `CtKey`, `CmpOp`, `PayloadBase` and `NatType` are now
  `#[repr(u32)]` and mapped in the UAPI audit, with the new `RtKey` and
  `ByteorderOp`: they were the nftables wire enums the audit could not
  see. All values matched the kernel already; now they are checked
  (686 discriminants across 70 enums).

- **Declarative set size.** `DeclaredSetBuilder::size(n)` /
  `DeclaredSet::size()`, so `NftablesConfig` can bound a set too, and
  `SetInfo::size` reads the kernel's back. A changed size is applied in
  place — the set keeps its elements and the rules bound to it keep their
  handles — through the new `NftablesDiff::sets_to_update`, committed in
  a batch of its own ahead of the rest of the apply: the kernel checks an
  element add against the size a set has *before* the commit, so growing
  a set and filling it in one batch is `ENFILE`. An in-place resize needs
  Linux 6.5; older kernels accept the update and keep the old size, which
  `apply` now reports as `Error::NotSupported` instead of leaving a diff
  that never converges. An undeclared size is never drift (the kernel
  gives any set a `dynset` writes to a size of 65535). `nlink-nft` takes
  `size <n>` on `add set` lines and `--size` on `add set`.

- **`Rule::flow_offload(flowtable)`** — `flow add @<flowtable>`. The
  expression existed (`Expr::FlowOffload`) but had no helper, and could
  not be installed at all (see Fixed, #375).

### Changed

- **`PerHostLimiter` installs in the recipe band (#434).** `FilterPriority`
  documents bands: operator `1..=49`, recipe `100..=199`. `PerPeerImpairer`
  used the recipe band. `PerHostLimiter` put rule `i`'s filter at `i + 1`,
  in the band reserved for operators, and a port rule's other three at
  `i + 101/201/301`. Rule `i` now takes the four priorities from
  `100 + 4 * i`.
  - Every protocol meets the rules in the order they were declared.
    Before, an address rule always came before every port rule's UDP and
    IPv6 filters.
  - No two rules can share a priority, so a port rule can have any number
    of rules after it. The old layout refused one 100, 200 or 300 places
    later. The limit is 16359 rules.

  The first `reconcile()` after upgrading moves every filter. It adds the
  new ones first, then removes the old ones. To make that work,
  `reconcile()` now removes any filter under the limiter's root that sends
  traffic into one of its rule classes from a priority it does not use.
  Before, it looked only inside its own bands. `apply()` rebuilds the tree
  as before.

- **`scripts/cut-release.sh` runs on this forge again (#358).** It was
  written against `gh` and a per-cycle branch, and its first pre-flight check
  failed on a missing binary, so the last cuts were done by hand around it.
  It now drives the flow those cuts followed with `fj`: a `release/X.Y.Z`
  branch and PR, a merge that is checked against master, a bare-semver tag
  that fires `release.yml`, and a `publish-crates.yml` dispatch. It has a
  `--dry-run` that changes nothing and `--from N` to resume.

- **`Rule::comment` is a human comment, written verbatim.** It used to be
  prefixed with `nlink:` and treated as the declarative key. In an
  `NftablesConfig` the key is the rule's `handle_key` and the comment
  follows it (`nlink:<key> <comment>`); an imperative rule's comment is
  stored exactly as given. `RuleInfo::key` is the key up to the first space.
  New: `NftablesConfig::validate`, `DeclaredChainBuilder::exclusive` (the
  chain owns all of its rules — those nlink did not write are deleted),
  `NftDiffOptions::enforce_rule_order`, `MoveReason::Reorder`.

- **Breaking: the nftables API reshape for 0.30.** One pass, so this cycle's
  features (and later ones) are additive:
  - `Expr::{Lookup, Limit, Log, Masquerade, Redirect}` wrap the new
    `#[non_exhaustive]` payload structs `LookupExpr` (new: `dreg` for map
    lookups, `invert` for `!= @set`), `LimitExpr` (new: `over`, settable
    burst), `LogExpr`, `MasqExpr`, `RedirExpr`; build them with `new()` +
    setters and push them with the new `Rule::expr`. `Expr::FlowOffload`'s
    field is `flowtable`. `NatExpr` is `#[non_exhaustive]`.
  - Every struct-like `RuleExpr` variant is `#[non_exhaustive]`;
    `RuleExpr::Lookup` gains `dreg`/`invert`, so inverted and map lookups
    decode typed.
  - `SetElement` has private fields (key, inclusive range end, map data,
    timeout, expiration, flags) with constructors — new: `mark`, `ifindex`,
    `inet_proto`, `ether` — and accessors. `add_set_elements` /
    `del_set_elements` (on `Connection` and `Transaction`) take the `&Set`
    and check each element against it: a mismatch is an error before
    anything is sent (a `Transaction` reports it from `commit`), and elements
    of interval sets and maps are refused until those encodings land.
  - Set flags are `SetFlags(pub u32)` (the `CtState` pattern) on `Set`,
    `DeclaredSet` and `SetInfo`; new `NFT_SET_{TIMEOUT,EVAL,OBJECT,CONCAT,EXPR}`.
  - `Table` and `Flowtable` are `#[non_exhaustive]`, like `ChainInfo`,
    `RuleInfo` and `SetInfo`.
  - `RuleInfo::comment` splits into `key` (nlink's identity) and
    `comment_text` (the comment as `nft` shows it, whoever set it).
  - `NftablesDiff`: `rules_to_add` is `Vec<RuleAdd { rule, placement }>`
    (new `RulePlacement`), and element changes are `Vec<SetElementsChange
    { set, elements }>`.

- **Breaking: `SetInfo` is `#[non_exhaustive]` and has a `size:
  Option<u32>` field.** Code that builds a `SetInfo` with a struct literal
  stops compiling; reading its fields is unaffected. `ChainInfo` and
  `RuleInfo` were already non-exhaustive, so the dump-side info types now
  agree — and the next attribute worth reading back is no longer a break.

- **A TBF without a queue limit is refused instead of installed as a
  black hole (#398).** `tbf_change()` only gives the qdisc a queue when
  `limit > 0`; with 0 its child stays `noop_qdisc` and every packet is
  dropped. `TbfConfig::new()` defaults the limit to 0 and
  `QdiscBuilder::tbf(rate, burst)` documented `limit_bytes` as "`None`
  leaves the kernel default" — there is none — so the shape most callers
  write first, a rate and a burst, installed fine, diffed clean, and
  passed no traffic (a ping through it: 0 sent, 7 dropped).
  `TbfConfig::write_options` now returns `Error::InvalidMessage("tbf: a
  queue limit is required …")`, as tc(8) refuses a tbf with neither
  `limit` nor `latency`; this covers `add_qdisc`/`replace_qdisc`, the
  declarative `apply` and `nlink-tc`. A declared TBF without a limit also
  no longer matches a live one, so a black hole an older version
  installed is reported and refused rather than left looking converged.
  An error rather than a derived default because any default is a latency
  budget nlink would be choosing for the caller; `TbfConfig::limit` now
  suggests `burst + rate * latency`.

- **A link declared in JSON/YAML without `state` is left as it is, not
  taken down (#399).** `LinkState`'s `Default` was `Down`, which is what
  serde filled in for an omitted `state`, while `LinkBuilder` defaulted to
  `Unchanged`. So `{"name": "eth0", "link-type": "physical", "mtu": 9000}`
  set the MTU and took the NIC down, on every apply. `LinkState::default()`
  is now `Unchanged`, matching the builder; the JSON schema's default
  follows. Write `"state": "down"` where down is meant.

### Fixed

- **`docs/library.md`, `docs/observability.md` and the README were never
  compiled, and 39 of their 40 Rust blocks no longer built (#449).** The
  recipes have been doctests since #319; these three documents were not.
  What they described had drifted from the library:
  - a subnet scanner and port checker (`NetworkScanner`,
    `ConnectivityChecker`) that nlink does not have;
  - `FlowerFilter::action(..)`, which never existed. `FlowerFilter`
    carried no actions beyond `goto_chain` until `actions()` (#450);
  - `MirredAction::mirror_egress`, which is now `mirror_by_index`;
  - fields that are now accessors, on `FdbEntry`, `BridgeVlanEntry`,
    `Nexthop`, `MplsRoute` and `TcMessage`;
  - the old `MacsecSaBuilder` and `MptcpEndpointBuilder::dev`;
  - a nftables ruleset diffed through a `Connection<Route>`;
  - `into_events_with_resync` called synchronously.

  All three files are now compiled the way the recipes are, each gated on
  the features its blocks use, and every block matches the current API.
  The flower examples now set an ethertype, which #288/#424 require.

- **Flower numbers were read in a different base from tc(8) (#432,
  #447).** tc(8) reads a numeric `ip_proto` as hex
  (`flower_parse_ip_proto` → `get_u8(.., 16)`). It reads an `ip_tos` or
  `ip_ttl` value as decimal, falling back to hex, and the mask as hex.
  `FlowerFilter::parse_params`, and so `nlink-tc`, did the opposite on
  both counts. The same command therefore installed a different filter,
  and the kernel accepted both:
  - `ip_proto 47` matched GRE in nlink and protocol 0x47 in tc(8);
  - `ip_ttl 64` matched TTL 100 in nlink and TTL 64 in tc(8).

  Both now read numbers the way tc(8) does: `ip_proto 2f`/`0x2f` is GRE,
  and `ip_proto 132` is an error, because 0x132 does not fit.

- **A flower filter did not take its ethertype from the filter's protocol
  (#433).** tc(8) writes `TCA_FLOWER_KEY_ETH_TYPE` from `protocol` unless
  that is `all`, so `protocol ip flower ip_proto tcp dst_port 80` is a
  normal filter. nlink took the ethertype from the flower keys alone and
  refused that filter ("needs an ethertype"); `nlink-tc` refused 9 of 13
  ordinary tc(8) flower command lines tested. Under `protocol 802.1ad`, a
  `vlan_id` match wrote an 802.1Q TPID on frames the protocol had already
  restricted to 802.1AD, and matched nothing (0 of 5 packets). The kernel
  does not echo the TPID, so no dump showed it.

  Now an ethertype set on the filter wins. Otherwise the filter's protocol
  is used, unless it is `all`. Otherwise a VLAN key implies 802.1Q. The
  `*_full` entry points (`add_filter_full`, `replace_filter_full`,
  `change_filter_full` and their `_by_index` forms) take the protocol as an
  argument and pass it on through the new `FilterConfig::set_protocol`. It
  is defaulted like `set_chain`, and every shipped config that carries a
  protocol stores it. The reconcile comparison of `PerPeerImpairer` and
  `PerHostLimiter` resolves the ethertype the same way, so it cannot drift
  from what is installed.

- **A link recreate left VXLAN remotes `via` it pointing at nothing
  (#438).** A VXLAN FDB entry can name an output device
  (`bridge fdb append ... dev vx9 dst ... via d0`, `NDA_IFINDEX`). Deleting
  `d0` does not touch it — `bridge fdb` then shows `via if10`, the old
  ifindex — so recreating `d0` (#417) silently broke every remote on a
  VXLAN not stacked on it. #426's check looked only at what the recreated
  link owns; user-made entries on other devices that send through it now
  block the recreate too, named in the error.

- **`RouteMessage::netlink_len` undercounted what `write_to` writes
  (#439).** It left out `RTA_SRC`, `RTA_IIF`, `RTA_PREF`, `RTA_EXPIRES` and
  `RTA_MULTIPATH`, and sized every address by the route's family, so an IPv4
  route through an IPv6 gateway (or a multipath nexthop of the other family)
  was counted short too: a fully populated IPv4 route encodes to 144 bytes
  and was reported as 68. It now mirrors the writer attribute for attribute
  and sizes each address by its own family.

- **A VLAN declared down on a lower device the apply brought up ended up
  (#436), and one declared up on a lower device declared down failed only
  on the second apply (#437).** The kernel couples a VLAN's state to its
  lower device's: `vlan_device_event()` brings every VLAN up when the lower
  device comes up and closes it when the lower goes down, and
  `vlan_dev_open()` refuses a VLAN whose lower is down (ENETDOWN). Now a
  declared-down VLAN whose lower device comes up in the apply is taken down
  again after the link changes, and a VLAN declared up on a lower device
  declared down is refused by `diff`/`apply` before anything changes —
  the kernel cannot hold that state.

- **A flower `vlan_id`, `vlan_prio` or `tcp_flags` match could install as a
  match-all (#431).** `fl_set_key` reads the VLAN keys only when
  `TCA_FLOWER_KEY_ETH_TYPE` is a VLAN tag (`is_vlan_key` →
  `eth_type_vlan`), and the TCP flags only under `ip_proto tcp`; anywhere
  else the kernel ACKs and ignores them. The typed builder could not even
  set a VLAN ethertype, so `FlowerFilter::vlan_id(10)` always claimed every
  packet: on a dummy carrying VLANs 10 and 20, a `vlan_id 10` filter
  counted all 15 packets sent, 10 of them untagged or on VLAN 20. Now
  `vlan_id`/`vlan_prio` imply 802.1Q unless an ethertype is set (or, since
  #433, the filter's protocol names one), `vlan()`
  and `qinq()` set one explicitly, and `write_options` refuses VLAN keys
  under any other ethertype and `tcp_flags` without `ip_proto tcp`, with a
  `flower: …` error — the same rule #424 applies to ports.

- **`nlink-ip link add` dropped options it could not apply (#428).** A
  `--local` or `--remote` it could not parse was skipped on
  gre/gretap/ipip/sit/vti/vti6/ip6gre/ip6gretap, so was an IPv6 address
  given to an IPv4 tunnel (and the reverse), and so was a bond's
  `--arp-ip-target`. The tunnel was created without it. `--txqlen` was
  accepted by every kind and applied by none, `--mtu` was discarded on
  vti/vti6/ip6gre/ip6gretap, and `--numtxqueues`/`--numrxqueues` were
  never applied at all. Now:
  - every option is checked before anything is created; an address of the
    wrong family names the tunnel kind that takes it;
  - `--mtu`, `--txqlen` and `--address` reach every kind, set right after
    creation where the kind's create message cannot carry them. If that
    fails the new link is deleted again, as one `ip link add` would leave
    nothing;
  - `--address` on a kind with no MAC of its own (the layer-3 tunnels,
    WireGuard, ipvlan) is an error;
  - the two queue-count options are gone.

- **A declared dynamic or timeout set lost its runtime elements on every
  apply (#395).** The documented way to declare a set that rules populate
  was to declare it with no elements. But the diff reconciled every set's
  elements exactly, so every element the packet path had added was
  "undeclared" and removed. Such sets now default to
  `SetElementMode::Ensure`, and with no declared elements their contents
  are not even read.

- **An in-place set resize zeroed the set's timeout and GC interval
  (#396).** An update sets both to whatever it carries, and nlink's `Set`
  carried neither, so resizing a set with `timeout 30s` left elements that
  never expired. The update now carries the declared values, or else the
  kernel's.

- **Declared rule order is enforced (#387).** `apply` used to append every
  new rule to the end of its chain, and the diff never compared order — so a
  rule declared between two installed ones landed last, and a reordered
  declaration produced an empty diff. First match wins, so this inverted
  policy. Each chain is now planned: the longest run of installed rules
  already in declared order stays put, and every other rule is inserted (or
  moved) immediately before the next staying rule, or after the last one —
  as few moves as possible, so counters survive. Opt out with
  `NftDiffOptions::enforce_rule_order(false)`.

- **A declared `.counter()` rule that had counted was replaced, and reset,
  on every apply (#388).** The kernel echoes live packet/byte counts, which
  never matched the zeros nlink writes. Bodies are now compared with a
  counter's values (and a quota's consumption) zeroed on both sides.

- **Rules declared without a key were re-added on every apply (#389)** — and
  `nlink-nft reconcile` duplicated its whole ruleset each run. Such a rule
  now gets a key derived from its chain, body and comment (`~` + FNV-1a-64),
  so it converges; editing it is a delete + insert in place. The reconcile
  DSL's chains are `exclusive()`, which also removes the duplicates earlier
  runs left.

- **Rule identity (#390).** A key that did not fit the kernel's comment was
  dropped silently, installing the rule without an identity; a keyed rule
  with a `.comment()` was stored under the comment; and of two kernel rules
  carrying the same key, the extra one was never deleted. Keys and comments
  are now validated up front (`NftablesConfig::validate`, which `diff`
  calls first), the key and the comment are stored together as
  `nlink:<key> <comment>`, and duplicate keyed rules are deleted.

- **Declared rules using a set lookup, `limit`, `log` or `reject with tcp
  reset` never converged (#374).** Each was installed fine and then
  reported as changed — and replaced — on every apply, because its writer
  disagreed with the kernel's dump: `nft_lookup_dump` and
  `nft_limit_dump` always emit their `FLAGS` attribute, a syslog `log`
  always dumps its level (`NFT_LOGLEVEL_WARNING` unless named), and a TCP
  reset's dump has no ICMP code while nlink always sent one (the comment
  claiming the kernel wanted it was wrong; `nft_reject_init` ignores it).
  The writers now send exactly what the kernel keeps. A packet `limit`
  with burst 0 is sent as the kernel's default of 5 for the same reason.
  Same class as #362, unseen for the same reason: the idempotency test
  only ever declared `match_tcp_dport` rules. `nftables_echo.rs` now
  declares one keyed rule per `Rule` helper and `Expr` writer arm and
  asserts the second diff is empty.

- **Every `Expr::FlowOffload` rule failed with `EINVAL` (#375).** It named
  the flowtable with `NFTA_FLOWTABLE_NAME` (2), the flowtable *object*'s
  attribute; the `flow_offload` expression's is `NFTA_FLOW_TABLE_NAME`
  (1, new constant), and 2 is above its maxtype, so the kernel never saw
  a name.

- **`match_saddr_in_set` / `match_daddr_in_set` had no `meta nfproto ipv4`
  guard (#376).** In an `inet` chain an IPv6 packet reached the 4-byte
  load at offset 12 / 16 and had bytes of its own source or destination
  address looked up as an IPv4 address. They now carry the guard the
  address matchers got in 0.20. **Behaviour change:** a declared rule
  using them changes body, so the first apply after upgrading replaces it
  once.

- **Recreating a drifted set that a rule references failed with `EBUSY`
  (#377).** A set whose key type or flags change is deleted and recreated
  (#275), but a rule that matches `@set` pins it, and the rule itself had
  not changed, so nothing deleted it first: every apply failed and the
  config could never converge — for nearly any real set, since a set
  exists to be referenced. Each keyed rule bound to a recreated set is now
  deleted ahead of the `DELSET` and re-inserted after the new set, right
  before the next rule that stayed, so chain order is unchanged (new
  `NftablesDiff::rules_to_move`). A pending in-place replace of such a
  rule becomes the re-insert. A rule nlink does not manage still pins the
  set; the diff now warns about it.

- **`Rule::position(handle)` places the rule *after* `handle`, not
  before.** `add_rule` always sends `NLM_F_APPEND` (#195), and with it the
  kernel links a positioned rule after the one named — nft's `add rule ...
  position`. The doc said "before", which was only true before #195. Doc
  fixed and pinned by an integration test.

- **A declared TBF was replaced on every apply at almost any rate but
  1 mbit (#400).** The diff compared the declared burst and mtu with the
  dump exactly, on the belief that the kernel echoes the byte-valued
  `TCA_TBF_BURST`/`PBURST`. It does not: `tbf_change()` keeps both buckets
  as nanoseconds and `tbf_dump()` reports them only as psched ticks, so
  the bytes read back are a tick round trip of the ones sent — 32768 at
  10 gbit comes back as 32719, the default mtu of 1514 at 100 mbit as
  1513. 1 mbit, the only rate any test used, happens to survive the trip.
  The comparison now pushes the declared values through the same trip
  (`psched_l2t_ns` with the kernel's mult/shift, `>> PSCHED_SHIFT`, then
  `tc_calc_xmitsize`). Found by `network_config_echo.rs`, which applies a
  rate sweep from 512 kbit to 10 gbit twice: 36 of its 48 shapes failed.

- **A declared fq_codel `quantum` below 256 or sfq `limit` above 16256 was
  replaced on every apply (#401).** The kernel clamps both on the way in —
  `fq_codel_change()` stores `max(256, quantum)`, `sfq_change()` caps the
  limit at depth × flows (127 × 128 by default) — and the diff compared
  the dump against the unclamped declaration. It now compares against the
  value the kernel keeps; the builder setters say so.

- **Editing a declared HTB root's `default_class` failed with a bare
  `EINVAL` on every apply (#402).** `sch_htb` has no change operation, so
  the replace the diff asks for is refused by the kernel ("Change operation
  not supported by specified qdisc"), and the diff can never converge. The
  only way through is delete + add, which takes every class and filter
  under the root with it — a tree `NetworkConfig` does not describe — so
  nlink still will not do that implicitly. `apply` now checks for a live
  HTB root first and returns `Error::NotSupported` naming the live and
  declared `default_class`/`r2q` and what to do (delete the qdisc and
  apply again). **Behaviour change:** that error used to be
  `is_invalid_argument()`; it is now `is_not_supported()`.

- **An IPv6 route declared with host bits in its destination was re-added
  on every apply (#403).** `ip6_route_info_create` masks the destination
  to its prefix, so `2001:db8::1/48` is installed and dumped as
  `2001:db8::/48`, and the diff — keyed on the declared address — never
  found it. Under purge the same mismatch would have scheduled the route
  for removal too. Both now key on the destination the kernel stores.
  IPv4 is unchanged: the kernel refuses host bits there ("Invalid prefix
  for given prefix length"), and the apply still reports that.

- **An IPv6 route declared with `.metric(0)` was re-added on every apply
  (#404).** #366 taught the diff that an IPv6 route with no metric comes
  back as 1024, but `ip6_route_info_create` tests the value, not its
  presence (`if (cfg->fc_metric == 0) cfg->fc_metric =
  IP6_RT_PRIO_USER`), so an explicit 0 is stored as 1024 too and still
  compared as 0. IPv4 keeps 0.

- **Changing a declared route's type (unicast → blackhole, unreachable,
  prohibit, or back) never reached the kernel (#405).** The diff matched a
  declared route against the live ones by gateway, device and metric, not
  type, and a blackhole has neither gateway nor device — so the old
  unicast route "matched", the diff came back empty, and the kernel kept
  forwarding traffic the config said to drop. The type is compared now;
  `apply` and the diff share one `DeclaredRouteType → rtm_type` mapping.

- **A bond port declared `.up()` could not be applied (#406).**
  `bond_enslave()` refuses a port that is up ("Device can not be enslaved
  while up", `EPERM`), and `apply` brought a new link up before enslaving
  it — so every `.link("eth1", |l| l.dummy().master("bond0").up())`
  failed, as did moving an up link into a bond. Links are now enslaved
  first, and a port is taken down before joining a bond, as ifenslave and
  systemd-networkd do. A bond also opens the port it enslaves and closes
  the one it releases, so across a bond master change the diff now
  re-asserts the declared state: a port released from a bond and declared
  up used to come back down, and one declared down came back up.

- **A bridge declared with an MTU took its ports' MTU instead (#407).**
  `br_add_if()`/`br_del_if()` move a bridge to its smallest port's MTU
  unless `BROPT_MTU_SET_BY_USER` is set, and only an `RTM_SETLINK` MTU
  change sets it — not the `IFLA_MTU` a bridge is created with (or that
  `ip link add … mtu` gives it). So `br0` declared at 9000 with a 1500
  port came out at 1500, and the next apply had to fix it. After the link
  changes, `apply` now re-asserts the declared MTU of every bridge whose
  ports changed, which also marks it user-set so it stays.

- **A MAC declared on a VRF or netkit link was dropped at creation
  (#408).** #275 wired `LinkBuilder::address` into the create path of
  vxlan/macvlan/ifb; the VRF, netkit and ovpn arms still ignored it, so the
  link came up with a random MAC and the next diff set the declared one —
  a second apply to converge. `VrfLink::address` and `NetkitLink::address`
  are new and the create path passes the MAC. ovpn and netkit in L3 mode
  (netkit's default) have no hardware address — the kernel answers a bare
  `EOPNOTSUPP` — so declaring one there is now refused up front naming the
  reason (for netkit: declare `NetkitMode::L2`), instead of being dropped
  and then failing on every later apply.

- **IPv6 addresses on a link set down, or moved into or out of a VRF or a
  bond, were lost until the next apply (#409).** Those link changes make
  the kernel drop the link's IPv6 addresses (`addrconf_ifdown()`, unless
  `keep_addr_on_down`); the diff had read them as present before the link
  step ran, so the address step skipped them and the second diff found
  them missing. The diff now schedules the declared IPv6 addresses of
  such a link for (re-)adding; an add that finds the address still there
  is reported as already present, not counted and not an error. A purging
  apply's removal of an address the link change already flushed is
  likewise "already absent" rather than `EADDRNOTAVAIL`.

- **A `WireguardConfig` private key that was not already X25519-clamped
  was rewritten on every apply (#410).** The kernel clamps the key before
  storing it (`curve25519_clamp_secret`) and `GET_DEVICE` returns the
  clamped copy, so any key that did not come from `wg genkey` — a derived
  one, a test constant — never matched. The diff now compares the declared
  key clamped.

- **A `WireguardConfig` peer with a preshared key was rewritten on every
  apply (#411).** The diff marked a declared PSK dirty unconditionally, on
  the premise that it cannot be read back — the same premise #281 found
  false for the private key: `GET_DEVICE` (which needs `CAP_NET_ADMIN`)
  returns every peer's `WGPEER_A_PRESHARED_KEY`. It is compared with the
  dump now; a declared all-zero key means "none", as in the kernel.

- **A `WireguardConfig` peer whose allowed IPs had host bits or a
  duplicate was rewritten on every apply (#412).** The kernel's
  allowed-IPs trie stores each prefix once, masked to its length, so
  `AllowedIPs = 10.201.0.9/16` (as wg-quick profiles often carry) dumps as
  `10.201.0.0/16` and a repeated prefix dumps once. The diff now compares
  the masked, de-duplicated sets.

- **Removing a rule from a `PerHostLimiter` made `reconcile()` fail with
  `EBUSY` (#413).** Its stale-filter pass only treats priorities `1..=n`
  and `101..=100+n` as its own, with `n` the *new* rule count, so the
  removed rule's filter read as unmanaged and stayed bound to the class
  being deleted — "HTB class in use". `PerPeerImpairer` had this fixed in
  #291 by ordering; here the filter was never selected at all. A filter
  whose target class is one the reconcile removes is now removed first,
  whatever its priority.

- **A `WireguardConfig` declaring `listen_port(0)` moved the device to a
  new random port on every apply (#414).** 0 asks the kernel to pick a
  port, and `GET_DEVICE` then reports the port it picked, never 0 — so the
  diff never matched, and writing 0 again makes `set_port()` bind another
  random port, so the device's peers lost it on each run. A declared 0 is
  now satisfied by any port. A device-level write also sends only the
  fields that differ, so a private-key change no longer rewrites (and
  rebinds) an unchanged port.

- **Changing a declared link's kind parameters did nothing (#417).** The
  link diff compared MTU, MAC, master and state, and nothing about the
  kind: a changed VXLAN VNI, VLAN id or protocol, or bond mode on an
  existing link was an empty diff, and the kernel kept the old value. The
  diff now reads the kind's `IFLA_INFO_DATA` back and compares the kind
  itself, VLAN id/protocol/parent, VXLAN VNI/port/remote/local/underlay,
  macvlan mode/parent, bond mode, `miimon`, delays, `xmit_hash_policy`,
  `min_links`, `resend_igmp`, `lacp_rate` and `ad_select`, VRF table and
  netkit mode/policies/scrubbing. Each was checked against the kernel's
  `changelink` for that kind: what it takes is changed in place
  (`LinkChanges::set_kind_params`); what it refuses or ignores —
  `vlan_changelink` silently ignores a new id or protocol, `vxlan_nl2conf`
  refuses a new VNI or port, bond mode needs a down bond with no ports, VRF
  has no `changelink` — makes the apply delete the link and create it again
  (`ConfigDiff::links_to_recreate`), putting back the addresses, routes,
  qdiscs, ports and stacked links the config declares on it. A recreate
  that would destroy something the config does not declare is refused with
  `Error::NotSupported` naming it, as is any netkit mode or scrub change. A
  bond delay is compared as the kernel stores it, rounded down to a
  multiple of `miimon`. The VXLAN port's doc comments said the default is
  4789; the kernel's default is the `vxlan` module's `udp_port`, 8472.

- **A VXLAN's IPv6 local or remote address was silently dropped (#418).**
  `VxlanLink` stored its endpoints as `Ipv4Addr` and wrote only
  `IFLA_VXLAN_LOCAL`/`IFLA_VXLAN_GROUP`, so `NetworkConfig`'s `create_link`
  skipped an IPv6 `vxlan_local`/`vxlan_remote` (a code comment said so) and
  the link came up as an IPv4 VXLAN with no endpoints; `nlink-ip link add
  vxlan` did the same with `--local`/`--remote`, and also ignored an
  unparseable address. `VxlanLink` gained `local6`, `remote6` and `group6`,
  which write `IFLA_VXLAN_LOCAL6`/`IFLA_VXLAN_GROUP6`; the declarative layer
  and `nlink-ip` use them; and the link diff reads both families back and
  compares them — in place within a family, recreating the link across
  families, which `vxlan_nl2conf` refuses on a live link.

- **`PerHostLimiter::limit_port_range` classified nothing (#416).**
  `reconcile()` installed no filter for a port range, and `apply()` none for
  a range wider than 10 ports — for a narrower one, a TCP filter per port
  with its errors discarded, and nothing for UDP. The rule's class existed
  and no traffic reached it. `FlowerFilter` gained `dst_port_range` /
  `src_port_range` (`TCA_FLOWER_KEY_PORT_{DST,SRC}_{MIN,MAX}`, kernel
  5.2+), and its `parse_params` takes tc(8)'s `dst_port 8000-8100`. A range
  without TCP/UDP/SCTP as `ip_proto`, which cls_flower would install as a
  match-all, or with `min >= max`, which it refuses, is an error. Both
  verbs now build their filters from one list, so a range gets the TCP and
  UDP filters `limit_port` gets, at the same priorities (IPv4 only, as
  `limit_port` was until #425); a one-port range is that port, and
  `start > end` fails before anything changes. Tested on traffic: UDP to
  ports inside the range lands in the rule's class, the rest in the default
  class.

- **A flower filter's exact port was dropped for every protocol but TCP and
  UDP (#424).** `FlowerFilter` wrote `src_port`/`dst_port` only under
  `ip_proto` TCP or UDP. With SCTP, any other protocol or no `ip_proto` at
  all, the port was left out and the filter installed as a match-all for
  the protocol: an SCTP port rule claimed every SCTP packet. It now writes
  `TCA_FLOWER_KEY_SCTP_{SRC,DST}` under SCTP, which `fl_set_key` reads there,
  and an exact port on any other protocol, or on none, is a `flower: …`
  error from `write_options`, as a port range has been since #416. So is an
  `ip_proto`, port, `ip_tos`, `ip_ttl` or `tcp_flags` under an ethertype
  other than IPv4 or IPv6 (ARP, a VLAN tag): `fl_set_key` reads them only
  under those two, and the old check refused only a missing ethertype.
  `FlowerFilter::ip_proto_sctp()` is new, and `parse_params` takes tc(8)'s
  `ip_proto sctp`. Tested on traffic: SCTP to the filter's port lands in its
  class; SCTP to other ports, and UDP to that port, in the default class.

- **`PerHostLimiter` port rules did not shape IPv6 (#425).** `limit_port`
  and `limit_port_range` installed flower filters for IPv4 only, so TCP and
  UDP over IPv6 to a limited port went to the default class. A port rule
  now has four filters, IPv4 and IPv6, TCP and UDP, each at its own
  priority, since the kernel refuses a second ethertype at one (the
  priorities moved again in #434). `apply()` and
  `reconcile()` still build them from one list. Two things came with it:
  a port rule that becomes an address rule no longer leaves its other
  filters behind — `reconcile()` kept them, classifying the port's traffic
  into the class the address rule now owns, which was already true of the
  IPv4 UDP filter; and rules whose filters would need the same priority (a
  port rule with another rule 100, 200 or 300 places after it, so only past
  100 rules) are refused before anything changes, where the kernel used to
  refuse the second filter mid-apply or `reconcile()` rewrote one of them
  forever. Tested on traffic: TCP SYNs and UDP datagrams over IPv4 and
  IPv6, to a port rule, inside and outside a range rule, land in exactly
  the classes they should after either verb, and a reconcile after either
  is a no-op.

- **A link recreate (#417) destroyed FDB entries, neighbours, nexthop
  objects and multipath routes without asking (#426).** The refusal checked
  addresses, routes by `RTA_OIF`, qdiscs, ports and stacked links. Deleting
  a link also takes its permanent, static and externally learned FDB
  entries — a VXLAN's head-end replication list (`bridge fdb append
  00:00:00:00:00:00 ... dst`), a bridge's static entries for the port, and
  for a bridge every entry in its database — its permanent, externally
  learned and proxy neighbours (`neigh_ifdown`), its nexthop objects
  (`nexthop_flush_dev`), and routes through it that carry no `RTA_OIF`:
  multipath routes (an IPv4 one goes whole — `fib_sync_down_dev` counts
  every nexthop dead on unregister) and routes through a nexthop object or
  group (`RTA_NH_ID`). None of these can be declared, so each now blocks the
  recreate and is named in the error and in `LinkRecreate::blocked_by`. The
  kernel's own FDB entries do not block: the address-list entries
  `ndo_dflt_fdb_dump` reports as `self permanent` (multicast joins, the MACs
  of links stacked on the device), a bridge port's or bridge's own MAC, and
  a VXLAN's default remote. The ports of a recreated bond or VRF are
  flushed on the way out (`__bond_release_one` closes them;
  `fib_netdev_event` and `addrconf_notify` flush a port leaving an L3
  master), so their undeclared routes — outside the VRF's own table — IPv6
  addresses, neighbours and nexthop objects block too. Two fixes made this
  possible: `RouteMessage::nh_id()` reads `RTA_NH_ID`, and an FDB entry's
  `NDA_DST` is decoded by length — it was decoded by family, which is
  `AF_BRIDGE`, so `FdbEntry::dst()` (and `nlink-bridge fdb show`) never
  showed a VXLAN remote.

- **Declared routes through a link set down, or moved into or out of a VRF
  or a bond, were lost until the next apply (#427).** Those link changes
  make the kernel flush every route through the link, in both families and
  every table: `fib_netdev_event` on NETDEV_DOWN, and on NETDEV_CHANGEUPPER
  to or from an L3 master (forced, whatever the nexthop's scope);
  `addrconf_notify` → `addrconf_ifdown` → `rt6_disable_ip` for IPv6. A
  bond takes its port down on the way in (`bond_enslave` refuses an up
  port) and closes it on the way out; a VRF cycles it. The diff read the
  routes before the link step ran, found the declared ones present and left
  them out, so the second apply was not a no-op and traffic was misrouted
  in between. The diff now leaves the routes through such links out of the
  comparison, so the declared ones are added back in the same apply — as
  #409 does for IPv6 addresses — and does the same for a VLAN on such a
  link, which `vlan_device_event` takes down with it (its IPv6 addresses,
  which #409 missed, too). A route add that finds the route present is
  reported as already there, not counted and not an error. A route declared
  through a link declared down cannot exist (the kernel refuses one by
  device with `ENETDOWN`, and one by a gateway it can no longer reach with
  `ENETUNREACH`), and the apply that takes the link down now fails with that
  error instead of reporting success and leaving the next apply to fail.

## [0.29.0] - 2026-10-01

> Upgrading from 0.28.x? See
> [`docs/migration_guide/0.28.0-to-0.29.0.md`](docs/migration_guide/0.28.0-to-0.29.0.md).
> One compile break — `NetemConfig` gained a public field — and two behaviour
> changes, both towards what was always meant: a netem replace now sets the
> whole state, and `NetemOptions::requires_recreation_for` stops asking for a
> delete-and-add a replace can do.

A netem release, found downstream again. A network-fault lab that "ran on a
lossy LTE link" for every experiment it made turned out to have **no random
loss at all**, because `loss 0.5% 25%` drops nothing (#369). Asking nlink for
bursty loss correctly, through netem's loss models, was not possible (#368).
Writing the test for that found that a netem replace keeps whatever it is not
sent (#370).

### Added

- **netem's Markov loss models can be written, not only read (#368).**
  `loss gemodel` (Gilbert-Elliot) and `loss state` (4-state Gilbert-Intuitive)
  are netem's two generators for **bursty** loss. Before this release nlink
  decoded them from the kernel and rejected them everywhere else:
  `NetemConfig` had no field for them, its tc-params parser refused them, and
  the declarative builder had no setter. So the only way to ask nlink for
  bursty loss was `loss <p>% <corr>%`, which does not produce bursts — its
  correlation suppresses small loss rates instead (#369).

  New:
  - `NetemConfig::loss_model(NetemLossModel)`, written as a nested
    `TCA_NETEM_LOSS`.
  - `QdiscBuilder::loss_model` on the declarative path, compared by
    `netem_matches` in the kernel's `u32` units, so a declared model diffs
    clean against its echo.
  - `NetemConfig::parse_params` accepts `loss|drop state …` and
    `loss|drop gemodel …`, with tc(8)'s defaults for omitted values.
  - `NetemLossModel::gilbert_elliot` / `gilbert_intuitive`, which apply those
    defaults, plus setters named for what they mean: `loss_in_bad` is tc's
    `1-h` and does the conversion; `p23` and `p14` are named, because tc's
    command line orders them opposite to the kernel struct. `NetemLossModel`
    is re-exported from `nlink::netlink::tc` and gains `PartialEq` and the
    optional serde/schemars derives.

  A model is exclusive with random `loss` and `loss_correlation`. The kernel
  would accept both and ignore the random values, so `write_options` rejects
  the combination. Field semantics and defaults were checked against what
  iproute2 6.15 installs. Tests cover:
  - the parser against those values;
  - an encode/decode round trip;
  - a kernel round trip;
  - deterministic models that must drop every packet, or none;
  - an apply-twice case for each model in
    `unchanged_declared_qdiscs_are_not_replaced_on_reapply`.

### Fixed

- **A netem replace could not remove `rate`, `reorder`, `corrupt` or a
  correlation, so a declaration that dropped one never converged (#370).**
  A replace of an existing netem is `netem_change()`, which updates only the
  attributes it is sent. `NetemConfig::write_options` wrote
  `TCA_NETEM_RATE`/`REORDER`/`CORRUPT`/`CORR` only when set, so after a
  replace the old value **stayed**. `diff()` then reported the stale value
  forever, and every `apply()` replaced the qdisc again — the #346 property,
  through a different door.

  It hid because no test removed an attribute: every netem case started from
  a fresh device or a different kind. Measured before the fix, replacing a
  fully loaded netem with `delay 20ms` left rate, reorder, corrupt and all
  three correlations in place. The writer now sends each of them as its off
  state (zero) when unset. The base `tc_netem_qopt` always carried latency,
  loss, duplicate, gap and limit, which is why those never had the problem.

  Covered by:
  - an imperative test that replaces a fully loaded netem and reads back what
    survived;
  - a `netem-attributes-removed` case in
    `unchanged_declared_qdiscs_are_not_replaced_on_reapply`, after the
    `netem` case that sets them.

  Both fail against the old writer.

- **The netem correlation docs promised bursts (#369).** `loss_correlation`
  and friends were "correlation between adjacent packets' loss outcomes".
  netem's correlation is an approximation that averages each random draw
  with the previous one, and it **lowers** a small probability rather than
  grouping events: `loss 0.5% 25%` drops 0 of 40 000 packets. The setters
  now say so, with the effective-rate table, and point at `loss_model` for
  bursty loss.

- **`NetemLossModel`'s doc comments described the models wrongly.**
  The 4-state model's states were "Good, Bad Burst, Bad Gap, Loss" while its
  transitions named state 3 as "Bad Burst"; `tc-netem(8)` numbers them
  good reception, good reception within a burst, burst losses, independent
  losses. Gilbert-Elliot's `h` was "Loss probability in Bad state". It is
  the probability of *delivering* there: the loss probability is `1-h`, the
  value `tc` takes and converts.

### Changed

- **`NetemOptions::requires_recreation_for` now answers `true` only for a
  live `slot` or ECN** — what `NetemConfig` cannot express, and so a replace
  cannot clear. With #370 a replace clears every parameter `NetemConfig`
  sets. The old answer ("any parameter dropped") was never needed for delay,
  jitter, loss or duplicate, and for reorder, corrupt and rate it was the
  workaround for #370. A caller that deleted and re-added on its say-so now
  replaces instead, which keeps statistics and does not drop what the qdisc
  holds.

## [0.28.1] - 2026-09-18

### Fixed

- **Every IPv6 route declared without a metric diffed as missing,
  forever** (#366) — the same shape as #362 one release earlier, in the
  route layer instead of nftables: `apply` reported no changes and
  `diff()` reported one, permanently, and they never converged.

  `diff_routes` compared `declared.metric.unwrap_or(0)` against the
  kernel's priority, on the reasoning that an unspecified metric comes
  back as 0. That holds for IPv4. IPv6 substitutes `IP6_RT_PRIO_USER`
  (1024, `include/net/ip6_route.h`), so a declared `None` was measured
  against 1024, never matched, and the route sat in `routes_to_add` on
  every diff. It compares against the kernel's default *for the family*
  now.

  Nothing broke visibly because `routes_to_add` applies with
  `NLM_F_REPLACE` and the apply path does not go through `diff_routes` —
  which is why it survived. It is what a consumer reading the diff sees:
  downstream, an `apply --check` CI gate could never go green on an IPv6
  topology.

  The test pins both halves: an unmetriced v4 *and* v6 route diff clean
  after apply, and an explicit `metric(700)` on either is still drift —
  the fix is "compare against the family default", not "an undeclared
  metric matches anything".

## [0.28.0] - 2026-09-18

> Upgrading from 0.27.0? See
> [`docs/migration_guide/0.27.0-to-0.28.0.md`](docs/migration_guide/0.27.0-to-0.28.0.md).
> One compile break — two enum variants grew fields — and two behaviour
> changes, both "something that always failed now works".

### Fixed

- **A declared `masquerade` rule diffed as changed on every reconcile,
  forever (#362).** `Expr::Masquerade` rendered only `NFTA_EXPR_NAME`,
  on the reasoning that basic masquerade has no attributes. It has none
  *inside* the data nest, but the nest itself is not optional:
  `nft_expr_dump` opens `NFTA_EXPR_DATA` for every expression whose ops
  have a `dump` callback and closes it whatever the callback wrote, so
  the kernel echoes an empty 4-byte nest. The declared body was
  therefore 4 bytes shorter than the kernel's, which no amount of TLV
  normalisation can reconcile — one side simply lacks an attribute — and
  the rule landed in `rules_to_replace` on every `NftablesConfig::diff`.

  It hid because `apply` converges anyway: re-issuing the rule is
  idempotent and keeps its handle, so the *applier* was right while the
  *diff* was wrong, and nothing downstream broke visibly. What it did
  break is anything that reads the diff — `NftablesDiff::is_empty()` was
  never true for a config with a masquerade rule, so nlink-lab's
  `apply --check` (a CI gate that exits non-zero on drift) reported
  drift forever, seconds after `apply` had reported none.

  A portless `redirect` had the same omission and is fixed with it. The
  regression test asserts the wire bytes, because `parse_expressions`
  cannot tell an absent nest from an empty one — which is exactly why
  this went unnoticed — plus a root test that a NAT config with both
  expressions diffs empty after apply.

- **`sfq` parameter edits failed with EINVAL.** A same-kind replace
  becomes `qdisc_change()` in the kernel and `sch_sfq` sets
  `.change = NULL`, so it answers *"Change operation not supported by
  specified qdisc"*. The declarative applier now falls back to del+add
  for that kind when the atomic replace is refused, the same way it
  already does for `ingress`/`clsact`. Changing the *kind* was never
  affected: that takes the create-and-graft path.

### Added

- **The declarative `QdiscBuilder` reaches every knob the imperative
  configs do, for `fq_codel`, `sfq`, `prio` and `tbf` (#361).**

  This was worse than a few missing fields. `fq_codel()`, `sfq()` and
  `prio()` hardcoded every field to `None` and **no setter existed for
  any of them** — so through the builder those three kinds were "kernel
  defaults or nothing", even for the fields `DeclaredQdiscType` already
  carried and the lowering and diff already honoured. Only a
  hand-written serde document could reach them.

  New on `QdiscBuilder`: `target(Duration)`, `interval(Duration)`,
  `flows(u32)`, `quantum(u32)`, `ecn(bool)` for fq_codel;
  `perturb(Duration)` for sfq; `bands(u8)` for prio; `peakrate(Rate)`
  and `mtu(u32)` for tbf. `limit(u32)` now reaches fq_codel and sfq as
  well as netem — all three take a packet count, while TBF's byte-valued
  limit keeps its own `limit_bytes(Bytes)`; `quantum` is shared by
  fq_codel and sfq for the same reason. Every setter is a no-op on a
  kind that does not have that knob, matching the existing netem
  setters.

  `DeclaredQdiscType` gains `FqCodel { flows, quantum, ecn }`,
  `Sfq { limit, quantum }` and `Tbf { peakrate_bps, mtu }`, and all four
  values take part in `qdisc_params_match`, so a drift in any of them is
  now seen rather than silently accepted.

  **`flows` is create-only, by the kernel's design.** `fq_codel_init`
  allocates the flow table and `fq_codel_change` opens with
  `if (tb[TCA_FQ_CODEL_FLOWS]) { if (q->flows) return -EINVAL; }` — so a
  change message carrying the attribute is rejected *even when the value
  is unchanged*, which would make every later edit of any other knob
  fail. It is therefore applied when the qdisc is created, dropped from
  change messages, and excluded from the diff (a difference there is not
  something a replace could close, so comparing it would churn on every
  reconcile). Delete the qdisc to resize the table.

  **This is the cycle's first breaking change, and it bumps the
  workspace to 0.28.0.** `DeclaredQdiscType::{FqCodel, Sfq}` grew
  fields, which breaks a downstream `match` that destructures them
  without `..`. Both are `#[non_exhaustive]` from now on — as `Netem`
  and `Tbf` became in 0.27 — so this is the last time a knob on them
  costs a major bump.


## [0.27.0] - 2026-09-13

> Upgrading from 0.26.0? See
> [`docs/migration_guide/0.26.0-to-0.27.0.md`](docs/migration_guide/0.26.0-to-0.27.0.md).
> Two compile breaks, and four behaviour changes with no compiler error —
> one of which lets a purge remove routes 0.26.0 left alone.

### Added

- **`NetworkConfig::apply_reconcile_with_options` — purge + retry in one
  call (#345).** `apply_reconcile` is the retry-on-`EBUSY`/`EAGAIN` shape
  a concurrent-mutator consumer is told to use, but every attempt
  recomputed the non-purge `diff()` and applied with
  `ApplyOptions::default()`, so purge was unreachable through it; anyone
  wanting both wrote the loop by hand around `apply_with_options`. The new
  method takes `ApplyOptions` and computes each attempt's diff with the
  same `purge` / `purge_tables` lowering `apply_with_options` uses (since
  #333/#335 that reaches every table the config declares into);
  `dry_run` and `continue_on_error` are honoured too. `apply_reconcile`
  delegates with the defaults and behaves as before. Root test: plain
  `apply_reconcile` leaves an undeclared address alone, the `with_purge`
  variant removes it in one attempt, and a second call reports zero
  changes.

- **`namespace::list_live()`, `impl AsFd for NamespaceFd`,
  `Connection::new_in_namespace_fd` / `NetlinkSocket::new_in_namespace_fd`
  (#186).** `list()` returns every entry under `/var/run/netns`,
  stale marker files included — `ip netns add` creates the file and
  mounts the namespace over it, and a crash leaves the file. Now that
  `is_namespace_path` exists (#181), `list_live()` filters through
  it; `list()`'s doc says what it includes and that names are
  `to_string_lossy`'d. The fd constructors take `impl AsFd` so the
  borrow checker keeps the namespace fd alive for the call; the
  `RawFd` forms stay. `prepare_etc_binds` reuses `path_to_cstring`
  instead of its own vaguer copy. The one item of #186 that was a
  design question — remount `/sys` even with nothing to overlay, as
  `ip netns exec` does — is answered no, in `spawn_with_etc`'s doc:
  with no overlay a mount namespace buys the child only a sysfs view
  nlink never reads, at the price of `CAP_SYS_ADMIN` and the container
  caveats of #334.

- **Declarative netem reaches parity with `NetemConfig` (#332).**
  `QdiscBuilder::netem` exposed `delay_ms`/`jitter_ms` and the
  percentages but no `rate`, no microsecond jitter, and three of the
  four correlations were missing — including `reorder_correlation_pct`,
  which the `reorder_pct` doc had named since 0.21 and which did not
  exist. An impairment written as `rate 100mbit jitter 250us` therefore
  could not be declared, so downstream kept netem on an imperative
  side path outside the `NetworkConfig` diff/idempotency/purge
  treatment its addresses and routes get.

  **This is the cycle's first breaking change, and it bumps the
  workspace to 0.27.0.** Adding fields to a struct variant breaks any
  downstream `match` that destructures `DeclaredQdiscType::Netem { .. }`
  field by field without `..` — cargo-semver-checks flags it, correctly.
  The variant is `#[non_exhaustive]` from now on, so this is the last
  time a netem knob costs a major bump; a destructuring match must add
  `..` once.

  New on `QdiscBuilder`: `rate(Rate)`, `delay(Duration)`,
  `jitter(Duration)`, `jitter_us`, `reorder_correlation_pct`,
  `duplicate_correlation_pct`, `corrupt_correlation_pct`, `gap`. The
  `Netem` variant gains the matching fields (`rate_bps` — bytes per
  second, tc(8)'s `bps`, like `Tbf::rate_bps`; the three correlations;
  `gap`), all optional, so a JSON document written before them still
  reads. `delay_ms` / `jitter_ms` now saturate instead of wrapping
  above 4 294 967 ms.

  The declarative → imperative lowering was three hand-copied `match`
  arms (add, replace, and the diff's options renderer) that every new
  field had to reach; it is one function now
  (`DeclaredQdiscType::netem_config`), and a unit test asserts a fully
  specified declaration lowers to the `NetemConfig` built by hand. The
  live test reads the installed qdisc back through the parsed
  `QdiscOptions::Netem` and checks rate, 250 µs jitter, gap and the
  reorder correlation — the existing declarative-qdisc test only
  checked that *a* netem existed.

- **`DiffOptions::purge_tables` / `ApplyOptions::with_purge_tables`,
  and `Connection<Route>::del_route_if_exists<R: RouteConfig>`
  (#333, #335).** The first names extra route tables a purge may
  clean — for the caller who owns a VRF table but has just stopped
  declaring into it, which is exactly when the leftovers need
  removing. The second is the table-aware, full-key sibling of
  `del_route_v4_if_exists` / `del_route_v6_if_exists`, which take a
  bare destination and can only name a main-table route; it reports
  `ESRCH`/`ENOENT` as `Ok(false)` so replaying a `DeclaredRoute` does
  not mean matching errno by hand.

- **`Stack::apply_in_with(ns, ApplyOptions)` / `diff_in_with(ns,
  DiffOptions)`, plus `apply_with` / `diff_with` for the default
  namespace, and `facade::apply::{network_in_with,
  wireguard_devices_in}` / `facade::diff::network_in_with` (#330).**
  `facade::apply::network_in` called `cfg.apply(&conn)` with no way to
  pass options, so a `Stack` could never purge — a reconcile-style
  consumer that wanted undeclared addresses and routes removed had to
  re-implement the three-call orchestration (nlink-lab did, ~120
  lines). The new forms carry the options to the network layer; the
  plain forms are unchanged and use the defaults.

### Changed

- **`require_root!()` could not tell host root from a rootless
  container's root, and six tests needed the difference (#357).**
  `euid == 0` is equally true inside a rootless container, where uid 0
  is an unprivileged host user wearing a mapping. Almost everything the
  suite does is owned by the user namespace that created it and works
  fine there — but mounting the `/etc` overlay or remounting `/sys` in a
  spawned namespace, installing a TC police rate table, and creating a
  WireGuard device are all checked against `init_user_ns`, so those six
  tests ran and failed `EPERM` on the privileged CI lane instead of
  skipping. New: `lab::is_host_root()` (the identity mapping in
  `/proc/self/uid_map`, which only the initial namespace carries),
  `require_host_root!()` / `require_host_root_void!()`, and
  `NLINK_TEST_STRICT_HOST_ROOT=1` for an environment that does provide
  host root — the `NLINK_TEST_STRICT_MODULES` bargain, so the skip is
  not silently mistaken for a pass. The lane is rootless and does not
  set it; those six stay covered by local root runs.

- **The privileged integration lane runs the suite, and gates on it
  (#350).** The "Integration tests (root in container)" step carried
  `continue-on-error: true` behind a note saying it would stay
  informational until #293 and #294 closed. Both closed in 0.26, and the
  flag was doing exactly what it says: the step's result never reached
  the job, so the lane reported `success` while the suite failed 278 of
  its 361 tests on it — every `LabNamespace` denied `EACCES` at the nsfs
  bind mount by the container's default AppArmor profile. (The red runs
  the issue cited, #213/#217, came from the *Library tests* step, which
  never had the flag.) A probe workflow run on the runner confirmed the
  enforcing profile, and found three more: workflow-level
  `container.options` is ignored by this runner, `/lib/modules` was not
  mounted in — so `has_module` could not see built-ins and their tests
  skipped, reporting `ok` (#273) — and `ping` was never installed, which
  three traffic tests need. The runner now grants `apparmor=unconfined`
  and mounts `/lib/modules` read-only; here, the flag and its note are
  gone, `iputils-ping` is installed, the runner-side contract is written
  next to the job, and the module-guard step fails outright if the
  `/lib/modules` mount ever disappears again rather than degrading into
  a green run that tested less. `NLINK_TEST_STRICT_MODULES` is
  unchanged; a genuinely optional feature is gated in the test with
  `require_module!`, not at the job.

- **`QdiscBuilder::tbf` takes `Rate` and `Bytes`, not a bare `u64`
  that meant bytes per second (#349).** Every imperative TC builder
  takes the typed units — the whole point of `Rate` is that bits and
  bytes per second cannot be confused, and the history behind it is an
  HTB class shaping at 800 Mbit/s because `"100mbit"` was read as bytes.
  The declarative TBF was the one exception: `tbf(rate_bps: u64,
  burst_bytes: u32)`, where a Rust caller writing `100_000_000` for
  100 Mbit/s got 800 Mbit/s with no error anywhere. **Breaking:** the
  signature is now `tbf(rate: Rate, burst: Bytes)`; a new
  `QdiscBuilder::limit_bytes(Bytes)` sets the TBF queue limit, which had
  no builder setter at all. The serde/JSON shape is unchanged
  (`rate_bps` / `burst_bytes` / `limit_bytes` integers in the kernel's
  units), and the `Tbf` variant is now `#[non_exhaustive]` like `Netem`
  so the next field is not the next compile break. Lowering goes through
  one `DeclaredQdiscType::tbf_config()` instead of three hand-copied
  arms; a unit test pins that `tbf(Rate::mbit(100), Bytes::kib(32))`
  lowers to `TbfConfig::new().rate(Rate::mbit(100)).burst(Bytes::kib(32))`.

- **`DsmarkConfig` and `AtmConfig` are deprecated: the kernel retired
  both qdiscs in Linux 6.8 (#347).** `sch_dsmark` and `sch_atm` went out
  with CBQ in the 6.8 "retire" series (their companion classifier
  `cls_tcindex` had already left in 6.3), so on any current kernel an add
  of either fails with `ENOENT`/`EOPNOTSUPP` whatever the arguments. The
  types stay for callers on older kernels, marked `#[deprecated(since =
  "0.27.0")]`, and will be dropped in a later release; `nlink-tc` still
  dispatches `dsmark` and `atm` for the same reason. Independently of the
  retirement, `DsmarkConfig::new().build()` could never install anywhere:
  every write in `write_options` was optional, so it sent an empty
  `TCA_OPTIONS` nest, and `dsmark_init` requires `TCA_DSMARK_INDICES` with
  no default — `EINVAL` on every kernel that had the qdisc, the #327 shape
  with no absent-nest fallback to reach for. `write_options` (and
  `parse_params`) now return a `dsmark: indices is required …` error
  instead of sending the request the kernel refuses. A wire-level unit
  test pins both the error and the attribute the nest carries when
  `indices` is set.

- **Purge reaches every table the config declares into, not just
  main (#333, #335).** `DeclaredRouteBuilder::table` (0.26) let a
  `NetworkConfig` declare routes into a VRF table, and the add/modify
  diff keyed on `(dst, prefix, table)` correctly — but the purge loop
  began with `if r.table_id() != 254 { continue }`, so a declared
  VRF route that left the config stayed in the kernel until the
  namespace died. Reconcile converged in one direction. The scope is
  now main ∪ every table some declared route names ∪
  `purge_tables`; tables the config never mentions (`local`,
  `default`, somebody else's VRF) stay out of reach, which is the
  safety fence the docs promised. The `static`/`boot` and route-type
  fences are unchanged.

  Also: a purge whose route vanished between diff and apply no longer
  fails the apply. The issue text assumed the private `del_route`
  helper already swallowed `ESRCH`; it did not — the error propagated
  and, without `continue_on_error`, aborted the remaining removals.
  It now goes through `del_route_if_exists` and reports the route as
  already absent, counting no change. And the `ApplyOptions` rustdoc
  no longer says `with_purge` "was removed in 0.19" four releases
  after it came back.

- **`Stack` bootstraps WireGuard links before the network layer
  (#330).** `apply_in` ran `NetworkConfig` first and `WireguardConfig`
  — with its `ensure_devices` — last, so any network layer that put an
  address on `wg0` or routed via a peer's tunnel address failed on a
  link that did not exist yet. The order is now: declared WireGuard
  links created and brought up (idempotent; the one mutation that
  precedes the pre-flight diff, and it creates nothing the stack does
  not declare) → pre-flight diff → network → nftables → WireGuard keys
  and peers. A stack without a WireGuard layer is unaffected. The live
  test declares an address on the tunnel and a route via the peer's
  tunnel address, applies, re-applies as a no-op, drops the route and
  purges it.

- **`WireguardConfig::ensure_devices` brings every declared link up
  (#329).** It created the links and returned; `add_link` creates a
  link administratively down, and the kernel refuses a route whose
  nexthop device is down (`ENETDOWN`, "Device for nexthop is not up").
  So the documented sequence — `ensure_devices`, then a `NetworkConfig`
  that addresses the tunnel and routes via the peer's tunnel address,
  then `apply` — failed at the second step for every route via the
  tunnel, and downstream (nlink-lab) grew its own `set_link_up` loop to
  get past it. The recipe said `ensure_devices` replaced the manual
  `add_link` + `set_link_up` pair; it replaced half of it.

  Every declared device is now raised on every call — desired state,
  not create-time state — so a device downed by hand comes back up on
  the next reconcile. The return value (names created) is unchanged.
  The live test now asserts the link is up, adds a route via the tunnel
  address, and re-raises a downed device.

### Fixed

- **A declared qdisc is no longer replaced on every reconcile (#346).**
  `diff_qdiscs` decided "same kind, different parameters" by rendering
  the declared config's `TCA_OPTIONS` and byte-comparing it with the
  kernel's. The kernel does not echo what it was sent: netem always
  reports `CORR`/`RATE`/`ECN`/`LATENCY64`/`JITTER64`, rounds latency to
  ticks and orders attributes its own way; fq_codel echoes every field
  with its defaults filled in. So an unchanged declaration was
  "different" on every `diff()`, landed in `qdiscs_to_replace`, and every
  `apply()` replaced the qdisc — `changes_made >= 1` forever (measured:
  a second `apply` of an unchanged netem reported `Replaced qdisc netem
  on dummy0`), statistics reset, traffic briefly disturbed, and the
  "second apply converges" property everything else in `NetworkConfig`
  has was broken for any interface with a declared netem.
  `qdisc_params_match` now compares field by field through the parsed
  `QdiscOptions`, in the kernel's units and quantisation: netem via the
  same `netem_matches` that `PerPeerImpairer::reconcile` uses to leave a
  leaf alone (which now also compares the five correlations), tbf
  (rate/burst/limit), htb (default class, r2q), fq_codel (only the
  declared fields, codel times through `codel_round_trip_us` — 20 ms
  reads back as 19999 µs), sfq (perturb) and prio (bands, priomap).
  Kinds without a parser fall back to the byte compare. Every kind's
  declarative → imperative lowering is now one `DeclaredQdiscType`
  method (`htb_config`, `fq_codel_config`, `sfq_config`, `prio_config`
  join `netem_config`/`tbf_config`) instead of three hand-copied arms.
  Unit tests feed the comparator the kernel's kind of echo (extra
  attributes, truncated codel target); a root test applies netem, tbf,
  htb, fq_codel, sfq and prio declarations twice each and asserts the
  second `diff()` is empty and the second `apply()` reports
  `changes_made == 0`.

- **A stale `ip netns` marker is `NamespaceNotFound`, not an `EINVAL`
  out of `setns` (#348).** `ip netns add` bind-mounts an nsfs inode over
  an empty file; after a crash or a bare `umount` the file stays. The
  by-name `spawn` / `spawn_with_etc` gated on `Path::exists()`, which
  the leftover passes, and `connection_for`, `connection_for_async`,
  `open`, `enter` and the sysctl helpers did not gate at all — so the
  failure surfaced from `setns(2)` inside `pre_exec` as "Invalid
  argument", which nothing downstream recognises as "the namespace is
  gone". Every by-name entry point now resolves through one check on
  `is_namespace_path` (the `statfs` nsfs test that `list_live` uses),
  returns the typed `Error::NamespaceNotFound` that `is_not_found()`
  matches, and logs the stale marker at `warn` since it is usually a
  bug the operator wants to see. `nlink-ip netns pids` / `set` gate the
  same way. Root test: a plain file under `/var/run/netns` is
  `is_not_found()` from all eight entry points.

- **`NetdevInfo::driver()` is `None` for every real device, and the
  docs said otherwise (#328).** The netdev-lifecycle recipe's table
  had `driver | ✗ | ✅ (DRIVER=)`, the module docs said "uevents know
  the driver", and five unit tests asserted `driver() == Some("veth")`
  — against uevents they had synthesised themselves. The `net`
  subsystem never emits `DRIVER=`: `dev_uevent()` adds it only for a
  device with a driver bound, and a net-class device has none — the
  driver binds to the bus parent (PCI, virtio, USB), whose uevents are
  in another subsystem, go only to the initial netns, and carry no
  `IFINDEX=` to join on. Measured across veth, dummy, bridge, vlan and
  a virtio NIC. `DriverBound`/`DriverUnbound` have the same problem:
  `KOBJ_BIND` fires on the bus device, so a `subsystem("net")` stream
  never sees one.

  The live test never looked at `driver()`, which is how the claim
  survived; it now asserts `driver().is_none()` on a real veth and
  `devtype() == Some("bridge")` on a real bridge — `DEVTYPE=`,
  `DEVPATH=` and `SEQNUM=` are the fields the uevent side really
  carries, and the table now says so. `NetdevInfo::devtype()` is new;
  `driver()` and the two variants stay, documented as reachable only
  by a kernel or driver that does emit the key. The unit tests keep
  their synthetic `DRIVER=` as a marker that the uevent half was
  joined, labelled as such.

- **`NamespaceSpec::{spawn,spawn_output}_with_etc` silently dropped
  the `/etc/netns` overlay for `Path` (#331).** The doc said "falls
  back to regular `spawn_path` (no overlay)" for `Path` and `Pid`,
  while `spawn_path_with_etc` existed and did the right thing given a
  name. A caller that switched a node from `Named` to `Path` lost
  `/etc/netns/<ns>/hosts` resolution with no error. `Path` now gets
  the overlay whenever the path is an entry of `NETNS_RUN_DIR` (its
  file name is the `ip netns` name the overlay directory is keyed by;
  `/var/run` and `/run` spellings both count). A path elsewhere and
  `Pid` (`/proc/<pid>/ns/net`) have no name and therefore no overlay
  to apply — that is now stated as such, not as a fallback, and the
  new `NamespaceSpec::etc_overlay_name()` tells a caller which case a
  spec is in before it spawns. Live test: a `Path` spec sees the
  overlaid `hosts`, a `Pid` spec for a process in the same namespace
  does not.

- **`spawn_*_with_etc` failed with `EPERM` inside containers whenever
  `/etc/netns/<ns>/` existed (#334).** The sysfs remount was fatal
  (#282 made it so, correctly: a child with *no* `/sys` is worse than
  one with a stale `/sys`), and inside Docker/Podman it always failed —
  `/sys` there is a read-only `nosuid,nodev,noexec` bind the runtime
  will not let go of, and the kernel's `mount_too_revealing` refuses a
  fresh sysfs that is less restrictive than the one already visible.
  So the moment a caller added a per-namespace `hosts` file, every
  exec in that namespace stopped working, while plain `spawn` kept
  working. Seven of nlink-lab's integration tests failed this way on
  its CI runner.

  Two changes. The replacement sysfs now copies the read-only /
  `nosuid` / `nodev` / `noexec` flags of the `/sys` it is replacing
  (`ip netns exec` copies read-only alone; the kernel locks all four).
  And the rule for the remount is now stated and followed: **never
  run with no `/sys`, never refuse to run over a merely stale one.**
  If the detach failed and the mount fails too, the host's `/sys` is
  still in place, so the exec proceeds and the `/etc` binds still
  apply; if the detach succeeded and the mount fails, the child would
  have no `/sys`, and that stays fatal. Bind-mount failures stay
  fatal. The `spawn_with_etc` rustdoc now lists which steps are fatal
  — it said "requires `CAP_SYS_ADMIN`", which is necessary and not
  sufficient. The flag mirroring is unit-tested; a real container
  refusal cannot be reproduced in this suite.

- **`PlugConfig::new().build()` could not install a plug qdisc (#327).**
  With no limit set, `write_options` wrote nothing — but the connection
  opened and closed the `TCA_OPTIONS` nest unconditionally, so the kernel
  received an *empty* nest rather than *no* nest. `plug_init` treats those
  differently: absent means "size the buffer as `txqueuelen × MTU`", empty
  means `nla_len(opt) < sizeof(tc_plug_qopt)` and `EINVAL`. So the form
  the type's own `new()` produces, and `nlink-tc qdisc add ... plug` with
  no arguments, failed every time, and there was no spelling at all for
  the kernel's default limit. `limit(0)` is not that spelling — it is a
  blackhole (`plug_enqueue` admits nothing past a zero limit), which the
  field's doc now says.

  `QdiscConfig` gains `has_options()` (default `true`); a config that
  returns `false` sends no `TCA_OPTIONS`. It is opt-in rather than a
  blanket "skip empty nests" because the kernel disagrees with itself per
  kind: `drr` and `qfq` classes refuse a missing nest and read their
  defaults from an empty one. `PlugConfig` returns `false` when `limit`
  is `None`; nothing else changes on the wire. The check that was
  missing: a live test installs the no-limit plug as a netem leaf, sends
  traffic into it and asserts the packets are held (backlog > 0, drops
  == 0) — the property that separates the default from the blackhole.

## [0.26.0] - 2026-09-10

### Added

- **`Connection::<Ethtool>::get_string_set` (#276).** String sets are
  how the kernel names what it otherwise reports by index — statistic
  names, private-flag names, feature names, link-mode names.
  `EthtoolCmd::StrsetGet`, `EthtoolStringSet`, the three attribute
  enums and the `StringSet` result struct were all defined, and **none
  of the 44 public methods on `Connection<Ethtool>` issued the command
  or returned the type**, so `EthtoolStringSet` had zero non-test
  references. The enum's own rustdoc describes query behaviour in the
  present tense, so a reader concluded the API existed and could not
  find it.

- **Plug qdisc control: `plug_buffer`, `plug_release_one`,
  `plug_release_indefinite`, `plug_set_limit` (#276).** The plug
  qdisc's whole purpose is buffer/release control and installing it
  **starts buffering immediately**. `PlugConfig::write_options` emitted
  only `TCQ_PLUG_LIMIT`, and the doc example called `plug_buffer` and
  `plug_release_one` — neither of which existed anywhere in the
  workspace. So the library let you stall an interface with no
  library-side way to unstall it.

- **Kernel-side uevent prefiltering: `UeventFilter` (#251).** A uevent
  monitor interested in one subsystem was woken for every USB, block,
  input and thermal event on the box, copied each into userspace and
  parsed it into a `HashMap` before discarding it. `UeventFilter`
  describes what the caller wants and `compile()` lowers it to a
  classic-BPF program attached with the new
  `NetlinkSocket::{attach_filter,detach_filter,lock_filter}`.

  `libudev`'s trick — hashing the subsystem and matching against the
  `udev_monitor_netlink_header` — does not apply here: that header
  belongs to udevd's group-2 rebroadcast, while nlink subscribes to
  group 1, the kernel's own uevents, which carry no header. What makes
  exact filtering possible instead is the kernel's fixed layout.
  `kobject_uevent_env()` emits `ACTION`, `DEVPATH` and `SUBSYSTEM`
  first and in that order, behind an `"<action>@<devpath>\0"` prefix,
  so `action` is a fixed-offset match at 0 and the `SUBSYSTEM=` key
  sits at exactly `2H + 17` for `H` the first NUL — one unrolled scan
  and then arithmetic. `DEVTYPE` and arbitrary `KEY=VALUE` land after
  the fixed three in no guaranteed order and stay in userspace;
  `CompiledUeventFilter::is_exact` says which case you are in.

  The program is an over-approximation by construction — it accepts
  whatever it cannot decide — so `UeventFilter::matches` is the
  authority. `Connection::<KobjectUevent>::recv_matching` applies both
  halves.
- **`Connection::<KobjectUevent>::{in_namespace,in_namespace_path}`.**
  Net-device uevents are delivered to the netns of the listening
  socket, so a monitor for a namespace's devices needs its socket
  opened there. The generic `namespace::connection_for` cannot serve
  this protocol (`KobjectUevent` deliberately has no `Default`, so a
  connection can't exist unsubscribed); `subscribe()` is now public
  for connections built another way.
- **Uevent re-enumeration: `util::uevent_trigger` (#252).** Uevents
  are the crate's only event source that can drop frames with no path
  back to truth: `events_with_resync` needs a redump factory and
  `NETLINK_KOBJECT_UEVENT` is broadcast-only — there is no
  `GETUEVENT`. The kernel's substitute is a write to
  `/sys/.../uevent`, which is all `udevadm trigger` is.
  `UeventTrigger` wraps that, and `resync_factory` plugs it into the
  existing resync machinery.

  It lives in `util` because the sysfs audit gate keeps `/sys` access
  out of the protocol layer, and it comes with three warnings in its
  rustdoc rather than a friendly surface: triggering needs root while
  *reading* uevents does not, so the recovery path is more privileged
  than the stream it repairs (`can_trigger()` exists to be called at
  startup, not at overflow time); a write broadcasts to every listener,
  so udevd re-runs its full rule set for each device touched; and it is
  best-effort re-announcement, not a snapshot — `ResyncEnd` here means
  "a re-announcement was requested", not "state is rebuilt".
  `ResyncMarker`'s docs now carry that caveat.
- **Netdev lifecycle join: `netlink::netdev` (#253).** rtnetlink knows
  a device's ifindex, flags, MTU and kind but nothing about its driver
  or sysfs path; uevents know the driver and devpath but carry no link
  attributes, and driver bind/unbind has no rtnetlink counterpart at
  all. Net uevents carry `IFINDEX=`, so the two share a primary key.
  `NetdevLifecycle` merges both sockets into one `NetdevEvent` stream
  and optionally mirrors it into a `Store<u32, NetdevInfo>`.

  Four decisions are recorded in the module docs, the recipe, and the
  tests. rtnetlink is authoritative for existence and uevents annotate,
  with a late-arriving annotation surfacing as `Changed` rather than
  being buffered behind a timeout that may never fire. ifindex reuse is
  caught by cross-checking the uevent's `INTERFACE=` on the `Added`
  transition only — enforcing it on every event would discard good
  annotations mid-rename, which `is_fully_attributed()` reports instead.
  The devpath is carried as a string and never resolved, because sysfs
  resolves in the mount namespace while the ifindex resolves in the
  network namespace. And inside a netns you see net uevents and nothing
  else, since other subsystems broadcast only to the initial namespace.

  New recipe: [`netdev-lifecycle`](docs/recipes/netdev-lifecycle.md).
- **`Store::{upsert,remove}`.** The reflector path drives a store from
  a resync-aware stream; `NetdevLifecycle` joins two sockets and owns
  its own notion of when a device exists, so the write primitives are
  public for sources that maintain the cache themselves.

### Fixed

- **`destroy_matching` took an `InetFilter` no public API could produce
  (#317).** `Connection::<SockDiag>::destroy_matching` takes `&InetFilter`,
  and there was no way in: `SocketFilter::tcp()` returns an
  `InetFilterBuilder` that was not re-exported, its `build()` yields a
  `SocketFilter` wrapping the filter in a `FilterKind` that was not
  re-exported either, and nothing gave the inner filter back. A struct
  literal compiled only because every field happens to be `pub` — not a
  guarantee anyone had stated, and one `#[non_exhaustive]` would have
  removed.

  `InetFilterBuilder::build_inet()` is the route in, and `FilterKind` plus
  the four filter builders are re-exported so a built `SocketFilter` can be
  taken apart again:

  ```rust
  let filter = SocketFilter::tcp()
      .states(&[TcpState::TimeWait])
      .build_inet();
  conn.destroy_matching(&filter).await?;
  ```

  Same class as #280 and #316 — a public signature whose argument the public
  API could not name or make. Found because `DestroyResult`'s doc example
  called `destroy_matching(&filter)` with `filter` never bound, so it had
  never had to name the type (#304).

- **The recipes compile now, and 37 of their 91 Rust blocks did not (#319).**
  Nothing had ever compiled `docs/recipes/`. The only check was
  `scripts/audit-recipe-drift.sh`, a grep for known-stale shapes whose own
  header called it a stop-gap for "a synthetic compile-fixture per recipe
  block".

  That fixture needs no generator: `src/recipe_doctests.rs` pulls each recipe
  in with `#[doc = include_str!]` under `#[cfg(doctest)]`, and rustdoc
  compiles every fenced Rust block in it. What that found, beyond the same
  missing-context errors #304 turned up:

  - `MirredAction::redirect_egress("ifb_eth0")` — the by-name form has never
    existed; mirred takes an ifindex.
  - `conn.del_link_by_name(...)`, `conn.subscribe_links()` — neither method
    exists. The second recipe was hand-rolling what `del_link_if_exists`
    does.
  - `del_sa(&dst, spi, proto)` against a four-argument `del_sa(src, dst, spi,
    proto)`, and `update_sa(&sa)`/`add_sa(&sa)` where both take the builder
    by value.
  - `use nlink::netlink::protocol::Route` and `use nlink::Netfilter` —
    private module, wrong path.
  - `v.vid`, `addr.ifindex`, `addr.address` as fields, years after the
    accessor convention moved them to methods.
  - `ReconcileOptions { .. }` and `ApplyOptions { .. }` struct literals on
    `#[non_exhaustive]` types — code no downstream reader could have written.
  - Two ASCII diagrams fenced as ```` ``` ````, which rustdoc reads as Rust.

  One that is worth its own line: the `bidirectional-rate-limit` recipe
  called `MatchallFilter::actions(...)`, which did not exist until #313 was
  fixed in this same release. The recipe had been describing the API the
  library should have had.

  Blocks that are genuinely fragments — a continuation starting with `.`, a
  diagram, the step-by-step excerpts in `define-your-own-genl-family.md` —
  are ```` ```text ````. That last recipe's finished file is compiled
  already, as `examples/macros/define_taskstats.rs`, and the recipe now says
  so.

  `audit-recipe-drift.sh` is **removed**: every pattern it grepped for is a
  compile error now. `audit-doc-examples.sh` widens to cover the examples,
  the bins, `nlink-macros` and the recipes — a stray ```` ```ignore ```` had
  already been living in `examples/macros/define_taskstats.rs`, outside the
  gate's original `crates/nlink/src` scope.

- **508 doc examples were ```` ```ignore ````; they are ```` ```no_run ```` now,
  and 24 of them did not compile (#304).** `ignore` renders a block and never
  compiles it, so an example rots silently against every rename, signature
  change and typed-unit migration. What the conversion turned up, in the
  library's own documentation:

  - `conn.add_qdisc("eth0", TcHandle::ROOT, cfg)` — three arguments to a
    two-argument method, left over from before `add_qdisc` took the parent
    from the config.
  - `.egress("100mbit")?`, `.loss(0.1)`, `.quantum(1500)` — the tc(8)-string
    and bare-number forms the 0.15 typed-unit migration replaced with `Rate`,
    `Percent` and `Bytes`. The `?` is still there from the parsing API that
    went with them.
  - `QfqConfig::new().handle(…)` and `DrrConfig::new().handle(…)` — neither
    config has ever had a `handle` setter; both carry no options at all.
  - `use nlink::netlink::protocol::Route` — a private module. Also
    `nlink::netlink::neigh::NeighborState` and `nlink::netlink::route::RouteType`
    (#316), `nlink::netlink::MptcpEndpointBuilder`, and
    `Connection::<Connector>::new_proc_events()`, which never existed.
  - `use rip_tuntap::{TunTap, Mode};` — the crate's name three renames ago.
  - `events()` and `into_events_with_resync()` called synchronously, five
    releases after 0.19 made them async.
  - `apply_netem`'s summary, description and example attached to
    `plug_buffer` for want of one blank `///` line (#311, fixed in #312).

  Each is a reader following the documentation into a compiler error. None
  would have survived a single `cargo test`.

  Five of them were not documentation bugs at all — the examples were
  describing a library that could not do what they said: #310 and #315
  (methods that overflow rustc's recursion limit in a caller), #313
  (`MatchallFilter` could not carry actions), #316 and #317 (argument types
  the public API cannot name or produce).

  **The systemic half.** `scripts/audit-doc-examples.sh` is a new CI gate
  that fails the build on any ```` ```ignore ````, and the all-features job
  now runs `cargo test -p nlink --all-features --doc` so feature-gated
  examples are compiled too — the default-feature `test` job was missing 40
  of them. `text` remains available for a block that is not Rust.

- **The recursion-limit class is closed at its source, not per method
  (#315, revising #310's fix).** #310 boxed three netem wrappers. The
  follow-up found the same failure in `RateLimiter::{apply,remove}`,
  `PerHostLimiter::{apply,remove}` and `PerPeerImpairer::apply` — so the
  per-method fix was going to be permanent whack-a-mole, one round per
  convenience wrapper anyone adds.

  A single `Box::pin` on `Connection::send_dump` closes all of it. That is
  where nlink's future-layout depth lives, and every mutating helper reaches
  it too — resolving an interface name before it sends anything. The nine
  per-method boxes from #310 and the first cut of #315 are gone; the
  behaviour they bought is now inherited by every caller and every wrapper
  written from here.

  Measured rather than assumed: removing the box from `send_request` or
  `send_ack` does *not* overflow, so neither is boxed; boxing per-wrapper
  does not work at all, because those helpers await several deep chains and
  lowering one sibling leaves the maximum where it was.

- **`RouteType` and `NeighborState` can be named from the modules whose
  builders take them (#316).** `Ipv4Route::route_type` and `Neighbor::state`
  are public methods whose argument types were only reachable through
  `netlink::types::`, or — for `NeighborState` — under the renamed
  `neigh::State`. Every doc example in those two modules imported them from
  the module itself, which did not compile. Both are re-exported there now;
  the existing paths still work.

- **`MatchallFilter` could not carry actions (#313).** `cls_matchall` matches
  every packet and carries no keys, so the action list is essentially the
  whole point of installing one — "mirror everything to this port", "police
  everything on ingress", "run this BPF program on every packet". nlink's
  `MatchallFilter` had no `actions` field and no setter; of the filter types
  only `FlowFilter` held an `ActionList`. Two doc examples (on `BpfAction`
  and `SimpleAction`) showed the `.actions()` call anyway. Both were
  ```` ```ignore ````, so nothing ever compiled them (#304).

  `MatchallFilter::actions(ActionList)` now exists. It composes with
  `goto_chain` rather than fighting it: both live in `TCA_MATCHALL_ACT`, so
  they share one nest with the goto emitted last — the order `tc(8)` uses
  and the order the kernel runs them in. Writing the attribute twice would
  have left the kernel to keep one nest and silently drop the other, which
  is why the regression test asserts the emitted bytes rather than a return
  value.

- **`del_netem`, `apply_netem` and `plug_buffer` could not be called from a
  small program at all (#310).** A caller got

  ```
  error: queries overflow the depth limit!
    = note: query depth increased by 130 when computing layout of
            `{async block@src/main.rs:...}`
  ```

  pointing at their own async block, with no mention of nlink — and no
  attribute nlink could set fixed it, because the limit belongs to the
  caller's crate.

  Every `async fn` that awaits another embeds the callee's future in its
  own, so rustc computes the layout by recursing once per level. The
  request chain already sat close to the default limit of 128, and these
  three wrappers are one frame deeper than the methods they call
  (`del_netem` → `del_qdisc` → `del_qdisc_full` → `send_ack` → …).
  `del_netem_by_index`, which skips the `InterfaceRef`-resolving layer, was
  fine. So the boundary was arbitrary: the whole API sat one frame under
  the ceiling. Each of the three now `Box::pin`s its inner await, which
  ends the recursion there — one allocation on a path that already does a
  syscall round trip.

  **Why nothing caught it.** Layout queries are cached, so a program that
  touches nlink anywhere else computes these layouts on a shallow stack
  first and hits the cache later. nlink's own tests, its binaries and its
  larger examples all did — including `route_tc_netem`, which calls two of
  the three. Only a program with nothing else in it hits the deep path
  first, which is exactly the shape of a small downstream tool. The guard
  is therefore a deliberately minimal example,
  `route_tc_minimal_caller`: it calls the three methods and does nothing
  else, and adding anything to it weakens it. (It guards the `send_dump`
  box that replaced the per-method fix — see #315 above.)

- **`apply_netem` was undocumented and `plug_buffer` was mislabelled
  (#311).** One missing blank `///` line joined `apply_netem`'s summary,
  description and example onto the doc comment of `plug_buffer`, ~50 lines
  above it. On docs.rs `plug_buffer`'s one-line summary — the line the impl
  page lists it by — read "Apply a netem configuration to an interface",
  its only example called a different method, and `apply_netem` itself had
  no documentation at all. The block moved down to the method it describes.

- **Parser-robustness fuzzing extended past six parsers (#279).** The
  property harness covered `MessageIter`, `AttrIter`, the fixed-size
  struct readers and exactly six typed RTNetlink parsers, out of roughly
  377 parse functions. Unfuzzed: nftables `RuleExpr` decoding (the
  newest and most intricate), conntrack, xfrm, uevent, and every
  `EventSource::parse_events` — the multicast entry points, which is
  where the policy's "one malformed frame must not kill a long-lived
  subscriber" is actually decided.

  Arbitrary bytes turned out to be a weak generator here: the walkers
  reject them early, so the parser code *after* `AttrIter` — where the
  yield was predicted — is barely reached. The harness now also builds
  **structurally valid** attribute chains with adversarial ids, lengths
  and payloads, and wraps them in well-formed netlink frames for the
  event parsers.

  **It found nothing.** 30,000 cases per property across every parser
  added, clean. Reported as a result rather than a non-event: the
  parsers hold, and the harness is now what keeps them holding.
  Mutation-verified — an unguarded fixed-size read injected into
  `parse_expressions` is caught.
- **Standalone TC actions used the wrong fixed header (#300).** The
  action API is the one TC surface that does not use `struct tcmsg`:
  `tc_ctl_action` parses attributes from `sizeof(struct tcamsg)` — four
  bytes — onward. nlink sent a 20-byte `tcmsg`, so the kernel skipped 4
  and read the remaining 16 as the start of the attribute chain, never
  found `TCA_ACT_TAB`, and refused **every** `add_action` /
  `del_action` / `get_action` / `dump_actions`:

  ```text
  header=20B: errno=-22  "Netlink action attributes missing"
  header=4B:  errno=-22  (past the check, on to the payload)
  ```

  `action_attr_slice` skipped 20 on the read side too, so the two halves
  were wrong together and looked self-consistent — its comment even
  noted that `tcmsg` is "4 bytes minimum" while the writer sent 20. New
  `TcaMsg` type, 4 bytes, used by all eight sites.

- **`add_address` failed for every `127.0.0.0/8` address (#293).**
  `inet_rtm_newaddr` rejects a loopback prefix at any scope but
  `RT_SCOPE_HOST`, and both constructors hardcoded `Scope::Universe`:

  ```text
  scope=0   (UNIVERSE): errno=-22  "ipv4: Invalid scope value"
  scope=254 (HOST):     errno=0    OK
  ```

  The scope is now derived from the address the way `iproute2` derives
  it; `.scope()` still overrides.

- **Public types that could not be named downstream (#280).** Each
  appears in a public signature or a public field while living in a
  private module, so a downstream crate could see it and not name it.
  Sharpest: `Error::validation` takes
  `impl IntoIterator<Item = ValidationErrorInfo>` and
  `ValidationErrorInfo` was not exported — **the public constructor was
  uncallable**. Also now reachable: `config::{ApplyError, LinkChanges}`
  (`ApplyResult` is `Serialize` under `serde`, so `ApplyError` was in
  the JSON ABI while unnameable in Rust), `tuntap::{TunTapInfo,
  list_devices}` (the feature's only enumeration API — both carried
  `#[allow(dead_code)]`, so the compiler already knew), and
  `output::{JsonBuilder, format_number, format_rate}`.

- **`with_dispatcher` documented a limitation that does not exist
  (#276).** It said `dump_stream` and the `*_with_resync` wrappers are
  "not yet supported" in dispatcher mode and "return a clear
  `Error::NotSupported`". Both halves were false: `DumpStream::new`
  handles dispatcher mode explicitly, the crate's own
  `dispatcher_mode_dump_stream_streams_links` test asserts it end to
  end, and no streaming path constructs `Error::NotSupported` anywhere.
  The mirror image of the `try_recv` bug: readers avoided a working
  feature — opening a second socket per netns, or materialising whole
  route tables eagerly — and anyone who wrote `if e.is_not_supported()`
  around it has unreachable code.

- **The `tuntap-async` feature gated zero code (#276).** Declared in
  `Cargo.toml`, documented in `lib.rs`, included in `full`, and with no
  `#[cfg(feature = "tuntap-async")]` anywhere in the crate and no
  `create_async` symbol. The module doc demonstrated
  `create_async().await` against a crate name (`rip_tuntap`) that does
  not exist. A user enabling it got no async API and no way to tell
  whether they had mistyped it. **Removed**, with a note pointing at
  `AsyncFd` for readiness-driven I/O.

- **Ten doc examples that could not compile (#280).** All inside
  ```` ```ignore ```` blocks, so nothing checked them — and they are the
  crate's most-read examples. One taught an **8× wrong unit**
  (`TbfConfig::new().rate(1_000_000)` where `rate` takes `Rate`, which
  is bytes/sec, so the "1 MB/s" comment described a value the type no
  longer accepts). Two called methods that do not exist
  (`set_link_up_by_name`, `NexthopGroupBuilder::add_member`). Corrected
  — and the ones on the `Connection` methods are now ```` ```no_run ````
  so they are compiled by `cargo test --doc` and cannot rot again.

- **`OutputOptions::{color, details, numeric}` documented as library
  behaviour (#276).** Nothing in `output/` reads them, so `color: true`
  looked like it would emit ANSI and `numeric: true` like it would stop
  resolving names. They are *not* dead, though — the `bins/` read them
  through their own `Printable` impls (`nlink-bridge` for `details`,
  `nlink-ss` for `numeric`), which is why they are documented rather
  than deleted as the issue suggested.

- **CLAUDE.md's stale claims.** "Active work" still described 0.24.0 as
  the open cycle, and the testing section still said `has_module()`
  checks `/sys/module/<name>` "so it works for both loadable and
  built-in features" — which is exactly the false premise behind #273.
- **`ifb_name()` could panic, and collided (#281).** `&self.dev[..11]`
  is a **byte** slice on a `String`, so a device name with a multi-byte
  character near the cut panicked — and any two devices sharing an
  11-byte prefix mapped to the same IFB, so removing shaping on one
  tore down the other's. Long names now get an FNV-1a suffix (FNV, not
  `DefaultHasher`, because the name must survive across process
  invocations and std reserves the right to change its algorithm) and
  the slice lands on a char boundary by construction.

- **nftables `apply` added flowtables *after* the rules (#281).** A rule
  carrying `flow add @ft` for a flowtable created in the same diff is
  validated at commit time, so the whole atomic batch failed. The
  module docstring stated the same wrong order, so doc and code agreed
  with each other and not with the dependency.

- **nftables `send_batch` aborted on an unrelated malformed frame
  (#281).** `msg_result?` ran *before* the seq-window filter, so on a
  connection also subscribed to nftables multicast, one malformed
  broadcast frame surfaced as an error out of `commit()` — even though
  the batch may well have committed. Now skipped, matching the
  request paths in the same file.

- **`WireguardConfig::diff` was never empty when a private key was
  declared (#281).** It marked the key dirty on the stated premise that
  the current value "can never be compared". The premise does not hold:
  `parse_device_attr_scalar` reads `WGDEVICE_A_PRIVATE_KEY`, the kernel
  returns it to a `CAP_NET_ADMIN` `GET_DEVICE`, and the all-zeros
  normalisation already distinguishes "unset". So any supervisor loop
  treating "diff non-empty" as drift rewrote the private key on every
  tick, and "the second apply is a no-op" could not be asserted. It is
  compared now; if the kernel does withhold it, the key is written,
  which is the old behaviour for exactly the case that justified it.

- **The ovpn peer `local` endpoint was never diffed (#281).**
  `peer_matches` compared `remote`, `vpn_ipv4`, `vpn_ipv6` and the
  keepalives — not `local`, which is stored, encoded on create, and read
  back on dump. Changing it was a silent no-op that `apply_reconcile`
  then reported as successful convergence. `OvpnPeer::local_socket()` is
  new, mirroring `remote_socket()`.

- **A declared route out of a not-yet-created interface matched any
  kernel route (#281).** `name_to_ifindex` is built from the *pre-apply*
  link dump, so a config declaring both a link and a route out of it
  resolved `declared_oif` to `None` on the first pass — and the
  "kernel picked the oif itself" arm then accepted any kernel route at
  the same `(dst, prefix, table)`. Declaring `vx0` plus
  `10.0.0.0/8 dev vx0` on a host that already had `10.0.0.0/8 dev eth0`
  omitted the route entirely; a second apply fixed it. "Declared a dev
  we cannot resolve yet" is now distinguished from "no dev declared".

- **`predicate_filter` swallowed the first replayed item of a resync
  (#281).** `last_key` was carried across the `ResyncStart` boundary, so
  if the last live event before `ENOBUFS` and the redump's first item
  were for the same object, the replayed copy was deduped away —
  immediately after the consumer had been told to invalidate its state.
  `ResyncStart` now clears the dedup memory. The existing test pinned
  the old behaviour, so this is a deliberate contract change: a resync
  replay is a fresh snapshot, and nothing before it is a duplicate of
  anything in it.

- **`ReflectExt` left `staging` populated on a stream error (#281).**
  With a resync window still open, every later event diverted into
  staging instead of the store and the cache silently froze — still
  answering, with stale data. Not reachable through the crate's own
  `ResyncStream`, but `reflect` is blanket-implemented for any
  `Stream<Item = Result<ResyncedEvent<V>>>`, so a caller composing their
  own was exposed.

- Removed a leftover stub in the nftables rule diff and fixed a broken
  intra-doc link that pointed at a private field (#281).

- **A failed dump reported success with a truncated result (#267).**
  `NLMSG_DONE` carries the dump's result code as an `int` payload, and
  nothing read it. Measured on this kernel:

  ```text
  RTM_GETLINK            -> NLMSG_DONE nlmsg_len=20, payload i32 = 0
  SOCK_DIAG_BY_FAMILY    -> NLMSG_DONE payload i32 = -2   (-ENOENT)
  (sdiag_protocol = DCCP or SCTP, neither of which has a diag handler here)
  ```

  Not `NLMSG_ERROR` — `NLMSG_DONE`. The failure is reported *only*
  there, which is why `sockdiag.rs`'s `NLMSG_DONE => return Ok(sockets)`
  turned a query the kernel refused into "no sockets found". iproute2
  reads it in `rtnl_dump_done()` and aborts on a negative value.

  Any dumper that failed partway yielded a partial list indistinguishable
  from a complete one — worst on the declarative paths, where
  `NetworkConfig`/`NftablesConfig::diff()` builds a plan from a dump:
  objects that exist become invisible and the diff proposes creating
  them, and with purge enabled it proposes deleting what it never saw.

- **`NLM_F_DUMP_INTR` was checked in four dump paths and missing from
  five (#271).** The crate had already decided this mattered — there is
  an `Error::DumpInterrupted`, with tests — and then checked it in fewer
  than half the loops. The unchecked ones were the sharp ones:
  `dump_stream` (the generic path behind `dump_stream::<T>()` and the
  `*_with_resync` wrappers, so it feeds the `Store` watch-cache, which
  `replace_all`s its whole map from a redump) and the nftables dumps
  that `diff()` turns into a **single atomic** apply.

  Both fixes live in one place: `netlink/dump_frame.rs` classifies a
  frame — seq filter, torn snapshot, ACK, error, DONE-with-result-code,
  data — and the loops act on the classification. The pattern behind
  these two bugs was diagnostic: the two *older* invariants (filter by
  `nlmsg_seq`, terminate on DONE) were in every copy of the loop and the
  two newer ones were not, because there were nine copies in three
  shapes. `scripts/audit-dump-termination.sh` is the new CI gate; a
  hand-rolled `is_done()` outside the classifier fails the build.

  The `devlink_get` loop, alone among its siblings, treats an ACK as the
  end of its response. That is preserved deliberately rather than
  normalised away — it is sent with `NLM_F_ACK` and answers with a
  single message — and now says so.

- **A torn redump fused the resync stream (#271).** Once nftables
  actually checked `NLM_F_DUMP_INTR`, the post-`ENOBUFS` redump started
  failing — correctly: it races the very mutations that overflowed the
  socket, so a torn snapshot there is the ordinary case. Fusing on it
  would mean a watch-cache gives up precisely when it is busiest, so the
  redump now retries — up to thirty times, 50 ms apart. Spread over
  time rather than spun: retrying a dump in a tight loop against a
  mutating kernel burns the whole budget in microseconds and then
  reports failure while the storm is still running. With the delay the
  integration test that fires 2000 rule inserts at a 256-byte rcvbuf
  recovers; without it, no attempt count is enough.
- **The operation timeout was a total budget on eager dumps and absent
  entirely on streaming ones (#272).** `with_timeout` wrapped the whole
  future, so for a multi-message dump the 30s default was a limit on
  *duration*, not on silence: a legitimately large dump — conntrack with
  millions of entries, a full BGP table, a big nftables ruleset — failed
  with `Error::Timeout` while the kernel was streaming perfectly well,
  and the caller could not tell "the kernel hung" from "this table is
  big" — which is the distinction the timeout was introduced to draw.
  Meanwhile `dump_stream` had no timeout at all: being poll-based it
  stayed `Pending` forever on a stalled kernel, the exact failure the
  default exists to prevent, still open on the newer of the two paths.

  Both are now per-frame deadlines, reset by every frame that arrives.
  A stall is caught as promptly as before; a big dump finishes.

  `RecvSession::recv_with_timeout` now exists. CLAUDE.md's canonical
  recv-loop template — the one every new loop is told to copy — has
  always named it, and it had **zero occurrences crate-wide**, so code
  written by following the documented template did not compile. The
  template is also updated for the dump classifier.

- **`Batch` dropped operations whose encoding failed, misaligning
  `BatchResults` (#277).** `BatchResults` is documented as "one
  `Result<()>` per operation in submission order", and `errors()` yields
  `(index, &Error)` pairs the caller maps back to what it submitted. An
  op that failed to encode was silently not pushed, so three
  submissions with a bad one in the middle produced **two** results,
  `all_ok() == true`, and index 1 describing the third submission. The
  caller concluded all three were configured. Encode failures now keep
  their slot.

- **WireGuard `get_device` returned a peer twice when its allowed IPs
  crossed a dump boundary (#277).** `wg_get_device_dump` re-emits
  `WGPEER_A_PUBLIC_KEY` on the continuation and sends the scalars —
  `RX_BYTES`, `TX_BYTES`, `LAST_HANDSHAKE_TIME`, `PERSISTENT_KEEPALIVE`,
  `ENDPOINT`, `PRESHARED_KEY` — only in the first chunk. nlink pushed
  every peer unconditionally, so a boundary peer came back once with
  stats and a partial `allowed_ips` and once with zeroed stats, no
  endpoint, and the remainder.

  The knock-on was worse than a duplicate row:
  `WireguardConfig::diff_against` keys the current state by public key,
  so the second, stats-less entry *overwrote* the full one — the
  declared peer was compared against a truncated view, `endpoint_set`
  and `allowed_ips_set` both fired, and `apply()` rewrote that peer on
  **every run**. `wg(8)` coalesces by public key; so does this now.

- **Event streams hot-spun on a dead fd (#277).** The `Direct` arm of
  `EventSubscription`/`OwnedEventStream` returned the error without
  fusing, so once the fd went bad — namespace teardown, `EBADF`,
  `ENOTCONN` — `poll_recv` returned `Ready(Err)` on every poll forever.
  A consumer that logged and continued, or used
  `.filter_map(Result::ok)`, spun at 100% CPU producing an unbounded
  error stream; only one that broke on the first error escaped. It now
  fuses — except on `ENOBUFS`, which is recoverable and which the whole
  resync machinery depends on *not* fusing.

- **`Dispatcher::fail_all` left multicast subscribers hanging (#277).**
  It cleared `pending` and `event_listeners` — the latter added by #202
  for exactly this — and never touched the `subscribers` broadcast
  senders, which stayed alive behind the `Arc`. So after a fatal recv
  error killed the driver, a consumer awaiting
  `subscribe_multicast(g).recv()` — the surface the `*_with_resync`
  wrappers use — parked forever: no error, no `Lagged`, no termination,
  indistinguishable from an idle network. The same bug #202 fixed, on
  the other surface.

- **`spawn_*_with_etc` could leave the child with no `/sys` (#282).**
  The setup detaches `/sys` with `umount2(MNT_DETACH)` and mounts a
  fresh sysfs for the target netns; the mount's failure was swallowed by
  an empty `if`, after the detach had already succeeded. A stale `/sys`
  showing the host's interfaces is bad; **nothing** there is worse,
  because anything enumerating interfaces through sysfs — `util::ifname`,
  which is what the `bins/` use — then fails outright instead of reading
  the wrong thing. The failure now aborts the spawn, as `ip netns exec`
  does.

- **Five setters that were stored and never read (#275).** Each is the
  same shape: a fluent setter accepts a value, the writer never looks at
  it, and the request goes out without it. Nothing errors — `apply()`
  returns `Ok` and reports changes; the interface simply is not what was
  declared.

  - **A declared MAC was never diffed.** `LinkBuilder::address(mac)`
    stored it and `compute_link_changes` compared state, MTU and master
    — not the address — so `.link("eth0", |l| l.address(mac))` on an
    existing interface produced an empty diff *forever*. `LinkChanges`
    gained `set_address` and `modify_link` applies it. On create it was
    silently dropped for VLAN and VXLAN even though both link types
    have an `address` setter.
  - **VXLAN, macvlan and IFB dropped a declared MTU on create.** This
    one broke the apply→converge contract visibly: `apply()` reported
    success and the very next `diff()` was non-empty, because
    `compute_link_changes` caught the MTU on the second pass. `IfbLink`
    also gained the `address` setter it was missing.
  - **nftables `DeclaredSet` key type and flags were never diffed.**
    Sets were matched by name alone, so changing a set's key type, or
    adding `NFT_SET_INTERVAL`/`constant`, produced an empty diff while
    every rule matching `@set` silently mismatched. Chains (#200),
    tables and flowtables (#208) all got this treatment; sets were left
    out of that pass. A set's key type cannot be changed in place, so
    drift now deletes and recreates it — with its elements — in the
    same transaction.
  - **ethtool `advertise()` emitted nothing.** `LinkModesBuilder`
    collected advertised modes into a `Vec<String>` with no read site,
    while a comment in `apply_link_modes` said to wire the setter up
    "when a downstream user asks for it" — the setter had already
    shipped and the rustdoc example already called it. They now go out
    as `ETHTOOL_A_LINKMODES_OURS`. A caller combining `.advertise(...)`
    with `.autoneg(true)` was renegotiating on the *old* advertisement
    and concluding the NIC had ignored it.
  - **MPTCP `dev(name)` resolved nothing.** Documented as "the device
    name will be resolved to an interface index"; the field had zero
    reads and the writer emitted `IF_IDX` only from the separate
    `ifindex`, so an endpoint reached the kernel with **no interface
    binding at all** and the path manager chose addresses on whatever
    interface it liked. The setter is **removed** rather than wired up:
    a `Connection<Mptcp>` cannot resolve a name in its own netns, and
    the only alternative — a `Connection<Route>` in the calling
    process's netns — is the namespace footgun the crate exists to
    avoid. Pass an index resolved through a connection in the right
    namespace.

- **MPTCP endpoint ports were byte-swapped (#275).**
  `MPTCP_PM_ADDR_ATTR_PORT` is host order (the kernel ingests it with
  `htons(nla_get_u16(...))`), and nlink wrote *and read* it big-endian —
  so it round-tripped through nlink perfectly while the kernel held the
  swapped value. `.port(8080)` installed an endpoint on **36895**, which
  is what `ip mptcp endpoint show` reported. Flagged at medium
  confidence and settled by measurement; the regression test asks
  iproute2, because a symmetric swap is invisible to nlink alone.

  `MPTCP_ATTR_SPORT`/`DPORT` stay big-endian and now say why: they are
  from `enum mptcp_event_attr`, which the kernel emits with
  `nla_put_be16` — a different attribute set with a different
  convention.

- **`diagnostics::LinkRates::total_bps` was 8x low (#274).** The fields
  were named `rx_bps`/`tx_bps` while being documented and computed as
  **bytes** per second, and `total_bps()` summed them and called the
  result bits. A "saturated at 1 Gbps" alert built on it did not fire
  until 8 Gbps. Aggravated by the crate having a *second* `LinkRates`
  (in `netlink::stats`) that had it right, while only the wrong one was
  re-exported at the crate root — so `nlink::LinkRates` was the broken
  one. The fields now say `rx_bytes_per_sec`/`tx_bytes_per_sec` and the
  `*_bps()` accessors convert, matching the other type exactly.

- **`min_bytes_for_rate` gated on a packet count (#274).** Named and
  documented in bytes, compared against `rx_packets + tx_packets`. A
  user setting `1_000_000` meaning "1 MB" waited for a million packets
  — roughly 1.5 GB at MTU — so loss and error detection stayed silent
  about 1500x longer than intended. It now compares bytes, and
  `find_bottleneck()` uses the same gate and the same
  `skip_loopback`/`skip_down` filters as `scan()` rather than a
  hardcoded loopback skip, so the two entry points no longer sample
  differently. `scan()`'s `prev_stats` map also evicts interfaces it did
  not sample, instead of retaining them forever and diffing a reused
  ifindex against the previous interface's counters.

- **`has_module` reported most of the kernel as missing, and every miss
  was a silent skip (#273).** It checked `/sys/module/<name>` alone,
  documented as covering built-ins too. It does not: sysfs publishes a
  directory for a built-in only if it exports parameters or a version.
  On the box this was measured on, **179 of the first 200 modules the
  kernel indexes have no `/sys/module` entry**. Nor did it cover a
  loadable module not yet used — `sch_htb` appears the moment something
  asks for an HTB qdisc, but not before.

  Both gaps made `require_module!` skip, and **a skipped test reports
  `ok`**. Not theoretical: the entire `ratelimit` and `impair`
  integration suite skipped on any machine where `sch_htb` had not
  happened to be loaded, which is how a dozen TC bugs rode out a release
  cycle. `has_module` now also consults `modules.builtin` and
  `modules.dep`. On the same box, module skips drop from 11 to 8 — and
  all 8 remaining are `ovpn`, which genuinely needs kernel 6.16.

  `NLINK_TEST_STRICT_MODULES` takes a comma-separated list of modules
  the environment is expected to provide; a skip for any of them becomes
  a failure. The privileged CI workflow sets it to the same list its
  guard step verifies, so a skip there is loud. A list rather than a
  flag, because failing on genuinely-optional features would just teach
  everyone to ignore the job.

- **`ext_ack` was never actually parsed (#292).** `NlMsgError::attrs`
  reads the TLVs at `sizeof(errno) + sizeof(nlmsghdr)` — where they are
  only when the echoed request has been *capped*. `netlink_ack()` caps
  it only if the socket asked, and nlink set `NETLINK_EXT_ACK` but never
  `NETLINK_CAP_ACK`. So the kernel echoed the whole request, the parser
  read request bytes as attributes, and **every kernel rejection reached
  the caller as a bare errno** despite the crate advertising extended-ack
  parsing as a headline feature. Measured on one request:

  ```text
  CAP_ACK off: payload=72B, TLVs at payload[40] -> nothing found
  CAP_ACK on:  payload=52B, TLVs at payload[20] -> "Parent Qdisc doesn't exists"
  ```

  Sockets now set `NETLINK_CAP_ACK` (kernel 4.3+, best-effort), which
  also shrinks every ACK by the size of the request. The unit tests could
  not have caught this — they synthesise the capped payload, a shape the
  kernel was not sending — so the regression test is an integration one
  that asks the kernel for a real rejection and demands the message.
- **TC class and filter dumps were always empty (#286).** `get_classes`
  and `get_filters` built their request from a zeroed `tcmsg`, so
  `tcm_ifindex` was 0 — and `tc_dump_tclass`/`tc_dump_tfilter` both open
  with `dev_get_by_index(); if (!dev) return 0;`. Not an error: an empty,
  successful dump, every time. `get_classes_by_index` and
  `get_filters_by_index` filtered that empty list client-side, so they
  inherited it, and so did `dump_live_tree` — which is why **every
  `reconcile()` in the crate believed nothing was installed** and re-added
  every class, leaf and filter on every pass. The requests now name their
  device, and the device-less forms enumerate links (the kernel has no
  "all devices" class dump; this is why `tc class show` requires `dev`).

  A filter dump additionally needs `tcm_parent`: without it the kernel
  walks the root qdisc alone, so ingress and clsact filters never
  appeared — `list_bpf_programs` returned an empty vec on an interface
  with BPF attached. `get_filters_by_index` now sweeps the root plus both
  clsact hooks and the classic ingress slot.

  Filter dumps also stop returning the handle-0 `tcf_proto` skeleton the
  kernel emits ahead of each chain (the bare
  `filter protocol ip pref 1 flower` line in `tc filter show`). It has no
  match criteria and cannot be deleted; returning it doubled every count.

- **`TC_H_CLSACT` was transcribed as `0xFFFFFFF2` (#268).** `pkt_sched.h`
  defines it as a plain alias of `TC_H_INGRESS` (`0xFFFFFFF1`);
  `0xFFFFFFF2` is `TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS)`, the parent a
  *filter* on the clsact ingress hook uses. `clsact_init` answers
  `EOPNOTSUPP` for any qdisc parent but `TC_H_INGRESS`, so **every
  `attach_bpf` call failed**, and a `clsact` in a `NetworkConfig` was worse
  than that: `QdiscBuilder::clsact()` left the parent at the `Root`
  default, so `apply` deleted the interface's real root qdisc and *then*
  failed to install the hook, leaving it bare.

  `TcHandle::CLSACT` is now `TC_H_INGRESS`, with `CLSACT_INGRESS` and
  `CLSACT_EGRESS` for the two filter parents. `QdiscConfig` grew
  `fixed_parent()`, which `add_qdisc`/`add_qdisc_by_index` honour, so the
  short form can no longer send a hook qdisc to `TC_H_ROOT`. The audit
  gate now covers `mod tc_handle` (`tc_handle = TC_H` in the modmap), so
  this particular drift cannot return.

- **`RateLimiter` shaped nothing at all (#258).** The HTB qdisc was created
  with `default_class(0x10)` — 16 — while the class it names was created at
  `TcHandle::new(1, 10)`, decimal 10. `htb_classify` could not resolve the
  `defcls`, fell through to `HTB_DIRECT`, and transmitted every packet
  unshaped. `RateLimiter` installs no filters, so that default class was
  the only thing between traffic and the wire.

- **`PerHostLimiter::apply` pointed the HTB default at a rule's class
  (#269).** It set `default` to `n + 1` — the *last rule's* class — while
  creating the real default at `n + 2`. Unmatched traffic was shaped at the
  last rule's rate instead of `default_rate`; with no rules configured it
  named the inner class `1:1` and fell through to `HTB_DIRECT`.
  `reconcile` used `n + 2`, so the two verbs built different trees and
  apply-then-reconcile was never a no-op.

- **`reconcile()` could never bootstrap (#287).** Every interface always
  has a root qdisc — the kernel installs `noqueue`, `pfifo_fast`,
  `net.core.default_qdisc` or `mq` implicitly — so the "nothing installed
  yet" arm was unreachable and all three recipes demanded
  `with_fallback_to_apply(true)` on a bare interface. An implicit root
  qdisc carries handle 0 (`qdisc_create` only allocates a handle for one
  that was asked for); those are now treated as absent. A root qdisc the
  operator actually configured still trips the guard.

- **`reconcile()` failed whenever the rule count changed (#291).** The
  default class used to sit one past the last rule, so editing the rule
  list moved it and the root qdisc's `defcls` had to move with it — via
  `change_qdisc`, and `htb` has no `.change` operation at all
  (`EINVAL`, "Change operation not supported by specified qdisc").
  The default class is now pinned at `1:ffff` with its leaf at `ffff:`,
  independent of the rules, so the `defcls` written at creation stays
  correct for the tree's life. Getting past that exposed a second
  ordering bug: stale classes were deleted before the filters pointing at
  them, and `htb_delete` refuses a class still in use (`EBUSY`). Filters
  now go first.

- **`reconcile()` ignored edited match criteria (#270).** The check
  accepted any live filter at the right priority whose kind was `flower`
  and whose classid was right — and both the priority and the classid are
  derived from the rule's *index*. Editing a rule in place (a different
  address, a different port, v4 to v6) changed neither, so `reconcile`
  reported no changes and left the old criteria classifying traffic
  forever. The new `flower_matches` compares the match keys, byte for
  byte, against what the writer would emit, and rejects a live filter
  that selects on more than was asked for.

- **Flower filters with only L4 keys installed as match-all (#288).**
  `cls_flower` reads `ip_proto` and the port keys only inside
  `if (key->basic.n_proto == htons(ETH_P_IP) || ... ETH_P_IPV6)`, and
  `n_proto` comes from `TCA_FLOWER_KEY_ETH_TYPE` — never from the filter's
  `tcm_info` protocol. `FlowerFilter`'s address setters imply the
  ethertype; the L4 ones did not. So
  `FlowerFilter::new().ip_proto_tcp().dst_port(443)` got a clean ACK and
  matched **everything** — which is what `PerHostLimiter::limit_port`
  built, sending all IPv4 traffic to the first port rule's class.
  `write_options` now refuses to emit an L4 key with no ethertype, and the
  recipe's port rules declare `.ipv4()`.

- **`RateLimiter::ingress` never installed its redirect (#289).** Two
  defects in one function: the request was built with `ack_request`, so it
  lacked `NLM_F_CREATE` and the kernel answered `ENOENT` ("Need both
  RTM_NEWTFILTER and NLM_F_CREATE to create a new filter"); and the
  hand-rolled `tc_u32_sel` payload was 28 bytes where the struct is 32 —
  it treated `__be32 hmask` as 16-bit — which `u32_change` rejects with
  `EINVAL`. It now uses `create_request` and the crate's own `TcU32Sel`.

- **`reconcile()` rewrote every fq_codel leaf on every pass (#290).** The
  target comparison used `==` between the microseconds asked for and the
  microseconds echoed back, but codel stores time in units of 2^-10 s and
  both conversions truncate: 20 ms goes in as 20000 and comes back as
  19999. Comparison now happens in the kernel's own quantisation — the
  same fix as the psched-tick one (#191-#194), for the same reason.

- **`del_filter_if_exists` errored when there was no qdisc (#291).** With
  nothing at `parent` there is nowhere for a filter to live, and the
  kernel says so with `EINVAL` ("Parent Qdisc doesn't exists") rather than
  `ENOENT` — so the not-found arm let it through and the whole point of
  the `_if_exists` variant was lost on any interface with no qdisc.

- **`Connection::<KobjectUevent>::try_recv` always failed (#251).** It
  was public, documented as returning `Ok(None)` when no event was
  waiting, and returned `Error::not_supported` on every call since it
  shipped. It now answers the question it documents, via the new
  `NetlinkSocket::try_recv_msg` — which issues the `recvmsg` directly
  with `MSG_DONTWAIT` rather than through the reactor's readiness
  bookkeeping, since a "try" that returned `None` merely because tokio
  had not yet observed the fd as readable would be useless for draining
  a backlog.
- **Uevent subscribers ran on the ~208 KiB system default receive
  buffer (#251).** `NetlinkSocket::set_rcvbuf` had zero callers in the
  library — its only user anywhere was an integration test *shrinking*
  a socket to provoke `ENOBUFS` — and it went straight to
  `SO_RCVBUFFORCE`, which needs `CAP_NET_ADMIN` and so was unusable by
  the unprivileged monitors that most need it. It now tries `SO_RCVBUF`
  first and escalates only when the readback shows the request was
  capped by `net.core.rmem_max`, swallowing the `EPERM` and keeping the
  best-effort size. `NetlinkSocket::rcvbuf` reports what was granted,
  and `Connection::<KobjectUevent>::new` now asks for 1 MiB
  (`with_rcvbuf` to override). This matters more for uevents than
  elsewhere: it is the one subscriber with no dump to resync from.

- **Endianness: five encoders wrote kernel fields in the wrong byte order
  (#261, #262, #278).**

  **Every FIB lookup resolved the wrong address.** `FibResultNl::for_addr` built
  `fl_addr` — a `__be32` in a natively-serialized struct — with `from_be_bytes`,
  which byte-reverses on any little-endian host: a lookup for `10.0.0.1` asked
  the kernel about `1.0.0.10`. It survived because the accessor was wrong in the
  same direction, so the two errors cancelled in-process and every round-trip
  test agreed with itself; the doc example compounded it by using `8.8.8.8`,
  which reverses to itself. The regression test asserts emitted **bytes** with a
  non-palindromic address.

  **`pedit` edited the wrong bytes of every packet.** `val`/`mask` are authored
  as big-endian-read integers and `struct tc_pedit_key` is serialized natively,
  so they need the swap at pack time — exactly as iproute2's `pack_key32()`
  ends with `htonl()`. Without it `set_ipv4_src(10.0.0.1)` rewrote packets to
  `1.0.0.10`.

  Two setters were also mis-shifted *within* that convention, independently of
  endianness: `set_ipv4_tos` addressed the version/IHL nibble instead of the TOS
  byte, and `set_ipv4_ttl` the high half of the header checksum instead of the
  TTL. The port and MAC setters were already correct, which is what made the
  pattern legible. All twelve setters now have wire-byte tests.

  **`tc_nat`'s mask was a no-op.** It was written as
  `u32::from_be_bytes(mask.to_be_bytes())` — the identity — so a `/24` reached
  the kernel as `0.255.255.255`, matching on the wrong three octets. The
  addresses were byte-reversed by the same mechanism as above.

  **Three writers emitted kernel-native fields as little-endian** — `xfrm`
  algorithm key lengths, hand-built nftables NLA headers, and `fib_rule`
  port ranges. Correct by accident on x86, wrong on the big-endian targets the
  `big-endian-check` CI lane exists to protect.

  `scripts/audit-bytes-le.sh` banned only `from_le_bytes` — the **reader** half.
  That is why the writer half survived: it is the same shape as #212, where
  `normalize_tlv`'s reader was corrected and its writer missed. The gate now
  bans both directions.

- **The rest of the UAPI drift, and two more gate blind spots (#263, #264,
  #265).** Finishing what the widened audit started.

  - **`nha_res_bucket` was off by one.** `NHA_RES_BUCKET_PAD` aliases `UNSPEC`
    at 0 rather than advancing the counter, so `INDEX`/`IDLE_TIME`/`NH_ID` are
    1/2/3, not 2/3/4. The sibling `nha_res_group` had it right, which is what
    made it look like a transcription slip rather than a misreading.
  - **Resilient nexthop group timers were in the wrong unit.**
    `nexthop.h` documents `NHA_RES_GROUP_IDLE_TIMER` and `UNBALANCED_TIMER` as
    `clock_t as u32` — USER_HZ ticks — and nlink passed seconds straight
    through, so a declared 60-second idle timer arrived as **0.6 s**. Same class
    as the psched tick bugs; the crate already does this conversion for
    `BridgeLink::ageing_time`. The unit test asserted the unconverted value, so
    it is re-derived and a second test pins the conversion independently.
  - **`DEVLINK_CMD_PORT_FUNCTION_SET` does not exist.** nlink invented it at 68,
    which is the kernel's `DEVLINK_CMD_TRAP_GROUP_DEL`. Port-function config
    goes through `DEVLINK_CMD_PORT_SET` carrying a `DEVLINK_ATTR_PORT_FUNCTION`
    nest, which is now what `set_port_function_state` sends.
  - **`NL80211_ATTR_MAX_SCAN_SSIDS` was both misnamed and wrong** — the kernel
    calls it `NL80211_ATTR_MAX_NUM_SCAN_SSIDS` and it is 43, not 11. Renamed to
    match, which also brings it under the audit.
  - `seg6_local_action::END_B6_ENCAPS` renamed to `END_B6_ENCAP`, the kernel's
    spelling. The value was already correct; the name is what kept it out of the
    audit.

  Two more gate gaps closed, both of which had been silently narrowing its
  coverage:

  - **Multi-line `#define`s truncated enum parsing.** `devlink.h` contains
    `#define DEVLINK_CMD_ESWITCH_MODE_GET \` followed by its value on the next
    line, *inside* the enum body. Stripping only the `#define` line left the
    continuation dangling, which ended the parse at `DEVLINK_CMD_ESWITCH_GET`
    — so **56 of devlink's 86 commands were never checked**. Continuations are
    now joined first; the count went 30 → 86. Everything newly visible turned
    out to be correct, which is worth knowing rather than assuming.
  - Mapping the `nexthop` and `srv6` modules brought their abbreviated
    constants under the audit for the first time.

  Const coverage across the three PRs: 0 → **1759**.

  Not fixed, deliberately: `seg6_local_flv_op`'s bit positions look one low, but
  only if the `SEG6_LOCAL_FLV_OPERATION` payload is a bitmask of `BIT(ordinal)`
  — and the macro that would settle that lives in the kernel tree, not the UAPI
  headers. Changing a wire value on inference risks breaking working code to fix
  a bug that may not exist, so the module carries a comment saying exactly that
  instead.

- **MACsec: `GcmAes256` configured GCM-AES-128, and no SA operation worked
  (#260).** `netlink/types/macsec.rs` was mis-transcribed throughout — six of
  its thirteen constant blocks were wrong, including two attributes and three
  commands the kernel has never defined.

  The security-relevant one: every cipher-suite id held the *previous* suite's
  value, so asking for `GCM_AES_256` selected **GCM-AES-128**. Silent — the
  reverse mapping was wrong in the same direction, so the returned state agreed.
  The unit test pinned the wrong values too, so the suite stayed green.

  The rest, briefly: `MACSEC_ATTR_SA_CONFIG` was 4 (the kernel's `SECY`), so
  every `add`/`del`/`upd` TXSA and RXSA failed `EINVAL`; `ADD_RXSA` was the
  kernel's `UPD_TXSA`, so adding an RX SA performed a TX SA update; three
  commands were above `MACSEC_CMD_MAX` and returned `EOPNOTSUPP`; the SecY
  encrypt/protect/replay attributes were three-way rotated; and the RX SC and
  per-SA statistics tables were in the wrong order, so packet counts were read
  as octet counts.

  One consequence was worse than a wrong number. RX SC statistics were looked
  up under a top-level `RXSC_STATS` attribute that does not exist; its invented
  value, 3, is `SA_LIST` *inside that nest* — so the parser fed the SA list to
  the statistics decoder and reported SA attributes as counters.

  Also fixed here: `get_device_by_index` folded **every** response of the
  `GET_TXSC` dump into one `MacsecDevice`, concatenating the SAs and RX SCs of
  every MACsec device on the host and leaving `ifindex` holding whichever came
  last. It now returns the requested device, filtering client-side so the
  answer is right whether or not the kernel honours the request's ifindex.

  The audit gate grew two capabilities to cover this class:
  `scripts/audit-uapi-constants.modmap` maps a module to a kernel prefix, for
  constants named with the suffix only — and a mapped module is checked
  *strictly*, so an invented attribute fails the build. Invented names are
  invisible to a value-only check: there is no wrong number to notice.

  The header parser also now strips C integer suffixes. The cipher ids are
  `ULL`-suffixed `#define`s, which it silently failed to parse — so the most
  dangerous constants in this file were unreachable by the audit that was
  supposed to protect them. Stripping the suffix made **942 more kernel
  constants** visible to the gate.

- **41 wrong UAPI constants, and the gate that let them through (#266, #259,
  #263, #264, #265).** `scripts/audit-uapi-constants.sh` checked only
  `#[repr(uN)]` enums — 642 discriminants. But most of the crate's wire
  constants are plain `pub const`s (there are **2039** of them, roughly 3x the
  enum surface), and none were checked at all. Every drift below lived in that
  blind spot.

  The audit now also verifies every `pub const NAME: uN = <literal>` whose name
  the kernel defines **verbatim** — 1573 of them. Exact-name-match is
  deliberately narrow: it needs no mapping table, cannot mis-mangle a name, and
  produced zero false positives. A constant nlink spells differently is out of
  scope for this pass rather than covered by a guess.

  Turning it on found 41 mismatches, all of them real:

  - **bridge**: `IFLA_BRPORT_MCAST_FLOOD` (23→27) and `MCAST_TO_UCAST` (24→28).
    The second was the kernel's `IFLA_BRPORT_FLUSH`, which `br_setport()` acts
    on by calling `br_fdb_delete_by_port()` — so setting `mcast_to_unicast`
    **wiped the bridge port's forwarding database** (#259).
  - **nl80211**: 11 ids, all on live paths — filtered scans emitted
    `STA_LISTEN_INTERVAL`/`STA_SUPPORTED_RATES` nests, the regulatory alpha2
    went out under `ATTR_STA_AID`, power-save used `ATTR_FRAME_MATCH`,
    `set_netns` used `ATTR_TESTDATA`, and the channel-survey dump keyed on
    `ATTR_4ADDR` so it parsed nothing from a real kernel (#263).
  - **devlink**: 8 ids — flash-update progress read msg/done/total out of a VF
    number, a stats blob and a trap name; `PORT_NEW` decoded as `PORT_DEL`
    (#264).
  - **netkit** (5), **nftables `log`** prefix/group swapped (2), **ETS** (3),
    **flower CT keys** (8, all seven too low), **`TCA_HTB_OFFLOAD`** (#265).

  `TCA_HTB_OFFLOAD` is the one worth singling out: it was wrong in *both*
  `types/tc.rs` and `sys_sizeof.rs` — the module whose stated job is to "lock
  the kernel-side values so a future edit cannot silently re-introduce
  off-by-N drift" — and `sys_sizeof.rs` asserted the two wrong values equal each
  other. The guard was hand-transcribed from the same wrong source it was meant
  to guard.

  Where an omitted kernel member caused the shift, it is now listed
  (`IFLA_NETKIT_PRIMARY`, `IFLA_BRPORT_MULTICAST_ROUTER`/`PAD`, `TCA_HTB_PAD`)
  so the gap that caused the slip is visible in the source.

  The gate's self-test gains two cases: a wrong plain const is caught, and an
  nlink-local one is ignored rather than guessed at.

### Changed

- **`schemars` 0.8 → 1.0 (BREAKING for the `schemars` feature; #245).** The
  0.8 API this integrated against is gone: `schemars::gen::SchemaGenerator`
  and `schemars::schema::Schema` moved to the crate root, `RootSchema` was
  removed, `schema_name()` returns `Cow<'static, str>`, and
  `is_referenceable()` became its inverse `inline_schema()`.

  `NetworkConfig::json_schema_value()` therefore returns `schemars::Schema`
  rather than `schemars::schema::RootSchema`. That is the whole of the
  breaking surface, and it is confined to the opt-in `schemars` feature —
  `json_schema()` (the `String` form) is unchanged. The workspace version
  moves to 0.26.0 accordingly, per the mid-cycle-bump convention
  (precedent 041a289).

  **The emitted schema is byte-for-byte the same dialect as before.**
  schemars 1.0 changed its *default* draft from 7 to 2020-12, which would
  have silently invalidated every editor `json.schemas` entry and CI
  validator pointed at this schema. `json_schema_value` now pins draft 7
  explicitly via `SchemaSettings::draft07()` rather than inheriting a
  default that has already moved once, and a new test asserts the
  `$schema` URI and the `definitions` (not `$defs`) subschema map — the
  assertion whose absence is what would have let this through unnoticed.

- **Dependency batch: `rand` 0.8 → 0.10, `netlink-sys` 0.8 → 0.9, `base64`
  0.22 → 0.23, `syn` 2 → 3, `x25519-dalek` 2 → 3, toolchain and MSRV 1.97 →
  1.98 (#243, #246).** Only `rand` needed code changes, and they are in
  WireGuard key generation: `thread_rng()` is gone in favour of `rng()`, and
  `fill_bytes` moved from a root `RngCore` onto `Rng`. Both call sites now go
  through one helper carrying a `CryptoRng` bound — a compile-time assertion
  that the generator behind these keys is cryptographic, since rand has moved
  this API twice and a future move to a non-cryptographic default would
  otherwise produce perfectly plausible-looking keys with nothing to see in
  the output.

  Rust 1.98 also promoted five `chunks_exact`-with-constant-size sites to
  errors under `--deny warnings` (new `chunks_exact_to_as_chunks` lint).
  Converted to `as_chunks::<N>()`, which turns three infallible-but-unproven
  `try_into().unwrap()` conversions into compile-time facts.

- **`x25519-dalek` 2 → 3 (#247).** No code change was required: 3.0's breaking
  changes are edition/MSRV, a removed `Zeroize` impl (secrets are still zeroized
  on drop), removed deprecated `Secret::new()` constructors, and `rand_core`
  0.10 — none of which this uses, and none of which touch key derivation.

  `bins/wg/src/keys.rs` previously had **no tests**, so nothing stood between a
  major bump of the curve implementation and silently wrong keys: a public key
  derived by a subtly different implementation is still 32 plausible bytes that
  base64-encode and round-trip fine, and produces a tunnel that simply never
  handshakes. It now carries RFC 7748 §6.1 known-answer tests, which check the
  changelog's no-derivation-change claim rather than trusting it, plus coverage
  that clamping the input doesn't move the derived key (X25519 clamps
  internally, so `genkey`'s clamped output and an unclamped key from another
  implementation must agree).

- **CI: fleet-standard rollout (myserver#33).** `workflow_dispatch` re-run
  path on CI, tag-input dispatch re-run pattern on the release workflow, a
  `cargo-deny` supply-chain job (new `deny.toml`; advisories, licenses,
  bans, sources), a dispatch-only `publish-crates.yml` lane with a
  semver-checks gate, and `rust-toolchain.toml` pinning 1.97. The
  `nlink-ip`/`nlink-bridge` bins now use `std::io::IsTerminal` instead
  of the unmaintained `atty` crate (RUSTSEC-2024-0375).

## [0.25.0] - 2026-07-15

### Added

- **Path-based netns create/delete: `namespace::create_path` /
  `namespace::delete_path`.** Persist a network namespace at an arbitrary
  bind-mount path instead of the `ip netns` convention `/var/run/netns/<name>`,
  so applications can own their netns directory (clearer ownership, no
  collisions with operator `ip netns add`). `create`/`delete` now delegate to
  the path-based core; behavior for the name-based API is unchanged. On a
  failed `create_path` any parent directory it had to create is rolled back, and
  a live bind mount is torn down before rollback, so a transient unshare/mount/
  restore failure can't leak a half-created tree or a pinned mount. Paths are
  passed to the kernel byte-exact (non-UTF-8 paths are honored, not mangled).
- **Live-netns predicate: `namespace::is_namespace_path` /
  `namespace::is_namespace`.** Infallible `bool` (mirrors `exists`)
  distinguishing a *live* netns bind-mount from a *stale* marker file left by
  an unclean shutdown, via a `statfs(2)` `nsfs`-magic check (`/proc/mounts` is
  unreliable under mount-namespace propagation). Lets a path-based caller
  detect-and-clear a stale marker before `create_path`, which refuses an
  existing path. `is_namespace` is the named wrapper resolving against
  `/var/run/netns/<name>`.

### Fixed

- **nftables: `NftablesConfig::apply` destroyed every table it did not declare
  (#190).** `diff()` scheduled **every table in the kernel** that was not in
  the declared config for deletion, and `apply()` committed those deletes in
  the atomic batch. `NFT_MSG_DELTABLE` cascades — all chains, rules, sets and
  flowtables in the table go with it — and `list_tables()` is unscoped, with no
  ownership marker consulted.

  So on any host also running Docker, firewalld, libvirt or kube-proxy,
  following the declarative-config recipe with a config declaring one table
  atomically destroyed `ip nat` (Docker), `inet firewalld`, `ip6 filter`, and
  everything else on the box. The host lost its firewall and NAT rules in a
  single commit, with no warning and no dry-run prompt. `nlink::lab` was
  shielded only because it applies inside a fresh netns.

  `diff()` now **never** emits table deletions. Purge is opt-in via
  `diff_with_options(&conn, &NftDiffOptions::default().purge_tables(true))`,
  mirroring `DiffOptions::purge` on the `NetworkConfig` side, and is reachable
  only through the explicit diff → inspect → apply flow. The
  [recipe](docs/recipes/nftables-declarative-config.md) sentence "the library
  only deletes what it owns" was true of *rules* and not of tables; it now says
  so, and is now true of tables too.

- **nftables: rules installed in reverse declaration order (#195).**
  `NLM_F_APPEND` was never set on `NFT_MSG_NEWRULE` — the constant was defined
  at `message.rs:237` and used nowhere in the crate. `nf_tables_newrule()`
  appends to the chain tail only when it is set; otherwise it **prepends**.
  nftables is first-match-wins, so this inverted policy: a declared
  `[accept tcp/22, drop]` installed as `[drop, accept]` and **SSH was blocked**.
  No test pinned rule order, which is why it survived; one does now.

- **nftables: `send_batch` discarded mid-batch kernel errors (#199, #209).**
  `Transaction` numbered its inner messages from its own counter starting at 1,
  unrelated to the socket's — so the recv loop's stated invariant ("inner seqs
  are strictly below `begin_seq`") was false, and its one-sided
  `if seq > end_seq { continue }` filter **threw away the `NLMSGERR` for a
  rejected op**. The kernel aborted the batch, its `BATCH_END` ACK never came,
  and the caller got an opaque 30-second `Error::Timeout` naming nothing. (This
  is the hang the `nftables_reconcile` integration tests were wrapped in a
  30s timeout to survive.) Conversely, an inner seq that happened to *equal*
  `end_seq` had its per-op ACK mistaken for the BATCH_END ACK, returning
  `Ok(())` for a batch that never committed.

  `send_batch` now allocates every inner seq from the socket counter at send
  time, so the batch occupies one contiguous `[begin_seq..=end_seq]` window and
  every response matches exactly — the CLAUDE.md recv-loop rule 1. The socket
  is now the *only* seq authority; `Transaction`'s counter is reduced to what it
  always really was, an allocator for the batch-local `NFTA_SET_ID`. Transaction
  messages also now carry a pid, which they never did. Separately (#209), a
  stray `NLMSG_DONE` no longer reports success: nfnetlink never terminates a
  batch with DONE, so the arm could only fire on a stale frame left by a
  cancelled dump (dumps and batches share the fd) — reporting an uncommitted
  batch as committed.

- **nftables: `DeclaredSet` / `DeclaredSetBuilder` are exported (#210).** They
  are the type of the **public** field `NftablesDiff::sets_to_add`, so leaving
  them unexported made that field unnameable from outside the crate.

- **TC config fields that never reached the wire (#201, #213, #214, #215).**
  Four cases of a value being accepted, stored, and then silently dropped —
  the compiler could not warn about any of them, because the field *was*
  assigned; it just was never read again.
  - **Filter `protocol` and `priority` were discarded (#201).** Every filter
    config (`U32Filter`, `FlowerFilter`, `MatchallFilter`, …) has public
    `.protocol()` / `.priority()` setters, and `add_filter` / `replace_filter`
    hardcoded `ETH_P_IP` and auto-priority instead of reading them. On a
    clsact/ingress hook that meant **IPv6, ARP and VLAN traffic never hit the
    filter at all**, and explicit priority ordering was ignored, so filters
    landed in an unintended evaluation order relative to operator-installed
    rules — with no error either way. `FilterConfig` gains defaulted
    `protocol()` / `priority()` accessors (defaults `None`, so external impls
    stay source-compatible, matching how `set_chain` was added); the shipped
    configs override them. Note `MatchallFilter` and `FlowerFilter` default to
    `ETH_P_ALL`, so filters that were silently IPv4-only now match everything,
    as their builders always claimed.
  - **`HtbQdiscConfig::r2q` never reached the wire (#213).** The field, its
    `.r2q()` setter and the `r2q` token in `parse_params` were all live, but
    `TcHtbGlob::new()` hardcoded `rate2quantum: 10` with no override. This is
    the "silent skipping is a bug" contract violated one layer *below* the
    parser: the parser dutifully accepted the token and the encoder threw it
    away, leaving class quanta wrong for high-rate hierarchies. Adds
    `TcHtbGlob::with_r2q`.
  - **`TcMessage::is_filter()` returned true for every qdisc (#214).** It
    tested `tcm_info != 0`, but `tc_fill_qdisc()` sets `tcm_info` to the qdisc
    **refcount** — always ≥ 1. So every qdisc claimed to be a filter, and
    `filter_protocol()` handed back refcount bits reinterpreted as an
    ethertype. `struct tcmsg` is byte-identical for qdiscs, classes and
    filters; the only reliable discriminator is the `nlmsg_type`, which lives
    in the netlink header. `TcMessage` now carries it (via a defaulted
    `FromNetlink::set_msg_type` hook the dump and event paths call), and
    `is_qdisc()` / `is_class()` / `is_filter()` classify on it. They return
    `false` rather than guessing when the type is unknown. `is_qdisc()` is new.
  - **`TCA_STATS_BASIC_HW` clobbered `TCA_STATS_BASIC` (#215).** The software
    total (id 1) and the hardware-offloaded *subset* of it (id 7) shared a
    match arm, so the HW value — arriving last, since 7 > 1 — overwrote the
    total. On a NIC with tc offload, `bytes()` / `packets()` therefore reported
    only the offloaded portion, **often 0** when nothing had been offloaded
    yet. Split into `stats_basic` / `stats_basic_hw`; `bytes()` and `packets()`
    keep returning the software total.

- **tc-string grammar now matches `tc(8)` (#203, #216, #217, #221).** Three
  silent misreadings of values users already pass. See
  [`docs/migration_guide/0.24.0-to-0.25.0.md`](docs/migration_guide/0.24.0-to-0.25.0.md)
  — these change behaviour with no compiler error.
  - **`mbps`/`kbps`/`gbps` are BYTES per second, not bits (#203).** iproute2
    matches its suffix table with `strcasecmp`, so lowercase `mbps` hits the
    `MBps = 8_000_000` entry. nlink mapped the whole family to bits, so every
    such string was **8x too small** — the exact bits-vs-bytes confusion the
    `Rate` newtype was introduced to kill. Suffix matching is now
    case-insensitive too. The unit test at `util/rate.rs:520` was *pinning*
    the bug (`100mbps == mbit(100)`); it now asserts `== mbit(800)`.
  - **A bare number in a time slot is MICROseconds (#216).** `tc(8)`'s internal
    unit is 1e6; nlink read a suffix-less number as **seconds**. So
    `netem delay 100` meant 100 *seconds* — a 1,000,000x error that
    effectively stopped the interface passing traffic. `m`/`min`/`h` are no
    longer accepted (`tc(8)` has no minute suffix, and it made a mistyped `ms`
    silently 60,000x too long).
  - **Negative rates and sizes error instead of becoming 0 (#217).**
    `f64 as u64` saturates, so `get_rate("-5mbit")` returned `Ok(0)` and the
    kernel then rejected it with a bare `EINVAL` rather than nlink's
    contract-mandated `"htb: invalid rate ..."`. A negative *duration* was
    worse — `Duration::from_secs_f64(-1.0)` **panics**, reachable straight
    from `NetemConfig::parse_params`.
  - **`Percent::from_str` doc (#221).** It claimed `"0.5"` was "treated as a
    fraction"; the code reads it as 0.5 **percent**, which is the
    `tc(8)`-correct behaviour. The doc was wrong, not the code — but anyone
    who believed it had a 100x error in their loss rate. Points at
    `Percent::from_fraction` now.
  - `get_size` also accepts the binary `kib`/`mib`/`gib`/`tib` spellings its
    own rustdoc had always advertised and which it used to reject.

- **psched tick conversion — TBF, HTB and police were all mis-programmed
  (#191, #192, #193, #194, #218).** Several TC wire fields that read like
  byte counts or microsecond durations are actually **psched ticks** (1 tick
  = 64 ns, so 15.625 ticks per µs). nlink never converted, and never read
  `/proc/net/psched` — `grep -ri psched` returned zero hits. The kernel runs
  `tc_tbf_qopt.buffer`, `tc_htb_opt.buffer` and `tc_police.burst` through
  `PSCHED_TICKS2NS()`, so every one of them was wrong:
  - **TBF** (#192) wrote the burst as raw bytes. At `rate 1mbit` with the
    default 32 KiB burst the kernel read 32 768 *ticks* (~2.1 ms), computed
    `max_size ~= 262` bytes, and `tbf_enqueue()` then **dropped every packet
    larger than 262 bytes** — a total blackhole for normal traffic. The
    correct value is 4 096 000 ticks, 125x larger.
  - **HTB** (#193) computed the buffer in microseconds and labelled it ticks,
    losing the 15.625 factor. A 100 mbit class landed with a token bucket of
    ~900 bytes — **below one MTU**, so it could never burst a full-size
    packet. Every `RateLimiter`, `PerHostLimiter` and `PerPeerImpairer` shape
    goes through this path. The hardcoded `hz = 1000` is also gone: iproute2's
    `get_hz()` returns 1e9 on modern kernels, which makes the default burst
    exactly one MTU rather than `rate/1000` bytes larger.
  - **police** (#194) wrote the burst as bytes *and* never emitted
    `TCA_POLICE_RATE` at all. `tcf_police_init()` calls `qdisc_get_rtab()` for
    any non-zero rate and fails the action when it returns NULL — which it
    does both when the attribute is absent and when the ratespec's `cell_log`
    is 0. Both held, so **a policer with a rate could not install**.
  - The **HTB rate table** was built with `cell_log = 3` while the
    accompanying `TcRateSpec` left `cell_log = 0`, so `qdisc_get_rtab()`
    discarded `TCA_HTB_RTAB`/`CTAB` outright — 1024 wasted bytes per class
    add, and ATM/ADSL `linklayer` handling could never work.
  - The **decode** side (#218) took the kernel's tick-valued buffer straight
    into a field named and typed as bytes, so reading back a qdisc created by
    real `tc` yielded a burst off by `15.625 / rate`, and `reconcile`
    considered a wildly wrong burst to be in sync.

  New public `nlink::netlink::psched` module: `Psched` (the cached
  `/proc/net/psched` clock, with the modern constants as an infallible
  fallback), plus `tc_calc_xmittime` / `tc_calc_xmitsize` / `tc_calc_rtable`
  — ports of iproute2's `tc_core.c`. `tc_calc_rtable` takes `&mut TcRateSpec`
  and stamps `cell_log`/`linklayer`/`cell_align` itself, so a table can no
  longer disagree with its own spec. TBF now also emits the byte-valued
  `TCA_TBF_BURST`/`TCA_TBF_PBURST` escape hatches iproute2 sends.

  These bugs survived because there was **no test anywhere in the crate that
  asserted a single byte** of a TC payload — the existing `write_options`
  tests built a message and threw it away. A writer and reader wrong in the
  same direction agree with each other. There is now a byte-level harness and
  a set of assertions pinned to values computed by hand from iproute2's
  algorithm, plus root-gated lab tests that round-trip through the kernel.

- **setns thread discipline (#185).** Four related hardenings on the
  per-thread `setns` state management:
  - `NetlinkSocket::new_in_namespace` (and everything above it:
    `Connection::new_in_namespace*`, `namespace::connection_for*`) now runs
    the namespace-sensitive half — `setns` + `socket(2)` — on a dedicated
    worker thread that **exits instead of restoring**, the same discipline
    `namespace::create` has used since 0.19. The calling thread's namespace
    is never touched, so the restore-failed/poisoned-tokio-worker class is
    structurally gone, and a panic during socket creation can no longer
    strand the caller in the target netns. `Error::NamespaceRestoreFailed`
    is retained for compatibility but no longer produced.
  - The `namespace::{get,set}_sysctl*` helpers likewise run on a dedicated
    entered worker thread instead of `setns`-ing the calling thread.
  - *Breaking:* `NamespaceGuard` is now `!Send` — namespace membership is
    per-thread, so a guard dropped on a different thread than the one that
    `enter`ed would restore the wrong thread. Moving it across threads
    (including holding it across an `.await` on a multi-threaded runtime)
    is now a compile error; any code that did so was already incorrect at
    runtime.
  - `NamespaceGuard::restore()` no longer performs a second, redundant
    restore in `Drop` after the explicit call.
- **Missing-namespace errors are now classifiable via `is_not_found()`
  (#184).** `namespace::open{,_path,_pid}`, `namespace::enter{,_path}`
  (and thus `execute_in` + the `{get,set}_sysctl*` helpers), and
  `NetlinkSocket::new_in_namespace_path` (and thus
  `Connection::new_in_namespace_path`, `namespace::connection_for*`, and
  `NamespaceSpec::connection*`) previously wrapped **all** open failures —
  including ENOENT — in stringly `Error::InvalidMessage`, so
  `connection_for("gone")` on a deleted namespace couldn't be handled with
  the documented recovery predicates. ENOENT now maps to the typed
  `Error::NamespaceNotFound` (carrying the path, the same shape
  `delete_path` uses), and every other open failure passes through as
  `Error::Io` with its errno intact, so `is_permission_denied()` & co.
  classify correctly too.
- **`NamespaceWatcher::recv()` now actually waits for events (#183).** The
  inotify fd is always nonblocking (the `inotify` crate initializes it with
  `IN_NONBLOCK`), so the previous direct `read_events` call surfaced
  `WouldBlock` as an immediate `Error::Io(EAGAIN)` whenever no event was
  already queued — the watcher could never perform its documented
  "wait until an event is available" contract, and the module's own doc
  example errored on its first iteration. `recv()` is now built on the
  crate's tokio-native `EventStream` (whose `stream` feature was already
  enabled but unused), parking the task on the fd until an event arrives.
  Watch-transition logic (parent-dir ↔ netns-dir) is unchanged. Events
  whose namespace name is not UTF-8 are now skipped with a
  `tracing::warn!` instead of silently dropped. Regression-tested
  unprivileged (recv must park, not error) and under the privileged CI
  gate (create → `Created`, delete → `Deleted` round-trip).
  *Breaking (semver-only): `NamespaceWatcher`/`NamespaceEventStream` no
  longer implement `UnwindSafe`/`RefUnwindSafe` — the tokio `AsyncFd`
  inside `EventStream` isn't unwind-safe, unlike the old raw fd + buffer.
  This is the 0.25.0 version-bump trigger for the cycle; no functional
  API changed.*
- **`namespace::create_path` hardening** (follow-up to #181, same cycle so
  no released behavior changes):
  - The failure rollback removes only directories that are still empty
    (`remove_dir` walking upward instead of `remove_dir_all`), so a failing
    create can no longer delete a marker a concurrent `create_path`
    installed under a shared ancestor.
  - The marker file is created with `create_new` — a lost race against a
    concurrent create (or an operator `ip netns add`) now fails with EEXIST
    instead of truncating the winner's marker.
  - The already-exists rejection is `ErrorKind::AlreadyExists`-shaped and
    `Error::is_already_exists()` matches it (previously a stringly
    `InvalidMessage` that no predicate classified), completing the
    detect-stale-and-retry loop `is_namespace_path` enables.
  - `is_namespace_path` documents that `NSFS_MAGIC` identifies nsfs, not
    the namespace *type* — a bind-mount of a PID/mount/UTS namespace also
    reports `true`.

- **nftables: a chain, table or flowtable whose *attributes* drifted produced
  an empty diff (#200, #208).** `diff()` matched declared objects against the
  kernel **by name only**. Flipping a chain from `policy(Accept)` to
  `policy(Drop)` — or changing its hook, priority, type or device — was
  therefore a no-op: the chain existed, so nothing was scheduled, `apply()`
  committed an empty batch, and the operator was told the reconcile succeeded
  while the box stayed default-allow. Same shape for `DeclaredTable::flags`
  and for a flowtable's devices/priority/flags. `NftablesDiff` gains
  `chains_to_modify` and `tables_to_modify`; all five chain attributes, table
  flags and the flowtable triple are now compared and re-emitted.

- **nftables: `Rule::reject()` was a plain drop (#205).** It pushed a bare
  `NF_DROP` verdict — no `reject` expression exists in the encoder at all — so
  a rule the caller declared as *reject* silently blackholed the packet and
  the client hung to its TCP timeout instead of failing fast. New
  `Expr::Reject { reject_type, icmp_code }` emits a real `reject` expression.

- **nftables: `Expr::Redirect` never redirected (#206).** The encoder wrote
  `NFTA_NAT_REG_PROTO_MIN` — an attribute from the **nat** namespace — into a
  `redir` expression nest. `redir` has its own namespace (`NFTA_REDIR_*`),
  where that id means something else entirely, so the kernel ignored the port
  and the redirect landed nowhere. The `NFTA_REDIR_*` constants are now
  defined and the encoder uses them.

- **nftables: three `SetKeyType` datatype ids were wrong (#207).** `InetProto`,
  `Mark` and `IfIndex` carried ids that did not match nft's `enum datatypes`,
  so a set declared with those key types was created with the wrong type and
  the kernel rejected (or silently mis-keyed) every element. `EtherAddr`'s key
  length was 8 where a MAC is 6. Concatenated key types packed their
  components in the wrong order — nft's `concat_subtype_add(t, n)` shifts the
  *accumulator* left, so component 0 ends up in the **high** bits, not the low
  ones. Verified against `nft --debug=netlink`.

- **nftables: `emit_tlv` wrote little-endian attribute headers (#212).** The
  writer used `to_le_bytes` for `nla_len`/`nla_type` while every reader in the
  crate parses them native-endian. Same value on x86_64, silently wrong on a
  big-endian target. Both sides are `to_ne_bytes` now.

- **dispatcher: an `events()` stream hung forever after a fatal recv error
  (#202).** `fail_all` cleared the `pending` map but never `event_listeners`, so
  in-flight *requests* saw the error while every event stream kept its sender
  alive. An `mpsc::Receiver` yields `None` only once every `Sender` is gone, so
  the `Poll::Ready(None) => take_fatal_error()` arm was unreachable and the
  stream parked on `Poll::Pending` **forever** — no error, no termination, no
  resync. From the consumer's side it was indistinguishable from an idle network,
  which means any reconnect logic hanging off the error branch never ran.

- **dispatcher: `shutdown()` could be lost, leaking the driver task and its fd
  (#219).** It signalled with `Notify::notify_waiters()`, which stores no permit
  and wakes only tasks *already registered* as waiters. The driver re-creates its
  `notified()` future each `select!` iteration, so it is unregistered for the
  whole of `route_buffer` and between iterations — and a `Connection::drop`
  landing in that window had its signal silently discarded. The driver then
  looped forever on a socket nobody could reach: the task never exited and the fd
  never closed, leaking one of each per connection under churn. `notify_one()`
  stores the permit.

- **socket: `recv_batch` never fanned out ENOBUFS (#220).** `recv_msg` and
  `poll_recv` both tell the resync subscribers the kernel dropped multicast
  frames; the `syscall_batch` siblings (`recv_batch` / `poll_recv_batch`) did
  not, so under that feature a resync stream never learned it had missed anything
  and never re-dumped. Narrow in practice (the batch paths are reachable only
  from dumps), fixed for consistency.

- **ethtool: link speed was always `None` and duplex was garbage (#196).** The
  kernel has a single `ETHTOOL_A_LINKMODES_OURS = 3`; nlink invented two
  variants there (`Supported` + `Advertised`), which shifted **every** later
  attribute id up by one. `Speed` then read `DUPLEX` — a 1-byte attribute, so
  the `len >= 4` guard never matched and speed silently read as `None` **on
  every interface, forever** — while `Duplex` read `MASTER_SLAVE_CFG` and
  reported garbage. On the write path a speed `u32` landed in an id the kernel's
  policy declares `NLA_U8`, so `set_link_modes` with a speed could only ever
  `EINVAL`. Both the request path and the multicast event decoder were affected.
  `OURS` carries both answers at once — supported modes in the bitset's mask,
  advertised modes in its value — so `LinkModes::supported` and `::advertised`
  are both populated from it.

- **UAPI constant drift, and the gate that ends the class (#227–#232).** Five
  more hand-transcribed enums had drifted from the kernel:
  - `EthtoolStringSet` omitted `ETH_SS_FEATURES` (4), so every set id from 4 up
    was one too low — asking for `LinkModes` actually requested `PHY_TUNABLES`
    (#227). It also invented two string sets that do not exist.
  - `EthtoolLinkinfoAttr` transposed `TP_MDIX` and `TP_MDIX_CTRL`, so the
    reported MDI-X status and its control setting were swapped (#228).
  - `EthtoolCmd::PhyGet` was 44, but the kernel inserted `MODULE_FW_FLASH_ACT`
    there and moved `PHY_GET` to 45 — so a PHY query would have sent the NIC a
    **module firmware-flash activate** (#229). Unused so far; fixed while free.
  - `EthtoolStatsAttr` omitted the kernel's `PAD` at index 1 and shipped values
    its own doc-comments described as wrong, while the connection module carried
    private shadow constants to work around its own public enum (#230).
  - nl80211 `BssStatus` started at 1 where the kernel starts at 0, so an
    *associated* BSS decoded as `IbssJoined`; devlink `PortFlavour` omitted
    `UNUSED`, so an unused port decoded as a PCI subfunction (#231).

  **`scripts/audit-uapi-constants.sh` (#232) now diffs every `#[repr(uN)]` enum
  in the crate against `/usr/include/linux` on every push** — 644 discriminants
  across 62 enums. Every enum must be classified: mapped to a kernel prefix, or
  declared nlink-only in the allowlist. An unclassified enum fails the build,
  because an unclassified enum is an unchecked one.

  It found **two more drifts on its first run**, neither of which anyone had
  reported:
  - `EthtoolCoalesceAttr`'s CQE-mode pair. The kernel lists **TX before RX**
    here, unlike every other RX/TX pair in the enum; nlink had them the natural
    way round, and therefore backwards.
  - nl80211 `ChannelWidth` stopped at `Width320 = 8`, but the kernel had since
    inserted the five S1G narrow widths (1/2/4/8/16 MHz) at 8..=12 and pushed
    320 MHz out to **13**. A Wi-Fi 7 320 MHz channel decoded as "unknown channel
    width", and an S1G 1 MHz channel decoded as **320 MHz** — the widest possible
    answer to the narrowest possible channel.

- **sockdiag: a `/0` prefix panicked the dump path (#204).** `ip_matches` built
  its mask with `u32::MAX << (32 - prefix_len)`, which for `prefix_len == 0` is
  a shift by the full width: a **panic** in debug builds, and in release a shift
  count masked back to zero — leaving `mask = u32::MAX`, so "any address"
  became an exact match on `0.0.0.0` and matched nothing. `src 0.0.0.0/0` is a
  legitimate ss filter and reaches this straight from user input, on the path
  every dump takes.

- **sockdiag: `not src <v4>` silently dropped v4-mapped IPv6 sockets (#198).**
  The bytecode compiler lowered a *negated* host condition kernel-side. But the
  kernel's hostcond deliberately matches an AF_INET cond against a v4-mapped
  AF_INET6 entry, where nlink's client-side `ip_matches` calls that a
  cross-family non-match — so the kernel cond is a strict **superset**, and
  complementing a superset yields a **subset**. `not src 10.0.0.0/8` therefore
  *rejected* the dual-stack listener's `::ffff:10.1.2.3` socket that the filter
  should have kept, and because the kernel had already dropped it, the
  client-side backstop could not bring it back. This broke the module's own
  stated invariant ("the compiler never emits a program that could
  under-approximate"). Negated host conds are no longer lowered at all; the
  conjunct is dropped, `exact` goes false, and the backstop decides. The
  `Nnf::NotHost` node is gone, so it cannot come back.

- **sockdiag: five documented `InetFilter` builders did nothing (#223).**
  `local_addr`, `remote_addr`, `interface`, `mark` and `cgroup_id` were assigned
  by their builders and read by **no code anywhere** — so
  `SocketFilter::tcp().local_addr("10.0.0.1")` returned *every TCP socket on the
  box*, with no error and no warning. Same for `UnixFilter::socket_types` and
  `path_pattern`: `.unix().stream().path("/run/foo")` returned every unix socket
  of every type. The addresses now lower kernel-side as `S_COND`/`D_COND`; the
  rest are applied client-side.

- **sockdiag: `FilterExpr::parse` accepted trailing garbage (#224).** The parser
  stopped at the first token it did not recognize and returned `Ok`, leaving the
  remainder unread. `"sport = :22 && dport = :80"` parsed as just
  `sport = :22` — a *superset* of the sockets asked for, and marked `exact`, so
  even the client-side backstop would not narrow it. Full input consumption is
  now required. (`or(`/`and(` without a separating space are accepted.)

- **sockdiag: `MemInfo.wmem_alloc` and `wmem_queued` were swapped (#222).** In
  `struct inet_diag_meminfo`, offset 4 is `idiag_wmem` = `sk_wmem_queued` and
  offset 12 is `idiag_tmem` = `sk_wmem_alloc` — nlink read them the other way
  round, so ss-style `skmem:` output had `t` and `w` transposed and
  `total_mem()` summed the wrong pair.

- **sockdiag: `MemInfo.rcvbuf`/`sndbuf` could never be populated (#197).** They
  live only in `INET_DIAG_SKMEMINFO`, and **no builder requested it** — so they
  read as a flat `0` forever and downstream dashboards graphed a clean,
  believable, permanently-zero line. Adds `InetFilterBuilder::with_sk_mem_info()`,
  and the `MEMINFO` and `SKMEMINFO` arms now **merge** instead of the later one
  clobbering the earlier (with `with_all_extensions()`, whichever the kernel
  emitted last used to win). The five SKMEMINFO-only fields are now
  `Option<u32>`: `None` means *you did not request it*, which is a different
  statement from `Some(0)` — the conflation is what kept this invisible.

- **sockdiag: `SocketFilter::mptcp()` was a mislabelled TCP dump (#225).**
  `IPPROTO_MPTCP` is **262** and does not fit `inet_diag_req_v2.sdiag_protocol`
  (a `__u8`); nlink sent the truncated byte (262 & 0xff == 6 == plain TCP) and
  never emitted the `INET_DIAG_REQ_PROTOCOL` attribute the kernel added for
  exactly this case. The result was **every TCP socket on the box, each stamped
  `Protocol::Mptcp`**. Relatedly, `INET_DIAG_INFO` was always decoded as
  `struct tcp_info` regardless of protocol — for SCTP it carries `struct
  sctp_info`, which is long enough to clear every length guard, so the decode
  produced plausible-looking garbage RTT and cwnd. The decode is now gated on
  the protocol.

- **sockdiag: every dump error claimed to come from `sock_destroy` (#226).** The
  inet, unix and netlink dump paths all tagged kernel errors with the one
  operation that had not run — so an `EINVAL` on a malformed bytecode program
  was reported as a `sock_destroy` failure, which is precisely the wrong place
  to look.

- **`DeclaredSet` / `DeclaredSetBuilder` were unnameable (#210).** They are the
  element type of the **public** `NftablesDiff::sets_to_add` field, but were
  never re-exported — so a downstream user could read the field and could not
  write down the type of what they read. Both are exported now.

- **`CTA_TIMEOUT` wrapped instead of saturating (#211).** A conntrack timeout
  above `u32::MAX` seconds truncated modulo 2^32 — a very long timeout could
  wrap to a very short one. It now saturates. The nftables set-name bound is
  255, not 256 (`NFT_NAME_MAXLEN` counts the NUL).

## [0.24.0] - 2026-07-03

> Upgrading? See
> [`docs/migration_guide/0.23.0-to-0.24.0.md`](docs/migration_guide/0.23.0-to-0.24.0.md)
> — a sockdiag/events/nftables depth release; the breaking surface is
> mechanical (`#[non_exhaustive]` on the three diff types, two new
> sockdiag struct fields) plus behaviour-visible bug fixes
> (`InetExtension::mask()` off-by-one, `TcpInfo` tail fields,
> `subscribe_all()` breadth).

### Added

- **Rule / Nexthop / NsId / MDB events (#165).** `NetworkEvent` gained
  `NewRule`/`DelRule` (`RuleMessage`), `NewNexthop`/`DelNexthop`
  (`Nexthop`), `NewNsId`/`DelNsId` (`NsIdMessage`) and `NewMdb`/`DelMdb`
  (`MdbEntry`) variants with matching `as_*`/`into_*` accessors —
  policy-routing, nexthop-object, namespace-ID and bridge-multicast-DB
  changes now surface as typed events. New `RtnetlinkGroup::{Nexthop,
  Mdb}` subscription variants plus `RTNLGRP_IPV4_NETCONF` /
  `RTNLGRP_IPV6_NETCONF` / `RTNLGRP_MDB` / `RTNLGRP_NEXTHOP` /
  `RTNLGRP_BRVLAN` group constants.
- **Socket → process attribution (#162).** sock_diag deliberately
  reports no PID, so every `ss -p`-style consumer re-implemented the
  `/proc/<pid>/fd` → `socket:[inode]` scan. It now lives in the library
  (feature `sockdiag`): `SocketOwnerMap::scan()` is one amortized
  `/proc` walk, `resolve(inode)` yields `ProcessRef { pid, start_time,
  comm, fd }` — `start_time` (stat field 22) makes `(pid, start_time)`
  a PID-reuse-safe identity. `CgroupPathMap::scan()` is the companion
  join for the already-exposed `InetSocket.cgroup_id`: cgroup-v2 ID →
  cgroupfs path (`resolve_relative` yields `system.slice/foo.service`
  shapes for unit/container joins). Both are best-effort snapshots —
  short-lived sockets and unreadable (other users') processes resolve
  to nothing; kernel 6.5+ BPF socket iterators are the race-free
  successor, this is the unprivileged baseline. `nlink-ss -p` now
  consumes the library version; new example
  `sockdiag_socket_owners`.
- **Typed nftables rule-expression decoding (#164).** `RuleInfo`
  previously exposed only raw `expression_bytes`; consumers wanting
  per-rule counters hand-parsed NFTA TLVs. New read-side `RuleExpr`
  enum (`Counter { packets, bytes }` with live kernel values,
  `Verdict`, `Meta`, `Cmp`, `Immediate`, `Payload`, and a lossless
  `Unknown { name, data }` fallback) plus `RuleInfo::expressions()`
  and the `RuleInfo::counter() -> Option<(packets, bytes)>` shortcut.
  Decoding is lazy and infallible — anything undecodable demotes to
  `Unknown` verbatim; `expression_bytes` and the diff's byte-wise
  body comparison are unchanged.
- **Ergonomics batch (#169).**
  - `del_link_if_exists` / `del_route_v4_if_exists` / `_v6` /
    `del_address_if_exists` / `del_qdisc_if_exists` /
    `del_filter_if_exists` on `Connection<Route>` — `Ok(bool)`
    instead of an error when there's nothing to delete, mirroring
    the nftables `del_*_if_exists` family.
  - **WireGuard device bootstrap**: `WireguardConfig::diff` reports
    absent declared devices in the new
    `WireguardConfigDiff::devices_to_add` instead of hard-failing;
    `WireguardConfig::ensure_devices(&Connection<Route>)` creates the
    missing links idempotently; `facade::apply::wireguard*` wires the
    two together so a bare `WireguardConfig` applies end-to-end.
  - **`WireguardConfigDiff` serializes** (feature `serde`) for typed
    drift reporting — public keys as base64, secret material redacted
    to presence booleans, keepalive as whole seconds.
  - **Namespace-spec facade variants**: `Stack::{apply,diff}_in`,
    `facade::{apply,diff}::{network,nftables,wireguard}_in` take a
    `NamespaceSpec` (named / path / PID — container support); new
    `NamespaceSpec::connection_async` for GENL families.
  - `RateLimiter::reconcile{,_dry_run,_with_options}` — idempotent
    convergence mirroring `PerHostLimiter::reconcile` (zero kernel
    calls when nothing drifted; covers the egress HTB shape, the IFB
    device, the ingress hook + redirect, and the IFB-side HTB shape).
  - `StackDiff::change_count()` / `StackApplyReport::change_count()`;
    `NETNS_RUN_DIR` re-exported at the crate root. (`LinkChanges`
    already implemented `Display`.)
- **Per-socket TCP byte-rate tracking (#171).**
  `SocketRateTracker::ingest(snapshot, at)` turns consecutive TCP
  dumps into per-socket goodput deltas keyed by the kernel socket
  cookie (never the inode — inodes get reused across poll intervals):
  `SocketRate { cookie, tx_goodput_bps, rx_goodput_bps,
  retrans_ratio }`. Bounded (cookies absent for N ingests evict),
  robust to counter regressions and same-instant double ingests. The
  architectural constraints are now documented on the sockdiag
  module: TCP-only (UDP diag has NO cumulative byte counters —
  rqueue/wqueue are queue depths, never diff them), goodput ≠ wire
  throughput, short flows invisible to polling (BPF socket iterators
  are the successor).
- **Full INET_DIAG_BC bytecode compiler + kernel-side expression
  filtering (#163).** The sockdiag bytecode compiler now lowers the
  complete `FilterExpr` grammar — `src`/`dst` host conditions
  (`inet_diag_hostcond`, v4/v6/prefix), `or`/`not` (De Morgan
  push-down + jump structure; the kernel has no NOT opcode), `!=`,
  and `state` (hoisted into the request header's `idiag_states` —
  there is no state opcode) — via the new
  `compile_filter(&FilterExpr) -> CompiledFilter { states, bytecode,
  exact }`. New `InetFilter::expr` + builder `filter_expr()`: the
  dump path compiles the expression once, runs it kernel-side, and
  applies the client-side `matches()` backstop whenever the lowering
  over-approximates (never under-approximates). `nlink-ss`
  expressions now pre-filter kernel-side. Emission discipline makes
  the kernel's `inet_diag_bc_audit` pass structural (every `yes` =
  own size); a faithful audit-oracle reimplementation runs over every
  compiled program in the unit tests, and the full matrix (or / not /
  hostconds v4+v6 / prefix / state hoist / nesting) was verified
  against a live kernel.
- **Congestion-control info structs (#163).** `INET_DIAG_VEGASINFO` /
  `DCTCPINFO` / `BBRINFO` now parse into typed
  `CcInfo::{Vegas,Dctcp,Bbr}` on the new `InetSocket.cc_info`
  (BBR bandwidth assembled from the wire's lo/hi split, bytes/sec).
  Request with `with_cc_info()` — one kernel extension bit gates all
  three; which arrives depends on the socket's CC algorithm.
- **Documentation & examples for the 0.24 surface.** New recipe
  [`per-process-bandwidth`](docs/recipes/per-process-bandwidth.md)
  (attribution + rate tracking + kernel-side filtering end-to-end);
  new runnable examples `sockdiag_rate_top` (per-process bandwidth
  top), `sockdiag_filter_expr` (`compile_filter` introspection +
  `CcInfo` display) and `config_stack` (the `Stack` facade end-to-end
  incl. `change_count()` and the `--apply` runner pattern); `events_monitor` now uses `subscribe_all()` and
  prints the rule/nexthop/nsid/MDB families; `nftables_firewall`
  decodes dumped rule expressions and per-rule counters;
  `ratelimit_simple` demonstrates `RateLimiter::reconcile`
  idempotence. `docs/library.md` gained a Socket Diagnostics chapter
  and WireGuard-bootstrap / reconcile / event-coverage notes; README
  and CLAUDE.md refreshed to match.

### Fixed (sockdiag)

- **`InetExtension::mask()` was off by one (#163).** The kernel
  checks `ext & (1 << (attr - 1))`, but `mask()` returned `1 << attr`
  — so `with_mem_info()` actually requested `INET_DIAG_INFO`,
  `with_tcp_info()` requested VEGASINFO, and so on, one extension
  over. Every variant's bit is now pinned by a unit test.

- **`TcpInfo` tail fields were never populated (#171).**
  `parse_tcp_info` stopped at byte 168, so `bytes_sent`,
  `bytes_retrans`, `busy_time`, `rwnd_limited`, `sndbuf_limited`,
  `delivered`, `delivered_ce`, `dsack_dups`, `reord_seen`,
  `rcv_ooopack` and `snd_wnd` — all declared on `TcpInfo` — silently
  read 0 on every kernel. The parser now decodes through byte 232
  (offsets pinned to uapi `linux/tcp.h`), with rule-1 guards so both
  older (shorter) and newer (longer) kernel structs parse cleanly.

### Changed (breaking)

- **`subscribe_all()` now joins every typed-event group (#165)** —
  previously it omitted `NsId`, `Ipv4Rule` and `Ipv6Rule` (and the new
  `Nexthop`/`Mdb` groups didn't exist), so those changes were silent
  under the "all" subscription. Consumers matching exhaustively on
  `NetworkEvent` were already forced to handle unknown variants
  (`#[non_exhaustive]`); the new variants simply start arriving.
- **`ConfigDiff`, `StackDiff` and `WireguardConfigDiff` are now
  `#[non_exhaustive]` (#165)** — literal construction and functional-
  update syntax outside nlink no longer compile. Construct them via
  `NetworkConfig::diff` / `Stack::diff` / `WireguardConfig::diff`
  (the only ways that ever made sense); this lets future diff
  categories (e.g. #169's WireGuard device bootstrap) land without a
  major bump.

### Fixed

- **XFRM dumps no longer spam the kernel log (#160).**
  `Connection::<Xfrm>::get_security_associations()` /
  `get_security_policies()` (and the `stream_sas()` / `stream_sps()`
  streaming variants) appended a zeroed `xfrm_usersa_info` /
  `xfrm_userpolicy_info` struct as the dump body. The XFRM dump
  callbacks parse the whole body as netlink attributes (`hdrlen = 0`),
  so the kernel logged a ratelimited `netlink: 224 bytes leftover
  after parsing attributes` warning (168 for policies) on every poll.
  Dump requests are now header-only, matching `ip xfrm state/policy`.
  Results were and remain correct — this kills the log noise.

## [0.23.0] - 2026-06-30

> Upgrading? See
> [`docs/migration_guide/0.22.0-to-0.23.0.md`](docs/migration_guide/0.22.0-to-0.23.0.md)
> — large but mostly additive; the only breaking changes are
> `Chain::new` returning `Result`, `LinkStats` accessors, and a few
> newly-`#[non_exhaustive]` nl80211 structs.

### Fixed

- **nftables set creation always failed with ERANGE (#137).** The
  `NFTA_SET_ID` attribute constant was `16` and `NFTA_SET_HANDLE`
  was `17`, but the kernel `enum nft_set_attributes` places
  `NFTA_SET_ID` at `10` and `NFTA_SET_HANDLE` at `16`. So every
  `NFT_MSG_NEWSET` carried its set id under attribute `16` — the
  *real* `NFTA_SET_HANDLE` — and the kernel rejected the create as a
  bogus handle (`errno 34`, ERANGE). The imperative
  `Connection::<Nftables>::add_set` was affected too; the drift went
  unnoticed because no integration test exercised sets against a live
  kernel until the declarative-set work above. Corrected both
  constants (same id-drift class as the `STA_INFO_RX_BITRATE` /
  `BAND_ATTR_VHT_CAPA` fixes), added `NFTA_SET_POLICY` / `NFTA_SET_DESC`,
  and pinned the whole `NFTA_SET_*` tail against its kernel-enum
  position with a regression test. As a bonus `SetInfo::handle` now
  parses (it was read off the wrong attribute and was always 0).
- **nl80211 `BAND_ATTR_VHT_CAPA` was the wrong attribute id (#137).**
  The PHY/wiphy audit found `NL80211_BAND_ATTR_VHT_CAPA` defined as
  `9`, but `9` is `IFTYPE_DATA` — `VHT_CAPA` is `8`. So a band's VHT
  capability field was parsed off the per-iftype HE/EHT nest instead.
  Corrected to `8` (the same id-drift class as the `STA_INFO_RX_BITRATE`
  fix below), and a new test pins every modelled `NL80211_BAND_ATTR_*`,
  `NL80211_FREQUENCY_ATTR_*`, and `NL80211_BAND_IFTYPE_ATTR_*` constant
  against its kernel-enum position so the class can't recur.
- **nl80211 `get_phys` truncated rich PHYs (#137).** The `GET_WIPHY`
  dump didn't set `NL80211_ATTR_SPLIT_WIPHY_DUMP`, so the kernel capped
  each wiphy's reply to a single message and silently dropped the
  bands/channels/HE caps that didn't fit — and each message was parsed
  as a *separate* `PhyInfo`. `get_phys` now requests the split dump and
  **reassembles** the multi-message-per-wiphy response by
  `NL80211_ATTR_WIPHY` index, merging bands by band index (a band whose
  frequency list spans messages is merged, not duplicated). A
  reassembly test pins the behaviour.
- **nl80211 `STA_INFO_RX_BITRATE` was the wrong attribute id (#137).**
  The station-info audit found `NL80211_STA_INFO_RX_BITRATE` defined as
  `12`, but `12` is `TX_FAILED` — `RX_BITRATE` is `14`. So a station's
  RX bitrate was parsed off the wrong attribute (and a present
  `TX_FAILED` would have been misread as a bitrate nest). Corrected to
  `14`, and a new test pins every modelled `NL80211_STA_INFO_*` constant
  against its position in `enum nl80211_sta_info` so the class can't
  recur.

### Added

- **Ergonomic newtype conversions — symmetric, lossless `From` impls
  (#137, Plan 201).** The type-safe newtypes gain the obvious
  inner-value conversions so `.into()` works at API boundaries:
  `Bytes` ⇄ `u64` (byte count), `TcHandle` ⇄ `u32` (packed handle),
  `FilterPriority` → `u16` (the inbound `From<u16>` already existed),
  `Percent` → `f64`, and `TableName` / `ChainName` → `String`. Every
  added impl is **lossless and unambiguous**, mirroring an existing
  named constructor/accessor (`Bytes::new`/`as_u64`,
  `TcHandle::from_raw`/`as_raw`, …). Deliberately **not** added:
  `From<f64> for Percent` (the inbound direction clamps — keep
  `Percent::new` explicit), the validating `String → TableName/
  ChainName` direction (stays `TryFrom`/`new`), and **anything on
  [`Rate`]** — a bare-integer `From` would reintroduce exactly the
  bytes-vs-bits unit ambiguity the type exists to prevent.
- **Reflector / watch-cache — `Store<K, V>` + `ReflectExt::reflect`
  (#137, Plan 195).** A `kube-rs`-style reflector that keeps an
  in-memory cache continuously up to date from a resync-aware event
  stream, with no new dependency. `Store<K, V>` is a cheap-to-clone,
  read-only handle over a shared `HashMap` (clone it for any number of
  readers; all observe the same map; accessors are `get` / `keys` /
  `values` / `snapshot` / `contains_key` / `len` / `with_read`).
  `stream.reflect(store, |ev| …)` wraps any
  `Stream<Item = Result<ResyncedEvent<V>>>` (e.g.
  `into_events_with_resync`) into a **pass-through** stream that applies
  each item to the store before re-yielding it — drive it in a task,
  read the store from anywhere. A caller-supplied closure maps each
  event to a `StoreOp` (`Upsert` / `Remove` / `Ignore`), so the
  reflector stays protocol-generic (for `NetworkEvent`, that closure is
  a `match` on `NewLink => Upsert`, `DelLink => Remove`, …). During a
  resync window (`Marker(ResyncStart)` … `Marker(ResyncEnd)`) the
  reflector stages a fresh snapshot from the `Resynced(V)` replay and
  swaps it in atomically at `ResyncEnd`, so a post-`ENOBUFS` redump
  *replaces* stale state rather than merging into it. Completes Plan
  195 alongside the already-shipped `ResyncStreamExt` combinators; the
  `backon`-based `StreamBackoff` remains intentionally deferred (the
  resync wrapper already handles `ENOBUFS` internally, and consumers
  that want reconnect backoff compose it at the spawn-loop level).
- **`NetworkConfig` declarative purge — re-wired with safety fences
  (#137, Plan 205).** The interface-side declarative config can once
  again *remove* undeclared kernel state, not just add it. Opt in per
  call: `cfg.diff_with_options(&conn, DiffOptions::default().purge(true))`
  populates the new `ConfigDiff::addresses_to_remove` /
  `ConfigDiff::routes_to_remove` collections (visible as `-` lines in
  the diff `Display`), and `cfg.apply_with_options(&conn,
  ApplyOptions::default().with_purge(true))` applies them. The previous
  purge knob was removed in 0.19 because it silently no-op'd (the diff
  phase never populated the removal collections); this is the fully
  wired replacement. **It is heavily fenced so a reconcile can't strip
  kernel-managed state**: only **global-scope** addresses on interfaces
  the config already manages are eligible (IPv6 link-local, loopback,
  and any non-universe scope are excluded), and only **`static`/`boot`
  main-table** routes of unicast/blackhole/unreachable/prohibit type
  (kernel/RA/DHCP/redirect routes, the auto-added connected route, and
  every non-main table are left untouched). **Links and qdiscs are
  never purged.** The default `diff`/`apply` path is unchanged — it can
  still only ever add state — so existing callers see no behaviour
  change. Validated against a live kernel (global address removed while
  the declared address and link-local survive; an admin route removed
  while the connected route stays; idempotent on re-diff).
- **JSON Schema for `NetworkConfig` via the new `schemars` feature
  (#137, Plan 189 §8).** Completes the config-tooling arc started by
  the validating `Deserialize` (#108): `NetworkConfig::json_schema()`
  returns a [JSON Schema](https://json-schema.org) (draft 7, pretty
  string) describing exactly the JSON that `from_json_str` accepts, and
  `json_schema_value()` returns the `schemars::schema::RootSchema` for
  callers that want to inspect or merge it. Wire it into editor tooling
  (`json.schemas` / `yaml.schemas`) for autocomplete + inline
  validation of network-config files, or check it into a repo for CI
  validation. The schema is faithful to the **human-facing** JSON
  shape, not the in-memory types: addresses/routes are CIDR strings
  (the schema delegates through the `AddressRepr`/`RouteRepr` serde
  shadows rather than exposing the parsed `address`/`prefix_len`
  fields), MACs are `aa:bb:..` strings, and the `default` route keyword
  is a string — verified by a test that asserts those fields are
  `"string"`-typed in the generated schema (a schema that didn't match
  the real JSON would be worse than none). Gated behind the new
  `schemars` cargo feature (implies `serde`; opt-in, no default-build
  cost), mirroring the `serde` feature. Scoped to the round-trippable
  `NetworkConfig` input format; the Serialize-only nftables declarative
  types are unaffected.
- **Declarative nftables sets — `DeclaredSet` + element-level diff
  (#137, Plan 198).** The declarative `NftablesConfig` now models named
  sets alongside tables/chains/rules/flowtables, closing the last gap
  versus `nft list ruleset`. Declare a set inside a table —
  `t.set("allowed_v4", |s| s.key_type(SetKeyType::Ipv4Addr).ipv4(addr))`
  — and `diff`/`apply` reconcile it: a declared set absent from the
  kernel is created, a managed set removed from the config is deleted,
  and a set present on both sides gets a real **element-level diff** —
  only the missing keys are added and the undeclared keys removed
  (`set_elements_to_add` / `set_elements_to_remove`), never a wholesale
  re-add. All of it commits inside the existing single
  `NFNL_MSG_BATCH_BEGIN…END` transaction, ordered so rules that
  reference a set by `@name` are released before the set is deleted and
  the set exists before the rules that match on it. New supporting API:
  the imperative `Connection::<Nftables>::list_set_elements` (dumps a
  set's current elements via the previously-unused `NFT_MSG_GETSETELEM`)
  and `Transaction::{add_set,del_set,add_set_elements,del_set_elements}`
  for batch composition. `SetKeyType` / `SetElement` now derive
  `Serialize` (under `serde`), and `Set` gained a `flags()` setter.
  The `nlink-nft` demo learns the matching reconcile DSL — `add set
  <family> <table> <name> type <kt> [flags const]` and `add element
  <family> <table> <set> <elems…>` in `nft diff`/`nft reconcile` files
  (and the imperative `nft apply` path) — with strict element parsing
  per key type (no silent fallback). Limitation: only a set's elements
  are reconciled in place, not its `key_type`/`flags` (same as a chain's
  hook/policy); dynamic/timeout sets that the kernel populates at
  runtime should be declared without elements to avoid churn. Demoed by
  the extended `examples/nftables/declarative.rs`.
- **nl80211 PHY/wiphy band-capability coverage (#137).** Completes the
  nl80211 read audit (scan + station + survey + now PHY). `get_phys`
  reports the full `iw phy` surface: `Band` gains HE (802.11ax) / EHT
  (802.11be) per-interface-type capabilities (`BandIftypeCapa` via
  `NL80211_BAND_ATTR_IFTYPE_DATA`, with `Band::he_supported()` /
  `eht_supported()` helpers) plus the HT/VHT MCS sets; `Frequency`
  gains the DFS state (`DfsState`), the bandwidth-restriction flags
  (`no_ht40_{minus,plus}` / `no_80mhz` / `no_160mhz`), and the kHz
  frequency offset; `PhyInfo` gains `cipher_suites`. `PhyInfo` / `Band`
  / `Frequency` are now `#[non_exhaustive]` + `Default` so future
  kernel attributes stay additive. The `nlink-wifi phy` command now
  prints per-band capabilities, the channel/frequency list with flags,
  bitrates, and cipher suites. (See also the split-dump and `VHT_CAPA`
  fixes above, without which this coverage would be silently truncated
  or mis-parsed.)
- **XFRM (IPsec) monitor event API (#137).** `Connection<Xfrm>` now
  implements `EventSource`: `subscribe(&[XfrmGroup])` /
  `subscribe_all()` join the kernel's `XFRMNLGRP_*` multicast groups,
  and `events()` / `into_events()` stream typed `XfrmEvent`s —
  `NewSa` / `DelSa` / `ExpireSa { hard }` / `NewPolicy` / `DelPolicy` /
  `ExpirePolicy { hard }` / `Acquire` (the SA-negotiation trigger IKE
  daemons watch) / `Report` / `FlushSa` / `FlushPolicy`. The enum is
  `#[non_exhaustive]` and unmodelled notification types (MIGRATE,
  MAPPING, …) surface as `XfrmEvent::Other { msg_type }` rather than
  being dropped. This closes the long-standing `ip xfrm monitor` stub
  (previously `"not yet implemented (no XFRM event API)"`) — the
  `nlink-ip xfrm monitor` subcommand now streams events. Event bodies
  are parsed from the authoritative `linux/xfrm.h` layouts: `DELSA` /
  `DELPOLICY` carry the compact `xfrm_usersa_id` / `xfrm_userpolicy_id`
  (surfaced as `XfrmSaId` / `XfrmPolicyId`), `EXPIRE` / `POLEXPIRE` wrap
  the state struct with a trailing `hard` byte, and `ACQUIRE` is pinned
  by a 280-byte `sizeof` regression test. The walker skips malformed
  frames (Parser-robustness rule 3) so one bad frame can't kill a
  long-lived subscriber. Demoed by `examples/xfrm/ipsec_monitor.rs`
  (`watch` mode + event collection during the `--apply` lifecycle).
- **nl80211 scan/BSS coverage (#137).** Following the station-info audit,
  audited the `NL80211_BSS_*` attribute ids against `enum nl80211_bss`
  (all correct — the RX_BITRATE-class drift was isolated to STA_INFO) and
  pinned them with a regression test. `ScanResult` now also reports
  `signal_unspec` (0–100 quality from drivers without an mBm value),
  `beacon_ies` (beacon IEs distinct from the probe-response set, with
  SSID fallback when no probe response was seen), `last_seen_boottime_ns`,
  and `frequency_offset_khz`. `ScanResult` is now `#[non_exhaustive]` +
  `Default`; a parse test covers the new attributes and confirms
  probe-response IEs win over beacon IEs for the SSID.
- **nl80211 station-info coverage (#137).** Following the RX_BITRATE
  fix above, `StationInfo` now also reports the standard `iw station
  dump` counters: `rx_packets` / `tx_packets` / `tx_retries` /
  `tx_failed`, `beacon_loss`, `rx_drop_misc`, `expected_throughput_kbps`,
  `beacon_signal_avg_dbm`, and `ack_signal_dbm`. The struct is now
  `#[non_exhaustive]` + `Default` so future kernel attributes are
  additive. Surfaced in the `nlink-wifi` station display; a parse test
  proves TX_FAILED (12) and RX_BITRATE (14) land in distinct fields.
- **nl80211 channel survey — `NL80211_CMD_GET_SURVEY` (#137).** Completes
  the wireless read trio (scan + station + survey). `Connection::
  get_survey[_by_index]` dumps per-frequency `SurveyInfo`: noise floor,
  the `in_use` flag, and the channel-time counters (`time`, `time_busy`,
  `time_ext_busy`, `time_rx`, `time_tx`, `time_scan`, `time_bss_rx`) plus
  `frequency_offset_khz`. Channel utilisation — the headline number for
  channel selection — is `time_busy / time`; the `nlink-wifi survey`
  subcommand prints it. `SurveyInfo` is `#[non_exhaustive]` + `Default`.
  A test pins every modelled `NL80211_SURVEY_INFO_*` constant against
  `enum nl80211_survey_info`, and parse tests cover the full nest, the
  zero-length `IN_USE` flag, and truncated/missing input.
- **Bridge per-VLAN entry options — `BRIDGE_VLANDB_ENTRY` (#137).**
  Builds on the VLAN-DB foundation from the gopts work to expose the
  per-(port, VLAN) options the legacy `BridgeVlanBuilder` membership
  path can't: per-VLAN STP state (MSTP), multicast router mode,
  multicast group limit, and neighbour suppression.
  `BridgeVlanEntryOptionsBuilder` + `Connection::
  {set,get}_bridge_vlan_entry_options[_by_index]` (`RTM_NEWVLAN` set /
  `RTM_GETVLAN` dump), with a typed `BridgeVlanState` enum
  (`BR_STATE_*`). Additive — the legacy add/del/PVID path is untouched.
  Wire-format + robustness tests pin the attribute codes against the
  kernel UAPI; read-only `MCAST_N_GROUPS` / per-VLAN `STATS` are not
  settable. Demoed by `nlink-bridge vlan options show|set`; recipe
  section in `docs/recipes/bridge-vlan.md`.
- **net_shaper `NET_SHAPER_CMD_GROUP` — hierarchical TX shaping (#137).**
  The net_shaper re-audit against the kernel 6.13 `net_shaper.yaml`
  found the family otherwise matched the UAPI (discriminants already
  pinned), but the `group` operation was defined-but-unwired — the one
  real gap. `Connection::group_shapers(NetShaperGroupRequest)` now
  atomically creates/updates a `Node`-scope shaper and attaches
  `Queue`-scope leaves under it (the "rate-limit this set of queues
  collectively" primitive), returning the node's handle. Leaves carry
  optional per-leaf `priority`/`weight` via `NetShaperLeaf`; the node
  carries the usual `metric`/`bw_*`/`burst`/`priority`/`weight`. The
  request encoding is hand-written (the derive doesn't model the
  repeated nested `leaves` attribute, whose `leaf-info` is
  `subset-of: net-shaper` and so reuses the net-shaper attribute IDs);
  request-shape tests pin the wire layout. `docs/recipes/tx-hw-shaping.md`
  §"Hierarchical shaping" now shows the real API (previously documented
  as deferred). Read paths unchanged.
- **MPLS / SRv6 / NextHop fixed-struct wire-format audit (#137).**
  Audited the fixed-size kernel structs in `mpls`, `srv6`, and
  `nexthop` (`MplsLabelEntry`, `Ipv6SrHdr`, `NhMsg`, `NexthopGrp`)
  against parser-robustness rule 1 (accept-larger-than-expected) and
  the chain/segment walkers against rule 2 (pathological-length).
  Outcome: **already robust** — every `from_bytes` reads its prefix via
  `ref_from_prefix` (ignores trailing bytes a future kernel appends),
  and every label-stack / group / segment walker is fixed-stride with
  explicit `<= len` bounds (not the length-field-driven loop the
  rule-2 bug class targets). Added regression tests pinning the
  invariant so a future edit to an exact-size (`len() == SIZE`) guard
  fails CI rather than silently reintroducing the
  `IFLA_INET6_CONF`-class bug. No behaviour change.
- **Bridge-global per-VLAN options — `BRIDGE_VLANDB_GOPTS` (#137
  bridge/FDB wire-format audit).** The 0.22.0 FDB work flagged that
  bridge *global* VLAN options were unmodelled; this lands them. Adds
  the newer **VLAN-DB netlink message family** (`RTM_NEWVLAN` /
  `RTM_DELVLAN` / `RTM_GETVLAN` over `struct br_vlan_msg`) — none of
  which nlink modelled before; the existing `BridgeVlanBuilder` only
  speaks the legacy `IFLA_AF_SPEC` + `RTM_SETLINK` per-port path.
  `BridgeVlanGlobalOptionsBuilder` + `Connection::
  {set,get}_bridge_vlan_global_options[_by_index]` configure and read
  the per-VLAN options that live on the **bridge device itself** —
  multicast snooping, IGMP/MLD querier + versions, the query
  counts/intervals, and the MST instance mapping — for a single VID or
  a VID range. Only options explicitly set are emitted (single-knob
  changes don't disturb the rest). The reader (`BridgeVlanGlobalOptions`)
  is `#[non_exhaustive]` with `Option` fields and follows the
  parser-robustness policy (length-guarded reads, accept-larger-than-
  expected `br_vlan_msg`, malformed dump messages skipped). Wire-format
  tests pin every attribute code against the kernel UAPI. The two
  nested/read-only attributes (`MCAST_ROUTER_PORTS`,
  `MCAST_QUERIER_STATE`) are recognized but deliberately not modelled.
  Demoed by `nlink-bridge vlan global show|set` and the `bridge_vlan`
  example; recipe section in `docs/recipes/bridge-vlan.md`. (Per-VLAN
  `BRIDGE_VLANDB_ENTRY` migration onto the VLAN-DB API remains tracked
  under #137.)
- **Property-based parser-robustness harnesses (#137, Plan 193 phase
  2-3).** Added a `proptest` **dev-dependency** and a `parser_proptest`
  test module that feeds arbitrary bytes to the protocol-stack parsers
  and proves the CLAUDE.md `## Parser robustness` invariants hold across
  the input space the audit scripts can't enumerate: `MessageIter` /
  `AttrIter` never panic and always terminate (the infinite-loop bug
  class — netlink-packet-route #152), `MessageIter` stays exhausted after
  yielding an error (Plan 193 rule 2), the fixed-size struct parsers and
  `get::*` extractors never panic on arbitrary bytes, `NlMsgHdr` accepts
  oversized input (rule 1), and the typed RTNetlink parsers
  (`LinkMessage`/`RouteMessage`/`AddressMessage`/`NeighborMessage`/
  `RuleMessage`/`TcMessage` `::from_bytes`) — the real kernel-response
  attack surface — return `Result` rather than panicking. Runs under
  `cargo test -p nlink --lib` (no root, no `cargo-fuzz` toolchain).

- **Opt-in dispatcher mode is now feature-complete (#134).**
  `Connection::with_dispatcher()` opts a connection into a per-`nlmsg_seq`
  background recv-driver that demultiplexes all frames off one socket, so
  **events, streaming dumps, and requests on the same connection no longer
  serialize** — the F1 regression #134 was filed for. Everything works in
  this mode: unicast requests (pipelined), `events()`/`into_events()`,
  `dump_stream`/`dump_typed_stream`, and the mixed subsystems
  (xfrm/netfilter/ethtool/`command`/`batch`). By design the **default
  stays the lean mutex path** (no background task, no runtime-context
  requirement for one-shot callers); `with_dispatcher()` is the
  concurrency opt-in, and `ConnectionPool<P>` remains the route to
  kernel-parallel dumps (the kernel serializes dumps per socket). See the
  per-stage entries below and CLAUDE.md §Concurrency.
- **Dispatcher mode: event streams now coexist with requests (#134
  streams stage — the headline fix).** `events()` / `into_events()` work
  on a dispatcher-mode `Connection`: instead of holding the request lock
  for the stream's lifetime (which blocked all concurrent requests — the
  exact regression #134 was filed for), they register a raw-frame
  listener on the background driver and consume driver-routed multicast
  (`seq == 0`) frames. A long-lived event subscriber and concurrent
  requests on the **same** connection now both make progress. Also
  hardened: `NetlinkSocket::next_seq()` now **skips 0** so a wrapped
  unicast seq can never be misrouted as a multicast notification. Default
  (mutex) mode is unchanged.
- **Dispatcher mode: mixed-subsystem recv loops migrated (#134 stage 3).**
  The subsystems that mix the driver-backed generic inners with their own
  hand-rolled `recv_msg` loops — xfrm (SA/policy dumps), netfilter
  (conntrack dump), ethtool (`*_GET` / stats / parameterized doit), the
  generic `command` / `dump_command` GENL escape hatches, and the route
  `batch` commit path — now route their loops through a new dual-mode
  `RecvSession` primitive. In the default mutex mode it holds the request
  lock and reads the socket exactly as before (zero behavior change); in
  dispatcher mode it registers the seq(s) on the background driver and
  consumes the routed channel, so the loop coexists with the driver
  instead of racing its `recv_msg`. Dump cycles additionally hold the
  dump-serialization lock (kernel `EBUSY`); the batch path registers all
  its op seqs onto one channel via `register_many`. Bespoke **single-reader**
  subsystems that never touch the driver (sockdiag, audit, connector,
  fib_lookup, selinux, uevent, nftables, nl80211, devlink) keep the
  request lock — it's the correct per-socket serialization there.
- **Dispatcher mode: streaming dumps now supported (#134 streams stage 2).**
  `dump_stream` / `dump_stream_with_body` and the GENL `dump_typed_stream`
  work on a dispatcher-mode `Connection`: they register their seq before
  sending and consume the driver-routed per-seq channel instead of
  polling the socket, so a streaming dump coexists with concurrent
  unicast requests and event subscribers on the same connection. Dumps
  still serialize against each other (the dump-serialization lock is held
  for the stream's lifetime — the kernel returns `EBUSY` on a 2nd
  in-flight dump per socket); use `ConnectionPool` for parallel dumps.
  This also closes the pre-existing no-lock latent race in
  `dump_typed_stream`.
- **Opt-in dispatcher mode — per-`nlmsg_seq` unicast demux foundation
  (#134, Plan 234 follow-on).** `Connection::with_dispatcher()` opts a
  connection into a new request path: a single background recv-driver
  task owns the socket's read side and demultiplexes each datagram to a
  per-`nlmsg_seq` registry, so single-message unicast requests on a
  shared `Arc<Connection>` **pipeline** instead of serializing through
  the F1 `request_lock`, and a long-lived `recv` no longer blocks
  unrelated requests. The driver is spawned lazily on first use and torn
  down on `Connection::drop`; per-seq registration is RAII
  (`PendingGuard`) so a cancelled/timed-out request is cancellation-safe
  (a late frame for a dropped seq is discarded). **Default is off** —
  the existing `request_lock` path is byte-for-byte unchanged, so this
  is a zero-regression addition. Two deliberate constraints in this
  foundation release: (1) **dumps still serialize** even in dispatcher
  mode, because the kernel serializes dumps per socket
  (`netlink_dump_start` returns `EBUSY` on a second concurrent dump);
  use `ConnectionPool<P>` for genuinely parallel dumps. (2) The
  **streaming APIs** (`events`/`into_events`/`dump_stream`/`*_with_resync`)
  return a clear `Error::NotSupported` on a dispatcher-mode connection —
  the driver owns recv, so a second reader would race it; use a
  default-mode `Connection` for events. The full cutover (retiring the
  mutex outright + migrating the streams onto the dispatcher) remains
  the tracked #134 follow-up; this lands the validated demux core behind
  the flag. Also: `Error::is_not_supported()` now also matches the
  library-level `Error::NotSupported` variant (previously errno-only).
- **FDB `NTF_*` flag completeness (#137 bridge/FDB wire-format audit).**
  The FDB builder/reader modelled only `NTF_SELF`/`NTF_MASTER`/
  `NTF_EXT_LEARNED`. Added the remaining `linux/neighbour.h` flags:
  `FdbEntryBuilder::sticky()` (`NTF_STICKY` — pin the entry against MAC
  learning) and `router()` (`NTF_ROUTER` — VXLAN/EVPN router peer) on the
  write side, plus `FdbEntry::is_sticky()`/`is_router()`/`is_offloaded()`
  (`NTF_OFFLOADED`, kernel-set/read-only)/`is_proxy()` accessors on the
  read side. Wire-format tests pin the flag values against the kernel
  UAPI and assert `write_add` lowers them into the `ndmsg.ndm_flags`
  byte. (Bridge global VLAN options — `BRIDGE_VLANDB_GOPTS` — remain
  unmodelled; tracked under #137.)
- **`WireguardConfig::from_wg_quick` + `WireguardConfig::client` (#137).**
  `from_wg_quick(ifname, contents)` parses a `wg-quick` / `wg setconf`
  style `[Interface]` + `[Peer]` config into a declarative
  `WireguardConfig` (then `.diff()` / `.apply()` as usual). It handles
  `PrivateKey`/`ListenPort`/`FwMark` and per-peer `PublicKey`/
  `PresharedKey`/`Endpoint`/`AllowedIPs`/`PersistentKeepalive`, accepts
  comma-separated allowed-IP CIDRs and `0x`-hex fwmarks, matches keys
  case-insensitively, and accepts-and-ignores the `wg-quick`-only
  userspace keys (`Address`, `DNS`, `MTU`, `Table`, `PreUp`/`PostUp`/…).
  Unknown keys, hostname endpoints (no DNS resolution), and peers
  missing a `PublicKey` are hard errors. `client(ifname, priv, server_pub,
  endpoint, allowed_ips, keepalive)` is a convenience constructor for the
  common single-peer client profile. (Plan 196 ergonomic follow-ups.)
- **TC `pedit` action `munge` DSL parser (#137).** `PeditAction::parse_params`
  was a stub that rejected all input; it now parses the `tc(8)` pedit
  syntax — `[ex] munge <spec> [munge ...] [<control>]` — covering the
  layered forms (`ip src|dst|ttl|tos`, `tcp|udp sport|dport`,
  `eth src|dst`), the raw form
  (`offset <off> [u8|u16|u32] set|add <val> [retain <mask>]`), and a
  trailing control verdict (`pipe`/`drop`/…). Values accept decimal or
  `0x`-hex. Per the strict parse_params contract, unmodelled forms
  (`ip6`, the `clear`/`or`/`and`/… ops) return a clear "not modelled"
  error pointing at `PeditAction::set_raw`/`add_raw` rather than being
  silently skipped. `nlink-tc action add pedit munge ...` now works
  (previously errored). The serialization, builder, and the
  `ParseParams` trait wiring were already in place.

- **`Connection::<Ovpn>::attach_socket` / `attach_socket_in_netns` —
  cross-netns transport-socket attach (#136).** The previously-stubbed
  `attach_socket(ifindex, peer_id, fd)` now issues a `peer-set` carrying
  `OVPN_A_PEER_SOCKET = fd`; the kernel resolves the fd via
  `sockfd_lookup` in the **calling process** (fds are process-global,
  not netns-scoped), so a controller that holds the fd can attach a
  socket created in another network namespace. `attach_socket_in_netns`
  additionally sets `OVPN_A_PEER_SOCKET_NETNSID` for the case where the
  kernel must be told the socket's namespace explicitly. **Redesign
  note:** #136 specified an `SCM_RIGHTS` sendmsg path; that premise was
  wrong — netlink generic-command handlers never receive `SCM_RIGHTS`
  file descriptors, and the upstream ovpn netlink spec passes the socket
  as a plain `u32` attribute. Verified against the kernel `ovpn.yaml`
  spec.
- **`NetlinkSocket::send_with_fds(msg, &[fd])` — generic `SCM_RIGHTS`
  `sendmsg(2)` primitive (#136).** A general control-message send path
  (the first `sendmsg`-with-`msg_control` in the crate; all other sends
  use plain `send(2)`). Provided for protocols/out-of-tree kernels that
  genuinely consume passed fds and for fd-relay scenarios; it is **not**
  used by ovpn (see above). cmsg buffer layout (`CMSG_SPACE`/`CMSG_LEN`,
  8-byte alignment) is unit-tested, and a compile-time assertion pins
  that the returned future stays `Send` (the `msghdr`/`iovec` raw
  pointers are built inside the synchronous `try_io` closure, never held
  across the await).

### Changed

- **Typed `TableName` for the nftables API (#137).** nftables table
  names are now the validated `TableName` newtype (mirroring the
  existing `ChainName`): empty / overlong / interior-NUL names are
  rejected at the boundary, and — the real win — `Chain::new(table,
  name)` no longer takes two interchangeable `&str`s, so swapping the
  table and chain arguments is a compile error. The name-taking methods
  (`Connection::{add_table, add_table_with_flags, del_table,
  del_table_if_exists, flush_table, list_chains_in, del_chain,
  del_chain_if_exists}` and `Chain::new`) accept `impl TryInto<TableName
  / ChainName>`, so plain `&str` / `String` call sites are **unchanged**
  (`conn.add_table("filter", Family::Inet)` still compiles, now with
  validation) while already-typed values pass through infallibly. Both
  newtypes gain `FromStr` (`"filter".parse()?`). **Breaking:**
  `Chain::new` now returns `Result` (a malformed name is a local `Err`
  instead of a kernel `EINVAL` later) — add `?` to its call sites. A
  new `From<Infallible> for Error` bridges the typed path's
  conversion. The transaction/batch builder name args remain `&str` for
  now (they return `Self`, so can't surface a validation error
  mid-chain) — a follow-up.
- **`LinkStats` follows the message-accessor convention (#137, Plan
  231 §6).** The parsed `LinkStats` (wrapping `rtnl_link_stats64`,
  reachable via `LinkMessage`) had bare `pub` fields, so it leaked the
  parser's layout and would break downstream the moment a counter was
  added — yet it escaped the `audit-message-accessor-convention.sh`
  gate because its name ends in `Stats`, not `Message`. Its fields are
  now `pub(crate)` behind the existing `rx_packets()` / `tx_bytes()` /
  … accessors and the struct is `#[non_exhaustive]`, and the audit gate
  now covers it. **Breaking:** read the counters via the accessors
  (`stats.rx_bytes()`) instead of field access (`stats.rx_bytes`). The
  separate user-facing `stats::LinkStats` aggregate (with `name` +
  `total_*` / rate helpers) is unchanged — it is a convenience DTO, not
  a parsed wrapper.
- **GENL command unification — closes the H9 stale-frame bug class
  (#135).** The hand-rolled per-family GENL command/dump paths for
  WireGuard, MACsec, MPTCP and ethtool now route through the audited
  canonical `Connection::{send_ack,send_request,send_dump}` helpers
  instead of bespoke single-`recv_msg` blocks. Five `SET`/query helpers
  (`wg_command`, `macsec_command`, `mptcp_command`, `mptcp_query`,
  `ethtool_set`) previously read exactly one datagram and `continue`d
  past any non-matching `nlmsg_seq`, so a stale or interleaved frame
  could make them return `Ok` **without consuming their own ACK** —
  desynchronizing the fd for the next request (the "H9" class). Routing
  through the shared helpers inherits the looped seq-filter + correct
  end-marker + 30 s operation timeout, closing it. In the same pass the
  four byte-identical `process_genl_response`/`process_ethtool_ack`
  copies and the three duplicated per-family `resolve_*_family`
  functions were deleted (the families now share
  `resolve_genl_family`), netting ~430 fewer lines. Library-internal
  only — no public type or method signature changed. (nl80211/devlink
  already used the shared resolver and conformant looped recv paths;
  their dump-path dedup rides along with the #134 dispatcher migration.)

## [0.22.0] - 2026-06-29

### Changed

- **All demo binaries are now `nlink-` prefixed.** The eight that
  previously built as the bare system-tool name (`ip`, `tc`, `ss`,
  `nft`, `bridge`, `wg`, `wifi`, `devlink`) now produce `nlink-ip`,
  `nlink-tc`, … matching `nlink-config`/`nlink-ethtool`, so a demo
  binary never shadows the real iproute2/iw/ethtool tool on `PATH`.
  Cargo package names were already `nlink-*`; only the `[[bin]] name`
  changed (and the CLI tests' `CARGO_BIN_EXE_*` references). Invoke as
  `nlink-ip link show` (or `cargo run -p nlink-ip -- link show`).

### Added

- **sockdiag: `INET_DIAG_REQ_BYTECODE` kernel-side filtering (#120) —
  closes #120 and the #115 coverage epic.** The inet dump now lowers a
  filter's exact source/destination port (`InetFilter::local_port` /
  `remote_port`, set by `ss --sport`/`--dport`) into an
  `inet_diag_bc_op` program attached as `INET_DIAG_REQ_BYTECODE`, so the
  **kernel** pre-filters and only matching sockets cross into userspace
  (previously the dump returned every socket and the bin discarded most).
  The new public `sockdiag::bytecode` module exposes `for_ports` (used by
  the dump path) and a general `compile(&FilterExpr)` that also lowers
  `sport`/`dport` comparisons (`=`/`<`/`<=`/`>`/`>=`) combined with
  `and`; unsupported predicates (`!=`, address/prefix, `state`, any
  `or`/`not`) yield `None` and fall back to the full dump. Any
  client-side filtering stays as the correctness backstop, so the
  pre-filter can only reduce traffic, never change results — and a
  malformed program is rejected by the kernel's `inet_diag_bc_audit`
  with EINVAL (loud), not mis-applied. Byte-exact layout is unit-tested;
  on-kernel semantics are validated by a `require_root!()` integration
  test under the privileged CI (now built with `lab,sockdiag`). Purely
  additive — no public type changed shape.

- **ethtool: RSS read (#119) — closes #119.**
  `Connection::<Ethtool>::get_rss` reads Receive Side Scaling settings
  (`ETHTOOL_MSG_RSS_GET`) for the default or a given context: the
  indirection table (`ETHTOOL_A_RSS_INDIR`, an array of receive-queue
  indices), the hash key (`ETHTOOL_A_RSS_HKEY`), and the raw hash-function
  bitmask (`ETHTOOL_A_RSS_HFUNC`). New `EthtoolRssAttr` enum + `Rss` type.
  Surfaced as `nlink-ethtool -x eth0`. With FEC-set + module-EEPROM, all
  three #119 ethtool gaps are landed.

- **ethtool: module-EEPROM read (#119).**
  `Connection::<Ethtool>::get_module_eeprom` reads raw SFP/QSFP module
  EEPROM bytes (`ETHTOOL_MSG_MODULE_EEPROM_GET`) via a
  `ModuleEepromRequest` (offset/length + page/bank/I2C-address setters,
  length bounded 1..=128). A new `ethtool_get_with` helper sends a
  parameterized `doit` GET (request flag, no dump) and returns the
  single reply, parsing out `ETHTOOL_A_MODULE_EEPROM_DATA`. Surfaced as
  `nlink-ethtool -m eth0` (hex dump). Second of #119's three ethtool gaps.

- **ethtool: `set_fec` FEC setter (#119).** `Connection::<Ethtool>::set_fec`
  configures Forward Error Correction via a `FecBuilder`
  (`ETHTOOL_MSG_FEC_SET`): `.mode("rs")` selects encodings (a named
  `ETHTOOL_A_FEC_MODES` bitset), `.auto(bool)` toggles negotiation.
  Mode names are the kernel-labelled bitset names `get_fec` reports
  (correct-by-construction round-trip); common spellings
  (`off`/`none`/`rs`/`baser`/`llrs`) are normalised. Surfaced as
  `nlink-ethtool set-fec eth0 rs --auto off`. First of #119's three
  ethtool gaps.

- **TC action: `gate` (IEEE 802.1Qci PSFP) typed config (#118) — closes
  the modelable side of #118.** `GateAction` admits packets only during
  the open windows of a cyclic time schedule (TSN per-stream gating):
  `priority`, `base-time`/`cycle-time`/`cycle-time-ext` (`Duration`s, ns
  on the wire, `tc(8)` time strings accepted), `clockid`
  (`TAI`/`REALTIME`/`MONOTONIC`/`BOOTTIME` or numeric), and a repeatable
  `sched-entry open|close <interval> [<ipv> [<max-octets>]]` schedule.
  The entry list is built as nested `TCA_GATE_ONE_ENTRY` items under
  `TCA_GATE_ENTRY_LIST` (gate-open is an `NLA_FLAG`). New `action::gate`
  wire module. 19 action parsers. **`xt`/`ipt` is intentionally not
  modelled**: `act_ipt` requires a `TCA_IPT_TARG` `xt_entry_target` blob
  built via libxtables, with no pure-netlink construction path — a
  hook/index-only config would be rejected with EINVAL, so it's
  documented as out-of-scope under #118 rather than shipped broken.

- **TC action: `ife` (Inter-FE) typed config (#118).** `IfeAction`
  tunnels skb metadata (mark / priority / tcindex) between forwarding
  elements: `encode` writes selected metadata into an IFE Ethernet
  header (with optional `dst`/`src` MAC + `type` ethertype overrides),
  `decode` reads it back. Each metadata item is `allow`ed (carry the
  skb's value) or `use`d with an explicit override. New `action::ife`
  wire module (`tc_ife` = `tc_gen` + flags; metadata rides in the nested
  `TCA_IFE_METALST` list). 18 action parsers. Second of #118's actions.

- **TC action: `ctinfo` typed config (#118).** `CtinfoAction` restores
  conntrack metadata into the packet — a DSCP value (under a state mask)
  into the IP DS field via `dscp <mask>[/<statemask>]`, and/or the
  connection mark into `skb->mark` via `cpmark [<mask>]` (bare `cpmark`
  uses the full mask), scoped by `zone`. Masks parse as `0x`-hex or
  decimal; at least one of `dscp`/`cpmark` is required. New
  `action::ctinfo` wire module (`tc_ctinfo` = `tc_gen` header; params
  ride as separate attrs). 17 action parsers. First of #118's four
  actions.

- **TC filter: `rsvp` / `rsvp6` classifier typed config (#117).**
  `RsvpFilter` matches flows by `session` (destination) and `sender`
  (source) address, narrowed by `ipproto` and `tunnelid`, with
  `classid`/`flowid` and `chain`. The address family is inferred from the
  addresses — an IPv6 session/sender selects the `rsvp6` kernel
  classifier, IPv4 selects `rsvp` — so a single config + both bin
  dispatch arms cover the pair. New `filter::rsvp` wire module
  (`tc_rsvp_pinfo`/`tc_rsvp_gpi`). **Port-level matching is not
  modelled**: `session <addr>/<port>` uses a protocol-specific
  general-port-info offset, so an embedded `/<port>` is rejected with a
  clear not-modelled error rather than emitting a zeroed/incorrect GPI;
  the `tunnel <id> skip <n>` creation form is likewise rejected. 11
  filter parsers total.

- **TC qdisc: `atm` (`sch_atm`) typed config (#116) — closes the qdisc
  side of #116.** The ATM qdisc is classful and takes no qdisc-level
  options, so `AtmConfig` is a unit config (`tc qdisc add … root atm`
  instantiates the classful qdisc). VC binding lives in the **classes**
  (`TCA_ATM_FD` + friends), which require the file descriptor of a live,
  application-owned ATM socket — no portable/testable surface — so nlink
  does not model an ATM class config; the rustdoc points at a hand-rolled
  `MessageBuilder` for that case. 35 qdisc parsers total. With this,
  `choke`/`gred`/`atm`/`pfifo_fast` from #116 are all landed.

- **TC qdisc: `gred` (Generic RED) setup-phase typed config (#116).**
  `GredConfig` models the GRED **setup** message — virtual-queue count
  (`DPs`, 1..=16), default VQ, GRIO flag, and global byte `limit` — sent
  as `struct tc_gred_sopt` under `TCA_GRED_DPS` (+ `TCA_GRED_LIMIT`). This
  is the mandatory first step that installs the virtual-queue table; a
  setup-only GRED is a complete, valid operation. **Per-VQ RED
  parameterization is deliberately not modelled**: it requires the
  256-byte RED stab probability table the kernel demands under
  `TCA_GRED_STAB` (which plain `RedConfig` also sidesteps), so
  `parse_params` rejects per-VQ tokens (`min`/`max`/`avpkt`/`bandwidth`/
  `DP`/`probability`/`prio`/…) with a clear not-modelled error rather than
  emitting a message the kernel would refuse — tracked as a #115 follow-up.
  34 qdisc parsers total. New `qdisc::gred` wire module.

- **TC qdiscs: `choke` and `pfifo_fast` typed configs (#116).** Two
  more qdisc kinds reach typed-first parity (33 qdisc parsers total).
  `ChokeConfig` is a RED-family AQM that shares `struct tc_red_qopt`
  with `RedConfig` and adds CHOKe differential dropping; its
  `parse_params` mirrors RED (`limit`/`min`/`max`/`probability`/`ecn`/
  `harddrop`, with `avpkt`/`burst`/`bandwidth` reported as not-modelled
  rather than silently dropped). `PfifoFastConfig` is a unit config —
  `pfifo_fast`'s bands and priomap are hardcoded kernel-side, so it
  accepts no options; adding it explicitly restores the kernel-default
  qdisc after a root replacement. Both wired into the `tc` bin
  dispatch + recognised-kinds list. First of the #115 coverage epic.

- **`nft` bin: declarative `reconcile`/`diff` over the `NftablesConfig`
  engine (#109).** New `nft reconcile <file>` reads a *desired-state*
  ruleset (the same `add table`/`add chain`/`add rule` grammar as
  `apply`), folds it into an `NftablesConfig`, diffs it against the
  live ruleset, and applies the minimal change set via the library's
  `diff`/`apply`/`apply_reconcile` engine (the same one the `config`
  binary uses for interfaces). `nft diff <file>` is the read-only
  preview; `--dry-run` / `--no-retry` tune `reconcile`. Because it is
  desired-state, `delete`/`flush` lines are rejected (removal is
  inferred from the diff) — `nft apply` remains the imperative,
  single-transaction path. The rule-spec parser is shared with
  `apply` (STRICT: an unrecognized token fails the whole parse, never
  a silent drop). This is deliberately *not* a serde-`Deserialize`
  path: nft rule bodies are low-level VM byte expressions, so the
  human-facing format is the rule DSL lowered through the typed
  builders. Parser unit tests cover the fold, the desired-state
  rejections, and strict error propagation.

- **library: strongly-typed, round-trippable `NetworkConfig` (#108).**
  The declarative `NetworkConfig` tree was `Serialize`-only; it now
  also implements a **validating** `serde::Deserialize` behind the
  `serde` feature, so the typed config round-trips through YAML/JSON
  directly (no stringly intermediate schema). The human-facing forms
  are idiomatic: addresses/routes round-trip as CIDR strings (`route`
  destinations as the `default` keyword for `0.0.0.0/0` / `::/0`),
  MACs as `aa:bb:cc:dd:ee:ff`. Validation is preserved rather than
  bypassed — deserialization goes through the same parse paths as the
  builders (via serde's `try_from`/`into` conversion attributes), so
  an out-of-range prefix, a malformed gateway, or a bad MAC is a
  deserialize **error**, not a silently-accepted struct. New
  high-level helpers `NetworkConfig::{from_json_str, to_json_string,
  to_json_string_pretty}`. The `serde` feature now also pulls
  `serde_json` for these. Additive (new trait impls + methods);
  `cargo-semver-checks` clean.

- **`ss`/library: AF_PACKET socket diagnostics (#29).** `query_packet`
  was a stub returning an empty list; it now issues a real
  `PACKET_DIAG` (`SOCK_DIAG_BY_FAMILY` with `sdiag_family = AF_PACKET`)
  dump and parses `packet_diag_msg` + `PACKET_DIAG_INFO`/`UID`/`FANOUT`/
  `MEMINFO` into `PacketSocket` (bound interface, protocol, type, uid,
  fanout, recv/send queues). New `Connection<SockDiag>::query_packet_sockets`
  convenience method, surfaced in the `ss` bin as `-0`/`--packet`.

- **`ethtool`/library: Forward Error Correction read (#29).** New
  `Connection<Ethtool>::get_fec`/`get_fec_by_name` over
  `ETHTOOL_MSG_FEC_GET`: configured-modes list, auto-negotiation flag,
  and the active FEC mode (raw `ETHTOOL_LINK_MODE_FEC_*` bit). Surfaced
  as `ethtool fec`. Read-only for now — a typed FEC setter needs the
  kernel-specific mode bit-names and is left to a follow-up.

- **`ethtool`/library: Energy-Efficient Ethernet get/set (#29).** New
  `Connection<Ethtool>::get_eee`/`set_eee` (+ `_by_name`) over
  `ETHTOOL_MSG_EEE_{GET,SET}`: read active/enabled/TX-LPI state, the
  TX-LPI timer, and the advertised/peer EEE link-mode lists; set
  `enabled`/`tx_lpi`/`tx_lpi_timer` via an `EeeBuilder`. Surfaced in
  the `ethtool` bin as `eee` (show) and `set-eee` (set).

- **`ethtool`/library: Wake-on-LAN get/set (#29).** New
  `Connection<Ethtool>::get_wol` / `set_wol` (plus `_by_name`)
  over `ETHTOOL_MSG_WOL_{GET,SET}`: read supported/active modes + the
  SecureOn password, and enable modes by name (`phy`, `ucast`, `mcast`,
  `bcast`, `arp`, `magic`, `magicsecure`, `filter`) via a `WolBuilder`.
  Unknown mode names are rejected before the request is sent. Surfaced
  in the `ethtool` bin as `wol`/`-w` (show) and `set-wol`/`-W` (with a
  `none` sentinel to disable all), printing the `p u m b a g s f`/`d`
  flag string ethtool(8) uses.

- **`tc`/library: `mpls` and `skbmod` actions (#29).** Two new typed
  TC actions in the standard `*Action` + `parse_params` shape, wired
  into `tc action add … mpls|skbmod`. `MplsAction` pushes/pops/modifies
  an MPLS shim or decrements its TTL (`label`, `tc`, `ttl`, `bos`,
  `protocol`) via `struct tc_mpls`. `SkbmodAction` rewrites L2
  src/dst MAC and/or ethertype, or swaps MAC (`set smac|dmac|etype`,
  `swap mac`) via `struct tc_skbmod`. Brings the typed-action count to
  16. (The remaining `ife`/`gate`/`ctinfo`/`xt` actions stay deferred —
  metadata-encap / time-gated-schedule / iptables-target wrappers that
  are complex or niche.)

- **`tc`/library: `tcindex` filter (#29).** New `TcindexFilter` typed
  config (`hash`, `mask`, `shift`, `fall_through`/`pass_on`, `classid`,
  `chain`) over the `TCA_TCINDEX_*` attributes, wired into `tc filter
  add … tcindex`. The canonical companion to the `dsmark` qdisc for
  DiffServ classification. Brings the typed-filter count to 10. (`rsvp`
  remains deferred — a session/sender classful filter that is rarely
  used and needs the `tc_rsvp_pinfo` selector struct.)

- **`wifi`/library: `del_station` (kick an AP client) (#29).** New
  `Connection<Nl80211>::del_station(iface, mac)` /
  `del_station_by_index` send `NL80211_CMD_DEL_STATION` to
  deauthenticate an associated station, surfaced as `nlink-wifi
  del-station <iface> <mac>`. Complements the existing read-only
  `station` listing for AP-mode management.

- **`tc`/library: `hhf` and `dsmark` qdiscs (#29).** Two more typed
  qdisc configs wired into `tc qdisc add … hhf|dsmark`. `HhfConfig`
  drives the Heavy-Hitter Filter (`limit`, `quantum`, `hh_limit`,
  `reset_timeout`, `admit_bytes`, `evict_timeout`, `nonhh_weight`) over
  the individual `TCA_HHF_*` attributes (timeouts sent as microseconds,
  matching the kernel's `usecs_to_jiffies`). `DsmarkConfig` drives the
  DiffServ-marking qdisc's `indices`/`default_index`/`set_tc_index`
  (per-index `mask`/`value` remain class-level). Brings the typed-qdisc
  count to 31.

- **`tc`/library: `sfb` and `multiq` qdiscs (#29).** Two more typed
  qdisc configs in the standard `*Config` + builder + strict
  `parse_params` shape, wired into `tc qdisc add … sfb|multiq`.
  `SfbConfig` drives Stochastic Fair Blue (`limit`, `rehash`, `db`,
  `max`, `target`, `increment`, `decrement`, `penalty_rate`,
  `penalty_burst`) packed into `struct tc_sfb_qopt` under
  `TCA_SFB_PARMS`. `MultiqConfig` drives the band-per-tx-queue qdisc —
  parameterless (the kernel derives band count from the device's
  tx-queue count), writing a zeroed `struct tc_multiq_qopt`. Brings the
  typed-qdisc count to 29.

- **`tc`/library: `cbs` and `skbprio` qdiscs (#29).** Two new typed
  qdisc configs with the standard `*Config` + fluent builder +
  strict `parse_params` shape, wired into `tc qdisc add … cbs|skbprio`.
  `CbsConfig` drives the IEEE 802.1Qav Credit-Based Shaper (AVB/TSN):
  `idleslope`/`sendslope` (kbit/s), `hicredit`/`locredit` (bytes), and
  `offload` packed into `struct tc_cbs_qopt` under `TCA_CBS_PARMS`.
  `SkbprioConfig` drives the SKB-priority queue (`limit` packets).
  Brings the typed-qdisc count to 27.

- **`tc` bin: `filter` parity — show across all parents, `--chain`,
  partial delete (#19).** `tc filter show dev X` now lists filters
  across *every* parent (root, ingress, clsact, …) instead of silently
  defaulting to `root` only — previously ingress/clsact filters
  vanished from the listing; pass `--parent <handle>` to narrow.
  `filter add/replace/change … --chain N` sets the filter chain index
  (tc(8) `chain N`), threaded generically through every kind via a new
  defaulted `FilterConfig::set_chain` trait method (additive; all nine
  shipped configs override it). `filter del` regained partial form:
  supplying both `--protocol` and `--prio` deletes one filter, supplying
  neither flushes every filter on the parent (`tc filter del dev X
  parent 1:`); a half-specified tuple is rejected rather than guessed.

- **`nlink-config` bin: `apply --reconcile` + higher-fidelity capture
  (#22).** `apply --reconcile` drives the library's `apply_reconcile`
  (recomputes the diff each attempt, bounded retry on transient kernel
  contention); mutually exclusive with `--dry-run`. `capture` now decodes
  qdisc options (htb/tbf/netem/fq_codel parameters) into the
  `options` map instead of leaving it empty, and unmodelled route/rule
  types are warned about and preserved verbatim rather than silently
  dropped to `None`. The duplicated `OutputFormat` enum (capture +
  example) is unified in `schema.rs`.

- **`nft` bin: idempotent deletes + richer `list rules` (#21).** `nft
  delete table/chain/rule/set` now uses the `*_if_exists` library
  variants, so deleting a missing object is a clean no-op ("… did not
  exist (no-op)") instead of an error — matching declarative teardown
  expectations. Added the missing `del_set_if_exists` library method.
  `list rules` now also surfaces each rule's `position`, `comment`, and
  expression-payload size (text + JSON), rather than only the handle;
  full expression disassembly stays out of scope (the library keeps rule
  expressions as raw bytes by design).

- **`ip` bin: `macsec add`/`set`/`del` (TX/RX SA + RX SC) (#17).** The
  `ip macsec` object was show-only; it now mutates MACsec secure
  associations over the existing `Connection<Macsec>` GENL API. `add tx
  --an <0-3> --key <hex> [--key-id <hex>] [--pn N] [--active on|off]`
  installs a TX SA; `add rx --sci <hex|dec>` creates an RX secure
  channel, and adding `--an` targets an RX SA within it; `set`
  updates an existing SA; `del` removes the SA/SC. The device is
  resolved to an ifindex up front so the `*_by_index` calls are
  namespace-safe, and `--an > 3` / odd-length hex are rejected before
  reaching the (panicking) builder.

- **`bridge` bin: `monitor` command (#25).** Streams bridge FDB changes
  in real time — `bridge monitor` subscribes to `RTNLGRP_NEIGH` and
  prints `NewFdb`/`DelFdb` events (text or `--json`, with `-t` for
  timestamps), mirroring `bridge monitor fdb`. (MDB-event monitoring is
  deferred until the library models `RTM_*MDB` notifications.)

- **`bridge` bin: `fdb add --extern-learn` and `fdb show --brport` (#25).**
  `fdb add … --extern-learn` marks an entry `NTF_EXT_LEARNED` (a
  user-space control plane owns it; the kernel won't age/overwrite it) —
  backed by a new `FdbEntryBuilder::extern_learn()` library setter. `fdb
  show <bridge> --brport <port>` lists only the entries learned on a
  given bridge port via the existing `get_fdb_for_port`, mirroring
  `bridge fdb show br <dev> brport <port>`.
- **`ip` bin: real `netns set <name> <nsid>` and nsid display in `netns
  list` (#17).** `netns set` was a stub that printed "Setting…" and
  returned `Ok` without doing anything; it now sends `RTM_NEWNSID` (new
  `Connection::set_nsid` library method) to assign the id — or
  auto-allocate on `auto`/`-1`, reading the chosen id back. `netns list`
  previously always showed no id because `get_namespace_id` returned
  `None`; it now queries each namespace via the existing `get_nsid`
  (`RTM_GETNSID`), so `(id: N)` appears for namespaces that have one.
- **`tc` bin: implement `qdisc show --invisible` (#19).** The flag was
  parsed but ignored, so `tc qdisc show invisible` behaved identically
  to a plain show. It now sets `TCA_DUMP_INVISIBLE` on the
  `RTM_GETQDISC` dump (via the new `Connection::get_qdiscs_full`
  library method), so the kernel also returns the auto-created default
  qdiscs it normally hides.

- **`wg` bin: `addconf` config-file apply (#23).** Completes the
  `setconf`/`syncconf`/`addconf` trio over `WireguardConfig`. `addconf`
  is the additive form — it appends the file's peers/settings without
  removing existing peers. (Because the library's `apply` never prunes
  unlisted peers, it currently coincides with `setconf`; the two diverge
  once `setconf` gains real unlisted-peer pruning.)

- **`ss` bin: implement `-O`/`--oneline` (#20).** The flag was parsed and
  stored but never read, so each socket's extended/memory/TCP-info/timer
  detail always wrapped onto `\t`-prefixed continuation lines. With
  `--oneline` those segments are now space-joined onto the socket's row,
  so each socket occupies exactly one line (matching real `ss -O`).

- **`ethtool` bin: surface already-parsed link detail in `show` (#27).**
  `show` now prints the data the library already decoded but the binary
  dropped: PHY address, MDI-X status (+ configured control), Signal
  Quality Index (`sqi`/`sqi_max`), the extended link state + substate
  (why a link is down), and pause-frame statistics in `show pause`. All
  appear in both the text and `--json` output, with stable string
  mappings for the MDI-X / ext-state enums.
- **`wifi` bin: show more station detail (#24).** `wifi station` now
  prints the already-parsed `signal_avg_dbm`, `connected_time_secs`, and
  `inactive_time_ms` fields (previously dropped), alongside the existing
  signal / bitrate / byte counters.

- **`wg` bin: incremental allowed-ips + private-key unset (#23).** `wg set
  … --allowed-ips` now honors the `+` prefix to *add* ranges without
  replacing the peer's set (a plain list still replaces, matching real
  `wg set`); a `-` prefix (single-range removal) returns a clear "not
  modelled" error since the library lacks the WGALLOWEDIP remove flag, and
  mixing plain/`+` is rejected. `wg set … --private-key /dev/null` (or an
  empty file) now unsets the device key (all-zero key = remove) instead of
  failing the length check.
- **`ss` / `nft` bins: extend unit coverage of the pure parsers (#20,
  #21).** Added `nft` tests for `parse_family` (+ aliases), `parse_hook`
  (incl. the netdev/inet `ingress` split), and `parse_cidr`; and `ss`
  tests for `format_addr` (unspecified-address and zero-port rendering).
- **`ip` bin: `ip link set <dev> --netns <name|pid>` (#17).** Moves a
  device into another network namespace, wiring the existing
  `set_link_netns_by_index` / `set_link_netns_pid_by_index` library APIs.
  The ifindex is resolved once up front so the move is namespace-safe; a
  numeric argument is treated as a target PID, anything else as a named
  netns under `/var/run/netns` (mirrors iproute2).
- **`wg` bin: `setconf` / `syncconf` config-file apply (#23).** A new
  bin-local parser reads the kernel-level WireGuard config-file format
  (`[Interface]` PrivateKey/ListenPort/FwMark, `[Peer]`
  PublicKey/PresharedKey/Endpoint/AllowedIPs/PersistentKeepalive) into the
  library's `WireguardConfig`, then `wg setconf <if> <file>` applies it and
  `wg syncconf <if> <file>` applies it with bounded retry (the documented
  reconcile shape). The parser is the inverse of `wg showconf` and is
  **strict** — unknown keys, malformed values, and a `[Peer]` without a
  `PublicKey` are hard errors (matching real `wg setconf`, which rejects
  wg-quick-only keys like `Address`/`DNS`/`MTU`). No library change; the
  parser lives in the binary (precedent: the `config` binary's schema).
- **`wg` bin: `--json` for `show` and `showconf` (#23).** Both gain
  `-j/--json` (+ `-p/--pretty`) emitting a stable device/peer shape. `show`
  hides the private/preshared keys (mirroring the `(hidden)` text output);
  `showconf --json` reveals them, since it is a config dump. Brings `wg`
  into line with the other binaries' machine-readable output.
- **`bridge` / `diag` bins: unit tests for the pure parse/format helpers
  (#25, #28).** Both binaries previously shipped with zero tests. Added
  non-root unit coverage for `bridge`'s `parse_vid_range` (VLAN id/range)
  and `OnOff` flag parser, and `diag`'s `parse_severity`, `severity_icon`,
  `oper_state_str`, `format_bytes`, plus the severity ordering the
  `--min-severity` filter relies on.

### Added

- **CLI parse-test suites for `ss`, `bridge`, and `nlink-config`
  (#20, #25, #22).** Each bin gained a `tests/cli_parsing.rs` mirroring
  the `ip`/`tc` pattern (`assert_cmd` + `predicates`). The suites are
  hermetic — they exercise clap's parse phase (root + per-subcommand
  `--help`, invalid input, arg conflicts, typed-value rejection) which
  completes before any netlink socket opens, so they run as a non-root
  user with no live kernel. They lock in the hardening-campaign
  additions (`ss --packet`/`--oneline`/`--sport`, `bridge fdb add
  --extern-learn`, `config apply --reconcile` ⊥ `--dry-run`) against
  silent regression, and `config example` is run end-to-end (it emits
  an embedded sample with no kernel access).

### Fixed

- **`ss` bin: JSON output honors display flags + process parity (#20).**
  `ss -j` previously dumped the `tcp_info`/`mem_info`/`congestion`/
  `mark` blocks unconditionally whenever the kernel returned them,
  regardless of the `-i`/`-m`/`-e` flags, and never emitted the
  owning-process data that `-p` shows in text. The JSON now mirrors
  the text columns: `tcp_info` (+ `congestion`) only with `-i`,
  `mem_info` only with `-m`, the extended `interface`/`mark` fields
  only with `-e`, an active `timer` only with `-o`, and a structured
  `process` array (`comm`/`pid`/`fd`) only with `-p`. Unit tests cover
  the gating in both directions.

- **`ip` bin: `sr tunsrc show --pretty` + POC version string (#17).**
  `sr tunsrc show -j` hand-rolled its JSON and ignored the global
  `--pretty` flag; it now builds the object via `serde_json` so
  `--pretty` is honored and the address is correctly escaped. The
  `ip --version`/`--help` strings now identify the binary as the
  nlink proof-of-concept ("not iproute2") so it can't be confused
  with a real `ip(8)`.

- **`tc` bin: namespace-safe `qdisc`/`class`/`filter show` (#19).** The
  three show paths resolved the device name→ifindex via
  `nlink::util::get_ifindex` (a `/sys/class/net` read in the *calling
  process's* mount namespace), which returns the wrong index inside a
  foreign netns. They now resolve over netlink via
  `Connection::get_link_by_name` (RTM_GETLINK in the connection's
  netns). The mutating paths were already netlink-safe via
  `resolve_interface`.

- **bin JSON robustness + deterministic `bridge vlan` output (#25, #19).**
  The `bridge` (`vlan`/`fdb`/`mdb`) and `tc` (`chain`) JSON show paths
  used `.expect("JSON serialization")`, a latent panic path; they now
  return a proper `Error` via a shared `to_json_string` helper.
  `bridge vlan show --json` also groups interfaces through a HashMap, so
  its output order was nondeterministic — it now sorts by ifindex for
  stable, diffable JSON.

- **`ip` bin: namespace-safe `maddr show` interface resolution (#17).**
  `maddr` resolved the interface name→index map by scanning
  `/sys/class/net`, which always reads the host namespace and so showed
  wrong indices inside a foreign netns. It now resolves the map over
  netlink (`RTM_GETLINK`). The `/proc/net/{dev_mcast,igmp,igmp6}` reads
  stay — they are per-netns and the kernel-blessed source for multicast
  membership (no netlink equivalent). Documented that `maddr add/del` is
  intentionally not offered: the kernel exposes static L2 multicast only
  via the `SIOCADDMULTI`/`SIOCDELMULTI` ioctls, out of scope for this
  netlink-first demo.
- **`tc` bin: remove the dead `-b`/`--batch` flag (#19).** It was a
  global option declared "(not yet implemented)" and never read — a
  silent no-op that violated the strict-no-op contract. Dropped rather
  than left lying; a real batch interpreter can return as a focused
  feature.
- **`bridge` bin: remove the dead `-s`/`--stats` flag (#25).** It was
  plumbed into `OutputOptions` but never read by any `fdb`/`vlan`/`mdb`
  output path — a silent no-op. The bridge entry types don't carry
  per-entry statistics (NDA_CACHEINFO ages, MDB timers, per-VLAN
  counters) yet, so there's nothing to show; surfacing real stats needs
  library support first. Dropped rather than left lying.
- **`ss` bin: ss-expression filters no longer pass non-inet sockets
  unconditionally (#20).** `FilterExpr::matches_socket_info` returned
  `true` for every unix/netlink/packet socket, so `ss -x 'sport = :22'`
  kept *all* unix sockets. Every predicate in the grammar
  (`sport`/`dport`/`src`/`dst`/`state`) reads inet fields, so an
  expression is inherently inet-only; a non-inet socket can't satisfy it
  and is now excluded — matching the `InetMatch` exclusion the binary
  already applies to `--sport`/`--dport`/`--src`/`--dst`.
- **`ip` bin: namespace-safe `neighbor show`/`flush` device filter (#17).**
  Both resolved the device via `get_neighbors_by_name`, which reads the
  name from the host `/sys` and so returns wrong results inside a foreign
  netns. They now resolve the ifindex over netlink (`get_link_by_name`)
  and use `get_neighbors_by_index`, per the CLAUDE.md "prefer `_by_index`"
  policy. A missing device is now a clear error instead of an empty list.
- **`ip` bin: strict-parse the link-add mode helpers (#17).** The bond
  `mode`/`xmit_hash_policy`/`lacp_rate`, `macvlan`/`macvtap` `mode`,
  `ipvlan` `mode`, and VLAN `protocol` parsers silently mapped unknown
  input to a default (e.g. `mode bogus` → `balance-rr`), hiding typos.
  They now return `Error::InvalidMessage` on unrecognized input, in line
  with the CLAUDE.md strict-parse contract.
- **`ip` bin: kill silent no-ops in `addr`/`tunnel`/`rule` (#17).**
  `ip addr add … peer <addr>` now actually sets the peer address (it was
  parsed and dropped); a bad peer value or family mismatch errors. `ip
  tunnel add … tos/pmtudisc/nopmtudisc/dev` were silently ignored — they
  are now wired to the tunnel builders (`tos`/`pmtudisc` error as "not
  modelled" for `vti`, which lacks them; `--pmtudisc` + `--nopmtudisc`
  together is rejected as contradictory). `ip rule … nop`/`goto`, which
  the rule builder does not model, now error instead of silently sending
  a plain table-lookup rule.
- **`ip` bin: honor `-j`/`-p` in `tunnel show` and `nexthop show` (#17).**
  `tunnel show` discarded the user's output flags entirely (it passed
  `OutputOptions::default()`), and `nexthop show` always pretty-printed
  JSON regardless of `-p`. Both now thread the real `OutputOptions`
  through, so `-j`/`-p` behave consistently with the other objects.
- **`devlink` bin: type-aware `param set` (#26).** The value was inferred
  lossily (bool → u32 → string), so a `u8`/`u16` parameter or an all-digit
  string label silently became a `u32`. `param set` now reads the
  parameter's declared type via `get_param` first and parses the value
  into it — rejecting out-of-range or non-boolean input — and only falls
  back to inference when the parameter can't be read.
- **`nft` bin: real chain type/hook/priority/policy in `list chains` (#21).**
  The text and JSON output hardcoded `type filter hook <n>` and showed the
  raw hook *number*. `list chains` now prints the actual `chain_type`,
  hook *name* (family-aware: netdev → ingress/egress, else the L3 hooks),
  `priority`, default `policy`, and bound `device` from the kernel's
  `ChainInfo`.
- **`devlink` bin: readable `monitor` output (#26).** `devlink monitor`
  printed raw `{:?}` Debug for each event. It now renders a concise line
  per event (`new device …`, `new port … (eth3)`, `health event …`,
  `flash update …`), with a Debug fallback for future event variants.
- **`ip` bin: namespace-safe `nexthop show` device names (#17).** The
  ifindex→name resolution scanned `/sys/class/net/*/ifindex`, which reads
  the calling process's mount namespace and prints the wrong (or no) device
  name for a nexthop dumped from a foreign netns. It now resolves names via
  a single `RTM_GETLINK` dump on the connection (`get_interface_names`),
  which is always relative to the connection's netns, and reuses the map for
  every nexthop instead of re-scanning sysfs per entry.

## [0.21.0] - 2026-06-04

**Major release.** Closes the remaining audit-derived plans from the
0.20-cycle suite plus the discretionary plans (197, 234) that were
seeded at cycle open. Breaks ABI on five APIs that were deprecated in
0.20.1 and on five `*Message` types that get field-visibility tightening.

### Breaking changes

- **`DpllPin::fractional_frequency_offset_ppt` widened from `Option<i32>`
  to `Option<i64>`.** Silent truncation on overflow was the audit
  finding that motivated the 0.20.1 deprecation. The
  `_i64` parallel field added in 0.20.1 is now the single field; the
  deprecated `i32` field is removed.
- **Raw-`u8` route-rule API removed.** `Connection::<Route>::flush_rules`,
  `get_rules_for_family`, and `del_rule_by_priority` no longer take
  `family: u8`. The `_typed(AddressFamily)` siblings from 0.20.1 take
  over the original names; the `_typed` suffix is dropped.
- **`QdiscBuilder::loss(f64)` removed.** Use `loss_pct(Percent)`.
- **`Verdict::Jump(String)` and `Verdict::Goto(String)` removed.** Use
  `Verdict::JumpTo(ChainName)` / `Verdict::GotoTo(ChainName)`.
  `RuleBuilder::jump` / `goto` now take pre-validated `ChainName`
  infallibly; new `try_jump` / `try_goto` siblings take `&str` and
  return `Result<Self>`.
- **`RuleMessage` fields demoted from `pub` to `pub(crate)`** + `#[non_exhaustive]`.
  Use the per-field accessor methods shipped in 0.20.1 Plan 231.
  Sibling types — `BridgeVlanEntry`, `FdbEntry`, `MplsRoute`,
  `Nexthop`, `NexthopGroupMember`, `NsIdMessage` — get the same
  treatment plus accessor methods. New
  `scripts/audit-message-accessor-convention.sh` CI gate locks the
  convention. `AddressMessage` / `LinkMessage` / `NeighborMessage` /
  `RouteMessage` / `TcMessage` gain `#[non_exhaustive]` (fields stay
  `pub`; bin construction is the source of literals).

### Added

- **Plan 197 — Declarative `OvpnConfig` for OpenVPN data-channel
  offload.** New `Connection<Ovpn>` GENL family covers 8 commands +
  3 multicast notifications (kernel 6.16+): `peer_new` / `peer_set`
  / `peer_get` / `peer_dump` / `peer_del`, `key_new` / `key_get` /
  `key_swap` / `key_del`, plus the `peer-del-ntf` / `key-swap-ntf` /
  `peer-float-ntf` multicast notifications via `subscribe_peers()`.
  Declarative `OvpnConfig::diff().apply()` and `apply_reconcile`
  mirror `WireguardConfig`'s pattern. Recipe at
  `docs/recipes/openvpn-dco.md`. Runnable example at
  `crates/nlink/examples/genl/ovpn.rs`. 44 lib + 7 root-gated
  integration tests. The `attach_socket` cross-netns SCM_RIGHTS
  helper is plumbed but returns `Error::NotSupported` pending a
  sendmsg-layer cmsghdr refactor (deferred to 0.21.x); same-netns
  callers already work via `OvpnPeer::socket = Some(fd)`.

- **Plan 234 — F1 follow-on: Dispatcher foundation + ENOBUFS
  routing.** New `netlink::dispatcher` module provides an
  `Arc`-shared, `Send + Sync` broadcast surface that the
  `NetlinkSocket` recv path routes ENOBUFS into. Every multicast
  subscriber sharing an `Arc<Connection>` receives
  `ResyncMarker::ResyncStart` on socket overflow (deliberate
  divergence from neli's silent-drop behaviour — see CLAUDE.md
  `## Concurrency`). `Connection<P>` exposes `dispatcher() -> &Dispatcher`.
  The F1 `tokio::sync::Mutex` stays for unicast requests pending the
  per-seq pipelining batch (queued as 0.21.x follow-on); this commit
  is the broadcast-side foundation + the socket hook + 24 new tests
  (13 unit + 11 integration including per-family wiring smoke checks
  for wireguard / macsec / mptcp / ethtool / nl80211 / devlink / dpll).

- **Plan 228 extension — Declarative netem parity setters.** Five
  new `*_pct(Percent)` setters on the declarative `QdiscBuilder` for
  netem: `duplicate_pct`, `corrupt_pct`, `reorder_pct`,
  `loss_correlation_pct`, `delay_correlation_pct`. Closes the
  declarative-vs-imperative netem gap noted in 0.20.1's "Deferred to
  0.21" list.

- **Plan 231 extension — Sibling `*Message` accessor sweep.** Four
  more types from `crates/nlink/src/netlink/{bridge_vlan,fdb,mpls,nexthop}`
  get per-field accessors + `#[non_exhaustive]` + `pub(crate)` field
  demotion. `audit-message-accessor-convention.sh` extended to
  cover them.

- **Plan 229 — Doc-drift sweep + new CI gates.** ~16 doc-comment
  sites flipped (sync `conn.events()` → `.await`, deprecated builder
  references replaced, WG `private_key` corrected post-PR-#9). New
  `scripts/audit-recipe-drift.sh` (blocking) catches stale recipe
  patterns. New `doctest-nlink` GHA job runs `cargo test --doc`
  non-blocking initially (per Plan 229 §3 — promoted to blocking
  after one cycle of stability).

- **Migration guide.** `docs/migration_guide/0.20.0-to-0.21.0.md`
  with before/after code samples for every breaking removal +
  quick-fix cheat sheet. README index updated.

### Deferred to 0.21.x

- Plan 234 per-seq unicast pipelining — the dispatcher's
  broadcast-side foundation ships here; per-seq oneshot
  registration + pending-map demux through the dispatcher's recv
  loop is the obvious next batch (~30 callsites across 6 files).
  The public API stays unchanged so the follow-on is a pure
  internal refactor.
- `attach_socket` cross-netns SCM_RIGHTS helper (Plan 197) —
  needs a sendmsg-layer `cmsghdr` refactor of `NetlinkSocket`.
  Same-netns fd passing already works.

### Notes

- `cargo-semver-checks` against `v0.20.1` is expected to fail on the
  breaking changes — that's the point of 0.21.0.
- Discretionary plans 235 (GENL command unification — was paired with
  Plan 234) and 236 (adversarial-input rubric — meta-plan, folded
  into per-plan test docs) are not in this release; 235 becomes a
  natural pairing for the Plan 234 unicast-pipelining follow-on.

## [0.20.1] - 2026-06-04

Patch release. **Additive only** — no breaking changes; `cargo-semver-checks`
clean against `v0.20.0`. Closes the remaining audit-derived plans the
0.20.0 emergency hotfix had to defer.

### Added

- **Plan 222.2-4 — Sizeof gate broader coverage.** Extended the
  `sys_sizeof.rs` constant-value gate (shipped in 0.20.0 with XFRM + nft
  CT phase) to cover TC HTB / flower keys, IFLA / RTA / ctnetlink, and
  DPLL / devlink / ethtool. Each module pins ~10-20 most-used constants
  against kernel UAPI v6.13 reference values.
- **Plan 223 — Big-endian wire-parsing sweep.** Three `from_le_bytes`
  sites that 0.19 N3 missed (`netfilter.rs`, `tc/action.rs`,
  `nftables/config/diff.rs`) corrected to `from_ne_bytes`. New
  `scripts/audit-bytes-le.sh` CI gate fails the build if `from_le_bytes`
  reappears in `crates/nlink/src/netlink/`. New `cargo check
  --target s390x-unknown-linux-gnu` CI job locks the BE-compile
  contract.
- **Plan 224 — `recv_msg` MSG_TRUNC handling + auto-grow.** `recv_msg`
  passes `MSG_TRUNC`, detects kernel-side truncation against the buffer
  size, auto-grows up to a 1 MiB cap and retries once, then escalates to
  a new `Error::Truncated { received, buffer_size }` variant with
  `is_truncated()` predicate. New `Error::Backpressure` variant for
  `EWOULDBLOCK` retry exhaustion (B19).
- **Plan 225 — WireGuard `parse_timespec` robustness.** Validates
  `secs >= 0` + `0 <= nanos < 1e9` before constructing `Duration`;
  uses `SystemTime::checked_add` to handle far-future overflow.
  Returns `None` on malformed input instead of panicking. Closes
  AUDIT_BUGS B5 (verified by reviewer repro).
- **Plan 226 — DPLL `sint` codegen runtime.** Added `nlink-macros`
  runtime support for the kernel's variable-length signed-integer wire
  format (`nla_put_sint`: 4 bytes if value fits in s32, 8 bytes
  otherwise). New `DpllPin::fractional_frequency_offset_ppt_i64:
  Option<i64>` field holds the full-width value alongside the existing
  (now deprecated) `Option<i32>` field. New `ffo_ppt_i64()` accessor.
- **Plan 227 — Typed `AddressFamily` newtype.** New
  `nlink::AddressFamily(u8)` with `v4()` / `v6()` / `bridge()` / etc.
  constructors. New `*_typed` methods on `Connection<Route>`
  (`flush_rules_typed`, `get_rules_typed`,
  `del_rule_by_priority_typed`) take `AddressFamily`. The raw-`u8`
  originals are deprecated (removal 0.21).
- **Plan 228 — Typed `Percent` on `QdiscBuilder::loss`.** New
  `loss_pct(Percent)` setter validates / clamps; original `loss(f64)`
  deprecated (removal 0.21). Mirrors the 0.13 typed-units rollout —
  closes the units-confusion bug class for the declarative path.
  Scope limited to `loss`; the other 5 netem setters
  (`duplicate` / `corrupt` / `reorder` / `loss_correlation` /
  `delay_correlation`) don't exist on the declarative `QdiscBuilder`
  (imperative `NetemConfig` already takes `Percent`); deferred to 0.21.
- **Plan 230 — Typed `ChainName` + `Verdict::JumpTo` / `Verdict::GotoTo`
  variants.** New `nftables::ChainName(String)` newtype validates
  non-empty / no-interior-NUL / `<= NFT_NAME_MAXLEN-1`. New
  `Verdict::JumpTo(ChainName)` and `Verdict::GotoTo(ChainName)` variants
  ride the existing `#[non_exhaustive]` enum. The `Verdict::Jump(String)`
  / `Verdict::Goto(String)` originals are deprecated (removal 0.21).
- **Plan 231 — `RuleMessage` per-field accessors.** 19 new accessor
  methods alongside the existing `pub` fields. `family_typed()` returns
  the new `AddressFamily` from Plan 227. Field visibility unchanged —
  field-to-pub(crate) demotion deferred to 0.21 alongside the
  audit-script gate.
- **Plan 232 — Bug-hunt LOW-tier batch.** Closes B6 (`Error::from_errno`
  redundancy), B9 (`send_dump_inner` `msg_start` underflow), B10
  (`parse_string_from_bytes` UTF-8 swallowing — now logs at WARN), B11
  (`WireguardConfig::apply` `.expect` panic path), B15
  (`audit.rs::AuditStatus` size check uses `>=`), B18 (`nlmsg_align`
  overflow on > 2 GiB; new `nlmsg_align_checked`), B19
  (`socket::send` `EWOULDBLOCK` retry — new `Error::Backpressure`).
  B13 / B14 / B17 / B20 deferred or judged non-bugs; documented
  inline.
- **Plan 233 — `DumpStream::with_skip_malformed` opt-in.** Default
  behaviour stays fuse-on-malformed (correctness > liveness for snapshot
  dumps). New `.with_skip_malformed(true)` setter switches to
  flatten-mode with WARN-level `tracing` per skip. Per-stream-API
  audit table + dump-vs-event policy documented inline.
- **Plan 237 — Audit-script self-test pattern.** Four new
  `scripts/test-audit-*.sh` self-tests verify the failure paths of the
  audit-by-grep CI scripts (recv-loop, sysfs-in-lib, example-registration,
  example-feature-gating). Each test injects a deliberately-broken
  fixture and asserts non-zero exit + message match. Closes the
  silent-broken-script class.

### Deprecated (removal: 0.21.0)

- `DpllPin::fractional_frequency_offset_ppt: Option<i32>` — silently
  truncates kernel-supplied FFO values that don't fit in s32. Use the
  new `_i64` field or `ffo_ppt_i64()` accessor.
- `Connection::<Route>::flush_rules(family: u8)` — use
  `flush_rules_typed(AddressFamily)`. Same for `get_rules_for_family`
  and `del_rule_by_priority` (raw-`u8` variants).
- `QdiscBuilder::loss(f64)` — use `loss_pct(Percent)`. Closes the
  units-confusion bug class for the declarative netem path.
- `Verdict::Jump(String)` and `Verdict::Goto(String)` — use
  `Verdict::JumpTo(ChainName::new(...)?)` / `Verdict::GotoTo(...)`
  which validate the chain name and reject interior NULs.

### Deferred to 0.21.0

- Plan 229 (doc-drift sweep) — to be done in 0.21 after the
  typed-API surface stabilises.
- Plan 234 (NlRouter dispatcher), Plan 235 (GENL command unification),
  Plan 236 (adversarial-input rubric — meta-plan with no code), Plan
  197 (declarative ovpn) — discretionary plans, slotted into 0.21
  cycle.
- Various per-plan extensions documented inline in commit messages and
  the `_changelog_batch_*.md` stubs preserved in git history.

## [0.20.0] - 2026-06-04

**Emergency release with breaking wire-format corrections.**

`Connection::<Xfrm>::flush_sp()` was silently flushing all
Security Associations instead of all Security Policies since the
XFRM family shipped. Four XFRM constants (`XFRM_MSG_FLUSHSA`,
`XFRM_MSG_FLUSHPOLICY`, `XFRMA_SRCADDR`, `XFRMA_OFFLOAD_DEV`)
were miscounted from the kernel UAPI enum and produced
catastrophically wrong wire bytes. Plus two dispatch errors
(`update_sa`/`update_sp` always returned EEXIST) and a
`CtKey::Expiration` discriminant change that was loading the
wrong conntrack field.

The `CtKey::Expiration` discriminant change (`7 → 5`) is a
breaking ABI change at the byte level: pre-0.20 anyone using
`CtKey::Expiration as u32` got `7` (the wrong value); post-0.20
they get `5` (the correct value). The change requires a minor
version bump in 0.x.y semver. The remainder of the 0.20-cycle
plan suite (sweeps 222.2-237 + the typed-API tightening +
discretionary 197/234/235) slides forward into 0.21.0.

All shipped nlink versions yanked back to 0.15.x; the
minimum-viable version is now 0.20.0.

### Fixed — XFRM constants (Plan 221)

- **CRITICAL: `Connection::<Xfrm>::flush_sp()` was silently
  flushing all Security Associations instead of all Security
  Policies.** Root cause: `XFRM_MSG_FLUSHPOLICY` was hardcoded
  to `28`, which is the kernel UAPI value for `XFRM_MSG_FLUSHSA`.
  Same miscount also broke `flush_sa()` (was sending
  `XFRM_MSG_UPDPOLICY = 25` with an 8-byte body the kernel
  expected to be 168 bytes).
- **CRITICAL: `Connection::<Xfrm>::update_sa()` and `update_sp()`
  always returned EEXIST when the target existed.** Both methods
  sent `XFRM_MSG_NEWSA`/`NEWPOLICY` with `NLM_F_REPLACE`; XFRM
  dispatches by `nlmsg_type` alone and ignores `NLM_F_REPLACE`,
  so the kernel called `xfrm_state_add`/`xfrm_policy_insert(excl=1)`
  → EEXIST whenever the target SA/SP existed. Fixed to use
  `XFRM_MSG_UPDSA` / `XFRM_MSG_UPDPOLICY` (newly added constants
  with the corrected values 26 and 25).
- **CRITICAL: `XFRMA_SRCADDR` attribute ID was `9` (= `XFRMA_LTIME_VAL`).**
  Every `del_sa`/`get_sa` with a src-address filter was emitting
  a 16-byte address under the lifetime-struct attribute ID.
  Strict-checking kernels EINVALed; lenient ones silently
  dropped the filter. Corrected to `13`.
- **CRITICAL: `XFRMA_OFFLOAD_DEV` attribute ID was `26`
  (= `XFRMA_ADDRESS_FILTER`).** Plan 153.1's IPsec offload
  feature has been broken since it shipped — strict-checking
  kernels EINVALed on the size mismatch; lenient kernels parsed
  8 bytes as a truncated `xfrm_address_filter` and silently
  installed a software-only SA. Corrected to `28`.

### Fixed — nftables `CtKey::Expiration` constant (Plan 221)

- **HIGH: `CtKey::Expiration` enum discriminant was `7`
  (= `NFT_CT_L3PROTOCOL`).** Every rule using
  `Expr::Ct { key: CtKey::Expiration }` was loading the conntrack
  L3 protocol byte instead of the relative expiration time in
  milliseconds. Corrected to `5`; the previously-shadowed
  variants `CtKey::Secmark`, `CtKey::Helper`, and
  `CtKey::L3Protocol` were added so the kernel values are all
  reachable through the typed enum.

### Added — constant-value sizeof gate (Plan 222.1)

- **New `sys_sizeof::xfrm_msg_type` / `xfrm_attr` / `nft_ct_keys`
  modules.** Mirror the kernel UAPI v6.13 values for every
  constant the Plan 221 hotfix touched + the surrounding common
  values for safety. A new test family
  `plan_222_1_*_match_kernel_uapi` locks the corrected discriminants
  at build time so a future commit can't re-introduce the
  off-by-N enum-counting error. The pre-existing
  `sys_sizeof::xfrm` (struct sizes) + `nft_verdict` (verdict
  values) gates cover adjacent territory; this is the
  constant-ID half.

### Fixed — 0.20-cycle pre-work (PRs #9, #10, follow-up)

These three changes already shipped to master between the 0.19.0
cut and this hotfix. They are not 0.19.1-specific but are
included in 0.19.1 by virtue of the master state.

- **Make `Connection::<Wireguard>::get_device*` return the device
  `private_key` for privileged callers.** The parse path is factored
  through a shared `parse_key()` helper that also normalizes the
  kernel's all-zeros sentinel (returned for a keyless device on a
  privileged read) to `None` for both `private_key` and
  `public_key`, matching the peer `preshared_key` arm. The `wg` bin
  renders the real key when set instead of a hardcoded
  `(hidden)`/`(none)`.

- **Fix permanent phantom diffs in `NftablesConfig::diff`.** The diff
  byte-compares nlink's lowered expressions against what the kernel
  echoes on dump; several matchers lowered to less than the kernel's
  canonical form, so a reapply re-emitted the rule on every reconcile.
  - L3-version-specific matchers now prepend the `meta nfproto ==
    ip{v4,v6}` guard `nft` itself emits in an `inet` chain: the
    address matchers (`match_{s,d}addr_{v4,v6}` + `_not`) and the ICMP
    type matchers (`match_icmp_type`/`match_icmpv6_type`). Its absence
    also made the load ambiguous in an `inet` chain and unrecoverable
    by `nft list ruleset`.
  - The `bitwise` writer now emits `NFTA_BITWISE_OP` (every
    prefix-masked match) and the `nat` writer emits
    `NFTA_NAT_REG_{ADDR,PROTO}_MAX` + `NFTA_NAT_FLAGS` (every
    `snat`/`dnat`) — attributes the kernel fills in and echoes. Latent
    since the original nftables support (0.10.0).
  - The `nat` writer skips `NFTA_NAT_FLAGS` when the derived
    `flags == 0` (no addr and no port), mirroring `nft_nat_dump`'s
    own behaviour. Without this, the no-addr-no-port path
    (`Expr::Nat(NatExpr::snat(family))` constructed via the typed
    internals, bypassing the fluent `Rule::snat_*` helpers) would
    reintroduce a phantom diff that the rest of this fix removes.
  - **One-time migration impact for `apply_reconcile` users**:
    rulesets installed by nlink ≤ 0.19 will diff non-empty on the
    first post-upgrade reconcile because the in-kernel form lacks
    the new attributes. The diff converges after one apply.

- **Modprobe `nft_nat` and `wireguard` in CI** so the related
  round-trip tests run instead of silently skipping.

### Yanked

- `0.19.0`, `0.18.0`, `0.17.0`, `0.16.0`, `0.15.x` — all shipped
  with the XFRM constant defects. Use 0.20.0+.

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
