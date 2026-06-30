# nlink migration guides

Per-release upgrade notes for downstream consumers. Each guide
covers the public-API differences between two adjacent releases —
what was deprecated, removed, renamed, or behaviour-changed, plus
the typed replacement to migrate to.

## Convention

One file per upgrade boundary, named `<from>-to-<to>.md`:

```
docs/migration_guide/
├── README.md                  ← this file
├── 0.13.0-to-0.14.0.md        ← upgrading from 0.13.0
├── 0.14.0-to-0.15.0.md        ← upgrading from 0.14.0
├── 0.15.1-to-0.16.0.md        ← upgrading from 0.15.1
└── 0.16.0-to-0.17.0.md        ← upgrading from 0.16.0
```

Files only exist for boundaries that have meaningful migration
work. Pure-additive releases skip a guide and are noted here
instead.

## What each guide covers

In rough order of importance to a downstream maintainer:

1. **Breaking removals** — symbols / modules / methods deleted in
   the new release. Include the typed replacement.
2. **Behaviour changes** — same signature but different runtime
   behaviour (e.g. an error path that used to be silent).
3. **New deprecations** — code that still works but will be
   removed in a future release. Include the planned removal
   release.
4. **Notable additive changes** — new APIs that supersede an
   older pattern but don't force a migration today.
5. **Worked examples** — at least one before/after diff per
   significant change so the migration is mechanical.

Things that **don't** need a migration-guide entry: bug fixes,
documentation updates, internal refactors, new examples /
recipes, performance work, dependency bumps.

## Index

| Boundary | Highlights |
|---|---|
| [`0.13.0-to-0.14.0`](0.13.0-to-0.14.0.md) | Mostly additive: typed-units rollout (25 `parse_params`), reconcile pattern, ctnetlink mutation. **One deprecation**: `nlink::tc::builders::*` and `nlink::tc::options/*` — actual removal shipped in 0.15.0. |
| [`0.14.0-to-0.15.0`](0.14.0-to-0.15.0.md) | **Major release.** The 0.14.0 deprecations are deleted: `tc::builders::*` and `tc::options/*` removed. Typed XFRM SA/SP CRUD, typed standalone-action CRUD. `bins/tc` behaviour changes for unknown kinds and partial-spec `del`. |
| [`0.15.1-to-0.16.0`](0.15.1-to-0.16.0.md) | **Substantial-but-mostly-additive.** MSRV bumped 1.85 → 1.95. Sealed-trait bounds on `Connection::<P>::new*` / `namespace::connection_for*` (turns family-id-not-resolved bugs into compile errors). `Error::Kernel*` gain `#[non_exhaustive]` for the new `ext_ack` field. New crate: `nlink-macros` (re-exported via `nlink::macros`). |
| [`0.16.0-to-0.17.0`](0.16.0-to-0.17.0.md) | **Small but two breaking nftables changes.** `Register` discriminants switched `8..=11` → `1..=4` (canonical `NFT_REG_x`); enum gained `#[repr(u32)]`. `NftablesDiff::rules_to_delete` tuple gained a chain field. Behaviour change: default 30-second operation timeout on every `Connection<P>` (opt-out via `.no_timeout()`). |
| [`0.17.0-to-0.18.0`](0.17.0-to-0.18.0.md) | **Purely additive.** No breaking changes. Driven by the nlink-lab upstream-asks report: declarative `chain_type` + `device` (Plan 180), `list_*_in` server-side filtered dumps (Plan 181), `Error::ext_ack()` accessors (Plan 182), `Display` for diff types (Plan 183), `Ipv{4,6}Route::default_route()` (Plan 184), ENOBUFS-resilient `Connection<Nftables>::{into,subscribe_all}_events_with_resync` (Plan 185). `events_with_resync` is now lifetime-generic; existing `'static` callers keep working unchanged. |
| [`0.18.0-to-0.19.0`](0.18.0-to-0.19.0.md) | **Mostly breaking** (concurrency + wire-format correctness). Headline: F1 — `Connection<P>` is now safe under shared `Arc<Connection>` use; the cost is `events()` / `into_events()` / `*_with_resync` constructors / `facade::watch::*` are now `async` (add `.await`), and `subscribe()` / `subscribe_all()` / `subscribe_group()` flipped `&mut self` → `&self` (drop `mut` from `Connection` bindings). Wire-format corrections: nftables `NFT_JUMP` / `NFT_GOTO` constants (every `Verdict::Jump` rule pre-0.19 was silently `NFT_BREAK`), `Hook::Ingress` split into `NetdevIngress` (hook 0) + `InetIngress` (hook 5) + new `NetdevEgress`, `DpllPin::phase_offset` widened to `Option<i64>`, XFRM struct sizes corrected. `ApplyOptions::with_purge` removed (was silently non-functional). Five new builder setters on `RouteMessageBuilder` + six on `NeighborMessageBuilder` close write-parse asymmetries (typed VXLAN FDB programming now works end-to-end). Build-time `sizeof(struct …)` CI gate prevents future drift. |
| [`0.20.0-to-0.21.0`](0.20.0-to-0.21.0.md) | **Breaking — closes the 0.20.1 deprecations.** `DpllPin::fractional_frequency_offset_ppt` widened `i32 → i64` (SyncE 8-byte sint no longer fails parse). Raw-`u8` route-rule API gone: `flush_rules` / `get_rules_for_family` / `del_rule_by_priority` take `AddressFamily`. `QdiscBuilder::loss(f64)` gone — use `.loss_pct(Percent)`; 5 new netem parity setters on the declarative path. `Verdict::Jump(String)` / `Verdict::Goto(String)` gone — use `JumpTo(ChainName)` / `GotoTo(ChainName)`. `RuleBuilder::jump(&str)` / `.goto(&str)` reworked: takes `ChainName` (infallible) or use new `try_jump(&str) -> Result<Self>` / `try_goto`. `RuleMessage` / `NsIdMessage` fields flipped to `pub(crate)` + `#[non_exhaustive]`; other 4 `*Message` types just gain `#[non_exhaustive]`. Sibling parsed-result types (`BridgeVlanEntry`, `FdbEntry`, `MplsRoute`, `Nexthop`, `NexthopGroupMember`) get the same accessor + `#[non_exhaustive]` treatment. New CI gates: `audit-message-accessor-convention`, `audit-recipe-drift`, `doctest-nlink`. |
| [`0.21.0-to-0.22.0`](0.21.0-to-0.22.0.md) | **Purely additive for the library** — `cargo-semver-checks` reports no breaking changes; bump and go. One tooling change: the eight demo binaries that built under the bare system-tool name are renamed `nlink-*` (`ip` → `nlink-ip`, …) so they can't shadow iproute2/iw/ethtool on `PATH` (package names were already `nlink-*`, so `cargo run -p nlink-ip` is unaffected). Large feature release: the #30 binary-hardening epic + the #29 library gaps + the #115 TC/ethtool/sockdiag coverage epic + validating `serde` on `NetworkConfig` (#108) + declarative `nft reconcile`/`diff` (#109). |
| [`0.22.0-to-0.23.0`](0.22.0-to-0.23.0.md) | **Large, mostly additive — small breaking surface.** Closes the #134–#137 epic. Three mechanical breaks: `Chain::new(table, name)` now returns `Result` (add `?`; nftables names are the validated `TableName`/`ChainName` newtypes — `&str` callers otherwise unchanged); the parsed `LinkStats` is read via accessors (`stats.rx_bytes()`); and `SurveyInfo`/`StationInfo`/`PhyInfo`/`Band`/`Frequency` became `#[non_exhaustive]`. Behaviour fixes (now-correct data): nftables set creation (was ERANGE), nl80211 VHT/RX-bitrate attrs + split-dump PHY reassembly, GENL command fd-desync. Headline additive: `Store` reflector watch-cache, declarative-config purge, JSON Schema (`schemars`), declarative nftables sets, opt-in dispatcher mode, XFRM monitor `EventSource`, newtype `From`/`Into` conversions. |

> **Upgrading from 0.13.0 to 0.15.0?** 0.14.0 was never
> published as its own release — its work merged into the 0.15.0
> ship. Read **both** files in order: `0.13.0-to-0.14.0.md`
> covers the additive surface (new typed-units `parse_params`,
> reconcile pattern, ctnetlink, `MacsecLink`); then
> `0.14.0-to-0.15.0.md` covers the legacy deletion that closes
> the arc.

## Authoring

When cutting a new release:

1. Read the `[Unreleased]` section of `CHANGELOG.md` since the
   previous release.
2. Create `<previous>-to-<new>.md` from the template-ish shape of
   the existing guides (Removals → Behaviour changes → New
   deprecations → Notable additive → Worked examples).
3. Add a row to the index table above.
4. Cross-link from the release's CHANGELOG entry.

The CHANGELOG is the source of truth for *what* changed; the
migration guide is the source of truth for *how to upgrade*.
Don't duplicate; link.
