# API design audit — 0.20 cycle pre-work

**Executive summary**: nlink's API surface has grown rapidly through six minor releases of typed-newtype consolidation, sealed traits, and recipe helpers. The foundational types (`TcHandle`, `Rate`, `Bytes`, `Percent`, `InterfaceRef`, `ParseParams`, `Error` predicates) are excellent and the conventions are consistently applied across recently-touched code. The serious issues I found are not new footguns at the level of the 0.14 unit confusion — they are (a) a small number of remaining raw-integer parameters at public method boundaries (rule family, declarative netem `f64`), (b) one struct (`RuleMessage`) that breaks the pub(crate)-fields-with-accessors convention used by every sibling message type, (c) ergonomic asymmetries in the by-name / by-index / *_full method explosion on Connection, and (d) widespread docstring drift around things that became `async` (`events()`, `into_events()`, `dump_stream*`) in 0.19 plus the recurring `loss(1.0)` examples that would now fail to compile because `loss` takes `Percent`. The most leverageful 0.20 cycle work would be: (1) sweep docstrings for "events() / .loss(1.0)" drift in one pass, (2) replace the remaining `family: u8` / `f64` raw parameters with `AddressFamily` / `Percent` newtypes, (3) decide whether to keep the `_by_name` / `_by_index` × `_full` 4-variant explosion or collapse with `impl Into<...>`, (4) align `RuleMessage` with the rest of the message types. Findings below total 22.

## Severity rubric
- **MAJOR**: footgun that silently produces wrong behaviour (like the units bug)
- **MID**: API surface that requires the user to know the docs to use correctly when a typed signature could prevent the mistake
- **MINOR**: inconsistency / naming / docs / cleanup
- **BIKESHED**: subjective preference — listed for the maintainer's call, not requested as a blocker

## Findings

### Finding A1 — Declarative `QdiscBuilder::loss(f64)` is unclamped and unchecked
**Severity**: MAJOR
**API**: `nlink::netlink::config::types::QdiscBuilder::loss` (also: `corrupt`, `duplicate` analogues if present)
**Footgun**: Imperative `NetemConfig::loss` is typed-`Percent` (0.13 unit-confusion lineage) and clamps to `0..=100`. The declarative twin `QdiscBuilder::loss(percent: f64)` takes a raw `f64` and stores it verbatim — passing `1.5` for "1.5%" works; passing `0.015` for "1.5% expressed as a fraction" silently yields 0.015% loss; passing `150.0` produces 150% loss with no validation. This is exactly the units-confusion pattern in a single subsystem: same word ("loss percent"), two incompatible argument shapes.
**Evidence**: `/var/home/mpardo/git/rip/crates/nlink/src/netlink/config/types.rs:1179` `pub fn loss(mut self, percent: f64) -> Self` vs `/var/home/mpardo/git/rip/crates/nlink/src/netlink/tc.rs:156` `pub fn loss(mut self, percent: crate::util::Percent) -> Self`.
**Suggested fix**: Change `QdiscBuilder::loss`, `corrupt`, `duplicate` to take `impl Into<Percent>` (or `Percent` directly). Breaking. Pair with `From<f64> for Percent` if you want to keep `.loss(1.0)` calls working through `into()`. Or simpler — just `Percent` everywhere.
**Breaking?**: yes (small)
**Confidence**: high

### Finding A2 — `flush_rules(family: u8)` / `get_rules_for_family(family: u8)` / `del_rule_by_priority(family: u8, ...)` take raw `u8`
**Severity**: MID
**API**: `nlink::Connection::flush_rules`, `get_rules_for_family`, `del_rule_by_priority` (in `crates/nlink/src/netlink/connection.rs` lines 1531, 1595, 1604)
**Footgun**: Callers must know that `family` is the libc `AF_INET`/`AF_INET6` constant cast to `u8` (where `AF_INET = 2` and `AF_INET6 = 10`). It is trivial to pass `4` (or even `1`) and get an empty result silently — `get_rules_for_family(4)` returns `Ok(vec![])` because no rule matches family 4. There is no validation, no typed wrapper. The TCs typed-newtype convention exists precisely to kill this.
**Evidence**: `pub async fn get_rules_for_family(&self, family: u8) -> Result<Vec<RuleMessage>>` with docs that say "Address family: `libc::AF_INET` for IPv4, `libc::AF_INET6` for IPv6" — "see the docs" is the smell.
**Suggested fix**: Introduce a small `AddressFamily` enum (`V4`, `V6`, `Other(u8)`) or reuse `nftables::Family` if appropriate. Take `impl Into<AddressFamily>` so `2u8.into()` still works for raw-call holdouts. Or add `flush_rules_v4` / `flush_rules_v6` siblings to `get_rules_v4` / `get_rules_v6` and deprecate `flush_rules(u8)`.
**Breaking?**: additive (deprecate, don't remove)
**Confidence**: high

### Finding A3 — `RuleMessage` has all-`pub` fields, breaking the message-type convention
**Severity**: MID
**API**: `nlink::netlink::messages::RuleMessage`
**Footgun**: Every other message type (`LinkMessage`, `AddressMessage`, `RouteMessage`, `NeighborMessage`, `TcMessage`) has `pub(crate)` fields with accessor methods (and the convention is applied in 0.19 documentation drift work). `RuleMessage` is the only outlier: `pub priority: u32`, `pub source: Option<IpAddr>`, `pub header: FibRuleHdr`, etc. Users can mutate these directly with no validation, and the `pub header: FibRuleHdr` exposes the internal C struct — that's load-bearing wire-format detail leaking into the public API. The internal accessor `del_rule_by_priority` already uses positional access on the `pub priority` field; that ties the API to the literal field name forever.
**Evidence**: `/var/home/mpardo/git/rip/crates/nlink/src/netlink/messages/rule.rs:39-80` vs `/var/home/mpardo/git/rip/crates/nlink/src/netlink/messages/link.rs:52-109`.
**Suggested fix**: Add accessor methods (`priority()`, `source()`, etc.), demote fields to `pub(crate)`. Breaking but mechanical. Bundle with the same one-pass migration tooling used in 0.19 for the dump-interruption work.
**Breaking?**: yes
**Confidence**: high

### Finding A4 — Doc drift: `conn.events()` / `into_events()` shown as sync throughout
**Severity**: MID
**API**: `nlink::Connection::events`, `into_events` — both became `async` in 0.19 Finding B
**Footgun**: A user copy-pasting any of the top-level examples gets a compile error (`async fn returns a Future, not the stream`). Worse, `mut conn` is shown in patterns where `subscribe()` is now `&self` (also 0.19 — F1 fix), so the example reads obsolete on two axes at once.
**Evidence**: `/var/home/mpardo/git/rip/crates/nlink/src/lib.rs:122` `let mut conn = Connection::<Route>::new()?;` followed by `let mut events = conn.events();` (line 125). Also `/var/home/mpardo/git/rip/crates/nlink/src/netlink/mod.rs:31,34`, `/var/home/mpardo/git/rip/crates/nlink/src/netlink/events.rs:12,15` (in the type-level docstring). The `addr.address` field-access at `/var/home/mpardo/git/rip/crates/nlink/src/netlink/mod.rs:38` also doesn't compile (field is `pub(crate)`; the lib.rs copy uses `addr.address()` correctly).
**Suggested fix**: Single sweep — `s/conn.events()/conn.events().await/`, `s/conn.into_events()/conn.into_events().await/`, `s/let mut conn/let conn/` in module/lib docstrings, fix the one `addr.address` → `addr.address()`. Doc-only.
**Breaking?**: no
**Confidence**: high

### Finding A5 — Doc drift: `NetemConfig::new().loss(1.0)` shown across many docs but doesn't compile
**Severity**: MID
**API**: `nlink::netlink::tc::NetemConfig::loss`
**Footgun**: `loss` takes `Percent` now (the typed-units pass). Examples in `tc.rs:16`, `tc.rs:5190`, `tc.rs:5530`, `mod.rs:56`, `impair.rs:54` (and example files) show `.loss(1.0)` which is a typed-argument error. New users copy-pasting will hit it.
**Evidence**: see line numbers above; the imperative TC `loss` signature is `pub fn loss(mut self, percent: crate::util::Percent) -> Self`.
**Suggested fix**: Either (a) sweep all docstrings to `.loss(Percent::new(1.0))` or (b) impl `From<f64> for Percent` so `.loss(1.0.into())` and `.loss(1.0)` (via `impl Into<Percent>` on the param) both work. Option (b) is more ergonomic — `loss(impl Into<Percent>)` lets the docs stay short. Doc-only or one-line API change.
**Breaking?**: no (additive `impl Into`) or doc-only
**Confidence**: high

### Finding A6 — `From<u16> for FilterPriority` opens the typed-band convention
**Severity**: MID
**API**: `nlink::FilterPriority` (`crates/nlink/src/netlink/tc_handle.rs:239`)
**Footgun**: `FilterPriority` exists specifically to encode the operator/recipe/app/system band convention. The blanket `impl From<u16> for FilterPriority { fn from(value: u16) -> Self { Self(value) } }` lets a caller write `add_filter(... 100u16.into() ...)` and silently land in the recipe band — which is reserved for nlink helpers (`PerPeerImpairer`, `PerHostLimiter`). The intent was to force `FilterPriority::recipe(0)` / `FilterPriority::app(0)`. The doc-comment labels this as "Compatibility conversion from raw u16" — the convention says compatibility conversions defeat the typed-newtype.
**Evidence**: `/var/home/mpardo/git/rip/crates/nlink/src/netlink/tc_handle.rs:239-245`.
**Suggested fix**: Remove the blanket `From<u16>`; keep `FilterPriority::from_raw(u16)` (already exists implicitly — add it explicitly) so the "I really do mean raw" callers have a clear escape hatch and the band intent is preserved. Breaking but small.
**Breaking?**: yes
**Confidence**: medium — the maintainer may have a good reason for the blanket impl (parser ergonomics?)

### Finding A7 — `Percent::new` silently clamps instead of erroring
**Severity**: MID
**API**: `nlink::util::Percent::new(f64)`
**Footgun**: `Percent::new(150.0)` quietly returns `Percent(100.0)`. `Percent::new(-1.0)` quietly returns `Percent(0.0)`. A caller who computed a probability wrong and got 1500 instead of 15 hits 100% packet loss in production with no warning. The kernel's accept-anything-and-saturate behaviour is fine inside the type — but at construction time silent clamping is the wrong default for a value the user explicitly set.
**Evidence**: `/var/home/mpardo/git/rip/crates/nlink/src/util/percent.rs:38-40`.
**Suggested fix**: Add `Percent::try_new(value: f64) -> Result<Percent>` that errors on out-of-range, document `Percent::new` as "saturating" (rename if not too churny). Or just deprecate `new` and rename to `clamped(f64)`. Additive.
**Breaking?**: no if additive; yes if rename
**Confidence**: medium

### Finding A8 — `Expr::Cmp { data: Vec<u8> }` (and `Immediate`, `Bitwise`) take raw bytes
**Severity**: MID
**API**: `nlink::netlink::nftables::expr::Expr::{Cmp, Immediate, Bitwise}`
**Footgun**: To compare against a u32 IPv4 the user has to encode it big-endian into a `Vec<u8>`. Wrong byte order produces wrong matches with no error. Wrong length (3 bytes vs 4 bytes) confuses the kernel. The 0.14-units lineage suggests there should be typed constructors like `Expr::cmp_ipv4(reg, op, addr: Ipv4Addr)` that handle the encoding.
**Evidence**: `/var/home/mpardo/git/rip/crates/nlink/src/netlink/nftables/expr.rs:13-26`. Note the comment about `Register::R0..=R3` mapping to `NFT_REG_1..NFT_REG_4` already documents one bug class that came out of raw-byte mistakes (Plan 178).
**Suggested fix**: Keep the `Vec<u8>` variants for power users; add typed builder helpers — `Rule::match_ipv4(...)`, `Rule::match_u16_be(...)` — already in `Rule::match_saddr_v4` style. Make sure they cover the common shapes (u8/u16/u32/u64 BE, IPv4, IPv6, MAC). The big payoff is the typed-helpers; the raw `Vec<u8>` can stay as an escape hatch.
**Breaking?**: no (additive)
**Confidence**: high — Plan 178's register-ID canonicalization confirms this byte-typed surface has bitten users.

### Finding A9 — CLAUDE.md and pool docs say `ConnectionPool::<Route>::new(8)?` but there's no such method
**Severity**: MINOR
**API**: `nlink::netlink::pool::ConnectionPool`
**Footgun**: Pool construction is exclusively via `ConnectionPoolBuilder::new().size(8).build().await?`. CLAUDE.md line 360 shows `let pool = Arc::new(ConnectionPool::<Route>::new(8)?);` which is not a real signature. Users reading the (canonical project) CLAUDE.md walk-through can't run the snippet. Also the project's own concurrency section refers to `ConnectionPool::<P>::new`.
**Evidence**: `/var/home/mpardo/git/rip/CLAUDE.md:360`; `/var/home/mpardo/git/rip/crates/nlink/src/netlink/pool/inner.rs` has `ConnectionPoolBuilder` only.
**Suggested fix**: Either (a) add `ConnectionPool::<P>::new(size: usize) -> Result<Self>` thin convenience over the builder for sync-constructible protocols, or (b) fix CLAUDE.md + the module docstring to show the builder. (a) is friendlier to readers of CLAUDE.md.
**Breaking?**: no
**Confidence**: high

### Finding A10 — `Connection::dump_typed(msg_type: u16)` exposes raw u16 message type
**Severity**: MID
**API**: `nlink::Connection::dump_typed`
**Footgun**: `pub async fn dump_typed<T: FromNetlink>(&self, msg_type: u16) -> Result<Vec<T>>` — the type parameter `T` already encodes which message type to dump (you can only meaningfully ask `dump_typed::<LinkMessage>(NlMsgType::RTM_GETLINK)`). The `msg_type: u16` parameter is therefore both redundant (the right value is determined by `T`) and a footgun (any `u16` compiles). The kernel will reply with whatever message types match, and `T::from_bytes` will silently drop anything it can't parse (line 822-826).
**Evidence**: `/var/home/mpardo/git/rip/crates/nlink/src/netlink/connection.rs:807` and `818-826`. The `from_bytes(payload).is_err()` arm silently skips bad parses with `continue`.
**Suggested fix**: Add `T::DUMP_MSG_TYPE: u16` associated constant on `FromNetlink` (or a sibling `DumpableMessage` trait), make `dump_typed` derive `msg_type` from it. The `u16` arg becomes implicit. Bonus: introduces a place to document the dump-type contract. Breaking (changes signature) but mechanical migration.
**Breaking?**: yes (small)
**Confidence**: medium

### Finding A11 — `set_link_state(impl Into<InterfaceRef>, up: bool)` — boolean trap
**Severity**: MID
**API**: `nlink::Connection::set_link_state`
**Footgun**: `set_link_state("eth0", true)` reads ambiguously at the call site — true for "up" or "enable"? The dedicated wrappers `set_link_up` and `set_link_down` already exist and are clearer; `set_link_state(_, true/false)` is a low-readability third path. Boolean-trap is the canonical naming smell.
**Evidence**: `/var/home/mpardo/git/rip/crates/nlink/src/netlink/connection.rs:2145`.
**Suggested fix**: Either (a) take `LinkAdminState::Up`/`Down` (an enum) instead of `bool`, or (b) delete `set_link_state` in favour of the two named methods — the public surface shrinks. (a) is the typed-newtype convention answer.
**Breaking?**: yes (small)
**Confidence**: medium-high

### Finding A12 — `_by_name` × `_by_index` × `_full` method explosion on TC
**Severity**: MINOR
**API**: `Connection::{add,del,replace,change}_qdisc[_full][_by_index[_full]]` and friends
**Footgun**: Connection has, for qdiscs alone, 16 variants:
  - `add_qdisc`, `add_qdisc_full`, `add_qdisc_by_index`, `add_qdisc_by_index_full`
  - same × {del, replace, change}
And another set for filters (`add_filter` × 4) and classes (`add_class` × 2 — note: classes are missing `_full` because the class signature is already fully specified). With qdisc taking `impl Into<InterfaceRef>` you could pass either a name or an index; the `_by_index` siblings are doc-helpers, not type-distinguished. The `_full` variants exist because `add_qdisc` defaults `parent` to `TcHandle::ROOT` and `handle` to `None` — that's a defaulting choice, not a fundamentally different API.
**Evidence**: see `connection.rs:2093-2152` and `tc.rs:5196-5485`; `filter.rs:3475-3779`.
**Suggested fix**: Two options:
  1. Keep `add_qdisc(iface, config)` (defaults) and `add_qdisc_full(iface, parent, handle, config)`, drop the `_by_index` half since `impl Into<InterfaceRef>` covers both.
  2. Take a `QdiscBuilder`-style typed-config that carries `parent`/`handle` internally, defaulting to root: `add_qdisc(iface, NetemConfig::new().parent(...).handle(...))`. Drops both axes.
Option 2 is more aligned with the typed-config convention. Either way, the API surface shrinks by ~50% across TC.
**Breaking?**: yes (deprecation cycle possible)
**Confidence**: high — surface bloat is unambiguous; the choice of which fix is a maintainer call.

### Finding A13 — `del_filter` has no `_full` variant; class has no `_full` variant
**Severity**: MINOR
**API**: `Connection::del_filter`, `Connection::add_class` and siblings
**Footgun**: Documented in passing in §A12: `del_qdisc_full` lets you pass an explicit handle but `del_filter` does not. The asymmetry implies one of two things to the user: either `del_filter` is missing functionality (and you must use the lower-level builder) or the `_full` distinction doesn't matter for filters. Neither is documented.
**Evidence**: `/var/home/mpardo/git/rip/crates/nlink/src/netlink/filter.rs:3765,3779` — only `del_filter` and `del_filter_by_index`.
**Suggested fix**: Either add `del_filter_full` for symmetry or document why it's absent (the filter's pref+handle+protocol identifies it uniquely vs qdisc which is a 1-per-attach-point thing). Best fixed alongside §A12.
**Breaking?**: no (additive) or doc-only
**Confidence**: medium

### Finding A14 — `timeout(mut self, ...)` (consuming) vs `enable_strict_checking(&self, ...)` (shared) inconsistency
**Severity**: MINOR
**API**: `Connection::timeout`, `Connection::no_timeout`, `Connection::enable_strict_checking`, `Connection::set_ext_ack`
**Footgun**: All four are "post-construction tuning". `timeout` and `no_timeout` consume `self` and return `Self` (builder pattern). `enable_strict_checking` and `set_ext_ack` take `&self` and mutate the underlying socket. A user who got used to `Connection::new()?.timeout(...)` will write `Connection::new()?.enable_strict_checking(true)?` and get the wrong shape — `Result<()>` not `Self`. Two patterns for one purpose.
**Evidence**: `connection.rs:296-358`.
**Suggested fix**: Pick one. Either (a) make all four `&self` (sockopts already are; just demote `timeout` to `&mut self` or take `Cell<Duration>` if `&self` is preferred for `Arc` sharing) or (b) make all four builder-style. (b) is cleaner if pre-share, but `timeout` is already shipped consuming-self; (a) is friendlier post-share. Picking (a) is the smaller change.
**Breaking?**: yes
**Confidence**: medium

### Finding A15 — Free functions `kbps_to_bytes` / `mbps_to_bytes` / etc. still public despite `Rate`
**Severity**: MINOR
**API**: `nlink::util::rate::{kbps_to_bytes, mbps_to_bytes, gbps_to_bytes, bytes_to_kbps, bytes_to_mbps, bytes_to_gbps, bits_to_bytes, bytes_to_bits}`
**Footgun**: These re-introduce exactly the unit-confusion class `Rate` was designed to kill. A caller computing `mbps_to_bytes(100)` and passing the result as a `u64` to something that expects bytes/sec is fine — but the same caller seeing `Rate::mbit(100).as_bytes_per_sec()` can't get the units wrong. The free functions are present "for compatibility" per the module docs but have been since 0.13. Two cycles seems like enough.
**Evidence**: `/var/home/mpardo/git/rip/crates/nlink/src/util/rate.rs:37-152`.
**Suggested fix**: Mark `#[deprecated(since = "0.20.0", note = "use Rate::* constructors")]`. Remove in 0.21 (matches the user's stated aggressive cadence — "deprecate same release as typed replacement; delete one release later").
**Breaking?**: no (deprecation only); later: yes
**Confidence**: high

### Finding A16 — `dump_typed`/`from_bytes` failures silently skipped
**Severity**: MID
**API**: `Connection::dump_typed`
**Footgun**: Line 822-826: `if let Ok(msg) = T::from_bytes(payload) { parsed.push(msg); }` — parse failures from a future-kernel attribute the local parser doesn't understand are silently dropped. The same code in event parsers is correct (per the parser-robustness policy: "skip malformed frames, don't kill the stream"). But for dumps the implication is different — you asked for "give me all the links" and we returned an incomplete list with no log, no warning, no error. The user has no way to know.
**Evidence**: `/var/home/mpardo/git/rip/crates/nlink/src/netlink/connection.rs:822-826`.
**Suggested fix**: At minimum log via `tracing::warn!` on each skipped frame (so observability shows the issue). Optionally surface a count via `Result<DumpResult<T>>` where `DumpResult` has `messages: Vec<T>` + `parse_errors: usize`. Tracing is the cheaper fix and matches the existing observability convention.
**Breaking?**: no (tracing) / yes (typed result)
**Confidence**: high

### Finding A17 — `events()` / `into_events()` async-ness silently serializes concurrent queries
**Severity**: MID
**API**: `Connection::events`, `Connection::into_events`, the resync variants
**Footgun**: The doc says concurrent queries on a connection with an active events stream "will block until the events stream is dropped." That is correct but easy to miss — a user who does `events()` then in another task calls `conn.get_links()` will see the get_links hang indefinitely (subject to the 30s default timeout, then `Error::Timeout` rather than a clear "events subscription held the lock" error). The Connection doesn't expose a way to test or surface this state.
**Evidence**: `/var/home/mpardo/git/rip/crates/nlink/src/netlink/stream.rs:300-309`.
**Suggested fix**: Either (a) when `Error::Timeout` fires from a method that lost the lock race, wrap it with a distinct variant like `Error::ConnectionBusy { holder: &'static str }`, or (b) document the pattern as a recipe and add a `Connection::has_active_subscription() -> bool` accessor so callers can check before issuing. (a) is more diagnostic-friendly.
**Breaking?**: no (additive)
**Confidence**: medium

### Finding A18 — Stale comment in CakeConfig and similar: "legacy string-args interface in `tc/options/cake.rs`"
**Severity**: MINOR
**API**: `CakeConfig` docstring
**Footgun**: The docstring at `tc.rs:2645-2648` references `tc/options/cake.rs` as a "legacy string-args interface that remains for `Connection::add_qdisc("eth0", "cake", &["bandwidth", ...])` callers." Per CLAUDE.md the string-args interface was deleted in 0.15.0; `tc_options.rs` is the parsing-back module, not a building module. This sends new contributors searching for a module that doesn't exist.
**Evidence**: `/var/home/mpardo/git/rip/crates/nlink/src/netlink/tc.rs:2645-2648`.
**Suggested fix**: Remove the paragraph (or update to point at `ParseParams::parse_params` for the typed-string parsing path).
**Breaking?**: no
**Confidence**: high

### Finding A19 — `dump_typed` arm `if response.len() < NLMSG_HDRLEN { continue; }` masks malformed-frame errors
**Severity**: MINOR
**API**: `Connection::dump_typed`
**Footgun**: `if response.len() < NLMSG_HDRLEN { continue; }` (line 819) is a silent skip without `tracing::warn!`. Same observation as A16 but for the truncation case — a downstream user who sees an "everything is fine, just got 3 links" result when the kernel actually sent 5 frames (2 of which were too short to be a header) has no diagnostic trail.
**Evidence**: `/var/home/mpardo/git/rip/crates/nlink/src/netlink/connection.rs:819-821`.
**Suggested fix**: Bundle with A16 — one tracing/diagnostic pass over `dump_typed`.
**Breaking?**: no
**Confidence**: high

### Finding A20 — `Verdict::Jump(String)` / `Verdict::Goto(String)` use bare `String` for chain refs
**Severity**: MINOR
**API**: `nlink::netlink::nftables::types::Verdict`
**Footgun**: A `Verdict::Jump("notes about my chain".to_string())` constructs cleanly and the kernel returns `EINVAL` only at apply time. nftables chain names have a known character set + length limit. The 0.19 nftables canonicalization work fixed wire-format mismatches; the typed-name pass would prevent the input-side mistake.
**Evidence**: `/var/home/mpardo/git/rip/crates/nlink/src/netlink/nftables/types.rs:214-216`.
**Suggested fix**: Introduce a newtype `ChainName(String)` that validates on construction (utf-8, length, allowed chars). Use it in `Verdict::Jump`/`Goto`, `DeclaredChain.name`, `Expr::Lookup.set`, etc. Bikeshed-flavored but consistent with the typed-units lineage. Could defer to 0.21 if 0.20 is already scoped.
**Breaking?**: yes (small)
**Confidence**: medium

### Finding A21 — Grouped bikesheds (5 items)
**Severity**: BIKESHED
**API**: various
**Footgun summaries**:
  1. `Connection::get_routes_for_table(table_id: u32)` takes a raw `u32` — same family-vs-table-id confusion class as A2. There's a kernel-defined set of reserved table IDs (`RT_TABLE_DEFAULT=253`, `RT_TABLE_MAIN=254`, `RT_TABLE_LOCAL=255`, plus `RT_TABLE_UNSPEC=0` and `RT_TABLE_COMPAT=252`). A `TableId(u32)` newtype with associated `TableId::MAIN`/`LOCAL`/`DEFAULT` constants would be safer. (Low impact in practice — table IDs are bounded by 32-bit but the named ones are the only common gotcha.)
  2. `Connection::resolve_interface_opt(&self, iface: Option<&InterfaceRef>) -> Result<Option<u32>>` — the `Option<&InterfaceRef>` argument is a strange shape (a borrow-to-an-option-of-an-interface). Consider `Result<Option<u32>>` over `IntoIterator<Item = &InterfaceRef>` or just have the caller pre-match.
  3. `Bytes` has `kb` (decimal) and `kib` (binary) both as constructors. The convention is non-obvious; one mnemonic users would land on instinctively is "kb=Kbit". Worth a doc-comment cross-reference at minimum.
  4. `Rate::parse(s: &str)` and `s.parse::<Rate>()` both exist; the inherent `parse` is documented but the standard library `FromStr` is the usual idiom. Either drop the inherent or leave a `#[doc(hidden)]` on it.
  5. `Connection::new()` returns `Connection<P>` but the `Send + Sync` story is documented in CLAUDE.md rather than at the type. A `// Connection<P>: Send + Sync` marker doctest at `Connection::new` ensures the property doesn't quietly regress (the rust compiler will catch it if the comment is `#[doc=...]` with a `static_assertions::assert_impl_all!`).
**Breaking?**: mostly no (additive doc changes)
**Confidence**: low-medium — these are all maintainer's-call items

### Finding A22 — `connection_for_path_async`'s doc-comment example uses pre-existing `Connection::from_parts` shape no longer documented elsewhere
**Severity**: MINOR
**API**: `nlink::netlink::namespace::connection_for_path_async`
**Footgun**: The docstring just says "See `connection_for_async` for details." But the function constructs via `NetlinkSocket::new_in_namespace_path` + `P::resolve_async(&socket)` + `Connection::from_parts(socket, state)`. `from_parts` is `pub(crate)`-ish (I see it referenced in pool/inner.rs and namespace.rs but it's not in the public re-exports). If users try to follow the imports to build their own custom-namespace path, they hit a dead end.
**Evidence**: `/var/home/mpardo/git/rip/crates/nlink/src/netlink/namespace.rs:281-303`.
**Suggested fix**: Either expose `from_parts` publicly (probably not — it's an internal seam), or expand the docstring to point at `Connection::for_namespace(NamespaceSpec::...)` as the documented public path, or — since `for_namespace` is the documented public path — point users there in the example.
**Breaking?**: no (doc-only or additive)
**Confidence**: low — minor docs issue

## Things that are designed well

The convention discipline in this codebase is unusually high for a Rust netlink crate. Concrete praise:

1. **The typed-units / typed-handles story is now genuinely complete**. `Rate`, `Bytes`, `Percent`, `TcHandle`, `FilterPriority`, `InterfaceRef` form a coherent set, with consistent Display/FromStr round-trip and arithmetic that matches the kernel's storage shape. The `Rate * Duration = Bytes` cross-type arithmetic is a small thing that makes a *lot* of recipe code read like the math. Keep investing here — the missing pieces in A20 are the natural extensions.

2. **The `ParseParams` sealed-trait design is exactly right**. Inherent methods on each config so existing direct callers keep working, blanket sealed-trait impl for generic dispatch, macro-generated impl block so adding a new typed config is one line. The strict-rejection contract has clear conventions documented at the trait level and (from the audit's view of `tc.rs`) is upheld in practice. The 45-shipped-parsers tally suggests this convention has scaled, which is the test.

3. **`Error` predicate API closes the variant-matching trap**. `is_busy()` / `is_not_found()` / `is_permission_denied()` work across `Error::Kernel`, `Error::KernelWithContext`, and `Error::Io` shapes via the common `errno()` accessor (Plan 187 §2.5). The `predicate_io_shape_sweep` test sweeps the contract so new predicates inherit it. The `chain_walk` / `root_cause` / `contexts` helpers that transparently see through `Box<nlink::Error>` source layers are a quietly nice piece of work — they handle the common downstream-wrapping mistake without making the wrapper rewrite their code.

4. **`#[non_exhaustive]` discipline on enums is consistently applied** across the recently-touched modules I looked at (nftables Family/Hook/ChainType/Priority/Policy/Verdict/Register/CmpOp/PayloadBase/MetaKey/LimitUnit, TC Cake* enums, NetworkEvent, ProcEvent, InterfaceRef, Error). Public structs correctly *do not* carry it (per CLAUDE convention). The two outliers — `LinkStats` (all `pub`, no `#[non_exhaustive]`, will break if kernel grows another counter) and `RuleMessage` (see A3) — are the only places where the convention would benefit from a sweep.

5. **The pool design correctly preserves the single-flight invariant per Connection**. Many "connection pool" abstractions in async Rust quietly allow multiplexing on one socket, then explain in the docs that it's actually serialized. nlink's pool gives N sockets to N tasks, and the Connection-level single-flight stays intact. This is the right choice — it matches the kernel's model (each socket has its own response queue) and means the `Send + Sync` story stays trivially correct under sharing.
