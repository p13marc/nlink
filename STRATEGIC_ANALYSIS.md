---
title: nlink — strategic analysis post-0.15.0
audience: maintainer
status: draft for review
date: 2026-04-26
methodology: codebase audit (~7000 LOC of source read) + competitor & kernel research with web verification of version-sensitive claims
---

# nlink — what to do next

A pre-publish audit caught the class-side legacy holdovers that made
0.15.0 the cleanest cut yet. This document is the *next* layer of
that thinking: now that the typed-API arc is closed, where should
the project go? What's worth building? What's worth deleting?

It's organised:

1. [Where we are](#1-where-we-are-at-0150) — honest baseline
2. [Concrete improvements](#2-concrete-improvements-quality-not-features) — quality wins, no new surface
3. [Features worth adding](#3-features-worth-adding) — kernel-side and library-side
4. [Strategic moves](#4-strategic-moves) — positioning, 1.0, YNL bet
5. [Prioritized roadmap](#5-prioritized-roadmap-016--10) — sequencing recommendation
6. [Anti-recommendations](#6-anti-recommendations) — explicitly *don't*

The headline conclusion: nlink at 0.15.0 is a quietly excellent
library that's underadvertised. The two highest-leverage moves
are (a) **`netkit` + tcx integration** (Cilium-driven; closes the
"cloud-native credibility" gap in <1 sprint) and (b) **a
`cargo-semver-checks` + `cargo public-api` CI gate** (the cheapest
1.0-prep step in existence). Everything else is gravy.

---

## 1. Where we are at 0.15.0

### What's genuinely good

| Dimension | State | Why it matters |
|---|---|---|
| **Protocol coverage** | rtnetlink + netfilter (ctnetlink + nftables) + xfrm + 6 GENL families + sock_diag + audit + selinux + fib_lookup + connector + uevent | **The only Rust library that covers all four protocol families with one coherent API.** `rtnetlink` (the obvious competition) only does RTM. |
| **Type safety** | 45 typed configs in sealed `ParseParams`; `Rate`/`Bytes`/`Percent`/`TcHandle`/`FilterPriority` newtypes | Permanently kills the unit-confusion bug class (which had a real bug before — see CLAUDE.md HTB anecdote) |
| **Async design** | tokio-native, `AsyncFd`, `tokio::sync::Mutex` only, no `async-trait` (uses RPITIT) | Modern; aligns with where the ecosystem is going |
| **Error UX** | `KernelWithContext` produces messages like `"add_link(veth0, kind=veth): File exists (errno 17)"` with 20+ `is_X()` predicates | Genuinely better than `rtnetlink` here — should be a marketing point |
| **Test count** | 765 lib tests + 13 integration test files (root-gated) + helper macros (`require_root!`, `require_module!`) | The `require_module!` pattern is novel and correct — most netlink libs just bit-rot when the kernel module isn't loaded |
| **Single publishable crate** | `nlink` is the only `publish = true` crate; 11 bins are POCs with `publish = false` | Avoids `rtnetlink`'s 8-crate version-drift hell |
| **Migration discipline** | Per-release `docs/migration_guide/<from>-to-<to>.md` + aggressive deprecate-then-delete cadence | Better than most ecosystem peers |

### What's measurably weak

| Dimension | State | Impact |
|---|---|---|
| **No streaming dump API** | `get_routes()` etc. materialize entire dumps into `Vec<Vec<u8>>` | OOM risk on large dumps (BGP router with 1M routes) |
| **No metrics hooks** | All public methods carry `tracing::instrument` but with `skip_all` (no parameter fields), no `metrics` crate integration | Can't filter `RUST_LOG` by parameter; no Prometheus story |
| **No MSRV declared** | `Cargo.toml` has `edition = "2024"` but no `rust-version`; integration CI uses `rust:1.85` container | Downstream consumers can't pin against a known floor; `cargo +1.80` may or may not work |
| **No semver-checks / public-api in CI** | Both rust.yml and integration-tests.yml lack semver gating | 1 in 6 crates accidentally violates semver per [obi1kenobi research](https://predr.ag/blog/semver-in-rust-tooling-breakage-and-edge-cases/); we just got lucky in 0.15.0 |
| **Test coverage gaps** | Netfilter nftables, all 6 GENL families, sock_diag filter DSL — **example-driven only**, no integration tests | Recipes can rot; no CI signal that nftables transactions still work end-to-end |
| **No fuzzing** | Zero `fuzz/` directory targets | Netlink message parsing is exactly the kind of code where fuzzing finds real off-by-one bugs |
| **Doc warnings** | `cargo doc -p nlink --no-deps` emits 7 unresolved cross-reference warnings | Visible to anyone landing on docs.rs |
| **3 inline TODOs in production code** | `genl/ethtool/connection.rs:384,516` (advertised modes bitset, ETHTOOL_A_FEATURES_WANTED encoding); `config/diff.rs:434` (HTB class delta detection) | Two are blocking ethtool feature mutation; the third is silent reconcile drift |
| **`bins/{ss,bridge}` Cargo.toml** | Pre-existing unused-deps that `cargo machete` flags (currently suppressed with `\|\| true`) | Either fix or archive these bins — see §2 |

### Recently-published competitor: `rtnetlink` 0.18.0 (2025-08-27)

[Verified via crates.io.](https://crates.io/crates/rtnetlink) Recent activity tells us what *they* think matters:

- 0.16/0.17/0.18 in March/May/August 2025 — they're shipping
- Breaking renames: `LinkSetRequest::master/nomaster` → `controller/nocontroller` (0.18) — they're still chasing API ergonomics
- VLAN filter on bridge itself, arbitrary `LinkMessage` for `RTM_DELLINK` — incremental coverage
- Still no nftables, no xfrm, no audit, no selinux, no fib_lookup, no full GENL story — **nlink's moat is intact and growing**

The strategic posture should not be "out-rtnetlink rtnetlink." It should be **"only nlink covers the four-protocol union."** Lead with that everywhere — README, blog post, crates.io description.

---

## 2. Concrete improvements (quality, not features)

These are pure quality wins. No new surface. Each is independently shippable.

### 2.1 Streaming dump API — `Stream<Item = Result<T>>` for routes/links/neighbors/FDB

**Problem:** `get_routes()` allocates `Vec<Vec<u8>>` then parses. On a BGP router with 1M routes, that's gigabytes resident before the caller sees the first row.

**Solution:** Add `stream_routes() -> impl Stream<Item = Result<RouteMessage>>` parallel to `get_routes`. Keep the materializing version for small-table convenience.

**Effort:** ~100 LOC per subsystem, 4 subsystems (route, link, neigh, fdb) = ~1.5 days. The infrastructure (`send_dump_inner`) is already iterator-shaped internally; the change is at the boundary.

**Files:** `crates/nlink/src/netlink/{connection,route,link,neigh,fdb}.rs`

### 2.2 Declare MSRV + add `cargo-msrv` check

**Problem:** No `rust-version` in `Cargo.toml`. Downstream consumers can't pin a floor; we have no signal when an inadvertent feature usage breaks the floor.

**Solution:**
- Add `rust-version = "1.82"` to `[workspace.package]` (conservative; covers `let-else`, `async fn in trait` stable since 1.75, `#[diagnostic::*]` since 1.78)
- Add `cargo-msrv verify` GHA step
- Document MSRV cadence: "N-2 stable, advanced in minor releases only"

**Effort:** 30 minutes once you commit to the number.

**Files:** `Cargo.toml` (workspace), `.github/workflows/rust.yml`, `docs/migration_guide/README.md`

### 2.3 `cargo-semver-checks` + `cargo public-api` in CI — *single highest-leverage 1.0-prep step*

**Problem:** Per [Predrag Gruevski's research](https://predr.ag/blog/semver-in-rust-tooling-breakage-and-edge-cases/), 1 in 6 crates accidentally violates semver. The pre-publish bug I found in 0.15.0 (the leftover `add_class_config` rename / stringly-typed holdover) was *exactly* the kind of issue these tools catch.

**Solution:**
```yaml
# .github/workflows/rust.yml addition
- name: cargo semver-checks
  uses: obi1kenobi/cargo-semver-checks-action@v2
  with:
    package: nlink

- name: cargo public-api snapshot
  run: |
    cargo install cargo-public-api --locked
    cargo public-api --diff-git-checkouts main HEAD --deny=all
```

**Effort:** 30 minutes; pays for itself the first time it catches an accidental signature change.

**Note:** [`cargo-semver-checks` is a Rust Project Goal 2025h1](https://rust-lang.github.io/rust-project-goals/2025h1/cargo-semver-checks.html) for merging into cargo. Adopt it now while we're early.

### 2.4 Close the ethtool TODOs

**Problem:** `genl/ethtool/connection.rs:384` and `:516` are TODOs blocking `ETHTOOL_A_FEATURES_WANTED` encoding. The lib can *read* feature bits but can't *set* them. This is the only inline TODO that matters in user-facing code.

**Solution:** Implement the bitset encoder. Estimate ~150 LOC + tests.

**Files:** `crates/nlink/src/netlink/genl/ethtool/{connection,types}.rs`

### 2.5 Observability: structured spans + optional `metrics` feature

**Problem:** Every public method has `tracing::instrument(..., skip_all, fields(method = "..."))`. That's the bare minimum. Users can't do `RUST_LOG="nlink[interface=eth0]=debug"`.

**Solution:** Add an optional `observability` feature that wires structured fields:
```rust
#[instrument(level = "debug", skip_all, fields(method = "add_qdisc", interface, kind))]
pub async fn add_qdisc(&self, iface: &str, qdisc: impl QdiscConfig) -> Result<()> {
    tracing::Span::current().record("interface", iface);
    tracing::Span::current().record("kind", qdisc.kind());
    // ...
}
```

Plus, behind a `metrics` feature flag (zero cost without it):
- `netlink_requests_total{method, status, errno_class}` counter
- `netlink_request_duration_seconds{method}` histogram
- `netlink_socket_backlog_bytes{protocol}` gauge

This unlocks Prometheus exporters and OpenTelemetry users overnight. Effort: ~2 days for both.

### 2.6 Fix doc warnings + `#![deny(missing_docs)]` on stable surface

`cargo doc -p nlink --no-deps` emits 7 unresolved cross-reference warnings. Fix them. Then commit to `#![deny(missing_docs)]` on the items we're calling stable for 1.0 (see §4.1).

Effort: 1 day total.

### 2.7 Fuzzing targets

**Problem:** Netlink-from-userns is an attack surface. Anyone shipping nlink-based code that consumes attacker-controlled netlink (containers, sandboxes) needs fuzz coverage.

**Solution:** `cargo-fuzz` with three initial targets:
- Top-level message parser (`MessageIter`)
- Each `parse_params` (one fuzz target per typed config kind via macro)
- nftables expression decoder

Seed corpus from `tests/integration/` captures.

Effort: 2 days setup + ongoing CI integration.

### 2.8 Decide what to do with `bins/ss` and `bins/bridge`

These bins have unused deps that `cargo machete` flags (currently suppressed with `|| true` in CI). They were last touched in the 2.x → workspace consolidation; nobody's actively developing them.

**Recommendation:** Either (a) audit + clean up to remove machete suppression, or (b) move them to an `archive/` directory and remove from `[workspace.members]`. Option (b) is cleaner — they're POCs from before the typed-API rollout, and rebuilding either properly is its own per-bin plan.

---

## 3. Features worth adding

### 3.1 Kernel features the library should support

Verified kernel versions and use-cases:

| Feature | Kernel | Why it matters | Effort |
|---|---|---|---|
| **`netkit` link kind** (`IFLA_NETKIT_PRIMARY`/`PEER`/`POLICY`) | [6.7 (Dec 2023)](https://lwn.net/Articles/949960/) | **Cilium 1.16+ uses netkit as veth replacement**. Without this, nlink can't be the netlink layer for any modern Cilium-style CNI. Highest-leverage missing link type. | 1-2 days |
| **`tcx` BPF attach hooks** (`BPF_TCX_INGRESS`/`EGRESS`) | [6.6](https://eunomia.dev/tutorials/20-tc/) | Kernel docs explicitly say "tc, classifier and action attach types are deprecated, with tcx/* recommended as the replacement." Pure netlink can't load BPF programs (`bpf()` syscall), but nlink should expose `tcx` link queries + attach-point management. Position as: "use nlink for netlink, [`aya`](https://github.com/aya-rs/aya) or [`libbpf-rs`](https://github.com/libbpf/libbpf-rs) for BPF program loading, glue them with our example." | 2 days for queries; example for full integration |
| **nftables `flowtable`** + hardware offload | mature (5.x cycle) | [`NFTA_FLOWTABLE_FLAGS` with `NF_FLOWTABLE_HW_OFFLOAD`](https://docs.kernel.org/networking/nf_flowtable.html). The headline nftables feature for fastpath forwarding. **Audit** `crates/nlink/src/netlink/nftables/` to confirm flowtable object support; if absent, ship it. | 2-3 days if absent |
| **XFRM IPsec offload** (`XFRMA_OFFLOAD_DEV`) | mature | Small extension to existing SA CRUD; unlocks NIC-accelerated IPsec for users on ConnectX-class hardware | 1 day |
| **devlink `rate` + port-function-state** | 5.x | SR-IOV rate limiting + smartNIC function provisioning. Cloud users want this. | 2 days |
| **nl80211 MLO (Multi-Link Operation)** | 6.6+ | Wi-Fi 7. The `wifi` bin loses credibility without MLO if anyone takes it seriously. | 3 days; lower priority |
| **`fq_pie`/`pie` v2 attribute additions** | various | Cheap parity wins | 0.5 day each |
| **Resilient nexthop groups** (`NHA_RESILIENT_BUCKET_TABLE`) | 5.15+ | Already partially there; add typed builder | 1 day |
| **`AUDIT_CONTAINER_*` fields** | 6.4+ | Container-aware audit IDs. The audit module currently does basic event subscription only. | 1 day |
| **MPTCP userspace path-manager** | 6.8+ | nlink has `mptcp` GENL support; verify parity vs in-kernel-PM split | 2 days audit + fixes |

### 3.2 Library features (project-internal)

| Feature | Why | Effort |
|---|---|---|
| **`MultiConnection` helper** — owns one `Connection` per protocol family, gives `multi.route().get_links()` / `multi.netfilter().add_conntrack()` | Common ask: users currently juggle 3-5 separate connections. Pure ergonomics. | 0.5 day |
| **`NetworkStatPoller`** — periodic snapshot of interface stats with delta computation | The 80% case for "monitoring tasks". Saves users wiring tokio intervals + caching themselves. | 1 day |
| **`TcDebugger`** — walks qdisc tree, validates parent/handle linkage, identifies orphaned classes/filters, flags priority collisions | Operators struggle to debug TC chains. Very high value, no good tool exists. | 3-5 days |
| **`#[derive(Builder)]` proc-macro** — generates fluent setters + `build()` for typed config structs | Eliminates ~1000 LOC of manual builder impl. Makes adding new typed configs trivial. | 2-3 days; lives in a new `nlink-macros` crate |
| **`#[derive(GenlMessage)]` proc-macro** — for downstream users defining their own GENL families | Ecosystem multiplier. Lets people use nlink as a netlink primitives library, not just a "supported families" library. | 3-4 days |
| **Error recovery recipes** — `docs/recipes/error-handling-patterns.md` covering EAGAIN/ENOBUFS retry, idempotent ops, SA conflict resolution | Documentation only; high value | 0.5 day |

### 3.3 Ecosystem integrations (proof-of-concept demos, not necessarily new crates)

These are **examples or demo bins** that double as marketing:

| Integration | Why | Form |
|---|---|---|
| **CNI plugin example** (`bins/cni-demo`) | No good pure-Rust CNI plugin framework exists. Implementing the CNI shape with nlink as backend is a 1-2 week project that opens the K8s/containerd/podman door. | New `bins/cni-demo` (POC) |
| **Prometheus exporter** (`bins/exporter`) | `node_exporter` has thin coverage of qdisc/conntrack/xfrm. An nlink-based exporter exposing these is the highest-conversion adoption hook for ops teams. | New `bins/exporter` (POC); ~500 LOC |
| **`aya` co-demo** | Load XDP/TC eBPF program with `aya`, attach via `tcx` (or fall back to TC), monitor counters with nlink. Co-marketing with `aya` team. | `examples/integrations/aya_tcx.rs` |
| **`tracing-opentelemetry` example** | No code changes needed in nlink (the spans are already there); just one example showing how to wire the existing `tracing` instrumentation to OTLP. | `examples/observability/otel.rs` |

---

## 4. Strategic moves

### 4.1 Plan the 1.0 cut around tokio's "stable core, unstable ring" pattern

**Problem:** nlink has ~150 public types and ~100 Connection methods across 10+ subsystems. Trying to lock everything as 1.0-stable is suicide.

**Solution:** Borrow tokio's pattern explicitly. Tokio reached 1.0 with `net`, `time`, `sync`, `task`, `runtime`, `io` stable; everything else lives in side-crates or behind `--cfg tokio_unstable`. Adapt for nlink:

**Stable for 1.0 (frozen API):**
- `Connection<Route>` core methods (link/addr/route/neigh/rule/qdisc/class/filter/action)
- `TcHandle`, `FilterPriority`, `Rate`, `Bytes`, `Percent` — units & handles
- The 45 typed `*Config` structs in `tc::{qdisc,class,filter,action}` + sealed `ParseParams`
- `Error`, `Result`, all `is_X()` predicates
- `nlink::lab::{LabNamespace, has_module, require_root!, require_module!}`
- `Connection::<Generic>` family resolution machinery (not the families themselves)

**Unstable / `--cfg nlink_unstable` for 1.0** (may evolve):
- All GENL family-specific surface (`wireguard`, `macsec`, `mptcp`, `ethtool`, `nl80211`, `devlink`)
- `xfrm` (relatively new, may get IPsec offload extensions)
- `nftables` (expression DSL is the most actively-evolving piece)
- `audit`, `selinux`, `connector`, `uevent` (low traffic, undertested)
- `sockdiag` (filter DSL is its own DSL)

The pattern: `nlink::wireguard` works *unchanged* under `--cfg nlink_unstable`, but the docs label it clearly and we reserve the right to break it in minor releases. **Tokio uses `--cfg`, not Cargo features, for this** because Cargo features are unification-prone.

Document the policy in `docs/stability.md`. Add a "Stability" badge to every API doc item via `#[doc(cfg(...))]`.

### 4.2 The YNL bet — biggest architectural decision left

**The trend:** Recent Linux kernels ship **YAML netlink specs** under `Documentation/netlink/specs/` for every new GENL family. As of [v6.17-rc2 (Aug 2025)](https://lkml.org/lkml/2025/8/12/686), the kernel even has a generic YAML parser integrated with the spec generation tooling. The kernel team explicitly intends this to "minimize the amount of hand written Netlink code for each new family, command, attribute" ([source](https://docs.kernel.org/userspace-api/netlink/specs.html)).

**The implication:** In 2-3 years, hand-writing each new GENL family in nlink will be a losing battle. New families will *only* ship with YAML specs; competitors that codegen will out-cover us.

**Three options:**

1. **Ignore it.** Keep hand-writing. Falls behind eventually. (Not recommended.)
2. **Build a YNL → Rust codegen.** Ambitious; ~1-2 month project. Output: `nlink-genl-codegen` crate that ingests `Documentation/netlink/specs/foo.yaml` and emits typed `Connection<Foo>` impls. Hard to get right (zerocopy invariants, async patterns, error mapping). High leverage if it works.
3. **Adopt an existing YNL implementation as upstream.** [`mdlayher/ynl`](https://github.com/mdlayher/ynl) is a Go reference; the kernel ships a Python codegen ([`tools/net/ynl/pyynl/ynl_gen_c.py`](https://docs.kernel.org/userspace-api/netlink/intro-specs.html)). Could fork or embed the Python codegen and emit Rust instead.

**Recommendation:** Don't commit to (2) or (3) in the 0.16 window. **Do** spend 2-3 days in 0.16 building a **proof-of-concept** that codegens *one* family (pick `taskstats` — it's small, frozen, and a good test) from its YAML spec. The PoC tells you whether (2) is feasible; if so, plan it for the 0.17 cycle and ship it before 1.0. If not, accept hand-writing as the long-term stance and document why.

This is the most consequential strategic question in front of the project. Worth a dedicated design-doc plan in the 0.16 cycle.

### 4.3 README rewrite — lead with the moat

The current README undersells. Three things to add at the top:

1. **A comparison table** vs `rtnetlink` showing the four-protocol-union claim. This is the elevator pitch.
2. **A "first 5 minutes" example** — `Connection::<Route>::new()`, list links, list routes, add a netem qdisc, done. Currently buried.
3. **The `--apply` testing pattern as a feature.** Most netlink libs make users say "I can't test this without root." nlink ships `require_root!` + `--apply` runners as a *project pattern*. Call it out.

### 4.4 docs.rs feature configuration

Add to `crates/nlink/Cargo.toml`:
```toml
[package.metadata.docs.rs]
all-features = true
rustdoc-args = ["--cfg", "docsrs"]
```

And per-item:
```rust
#[cfg_attr(docsrs, doc(cfg(feature = "lab")))]
pub mod lab { ... }
```

This makes docs.rs render the feature requirement next to every item — tokio does this, it's a UX win for free.

### 4.5 Set a `nlink_unstable` cfg name reservation now

Even before any unstable items exist, document in 0.16's CHANGELOG: "we reserve `--cfg nlink_unstable` for items that may change pre-1.0; using items behind this cfg constitutes opt-in to API instability."

This bakes the convention before anyone gets used to a different one.

---

## 5. Prioritized roadmap (0.16 → 1.0)

### 0.16.0 (target: 6-8 weeks out, ~3 weeks of focused work)

**Quality gates (required):**
- 2.2 Declare MSRV (`1.82`) + `cargo-msrv` CI
- 2.3 `cargo-semver-checks` + `cargo public-api` in CI ← *single most valuable change*
- 2.6 Fix the 7 doc warnings; commit to `#![deny(missing_docs)]` on the stable-surface items (per §4.1)
- 4.4 docs.rs feature config
- 4.5 Reserve `nlink_unstable` cfg name (announce in CHANGELOG)

**High-leverage features:**
- 3.1 `netkit` link kind support — *Cilium-driven, ~2 days, biggest cloud-native win*
- 3.1 `tcx` BPF attach-point queries (just the netlink-side; full BPF integration via aya example)
- 2.4 Close the ethtool TODOs (advertised modes + features-wanted bitset encoding)
- 4.2 YNL codegen proof-of-concept (one family, ~3 days, no commit to direction)

**Nice-to-have:**
- 2.1 Streaming dump API for routes/links/neighbors/FDB (~1.5 days)
- 2.5 Observability feature (structured spans + optional `metrics` integration; ~2 days)
- 3.3 Prometheus exporter POC bin (~1 day for a basic one)

**Total:** ~3-4 weeks of focused work. Pick the quality gates as non-negotiable; pick 2-3 features.

### 0.17.0 (3 months after 0.15.0 — ~Aug 2026)

- nftables `flowtable` + hw-offload (3.1)
- XFRM IPsec offload (`XFRMA_OFFLOAD_DEV`)
- devlink rate / port-function-state
- 2.7 Fuzzing targets in CI
- 3.2 `MultiConnection`, `NetworkStatPoller`, `TcDebugger` (pick 1-2)
- 3.3 CNI demo bin (positioning)
- YNL codegen first real family (if 0.16 PoC was promising)
- 2.8 Resolve `bins/{ss,bridge}` situation

### 1.0.0-rc / 1.0.0 (target: ~Q4 2026)

- 4.1 Stability tier declaration shipped (stable items frozen, unstable items behind `--cfg nlink_unstable`)
- All public stable-tier items documented (`#![deny(missing_docs)]` enforced)
- `cargo public-api` baseline locked
- Demand-gated features delivered if anyone asked (`ct_expect`, `nfqueue`, `nflog`, MPTCP userspace PM, MLO)
- README rewrite (4.3) shipped
- `docs/book/` mdBook (recipes become chapters)
- 1.0 stability blog post published, ideally with at least one downstream production user testimony

---

## 6. Anti-recommendations

Things that will tempt you and shouldn't be done:

| Don't | Why |
|---|---|
| `async-std` support | That ship has sailed. Tokio-only is correct. |
| `no_std` support | Netlink is a Linux syscall. Meaningless. |
| TypeScript/WASM bindings | Wrong audience for this domain. |
| io_uring batching | The kernel's netlink dump engine is the bottleneck, not the recv path. Mention as future-work in README to deflect issues; don't actually build it for 1.0. |
| Splitting nlink into multiple crates `nlink-core` / `nlink-rtnetlink` / etc. | This is exactly what `rtnetlink` did and exactly what users complain about. The "one publishable crate" decision is correct; defend it. |
| Going for "out-rtnetlink rtnetlink" by deepening RTM coverage exclusively | Unwinnable inertia battle. The four-protocol union is the moat. |
| `async-trait` adoption to make `Connection<P>` more polymorphic | RPITIT is already used; staying away from `async-trait` is correct. |
| A `nlink-next` "v2 dev" parallel crate | Too much overhead for one maintainer. The aggressive deprecation cadence (deprecate in N, delete in N+1) plus stability tiering at 1.0 is the right answer. |
| DHCP client / DNS resolver / netconf — anything that's "network userspace" but not "netlink protocol" | Stay in lane. Mention "we don't do this on purpose" in README. |
| Self-hosted CI runners for kernel matrix testing | Operationally expensive. The privileged GHA + ubuntu-latest kernel is a fine baseline; only add a self-hosted runner if a kernel-specific bug surfaces (already documented in the workflow). |

---

## Sources

Verified during this analysis:

- [`netkit` landed in Linux 6.7](https://lwn.net/Articles/949960/) — Cilium primary use case
- [TCX requires Linux 6.6+; tc/cls_bpf attach types are kernel-deprecated](https://eunomia.dev/tutorials/20-tc/)
- [`rtnetlink` 0.18.0 (2025-08-27)](https://crates.io/crates/rtnetlink) — release activity verified, scope verified absent (no nftables/xfrm/audit)
- [Linux netlink YAML specs](https://docs.kernel.org/userspace-api/netlink/specs.html) and [generic YAML parser merged for v6.17-rc2](https://lkml.org/lkml/2025/8/12/686)
- [nftables flowtable + hardware offload](https://docs.kernel.org/networking/nf_flowtable.html) (`NFTA_FLOWTABLE_FLAGS`, `NF_FLOWTABLE_HW_OFFLOAD`)
- [`cargo-semver-checks` is a Rust Project Goal 2025h1](https://rust-lang.github.io/rust-project-goals/2025h1/cargo-semver-checks.html); [Predrag Gruevski's research on semver violation rates](https://predr.ag/blog/semver-in-rust-tooling-breakage-and-edge-cases/)

Codebase audit grounded in direct reads of `crates/nlink/src/netlink/{tc,filter,action,xfrm,netfilter,nftables,genl/*}.rs`, `bins/tc/src/commands/`, `crates/nlink/tests/integration/`, `.github/workflows/`, and `Cargo.toml`. File-and-line refs in §1-2 are verified as of commit `bcb4014`.

---

## End of report

Net opinion: **0.16 should be a quality cycle, not a feature cycle.** The single most valuable thing to ship is `cargo-semver-checks` + `cargo public-api` in CI plus an MSRV declaration — the stuff that prepares for 1.0. Beyond that, `netkit` support is the one feature with outsized strategic value (Cilium credibility). Everything else can wait or ship opportunistically.

The YNL question is the real strategic decision. A 3-day proof-of-concept in 0.16 will tell you whether to plan a major codegen shift for 0.17 or accept hand-writing as the long-term stance. Don't skip it.
