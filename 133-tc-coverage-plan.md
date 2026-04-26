---
to: nlink maintainers
from: nlink maintainers
subject: TC coverage gaps — sch_fq_pie + actions polish + cls_basic ematch
target version: 0.15.0 (released under `[Unreleased]`)
date: 2026-04-19; closed 2026-04-25
status: **CLOSED — all 4 PRs shipped under `[Unreleased]`.** PR A typed `CakeConfig` (`17e5f37`), PR B `FqPieConfig` (`6a62504`), PR D `BpfAction` + `SimpleAction` (`5e20fca`). **PR C** shipped as Plan 142 Phase 1 (`e2ee5d8`): `BasicFilter` ematch tree (cmp + u32; meta deferred until golden hex available), 12 unit tests, `tcf_ematch_*` wire structs in `types/tc/filter/ematch`. Filter side at 9/9 typed-first; the bin's `#[allow(deprecated)]` on `filter_builder` came off in Plan 139 PR C (`0d095ae`). This plan is historical reference — the substance lives in CHANGELOG `## [Unreleased]` and [`docs/migration_guide/0.14.0-to-0.15.0.md`](docs/migration_guide/0.14.0-to-0.15.0.md).
related: Plan 142 master; Plan 139 PR C (`56371db`) deletion of the legacy modules made every typed config the canonical surface.
---

# TC Coverage Plan

> **Status (2026-04-20):** 3 of 4 PRs have landed on `master` under
> `[Unreleased]`. PR A (typed `CakeConfig`, commit `17e5f37`), PR B
> (`FqPieConfig`, commit `6a62504`), and PR D (`BpfAction` +
> `SimpleAction`, commit `5e20fca`) are done.
>
> **PR C (`BasicFilter` ematch — cmp/u32/meta) is still pending and
> needs to be picked back up.** See §4 below for the scope. The
> deferral reason: the ematch wire format
> (`TCA_BASIC_EMATCHES` → `TCA_EMATCH_TREE_HDR` + `TCA_EMATCH_TREE_LIST`
> with per-kind structs `tcf_em_cmp` / `em_u32` / `tcf_meta_val`)
> should be validated against golden hex captured from `tc filter add
> ... basic match cmp ...` before shipping — subtle encoding bugs only
> surface when packets start missing their intended class.
>
> Suggested resumption: start with cmp (best-documented, widest
> coverage), add meta next (Plan 135's cgroup-classification recipe
> blocks on it), then u32 if demand justifies it. The convenience
> helpers (`ip_proto_eq`, `skb_mark_eq`) should land alongside cmp.

## 0. Summary

Gap-fill the TC support after Tier-1 type-safety lands. Each item is
small (1-3 days each) and additive (no BC break).

| Item | Status today | Effort | Value |
|---|---|---|---|
| `sch_cake` (legacy string-args) | Implemented in `tc/options/cake.rs` (the imperative `pub fn build(builder, &[String])` form used by raw `Connection::add_class`) | — | Done in legacy form |
| `sch_cake` (typed `CakeConfig` builder) | **Missing** — no `CakeConfig` struct in `tc.rs` matching the modern typed builders (HtbQdiscConfig etc.) | 1.5 days | Bring cake into the typed-builder API |
| `sch_fq_pie` | Missing | 1 day | Modern AQM completeness |
| `cls_basic` | Skeleton exists (no `ematch` support) | 2-3 days | The whole point of cls_basic is composable matches |
| BPF classifier | Implemented (`BpfFilter`) | — | Spot polish: documentation + helpers for common `tc + bpf` patterns |
| BPF actions (`act_bpf`) | Missing | 1 day | Companion to the classifier |
| `act_simple` (counter) | Missing | 0.5 day | Useful for traffic accounting |

So the meat is: **typed CakeConfig + fq_pie + cls_basic ematch +
act_bpf**. Other items slot in as time allows.

**Two competing TC option styles** to be aware of:

- **Legacy imperative** (`crates/nlink/src/tc/options/<kind>.rs`):
  `pub fn build(builder: &mut MessageBuilder, params: &[String]) ->
  Result<()>`. Used by `Connection::add_class("eth0", "1:0", "1:1",
  "cake", &["bandwidth", "100mbit", ...])`.
- **Typed modern** (`crates/nlink/src/netlink/tc.rs`):
  `HtbQdiscConfig`, `NetemConfig`, etc. with builder methods. Used
  by `Connection::add_class_config(...)` and friends.

Cake has the legacy form, not the typed form. Plan 133 adds the typed
form so cake reaches parity with the rest.

This plan sequences and scopes each, with kernel constants and
attribute layouts pre-fetched (training data; verify before
implementation).

---

## 1. Goals & non-goals

### Goals

1. Add typed `CakeConfig` qdisc builder (cake exists in legacy
   string-form; bring it to the typed API parity).
2. Add `FqPieConfig` qdisc builder and integration.
3. Extend `BasicFilter` with `ematch` (extended match) trees so it
   becomes useful (today it's just a passthrough to a classid).
4. Add `BpfAction` action builder mirroring `BpfFilter`.
5. Add `SimpleAction` (string-printing action useful for testing).
6. Document the patterns (recipe doc + CLAUDE.md).

### Non-goals

1. Coverage of every remaining qdisc type (gred, choke, multiq, etc.).
   Add as needed.
2. ematch as a fully composable expression DSL — start with the
   primitive matches users actually use (u32/cmp/meta).
3. BPF program loading. We bind to fd / pinned path; loading is
   `aya`/`libbpf-rs` territory.

---

## 2. Typed `CakeConfig`

### 2.0. Why

Cake (Common Applications Kept Enhanced) is the most-used modern AQM
qdisc on real-world deployments (OpenWrt's default, recommended by
the `bufferbloat.net` community). Today nlink supports it via the
legacy `pub fn build(builder, &[String])` interface, but the typed
API in `tc.rs` doesn't include `CakeConfig`. That means callers have
to drop into `Connection::add_class("eth0", parent, classid, "cake",
&["bandwidth", "100mbit", ...])` instead of the typed
`add_qdisc_config`.

### 2.1. API sketch

Mirror existing typed builders. Fields per the kernel
`include/uapi/linux/pkt_sched.h` `TCA_CAKE_*` enum (~17 attributes):

```rust
#[derive(Debug, Clone, Default)]
pub struct CakeConfig {
    pub bandwidth: Option<Rate>,            // Plan 129
    pub rtt: Option<Duration>,
    pub target: Option<Duration>,
    pub overhead: Option<i16>,
    pub mpu: Option<u16>,
    pub diffserv_mode: Option<CakeDiffserv>,
    pub flow_mode: Option<CakeFlowMode>,
    pub atm_mode: Option<CakeAtmMode>,
    pub autorate: bool,
    pub memory_limit: Option<Bytes>,        // Plan 129
    pub nat: bool,
    pub raw: bool,
    pub wash: bool,
    pub ingress: bool,
    pub ack_filter: Option<CakeAckFilter>,
    pub split_gso: bool,
    pub fwmark: Option<u32>,                // Linux 5.x+
    pub parent: String,
    pub handle: Option<String>,
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum CakeDiffserv { Diffserv3, Diffserv4, Diffserv8, Besteffort, Precedence }

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum CakeFlowMode { Flowblind, Srchost, Dsthost, Hosts, Flows, DualSrchost, DualDsthost, Triple }

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum CakeAtmMode { None, Atm, Ptm }

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum CakeAckFilter { Disabled, Filter, Aggressive }

impl CakeConfig {
    pub fn new() -> Self;
    pub fn bandwidth(self, r: Rate) -> Self;
    pub fn rtt(self, d: Duration) -> Self;
    // ... full builder ...
    pub fn build(self) -> Self;
}

impl QdiscConfig for CakeConfig {
    fn kind(&self) -> &'static str { "cake" }
    fn write_options(&self, b: &mut MessageBuilder) -> Result<()>;
}
```

### 2.2. Stats parsing

Cake stats are nested (per-tin breakdown). Add `CakeStats` parser to
`tc_options.rs`:

```rust
pub enum QdiscOptions {
    // ... existing variants ...
    Cake(CakeOptions),
}

pub struct CakeOptions {
    // global fields
    pub tins: Vec<CakeTinStats>,
}
pub struct CakeTinStats {
    pub send_packets: u64,
    pub send_bytes: u64,
    pub drops: u64,
    pub ecn_marks: u64,
    pub way_indirect_hits: u32,
    pub way_misses: u32,
    pub way_collisions: u32,
    pub backlog_bytes: u32,
    pub backlog_packets: u32,
    // ...
}
```

This makes the per-tin observability that's cake's selling point
actually accessible.

### 2.3. Effort

~1.5 days: builder + write_options + stats parser + integration test
+ doc/example.

---

## 3. `sch_fq_pie`

### 2.1. Background

- Mainline since Linux 5.6 (Mar 2020). Stable.
- Combines fq_codel's per-flow tracking with PIE's AQM.
- Constants in `include/uapi/linux/pkt_sched.h` under `TCA_FQ_PIE_*`.
- ~12 attributes, all flat (no nesting).

### 2.2. Attribute list (verify against kernel)

```c
enum {
    TCA_FQ_PIE_UNSPEC,
    TCA_FQ_PIE_LIMIT,           // u32 — packet limit
    TCA_FQ_PIE_FLOWS,           // u32 — number of flows (default 1024)
    TCA_FQ_PIE_TARGET,          // u32 — target delay in microseconds
    TCA_FQ_PIE_TUPDATE,         // u32 — update interval in microseconds
    TCA_FQ_PIE_ALPHA,           // u32 — alpha (PIE control)
    TCA_FQ_PIE_BETA,            // u32 — beta (PIE control)
    TCA_FQ_PIE_QUANTUM,         // u32 — quantum in bytes
    TCA_FQ_PIE_MEMORY_LIMIT,    // u32 — memory limit in bytes
    TCA_FQ_PIE_ECN_PROB,        // u32 — ECN probability (per-mille)
    TCA_FQ_PIE_ECN,             // u32 — enable ECN (boolean)
    TCA_FQ_PIE_BYTEMODE,        // u32 — byte mode (boolean)
    TCA_FQ_PIE_DQ_RATE_ESTIMATOR, // u32 — DQ rate estimator
};
```

### 2.3. API

Mirror existing `PieConfig` and `FqCodelConfig`:

```rust
// crates/nlink/src/netlink/tc.rs

#[derive(Debug, Clone)]
pub struct FqPieConfig {
    pub limit: Option<u32>,
    pub flows: Option<u32>,
    pub target: Option<Duration>,
    pub tupdate: Option<Duration>,
    pub alpha: Option<u32>,
    pub beta: Option<u32>,
    pub quantum: Option<Bytes>,           // per Plan 129
    pub memory_limit: Option<Bytes>,
    pub ecn_prob: Option<Percent>,        // per Plan 129
    pub ecn: bool,
    pub bytemode: bool,
    pub dq_rate_estimator: bool,
    pub parent: String,
    pub handle: Option<String>,
}

impl FqPieConfig {
    pub fn new() -> Self;
    pub fn limit(self, packets: u32) -> Self;
    pub fn flows(self, n: u32) -> Self;
    pub fn target(self, d: Duration) -> Self;
    pub fn tupdate(self, d: Duration) -> Self;
    pub fn alpha(self, a: u32) -> Self;
    pub fn beta(self, b: u32) -> Self;
    pub fn quantum(self, q: Bytes) -> Self;
    pub fn memory_limit(self, m: Bytes) -> Self;
    pub fn ecn_prob(self, p: Percent) -> Self;
    pub fn ecn(self) -> Self;          // setter, idiomatic
    pub fn bytemode(self) -> Self;
    pub fn dq_rate_estimator(self) -> Self;
    pub fn parent(self, parent: impl Into<String>) -> Self;
    pub fn handle(self, handle: impl Into<String>) -> Self;
    pub fn build(self) -> Self;
}

impl QdiscConfig for FqPieConfig {
    fn kind(&self) -> &'static str { "fq_pie" }
    fn write_options(&self, b: &mut MessageBuilder) -> Result<()>;
}
```

### 2.4. Kernel encoding

`write_options` emits each set field as a TCA_FQ_PIE_* attribute.
Follow `PieConfig::write_options` (same shape).

### 2.5. Tests

- Unit test: `FqPieConfig::new().limit(1000).flows(2048).build()`
- Integration test: deploy fq_pie on a dummy interface, dump,
  verify `kind == "fq_pie"` and parsed limit matches.

### 2.6. Kernel constants location

Add to `crates/nlink/src/netlink/types/tc.rs`:

```rust
pub mod fq_pie {
    pub const TCA_FQ_PIE_UNSPEC: u16 = 0;
    pub const TCA_FQ_PIE_LIMIT: u16 = 1;
    // ... etc
}
```

### 2.7. Effort

~1 day. Builder + write_options + tests + 1 example.

---

## 4. `cls_basic` with `ematch`

### 3.1. Background

`cls_basic` is the kernel's "compose primitive matches via boolean
operators" classifier. It exists for cases where flower/u32 are too
specialized. Today our `BasicFilter` (`crates/nlink/src/netlink/filter.rs:1186`)
is a stub: classid + priority + protocol, no actual match expression.

To make it useful, add `ematch` (extended match) tree support. ematch
attributes live under `TCA_BASIC_EMATCHES`.

### 3.2. Scope

ematch supports many kinds (u32, cmp, meta, nbyte, text). Implement
the three most-used:

- **`cmp`** — compare a packet field against a constant (e.g., "byte
  9 of L3 == 0x06" matches TCP). Most general.
- **`u32`** — same selectors as cls_u32 but inside a basic filter.
- **`meta`** — match on metadata (skb->priority, dev->ifindex,
  cgroup, route realm). Useful for sandbox/cgroup classification.

Skip for v0.13: nbyte (raw byte match), text (regex-style — rarely
used), ipset (pulls in netfilter dep).

### 3.3. API sketch

```rust
// crates/nlink/src/netlink/filter.rs

#[derive(Debug, Clone)]
pub enum EmatchKind {
    Cmp(EmatchCmp),
    U32(EmatchU32),
    Meta(EmatchMeta),
}

#[derive(Debug, Clone, Copy)]
pub enum EmatchOp { And, Or, Xor }

#[derive(Debug, Clone)]
pub struct Ematch {
    pub kind: EmatchKind,
    pub op: EmatchOp,             // joins with previous match
    pub negate: bool,
}

#[derive(Debug, Clone)]
pub struct EmatchCmp {
    pub layer: CmpLayer,          // L2 / L3 / L4
    pub offset: u16,
    pub mask: u32,
    pub value: u32,
    pub op: CmpOp,                // EQ / GT / LT
}

// ...

#[derive(Debug, Clone, Default)]
pub struct BasicFilter {
    classid: Option<u32>,
    priority: u16,
    matches: Vec<Ematch>,
    chain: Option<u32>,
}

impl BasicFilter {
    pub fn new() -> Self;
    pub fn classid(self, classid: TcHandle) -> Self;       // per Plan 130
    pub fn priority(self, prio: FilterPriority) -> Self;   // per Plan 130

    /// Add an ematch joined with AND (default).
    pub fn ematch(self, m: Ematch) -> Self;

    /// Convenience: match packets whose IP protocol byte equals `proto`.
    pub fn ip_proto_eq(self, proto: u8) -> Self;

    /// Convenience: match packets with skb mark == `mark`.
    pub fn skb_mark_eq(self, mark: u32) -> Self;

    pub fn build(self) -> Self;
}

impl FilterConfig for BasicFilter {
    fn kind(&self) -> &'static str { "basic" }
    fn classid(&self) -> Option<u32>;
    fn write_options(&self, b: &mut MessageBuilder) -> Result<()>;
}
```

### 3.4. Kernel encoding

ematch wire format is gnarly:

```
TCA_BASIC_EMATCHES (nested)
  ├── TCA_EMATCH_TREE_HDR  (header: nmatches, progid)
  └── TCA_EMATCH_TREE_LIST (nested)
        ├── tcf_ematch_hdr { matchid, kind, flags, pad }
        └── kind-specific data (e.g., struct tcf_em_cmp for cmp)
```

Implement carefully. `iproute2`'s `m_ematch.c` is the reference.

### 3.5. Tests

- Unit: build a 2-match BasicFilter, verify the wire format produces
  the expected attribute layout (compare bytes to a known-good
  reference).
- Integration: install BasicFilter with a CMP match on tcp port 80,
  send TCP packet, verify counter increment via dump.

### 3.6. Effort

~2-3 days:
- 0.5d: ematch wire format research and tcf_ematch_* struct
  definitions
- 1d: builder API and write_options for cmp + u32 + meta
- 0.5d: convenience helpers (ip_proto_eq, skb_mark_eq, etc.)
- 0.5d: integration tests
- 0.5d: docs + example

---

## 5. `act_bpf` (BPF action)

### 4.1. Background

Companion to `BpfFilter`. Where the classifier matches packets, the
action runs a BPF program for side effects (mark, redirect, drop).
Constants under `TCA_ACT_BPF_*`.

### 4.2. API sketch

```rust
// crates/nlink/src/netlink/action.rs

#[derive(Debug, Clone)]
pub struct BpfAction {
    program: BpfProgRef,         // Fd(u32) | Pinned(PathBuf)
    name: Option<String>,
    action: Option<TcAction>,    // GactPolicy: pipe/ok/drop/etc.
}

#[derive(Debug, Clone)]
enum BpfProgRef {
    Fd(i32),
    Pinned(PathBuf),
}

impl BpfAction {
    pub fn from_fd(fd: i32) -> Self;
    pub fn from_pinned(path: impl Into<PathBuf>) -> Result<Self>;

    pub fn name(self, name: impl Into<String>) -> Self;
    pub fn pipe(self) -> Self;
    pub fn ok(self) -> Self;
    pub fn drop(self) -> Self;
    pub fn build(self) -> Self;
}

impl ActionConfig for BpfAction {
    fn kind(&self) -> &'static str { "bpf" }
    fn write_options(&self, b: &mut MessageBuilder) -> Result<()>;
}
```

### 4.3. Effort

~1 day. Mirrors `BpfFilter` closely.

---

## 6. `act_simple`

A trivial action that prints a string when invoked. Useful for
debugging filter chains. ~0.5 day.

```rust
pub struct SimpleAction { sdata: String, action: Option<TcAction> }
// SimpleAction::new("matched-port-80").build()
```

---

## 7. Files touched

| Path | Change | Approx LOC |
|---|---|---|
| `crates/nlink/src/netlink/types/tc.rs` | Add `fq_pie`, `bpf_action`, `simple_action`, `ematch` constant modules | ~150 |
| `crates/nlink/src/netlink/types/tc/qdisc/fq_pie.rs` | (or inline in tc.rs) struct defs | ~50 |
| `crates/nlink/src/netlink/tc.rs` | `FqPieConfig` builder + `QdiscConfig` impl | ~250 |
| `crates/nlink/src/netlink/filter.rs` | Extend `BasicFilter` with ematch | ~400 |
| `crates/nlink/src/netlink/filter.rs` | `Ematch`/`EmatchKind`/`EmatchCmp`/`EmatchU32`/`EmatchMeta` types | ~300 |
| `crates/nlink/src/netlink/action.rs` | `BpfAction`, `SimpleAction` builders | ~250 |
| `crates/nlink/tests/integration/tc.rs` | New tests (3-4) | ~150 |
| `crates/nlink/examples/route/tc/fq_pie.rs` | New | ~50 |
| `crates/nlink/examples/route/tc/basic_ematch.rs` | New | ~80 |
| `docs/recipes/aqm.md` | (Optional) | ~120 |
| `CLAUDE.md`, `README.md` | Mention new qdiscs/filters | ~30 |
| `CHANGELOG.md` | Entry | ~20 |

Total ~1800 LOC.

---

## 8. Tests

Unit:
- `FqPieConfig` builder: chain, defaults, build returns Self
- `BasicFilter::ematch` chains correctly; AND/OR/XOR ops set
- `Ematch{Cmp,U32,Meta}` write_options produces expected wire bytes
  (compare against a recorded golden hex dump from `tc filter add ...
  basic match cmp ...`)

Integration:
- `test_add_fq_pie_qdisc`: deploy + dump + assert kind/limit
- `test_basic_filter_with_cmp_ematch`: deploy classifier matching
  a TCP port, verify packet counter increments after sending
- `test_bpf_action_attached`: load a trivial BPF program (or use a
  pinned program from `/sys/fs/bpf/`), attach as action, verify
  it's listed in filter dump
- `test_simple_action_emits_log`: install simple action, verify
  netlink dump reports the sdata string

---

## 9. Documentation

- `docs/recipes/aqm.md` (new, optional): comparison of fq_codel /
  pie / cake / fq_pie with guidance on when to use each.
- `examples/route/tc/fq_pie.rs`: 30-line "deploy fq_pie on dummy
  interface" example.
- `examples/route/tc/basic_ematch.rs`: 60-line "match TCP port 80
  with cls_basic + cmp ematch" example.
- `CLAUDE.md`: small additions under TC patterns.

CHANGELOG:

```markdown
### Added

- `FqPieConfig` qdisc — flow-isolating PIE-based AQM (Linux 5.6+).
- `BasicFilter` extended-match (ematch) support — compose `cmp`,
  `u32`, and `meta` primitive matches with AND/OR/XOR.
- `BpfAction` — companion to `BpfFilter` for BPF-driven actions.
- `SimpleAction` — debugging action that emits a tagged event.
```

---

## 10. Open questions

1. **`cls_basic` vs `cls_flower` overlap.** Flower is more
   ergonomic for IP/L4 matching but doesn't compose well with
   meta/cgroup matches. Basic+ematch is the right tool for
   "match on cgroup AND port AND skb mark." Document the choice
   guide in the recipe.
2. **ematch nesting (parenthesized expressions).** Linux ematch
   supports nested trees via `TCA_EMATCH_TREE_LIST` substructure.
   v0.13 ships flat lists (AND/OR sequence); nested via a follow-on
   PR if demand arises.
3. **`SimpleAction` retention policy.** sdata is just a string the
   kernel logs to the audit subsystem (or similar). Verify it's
   actually useful before shipping; if it's a vestige, drop.

---

## 11. Phasing

Four independent PRs:
- PR A: typed `CakeConfig` + `CakeOptions` parser (~450 LOC)
- PR B: `FqPieConfig` (~250 LOC)
- PR C: `BasicFilter` ematch (~700 LOC)
- PR D: `BpfAction` + `SimpleAction` (~400 LOC)

Order doesn't matter. Each is self-contained.

---

## 12. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| ematch wire format mismatches kernel expectations | Medium | Capture golden hex from `tc(8)` and write byte-comparison tests |
| fq_pie attributes get added in newer kernels we don't handle | Low | Only consume known attributes on dump; ignore unknown |
| BPF action requires bpf() syscall plumbing we don't want | Low | Take fd or pinned path; don't load programs ourselves |
| SimpleAction not actually useful | Medium | Keep behind a `--feature debug-actions`? Or just ship and see |

---

## 13. What we are NOT doing

- No coverage of `sch_gred`, `sch_choke`, `sch_multiq`, `sch_ets`,
  etc.
- No ematch nesting.
- No BPF program loading.
- No userspace BPF helpers (those live in aya/libbpf-rs).
- No `act_pedit`/`act_csum` extensions beyond what's already there.

---

## 14. Definition of done

- [ ] `CakeConfig` (typed builder) works: build, deploy, dump, verify
      against legacy `tc/options/cake.rs` output for parity
- [ ] `CakeOptions` parser added to `tc_options.rs` for per-tin stats
- [ ] `FqPieConfig` works: build, deploy, dump, verify
- [ ] `BasicFilter` ematch with cmp/u32/meta: build, deploy, packet
      classification verified end-to-end
- [ ] `BpfAction` works with a fd-based reference (skip pinned path
      verification if `cls_flower` env restrictions block it)
- [ ] `SimpleAction` ships and is documented
- [ ] All docs/examples updated
- [ ] CHANGELOG entry written

---

End of plan.
