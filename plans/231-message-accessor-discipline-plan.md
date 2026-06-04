---
to: nlink maintainers
from: 0.20 cycle pre-work — deep audit derivation
subject: `RuleMessage` accessor discipline + convention-alignment sweep
status: planning
target version: 0.20.0
parent: [Plan 220 master](220-0.20-master-plan.md)
source: [AUDIT_API.md](../AUDIT_API.md) Finding A3
created: 2026-06-04
---

# Plan 231 — `RuleMessage` accessor discipline + convention sweep

## 1. Why this plan exists

`RuleMessage` breaks the message-type convention used by every
other `*Message` in the lib.

Convention (confirmed across `LinkMessage`, `AddressMessage`,
`RouteMessage`, `NeighborMessage`, `TcMessage`):

- All fields are `pub(crate)`.
- A typed accessor method (`fn family(&self) -> AddressFamily`,
  `fn index(&self) -> u32`, etc.) is provided per field.
- The struct is `#[non_exhaustive]` so destructuring at the
  external boundary is prohibited.
- Raw kernel-layout structs (`IfInfoMsg`, `IfAddrMsg`, etc.) are
  never exposed through public field access; accessors lift the
  load-bearing fields out and convert the raw integers to typed
  forms at the boundary.

Outlier — `RuleMessage`
(`crates/nlink/src/netlink/messages/rule.rs:38-80`):

```rust
#[derive(Debug, Clone, Default)]
pub struct RuleMessage {
    /// Fixed-size header.
    pub header: FibRuleHdr,        // ← raw kernel struct leaked
    pub priority: u32,             // ← all fields pub
    pub source: Option<IpAddr>,
    pub destination: Option<IpAddr>,
    pub iifname: Option<String>,
    pub oifname: Option<String>,
    pub fwmark: Option<u32>,
    pub fwmask: Option<u32>,
    pub table: u32,                // ← shadows header.table; conflict mode unclear
    // ... 11 more pub fields ...
}
```

Three concrete consequences:

1. **`pub header: FibRuleHdr` leaks the internal C struct
   layout** through the public API. Any future change to
   `FibRuleHdr` (e.g., kernel adds a `dst_len_64` field that
   forces the struct to grow) is now a public-API break.

2. **Direct field mutation has no validation**. A downstream
   consumer can write `msg.priority = u32::MAX` and the lib has
   no way to prevent it. Other `*Message` types prevent this by
   construction (only the parser sets fields).

3. **Field-name lock-in**. The internal `del_rule_by_priority`
   reads `rule.priority` (positional access on the pub field, at
   `connection.rs:1609`). Renaming the field requires also
   updating that lib-internal callsite — but if we exposed it as
   `priority()`, the accessor's contract is the public surface
   and the field is free to rename.

The audit lists this as **MID** severity: inconsistency that
reads as suspect to anyone learning the codebase. The fix is
mechanical.

This plan does the `RuleMessage` flip plus a sweep of any other
`*Message` types that drift from the convention.

## 2. Sweep target — full table

Pre-work for the plan: grep `pub struct .*Message` under
`crates/nlink/src/netlink/`. Confirmed message types as of
audit-time:

| Type | File | Convention status |
|---|---|---|
| `LinkMessage` | `messages/link.rs:52` | ✅ `pub(crate)` + accessors |
| `AddressMessage` | `messages/address.rs` | ✅ `pub(crate)` + accessors |
| `RouteMessage` | `messages/route.rs` | ✅ `pub(crate)` + accessors |
| `NeighborMessage` | `messages/neighbor.rs` | ✅ `pub(crate)` + accessors |
| `TcMessage` | `messages/tc.rs` | ✅ `pub(crate)` + accessors (TcHandle-typed) |
| `RuleMessage` | `messages/rule.rs:38` | ❌ **all `pub`, header leaked** |
| `BridgeVlanMessage` | tbd | audit-time check |
| `FdbMessage` | tbd | audit-time check |
| `MplsRouteMessage` | tbd | audit-time check |
| `NexthopMessage` | tbd | audit-time check |

The first five are the convention; `RuleMessage` is the
audit-confirmed outlier. The last four are audit-time grep
targets — confirm each matches the convention before deciding
whether to include in the sweep.

Out of scope (not message types but flagged for awareness):

- `LinkStats` (all `pub`, no `#[non_exhaustive]`) — flagged in
  Finding A21 as a sibling convention break. Defer to 0.21
  because the kernel-stats counter set grows and the convention
  needs a separate thought about forward-compat.

## 3. The convention restated

For any `*Message` in `crates/nlink/src/netlink/messages/`:

1. **Fields are `pub(crate)`**. The struct is mutated by parser
   code; consumed by readers via accessors.
2. **Struct carries `#[non_exhaustive]`**. External
   destructuring is statically prohibited; the kernel's wire
   format may grow.
3. **Each load-bearing field has an accessor method**
   (`pub fn field_name(&self) -> FieldType`).
4. **Accessors return typed forms** where the raw field is a
   numeric kernel constant. `family: u8` becomes
   `family() -> AddressFamily` (per Plan 227).
5. **Raw kernel-layout structs (`*Hdr`, `*Msg`) are not exposed
   as public fields**. Their useful fields are lifted into
   per-field accessors.

## 4. Per-struct change details

### 4.1 `RuleMessage` (`messages/rule.rs:38-80`)

```rust
#[derive(Debug, Clone, Default)]
#[non_exhaustive]              // ← NEW
pub struct RuleMessage {
    pub(crate) header: FibRuleHdr,            // ← was pub
    pub(crate) priority: u32,                 // ← was pub
    pub(crate) source: Option<IpAddr>,
    pub(crate) destination: Option<IpAddr>,
    pub(crate) iifname: Option<String>,
    pub(crate) oifname: Option<String>,
    pub(crate) fwmark: Option<u32>,
    pub(crate) fwmask: Option<u32>,
    pub(crate) table: u32,
    pub(crate) goto: Option<u32>,
    pub(crate) flow: Option<u32>,
    pub(crate) tun_id: Option<u64>,
    pub(crate) suppress_ifgroup: Option<u32>,
    pub(crate) suppress_prefixlen: Option<u32>,
    pub(crate) l3mdev: Option<u8>,
    pub(crate) uid_range: Option<FibRuleUidRange>,
    pub(crate) protocol: Option<u8>,
    pub(crate) ip_proto: Option<u8>,
    pub(crate) sport_range: Option<FibRulePortRange>,
    pub(crate) dport_range: Option<FibRulePortRange>,
}

impl RuleMessage {
    /// Address family of the rule. Per Plan 227, returns the
    /// typed [`AddressFamily`] rather than the raw `u8`.
    pub fn family(&self) -> AddressFamily {
        // header.family is the wire-format byte; the parser
        // accepted whatever the kernel gave us. If a future
        // kernel introduces an AF_* we don't model, fall back
        // to Unspec — the user can still see the raw bytes via
        // the catch-all path in 0.21 if they need it.
        AddressFamily::try_from_raw(self.header.family)
            .unwrap_or(AddressFamily::Unspec)
    }

    pub fn priority(&self) -> u32 { self.priority }

    pub fn source(&self) -> Option<IpAddr> { self.source }

    pub fn destination(&self) -> Option<IpAddr> { self.destination }

    pub fn iifname(&self) -> Option<&str> {
        self.iifname.as_deref()
    }

    pub fn oifname(&self) -> Option<&str> {
        self.oifname.as_deref()
    }

    pub fn fwmark(&self) -> Option<u32> { self.fwmark }

    pub fn fwmask(&self) -> Option<u32> { self.fwmask }

    /// Routing table ID. The kernel exposes a 32-bit value via
    /// `FRA_TABLE` that overrides the legacy 8-bit `header.table`
    /// field for tables > 255. Returns the override value.
    pub fn table(&self) -> u32 { self.table }

    pub fn goto(&self) -> Option<u32> { self.goto }
    pub fn flow(&self) -> Option<u32> { self.flow }
    pub fn tun_id(&self) -> Option<u64> { self.tun_id }
    pub fn suppress_ifgroup(&self) -> Option<u32> { self.suppress_ifgroup }
    pub fn suppress_prefixlen(&self) -> Option<u32> { self.suppress_prefixlen }
    pub fn l3mdev(&self) -> Option<u8> { self.l3mdev }
    pub fn uid_range(&self) -> Option<FibRuleUidRange> { self.uid_range }
    pub fn protocol(&self) -> Option<u8> { self.protocol }
    pub fn ip_proto(&self) -> Option<u8> { self.ip_proto }
    pub fn sport_range(&self) -> Option<FibRulePortRange> { self.sport_range }
    pub fn dport_range(&self) -> Option<FibRulePortRange> { self.dport_range }

    /// The fixed-size header. Returns a copy because the
    /// internal struct must not be borrowed for mutation
    /// outside the parser.
    ///
    /// Prefer the field-level accessors above; this exists as
    /// an escape hatch for callers that need the raw header
    /// bytes (e.g., re-encoding for a custom message).
    pub fn header(&self) -> FibRuleHdr { self.header }
}
```

Internal sites that read fields directly (e.g.
`del_rule_by_priority` at `connection.rs:1609` reading
`rule.priority`) keep working — `pub(crate)` field access from
inside the crate is allowed. No internal-call churn beyond the
two or three sites that read fields.

### 4.2 Adjacent message types — audit pre-work

The audit-time grep for "`pub.*: .* in messages/`" returns:

- `BridgeVlanMessage`, `FdbMessage`, `MplsRouteMessage`,
  `NexthopMessage` — pre-work step 1 is to check each. If any
  match the `RuleMessage` shape, include them in this plan's
  scope. Per CLAUDE.md "Investigate before destroying" the
  convention sweep needs a real grep, not an attribute search.

If any of those four match the convention already, this plan
scopes down to `RuleMessage` alone.

## 5. Migration (worked example)

```rust
// Before (downstream code reading rule properties):
let rules: Vec<RuleMessage> = conn.get_rules().await?;
for r in &rules {
    println!("rule priority {} family {} from {:?}",
             r.priority, r.header.family, r.source);
}

// After:
let rules: Vec<RuleMessage> = conn.get_rules().await?;
for r in &rules {
    println!("rule priority {} family {:?} from {:?}",
             r.priority(),
             r.family(),     // ← now AddressFamily (Plan 227)
             r.source());
}
```

And the destructure-rejection case:

```rust
// Before (compiled, even though it's a load-bearing assumption
// about a kernel-layout struct):
let RuleMessage { priority, header, source, .. } = rule;

// After: compile error. The struct is #[non_exhaustive] and
// fields are pub(crate); the caller must read via accessors.
```

The migration guide entry:

```markdown
### `RuleMessage` accessor discipline (Plan 231)

`RuleMessage` joins every other `*Message` in the lib in using
`pub(crate)` fields + accessor methods. `#[non_exhaustive]` is
added so external destructuring stops compiling. The
`header` field is no longer a public `FibRuleHdr`; a
`header() -> FibRuleHdr` accessor returns a copy.

Net behaviour change: callers replace `rule.priority` with
`rule.priority()` (and similarly for every other field). The
`rule.header.family` read becomes `rule.family()`, which now
returns the typed `AddressFamily` (per Plan 227) instead of a
raw `u8`.

Destructuring `RuleMessage` from outside the crate stops
compiling. Use the field accessors.
```

## 6. Test plan

1. **Unit tests** at the `messages/rule.rs` definition site,
   confirming each accessor's return shape:

   ```rust
   #[test]
   fn rule_message_accessors_match_typed_contracts() {
       let r = RuleMessage::default();
       let _: AddressFamily = r.family();   // Plan 227 typed return
       let _: u32 = r.priority();
       let _: Option<IpAddr> = r.source();
       let _: Option<&str> = r.iifname();   // &str, not &String
       let _: FibRuleHdr = r.header();       // owned copy
   }
   ```

2. **Trybuild compile-fail** confirming external destructuring
   no longer compiles:

   ```rust
   // tests/compile_fail/rule_destructure.rs (expected: fail)
   use nlink::RuleMessage;
   fn _no(r: RuleMessage) {
       let RuleMessage { priority, .. } = r;  // pub(crate) field
   }
   ```

3. **Integration round-trip** confirming a rule populated via
   `RuleBuilder`, applied, dumped, and parsed back exposes the
   same field values through the accessors.

4. **Convention audit script** — extend
   `scripts/audit-message-accessor-convention.sh` (new) to fail
   the build if any `crates/nlink/src/netlink/messages/*.rs`
   file has `pub field:` that isn't `pub(crate)`. Run in CI
   alongside the existing audit scripts. This is the durable
   prevention — Plan 231's sweep is the one-time flip; the
   audit script keeps the convention from drifting again.

## 7. Risks

- **Hard compile break for downstream destructuring**. Anyone
  with `let RuleMessage { priority, ... } = r` in their tree
  breaks. Mitigation: the migration guide spells out the
  field-to-accessor mapping. Plus, the broader 0.20 cycle is a
  minor-version-bump with multiple typed-API tightenings; we're
  already telling consumers "expect to migrate" via 227, 228,
  230.

- **`pub fn header(&self) -> FibRuleHdr` still leaks the
  kernel-layout struct**. It returns a copy (not a reference)
  so mutation is impossible, but the type is still public. If
  `FibRuleHdr` grows a field in 0.21, the accessor's return
  type changes (technically breaking). Acceptable: the
  alternative — synthesize a typed `RuleHeader` struct
  duplicating the kernel layout — is busywork; the `header()`
  accessor is documented as the escape hatch, with the
  field-level accessors being the recommended path.

- **The convention audit script could fire on the
  not-yet-swept structs in §4.2**. Mitigation: pre-work step 1
  resolves the audit; the script lands with the sweep, not
  before.

- **`family()` returning `AddressFamily` rather than `u8` is a
  silent typed-return change**. Per Plan 227's pattern, raw
  `u8` access stays available via `rule.header().family` (the
  raw kernel byte) as an escape hatch. The accessor return is
  the typed form.

## 8. Acceptance

This plan ships when:

- ✅ `RuleMessage` fields are `pub(crate)`.
- ✅ `#[non_exhaustive]` is added.
- ✅ Per-field accessors exist with the §4.1 signatures.
- ✅ `rule.family()` returns `AddressFamily` (per Plan 227).
- ✅ The pre-work grep (§4.2) confirms no other `*Message`
  needs the same flip — or those are included in scope.
- ✅ The compile-fail trybuild test confirms external
  destructuring is rejected.
- ✅ `scripts/audit-message-accessor-convention.sh` exists and
  passes; wired into CI.
- ✅ Internal callsites that read `rule.priority` etc. are
  migrated to the accessors (or stay as `pub(crate)` field
  reads — either is fine inside the crate, but consistency
  suggests using accessors).
- ✅ The migration guide gains the §5 entry.

## 9. Cross-references

- [Plan 220 master](220-0.20-master-plan.md) §3.3 — typed-API
  tightening cluster
- [AUDIT_API.md](../AUDIT_API.md) Finding A3 (this plan's
  source) + A21 (sibling `LinkStats` convention break, deferred)
- [Plan 227 — `AddressFamily`](227-family-newtype-plan.md) —
  `family()` accessor returns the typed form
- [Plan 230 — `ChainName`](230-verdict-chainname-plan.md) —
  sibling nftables-surface tightening
- 0.19 Plan 207d — route identity widening; same `Message`
  family touched, established the `pub(crate)` discipline this
  plan extends
- CLAUDE.md `## Parser robustness` — the parser policy that
  these accessors enforce at the consumption end
- CLAUDE.md `## Type-safe units` — the typed-newtype convention
  this plan extends to message accessors
