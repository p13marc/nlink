---
to: nlink maintainers
from: nlink maintainers (audit triggered during the 0.16 cycle by a code review pass)
subject: Stale-example audit — 9 orphan example files + CI gap
status: closed by Plan 168 (2026-05-25 post-audit) — all 9 orphans triaged: 5 fixed in place + registered (`bridge/vlan.rs`, `bridge/fdb.rs`, `route/mpls.rs`, `route/nexthop.rs`, `route/srv6.rs`), 3 diagnostics demos deleted and replaced by one comprehensive `diagnostics/health_check.rs`, 1 full rewrite (`config/declarative.rs` — closure-based `NetworkConfig` API). Allowlist file deleted (script gracefully no-ops when absent). The `audit-example-registration` CI gate now enforces zero orphans from a clean slate.
target version: 0.16.0 (audit + closeout)
parent: 146-0.16-master-plan.md
created: 2026-05-24
---

# Plan 160 — example-registration audit + CI gap remediation

## Why this exists

A code-review pass during the 0.16 cycle (after Plan 156 landed)
discovered **9 example files under `crates/nlink/examples/` that
are not registered as `[[example]]` entries** in
`crates/nlink/Cargo.toml`. Since Cargo only auto-discovers examples
at the top level of `examples/` (one level deep), every file in a
subdirectory must be declared explicitly. Without that declaration:

- `cargo build --workspace --all-targets` doesn't compile them.
- `cargo run --example <name>` can't invoke them.
- API drift accumulates silently — there's no compile signal.

All 9 files fail to compile against the current API. **None of the
failures are 0.16 regressions** — verified per-symbol via
`git log -S '<symbol>' -- crates/nlink/src/` that the referenced
APIs either (a) were renamed long before 0.16 or (b) never existed
in tree at all. The examples were written speculatively against
design notes that the implementation never matched.

The 0.16 cycle does **not** ship a fix for the examples themselves
— each one needs per-file judgement that's better made when
someone has time to read the file and decide "update vs delete".
What ships in 0.16 is the **safety net** that prevents this from
recurring:

- `scripts/audit-example-registration.sh` (in tree, dormant —
  see "Wiring" below).
- This plan as the catalog + recommendation.
- A `CLAUDE.md` convention note that future examples MUST be
  registered.

## Per-file catalog

Categories (per the 0.16 audit):

- **R = Rename-only** — symbol just needs a one-token edit
  (e.g., `link_kind()` → `kind()`); the example was right once,
  drifted on a rename. Possibly fixable in <10 minutes.
- **F = Format-string bug** — example uses
  `println!(r#"...{}..."#)` where the raw-string body contains
  `{}` placeholders the format-string parser tries to consume.
  Mechanical fix (`println!("{}", r#"..."#)` or escape braces).
- **P = Phantom API** — references symbols / fields / methods
  that never existed in tree. The example was written from a
  design doc the implementation diverged from. Needs either a
  full rewrite or deletion.
- **O = Obsolete shape** — references an API shape that was
  replaced (e.g., the `LinkConfig` struct-based API replaced by
  the closure-based `NetworkConfig::link(name, |b| ...)`
  builder). Rewrite required.

| File | Category | Notes |
|---|---|---|
| `bridge/fdb.rs` | P | `LinkMessage::link_kind()` never existed (use `.kind()`). `FdbEntry::is_local()` never existed (type carries `is_self` / `is_master` / `is_extern_learn` / `is_permanent`). Speculative write that didn't match what shipped. |
| `bridge/vlan.rs` | R + F | `.link_kind()` → `.kind()` — single occurrence. Plus 7 raw-string printlns whose bodies contain `{}` placeholders. |
| `config/declarative.rs` | O | Whole example is written against a struct-based API (`LinkConfig`, `AddressConfig`, `RouteConfig`, `QdiscConfig`) that the `nlink::netlink::config` module never exposed. The actual API is closure-based: `NetworkConfig::new().link(name, |b: LinkBuilder| …)`. Full rewrite required. |
| `diagnostics/bottleneck.rs` | P + F | Reads `bottleneck.score` — `Bottleneck` (diagnostics.rs:344) has `location` / `bottleneck_type` / `current_rate` / `drop_rate` / `total_drops` / `recommendation`; no `score`. |
| `diagnostics/connectivity.rs` | P | Reads `route.dev` and `route.src` — `RouteInfo` (diagnostics.rs:329) has `destination` / `prefix_len` / `gateway` / `oif` / `metric`. Also treats `gateway_reachable` as `Option<bool>` but it's a plain `bool`. |
| `diagnostics/scan.rs` | P + F | Reads `iface.up` / `iface.carrier` as bools — actual field is `state: OperState`. Reads `RouteDiag::has_default_v4` — actual field is `has_default_ipv4` (always was). |
| `route/mpls.rs` | R + F | `route.gateway` → `route.via`. Plus 9 raw-string printlns with format placeholders. |
| `route/nexthop.rs` | R + F | `nh.is_blackhole()` → `nh.blackhole` (field, not method). Plus 8 raw-string printlns with format placeholders. |
| `route/srv6.rs` | P + F | Reads `route.table` — `Srv6LocalRoute` (srv6.rs:363) has `sid` / `prefix_len` / `action` / `oif` / `iif` / `protocol`; no `table` ever existed. |

**Verdict per file:**

- **Trivially fixable (R + F)** — `bridge/vlan.rs`, `route/mpls.rs`,
  `route/nexthop.rs`. Maintainer should pick a sitting and
  knock these out together; each is ~20 minutes of mechanical
  edits (rename + raw-string `println!("{}", r#"..."#)` pass +
  register in Cargo.toml).
- **Rewrite required (P / O)** — the other 6. Recommendation:
  decide which still demonstrate something useful and rewrite
  those; delete the rest. `config/declarative.rs` is the most
  valuable to rewrite (declarative-config is a real headline
  API) and the most expensive (full file rewrite). The
  diagnostics trio are mostly `println!`-of-doc-strings —
  arguably better replaced by the `--apply` runner pattern
  documented in `CLAUDE.md` (Active work).

## CI-gap analysis

The CI workflow at `.github/workflows/rust.yml` runs:

```yaml
build-and-test-default-features:
  - run: cargo build --workspace --all-targets
  - run: cargo test --workspace
build-and-test-all-features:
  - run: cargo build --workspace --all-targets --all-features
  - run: cargo test --workspace --all-features
```

`--all-targets` includes examples — but **only the examples
Cargo knows about**, i.e., the ones declared in `Cargo.toml` plus
top-level `examples/*.rs`. Files in subdirectories without an
explicit `[[example]]` entry are silently invisible to cargo. So
"CI is green" + "the 9 orphans don't compile" coexist consistently.

The existing `audit-examples` job (`rust.yml:136`) runs
`scripts/audit-example-features.sh`, which iterates over the
`[[example]]` blocks in `Cargo.toml` to check feature-gating. It
also inherits the registration blind spot — only sees registered
examples.

## Wiring (the safety net)

`scripts/audit-example-registration.sh` is in tree, **wired into
CI** as the `audit-example-registration` workflow job in
`.github/workflows/rust.yml`. The script:

1. Walks `crates/nlink/examples/` recursively for every `*.rs`.
2. Skips files registered via `path = "..."` in
   `crates/nlink/Cargo.toml` (those compile in the existing
   `build-and-test-*` jobs).
3. Skips files exempted in
   `scripts/audit-example-registration.allowlist` (the 9 known
   orphans below).
4. **Fails CI** for any new orphan that's neither registered nor
   allowlisted — with a copy-paste fix block in the error message.
5. Warns when the allowlist contains stale paths (the file was
   deleted or moved without pruning the entry).

Allowlist shrinkage = Plan 160 progress. Each time an orphan is
resolved (fixed-and-registered, or deleted), drop the matching
line from `scripts/audit-example-registration.allowlist`. When
the file is empty, the catalog is closed and the file can be
deleted.

### Current allowlist (= the 9 known orphans, with category)

```
examples/bridge/fdb.rs                # P  — link_kind() + is_local() never existed
examples/bridge/vlan.rs               # R+F
examples/config/declarative.rs        # O  — struct API never existed; actual is closure-based
examples/diagnostics/bottleneck.rs    # P+F — Bottleneck::score never existed
examples/diagnostics/connectivity.rs  # P  — route.dev/src never existed
examples/diagnostics/scan.rs          # P+F — field names never existed
examples/route/mpls.rs                # R+F — route.gateway → route.via
examples/route/nexthop.rs             # R+F — nh.is_blackhole() → nh.blackhole
examples/route/srv6.rs                # P+F — Srv6LocalRoute::table never existed
```

Categories: R = trivial rename, F = raw-string format bug,
P = phantom (symbol never existed), O = obsolete API shape.

## Acceptance criteria

For this plan to close:

- [x] `scripts/audit-example-registration.sh` ships in tree.
- [x] `scripts/audit-example-registration.allowlist` exempts the
      9 known orphans (each entry annotated with its category).
- [x] This plan documents the 9 orphans + per-file category.
- [x] CLAUDE.md project conventions note registers
      "every example .rs must have an `[[example]]` entry".
- [x] **Workflow stanza wired** — `audit-example-registration`
      job in `.github/workflows/rust.yml` runs the script on
      every push/PR. Allowlist makes it green today; any NEW
      orphan fails CI loudly.
- [ ] Maintainer triages the 9 orphans (one or more follow-up
      commits, one per file or grouped) — each triage edit
      removes the file's line from the allowlist.
- [ ] Once the allowlist is empty, delete the file itself
      (the script no-ops when the allowlist file is absent).

## Cross-references

- `scripts/audit-example-registration.sh` — the safety-net script.
- `scripts/audit-example-features.sh` — sibling script (different
  concern: required-features gating for the examples that ARE
  registered).
- `.github/workflows/rust.yml` — where the workflow stanza lands
  in the enforcement phase.
- `CLAUDE.md` — convention note added in the same commit as this
  plan.
