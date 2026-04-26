---
to: nlink maintainers
from: nlink maintainers
subject: Example cleanup — promote read-only-print examples to real API usage
target version: 0.15.0 (all phases shipped under `[Unreleased]`)
date: 2026-04-20; closed 2026-04-25
status: **CLOSED — all phases shipped, plan ready to archive.** Phase 1 (`62b2ee5` htb, `87d0a56` wireguard); Phase 2 (`9168f40` macsec + mptcp, plus `fef5660` `MacsecLink` rtnetlink builder + `d52cd5d` doc cleanup); Phase 3 (`c872d37` ethtool_rings + nl80211 + devlink); previously-deferred `netfilter/conntrack.rs` promoted under Plan 137 PR A slice 3 (`1e9307e`) once the library gained typed conntrack mutation. The `MacsecLink` follow-up resolves the §2.2 caveat about shelling out to `ip(8)`. Historical reference; substance is in CHANGELOG `## [Unreleased]`.
related: Plan 137 (resolved the conntrack deferral); audit conversation 2026-04-20; `impair/per_peer.rs` template
---

# Example Cleanup — Remaining Work

## 0. Summary

A 2026-04-20 audit of `crates/nlink/examples/` found **35 of 62
files** were "read-only print" — `conn.get_X()` → iterate →
`println!`. They teach the dump API but not how to *use* nlink for
mutation, recipe composition, or lifecycle management. The audit
attributed the pattern to nlink growing as an observability library
first, with new modules copy-pasting the "list X" template.

Commit `d023381` took the worst offender and three quick wins:

1. Rewrote `examples/ratelimit/simple.rs` (was 165 lines with
   ~94 lines of Rust source inside `println!` string literals).
   Now follows `impair/per_peer.rs`: default prints usage, `--apply`
   spins up a namespace + dummy, runs RateLimiter → PerHostLimiter
   with `reconcile()`, verifies no-op on second call, cleans up.
2. Deleted 4 orphan TC examples (`classes.rs` / `filters.rs` /
   `chains.rs` / `actions.rs`) — they weren't registered in
   `Cargo.toml`, so they weren't runnable, and each was just dump
   iteration.
3. Promoted `examples/genl/ethtool_features.rs` from query-only to
   query + `--toggle <feature>` + verify + restore. Default behavior
   preserved.

This plan tracks the remaining work so we don't forget it.

---

## 1. The template — `impair/per_peer.rs`

The shape that's already proven and should be reused:

1. A `print_overview()` that prints usage patterns + topology
   diagram. Runs without privileges.
2. A `--apply` gate that requires root, creates a temporary namespace
   + a dummy (or veth) interface inside it, runs the real API path,
   dumps the resulting state, removes the namespace.
3. Clear assertion/echo of each step so `cargo run -p nlink
   --example foo -- --apply` is self-documenting output.

---

## 2. Candidates to promote

### 2.1 High-value (substantial user flows)

| File | Current | Proposed | Notes |
|---|---|---|---|
| ~~`genl/wireguard.rs`~~ | ~~Dumps devices + peers~~ | **Done** — `--apply` creates wg0 via rtnetlink, sets private key + listen port + peer via GENL, dumps, and cleans up; `show` subcommand retains read-only probing. |
| ~~`genl/macsec.rs`~~ | ~~Lists TX/RX SAs/SCs~~ | **Done** — `--apply` builds a dummy + macsec-on-top (via `ip link add` since there's no `MacsecLink` builder yet), then adds a TX SA + RX SC/SA + dumps + cleans up. Follow-up: add `MacsecLink` rtnetlink helper. |
| ~~`genl/mptcp.rs`~~ | ~~Gets limits + endpoints~~ | **Done** — `--apply` creates a dummy with a v4 address, adds two endpoints bound to it, sets limits, dumps, flips flags on one, deletes, flushes. |
| ~~`route/tc/htb.rs`~~ | ~~`show` / `classes` subcommands — dump only~~ | **Done** — `--apply` builds a 3-class HTB tree + 2 flower filters in a temp namespace, dumps, tears down. Query subcommands retained. |
| `route/addresses.rs` | Partly real, partly list-only | Tighten to a single add/del/show lifecycle on a dummy | Already partly there |

### 2.2 Medium-value (typed builder coverage)

| File | Current | Proposed | Notes |
|---|---|---|---|
| ~~`genl/devlink.rs`~~ | ~~Lists devices/ports/reporters~~ | **Done** — `--reload <bus/device>` exercises `ReloadAction::DriverReinit` with a pre/post snapshot. Inventory mode unchanged (default). |
| ~~`genl/nl80211.rs`~~ | ~~Lists wireless interfaces~~ | **Done** — `--scan <iface>` triggers an active scan, waits for the `ScanComplete` multicast event (15s timeout), then prints BSSes. Inventory mode unchanged (default). |
| ~~`genl/ethtool_rings.rs`~~ | ~~Queries ring sizes~~ | **Done** — `--set-rx <N>` / `--set-tx <N>` snapshot current sizes, apply, verify, restore. Mirrors the `ethtool_features` promote pattern. |
| `netfilter/conntrack.rs` (122 lines) | Lists conntrack entries | **Deferred** — nlink's `Netfilter` connection only exposes `get_conntrack` / `get_conntrack_v6`; no add/del API. Either (a) extend the library (blocked by plan §5 non-goals), or (b) generate real traffic via veth + forwarding and observe — too involved for an example promote. Park until there's a concrete user ask. |

### 2.3 Low-value (leave as-is or shrink)

These are legitimate "how do I query X" demos. Keep but resist the temptation to let them grow:

- `route/list_interfaces.rs` — canonical hello-world, 51 lines. Fine.
- `route/routes.rs` — route table viewer. Fine.
- `route/neighbors.rs` — ARP/NDP viewer. Fine.
- `sockdiag/{summary,list_sockets,tcp_connections,unix_sockets}.rs` — observability demos; the `kill.rs` counterpart covers the mutation path.
- `diagnostics/{bottleneck,connectivity,scan}.rs` — these use the `Diagnostics` wrapper which itself is a real API; keep.
- `events/*` — all DEMO category (event-stream loops). Their purpose is to show subscription, not mutation.

### 2.4 Orphan check

Every `.rs` file under `examples/` should be registered in
`Cargo.toml` under `[[example]]`. Audit found ~16 orphan files; 4
were deleted in `d023381`. Before each promote, verify registration.

---

## 3. Cross-cutting improvements

1. **Consistent CLI conventions.** Settle on:
   - No args → print usage (no privileges)
   - `--apply` → run the real flow (requires root, uses namespace)
   - `--iface <name>` or positional → target interface for query-only
     examples
   - `--set X=Y` / `--toggle X` → opt-in mutation for promote
     candidates
2. **Namespace scoping.** All `--apply` flows should use a temporary
   named namespace (see `impair/per_peer.rs` — PID-suffixed
   `nlink-<module>-demo-<pid>`). Never touch the host's real network.
3. **Dummy interface by default.** Demos should create `DummyLink`
   inside the namespace rather than require a pre-existing
   `eth0`/`wlan0`.
4. **Explicit cleanup.** Always `namespace::delete(&ns)` in a scope
   guard (see the `result?` pattern after the inner async block in
   `per_peer.rs`) so a panic doesn't leak the namespace.

---

## 4. Suggested phasing

**Phase 1 (0.15.0 headline examples, ~1 day):**
- ~~Promote `genl/wireguard.rs` (write-path is the flagship GENL feature).~~ **Done.**
- ~~Promote `route/tc/htb.rs` to a TC pipeline example.~~ **Done.**

**Phase 2 (0.15.0 GENL completeness, ~1 day):**
- ~~Promote `genl/macsec.rs`, `genl/mptcp.rs` — mirror the wireguard shape.~~ **Done.**

**Phase 3 (opportunistic):**
- ~~`ethtool_rings.rs`, `devlink.rs`, `nl80211.rs`~~ — **done.**
- `conntrack.rs` — **deferred** pending library add/del API. See §2.2
  row for the full rationale.

Each promote is ~50-150 LOC. No BC impact. No test changes required
(examples don't run in CI).

---

## 5. Non-goals

- **Don't write integration tests for examples.** They're demos, not
  test assets. Integration tests live in `crates/nlink/tests/`.
- **Don't add library features** to make examples cleaner. If an
  example needs a helper that doesn't exist, decide separately
  whether the helper belongs in the library or not — don't let
  example ergonomics drive API.
- **Don't delete event-monitor examples** even though they print a
  lot. Their purpose is to demonstrate the stream API, and the
  loop structure is the point.

---

## 6. Definition of done (per promoted example)

- [ ] Registered in `Cargo.toml` under `[[example]]`.
- [ ] No-args mode runs without root and prints usage.
- [ ] `--apply` (or equivalent) gated on `geteuid() == 0`, uses a
      temporary namespace, creates its own test interfaces.
- [ ] Dumps state at the mutation boundaries so the output tells the
      story.
- [ ] Cleans up the namespace even on error (scope guard).
- [ ] `cargo build --example <name>` clean, clippy clean.

---

## 7. Tracking

After landing any of these, tick the matching row in §2 and update
`128b-roadmap-overview.md`. When §2.1 + §2.2 are all done, archive
this plan.

End of plan.
