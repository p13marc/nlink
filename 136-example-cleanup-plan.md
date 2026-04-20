---
to: nlink maintainers
from: nlink maintainers
subject: Example cleanup — promote read-only-print examples to real API usage
target version: 0.15.0 (or opportunistic)
date: 2026-04-20
status: draft — partial work landed on master (commit d023381), rest tracked here
related: audit in conversation 2026-04-20; builds on the `impair/per_peer.rs` template
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
| `genl/wireguard.rs` (225 lines) | Dumps devices + peers | Create wg device + add peer + verify via dump | The typed `set_device` / `set_peer` API is the whole point; today's example never calls it |
| `genl/macsec.rs` (200 lines) | Lists TX/RX SAs/SCs | Create device + add TX SA + add RX SC + RX SA + verify | Same shape as wg: write path is the value-add |
| `genl/mptcp.rs` (216 lines) | Gets limits + endpoints | Add endpoint + set limits + delete endpoint | Same pattern |
| `route/tc/htb.rs` (149 lines) | `show` / `classes` subcommands — dump only | Add `--apply` that builds a 3-class HTB tree with flower filters, dumps, tears down | Becomes the canonical "TC pipeline" example; replaces the stale tc(8) hint-comment at the bottom |
| `route/addresses.rs` | Partly real, partly list-only | Tighten to a single add/del/show lifecycle on a dummy | Already partly there |

### 2.2 Medium-value (typed builder coverage)

| File | Current | Proposed | Notes |
|---|---|---|---|
| `genl/devlink.rs` (96 lines) | Lists devices/ports/reporters | Add a `--reload <dev>` subcommand that exercises `reload()` with `ReloadAction::DriverReinit`; fall back to info-only for non-devlink hardware | Most dev envs won't have devlink HW, so keep query default |
| `genl/nl80211.rs` (89 lines) | Lists wireless interfaces | Add `--scan <iface>` that triggers a scan + prints results | Requires WiFi hardware |
| `genl/ethtool_rings.rs` (125 lines) | Queries ring sizes | Add `--set-rx <N> --set-tx <N>` that configures + verifies + restores | Mirrors the `ethtool_features` promote pattern |
| `netfilter/conntrack.rs` (122 lines) | Lists conntrack entries | Add `--add-test-entry` that injects a test flow via CTA_* attributes, dumps, removes | Requires `ip_conntrack`; verify library support first |

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
- Promote `genl/wireguard.rs` (write-path is the flagship GENL feature).
- Promote `route/tc/htb.rs` to a TC pipeline example.

**Phase 2 (0.15.0 GENL completeness, ~1 day):**
- Promote `genl/macsec.rs`, `genl/mptcp.rs` — mirror the wireguard shape.

**Phase 3 (opportunistic):**
- `ethtool_rings.rs`, `devlink.rs`, `nl80211.rs`, `conntrack.rs` —
  lower value, land when someone's touching the related module.

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
