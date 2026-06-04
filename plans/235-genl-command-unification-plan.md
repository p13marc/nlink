---
to: nlink maintainers
from: 0.20 cycle pre-work — deep audit derivation
subject: Plan 208 Phase 3-4 — GENL command + family-resolution unification
status: planning — discretionary; cycle ships without it if other plans crowd
target version: 0.20.0 (or 0.21.0)
parent: [Plan 220 master](220-0.20-master-plan.md)
source: [plans/INDEX.md](INDEX.md) `## 0.20 cycle seed` Plan 208 Phase 3-4 row; CHANGELOG `## [0.19.0]` finding H9
created: 2026-06-04
---

# Plan 235 — Plan 208 Phase 3-4: GENL command + family-resolution unification

## 1. Why this plan exists

0.19 Plan 208 closed 8 of 9 recv-loops in `crates/nlink/src/`
against the canonical "Recv-loop shape" template in CLAUDE.md.
The 9th was the GENL command path in `wg_command` — finding H9
in the 0.19 audit. The race shape was: a stale frame from a
prior request on the same socket delivered to `wg_command`,
which lacked the mandatory seq filter, was interpreted as the
current request's response, and produced a wrong-shaped result.
H9 shipped fixed in 0.19, but the broader pattern — every GENL
family carries its own command-path recv loop, NOT routed
through the standard `send_request_inner` helper — is still
present.

This plan finishes the unification. Two phases:

- **Phase 3 (command path)**: every GENL family's command path
  shares one helper that follows the canonical template.
- **Phase 4 (family-resolution path)**: every GENL family's
  family-ID resolution shares one helper that follows the
  canonical template. Plan 099 unified the `mcast_group()`
  resolution in 0.15; this finishes the symmetric work for the
  unicast command/family path.

H9 was the load-bearing failure. The audit caught it because the
review compared the wg_command shape to the recv-loop template
and found the seq filter missing. Other family command paths
may have the same shape — the audit didn't walk all of them.
This plan does.

This plan is **discretionary** for 0.20. Plan 234 (the
dispatcher) subsumes most of Phase 3 (the dispatcher's recv
loop is the canonical implementation of the template — every
GENL command goes through it). If Plan 234 ships first, this
plan reduces to "verify the dispatcher handles each family's
command shape correctly" plus the Phase 4 family-ID work.

## 2. The audit table

Walk every GENL family in `crates/nlink/src/netlink/genl/` and
classify its command-path recv shape:

| Family | File | Dispatcher shape | Conforms to template? |
|---|---|---|---|
| wireguard | `genl/wireguard/connection.rs` | `wg_command` helper | YES (fixed in 0.19 H9 — seq filter + DONE/ACK end marker) |
| macsec | `genl/macsec/connection.rs` | per-method `send_request_and_wait` | **TBD — audit needed** |
| mptcp | `genl/mptcp/connection.rs` | per-method | **TBD** |
| ethtool | `genl/ethtool/connection.rs` | per-method (multiple commands per file: rings, channels, linkmodes, …) | **TBD — high surface area** |
| nl80211 | `genl/nl80211/connection.rs` | per-method | **TBD** |
| devlink | `genl/devlink/connection.rs` | per-method | **TBD** |
| dpll | `genl/dpll/connection.rs` | macro-derived via `send_typed` | YES — `send_typed` routes through the standard helper |
| net_shaper | `genl/net_shaper/connection.rs` | macro-derived via `send_typed` | YES |
| nlink-macros user families | `nlink-macros::__rt` | shared `send_typed` runtime | YES (by construction) |

The "TBD" rows are pre-macro families that pre-date Plan 154's
`#[derive(GenlMessage)]` + `send_typed` infrastructure. They each
roll their own request/response builder. They MAY follow the
template (the convention is well-known by now) but the audit
hasn't confirmed it. This plan's Phase 3 is the confirmation +
unification pass.

### 2.1 Family-resolution paths (Phase 4)

Every GENL family resolves its numeric family ID at connection
construction. Plan 099 unified the mcast-group resolution but the
unicast family-ID path is per-family:

| Family | Resolution path |
|---|---|
| wireguard | `genl::wireguard::Wireguard::resolve_family_id` |
| macsec | `genl::macsec::Macsec::resolve_family_id` |
| mptcp | `genl::mptcp::Mptcp::resolve_family_id` |
| ethtool | `genl::ethtool::Ethtool::resolve_family_id` |
| nl80211 | `genl::nl80211::Nl80211::resolve_family_id` |
| devlink | `genl::devlink::Devlink::resolve_family_id` |
| dpll | `genl::dpll::Dpll` — via `send_typed` runtime |
| net_shaper | `genl::net_shaper::NetShaper` — via `send_typed` runtime |
| Macro-generated | via `__rt::resolve_family_id` |

The macro-derived families share one path; the older families
each have their own. The risk is the same as Phase 3 — a
missing seq filter or wrong end-marker in any of these means
the family-ID resolution at connection-init can return the
wrong number (a stale frame from a prior `CTRL_GET_FAMILY`
on the same socket).

## 3. The unified helper

Add to `crates/nlink/src/netlink/genl/mod.rs`:

```rust
/// Send a GENL command and await its response, following the
/// canonical recv-loop shape (CLAUDE.md `## Recv-loop shape`).
///
/// Used by every GENL family's command path. Mandatory seq
/// filter + `NLMSG_DONE` / ACK end marker + default Connection
/// timeout.
pub(crate) async fn send_genl_command<P: ProtocolState>(
    conn: &Connection<P>,
    family_id: u16,
    cmd: u8,
    flags: u16,                  // NLM_F_REQUEST | NLM_F_ACK by default
    payload: &[u8],
) -> Result<Vec<u8>> {
    // ... builds GenlMsgHdr + payload, calls Connection::send_request_and_wait
    //     which is the existing canonical implementation.
}

/// Resolve a GENL family ID by name. Standardized over every
/// older per-family `resolve_family_id` implementation.
pub(crate) async fn resolve_family_id<P: ProtocolState>(
    conn: &Connection<P>,
    family_name: &str,
) -> Result<u16> {
    // ... CTRL_CMD_GETFAMILY via send_genl_command, parses
    //     CTRL_ATTR_FAMILY_ID. Single implementation; replaces
    //     the 6 per-family copies.
}
```

`send_request_and_wait` is the existing F1-era canonical
implementation. If Plan 234 (the dispatcher) lands, that helper
routes through the dispatcher. Either way, every GENL command
inherits the recv-loop template "for free" by going through
this helper instead of rolling its own.

## 4. Per-family migration

For each "TBD" row in §2:

1. Open the family's `connection.rs`.
2. For every method that sends a command, audit its current
   recv shape against the canonical template. Look for:
   - Missing seq filter (the H9 bug class).
   - Wrong end marker (e.g. checking `NLMSG_ERROR` first then
     `NLMSG_DONE`, but exiting on a per-op ACK mid-dump).
   - No timeout (the default 30s should be inherited via the
     Connection's default — if a method is manually building
     its own recv loop, it must explicitly request the timeout).
3. Replace the per-method recv loop with `send_genl_command(...)`
   or, for dumps, the existing canonical `dump_typed_stream`
   helper.
4. Replace the per-family `resolve_family_id` with
   `genl::resolve_family_id(conn, "<family-name>")`.

The migration order should be: smallest families first (macsec,
mptcp) for the easy wins, then ethtool last because of its
surface area (one connection.rs file with ~30 commands).

## 5. Test plan

- **Existing tests**: every family has unit tests for its
  message-building and response-parsing. Those must continue to
  pass; the unified helper does not change wire shape.
- **New test (`send_genl_command_filters_stale_seq`)**: synthetic
  test that injects a stale GENL response into the mock socket
  before the real one; assert the helper skips the stale frame
  and returns the real response. This is the H9 regression test
  written generically — the test is parameterized over every
  family by passing the family-id + cmd combination.
- **New test (`resolve_family_id_filters_stale_seq`)**: same
  pattern for the family-resolution path.
- **Audit script update**: extend
  `scripts/audit-recv-loop-error-handling.sh` to assert that no
  file under `crates/nlink/src/netlink/genl/` rolls its own recv
  loop — every command path must go through `send_genl_command`
  or `send_typed`. Whitelist the families that legitimately
  need direct loop access (none expected after the migration).

## 6. Risks

- **Plan 234 overlap**. If the dispatcher (Plan 234) lands first,
  the dispatcher's recv loop is the canonical implementation for
  every command. Plan 235's Phase 3 reduces to "delete the per-
  family recv-loop code and let the dispatcher handle it";
  Phase 4 (family-resolution) remains. Mitigation: this plan's
  Phase 3 is gated on Plan 234's status — if Plan 234 ships in
  0.20, Phase 3 is "delete dead code"; if Plan 234 slips, Phase 3
  is "introduce the unified helper".

- **Behavior change on a per-family edge case**. Some pre-macro
  families may handle GENL-specific error patterns (e.g.,
  `CTRL_CMD_GET_FAMILY` returning `ENOENT` for missing families)
  in ways the unified helper doesn't preserve. Mitigation: the
  migration is incremental per family; tests pin each family's
  observable error shape before and after.

- **ethtool's surface area**. ethtool has the most commands of
  any family (~30, varies by kernel). The migration there is
  the bulk of the plan's work. Mitigation: split into a
  per-command-group commit (rings, channels, linkmodes, FEC,
  …) so the diff per commit is small. Each commit lands its
  own test.

- **Family-resolution dedup is largely cosmetic**. The current
  per-family `resolve_family_id` implementations work today.
  The unification's benefit is "one place to audit for the
  recv-loop shape" — real but unsexy. Mitigation: the per-
  family copies are removed, not just dual-wired; one place
  to fix bugs.

- **Discretionary status**. If the cycle runs out of room,
  Phase 3 may slide while Phase 4 lands (or vice versa). The
  plan accepts a split — each phase is independently shippable
  as long as the test gates pass.

## 7. Acceptance

The plan lands when:

- §2's audit table is filled in (every TBD row resolved).
- `send_genl_command` and `resolve_family_id` helpers shipped.
- Every "TBD" family migrated to the helpers (Phase 3 + Phase 4).
- The per-family-loop check in
  `scripts/audit-recv-loop-error-handling.sh` is green.
- The H9-regression test pattern is parameterized over every
  family and passes.
- CHANGELOG `## [Unreleased]` calls out the recv-loop closure.

If the cycle ends with a partial landing, the partial state
must be:

- All "TBD" families either migrated OR explicitly documented
  as not-yet-migrated in `CLAUDE.md ## Recv-loop shape` with
  the rationale (e.g., "ethtool migration deferred to 0.21
  because of surface area").
- No half-migrated family (every family is either fully
  unified OR fully on the old shape; no mixed state per file).

## 8. Cross-references

- CHANGELOG `## [0.19.0]` finding H9 — the wg_command stale-
  frame race that motivated this plan.
- CLAUDE.md `## Recv-loop shape (canonical)` — the template
  every command path must follow.
- [Plan 208](208-recv-loop-completion-plan.md) (0.19) — the
  9-loop closeout this plan finishes (Phase 3-4 carryover).
- [Plan 099](099-mcast-group-unification-plan.md) (0.15) — the
  prior unification of `mcast_group()` resolution; symmetric
  precedent for Phase 4.
- [Plan 154](154-nlink-macros-plan.md) (0.16) — the macro
  infrastructure that already routes dpll + net_shaper + user
  families through the unified path.
- [Plan 234](234-nlrouter-dispatcher-plan.md) — the dispatcher
  that subsumes Phase 3 if it lands first.
- `scripts/audit-recv-loop-error-handling.sh` — the CI gate
  that enforces the recv-loop shape; extends to cover GENL
  command paths in this plan.
- [Plan 170](170-send-batch-recv-loop-plan.md) +
  [Plan 172](172-recv-loop-audit-plan.md) — the prior recv-loop
  hardening passes that established the template.
