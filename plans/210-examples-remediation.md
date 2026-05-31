---
to: nlink maintainers
from: 0.19 second deep-audit
subject: Plan 210 — Examples remediation (H10 + L1-L33 + cleanup convention)
status: queued for 0.19 — HIGH for H10; LOW-bundle otherwise
target version: 0.19.0
parent: [203](203-0.19-second-batch-master.md)
source: docs/AUDIT_REPORT_2026_05_31.md §H10, L1–L33
created: 2026-05-31
---

# Plan 210 — Examples remediation

## 1. Why this plan exists

The examples audit found 50 findings, most LOW but one HIGH:
- **H10** `examples/nftables/firewall.rs` has no root check + leaks
  a stray `example` nftables table on partial-failure
- 12 stale example-name doc-comments (users hit "no such example")
- 14 `--apply` examples exit 1 on non-root instead of the
  CLAUDE.md `Ok(())` skip convention
- 7 examples document "Requires root" but lack the check
- Various stale comments referencing deleted plans

Examples are the canonical learning channel; bugs here mislead
every new user.

## 2. Phase 1 — H10 firewall.rs cleanup leak

**File:** `crates/nlink/examples/nftables/firewall.rs:21-152`

Restructure to always run cleanup, even on partial failure:

```rust
async fn run() -> Result<()> {
    let conn = Connection::<Nftables>::new()?;
    nlink::require_root!();

    let result = async {
        conn.add_table("example", Family::Inet).await?;
        conn.add_chain(/* ... */).await?;
        // ... rest of demo ...
        Ok::<_, Error>(())
    }.await;

    // Always run cleanup, even on Err.
    let _ = conn.flush_table("example", Family::Inet).await;
    let _ = conn.del_table("example", Family::Inet).await;

    result
}
```

Adds `nlink::require_root!()` early-return for non-root invocation.

## 3. Phase 2 — Stale example-name doc-comments (L1-L11)

12 files have `Run with: cargo run -p rip --example NAME`
where:
- Package is `nlink` not `rip` (legacy name)
- Registered name is `route_NAME` / `route_tc_NAME` not bare `NAME`

| File | Fix in doc comment |
|---|---|
| `examples/route/list_interfaces.rs:6` | `nlink` + `route_list_interfaces` |
| `examples/route/stats.rs:6` | same |
| `examples/route/addresses.rs:6,9-10` | `route_addresses` |
| `examples/route/routes.rs:6,9-10` | `route_routes` |
| `examples/route/neighbors.rs:6,9` | `route_neighbors` |
| `examples/route/namespaces.rs:10,13` | `route_namespaces` |
| `examples/route/error_handling.rs:6` | `route_error_handling` |
| `examples/route/link_create.rs:6,11-14` | `route_link_create` |
| `examples/route/tc/netem.rs:6,11-14` | `route_tc_netem` |
| `examples/route/tc/stats.rs:6,9-10` | `route_tc_stats` |
| `docs/recipes/conntrack-programmatic.md:347` | `--example netfilter_conntrack` |

Mechanical edit. Add an audit script
`scripts/audit-example-doc-names.sh` that greps each example's
top comment for `cargo run -p` and verifies the package name and
example name match Cargo.toml. Wire into CI as a separate gate.

## 4. Phase 3 — `--apply` skip convention (L12-L25)

14 examples that use the `--apply` runner pattern call
`std::process::exit(1)` on non-root. The CLAUDE.md convention is
to `return Ok(())` so non-root invocation exits cleanly.

Replace each:
```rust
if unsafe { libc::geteuid() } != 0 {
    eprintln!("--apply requires root; run with sudo");
    std::process::exit(1);
}
```

With:
```rust
nlink::require_root!();
```

Files (14):
- `examples/genl/wireguard.rs:158-161`
- `examples/netfilter/conntrack.rs:111-114`
- `examples/netfilter/conntrack_events.rs:89-92,109-112`
- `examples/impair/per_peer.rs:48-51`
- `examples/ratelimit/simple.rs:53-56`
- `examples/route/tc/htb.rs:148-151`
- `examples/genl/macsec.rs:148-151`
- `examples/genl/mptcp.rs:144-147`
- `examples/genl/devlink.rs:139-142`
- `examples/genl/ethtool_features.rs:106-109`
- `examples/genl/ethtool_rings.rs:119-122`
- `examples/genl/nl80211.rs:132-135`
- `examples/xfrm/ipsec_monitor.rs:157-160`
- `examples/lab/three_namespace.rs:51-54`

Pattern is mechanical. Plus L43-L44 (`macros/define_taskstats.rs`)
which uses `return Err(e)` for EPERM — switch to `Ok(())`.

## 5. Phase 4 — Missing root pre-checks (L26-L33)

Add `nlink::require_root!()` (with print-overview on non-root) to:
- `examples/nftables/firewall.rs:21-152` (covered by Phase 1)
- `examples/nftables/declarative.rs:46-58` — `apply` path
- `examples/config/declarative.rs:48-58,69` — `apply` + teardown
- `examples/route/batch.rs:14-60`
- `examples/route/bond.rs:21-83`
- `examples/route/tc/bpf.rs:22-79`
- `examples/route/link_create.rs:23-78`

Pattern:
```rust
fn main() -> Result<()> {
    if !is_root() {
        print_overview();
        return Ok(());
    }
    run_apply()
}

fn print_overview() {
    println!("This example demonstrates X. Run as root with --apply to actually X.");
}
```

## 6. Phase 5 — Documentation drift in examples (L36-L42)

| File:line | Fix |
|---|---|
| `route/addresses.rs:73` | drop "i32 keys" comment (it's u32) |
| `events/resync_loop.rs:20-25` | drop "deferred to 0.17" — Plan 151 shipped |
| `diagnostics/health_check.rs:1-19` | drop "Plan 168 Phase 2 closeout" — historical |
| `events/multi_source.rs:33` | clarify EPERM possibility in connector error message |
| `genl/wireguard.rs:43-44` | note on private-key clamping |
| `genl/macsec.rs:33-36` | "demo keys, not real keys" note |

## 7. Tests

- Run `scripts/audit-example-registration.sh` — must pass.
- Run new `scripts/audit-example-doc-names.sh` — must pass.
- `cargo build --workspace --all-targets` — clean.
- `cargo run -p nlink --example route_list_interfaces` (sanity).

## 8. CHANGELOG entry

```markdown
### Fixed

- **`examples/nftables/firewall.rs` no longer leaks an
  `example` nftables table on partial failure** (H10). Cleanup
  now runs unconditionally; root check added.

- **14 example `--apply` paths use `nlink::require_root!()` skip
  convention** instead of `exit(1)`. Matches CLAUDE.md and
  doesn't pollute CI exit codes.

- **12 example doc-comments renamed to match Cargo.toml-
  registered names**. Users copy-pasting `cargo run -p nlink
  --example <name>` get the right command.

- **7 examples documenting "Requires root" gained the check**
  itself. Non-root invocation prints overview + exits 0.

- **Various stale plan-number references in example comments
  cleaned up.**

### Added

- **`scripts/audit-example-doc-names.sh` CI gate** — fails build
  if any example's top doc comment uses a `cargo run -p` invocation
  that doesn't match the package + example name in `Cargo.toml`.
  Prevents the L1-L11 drift class from recurring.
```

## 9. Acceptance criteria

- [ ] H10 firewall.rs cleanup wrap + root check
- [ ] 12 doc-comments updated (L1-L11)
- [ ] 14 `--apply` paths use require_root! (L12-L25)
- [ ] 7 root pre-checks added (L26-L33)
- [ ] Example doc-name CI gate created
- [ ] All examples build and run with `cargo build --workspace`
- [ ] CHANGELOG entries

## 10. Effort estimate

| Phase | Time |
|---|---|
| Phase 1 — H10 firewall.rs | 30 min |
| Phase 2 — 12 doc renames | 30 min |
| Phase 3 — 14 require_root! conversions | 1 h |
| Phase 4 — 7 root pre-checks | 1 h |
| Phase 5 — drift cleanup | 30 min |
| Audit script + CI integration | 30 min |
| CHANGELOG | 30 min |
| **Total** | **~4 h** |

## 11. Risks

- **Low risk** — mechanical edits + script integration.
- **CI gate may surface more drift than expected** — script run
  before merge will catch any I missed. Acceptable.

## 12. Cross-cutting artifacts

| Artifact | Action |
|---|---|
| `CHANGELOG.md` | 5 fixed + 1 added entries |
| `scripts/audit-example-doc-names.sh` (new) | CI gate |
| `.github/workflows/*.yml` | wire new gate into CI |
| `crates/nlink/examples/` | ~30 file edits |

End of plan.
