# Declarative nftables config — diff + apply + reconcile

How to manage an entire nftables ruleset declaratively: define
the desired state in Rust (or load it from TOML/YAML/JSON in your
own crate), let nlink compute the diff against the kernel, and
apply atomically. Idempotent — re-applying the same config is a
no-op. Mirrors the existing
[`NetworkConfig`](../../crates/nlink/src/netlink/config/mod.rs)
pattern for links / addresses / routes / qdiscs.

## When to use this

- You manage a firewall from a config file rather than a sequence
  of shell commands. The "load on boot, reconcile on file change"
  loop wants a deterministic diff that doesn't churn unnecessarily.
- You need **atomic apply** so other readers never observe a
  partially-applied ruleset (firewall in an inconsistent state
  during a multi-rule update is a security incident).
- You're writing a Kubernetes-shaped operator (`CustomResource → kernel state`)
  where the controller pattern needs a clean diff/apply primitive.

Don't use it when:

- One-off rule mutations from CLI tools — the imperative
  [`Connection::<Nftables>::{add_table, add_chain, add_rule}`](../../crates/nlink/src/netlink/nftables/connection.rs)
  methods are simpler.
- You need full nftables expressiveness with maps, named counters,
  or quota objects — 0.16 covers tables, chains, rules, and
  flowtables; sets/maps land in a follow-up.

## Permissions

Like every nftables operation: **CAP_NET_ADMIN** in the relevant
network namespace. Most production code runs the apply step as
root or with the capability granted via
`setcap cap_net_admin=ep`. `Error::is_permission_denied()`
detects EPERM cleanly.

## High-level shape

```rust,no_run
use nlink::{Connection, Nftables};
use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{Family, Hook, Policy, Priority};

# async fn run() -> nlink::Result<()> {
let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| {
    t.chain("input", |c| {
        c.hook(Hook::Input)
            .priority(Priority::Filter)
            .policy(Policy::Drop)
    })
    .chain("output", |c| {
        c.hook(Hook::Output)
            .priority(Priority::Filter)
            .policy(Policy::Accept)
    })
});

let conn = Connection::<Nftables>::new()?;

// 1. Compute the diff against current kernel state.
let diff = cfg.diff(&conn).await?;
tracing::info!("{}", diff.summary());

// 2. Apply atomically — single NFNL_MSG_BATCH_BEGIN ... BATCH_END
//    commit. Kernel either accepts the whole batch or rolls back.
let applied = diff.apply(&conn).await?;
tracing::info!(changes = applied, "ruleset converged");
# Ok(())
# }
```

The `summary()` output gives a human-readable change list — wire
it to `tracing::info!` so operators see what's about to happen:

```text
NftablesDiff: 3 changes:
  + table Inet filter
  + chain Inet filter/input
  + chain Inet filter/output
```

## Idempotent re-apply

The whole point of declarative is "re-applying the same config is
free." Verify with a unit test in your downstream code:

```rust,no_run
# use nlink::{Connection, Nftables};
# use nlink::netlink::nftables::config::NftablesConfig;
# async fn run(cfg: NftablesConfig, conn: &Connection<Nftables>) -> nlink::Result<()> {
let first = cfg.diff(conn).await?;
first.apply(conn).await?;

let second = cfg.diff(conn).await?;
assert!(second.is_empty(), "second diff should be no-op");
# Ok(())
# }
```

For tables/chains/flowtables this works out of the box —
name-based identity is stable. **Rules are a known exception** —
see the next section.

## Rule identity caveat (0.16)

The 0.16 diff uses **name-based identity** for tables, chains,
and flowtables, and **always re-applies declared rules** without
removing extras. Why: full rule-equivalence diffing requires
canonicalizing the typed `Rule` (Plan 157 §4.3) — the kernel may
re-emit rules with different attribute orderings or compat
attributes (`NFTA_RULE_COMPAT` on rules originally created via
`iptables-nft`), so a naive byte-compare produces false-positive
replaces. The canonicalization layer needs a refactor of the
`Rule` type's match-collection representation that's deferred to
the next release cycle.

Practical implications for **0.16**:

- Re-applying a config that contains rules adds those rules again
  on every apply (the kernel doesn't enforce dedup). To avoid
  accumulating duplicates, **flush the table before re-applying**
  in the reconcile loop:

  ```rust,no_run
  # use nlink::{Connection, Nftables};
  # use nlink::netlink::nftables::config::NftablesConfig;
  # use nlink::netlink::nftables::types::Family;
  # async fn run(cfg: NftablesConfig, conn: &Connection<Nftables>) -> nlink::Result<()> {
  // Recipe pattern: bracket apply with a flush so the post-state
  // is fully determined by the config (no leftover state from
  // earlier applies).
  let _ = conn.del_table("filter", Family::Inet).await; // ignore "not found"
  let diff = cfg.diff(conn).await?;
  diff.apply(conn).await?;
  # Ok(())
  # }
  ```

  This trades atomicity (delete and apply are two transactions)
  for simplicity. For sites that need true atomicity on every
  reapply, wait for the canonicalization landing in 0.17 — or
  drop into the raw `Transaction` API and bundle the delete +
  re-add by hand.

- Operator-pattern users (Kubernetes controllers) typically have
  the same loop already — the controller-runtime "delete + create
  on diff" pattern is well-understood.

## `apply_reconcile` — retry on conflict

When multiple processes mutate nftables concurrently (think:
systemd-resolved adding stub-resolver rules while your operator
applies its ruleset), the kernel returns EBUSY for the loser.
`apply_reconcile` retries with exponential backoff:

```rust,no_run
use nlink::netlink::nftables::config::ReconcileOptions;
use std::time::Duration;
# use nlink::netlink::nftables::config::{NftablesConfig, NftablesDiff};
# use nlink::{Connection, Nftables};
# async fn run(diff: NftablesDiff, conn: &Connection<Nftables>) -> nlink::Result<()> {
let opts = ReconcileOptions {
    max_retries: 5,
    backoff: Duration::from_millis(50),
};
let report = diff.apply_reconcile(conn, opts).await?;
if report.attempts > 1 {
    tracing::warn!(
        retries = report.attempts - 1,
        "concurrent nftables mutator detected; retried successfully",
    );
}
# Ok(())
# }
```

`ReconcileOptions::default()` is `max_retries: 3, backoff: 100ms`.
Non-transient errors (permission denied, invalid argument, etc.)
surface immediately without retry — the predicate is
`Error::is_busy() || Error::is_try_again()`.

## Loading from a config file

The declarative types are pure data — derive `Serialize` /
`Deserialize` in your downstream crate to get TOML/YAML/JSON
support for free. nlink doesn't bundle a serde feature in 0.16
because adding the dep to the lib crate would force every
downstream user to compile it; doing the derives in your own
binary keeps nlink lean.

Sketch (downstream):

```rust,ignore
// In your binary's crate, wrap the nlink type with serde derives.
#[derive(serde::Deserialize)]
struct FirewallConfig {
    // ... your own schema fields ...
}

impl FirewallConfig {
    fn into_nftables(self) -> NftablesConfig {
        NftablesConfig::new().table(
            &self.table_name,
            Family::Inet,
            |t| { /* ... map your schema to the builder ... */ },
        )
    }
}
```

Pair with [`notify`](https://docs.rs/notify) for file-watch and
the apply loop becomes:

```text
config file changes
  → reload TOML
  → cfg.diff(&conn).await?
  → diff.apply_reconcile(&conn, opts).await?
```

## What else lives where

- **Imperative ad-hoc mutations**:
  [`Connection::<Nftables>::{add_table, add_chain, add_rule}`](../../crates/nlink/src/netlink/nftables/connection.rs)
  for one-off changes.
- **Atomic multi-op batches without the diff layer**:
  [`Connection::<Nftables>::transaction()`](../../crates/nlink/src/netlink/nftables/connection.rs)
  gives you the raw `NFNL_MSG_BATCH_*` plumbing — that's what
  `NftablesDiff::apply` uses under the hood.
- **Event-driven reaction to other tools mutating nftables**:
  [`Connection::<Nftables>::subscribe`](../../crates/nlink/src/netlink/nftables/connection.rs)
  + `events()` (Plan 150 §9.2) — the `NftablesEvent::NewRule` /
  `DelRule` / etc. variants are how you detect external drift
  to trigger an immediate reconcile.
- **Stateful firewall recipe** (the imperative companion):
  [`nftables-stateful-fw.md`](nftables-stateful-fw.md) — same
  shape ruleset but built via the `Transaction` API for the
  one-shot case.

## See also

- Plan 157 ([`plans/157-0.16-nftables-declarative-config-plan.md`](../../plans/157-0.16-nftables-declarative-config-plan.md))
  — design rationale + the per-phase status, including why
  canonicalization is deferred.
- [`crates/nlink/src/netlink/nftables/config/`](../../crates/nlink/src/netlink/nftables/config/) —
  source of `NftablesConfig`, `NftablesDiff`, the diff algorithm,
  and `apply_reconcile`.
- Kernel docs: `Documentation/networking/nf_tables.rst` and
  `man 8 nft`.
