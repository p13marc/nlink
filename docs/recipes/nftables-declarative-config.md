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
// 0.19: NftablesDiff implements Display directly; .summary() was
// deprecated in Plan 188 §2.6 in favor of the Display impl.
tracing::info!("{}", diff);

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

## Rule identity (Plan 157b v2)

Each rule that participates in reconciliation needs a stable
identity key — same shape as `LinkConfig::name` or
`RouteConfig::destination` in the existing `NetworkConfig`. Use
`.rule_keyed("chain", "your-key", |r| ...)` instead of `.rule(...)`:

```rust,no_run
use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{Family, Hook, Policy};

let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| {
    t.chain("input", |c| c.hook(Hook::Input).policy(Policy::Drop))
        .rule_keyed("input", "ssh-allow", |r| r.match_tcp_dport(22).accept())
        .rule_keyed("input", "icmp-allow", |r| r.match_l4proto(1 /* IPPROTO_ICMP */).accept())
});
```

Under the hood: the `handle_key` is encoded as
`NFTA_RULE_USERDATA` (libnftnl-compatible TLV — shows up as
`comment "nlink:ssh-allow"` in `nft list ruleset` output), so the
kernel round-trips it across dumps. The diff:

- Matches declared rules to kernel rules by key.
- For matched pairs: byte-compares the expression list. Differ →
  in-place `replace_rule` (atomic kernel-side update at the
  rule's handle; preserves position; no flush).
- Declared key with no kernel match → add.
- Kernel rule with our `nlink:<key>` prefix but not in declared
  → delete (it's ours; it shouldn't be there).
- Kernel rule without an `nlink:` prefix → left alone (foreign
  rule from `iptables-nft`, hand-edited via `nft -f`, etc.).

```rust,no_run
# use nlink::{Connection, Nftables};
# use nlink::netlink::nftables::config::NftablesConfig;
# async fn run(cfg: NftablesConfig, conn: &Connection<Nftables>) -> nlink::Result<()> {
// Idempotent re-apply: second diff is empty.
cfg.diff(conn).await?.apply(conn).await?;
let second_diff = cfg.diff(conn).await?;
assert!(second_diff.is_empty()); // no-op
# Ok(())
# }
```

### Anonymous rules (no key) — documented limitation

Rules declared with bare `.rule(...)` (no `handle_key`) have no
identity for the diff. The library treats them as "always add"
and emits a `tracing::warn!` so operators notice. Documented
trade-off; same shape as a `LinkConfig` without a name would be
in `NetworkConfig` — pathological.

If your config has any rule you want to reconcile across
applies, use `.rule_keyed(...)`. Operators typically derive
keys from their config schema:
`service-foo/ingress/allow`, `firewall-rule-3142`, etc.

### Foreign rules are preserved

Rules in your chains created by other tools (no `nlink:` prefix
on their comment, or no comment at all) are left alone by the
diff. The library only deletes what it owns. If you want a clean
chain (drop everything not declared), use the imperative
`conn.del_chain(...)` first.

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

### From the CLI — `nft reconcile` / `nft diff`

The in-tree `nft` binary demonstrates the whole loop. `nft
reconcile <file>` reads a *desired-state* ruleset (the same `add
table` / `add chain` / `add rule` grammar as `nft apply`, but
interpreted as "what should exist"), folds it into an
`NftablesConfig`, diffs it against the live ruleset, and applies
the minimal change set via `apply_reconcile`. `nft diff <file>`
is the read-only preview.

```text
# fw.nft — desired state
add table inet filter
add chain inet filter input hook input priority 0 policy drop
add rule inet filter input tcp dport 22 accept

$ nft diff fw.nft        # preview
$ nft reconcile fw.nft   # apply the minimal delta
```

Because it is desired-state, `delete` / `flush` lines are rejected —
removal is inferred from the diff. (`nft apply` remains the
imperative, single-transaction path.) See `bins/nft/src/main.rs`
`parse_ruleset`.

### From your own crate

The nft rule body is a low-level expression VM (`Vec<Expr>` with
raw byte payloads), so it is *not* serde-deserializable — a
human-facing ruleset is always lowered into `Rule` through the
builders (that's what `parse_ruleset` does). To load from
TOML/YAML/JSON, define your own schema and map it onto the
builder:

```rust,ignore
// In your crate, wrap a serde schema that lowers into NftablesConfig.
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

(The *interface*-side `NetworkConfig` is different: with the
`serde` feature it deserializes directly — its fields are typed
values, not an expression VM. See the
[library guide](../library.md#declarative-network-configuration).)

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

- `CHANGELOG.md ## [0.16.0]` (declarative-config + USERDATA-keyed
  reconciliation sections) — design rationale, including why
  canonicalization was redesigned to comment-tagging
  (matches kube-proxy / Google nftables / libnftnl precedent).
- [`crates/nlink/src/netlink/nftables/config/`](../../crates/nlink/src/netlink/nftables/config/) —
  source of `NftablesConfig`, `NftablesDiff`, the diff algorithm,
  and `apply_reconcile`.
- Kernel docs: `Documentation/networking/nf_tables.rst` and
  `man 8 nft`.
