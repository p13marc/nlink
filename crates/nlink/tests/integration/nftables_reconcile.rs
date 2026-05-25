//! Plan 157 declarative `NftablesConfig` — diff + atomic apply +
//! `apply_reconcile`. Six §4.6 scenarios per the original Plan 157
//! design matrix, mirrored in §5.4 of Plan 166.
//!
//! All tests root-gated via `require_root!()`; module-gated on
//! `nf_tables`. The lab namespace is fresh per test, so the
//! starting state is always "no tables we own."

use nlink::netlink::nftables::config::{NftablesConfig, ReconcileOptions};
use nlink::netlink::nftables::types::{Family, Hook, Policy, Priority};
use nlink::netlink::{Connection, Nftables, namespace};

use crate::common::TestNamespace;

fn nft_in_ns(ns: &TestNamespace) -> nlink::Result<Connection<Nftables>> {
    namespace::connection_for(ns.name())
}

/// Build a canonical "filter / input" config with N keyed rules.
fn cfg_with_n_rules(n: usize) -> NftablesConfig {
    NftablesConfig::new().table("filter_rec", Family::Inet, |mut t| {
        t = t.chain("input", |c| {
            c.hook(Hook::Input)
                .priority(Priority::Filter)
                .policy(Policy::Drop)
        });
        for i in 0..n {
            let port = 1000 + i as u16;
            t = t.rule_keyed("input", format!("k{i}"), move |r| {
                r.match_tcp_dport(port).accept()
            });
        }
        t
    })
}

#[tokio::test]
async fn reconcile_empty_to_full_applies_everything() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("rec-empty-to-full")?;
    let nft = nft_in_ns(&ns)?;

    let cfg = cfg_with_n_rules(3);
    let diff = cfg.diff(&nft).await?;
    assert_eq!(diff.tables_to_add.len(), 1, "one new table");
    assert_eq!(diff.chains_to_add.len(), 1, "one new chain");
    assert_eq!(diff.rules_to_add.len(), 3, "three new rules");

    let applied = diff.apply(&nft).await?;
    assert!(applied >= 5, "apply count should cover table+chain+rules");
    Ok(())
}

#[tokio::test]
async fn reconcile_idempotent_reapply_yields_empty_diff() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("rec-idempotent")?;
    let nft = nft_in_ns(&ns)?;

    let cfg = cfg_with_n_rules(2);
    cfg.diff(&nft).await?.apply(&nft).await?;

    let again = cfg.diff(&nft).await?;
    assert!(
        again.is_empty(),
        "second diff after no kernel state change must be empty; got {}",
        again.summary()
    );
    Ok(())
}

#[tokio::test]
async fn reconcile_add_one_rule_in_existing_chain() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("rec-add-rule")?;
    let nft = nft_in_ns(&ns)?;

    cfg_with_n_rules(1).diff(&nft).await?.apply(&nft).await?;
    let bigger = cfg_with_n_rules(2);
    let diff = bigger.diff(&nft).await?;
    assert_eq!(diff.tables_to_add.len(), 0, "table already present");
    assert_eq!(diff.chains_to_add.len(), 0, "chain already present");
    assert_eq!(diff.rules_to_add.len(), 1, "only the new rule should be added");
    diff.apply(&nft).await?;
    Ok(())
}

#[tokio::test]
async fn reconcile_replace_one_rule_emits_replace_op() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("rec-replace")?;
    let nft = nft_in_ns(&ns)?;

    cfg_with_n_rules(2).diff(&nft).await?.apply(&nft).await?;

    // Same keys, different port for "k0".
    let mutated = NftablesConfig::new().table("filter_rec", Family::Inet, |t| {
        t.chain("input", |c| {
            c.hook(Hook::Input)
                .priority(Priority::Filter)
                .policy(Policy::Drop)
        })
        .rule_keyed("input", "k0", |r| r.match_tcp_dport(9000).accept())
        .rule_keyed("input", "k1", |r| r.match_tcp_dport(1001).accept())
    });

    let diff = mutated.diff(&nft).await?;
    assert_eq!(
        diff.rules_to_replace.len(),
        1,
        "one rule changed — should be a single in-place replace"
    );
    assert!(diff.rules_to_add.is_empty(), "no new rules expected");
    diff.apply(&nft).await?;
    Ok(())
}

#[tokio::test]
async fn reconcile_delete_one_rule_emits_delete_op() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("rec-del-rule")?;
    let nft = nft_in_ns(&ns)?;

    cfg_with_n_rules(2).diff(&nft).await?.apply(&nft).await?;

    let smaller = cfg_with_n_rules(1);
    let diff = smaller.diff(&nft).await?;
    assert_eq!(
        diff.rules_to_delete.len(),
        1,
        "one rule absent from desired state → one delete"
    );
    diff.apply(&nft).await?;
    Ok(())
}

#[tokio::test]
async fn reconcile_cascade_delete_table_via_empty_config() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("rec-cascade")?;
    let nft = nft_in_ns(&ns)?;

    cfg_with_n_rules(2).diff(&nft).await?.apply(&nft).await?;

    // Empty config → diff must propose deleting the table we own.
    let teardown = NftablesConfig::new();
    let diff = teardown.diff(&nft).await?;
    assert_eq!(
        diff.tables_to_delete.len(),
        1,
        "empty config must propose dropping our own table"
    );
    diff.apply(&nft).await?;
    Ok(())
}

#[tokio::test]
async fn apply_reconcile_succeeds_in_one_attempt_when_uncontended() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("rec-reconcile-once")?;
    let nft = nft_in_ns(&ns)?;

    let cfg = cfg_with_n_rules(2);
    let diff = cfg.diff(&nft).await?;
    let report = diff
        .apply_reconcile(&nft, ReconcileOptions::default())
        .await?;
    assert_eq!(report.attempts, 1, "no contention → single attempt");
    assert!(report.change_count >= 4, "expected table+chain+2 rules");
    Ok(())
}
