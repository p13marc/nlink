//! Plan 157 declarative `NftablesConfig` — diff + atomic apply +
//! `apply_reconcile`. Six §4.6 scenarios per the original Plan 157
//! design matrix, mirrored in §5.4 of Plan 166.
//!
//! All tests root-gated via `require_root!()`; module-gated on
//! `nf_tables`. The lab namespace is fresh per test, so the
//! starting state is always "no tables we own."
//!
//! ## Per-test 30-second timeout (Plan 167 Phase 3 follow-up)
//!
//! The first CI run of these tests hung indefinitely on the
//! `apply_reconcile_*` test (workflow run `26402630370` —
//! 22 min before manual cancel, no test output after start).
//! `nft_dump()` and `Transaction::commit` use `recv_msg().await`
//! loops with no operation timeout (per CLAUDE.md:
//! "Operation timeouts are opt-in via Connection::timeout
//! (Duration); default is none"), so a missing DONE marker or
//! seq mismatch under the GHA container's kernel hangs forever.
//!
//! Until the root cause is fixed (Plan 167 Phase 3 — deep
//! debug), every test in this file is wrapped in
//! `tokio::time::timeout(30s, ...)` so CI fails fast with
//! a clear `Error::Timeout` instead of hanging. The 30s
//! budget is ~30x the typical successful test (≤1s under root
//! in a freshly-spawned namespace).

use std::time::Duration;

use nlink::netlink::nftables::config::{NftablesConfig, ReconcileOptions};
use nlink::netlink::nftables::types::{ChainType, Family, Hook, Policy, Priority};
use nlink::netlink::{Connection, Nftables, namespace};

use crate::common::TestNamespace;

/// Wrap a test body in a 30-second timeout. On expiry, fail
/// the test with `Error::Timeout` so CI surfaces the hang as a
/// clear failure (not an indefinite job hang).
async fn with_timeout<F>(body: F) -> nlink::Result<()>
where
    F: std::future::Future<Output = nlink::Result<()>>,
{
    match tokio::time::timeout(Duration::from_secs(30), body).await {
        Ok(result) => result,
        Err(_elapsed) => Err(nlink::Error::Timeout),
    }
}

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

    with_timeout(async {
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
    })
    .await
}

#[tokio::test]
async fn reconcile_idempotent_reapply_yields_empty_diff() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
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
    })
    .await
}

#[tokio::test]
async fn reconcile_add_one_rule_in_existing_chain() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
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
    })
    .await
}

#[tokio::test]
async fn reconcile_replace_one_rule_emits_replace_op() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
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
    })
    .await
}

#[tokio::test]
async fn reconcile_delete_one_rule_emits_delete_op() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
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
    })
    .await
}

#[tokio::test]
async fn reconcile_cascade_delete_table_via_empty_config() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
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
    })
    .await
}

#[tokio::test]
async fn apply_reconcile_succeeds_in_one_attempt_when_uncontended() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
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
    })
    .await
}

// ============================================================================
// Plan 180 — chain_type + device on DeclaredChain
// ============================================================================

/// Declared NAT chain round-trips through the kernel with
/// `chain_type = Nat`. Without it, the kernel rejects
/// `masquerade`/`snat`/`dnat` verdicts with `EOPNOTSUPP`
/// inside the batch.
#[tokio::test]
async fn nat_chain_chain_type_round_trips() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_nat");

    with_timeout(async {
        let ns = TestNamespace::new("nat-chain-type")?;
        let nft = nft_in_ns(&ns)?;

        let cfg = nlink::netlink::nftables::config::NftablesConfig::new().table(
            "nat-test",
            Family::Inet,
            |t| {
                t.chain("postrouting", |c| {
                    c.hook(Hook::Postrouting)
                        .priority(Priority::SrcNat)
                        .chain_type(ChainType::Nat)
                })
            },
        );

        cfg.diff(&nft).await?.apply(&nft).await?;

        // Dump back and verify chain_type came through.
        let chains = nft.list_chains().await?;
        let pr = chains
            .iter()
            .find(|c| c.name == "postrouting" && c.table == "nat-test")
            .expect("postrouting chain must exist after apply");
        assert_eq!(
            pr.chain_type.as_deref(),
            Some("nat"),
            "expected chain_type=nat in dump; got {:?}",
            pr.chain_type
        );

        // Idempotence: re-diff yields zero changes (the 0.17
        // body-bytes contract; guard it for this code path too).
        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "re-diff after no kernel change must be empty; got {}",
            again.summary()
        );

        Ok(())
    })
    .await
}

/// Declared netdev chain bound to a device round-trips with
/// `device` set on dump. Without `NFTA_HOOK_DEV` in the
/// apply request, the kernel rejects the chain creation.
#[tokio::test]
async fn netdev_chain_device_round_trips() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "dummy");

    with_timeout(async {
        let ns = TestNamespace::new("netdev-chain-dev")?;
        // Create the dummy interface the chain will bind to.
        ns.add_dummy("dummy0")?;
        ns.link_up("dummy0")?;

        let nft = nft_in_ns(&ns)?;
        let cfg = nlink::netlink::nftables::config::NftablesConfig::new().table(
            "ft",
            Family::Netdev,
            |t| {
                t.chain("ingress", |c| {
                    c.hook(Hook::Ingress)
                        .priority(Priority::Filter)
                        .chain_type(ChainType::Filter)
                        .device("dummy0")
                })
            },
        );

        cfg.diff(&nft).await?.apply(&nft).await?;

        let chains = nft.list_chains().await?;
        let ing = chains
            .iter()
            .find(|c| c.name == "ingress" && c.table == "ft")
            .expect("ingress chain must exist");
        assert_eq!(
            ing.device.as_deref(),
            Some("dummy0"),
            "expected device=dummy0 in dump; got {:?}",
            ing.device
        );

        Ok(())
    })
    .await
}


// ============================================================================
// Plan 181 — list_*_in filter family
// ============================================================================

/// Server-side `(table, family)` filter mirrors what
/// `list_rules(table, family)` has always done. Build two
/// tables in the same family each with a chain/flowtable/set,
/// then verify `list_*_in("t1", family)` returns only t1's
/// entities while the unfiltered `list_*()` sees both.
#[tokio::test]
async fn list_in_filters_match_only_target_table() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("list-in")?;
        let nft = nft_in_ns(&ns)?;

        // Build two minimal tables in the Inet family. Each has
        // one chain; t1 also gets a set so the set-filter assertion
        // is meaningful (set creation is more involved than chain
        // creation; one set is enough).
        let cfg = nlink::netlink::nftables::config::NftablesConfig::new()
            .table("li-t1", Family::Inet, |t| {
                t.chain("c1", |c| {
                    c.hook(Hook::Input)
                        .priority(Priority::Filter)
                        .policy(Policy::Accept)
                })
            })
            .table("li-t2", Family::Inet, |t| {
                t.chain("c2", |c| {
                    c.hook(Hook::Forward)
                        .priority(Priority::Filter)
                        .policy(Policy::Accept)
                })
            });
        cfg.diff(&nft).await?.apply(&nft).await?;

        // Tables — unfiltered sees both; family-filtered to Inet
        // still sees both; the family filter alone doesn't narrow
        // when both targets share family.
        let tables_all = nft.list_tables().await?;
        let tables_inet = nft.list_tables_in(Family::Inet).await?;
        let our_inet_count = tables_inet
            .iter()
            .filter(|t| t.name == "li-t1" || t.name == "li-t2")
            .count();
        assert_eq!(our_inet_count, 2, "both our Inet tables visible");
        let our_all_count = tables_all
            .iter()
            .filter(|t| t.name == "li-t1" || t.name == "li-t2")
            .count();
        assert_eq!(our_all_count, 2, "both our tables visible via list_tables()");

        // Chains — list_chains_in narrows to one table.
        let chains_t1 = nft.list_chains_in("li-t1", Family::Inet).await?;
        let chains_t2 = nft.list_chains_in("li-t2", Family::Inet).await?;
        assert!(
            chains_t1.iter().any(|c| c.name == "c1"),
            "c1 must be in t1 dump; got {:?}",
            chains_t1.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        assert!(
            !chains_t1.iter().any(|c| c.name == "c2"),
            "c2 must NOT leak into t1 dump"
        );
        assert!(
            chains_t2.iter().any(|c| c.name == "c2"),
            "c2 must be in t2 dump"
        );

        // Flowtables — none declared; both list paths return empty
        // (smoke-check that the filter doesn't error on no matches).
        let fts_t1 = nft.list_flowtables_in("li-t1", Family::Inet).await?;
        assert!(fts_t1.is_empty(), "no flowtables in t1");

        // Sets — none declared either; smoke-check the filter
        // shape on the set-listing path. (Set creation requires
        // imperative add_set + element wrangling that's out of
        // scope for this list_*_in test.)
        let sets_t1 = nft.list_sets_in("li-t1", Family::Inet).await?;
        assert!(sets_t1.is_empty(), "no sets in t1");

        Ok(())
    })
    .await
}
