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
//! **That root cause was #199, fixed in 0.25.0**: `Transaction`
//! numbered its inner messages from its own counter starting at
//! 1, unrelated to the socket's, so `send_batch`'s seq filter
//! discarded the kernel's mid-batch NLMSGERR and then waited
//! forever for a BATCH_END ACK the aborted batch never sent.
//! The 30-second wrapper stays as a belt-and-braces guard so a
//! future regression of the same shape fails fast instead of
//! burning a CI job. The budget is ~30x the typical successful
//! test (≤1s under root in a freshly-spawned namespace).

use std::time::Duration;

use nlink::netlink::nftables::config::{NftDiffOptions, NftablesConfig, ReconcileOptions};
use nlink::netlink::nftables::types::{ChainType, Family, Hook, Policy, Priority, SetKeyType};
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
            again
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

/// Teardown-by-empty-config, which since #190 requires opting into purge.
///
/// `diff()` no longer proposes any table deletion — it could not tell our
/// table from Docker's, and deleting a table cascades to everything inside it.
/// `diff_with_options(.., purge_tables(true))` is the explicit opt-in.
#[tokio::test]
async fn reconcile_cascade_delete_table_via_empty_config() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-cascade")?;
        let nft = nft_in_ns(&ns)?;

        cfg_with_n_rules(2).diff(&nft).await?.apply(&nft).await?;

        // Without the opt-in, an empty config is a no-op on tables.
        let teardown = NftablesConfig::new();
        assert!(
            teardown.diff(&nft).await?.tables_to_delete.is_empty(),
            "plain diff() must never propose a table deletion (#190)"
        );

        // With it, the table we own is dropped.
        let diff = teardown
            .diff_with_options(&nft, &NftDiffOptions::default().purge_tables(true))
            .await?;
        assert_eq!(
            diff.tables_to_delete.len(),
            1,
            "purge_tables(true) must propose dropping the table"
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
            pr.chain_type,
            Some(ChainType::Nat),
            "expected chain_type=Nat in dump; got {:?}",
            pr.chain_type
        );

        // Idempotence: re-diff yields zero changes (the 0.17
        // body-bytes contract; guard it for this code path too).
        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "re-diff after no kernel change must be empty; got {}",
            again
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
                    c.hook(Hook::NetdevIngress)
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

/// Plan 185 — driving the wrapper end-to-end through a real
/// `ENOBUFS` overflow. Shrinks the multicast subscriber's
/// `SO_RCVBUF` to a tiny value, opens a second mutator
/// connection that floods the kernel with rule add/delete in a
/// tight loop, then drains the resync stream slowly. The wrapper
/// must observe the ENOBUFS, invoke the factory, walk the
/// snapshot, and emit
/// `Marker(ResyncStart) → Resynced(...) → Marker(ResyncEnd)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn into_events_with_resync_recovers_from_enobufs() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    use std::sync::Arc;

    use nlink::netlink::nftables::NftablesEvent;
    use nlink::netlink::resync::{ConnectionFactory, ResyncMarker, ResyncedEvent};
    use tokio_stream::StreamExt;

    with_timeout(async {
        let ns = TestNamespace::new("nft-resync")?;
        let ns_name = ns.name().to_string();

        // Seed config: one table + one chain. The rules we churn
        // through during the flood live in this chain.
        let cfg = NftablesConfig::new().table("flood", Family::Inet, |t| {
            t.chain("input", |c| {
                c.hook(Hook::Input)
                    .priority(Priority::Filter)
                    .policy(Policy::Accept)
            })
        });
        let seed = nft_in_ns(&ns)?;
        cfg.diff(&seed).await?.apply(&seed).await?;
        drop(seed);

        // Subscriber connection — set a tiny rcvbuf via the
        // SO_RCVBUFFORCE helper landed in this same plan, so the
        // flood overflows it in a handful of mutations rather
        // than minutes.
        let event_conn = nft_in_ns(&ns)?;
        event_conn.socket().set_rcvbuf(256)?;

        // Factory: open fresh Nftables connections inside the
        // same namespace for the resync snapshot dump.
        let factory: ConnectionFactory<Nftables> = {
            let ns_name = ns_name.clone();
            Arc::new(move || {
                let ns_name = ns_name.clone();
                Box::pin(async move { namespace::connection_for(&ns_name) })
            })
        };

        let mut stream = event_conn.into_events_with_resync(factory).await?;

        // Mutator task: tight rule add/delete loop. Runs until
        // we cancel via the abort handle. Uses get_rule + handle
        // tracking via the integration test's existing churn
        // pattern.
        let mut_ns = ns_name.clone();
        let mutator = tokio::spawn(async move {
            let nft = namespace::connection_for::<Nftables>(&mut_ns)?;
            for i in 0..2_000u32 {
                use nlink::netlink::nftables::Rule;
                let rule = Rule::new("flood", "input")
                    .family(Family::Inet)
                    .accept()
                    .comment(&format!("r{i}"));
                let _ = nft.add_rule(rule).await;
                // No delete — we want the kernel to emit more
                // mcast events than the subscriber drains. The
                // table is torn down with the netns at test exit.
            }
            Ok::<_, nlink::Error>(())
        });

        // Drain the stream slowly. Look for the resync marker
        // sequence. Bail after a generous deadline so a
        // mis-behaving kernel doesn't hang the suite.
        let mut saw_start = false;
        let mut snapshot_count = 0usize;
        let mut saw_end = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);

        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                item = stream.next() => {
                    let Some(item) = item else { break };
                    match item? {
                        ResyncedEvent::Marker(ResyncMarker::ResyncStart) => {
                            saw_start = true;
                        }
                        ResyncedEvent::Resynced(ev) => {
                            assert!(
                                saw_start,
                                "Resynced item before ResyncStart marker"
                            );
                            snapshot_count += 1;
                            // The snapshot must contain our seed
                            // table + chain.
                            match ev {
                                NftablesEvent::NewTable(t) => {
                                    assert_eq!(t.name, "flood");
                                }
                                NftablesEvent::NewChain(_)
                                | NftablesEvent::NewRule(_)
                                | NftablesEvent::NewFlowtable(_)
                                | NftablesEvent::NewSet(_) => {}
                                other => panic!(
                                    "snapshot must emit only New* variants; got {other:?}"
                                ),
                            }
                        }
                        ResyncedEvent::Marker(ResyncMarker::ResyncEnd) => {
                            assert!(saw_start, "ResyncEnd before ResyncStart");
                            saw_end = true;
                            break;
                        }
                        ResyncedEvent::Event(_) => {
                            // Live event; ignored — we're chasing
                            // the resync sequence.
                        }
                        _ => {}
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    // Slow consumer — gives the mutator room to
                    // flood the subscriber's tiny rcvbuf.
                }
            }
            // Throttle the consumer so the mutator gets ahead.
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        mutator.abort();

        assert!(saw_start, "wrapper must emit ResyncMarker::ResyncStart on ENOBUFS");
        assert!(saw_end, "wrapper must emit ResyncMarker::ResyncEnd after snapshot");
        assert!(
            snapshot_count >= 2,
            "snapshot must include at least the seed table + chain; got {snapshot_count}"
        );

        Ok(())
    })
    .await
}

/// Plan 185 — `into_events_with_resync` walks the ruleset
/// snapshot via a fresh `Connection<Nftables>` from the factory
/// and yields the snapshot as `Resynced(...)` items between
/// `ResyncStart` / `ResyncEnd` markers when the multicast stream
/// reports `ENOBUFS`.
///
/// Driving an actual ENOBUFS in CI is flaky (it requires
/// outpacing the kernel's send buffer), so this test asserts the
/// *snapshot* shape end-to-end: build a ruleset, point the
/// factory at a freshly-constructed connection, and verify the
/// snapshot enumerates every table/chain/set we declared. The
/// state-machine logic itself is exercised by the lib's
/// `events_with_resync` unit tests + the Plan 151 recipe.
#[tokio::test]
async fn nftables_snapshot_walks_ruleset() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("nft-snap")?;
        let nft = nft_in_ns(&ns)?;

        // Build a 2-table ruleset so the snapshot has something
        // structural to enumerate.
        let cfg = NftablesConfig::new()
            .table("snap-t1", Family::Inet, |t| {
                t.chain("input", |c| {
                    c.hook(Hook::Input)
                        .priority(Priority::Filter)
                        .policy(Policy::Accept)
                })
            })
            .table("snap-t2", Family::Inet, |t| {
                t.chain("fwd", |c| {
                    c.hook(Hook::Forward)
                        .priority(Priority::Filter)
                        .policy(Policy::Accept)
                })
            });
        cfg.diff(&nft).await?.apply(&nft).await?;

        // Build the snapshot directly (skips the multicast
        // subscribe path). The factory pattern is what
        // into_events_with_resync would use internally.
        let snapshot =
            nlink::netlink::nftables::resync::nftables_snapshot(&nft).await?;

        use nlink::netlink::nftables::NftablesEvent;
        let mut tables: Vec<&str> = snapshot
            .iter()
            .filter_map(|e| match e {
                NftablesEvent::NewTable(t)
                    if t.name == "snap-t1" || t.name == "snap-t2" =>
                {
                    Some(t.name.as_str())
                }
                _ => None,
            })
            .collect();
        tables.sort();
        assert_eq!(
            tables,
            vec!["snap-t1", "snap-t2"],
            "snapshot must enumerate every declared table"
        );

        let mut chains: Vec<&str> = snapshot
            .iter()
            .filter_map(|e| match e {
                NftablesEvent::NewChain(c)
                    if c.table == "snap-t1" || c.table == "snap-t2" =>
                {
                    Some(c.name.as_str())
                }
                _ => None,
            })
            .collect();
        chains.sort();
        assert_eq!(
            chains,
            vec!["fwd", "input"],
            "snapshot must enumerate every declared chain"
        );

        Ok(())
    })
    .await
}

// ============================================================================
// Rule::{dnat,snat}_v6 — kernel acceptance + exact wire round-trip
// ============================================================================

/// An `ip6` DNAT rule built with `Rule::dnat_v6` is accepted by the
/// kernel *and* its dumped expression bytes match what nlink rendered.
///
/// The unit tests in `nftables::types` only assert the in-memory expr
/// layout (R0 holds the address, the register is marked in use). They
/// cannot prove the load-bearing claim `dnat_v6` makes about the wire
/// format: that the kernel accepts `Family::Ip6` in the NAT expr with the
/// 16-byte `R0` load. Routing the rule through the declarative diff path
/// gives a far stronger assertion than "expression_bytes is non-empty":
/// after applying, a second `diff` re-renders the declared rule to bytes
/// and byte-compares (normalized) against the kernel's dump. An empty
/// second diff means the kernel stored exactly the expr layout nlink
/// emitted — a register-layout disagreement would either be rejected at
/// apply (`EINVAL`) or surface as a non-empty re-diff.
#[tokio::test]
async fn dnat_v6_rule_round_trips() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_nat");

    with_timeout(async {
        use nlink::netlink::nftables::config::NftablesConfig;
        use std::net::Ipv6Addr;

        let ns = TestNamespace::new("dnat-v6")?;
        let nft = nft_in_ns(&ns)?;

        let target: Ipv6Addr = "fd30::2".parse().unwrap();
        let cfg = NftablesConfig::new().table("nat6", Family::Ip6, |t| {
            t.chain("prerouting", |c| {
                c.hook(Hook::Prerouting)
                    .priority(Priority::DstNat)
                    .chain_type(ChainType::Nat)
            })
            .rule_keyed("prerouting", "dnat-v6", |r| {
                r.match_tcp_dport(80).dnat_v6(target, Some(8080))
            })
        });

        cfg.diff(&nft).await?.apply(&nft).await?;

        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "kernel must store exactly the dnat_v6 expr nlink rendered; \
             re-diff was non-empty: {again}"
        );

        Ok(())
    })
    .await
}

/// The SNAT counterpart to [`dnat_v6_rule_round_trips`]. SNAT and DNAT are
/// distinct kernel verdicts validated against different hooks, so a v6
/// SNAT on a `postrouting`/`SrcNat` chain is a separate acceptance path
/// from DNAT on prerouting — the structural unit test cannot stand in for
/// it. Same diff-idempotency assertion: an empty second diff proves the
/// kernel stored the exact `Family::Ip6` SNAT expr nlink emitted.
#[tokio::test]
async fn snat_v6_rule_round_trips() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_nat");

    with_timeout(async {
        use nlink::netlink::nftables::config::NftablesConfig;
        use std::net::Ipv6Addr;

        let ns = TestNamespace::new("snat-v6")?;
        let nft = nft_in_ns(&ns)?;

        let target: Ipv6Addr = "fd30::1".parse().unwrap();
        let cfg = NftablesConfig::new().table("nat6", Family::Ip6, |t| {
            t.chain("postrouting", |c| {
                c.hook(Hook::Postrouting)
                    .priority(Priority::SrcNat)
                    .chain_type(ChainType::Nat)
            })
            .rule_keyed("postrouting", "snat-v6", |r| {
                r.match_saddr_v6("fd30::100".parse().unwrap(), 128)
                    .snat_v6(target, Some(8080))
            })
        });

        cfg.diff(&nft).await?.apply(&nft).await?;

        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "kernel must store exactly the snat_v6 expr nlink rendered; \
             re-diff was non-empty: {again}"
        );

        Ok(())
    })
    .await
}

/// Address matches in an `inet` chain must round-trip to an empty
/// re-diff (an empty re-diff is byte-equality against the kernel's
/// stored rule). Covers all four legs: v4/v6 × exact (`/32`, `/128`,
/// the nfproto guard) and prefix (`/24`, `/64`, the masked `Bitwise`
/// path); the v4 legs guard against the v4/v6 guard asymmetry.
#[tokio::test]
async fn inet_addr_matches_round_trip() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let ns = TestNamespace::new("inet-addr-rt")?;
        let nft = nft_in_ns(&ns)?;

        let v4: Ipv4Addr = "10.1.2.3".parse().unwrap();
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let cfg = NftablesConfig::new().table("filter_addr", Family::Inet, |t| {
            t.chain("input", |c| {
                c.hook(Hook::Input).priority(Priority::Filter)
            })
            .rule_keyed("input", "v4-exact", |r| r.match_saddr_v4(v4, 32).accept())
            .rule_keyed("input", "v4-prefix", |r| r.match_daddr_v4(v4, 24).accept())
            .rule_keyed("input", "v6-exact", |r| r.match_saddr_v6(v6, 128).accept())
            .rule_keyed("input", "v6-prefix", |r| r.match_daddr_v6(v6, 64).accept())
        });

        cfg.diff(&nft).await?.apply(&nft).await?;

        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "kernel inserts a meta nfproto guard before inet addr matches; \
             nlink must render it too — re-diff was non-empty: {again}"
        );

        Ok(())
    })
    .await
}

/// ICMP/ICMPv6 type matches in an `inet` chain must round-trip. Both
/// protocols are L3-version-specific, so `nft` prepends a `meta nfproto`
/// guard ahead of the `meta l4proto` match — the same asymmetry as the
/// address matchers, on a different matcher family.
#[tokio::test]
async fn inet_icmp_type_matches_round_trip() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("inet-icmp-rt")?;
        let nft = nft_in_ns(&ns)?;

        let cfg = NftablesConfig::new().table("filter_icmp", Family::Inet, |t| {
            t.chain("input", |c| {
                c.hook(Hook::Input).priority(Priority::Filter)
            })
            .rule_keyed("input", "icmp", |r| r.match_icmp_type(8).accept())
            .rule_keyed("input", "icmpv6", |r| r.match_icmpv6_type(128).accept())
        });

        cfg.diff(&nft).await?.apply(&nft).await?;

        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "kernel inserts a meta nfproto guard before inet icmp matches; \
             nlink must render it too — re-diff was non-empty: {again}"
        );

        Ok(())
    })
    .await
}

/// Addr-only SNAT (no port) must round-trip — guards the `NFTA_NAT_FLAGS`
/// derivation for the `MAP_IPS`-only case (flags=1). The snat/dnat
/// round-trip tests cover the addr+port case (flags=3).
#[tokio::test]
async fn snat_v6_addr_only_round_trips() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_nat");
    with_timeout(async {
        use std::net::Ipv6Addr;
        let ns = TestNamespace::new("snat-v6-addr")?;
        let nft = nft_in_ns(&ns)?;
        let target: Ipv6Addr = "fd30::1".parse().unwrap();
        let cfg = NftablesConfig::new().table("n", Family::Ip6, |t| {
            t.chain("post", |c| {
                c.hook(Hook::Postrouting)
                    .priority(Priority::SrcNat)
                    .chain_type(ChainType::Nat)
            })
            .rule_keyed("post", "snat", |r| {
                r.match_saddr_v6("fd30::100".parse().unwrap(), 128)
                    .snat_v6(target, None)
            })
        });
        cfg.diff(&nft).await?.apply(&nft).await?;
        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "addr-only snat must round-trip (flags=MAP_IPS only); \
             re-diff was non-empty: {again}"
        );
        Ok(())
    })
    .await
}

/// Combine all three PR #10 fixes in one rule: a `Family::Inet`
/// postrouting chain with `chain_type=nat`, a prefix-masked source
/// match (`match_saddr_v6(.., 64)` — exercises the `bitwise OP`
/// emit) preceded by the `meta nfproto == ipv6` guard, then `snat_v6`
/// to a single address (exercises NAT MAX-regs + FLAGS=MAP_IPS).
/// All three fixes are load-bearing for the second `diff` to be empty.
#[tokio::test]
async fn inet_snat_with_prefix_source_round_trips() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_nat");
    with_timeout(async {
        use std::net::Ipv6Addr;
        let ns = TestNamespace::new("inet-snat-prefix-src")?;
        let nft = nft_in_ns(&ns)?;
        let src_prefix: Ipv6Addr = "fd30:beef::".parse().unwrap();
        let target: Ipv6Addr = "fd30::1".parse().unwrap();
        let cfg = NftablesConfig::new().table("n", Family::Inet, |t| {
            t.chain("post", |c| {
                c.hook(Hook::Postrouting)
                    .priority(Priority::SrcNat)
                    .chain_type(ChainType::Nat)
            })
            .rule_keyed("post", "snat-prefix", |r| {
                r.match_saddr_v6(src_prefix, 64).snat_v6(target, None)
            })
        });
        cfg.diff(&nft).await?.apply(&nft).await?;
        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "inet-chain prefix-masked-source SNAT must round-trip — \
             requires all three fixes (nfproto guard + bitwise OP + \
             NAT MAX/FLAGS); re-diff was non-empty: {again}"
        );
        Ok(())
    })
    .await
}

// =============================================================================
// Plan 198 — declarative sets + element-level diff
// =============================================================================

/// A `filter_set` table holding an `allowed_v4` IPv4 set with the
/// given element octets (each `(a,b,c,d)`).
fn cfg_with_set(elems: &[(u8, u8, u8, u8)]) -> NftablesConfig {
    let elems: Vec<std::net::Ipv4Addr> = elems
        .iter()
        .map(|(a, b, c, d)| std::net::Ipv4Addr::new(*a, *b, *c, *d))
        .collect();
    NftablesConfig::new().table("filter_set", Family::Inet, move |t| {
        t.set("allowed_v4", move |mut s| {
            s = s.key_type(SetKeyType::Ipv4Addr);
            for ip in &elems {
                s = s.ipv4(*ip);
            }
            s
        })
    })
}

#[tokio::test]
async fn reconcile_empty_to_set_with_elements_applies() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-set-create")?;
        let nft = nft_in_ns(&ns)?;

        let cfg = cfg_with_set(&[(10, 0, 0, 1), (10, 0, 0, 2)]);
        let diff = cfg.diff(&nft).await?;
        assert_eq!(diff.tables_to_add.len(), 1, "one new table");
        assert_eq!(diff.sets_to_add.len(), 1, "one new set");
        // Elements of a brand-new set are installed wholesale.
        assert_eq!(diff.set_elements_to_add.len(), 1, "one element batch");
        assert_eq!(diff.set_elements_to_add[0].3.len(), 2, "two elements");

        diff.apply(&nft).await?;

        // Kernel now reports both elements.
        let kernel = nft
            .list_set_elements("filter_set", "allowed_v4", Family::Inet)
            .await?;
        assert_eq!(kernel.len(), 2, "kernel set must hold both elements");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reconcile_set_idempotent_reapply_is_empty() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-set-idem")?;
        let nft = nft_in_ns(&ns)?;

        let cfg = cfg_with_set(&[(10, 0, 0, 1), (10, 0, 0, 2)]);
        cfg.diff(&nft).await?.apply(&nft).await?;

        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "set + elements must round-trip to an empty diff; got {again}"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reconcile_add_one_set_element() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-set-add-elem")?;
        let nft = nft_in_ns(&ns)?;

        cfg_with_set(&[(10, 0, 0, 1)])
            .diff(&nft)
            .await?
            .apply(&nft)
            .await?;

        // Declare the same set with one extra element.
        let bigger = cfg_with_set(&[(10, 0, 0, 1), (10, 0, 0, 2)]);
        let diff = bigger.diff(&nft).await?;
        assert!(diff.sets_to_add.is_empty(), "set already exists");
        assert_eq!(
            diff.set_elements_to_add.len(),
            1,
            "exactly one element-add batch"
        );
        assert_eq!(
            diff.set_elements_to_add[0].3.len(),
            1,
            "only the single new element is added (element-level diff)"
        );
        assert!(
            diff.set_elements_to_remove.is_empty(),
            "nothing to remove"
        );
        diff.apply(&nft).await?;

        let kernel = nft
            .list_set_elements("filter_set", "allowed_v4", Family::Inet)
            .await?;
        assert_eq!(kernel.len(), 2);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reconcile_remove_one_set_element() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-set-del-elem")?;
        let nft = nft_in_ns(&ns)?;

        cfg_with_set(&[(10, 0, 0, 1), (10, 0, 0, 2)])
            .diff(&nft)
            .await?
            .apply(&nft)
            .await?;

        // Declare the same set with one element dropped.
        let smaller = cfg_with_set(&[(10, 0, 0, 1)]);
        let diff = smaller.diff(&nft).await?;
        assert!(diff.set_elements_to_add.is_empty(), "nothing to add");
        assert_eq!(
            diff.set_elements_to_remove.len(),
            1,
            "exactly one element-remove batch"
        );
        assert_eq!(
            diff.set_elements_to_remove[0].3.len(),
            1,
            "only the undeclared element is removed"
        );
        diff.apply(&nft).await?;

        let kernel = nft
            .list_set_elements("filter_set", "allowed_v4", Family::Inet)
            .await?;
        assert_eq!(kernel.len(), 1, "kernel set must hold just the kept element");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reconcile_delete_set_when_removed_from_config() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-set-delete")?;
        let nft = nft_in_ns(&ns)?;

        cfg_with_set(&[(10, 0, 0, 1)])
            .diff(&nft)
            .await?
            .apply(&nft)
            .await?;

        // Same table, but the set is gone from the declaration.
        let no_set = NftablesConfig::new().table("filter_set", Family::Inet, |t| t);
        let diff = no_set.diff(&nft).await?;
        assert_eq!(diff.sets_to_delete.len(), 1, "the dropped set is deleted");
        diff.apply(&nft).await?;

        let sets = nft.list_sets_in("filter_set", Family::Inet).await?;
        assert!(sets.is_empty(), "set must be gone after reconcile");
        Ok(())
    })
    .await
}
