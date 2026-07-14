//! Live-kernel verification of the nftables safety fixes (#190, #195, #199).
//!
//! These three are the ones that hurt on a real host:
//!
//! - **#190** — `apply()` deleted every kernel table it did not declare.
//! - **#195** — rules installed in *reverse* declaration order.
//! - **#199** — a mid-batch kernel rejection was discarded, so the caller got
//!   an opaque 30-second timeout instead of the error.
//!
//! Each one is a claim about what the kernel ends up holding, so each is
//! checked by asking the kernel.

use std::time::Duration;

use nlink::netlink::nftables::config::{NftDiffOptions, NftablesConfig};
use nlink::netlink::nftables::types::{Chain, ChainType, Family, Hook, Policy, Priority, Rule};
use nlink::netlink::{Connection, Nftables, namespace};

use crate::common::TestNamespace;

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

/// A config declaring exactly one table, and nothing else.
fn only_my_table() -> NftablesConfig {
    NftablesConfig::new().table("myapp", Family::Inet, |t| {
        t.chain("input", |c| {
            c.hook(Hook::Input)
                .priority(Priority::Filter)
                .policy(Policy::Accept)
                .chain_type(ChainType::Filter)
        })
    })
}

/// **The one that mattered (#190).** A table nlink did not declare must
/// survive an apply.
///
/// Before the fix, `diff()` scheduled *every* undeclared table for deletion
/// and `apply()` committed it in the atomic batch — and `NFT_MSG_DELTABLE`
/// cascades to all chains, rules and sets inside. On any host also running
/// Docker, firewalld, libvirt or kube-proxy, applying a config that declared
/// one table destroyed `ip nat`, `inet firewalld`, `ip6 filter` and everything
/// else, in a single commit, with no warning.
///
/// The lab namespace stands in for the host here: `foreign` is a table nlink
/// did not create and must not touch.
#[tokio::test]
async fn apply_does_not_delete_an_undeclared_table() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-noPurge")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        // A table created out-of-band — as Docker or firewalld would.
        conn.add_table("foreign", Family::Ip).await?;

        // Apply a config that says nothing about it.
        let diff = only_my_table().diff(&conn).await?;
        assert!(
            diff.tables_to_delete.is_empty(),
            "diff() must never schedule a table deletion; it scheduled {:?}",
            diff.tables_to_delete,
        );
        diff.apply(&conn).await?;

        let tables = conn.list_tables().await?;
        assert!(
            tables.iter().any(|t| t.name == "foreign"),
            "the foreign table was destroyed by an apply that never mentioned it",
        );
        assert!(
            tables.iter().any(|t| t.name == "myapp"),
            "the declared table was not created",
        );

        Ok(())
    })
    .await
}

/// Purge is still reachable — but only when asked for explicitly.
#[tokio::test]
async fn purge_is_opt_in_and_still_works() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-purge")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        conn.add_table("foreign", Family::Ip).await?;

        let diff = only_my_table()
            .diff_with_options(&conn, &NftDiffOptions::default().purge_tables(true))
            .await?;
        assert!(
            diff.tables_to_delete
                .iter()
                .any(|(_, name)| name == "foreign"),
            "purge_tables(true) must schedule the undeclared table for deletion",
        );
        diff.apply(&conn).await?;

        let tables = conn.list_tables().await?;
        assert!(
            !tables.iter().any(|t| t.name == "foreign"),
            "purge was requested but the foreign table survived",
        );

        Ok(())
    })
    .await
}

/// **Rule order (#195).** The kernel must hold rules in the order they were
/// declared.
///
/// `nf_tables_newrule()` appends to the chain tail only when `NLM_F_APPEND` is
/// set; without it, it *prepends*. nlink never set the flag (it was defined
/// and used nowhere), so rules landed in reverse. nftables is first-match-wins,
/// which inverts the policy exactly: a declared `[accept ssh, drop]` installed
/// as `[drop, accept]`, and **SSH was blocked**.
///
/// No test pinned rule order before now, which is why this survived.
#[tokio::test]
async fn rules_install_in_declaration_order() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-order")?;
    let conn = nft_in_ns(&ns)?;

    with_timeout(async {
        conn.add_table("ordering", Family::Inet).await?;
        conn.add_chain(
            Chain::new("ordering", "input")?
                .family(Family::Inet)
                .hook(Hook::Input)
                .priority(Priority::Filter)
                .chain_type(ChainType::Filter)
                .policy(Policy::Drop),
        )
        .await?;

        // The exact shape from the issue: accept SSH, then drop everything.
        // Comments give each rule an identity we can assert the order of.
        conn.add_rule(
            Rule::new("ordering", "input")
                .family(Family::Inet)
                .comment("nlink:1-accept-ssh")
                .match_tcp_dport(22)
                .accept(),
        )
        .await?;
        conn.add_rule(
            Rule::new("ordering", "input")
                .family(Family::Inet)
                .comment("nlink:2-drop-all")
                .drop(),
        )
        .await?;

        let rules = conn.list_rules("ordering", Family::Inet).await?;
        assert_eq!(rules.len(), 2, "expected exactly the two rules we added");

        let order: Vec<_> = rules.iter().map(|r| r.comment.as_deref()).collect();
        assert_eq!(
            order,
            vec![Some("nlink:1-accept-ssh"), Some("nlink:2-drop-all")],
            "the kernel is holding the rules in REVERSE declaration order, so \
             the bare drop matches first and SSH is blocked (#195)",
        );

        Ok(())
    })
    .await
}

/// **Batch errors (#199).** A kernel rejection mid-batch must surface as that
/// error, promptly — not as a 30-second timeout.
///
/// `Transaction` numbered its inner messages from its own counter starting at
/// 1, unrelated to the socket's. `send_batch`'s `seq > end_seq { continue }`
/// filter therefore discarded the NLMSGERR for a rejected op. The kernel
/// aborted the batch, so the BATCH_END ACK never arrived, and the loop spun to
/// the 30s operation timeout with no indication of what failed.
///
/// Here the batch references a chain that does not exist, which the kernel
/// rejects. We assert we get *an error other than Timeout*, and that it
/// arrives fast.
#[tokio::test]
async fn a_rejected_batch_reports_the_kernel_error_not_a_timeout() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-batchErr")?;
    let conn = nft_in_ns(&ns)?;

    conn.add_table("batch", Family::Inet).await?;

    // A rule in a chain that was never created — the kernel rejects this op.
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        conn.transaction()
            .add_rule(
                Rule::new("batch", "nonexistent")
                    .family(Family::Inet)
                    .accept(),
            )
            .commit(&conn),
    )
    .await;

    let inner = result.expect(
        "the batch hung: a mid-batch kernel error was discarded and the \
         BATCH_END ACK never came (#199)",
    );

    let err = inner.expect_err("the kernel should have rejected a rule in a missing chain");
    assert!(
        !matches!(err, nlink::Error::Timeout),
        "expected the kernel's error, got a timeout — the error was discarded: {err}",
    );

    Ok(())
}
