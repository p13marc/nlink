//! Declarative `NftablesConfig` end-to-end (Plan 157 + 157b v2).
//!
//! Run as root (needs `CAP_NET_ADMIN`):
//!   `sudo -E cargo run --example nftables_declarative`
//!
//! Build only:
//!   `cargo build --example nftables_declarative`
//!
//! Demonstrates:
//!   1. Build an `NftablesConfig` with two `rule_keyed` rules.
//!   2. Compute the diff against the kernel (empty starting state
//!      → all-adds).
//!   3. Apply atomically (single NFNL_MSG_BATCH_BEGIN…END commit).
//!   4. Re-compute the diff (now empty — idempotent reapply).
//!   5. Mutate one rule's body, keep its handle_key; the diff is
//!      a single `rules_to_replace` op (in-place
//!      NFT_MSG_NEWRULE+NLM_F_REPLACE at the kernel handle).
//!   6. Tear down with `del_table`.
//!
//! Each keyed rule round-trips its key through `NFTA_RULE_USERDATA`
//! as `"nlink:<key>"` so `nft list ruleset` shows
//! `comment "nlink:ssh-allow"`.

use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{Family, Hook, Policy, Priority};
use nlink::netlink::{Connection, Nftables};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Nftables>::new()?;

    // -- Step 1: declare the desired state ----------------------
    let cfg = NftablesConfig::new().table("filter_demo", Family::Inet, |t| {
        t.chain("input", |c| {
            c.hook(Hook::Input)
                .priority(Priority::Filter)
                .policy(Policy::Drop)
        })
        .rule_keyed("input", "ssh-allow", |r| r.match_tcp_dport(22).accept())
        .rule_keyed("input", "icmp-allow", |r| {
            r.match_l4proto(1 /* IPPROTO_ICMP */).accept()
        })
    });

    // -- Step 2: diff against current kernel state --------------
    let diff = match cfg.diff(&conn).await {
        Ok(d) => d,
        Err(e) if e.is_permission_denied() => {
            eprintln!(
                "EPERM: nftables config diff requires CAP_NET_ADMIN; \
                 re-run with sudo (rule integrity end-to-end demo)",
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    println!("initial diff:\n{}", diff);

    // -- Step 3: apply atomically -------------------------------
    let applied = diff.apply(&conn).await?;
    println!("\napplied {applied} ops\n");

    // -- Step 4: re-diff — should be empty (idempotent) ---------
    let reapply_diff = cfg.diff(&conn).await?;
    assert!(
        reapply_diff.is_empty(),
        "idempotent re-apply should produce empty diff; got: {}",
        reapply_diff,
    );
    println!("reapply diff: {} (empty — idempotent ✓)\n", reapply_diff);

    // -- Step 5: mutate one rule, keep the key ------------------
    let updated = NftablesConfig::new().table("filter_demo", Family::Inet, |t| {
        t.chain("input", |c| {
            c.hook(Hook::Input)
                .priority(Priority::Filter)
                .policy(Policy::Drop)
        })
        .rule_keyed("input", "ssh-allow", |r| r.match_tcp_dport(2222).accept()) // new port
        .rule_keyed("input", "icmp-allow", |r| r.match_l4proto(1).accept())
    });
    let mut_diff = updated.diff(&conn).await?;
    println!("after port change:\n{}", mut_diff);
    assert_eq!(
        mut_diff.rules_to_replace.len(),
        1,
        "expected exactly one in-place replace for the changed rule",
    );

    let applied = mut_diff.apply(&conn).await?;
    println!("\napplied {applied} op (1 = single replace_rule via NLM_F_REPLACE)\n");

    // -- Step 6: cleanup ---------------------------------------
    let teardown = NftablesConfig::new(); // empty → delete everything we own
    let drop_diff = teardown.diff(&conn).await?;
    println!("teardown diff:\n{}", drop_diff);
    let applied = drop_diff.apply(&conn).await?;
    println!("\nteardown applied {applied} ops — demo complete");

    Ok(())
}
