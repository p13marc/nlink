//! Plan 150 nftables flowtable — `add_flowtable` + `list_flowtables`
//! + hw_offload flag plumbing.
//!
//! Mirrors §5.3 of `plans/166-0.17-integration-test-backfill-plan.md`.
//! HW offload accept-but-fallback behaviour is **not** asserted here
//! — the kernel takes the flag with or without supporting hardware,
//! so we only check that the bit round-trips back via the dump.
//!
//! Per-test 30-second timeout for defensive hang protection — see
//! `nftables_reconcile.rs` for the rationale (Plan 167 Phase 3).
//! These tests passed in the first CI run but share the
//! `Connection<Nftables>` dump/commit path that hung the
//! reconcile suite, so the timeout is preventive.

use std::time::Duration;

use nlink::netlink::nftables::Flowtable;
use nlink::netlink::nftables::types::Family;
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

#[tokio::test]
async fn add_flowtable_basic_roundtrips() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nf_flow_table");

    with_timeout(async {
        let ns = TestNamespace::new("ft-basic")?;
        let nft = nft_in_ns(&ns)?;

        nft.add_table("filter", Family::Inet).await?;

        let ft = Flowtable::new(Family::Inet, "filter", "ft0");
        nft.add_flowtable(&ft).await?;

        let dumped = nft.list_flowtables().await?;
        let ours = dumped
            .iter()
            .find(|f| f.name == "ft0" && f.table == "filter")
            .expect("ft0 must appear in list_flowtables");
        assert_eq!(ours.family, Family::Inet, "family must round-trip");

        nft.del_flowtable(Family::Inet, "filter", "ft0").await?;
        nft.del_table("filter", Family::Inet).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn flowtable_hw_offload_flag_round_trips() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nf_flow_table");

    with_timeout(async {
        let ns = TestNamespace::new("ft-hwoff")?;
        let nft = nft_in_ns(&ns)?;

        nft.add_table("filter", Family::Inet).await?;

        // No device — flowtable accepts an empty device list and the
        // kernel still records the requested flag bits.
        let ft = Flowtable::new(Family::Inet, "filter", "ft_hwoff").hw_offload(true);
        match nft.add_flowtable(&ft).await {
            Ok(()) => {}
            // Kernels without NF_FLOW_TABLE_HW reject HW_OFFLOAD with
            // EOPNOTSUPP; treat as a skip on that test path so the
            // suite stays green on minimal kernels.
            Err(e) if e.is_not_supported() => {
                eprintln!("Skipping HW offload assertion: kernel reports EOPNOTSUPP");
                nft.del_table("filter", Family::Inet).await?;
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        let dumped = nft.list_flowtables().await?;
        let ours = dumped
            .iter()
            .find(|f| f.name == "ft_hwoff")
            .expect("ft_hwoff must appear in list_flowtables");
        assert!(
            ours.flags & nlink::netlink::nftables::NFT_FLOWTABLE_HW_OFFLOAD != 0,
            "HW_OFFLOAD bit must round-trip from kernel"
        );

        nft.del_flowtable(Family::Inet, "filter", "ft_hwoff").await?;
        nft.del_table("filter", Family::Inet).await?;
        Ok(())
    })
    .await
}
