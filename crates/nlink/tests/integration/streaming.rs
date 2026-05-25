//! Plan 149 streaming dump API — `stream_links` parity round-trip.
//!
//! Mirrors §5.2 of `plans/166-0.17-integration-test-backfill-plan.md`.
//! The acceptance check is that the streaming path observes the same
//! interfaces as the eager `get_links()` path — i.e. the
//! `DumpStream::poll_next` parser is wire-equivalent to the bulk
//! parser used by the eager API.

use nlink::netlink::link::DummyLink;
use tokio_stream::StreamExt;

use crate::common::TestNamespace;

#[tokio::test]
async fn stream_links_yields_all_populated_links() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("stream-links")?;
    let conn = ns.connection()?;

    for i in 0..5 {
        conn.add_link(DummyLink::new(format!("d{i}"))).await?;
    }

    // Streaming dump.
    let mut count = 0usize;
    let mut stream = conn.stream_links().await?;
    while let Some(item) = stream.next().await {
        item?;
        count += 1;
    }

    // Lab namespace ships loopback + our 5 dummies. The kernel may
    // surface additional links (qdisc-installed ifb on some
    // configs), so assert a lower bound, not equality.
    assert!(
        count >= 6,
        "stream_links should observe loopback + 5 dummies (≥ 6); got {count}"
    );
    Ok(())
}

#[tokio::test]
async fn stream_links_matches_eager_dump_count() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("stream-vs-eager")?;
    let conn = ns.connection()?;

    for i in 0..3 {
        conn.add_link(DummyLink::new(format!("d{i}"))).await?;
    }

    let eager = conn.get_links().await?;

    let mut streamed = 0usize;
    let mut stream = conn.stream_links().await?;
    while let Some(item) = stream.next().await {
        item?;
        streamed += 1;
    }

    assert_eq!(
        streamed,
        eager.len(),
        "streaming dump must parse the same frame count as the eager dump"
    );
    Ok(())
}
