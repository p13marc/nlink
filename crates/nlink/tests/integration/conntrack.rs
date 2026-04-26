//! Conntrack integration tests (Plan 137 PRs A+B un-park).
//!
//! All tests are gated with `require_root!()` + `require_module!`
//! so the suite skips cleanly when run as a regular user or on a
//! kernel without conntrack support. Under sudo + with the
//! `nf_conntrack` / `nf_conntrack_netlink` modules loaded (or
//! built in), each test runs in an isolated `LabNamespace`.
//!
//! Mirrors the assertions from `examples/netfilter/conntrack.rs
//! --apply` and `examples/netfilter/conntrack_events.rs --apply`,
//! which were the manual-validation channel before this file
//! existed.

use std::{net::Ipv4Addr, time::Duration};

use nlink::netlink::{
    Connection, Netfilter, namespace,
    netfilter::{
        ConntrackBuilder, ConntrackEvent, ConntrackGroup, ConntrackStatus, ConntrackTuple,
        IpProtocol, TcpConntrackState,
    },
};
use tokio_stream::StreamExt;

use crate::common::TestNamespace;

/// Open a namespace-scoped Netfilter connection.
fn nf_in_ns(ns: &TestNamespace) -> nlink::Result<Connection<Netfilter>> {
    namespace::connection_for(ns.name())
}

#[tokio::test]
async fn ct_inject_and_query_tcp_entry() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-inject-query")?;
    let nf = nf_in_ns(&ns)?;

    let orig =
        ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)).ports(40000, 80);

    nf.add_conntrack(
        ConntrackBuilder::new_v4(IpProtocol::Tcp)
            .orig(orig)
            .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
            .timeout(Duration::from_secs(120))
            .mark(0x42)
            .tcp_state(TcpConntrackState::Established),
    )
    .await?;

    let entries = nf.get_conntrack().await?;
    let injected = entries
        .iter()
        .find(|e| {
            e.proto == IpProtocol::Tcp
                && e.orig.src_port == Some(40000)
                && e.orig.dst_port == Some(80)
        })
        .expect("injected TCP entry should appear in dump");
    assert_eq!(injected.mark, Some(0x42), "mark must round-trip");
    assert_eq!(
        injected.tcp_state,
        Some(TcpConntrackState::Established),
        "tcp_state must round-trip"
    );
    assert!(injected.id.is_some(), "kernel always assigns an id");

    Ok(())
}

#[tokio::test]
async fn ct_update_changes_mark_in_place() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-update")?;
    let nf = nf_in_ns(&ns)?;

    let orig =
        ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)).ports(40001, 81);

    nf.add_conntrack(
        ConntrackBuilder::new_v4(IpProtocol::Tcp)
            .orig(orig.clone())
            .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
            .timeout(Duration::from_secs(120))
            .mark(0x42)
            .tcp_state(TcpConntrackState::Established),
    )
    .await?;

    nf.update_conntrack(
        ConntrackBuilder::new_v4(IpProtocol::Tcp)
            .orig(orig)
            .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
            .timeout(Duration::from_secs(60))
            .mark(0x99)
            .tcp_state(TcpConntrackState::Established),
    )
    .await?;

    let entries = nf.get_conntrack().await?;
    let updated = entries
        .iter()
        .find(|e| {
            e.proto == IpProtocol::Tcp
                && e.orig.src_port == Some(40001)
                && e.orig.dst_port == Some(81)
        })
        .expect("updated entry should still appear in dump");
    assert_eq!(updated.mark, Some(0x99), "mark must reflect update");

    Ok(())
}

#[tokio::test]
async fn ct_del_by_id_removes_entry() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-del")?;
    let nf = nf_in_ns(&ns)?;

    let orig =
        ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)).ports(40002, 82);

    nf.add_conntrack(
        ConntrackBuilder::new_v4(IpProtocol::Tcp)
            .orig(orig)
            .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
            .timeout(Duration::from_secs(120))
            .tcp_state(TcpConntrackState::Established),
    )
    .await?;

    let entries = nf.get_conntrack().await?;
    let id = entries
        .iter()
        .find(|e| e.orig.src_port == Some(40002) && e.orig.dst_port == Some(82))
        .and_then(|e| e.id)
        .expect("just-added entry has an id");

    nf.del_conntrack_by_id(id).await?;

    let after = nf.get_conntrack().await?;
    assert!(
        !after
            .iter()
            .any(|e| e.orig.src_port == Some(40002) && e.orig.dst_port == Some(82)),
        "entry should be gone after del_conntrack_by_id"
    );

    Ok(())
}

#[tokio::test]
async fn ct_flush_empties_table() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-flush")?;
    let nf = nf_in_ns(&ns)?;

    // Inject a couple of entries to flush.
    for port in 40010u16..40013 {
        nf.add_conntrack(
            ConntrackBuilder::new_v4(IpProtocol::Tcp)
                .orig(
                    ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
                        .ports(port, 90),
                )
                .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
                .timeout(Duration::from_secs(60))
                .tcp_state(TcpConntrackState::Established),
        )
        .await?;
    }

    let before = nf.get_conntrack().await?;
    assert!(before.len() >= 3, "expected at least 3 entries pre-flush");

    nf.flush_conntrack().await?;

    let after = nf.get_conntrack().await?;
    assert!(
        after.is_empty(),
        "flush_conntrack must wipe the table; found {} entries",
        after.len()
    );

    Ok(())
}

#[tokio::test]
async fn ct_subscribe_observes_new_event() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-events")?;
    // Two namespace-scoped connections: one to mutate, one to subscribe.
    let nf_mut: Connection<Netfilter> = namespace::connection_for(ns.name())?;
    let mut nf_sub: Connection<Netfilter> = namespace::connection_for(ns.name())?;

    nf_sub.subscribe(&[ConntrackGroup::New])?;
    let mut events = nf_sub.events();

    let orig = ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
        .ports(50001, 443);

    nf_mut
        .add_conntrack(
            ConntrackBuilder::new_v4(IpProtocol::Tcp)
                .orig(orig)
                .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
                .timeout(Duration::from_secs(60))
                .tcp_state(TcpConntrackState::Established),
        )
        .await?;

    // Drain up to one event with a generous timeout; the multicast
    // delivery is fast in practice but CI variance warrants a buffer.
    let event = tokio::time::timeout(Duration::from_secs(3), events.next())
        .await
        .expect("event stream must yield within 3s")
        .expect("event stream did not end");
    let event = event?;
    match event {
        ConntrackEvent::New(entry) => {
            assert_eq!(
                entry.orig.dst_port,
                Some(443),
                "received NEW event must be for the just-injected entry"
            );
        }
        other => panic!("expected ConntrackEvent::New, got {:?}", other),
    }

    Ok(())
}

#[tokio::test]
async fn ct_subscribe_observes_destroy_event_on_flush() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-events-destroy")?;

    // Make sure conntrack events are enabled inside the namespace.
    // On most kernels this defaults to "1" but some configs (or
    // sysctl presets that bleed into new netns) leave it off, in
    // which case the flush below silently produces no Destroy
    // events and the test times out. Best-effort: ignore failure
    // so we still cover kernels where the sysctl is already on or
    // missing. If the sysctl path doesn't exist (kernel built
    // without CONFIG_NF_CONNTRACK_EVENTS) the whole test is
    // pointless — skip cleanly.
    if std::path::Path::new("/proc/sys/net/netfilter/nf_conntrack_events").exists() {
        let _ = nlink::netlink::namespace::set_sysctl(
            ns.name(),
            "net.netfilter.nf_conntrack_events",
            "1",
        );
    } else {
        eprintln!(
            "Skipping test: /proc/sys/net/netfilter/nf_conntrack_events not present \
             (kernel built without CONFIG_NF_CONNTRACK_EVENTS?)"
        );
        return Ok(());
    }

    let nf_mut: Connection<Netfilter> = namespace::connection_for(ns.name())?;
    let mut nf_sub: Connection<Netfilter> = namespace::connection_for(ns.name())?;

    // Inject first so there's something to destroy.
    let orig = ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
        .ports(50002, 8080);
    nf_mut
        .add_conntrack(
            ConntrackBuilder::new_v4(IpProtocol::Tcp)
                .orig(orig)
                .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
                .timeout(Duration::from_secs(60))
                .tcp_state(TcpConntrackState::Established),
        )
        .await?;

    // Subscribe to ALL conntrack groups (not just Destroy). If CI
    // still reports zero events, we'll see in the diagnostic
    // prints whether ANY event arrives — that distinguishes
    // "subscription doesn't work" (none) from "flush doesn't
    // generate Destroy events for synthetic entries" (other
    // events arrive, just not Destroy).
    nf_sub.subscribe_all()?;
    let mut events = nf_sub.events();

    // Give the kernel a beat to register the multicast subscription
    // before triggering the events. Bumped 250ms → 1s after CI
    // still received zero events with 250ms.
    tokio::time::sleep(Duration::from_secs(1)).await;

    nf_mut.flush_conntrack().await?;

    // Drain until we see a Destroy for our port (other system traffic
    // could in principle generate Destroys; in a fresh netns this is
    // overwhelmingly unlikely but loop with a budget for safety).
    // 30s deadline absorbs CI scheduler jitter; the diagnostic
    // print below tells us what (if any) events arrived during the
    // wait so a future timeout failure has a paper trail.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut event_count = 0usize;
    loop {
        if std::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for ConntrackEvent::Destroy after {event_count} events"
            );
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let ev = match tokio::time::timeout(remaining, events.next()).await {
            Ok(Some(Ok(ev))) => ev,
            Ok(Some(Err(e))) => return Err(e),
            Ok(None) => panic!("event stream ended unexpectedly"),
            Err(_) => panic!(
                "timed out waiting for ConntrackEvent::Destroy after {event_count} events"
            ),
        };
        event_count += 1;
        eprintln!("conntrack event #{event_count}: {ev:?}");
        if let ConntrackEvent::Destroy(entry) = ev
            && entry.orig.dst_port == Some(8080)
        {
            return Ok(());
        }
    }
}
