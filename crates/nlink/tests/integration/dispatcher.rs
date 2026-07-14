//! Plan 234 (0.21) — Dispatcher integration coverage.
//!
//! Validates the dispatcher foundation end-to-end against a real
//! netlink socket (root-gated). Three classes of test, mapping to
//! Plan 234 §6:
//!
//! 1. **Wiring correctness** — every `Connection::new` /
//!    `from_parts` installs a dispatcher on its socket; the
//!    `dispatcher()` accessor returns the same instance the
//!    socket-side ENOBUFS path fans into.
//! 2. **Synthetic ENOBUFS routing** — multiple multicast
//!    subscribers all receive `ResyncMarker::ResyncStart` when the
//!    socket's `synth_enobufs_for_test()` fires, simulating the
//!    real kernel-side overflow path without the multi-minute
//!    flood the integration test would otherwise need.
//! 3. **Per-family smoke checks** — the dispatcher is wired the
//!    same way for every Connection<P> variant (Route, Generic,
//!    Netfilter, Nftables, Wireguard, Macsec, Mptcp, Ethtool,
//!    Nl80211, Devlink, DPLL, NetShaper). The per-family tests
//!    instantiate the family-resolved Connection where possible
//!    and assert the dispatcher is reachable. Failures here
//!    surface a Plan 235 (GENL command unification) gap before
//!    that follow-up lands.
//!
//! All tests are `require_root!()`-gated and skip cleanly when
//! run as a regular user. The synthetic-ENOBUFS test is the
//! exception — it works without root because it uses the
//! `synth_enobufs_for_test()` injection point that doesn't touch
//! the kernel.

use std::sync::Arc;
use std::time::Duration;

use nlink::Result;
use nlink::netlink::{
    Connection, Generic, Route,
    dispatcher::DispatcherEvent,
    resync::ResyncMarker,
};

// ============================================================================
// §6 — Wiring correctness
// ============================================================================

/// Plan 234 §6 — every Connection construction path installs the
/// dispatcher so the socket-side recv loop can fan ENOBUFS.
///
/// No root required — `Connection::<Route>::new()` doesn't need
/// privileges (the bind happens in the calling process's netns; the
/// socket isn't yet used to mutate anything).
#[tokio::test]
async fn connection_new_installs_dispatcher_on_socket() {
    nlink::lab::init_test_tracing();
    let conn = match Connection::<Route>::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skip: cannot create Route connection: {e}");
            return;
        }
    };

    let dispatcher = conn.dispatcher();
    // Subscribe so the active count is non-zero.
    let _rx = dispatcher.subscribe_multicast(7);
    assert_eq!(dispatcher.active_group_count(), 1);

    // Confirm the socket sees the same dispatcher instance.
    let installed = conn
        .socket()
        .dispatcher_for_test()
        .expect("Connection::new must call socket.install_dispatcher");
    assert_eq!(
        installed.active_group_count(),
        1,
        "socket's dispatcher must be the same instance as Connection's"
    );
}

/// Plan 234 §6 — Generic family construction path also installs
/// the dispatcher.
#[tokio::test]
async fn connection_generic_new_installs_dispatcher_on_socket() {
    nlink::lab::init_test_tracing();
    let conn = match Connection::<Generic>::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skip: cannot create Generic connection: {e}");
            return;
        }
    };
    let dispatcher = conn.dispatcher();
    let _rx = dispatcher.subscribe_multicast(1);
    assert_eq!(
        conn.socket()
            .dispatcher_for_test()
            .expect("dispatcher must be installed on socket")
            .active_group_count(),
        1
    );
}

// ============================================================================
// §6.3 — Synthetic ENOBUFS recovery
// ============================================================================

/// Plan 234 §6.3 — the synthetic ENOBUFS injection fans
/// `ResyncMarker::ResyncStart` to every active multicast
/// subscriber.
///
/// No root required: the test uses `synth_enobufs_for_test()` so
/// it doesn't depend on the kernel emitting a real ENOBUFS.
#[tokio::test]
async fn synthetic_enobufs_fans_out_resync_start_to_all_subscribers() {
    nlink::lab::init_test_tracing();
    let conn = match Connection::<Route>::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skip: {e}");
            return;
        }
    };
    let mut rx1 = conn.dispatcher().subscribe_multicast(1);
    let mut rx2 = conn.dispatcher().subscribe_multicast(2);
    let mut rx3 = conn.dispatcher().subscribe_multicast(3);

    conn.socket().synth_enobufs_for_test();

    for (i, rx) in [&mut rx1, &mut rx2, &mut rx3].iter_mut().enumerate() {
        match rx.recv().await {
            Ok(DispatcherEvent::Resync(ResyncMarker::ResyncStart)) => {}
            other => panic!(
                "subscriber {i} expected ResyncStart, got {other:?}"
            ),
        }
    }
}

// ============================================================================
// §6.1.1 — Per-family smoke
// ============================================================================

// Each per-family test asserts the dispatcher is installed and
// reachable for that family's Connection<P>. They do NOT exercise
// the full "100 requests + multicast subscriber" load described in
// Plan 234 §6.1.1 — that requires a real kernel-side family to be
// loaded, which the CI runner doesn't guarantee. These tests are
// the wiring half; the load half lands when Plan 235 (GENL command
// unification) does, because the round-trip helpers will all share
// the same plumbing.

macro_rules! per_family_dispatcher_test {
    ($name:ident, $marker:ty, $construct:expr, $why_skip:literal) => {
        #[tokio::test]
        async fn $name() {
            nlink::lab::init_test_tracing();
            let conn: Connection<$marker> = match $construct {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        concat!("skip ", stringify!($name), ": ", $why_skip, " ({})"),
                        e
                    );
                    return;
                }
            };
            let dispatcher = conn.dispatcher();
            let _rx = dispatcher.subscribe_multicast(1);
            assert_eq!(
                conn.socket()
                    .dispatcher_for_test()
                    .expect("dispatcher installed on socket")
                    .active_group_count(),
                1
            );
        }
    };
}

// Generic GENL families — async constructor. If the running kernel
// doesn't have the family loaded, new_async() returns
// FamilyNotFound and the test skips gracefully.

per_family_dispatcher_test!(
    wireguard_connection_has_dispatcher,
    nlink::netlink::Wireguard,
    Connection::<nlink::netlink::Wireguard>::new_async().await,
    "wireguard kernel module absent"
);

per_family_dispatcher_test!(
    macsec_connection_has_dispatcher,
    nlink::netlink::Macsec,
    Connection::<nlink::netlink::Macsec>::new_async().await,
    "macsec kernel module absent"
);

per_family_dispatcher_test!(
    mptcp_connection_has_dispatcher,
    nlink::netlink::Mptcp,
    Connection::<nlink::netlink::Mptcp>::new_async().await,
    "mptcp_pm kernel module absent"
);

per_family_dispatcher_test!(
    ethtool_connection_has_dispatcher,
    nlink::netlink::Ethtool,
    Connection::<nlink::netlink::Ethtool>::new_async().await,
    "ethtool family unavailable"
);

per_family_dispatcher_test!(
    nl80211_connection_has_dispatcher,
    nlink::netlink::Nl80211,
    Connection::<nlink::netlink::Nl80211>::new_async().await,
    "nl80211 family unavailable"
);

per_family_dispatcher_test!(
    devlink_connection_has_dispatcher,
    nlink::netlink::Devlink,
    Connection::<nlink::netlink::Devlink>::new_async().await,
    "devlink family unavailable"
);

per_family_dispatcher_test!(
    dpll_connection_has_dispatcher,
    nlink::netlink::Dpll,
    Connection::<nlink::netlink::Dpll>::new_async().await,
    "DPLL family unavailable"
);

// ============================================================================
// §6.2 — Stress: requests with active multicast subscriber
// ============================================================================

/// Plan 234 §6.2 — the dispatcher infrastructure must coexist with
/// concurrent request paths on a shared `Arc<Connection>`. The full
/// pipelining work (where the F1 mutex retires) is the next batch;
/// this test confirms that even with a multicast subscriber holding
/// the dispatcher's broadcast channel, concurrent unicast requests
/// still complete correctly through the F1 mutex.
///
/// 16 concurrent `get_links()` calls + 1 dispatcher subscriber.
/// Today they serialize through the F1 mutex — the test asserts
/// correctness, not pipelining throughput (which is the follow-up's
/// regression target).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_coexist_with_dispatcher_subscriber() -> Result<()> {
    nlink::lab::init_test_tracing();
    let conn = match Connection::<Route>::new() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("skip: {e}");
            return Ok(());
        }
    };

    // Subscribe to a dispatcher channel — proof that the dispatcher
    // state coexists with concurrent requests.
    let mut rx = conn.dispatcher().subscribe_multicast(7);

    // 16 concurrent get_links — should all complete without
    // hanging or returning wrong data.
    let mut handles = Vec::with_capacity(16);
    for _ in 0..16 {
        let c = conn.clone();
        handles.push(tokio::spawn(async move { c.get_links().await }));
    }
    for h in handles {
        let _links = h.await.expect("task panicked")?;
    }

    // Dispatcher subscriber should still be live — emit a
    // synthetic ENOBUFS and confirm we see the marker.
    conn.socket().synth_enobufs_for_test();
    match rx.recv().await {
        Ok(DispatcherEvent::Resync(ResyncMarker::ResyncStart)) => {}
        other => panic!("expected ResyncStart, got {other:?}"),
    }
    Ok(())
}

// ============================================================================
// #219 — shutdown must actually reach the driver.
// ============================================================================

/// Dropping a dispatcher-mode `Connection` closes its fd.
///
/// This is the end-to-end check that shutdown reaches the driver at all, over a
/// churn loop that would accumulate fds if it didn't.
///
/// **It does not, on its own, pin #219.** That bug is a lost-wakeup race:
/// `shutdown()` signalled with `Notify::notify_waiters()`, which stores no
/// permit and wakes only tasks *already registered* as waiters, and the driver
/// is unregistered for the whole of `route_buffer` and between `select!`
/// iterations. In the steady state this loop exercises, the driver is parked in
/// `notified()` when the drop lands — which is precisely the case
/// `notify_waiters` handles — so this test passes either way. Verified by
/// reintroducing the bug.
///
/// The race itself is pinned deterministically by
/// `dispatcher::tests::shutdown_signalled_with_no_waiter_is_not_lost`, which
/// signals with no waiter registered and fails under `notify_waiters`.
///
/// Unprivileged: opening an `NETLINK_ROUTE` socket needs no capability.
#[tokio::test]
async fn dropping_a_dispatcher_connection_closes_its_fd() -> Result<()> {
    fn open_fds() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("/proc/self/fd")
            .count()
    }

    // Warm up: the first connection may allocate thread-local and runtime fds
    // that are not returned, which would read as a leak.
    {
        let conn = Connection::<Route>::new()?.with_dispatcher();
        let _ = conn.get_links().await?;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    let baseline = open_fds();

    for _ in 0..20 {
        let conn = Connection::<Route>::new()?.with_dispatcher();
        // Drive a request so the driver task is actually spawned (it starts
        // lazily) and is mid-loop when the connection drops.
        let _ = conn.get_links().await?;
        drop(conn);
    }

    // The driver exits asynchronously, so give the runtime a moment to reap the
    // tasks before counting. Poll rather than sleep-and-hope.
    for _ in 0..40 {
        if open_fds() <= baseline {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!(
        "fd leak: {} open fds after 20 create/drop cycles, was {baseline} before — \
         the shutdown signal is not reaching the driver, so it loops forever \
         holding its socket",
        open_fds(),
    );
}
