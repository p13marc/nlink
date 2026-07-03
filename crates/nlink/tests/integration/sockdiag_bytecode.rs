//! Sockdiag `INET_DIAG_REQ_BYTECODE` integration tests.
//!
//! These validate the bytecode compiler against a **real kernel**: the
//! kernel audits every program (`inet_diag_bc_audit`) and rejects a
//! malformed one with `EINVAL`, so a query that succeeds proves the
//! program is structurally valid, and the returned set proves the
//! semantics. Byte-layout correctness is pinned by the unit tests in
//! `sockdiag::bytecode`; this is the on-kernel behaviour check.
//!
//! Gated with `require_root!()` so it skips cleanly for the non-root
//! maintainer and runs under the privileged CI.

use std::net::TcpListener;

use nlink::{
    netlink::{Connection, SockDiag},
    sockdiag::{
        InetFilter, Protocol, SocketFilter, SocketInfo, TcpState, bytecode, filter::FilterKind,
    },
};

fn sport_query(port: u16) -> SocketFilter {
    // local_port drives the INET_DIAG_REQ_BYTECODE pre-filter in the
    // inet dump path (sport == port).
    SocketFilter {
        kind: FilterKind::Inet(InetFilter {
            protocol: Protocol::Tcp,
            states: TcpState::all_mask(),
            local_port: Some(port),
            ..Default::default()
        }),
    }
}

#[tokio::test]
async fn bytecode_sport_filter_matches_kernel_side() -> nlink::Result<()> {
    require_root!();

    // A listening socket whose source port we target via local_port.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    // Sanity: the port lowers to a valid bytecode program.
    assert!(
        bytecode::for_ports(Some(port), None).is_some(),
        "exact sport should compile to bytecode"
    );

    let conn = Connection::<SockDiag>::new()?;

    // Run a kernel-filtered dump. If the program were malformed the
    // kernel bc-audit would reject the query with EINVAL here.
    let filtered = conn.query(&sport_query(port)).await?;

    // The kernel pre-filter must keep our listener...
    let saw_listener = filtered.iter().any(|s| match s {
        SocketInfo::Inet(i) => i.local.port() == port,
        _ => false,
    });
    assert!(
        saw_listener,
        "kernel-filtered dump should include our :{port} listener"
    );

    // ...and exclude every socket with a different source port — the
    // whole point is that the kernel dropped them before userspace.
    let other_ports = filtered
        .iter()
        .filter(|s| matches!(s, SocketInfo::Inet(i) if i.local.port() != port))
        .count();
    assert_eq!(
        other_ports, 0,
        "bytecode dump leaked {other_ports} sockets with a non-:{port} sport"
    );

    drop(listener);
    Ok(())
}

// ============================================================================
// #163 — full compiler: expressions, host conds, or/not, state hoist,
// CC-info structs. A successful dump proves audit-validity (the kernel
// EINVALs malformed programs); the returned set proves semantics.
// ============================================================================

use nlink::sockdiag::{CcInfo, FilterExpr};

fn expr_query(expr: &str) -> SocketFilter {
    SocketFilter {
        kind: FilterKind::Inet(InetFilter {
            protocol: Protocol::Tcp,
            states: TcpState::all_mask(),
            expr: Some(FilterExpr::parse(expr).expect("expr parses")),
            ..Default::default()
        }),
    }
}

fn inet_ports(sockets: &[SocketInfo]) -> Vec<u16> {
    sockets
        .iter()
        .filter_map(|s| s.as_inet().map(|i| i.local.port()))
        .collect()
}

#[tokio::test]
async fn expr_or_of_two_sports_keeps_both_and_leaks_nothing() -> nlink::Result<()> {
    require_root!();

    let a = TcpListener::bind("127.0.0.1:0").expect("bind a");
    let b = TcpListener::bind("127.0.0.1:0").expect("bind b");
    let (pa, pb) = (a.local_addr().unwrap().port(), b.local_addr().unwrap().port());

    let conn = Connection::<SockDiag>::new()?;
    let got = conn
        .query(&expr_query(&format!("sport = :{pa} or sport = :{pb}")))
        .await?;
    let ports = inet_ports(&got);
    assert!(ports.contains(&pa), "listener A kept");
    assert!(ports.contains(&pb), "listener B kept");
    assert!(
        ports.iter().all(|p| *p == pa || *p == pb),
        "no other sport leaked: {ports:?}"
    );
    Ok(())
}

#[tokio::test]
async fn expr_not_sport_excludes_target() -> nlink::Result<()> {
    require_root!();

    let a = TcpListener::bind("127.0.0.1:0").expect("bind a");
    let b = TcpListener::bind("127.0.0.1:0").expect("bind b");
    let (pa, pb) = (a.local_addr().unwrap().port(), b.local_addr().unwrap().port());

    let conn = Connection::<SockDiag>::new()?;
    let got = conn.query(&expr_query(&format!("not sport = :{pa}"))).await?;
    let ports = inet_ports(&got);
    assert!(!ports.contains(&pa), "negated port excluded");
    assert!(ports.contains(&pb), "other listener kept");
    Ok(())
}

#[tokio::test]
async fn expr_src_hostcond_includes_and_excludes() -> nlink::Result<()> {
    require_root!();

    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().unwrap().port();
    let conn = Connection::<SockDiag>::new()?;

    // src 127.0.0.1 keeps the loopback listener.
    let got = conn
        .query(&expr_query(&format!("src 127.0.0.1 and sport = :{port}")))
        .await?;
    assert!(inet_ports(&got).contains(&port), "loopback src kept");

    // A src the listener doesn't have excludes it.
    let got = conn
        .query(&expr_query(&format!("src 203.0.113.1 and sport = :{port}")))
        .await?;
    assert!(
        !inet_ports(&got).contains(&port),
        "foreign src excluded the listener"
    );
    Ok(())
}

#[tokio::test]
async fn expr_v6_hostcond_matches_loopback() -> nlink::Result<()> {
    require_root!();

    let l = TcpListener::bind("[::1]:0").expect("bind v6");
    let port = l.local_addr().unwrap().port();
    let conn = Connection::<SockDiag>::new()?;
    let got = conn
        .query(&expr_query(&format!("src ::1 and sport = :{port}")))
        .await?;
    assert!(inet_ports(&got).contains(&port), "v6 loopback listener kept");
    Ok(())
}

#[tokio::test]
async fn expr_state_hoists_into_header_mask() -> nlink::Result<()> {
    require_root!();

    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().unwrap().port();
    let conn = Connection::<SockDiag>::new()?;

    // state listen and sport = :P → the state half rides in
    // idiag_states, the port half in bytecode.
    let got = conn
        .query(&expr_query(&format!("state listening and sport = :{port}")))
        .await?;
    assert!(inet_ports(&got).contains(&port), "listener kept");

    // state established and sport = :P → the listener must NOT appear.
    let got = conn
        .query(&expr_query(&format!("state established and sport = :{port}")))
        .await?;
    assert!(
        !inet_ports(&got).contains(&port),
        "listener filtered out by hoisted state mask"
    );
    Ok(())
}

#[tokio::test]
async fn cc_info_struct_matches_congestion_name() -> nlink::Result<()> {
    require_root!();

    // An established loopback pair so tcp_info/CC state exists.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let _client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let (_server, _) = listener.accept().expect("accept");

    let conn = Connection::<SockDiag>::new()?;
    let filter = SocketFilter {
        kind: FilterKind::Inet(InetFilter {
            protocol: Protocol::Tcp,
            states: TcpState::all_mask(),
            expr: Some(FilterExpr::parse(&format!("dport = :{port}")).unwrap()),
            // CC name + CC-info struct + tcp_info.
            extensions: nlink::sockdiag::InetExtension::Cong.mask()
                | nlink::sockdiag::InetExtension::VegasInfo.mask()
                | nlink::sockdiag::InetExtension::Info.mask(),
            ..Default::default()
        }),
    };
    let got = conn.query(&filter).await?;
    assert!(!got.is_empty(), "established pair visible");

    for s in got.iter().filter_map(|s| s.as_inet()) {
        // cc_info variant, when present, must agree with the CC name.
        match (&s.congestion, &s.cc_info) {
            (Some(name), Some(CcInfo::Bbr(_))) => assert_eq!(name, "bbr"),
            (Some(name), Some(CcInfo::Dctcp(_))) => assert_eq!(name, "dctcp"),
            (Some(name), Some(CcInfo::Vegas(_))) => assert_eq!(name, "vegas"),
            // cubic/reno have no diag get_info → cc_info None; any
            // (name, None) combination is fine.
            _ => {}
        }
    }
    Ok(())
}
