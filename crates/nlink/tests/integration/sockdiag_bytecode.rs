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
