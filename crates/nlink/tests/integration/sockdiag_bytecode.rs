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
        FilterExpr, InetFilter, Protocol, SocketFilter, SocketInfo, TcpState, bytecode,
        filter::FilterKind,
    },
};

fn inet_query(bytecode: Option<Vec<u8>>) -> SocketFilter {
    SocketFilter {
        kind: FilterKind::Inet(InetFilter {
            protocol: Protocol::Tcp,
            states: TcpState::all_mask(),
            bytecode,
            ..Default::default()
        }),
    }
}

#[tokio::test]
async fn bytecode_sport_filter_matches_kernel_side() -> nlink::Result<()> {
    require_root!();

    // A listening socket whose source port we can target.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    let conn = Connection::<SockDiag>::new()?;

    // Compile `sport == <port>` to bytecode and run a kernel-filtered
    // dump. If the program were malformed the kernel would EINVAL here.
    let expr = FilterExpr::parse(&format!("sport = :{port}")).unwrap();
    let code = bytecode::compile(&expr).expect("sport eq compiles");
    let filtered = conn.query(&inet_query(Some(code))).await?;

    // The kernel pre-filter must keep our listener...
    let saw_listener = filtered.iter().any(|s| match s {
        SocketInfo::Inet(i) => i.local.port() == port,
        _ => false,
    });
    assert!(saw_listener, "kernel-filtered dump should include our :{port} listener");

    // ...and exclude every socket with a different source port (this is
    // the whole point — the kernel dropped them before userspace).
    let other_ports = filtered
        .iter()
        .filter_map(|s| match s {
            SocketInfo::Inet(i) if i.local.port() != port => Some(i.local.port()),
            _ => None,
        })
        .count();
    assert_eq!(
        other_ports, 0,
        "bytecode dump leaked {other_ports} sockets with a non-:{port} sport"
    );

    drop(listener);
    Ok(())
}

#[tokio::test]
async fn bytecode_and_chain_is_accepted_by_kernel() -> nlink::Result<()> {
    require_root!();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let conn = Connection::<SockDiag>::new()?;

    // An AND-chain (sport range) must also pass the kernel bc-audit.
    let expr =
        FilterExpr::parse(&format!("sport >= :{port} and sport <= :{port}")).unwrap();
    let code = bytecode::compile(&expr).expect("and-chain compiles");
    let filtered = conn.query(&inet_query(Some(code))).await?;

    assert!(
        filtered.iter().any(|s| matches!(s, SocketInfo::Inet(i) if i.local.port() == port)),
        "AND-chain bytecode should keep our :{port} listener"
    );

    drop(listener);
    Ok(())
}
