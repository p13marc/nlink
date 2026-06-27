//! ss command - socket statistics.
//!
//! This is a Rust implementation of the `ss` utility from iproute2,
//! providing detailed socket information for TCP, UDP, Unix, and other sockets.

mod output;

use std::net::IpAddr;

use clap::Parser;
use nlink::{
    netlink::{Connection, SockDiag},
    output::OutputFormat,
    sockdiag::{InetFilter, Protocol, SocketFilter, SocketInfo, TcpState, UnixFilter},
};

#[derive(Parser)]
#[command(name = "ss", version, about = "Socket statistics utility")]
struct Cli {
    /// Display listening sockets.
    #[arg(short = 'l', long)]
    listening: bool,

    /// Display all sockets.
    #[arg(short = 'a', long)]
    all: bool,

    /// Display TCP sockets.
    #[arg(short = 't', long)]
    tcp: bool,

    /// Display UDP sockets.
    #[arg(short = 'u', long)]
    udp: bool,

    /// Display Unix sockets.
    #[arg(short = 'x', long)]
    unix: bool,

    /// Display raw sockets.
    #[arg(short = 'w', long)]
    raw: bool,

    /// Display SCTP sockets.
    #[arg(short = 'S', long)]
    sctp: bool,

    /// Display MPTCP sockets.
    #[arg(short = 'M', long)]
    mptcp: bool,

    /// Display netlink sockets.
    #[arg(long)]
    netlink: bool,

    /// Display IPv4 sockets only.
    #[arg(short = '4', long)]
    ipv4: bool,

    /// Display IPv6 sockets only.
    #[arg(short = '6', long)]
    ipv6: bool,

    /// Show process using socket.
    #[arg(short = 'p', long)]
    processes: bool,

    /// Show extended socket info.
    #[arg(short = 'e', long)]
    extended: bool,

    /// Show memory info.
    #[arg(short = 'm', long)]
    memory: bool,

    /// Show internal TCP info.
    #[arg(short = 'i', long)]
    info: bool,

    /// Show timer info.
    #[arg(short = 'o', long)]
    options: bool,

    /// Don't resolve service names.
    #[arg(short = 'n', long)]
    numeric: bool,

    /// Resolve host names.
    #[arg(short = 'r', long)]
    resolve: bool,

    /// Show only sockets connected to this address.
    #[arg(long)]
    dst: Option<String>,

    /// Show only sockets bound to this address.
    #[arg(long)]
    src: Option<String>,

    /// Show only sockets using this port.
    #[arg(long)]
    dport: Option<u16>,

    /// Show only sockets bound to this port.
    #[arg(long)]
    sport: Option<u16>,

    /// Don't display header.
    #[arg(short = 'H', long)]
    no_header: bool,

    /// One socket per line.
    #[arg(short = 'O', long)]
    oneline: bool,

    /// Output in JSON format.
    #[arg(short = 'j', long)]
    json: bool,

    /// Print summary statistics.
    #[arg(short = 's', long)]
    summary: bool,

    /// Forcibly close matching sockets (requires CAP_NET_ADMIN).
    #[arg(short = 'K', long)]
    kill: bool,

    /// Filter expression (ss-compatible syntax).
    ///
    /// Examples: 'sport = :22', 'dst 192.168.0.0/16 and state established',
    /// '( sport = :80 or sport = :443 ) and state listening'
    #[arg(trailing_var_arg = true)]
    filter_expr: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .init();

    let cli = Cli::parse();

    // Determine output format
    let format = if cli.json {
        OutputFormat::Json
    } else {
        OutputFormat::Text
    };

    let opts = output::DisplayOptions {
        numeric: cli.numeric,
        resolve: cli.resolve,
        extended: cli.extended,
        memory: cli.memory,
        info: cli.info,
        options: cli.options,
        processes: cli.processes,
        no_header: cli.no_header,
        oneline: cli.oneline,
    };

    // Create socket diagnostics connection
    let conn = Connection::<SockDiag>::new()?;

    // Handle summary mode
    if cli.summary {
        return run_summary(&conn, format).await;
    }

    // Handle kill mode
    if cli.kill {
        return run_kill(&cli, &conn).await;
    }

    // Determine which socket types to query
    let query_tcp =
        cli.tcp || (!cli.udp && !cli.unix && !cli.raw && !cli.sctp && !cli.mptcp && !cli.netlink);
    let query_udp = cli.udp;
    let query_unix = cli.unix;
    let query_raw = cli.raw;
    let query_sctp = cli.sctp;
    let query_mptcp = cli.mptcp;
    let query_netlink = cli.netlink;

    // Determine state filter
    let states = if cli.all {
        TcpState::all_mask()
    } else if cli.listening {
        TcpState::Listen.mask()
    } else {
        TcpState::connected_mask()
    };

    // Collect all results
    let mut all_results = Vec::new();

    // Query TCP sockets
    if query_tcp {
        let mut filter = InetFilter {
            protocol: Protocol::Tcp,
            states,
            ..Default::default()
        };
        apply_inet_filters(&cli, &mut filter);

        let sockets = conn
            .query(&SocketFilter {
                kind: nlink::sockdiag::filter::FilterKind::Inet(filter),
            })
            .await?;
        all_results.extend(sockets);
    }

    // Query UDP sockets
    if query_udp {
        let mut filter = InetFilter {
            protocol: Protocol::Udp,
            states: if cli.all || cli.listening {
                TcpState::all_mask()
            } else {
                // Default `ss -u` shows both connected (ESTABLISHED)
                // and unconnected/bound (CLOSE → "UNCONN") UDP
                // sockets — the latter is most UDP sockets (DNS,
                // DHCP, ...). Previously only bit 1 was set, so plain
                // `ss -u` silently missed every UNCONN socket.
                (1 << 1) | (1 << 7) // ESTABLISHED | CLOSE (UNCONN)
            },
            ..Default::default()
        };
        apply_inet_filters(&cli, &mut filter);

        let sockets = conn
            .query(&SocketFilter {
                kind: nlink::sockdiag::filter::FilterKind::Inet(filter),
            })
            .await?;
        all_results.extend(sockets);
    }

    // Query SCTP sockets
    if query_sctp {
        let mut filter = InetFilter {
            protocol: Protocol::Sctp,
            states,
            ..Default::default()
        };
        apply_inet_filters(&cli, &mut filter);

        let sockets = conn
            .query(&SocketFilter {
                kind: nlink::sockdiag::filter::FilterKind::Inet(filter),
            })
            .await?;
        all_results.extend(sockets);
    }

    // Query MPTCP sockets
    if query_mptcp {
        let mut filter = InetFilter {
            protocol: Protocol::Mptcp,
            states,
            ..Default::default()
        };
        apply_inet_filters(&cli, &mut filter);

        let sockets = conn
            .query(&SocketFilter {
                kind: nlink::sockdiag::filter::FilterKind::Inet(filter),
            })
            .await?;
        all_results.extend(sockets);
    }

    // Query raw sockets
    if query_raw {
        let mut filter = InetFilter {
            protocol: Protocol::Raw,
            states: TcpState::all_mask(),
            ..Default::default()
        };
        apply_inet_filters(&cli, &mut filter);

        let sockets = conn
            .query(&SocketFilter {
                kind: nlink::sockdiag::filter::FilterKind::Inet(filter),
            })
            .await?;
        all_results.extend(sockets);
    }

    // Query Unix sockets
    if query_unix {
        let filter = UnixFilter {
            states: if cli.all {
                TcpState::all_mask()
            } else if cli.listening {
                TcpState::Listen.mask()
            } else {
                TcpState::connected_mask()
            },
            ..Default::default()
        };

        let sockets = conn
            .query(&SocketFilter {
                kind: nlink::sockdiag::filter::FilterKind::Unix(filter),
            })
            .await?;
        all_results.extend(sockets);
    }

    // Query Netlink sockets
    if query_netlink {
        let filter = nlink::sockdiag::filter::NetlinkFilter::default();

        let sockets = conn
            .query(&SocketFilter {
                kind: nlink::sockdiag::filter::FilterKind::Netlink(filter),
            })
            .await?;
        all_results.extend(sockets);
    }

    // Apply address/port filters client-side. The kernel-side inet
    // filter does not emit INET_DIAG_REQ_BYTECODE yet, so --sport/
    // --dport/--src/--dst must be enforced here on the dumped results
    // (previously they were parsed and then silently ignored). Tracked
    // for kernel-side bytecode in the library-gaps issue.
    let inet_match = InetMatch::from_cli(&cli)?;
    if inet_match.is_active() {
        all_results.retain(|sock| inet_match.matches(sock));
    }

    // Apply expression filter if provided
    if !cli.filter_expr.is_empty() {
        let expr_str = cli.filter_expr.join(" ");
        let expr =
            nlink::sockdiag::FilterExpr::parse(&expr_str).map_err(|e| anyhow::anyhow!("{e}"))?;
        all_results.retain(|sock| expr.matches_socket_info(sock));
    }

    // Output results
    match format {
        OutputFormat::Json => {
            output::print_json(&all_results)?;
        }
        OutputFormat::Text => {
            output::print_text(&all_results, &opts)?;
        }
    }

    Ok(())
}

/// Run kill mode - destroy matching TCP sockets.
async fn run_kill(cli: &Cli, conn: &Connection<SockDiag>) -> anyhow::Result<()> {
    use nlink::sockdiag::{InetFilter, TcpState};

    // Build filter from CLI arguments (TCP only - only TCP supports SOCK_DESTROY)
    let states = if cli.all {
        TcpState::all_mask()
    } else if cli.listening {
        TcpState::Listen.mask()
    } else {
        TcpState::connected_mask()
    };

    let mut filter = InetFilter {
        protocol: Protocol::Tcp,
        states,
        ..Default::default()
    };
    apply_inet_filters(cli, &mut filter);

    let result = conn.destroy_matching(&filter).await?;

    if result.destroyed > 0 {
        eprintln!("Destroyed {} socket(s)", result.destroyed);
    }
    for err in &result.errors {
        eprintln!("Failed to destroy {}: {}", err.socket, err.error);
    }

    if result.destroyed == 0 && result.errors.is_empty() {
        eprintln!("No matching sockets found");
    }

    Ok(())
}

/// Run summary mode - show socket statistics without listing individual sockets.
async fn run_summary(conn: &Connection<SockDiag>, format: OutputFormat) -> anyhow::Result<()> {
    let summary = conn.socket_summary().await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        OutputFormat::Text => {
            println!("{summary}");
        }
    }

    Ok(())
}

fn apply_inet_filters(cli: &Cli, filter: &mut InetFilter) {
    // Apply family filter
    if cli.ipv4 {
        filter.family = Some(nlink::sockdiag::AddressFamily::Inet);
    } else if cli.ipv6 {
        filter.family = Some(nlink::sockdiag::AddressFamily::Inet6);
    }

    // Apply port filters
    if let Some(port) = cli.sport {
        filter.local_port = Some(port);
    }
    if let Some(port) = cli.dport {
        filter.remote_port = Some(port);
    }

    // Address filters (--src/--dst) are validated and enforced
    // client-side via `InetMatch` after the dump — the kernel-side
    // filter is a no-op without bytecode, and the previous
    // parse-or-silently-ignore here hid typos.

    // Apply extension requests
    // Extension bits are 1<<(DIAG_TYPE-1) since constants are 1-based
    if cli.memory {
        filter.extensions |= 1 << 0; // INET_DIAG_MEMINFO (1)
        filter.extensions |= 1 << 6; // INET_DIAG_SKMEMINFO (7)
    }
    if cli.info {
        filter.extensions |= 1 << 1; // INET_DIAG_INFO (2)
        filter.extensions |= 1 << 2; // INET_DIAG_VEGASINFO (3)
        filter.extensions |= 1 << 3; // INET_DIAG_CONG (4)
    }
}

/// Client-side address/port matcher for inet sockets, built from the
/// CLI's `--sport`/`--dport`/`--src`/`--dst`. Address parsing is strict
/// (a malformed `--src`/`--dst` is an error, not a silent no-op).
struct InetMatch {
    sport: Option<u16>,
    dport: Option<u16>,
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
}

impl InetMatch {
    fn from_cli(cli: &Cli) -> anyhow::Result<Self> {
        Ok(Self {
            sport: cli.sport,
            dport: cli.dport,
            src: parse_addr_opt(cli.src.as_deref(), "--src")?,
            dst: parse_addr_opt(cli.dst.as_deref(), "--dst")?,
        })
    }

    fn is_active(&self) -> bool {
        self.sport.is_some() || self.dport.is_some() || self.src.is_some() || self.dst.is_some()
    }

    fn matches(&self, sock: &SocketInfo) -> bool {
        // A port/address filter only makes sense for inet sockets;
        // exclude non-inet sockets when such a filter is active.
        let Some(inet) = sock.as_inet() else {
            return false;
        };
        if let Some(p) = self.sport
            && inet.local.port() != p
        {
            return false;
        }
        if let Some(p) = self.dport
            && inet.remote.port() != p
        {
            return false;
        }
        if let Some(ip) = self.src
            && inet.local.ip() != ip
        {
            return false;
        }
        if let Some(ip) = self.dst
            && inet.remote.ip() != ip
        {
            return false;
        }
        true
    }
}

/// Strictly parse an optional address string, erroring on a malformed
/// value rather than silently dropping the filter.
fn parse_addr_opt(s: Option<&str>, what: &str) -> anyhow::Result<Option<IpAddr>> {
    match s {
        None => Ok(None),
        Some(s) => s
            .parse::<IpAddr>()
            .map(Some)
            .map_err(|_| anyhow::anyhow!("invalid {what} address `{s}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nlink::sockdiag::{AddressFamily, InetSocket, Protocol, TcpState};

    fn inet(local: &str, remote: &str) -> SocketInfo {
        SocketInfo::Inet(Box::new(InetSocket::new(
            AddressFamily::Inet,
            Protocol::Tcp,
            TcpState::Established,
            local.parse().unwrap(),
            remote.parse().unwrap(),
        )))
    }

    #[test]
    fn parse_addr_opt_strict() {
        assert!(parse_addr_opt(None, "--src").unwrap().is_none());
        assert!(parse_addr_opt(Some("10.0.0.1"), "--src").unwrap().is_some());
        assert!(parse_addr_opt(Some("not-an-ip"), "--src").is_err());
    }

    #[test]
    fn inet_match_filters() {
        let m = InetMatch {
            sport: Some(22),
            dport: None,
            src: None,
            dst: Some("9.9.9.9".parse().unwrap()),
        };
        assert!(m.is_active());
        assert!(m.matches(&inet("1.2.3.4:22", "9.9.9.9:5000")));
        assert!(!m.matches(&inet("1.2.3.4:80", "9.9.9.9:5000"))); // wrong sport
        assert!(!m.matches(&inet("1.2.3.4:22", "8.8.8.8:5000"))); // wrong dst
    }

    #[test]
    fn inet_match_inactive_is_noop_builder() {
        let m = InetMatch {
            sport: None,
            dport: None,
            src: None,
            dst: None,
        };
        assert!(!m.is_active());
    }
}
