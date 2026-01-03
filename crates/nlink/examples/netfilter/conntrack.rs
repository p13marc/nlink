//! List connection tracking entries.
//!
//! This example demonstrates how to query the kernel's connection tracking
//! table (conntrack). This shows active network connections tracked by
//! netfilter for NAT and stateful firewall purposes.
//!
//! Run with: cargo run -p nlink --example netfilter_conntrack
//!
//! Note: Requires conntrack to be enabled in the kernel.

use nlink::netlink::netfilter::{IpProtocol, TcpConntrackState};
use nlink::netlink::{Connection, Netfilter};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Netfilter>::new()?;

    // Get IPv4 connection tracking entries
    println!("=== IPv4 Connection Tracking Entries ===\n");
    let entries = conn.get_conntrack().await?;

    if entries.is_empty() {
        println!("No connection tracking entries found.");
        println!("(Connection tracking may not be enabled or there are no active connections)\n");
    } else {
        println!(
            "{:<6} {:<22} {:<22} {:<12} {:<8}",
            "PROTO", "SOURCE", "DESTINATION", "STATE", "TIMEOUT"
        );
        println!("{}", "-".repeat(75));

        for entry in &entries {
            let proto = match entry.proto {
                IpProtocol::Tcp => "tcp",
                IpProtocol::Udp => "udp",
                IpProtocol::Icmp => "icmp",
                IpProtocol::Icmpv6 => "icmpv6",
                IpProtocol::Other(n) => {
                    // Skip unknown protocols in display
                    if n == 0 {
                        continue;
                    }
                    "other"
                }
            };

            let src = format!(
                "{}:{}",
                entry
                    .orig
                    .src_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_default(),
                entry.orig.src_port.unwrap_or(0)
            );

            let dst = format!(
                "{}:{}",
                entry
                    .orig
                    .dst_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_default(),
                entry.orig.dst_port.unwrap_or(0)
            );

            let state = entry
                .tcp_state
                .map(|s| match s {
                    TcpConntrackState::Established => "ESTABLISHED",
                    TcpConntrackState::SynSent => "SYN_SENT",
                    TcpConntrackState::SynRecv => "SYN_RECV",
                    TcpConntrackState::FinWait => "FIN_WAIT",
                    TcpConntrackState::CloseWait => "CLOSE_WAIT",
                    TcpConntrackState::LastAck => "LAST_ACK",
                    TcpConntrackState::TimeWait => "TIME_WAIT",
                    TcpConntrackState::Close => "CLOSE",
                    TcpConntrackState::Listen => "LISTEN",
                    _ => "-",
                })
                .unwrap_or("-");

            let timeout = entry.timeout.map(|t| format!("{}s", t)).unwrap_or_default();

            println!(
                "{:<6} {:<22} {:<22} {:<12} {:<8}",
                proto, src, dst, state, timeout
            );
        }

        println!("\nTotal: {} entries", entries.len());
    }

    // Get IPv6 connection tracking entries
    println!("\n=== IPv6 Connection Tracking Entries ===\n");
    let entries_v6 = conn.get_conntrack_v6().await?;

    if entries_v6.is_empty() {
        println!("No IPv6 connection tracking entries found.\n");
    } else {
        println!("Found {} IPv6 entries", entries_v6.len());
        for entry in entries_v6.iter().take(5) {
            let proto = match entry.proto {
                IpProtocol::Tcp => "tcp",
                IpProtocol::Udp => "udp",
                _ => "other",
            };
            println!(
                "  {} {:?} -> {:?}",
                proto, entry.orig.src_ip, entry.orig.dst_ip
            );
        }
        if entries_v6.len() > 5 {
            println!("  ... and {} more", entries_v6.len() - 5);
        }
    }

    Ok(())
}
