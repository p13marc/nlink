//! IPsec Security Associations and Policies monitor.
//!
//! This example shows how to query IPsec Security Associations (SAs)
//! and Security Policies (SPs) using the NETLINK_XFRM protocol.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example xfrm_ipsec_monitor
//! ```
//!
//! # Requirements
//!
//! - Requires CAP_NET_ADMIN or root privileges to query XFRM state
//! - IPsec must be configured (e.g., with strongSwan, Libreswan, or iproute2)

use nlink::netlink::xfrm::{IpsecProtocol, PolicyDirection, XfrmMode};
use nlink::netlink::{Connection, Xfrm};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Xfrm>::new()?;

    // List Security Associations
    println!("=== Security Associations ===\n");
    let sas = conn.get_security_associations().await?;

    if sas.is_empty() {
        println!("No Security Associations found.");
        println!("(IPsec SAs are created when VPN tunnels are established)");
    } else {
        for sa in &sas {
            println!(
                "SA: {:?} -> {:?}",
                sa.src_addr
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "?".to_string()),
                sa.dst_addr
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "?".to_string())
            );
            println!("  SPI: 0x{:08x}", sa.spi);
            println!(
                "  Protocol: {}",
                match sa.protocol {
                    IpsecProtocol::Esp => "ESP",
                    IpsecProtocol::Ah => "AH",
                    IpsecProtocol::Comp => "COMP",
                    IpsecProtocol::Other(n) => {
                        println!("  Protocol number: {}", n);
                        "OTHER"
                    }
                }
            );
            println!(
                "  Mode: {}",
                match sa.mode {
                    XfrmMode::Transport => "transport",
                    XfrmMode::Tunnel => "tunnel",
                    XfrmMode::Beet => "beet",
                    XfrmMode::Other(n) => {
                        println!("  Mode number: {}", n);
                        "other"
                    }
                }
            );
            println!("  ReqID: {}", sa.reqid);

            if let Some(ref enc) = sa.enc_alg {
                println!("  Encryption: {} ({} bits)", enc.name, enc.key_len);
            }
            if let Some(ref auth) = sa.auth_alg {
                println!("  Authentication: {} ({} bits)", auth.name, auth.key_len);
            }
            if let Some(ref aead) = sa.aead_alg {
                println!(
                    "  AEAD: {} ({} bits, ICV {} bits)",
                    aead.name, aead.key_len, aead.icv_len
                );
            }

            println!("  Stats: {} bytes, {} packets", sa.bytes, sa.packets);

            if let Some(mark) = &sa.mark {
                println!("  Mark: 0x{:x}/0x{:x}", mark.v, mark.m);
            }
            if let Some(if_id) = sa.if_id {
                println!("  Interface ID: {}", if_id);
            }

            println!();
        }
    }

    // List Security Policies
    println!("\n=== Security Policies ===\n");
    let policies = conn.get_security_policies().await?;

    if policies.is_empty() {
        println!("No Security Policies found.");
        println!("(IPsec policies define which traffic should be protected)");
    } else {
        for pol in &policies {
            println!(
                "Policy: {} (index {})",
                match pol.direction {
                    PolicyDirection::In => "IN",
                    PolicyDirection::Out => "OUT",
                    PolicyDirection::Forward => "FWD",
                    PolicyDirection::Unknown(n) => {
                        println!("  Direction number: {}", n);
                        "?"
                    }
                },
                pol.index
            );
            println!("  Priority: {}", pol.priority);
            println!(
                "  Action: {}",
                match pol.action {
                    nlink::netlink::xfrm::PolicyAction::Allow => "allow",
                    nlink::netlink::xfrm::PolicyAction::Block => "block",
                    nlink::netlink::xfrm::PolicyAction::Unknown(n) => {
                        println!("  Action number: {}", n);
                        "?"
                    }
                }
            );

            // Selector info
            let sel = &pol.selector;
            if let Some(src) = &sel.src_addr {
                println!("  Source: {}/{}", src, sel.src_prefix_len);
            }
            if let Some(dst) = &sel.dst_addr {
                println!("  Dest: {}/{}", dst, sel.dst_prefix_len);
            }
            if sel.proto != 0 {
                println!("  Protocol: {}", sel.proto);
            }
            if let Some(sport) = sel.src_port {
                println!("  Source port: {}", sport);
            }
            if let Some(dport) = sel.dst_port {
                println!("  Dest port: {}", dport);
            }

            if let Some(mark) = &pol.mark {
                println!("  Mark: 0x{:x}/0x{:x}", mark.v, mark.m);
            }
            if let Some(if_id) = pol.if_id {
                println!("  Interface ID: {}", if_id);
            }

            println!();
        }
    }

    println!("\nTo create IPsec SAs/policies, use tools like:");
    println!("  - ip xfrm state add ...");
    println!("  - ip xfrm policy add ...");
    println!("  - strongSwan/Libreswan VPN");

    Ok(())
}
