//! MACsec (IEEE 802.1AE) Configuration Example
//!
//! Demonstrates MACsec device configuration via Generic Netlink.
//! MACsec provides Layer 2 encryption for point-to-point links.
//!
//! Run: cargo run -p nlink --example genl_macsec

use nlink::netlink::{Connection, Macsec};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    println!("=== MACsec Device Configuration ===\n");

    // Create MACsec connection
    match Connection::<Macsec>::new_async().await {
        Ok(conn) => {
            println!("MACsec GENL family ID: {}\n", conn.family_id());

            // Try to find MACsec interfaces
            let route_conn = nlink::netlink::Connection::<nlink::Route>::new()?;
            let links = route_conn.get_links().await?;
            let macsec_links: Vec<_> = links
                .iter()
                .filter(|l| l.link_kind() == Some("macsec"))
                .collect();

            if macsec_links.is_empty() {
                println!("No MACsec interfaces found.\n");
                println!("Create a MACsec interface with:");
                println!("  sudo ip link add macsec0 link eth0 type macsec");
                println!("  sudo ip link set macsec0 up");
                println!();
            } else {
                for link in &macsec_links {
                    let name = link.name_or("?");
                    println!("MACsec interface: {}", name);

                    match conn.get_device(name).await {
                        Ok(device) => {
                            println!("  SCI: {:016x}", device.sci);
                            println!("  Cipher: {:?}", device.cipher_suite);
                            println!("  Encoding SA: {}", device.encoding_sa);
                            println!("  Encryption: {}", device.encryption);
                            println!("  Protect: {}", device.protect);

                            // TX SA info
                            println!("  TX SC:");
                            for sa in &device.tx_sc.sas {
                                println!(
                                    "    SA {}: active={}, PN={}",
                                    sa.an, sa.active, sa.next_pn
                                );
                            }

                            // RX SC info
                            for rxsc in &device.rx_scs {
                                println!("  RX SC {:016x}:", rxsc.sci);
                                for sa in &rxsc.sas {
                                    println!("    SA {}: active={}", sa.an, sa.active);
                                }
                            }
                        }
                        Err(e) => println!("  Error: {}", e),
                    }
                    println!();
                }
            }
        }
        Err(e) => {
            println!("MACsec GENL not available: {}\n", e);
            println!("Load MACsec module with: sudo modprobe macsec");
            println!();
        }
    }

    // Example MACsec configurations
    println!("=== MACsec Configuration Examples ===\n");

    println!("--- Create MACsec interface ---");
    println!(
        r#"
    # Create MACsec interface over eth0
    sudo ip link add macsec0 link eth0 type macsec

    # With specific options
    sudo ip link add macsec0 link eth0 type macsec \
        sci 0x0011223344550001 \
        encrypt on

    sudo ip link set macsec0 up
"#
    );

    println!("--- Query MACsec device ---");
    println!(
        r#"
    use nlink::netlink::{{Connection, Macsec}};

    let conn = Connection::<Macsec>::new_async().await?;

    // Get device information by name (resolved via netlink)
    let device = conn.get_device("macsec0").await?;
    println!("SCI: {:016x}", device.sci);
    println!("Cipher: {:?}", device.cipher_suite);
    println!("Encoding SA: {}", device.encoding_sa);

    // List TX SAs
    for sa in &device.tx_sc.sas {
        println!("TX SA {}: active={}", sa.an, sa.active);
    }

    // List RX SCs and SAs
    for rxsc in &device.rx_scs {
        println!("RX SC {:016x}:", rxsc.sci);
        for sa in &rxsc.sas {
            println!("  SA {}: active={}", sa.an, sa.active);
        }
    }
"#
    );

    println!("--- Add TX SA ---");
    println!(
        r#"
    use nlink::netlink::genl::macsec::MacsecSaBuilder;

    // Add TX SA with key (AN 0-3)
    let key = [0u8; 16];  // 128-bit key for GCM-AES-128
    conn.add_tx_sa("macsec0",
        MacsecSaBuilder::new(0)  // AN (Association Number)
            .key(&key)
            .pn(1)              // Initial packet number
            .active(true)
    ).await?;
"#
    );

    println!("--- Update TX SA ---");
    println!(
        r#"
    // Activate/deactivate SA
    conn.update_tx_sa("macsec0",
        MacsecSaBuilder::new(0)
            .active(false)  // Deactivate
    ).await?;

    // Update packet number
    conn.update_tx_sa("macsec0",
        MacsecSaBuilder::new(0)
            .pn(1000000)
    ).await?;
"#
    );

    println!("--- Add RX SC (peer) ---");
    println!(
        r#"
    // Add RX SC for a peer (using their SCI)
    let peer_sci = 0x001122334455_0001u64;  // MAC + port
    conn.add_rx_sc("macsec0", peer_sci).await?;

    // Add RX SA for the peer
    let peer_key = [0u8; 16];
    conn.add_rx_sa("macsec0", peer_sci,
        MacsecSaBuilder::new(0)
            .key(&peer_key)
            .pn(1)
            .active(true)
    ).await?;
"#
    );

    println!("--- Delete SAs and SCs ---");
    println!(
        r#"
    // Delete TX SA
    conn.del_tx_sa("macsec0", 0).await?;

    // Delete RX SA
    conn.del_rx_sa("macsec0", peer_sci, 0).await?;

    // Delete RX SC
    conn.del_rx_sc("macsec0", peer_sci).await?;
"#
    );

    println!("=== MACsec Key Management ===\n");
    println!("MACsec typically uses:");
    println!("- Pre-shared keys (PSK) for simple deployments");
    println!("- MKA (MACsec Key Agreement) with 802.1X for enterprise");
    println!();
    println!("Key sizes:");
    println!("- GCM-AES-128: 16-byte key");
    println!("- GCM-AES-256: 32-byte key");
    println!("- GCM-AES-XPN-128: 16-byte key (extended PN)");
    println!("- GCM-AES-XPN-256: 32-byte key (extended PN)");
    println!();

    Ok(())
}
