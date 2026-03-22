//! Devlink device management via Generic Netlink.
//!
//! Demonstrates listing devices, querying firmware info,
//! health reporters, and ports.
//!
//! Run with: cargo run -p nlink --example genl_devlink
//!
//! Note: Requires a NIC with devlink support (mlx5, ice, bnxt, etc.).

use nlink::netlink::{Connection, Devlink};

#[tokio::main]
async fn main() -> nlink::netlink::Result<()> {
    let conn = match Connection::<Devlink>::new_async().await {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("Failed to connect to devlink: {}", e);
            eprintln!("Make sure devlink-capable drivers are loaded.");
            return Ok(());
        }
    };

    // List devices
    println!("=== Devlink Devices ===\n");
    let devices = conn.get_devices().await?;

    if devices.is_empty() {
        println!("No devlink devices found.");
        println!("Devlink requires supported NIC drivers (mlx5, ice, bnxt, etc.).");
        return Ok(());
    }

    for dev in &devices {
        println!("  {}", dev.path());
    }

    // Get info for each device
    for dev in &devices {
        println!("\n=== {} ===\n", dev.path());

        match conn.get_device_info(&dev.bus, &dev.device).await {
            Ok(info) => {
                println!("  Driver: {}", info.driver);
                if !info.versions_running.is_empty() {
                    println!("  Versions:");
                    for v in &info.versions_running {
                        println!("    {}: {}", v.name, v.value);
                    }
                }
                if info.has_pending_update() {
                    println!("  *** Pending firmware update! ***");
                }
            }
            Err(e) => println!("  Could not get info: {}", e),
        }

        // List ports
        match conn.get_ports().await {
            Ok(ports) => {
                let dev_ports: Vec<_> = ports
                    .iter()
                    .filter(|p| p.bus == dev.bus && p.device == dev.device)
                    .collect();
                if !dev_ports.is_empty() {
                    println!("  Ports:");
                    for port in &dev_ports {
                        println!(
                            "    {} flavour={:?} netdev={:?}",
                            port.path(),
                            port.flavour,
                            port.netdev_name
                        );
                    }
                }
            }
            Err(e) => println!("  Could not list ports: {}", e),
        }

        // Health reporters
        match conn.get_health_reporters(&dev.bus, &dev.device).await {
            Ok(reporters) if !reporters.is_empty() => {
                println!("  Health reporters:");
                for r in &reporters {
                    println!(
                        "    {}: state={:?} errors={}",
                        r.name, r.state, r.error_count
                    );
                }
            }
            Ok(_) => {}
            Err(e) => println!("  Could not list health reporters: {}", e),
        }
    }

    Ok(())
}
