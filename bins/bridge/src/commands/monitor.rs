//! `bridge monitor` command implementation.
//!
//! Streams bridge forwarding-database (FDB) changes as the kernel learns,
//! ages, or removes them. FDB entries arrive as `AF_BRIDGE` neighbour
//! notifications on the `RTNLGRP_NEIGH` multicast group, surfaced by the
//! library as `NetworkEvent::NewFdb` / `NetworkEvent::DelFdb`.
//!
//! Note: multicast-database (MDB) monitoring is not wired here yet — the
//! library's event layer does not model `RTM_*MDB` notifications. When it
//! does, this command gains an `mdb` object filter.

use std::collections::HashMap;

use clap::Args;
use nlink::{
    netlink::{Connection, Result, Route, RtnetlinkGroup, fdb::FdbEntry},
    output::{OutputFormat, OutputOptions},
};
use tokio_stream::StreamExt;

#[derive(Args)]
pub struct MonitorCmd {
    /// Prefix each event line with a wall-clock timestamp.
    #[arg(short = 't', long)]
    timestamp: bool,
}

impl MonitorCmd {
    pub async fn run(
        &self,
        conn: &Connection<Route>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        conn.subscribe(&[RtnetlinkGroup::Neigh])?;

        // Resolve ifindex -> name once up front. New interfaces that appear
        // mid-stream fall back to `if<N>`.
        let names = conn.get_interface_names().await.unwrap_or_default();

        if format == OutputFormat::Text {
            eprintln!("Monitoring bridge FDB events (Ctrl+C to stop)...");
        }

        let mut events = conn.events().await;
        while let Some(result) = events.next().await {
            let event = result?;
            let action = event.action(); // "new" / "del"
            let Some(fdb) = event.into_fdb() else {
                continue;
            };
            match format {
                OutputFormat::Json => print_json(&fdb, action, &names, opts),
                OutputFormat::Text => print_text(&fdb, action, &names, self.timestamp),
            }
        }

        Ok(())
    }
}

fn dev_name(names: &HashMap<u32, String>, ifindex: u32) -> String {
    names
        .get(&ifindex)
        .cloned()
        .unwrap_or_else(|| format!("if{ifindex}"))
}

fn print_text(fdb: &FdbEntry, action: &str, names: &HashMap<u32, String>, timestamp: bool) {
    // `new`/`del` -> the iproute2-style `<nothing>`/`Deleted ` prefix.
    let prefix = if action == "del" { "Deleted " } else { "" };

    let mut line = format!(
        "{prefix}{} dev {}",
        fdb.mac_str(),
        dev_name(names, fdb.ifindex())
    );
    if let Some(master_idx) = fdb.master() {
        line.push_str(&format!(" master {}", dev_name(names, master_idx)));
    }
    if let Some(vlan) = fdb.vlan() {
        line.push_str(&format!(" vlan {vlan}"));
    }
    if let Some(dst) = fdb.dst() {
        line.push_str(&format!(" dst {dst}"));
    }
    if let Some(vni) = fdb.vni() {
        line.push_str(&format!(" vni {vni}"));
    }
    if fdb.is_permanent() {
        line.push_str(" permanent");
    }
    if fdb.is_extern_learn() {
        line.push_str(" extern_learn");
    }

    if timestamp {
        // SystemTime avoids a chrono dependency; seconds since the epoch is
        // enough to correlate events in a POC monitor.
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        println!("[{secs}] {line}");
    } else {
        println!("{line}");
    }
}

fn print_json(fdb: &FdbEntry, action: &str, names: &HashMap<u32, String>, opts: &OutputOptions) {
    let mut obj = serde_json::json!({
        "event": action,
        "mac": fdb.mac_str(),
        "ifindex": fdb.ifindex(),
        "dev": dev_name(names, fdb.ifindex()),
        "state": if fdb.is_permanent() { "permanent" } else { "dynamic" },
    });
    if let Some(master_idx) = fdb.master() {
        obj["master_ifindex"] = serde_json::json!(master_idx);
        obj["master"] = serde_json::json!(dev_name(names, master_idx));
    }
    if let Some(vlan) = fdb.vlan() {
        obj["vlan"] = serde_json::json!(vlan);
    }
    if let Some(dst) = fdb.dst() {
        obj["dst"] = serde_json::json!(dst.to_string());
    }
    if let Some(vni) = fdb.vni() {
        obj["vni"] = serde_json::json!(vni);
    }
    if fdb.is_extern_learn() {
        obj["extern_learn"] = serde_json::json!(true);
    }

    let out = if opts.pretty {
        serde_json::to_string_pretty(&obj)
    } else {
        serde_json::to_string(&obj)
    };
    match out {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("bridge monitor: JSON serialization failed: {e}"),
    }
}
