//! ip maddress command implementation.
//!
//! Multicast address management. Shows link-layer and IP multicast addresses
//! that are subscribed on interfaces.

use clap::{Args, Subcommand};
use nlink::netlink::Result;
use nlink::output::{OutputFormat, OutputOptions, Printable, print_all};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Args)]
pub struct MaddressCmd {
    #[command(subcommand)]
    action: Option<MaddressAction>,
}

#[derive(Subcommand)]
enum MaddressAction {
    /// Show multicast addresses.
    Show {
        /// Interface name.
        dev: Option<String>,
    },
}

/// Multicast address information.
#[derive(Debug)]
struct McastInfo {
    ifindex: u32,
    ifname: String,
    link_mcast: Vec<String>,
    inet_mcast: Vec<Ipv4Addr>,
    inet6_mcast: Vec<Ipv6Addr>,
}

impl Printable for McastInfo {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> std::io::Result<()> {
        writeln!(w, "{}: {}", self.ifindex, self.ifname)?;

        // Link-layer multicast addresses
        for addr in &self.link_mcast {
            writeln!(w, "\tlink  {}", addr)?;
        }

        // IPv4 multicast addresses
        for addr in &self.inet_mcast {
            writeln!(w, "\tinet  {} users 1", addr)?;
        }

        // IPv6 multicast addresses
        for addr in &self.inet6_mcast {
            writeln!(w, "\tinet6 {} users 1", addr)?;
        }

        Ok(())
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ifindex": self.ifindex,
            "ifname": self.ifname,
            "link": self.link_mcast,
            "inet": self.inet_mcast.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            "inet6": self.inet6_mcast.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        })
    }
}

impl MaddressCmd {
    pub async fn run(
        &self,
        format: OutputFormat,
        opts: &OutputOptions,
        family: Option<u8>,
    ) -> Result<()> {
        let dev = match &self.action {
            Some(MaddressAction::Show { dev }) => dev.as_deref(),
            None => None,
        };
        self.show(dev, format, opts, family).await
    }

    async fn show(
        &self,
        dev: Option<&str>,
        format: OutputFormat,
        opts: &OutputOptions,
        family: Option<u8>,
    ) -> Result<()> {
        let mut interfaces: HashMap<String, McastInfo> = HashMap::new();

        // Get interface index mapping
        let if_indices = get_interface_indices()?;

        // Filter by device if specified
        let filter_dev = dev.map(|s| s.to_string());

        // Read link-layer multicast from /proc/net/dev_mcast
        if (family.is_none() || family == Some(libc::AF_PACKET as u8))
            && let Ok(content) = fs::read_to_string("/proc/net/dev_mcast")
        {
            for line in content.lines() {
                // Format: ifindex ifname refcount global_use address
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let ifname = parts[1].to_string();
                    if let Some(ref f) = filter_dev
                        && &ifname != f
                    {
                        continue;
                    }
                    let addr = parts[4].to_string();
                    let formatted = format_mac_from_hex(&addr);

                    let entry = interfaces
                        .entry(ifname.clone())
                        .or_insert_with(|| McastInfo {
                            ifindex: if_indices.get(&ifname).copied().unwrap_or(0),
                            ifname: ifname.clone(),
                            link_mcast: Vec::new(),
                            inet_mcast: Vec::new(),
                            inet6_mcast: Vec::new(),
                        });
                    if !entry.link_mcast.contains(&formatted) {
                        entry.link_mcast.push(formatted);
                    }
                }
            }
        }

        // Read IPv4 multicast from /proc/net/igmp
        if (family.is_none() || family == Some(libc::AF_INET as u8))
            && let Ok(content) = fs::read_to_string("/proc/net/igmp")
        {
            let mut current_if: Option<String> = None;
            for line in content.lines() {
                let line = line.trim();
                // Interface line: "Idx Device ..."
                if line.starts_with("Idx") {
                    continue;
                }
                // Interface line starts with a number
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                // Check if it's an interface line (starts with index number)
                if let Ok(_idx) = parts[0].parse::<u32>() {
                    if parts.len() >= 2 {
                        let ifname = parts[1].trim_end_matches(':').to_string();
                        if let Some(ref f) = filter_dev
                            && &ifname != f
                        {
                            current_if = None;
                            continue;
                        }
                        current_if = Some(ifname);
                    }
                } else if let Some(ref ifname) = current_if {
                    // Multicast group line
                    if let Some(addr) = parse_igmp_addr(parts[0]) {
                        let entry = interfaces
                            .entry(ifname.clone())
                            .or_insert_with(|| McastInfo {
                                ifindex: if_indices.get(ifname).copied().unwrap_or(0),
                                ifname: ifname.clone(),
                                link_mcast: Vec::new(),
                                inet_mcast: Vec::new(),
                                inet6_mcast: Vec::new(),
                            });
                        if !entry.inet_mcast.contains(&addr) {
                            entry.inet_mcast.push(addr);
                        }
                    }
                }
            }
        }

        // Read IPv6 multicast from /proc/net/igmp6
        if (family.is_none() || family == Some(libc::AF_INET6 as u8))
            && let Ok(content) = fs::read_to_string("/proc/net/igmp6")
        {
            for line in content.lines() {
                // Format: ifindex ifname address refcount flags timer
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let ifname = parts[1].to_string();
                    if let Some(ref f) = filter_dev
                        && &ifname != f
                    {
                        continue;
                    }
                    if let Some(addr) = parse_ipv6_hex(parts[2]) {
                        let entry = interfaces
                            .entry(ifname.clone())
                            .or_insert_with(|| McastInfo {
                                ifindex: if_indices.get(&ifname).copied().unwrap_or(0),
                                ifname: ifname.clone(),
                                link_mcast: Vec::new(),
                                inet_mcast: Vec::new(),
                                inet6_mcast: Vec::new(),
                            });
                        if !entry.inet6_mcast.contains(&addr) {
                            entry.inet6_mcast.push(addr);
                        }
                    }
                }
            }
        }

        // Sort by interface index
        let mut mcast_list: Vec<McastInfo> = interfaces.into_values().collect();
        mcast_list.sort_by_key(|m| m.ifindex);

        print_all(&mcast_list, format, opts)?;

        Ok(())
    }
}

/// Get interface name to index mapping.
fn get_interface_indices() -> Result<HashMap<String, u32>> {
    let mut indices = HashMap::new();

    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let ifname = entry.file_name().to_string_lossy().to_string();
            let index_path = entry.path().join("ifindex");
            if let Ok(content) = fs::read_to_string(&index_path)
                && let Ok(idx) = content.trim().parse::<u32>()
            {
                indices.insert(ifname, idx);
            }
        }
    }

    Ok(indices)
}

/// Format a hex MAC address string (e.g., "01005e000001") to colon-separated format.
fn format_mac_from_hex(hex: &str) -> String {
    let bytes: Vec<String> = hex
        .as_bytes()
        .chunks(2)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or("00").to_string())
        .collect();
    bytes.join(":")
}

/// Parse an IGMP address (hex format, big-endian).
fn parse_igmp_addr(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let val = u32::from_str_radix(hex, 16).ok()?;
    // IGMP stores in little-endian
    Some(Ipv4Addr::from(val.swap_bytes()))
}

/// Parse an IPv6 address from hex string.
fn parse_ipv6_hex(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        if let Ok(s) = std::str::from_utf8(chunk)
            && let Ok(b) = u8::from_str_radix(s, 16)
        {
            octets[i] = b;
        }
    }
    Some(Ipv6Addr::from(octets))
}
