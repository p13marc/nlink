//! Printable implementation for LinkMessage.

use std::io::Write;

use rip_netlink::messages::LinkMessage;

use crate::{OutputOptions, Printable};

impl Printable for LinkMessage {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> std::io::Result<()> {
        let name = self.name.as_deref().unwrap_or("?");

        // Build flags string, adding NO-CARRIER if carrier is false
        let mut flags = rip_lib::names::format_link_flags(self.flags());
        if let Some(false) = self.carrier
            && !self.is_loopback()
        {
            flags = format!("NO-CARRIER,{}", flags);
        }

        let mtu = self.mtu.unwrap_or(0);
        let qdisc = self.qdisc.as_deref().unwrap_or("noqueue");
        let operstate = self.operstate.map(|s| s.name()).unwrap_or("UNKNOWN");

        // Line 1: index, name, flags, mtu, qdisc, state, group, qlen
        write!(
            w,
            "{}: {}: <{}> mtu {} qdisc {} state {}",
            self.ifindex(),
            name,
            flags,
            mtu,
            qdisc,
            operstate
        )?;

        if let Some(group) = self.group {
            write!(w, " group {}", group_name(group))?;
        }

        if let Some(qlen) = self.txqlen {
            write!(w, " qlen {}", qlen)?;
        }

        if let Some(master) = self.master
            && let Ok(master_name) = rip_lib::ifname::index_to_name(master)
        {
            write!(w, " master {}", master_name)?;
        }

        writeln!(w)?;

        // Line 2: link type, address
        write!(w, "    link/{}", link_type_name(self.header.ifi_type))?;
        if let Some(ref addr) = self.mac_address() {
            write!(w, " {}", addr)?;
        }
        if let Some(ref brd) = self.broadcast
            && brd.len() == 6
        {
            write!(
                w,
                " brd {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                brd[0], brd[1], brd[2], brd[3], brd[4], brd[5]
            )?;
        }
        // Show permanent address if different from current
        if let Some(ref perm) = self.perm_address {
            let perm_mac = if perm.len() == 6 {
                Some(format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    perm[0], perm[1], perm[2], perm[3], perm[4], perm[5]
                ))
            } else {
                None
            };
            if perm_mac.as_ref() != self.mac_address().as_ref()
                && let Some(ref perm_str) = perm_mac
            {
                write!(w, " permaddr {}", perm_str)?;
            }
        }
        writeln!(w)?;

        Ok(())
    }

    fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "ifindex": self.ifindex(),
            "ifname": self.name.as_deref().unwrap_or(""),
            "flags": rip_lib::names::format_link_flags(self.flags()),
            "mtu": self.mtu.unwrap_or(0),
            "qdisc": self.qdisc.as_deref().unwrap_or(""),
            "operstate": self.operstate.map(|s| s.name()).unwrap_or("UNKNOWN"),
            "link_type": link_type_name(self.header.ifi_type),
        });

        if let Some(ref addr) = self.mac_address() {
            obj["address"] = serde_json::json!(addr);
        }
        if let Some(master) = self.master {
            obj["master"] = serde_json::json!(master);
        }
        if let Some(ref info) = self.link_info
            && let Some(ref kind) = info.kind
        {
            obj["link_kind"] = serde_json::json!(kind);
        }
        if let Some(txqlen) = self.txqlen {
            obj["txqlen"] = serde_json::json!(txqlen);
        }
        if let Some(group) = self.group {
            obj["group"] = serde_json::json!(group_name(group));
        }

        obj
    }
}

fn group_name(group: u32) -> String {
    if group == 0 {
        "default".to_string()
    } else {
        format!("{}", group)
    }
}

fn link_type_name(ifi_type: u16) -> &'static str {
    match ifi_type {
        1 => "ether",      // ARPHRD_ETHER
        772 => "loopback", // ARPHRD_LOOPBACK
        776 => "sit",      // ARPHRD_SIT
        778 => "gre",      // ARPHRD_IPGRE
        823 => "ip6gre",   // ARPHRD_IP6GRE
        65534 => "none",   // ARPHRD_NONE
        _ => "unknown",
    }
}
