//! Printable implementation for RouteMessage.

use std::io::Write;

use crate::netlink::messages::RouteMessage;
use crate::netlink::types::route::{RouteProtocol, RouteScope};

use crate::output::{OutputOptions, Printable};

impl Printable for RouteMessage {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> std::io::Result<()> {
        // Destination
        if let Some(ref dst) = self.destination {
            write!(w, "{}/{}", dst, self.dst_len())?;
        } else {
            write!(w, "default")?;
        }

        // Gateway
        if let Some(ref gw) = self.gateway {
            write!(w, " via {}", gw)?;
        }

        // Device
        if let Some(oif) = self.oif {
            let dev = crate::util::get_ifname_or_index(oif as i32);
            write!(w, " dev {}", dev)?;
        }

        // Protocol
        let protocol = self.protocol();
        if protocol != RouteProtocol::Unspec {
            write!(w, " proto {}", protocol.name())?;
        }

        // Scope
        let scope = self.scope();
        if scope != RouteScope::Universe {
            write!(w, " scope {}", scope.name())?;
        }

        // Preferred source
        if let Some(ref src) = self.prefsrc {
            write!(w, " src {}", src)?;
        }

        // Metric
        if let Some(prio) = self.priority {
            write!(w, " metric {}", prio)?;
        }

        writeln!(w)?;

        Ok(())
    }

    fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "type": self.route_type().name(),
            "protocol": self.protocol().name(),
            "scope": self.scope().name(),
            "table": crate::util::names::table_name(self.table_id()),
        });

        if let Some(ref dst) = self.destination {
            obj["dst"] = serde_json::json!(format!("{}/{}", dst, self.dst_len()));
        } else {
            obj["dst"] = serde_json::json!("default");
        }

        if let Some(ref gw) = self.gateway {
            obj["gateway"] = serde_json::json!(gw.to_string());
        }

        if let Some(oif) = self.oif {
            let dev = crate::util::get_ifname_or_index(oif as i32);
            obj["dev"] = serde_json::json!(dev);
        }

        if let Some(ref src) = self.prefsrc {
            obj["prefsrc"] = serde_json::json!(src.to_string());
        }

        if let Some(prio) = self.priority {
            obj["metric"] = serde_json::json!(prio);
        }

        obj
    }
}
