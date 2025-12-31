//! Printable implementation for TcMessage.

use std::io::Write;

use crate::netlink::messages::TcMessage;
use crate::netlink::types::tc::tc_handle;

use crate::output::{OutputOptions, Printable};

impl Printable for TcMessage {
    fn print_text<W: Write>(&self, w: &mut W, opts: &OutputOptions) -> std::io::Result<()> {
        let dev = crate::util::get_ifname_or_index(self.ifindex());

        write!(
            w,
            "qdisc {} {} dev {} ",
            self.kind().unwrap_or(""),
            tc_handle::format(self.handle()),
            dev
        )?;

        if self.parent() == tc_handle::ROOT {
            write!(w, "root ")?;
        } else if self.parent() == tc_handle::INGRESS {
            write!(w, "ingress ")?;
        } else if self.parent() != 0 {
            write!(w, "parent {} ", tc_handle::format(self.parent()))?;
        }

        write!(w, "refcnt 2")?; // placeholder

        writeln!(w)?;

        if opts.stats {
            writeln!(
                w,
                " Sent {} bytes {} pkt (dropped {}, overlimits {} requeues {})",
                self.bytes(),
                self.packets(),
                self.drops(),
                self.overlimits(),
                self.requeues()
            )?;
            writeln!(w, " backlog {}b {}p", self.backlog(), self.qlen())?;
        }

        Ok(())
    }

    fn to_json(&self) -> serde_json::Value {
        let dev = crate::util::get_ifname_or_index(self.ifindex());

        serde_json::json!({
            "dev": dev,
            "kind": self.kind().unwrap_or(""),
            "handle": tc_handle::format(self.handle()),
            "parent": tc_handle::format(self.parent()),
            "bytes": self.bytes(),
            "packets": self.packets(),
            "drops": self.drops(),
            "overlimits": self.overlimits(),
            "requeues": self.requeues(),
            "qlen": self.qlen(),
            "backlog": self.backlog(),
        })
    }
}
