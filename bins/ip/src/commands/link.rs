//! ip link command implementation.

use clap::{Args, Subcommand};
use rip_netlink::attr::{AttrIter, get};
use rip_netlink::message::{NLMSG_HDRLEN, NlMsgHdr, NlMsgType};
use rip_netlink::types::link::{IfInfoMsg, IflaAttr, IflaInfo, OperState};
use rip_netlink::{Connection, Result, connection::dump_request};
use rip_output::{OutputFormat, OutputOptions};
use std::io::{self, Write};

use super::link_add::{LinkAddType, add_link};

#[derive(Args)]
pub struct LinkCmd {
    #[command(subcommand)]
    action: Option<LinkAction>,
}

#[derive(Subcommand)]
enum LinkAction {
    /// Show link information.
    Show {
        /// Interface name or index.
        dev: Option<String>,
    },

    /// Add a virtual link.
    Add {
        #[command(subcommand)]
        link_type: LinkAddType,
    },

    /// Delete a link.
    Del {
        /// Interface name.
        dev: String,
    },

    /// Set link attributes.
    Set {
        /// Interface name.
        dev: String,

        /// Bring interface up.
        #[arg(long)]
        up: bool,

        /// Bring interface down.
        #[arg(long)]
        down: bool,

        /// Set MTU.
        #[arg(long)]
        mtu: Option<u32>,

        /// Set interface name.
        #[arg(long)]
        name: Option<String>,

        /// Set TX queue length.
        #[arg(long)]
        txqlen: Option<u32>,

        /// Set MAC address.
        #[arg(long)]
        address: Option<String>,

        /// Set master device.
        #[arg(long)]
        master: Option<String>,

        /// Remove from master device.
        #[arg(long)]
        nomaster: bool,
    },
}

impl LinkCmd {
    pub async fn run(
        self,
        conn: &Connection,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match self.action.unwrap_or(LinkAction::Show { dev: None }) {
            LinkAction::Show { dev } => Self::show(conn, dev.as_deref(), format, opts).await,
            LinkAction::Add { link_type } => add_link(conn, link_type).await,
            LinkAction::Del { dev } => Self::del(conn, &dev).await,
            LinkAction::Set {
                dev,
                up,
                down,
                mtu,
                name,
                txqlen,
                address,
                master,
                nomaster,
            } => {
                Self::set(
                    conn, &dev, up, down, mtu, name, txqlen, address, master, nomaster,
                )
                .await
            }
        }
    }

    async fn show(
        conn: &Connection,
        dev: Option<&str>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        // Build request
        let mut builder = dump_request(NlMsgType::RTM_GETLINK);
        let ifinfo = IfInfoMsg::new();
        builder.append(&ifinfo);

        // Send and receive
        let responses = conn.dump(builder).await?;

        let mut stdout = io::stdout().lock();
        let mut links = Vec::new();

        for response in &responses {
            if let Some(link) = parse_link_message(response)? {
                // Filter by device name if specified
                if let Some(filter_dev) = dev {
                    if link.name != filter_dev {
                        continue;
                    }
                }
                links.push(link);
            }
        }

        match format {
            OutputFormat::Text => {
                for link in &links {
                    print_link_text(&mut stdout, link, opts)?;
                }
            }
            OutputFormat::Json => {
                let json: Vec<_> = links.iter().map(|l| l.to_json()).collect();
                if opts.pretty {
                    serde_json::to_writer_pretty(&mut stdout, &json)?;
                } else {
                    serde_json::to_writer(&mut stdout, &json)?;
                }
                writeln!(stdout)?;
            }
        }

        Ok(())
    }

    async fn del(conn: &Connection, dev: &str) -> Result<()> {
        use rip_lib::ifname::name_to_index;
        use rip_netlink::connection::ack_request;

        let ifindex = name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

        let ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        let mut builder = ack_request(NlMsgType::RTM_DELLINK);
        builder.append(&ifinfo);

        conn.request_ack(builder).await?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn set(
        conn: &Connection,
        dev: &str,
        up: bool,
        down: bool,
        mtu: Option<u32>,
        name: Option<String>,
        txqlen: Option<u32>,
        address: Option<String>,
        master: Option<String>,
        nomaster: bool,
    ) -> Result<()> {
        use rip_lib::ifname::name_to_index;
        use rip_netlink::connection::ack_request;
        use rip_netlink::types::link::iff;

        let ifindex = name_to_index(dev).map_err(|e| {
            rip_netlink::Error::InvalidMessage(format!("interface not found: {}", e))
        })?;

        let mut ifinfo = IfInfoMsg::new().with_index(ifindex as i32);

        // Set flags
        if up {
            ifinfo.ifi_flags = iff::UP;
            ifinfo.ifi_change = iff::UP;
        } else if down {
            ifinfo.ifi_flags = 0;
            ifinfo.ifi_change = iff::UP;
        }

        let mut builder = ack_request(NlMsgType::RTM_SETLINK);
        builder.append(&ifinfo);

        // Add MTU if specified
        if let Some(mtu_val) = mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu_val);
        }

        // Add new name if specified
        if let Some(new_name) = name {
            builder.append_attr_str(IflaAttr::Ifname as u16, &new_name);
        }

        // Add TX queue length if specified
        if let Some(qlen) = txqlen {
            builder.append_attr_u32(IflaAttr::TxqLen as u16, qlen);
        }

        // Add MAC address if specified
        if let Some(addr_str) = address {
            let mac = rip_lib::addr::parse_mac(&addr_str).map_err(|e| {
                rip_netlink::Error::InvalidMessage(format!("invalid MAC address: {}", e))
            })?;
            builder.append_attr(IflaAttr::Address as u16, &mac);
        }

        // Set or clear master
        if let Some(master_name) = master {
            let master_idx = name_to_index(&master_name).map_err(|e| {
                rip_netlink::Error::InvalidMessage(format!("master device not found: {}", e))
            })?;
            builder.append_attr_u32(IflaAttr::Master as u16, master_idx);
        } else if nomaster {
            builder.append_attr_u32(IflaAttr::Master as u16, 0);
        }

        conn.request_ack(builder).await?;

        Ok(())
    }
}

/// Parsed link information.
#[derive(Debug)]
struct LinkInfo {
    index: i32,
    name: String,
    flags: u32,
    mtu: u32,
    qdisc: String,
    operstate: OperState,
    link_type: String,
    address: Option<String>,
    broadcast: Option<String>,
    master: Option<i32>,
    link_kind: Option<String>,
    txqlen: Option<u32>,
    group: Option<u32>,
    carrier: Option<u8>,
    perm_address: Option<String>,
    alt_names: Vec<String>,
}

impl LinkInfo {
    fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "ifindex": self.index,
            "ifname": self.name,
            "flags": rip_lib::names::format_link_flags(self.flags),
            "mtu": self.mtu,
            "qdisc": self.qdisc,
            "operstate": self.operstate.name(),
            "link_type": self.link_type,
        });

        if let Some(ref addr) = self.address {
            obj["address"] = serde_json::json!(addr);
        }
        if let Some(ref brd) = self.broadcast {
            obj["broadcast"] = serde_json::json!(brd);
        }
        if let Some(master) = self.master {
            obj["master"] = serde_json::json!(master);
        }
        if let Some(ref kind) = self.link_kind {
            obj["link_kind"] = serde_json::json!(kind);
        }
        if let Some(txqlen) = self.txqlen {
            obj["txqlen"] = serde_json::json!(txqlen);
        }
        if let Some(group) = self.group {
            obj["group"] = serde_json::json!(group_name(group));
        }
        if let Some(ref perm) = self.perm_address {
            obj["permaddr"] = serde_json::json!(perm);
        }
        if !self.alt_names.is_empty() {
            obj["altnames"] = serde_json::json!(self.alt_names);
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

fn parse_link_message(data: &[u8]) -> Result<Option<LinkInfo>> {
    if data.len() < NLMSG_HDRLEN + IfInfoMsg::SIZE {
        return Ok(None);
    }

    let header = NlMsgHdr::from_bytes(data)?;

    // Skip non-link messages
    if header.nlmsg_type != NlMsgType::RTM_NEWLINK {
        return Ok(None);
    }

    let payload = &data[NLMSG_HDRLEN..];
    let ifinfo = IfInfoMsg::from_bytes(payload)?;
    let attrs_data = &payload[IfInfoMsg::SIZE..];

    let mut name = String::new();
    let mut mtu = 0u32;
    let mut qdisc = String::new();
    let mut operstate = OperState::Unknown;
    let mut address = None;
    let mut broadcast = None;
    let mut master = None;
    let mut link_kind = None;
    let mut txqlen = None;
    let mut group = None;
    let mut carrier = None;
    let mut perm_address = None;
    let mut alt_names = Vec::new();

    for (attr_type, attr_data) in AttrIter::new(attrs_data) {
        match IflaAttr::from(attr_type) {
            IflaAttr::Ifname => {
                name = get::string(attr_data).unwrap_or("").to_string();
            }
            IflaAttr::Mtu => {
                mtu = get::u32_ne(attr_data).unwrap_or(0);
            }
            IflaAttr::Qdisc => {
                qdisc = get::string(attr_data).unwrap_or("").to_string();
            }
            IflaAttr::Operstate => {
                operstate = OperState::from(get::u8(attr_data).unwrap_or(0));
            }
            IflaAttr::Address => {
                address = Some(rip_lib::addr::format_mac(attr_data));
            }
            IflaAttr::Broadcast => {
                broadcast = Some(rip_lib::addr::format_mac(attr_data));
            }
            IflaAttr::Master => {
                master = Some(get::i32_ne(attr_data).unwrap_or(0));
            }
            IflaAttr::TxqLen => {
                txqlen = Some(get::u32_ne(attr_data).unwrap_or(0));
            }
            IflaAttr::Group => {
                group = Some(get::u32_ne(attr_data).unwrap_or(0));
            }
            IflaAttr::Carrier => {
                carrier = Some(get::u8(attr_data).unwrap_or(0));
            }
            IflaAttr::PermAddress => {
                perm_address = Some(rip_lib::addr::format_mac(attr_data));
            }
            IflaAttr::AltIfname => {
                if let Ok(s) = get::string(attr_data) {
                    alt_names.push(s.to_string());
                }
            }
            IflaAttr::PropList => {
                // Parse nested property list for altnames
                for (prop_type, prop_data) in AttrIter::new(attr_data) {
                    if IflaAttr::from(prop_type) == IflaAttr::AltIfname {
                        if let Ok(s) = get::string(prop_data) {
                            alt_names.push(s.to_string());
                        }
                    }
                }
            }
            IflaAttr::Linkinfo => {
                // Parse nested linkinfo
                for (info_type, info_data) in AttrIter::new(attr_data) {
                    if IflaInfo::from(info_type) == IflaInfo::Kind {
                        link_kind = Some(get::string(info_data).unwrap_or("").to_string());
                    }
                }
            }
            _ => {}
        }
    }

    // Determine link type from device type
    let link_type = match ifinfo.ifi_type {
        1 => "ether",      // ARPHRD_ETHER
        772 => "loopback", // ARPHRD_LOOPBACK
        _ => "unknown",
    }
    .to_string();

    Ok(Some(LinkInfo {
        index: ifinfo.ifi_index,
        name,
        flags: ifinfo.ifi_flags,
        mtu,
        qdisc,
        operstate,
        link_type,
        address,
        broadcast,
        master,
        link_kind,
        txqlen,
        group,
        carrier,
        perm_address,
        alt_names,
    }))
}

fn print_link_text<W: Write>(w: &mut W, link: &LinkInfo, _opts: &OutputOptions) -> io::Result<()> {
    // Build flags string, adding NO-CARRIER if carrier is 0
    let mut flags = rip_lib::names::format_link_flags(link.flags);
    if let Some(carrier) = link.carrier {
        if carrier == 0 && !flags.contains("LOOPBACK") {
            // Insert NO-CARRIER at the beginning
            flags = format!("NO-CARRIER,{}", flags);
        }
    }

    // Line 1: index, name, flags, mtu, qdisc, state, group, qlen
    write!(
        w,
        "{}: {}: <{}> mtu {} qdisc {} state {}",
        link.index,
        link.name,
        flags,
        link.mtu,
        link.qdisc,
        link.operstate.name()
    )?;

    if let Some(group) = link.group {
        write!(w, " group {}", group_name(group))?;
    }

    if let Some(qlen) = link.txqlen {
        write!(w, " qlen {}", qlen)?;
    }

    if let Some(master) = link.master {
        if let Ok(master_name) = rip_lib::ifname::index_to_name(master as u32) {
            write!(w, " master {}", master_name)?;
        }
    }

    writeln!(w)?;

    // Line 2: link type, address
    write!(w, "    link/{}", link.link_type)?;
    if let Some(ref addr) = link.address {
        write!(w, " {}", addr)?;
    }
    if let Some(ref brd) = link.broadcast {
        write!(w, " brd {}", brd)?;
    }
    // Show permanent address if different from current
    if let Some(ref perm) = link.perm_address {
        if link.address.as_ref() != Some(perm) {
            write!(w, " permaddr {}", perm)?;
        }
    }
    writeln!(w)?;

    // Show alternate names
    for altname in &link.alt_names {
        writeln!(w, "    altname {}", altname)?;
    }

    Ok(())
}
