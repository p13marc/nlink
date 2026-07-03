//! Output formatting for ss command.

use std::{
    io::{self, Write},
    net::SocketAddr,
};

use nlink::{
    output::formatting::format_rate_bps,
    sockdiag::{InetSocket, SocketInfo, UnixSocket},
};

/// Display options for socket output.
pub struct DisplayOptions {
    /// Don't resolve service names.
    pub numeric: bool,
    /// Resolve host names.
    pub resolve: bool,
    /// Show extended info.
    pub extended: bool,
    /// Show memory info.
    pub memory: bool,
    /// Show TCP info.
    pub info: bool,
    /// Show timer info.
    pub options: bool,
    /// Show processes.
    pub processes: bool,
    /// Don't show header.
    pub no_header: bool,
    /// One socket per line.
    pub oneline: bool,
}

/// Print sockets in JSON format.
///
/// The JSON honors the same display flags as the text output: the
/// `tcp_info` block appears only with `-i`, `mem_info` only with `-m`,
/// the extended `interface`/`mark` fields only with `-e`, an active
/// `timer` only with `-o`, and the `process` array only with `-p`.
/// This keeps `-j` field-for-field consistent with the text columns
/// rather than dumping every captured attribute unconditionally.
pub fn print_json(sockets: &[SocketInfo], opts: &DisplayOptions) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    // -p/--processes: build the socket-inode → process map once, the
    // same way the text path does.
    let procs = if opts.processes {
        crate::procmap::build()
    } else {
        crate::procmap::ProcMap::new()
    };

    let json_sockets: Vec<_> = sockets
        .iter()
        .map(|s| match s {
            SocketInfo::Inet(inet) => inet_to_json(inet, opts, &procs),
            SocketInfo::Unix(unix) => unix_to_json(unix, opts, &procs),
            SocketInfo::Netlink(nl) => serde_json::json!({
                "netid": "nl",
                "protocol": nl.protocol_name(),
                "portid": nl.portid,
                "inode": nl.inode,
            }),
            SocketInfo::Packet(pkt) => serde_json::json!({
                "netid": pkt.netid(),
                "protocol": pkt.protocol_name(),
                "inode": pkt.inode,
            }),
        })
        .collect();

    serde_json::to_writer_pretty(&mut handle, &json_sockets)?;
    writeln!(handle)?;
    Ok(())
}

/// Render the processes holding a socket open as a JSON array, or
/// `None` when none are known. Mirrors `procmap::format_users` but in
/// structured form for `-j -p`.
fn procs_to_json(map: &crate::procmap::ProcMap, inode: u32) -> Option<serde_json::Value> {
    let procs = map.resolve(inode);
    if procs.is_empty() {
        return None;
    }
    let arr: Vec<_> = procs
        .iter()
        .map(|p| {
            serde_json::json!({
                "comm": p.comm,
                "pid": p.pid,
                "fd": p.fd,
            })
        })
        .collect();
    Some(serde_json::Value::Array(arr))
}

fn inet_to_json(
    sock: &InetSocket,
    opts: &DisplayOptions,
    procs: &crate::procmap::ProcMap,
) -> serde_json::Value {
    let mut json = serde_json::json!({
        "netid": sock.netid(),
        "state": sock.state.name(),
        "recv_q": sock.recv_q,
        "send_q": sock.send_q,
        "local": {
            "address": sock.local.ip().to_string(),
            "port": sock.local.port(),
        },
        "remote": {
            "address": sock.remote.ip().to_string(),
            "port": sock.remote.port(),
        },
        "uid": sock.uid,
        "inode": sock.inode,
    });

    // -o: active retransmission/keepalive timer.
    if opts.options
        && let Some(timer) = sock.timer.describe()
    {
        json["timer"] = serde_json::Value::String(timer);
    }

    // -e: extended fields (bound interface, firewall mark).
    if opts.extended {
        if sock.interface > 0 {
            json["interface"] = serde_json::Value::Number(sock.interface.into());
        }
        if let Some(mark) = sock.mark {
            json["mark"] = serde_json::Value::Number(mark.into());
        }
    }

    // -i: TCP info. The congestion algorithm rides along with it,
    // matching the text layout where `cong` prefixes the info segment.
    if opts.info
        && let Some(ref info) = sock.tcp_info
    {
        json["tcp_info"] = serde_json::json!({
            "rtt": info.rtt,
            "rttvar": info.rttvar,
            "snd_cwnd": info.snd_cwnd,
            "snd_ssthresh": info.snd_ssthresh,
            "rcv_space": info.rcv_space,
            "retrans": info.retrans,
            "lost": info.lost,
            "pacing_rate": info.pacing_rate,
            "delivery_rate": info.delivery_rate,
            "min_rtt": info.min_rtt,
        });
        if let Some(ref cong) = sock.congestion {
            json["congestion"] = serde_json::Value::String(cong.clone());
        }
    }

    // -m: socket memory info.
    if opts.memory
        && let Some(ref mem) = sock.mem_info
    {
        json["mem_info"] = serde_json::json!({
            "rmem_alloc": mem.rmem_alloc,
            "rcvbuf": mem.rcvbuf,
            "wmem_alloc": mem.wmem_alloc,
            "sndbuf": mem.sndbuf,
            "fwd_alloc": mem.fwd_alloc,
            "wmem_queued": mem.wmem_queued,
            "optmem": mem.optmem,
            "backlog": mem.backlog,
            "drops": mem.drops,
        });
    }

    // -p: owning processes.
    if opts.processes
        && let Some(p) = procs_to_json(procs, sock.inode)
    {
        json["process"] = p;
    }

    json
}

fn unix_to_json(
    sock: &UnixSocket,
    opts: &DisplayOptions,
    procs: &crate::procmap::ProcMap,
) -> serde_json::Value {
    let mut json = serde_json::json!({
        "netid": sock.netid(),
        "state": sock.state.name(),
        "inode": sock.inode,
    });

    if let Some(recv_q) = sock.recv_q {
        json["recv_q"] = serde_json::Value::Number(recv_q.into());
    }
    if let Some(send_q) = sock.send_q {
        json["send_q"] = serde_json::Value::Number(send_q.into());
    }

    let path = sock.name();
    if !path.is_empty() {
        json["path"] = serde_json::Value::String(path);
    }

    if let Some(peer) = sock.peer_inode {
        json["peer_inode"] = serde_json::Value::Number(peer.into());
    }

    if let Some(uid) = sock.uid {
        json["uid"] = serde_json::Value::Number(uid.into());
    }

    // -p: owning processes.
    if opts.processes
        && let Some(p) = procs_to_json(procs, sock.inode)
    {
        json["process"] = p;
    }

    json
}

/// Print sockets in text format.
pub fn print_text(sockets: &[SocketInfo], opts: &DisplayOptions) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    // -p/--processes: build the socket-inode → process map once.
    let procs = if opts.processes {
        crate::procmap::build()
    } else {
        crate::procmap::ProcMap::new()
    };

    if !opts.no_header {
        writeln!(
            handle,
            "{:<8} {:<12} {:>6} {:>6} {:>25} {:>25}",
            "Netid", "State", "Recv-Q", "Send-Q", "Local Address:Port", "Peer Address:Port"
        )?;
    }

    for sock in sockets {
        match sock {
            SocketInfo::Inet(inet) => print_inet_socket(&mut handle, inet, opts, &procs)?,
            SocketInfo::Unix(unix) => print_unix_socket(&mut handle, unix, opts, &procs)?,
            SocketInfo::Netlink(nl) => {
                writeln!(
                    handle,
                    "{:<8} {:<12} {:>6} {:>6} {:>25} {:>25}",
                    "nl",
                    "UNCONN",
                    nl.recv_q.unwrap_or(0),
                    nl.send_q.unwrap_or(0),
                    format!("{}:{}", nl.protocol_name(), nl.portid),
                    "*"
                )?;
            }
            SocketInfo::Packet(pkt) => {
                writeln!(
                    handle,
                    "{:<8} {:<12} {:>6} {:>6} {:>25} {:>25}",
                    pkt.netid(),
                    "UNCONN",
                    pkt.recv_q.unwrap_or(0),
                    pkt.send_q.unwrap_or(0),
                    format!("*:{}", pkt.protocol),
                    "*"
                )?;
            }
        }
    }

    Ok(())
}

fn print_inet_socket(
    handle: &mut impl Write,
    sock: &InetSocket,
    opts: &DisplayOptions,
    procs: &crate::procmap::ProcMap,
) -> io::Result<()> {
    let local = format_addr(&sock.local, opts.numeric, opts.resolve);
    let remote = format_addr(&sock.remote, opts.numeric, opts.resolve);

    let users = if opts.processes {
        crate::procmap::format_users(procs, sock.inode)
    } else {
        String::new()
    };

    let main = format!(
        "{:<8} {:<12} {:>6} {:>6} {:>25} {:>25}{}",
        sock.netid(),
        sock.state.name(),
        sock.recv_q,
        sock.send_q,
        local,
        remote,
        users
    );

    // Detail segments that normally wrap onto `\t`-prefixed
    // continuation lines. With -O/--oneline they are joined onto the
    // socket's row instead (see `emit_row`).
    let mut details: Vec<String> = Vec::new();

    // Timer info (-o): only printed when a timer is active.
    if opts.options
        && let Some(timer) = sock.timer.describe()
    {
        details.push(timer);
    }

    // Extended info
    if opts.extended {
        let mut s = format!("uid:{} ino:{}", sock.uid, sock.inode);
        if sock.interface > 0 {
            s.push_str(&format!(" if:{}", sock.interface));
        }
        if let Some(mark) = sock.mark {
            s.push_str(&format!(" fwmark:0x{:x}", mark));
        }
        details.push(s);
    }

    // Memory info
    if opts.memory
        && let Some(ref mem) = sock.mem_info
    {
        details.push(format!(
            "skmem:(r{},rb{},t{},tb{},f{},w{},o{},bl{},d{})",
            mem.rmem_alloc,
            mem.rcvbuf,
            mem.wmem_alloc,
            mem.sndbuf,
            mem.fwd_alloc,
            mem.wmem_queued,
            mem.optmem,
            mem.backlog,
            mem.drops
        ));
    }

    // TCP info
    if opts.info
        && let Some(ref info) = sock.tcp_info
    {
        let mut parts = Vec::new();

        if let Some(ref cong) = sock.congestion {
            // `cong` already holds the algorithm name (cubic, bbr, …);
            // don't hardcode a `cubic:` prefix in front of it.
            parts.push(cong.clone());
        }

        parts.push(format!("wscale:{}:{}", info.wscale >> 4, info.wscale & 0xf));

        if info.rto > 0 {
            parts.push(format!("rto:{}", info.rto as f64 / 1000.0));
        }
        if info.rtt > 0 {
            parts.push(format!(
                "rtt:{:.3}/{:.3}",
                info.rtt as f64 / 1000.0,
                info.rttvar as f64 / 1000.0
            ));
        }
        if info.min_rtt > 0 {
            parts.push(format!("minrtt:{:.3}", info.min_rtt as f64 / 1000.0));
        }

        parts.push(format!("cwnd:{}", info.snd_cwnd));
        if info.snd_ssthresh < 0xFFFF {
            parts.push(format!("ssthresh:{}", info.snd_ssthresh));
        }

        if info.bytes_sent > 0 {
            parts.push(format!("bytes_sent:{}", info.bytes_sent));
        }
        if info.bytes_received > 0 {
            parts.push(format!("bytes_rcvd:{}", info.bytes_received));
        }
        if info.bytes_acked > 0 {
            parts.push(format!("bytes_acked:{}", info.bytes_acked));
        }

        if info.segs_out > 0 {
            parts.push(format!("segs_out:{}", info.segs_out));
        }
        if info.segs_in > 0 {
            parts.push(format!("segs_in:{}", info.segs_in));
        }

        if info.retrans > 0 {
            parts.push(format!("retrans:{}/{}", info.retrans, info.total_retrans));
        }
        if info.lost > 0 {
            parts.push(format!("lost:{}", info.lost));
        }

        if info.pacing_rate > 0 {
            parts.push(format!(
                "pacing_rate:{}",
                format_rate_bps(info.pacing_rate * 8)
            ));
        }
        if info.delivery_rate > 0 {
            parts.push(format!(
                "delivery_rate:{}",
                format_rate_bps(info.delivery_rate * 8)
            ));
        }

        if info.rcv_space > 0 {
            parts.push(format!("rcv_space:{}", info.rcv_space));
        }
        if info.rcv_ssthresh > 0 {
            parts.push(format!("rcv_ssthresh:{}", info.rcv_ssthresh));
        }

        details.push(parts.join(" "));
    }

    emit_row(handle, &main, &details, opts.oneline)
}

/// Emit a socket row plus its detail segments. In the default layout
/// each detail wraps onto its own `\t`-prefixed continuation line; with
/// -O/--oneline they are space-joined onto the row so each socket
/// occupies exactly one line.
fn emit_row(
    handle: &mut impl Write,
    main: &str,
    details: &[String],
    oneline: bool,
) -> io::Result<()> {
    if oneline {
        if details.is_empty() {
            writeln!(handle, "{main}")
        } else {
            writeln!(handle, "{main} {}", details.join(" "))
        }
    } else {
        writeln!(handle, "{main}")?;
        for d in details {
            writeln!(handle, "\t {d}")?;
        }
        Ok(())
    }
}

fn print_unix_socket(
    handle: &mut impl Write,
    sock: &UnixSocket,
    opts: &DisplayOptions,
    procs: &crate::procmap::ProcMap,
) -> io::Result<()> {
    let path = sock.name();
    let path_display = if path.is_empty() {
        "*".to_string()
    } else {
        path
    };

    let peer = if let Some(peer_ino) = sock.peer_inode {
        format!("peer:{}", peer_ino)
    } else {
        "*".to_string()
    };

    let users = if opts.processes {
        crate::procmap::format_users(procs, sock.inode)
    } else {
        String::new()
    };

    let main = format!(
        "{:<8} {:<12} {:>6} {:>6} {:>25} {:>25}{}",
        sock.netid(),
        sock.state.name(),
        sock.recv_q.unwrap_or(0),
        sock.send_q.unwrap_or(0),
        path_display,
        peer,
        users
    );

    let mut details: Vec<String> = Vec::new();
    if opts.extended {
        let mut s = format!("ino:{}", sock.inode);
        if let Some(uid) = sock.uid {
            s.push_str(&format!(" uid:{}", uid));
        }
        details.push(s);
    }

    emit_row(handle, &main, &details, opts.oneline)
}

fn format_addr(addr: &SocketAddr, numeric: bool, resolve: bool) -> String {
    let ip_str = if addr.ip().is_unspecified() {
        "*".to_string()
    } else if resolve && !numeric {
        // -r: reverse-DNS the address, falling back to numeric when
        // there's no PTR record.
        crate::dns::reverse_lookup(addr.ip()).unwrap_or_else(|| addr.ip().to_string())
    } else {
        addr.ip().to_string()
    };

    let port_str = if addr.port() == 0 {
        "*".to_string()
    } else if numeric {
        addr.port().to_string()
    } else {
        // Could resolve service names here
        addr.port().to_string()
    };

    format!("{}:{}", ip_str, port_str)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use nlink::sockdiag::{InetSocket, TcpInfo};

    use nlink::sockdiag::ProcessRef;

    use super::{DisplayOptions, format_addr, inet_to_json, procs_to_json};
    use crate::procmap::ProcMap;

    #[test]
    fn unspecified_addr_renders_star() {
        let a: SocketAddr = "0.0.0.0:22".parse().unwrap();
        assert_eq!(format_addr(&a, true, false), "*:22");
    }

    #[test]
    fn zero_port_renders_star() {
        let a: SocketAddr = "10.0.0.1:0".parse().unwrap();
        assert_eq!(format_addr(&a, true, false), "10.0.0.1:*");
    }

    #[test]
    fn numeric_addr_and_port() {
        let a: SocketAddr = "192.168.1.5:443".parse().unwrap();
        assert_eq!(format_addr(&a, true, false), "192.168.1.5:443");
    }

    /// All display flags off: JSON carries only the core fields, never
    /// the detail blocks — even when the socket captured them.
    fn opts_all_off() -> DisplayOptions {
        DisplayOptions {
            numeric: true,
            resolve: false,
            extended: false,
            memory: false,
            info: false,
            options: false,
            processes: false,
            no_header: false,
            oneline: false,
        }
    }

    fn socket_with_details() -> InetSocket {
        InetSocket {
            interface: 7,
            mark: Some(0x1234),
            tcp_info: Some(TcpInfo::default()),
            congestion: Some("bbr".into()),
            ..Default::default()
        }
    }

    #[test]
    fn json_omits_detail_blocks_without_flags() {
        let sock = socket_with_details();
        let json = inet_to_json(&sock, &opts_all_off(), &ProcMap::new());
        // Detail blocks are gated off.
        assert!(json.get("tcp_info").is_none());
        assert!(json.get("congestion").is_none());
        assert!(json.get("interface").is_none());
        assert!(json.get("mark").is_none());
        assert!(json.get("process").is_none());
        // Core fields are always present.
        assert!(json.get("state").is_some());
        assert!(json.get("local").is_some());
    }

    #[test]
    fn json_includes_blocks_when_flags_set() {
        let sock = socket_with_details();
        let opts = DisplayOptions {
            extended: true,
            info: true,
            ..opts_all_off()
        };
        let json = inet_to_json(&sock, &opts, &ProcMap::new());
        assert!(json.get("tcp_info").is_some());
        assert_eq!(json["congestion"], "bbr");
        assert_eq!(json["interface"], 7);
        assert_eq!(json["mark"], 0x1234);
    }

    #[test]
    fn json_process_block_only_with_p_flag() {
        let mut map = ProcMap::new();
        map.insert(
            99,
            ProcessRef {
                pid: 100,
                start_time: 1,
                comm: "sshd".into(),
                fd: 3,
            },
        );
        let sock = InetSocket {
            inode: 99,
            ..Default::default()
        };

        // Without -p: absent even though the map has an entry.
        let json = inet_to_json(&sock, &opts_all_off(), &map);
        assert!(json.get("process").is_none());

        // With -p: present and structured.
        let opts = DisplayOptions {
            processes: true,
            ..opts_all_off()
        };
        let json = inet_to_json(&sock, &opts, &map);
        let procs = json["process"].as_array().expect("process array");
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0]["comm"], "sshd");
        assert_eq!(procs[0]["pid"], 100);
        assert_eq!(procs[0]["fd"], 3);
    }

    #[test]
    fn procs_to_json_none_when_absent() {
        assert!(procs_to_json(&ProcMap::new(), 42).is_none());
    }
}
