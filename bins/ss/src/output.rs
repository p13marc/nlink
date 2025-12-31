//! Output formatting for ss command.

use rip::sockdiag::{InetSocket, SocketInfo, UnixSocket};
use std::io::{self, Write};
use std::net::SocketAddr;

/// Display options for socket output.
#[allow(dead_code)]
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
pub fn print_json(sockets: &[SocketInfo]) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    let json_sockets: Vec<_> = sockets
        .iter()
        .map(|s| match s {
            SocketInfo::Inet(inet) => inet_to_json(inet),
            SocketInfo::Unix(unix) => unix_to_json(unix),
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

fn inet_to_json(sock: &InetSocket) -> serde_json::Value {
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

    if let Some(ref info) = sock.tcp_info {
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
    }

    if let Some(ref mem) = sock.mem_info {
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

    if let Some(ref cong) = sock.congestion {
        json["congestion"] = serde_json::Value::String(cong.clone());
    }

    if let Some(mark) = sock.mark {
        json["mark"] = serde_json::Value::Number(mark.into());
    }

    json
}

fn unix_to_json(sock: &UnixSocket) -> serde_json::Value {
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

    json
}

/// Print sockets in text format.
pub fn print_text(sockets: &[SocketInfo], opts: &DisplayOptions) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    if !opts.no_header {
        writeln!(
            handle,
            "{:<8} {:<12} {:>6} {:>6} {:>25} {:>25}",
            "Netid", "State", "Recv-Q", "Send-Q", "Local Address:Port", "Peer Address:Port"
        )?;
    }

    for sock in sockets {
        match sock {
            SocketInfo::Inet(inet) => print_inet_socket(&mut handle, inet, opts)?,
            SocketInfo::Unix(unix) => print_unix_socket(&mut handle, unix, opts)?,
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
) -> io::Result<()> {
    let local = format_addr(&sock.local, opts.numeric);
    let remote = format_addr(&sock.remote, opts.numeric);

    writeln!(
        handle,
        "{:<8} {:<12} {:>6} {:>6} {:>25} {:>25}",
        sock.netid(),
        sock.state.name(),
        sock.recv_q,
        sock.send_q,
        local,
        remote
    )?;

    // Extended info
    if opts.extended {
        write!(handle, "\t uid:{} ino:{}", sock.uid, sock.inode)?;
        if sock.interface > 0 {
            write!(handle, " if:{}", sock.interface)?;
        }
        if let Some(mark) = sock.mark {
            write!(handle, " fwmark:0x{:x}", mark)?;
        }
        writeln!(handle)?;
    }

    // Memory info
    if opts.memory
        && let Some(ref mem) = sock.mem_info {
            writeln!(
                handle,
                "\t skmem:(r{},rb{},t{},tb{},f{},w{},o{},bl{},d{})",
                mem.rmem_alloc,
                mem.rcvbuf,
                mem.wmem_alloc,
                mem.sndbuf,
                mem.fwd_alloc,
                mem.wmem_queued,
                mem.optmem,
                mem.backlog,
                mem.drops
            )?;
        }

    // TCP info
    if opts.info
        && let Some(ref info) = sock.tcp_info {
            let mut parts = Vec::new();

            if let Some(ref cong) = sock.congestion {
                parts.push(format!("cubic:{}", cong));
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
                parts.push(format!("pacing_rate:{}", format_rate(info.pacing_rate)));
            }
            if info.delivery_rate > 0 {
                parts.push(format!("delivery_rate:{}", format_rate(info.delivery_rate)));
            }

            if info.rcv_space > 0 {
                parts.push(format!("rcv_space:{}", info.rcv_space));
            }
            if info.rcv_ssthresh > 0 {
                parts.push(format!("rcv_ssthresh:{}", info.rcv_ssthresh));
            }

            writeln!(handle, "\t {}", parts.join(" "))?;
        }

    Ok(())
}

fn print_unix_socket(
    handle: &mut impl Write,
    sock: &UnixSocket,
    opts: &DisplayOptions,
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

    writeln!(
        handle,
        "{:<8} {:<12} {:>6} {:>6} {:>25} {:>25}",
        sock.netid(),
        sock.state.name(),
        sock.recv_q.unwrap_or(0),
        sock.send_q.unwrap_or(0),
        path_display,
        peer
    )?;

    if opts.extended {
        write!(handle, "\t ino:{}", sock.inode)?;
        if let Some(uid) = sock.uid {
            write!(handle, " uid:{}", uid)?;
        }
        writeln!(handle)?;
    }

    Ok(())
}

fn format_addr(addr: &SocketAddr, numeric: bool) -> String {
    let ip_str = if addr.ip().is_unspecified() {
        "*".to_string()
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

fn format_rate(bytes_per_sec: u64) -> String {
    if bytes_per_sec >= 1_000_000_000 {
        format!("{:.1}Gbps", bytes_per_sec as f64 * 8.0 / 1_000_000_000.0)
    } else if bytes_per_sec >= 1_000_000 {
        format!("{:.1}Mbps", bytes_per_sec as f64 * 8.0 / 1_000_000.0)
    } else if bytes_per_sec >= 1_000 {
        format!("{:.1}Kbps", bytes_per_sec as f64 * 8.0 / 1_000.0)
    } else {
        format!("{}bps", bytes_per_sec * 8)
    }
}
