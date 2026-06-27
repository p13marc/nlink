//! Socket-inode → process mapping for `ss -p`.
//!
//! Builds a map from socket inode to the processes holding that
//! socket open by walking `/proc/<pid>/fd/*` symlinks (they point to
//! `socket:[<inode>]`). This is the same approach `ss(8)` / `lsof`
//! take. Best-effort: processes whose `fd/` dir can't be read (other
//! users' processes when unprivileged) are silently skipped, matching
//! `ss`'s behaviour.
//!
//! This binary is a CLI tool, so reading `/proc` directly is fine —
//! the library's namespace-safety policy applies only to
//! `crates/nlink/src`.

use std::{collections::HashMap, fs};

/// One process holding a socket open.
#[derive(Debug, Clone)]
pub struct ProcEntry {
    pub pid: i32,
    pub comm: String,
    pub fd: i32,
}

/// inode → processes holding it open.
pub type ProcMap = HashMap<u32, Vec<ProcEntry>>;

/// Scan `/proc` and build the socket-inode → process map.
pub fn build() -> ProcMap {
    let mut map: ProcMap = HashMap::new();

    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return map;
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<i32>() else {
            continue; // non-PID entries like "self", "meminfo"
        };

        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue; // permission denied / process gone
        };

        let mut comm: Option<String> = None;
        for fd_entry in fds.flatten() {
            let Ok(target) = fs::read_link(fd_entry.path()) else {
                continue;
            };
            let Some(target) = target.to_str() else {
                continue;
            };
            // Targets look like "socket:[12345]".
            let Some(inode) = parse_socket_inode(target) else {
                continue;
            };
            let fd = fd_entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(-1);

            // Read comm lazily, once per process that owns a socket.
            let comm = comm.get_or_insert_with(|| read_comm(pid));
            map.entry(inode).or_default().push(ProcEntry {
                pid,
                comm: comm.clone(),
                fd,
            });
        }
    }

    map
}

/// Parse `socket:[12345]` → `12345`.
fn parse_socket_inode(target: &str) -> Option<u32> {
    let rest = target.strip_prefix("socket:[")?;
    let num = rest.strip_suffix(']')?;
    num.parse().ok()
}

fn read_comm(pid: i32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".to_string())
}

/// Render the `users:((...))` suffix `ss -p` appends to a socket line.
/// Returns an empty string when no process is known for the inode.
pub fn format_users(map: &ProcMap, inode: u32) -> String {
    let Some(procs) = map.get(&inode) else {
        return String::new();
    };
    if procs.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = procs
        .iter()
        .map(|p| format!("(\"{}\",pid={},fd={})", p.comm, p.pid, p.fd))
        .collect();
    format!(" users:({})", parts.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_socket_inode() {
        assert_eq!(parse_socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(parse_socket_inode("pipe:[999]"), None);
        assert_eq!(parse_socket_inode("/dev/null"), None);
        assert_eq!(parse_socket_inode("socket:[]"), None);
    }

    #[test]
    fn format_users_empty_when_absent() {
        let map = ProcMap::new();
        assert_eq!(format_users(&map, 42), "");
    }

    #[test]
    fn format_users_renders_entries() {
        let mut map = ProcMap::new();
        map.insert(
            7,
            vec![ProcEntry {
                pid: 100,
                comm: "sshd".into(),
                fd: 3,
            }],
        );
        assert_eq!(format_users(&map, 7), " users:((\"sshd\",pid=100,fd=3))");
    }
}
