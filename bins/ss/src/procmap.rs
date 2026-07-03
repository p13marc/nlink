//! Socket-inode → process mapping for `ss -p`.
//!
//! Thin adapter over the library's attribution utility
//! (`nlink::sockdiag::SocketOwnerMap`, #162) — the `/proc/<pid>/fd`
//! walk lives there now so every downstream gets it, not just this
//! bin. Only the `users:((...))` text rendering stays here.

pub use nlink::sockdiag::SocketOwnerMap as ProcMap;

/// Scan `/proc` and build the socket-inode → process map.
pub fn build() -> ProcMap {
    ProcMap::scan()
}

/// Render the `users:((...))` suffix `ss -p` appends to a socket line.
/// Returns an empty string when no process is known for the inode.
pub fn format_users(map: &ProcMap, inode: u32) -> String {
    let procs = map.resolve(inode);
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
    use nlink::sockdiag::ProcessRef;

    use super::*;

    fn entry(pid: i32, comm: &str, fd: i32) -> ProcessRef {
        ProcessRef {
            pid,
            start_time: 1,
            comm: comm.into(),
            fd,
        }
    }

    #[test]
    fn format_users_empty_when_absent() {
        let map = ProcMap::new();
        assert_eq!(format_users(&map, 42), "");
    }

    #[test]
    fn format_users_renders_entries() {
        let mut map = ProcMap::new();
        map.insert(7, entry(100, "sshd", 3));
        assert_eq!(format_users(&map, 7), " users:((\"sshd\",pid=100,fd=3))");
    }
}
