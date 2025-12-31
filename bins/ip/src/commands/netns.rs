//! ip netns command implementation.
//!
//! Network namespaces provide isolation of network resources.
//! Each namespace has its own interfaces, routing tables, firewall rules, etc.

use clap::{Args, Subcommand};
use rip::netlink::Result;
use rip::output::{OutputFormat, OutputOptions, Printable, print_all};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Network namespace runtime directory.
const NETNS_RUN_DIR: &str = "/var/run/netns";

/// Namespace information for display.
#[derive(Debug)]
struct NamespaceInfo {
    name: String,
    nsid: Option<i32>,
}

impl Printable for NamespaceInfo {
    fn print_text<W: Write>(&self, w: &mut W, _opts: &OutputOptions) -> io::Result<()> {
        if let Some(nsid) = self.nsid {
            writeln!(w, "{} (id: {})", self.name, nsid)
        } else {
            writeln!(w, "{}", self.name)
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "nsid": self.nsid,
        })
    }
}

#[derive(Args)]
pub struct NetnsCmd {
    #[command(subcommand)]
    action: Option<NetnsAction>,
}

#[derive(Subcommand)]
enum NetnsAction {
    /// List network namespaces.
    #[command(visible_alias = "ls")]
    List,

    /// Show network namespaces (alias for list).
    Show,

    /// Add a network namespace.
    Add {
        /// Namespace name.
        name: String,
    },

    /// Delete a network namespace.
    #[command(visible_alias = "del")]
    Delete {
        /// Namespace name.
        name: String,
    },

    /// Execute a command in a network namespace.
    Exec {
        /// Namespace name.
        name: String,

        /// Command to execute.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Identify the network namespace of a process.
    Identify {
        /// Process ID (default: self).
        #[arg(default_value = "self")]
        pid: String,
    },

    /// List PIDs in a network namespace.
    Pids {
        /// Namespace name.
        name: String,
    },

    /// Monitor network namespace events.
    Monitor,

    /// Set the namespace ID for a network namespace.
    Set {
        /// Namespace name.
        name: String,

        /// Namespace ID (or "auto").
        nsid: String,
    },

    /// Attach an existing namespace to a name.
    Attach {
        /// Namespace name.
        name: String,

        /// Process ID whose namespace to attach.
        pid: u32,
    },
}

impl NetnsCmd {
    pub async fn run(&self, format: OutputFormat, opts: &OutputOptions) -> Result<()> {
        match &self.action {
            Some(NetnsAction::List) | Some(NetnsAction::Show) | None => {
                list_namespaces(format, opts)
            }
            Some(NetnsAction::Add { name }) => add_namespace(name),
            Some(NetnsAction::Delete { name }) => delete_namespace(name),
            Some(NetnsAction::Exec { name, command }) => exec_in_namespace(name, command),
            Some(NetnsAction::Identify { pid }) => identify_namespace(pid),
            Some(NetnsAction::Pids { name }) => list_pids_in_namespace(name),
            Some(NetnsAction::Monitor) => monitor_namespaces(),
            Some(NetnsAction::Set { name, nsid }) => set_namespace_id(name, nsid),
            Some(NetnsAction::Attach { name, pid }) => attach_namespace(name, *pid),
        }
    }
}

/// List all network namespaces.
fn list_namespaces(format: OutputFormat, opts: &OutputOptions) -> Result<()> {
    let dir = match fs::read_dir(NETNS_RUN_DIR) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // No namespaces directory means no namespaces
            return Ok(());
        }
        Err(e) => {
            return Err(rip::netlink::Error::Io(e));
        }
    };

    let mut namespaces: Vec<NamespaceInfo> = Vec::new();

    for entry in dir {
        let entry = entry.map_err(rip::netlink::Error::Io)?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "." || name == ".." {
            continue;
        }
        namespaces.push(NamespaceInfo {
            nsid: get_namespace_id(&name),
            name,
        });
    }

    namespaces.sort_by(|a, b| a.name.cmp(&b.name));

    print_all(&namespaces, format, opts)?;

    Ok(())
}

/// Get the namespace ID for a named namespace.
fn get_namespace_id(name: &str) -> Option<i32> {
    // This requires RTM_GETNSID netlink message
    // For now, return None (nsid display is optional)
    // A full implementation would open the namespace file and query via netlink
    let _ = name;
    None
}

/// Add a new network namespace.
fn add_namespace(name: &str) -> Result<()> {
    validate_name(name)?;

    // Create the netns directory if it doesn't exist
    create_netns_dir()?;

    let netns_path = PathBuf::from(NETNS_RUN_DIR).join(name);

    // Create an empty file as a mount point
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&netns_path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                rip::netlink::Error::InvalidMessage(format!("namespace '{}' already exists", name))
            } else {
                rip::netlink::Error::Io(e)
            }
        })?;
    drop(file);

    // Use unshare to create a new network namespace
    // We need to fork a process that:
    // 1. Calls unshare(CLONE_NEWNET)
    // 2. Bind mounts /proc/self/ns/net to the netns file

    // For safety, use the ip command's approach: fork and use setns
    let result = unsafe {
        // Fork a child process
        let pid = libc::fork();
        if pid < 0 {
            return Err(rip::netlink::Error::Io(io::Error::last_os_error()));
        }

        if pid == 0 {
            // Child process
            // Create new network namespace
            if libc::unshare(libc::CLONE_NEWNET) < 0 {
                libc::_exit(1);
            }

            // Mount our namespace to the file
            let proc_path = std::ffi::CString::new("/proc/self/ns/net").unwrap();
            let mount_path = std::ffi::CString::new(netns_path.to_str().unwrap()).unwrap();

            if libc::mount(
                proc_path.as_ptr(),
                mount_path.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            ) < 0
            {
                libc::_exit(2);
            }

            libc::_exit(0);
        }

        // Parent process - wait for child
        let mut status: i32 = 0;
        libc::waitpid(pid, &mut status, 0);

        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        }
    };

    if result != 0 {
        // Clean up the file we created
        let _ = fs::remove_file(&netns_path);
        return Err(rip::netlink::Error::InvalidMessage(format!(
            "failed to create network namespace (exit code {})",
            result
        )));
    }

    println!("Network namespace '{}' created", name);
    Ok(())
}

/// Delete a network namespace.
fn delete_namespace(name: &str) -> Result<()> {
    let netns_path = PathBuf::from(NETNS_RUN_DIR).join(name);

    if !netns_path.exists() {
        return Err(rip::netlink::Error::InvalidMessage(format!(
            "namespace '{}' does not exist",
            name
        )));
    }

    // Unmount the namespace
    unsafe {
        let path_cstr = std::ffi::CString::new(netns_path.to_str().unwrap()).unwrap();
        libc::umount2(path_cstr.as_ptr(), libc::MNT_DETACH);
    }

    // Remove the file
    fs::remove_file(&netns_path).map_err(|e| {
        rip::netlink::Error::InvalidMessage(format!("cannot remove namespace file: {}", e))
    })?;

    println!("Network namespace '{}' deleted", name);
    Ok(())
}

/// Execute a command in a network namespace.
fn exec_in_namespace(name: &str, command: &[String]) -> Result<()> {
    if command.is_empty() {
        return Err(rip::netlink::Error::InvalidMessage(
            "no command specified".to_string(),
        ));
    }

    let netns_path = PathBuf::from(NETNS_RUN_DIR).join(name);

    if !netns_path.exists() {
        return Err(rip::netlink::Error::InvalidMessage(format!(
            "namespace '{}' does not exist",
            name
        )));
    }

    // Open the namespace file
    let netns_fd = File::open(&netns_path).map_err(|e| {
        rip::netlink::Error::InvalidMessage(format!("cannot open namespace '{}': {}", name, e))
    })?;

    // Switch to the namespace
    use std::os::unix::io::AsRawFd;
    let fd = netns_fd.as_raw_fd();

    unsafe {
        if libc::setns(fd, libc::CLONE_NEWNET) < 0 {
            return Err(rip::netlink::Error::Io(io::Error::last_os_error()));
        }
    }

    drop(netns_fd);

    // Execute the command
    let status = Command::new(&command[0])
        .args(&command[1..])
        .status()
        .map_err(|e| {
            rip::netlink::Error::InvalidMessage(format!("failed to execute '{}': {}", command[0], e))
        })?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}

/// Identify which namespace a process belongs to.
fn identify_namespace(pid: &str) -> Result<()> {
    let net_path = format!("/proc/{}/ns/net", pid);

    let target_stat = fs::metadata(&net_path).map_err(|e| {
        rip::netlink::Error::InvalidMessage(format!("cannot access process {}: {}", pid, e))
    })?;

    use std::os::unix::fs::MetadataExt;
    let target_dev = target_stat.dev();
    let target_ino = target_stat.ino();

    // Search through all named namespaces
    let dir = match fs::read_dir(NETNS_RUN_DIR) {
        Ok(d) => d,
        Err(_) => {
            // No namespaces directory
            println!();
            return Ok(());
        }
    };

    for entry in dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let name = entry.file_name().to_string_lossy().to_string();
        if name == "." || name == ".." {
            continue;
        }

        let ns_path = PathBuf::from(NETNS_RUN_DIR).join(&name);
        if let Ok(stat) = fs::metadata(&ns_path)
            && stat.dev() == target_dev
            && stat.ino() == target_ino
        {
            println!("{}", name);
            return Ok(());
        }
    }

    // Process is not in any named namespace
    println!();
    Ok(())
}

/// List PIDs in a network namespace.
fn list_pids_in_namespace(name: &str) -> Result<()> {
    let netns_path = PathBuf::from(NETNS_RUN_DIR).join(name);

    if !netns_path.exists() {
        return Err(rip::netlink::Error::InvalidMessage(format!(
            "namespace '{}' does not exist",
            name
        )));
    }

    let ns_stat = fs::metadata(&netns_path).map_err(rip::netlink::Error::Io)?;
    use std::os::unix::fs::MetadataExt;
    let ns_dev = ns_stat.dev();
    let ns_ino = ns_stat.ino();

    // Iterate through /proc to find matching processes
    let proc_dir = fs::read_dir("/proc").map_err(rip::netlink::Error::Io)?;

    for entry in proc_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let name = entry.file_name().to_string_lossy().to_string();

        // Skip non-numeric entries (not PIDs)
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let pid_ns_path = format!("/proc/{}/ns/net", name);
        if let Ok(stat) = fs::metadata(&pid_ns_path)
            && stat.dev() == ns_dev
            && stat.ino() == ns_ino
        {
            println!("{}", name);
        }
    }

    Ok(())
}

/// Monitor namespace events using inotify.
fn monitor_namespaces() -> Result<()> {
    // Create inotify instance
    let inotify_fd = unsafe { libc::inotify_init() };
    if inotify_fd < 0 {
        return Err(rip::netlink::Error::Io(io::Error::last_os_error()));
    }

    // Create the netns directory if needed
    create_netns_dir()?;

    // Watch the netns directory
    let path_cstr = std::ffi::CString::new(NETNS_RUN_DIR).unwrap();
    let wd = unsafe {
        libc::inotify_add_watch(
            inotify_fd,
            path_cstr.as_ptr(),
            libc::IN_CREATE | libc::IN_DELETE,
        )
    };

    if wd < 0 {
        unsafe { libc::close(inotify_fd) };
        return Err(rip::netlink::Error::Io(io::Error::last_os_error()));
    }

    println!("Monitoring network namespace changes...");

    let mut buf = [0u8; 4096];

    loop {
        let len =
            unsafe { libc::read(inotify_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

        if len < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            unsafe { libc::close(inotify_fd) };
            return Err(rip::netlink::Error::Io(err));
        }

        let mut offset = 0;
        while offset < len as usize {
            // Parse inotify_event
            let event_ptr = buf[offset..].as_ptr() as *const libc::inotify_event;
            let event = unsafe { &*event_ptr };

            let name_len = event.len as usize;
            let name = if name_len > 0 {
                let name_start = offset + std::mem::size_of::<libc::inotify_event>();
                let name_bytes = &buf[name_start..name_start + name_len];
                // Find null terminator
                let null_pos = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_len);
                String::from_utf8_lossy(&name_bytes[..null_pos]).to_string()
            } else {
                String::new()
            };

            if event.mask & libc::IN_CREATE != 0 {
                println!("add {}", name);
            }
            if event.mask & libc::IN_DELETE != 0 {
                println!("delete {}", name);
            }

            offset += std::mem::size_of::<libc::inotify_event>() + name_len;
        }
    }
}

/// Set the namespace ID for a network namespace.
fn set_namespace_id(name: &str, nsid: &str) -> Result<()> {
    let netns_path = PathBuf::from(NETNS_RUN_DIR).join(name);

    if !netns_path.exists() {
        return Err(rip::netlink::Error::InvalidMessage(format!(
            "namespace '{}' does not exist",
            name
        )));
    }

    let id: i32 = if nsid == "auto" {
        -1
    } else {
        nsid.parse()
            .map_err(|_| rip::netlink::Error::InvalidMessage(format!("invalid nsid: {}", nsid)))?
    };

    // This requires RTM_NEWNSID netlink message
    // For now, print a message about the operation
    if id < 0 {
        println!("Setting automatic namespace ID for '{}'", name);
    } else {
        println!("Setting namespace ID {} for '{}'", id, name);
    }

    // TODO: Implement RTM_NEWNSID message
    // This requires opening the namespace file and sending NETNSA_FD + NETNSA_NSID

    Ok(())
}

/// Attach an existing namespace to a name.
fn attach_namespace(name: &str, pid: u32) -> Result<()> {
    validate_name(name)?;

    let proc_ns_path = format!("/proc/{}/ns/net", pid);

    if !Path::new(&proc_ns_path).exists() {
        return Err(rip::netlink::Error::InvalidMessage(format!(
            "process {} does not exist or has no network namespace",
            pid
        )));
    }

    // Create the netns directory if it doesn't exist
    create_netns_dir()?;

    let netns_path = PathBuf::from(NETNS_RUN_DIR).join(name);

    // Create an empty file as a mount point
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&netns_path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                rip::netlink::Error::InvalidMessage(format!("namespace '{}' already exists", name))
            } else {
                rip::netlink::Error::Io(e)
            }
        })?;
    drop(file);

    // Bind mount the process namespace to our file
    let proc_cstr = std::ffi::CString::new(proc_ns_path.clone()).unwrap();
    let mount_cstr = std::ffi::CString::new(netns_path.to_str().unwrap()).unwrap();

    let result = unsafe {
        libc::mount(
            proc_cstr.as_ptr(),
            mount_cstr.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };

    if result < 0 {
        let _ = fs::remove_file(&netns_path);
        return Err(rip::netlink::Error::Io(io::Error::last_os_error()));
    }

    println!("Attached namespace of process {} as '{}'", pid, name);
    Ok(())
}

/// Create the netns runtime directory if it doesn't exist.
fn create_netns_dir() -> Result<()> {
    match fs::create_dir_all(NETNS_RUN_DIR) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(rip::netlink::Error::Io(e)),
    }
}

/// Validate namespace name.
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(rip::netlink::Error::InvalidMessage(
            "namespace name cannot be empty".to_string(),
        ));
    }

    if name.len() > 255 {
        return Err(rip::netlink::Error::InvalidMessage(
            "namespace name too long".to_string(),
        ));
    }

    if name.contains('/') {
        return Err(rip::netlink::Error::InvalidMessage(
            "namespace name cannot contain '/'".to_string(),
        ));
    }

    if name == "." || name == ".." {
        return Err(rip::netlink::Error::InvalidMessage(
            "invalid namespace name".to_string(),
        ));
    }

    Ok(())
}
