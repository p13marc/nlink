# Analysis: Mount Namespace Support in Spawn Functions

**Date:** 2026-03-30
**In response to:** nlink-lab feature request (NLINK_FEATURE_REQUEST_MOUNT_NS.md)
**Status:** Ready to implement with modifications

---

## Verdict

The feature request is valid, well-motivated, and should be implemented. However, the
proposed implementation has a **critical async-signal-safety issue** that must be fixed
before merging. The iproute2 reference implementation also uses `MS_SLAVE` (not
`MS_PRIVATE`) for mount propagation, which we should match.

---

## What the Feature Request Gets Right

1. **Motivation is solid.** Per-namespace `/etc/hosts` and `/etc/resolv.conf` is a real
   need for network lab engines, containers, and any multi-namespace test environment.

2. **`/etc/netns/<name>/` is the established Linux convention.** Documented in
   `ip-netns(8)` and implemented in iproute2 since 2013.

3. **Must be in nlink, not the consumer.** Rust's `Command::pre_exec()` can only be
   called once. nlink already uses it for `setns()`. The consumer cannot inject additional
   `pre_exec()` logic.

4. **Option A (new functions) is the right API choice.** Simple, self-documenting,
   no builder overhead. Option B is over-engineered for a single feature.

5. **The syscalls (`unshare`, `mount`) are safe in `pre_exec()`.** They are thin glibc
   wrappers around raw syscall numbers — no locks, no allocations.

---

## What Must Be Changed

### Critical: `read_dir()` in `pre_exec()` is unsafe

The proposed implementation calls `std::fs::read_dir()` and `CString::new()` inside
the `pre_exec()` closure. This is **not async-signal-safe**.

**Why it matters:**

- `read_dir()` calls `opendir(3)` which calls `malloc()`
- `CString::new()` allocates via the Rust allocator
- `malloc()` is NOT async-signal-safe — it uses internal locks
- In a multi-threaded program (tokio), another thread may hold a malloc lock at
  `fork()` time, causing the child to **deadlock**
- Rust's `CommandExt::pre_exec` documentation explicitly warns:
  > "This is often a very constrained environment where normal operations like
  > malloc... are not guaranteed to work"

**Why iproute2 gets away with it:**

iproute2's `ip netns exec` calls `fork()` in C and runs `opendir()`/`readdir()`/
`mount()` as regular code in the child process. The `ip` command is single-threaded,
so there are no other threads that could hold malloc locks. The async-signal-safety
requirement is stricter in Rust's `pre_exec()` context because the runtime may have
spawned threads (allocator threads, tokio worker threads, etc.).

**Fix: pre-compute the file list before fork.**

```
Parent process (before fork, all allocations are safe):
  1. read_dir("/etc/netns/<name>/")
  2. Build Vec<(CString, CString)> of (source, target) path pairs
  3. Capture this Vec in the pre_exec closure

Child process (in pre_exec, after fork — only raw syscalls):
  1. setns(ns_fd, CLONE_NEWNET)
  2. unshare(CLONE_NEWNS)
  3. mount("", "/", MS_SLAVE | MS_REC)
  4. for each (src, dst) in captured pairs:
       mount(src, dst, MS_BIND)
```

Zero allocations in `pre_exec()`. All data is pre-computed and moved into the closure.

### Should Use `MS_SLAVE | MS_REC`, Not `MS_PRIVATE | MS_REC`

The feature request proposes `MS_REC | MS_PRIVATE`. iproute2 uses `MS_SLAVE | MS_REC`.

| Flag | Parent -> Child | Child -> Parent |
|------|:-:|:-:|
| `MS_PRIVATE` | No | No |
| `MS_SLAVE` | **Yes** | No |

`MS_SLAVE` is better because:
- Child still sees new mounts from the parent (e.g., if a USB device is mounted)
- Child's bind mounts (`/etc/hosts` overlay) don't propagate back
- Matches the iproute2 reference implementation exactly

### Missing: `/sys` Remount

iproute2's `netns_switch()` also remounts `/sys` (sysfs) so it reflects the new
network namespace. Without this, `/sys/class/net/` in the child still shows the
host's interfaces. The feature request doesn't mention this.

For the initial implementation, we can skip `/sys` remount since:
- The primary use case (DNS isolation via `/etc/hosts`, `/etc/resolv.conf`) doesn't need it
- Programs that need sysfs info typically use netlink, not `/sys/`
- It can be added later as a separate option

Document this limitation.

### Subdirectory Handling

iproute2's `bind_etc()` does NOT recurse into subdirectories. If
`/etc/netns/myns/ssh/` exists, it bind-mounts the entire directory onto `/etc/ssh/`
as a unit. Our implementation should match this behavior — iterate top-level entries
only, bind-mount each (file or directory) onto `/etc/<entry>`.

---

## Proposed Implementation

### API (Option A — new functions)

```rust
/// Spawn a process in a network namespace with /etc/netns/ file overlays.
///
/// Like `spawn()`, but also creates a private mount namespace and bind-mounts
/// files from `/etc/netns/<ns_name>/` over `/etc/`. Mirrors `ip netns exec`.
///
/// If `/etc/netns/<ns_name>/` does not exist, the overlay step is skipped
/// and behavior is identical to `spawn()`.
///
/// Requires `CAP_SYS_ADMIN` (for `unshare(CLONE_NEWNS)`).
pub fn spawn_with_etc(
    ns_name: &str,
    cmd: std::process::Command,
) -> Result<std::process::Child>

/// Like `spawn_output()`, but with /etc/netns/ file overlays.
pub fn spawn_output_with_etc(
    ns_name: &str,
    cmd: std::process::Command,
) -> Result<std::process::Output>

/// Path-based variant. `ns_name` is needed to locate `/etc/netns/<name>/`.
pub fn spawn_path_with_etc<P: AsRef<Path>>(
    path: P,
    ns_name: &str,
    cmd: std::process::Command,
) -> Result<std::process::Child>
```

Note: renamed from `spawn_with_etc_overlay` to `spawn_with_etc` for brevity.
The `_with_etc` suffix is clear enough — it mirrors the `ip netns exec` convention.

### Implementation Pattern

```rust
pub fn spawn_with_etc(
    ns_name: &str,
    cmd: std::process::Command,
) -> Result<std::process::Child> {
    let path = PathBuf::from(NETNS_RUN_DIR).join(ns_name);
    if !path.exists() {
        return Err(Error::NamespaceNotFound { name: ns_name.to_string() });
    }
    spawn_path_with_etc(&path, ns_name, cmd)
}

pub fn spawn_path_with_etc<P: AsRef<Path>>(
    path: P,
    ns_name: &str,
    mut cmd: std::process::Command,
) -> Result<std::process::Child> {
    use std::os::unix::process::CommandExt;

    let ns_fd = open_path(path)?;
    let raw_fd = ns_fd.as_raw_fd();

    // Pre-compute bind mount pairs BEFORE fork (allocation-safe here).
    let bind_mounts = prepare_etc_binds(ns_name)?;

    unsafe {
        cmd.pre_exec(move || {
            // 1. Enter network namespace
            if libc::setns(raw_fd, libc::CLONE_NEWNET) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            // 2. Skip mount overlay if no bind mounts to apply
            if bind_mounts.is_empty() {
                return Ok(());
            }

            // 3. Create private mount namespace
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            // 4. Prevent mount propagation back to host
            let none = b"\0" as *const u8 as *const libc::c_char;
            let root = b"/\0" as *const u8 as *const libc::c_char;
            if libc::mount(none, root, std::ptr::null(), libc::MS_SLAVE | libc::MS_REC, std::ptr::null()) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            // 5. Apply pre-computed bind mounts (no allocations)
            for (src, dst) in &bind_mounts {
                if libc::mount(src.as_ptr(), dst.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            Ok(())
        });
    }

    let child = cmd.spawn().map_err(Error::Io)?;
    drop(ns_fd);
    Ok(child)
}

/// Pre-compute bind mount pairs from /etc/netns/<name>/.
/// Called in the parent process where allocation is safe.
fn prepare_etc_binds(ns_name: &str) -> Result<Vec<(CString, CString)>> {
    let etc_netns = PathBuf::from("/etc/netns").join(ns_name);

    let entries = match std::fs::read_dir(&etc_netns) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(e)),
    };

    let mut binds = Vec::new();
    for entry in entries {
        let entry = entry.map_err(Error::Io)?;
        let file_name = entry.file_name();
        let src = entry.path();
        let dst = Path::new("/etc").join(&file_name);

        // Only overlay if the target exists (can't bind-mount over nothing)
        if !dst.exists() {
            continue;
        }

        let src_c = CString::new(src.as_os_str().as_encoded_bytes())
            .map_err(|_| Error::InvalidMessage("null byte in path".into()))?;
        let dst_c = CString::new(dst.as_os_str().as_encoded_bytes())
            .map_err(|_| Error::InvalidMessage("null byte in path".into()))?;

        binds.push((src_c, dst_c));
    }

    Ok(binds)
}
```

### NamespaceSpec Integration

Also add to `NamespaceSpec`:

```rust
impl NamespaceSpec {
    /// Spawn with /etc/netns/ file overlays.
    pub fn spawn_with_etc(&self, cmd: Command) -> Result<Child> {
        match self {
            NamespaceSpec::Default => cmd.spawn().map_err(Error::Io),
            NamespaceSpec::Named(name) => spawn_with_etc(name, cmd),
            NamespaceSpec::Path(path) => {
                // For path-based specs, there's no namespace name to derive
                // the /etc/netns/ directory from. Fall back to regular spawn.
                spawn_path(path, cmd)
            }
            NamespaceSpec::Pid(pid) => {
                let path = format!("/proc/{}/ns/net", pid);
                spawn_path(&path, cmd)
            }
        }
    }
}
```

---

## Files to Modify

| File | Changes |
|------|---------|
| `crates/nlink/src/netlink/namespace.rs` | Add `spawn_with_etc`, `spawn_output_with_etc`, `spawn_path_with_etc`, `prepare_etc_binds` |
| `crates/nlink/src/netlink/namespace.rs` | Add `NamespaceSpec::spawn_with_etc` |
| `CHANGELOG.md` | Add feature entry |
| `CLAUDE.md` | Add usage example in namespace section |
| `docs/library.md` | Add example |
| `crates/nlink/examples/README.md` | Document if example is added |

---

## Testing

| Test | Description |
|------|-------------|
| `test_spawn_with_etc_hosts` | Create ns, write `/etc/netns/<name>/hosts`, spawn `cat /etc/hosts`, verify custom content |
| `test_spawn_with_etc_resolv` | Same for `/etc/resolv.conf` |
| `test_spawn_with_etc_no_dir` | No `/etc/netns/<name>/` dir — should succeed (no-op, identical to `spawn()`) |
| `test_spawn_with_etc_host_unaffected` | After spawning with overlay, verify host's `/etc/hosts` is unchanged |
| `test_spawn_with_etc_subdir` | `/etc/netns/<name>/ssh/` overlays entire `/etc/ssh/` |
| `test_spawn_without_etc_unchanged` | Existing `spawn()` behavior is not affected |

All tests require root (`CAP_SYS_ADMIN`).

---

## Limitations (Documented)

1. **No `/sys` remount.** The child process sees the host's sysfs. Programs needing
   network-namespace-aware sysfs should use netlink queries instead. This can be added
   as a future enhancement.

2. **Path-based specs can't derive namespace name.** `spawn_path_with_etc()` requires
   an explicit `ns_name` parameter to locate `/etc/netns/<name>/`. `NamespaceSpec::Path`
   and `NamespaceSpec::Pid` fall back to regular `spawn()` without overlays.

3. **Requires `CAP_SYS_ADMIN`.** `unshare(CLONE_NEWNS)` needs this capability. This is
   consistent with all other nlink namespace operations.

---

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Deadlock from malloc in `pre_exec` | **Critical** | Pre-compute file list before fork |
| Mount propagation leak to host | Medium | Use `MS_SLAVE \| MS_REC` before bind mounts |
| Existing `spawn()` behavior changes | Low | Purely additive — new functions only |
| Performance overhead | None | `read_dir()` runs once in parent, ~0 cost |

---

## References

- `ip-netns(8)` man page — documents `/etc/netns/<name>/` convention
- `iproute2/lib/namespace.c:netns_switch()` — uses `MS_SLAVE | MS_REC`, remounts `/sys`
- `iproute2/lib/namespace.c:bind_etc()` — iterates top-level entries only, no recursion
- `signal-safety(7)` — POSIX async-signal-safe function list
- `mount_namespaces(7)` — propagation types (shared, slave, private, unbindable)
- Rust `std::os::unix::process::CommandExt::pre_exec` — safety requirements
