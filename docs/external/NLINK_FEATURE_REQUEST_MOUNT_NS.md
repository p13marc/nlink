# nlink Feature Request: Mount Namespace Support in Spawn Functions

**Date:** 2026-03-30
**Requested by:** nlink-lab
**Priority:** Medium (blocks nlink-lab Phase 2 DNS isolation)

---

## Summary

Add optional mount namespace isolation to nlink's process spawn functions so
that processes started inside a network namespace can see per-namespace file
overrides (e.g., `/etc/hosts`, `/etc/resolv.conf`). This mirrors the behavior
of `ip netns exec` from iproute2.

## Motivation

nlink-lab needs to provide per-namespace DNS configuration (custom `/etc/hosts`
and `/etc/resolv.conf` for each lab node). Currently, nlink's
`namespace::spawn()` only enters the network namespace via
`setns(fd, CLONE_NEWNET)`. All spawned processes share the host's filesystem,
so there is no way to give different namespaces different `/etc/` files.

The standard Linux convention for this is the `/etc/netns/<name>/` directory.
When `ip netns exec <name> <cmd>` runs, it:

1. Enters the network namespace (`setns(CLONE_NEWNET)`)
2. Creates a private mount namespace (`unshare(CLONE_NEWNS)`)
3. Bind-mounts each file from `/etc/netns/<name>/` over `/etc/`

nlink's spawn functions should support the same behavior so that consumers
(like nlink-lab) can provide per-namespace file overrides without shelling out
to `ip netns exec`.

## Why This Must Happen in nlink (Not the Consumer)

The mount namespace setup must happen inside the `pre_exec()` hook — after
`fork()` but before `exec()`. This is deep inside nlink's spawn implementation.
Consumers cannot inject custom `pre_exec()` logic into nlink's
`namespace::spawn()` because `Command::pre_exec()` can only be called once
before spawn, and nlink already uses it.

## Current Spawn Flow

```
nlink::namespace::spawn(ns_name, cmd):
    ns_fd = open(/var/run/netns/{ns_name})
    cmd.pre_exec(|| {
        setns(ns_fd, CLONE_NEWNET)    // enter network namespace
    })
    cmd.spawn()
```

## Proposed Spawn Flow

```
nlink::namespace::spawn(ns_name, cmd, opts):
    ns_fd = open(/var/run/netns/{ns_name})
    cmd.pre_exec(|| {
        setns(ns_fd, CLONE_NEWNET)    // 1. enter network namespace

        if opts.etc_overlay {
            unshare(CLONE_NEWNS)      // 2. private mount namespace
            mount("/", MS_REC | MS_PRIVATE)  // 3. stop propagation
            bind_mount_etc_netns(ns_name)    // 4. overlay files
        }
    })
    cmd.spawn()
```

## Proposed API

### Option A: New Functions (backward compatible, no breaking changes)

```rust
/// Spawn a process in a network namespace with /etc/netns/ file overlays.
///
/// Like `spawn()`, but also creates a private mount namespace in the child
/// and bind-mounts files from `/etc/netns/<ns_name>/` over `/etc/`.
/// This mirrors `ip netns exec` behavior.
pub fn spawn_with_etc_overlay(
    ns_name: &str,
    cmd: std::process::Command,
) -> Result<std::process::Child>

/// Like `spawn_output()`, but with /etc/netns/ file overlays.
pub fn spawn_output_with_etc_overlay(
    ns_name: &str,
    cmd: std::process::Command,
) -> Result<std::process::Output>

/// Path-based variants for container/PID namespace entry.
pub fn spawn_with_etc_overlay_path<P: AsRef<Path>>(
    path: P,
    ns_name: &str,  // needed to locate /etc/netns/<name>/
    cmd: std::process::Command,
) -> Result<std::process::Child>
```

### Option B: SpawnOptions Builder (more flexible)

```rust
pub struct SpawnOptions {
    /// If true, create a mount namespace and bind-mount /etc/netns/<name>/.
    pub etc_overlay: bool,
    // Future: additional mount points, environment overrides, etc.
}

impl Default for SpawnOptions {
    fn default() -> Self {
        Self { etc_overlay: false }
    }
}

pub fn spawn_with_opts(
    ns_name: &str,
    cmd: std::process::Command,
    opts: SpawnOptions,
) -> Result<std::process::Child>
```

**Recommendation:** Option A for simplicity. Option B if you anticipate more
spawn-time options in the future.

## Implementation Details

### pre_exec() Hook (runs in forked child, not a thread)

```rust
unsafe fn setup_etc_overlay(ns_name: &str) -> std::io::Result<()> {
    // 1. Create private mount namespace.
    //    Safe: we're in the forked child process, not a thread.
    //    This only affects the child — parent is unaffected.
    if libc::unshare(libc::CLONE_NEWNS) != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // 2. Make the entire mount tree private so our bind mounts
    //    don't propagate back to the host's mount namespace.
    let root = std::ffi::CString::new("/").unwrap();
    let none = std::ffi::CString::new("none").unwrap();
    if libc::mount(
        none.as_ptr(),
        root.as_ptr(),
        std::ptr::null(),
        libc::MS_REC | libc::MS_PRIVATE,
        std::ptr::null(),
    ) != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // 3. Bind-mount each file from /etc/netns/<name>/ over /etc/.
    //    If /etc/netns/<name>/ doesn't exist, this is a no-op.
    let etc_netns = format!("/etc/netns/{ns_name}");
    let entries = match std::fs::read_dir(&etc_netns) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };

    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let src = entry.path();
        let dst = std::path::Path::new("/etc").join(&file_name);

        // Only overlay if the target exists (can't bind-mount over nothing).
        // For files that don't exist in /etc/, skip silently.
        if !dst.exists() {
            continue;
        }

        let src_c = std::ffi::CString::new(
            src.as_os_str().as_encoded_bytes()
        ).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "null byte in path"
        ))?;
        let dst_c = std::ffi::CString::new(
            dst.as_os_str().as_encoded_bytes()
        ).map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "null byte in path"
        ))?;

        if libc::mount(
            src_c.as_ptr(),
            dst_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        ) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}
```

### Key Considerations

1. **Safety of `unshare(CLONE_NEWNS)` in `pre_exec()`:**
   `pre_exec()` runs in the forked child process, not in a thread. The child
   is an independent process at this point. `unshare(CLONE_NEWNS)` creates a
   private mount namespace for the child only. The parent process (and all its
   threads) are completely unaffected. This is the same pattern `ip netns exec`
   uses (see `iproute2/ip/ipnetns.c:netns_exec()`).

2. **Mount propagation:** `MS_REC | MS_PRIVATE` on `/` is required to prevent
   bind mounts from propagating back to the host. Without this, systemd's
   default `shared` propagation would make our mounts visible everywhere.

3. **No-op when `/etc/netns/<name>/` doesn't exist:** If the consumer didn't
   create per-namespace files, the overlay step is silently skipped. Existing
   behavior is fully preserved.

4. **Target file must exist:** `mount --bind` requires the target to exist.
   `/etc/hosts` and `/etc/resolv.conf` always exist on normal systems. Files
   that don't exist in `/etc/` are skipped.

5. **Async-safety in `pre_exec()`:** The `pre_exec()` closure runs between
   `fork()` and `exec()` in a signal-restricted context. The implementation
   uses only async-signal-safe syscalls (`unshare`, `mount`, `setns`) and
   avoids allocations where possible. The `read_dir()` call and `CString`
   allocations are technically not async-signal-safe, but this matches the
   existing pattern in nlink's spawn code (which already allocates in
   `pre_exec()`). For maximum correctness, the directory listing could be
   computed before `fork()` and passed to `pre_exec()` via captured variables.

6. **Root required:** `unshare(CLONE_NEWNS)` requires `CAP_SYS_ADMIN` (or
   root). This is fine — nlink operations already require root for namespace
   creation and netlink operations.

## Testing

| Test | Description |
|------|-------------|
| `test_spawn_with_etc_overlay_hosts` | Create namespace, write `/etc/netns/<name>/hosts`, spawn `cat /etc/hosts` with overlay, verify custom content |
| `test_spawn_with_etc_overlay_resolv` | Same for `/etc/resolv.conf` |
| `test_spawn_with_etc_overlay_no_dir` | No `/etc/netns/<name>/` dir — should succeed (no-op) |
| `test_spawn_with_etc_overlay_host_unaffected` | After spawning with overlay, verify host's `/etc/hosts` is unchanged |
| `test_spawn_without_overlay_unchanged` | Existing `spawn()` behavior is not affected |

## Reference

- `ip-netns(8)` man page: documents the `/etc/netns/<name>/` convention
- `iproute2/ip/ipnetns.c:netns_exec()`: reference implementation
- `unshare(2)` man page: `CLONE_NEWNS` semantics
- `mount_namespaces(7)`: mount propagation types (shared, private, slave)

## Impact on Existing API

**None.** This is purely additive:
- Option A adds new functions; existing functions are unchanged.
- Option B adds a new function with options; existing functions are unchanged.
- Default behavior (no overlay) is preserved.
- No breaking changes to the public API.
