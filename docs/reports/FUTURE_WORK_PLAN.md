# Future Work Plan

Plans for closing nlink library gaps before starting nlink-lab development.

See also: [NLINK_LAB_READINESS_REPORT.md](../NLINK_LAB_READINESS_REPORT.md) for full gap analysis.

---

## Plan 1: Sysctl Management

**Priority:** Critical (blocks nlink-lab)
**Effort:** 1-2 days

### Goal

Add namespace-aware sysctl read/write support via `/proc/sys/` filesystem operations.

### API Design

```rust
use nlink::netlink::namespace;

// Standalone functions (operate in a named namespace)
namespace::set_sysctl("myns", "net.ipv4.ip_forward", "1")?;
namespace::get_sysctl("myns", "net.ipv4.ip_forward")?; // -> "1"
namespace::set_sysctls("myns", &[
    ("net.ipv4.ip_forward", "1"),
    ("net.ipv6.conf.all.forwarding", "1"),
])?;

// Default namespace variants (no namespace switching)
sysctl::get("net.ipv4.ip_forward")?;
sysctl::set("net.ipv4.ip_forward", "1")?;
```

### Implementation Steps

1. **Create `crates/nlink/src/netlink/sysctl.rs`**
   - Helper to convert dotted sysctl key to `/proc/sys/` path
     (`net.ipv4.ip_forward` -> `/proc/sys/net/ipv4/ip_forward`)
   - `pub fn get(key: &str) -> Result<String>` — read from `/proc/sys/`
   - `pub fn set(key: &str, value: &str) -> Result<()>` — write to `/proc/sys/`
   - `pub fn set_many(entries: &[(&str, &str)]) -> Result<()>` — batch write

2. **Add namespace-aware wrappers in `namespace.rs`**
   - `pub fn get_sysctl(ns_name: &str, key: &str) -> Result<String>`
     Uses `execute_in(ns_name, || sysctl::get(key))`
   - `pub fn set_sysctl(ns_name: &str, key: &str, value: &str) -> Result<()>`
   - `pub fn set_sysctls(ns_name: &str, entries: &[(&str, &str)]) -> Result<()>`
   - Path-based variants: `get_sysctl_path()`, `set_sysctl_path()`

3. **Register module in `netlink/mod.rs`**
   - Add `pub mod sysctl;`

4. **Error handling**
   - Return `Error::PermissionDenied` for EACCES (not root)
   - Return `Error::InvalidArgument` for non-existent sysctl keys
   - Return `Error::NamespaceNotFound` when namespace doesn't exist

5. **Integration tests** (`tests/integration/sysctl.rs`)
   - Test get/set in a namespace
   - Test `ip_forward` toggle
   - Test batch set
   - Test error on invalid key
   - Test error on permission denied (if not root)

### Notes

- This is pure filesystem I/O, not netlink. The `execute_in()` infrastructure
  handles namespace switching via `setns()`.
- The functions are synchronous (filesystem reads are fast and don't benefit
  from async). If needed, `tokio::task::spawn_blocking` can be used by callers.
- Key validation: reject keys containing `..` or `/` to prevent path traversal.

---

## Plan 2: Namespace Process Spawning

**Priority:** Critical (blocks nlink-lab)
**Effort:** 2-3 days

### Goal

Add the ability to spawn child processes inside network namespaces without
shelling out to `ip netns exec`.

### API Design

```rust
use nlink::netlink::namespace;
use std::process::Command;

// Spawn in named namespace
let child = namespace::spawn("myns", Command::new("iperf3").arg("-s"))?;
child.wait()?;

// Spawn with output capture
let output = namespace::spawn_output("myns", Command::new("ip").arg("addr"))?;
println!("{}", String::from_utf8_lossy(&output.stdout));

// NamespaceSpec integration
let spec = NamespaceSpec::Named("myns");
let child = spec.spawn(Command::new("ping").arg("-c1").arg("10.0.0.1"))?;
```

### Implementation Steps

1. **Add spawn functions to `namespace.rs`**

   Core implementation using `CommandExt::pre_exec()`:
   ```rust
   use std::os::unix::process::CommandExt;

   pub fn spawn(ns_name: &str, mut cmd: Command) -> Result<Child> {
       let ns_fd = open(ns_name)?;
       let raw_fd = ns_fd.as_raw_fd();
       // Keep ns_fd alive by moving into the closure's capture
       unsafe {
           cmd.pre_exec(move || {
               // setns in the child process after fork, before exec
               if libc::setns(raw_fd, libc::CLONE_NEWNET) != 0 {
                   return Err(std::io::Error::last_os_error());
               }
               Ok(())
           });
       }
       let child = cmd.spawn().map_err(Error::Io)?;
       // ns_fd is dropped here (after fork), which is fine — child has switched
       drop(ns_fd);
       Ok(child)
   }
   ```

   **Important:** `pre_exec` runs between `fork()` and `exec()` in the child
   process. The parent process is unaffected. This is the standard safe pattern
   for namespace-aware spawning.

2. **Convenience functions**
   - `pub fn spawn_output(ns_name: &str, cmd: Command) -> Result<Output>`
     — spawn and wait for output
   - `pub fn spawn_path(path: &Path, cmd: Command) -> Result<Child>`
     — spawn in namespace by path
   - `pub fn spawn_pid(pid: u32, cmd: Command) -> Result<Child>`
     — spawn in namespace of given PID

3. **NamespaceSpec integration**
   - Add `pub fn spawn(&self, cmd: Command) -> Result<Child>` to `NamespaceSpec`
   - Dispatches to the appropriate variant

4. **fd lifetime safety**
   - `NamespaceFd` must outlive the `pre_exec` closure. The fd is `dup()`-ed
     by the kernel during `fork()`, so the child gets its own copy. The parent
     can drop `NamespaceFd` after `spawn()` returns.
   - Alternative: use `dup()` explicitly and close in `pre_exec` after `setns`.

5. **Integration tests** (`tests/integration/namespace_spawn.rs`)
   - Spawn `ip link show` in a namespace, verify output
   - Spawn a background process, verify it's running, kill it
   - Spawn in namespace with a dummy interface, verify it's visible
   - Test error when namespace doesn't exist
   - Test error when binary doesn't exist

6. **Migrate test infrastructure**
   - Update `TestNamespace::exec()` to use the new `namespace::spawn_output()`
     instead of shelling out to `ip netns exec`
   - This validates the implementation with the entire existing test suite

### Notes

- `pre_exec` is `unsafe` because it runs in a `fork()`-ed child. The closure
  must be async-signal-safe. `setns()` is async-signal-safe (it's a syscall).
- For tokio integration, callers can use `tokio::process::Command` which also
  supports `pre_exec` via the same `CommandExt` trait.
- The parent process's namespace is never affected — this is the key advantage
  over `execute_in()` which changes the current thread's namespace.

---

## Backlog (not blocking nlink-lab)

These items from the previous plan remain valid but are lower priority:

| Item | Priority | Notes |
|------|----------|-------|
| CI integration tests | Medium | GitHub Actions with privileged containers |
| MACsec enhancements | Medium | Device creation, stats, hardware offload |
| SRv6 advanced features | Low | HMAC, policy, uSID, counters |
| Additional edge case tests | Low | Error conditions, race conditions |
| `ss` binary remaining features | Low | Kill mode, expression filters, DCCP/VSOCK |
| VRF in NetworkConfig | Low | Add `DeclaredLinkType::Vrf` variant |
