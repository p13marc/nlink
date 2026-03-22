# Plan 039: Namespace Process Spawning

**Priority:** Critical (blocks nlink-lab)
**Effort:** 2-3 days
**Target:** Library

## Summary

Add the ability to spawn child processes inside network namespaces without
shelling out to `ip netns exec`. Uses `CommandExt::pre_exec()` + `setns()` to
switch the child process's namespace between `fork()` and `exec()`, leaving
the parent process unaffected.

## API Design

```rust
use nlink::netlink::namespace;
use std::process::Command;

// Spawn in named namespace — returns std::process::Child
let mut child = namespace::spawn("myns", Command::new("iperf3").arg("-s"))?;
child.kill()?;

// Spawn and collect output
let output = namespace::spawn_output("myns", Command::new("ip").arg("addr"))?;
println!("{}", String::from_utf8_lossy(&output.stdout));

// Spawn by path
let child = namespace::spawn_path("/proc/1234/ns/net", Command::new("ping").arg("10.0.0.1"))?;

// NamespaceSpec integration
let spec = NamespaceSpec::Named("myns");
let child = spec.spawn(Command::new("nginx"))?;
let output = spec.spawn_output(Command::new("ip").arg("link"))?;
```

## Implementation

### Core: `pre_exec` + `setns` pattern

```rust
use std::os::unix::process::CommandExt;

pub fn spawn(ns_name: &str, mut cmd: Command) -> Result<Child> {
    let ns_fd = open(ns_name)?;
    let raw_fd = ns_fd.as_raw_fd();

    // SAFETY: setns is async-signal-safe. pre_exec runs in the child
    // process after fork() but before exec(). The fd is valid because
    // ns_fd is kept alive until after spawn() returns.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setns(raw_fd, libc::CLONE_NEWNET) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = cmd.spawn().map_err(Error::Io)?;
    drop(ns_fd); // Child has forked; parent can close the fd
    Ok(child)
}
```

### Key safety considerations

- `pre_exec` runs between `fork()` and `exec()` — must be async-signal-safe
- `libc::setns()` is a syscall, which is async-signal-safe
- `ns_fd` must outlive the `pre_exec` closure — it's captured by the closure
  and the closure runs during `cmd.spawn()`, before `ns_fd` is dropped
- The parent process's namespace is **never** affected

## Progress

### Core Functions (`namespace.rs`)

- [x] `pub fn spawn(ns_name: &str, cmd: Command) -> Result<Child>`
- [x] `pub fn spawn_output(ns_name: &str, cmd: Command) -> Result<Output>`
- [x] `pub fn spawn_path<P: AsRef<Path>>(path: P, cmd: Command) -> Result<Child>`
- [x] `pub fn spawn_output_path<P: AsRef<Path>>(path: P, cmd: Command) -> Result<Output>`

### NamespaceSpec Integration

- [x] `pub fn spawn(&self, cmd: Command) -> Result<Child>` on `NamespaceSpec`
- [x] `pub fn spawn_output(&self, cmd: Command) -> Result<Output>` on `NamespaceSpec`
- [x] Handle `NamespaceSpec::Default` (spawn without namespace switching)

### Error Handling

- [x] Map `ESRCH` / bad namespace to `Error::NamespaceNotFound`
- [x] Map spawn failures to `Error::Io`
- [x] Map `setns` EPERM to `Error::PermissionDenied`

### Tests (`tests/integration/namespace_spawn.rs`)

- [x] Spawn `ip link show` in namespace, verify loopback is present
- [x] Spawn process in namespace with dummy interface, verify it's visible
- [x] Spawn background process, verify it's running, kill it
- [x] `spawn_output` captures stdout correctly
- [x] Error on non-existent namespace
- [x] Error on non-existent binary
- [x] Parent namespace is unaffected after spawn

### Migrate Test Infrastructure

- [x] Update `TestNamespace::exec()` in `tests/common/mod.rs` to use
      `namespace::spawn_output()` instead of `ip netns exec`
- [ ] Verify all existing integration tests still pass

### Documentation

- [x] Doc comments with examples on all public functions
- [x] CLAUDE.md update with namespace spawn examples
- [x] SAFETY comments on the `pre_exec` + `setns` block
