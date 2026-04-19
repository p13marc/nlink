---
to: nlink maintainers
from: nlink maintainers
subject: More cookbook recipes + public lab/test helpers
target version: 0.13.0
date: 2026-04-19
status: draft, awaiting review
---

# Recipes & Lab Helpers Plan

## 0. Summary

Two related additive pieces of work:

1. **More cookbook recipes** under `docs/recipes/`. Today we have one
   (`per-peer-impairment.md`). Add several focused recipes covering
   common nlink uses:
   - Bridge VLAN setup
   - Bidirectional rate limiting (egress + ingress)
   - WireGuard mesh in namespaces
   - IPsec with XFRM
   - nftables stateful firewall + connection tracking
   - Per-cgroup classification
   - Multi-namespace event monitoring
2. **Lab/test helpers as a public module.** Today `TestNamespace` and
   friends live in `crates/nlink/tests/common/mod.rs` (test-only).
   Promote them to a public, feature-gated `nlink::lab` module so
   downstream consumers can build their own integration tests
   without re-implementing namespace setup.

Both are additive (no BC break). The lab module behind a `lab`
feature flag avoids forcing the dep on production users.

---

## 1. Goals & non-goals

### Goals

1. 6-8 new cookbook recipes covering common nlink usage patterns,
   each ~200 lines (problem statement, code, caveats).
2. A `nlink::lab` module behind `lab` feature flag exposing:
   - `TestNamespace` (rename to `LabNamespace` to signal "not just for
     tests")
   - `connect_to`, `add_dummy`, `link_up`, `add_addr`
   - New: `LabBridge` (create + manage a bridge), `LabVeth` (paired
     veth with optional namespace separation)
   - New: `with_namespace<F>(name, F)` runner that creates,
     executes, cleans up
3. Recipes link from the README index, the rustdoc, and from
   `CLAUDE.md`.
4. Lab module documented enough that downstream test suites can
   adopt it.

### Non-goals

1. A full property-based testing framework. Just helpers.
2. Network simulation (we have impairment via `PerPeerImpairer`;
   that's the simulation primitive).
3. Recipes that require BPF compilation or external toolchains.
4. Recipes that require non-Linux components.

---

## 2. Cookbook recipes

### 2.1. Recipe index

Each recipe in `docs/recipes/<topic>.md`. Index at `docs/recipes/README.md`.

| Recipe | Sketch | LOC est. |
|---|---|---|
| `per-peer-impairment.md` | **Already exists** | — |
| `bridge-vlan.md` | Build a VLAN-aware bridge with two trunk ports + access ports per VLAN | 200 |
| `bidirectional-rate-limit.md` | Egress shaping with HTB + ingress policing via IFB | 250 |
| `wireguard-mesh.md` | 3-peer WireGuard mesh in 3 namespaces, generated keys, configured via nlink::genl::wireguard | 300 |
| `xfrm-ipsec-tunnel.md` | Site-to-site IPsec tunnel between two namespaces using XFRM | 250 |
| `nftables-stateful-fw.md` | Stateful firewall (allow established, drop new from WAN) + conntrack lookup | 200 |
| `cgroup-classification.md` | Classify traffic by cgroup membership using cls_basic + meta ematch (depends on Plan 133) | 200 |
| `multi-namespace-events.md` | Watch link/addr/route events across N namespaces concurrently with `StreamMap` | 180 |

Total ~1600 lines of documentation across 7 new recipes.

### 2.2. Recipe template

Standardize structure (matches the existing `per-peer-impairment.md`):

```markdown
# <Recipe title>

## When to use this

Brief problem statement. When this is the right tool, when it isn't.

## High-level approach

Diagram if helpful. One-paragraph summary of the technique.

## Code

```rust
// Self-contained example. Compiles. Runs end-to-end (with root).
```

## Symmetry / direction notes

If the recipe has direction-sensitive aspects (e.g., source vs
destination matching, ingress vs egress), call them out.

## Caveats

- Required kernel modules
- Required namespaces / capabilities
- Compatibility with sibling helpers / tools

## Hand-rolled equivalent

If a high-level helper exists, link to it. Otherwise show the
hand-rolled netlink primitive sequence so users can adapt.

## See also

- Other recipes
- API doc links
- Kernel docs
```

### 2.3. Cross-references

Each recipe ends with cross-references to:
- Other recipes (transitive cookbook navigation)
- API docs on docs.rs
- Relevant kernel documentation (man pages, `Documentation/networking/`)

`docs/recipes/README.md` lists all recipes with one-line descriptions.

`README.md` (root) links to `docs/recipes/README.md` from the
"Recipes" section.

`CLAUDE.md` adds a "Recipe index" subsection pointing at the same.

---

## 3. Lab / test helpers as a public module

### 3.1. Today

`crates/nlink/tests/common/mod.rs` (195 LOC):

```rust
pub struct TestNamespace { name: String }

impl TestNamespace {
    pub fn new(prefix: &str) -> Result<Self>;
    pub fn name(&self) -> &str;
    pub fn connection(&self) -> Result<Connection<Route>>;
    pub fn exec(&self, cmd: &str, args: &[&str]) -> Result<String>;
    pub fn exec_ignore(&self, cmd: &str, args: &[&str]);
    pub fn connect_to(&self, other: &TestNamespace, local_name: &str, remote_name: &str) -> Result<()>;
    pub fn add_dummy(&self, name: &str) -> Result<()>;
    pub fn link_up(&self, name: &str) -> Result<()>;
    pub fn add_addr(&self, dev: &str, addr: &str) -> Result<()>;
}

impl Drop for TestNamespace { /* ip netns delete */ }
```

Used by `tests/integration/*.rs` exclusively.

### 3.2. The case for promoting to public

- Downstream nlink consumers (nlink-lab, others) build similar
  abstractions repeatedly.
- TestNamespace's API is exactly the right shape for "spin up an
  isolated network env, run code, clean up."
- The functionality (namespace create/delete, command spawn) all
  uses public nlink APIs already; the helper is just convenient
  packaging.

### 3.3. Design

```rust
// crates/nlink/src/lab/mod.rs (gated by `lab` feature)

/// An ephemeral, isolated network namespace for testing or local
/// experimentation. Created on `LabNamespace::new`, deleted on drop.
///
/// Requires `CAP_SYS_ADMIN` (typically root). Use this for
/// integration tests and local lab setups.
pub struct LabNamespace {
    name: String,
}

impl LabNamespace {
    /// Create a uniquely-named namespace.
    pub fn new(prefix: &str) -> Result<Self>;

    /// Create a namespace with a specific name (errors if it exists).
    pub fn named(name: &str) -> Result<Self>;

    pub fn name(&self) -> &str;

    /// Get a `Connection<Route>` scoped to this namespace.
    pub fn connection(&self) -> Result<Connection<Route>>;

    /// Get a generic-protocol connection.
    pub fn connection_for<P: Protocol>(&self) -> Result<Connection<P>>;

    /// Spawn a child process inside this namespace.
    pub fn spawn(&self, cmd: Command) -> Result<Child>;

    /// Spawn and collect output.
    pub fn spawn_output(&self, cmd: Command) -> Result<Output>;

    /// Convenience: `ip` command runner inside the namespace.
    pub fn exec_ip(&self, args: &[&str]) -> Result<String>;
}

impl Drop for LabNamespace { /* cleanup */ }
```

```rust
// Bridge / veth builders

pub struct LabBridge<'a> {
    ns: &'a LabNamespace,
    name: String,
}

impl<'a> LabBridge<'a> {
    pub fn new(ns: &'a LabNamespace, name: &str) -> Self;
    pub async fn create(self) -> Result<Self>;
    pub async fn add_port(self, port: &str) -> Result<Self>;
    pub async fn up(self) -> Result<Self>;
    pub fn name(&self) -> &str;
}

pub struct LabVeth { /* ... */ }

/// Build a veth pair, optionally moving the peer to another namespace.
impl LabVeth {
    pub fn new(local_name: &str, peer_name: &str) -> Self;
    pub fn peer_in(mut self, ns: &LabNamespace) -> Self;
    pub async fn create_in(self, ns: &LabNamespace) -> Result<Self>;
    pub fn local_name(&self) -> &str;
    pub fn peer_name(&self) -> &str;
}
```

```rust
// Run a closure in a namespace, with auto-cleanup.

/// Convenience: create a namespace, run an async closure, delete on
/// completion (even on panic — `LabNamespace`'s `Drop` handles it).
pub async fn with_namespace<F, Fut, T>(prefix: &str, f: F) -> Result<T>
where
    F: FnOnce(LabNamespace) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let ns = LabNamespace::new(prefix)?;
    f(ns).await
}
```

### 3.4. Feature flag

```toml
# crates/nlink/Cargo.toml

[features]
default = []
sockdiag = []
tuntap = []
tc = []
output = ["dep:serde", "dep:serde_json"]
namespace_watcher = []
lab = []      # NEW
full = ["sockdiag", "tuntap", "tc", "output", "namespace_watcher", "lab"]
```

Lab module re-exports gated:

```rust
// crates/nlink/src/lib.rs

#[cfg(feature = "lab")]
pub mod lab;
```

### 3.5. Migrate `tests/common/mod.rs` to use the public lab module

After promoting, the test helper becomes a thin alias:

```rust
// crates/nlink/tests/common/mod.rs

#[cfg(feature = "lab")]
pub use nlink::lab::LabNamespace as TestNamespace;
```

Or just delete `tests/common/mod.rs` and update integration tests
to import from `nlink::lab` directly. The latter is cleaner.

### 3.6. Documentation

- Module-level rustdoc on `nlink::lab` with usage example.
- New recipe: `docs/recipes/lab-setup.md` showing how to build a
  3-namespace test environment.
- CLAUDE.md mention under "Testing" section.

---

## 4. Files touched

### 4.1. Recipes

| Path | Change | Approx LOC |
|---|---|---|
| `docs/recipes/README.md` | New: index of all recipes | 60 |
| `docs/recipes/bridge-vlan.md` | New | 200 |
| `docs/recipes/bidirectional-rate-limit.md` | New | 250 |
| `docs/recipes/wireguard-mesh.md` | New | 300 |
| `docs/recipes/xfrm-ipsec-tunnel.md` | New | 250 |
| `docs/recipes/nftables-stateful-fw.md` | New | 200 |
| `docs/recipes/cgroup-classification.md` | New (depends on Plan 133's BasicFilter ematch) | 200 |
| `docs/recipes/multi-namespace-events.md` | New | 180 |
| `docs/recipes/lab-setup.md` | New | 150 |
| `README.md` | Add "Recipes" section linking the index | 15 |
| `CLAUDE.md` | Add recipe index pointer | 20 |

Total ~1825 lines of docs.

### 4.2. Lab module

| Path | Change | Approx LOC |
|---|---|---|
| `crates/nlink/src/lab/mod.rs` | New: `LabNamespace`, `with_namespace` | 200 |
| `crates/nlink/src/lab/bridge.rs` | New: `LabBridge` builder | 150 |
| `crates/nlink/src/lab/veth.rs` | New: `LabVeth` builder | 120 |
| `crates/nlink/src/lib.rs` | `#[cfg(feature = "lab")] pub mod lab;` | 5 |
| `crates/nlink/Cargo.toml` | Add `lab` feature + add to `full` | 5 |
| `crates/nlink/tests/common/mod.rs` | Migrate to use `nlink::lab` (or delete) | -100 |
| `crates/nlink/tests/integration/*.rs` | Update imports | ~30 |
| `crates/nlink/examples/lab/three_namespace.rs` | New runnable demo | 100 |

Total ~510 LOC code + tests refactor.

---

## 5. Tests

### 5.1. Recipes

Each recipe is **runnable code** as part of the integration suite (or
flagged out if it requires environment we don't have in CI):

```rust
// crates/nlink/tests/integration/recipes.rs

#[cfg(feature = "lab")]
mod recipe_smoke {
    /// The bridge VLAN recipe builds successfully end-to-end.
    #[tokio::test]
    async fn bridge_vlan_recipe() -> nlink::Result<()> {
        require_root!();
        // Inline the recipe code; assert at the end that the resulting
        // state matches what the recipe documents.
    }
}
```

This catches recipe rot: if a kernel API or our wrapper changes and a
recipe stops working, CI tells us.

### 5.2. Lab module

- `LabNamespace` lifecycle: create → connection → drop deletes
  namespace.
- `LabBridge` builder: create → add_port → up → assert via dump.
- `LabVeth` peer_in: pair created, peer correctly placed in other ns.
- `with_namespace` runs closure, cleans up even on panic.

---

## 6. Documentation

### 6.1. README addition

```markdown
## Recipes

Cookbook-style end-to-end examples for common nlink use cases:

- [Per-peer impairment](docs/recipes/per-peer-impairment.md)
- [Bridge VLAN setup](docs/recipes/bridge-vlan.md)
- [Bidirectional rate limiting](docs/recipes/bidirectional-rate-limit.md)
- [WireGuard mesh in namespaces](docs/recipes/wireguard-mesh.md)
- [XFRM IPsec site-to-site tunnel](docs/recipes/xfrm-ipsec-tunnel.md)
- [nftables stateful firewall](docs/recipes/nftables-stateful-fw.md)
- [Cgroup-based traffic classification](docs/recipes/cgroup-classification.md)
- [Multi-namespace event monitoring](docs/recipes/multi-namespace-events.md)
- [Setting up a lab environment](docs/recipes/lab-setup.md)
```

### 6.2. CHANGELOG

```markdown
### Added

- `nlink::lab` module (behind `lab` feature flag): public
  `LabNamespace`, `LabBridge`, `LabVeth`, `with_namespace` helpers.
  Promoted from `tests/common/mod.rs` so downstream consumers can
  build integration tests on the same primitives.
- 8 new cookbook recipes under `docs/recipes/` covering bridge VLANs,
  bidirectional rate limiting, WireGuard mesh, IPsec tunnels,
  nftables stateful firewall, cgroup classification, multi-namespace
  events, and lab setup.
```

---

## 7. Open questions

1. **Recipe location: `docs/recipes/` or `crates/nlink/recipes/`?**
   Lean: `docs/recipes/`. Recipes are cross-crate (touch ratelimit,
   impair, route, genl, etc.). Keeping them at workspace level
   makes that natural.
2. **Lab module name: `lab` or `testing` or `playground`?**
   Lean: `lab`. Suggests "set up an experiment" without claiming
   it's only for tests. `testing` is too narrow (lab-style setups
   are useful in CLI tools too).
3. **Should `LabNamespace::Drop` log on cleanup failure?**
   Yes — at WARN via tracing (Plan 134). Otherwise silent failures
   leak namespaces.
4. **Recipe doctests vs separate `tests/integration/recipes.rs`?**
   Lean: separate test file. Doctests in recipes would clutter the
   docs and slow `cargo test`. The smoke test file mirrors recipe
   code with assertions.
5. **Examples vs recipes overlap.** Examples (`crates/nlink/examples/`)
   are runnable Rust binaries; recipes are markdown explanations
   with code. Both have value: examples are `cargo run`-able;
   recipes are skim-friendly. Keep both; cross-link.

---

## 8. Phasing

Two independent PRs:

- **PR A: Lab module** (~510 LOC code + ~100 LOC test migration)
  - Promote `TestNamespace` → `LabNamespace`
  - Add `LabBridge`, `LabVeth`, `with_namespace`
  - Migrate test helpers
  - Lab feature flag + dev-dep wiring
  - One recipe (`docs/recipes/lab-setup.md`) demonstrating the module

- **PR B: Recipes** (~1700 LOC docs)
  - The 7 new recipes, in any order
  - Smoke tests in `tests/integration/recipes.rs`
  - README + CLAUDE.md cross-references

Order: A first, then B can use lab helpers in recipe code samples.

---

## 9. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Recipe code rots when APIs evolve | Certain | Smoke tests catch this in CI |
| `lab` feature pulls in heavy dev-deps | Low | Audit dep tree; should be zero new deps |
| `LabNamespace` cleanup fails silently → namespace leak | Medium | WARN log on drop failure; document with a manual `ip netns list` check |
| 8 recipes is too many to maintain | Medium | Start with 3-4; add more as demand emerges. Recipe README lists "wanted" topics for community contributions. |
| Recipe lengths balloon | Medium | Template enforces structure; 200-line target |

---

## 10. What we are NOT doing

- **No recipe directories per topic** (e.g., `docs/recipes/tc/`).
  Flat structure for now; reorganize when there are 20+ recipes.
- **No HTML rendering / mdbook**. Plain markdown viewable on GitHub
  is enough.
- **No "test recipe" framework** for capturing recipe-as-test
  declaratively. The smoke tests are hand-written.
- **No per-recipe `cargo` example.** Recipes are docs; examples are
  bins. Don't conflate.
- **No `lab` feature in the default feature set.** Opt-in.

---

## 11. Definition of done

### PR A: Lab module

- [ ] `nlink::lab::LabNamespace` exists, gated by `lab` feature
- [ ] `LabBridge` and `LabVeth` builders exist
- [ ] `with_namespace` async runner exists
- [ ] `tests/common/mod.rs` migrated (or deleted in favor of
      direct `nlink::lab` imports)
- [ ] All existing integration tests pass after migration
- [ ] `crates/nlink/examples/lab/three_namespace.rs` runs (with sudo)
- [ ] Module-level rustdoc with usage example
- [ ] CHANGELOG entry written

### PR B: Recipes

- [ ] 7 new recipes under `docs/recipes/`
- [ ] `docs/recipes/README.md` index
- [ ] README and CLAUDE.md updated to point at recipe index
- [ ] `tests/integration/recipes.rs` smoke-tests each recipe
- [ ] CHANGELOG entry written

---

End of plan.
