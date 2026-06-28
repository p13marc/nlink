//! Integration test entry point.
//!
//! This file serves as the entry point for integration tests.
//! The actual tests are organized in the `integration/` directory.
//!
//! # Running Tests
//!
//! Integration tests require root privileges:
//!
//! ```bash
//! # Run all integration tests
//! sudo cargo test --test integration
//!
//! # Run specific test module
//! sudo cargo test --test integration link
//!
//! # Run a single test
//! sudo cargo test --test integration test_create_veth_pair
//!
//! # Run with output
//! sudo cargo test --test integration -- --nocapture
//! ```
//!
//! # Test Organization
//!
//! - `link.rs` - Link creation, modification, and deletion
//! - `address.rs` - IP address management
//! - `route.rs` - Route management
//! - `tc.rs` - Traffic control (qdisc, class, filter)
//! - `events.rs` - Event monitoring

#[macro_use]
#[path = "common/mod.rs"]
mod common;

#[path = "integration/link.rs"]
mod link;

#[path = "integration/address.rs"]
mod address;

#[path = "integration/route.rs"]
mod route;

#[path = "integration/tc.rs"]
mod tc;

#[path = "integration/events.rs"]
mod events;

#[path = "integration/config.rs"]
mod config;

// Plan 186 — VLAN parent ifindex race repro + topo-sort
// regression coverage. Lives in its own module so the focused
// scenarios stay out of the broader `config` integration
// surface.
#[path = "integration/network_config_apply.rs"]
mod network_config_apply;

#[path = "integration/ratelimit.rs"]
mod ratelimit;

#[path = "integration/impair.rs"]
mod impair;

#[path = "integration/diagnostics.rs"]
mod diagnostics;

#[path = "integration/timeout.rs"]
mod timeout;

#[path = "integration/sysctl.rs"]
mod sysctl;

#[path = "integration/namespace_spawn.rs"]
mod namespace_spawn;

#[path = "integration/conntrack.rs"]
mod conntrack;

// Feature-gated: only compiles when `sockdiag` is enabled. The
// privileged integration workflow builds with `lab,sockdiag` so the
// on-kernel bytecode validation runs there.
#[cfg(feature = "sockdiag")]
#[path = "integration/sockdiag_bytecode.rs"]
mod sockdiag_bytecode;

#[path = "integration/neigh.rs"]
mod neigh;

// Plan 166 backfill — root-gated tests for the headline 0.16 features.
// Each module gates on `require_root!()` so this all early-returns
// when run as a regular user.

#[path = "integration/ergonomics.rs"]
mod ergonomics;

#[path = "integration/streaming.rs"]
mod streaming;

#[path = "integration/flowtable.rs"]
mod flowtable;

#[path = "integration/nftables_diag.rs"]
mod nftables_diag;

#[path = "integration/nftables_reconcile.rs"]
mod nftables_reconcile;

#[path = "integration/syscall_batch.rs"]
mod syscall_batch;

#[path = "integration/pool.rs"]
mod pool;

// Plan 194 — concurrent stress + seq-routing regression.
// Spawns 16 concurrent dumps on a shared Arc<Connection>
// and 16 concurrent LabNamespace::new calls. Both root-gated.
#[path = "integration/concurrent_stress.rs"]
mod concurrent_stress;

// 0.19 cycle backfill — Plan 188/196/199/200/202 round-trips
// surfaced by the post-cycle audit as kernel-touching surfaces
// with only unit-test coverage. All root-gated; WG/nft tests
// also gated by require_module!().
#[path = "integration/cycle_0_19_backfill.rs"]
mod cycle_0_19_backfill;

// Plan 221 — 0.19.1 XFRM hotfix regression tests. Root-gated +
// `xfrm_user` module-gated. Lock the corrected constant + dispatch
// values so a future commit can't re-introduce the bug class.
#[path = "integration/xfrm_hotfix.rs"]
mod xfrm_hotfix;

// Plan 197 — OVPN GENL family integration tests. Root-gated +
// `ovpn` module-gated (kernel 6.16+). Exercises peer + key ops
// + the declarative OvpnConfig diff + apply cycle.
#[path = "integration/ovpn.rs"]
mod ovpn;

// Plan 234 (0.21) — Dispatcher foundation: ENOBUFS routing to
// ResyncMarker::ResyncStart, per-family wiring smoke checks,
// concurrent-request coexistence with dispatcher subscribers.
#[path = "integration/dispatcher.rs"]
mod dispatcher;
