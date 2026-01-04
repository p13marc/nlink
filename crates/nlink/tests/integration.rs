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

#[path = "integration/ratelimit.rs"]
mod ratelimit;
