//! `PooledConnection<'p, P>` — RAII guard that derefs to
//! `&Connection<P>` and returns the connection on drop.

use std::ops::Deref;

use super::inner::ConnectionPool;
use crate::netlink::{connection::Connection, protocol::ProtocolState};

/// A pooled connection borrowed from a [`ConnectionPool`].
///
/// Implements `Deref<Target = Connection<P>>` so every typed
/// connection method is callable directly on the guard. On drop the
/// underlying `Connection` is returned to the pool. Use
/// [`Self::invalidate`] to mark the connection as bad and have it
/// dropped (instead of returned) on guard drop.
#[non_exhaustive]
pub struct PooledConnection<'p, P: ProtocolState> {
    pool: &'p ConnectionPool<P>,
    conn: Option<Connection<P>>,
}

impl<'p, P: ProtocolState> PooledConnection<'p, P> {
    pub(super) fn new(pool: &'p ConnectionPool<P>, conn: Connection<P>) -> Self {
        Self {
            pool,
            conn: Some(conn),
        }
    }

    /// Mark this connection as unhealthy. On drop it will be
    /// dropped (closing its socket) instead of being returned to
    /// the pool — the next acquire of a fresh connection will
    /// block until the pool refills, since the pool's
    /// builder-on-acquire-rebuild is a deliberate 0.17 follow-up
    /// (see Plan 159 §8 risk note).
    ///
    /// Use when you've observed a recoverable error that suggests
    /// the socket may be in a bad state (rare; most kernel errors
    /// are per-request, not per-socket).
    ///
    /// **Consumes the guard** (Plan 162) so a subsequent `&*p`
    /// is a compile error (E0382 — use of moved value) instead
    /// of a runtime panic. The "invalidate then drop" use case
    /// is source-compatible — the guard is gone after the call
    /// either way.
    ///
    /// ```compile_fail
    /// # use nlink::netlink::pool::PooledConnection;
    /// # async fn run<P: nlink::netlink::ProtocolState>(p: PooledConnection<'_, P>) {
    /// p.invalidate();
    /// let _ = &*p;  // compile error: borrow of moved value `p`
    /// # }
    /// ```
    pub fn invalidate(mut self) {
        // Drop the connection now; the slot will be reclaimed by
        // the next user calling acquire() — *which will block*
        // because the channel is one connection short. Plan 159 §8
        // documents this as the deliberate 0.16 trade-off: simpler
        // implementation, with a manual `invalidate-then-refill`
        // escape if needed.
        if let Some(conn) = self.conn.take() {
            tracing::warn!(
                ns = ?self.pool.namespace(),
                "PooledConnection::invalidate: dropping pooled connection"
            );
            drop(conn);
        }
        // `self` drops here; Drop sees conn == None and is a no-op.
    }
}

impl<P: ProtocolState> Deref for PooledConnection<'_, P> {
    type Target = Connection<P>;

    fn deref(&self) -> &Connection<P> {
        // INVARIANT: `conn` is set on construction and only
        // cleared by `invalidate(self)` which consumes the guard.
        // So any live `&self` borrow proves the guard hasn't
        // been moved, which proves `conn` is still `Some`.
        // The `debug_assert!` documents the invariant; the
        // `expect` is statically unreachable from safe code.
        debug_assert!(
            self.conn.is_some(),
            "PooledConnection::conn cleared without consuming \
             the guard — would imply a use-after-move past the \
             Rust borrow checker. Bug."
        );
        self.conn
            .as_ref()
            .expect("PooledConnection holds a Connection until drop (see invariant above)")
    }
}

impl<P: ProtocolState> Drop for PooledConnection<'_, P> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            // try_send is non-blocking. Capacity == pool size, so
            // for the exact set of pooled connections this can
            // only fail if the receiver was dropped (pool closed)
            // — in which case dropping `conn` here is the correct
            // teardown.
            let _ = self.pool.inner.available.try_send(conn);
        }
    }
}
