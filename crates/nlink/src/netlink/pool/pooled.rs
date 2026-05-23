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
    pub fn invalidate(&mut self) {
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
    }
}

impl<P: ProtocolState> Deref for PooledConnection<'_, P> {
    type Target = Connection<P>;

    fn deref(&self) -> &Connection<P> {
        // The Option is only `None` after `invalidate()`, after
        // which the guard is one drop away from gone — no caller
        // can deref through the guard between `invalidate()` and
        // the drop because `invalidate` takes `&mut self` and
        // deref needs `&self`. So this `expect` cannot fire from
        // safe code.
        self.conn
            .as_ref()
            .expect("PooledConnection holds a Connection until drop")
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
