//! Shared types for TC recipe `reconcile()` operations.
//!
//! Each TC recipe helper (currently [`PerPeerImpairer`] and
//! [`PerHostLimiter`]) exposes both a destructive [`apply()`] verb and a
//! non-destructive [`reconcile()`] verb. `reconcile()` returns a
//! [`ReconcileReport`] describing the change set it computed (and, when
//! not in dry-run mode, executed).
//!
//! See `docs/recipes/per-peer-impairment.md` and the reconcile-loop
//! example in `CLAUDE.md` for usage.
//!
//! [`PerPeerImpairer`]: super::impair::PerPeerImpairer
//! [`PerHostLimiter`]: super::ratelimit::PerHostLimiter
//! [`apply()`]: super::impair::PerPeerImpairer::apply
//! [`reconcile()`]: super::impair::PerPeerImpairer::reconcile

use super::tc_handle::{FilterPriority, TcHandle};

/// Knobs controlling [`reconcile()`] behavior.
///
/// [`reconcile()`]: super::impair::PerPeerImpairer::reconcile
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ReconcileOptions {
    /// When `true`, fall back to [`apply()`] (destructive rebuild) if the
    /// live tree is too divergent to incrementally fix — e.g. the root
    /// qdisc is the wrong kind.
    ///
    /// Default: `false` (return an error so the caller can decide).
    ///
    /// [`apply()`]: super::impair::PerPeerImpairer::apply
    pub fallback_to_apply: bool,

    /// When `true`, compute the change set but make no kernel calls.
    /// The returned [`ReconcileReport`] still describes the intended
    /// changes and `dry_run` is set to `true`.
    pub dry_run: bool,
}

impl ReconcileOptions {
    /// Construct default options (no fallback, not dry-run).
    pub const fn new() -> Self {
        Self {
            fallback_to_apply: false,
            dry_run: false,
        }
    }

    /// Set the `fallback_to_apply` flag.
    pub const fn with_fallback_to_apply(mut self, v: bool) -> Self {
        self.fallback_to_apply = v;
        self
    }

    /// Set the `dry_run` flag.
    pub const fn with_dry_run(mut self, v: bool) -> Self {
        self.dry_run = v;
        self
    }
}

/// Outcome of a [`reconcile()`] call.
///
/// `changes_made` counts kernel calls actually issued (or, in dry-run
/// mode, the calls that *would* be issued). `is_noop()` is the cheap
/// "did anything change?" check.
///
/// [`reconcile()`]: super::impair::PerPeerImpairer::reconcile
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ReconcileReport {
    /// Number of kernel mutations issued (or planned, in dry-run mode).
    pub changes_made: usize,
    /// Number of new rules whose tree (class + leaf qdisc + filter) was
    /// freshly added.
    pub rules_added: usize,
    /// Number of existing rules whose class options or leaf netem options
    /// were modified in place.
    pub rules_modified: usize,
    /// Number of rules whose class+leaf+filter were removed because the
    /// desired config no longer mentions them.
    pub rules_removed: usize,
    /// Whether the default-class branch (class + optional leaf) was
    /// added, modified, or removed.
    pub default_modified: bool,
    /// Whether the root HTB qdisc itself was added or modified.
    pub root_modified: bool,
    /// Objects in the helper's deterministic handle range that were
    /// removed because no desired rule mapped to them.
    pub stale_removed: Vec<StaleObject>,
    /// Objects outside the helper's handle range that the live tree
    /// contained. Reported but never mutated — the operator may have
    /// installed them out-of-band.
    pub unmanaged: Vec<UnmanagedObject>,
    /// `true` if this report was produced by a dry-run; no kernel state
    /// was changed.
    pub dry_run: bool,
}

impl ReconcileReport {
    /// Whether reconcile made no changes (i.e. the live tree already
    /// matched the desired tree).
    pub fn is_noop(&self) -> bool {
        self.changes_made == 0
    }
}

/// An object the helper recognized as belonging to its managed range
/// (by handle) but that the desired tree no longer references.
/// `reconcile()` removes these.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StaleObject {
    /// Object kind: `"class"`, `"qdisc"`, or `"filter"`.
    pub kind: &'static str,
    /// The handle (qdisc/class) or filter parent.
    pub handle: TcHandle,
    /// Filter priority, if `kind == "filter"`.
    pub priority: Option<FilterPriority>,
}

/// An object outside the helper's managed range. `reconcile()` does not
/// touch these but reports them so callers can audit drift.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UnmanagedObject {
    /// Object kind: `"class"`, `"qdisc"`, or `"filter"`.
    pub kind: &'static str,
    /// The handle (qdisc/class) or filter parent.
    pub handle: TcHandle,
    /// Filter priority, if `kind == "filter"`.
    pub priority: Option<FilterPriority>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_default_is_noop() {
        let r = ReconcileReport::default();
        assert!(r.is_noop());
        assert_eq!(r.changes_made, 0);
        assert!(!r.dry_run);
    }

    #[test]
    fn options_builder() {
        let o = ReconcileOptions::new()
            .with_dry_run(true)
            .with_fallback_to_apply(true);
        assert!(o.dry_run);
        assert!(o.fallback_to_apply);
    }
}
