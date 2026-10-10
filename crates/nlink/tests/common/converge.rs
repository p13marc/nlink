//! Convergence and transition checks for the declarative configs.
//!
//! The declarative diffs compare a declaration against the kernel's dump
//! of what the last apply installed. Wherever the kernel stores something
//! other than what it was sent, or an apply step undoes an earlier one,
//! the next diff is not empty and every apply after it rewrites the same
//! thing forever — invisible applying once to an empty namespace.
//!
//! So every step here is applied, diffed, applied again and diffed again,
//! and all four must say "nothing to do". A case with several steps
//! applies them in order to one namespace: that is how a change from one
//! declared value to another gets exercised at all. And because a diff
//! that does not compare a field agrees with anything, a case can end in
//! a check that reads the kernel through something else.

use nlink::netlink::config::{ApplyOptions, DiffOptions, NetworkConfig};
use nlink::netlink::genl::wireguard::WireguardConfig;
use nlink::netlink::nftables::config::{NftDiffOptions, NftablesConfig};
use nlink::netlink::{Connection, Nftables, Route, Wireguard};

use super::{STEP_TIMEOUT, TestNamespace};

/// A declarative config the harness can apply and diff.
pub(crate) trait Declarative {
    type Conn;

    async fn connect(ns: &TestNamespace) -> nlink::Result<Self::Conn>;

    /// Apply, returning how many changes were made; an apply that reports
    /// errors is an `Err`.
    async fn apply(&self, conn: &Self::Conn, purge: bool) -> Result<usize, String>;

    /// The diff against the kernel, rendered, or `None` when it is empty.
    async fn pending(&self, conn: &Self::Conn, purge: bool) -> Result<Option<String>, String>;
}

impl Declarative for NetworkConfig {
    type Conn = Connection<Route>;

    async fn connect(ns: &TestNamespace) -> nlink::Result<Self::Conn> {
        ns.connection()
    }

    async fn apply(&self, conn: &Self::Conn, purge: bool) -> Result<usize, String> {
        let applied = self
            .apply_with_options(conn, ApplyOptions::default().with_purge(purge))
            .await
            .map_err(|e| e.to_string())?;
        if !applied.is_success() {
            return Err(format!("reported errors: {:?}", applied.errors));
        }
        Ok(applied.changes_made)
    }

    async fn pending(&self, conn: &Self::Conn, purge: bool) -> Result<Option<String>, String> {
        let diff = self
            .diff_with_options(conn, DiffOptions::default().purge(purge))
            .await
            .map_err(|e| e.to_string())?;
        Ok((!diff.is_empty()).then(|| diff.to_string()))
    }
}

impl Declarative for NftablesConfig {
    type Conn = Connection<Nftables>;

    async fn connect(ns: &TestNamespace) -> nlink::Result<Self::Conn> {
        ns.connection_for()
    }

    async fn apply(&self, conn: &Self::Conn, purge: bool) -> Result<usize, String> {
        let options = NftDiffOptions::default().purge_tables(purge);
        let diff = self
            .diff_with_options(conn, &options)
            .await
            .map_err(|e| format!("diff: {e}"))?;
        diff.apply(conn).await.map_err(|e| e.to_string())
    }

    async fn pending(&self, conn: &Self::Conn, purge: bool) -> Result<Option<String>, String> {
        let options = NftDiffOptions::default().purge_tables(purge);
        let diff = self
            .diff_with_options(conn, &options)
            .await
            .map_err(|e| e.to_string())?;
        Ok((!diff.is_empty()).then(|| diff.to_string()))
    }
}

/// WireGuard has no purge: a step that asks for one is a test bug.
impl Declarative for WireguardConfig {
    type Conn = (Connection<Route>, Connection<Wireguard>);

    async fn connect(ns: &TestNamespace) -> nlink::Result<Self::Conn> {
        Ok((ns.connection()?, ns.connection_for_async().await?))
    }

    async fn apply(&self, (route, wg): &Self::Conn, purge: bool) -> Result<usize, String> {
        assert!(!purge, "WireguardConfig has no purge");
        self.ensure_devices(route)
            .await
            .map_err(|e| format!("ensure_devices: {e}"))?;
        let applied = self.apply(wg).await.map_err(|e| e.to_string())?;
        Ok(applied.total_writes())
    }

    async fn pending(&self, (_, wg): &Self::Conn, purge: bool) -> Result<Option<String>, String> {
        assert!(!purge, "WireguardConfig has no purge");
        let diff = self.diff(wg).await.map_err(|e| e.to_string())?;
        Ok((!diff.is_empty()).then(|| diff.to_string()))
    }
}

/// Apply `cfg` and check that it converged: the diff after the apply is
/// empty, a second apply changes nothing, and the diff after that is
/// empty too.
pub async fn converges<D: Declarative>(conn: &D::Conn, cfg: &D, purge: bool) -> Result<(), String> {
    cfg.apply(conn, purge)
        .await
        .map_err(|e| format!("first apply failed: {e}"))?;
    if let Some(diff) = cfg
        .pending(conn, purge)
        .await
        .map_err(|e| format!("diff after apply failed: {e}"))?
    {
        return Err(format!("diff after apply is not empty:\n{diff}"));
    }
    let changes = cfg
        .apply(conn, purge)
        .await
        .map_err(|e| format!("second apply failed: {e}"))?;
    if changes != 0 {
        return Err(format!("second apply made {changes} change(s)"));
    }
    if let Some(diff) = cfg
        .pending(conn, purge)
        .await
        .map_err(|e| format!("diff after second apply failed: {e}"))?
    {
        return Err(format!("diff after second apply is not empty:\n{diff}"));
    }
    Ok(())
}

/// What the kernel must hold after a case's last step.
type Check = Box<dyn Fn(&TestNamespace) -> Result<(), String>>;

/// One declaration, or a sequence applied in order to one namespace.
pub struct Case<D> {
    name: String,
    steps: Vec<D>,
    purge: bool,
    check: Option<Check>,
}

pub fn case<D>(name: impl Into<String>, steps: Vec<D>) -> Case<D> {
    Case {
        name: name.into(),
        steps,
        purge: false,
        check: None,
    }
}

impl<D> Case<D> {
    /// Apply and diff every step with purge on.
    pub fn purging(mut self) -> Self {
        self.purge = true;
        self
    }

    /// After the last step converged, `check` must pass too. Read the
    /// kernel with something other than nlink (`ip_json`) where you can.
    pub fn check(mut self, check: impl Fn(&TestNamespace) -> Result<(), String> + 'static) -> Self {
        self.check = Some(Box::new(check));
        self
    }
}

async fn run_case<D: Declarative>(ns: &TestNamespace, case: &Case<D>) -> Result<(), String> {
    let conn = D::connect(ns).await.map_err(|e| format!("connect: {e}"))?;
    for (i, step) in case.steps.iter().enumerate() {
        let outcome =
            match tokio::time::timeout(STEP_TIMEOUT, converges(&conn, step, case.purge)).await {
                Ok(outcome) => outcome,
                Err(_elapsed) => Err("timed out".to_string()),
            };
        outcome.map_err(|why| format!("step {}: {why}", i + 1))?;
    }
    if let Some(check) = &case.check {
        check(ns).map_err(|why| format!("check after the last step: {why}"))?;
    }
    Ok(())
}

/// Run every case in its own namespace, then fail once, listing every
/// case that did not converge — so a run reports every red shape at once
/// instead of stopping at the first.
pub async fn assert_converges<D: Declarative>(
    prefix: &str,
    cases: Vec<Case<D>>,
) -> nlink::Result<()> {
    let mut failures = Vec::new();
    for case in cases {
        let ns = TestNamespace::new(prefix)?;
        if let Err(why) = run_case(&ns, &case).await {
            failures.push(format!("[{}] {why}", case.name));
        }
    }
    assert!(
        failures.is_empty(),
        "{} case(s) did not converge:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
    Ok(())
}

/// Apply `steps` in order to `ns`, each of which must converge, and run
/// `check(i, conn)` after step `i` (0-based). Stops at the first failure.
pub async fn assert_transition<D: Declarative>(
    ns: &TestNamespace,
    steps: &[D],
    purge: bool,
    mut check: impl AsyncFnMut(usize, &D::Conn) -> Result<(), String>,
) -> nlink::Result<()> {
    let conn = D::connect(ns).await?;
    for (i, step) in steps.iter().enumerate() {
        let outcome = match tokio::time::timeout(STEP_TIMEOUT, converges(&conn, step, purge)).await
        {
            Ok(outcome) => outcome,
            Err(_elapsed) => Err("timed out".to_string()),
        };
        if let Err(why) = outcome {
            panic!("step {} did not converge: {why}", i + 1);
        }
        if let Err(why) = check(i, &conn).await {
            panic!("check after step {} failed: {why}", i + 1);
        }
    }
    Ok(())
}

/// `ip -j <args>` inside `ns`, parsed.
///
/// An independent reader: a diff converging only shows that the diff and
/// the kernel agree, and a diff that does not compare a field agrees
/// with anything.
pub fn ip_json(ns: &TestNamespace, args: &[&str]) -> Result<serde_json::Value, String> {
    let mut full = vec!["-j"];
    full.extend_from_slice(args);
    let out = ns
        .exec("ip", &full)
        .map_err(|e| format!("ip {}: {e}", args.join(" ")))?;
    serde_json::from_str(&out).map_err(|e| format!("ip {}: {e}: {out}", args.join(" ")))
}
