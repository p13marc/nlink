//! Declarative types — `NftablesConfig` builder + per-object
//! declared structs.

use super::super::{
    expr::Expr,
    types::{
        ChainType, Family, Hook, Policy, Priority, Rule, Set, SetDataType, SetElement, SetFlags,
        SetKeyType,
    },
    object::{Object, ObjectConfig},
};

/// A complete declarative nftables ruleset. Construct via
/// [`Self::new`] + fluent setters; commit via the diff/apply
/// flow on `Connection<Nftables>`.
///
/// See the module-level docs for usage.
#[derive(Debug, Clone, Default)]
pub struct NftablesConfig {
    pub(crate) tables: Vec<DeclaredTable>,
}

impl NftablesConfig {
    /// Construct an empty config. Add tables via [`Self::table`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a table. The closure receives a
    /// `DeclaredTableBuilder` that lets you nest chains, rules,
    /// and flowtables inside the table — matching the visual
    /// hierarchy of `nft list ruleset`.
    pub fn table<F>(mut self, name: impl Into<String>, family: Family, f: F) -> Self
    where
        F: FnOnce(DeclaredTableBuilder) -> DeclaredTableBuilder,
    {
        let builder = DeclaredTableBuilder::new(name.into(), family);
        let built = f(builder);
        self.tables.push(built.into_table());
        self
    }

    /// All declared tables. Borrowed view.
    pub fn tables(&self) -> &[DeclaredTable] {
        &self.tables
    }

    /// Is this config empty?
    pub fn is_empty(&self) -> bool {
        self.tables.is_empty()
    }
}

// =============================================================================
// DeclaredTable
// =============================================================================

/// A declared table — name, family, flags, and nested chains +
/// rules + flowtables.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
pub struct DeclaredTable {
    pub(crate) name: String,
    pub(crate) family: Family,
    pub(crate) flags: u32,
    pub(crate) chains: Vec<DeclaredChain>,
    pub(crate) rules: Vec<DeclaredRule>,
    pub(crate) flowtables: Vec<DeclaredFlowtable>,
    pub(crate) sets: Vec<DeclaredSet>,
    pub(crate) objects: Vec<DeclaredObject>,
}

impl DeclaredTable {
    /// Table name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Address family.
    pub fn family(&self) -> Family {
        self.family
    }
    /// Flags bitmask (combine `NFT_TABLE_F_*` constants from
    /// [`super::super`][crate::netlink::nftables]).
    pub fn flags(&self) -> u32 {
        self.flags
    }
    pub fn chains(&self) -> &[DeclaredChain] {
        &self.chains
    }
    pub fn rules(&self) -> &[DeclaredRule] {
        &self.rules
    }
    pub fn flowtables(&self) -> &[DeclaredFlowtable] {
        &self.flowtables
    }
    /// Named sets declared in this table.
    pub fn sets(&self) -> &[DeclaredSet] {
        &self.sets
    }
    /// Declared stateful objects.
    pub fn objects(&self) -> &[DeclaredObject] {
        &self.objects
    }
}

/// A declared named stateful object — a counter, quota or limit.
///
/// Reconciled by name and type. Only the configuration is compared, never
/// the live state, so a counter keeps counting and a quota keeps what it has
/// used across applies. A changed quota is updated in place and keeps its
/// consumption. A limit cannot be updated (the kernel accepts the message
/// and changes nothing), so a changed limit is deleted and recreated, and
/// the rules using it move out of the way and back to their places.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredObject {
    pub(crate) name: String,
    pub(crate) config: ObjectConfig,
}

impl DeclaredObject {
    /// Object name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Its configuration.
    pub fn config(&self) -> &ObjectConfig {
        &self.config
    }
    /// The runtime [`Object`] this declaration describes, in `table`.
    pub(crate) fn to_object(&self, table: &str, family: Family) -> Object {
        Object::new(table, &self.name, self.config.clone()).family(family)
    }
}

/// Closure-style builder for [`DeclaredTable`]. Returned by the
/// closure passed to [`NftablesConfig::table`].
pub struct DeclaredTableBuilder {
    name: String,
    family: Family,
    flags: u32,
    chains: Vec<DeclaredChain>,
    rules: Vec<DeclaredRule>,
    flowtables: Vec<DeclaredFlowtable>,
    sets: Vec<DeclaredSet>,
    objects: Vec<DeclaredObject>,
}

impl DeclaredTableBuilder {
    fn new(name: String, family: Family) -> Self {
        Self {
            name,
            family,
            flags: 0,
            chains: Vec::new(),
            rules: Vec::new(),
            flowtables: Vec::new(),
            sets: Vec::new(),
            objects: Vec::new(),
        }
    }

    /// Set the table's flags bitmask. Use the `NFT_TABLE_F_*`
    /// constants from [`crate::netlink::nftables`]
    /// (e.g. `NFT_TABLE_F_PERSIST` for kernel-6.9+ persistent
    /// tables).
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Convenience: enable `NFT_TABLE_F_PERSIST`.
    pub fn persist(mut self, on: bool) -> Self {
        if on {
            self.flags |= super::super::NFT_TABLE_F_PERSIST;
        } else {
            self.flags &= !super::super::NFT_TABLE_F_PERSIST;
        }
        self
    }

    /// Declare a chain. The closure receives a
    /// [`DeclaredChainBuilder`] for nested chain configuration.
    pub fn chain<F>(mut self, name: impl Into<String>, f: F) -> Self
    where
        F: FnOnce(DeclaredChainBuilder) -> DeclaredChainBuilder,
    {
        let builder = DeclaredChainBuilder::new(name.into());
        self.chains.push(f(builder).into_chain());
        self
    }

    /// Declare a rule in the named chain. The closure receives a
    /// [`Rule`] builder identical to the imperative API. The
    /// rule's table is set to this table; the rule's chain is set
    /// from the `chain` argument.
    pub fn rule<F>(mut self, chain: impl AsRef<str>, f: F) -> Self
    where
        F: FnOnce(Rule) -> Rule,
    {
        let rule = Rule::new(&self.name, chain.as_ref()).family(self.family);
        self.rules.push(DeclaredRule {
            table: self.name.clone(),
            chain: chain.as_ref().to_string(),
            family: self.family,
            handle_key: None,
            body: f(rule),
        });
        self
    }

    /// Declare a rule with an explicit `handle_key` for diff
    /// identity. Rules with the same key are matched across diffs;
    /// rules without a key are re-applied on every diff.
    pub fn rule_keyed<F>(
        mut self,
        chain: impl AsRef<str>,
        key: impl Into<String>,
        f: F,
    ) -> Self
    where
        F: FnOnce(Rule) -> Rule,
    {
        let rule = Rule::new(&self.name, chain.as_ref()).family(self.family);
        self.rules.push(DeclaredRule {
            table: self.name.clone(),
            chain: chain.as_ref().to_string(),
            family: self.family,
            handle_key: Some(key.into()),
            body: f(rule),
        });
        self
    }

    /// Declare a flowtable. The closure receives a
    /// [`DeclaredFlowtableBuilder`] for device list + flags.
    pub fn flowtable<F>(mut self, name: impl Into<String>, f: F) -> Self
    where
        F: FnOnce(DeclaredFlowtableBuilder) -> DeclaredFlowtableBuilder,
    {
        let builder = DeclaredFlowtableBuilder::new(name.into());
        self.flowtables.push(f(builder).into_flowtable(self.family, &self.name));
        self
    }

    /// Declare a named set. The closure receives a
    /// [`DeclaredSetBuilder`] for the key type, flags, and initial
    /// elements. The set is reconciled by name (created if absent,
    /// deleted if removed from the config); its declared elements
    /// are reconciled element-by-element against the kernel on
    /// [`apply`](super::NftablesDiff::apply).
    pub fn set<F>(mut self, name: impl Into<String>, f: F) -> Self
    where
        F: FnOnce(DeclaredSetBuilder) -> DeclaredSetBuilder,
    {
        let builder = DeclaredSetBuilder::new(name.into());
        self.sets.push(f(builder).into_set());
        self
    }

    /// Declare a named stateful object — see [`DeclaredObject`]. Rules use
    /// it with [`Rule::counter_named`](crate::netlink::nftables::Rule::counter_named)
    /// and friends; object maps name it in their elements.
    pub fn object(mut self, name: impl Into<String>, config: ObjectConfig) -> Self {
        self.objects.push(DeclaredObject {
            name: name.into(),
            config,
        });
        self
    }

    fn into_table(self) -> DeclaredTable {
        DeclaredTable {
            name: self.name,
            family: self.family,
            flags: self.flags,
            chains: self.chains,
            rules: self.rules,
            flowtables: self.flowtables,
            sets: self.sets,
            objects: self.objects,
        }
    }
}

// =============================================================================
// DeclaredChain
// =============================================================================

/// A declared chain — name + optional base-chain hook spec.
/// Non-base (regular) chains omit the hook fields.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
pub struct DeclaredChain {
    pub(crate) name: String,
    pub(crate) hook: Option<Hook>,
    pub(crate) priority: Option<Priority>,
    pub(crate) policy: Option<Policy>,
    pub(crate) chain_type: Option<ChainType>,
    pub(crate) device: Option<String>,
    pub(crate) exclusive: bool,
}

impl DeclaredChain {
    /// Whether this chain owns all of its rules: a rule nlink did not write
    /// is deleted rather than left alone. See
    /// [`DeclaredChainBuilder::exclusive`].
    pub fn exclusive(&self) -> bool {
        self.exclusive
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn hook(&self) -> Option<Hook> {
        self.hook
    }
    pub fn priority(&self) -> Option<Priority> {
        self.priority
    }
    pub fn policy(&self) -> Option<Policy> {
        self.policy
    }
    pub fn chain_type(&self) -> Option<ChainType> {
        self.chain_type
    }
    pub fn device(&self) -> Option<&str> {
        self.device.as_deref()
    }

    /// Is this a base chain (one that hooks into the kernel
    /// packet path)? Non-base chains are jump-only.
    pub fn is_base(&self) -> bool {
        self.hook.is_some()
    }
}

pub struct DeclaredChainBuilder {
    name: String,
    hook: Option<Hook>,
    priority: Option<Priority>,
    policy: Option<Policy>,
    chain_type: Option<ChainType>,
    device: Option<String>,
    exclusive: bool,
}

impl DeclaredChainBuilder {
    fn new(name: String) -> Self {
        Self {
            name,
            hook: None,
            priority: None,
            policy: None,
            chain_type: None,
            device: None,
            exclusive: false,
        }
    }

    /// Own every rule in this chain: rules nlink did not write — added by
    /// hand, by another tool, or by an older nlink that left rules without
    /// a key — are deleted instead of left alone. Off by default, because
    /// a chain shared with other software would lose its rules.
    pub fn exclusive(mut self) -> Self {
        self.exclusive = true;
        self
    }

    /// Set the hook (makes this a base chain). Pair with
    /// [`Self::priority`].
    pub fn hook(mut self, hook: Hook) -> Self {
        self.hook = Some(hook);
        self
    }

    /// Set the chain priority. Only meaningful for base chains.
    pub fn priority(mut self, p: Priority) -> Self {
        self.priority = Some(p);
        self
    }

    /// Set the default policy for the chain (`Accept` or `Drop`).
    /// Only meaningful for base chains; non-base chains return
    /// to the calling chain unconditionally.
    pub fn policy(mut self, p: Policy) -> Self {
        self.policy = Some(p);
        self
    }

    /// Set the chain type. [`ChainType::Filter`] is the kernel
    /// default for base chains; [`ChainType::Nat`] is
    /// **required** for `prerouting`/`postrouting` NAT chains —
    /// without it `masquerade`/`snat`/`dnat` verdicts refuse to
    /// load with `EOPNOTSUPP` and the apply rolls back.
    /// Mirrors the imperative [`Chain::chain_type`](crate::netlink::nftables::types::Chain::chain_type) setter.
    pub fn chain_type(mut self, ct: ChainType) -> Self {
        self.chain_type = Some(ct);
        self
    }

    /// Bind a [`Family::Netdev`] base chain to a specific
    /// interface (`type filter hook ingress device eth0 priority -150`).
    /// **Required** for netdev hooks; ignored on other
    /// families. Mirrors the imperative [`Chain::device`](crate::netlink::nftables::types::Chain::device)
    /// setter.
    pub fn device(mut self, dev: impl Into<String>) -> Self {
        self.device = Some(dev.into());
        self
    }

    fn into_chain(self) -> DeclaredChain {
        DeclaredChain {
            name: self.name,
            hook: self.hook,
            priority: self.priority,
            policy: self.policy,
            chain_type: self.chain_type,
            device: self.device,
            exclusive: self.exclusive,
        }
    }
}

// =============================================================================
// DeclaredSet
// =============================================================================

/// A declared named set — name, key type, flags, optional size and
/// timeouts, and its declared elements.
///
/// Reconciled by **name** (created if absent in the kernel, deleted
/// if removed from the config). A changed `key_type` or `flags` cannot
/// be applied to an existing set, so the set is deleted and recreated
/// with its declared elements. A changed `size`, `timeout` or
/// `gc_interval` is applied in place (kernel 6.5+). The declared
/// `elements` are reconciled per the set's [`SetElementMode`]: by default
/// exactly for a plain set — missing keys added, undeclared ones removed —
/// and only added for a set rules write to ([`DeclaredSetBuilder::dynamic`])
/// or whose elements time out, so that what the packet path put there
/// stays.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
pub struct DeclaredSet {
    pub(crate) name: String,
    pub(crate) key_type: SetKeyType,
    pub(crate) flags: SetFlags,
    pub(crate) size: Option<u32>,
    pub(crate) timeout: Option<std::time::Duration>,
    pub(crate) gc_interval: Option<std::time::Duration>,
    pub(crate) element_mode: Option<SetElementMode>,
    pub(crate) data_type: Option<SetDataType>,
    pub(crate) elements: Vec<SetElement>,
}

/// How a declared set's elements are reconciled with the kernel's.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetElementMode {
    /// The set holds the declared elements and nothing else: undeclared
    /// elements are removed. The default for a set nothing else writes to.
    Exact,
    /// The declared elements are added if missing; elements the declaration
    /// does not name are left. The default for a dynamic set
    /// (`NFT_SET_EVAL`) and one whose elements time out (`NFT_SET_TIMEOUT`):
    /// their elements come from the packet path, and removing them on every
    /// apply would undo what the rules did.
    Ensure,
}

impl DeclaredSet {
    /// Set name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Key type.
    pub fn key_type(&self) -> &SetKeyType {
        &self.key_type
    }
    /// Flags.
    pub fn flags(&self) -> SetFlags {
        self.flags
    }
    /// Declared maximum element count, if any.
    pub fn size(&self) -> Option<u32> {
        self.size
    }
    /// What a map maps its keys to; `None` for a set.
    pub fn data_type(&self) -> Option<&SetDataType> {
        self.data_type.as_ref()
    }
    /// Declared default element timeout, if any.
    pub fn timeout(&self) -> Option<std::time::Duration> {
        self.timeout
    }
    /// Declared garbage-collection interval, if any.
    pub fn gc_interval(&self) -> Option<std::time::Duration> {
        self.gc_interval
    }
    /// How the elements are reconciled: the declared mode, else
    /// [`SetElementMode::Ensure`] for a dynamic or timeout set and
    /// [`SetElementMode::Exact`] for any other.
    pub fn element_mode(&self) -> SetElementMode {
        self.element_mode.unwrap_or(
            if self.flags.contains(SetFlags::EVAL) || self.flags.contains(SetFlags::TIMEOUT) {
                SetElementMode::Ensure
            } else {
                SetElementMode::Exact
            },
        )
    }
    /// Declared elements.
    pub fn elements(&self) -> &[SetElement] {
        &self.elements
    }

    /// The elements as they are written: for an interval set, the declared
    /// ranges sorted and merged where they overlap or touch (sending
    /// overlapping ranges is an error from the kernel).
    pub(crate) fn wire_elements(&self) -> Vec<SetElement> {
        use crate::netlink::nftables::interval;
        if self.merges_ranges() {
            interval::canonicalize(self.elements.iter().map(interval::range_of).collect())
                .iter()
                .map(interval::element_of)
                .collect()
        } else {
            self.elements.clone()
        }
    }

    /// Whether this is an interval set whose ranges merge where they touch
    /// — one of single keys. In an interval set of concatenated keys each
    /// field is a range of its own, the kernel keeps each element as
    /// written, and overlapping elements are an error.
    ///
    /// A map's ranges are not merged either: two touching ranges that map
    /// to different values are two elements.
    pub(crate) fn merges_ranges(&self) -> bool {
        self.flags.contains(SetFlags::INTERVAL)
            && self.data_type.is_none()
            && !crate::netlink::nftables::types::ranges_per_field(&self.key_type, self.flags)
    }

    /// The flags the kernel reports for this set once created.
    pub(crate) fn wire_flags(&self) -> SetFlags {
        self.to_set("", Family::Inet).wire_flags()
    }

    /// The runtime [`Set`] this declaration describes, in `table`.
    pub(crate) fn to_set(&self, table: &str, family: Family) -> Set {
        let mut set = Set::new(table, &self.name)
            .family(family)
            .key_type(self.key_type.clone())
            .flags(self.flags);
        if let Some(size) = self.size {
            set = set.size(size);
        }
        set.timeout = self.timeout;
        set.gc_interval = self.gc_interval;
        set.data_type = self.data_type.clone();
        set
    }
}

/// Closure-style builder for [`DeclaredSet`]. Returned by the
/// closure passed to [`DeclaredTableBuilder::set`].
pub struct DeclaredSetBuilder {
    name: String,
    key_type: SetKeyType,
    flags: SetFlags,
    size: Option<u32>,
    timeout: Option<std::time::Duration>,
    gc_interval: Option<std::time::Duration>,
    element_mode: Option<SetElementMode>,
    data_type: Option<SetDataType>,
    elements: Vec<SetElement>,
}

impl DeclaredSetBuilder {
    fn new(name: String) -> Self {
        Self {
            name,
            // Match `Set::new`'s default so an unconfigured set is
            // still well-formed.
            key_type: SetKeyType::Ipv4Addr,
            flags: SetFlags::empty(),
            size: None,
            timeout: None,
            gc_interval: None,
            element_mode: None,
            data_type: None,
            elements: Vec::new(),
        }
    }

    /// A map — see [`Set::map`](crate::netlink::nftables::Set::map). A
    /// changed data type recreates it; an element whose data changed is
    /// replaced (removed and added in the same batch).
    pub fn map(mut self, data: SetDataType) -> Self {
        self.flags |= data.flag();
        self.data_type = Some(data);
        self
    }

    /// A verdict map: `map(SetDataType::Verdict)`.
    pub fn vmap(self) -> Self {
        self.map(SetDataType::Verdict)
    }

    /// Set the key type (`SetKeyType::Ipv4Addr`, `InetService`, …).
    pub fn key_type(mut self, key_type: SetKeyType) -> Self {
        self.key_type = key_type;
        self
    }

    /// Set the flags directly ([`SetFlags`], combined with `|`).
    pub fn flags(mut self, flags: SetFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Maximum number of elements (`nft add set ... { size N; }`); see
    /// [`Set::size`](crate::netlink::nftables::Set::size).
    ///
    /// Unlike the key type and flags, a changed size is applied to the
    /// existing set in place — its elements and the rules bound to it
    /// stay — in a batch committed ahead of the rest of the apply, so
    /// that elements a larger size admits can be added in the same apply.
    /// That needs kernel 6.5+: older kernels accept the update and keep
    /// the old size, which `apply` reports as an error rather than leave
    /// a diff that never converges. Leaving the size undeclared never
    /// counts as drift, whatever the kernel holds.
    pub fn size(mut self, size: u32) -> Self {
        self.size = Some(size);
        self
    }

    /// An interval set, holding ranges and prefixes — see
    /// [`Set::interval`](crate::netlink::nftables::Set::interval).
    /// Declared ranges that overlap or touch are merged, as the kernel's
    /// lookups would see them.
    pub fn interval(mut self) -> Self {
        self.flags |= SetFlags::INTERVAL;
        self
    }

    /// A set rules write to — see
    /// [`Set::dynamic`](crate::netlink::nftables::Set::dynamic). Its
    /// elements default to [`SetElementMode::Ensure`].
    pub fn dynamic(mut self) -> Self {
        self.flags |= SetFlags::EVAL;
        self
    }

    /// Default element timeout — see
    /// [`Set::timeout`](crate::netlink::nftables::Set::timeout). Compared
    /// with the kernel's in multiples of 20 ms (the kernel keeps it in
    /// jiffies, and 20 ms is a whole number of jiffies at every `HZ`), and
    /// changed in place. Leaving it undeclared never counts as drift.
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.flags |= SetFlags::TIMEOUT;
        self.timeout = Some(timeout);
        self
    }

    /// Elements may carry their own timeouts — see
    /// [`Set::per_element_timeouts`](crate::netlink::nftables::Set::per_element_timeouts).
    pub fn per_element_timeouts(mut self) -> Self {
        self.flags |= SetFlags::TIMEOUT;
        self
    }

    /// Garbage-collection interval — see
    /// [`Set::gc_interval`](crate::netlink::nftables::Set::gc_interval).
    /// Changed in place; leaving it undeclared never counts as drift.
    pub fn gc_interval(mut self, interval: std::time::Duration) -> Self {
        self.flags |= SetFlags::TIMEOUT;
        self.gc_interval = Some(interval);
        self
    }

    /// How the declared elements are reconciled; see [`SetElementMode`] for
    /// the default.
    pub fn element_mode(mut self, mode: SetElementMode) -> Self {
        self.element_mode = Some(mode);
        self
    }

    /// Convenience: mark the set constant (`NFT_SET_CONSTANT`).
    pub fn constant(mut self) -> Self {
        self.flags |= SetFlags::CONSTANT;
        self
    }

    /// Add a raw element.
    pub fn element(mut self, elem: SetElement) -> Self {
        self.elements.push(elem);
        self
    }

    /// Add many elements from an iterator.
    pub fn elements<I>(mut self, elems: I) -> Self
    where
        I: IntoIterator<Item = SetElement>,
    {
        self.elements.extend(elems);
        self
    }

    /// Convenience: add an IPv4-address element.
    pub fn ipv4(self, addr: std::net::Ipv4Addr) -> Self {
        self.element(SetElement::ipv4(addr))
    }

    /// Convenience: add an IPv6-address element.
    pub fn ipv6(self, addr: std::net::Ipv6Addr) -> Self {
        self.element(SetElement::ipv6(addr))
    }

    /// Convenience: add a port-number element (`inet_service`).
    pub fn port(self, port: u16) -> Self {
        self.element(SetElement::port(port))
    }

    fn into_set(self) -> DeclaredSet {
        DeclaredSet {
            name: self.name,
            key_type: self.key_type,
            flags: self.flags,
            size: self.size,
            timeout: self.timeout,
            gc_interval: self.gc_interval,
            element_mode: self.element_mode,
            data_type: self.data_type,
            elements: self.elements,
        }
    }
}

// =============================================================================
// DeclaredRule
// =============================================================================

/// A declared rule — owning table + chain + the typed `Rule`
/// body. Optional `handle_key` for stable diff identity across
/// reapplies.
///
/// Without a `handle_key`, the rule is treated as anonymous: every
/// diff sees it as "not in current state" and re-installs it. This
/// is harmless for write-only rulesets but churns kernel state on
/// every reconcile. For declarative configs that get re-applied,
/// supply a `handle_key` via `DeclaredTableBuilder::rule_keyed`.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
pub struct DeclaredRule {
    pub(crate) table: String,
    pub(crate) chain: String,
    pub(crate) family: Family,
    pub(crate) handle_key: Option<String>,
    // Plan 189: skip the expression body in JSON output —
    // the Expr tree is wire-format detail. Consumers can
    // call `body()` programmatically for the Rust value or
    // `Display`-render it for human-readable text. See
    // §"Plan 189" of the migration guide.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) body: Rule,
}

impl DeclaredRule {
    pub fn table(&self) -> &str {
        &self.table
    }
    pub fn chain(&self) -> &str {
        &self.chain
    }
    pub fn family(&self) -> Family {
        self.family
    }
    pub fn handle_key(&self) -> Option<&str> {
        self.handle_key.as_deref()
    }
    pub fn body(&self) -> &Rule {
        &self.body
    }
    /// Borrow the rule's typed expression list. Used by the diff
    /// path for byte-comparison of two rules' expression payloads.
    pub fn exprs(&self) -> &[Expr] {
        &self.body.exprs
    }
}

// =============================================================================
// DeclaredFlowtable
// =============================================================================

/// A declared flowtable inside a table.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
pub struct DeclaredFlowtable {
    pub(crate) family: Family,
    pub(crate) table: String,
    pub(crate) name: String,
    pub(crate) devs: Vec<String>,
    pub(crate) priority: i32,
    pub(crate) flags: u32,
}

impl DeclaredFlowtable {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn family(&self) -> Family {
        self.family
    }
    pub fn table(&self) -> &str {
        &self.table
    }
    pub fn devs(&self) -> &[String] {
        &self.devs
    }
    pub fn priority(&self) -> i32 {
        self.priority
    }
    pub fn flags(&self) -> u32 {
        self.flags
    }
}

pub struct DeclaredFlowtableBuilder {
    name: String,
    devs: Vec<String>,
    priority: i32,
    flags: u32,
}

impl DeclaredFlowtableBuilder {
    fn new(name: String) -> Self {
        Self {
            name,
            devs: Vec::new(),
            priority: 0,
            flags: 0,
        }
    }

    pub fn device(mut self, dev: impl Into<String>) -> Self {
        self.devs.push(dev.into());
        self
    }

    pub fn priority(mut self, p: i32) -> Self {
        self.priority = p;
        self
    }

    pub fn hw_offload(mut self, on: bool) -> Self {
        if on {
            self.flags |= super::super::NFT_FLOWTABLE_HW_OFFLOAD;
        } else {
            self.flags &= !super::super::NFT_FLOWTABLE_HW_OFFLOAD;
        }
        self
    }

    pub fn counter(mut self, on: bool) -> Self {
        if on {
            self.flags |= super::super::NFT_FLOWTABLE_COUNTER;
        } else {
            self.flags &= !super::super::NFT_FLOWTABLE_COUNTER;
        }
        self
    }

    fn into_flowtable(self, family: Family, table: &str) -> DeclaredFlowtable {
        DeclaredFlowtable {
            family,
            table: table.to_string(),
            name: self.name,
            devs: self.devs,
            priority: self.priority,
            flags: self.flags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::nftables::NFT_TABLE_F_PERSIST;

    #[test]
    fn empty_config_has_no_tables() {
        let cfg = NftablesConfig::new();
        assert!(cfg.is_empty());
        assert_eq!(cfg.tables().len(), 0);
    }

    #[test]
    fn declarative_composition_round_trips_to_struct_fields() {
        let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| {
            t.persist(true)
                .chain("input", |c| {
                    c.hook(Hook::Input)
                        .priority(Priority::Filter)
                        .policy(Policy::Drop)
                })
                .rule("input", |r| r)
                .rule_keyed("input", "allow-icmp", |r| r)
                .flowtable("ft", |f| f.device("eth0").hw_offload(true))
        });

        assert_eq!(cfg.tables().len(), 1);
        let t = &cfg.tables()[0];
        assert_eq!(t.name(), "filter");
        assert_eq!(t.family(), Family::Inet);
        assert!(t.flags() & NFT_TABLE_F_PERSIST != 0);

        assert_eq!(t.chains().len(), 1);
        let c = &t.chains()[0];
        assert_eq!(c.name(), "input");
        assert!(c.is_base());
        assert!(c.hook().is_some());
        assert_eq!(c.policy(), Some(Policy::Drop));

        assert_eq!(t.rules().len(), 2);
        assert_eq!(t.rules()[0].chain(), "input");
        assert!(t.rules()[0].handle_key().is_none());
        assert_eq!(t.rules()[1].handle_key(), Some("allow-icmp"));

        assert_eq!(t.flowtables().len(), 1);
        let f = &t.flowtables()[0];
        assert_eq!(f.name(), "ft");
        assert_eq!(f.devs(), &["eth0"]);
        assert!(f.flags() & super::super::super::NFT_FLOWTABLE_HW_OFFLOAD != 0);
    }

    #[test]
    fn flowtable_carries_owning_table_and_family() {
        let cfg = NftablesConfig::new().table("nat", Family::Ip, |t| {
            t.flowtable("ft1", |f| f.device("eth0"))
        });
        let ft = &cfg.tables()[0].flowtables()[0];
        assert_eq!(ft.table(), "nat");
        assert_eq!(ft.family(), Family::Ip);
    }

    #[test]
    fn persist_flag_toggles_off() {
        let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| {
            t.persist(true).persist(false)
        });
        assert_eq!(cfg.tables()[0].flags() & NFT_TABLE_F_PERSIST, 0);
    }

    // ---- Plan 180: chain_type + device on DeclaredChain ----

    #[test]
    fn declared_chain_type_round_trips_to_struct() {
        let cfg = NftablesConfig::new().table("nat", Family::Inet, |t| {
            t.chain("postrouting", |c| {
                c.hook(Hook::Postrouting)
                    .priority(Priority::SrcNat)
                    .chain_type(ChainType::Nat)
            })
        });
        let chain = cfg.tables().first().unwrap().chains().first().unwrap();
        assert_eq!(chain.chain_type(), Some(ChainType::Nat));
        assert_eq!(chain.device(), None);
        assert!(chain.is_base());
    }

    #[test]
    fn declared_chain_device_round_trips_to_struct() {
        let cfg = NftablesConfig::new().table("ft", Family::Netdev, |t| {
            t.chain("ingress", |c| {
                c.hook(Hook::NetdevIngress)
                    .priority(Priority::Filter)
                    .chain_type(ChainType::Filter)
                    .device("eth0")
            })
        });
        let chain = cfg.tables().first().unwrap().chains().first().unwrap();
        assert_eq!(chain.chain_type(), Some(ChainType::Filter));
        assert_eq!(chain.device(), Some("eth0"));
    }

    #[test]
    fn declared_chain_omits_chain_type_and_device_by_default() {
        let cfg = NftablesConfig::new().table("filter", Family::Inet, |t| {
            t.chain("input", |c| {
                c.hook(Hook::Input)
                    .priority(Priority::Filter)
                    .policy(Policy::Drop)
            })
        });
        let chain = cfg.tables().first().unwrap().chains().first().unwrap();
        assert_eq!(chain.chain_type(), None);
        assert_eq!(chain.device(), None);
        assert_eq!(chain.policy(), Some(Policy::Drop));
    }
}
