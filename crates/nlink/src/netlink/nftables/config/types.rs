//! Declarative types — `NftablesConfig` builder + per-object
//! declared structs.

use super::super::{
    expr::Expr,
    types::{ChainType, Family, Hook, Policy, Priority, Rule},
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
    /// [`DeclaredTableBuilder`] that lets you nest chains, rules,
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
#[derive(Debug, Clone)]
pub struct DeclaredTable {
    pub(crate) name: String,
    pub(crate) family: Family,
    pub(crate) flags: u32,
    pub(crate) chains: Vec<DeclaredChain>,
    pub(crate) rules: Vec<DeclaredRule>,
    pub(crate) flowtables: Vec<DeclaredFlowtable>,
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

    fn into_table(self) -> DeclaredTable {
        DeclaredTable {
            name: self.name,
            family: self.family,
            flags: self.flags,
            chains: self.chains,
            rules: self.rules,
            flowtables: self.flowtables,
        }
    }
}

// =============================================================================
// DeclaredChain
// =============================================================================

/// A declared chain — name + optional base-chain hook spec.
/// Non-base (regular) chains omit the hook fields.
#[derive(Debug, Clone)]
pub struct DeclaredChain {
    pub(crate) name: String,
    pub(crate) hook: Option<Hook>,
    pub(crate) priority: Option<Priority>,
    pub(crate) policy: Option<Policy>,
    pub(crate) chain_type: Option<ChainType>,
    pub(crate) device: Option<String>,
}

impl DeclaredChain {
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
        }
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
    /// Mirrors the imperative [`Chain::chain_type`] setter.
    pub fn chain_type(mut self, ct: ChainType) -> Self {
        self.chain_type = Some(ct);
        self
    }

    /// Bind a [`Family::Netdev`] base chain to a specific
    /// interface (`type filter hook ingress device eth0 priority -150`).
    /// **Required** for netdev hooks; ignored on other
    /// families. Mirrors the imperative [`Chain::device`]
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
/// supply a `handle_key` via [`DeclaredTableBuilder::rule_keyed`].
#[derive(Debug, Clone)]
pub struct DeclaredRule {
    pub(crate) table: String,
    pub(crate) chain: String,
    pub(crate) family: Family,
    pub(crate) handle_key: Option<String>,
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
                c.hook(Hook::Ingress)
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
