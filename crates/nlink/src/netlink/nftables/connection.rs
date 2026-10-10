//! nftables connection implementation for `Connection<Nftables>`.

use super::object::{Object, ObjectInfo, ObjectType};
use super::{expr::write_expressions, types::*, *};
use crate::netlink::{
    attr::AttrIter,
    builder::MessageBuilder,
    connection::Connection,
    dump_frame::{Classification, classify, ends_dump},
    error::{Error, Result},
    message::{
        MessageIter, NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REPLACE,
        NLM_F_REQUEST, NLMSG_HDRLEN, NlMsgError,
    },
    protocol::Nftables,
};

impl Connection<Nftables> {
    // =========================================================================
    // Tables
    // =========================================================================

    /// Create an nftables table.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::nftables::Family;
    /// # let conn = nlink::Connection::<nlink::netlink::Nftables>::new()?;
    /// conn.add_table("filter", Family::Inet).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_table"))]
    pub async fn add_table<N>(&self, name: N, family: Family) -> Result<()>
    where
        N: TryInto<TableName>,
        N::Error: Into<Error>,
    {
        self.add_table_with_flags(name, family, 0).await
    }

    /// Add a table with the given `flags` bitmask. Combine the
    /// `NFT_TABLE_F_*` constants from [`super::NFT_TABLE_F_DORMANT`],
    /// [`super::NFT_TABLE_F_OWNER`], and [`super::NFT_TABLE_F_PERSIST`].
    ///
    /// Most callers want plain [`Self::add_table`] (flags = 0); use
    /// this method when you need a dormant table, owner-locked table,
    /// or persistent table (kernel 6.9+ for `NFT_TABLE_F_PERSIST`).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::{Connection, Nftables};
    /// use nlink::netlink::nftables::{Family, NFT_TABLE_F_PERSIST};
    ///
    /// let conn = Connection::<Nftables>::new()?;
    /// // Create a table that survives `nft flush ruleset`.
    /// conn.add_table_with_flags("filter", Family::Inet, NFT_TABLE_F_PERSIST).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "add_table_with_flags", flags)
    )]
    pub async fn add_table_with_flags<N>(
        &self,
        name: N,
        family: Family,
        flags: u32,
    ) -> Result<()>
    where
        N: TryInto<TableName>,
        N::Error: Into<Error>,
    {
        let name: TableName = name.try_into().map_err(Into::into)?;

        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_NEWTABLE),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_TABLE_NAME, name.as_str());
        if flags != 0 {
            // NFTA_TABLE_FLAGS is big-endian per kernel convention
            // (matches the existing list_tables parser at
            // `parse_table` which reads it as `from_be_bytes`).
            builder.append_attr_u32_be(NFTA_TABLE_FLAGS, flags);
        }

        self.nft_request_ack(builder).await
    }

    /// List all nftables tables.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_tables"))]
    pub async fn list_tables(&self) -> Result<Vec<Table>> {
        self.list_tables_filtered(0).await
    }

    /// List tables in a specific address family. Server-side
    /// filtered via `nfgen_family` — more efficient than
    /// `list_tables().filter(|t| t.family() == family)` on
    /// hosts with tables in many families (`ip`, `ip6`,
    /// `inet`, `arp`, `bridge`, `netdev`). Plan 181.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_tables_in"))]
    pub async fn list_tables_in(&self, family: Family) -> Result<Vec<Table>> {
        let mut tables = self.list_tables_filtered(family as u8).await?;
        // Defensive: even though the kernel honors `nfgen_family`
        // on table dumps (unlike chain/flowtable/set dumps where
        // the table-name attribute is just a hint), filter
        // client-side too so the contract holds across all
        // kernel versions.
        tables.retain(|t| t.family == family);
        Ok(tables)
    }

    async fn list_tables_filtered(&self, family_byte: u8) -> Result<Vec<Table>> {
        let builder = build_list_tables_request(family_byte);
        let responses = self.nft_dump(builder).await?;
        let mut tables = Vec::new();

        for (family_byte, payload) in &responses {
            let family = Family::from_u8(*family_byte).unwrap_or(Family::Inet);
            if let Some(table) = parse_table(payload, family) {
                tables.push(table);
            }
        }

        Ok(tables)
    }

    /// Add a flowtable to the named table.
    ///
    /// Constructs and emits an `NFT_MSG_NEWFLOWTABLE`. The nested
    /// `NFTA_FLOWTABLE_HOOK` carries `NF_NETDEV_INGRESS` (= 0) +
    /// the configured priority + the device list. See
    /// [`super::Flowtable`] for builder shape.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::netlink::Nftables>::new()?;
    /// use nlink::netlink::nftables::{Flowtable, Family};
    /// let ft = Flowtable::new(Family::Inet, "filter", "ft")
    ///     .device("eth0").device("eth1").hw_offload(true);
    /// conn.add_flowtable(&ft).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_flowtable"))]
    pub async fn add_flowtable(&self, ft: &super::types::Flowtable) -> Result<()> {
        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_NEWFLOWTABLE),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        let nfgenmsg = NfGenMsg::new(ft.family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_FLOWTABLE_TABLE, &ft.table);
        builder.append_attr_str(NFTA_FLOWTABLE_NAME, &ft.name);

        // Nested NFTA_FLOWTABLE_HOOK with hook-num, priority, devs.
        let hook = builder.nest_start(NFTA_FLOWTABLE_HOOK | 0x8000);
        builder.append_attr_u32_be(NFTA_FLOWTABLE_HOOK_NUM, NF_NETDEV_INGRESS);
        builder.append_attr_u32_be(NFTA_FLOWTABLE_HOOK_PRIORITY, ft.priority as u32);
        if !ft.devs.is_empty() {
            let devs = builder.nest_start(NFTA_FLOWTABLE_HOOK_DEVS | 0x8000);
            for dev in &ft.devs {
                // Each device is a nested attribute carrying
                // NFTA_DEVICE_NAME = 1 (string).
                let dev_nest = builder.nest_start(1u16 | 0x8000); // NFTA_LIST_ELEM
                builder.append_attr_str(NFTA_DEVICE_NAME, dev);
                builder.nest_end(dev_nest);
            }
            builder.nest_end(devs);
        }
        builder.nest_end(hook);

        if ft.flags != 0 {
            builder.append_attr_u32_be(NFTA_FLOWTABLE_FLAGS, ft.flags);
        }

        self.nft_request_ack(builder).await
    }

    /// Delete a flowtable from the named table.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_flowtable"))]
    pub async fn del_flowtable(
        &self,
        family: Family,
        table: &str,
        name: &str,
    ) -> Result<()> {
        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_DELFLOWTABLE),
            NLM_F_REQUEST | NLM_F_ACK,
        );
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_FLOWTABLE_TABLE, table);
        builder.append_attr_str(NFTA_FLOWTABLE_NAME, name);

        self.nft_request_ack(builder).await
    }

    /// Dump all flowtables in the kernel.
    ///
    /// Returns one [`super::types::Flowtable`] per kernel-installed
    /// flowtable. The parsed flowtables carry `use_count` and
    /// `handle` populated by the kernel; `devs` is reported via
    /// the nested hook block.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_flowtables"))]
    pub async fn list_flowtables(&self) -> Result<Vec<super::types::Flowtable>> {
        self.list_flowtables_filtered(0, None).await
    }

    /// List flowtables in a specific table+family. Server-side
    /// filtered via `NFTA_FLOWTABLE_TABLE` + `nfgen_family` —
    /// more efficient than `list_flowtables().filter(|f|
    /// f.table == "…")` on hosts with many tables. Plan 181.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_flowtables_in"))]
    pub async fn list_flowtables_in(
        &self,
        table: &str,
        family: Family,
    ) -> Result<Vec<super::types::Flowtable>> {
        self.list_flowtables_filtered(family as u8, Some(table)).await
    }

    async fn list_flowtables_filtered(
        &self,
        family_byte: u8,
        table: Option<&str>,
    ) -> Result<Vec<super::types::Flowtable>> {
        let builder = build_list_flowtables_request(family_byte, table);
        let responses = self.nft_dump(builder).await?;
        let mut out = Vec::new();
        for (family_byte, payload) in &responses {
            let family = Family::from_u8(*family_byte).unwrap_or(Family::Inet);
            if let Some(ft) = parse_flowtable(payload, family) {
                out.push(ft);
            }
        }
        if let Some(t) = table {
            out.retain(|f| f.table == t);
        }
        Ok(out)
    }

    /// Delete an nftables table.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_table"))]
    pub async fn del_table<N>(&self, name: N, family: Family) -> Result<()>
    where
        N: TryInto<TableName>,
        N::Error: Into<Error>,
    {
        let name: TableName = name.try_into().map_err(Into::into)?;
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_DELTABLE), NLM_F_REQUEST | NLM_F_ACK);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_TABLE_NAME, name.as_str());

        self.nft_request_ack(builder).await
    }

    /// Delete a table if it exists. Returns `Ok(true)` if the
    /// table was deleted, `Ok(false)` if it didn't exist.
    /// Unlike [`Self::del_table`], does NOT error on `ENOENT`.
    ///
    /// Saves the `let _ = conn.del_table(...).await;` ignore
    /// pattern that nearly all callers reach for. Plan 188 §2.7 / feedback W8.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_table_if_exists"))]
    pub async fn del_table_if_exists<N>(&self, name: N, family: Family) -> Result<bool>
    where
        N: TryInto<TableName>,
        N::Error: Into<Error>,
    {
        match self.del_table(name, family).await {
            Ok(()) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Flush all rules from a table (keeps chains).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_table"))]
    pub async fn flush_table<N>(&self, name: N, family: Family) -> Result<()>
    where
        N: TryInto<TableName>,
        N::Error: Into<Error>,
    {
        let name: TableName = name.try_into().map_err(Into::into)?;
        // Flush is done by deleting all rules in the table
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_DELRULE), NLM_F_REQUEST | NLM_F_ACK);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_RULE_TABLE, name.as_str());

        self.nft_request_ack(builder).await
    }

    // =========================================================================
    // Chains
    // =========================================================================

    /// Create an nftables chain.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::nftables::Chain;
    /// # use nlink::netlink::nftables::ChainType;
    /// # use nlink::netlink::nftables::Family;
    /// # use nlink::netlink::nftables::Hook;
    /// # use nlink::netlink::nftables::Policy;
    /// # use nlink::netlink::nftables::Priority;
    /// # let conn = nlink::Connection::<nlink::netlink::Nftables>::new()?;
    /// conn.add_chain(
    ///     Chain::new("filter", "input")?
    ///         .family(Family::Inet)
    ///         .hook(Hook::Input)
    ///         .priority(Priority::Filter)
    ///         .policy(Policy::Accept)
    ///         .chain_type(ChainType::Filter)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_chain"))]
    pub async fn add_chain(&self, chain: Chain) -> Result<()> {
        // Validate: base chains require type
        if chain.hook.is_some() && chain.chain_type.is_none() {
            return Err(Error::InvalidMessage(
                "base chains with a hook require chain_type".into(),
            ));
        }

        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_NEWCHAIN),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        let nfgenmsg = NfGenMsg::new(chain.family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_CHAIN_TABLE, chain.table.as_str());
        builder.append_attr_str(NFTA_CHAIN_NAME, chain.name.as_str());

        if let Some(chain_type) = chain.chain_type {
            builder.append_attr_str(NFTA_CHAIN_TYPE, chain_type.as_str());
        }

        if let Some(hook) = chain.hook {
            let hook_nest = builder.nest_start(NFTA_CHAIN_HOOK | 0x8000);
            builder.append_attr_u32_be(NFTA_HOOK_HOOKNUM, hook.to_u32());
            let priority = chain.priority.unwrap_or(Priority::Filter).to_i32();
            builder.append_attr_u32_be(NFTA_HOOK_PRIORITY, priority as u32);
            if let Some(dev) = &chain.device {
                builder.append_attr_str(NFTA_HOOK_DEV, dev);
            }
            builder.nest_end(hook_nest);
        }

        if let Some(policy) = chain.policy {
            builder.append_attr_u32_be(NFTA_CHAIN_POLICY, policy.to_u32());
        }

        self.nft_request_ack(builder).await
    }

    /// List all chains. Dumps every family + table — for
    /// per-table results, use [`Self::list_chains_in`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_chains"))]
    pub async fn list_chains(&self) -> Result<Vec<ChainInfo>> {
        self.list_chains_filtered(0, None).await
    }

    /// List chains in a specific table+family. Server-side
    /// filtered via `NFTA_CHAIN_TABLE` + `nfgen_family` —
    /// more efficient than `list_chains().filter(|c|
    /// c.table == "…")` on hosts with many tables. Plan 181.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_chains_in"))]
    pub async fn list_chains_in<T>(&self, table: T, family: Family) -> Result<Vec<ChainInfo>>
    where
        T: TryInto<TableName>,
        T::Error: Into<Error>,
    {
        let table: TableName = table.try_into().map_err(Into::into)?;
        self.list_chains_filtered(family as u8, Some(table.as_str()))
            .await
    }

    async fn list_chains_filtered(
        &self,
        family_byte: u8,
        table: Option<&str>,
    ) -> Result<Vec<ChainInfo>> {
        let builder = build_list_chains_request(family_byte, table);
        let responses = self.nft_dump(builder).await?;
        let mut chains = Vec::new();

        for (family_byte, payload) in &responses {
            let family = Family::from_u8(*family_byte).unwrap_or(Family::Inet);
            if let Some(chain) = parse_chain(payload, family) {
                chains.push(chain);
            }
        }

        // Defensive client-side filter — see comment above.
        if let Some(t) = table {
            chains.retain(|c| c.table == t);
        }

        Ok(chains)
    }

    /// Delete a chain.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_chain"))]
    pub async fn del_chain<T, N>(&self, table: T, name: N, family: Family) -> Result<()>
    where
        T: TryInto<TableName>,
        T::Error: Into<Error>,
        N: TryInto<ChainName>,
        N::Error: Into<Error>,
    {
        let table: TableName = table.try_into().map_err(Into::into)?;
        let name: ChainName = name.try_into().map_err(Into::into)?;
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_DELCHAIN), NLM_F_REQUEST | NLM_F_ACK);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_CHAIN_TABLE, table.as_str());
        builder.append_attr_str(NFTA_CHAIN_NAME, name.as_str());

        self.nft_request_ack(builder).await
    }

    /// Delete a chain if it exists. Returns `Ok(true)` if the
    /// chain was deleted, `Ok(false)` if it didn't exist.
    /// Plan 188 §2.7 / feedback W8.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_chain_if_exists"))]
    pub async fn del_chain_if_exists<T, N>(
        &self,
        table: T,
        name: N,
        family: Family,
    ) -> Result<bool>
    where
        T: TryInto<TableName>,
        T::Error: Into<Error>,
        N: TryInto<ChainName>,
        N::Error: Into<Error>,
    {
        match self.del_chain(table, name, family).await {
            Ok(()) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    // =========================================================================
    // Rules
    // =========================================================================

    /// Add a rule to a chain.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::nftables::Family;
    /// # use nlink::netlink::nftables::Rule;
    /// # let conn = nlink::Connection::<nlink::netlink::Nftables>::new()?;
    /// conn.add_rule(
    ///     Rule::new("filter", "input")
    ///         .family(Family::Inet)
    ///         .match_tcp_dport(22)
    ///         .accept()
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_rule"))]
    pub async fn add_rule(&self, rule: Rule) -> Result<()> {
        // NLM_F_APPEND is not optional. nf_tables_newrule() appends to the
        // chain tail only when it is set; without it the kernel *prepends*, so
        // rules land in reverse declaration order. nftables is first-match-wins,
        // so that inverts policy — a declared [accept ssh, drop] installs as
        // [drop, accept] and SSH is blocked (#195).
        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_NEWRULE),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
        );
        let nfgenmsg = NfGenMsg::new(rule.family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_RULE_TABLE, &rule.table);
        builder.append_attr_str(NFTA_RULE_CHAIN, &rule.chain);

        if let Some(pos) = rule.position {
            builder.append_attr_u64_be(NFTA_RULE_POSITION, pos);
        }

        if !rule.exprs.is_empty() {
            write_expressions(&mut builder, &rule.exprs);
        }

        // Key and comment → NFTA_RULE_USERDATA TLV.
        if let Some(udata) =
            super::userdata::encode_rule_userdata(rule.key.as_deref(), rule.comment.as_deref())?
        {
            builder.append_attr(NFTA_RULE_USERDATA, &udata);
        }

        self.nft_request_ack(builder).await
    }

    /// List all rules in a table.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_rules"))]
    pub async fn list_rules(&self, table: &str, family: Family) -> Result<Vec<RuleInfo>> {
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_GETRULE), NLM_F_REQUEST | NLM_F_DUMP);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_RULE_TABLE, table);

        let responses = self.nft_dump(builder).await?;
        let mut rules = Vec::new();

        for (family_byte, payload) in &responses {
            let family = Family::from_u8(*family_byte).unwrap_or(Family::Inet);
            if let Some(rule) = parse_rule(payload, family) {
                rules.push(rule);
            }
        }

        Ok(rules)
    }

    /// Delete a rule by handle.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_rule"))]
    pub async fn del_rule(
        &self,
        table: &str,
        chain: &str,
        family: Family,
        handle: u64,
    ) -> Result<()> {
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_DELRULE), NLM_F_REQUEST | NLM_F_ACK);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_RULE_TABLE, table);
        builder.append_attr_str(NFTA_RULE_CHAIN, chain);
        builder.append_attr_u64_be(NFTA_RULE_HANDLE, handle);

        self.nft_request_ack(builder).await
    }

    /// Delete a rule by handle if it exists. Returns
    /// `Ok(true)` if the rule was deleted, `Ok(false)` if it
    /// didn't exist (kernel returned ENOENT — typical when a
    /// stale handle survives a transaction rollback).
    /// Plan 188 §2.7 / feedback W8.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_rule_if_exists"))]
    pub async fn del_rule_if_exists(
        &self,
        table: &str,
        chain: &str,
        family: Family,
        handle: u64,
    ) -> Result<bool> {
        match self.del_rule(table, chain, family, handle).await {
            Ok(()) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    // =========================================================================
    // Sets
    // =========================================================================

    /// Create an nftables set.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_set"))]
    pub async fn add_set(&self, set: Set) -> Result<()> {
        // NFT_NAME_MAXLEN - 1 = 255, the same bound TableName and ChainName
        // enforce. The old `> 256` accepted a 256-byte name that the kernel
        // then rejected at apply time rather than at the API boundary (#211).
        if set.name.is_empty() || set.name.len() > 255 {
            return Err(Error::InvalidMessage(format!(
                "set name must be 1-255 bytes, got {}",
                set.name.len(),
            )));
        }

        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_NEWSET),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        let nfgenmsg = NfGenMsg::new(set.family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_SET_TABLE, &set.table);
        builder.append_attr_str(NFTA_SET_NAME, &set.name);
        builder.append_attr_u32_be(NFTA_SET_KEY_TYPE, set.key_type.type_id());
        builder.append_attr_u32_be(NFTA_SET_KEY_LEN, set.key_type.len());
        builder.append_attr_u32_be(NFTA_SET_FLAGS, set.wire_flags().bits());
        append_set_data_type(&mut builder, &set);
        append_set_timeouts(&mut builder, &set);
        append_set_desc(&mut builder, &set);
        // Set ID (arbitrary, used for referencing in same batch)
        builder.append_attr_u32_be(NFTA_SET_ID, 1);

        self.nft_request_ack(builder).await
    }

    /// List all sets in a family. Already family-filtered;
    /// for `(table, family)`-scoped results use
    /// [`Self::list_sets_in`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_sets"))]
    pub async fn list_sets(&self, family: Family) -> Result<Vec<SetInfo>> {
        self.list_sets_filtered(family as u8, None).await
    }

    /// List sets in a specific table+family. Server-side
    /// filtered via `NFTA_SET_TABLE` + `nfgen_family` —
    /// more efficient than `list_sets(family).filter(|s|
    /// s.table == "…")` on hosts with many tables. Plan 181.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_sets_in"))]
    pub async fn list_sets_in(
        &self,
        table: &str,
        family: Family,
    ) -> Result<Vec<SetInfo>> {
        self.list_sets_filtered(family as u8, Some(table)).await
    }

    async fn list_sets_filtered(
        &self,
        family_byte: u8,
        table: Option<&str>,
    ) -> Result<Vec<SetInfo>> {
        let builder = build_list_sets_request(family_byte, table);
        let responses = self.nft_dump(builder).await?;
        let mut sets = Vec::new();

        for (family_byte, payload) in &responses {
            let family = Family::from_u8(*family_byte).unwrap_or(Family::Inet);
            if let Some(set) = parse_set(payload, family) {
                sets.push(set);
            }
        }
        if let Some(t) = table {
            sets.retain(|s| s.table == t);
        }
        Ok(sets)
    }

    /// Delete a set.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_set"))]
    pub async fn del_set(&self, table: &str, name: &str, family: Family) -> Result<()> {
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_DELSET), NLM_F_REQUEST | NLM_F_ACK);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_SET_TABLE, table);
        builder.append_attr_str(NFTA_SET_NAME, name);

        self.nft_request_ack(builder).await
    }

    /// Delete a set, treating "not found" as success.
    ///
    /// Returns `Ok(true)` if the set was deleted, `Ok(false)` if it did
    /// not exist. Mirrors [`del_table_if_exists`](Self::del_table_if_exists)
    /// for idempotent teardown.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_set_if_exists"))]
    pub async fn del_set_if_exists(&self, table: &str, name: &str, family: Family) -> Result<bool> {
        match self.del_set(table, name, family).await {
            Ok(()) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Add elements to a set.
    ///
    /// Takes the [`Set`] itself — the same value `add_set` was given, or one
    /// describing the existing set — because how an element is written
    /// depends on the set's key type and flags. Elements that do not fit
    /// the set are an error, not something dropped.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_set_elements"))]
    pub async fn add_set_elements(&self, set: &Set, elements: &[SetElement]) -> Result<()> {
        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_NEWSETELEM),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        );
        append_set_elements(&mut builder, set, elements, ElementWrite::Add)?;
        self.nft_request_ack(builder).await
    }

    /// Delete elements from a set. See [`add_set_elements`](Self::add_set_elements)
    /// for why it takes the [`Set`].
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_set_elements"))]
    pub async fn del_set_elements(&self, set: &Set, elements: &[SetElement]) -> Result<()> {
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_DELSETELEM), NLM_F_REQUEST | NLM_F_ACK);
        append_set_elements(&mut builder, set, elements, ElementWrite::Delete)?;
        self.nft_request_ack(builder).await
    }

    // =========================================================================
    // Stateful objects
    // =========================================================================

    /// Create a named stateful object — a counter, quota or limit that rules
    /// use by name ([`Rule::counter_named`] …) and object maps pick per
    /// packet. `EEXIST` if one of that name and type is already there.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_object"))]
    pub async fn add_object(&self, object: &Object) -> Result<()> {
        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_NEWOBJ),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        append_object(&mut builder, object);
        self.nft_request_ack(builder).await
    }

    /// Delete the object `name` of `object_type` — objects are named per
    /// type, so the kernel needs both. `EBUSY` while a rule or set element
    /// uses it.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_object"))]
    pub async fn del_object(
        &self,
        table: &str,
        name: &str,
        object_type: ObjectType,
        family: Family,
    ) -> Result<()> {
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_DELOBJ), NLM_F_REQUEST | NLM_F_ACK);
        append_object_key(&mut builder, table, name, object_type, family);
        self.nft_request_ack(builder).await
    }

    /// List the stateful objects in a family.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_objects"))]
    pub async fn list_objects(&self, family: Family) -> Result<Vec<ObjectInfo>> {
        self.dump_objects(NFT_MSG_GETOBJ, family, None).await
    }

    /// List the stateful objects in one table.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_objects_in"))]
    pub async fn list_objects_in(&self, table: &str, family: Family) -> Result<Vec<ObjectInfo>> {
        self.dump_objects(NFT_MSG_GETOBJ, family, Some(table)).await
    }

    /// Read the object `name` of `object_type` and reset it in one step —
    /// a counter back to zero, a quota's consumption to none — returning
    /// its state from just before (`nft reset counter`). Nothing is lost
    /// between the read and the reset. `None` if there is no such object.
    /// The ruleset's current generation: the id every committed batch
    /// increments (`NFT_MSG_GETGEN`).
    ///
    /// Read it before and after a set of dumps; if it moved, the dumps may
    /// mix two rulesets and should be taken again (#503).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "generation"))]
    pub async fn generation(&self) -> Result<u32> {
        let mut builder = MessageBuilder::new(nft_msg_type(NFT_MSG_GETGEN), NLM_F_REQUEST);
        // AF_UNSPEC: the generation is the ruleset's, not a family's.
        builder.append(&NfGenMsg {
            nfgen_family: 0,
            version: 0,
            res_id: 0,
        });
        let (_, payload) = self.nft_get_one(builder).await?;
        super::events::parse_gen(&payload)
            .map(|g| g.id)
            .ok_or_else(|| Error::InvalidMessage("nftables: GETGEN answer without an id".into()))
    }

    #[tracing::instrument(level = "debug", skip_all, fields(method = "reset_object"))]
    pub async fn reset_object(
        &self,
        table: &str,
        name: &str,
        object_type: ObjectType,
        family: Family,
    ) -> Result<Option<ObjectInfo>> {
        let mut builder = MessageBuilder::new(nft_msg_type(NFT_MSG_GETOBJ_RESET), NLM_F_REQUEST);
        append_object_key(&mut builder, table, name, object_type, family);
        match self.nft_get_one(builder).await {
            Ok((family_byte, payload)) => {
                let family = Family::from_u8(family_byte).unwrap_or(family);
                Ok(super::object::parse_object(&payload, family))
            }
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn dump_objects(
        &self,
        msg: u8,
        family: Family,
        table: Option<&str>,
    ) -> Result<Vec<ObjectInfo>> {
        let mut builder = MessageBuilder::new(nft_msg_type(msg), NLM_F_REQUEST | NLM_F_DUMP);
        builder.append(&NfGenMsg::new(family));
        if let Some(table) = table {
            builder.append_attr_str(NFTA_OBJ_TABLE, table);
        }
        let responses = self.nft_dump(builder).await?;
        let mut objects: Vec<ObjectInfo> = responses
            .iter()
            .filter_map(|(family_byte, payload)| {
                let family = Family::from_u8(*family_byte).unwrap_or(family);
                super::object::parse_object(payload, family)
            })
            .collect();
        if let Some(table) = table {
            objects.retain(|o| o.table == table);
        }
        Ok(objects)
    }

    /// List the current elements of a named set.
    ///
    /// Dumps `NFT_MSG_GETSETELEM` for `(table, set, family)` and
    /// returns each element's key bytes as a [`SetElement`]. Used by
    /// the declarative [`NftablesConfig::diff`](super::config::NftablesConfig::diff)
    /// to compute an element-level diff (add missing keys, remove
    /// undeclared ones); also useful standalone to read a set's
    /// contents.
    ///
    /// The key and the element flags are read; map data and timeouts are
    /// not decoded yet. For an interval set the wire elements are paired
    /// back into ranges ([`SetElement::key_end`]) — which takes one more
    /// round-trip to learn the set's flags.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_set_elements"))]
    pub async fn list_set_elements(
        &self,
        table: &str,
        set: &str,
        family: Family,
    ) -> Result<Vec<SetElement>> {
        let builder = build_list_set_elements_request(family as u8, table, set);
        let responses = self.nft_dump(builder).await?;
        let mut elements = Vec::new();
        for (_family_byte, payload) in &responses {
            parse_set_elements(payload, &mut elements);
        }
        // An interval set of concatenated keys (`NFT_SET_CONCAT`) holds each
        // range in one element already; another interval set holds starts
        // and end-plus-ones to pair.
        let flags = self
            .list_sets_in(table, family)
            .await?
            .iter()
            .find(|s| s.name == set)
            .map_or(SetFlags::empty(), |s| s.flags);
        if flags.contains(SetFlags::INTERVAL) && !flags.contains(SetFlags::CONCAT) {
            elements = super::interval::pair_elements(&elements);
        }
        Ok(elements)
    }

    // =========================================================================
    // Batch Transactions
    // =========================================================================

    /// Create a new batch transaction builder.
    ///
    /// All operations added to the transaction are applied atomically.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::nftables::{Chain, ChainType, Family, Hook, Policy, Priority, Rule};
    /// # let conn = nlink::Connection::<nlink::netlink::Nftables>::new()?;
    /// let chain = Chain::new("filter", "input")?
    ///     .family(Family::Inet)
    ///     .hook(Hook::Input)
    ///     .priority(Priority::Filter)
    ///     .chain_type(ChainType::Filter)
    ///     .policy(Policy::Accept);
    /// let rule = Rule::new("filter", "input").family(Family::Inet);
    ///
    /// conn.transaction()
    ///     .add_table("filter", Family::Inet)
    ///     .add_chain(chain)
    ///     .add_rule(rule)
    ///     .commit(&conn)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn transaction(&self) -> Transaction {
        Transaction::new()
    }

    /// Flush the entire ruleset (all tables, chains, rules, sets).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_ruleset"))]
    pub async fn flush_ruleset(&self) -> Result<()> {
        // Delete all tables across all families
        let tables = self.list_tables().await?;
        for table in tables {
            self.del_table(table.name.as_str(), table.family).await?;
        }
        Ok(())
    }

    /// Send a batch of messages atomically.
    ///
    /// Per nfnetlink(7): the kernel processes a batch of mutation
    /// messages wrapped in `NFNL_MSG_BATCH_BEGIN ... NFNL_MSG_BATCH_END`.
    /// Each inner message that set `NLM_F_ACK` gets one ACK
    /// response (with that op's `nlmsg_seq`). `BATCH_END` here also
    /// sets `NLM_F_ACK` so the kernel sends a final ACK at the
    /// `end_seq` we can wait on as the "commit succeeded" signal.
    ///
    /// Response-loop rules (Plan 170, after the 0.16 cycle's CI
    /// hang surfaced the bugs):
    /// 1. **Filter by `nlmsg_seq`** — only consider messages in
    ///    `[begin_seq, end_seq]`. Stale traffic from prior
    ///    operations on the same fd is ignored.
    /// 2. **Terminate on the end_seq ACK specifically** — not on
    ///    the first per-op ACK, which can fire mid-batch and
    ///    leave the loop thinking the batch is done.
    /// 3. **Collect every refused operation** — an op-level
    ///    `NLMSGERR` (non-ack) means the kernel rejected an op and
    ///    the batch will not commit, but nfnetlink keeps going and
    ///    reports every refused op. Read them all, then return
    ///    [`Error::NftBatch`] naming each (#481).
    /// 4. **Hard-cap with a 30s timeout** — pending Plan 171's
    ///    `Connection<P>`-wide default timeout. If the kernel
    ///    skips the end-seq ACK (unexpected on Linux ≥ 4.6 per
    ///    `net/netfilter/nfnetlink.c`) the call fails fast with
    ///    `Error::Timeout` instead of hanging.
    async fn send_batch(&self, mut messages: Vec<Vec<u8>>) -> Result<()> {
        if messages.is_empty() {
            return Ok(());
        }

        let mut batch = Vec::new();

        // NFNL_MSG_BATCH_BEGIN — control message; no ACK requested.
        let mut begin = MessageBuilder::new(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST);
        let nfgenmsg = NfGenMsg {
            nfgen_family: 0,
            version: 0,
            res_id: 10u16.to_be(), // NFNL_SUBSYS_NFTABLES
        };
        begin.append(&nfgenmsg);
        let begin_seq = self.socket().next_seq();
        begin.set_seq(begin_seq);
        begin.set_pid(self.socket().pid());
        batch.extend_from_slice(&begin.finish());

        // Inner messages — renumbered here, from the socket's counter.
        //
        // Whatever seq they arrived with is discarded. `Transaction` numbers
        // its messages from its own counter starting at 1, unrelated to the
        // socket's, so the old code's stated invariant ("inner seqs are
        // strictly below begin_seq") was simply false — and the recv loop's
        // `seq > end_seq { continue }` filter then *discarded mid-batch kernel
        // errors*. The kernel aborted the batch, its BATCH_END ACK never came,
        // and the caller got an opaque 30s Error::Timeout with no clue what
        // failed. Worse, an inner seq that happened to equal end_seq had its
        // per-op ACK mistaken for the BATCH_END ACK, returning Ok(()) for a
        // batch that never committed (#199).
        //
        // Allocating here makes the batch occupy one contiguous
        // [begin_seq ..= end_seq] window, so every response can be matched
        // exactly. It also makes the socket the single source of seqs, so a
        // future caller cannot reintroduce a second counter.
        //
        let pid = self.socket().pid();
        let mut inner_seqs = Vec::with_capacity(messages.len());
        for msg_data in &mut messages {
            let seq = self.socket().next_seq();
            stamp_seq_pid(msg_data, seq, pid)?;
            inner_seqs.push(seq);
            batch.extend_from_slice(msg_data);
        }

        // NFNL_MSG_BATCH_END — request an ACK so the kernel
        // gives us a deterministic commit-completion signal at
        // a known seq. Without NLM_F_ACK here, some kernels
        // skip the response and the loop relies on the
        // per-op ACK absence to terminate — fragile.
        let mut end = MessageBuilder::new(NFNL_MSG_BATCH_END, NLM_F_REQUEST | NLM_F_ACK);
        let nfgenmsg = NfGenMsg {
            nfgen_family: 0,
            version: 0,
            res_id: 10u16.to_be(),
        };
        end.append(&nfgenmsg);
        let end_seq = self.socket().next_seq();
        end.set_seq(end_seq);
        end.set_pid(self.socket().pid());
        batch.extend_from_slice(&end.finish());

        // Every seq the kernel can answer with: BATCH_BEGIN, the inner ops,
        // BATCH_END. The session serializes in mutex mode (the F1 fix) and,
        // in dispatcher mode, registers all of them with the driver rather
        // than racing its recv (#466). Registered before the send.
        let all_seqs: Vec<u32> = std::iter::once(begin_seq)
            .chain(inner_seqs.iter().copied())
            .chain(std::iter::once(end_seq))
            .collect();
        let mut session = self.recv_session_multi(&all_seqs).await?;
        self.socket().send(&batch).await?;
        let mut failures: Vec<super::NftBatchFailure> = Vec::new();

        // (4) Wrap in the Connection-level operation timeout
        // (Plan 171 default: 30s). Surfaces a missing end-seq
        // ACK as Error::Timeout instead of an indefinite hang.
        self.with_timeout(async {
            loop {
                // nfnetlink processes the whole batch inside our sendmsg and
                // queues every answer before it returns. So once one failure
                // is in, everything else the kernel has to say is already in
                // the socket: drain it without waiting for an END ACK a
                // refused batch may not get.
                let data: Vec<u8> = if failures.is_empty() {
                    session.recv_with_timeout(self).await?
                } else {
                    match session.try_recv(self)? {
                        Some(data) => data,
                        None => return Err(Error::NftBatch { failures }),
                    }
                };

                for msg_result in MessageIter::new(&data) {
                    // (0) A malformed frame that is not ours is not our
                    //     problem. This used to be `msg_result?`, which
                    //     runs *before* the seq filter below — so on a
                    //     connection also subscribed to nftables
                    //     multicast, one malformed broadcast frame
                    //     surfaced as an error out of `commit()`, even
                    //     though the batch may well have committed. The
                    //     opposite of the skip-and-continue policy the
                    //     request paths in this file already use (#281).
                    let Ok((header, payload)) = msg_result else {
                        tracing::trace!(
                            "nftables batch: skipping malformed frame while \
                             waiting for the batch window"
                        );
                        continue;
                    };

                    // (1) Seq filter — an exact window, per CLAUDE.md's
                    //     recv-loop rule 1. The old one-sided `> end_seq`
                    //     bound silently swallowed mid-batch kernel errors
                    //     (#199).
                    if !all_seqs.contains(&header.nlmsg_seq) {
                        continue;
                    }

                    if header.is_error() {
                        let err = NlMsgError::from_bytes(payload)?;
                        err.warn_if_ack_warns(header.nlmsg_flags, payload);
                        if err.is_ack() {
                            // (2) Only the BATCH_END ACK means the batch
                            //     committed. Per-op ACKs can fire mid-batch
                            //     and must not be mistaken for it — and after
                            //     a failure it means nothing was committed.
                            if header.nlmsg_seq == end_seq {
                                if failures.is_empty() {
                                    return Ok(());
                                }
                                return Err(Error::NftBatch { failures });
                            }
                            continue;
                        }
                        // (3) The kernel refused a message. Record which one
                        //     and keep reading: it reports every refused
                        //     operation, then rolls the batch back (#481).
                        let ext = err.ext_ack(header.nlmsg_flags, payload);
                        let seq = header.nlmsg_seq;
                        let failure = if seq == begin_seq {
                            super::NftBatchFailure::of_batch("batch begin", err.error, ext)
                        } else if seq == end_seq {
                            super::NftBatchFailure::of_batch("commit", err.error, ext)
                        } else {
                            let index = inner_seqs.iter().position(|s| *s == seq).unwrap_or(0);
                            let message = messages.get(index).map_or(&[][..], Vec::as_slice);
                            super::NftBatchFailure::of_message(index, message, err.error, ext)
                        };
                        failures.push(failure);
                        if seq == end_seq {
                            return Err(Error::NftBatch { failures });
                        }
                        continue;
                    }

                    // NLMSG_DONE is a *dump* terminator; nfnetlink never emits
                    // one for a batch. Treating it as success meant a stale
                    // DONE — left in the socket buffer by a cancelled dump,
                    // since dumps and batches share the fd — could report an
                    // uncommitted batch as committed (#209). The only success
                    // signal is the BATCH_END ACK above.
                    if header.is_done() {
                        return Err(Error::InvalidMessage(format!(
                            "nftables batch: unexpected NLMSG_DONE at seq {} \
                             (nfnetlink does not terminate batches with DONE)",
                            header.nlmsg_seq,
                        )));
                    }
                }
            }
        })
        .await
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /// Send a request and wait for ACK.
    ///
    /// All nftables mutation messages are wrapped in a batch
    /// (NFNL_MSG_BATCH_BEGIN / NFNL_MSG_BATCH_END) because the kernel
    /// requires batch wrapping for mutation operations since Linux 4.6.
    async fn nft_request_ack(&self, mut builder: MessageBuilder) -> Result<()> {
        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        self.send_batch(vec![builder.finish()]).await
    }

    /// Send a single (non-dump) GET and return its one reply:
    /// `(nfgen_family, payload after the nfgenmsg)`.
    async fn nft_get_one(&self, mut builder: MessageBuilder) -> Result<(u8, Vec<u8>)> {
        // The session serializes in mutex mode and registers the seq with
        // the driver in dispatcher mode; reading the socket directly raced
        // the driver's own recv there (#466).
        let seq = self.socket().next_seq();
        let mut session = self.recv_session(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());
        self.socket().send(&builder.finish()).await?;

        self.with_timeout(async {
            loop {
                let data: Vec<u8> = session.recv_with_timeout(self).await?;
                for msg_result in MessageIter::new(&data) {
                    let (header, payload) = msg_result?;
                    match classify(header, payload, seq) {
                        Classification::SkipSeq | Classification::Ack => continue,
                        Classification::Error(e) => return Err(e),
                        Classification::Done(result) => {
                            result?;
                            return Err(Error::InvalidMessage(
                                "nftables: GET answered with NLMSG_DONE and no reply".into(),
                            ));
                        }
                        Classification::Data { payload } if payload.len() >= NFGENMSG_HDRLEN => {
                            return Ok((payload[0], payload[NFGENMSG_HDRLEN..].to_vec()));
                        }
                        Classification::Data { .. } => continue,
                    }
                }
            }
        })
        .await
    }

    /// Subscribe to one or more nftables multicast groups.
    ///
    /// Once subscribed, use
    /// [`Self::events`](crate::netlink::Connection::events) /
    /// [`Self::into_events`](crate::netlink::Connection::into_events)
    /// to consume the resulting
    /// `Stream<Item = Result<NftablesEvent>>`.
    /// See [`NftablesGroup`] for the available groups (only `All`
    /// today — the kernel ships a single group for the family).
    ///
    /// Mirrors the
    /// [`Connection::<Netfilter>::subscribe`](crate::netlink::Connection::subscribe)
    /// shape used for conntrack events.
    ///
    /// # Example
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, Nftables};
    /// use nlink::netlink::nftables::{NftablesEvent, NftablesGroup};
    /// use tokio_stream::StreamExt;
    ///
    /// let mut nft = Connection::<Nftables>::new()?;
    /// nft.subscribe(&[NftablesGroup::All])?;
    /// let mut events = nft.events().await;
    /// while let Some(evt) = events.next().await {
    ///     match evt? {
    ///         NftablesEvent::NewTable(t) => println!("+ table {}", t.name),
    ///         NftablesEvent::DelTable(t) => println!("- table {}", t.name),
    ///         _ => {}
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "info", skip(self), fields(groups = ?groups))]
    pub fn subscribe(&self, groups: &[super::events::NftablesGroup]) -> Result<()> {
        for g in groups {
            self.socket().add_membership(g.to_kernel_group())?;
        }
        Ok(())
    }

    /// Subscribe to every nftables multicast group.
    ///
    /// Convenience for the typical "watch any ruleset mutation"
    /// pattern. Today equivalent to `subscribe(&[NftablesGroup::All])`;
    /// future kernel additions are picked up automatically.
    pub fn subscribe_all(&self) -> Result<()> {
        self.subscribe(&[super::events::NftablesGroup::All])
    }

    /// Send a dump request and collect responses.
    ///
    /// Returns (nfgen_family, payload_after_nfgenmsg) tuples.
    ///
    /// A dump the kernel marks `NLM_F_DUMP_INTR` — the ruleset changed under
    /// it — is read to its end and sent again, a bounded number of times,
    /// rather than failing the caller's diff (#494).
    async fn nft_dump(&self, builder: MessageBuilder) -> Result<Vec<(u8, Vec<u8>)>> {
        const ATTEMPTS: usize = 10;
        let mut attempt = 0;
        loop {
            match self.nft_dump_once(builder.clone()).await {
                Err(e) if e.is_dump_interrupted() && attempt + 1 < ATTEMPTS => {
                    attempt += 1;
                    tracing::debug!(attempt, "nftables dump interrupted; re-dumping");
                }
                other => return other,
            }
        }
    }

    async fn nft_dump_once(&self, mut builder: MessageBuilder) -> Result<Vec<(u8, Vec<u8>)>> {
        // F1 fix — serialize the send + recv-loop pair so concurrent
        // tasks on a shared `Arc<Connection>` don't race on the recv
        // side; in dispatcher mode, register with the driver instead of
        // racing its recv (#466). See connection.rs `Concurrency` docstring.
        let seq = self.socket().next_seq();
        let mut session = self.recv_session_dump(seq).await?;
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        // Plan 172 — wrap the recv loop in the Connection-level
        // operation timeout (Plan 171 default: 30s). Without
        // this, a missing NLMSG_DONE from the kernel would hang
        // the dump indefinitely.
        self.with_timeout(async {
            let mut results = Vec::new();
            let mut interrupted = false;

            loop {
                let data: Vec<u8> = session.recv_with_timeout(self).await?;
                let mut done = false;

                for msg_result in MessageIter::new(&data) {
                    let (header, payload) = msg_result?;

                    // Read a torn dump to its end before the retry, so its
                    // frames are not left for the next request (#494).
                    if interrupted {
                        if ends_dump(header, seq) {
                            return Err(Error::DumpInterrupted);
                        }
                        continue;
                    }

                    // `diff()` builds its plan from these dumps and
                    // `apply()` commits the plan in one atomic batch, so
                    // a torn snapshot (`NLM_F_DUMP_INTR`) or a dump that
                    // gave up partway becomes a wrong ruleset applied
                    // all at once — and with `purge_tables` on, a
                    // deletion of objects that were only missing because
                    // the dump was short. Neither was checked here
                    // (#267, #271).
                    match classify(header, payload, seq) {
                        Classification::SkipSeq | Classification::Ack => continue,
                        Classification::Error(Error::DumpInterrupted) => {
                            if ends_dump(header, seq) {
                                return Err(Error::DumpInterrupted);
                            }
                            interrupted = true;
                        }
                        Classification::Error(e) => return Err(e),
                        Classification::Done(result) => {
                            result?;
                            done = true;
                            break;
                        }
                        Classification::Data { payload } => {
                            // Extract nfgenmsg family from the payload
                            if payload.len() >= NFGENMSG_HDRLEN {
                                let family = payload[0];
                                results.push((family, payload[NFGENMSG_HDRLEN..].to_vec()));
                            }
                        }
                    }
                }

                if done {
                    break;
                }
            }

            Ok(results)
        })
        .await
    }
}

/// Overwrite an already-`finish()`ed message's `nlmsg_seq` and `nlmsg_pid` in
/// place.
///
/// `send_batch` calls this on every inner message so the whole batch occupies
/// one contiguous seq window allocated from the socket's counter — see #199.
/// A free function (not a method) so the unit tests can exercise it without an
/// open socket, matching the Plan 181 convention below.
///
/// `struct nlmsghdr` is `len@0 type@4 flags@6 seq@8 pid@12`.
pub(crate) fn stamp_seq_pid(msg: &mut [u8], seq: u32, pid: u32) -> Result<()> {
    const SEQ_OFFSET: usize = 8;
    const PID_OFFSET: usize = 12;

    if msg.len() < NLMSG_HDRLEN {
        return Err(Error::InvalidMessage(format!(
            "nftables batch: inner message is {} bytes, shorter than a \
             {NLMSG_HDRLEN}-byte netlink header",
            msg.len(),
        )));
    }

    msg[SEQ_OFFSET..SEQ_OFFSET + 4].copy_from_slice(&seq.to_ne_bytes());
    // Transaction's builders never set a pid, unlike every other request path
    // in the crate. Stamp it here so they match.
    msg[PID_OFFSET..PID_OFFSET + 4].copy_from_slice(&pid.to_ne_bytes());
    Ok(())
}

// =============================================================================
// Plan 181 — list_*_in request-builder helpers (free functions)
//
// Extracted from the `list_*_filtered` methods so the wire-shape
// unit tests can construct + inspect the request bytes without
// going through `nft_dump` (which needs an open socket).
// =============================================================================

pub(crate) fn build_list_tables_request(family_byte: u8) -> MessageBuilder {
    let mut builder =
        MessageBuilder::new(nft_msg_type(NFT_MSG_GETTABLE), NLM_F_REQUEST | NLM_F_DUMP);
    let nfgenmsg = NfGenMsg {
        nfgen_family: family_byte,
        version: 0,
        res_id: 0,
    };
    builder.append(&nfgenmsg);
    builder
}

pub(crate) fn build_list_chains_request(
    family_byte: u8,
    table: Option<&str>,
) -> MessageBuilder {
    let mut builder =
        MessageBuilder::new(nft_msg_type(NFT_MSG_GETCHAIN), NLM_F_REQUEST | NLM_F_DUMP);
    let nfgenmsg = NfGenMsg {
        nfgen_family: family_byte,
        version: 0,
        res_id: 0,
    };
    builder.append(&nfgenmsg);
    if let Some(t) = table {
        // Plan 181 — kernels prior to ~6.10 ignore NFTA_CHAIN_TABLE
        // on dump requests (it's an optimization hint, not a
        // contract). Send it anyway in case the running kernel
        // honors it; client-side `retain` in the caller catches
        // the rest.
        builder.append_attr_str(NFTA_CHAIN_TABLE, t);
    }
    builder
}

pub(crate) fn build_list_flowtables_request(
    family_byte: u8,
    table: Option<&str>,
) -> MessageBuilder {
    let mut builder = MessageBuilder::new(
        nft_msg_type(NFT_MSG_GETFLOWTABLE),
        NLM_F_REQUEST | NLM_F_DUMP,
    );
    let nfgenmsg = NfGenMsg {
        nfgen_family: family_byte,
        version: 0,
        res_id: 0,
    };
    builder.append(&nfgenmsg);
    if let Some(t) = table {
        builder.append_attr_str(NFTA_FLOWTABLE_TABLE, t);
    }
    builder
}

pub(crate) fn build_list_sets_request(
    family_byte: u8,
    table: Option<&str>,
) -> MessageBuilder {
    let mut builder =
        MessageBuilder::new(nft_msg_type(NFT_MSG_GETSET), NLM_F_REQUEST | NLM_F_DUMP);
    let nfgenmsg = NfGenMsg {
        nfgen_family: family_byte,
        version: 0,
        res_id: 0,
    };
    builder.append(&nfgenmsg);
    if let Some(t) = table {
        builder.append_attr_str(NFTA_SET_TABLE, t);
    }
    builder
}

pub(crate) fn build_list_set_elements_request(
    family_byte: u8,
    table: &str,
    set: &str,
) -> MessageBuilder {
    let mut builder = MessageBuilder::new(
        nft_msg_type(NFT_MSG_GETSETELEM),
        NLM_F_REQUEST | NLM_F_DUMP,
    );
    let nfgenmsg = NfGenMsg {
        nfgen_family: family_byte,
        version: 0,
        res_id: 0,
    };
    builder.append(&nfgenmsg);
    builder.append_attr_str(NFTA_SET_ELEM_LIST_TABLE, table);
    builder.append_attr_str(NFTA_SET_ELEM_LIST_SET, set);
    builder
}

// =============================================================================
// Attribute Parsing
// =============================================================================

pub(crate) fn parse_table(data: &[u8], family: Family) -> Option<Table> {
    let mut table = Table {
        name: String::new(),
        family,
        flags: 0,
        use_count: 0,
        handle: 0,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type & 0x7FFF {
            NFTA_TABLE_NAME => {
                table.name = attr_str(payload)?;
            }
            NFTA_TABLE_FLAGS if payload.len() >= 4 => {
                table.flags = u32::from_be_bytes(payload[..4].try_into().unwrap());
            }
            NFTA_TABLE_USE if payload.len() >= 4 => {
                table.use_count = u32::from_be_bytes(payload[..4].try_into().unwrap());
            }
            NFTA_TABLE_HANDLE if payload.len() >= 8 => {
                table.handle = u64::from_be_bytes(payload[..8].try_into().unwrap());
            }
            _ => {}
        }
    }

    if table.name.is_empty() {
        None
    } else {
        Some(table)
    }
}

pub(crate) fn parse_chain(data: &[u8], family: Family) -> Option<ChainInfo> {
    let mut chain = ChainInfo {
        table: String::new(),
        name: String::new(),
        family,
        hook: None,
        priority: None,
        chain_type: None,
        policy: None,
        handle: 0,
        device: None,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type & 0x7FFF {
            NFTA_CHAIN_TABLE => {
                chain.table = attr_str(payload).unwrap_or_default();
            }
            NFTA_CHAIN_NAME => {
                chain.name = attr_str(payload).unwrap_or_default();
            }
            NFTA_CHAIN_HANDLE if payload.len() >= 8 => {
                chain.handle = u64::from_be_bytes(payload[..8].try_into().unwrap());
            }
            NFTA_CHAIN_HOOK => {
                for (hook_attr, hook_payload) in AttrIter::new(payload) {
                    match hook_attr & 0x7FFF {
                        NFTA_HOOK_HOOKNUM if hook_payload.len() >= 4 => {
                            chain.hook =
                                Some(u32::from_be_bytes(hook_payload[..4].try_into().unwrap()));
                        }
                        NFTA_HOOK_PRIORITY if hook_payload.len() >= 4 => {
                            chain.priority =
                                Some(i32::from_be_bytes(hook_payload[..4].try_into().unwrap()));
                        }
                        NFTA_HOOK_DEV => {
                            chain.device = attr_str(hook_payload);
                        }
                        _ => {}
                    }
                }
            }
            NFTA_CHAIN_POLICY if payload.len() >= 4 => {
                chain.policy = Some(u32::from_be_bytes(payload[..4].try_into().unwrap()));
            }
            NFTA_CHAIN_TYPE => {
                chain.chain_type = attr_str(payload)
                    .as_deref()
                    .and_then(super::types::ChainType::from_kernel_string);
            }
            _ => {}
        }
    }

    if chain.name.is_empty() {
        None
    } else {
        Some(chain)
    }
}

pub(crate) fn parse_rule(data: &[u8], family: Family) -> Option<RuleInfo> {
    let mut rule = RuleInfo {
        table: String::new(),
        chain: String::new(),
        family,
        handle: 0,
        position: None,
        key: None,
        comment_text: None,
        userdata_raw: None,
        expression_bytes: Vec::new(),
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type & 0x7FFF {
            NFTA_RULE_TABLE => {
                rule.table = attr_str(payload).unwrap_or_default();
            }
            NFTA_RULE_CHAIN => {
                rule.chain = attr_str(payload).unwrap_or_default();
            }
            NFTA_RULE_HANDLE if payload.len() >= 8 => {
                rule.handle = u64::from_be_bytes(payload[..8].try_into().unwrap());
            }
            NFTA_RULE_POSITION if payload.len() >= 8 => {
                rule.position = Some(u64::from_be_bytes(payload[..8].try_into().unwrap()));
            }
            NFTA_RULE_EXPRESSIONS => {
                rule.expression_bytes = payload.to_vec();
            }
            NFTA_RULE_USERDATA => {
                rule.userdata_raw = Some(payload.to_vec());
                rule.key = super::userdata::parse_nlink_comment(payload);
                rule.comment_text = super::userdata::parse_comment(payload);
            }
            _ => {}
        }
    }

    if rule.table.is_empty() {
        None
    } else {
        Some(rule)
    }
}

pub(crate) fn parse_set(data: &[u8], family: Family) -> Option<SetInfo> {
    let mut set = SetInfo {
        table: String::new(),
        name: String::new(),
        family,
        flags: SetFlags::empty(),
        key_type: 0,
        key_len: 0,
        handle: 0,
        size: None,
        timeout: None,
        gc_interval: None,
        data_type: None,
        data_len: None,
        object_type: None,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type & 0x7FFF {
            NFTA_SET_DATA_TYPE if payload.len() >= 4 => {
                set.data_type = Some(u32::from_be_bytes(payload[..4].try_into().unwrap()));
            }
            NFTA_SET_DATA_LEN if payload.len() >= 4 => {
                set.data_len = Some(u32::from_be_bytes(payload[..4].try_into().unwrap()));
            }
            NFTA_SET_OBJ_TYPE if payload.len() >= 4 => {
                set.object_type = Some(u32::from_be_bytes(payload[..4].try_into().unwrap()));
            }
            NFTA_SET_TIMEOUT if payload.len() >= 8 => {
                let ms = u64::from_be_bytes(payload[..8].try_into().unwrap());
                set.timeout = Some(std::time::Duration::from_millis(ms));
            }
            NFTA_SET_GC_INTERVAL if payload.len() >= 4 => {
                let ms = u32::from_be_bytes(payload[..4].try_into().unwrap());
                set.gc_interval = Some(std::time::Duration::from_millis(ms.into()));
            }
            // Always dumped, without NLA_F_NESTED, and empty when the set
            // has no size.
            NFTA_SET_DESC => {
                for (desc_type, desc) in AttrIter::new(payload) {
                    if desc_type & 0x7FFF == NFTA_SET_DESC_SIZE && desc.len() >= 4 {
                        set.size = Some(u32::from_be_bytes(desc[..4].try_into().unwrap()));
                    }
                }
            }
            NFTA_SET_TABLE => {
                set.table = attr_str(payload).unwrap_or_default();
            }
            NFTA_SET_NAME => {
                set.name = attr_str(payload).unwrap_or_default();
            }
            NFTA_SET_FLAGS if payload.len() >= 4 => {
                set.flags = SetFlags(u32::from_be_bytes(payload[..4].try_into().unwrap()));
            }
            NFTA_SET_KEY_TYPE if payload.len() >= 4 => {
                set.key_type = u32::from_be_bytes(payload[..4].try_into().unwrap());
            }
            NFTA_SET_KEY_LEN if payload.len() >= 4 => {
                set.key_len = u32::from_be_bytes(payload[..4].try_into().unwrap());
            }
            NFTA_SET_HANDLE if payload.len() >= 8 => {
                set.handle = u64::from_be_bytes(payload[..8].try_into().unwrap());
            }
            _ => {}
        }
    }

    if set.name.is_empty() { None } else { Some(set) }
}

/// Parse the element keys out of one `NFT_MSG_GETSETELEM` dump
/// message, appending each as a [`SetElement`] to `out`.
///
/// Walks `NFTA_SET_ELEM_LIST_ELEMENTS` → per-element `NFTA_LIST_ELEM`
/// → `NFTA_SET_ELEM_KEY` → `NFTA_DATA_VALUE` (the raw key bytes).
/// Map data (`NFTA_SET_ELEM_DATA`) is ignored — [`SetElement`] is
/// key-only. Per parser-robustness rule 3, malformed nests are
/// silently skipped (no element pushed) rather than aborting the
/// whole dump.
pub(crate) fn parse_set_elements(data: &[u8], out: &mut Vec<SetElement>) {
    for (attr_type, payload) in AttrIter::new(data) {
        if attr_type & 0x7FFF != NFTA_SET_ELEM_LIST_ELEMENTS {
            continue;
        }
        // Each child is an NFTA_LIST_ELEM wrapping one element.
        for (elem_type, elem_payload) in AttrIter::new(payload) {
            if elem_type & 0x7FFF != NFTA_LIST_ELEM {
                continue;
            }
            if let Some(elem) = parse_set_elem(elem_payload) {
                out.push(elem);
            }
        }
    }
}

/// Decode one element nest: the `NFTA_SET_ELEM_KEY` → `NFTA_DATA_VALUE`
/// key bytes and `NFTA_SET_ELEM_FLAGS`. An element without a key is kept
/// only when it is the catch-all element.
fn parse_set_elem(elem: &[u8]) -> Option<SetElement> {
    let mut key = None;
    let mut key_end = None;
    let mut flags = 0;
    let mut timeout = None;
    let mut expiration = None;
    let mut data = None;
    let millis = |payload: &[u8]| {
        payload
            .get(..8)
            .map(|b| std::time::Duration::from_millis(u64::from_be_bytes(b.try_into().unwrap())))
    };
    let value = |payload: &[u8]| {
        AttrIter::new(payload)
            .find(|(data_type, _)| data_type & 0x7FFF == NFTA_DATA_VALUE)
            .map(|(_, data)| data.to_vec())
    };
    for (attr_type, payload) in AttrIter::new(elem) {
        match attr_type & 0x7FFF {
            NFTA_SET_ELEM_KEY => key = value(payload),
            NFTA_SET_ELEM_KEY_END => key_end = value(payload),
            NFTA_SET_ELEM_TIMEOUT => timeout = millis(payload),
            NFTA_SET_ELEM_DATA => {
                data = AttrIter::new(payload).find_map(|(data_type, inner)| {
                    match data_type & 0x7FFF {
                        NFTA_DATA_VALUE => Some(SetElementData::Value(inner.to_vec())),
                        NFTA_DATA_VERDICT => {
                            super::expr::parse_verdict(inner).map(SetElementData::Verdict)
                        }
                        _ => None,
                    }
                });
            }
            NFTA_SET_ELEM_OBJREF => {
                data = attr_str(payload).map(SetElementData::Object);
            }
            NFTA_SET_ELEM_EXPIRATION => expiration = millis(payload),
            NFTA_SET_ELEM_FLAGS if payload.len() >= 4 => {
                flags = u32::from_be_bytes(payload[..4].try_into().unwrap());
            }
            _ => {}
        }
    }
    match key {
        Some(key) => Some(
            SetElement::from_wire(key, flags)
                .with_key_end(key_end)
                .with_timers(timeout, expiration)
                .with_data(data),
        ),
        None if flags & NFT_SET_ELEM_CATCHALL != 0 => Some(SetElement::from_wire(Vec::new(), flags)),
        None => None,
    }
}

/// Extract a null-terminated string from attribute payload.
fn attr_str(payload: &[u8]) -> Option<String> {
    if payload.is_empty() {
        return None;
    }
    let s = std::str::from_utf8(payload)
        .unwrap_or("")
        .trim_end_matches('\0');
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

// =============================================================================
// Batch Transaction
// =============================================================================

/// Represents a batch of nftables operations to be applied atomically.
///
/// All operations are queued and sent in a single batch wrapped with
/// `NFNL_MSG_BATCH_BEGIN` / `NFNL_MSG_BATCH_END`.
#[must_use = "builders do nothing unless used"]
pub struct Transaction {
    messages: Vec<Vec<u8>>,
    /// Allocator for `NFTA_SET_ID` — a **batch-local** identifier that lets a
    /// set-element add reference a set created in the same batch.
    ///
    /// This is not a netlink sequence number. It used to double as one, which
    /// is what broke `send_batch`'s response matching (#199): the counter is
    /// unrelated to the socket's, so the batch's seqs were not a contiguous
    /// window and mid-batch kernel errors were silently discarded.
    /// `send_batch` now assigns every `nlmsg_seq` itself.
    set_id_counter: u32,
    /// The first error a builder method could not return (they return
    /// `Self`): an element that does not fit its set, say. `commit` reports
    /// it instead of sending the batch, so nothing is dropped silently.
    error: Option<Error>,
}

impl Transaction {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
            set_id_counter: 1,
            error: None,
        }
    }

    /// An empty transaction, for unit tests that inspect the bytes.
    #[cfg(test)]
    pub(crate) fn new_for_test() -> Self {
        Self::new()
    }

    /// The messages built so far, for unit tests.
    #[cfg(test)]
    pub(crate) fn messages_for_test(self) -> Vec<Vec<u8>> {
        self.messages
    }

    /// Keep the first deferred error.
    fn defer(&mut self, error: Error) {
        self.error.get_or_insert(error);
    }

    /// Allocate a batch-local `NFTA_SET_ID`.
    ///
    /// See the `set_id_counter` field's own docs for why this is not a
    /// netlink sequence number. (That link used to be an intra-doc
    /// reference to a *private* field, which rustdoc cannot resolve —
    /// caught by the `-D rustdoc::broken_intra_doc_links` CI gate only
    /// because it is a `Self::` path; #281.)
    fn next_set_id(&mut self) -> u32 {
        let id = self.set_id_counter;
        self.set_id_counter += 1;
        id
    }

    /// Add a table creation to the batch.
    pub fn add_table(mut self, name: &str, family: Family) -> Self {
        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_NEWTABLE),
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
        );
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_TABLE_NAME, name);
        self.messages.push(builder.finish());
        self
    }

    /// Add a chain creation to the batch. Fails (`EEXIST`) if the chain
    /// exists; see [`update_chain`](Self::update_chain).
    pub fn add_chain(self, chain: Chain) -> Self {
        self.push_newchain(chain, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL)
    }

    /// Change an existing chain in place, or create it if it does not
    /// exist (`nft add chain`): `NFT_MSG_NEWCHAIN` without `NLM_F_EXCL`,
    /// which `nf_tables_newchain` turns into `nf_tables_updchain` for an
    /// existing chain. That changes a base chain's **policy** and keeps its
    /// rules. The kernel refuses to change a live base chain's hook,
    /// priority or type (`EEXIST`); those need the chain deleted and
    /// created again (#456).
    pub fn update_chain(self, chain: Chain) -> Self {
        self.push_newchain(chain, NLM_F_REQUEST | NLM_F_CREATE)
    }

    fn push_newchain(mut self, chain: Chain, flags: u16) -> Self {
        let mut builder = MessageBuilder::new(nft_msg_type(NFT_MSG_NEWCHAIN), flags);
        let nfgenmsg = NfGenMsg::new(chain.family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_CHAIN_TABLE, chain.table.as_str());
        builder.append_attr_str(NFTA_CHAIN_NAME, chain.name.as_str());

        if let Some(chain_type) = chain.chain_type {
            builder.append_attr_str(NFTA_CHAIN_TYPE, chain_type.as_str());
        }

        if let Some(hook) = chain.hook {
            let hook_nest = builder.nest_start(NFTA_CHAIN_HOOK | 0x8000);
            builder.append_attr_u32_be(NFTA_HOOK_HOOKNUM, hook.to_u32());
            let priority = chain.priority.unwrap_or(Priority::Filter).to_i32();
            builder.append_attr_u32_be(NFTA_HOOK_PRIORITY, priority as u32);
            if let Some(dev) = &chain.device {
                builder.append_attr_str(NFTA_HOOK_DEV, dev);
            }
            builder.nest_end(hook_nest);
        }

        if let Some(policy) = chain.policy {
            builder.append_attr_u32_be(NFTA_CHAIN_POLICY, policy.to_u32());
        }

        self.messages.push(builder.finish());
        self
    }

    /// Add a rule to the batch.
    ///
    /// Rules are appended in the order they are added — see the
    /// `NLM_F_APPEND` note on [`Connection::add_rule`] (#195).
    pub fn add_rule(self, rule: Rule) -> Self {
        let position = rule.position;
        self.push_newrule(rule, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_APPEND, position)
    }

    /// Insert a rule immediately **before** the rule with kernel handle
    /// `before` (nft's `insert rule ... position <handle>`). Without
    /// `NLM_F_APPEND` the kernel links the new rule ahead of the
    /// positioned one; [`add_rule`](Self::add_rule)'s `NLM_F_APPEND` puts it
    /// after. Rule order is policy, so the declarative apply uses this to
    /// put a rule back exactly where it was.
    pub(crate) fn insert_rule_before(self, rule: Rule, before: u64) -> Self {
        self.push_newrule(rule, NLM_F_REQUEST | NLM_F_CREATE, Some(before))
    }

    fn push_newrule(mut self, rule: Rule, flags: u16, position: Option<u64>) -> Self {
        let mut builder = MessageBuilder::new(nft_msg_type(NFT_MSG_NEWRULE), flags);
        let nfgenmsg = NfGenMsg::new(rule.family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_RULE_TABLE, &rule.table);
        builder.append_attr_str(NFTA_RULE_CHAIN, &rule.chain);

        if let Some(pos) = position {
            builder.append_attr_u64_be(NFTA_RULE_POSITION, pos);
        }

        if !rule.exprs.is_empty() {
            write_expressions(&mut builder, &rule.exprs);
        }

        // Comment → NFTA_RULE_USERDATA TLV (Plan 157b v2).
        match super::userdata::encode_rule_userdata(rule.key.as_deref(), rule.comment.as_deref()) {
            Ok(Some(udata)) => builder.append_attr(NFTA_RULE_USERDATA, &udata),
            Ok(None) => {}
            Err(e) => {
                self.defer(e);
                return self;
            }
        }

        self.messages.push(builder.finish());
        self
    }

    /// Replace an existing rule's body at a specific kernel handle.
    /// Emits `NFT_MSG_NEWRULE | NLM_F_REPLACE | NFTA_RULE_HANDLE`,
    /// which the kernel atomically swaps in-place (preserves rule
    /// position; no flush). Used by `NftablesDiff::apply` when a
    /// keyed rule's body has changed but its identity (handle_key
    /// → `NFTA_RULE_USERDATA`) still matches.
    ///
    /// Plan 157b v2.
    pub fn replace_rule(mut self, rule: Rule, handle: u64) -> Self {
        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_NEWRULE),
            NLM_F_REQUEST | NLM_F_REPLACE,
        );
        let nfgenmsg = NfGenMsg::new(rule.family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_RULE_TABLE, &rule.table);
        builder.append_attr_str(NFTA_RULE_CHAIN, &rule.chain);
        builder.append_attr_u64_be(NFTA_RULE_HANDLE, handle);

        if !rule.exprs.is_empty() {
            write_expressions(&mut builder, &rule.exprs);
        }

        match super::userdata::encode_rule_userdata(rule.key.as_deref(), rule.comment.as_deref()) {
            Ok(Some(udata)) => builder.append_attr(NFTA_RULE_USERDATA, &udata),
            Ok(None) => {}
            Err(e) => {
                self.defer(e);
                return self;
            }
        }

        self.messages.push(builder.finish());
        self
    }

    /// Add a table deletion to the batch.
    pub fn del_table(mut self, name: &str, family: Family) -> Self {
        let mut builder = MessageBuilder::new(nft_msg_type(NFT_MSG_DELTABLE), NLM_F_REQUEST);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_TABLE_NAME, name);
        self.messages.push(builder.finish());
        self
    }

    /// Add a table creation with explicit table-level flags
    /// (`NFT_TABLE_F_DORMANT` / `_OWNER` / `_PERSIST`) to the
    /// batch. Mirrors the imperative
    /// [`Connection::<Nftables>::add_table_with_flags`](Connection).
    /// Use [`Self::add_table`] when no flags are needed.
    pub fn add_table_with_flags(mut self, name: &str, family: Family, flags: u32) -> Self {
        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_NEWTABLE),
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
        );
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_TABLE_NAME, name);
        if flags != 0 {
            // NFTA_TABLE_FLAGS is big-endian per kernel convention
            // (matches the existing list_tables parser at
            // `parse_table` which reads it as `from_be_bytes`).
            builder.append_attr_u32_be(NFTA_TABLE_FLAGS, flags);
        }
        self.messages.push(builder.finish());
        self
    }

    /// Add a chain deletion to the batch. Mirrors the imperative
    /// [`Connection::<Nftables>::del_chain`](Connection) shape.
    pub fn del_chain(mut self, table: &str, name: &str, family: Family) -> Self {
        let mut builder = MessageBuilder::new(nft_msg_type(NFT_MSG_DELCHAIN), NLM_F_REQUEST);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_CHAIN_TABLE, table);
        builder.append_attr_str(NFTA_CHAIN_NAME, name);
        self.messages.push(builder.finish());
        self
    }

    /// Add a rule deletion to the batch (by kernel handle).
    /// Mirrors the imperative
    /// [`Connection::<Nftables>::del_rule`](Connection).
    pub fn del_rule(mut self, table: &str, chain: &str, family: Family, handle: u64) -> Self {
        let mut builder = MessageBuilder::new(nft_msg_type(NFT_MSG_DELRULE), NLM_F_REQUEST);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_RULE_TABLE, table);
        builder.append_attr_str(NFTA_RULE_CHAIN, chain);
        builder.append_attr_u64_be(NFTA_RULE_HANDLE, handle);
        self.messages.push(builder.finish());
        self
    }

    /// Add a flowtable creation to the batch. Mirrors the
    /// imperative [`Connection::<Nftables>::add_flowtable`](Connection).
    pub fn add_flowtable(mut self, ft: &super::types::Flowtable) -> Self {
        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_NEWFLOWTABLE),
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
        );
        let nfgenmsg = NfGenMsg::new(ft.family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_FLOWTABLE_TABLE, &ft.table);
        builder.append_attr_str(NFTA_FLOWTABLE_NAME, &ft.name);

        let hook = builder.nest_start(NFTA_FLOWTABLE_HOOK | 0x8000);
        builder.append_attr_u32_be(NFTA_FLOWTABLE_HOOK_NUM, NF_NETDEV_INGRESS);
        builder.append_attr_u32_be(NFTA_FLOWTABLE_HOOK_PRIORITY, ft.priority as u32);
        if !ft.devs.is_empty() {
            let devs = builder.nest_start(NFTA_FLOWTABLE_HOOK_DEVS | 0x8000);
            for dev in &ft.devs {
                let dev_nest = builder.nest_start(1u16 | 0x8000); // NFTA_LIST_ELEM
                builder.append_attr_str(NFTA_DEVICE_NAME, dev);
                builder.nest_end(dev_nest);
            }
            builder.nest_end(devs);
        }
        builder.nest_end(hook);

        if ft.flags != 0 {
            builder.append_attr_u32_be(NFTA_FLOWTABLE_FLAGS, ft.flags);
        }

        self.messages.push(builder.finish());
        self
    }

    /// Add a flowtable deletion to the batch. Mirrors the
    /// imperative [`Connection::<Nftables>::del_flowtable`](Connection).
    pub fn del_flowtable(mut self, family: Family, table: &str, name: &str) -> Self {
        let mut builder = MessageBuilder::new(nft_msg_type(NFT_MSG_DELFLOWTABLE), NLM_F_REQUEST);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_FLOWTABLE_TABLE, table);
        builder.append_attr_str(NFTA_FLOWTABLE_NAME, name);
        self.messages.push(builder.finish());
        self
    }

    /// Add a set creation to the batch. Mirrors the imperative
    /// [`Connection::<Nftables>::add_set`](Connection).
    ///
    /// The per-transaction `NFTA_SET_ID` is set to the message's
    /// sequence number so it's unique within the batch (the kernel
    /// uses it to disambiguate sets created in the same
    /// transaction; element adds reference the set by name, so they
    /// don't need it).
    pub fn add_set(self, set: Set) -> Self {
        self.push_newset(set, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL)
    }

    /// Update an existing set in place: `NFT_MSG_NEWSET` without
    /// `NLM_F_EXCL` (or `NLM_F_CREATE` — a set that has gone is `ENOENT`,
    /// not silently recreated).
    ///
    /// The kernel (6.2+) first checks the key, data, flags and lengths
    /// match the existing set (`EEXIST` otherwise), then at commit takes
    /// the new size (6.5+, when non-zero) and **overwrites** the timeout
    /// and GC interval with what the message carries — absent means 0. So
    /// `set` must carry the timeout and GC interval the set is to keep; the
    /// declarative diff fills in the kernel's where the declaration has
    /// none. Older kernels accept the message and change nothing.
    pub(crate) fn update_set(self, set: Set) -> Self {
        self.push_newset(set, NLM_F_REQUEST)
    }

    fn push_newset(mut self, set: Set, flags: u16) -> Self {
        let set_id = self.next_set_id();
        let mut builder = MessageBuilder::new(nft_msg_type(NFT_MSG_NEWSET), flags);
        let nfgenmsg = NfGenMsg::new(set.family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_SET_TABLE, &set.table);
        builder.append_attr_str(NFTA_SET_NAME, &set.name);
        builder.append_attr_u32_be(NFTA_SET_KEY_TYPE, set.key_type.type_id());
        builder.append_attr_u32_be(NFTA_SET_KEY_LEN, set.key_type.len());
        builder.append_attr_u32_be(NFTA_SET_FLAGS, set.wire_flags().bits());
        append_set_data_type(&mut builder, &set);
        append_set_timeouts(&mut builder, &set);
        append_set_desc(&mut builder, &set);
        builder.append_attr_u32_be(NFTA_SET_ID, set_id);
        self.messages.push(builder.finish());
        self
    }

    /// Add a set deletion to the batch. Mirrors the imperative
    /// [`Connection::<Nftables>::del_set`](Connection).
    pub fn del_set(mut self, table: &str, name: &str, family: Family) -> Self {
        let mut builder = MessageBuilder::new(nft_msg_type(NFT_MSG_DELSET), NLM_F_REQUEST);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_SET_TABLE, table);
        builder.append_attr_str(NFTA_SET_NAME, name);
        self.messages.push(builder.finish());
        self
    }

    /// Add set-element insertions to the batch. Mirrors the
    /// imperative [`Connection::<Nftables>::add_set_elements`](Connection);
    /// an element that does not fit the set fails [`commit`](Self::commit).
    pub fn add_set_elements(mut self, set: &Set, elements: &[SetElement]) -> Self {
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_NEWSETELEM), NLM_F_REQUEST | NLM_F_CREATE);
        match append_set_elements(&mut builder, set, elements, ElementWrite::Add) {
            Ok(()) => self.messages.push(builder.finish()),
            Err(e) => self.defer(e),
        }
        self
    }

    /// Add set-element removals to the batch. Mirrors the
    /// imperative [`Connection::<Nftables>::del_set_elements`](Connection).
    pub fn del_set_elements(mut self, set: &Set, elements: &[SetElement]) -> Self {
        let mut builder = MessageBuilder::new(nft_msg_type(NFT_MSG_DELSETELEM), NLM_F_REQUEST);
        match append_set_elements(&mut builder, set, elements, ElementWrite::Delete) {
            Ok(()) => self.messages.push(builder.finish()),
            Err(e) => self.defer(e),
        }
        self
    }

    /// Add an object creation to the batch. Mirrors
    /// [`Connection::<Nftables>::add_object`](Connection).
    pub fn add_object(mut self, object: &Object) -> Self {
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_NEWOBJ), NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL);
        append_object(&mut builder, object);
        self.messages.push(builder.finish());
        self
    }

    /// Update an existing object in place: `NFT_MSG_NEWOBJ` without
    /// `NLM_F_EXCL`. Only a quota can be updated — its size and `over`
    /// change and its consumption stays. For a counter or a limit the
    /// kernel accepts the message and changes **nothing** (they have no
    /// update operation), so a changed limit must be deleted and created.
    pub fn update_object(mut self, object: &Object) -> Self {
        let mut builder = MessageBuilder::new(nft_msg_type(NFT_MSG_NEWOBJ), NLM_F_REQUEST);
        append_object(&mut builder, object);
        self.messages.push(builder.finish());
        self
    }

    /// Add an object deletion to the batch. Mirrors
    /// [`Connection::<Nftables>::del_object`](Connection).
    pub fn del_object(
        mut self,
        table: &str,
        name: &str,
        object_type: ObjectType,
        family: Family,
    ) -> Self {
        let mut builder = MessageBuilder::new(nft_msg_type(NFT_MSG_DELOBJ), NLM_F_REQUEST);
        append_object_key(&mut builder, table, name, object_type, family);
        self.messages.push(builder.finish());
        self
    }

    /// Add a message nlink does not model — see [`RawMessage`]. It goes in
    /// the batch like any other operation and commits atomically with it.
    pub fn raw(mut self, message: RawMessage) -> Self {
        let mut builder = MessageBuilder::new(
            nft_msg_type(message.msg),
            NLM_F_REQUEST | message.flags,
        );
        builder.append(&NfGenMsg::new(message.family));
        builder.append_bytes(&message.attrs);
        self.messages.push(builder.finish());
        self
    }

    /// Commit the transaction atomically. If a builder method recorded an
    /// error, that error is returned and nothing is sent.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "commit"))]
    pub async fn commit(self, conn: &Connection<Nftables>) -> Result<()> {
        if let Some(error) = self.error {
            return Err(error);
        }
        conn.send_batch(self.messages).await
    }
}

/// An nftables message nlink does not model, for
/// [`Transaction::raw`]: an `NFT_MSG_*` type, the family, extra
/// `NLM_F_*` flags (`NLM_F_REQUEST` is always set) and the attribute bytes
/// that follow the `nfgenmsg` header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RawMessage {
    /// `NFT_MSG_*` message type (the low byte; the nftables subsystem is
    /// added).
    pub msg: u8,
    /// Address family for the `nfgenmsg` header.
    pub family: Family,
    /// `NLM_F_*` flags besides `NLM_F_REQUEST` (e.g. `NLM_F_CREATE`).
    pub flags: u16,
    /// Attributes, already encoded.
    pub attrs: Vec<u8>,
}

impl RawMessage {
    /// An empty message of type `msg` for `family`.
    pub fn new(msg: u8, family: Family) -> Self {
        Self {
            msg,
            family,
            flags: 0,
            attrs: Vec::new(),
        }
    }

    /// Set the extra `NLM_F_*` flags.
    pub fn flags(mut self, flags: u16) -> Self {
        self.flags = flags;
        self
    }

    /// Set the attribute bytes.
    pub fn attrs(mut self, attrs: Vec<u8>) -> Self {
        self.attrs = attrs;
        self
    }
}

/// Append an object's table, name, type and data: a NEWOBJ's attributes.
fn append_object(builder: &mut MessageBuilder, object: &Object) {
    append_object_key(
        builder,
        &object.table,
        &object.name,
        object.config.object_type(),
        object.family,
    );
    super::object::append_object_data(builder, &object.config);
}

/// Append what names an object: nfgenmsg, table, name and type.
fn append_object_key(
    builder: &mut MessageBuilder,
    table: &str,
    name: &str,
    object_type: ObjectType,
    family: Family,
) {
    builder.append(&NfGenMsg::new(family));
    builder.append_attr_str(NFTA_OBJ_TABLE, table);
    builder.append_attr_str(NFTA_OBJ_NAME, name);
    builder.append_attr_u32_be(NFTA_OBJ_TYPE, object_type as u32);
}

/// Append a map's data type, and its data length for a value map.
fn append_set_data_type(builder: &mut MessageBuilder, set: &Set) {
    match &set.data_type {
        None => {}
        Some(SetDataType::Object(object_type)) => {
            builder.append_attr_u32_be(NFTA_SET_OBJ_TYPE, *object_type as u32);
        }
        Some(data) => {
            if let Some(type_id) = data.type_id() {
                builder.append_attr_u32_be(NFTA_SET_DATA_TYPE, type_id);
            }
            if let Some(len) = data.len() {
                builder.append_attr_u32_be(NFTA_SET_DATA_LEN, len);
            }
        }
    }
}

/// Append the set's default element timeout and GC interval, if any.
fn append_set_timeouts(builder: &mut MessageBuilder, set: &Set) {
    if let Some(timeout) = set.timeout {
        builder.append_attr_u64_be(NFTA_SET_TIMEOUT, super::expr::millis(timeout));
    }
    if let Some(gc) = set.gc_interval {
        let ms = u32::try_from(gc.as_millis()).unwrap_or(u32::MAX);
        builder.append_attr_u32_be(NFTA_SET_GC_INTERVAL, ms);
    }
}

/// Append the `NFTA_SET_DESC` nest: the set size, if any, and for an
/// interval set of concatenated keys the length of each field in bytes
/// (`NFTA_SET_DESC_CONCAT`), which the kernel requires with
/// `NFT_SET_CONCAT` and which selects the `pipapo` backend. Shared by the
/// imperative and `Transaction` set creation paths.
fn append_set_desc(builder: &mut MessageBuilder, set: &Set) {
    let fields = set
        .ranges_per_field()
        .then(|| set.key_type.concat_fields())
        .flatten();
    if set.size.is_none() && fields.is_none() {
        return;
    }
    let desc = builder.nest_start(NFTA_SET_DESC);
    if let Some(size) = set.size {
        builder.append_attr_u32_be(NFTA_SET_DESC_SIZE, size);
    }
    if let Some(fields) = fields {
        let concat = builder.nest_start(NFTA_SET_DESC_CONCAT);
        for field in fields {
            let elem = builder.nest_start(NFTA_LIST_ELEM);
            builder.append_attr_u32_be(NFTA_SET_FIELD_LEN, field.len());
            builder.nest_end(elem);
        }
        builder.nest_end(concat);
    }
    builder.nest_end(desc);
}

/// Whether elements are being added or deleted: a delete names elements by
/// key alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ElementWrite {
    Add,
    Delete,
}

/// Check `elements` against the set they go into: everything the writer
/// cannot encode is an error, never something dropped. Shared by the
/// element writers and `NftablesConfig::validate`.
pub(crate) fn check_elements(set: &Set, elements: &[SetElement], write: ElementWrite) -> Result<()> {
    // Ranges are compared and incremented as big-endian numbers, which a
    // host-order key is not; `nft` byte-swaps those, nlink does not model
    // that.
    if !elements.is_empty()
        && set.flags.contains(SetFlags::INTERVAL)
        && set.key_type.is_host_order()
    {
        return Err(Error::InvalidMessage(format!(
            "set {}: interval sets of {:?} keys are not modelled (host byte order)",
            set.name, set.key_type
        )));
    }
    // A map is declared with its data type, which is what its elements are
    // checked against; one flagged MAP without it could only take
    // elements nlink cannot check.
    if write == ElementWrite::Add
        && !elements.is_empty()
        && (set.flags.contains(SetFlags::MAP) || set.flags.contains(SetFlags::OBJECT))
        && set.data_type.is_none()
    {
        return Err(Error::InvalidMessage(format!(
            "set {}: a map's elements need its data type (`Set::map`)",
            set.name
        )));
    }
    for elem in elements {
        elem.check_for(set, write == ElementWrite::Delete)?;
    }
    Ok(())
}

/// Append the `NFTA_SET_ELEM_LIST_*` header + per-element nest used
/// by both `NEWSETELEM` and `DELSETELEM` messages. Shared by the
/// imperative `Connection` methods and the `Transaction` builders so
/// the wire shape stays identical.
fn append_set_elements(
    builder: &mut MessageBuilder,
    set: &Set,
    elements: &[SetElement],
    write: ElementWrite,
) -> Result<()> {
    check_elements(set, elements, write)?;
    // A delete names the element by its key (and range end); its data and
    // timeout are the kernel's business, not the request's.
    let carry = |e: &SetElement| match write {
        ElementWrite::Add => (e.timeout(), e.data().cloned()),
        ElementWrite::Delete => (None, None),
    };

    let nfgenmsg = NfGenMsg::new(set.family);
    builder.append(&nfgenmsg);
    builder.append_attr_str(NFTA_SET_ELEM_LIST_TABLE, &set.table);
    builder.append_attr_str(NFTA_SET_ELEM_LIST_SET, &set.name);

    // An interval set stores a range as a start and an end-plus-one
    // flagged INTERVAL_END (see `interval`) — except one of concatenated
    // keys, which stores it in one element with its inclusive end
    // (KEY_END); other sets one element each.
    // An element's timeout and map data go on its start: the kernel refuses
    // either on an interval end (EINVAL).
    let wire: Vec<super::interval::WireElement> = if set.ranges_per_field() {
        elements
            .iter()
            .map(|e| super::interval::WireElement {
                key: e.key().to_vec(),
                key_end: e.key_end().filter(|end| *end != e.key()).map(<[u8]>::to_vec),
                flags: 0,
                timeout: carry(e).0,
                data: carry(e).1,
            })
            .collect()
    } else if set.flags.contains(SetFlags::INTERVAL) {
        elements
            .iter()
            .flat_map(|e| {
                let mut wire = super::interval::lower(&super::interval::range_of(e));
                (wire[0].timeout, wire[0].data) = carry(e);
                wire
            })
            .collect()
    } else {
        elements
            .iter()
            .map(|e| super::interval::WireElement {
                key: e.key().to_vec(),
                key_end: None,
                flags: 0,
                timeout: carry(e).0,
                data: carry(e).1,
            })
            .collect()
    };
    let elems_nest = builder.nest_start(NFTA_SET_ELEM_LIST_ELEMENTS | 0x8000);
    for elem in &wire {
        let elem_nest = builder.nest_start(NFTA_LIST_ELEM | 0x8000);
        let key_nest = builder.nest_start(NFTA_SET_ELEM_KEY | 0x8000);
        builder.append_attr(NFTA_DATA_VALUE, &elem.key);
        builder.nest_end(key_nest);
        if let Some(end) = &elem.key_end {
            let end_nest = builder.nest_start(NFTA_SET_ELEM_KEY_END | 0x8000);
            builder.append_attr(NFTA_DATA_VALUE, end);
            builder.nest_end(end_nest);
        }
        if elem.flags != 0 {
            builder.append_attr_u32_be(NFTA_SET_ELEM_FLAGS, elem.flags);
        }
        if let Some(timeout) = elem.timeout {
            builder.append_attr_u64_be(NFTA_SET_ELEM_TIMEOUT, super::expr::millis(timeout));
        }
        match &elem.data {
            None => {}
            Some(SetElementData::Value(value)) => {
                let nest = builder.nest_start(NFTA_SET_ELEM_DATA | 0x8000);
                builder.append_attr(NFTA_DATA_VALUE, value);
                builder.nest_end(nest);
            }
            Some(SetElementData::Verdict(verdict)) => {
                let nest = builder.nest_start(NFTA_SET_ELEM_DATA | 0x8000);
                super::expr::write_verdict_data(builder, verdict);
                builder.nest_end(nest);
            }
            // An object map names the object outside the data nest.
            Some(SetElementData::Object(name)) => {
                builder.append_attr_str(NFTA_SET_ELEM_OBJREF, name);
            }
        }
        builder.nest_end(elem_nest);
    }
    builder.nest_end(elems_nest);
    Ok(())
}

/// Parse a flowtable from `NFT_MSG_GETFLOWTABLE` response payload.
pub(crate) fn parse_flowtable(data: &[u8], family: Family) -> Option<super::types::Flowtable> {
    let mut ft = super::types::Flowtable {
        family,
        table: String::new(),
        name: String::new(),
        devs: Vec::new(),
        priority: 0,
        flags: 0,
        use_count: 0,
        handle: 0,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type & 0x7FFF {
            NFTA_FLOWTABLE_TABLE => {
                ft.table = attr_str(payload)?;
            }
            NFTA_FLOWTABLE_NAME => {
                ft.name = attr_str(payload)?;
            }
            NFTA_FLOWTABLE_USE if payload.len() >= 4 => {
                ft.use_count = u32::from_be_bytes(payload[..4].try_into().ok()?);
            }
            NFTA_FLOWTABLE_HANDLE if payload.len() >= 8 => {
                ft.handle = u64::from_be_bytes(payload[..8].try_into().ok()?);
            }
            NFTA_FLOWTABLE_FLAGS if payload.len() >= 4 => {
                ft.flags = u32::from_be_bytes(payload[..4].try_into().ok()?);
            }
            NFTA_FLOWTABLE_HOOK => {
                // Nested: walk for priority + devs list.
                for (h_attr, h_payload) in AttrIter::new(payload) {
                    match h_attr & 0x7FFF {
                        NFTA_FLOWTABLE_HOOK_PRIORITY if h_payload.len() >= 4 => {
                            ft.priority = i32::from_be_bytes(
                                h_payload[..4].try_into().ok()?,
                            );
                        }
                        NFTA_FLOWTABLE_HOOK_DEVS => {
                            // List of nested NFTA_LIST_ELEM each
                            // carrying NFTA_DEVICE_NAME.
                            for (_le_attr, le_payload) in AttrIter::new(h_payload) {
                                for (d_attr, d_payload) in AttrIter::new(le_payload) {
                                    if d_attr & 0x7FFF == NFTA_DEVICE_NAME
                                        && let Some(s) = attr_str(d_payload)
                                    {
                                        ft.devs.push(s);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if ft.name.is_empty() {
        return None;
    }
    Some(ft)
}

#[cfg(test)]
mod transaction_tests {
    //! Wire-shape unit tests for [`Transaction`] — verifies the new
    //! batch operations (`del_chain` / `del_rule` / `add_flowtable` /
    //! `del_flowtable` / `add_table_with_flags`) emit the right
    //! netlink message bytes without needing a live netlink socket.
    //!
    //! The atomic `NftablesDiff::apply` path that Plan 157 ships
    //! routes every diff op through these methods, so verifying each
    //! method's wire shape catches the bulk of the refactor risk.

    use super::*;

    /// Construct a Transaction. The constructor is private; reach
    /// into it via `Transaction::new` (same-module access).
    fn new_tx() -> Transaction {
        Transaction::new()
    }

    /// Walk a single batch message and assert `(nlmsg_type, flags)`.
    /// Skips the per-message sequence-number check — that's
    /// asserted separately.
    fn assert_header(msg: &[u8], expected_type: u16, expected_flags: u16) {
        assert!(msg.len() >= 16, "msg too short for nlmsghdr: {}", msg.len());
        let ty = u16::from_ne_bytes([msg[4], msg[5]]);
        let flags = u16::from_ne_bytes([msg[6], msg[7]]);
        assert_eq!(ty, expected_type, "nlmsg_type mismatch");
        assert_eq!(flags, expected_flags, "nlmsg_flags mismatch");
    }

    /// Find an attribute by type in the post-nfgenmsg payload.
    fn find_attr(payload: &[u8], wanted_type: u16) -> Option<Vec<u8>> {
        let mut offset = 0;
        while offset + 4 <= payload.len() {
            let len = u16::from_ne_bytes([payload[offset], payload[offset + 1]]) as usize;
            let ty = u16::from_ne_bytes([payload[offset + 2], payload[offset + 3]]) & 0x7FFF;
            if len < 4 || offset + len > payload.len() {
                return None;
            }
            if ty == wanted_type {
                return Some(payload[offset + 4..offset + len].to_vec());
            }
            offset += (len + 3) & !3;
        }
        None
    }

    fn body_after_nfgenmsg(msg: &[u8]) -> &[u8] {
        // Skip nlmsghdr (16 bytes) + nfgenmsg (4 bytes).
        &msg[16 + 4..]
    }

    #[test]
    fn del_chain_emits_correct_wire_message() {
        let tx = new_tx().del_chain("filter", "input", Family::Inet);
        assert_eq!(tx.messages.len(), 1);

        let msg = &tx.messages[0];
        assert_header(msg, nft_msg_type(NFT_MSG_DELCHAIN), NLM_F_REQUEST);

        let body = body_after_nfgenmsg(msg);
        let table = find_attr(body, NFTA_CHAIN_TABLE).expect("NFTA_CHAIN_TABLE missing");
        let name = find_attr(body, NFTA_CHAIN_NAME).expect("NFTA_CHAIN_NAME missing");
        // Strings are NUL-terminated on the wire — strip before compare.
        assert_eq!(&table[..table.len().saturating_sub(1)], b"filter");
        assert_eq!(&name[..name.len().saturating_sub(1)], b"input");
    }

    #[test]
    fn add_chain_emits_nfta_hook_dev_for_netdev_chain() {
        // Plan 180 — netdev base chain must carry
        // NFTA_HOOK_DEV inside the NFTA_CHAIN_HOOK nest.
        let chain = Chain::new("ft", "ingress")
            .unwrap()
            .family(Family::Netdev)
            .hook(Hook::NetdevIngress)
            .priority(Priority::Filter)
            .chain_type(ChainType::Filter)
            .device("eth0");
        let tx = new_tx().add_chain(chain);
        assert_eq!(tx.messages.len(), 1);

        let body = body_after_nfgenmsg(&tx.messages[0]);
        // Pull the NFTA_CHAIN_HOOK nest and look inside it for
        // NFTA_HOOK_DEV.
        let hook_nest = find_attr(body, NFTA_CHAIN_HOOK).expect("NFTA_CHAIN_HOOK missing");
        let dev = find_attr(&hook_nest, NFTA_HOOK_DEV).expect("NFTA_HOOK_DEV missing");
        assert_eq!(&dev[..dev.len().saturating_sub(1)], b"eth0");
    }

    #[test]
    fn add_chain_emits_nfta_chain_type_for_nat_chain() {
        // Plan 180 — NAT chain must carry NFTA_CHAIN_TYPE="nat"
        // so the kernel accepts masquerade/snat/dnat verdicts.
        let chain = Chain::new("nat", "postrouting")
            .unwrap()
            .family(Family::Inet)
            .hook(Hook::Postrouting)
            .priority(Priority::SrcNat)
            .chain_type(ChainType::Nat);
        let tx = new_tx().add_chain(chain);
        let body = body_after_nfgenmsg(&tx.messages[0]);
        let ct = find_attr(body, NFTA_CHAIN_TYPE).expect("NFTA_CHAIN_TYPE missing");
        assert_eq!(&ct[..ct.len().saturating_sub(1)], b"nat");
    }

    // ---- Plan 181 wire-shape tests for list_*_in --------------------
    // Each test constructs the request bytes via the extracted
    // `build_list_*_request` helper and asserts the right
    // NFT_MSG_GET* type + NLM_F_REQUEST|DUMP flags + nfgen_family
    // byte + (where applicable) the NFTA_*_TABLE filter attribute.

    fn body_after_nlmsghdr(msg: &[u8]) -> &[u8] {
        // Skip nlmsghdr (16 bytes) only — leaves nfgenmsg in front
        // so the caller can verify the family byte.
        &msg[16..]
    }

    #[test]
    fn build_list_tables_request_carries_family_and_dump_flags() {
        let bytes =
            super::build_list_tables_request(super::super::types::Family::Inet as u8).finish();
        assert_header(
            &bytes,
            super::nft_msg_type(super::super::NFT_MSG_GETTABLE),
            NLM_F_REQUEST | NLM_F_DUMP,
        );
        let body = body_after_nlmsghdr(&bytes);
        assert!(body.len() >= NFGENMSG_HDRLEN, "missing nfgenmsg");
        assert_eq!(
            body[0],
            super::super::types::Family::Inet as u8,
            "nfgen_family must be Inet"
        );
        // No table-name attribute on the tables-list request.
        let post_nfgen = &body[NFGENMSG_HDRLEN..];
        assert!(post_nfgen.is_empty(), "tables list must not carry attrs");
    }

    #[test]
    fn build_list_chains_request_emits_nfta_chain_table_when_table_present() {
        let bytes = super::build_list_chains_request(
            super::super::types::Family::Inet as u8,
            Some("filter"),
        )
        .finish();
        assert_header(
            &bytes,
            super::nft_msg_type(super::super::NFT_MSG_GETCHAIN),
            NLM_F_REQUEST | NLM_F_DUMP,
        );
        let body = body_after_nlmsghdr(&bytes);
        assert_eq!(body[0], super::super::types::Family::Inet as u8);
        let post_nfgen = &body[NFGENMSG_HDRLEN..];
        let table = find_attr(post_nfgen, NFTA_CHAIN_TABLE)
            .expect("NFTA_CHAIN_TABLE must be present when table arg set");
        assert_eq!(&table[..table.len().saturating_sub(1)], b"filter");
    }

    #[test]
    fn build_list_flowtables_request_emits_nfta_flowtable_table() {
        let bytes = super::build_list_flowtables_request(
            super::super::types::Family::Inet as u8,
            Some("filter"),
        )
        .finish();
        assert_header(
            &bytes,
            super::nft_msg_type(super::super::NFT_MSG_GETFLOWTABLE),
            NLM_F_REQUEST | NLM_F_DUMP,
        );
        let body = body_after_nlmsghdr(&bytes);
        assert_eq!(body[0], super::super::types::Family::Inet as u8);
        let post_nfgen = &body[NFGENMSG_HDRLEN..];
        let table = find_attr(post_nfgen, NFTA_FLOWTABLE_TABLE)
            .expect("NFTA_FLOWTABLE_TABLE must be present");
        assert_eq!(&table[..table.len().saturating_sub(1)], b"filter");
    }

    #[test]
    fn build_list_sets_request_emits_nfta_set_table() {
        let bytes = super::build_list_sets_request(
            super::super::types::Family::Inet as u8,
            Some("filter"),
        )
        .finish();
        assert_header(
            &bytes,
            super::nft_msg_type(super::super::NFT_MSG_GETSET),
            NLM_F_REQUEST | NLM_F_DUMP,
        );
        let body = body_after_nlmsghdr(&bytes);
        assert_eq!(body[0], super::super::types::Family::Inet as u8);
        let post_nfgen = &body[NFGENMSG_HDRLEN..];
        let table = find_attr(post_nfgen, NFTA_SET_TABLE)
            .expect("NFTA_SET_TABLE must be present");
        assert_eq!(&table[..table.len().saturating_sub(1)], b"filter");
    }

    #[test]
    fn build_list_set_elements_request_carries_table_and_set() {
        let bytes = super::build_list_set_elements_request(
            super::super::types::Family::Inet as u8,
            "filter",
            "allowed_v4",
        )
        .finish();
        assert_header(
            &bytes,
            super::nft_msg_type(super::super::NFT_MSG_GETSETELEM),
            NLM_F_REQUEST | NLM_F_DUMP,
        );
        let body = body_after_nlmsghdr(&bytes);
        assert_eq!(body[0], super::super::types::Family::Inet as u8);
        let post_nfgen = &body[NFGENMSG_HDRLEN..];
        let table = find_attr(post_nfgen, NFTA_SET_ELEM_LIST_TABLE)
            .expect("NFTA_SET_ELEM_LIST_TABLE must be present");
        let set = find_attr(post_nfgen, NFTA_SET_ELEM_LIST_SET)
            .expect("NFTA_SET_ELEM_LIST_SET must be present");
        assert_eq!(&table[..table.len().saturating_sub(1)], b"filter");
        assert_eq!(&set[..set.len().saturating_sub(1)], b"allowed_v4");
    }

    #[test]
    fn nfta_set_attr_ids_match_kernel_enum() {
        // Regression for the ERANGE-on-NEWSET bug: `NFTA_SET_ID` was
        // 16 and `NFTA_SET_HANDLE` 17, but the kernel
        // `enum nft_set_attributes` puts ID at 10 and HANDLE at 16.
        // Sending the set id under attribute 16 made the kernel read
        // it as a (bogus) handle and reject every set create. Pin the
        // whole tail of the enum so the class can't recur.
        use super::super::*;
        assert_eq!(NFTA_SET_TABLE, 1);
        assert_eq!(NFTA_SET_NAME, 2);
        assert_eq!(NFTA_SET_FLAGS, 3);
        assert_eq!(NFTA_SET_KEY_TYPE, 4);
        assert_eq!(NFTA_SET_KEY_LEN, 5);
        assert_eq!(NFTA_SET_DATA_TYPE, 6);
        assert_eq!(NFTA_SET_DATA_LEN, 7);
        assert_eq!(NFTA_SET_POLICY, 8);
        assert_eq!(NFTA_SET_DESC, 9);
        assert_eq!(NFTA_SET_ID, 10);
        assert_eq!(NFTA_SET_HANDLE, 16);
    }

    #[test]
    fn tx_add_set_emits_key_type_len_flags_and_id() {
        let set = Set::new("filter", "allowed_v4")
            .family(Family::Inet)
            .key_type(SetKeyType::Ipv4Addr);
        let tx = new_tx().add_set(set);
        assert_eq!(tx.messages.len(), 1);
        let msg = &tx.messages[0];
        assert_header(
            msg,
            nft_msg_type(NFT_MSG_NEWSET),
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
        );
        let body = body_after_nfgenmsg(msg);
        let name = find_attr(body, NFTA_SET_NAME).expect("NFTA_SET_NAME missing");
        assert_eq!(&name[..name.len().saturating_sub(1)], b"allowed_v4");
        let kt = find_attr(body, NFTA_SET_KEY_TYPE).expect("NFTA_SET_KEY_TYPE missing");
        assert_eq!(u32::from_be_bytes(kt.try_into().unwrap()), 7); // ipv4_addr
        let kl = find_attr(body, NFTA_SET_KEY_LEN).expect("NFTA_SET_KEY_LEN missing");
        assert_eq!(u32::from_be_bytes(kl.try_into().unwrap()), 4);
        assert!(find_attr(body, NFTA_SET_ID).is_some(), "NFTA_SET_ID missing");
    }

    #[test]
    fn tx_add_set_without_size_emits_no_desc() {
        let tx = new_tx().add_set(Set::new("filter", "s"));
        let body = body_after_nfgenmsg(&tx.messages[0]);
        assert!(find_attr(body, NFTA_SET_DESC).is_none());
    }

    #[test]
    fn tx_add_set_size_nests_desc_size() {
        let tx = new_tx().add_set(Set::new("filter", "s").size(1024));
        let body = body_after_nfgenmsg(&tx.messages[0]);
        let desc = find_attr(body, NFTA_SET_DESC).expect("NFTA_SET_DESC missing");
        let size = find_attr(&desc, NFTA_SET_DESC_SIZE).expect("NFTA_SET_DESC_SIZE missing");
        assert_eq!(u32::from_be_bytes(size.try_into().unwrap()), 1024);
    }

    #[test]
    fn tx_update_set_is_a_newset_without_excl_or_create() {
        let tx = new_tx().update_set(Set::new("filter", "s").size(4096));
        // An update must not be EXCL (EEXIST on the existing set) and is
        // not CREATE either: a set that vanished is ENOENT, not recreated.
        assert_header(&tx.messages[0], nft_msg_type(NFT_MSG_NEWSET), NLM_F_REQUEST);
        let body = body_after_nfgenmsg(&tx.messages[0]);
        let desc = find_attr(body, NFTA_SET_DESC).expect("NFTA_SET_DESC missing");
        let size = find_attr(&desc, NFTA_SET_DESC_SIZE).expect("NFTA_SET_DESC_SIZE missing");
        assert_eq!(u32::from_be_bytes(size.try_into().unwrap()), 4096);
    }

    #[test]
    fn parse_set_reads_the_size_from_the_desc_nest() {
        // As `nf_tables_fill_set` dumps it: the DESC nest without
        // NLA_F_NESTED, holding SIZE only when the set has one.
        let dump = |size: Option<u32>| {
            let mut b = MessageBuilder::new(0, 0);
            b.append_attr_str(NFTA_SET_NAME, "s");
            let desc = b.nest_start(NFTA_SET_DESC);
            if let Some(size) = size {
                b.append_attr_u32_be(NFTA_SET_DESC_SIZE, size);
            }
            b.nest_end(desc);
            b.as_bytes()[16..].to_vec()
        };
        let sized = parse_set(&dump(Some(1024)), Family::Inet).unwrap();
        assert_eq!(sized.size, Some(1024));
        let unbounded = parse_set(&dump(None), Family::Inet).unwrap();
        assert_eq!(unbounded.size, None);
    }

    #[test]
    fn tx_element_that_does_not_fit_the_set_is_deferred_not_dropped() {
        // A port (2 bytes) into an IPv4 set (4-byte keys).
        let set = Set::new("t", "s").key_type(SetKeyType::Ipv4Addr);
        let tx = new_tx().add_set_elements(&set, &[SetElement::port(80)]);
        assert!(tx.messages.is_empty(), "nothing must be queued");
        let err = tx.error.expect("the mismatch must be recorded for commit");
        assert!(err.to_string().contains("element key is 2 bytes"), "{err}");

        // Only the first error is kept.
        let tx = new_tx()
            .add_set_elements(&set, &[SetElement::port(80)])
            .del_set_elements(&set, &[SetElement::mark(1), SetElement::port(1)]);
        assert!(tx.error.unwrap().to_string().contains("2 bytes"));
    }

    #[test]
    fn interval_elements_go_out_as_start_and_flagged_end_plus_one() {
        let set = Set::new("t", "s").interval();
        let tx = new_tx().add_set_elements(
            &set,
            &[
                SetElement::ipv4_prefix(std::net::Ipv4Addr::new(10, 0, 0, 0), 24).unwrap(),
                // A single address in an interval set is the range [a, a].
                SetElement::ipv4(std::net::Ipv4Addr::new(192, 0, 2, 7)),
            ],
        );
        assert!(tx.error.is_none(), "{:?}", tx.error);
        let mut wire = Vec::new();
        super::parse_set_elements(body_after_nfgenmsg(&tx.messages[0]), &mut wire);
        let got: Vec<(Vec<u8>, bool)> = wire
            .iter()
            .map(|e| (e.key().to_vec(), e.is_interval_end()))
            .collect();
        assert_eq!(
            got,
            [
                (vec![10, 0, 0, 0], false),
                (vec![10, 0, 1, 0], true),
                (vec![192, 0, 2, 7], false),
                (vec![192, 0, 2, 8], true),
            ]
        );
        // And they pair back into the ranges that were sent.
        let ranges: Vec<_> = super::super::interval::pair(&wire);
        assert_eq!(
            ranges,
            [
                (vec![10, 0, 0, 0], vec![10, 0, 0, 255]),
                (vec![192, 0, 2, 7], vec![192, 0, 2, 7]),
            ]
        );
    }

    #[test]
    fn element_shapes_the_set_cannot_take_are_refused() {
        let v4 = std::net::Ipv4Addr::new(10, 0, 0, 1);
        let refused = |set: &Set, elem: SetElement| {
            new_tx().add_set_elements(set, &[elem]).error.is_some()
        };
        // A map flagged by hand, without its data type, cannot be checked.
        assert!(refused(&Set::new("t", "m").flags(SetFlags::MAP), SetElement::ipv4(v4)));
        // A map element needs data, of the map's type and length.
        let marks = Set::new("t", "m").map(SetDataType::Value(SetKeyType::Mark));
        assert!(refused(&marks, SetElement::ipv4(v4)));
        assert!(refused(&marks, SetElement::ipv4(v4).value(SetElement::port(1))));
        assert!(refused(&marks, SetElement::ipv4(v4).verdict(Verdict::Accept)));
        assert!(!refused(&marks, SetElement::ipv4(v4).value(SetElement::mark(1))));
        // Data needs a map.
        assert!(refused(&Set::new("t", "s"), SetElement::ipv4(v4).verdict(Verdict::Drop)));
        // A range needs an interval set.
        assert!(refused(&Set::new("t", "s"), SetElement::ipv4_range(v4, v4)));
        // A range that runs backwards.
        let back = SetElement::ipv4_range(v4, std::net::Ipv4Addr::new(10, 0, 0, 0));
        assert!(refused(&Set::new("t", "s").interval(), back));
        // Host-order keys do not compare as numbers.
        let marks = Set::new("t", "s").key_type(SetKeyType::Mark).interval();
        assert!(refused(&marks, SetElement::mark(1)));
        // A prefix longer than the address.
        assert!(SetElement::ipv4_prefix(v4, 33).is_err());
    }

    #[test]
    fn set_flags_combine_like_the_kernel_bits() {
        let flags = SetFlags::INTERVAL | SetFlags::TIMEOUT;
        assert_eq!(flags.bits(), NFT_SET_INTERVAL | NFT_SET_TIMEOUT);
        assert!(flags.contains(SetFlags::TIMEOUT));
        assert!(!flags.contains(SetFlags::MAP));
        assert_eq!(SetFlags::default(), SetFlags::empty());
    }

    fn ip_port() -> SetKeyType {
        SetKeyType::Concat(vec![SetKeyType::Ipv4Addr, SetKeyType::InetService])
    }

    /// The field lengths, in bytes, out of a NEWSET's DESC_CONCAT nest.
    fn concat_field_lens(body: &[u8]) -> Option<Vec<u32>> {
        let desc = find_attr(body, NFTA_SET_DESC)?;
        let concat = find_attr(&desc, NFTA_SET_DESC_CONCAT)?;
        Some(
            crate::netlink::attr::AttrIter::new(&concat)
                .map(|(_, field)| {
                    let len = find_attr(field, NFTA_SET_FIELD_LEN).expect("NFTA_SET_FIELD_LEN");
                    u32::from_be_bytes(len.try_into().unwrap())
                })
                .collect(),
        )
    }

    #[test]
    fn an_interval_set_of_concatenated_keys_carries_concat_and_its_field_lengths() {
        let tx = new_tx().add_set(Set::new("t", "s").key_type(ip_port()).interval().size(64));
        let body = body_after_nfgenmsg(&tx.messages[0]);
        let flags = find_attr(body, NFTA_SET_FLAGS).expect("NFTA_SET_FLAGS");
        assert_eq!(
            u32::from_be_bytes(flags.try_into().unwrap()),
            NFT_SET_INTERVAL | NFT_SET_CONCAT
        );
        // Bytes, not bits, and unpadded: the kernel rounds each up to a
        // register itself and checks the sum against the 8-byte key.
        assert_eq!(concat_field_lens(body), Some(vec![4, 2]));
        let kl = find_attr(body, NFTA_SET_KEY_LEN).expect("NFTA_SET_KEY_LEN");
        assert_eq!(u32::from_be_bytes(kl.try_into().unwrap()), 8);
        // The size shares the nest.
        let desc = find_attr(body, NFTA_SET_DESC).unwrap();
        assert!(find_attr(&desc, NFTA_SET_DESC_SIZE).is_some());
    }

    #[test]
    fn a_hash_set_of_concatenated_keys_has_no_concat_flag() {
        // As nft: without the interval flag the kernel hashes the whole
        // key, and NFT_SET_CONCAT without a DESC_CONCAT is EINVAL.
        let tx = new_tx().add_set(Set::new("t", "s").key_type(ip_port()));
        let body = body_after_nfgenmsg(&tx.messages[0]);
        let flags = find_attr(body, NFTA_SET_FLAGS).expect("NFTA_SET_FLAGS");
        assert_eq!(u32::from_be_bytes(flags.try_into().unwrap()), 0);
        assert!(find_attr(body, NFTA_SET_DESC).is_none());
    }

    #[test]
    fn concatenated_ranges_go_out_as_one_element_with_its_inclusive_end() {
        let set = Set::new("t", "s").key_type(ip_port()).interval();
        let net = SetElement::ipv4_prefix(std::net::Ipv4Addr::new(10, 0, 0, 0), 24).unwrap();
        let one = SetElement::concat([
            SetElement::ipv4(std::net::Ipv4Addr::new(192, 0, 2, 7)),
            SetElement::port(53),
        ]);
        let tx = new_tx().add_set_elements(
            &set,
            &[SetElement::concat([net, SetElement::port_range(1000, 2000)]), one.clone()],
        );
        assert!(tx.error.is_none(), "{:?}", tx.error);
        let mut wire = Vec::new();
        super::parse_set_elements(body_after_nfgenmsg(&tx.messages[0]), &mut wire);
        assert_eq!(wire.len(), 2, "no end-plus-one elements: {wire:?}");
        assert!(wire.iter().all(|e| !e.is_interval_end()));
        assert_eq!(wire[0].key(), [10, 0, 0, 0, 0x03, 0xe8, 0, 0]);
        assert_eq!(wire[0].key_end(), Some(&[10, 0, 0, 255, 0x07, 0xd0, 0, 0][..]));
        // A single key has no KEY_END.
        assert_eq!(wire[1], one);
    }

    #[test]
    fn a_key_end_equal_to_the_key_reads_back_as_a_single_key() {
        // What nft writes for a single key in a concatenated interval set.
        let mut builder = MessageBuilder::new(0, 0);
        let list = builder.nest_start(NFTA_SET_ELEM_LIST_ELEMENTS);
        let elem = builder.nest_start(NFTA_LIST_ELEM);
        for attr in [NFTA_SET_ELEM_KEY, NFTA_SET_ELEM_KEY_END] {
            let nest = builder.nest_start(attr);
            builder.append_attr(NFTA_DATA_VALUE, &[1, 2, 3, 4, 0, 53, 0, 0]);
            builder.nest_end(nest);
        }
        builder.nest_end(elem);
        builder.nest_end(list);
        let mut out = Vec::new();
        super::parse_set_elements(&builder.as_bytes()[16..], &mut out);
        assert_eq!(out.len(), 1);
        assert!(!out[0].is_range());
    }

    #[test]
    fn a_concatenated_range_is_checked_field_by_field() {
        let set = Set::new("t", "s").key_type(ip_port()).interval();
        // As one 8-byte number the end is after the start; as fields the
        // port range runs backwards.
        let backwards = SetElement::concat([
            SetElement::ipv4_range(
                std::net::Ipv4Addr::new(10, 0, 0, 9),
                std::net::Ipv4Addr::new(10, 0, 0, 10),
            ),
            SetElement::port_range(100, 50),
        ]);
        let err = new_tx().add_set_elements(&set, &[backwards]).error.unwrap();
        assert!(err.to_string().contains("is not at or after its start"), "{err}");
        // Host-order fields do not compare as numbers in a range either.
        let mark_port = Set::new("t", "s")
            .key_type(SetKeyType::Concat(vec![SetKeyType::Mark, SetKeyType::InetService]))
            .interval();
        let elem = SetElement::concat([SetElement::mark(1), SetElement::port(1)]);
        assert!(new_tx().add_set_elements(&mark_port, &[elem]).error.is_some());
    }

    #[test]
    fn set_timeouts_go_out_in_milliseconds_and_read_back() {
        use std::time::Duration;
        let set = Set::new("t", "s")
            .dynamic()
            .timeout(Duration::from_secs(60))
            .gc_interval(Duration::from_millis(1500));
        let tx = new_tx().add_set(set);
        let body = body_after_nfgenmsg(&tx.messages[0]);
        let flags = find_attr(body, NFTA_SET_FLAGS).unwrap();
        assert_eq!(
            u32::from_be_bytes(flags.try_into().unwrap()),
            NFT_SET_EVAL | NFT_SET_TIMEOUT
        );
        let timeout = find_attr(body, NFTA_SET_TIMEOUT).expect("NFTA_SET_TIMEOUT");
        assert_eq!(u64::from_be_bytes(timeout.try_into().unwrap()), 60_000);
        let gc = find_attr(body, NFTA_SET_GC_INTERVAL).expect("NFTA_SET_GC_INTERVAL");
        assert_eq!(u32::from_be_bytes(gc.try_into().unwrap()), 1500);
        // The writer's attributes are what parse_set reads.
        let info = parse_set(body, Family::Inet).unwrap();
        assert_eq!(info.timeout, Some(Duration::from_secs(60)));
        assert_eq!(info.gc_interval, Some(Duration::from_millis(1500)));
    }

    #[test]
    fn element_timeouts_need_a_timeout_set_and_go_on_the_start_only() {
        use std::time::Duration;
        let v4 = std::net::Ipv4Addr::new(10, 0, 0, 1);
        let elem = SetElement::ipv4(v4).with_timeout(Duration::from_secs(5));
        let err = new_tx()
            .add_set_elements(&Set::new("t", "s"), std::slice::from_ref(&elem))
            .error
            .expect("a timeout on a set without timeouts");
        assert!(err.to_string().contains("needs a set with timeouts"), "{err}");

        // In an interval set the end element must not carry it (EINVAL).
        let set = Set::new("t", "s").interval().per_element_timeouts();
        let tx = new_tx().add_set_elements(&set, &[elem]);
        assert!(tx.error.is_none(), "{:?}", tx.error);
        let mut wire = Vec::new();
        super::parse_set_elements(body_after_nfgenmsg(&tx.messages[0]), &mut wire);
        assert_eq!(wire.len(), 2);
        assert_eq!(wire[0].timeout(), Some(Duration::from_secs(5)));
        assert!(wire[1].is_interval_end() && wire[1].timeout().is_none());
    }

    #[test]
    fn a_map_carries_its_data_type_and_a_value_map_its_length() {
        let tx = new_tx()
            .add_set(Set::new("t", "marks").map(SetDataType::Value(SetKeyType::Mark)))
            .add_set(Set::new("t", "vm").vmap());
        let marks = body_after_nfgenmsg(&tx.messages[0]);
        let be = |b: Vec<u8>| u32::from_be_bytes(b.try_into().unwrap());
        assert_eq!(be(find_attr(marks, NFTA_SET_FLAGS).unwrap()), NFT_SET_MAP);
        assert_eq!(be(find_attr(marks, NFTA_SET_DATA_TYPE).unwrap()), 19); // TYPE_MARK
        assert_eq!(be(find_attr(marks, NFTA_SET_DATA_LEN).unwrap()), 4);
        let info = parse_set(marks, Family::Inet).unwrap();
        assert_eq!((info.data_type, info.data_len), (Some(19), Some(4)));

        // A verdict map's type is NFT_DATA_VERDICT; the kernel sizes it.
        let vm = body_after_nfgenmsg(&tx.messages[1]);
        assert_eq!(be(find_attr(vm, NFTA_SET_DATA_TYPE).unwrap()), NFT_DATA_VERDICT);
        assert!(find_attr(vm, NFTA_SET_DATA_LEN).is_none());
    }

    #[test]
    fn map_elements_carry_their_data_and_read_it_back() {
        let v4 = |n| std::net::Ipv4Addr::new(10, 0, 0, n);
        let jump = Verdict::JumpTo(ChainName::new("c2").unwrap());
        let vm = Set::new("t", "vm").vmap();
        let elems = [
            SetElement::ipv4(v4(1)).verdict(Verdict::Accept),
            SetElement::ipv4(v4(2)).verdict(jump),
        ];
        let tx = new_tx().add_set_elements(&vm, &elems);
        let mut back = Vec::new();
        super::parse_set_elements(body_after_nfgenmsg(&tx.messages[0]), &mut back);
        assert_eq!(back, elems);

        let marks = Set::new("t", "m").map(SetDataType::Value(SetKeyType::Mark));
        let elems = [SetElement::ipv4(v4(1)).value(SetElement::mark(0x10))];
        let tx = new_tx().add_set_elements(&marks, &elems);
        let mut back = Vec::new();
        super::parse_set_elements(body_after_nfgenmsg(&tx.messages[0]), &mut back);
        assert_eq!(back, elems);

        // A delete names the key only.
        let tx = new_tx().del_set_elements(&marks, &[SetElement::ipv4(v4(1))]);
        assert!(tx.error.is_none(), "{:?}", tx.error);
        let mut back = Vec::new();
        super::parse_set_elements(body_after_nfgenmsg(&tx.messages[0]), &mut back);
        assert_eq!(back[0].data(), None);
    }

    #[test]
    fn an_interval_map_puts_the_data_on_the_start_and_reads_it_back_on_the_range() {
        let map = Set::new("t", "m")
            .key_type(SetKeyType::InetService)
            .interval()
            .vmap();
        let range = SetElement::port_range(1000, 2000).verdict(Verdict::Drop);
        let tx = new_tx().add_set_elements(&map, std::slice::from_ref(&range));
        let mut wire = Vec::new();
        super::parse_set_elements(body_after_nfgenmsg(&tx.messages[0]), &mut wire);
        assert_eq!(wire.len(), 2);
        assert_eq!(wire[0].data(), Some(&SetElementData::Verdict(Verdict::Drop)));
        assert!(wire[1].is_interval_end() && wire[1].data().is_none());
        let paired = super::super::interval::pair_elements(&wire);
        assert_eq!(paired.len(), 1);
        assert_eq!(paired[0].key_end(), range.key_end());
        assert_eq!(paired[0].data(), range.data());
    }

    #[test]
    fn tx_del_set_emits_table_and_name() {
        let tx = new_tx().del_set("filter", "allowed_v4", Family::Inet);
        let msg = &tx.messages[0];
        assert_header(msg, nft_msg_type(NFT_MSG_DELSET), NLM_F_REQUEST);
        let body = body_after_nfgenmsg(msg);
        let table = find_attr(body, NFTA_SET_TABLE).expect("NFTA_SET_TABLE missing");
        let name = find_attr(body, NFTA_SET_NAME).expect("NFTA_SET_NAME missing");
        assert_eq!(&table[..table.len().saturating_sub(1)], b"filter");
        assert_eq!(&name[..name.len().saturating_sub(1)], b"allowed_v4");
    }

    #[test]
    fn tx_add_set_elements_nests_key_value() {
        let elems = vec![
            SetElement::ipv4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            SetElement::ipv4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
        ];
        let set = Set::new("filter", "allowed_v4");
        let tx = new_tx().add_set_elements(&set, &elems);
        let msg = &tx.messages[0];
        assert_header(
            msg,
            nft_msg_type(NFT_MSG_NEWSETELEM),
            NLM_F_REQUEST | NLM_F_CREATE,
        );
        let body = body_after_nfgenmsg(msg);
        let set = find_attr(body, NFTA_SET_ELEM_LIST_SET).expect("NFTA_SET_ELEM_LIST_SET missing");
        assert_eq!(&set[..set.len().saturating_sub(1)], b"allowed_v4");
        // The whole ELEMENTS nest round-trips back through the parser.
        let mut parsed = Vec::new();
        super::parse_set_elements(body, &mut parsed);
        assert_eq!(parsed, elems, "tx-written elements must parse back identically");
    }

    #[test]
    fn parse_set_elements_skips_malformed_and_extracts_keys() {
        // Build a minimal ELEMENTS nest by hand via the shared writer,
        // then confirm the parser pulls exactly the key bytes.
        let mut builder = MessageBuilder::new(nft_msg_type(NFT_MSG_NEWSETELEM), NLM_F_REQUEST);
        let set = Set::new("t", "s").key_type(SetKeyType::InetService);
        super::append_set_elements(
            &mut builder,
            &set,
            &[SetElement::port(80), SetElement::port(443)],
            super::ElementWrite::Add,
        )
        .unwrap();
        let msg = builder.finish();
        let body = body_after_nfgenmsg(&msg);
        let mut out = Vec::new();
        super::parse_set_elements(body, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].key(), 80u16.to_be_bytes());
        assert_eq!(out[1].key(), 443u16.to_be_bytes());

        // Truncated / garbage payload must not panic and yields nothing.
        let mut none = Vec::new();
        super::parse_set_elements(&[0x01, 0x00, 0xff], &mut none);
        assert!(none.is_empty());
    }

    #[test]
    fn del_rule_emits_correct_wire_message_with_handle() {
        let tx = new_tx().del_rule("filter", "input", Family::Inet, 0xDEAD_BEEF);
        assert_eq!(tx.messages.len(), 1);

        let msg = &tx.messages[0];
        assert_header(msg, nft_msg_type(NFT_MSG_DELRULE), NLM_F_REQUEST);

        let body = body_after_nfgenmsg(msg);
        let handle = find_attr(body, NFTA_RULE_HANDLE).expect("NFTA_RULE_HANDLE missing");
        assert_eq!(handle.len(), 8, "handle must be u64 big-endian");
        assert_eq!(u64::from_be_bytes(handle.try_into().unwrap()), 0xDEAD_BEEF);
    }

    #[test]
    fn add_flowtable_emits_nested_hook_block() {
        let ft = super::super::types::Flowtable {
            family: Family::Inet,
            table: "filter".into(),
            name: "ft".into(),
            devs: vec!["eth0".into()],
            priority: -300,
            flags: NFT_FLOWTABLE_HW_OFFLOAD,
            use_count: 0,
            handle: 0,
        };
        let tx = new_tx().add_flowtable(&ft);
        assert_eq!(tx.messages.len(), 1);

        let msg = &tx.messages[0];
        assert_header(
            msg,
            nft_msg_type(NFT_MSG_NEWFLOWTABLE),
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
        );

        let body = body_after_nfgenmsg(msg);
        assert!(find_attr(body, NFTA_FLOWTABLE_TABLE).is_some());
        assert!(find_attr(body, NFTA_FLOWTABLE_NAME).is_some());
        // Hook block is a nested attribute (NLA_F_NESTED set on the
        // type byte) — verified by the flag bit in the on-wire type.
        let mut hook_found_with_nested_flag = false;
        let mut offset = 0;
        while offset + 4 <= body.len() {
            let len = u16::from_ne_bytes([body[offset], body[offset + 1]]) as usize;
            let raw_ty = u16::from_ne_bytes([body[offset + 2], body[offset + 3]]);
            if len < 4 || offset + len > body.len() {
                break;
            }
            if (raw_ty & 0x7FFF) == NFTA_FLOWTABLE_HOOK && (raw_ty & 0x8000) != 0 {
                hook_found_with_nested_flag = true;
            }
            offset += (len + 3) & !3;
        }
        assert!(hook_found_with_nested_flag, "hook block missing NLA_F_NESTED flag");
        // Flags attr present + correct value (HW_OFFLOAD = 1, big-endian).
        let flags = find_attr(body, NFTA_FLOWTABLE_FLAGS).expect("flags missing");
        assert_eq!(u32::from_be_bytes(flags.try_into().unwrap()), NFT_FLOWTABLE_HW_OFFLOAD);
    }

    #[test]
    fn del_flowtable_emits_table_plus_name() {
        let tx = new_tx().del_flowtable(Family::Inet, "filter", "ft");
        assert_eq!(tx.messages.len(), 1);

        let msg = &tx.messages[0];
        assert_header(msg, nft_msg_type(NFT_MSG_DELFLOWTABLE), NLM_F_REQUEST);

        let body = body_after_nfgenmsg(msg);
        assert!(find_attr(body, NFTA_FLOWTABLE_TABLE).is_some());
        assert!(find_attr(body, NFTA_FLOWTABLE_NAME).is_some());
    }

    #[test]
    fn add_table_with_flags_emits_flags_attr() {
        let tx = new_tx().add_table_with_flags(
            "filter",
            Family::Inet,
            NFT_TABLE_F_DORMANT,
        );
        assert_eq!(tx.messages.len(), 1);

        let msg = &tx.messages[0];
        assert_header(
            msg,
            nft_msg_type(NFT_MSG_NEWTABLE),
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
        );

        let body = body_after_nfgenmsg(msg);
        let flags = find_attr(body, NFTA_TABLE_FLAGS).expect("NFTA_TABLE_FLAGS missing");
        assert_eq!(
            u32::from_be_bytes(flags.try_into().unwrap()),
            NFT_TABLE_F_DORMANT
        );
    }

    #[test]
    fn add_table_with_flags_omits_flags_attr_when_zero() {
        // Sanity: zero flags → no NFTA_TABLE_FLAGS attribute (saves
        // bytes; matches the imperative add_table_with_flags shape).
        let tx = new_tx().add_table_with_flags("filter", Family::Inet, 0);
        let body = body_after_nfgenmsg(&tx.messages[0]);
        assert!(find_attr(body, NFTA_TABLE_FLAGS).is_none());
    }

    #[test]
    fn chained_batch_preserves_message_order_and_seq_numbers() {
        let tx = new_tx()
            .del_rule("filter", "input", Family::Inet, 1)
            .del_chain("filter", "input", Family::Inet)
            .del_table("filter", Family::Inet);
        assert_eq!(tx.messages.len(), 3);

        // Transaction no longer assigns sequence numbers at all — send_batch
        // stamps them from the socket's counter, so the batch occupies one
        // contiguous window and every response can be matched exactly (#199).
        // This used to assert vec![1, 2, 3], numbers from a counter unrelated
        // to the socket's, which is precisely what broke response matching.
        let seqs: Vec<u32> = tx
            .messages
            .iter()
            .map(|m| u32::from_ne_bytes([m[8], m[9], m[10], m[11]]))
            .collect();
        assert_eq!(seqs, vec![0, 0, 0], "send_batch is the only seq authority");

        // Order is preserved: DELRULE, DELCHAIN, DELTABLE.
        let types: Vec<u16> = tx
            .messages
            .iter()
            .map(|m| u16::from_ne_bytes([m[4], m[5]]))
            .collect();
        assert_eq!(
            types,
            vec![
                nft_msg_type(NFT_MSG_DELRULE),
                nft_msg_type(NFT_MSG_DELCHAIN),
                nft_msg_type(NFT_MSG_DELTABLE),
            ]
        );
    }

    /// `send_batch` renumbers every inner message from the socket counter, so
    /// the batch is a contiguous `[begin_seq ..= end_seq]` window (#199).
    ///
    /// This mirrors what `send_batch` does, without needing an open socket.
    #[test]
    fn batch_renumbering_yields_a_contiguous_window() {
        let mut tx = Transaction::new();
        tx = tx
            .del_rule("filter", "input", Family::Inet, 1)
            .del_chain("filter", "input", Family::Inet)
            .del_table("filter", Family::Inet);
        let mut messages = tx.messages;

        // A socket that has already served a few requests — the situation in
        // which the old code broke, since NftablesConfig::diff burns ~5-6 seqs
        // on its dumps before the batch even starts.
        let mut next = 6u32;
        let mut alloc = || {
            let s = next;
            next += 1;
            s
        };

        let begin_seq = alloc();
        let mut inner_seqs = Vec::new();
        for m in &mut messages {
            let seq = alloc();
            stamp_seq_pid(m, seq, 4242).unwrap();
            inner_seqs.push(seq);
        }
        let end_seq = alloc();

        // The whole batch is one contiguous run.
        assert_eq!(begin_seq, 6);
        assert_eq!(inner_seqs, vec![7, 8, 9]);
        assert_eq!(end_seq, 10);

        let window = begin_seq..=end_seq;
        for seq in &inner_seqs {
            assert!(
                window.contains(seq),
                "inner seq {seq} must fall inside the batch window — the old \
                 Transaction counter put them at 1,2,3, BELOW begin_seq, so \
                 the recv loop discarded their errors",
            );
        }

        // And the seq/pid really landed in the header.
        assert_eq!(u32::from_ne_bytes(messages[0][8..12].try_into().unwrap()), 7);
        assert_eq!(
            u32::from_ne_bytes(messages[0][12..16].try_into().unwrap()),
            4242,
            "pid must be stamped too; Transaction's builders never set one",
        );
    }

    #[test]
    fn stamp_seq_pid_rejects_a_runt_message() {
        let mut runt = vec![0u8; 8];
        assert!(stamp_seq_pid(&mut runt, 1, 1).is_err());
    }

    /// Without NLM_F_APPEND the kernel PREPENDS, so rules install in reverse
    /// declaration order. nftables is first-match-wins, so a declared
    /// [accept ssh, drop] becomes [drop, accept] and SSH is blocked (#195).
    #[test]
    fn newrule_sets_nlm_f_append() {
        let tx = Transaction::new().add_rule(
            Rule::new("filter", "input")
                .family(Family::Inet)
                .match_tcp_dport(22)
                .accept(),
        );

        // nlmsg_flags is at offset 6..8.
        let flags = u16::from_ne_bytes(tx.messages[0][6..8].try_into().unwrap());
        assert!(
            flags & NLM_F_APPEND != 0,
            "NFT_MSG_NEWRULE without NLM_F_APPEND installs rules in reverse order",
        );
    }
}

// =========================================================================
// Streaming dump support — Plan 149 closeout
// =========================================================================

use crate::netlink::dump_stream::DumpStream;
use crate::netlink::parse::{FromNetlink, PResult};

impl FromNetlink for RuleInfo {
    /// Default body: AF_UNSPEC nfgenmsg. The kernel returns rules
    /// across every family + table; for filtered dumps use the
    /// table+family-aware
    /// [`Connection::<Nftables>::stream_rules`].
    fn write_dump_header(buf: &mut Vec<u8>) {
        let nfgenmsg = NfGenMsg {
            nfgen_family: 0, // AF_UNSPEC
            version: 0,
            res_id: 0,
        };
        buf.extend_from_slice(nfgenmsg.as_bytes());
    }

    fn parse(input: &mut &[u8]) -> PResult<Self> {
        let consumed = *input;
        *input = &input[input.len()..];
        Self::from_bytes(consumed).map_err(|_| {
            winnow::error::ErrMode::Cut(winnow::error::ContextError::new())
        })
    }

    /// Parse a post-nlmsghdr rule frame: `nfgenmsg + attrs`.
    /// Extracts the family from the nfgenmsg, then delegates to
    /// the existing `parse_rule` so the eager `list_rules` path
    /// and this streaming path share one parser.
    fn from_bytes(payload: &[u8]) -> crate::Result<Self> {
        if payload.len() < NFGENMSG_HDRLEN {
            return Err(crate::Error::InvalidMessage(
                "nft rule body shorter than nfgenmsg".into(),
            ));
        }
        let family = Family::from_u8(payload[0]).unwrap_or(Family::Inet);
        let attrs = &payload[NFGENMSG_HDRLEN..];
        parse_rule(attrs, family).ok_or_else(|| {
            crate::Error::InvalidMessage("nft rule parse failed".into())
        })
    }
}

impl Connection<Nftables> {
    /// Stream rules in `table` for `family` — one [`RuleInfo`]
    /// per `next().await`, bounded-memory. Preferred over the
    /// eager [`list_rules`](Self::list_rules) on rule-heavy
    /// hosts (CDN edges, service meshes with thousands of
    /// per-tenant rules).
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::Connection;
    /// # use nlink::Nftables;
    /// use tokio_stream::StreamExt;
    /// use nlink::netlink::nftables::types::Family;
    /// let conn = Connection::<Nftables>::new()?;
    /// let mut stream = conn.stream_rules("filter", Family::Inet).await?;
    /// while let Some(rule) = stream.next().await {
    ///     let rule = rule?;
    ///     println!("{}/{} handle={}", rule.table, rule.chain, rule.handle);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn stream_rules(
        &self,
        table: &str,
        family: Family,
    ) -> Result<DumpStream<'_, Nftables, RuleInfo>> {
        // Build nfgenmsg + NFTA_RULE_TABLE filter attr.
        let mut body = Vec::with_capacity(4 + 4 + table.len() + 1);
        let nfgenmsg = NfGenMsg::new(family);
        body.extend_from_slice(nfgenmsg.as_bytes());

        // NFTA_RULE_TABLE attribute: 4-byte header (len + type) +
        // null-terminated string, padded to 4 bytes.
        let str_len = table.len() + 1;
        let attr_len = 4 + str_len;
        // `struct nlattr`'s nla_len/nla_type are kernel-native. These were
        // little-endian, which is the same bug #212 fixed in
        // `normalize_tlv` — the reader half was corrected then, the writer
        // half here was missed because the audit only banned
        // `from_le_bytes` (#278).
        body.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        body.extend_from_slice(&NFTA_RULE_TABLE.to_ne_bytes());
        body.extend_from_slice(table.as_bytes());
        body.push(0); // null terminator
        // Pad to 4 bytes
        let padding = (4 - (attr_len % 4)) % 4;
        body.resize(body.len() + padding, 0);

        self.dump_stream_with_body::<RuleInfo>(
            nft_msg_type(NFT_MSG_GETRULE),
            &body,
        )
        .await
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;

    #[test]
    fn rule_write_dump_header_emits_4byte_nfgenmsg() {
        let mut buf = Vec::new();
        <RuleInfo as FromNetlink>::write_dump_header(&mut buf);
        assert_eq!(buf.len(), NFGENMSG_HDRLEN);
        assert_eq!(buf[0], 0); // AF_UNSPEC
    }

    #[test]
    fn rule_from_bytes_rejects_truncated_payload() {
        // shorter than nfgenmsg
        let payload = vec![0u8; 2];
        assert!(<RuleInfo as FromNetlink>::from_bytes(&payload).is_err());
    }

    #[test]
    fn rule_from_bytes_parses_family_from_nfgenmsg() {
        // nfgenmsg with AF_INET (2) + NFTA_RULE_TABLE attr "filter"
        let mut body = Vec::new();
        body.push(2); // AF_INET
        body.push(0); // version
        body.extend_from_slice(&0u16.to_be_bytes()); // res_id
        let table = b"filter\0";
        let attr_len = 4 + table.len();
        body.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        body.extend_from_slice(&NFTA_RULE_TABLE.to_ne_bytes());
        body.extend_from_slice(table);
        // pad to 4
        let pad = (4 - body.len() % 4) % 4;
        body.resize(body.len() + pad, 0);
        // Add NFTA_RULE_CHAIN
        let chain = b"input\0";
        let attr_len2 = 4 + chain.len();
        body.extend_from_slice(&(attr_len2 as u16).to_ne_bytes());
        body.extend_from_slice(&NFTA_RULE_CHAIN.to_ne_bytes());
        body.extend_from_slice(chain);
        let pad = (4 - body.len() % 4) % 4;
        body.resize(body.len() + pad, 0);
        // Add NFTA_RULE_HANDLE = 7 (8-byte big-endian u64)
        body.extend_from_slice(&12u16.to_ne_bytes()); // len = 4 + 8
        body.extend_from_slice(&NFTA_RULE_HANDLE.to_ne_bytes());
        body.extend_from_slice(&7u64.to_be_bytes());

        let rule = <RuleInfo as FromNetlink>::from_bytes(&body).expect("parse");
        // nftables Family::Ip = 2 (IPv4-only table) — matches what
        // we passed in nfgenmsg. AF_INET (libc) also = 2 but
        // nftables doesn't use AF_* identifiers.
        assert_eq!(rule.family, Family::Ip);
        assert_eq!(rule.table, "filter");
        assert_eq!(rule.chain, "input");
        assert_eq!(rule.handle, 7);
    }
}

#[cfg(test)]
mod userdata_roundtrip_tests {
    //! Plan 157b v2 — wire-level round-trip test for
    //! `Rule::comment` → `NFTA_RULE_USERDATA` → `RuleInfo::comment`.
    //! Validates that a comment we emit on a `Transaction::add_rule`
    //! is recoverable by `parse_rule` from the on-wire bytes.

    use super::*;
    use crate::netlink::nftables::types::Rule;

    /// Strip the netlink header from a Transaction message and
    /// return the body. Same shape as what `parse_rule` consumes
    /// inside `nft_dump`.
    fn body_after_nfgenmsg(msg: &[u8]) -> &[u8] {
        // 16 bytes nlmsghdr + 4 bytes nfgenmsg = 20.
        &msg[20..]
    }

    #[test]
    fn key_and_comment_round_trip_through_transaction_add_rule() {
        let mut rule = Rule::new("filter", "input")
            .family(Family::Inet)
            .comment("allow ssh");
        rule.key = Some("ssh-accept".into());
        let tx = Transaction::new().add_rule(rule);
        // Transaction stores raw messages in self.messages.
        let messages = &tx.messages;
        assert_eq!(messages.len(), 1, "expected exactly one rule msg");

        // Parse the rule body back out (skip nlmsghdr + nfgenmsg).
        let body = body_after_nfgenmsg(&messages[0]);
        let parsed = super::parse_rule(body, Family::Inet)
            .expect("parse_rule should succeed on a well-formed body");
        assert_eq!(parsed.table, "filter");
        assert_eq!(parsed.chain, "input");
        assert_eq!(
            parsed.key.as_deref(),
            Some("ssh-accept"),
            "the key should round-trip from emit through parse",
        );
        assert_eq!(parsed.comment_text.as_deref(), Some("nlink:ssh-accept allow ssh"));
        assert!(
            parsed.userdata_raw.is_some(),
            "raw userdata should also be preserved",
        );
    }

    #[test]
    fn an_imperative_comment_is_written_verbatim_with_no_key() {
        let rule = Rule::new("filter", "input").comment("allow ssh");
        let tx = Transaction::new().add_rule(rule);
        let body = body_after_nfgenmsg(&tx.messages[0]);
        let parsed = super::parse_rule(body, Family::Inet).expect("parse");
        assert_eq!(parsed.key, None);
        assert_eq!(parsed.comment_text.as_deref(), Some("allow ssh"));
    }

    #[test]
    fn an_overlong_comment_fails_the_transaction_instead_of_vanishing() {
        let rule = Rule::new("filter", "input").comment(&"x".repeat(128));
        let tx = Transaction::new().add_rule(rule);
        assert!(tx.messages.is_empty());
        assert!(tx.error.is_some());
    }

    #[test]
    fn rule_without_comment_has_none_after_parse() {
        let rule = Rule::new("filter", "input").family(Family::Inet);
        let tx = Transaction::new().add_rule(rule);
        let body = body_after_nfgenmsg(&tx.messages[0]);
        let parsed = super::parse_rule(body, Family::Inet).expect("parse");
        assert!(parsed.key.is_none());
        assert!(parsed.userdata_raw.is_none());
    }

    #[test]
    fn replace_rule_carries_key_and_handle() {
        let mut rule = Rule::new("filter", "input").family(Family::Inet);
        rule.key = Some("ssh-accept".into());
        let tx = Transaction::new().replace_rule(rule, 42);
        let body = body_after_nfgenmsg(&tx.messages[0]);
        let parsed = super::parse_rule(body, Family::Inet).expect("parse");
        assert_eq!(parsed.handle, 42);
        assert_eq!(parsed.key.as_deref(), Some("ssh-accept"));
    }
}
