//! nftables connection implementation for `Connection<Nftables>`.

use super::{expr::write_expressions, types::*, *};
use crate::netlink::{
    attr::AttrIter,
    builder::MessageBuilder,
    connection::Connection,
    error::{Error, Result},
    message::{
        MessageIter, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST, NlMsgError,
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
    /// ```ignore
    /// conn.add_table("filter", Family::Inet).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_table"))]
    pub async fn add_table(&self, name: &str, family: Family) -> Result<()> {
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
    /// ```ignore
    /// use nlink::{Connection, Nftables};
    /// use nlink::netlink::nftables::{Family, NFT_TABLE_F_PERSIST};
    ///
    /// let conn = Connection::<Nftables>::new()?;
    /// // Create a table that survives `nft flush ruleset`.
    /// conn.add_table_with_flags("filter", Family::Inet, NFT_TABLE_F_PERSIST).await?;
    /// ```
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "add_table_with_flags", flags)
    )]
    pub async fn add_table_with_flags(
        &self,
        name: &str,
        family: Family,
        flags: u32,
    ) -> Result<()> {
        if name.is_empty() || name.len() > 256 {
            return Err(Error::InvalidMessage(
                "table name must be 1-256 characters".into(),
            ));
        }

        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_NEWTABLE),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
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

        self.nft_request_ack(builder).await
    }

    /// List all nftables tables.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_tables"))]
    pub async fn list_tables(&self) -> Result<Vec<Table>> {
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_GETTABLE), NLM_F_REQUEST | NLM_F_DUMP);
        let nfgenmsg = NfGenMsg {
            nfgen_family: 0, // AF_UNSPEC = all families
            version: 0,
            res_id: 0,
        };
        builder.append(&nfgenmsg);

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
    /// ```ignore
    /// use nlink::netlink::nftables::{Flowtable, Family};
    /// let ft = Flowtable::new(Family::Inet, "filter", "ft")
    ///     .device("eth0").device("eth1").hw_offload(true);
    /// conn.add_flowtable(&ft).await?;
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
        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_GETFLOWTABLE),
            NLM_F_REQUEST | NLM_F_DUMP,
        );
        // AF_UNSPEC = all families.
        let nfgenmsg = NfGenMsg {
            nfgen_family: 0,
            version: 0,
            res_id: 0,
        };
        builder.append(&nfgenmsg);

        let responses = self.nft_dump(builder).await?;
        let mut out = Vec::new();
        for (family_byte, payload) in &responses {
            let family = Family::from_u8(*family_byte).unwrap_or(Family::Inet);
            if let Some(ft) = parse_flowtable(payload, family) {
                out.push(ft);
            }
        }
        Ok(out)
    }

    /// Delete an nftables table.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_table"))]
    pub async fn del_table(&self, name: &str, family: Family) -> Result<()> {
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_DELTABLE), NLM_F_REQUEST | NLM_F_ACK);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_TABLE_NAME, name);

        self.nft_request_ack(builder).await
    }

    /// Flush all rules from a table (keeps chains).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_table"))]
    pub async fn flush_table(&self, name: &str, family: Family) -> Result<()> {
        // Flush is done by deleting all rules in the table
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_DELRULE), NLM_F_REQUEST | NLM_F_ACK);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_RULE_TABLE, name);

        self.nft_request_ack(builder).await
    }

    // =========================================================================
    // Chains
    // =========================================================================

    /// Create an nftables chain.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.add_chain(
    ///     Chain::new("filter", "input")
    ///         .family(Family::Inet)
    ///         .hook(Hook::Input)
    ///         .priority(Priority::Filter)
    ///         .policy(Policy::Accept)
    ///         .chain_type(ChainType::Filter)
    /// ).await?;
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
        builder.append_attr_str(NFTA_CHAIN_TABLE, &chain.table);
        builder.append_attr_str(NFTA_CHAIN_NAME, &chain.name);

        if let Some(chain_type) = chain.chain_type {
            builder.append_attr_str(NFTA_CHAIN_TYPE, chain_type.as_str());
        }

        if let Some(hook) = chain.hook {
            let hook_nest = builder.nest_start(NFTA_CHAIN_HOOK | 0x8000);
            builder.append_attr_u32_be(NFTA_HOOK_HOOKNUM, hook.to_u32());
            let priority = chain.priority.unwrap_or(Priority::Filter).to_i32();
            builder.append_attr_u32_be(NFTA_HOOK_PRIORITY, priority as u32);
            builder.nest_end(hook_nest);
        }

        if let Some(policy) = chain.policy {
            builder.append_attr_u32_be(NFTA_CHAIN_POLICY, policy.to_u32());
        }

        self.nft_request_ack(builder).await
    }

    /// List all chains.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_chains"))]
    pub async fn list_chains(&self) -> Result<Vec<ChainInfo>> {
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_GETCHAIN), NLM_F_REQUEST | NLM_F_DUMP);
        let nfgenmsg = NfGenMsg {
            nfgen_family: 0,
            version: 0,
            res_id: 0,
        };
        builder.append(&nfgenmsg);

        let responses = self.nft_dump(builder).await?;
        let mut chains = Vec::new();

        for (family_byte, payload) in &responses {
            let family = Family::from_u8(*family_byte).unwrap_or(Family::Inet);
            if let Some(chain) = parse_chain(payload, family) {
                chains.push(chain);
            }
        }

        Ok(chains)
    }

    /// Delete a chain.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_chain"))]
    pub async fn del_chain(&self, table: &str, name: &str, family: Family) -> Result<()> {
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_DELCHAIN), NLM_F_REQUEST | NLM_F_ACK);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_CHAIN_TABLE, table);
        builder.append_attr_str(NFTA_CHAIN_NAME, name);

        self.nft_request_ack(builder).await
    }

    // =========================================================================
    // Rules
    // =========================================================================

    /// Add a rule to a chain.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.add_rule(
    ///     Rule::new("filter", "input")
    ///         .family(Family::Inet)
    ///         .match_tcp_dport(22)
    ///         .accept()
    /// ).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_rule"))]
    pub async fn add_rule(&self, rule: Rule) -> Result<()> {
        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_NEWRULE),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
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

    // =========================================================================
    // Sets
    // =========================================================================

    /// Create an nftables set.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_set"))]
    pub async fn add_set(&self, set: Set) -> Result<()> {
        if set.name.is_empty() || set.name.len() > 256 {
            return Err(Error::InvalidMessage(
                "set name must be 1-256 characters".into(),
            ));
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
        builder.append_attr_u32_be(NFTA_SET_FLAGS, set.flags);
        // Set ID (arbitrary, used for referencing in same batch)
        builder.append_attr_u32_be(NFTA_SET_ID, 1);

        self.nft_request_ack(builder).await
    }

    /// List all sets.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_sets"))]
    pub async fn list_sets(&self, family: Family) -> Result<Vec<SetInfo>> {
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_GETSET), NLM_F_REQUEST | NLM_F_DUMP);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);

        let responses = self.nft_dump(builder).await?;
        let mut sets = Vec::new();

        for (family_byte, payload) in &responses {
            let family = Family::from_u8(*family_byte).unwrap_or(Family::Inet);
            if let Some(set) = parse_set(payload, family) {
                sets.push(set);
            }
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

    /// Add elements to a set.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_set_elements"))]
    pub async fn add_set_elements(
        &self,
        table: &str,
        set: &str,
        family: Family,
        elements: &[SetElement],
    ) -> Result<()> {
        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_NEWSETELEM),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        );
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_SET_ELEM_LIST_TABLE, table);
        builder.append_attr_str(NFTA_SET_ELEM_LIST_SET, set);

        let elems_nest = builder.nest_start(NFTA_SET_ELEM_LIST_ELEMENTS | 0x8000);
        for elem in elements {
            let elem_nest = builder.nest_start(NFTA_LIST_ELEM | 0x8000);
            let key_nest = builder.nest_start(NFTA_SET_ELEM_KEY | 0x8000);
            builder.append_attr(NFTA_DATA_VALUE, &elem.key);
            builder.nest_end(key_nest);
            builder.nest_end(elem_nest);
        }
        builder.nest_end(elems_nest);

        self.nft_request_ack(builder).await
    }

    /// Delete elements from a set.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_set_elements"))]
    pub async fn del_set_elements(
        &self,
        table: &str,
        set: &str,
        family: Family,
        elements: &[SetElement],
    ) -> Result<()> {
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_DELSETELEM), NLM_F_REQUEST | NLM_F_ACK);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_SET_ELEM_LIST_TABLE, table);
        builder.append_attr_str(NFTA_SET_ELEM_LIST_SET, set);

        let elems_nest = builder.nest_start(NFTA_SET_ELEM_LIST_ELEMENTS | 0x8000);
        for elem in elements {
            let elem_nest = builder.nest_start(NFTA_LIST_ELEM | 0x8000);
            let key_nest = builder.nest_start(NFTA_SET_ELEM_KEY | 0x8000);
            builder.append_attr(NFTA_DATA_VALUE, &elem.key);
            builder.nest_end(key_nest);
            builder.nest_end(elem_nest);
        }
        builder.nest_end(elems_nest);

        self.nft_request_ack(builder).await
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
    /// ```ignore
    /// conn.transaction()
    ///     .add_table("filter", Family::Inet)
    ///     .add_chain(chain)
    ///     .add_rule(rule)
    ///     .commit(&conn)
    ///     .await?;
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
            self.del_table(&table.name, table.family).await?;
        }
        Ok(())
    }

    /// Send a batch of messages atomically.
    async fn send_batch(&self, messages: Vec<Vec<u8>>) -> Result<()> {
        if messages.is_empty() {
            return Ok(());
        }

        let mut batch = Vec::new();

        // NFNL_MSG_BATCH_BEGIN
        let mut begin = MessageBuilder::new(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST);
        let nfgenmsg = NfGenMsg {
            nfgen_family: 0,
            version: 0,
            res_id: 10u16.to_be(), // NFNL_SUBSYS_NFTABLES
        };
        begin.append(&nfgenmsg);
        let seq = self.socket().next_seq();
        begin.set_seq(seq);
        begin.set_pid(self.socket().pid());
        batch.extend_from_slice(&begin.finish());

        // Add all messages with sequential sequence numbers
        for msg_data in &messages {
            batch.extend_from_slice(msg_data);
        }

        // NFNL_MSG_BATCH_END
        let mut end = MessageBuilder::new(NFNL_MSG_BATCH_END, NLM_F_REQUEST);
        let nfgenmsg = NfGenMsg {
            nfgen_family: 0,
            version: 0,
            res_id: 10u16.to_be(),
        };
        end.append(&nfgenmsg);
        end.set_seq(self.socket().next_seq());
        end.set_pid(self.socket().pid());
        batch.extend_from_slice(&end.finish());

        self.socket().send(&batch).await?;

        // Wait for ACK of the batch
        loop {
            let data: Vec<u8> = self.socket().recv_msg().await?;

            for msg_result in MessageIter::new(&data) {
                let (header, payload) = msg_result?;

                if header.is_error() {
                    let err = NlMsgError::from_bytes(payload)?;
                    if err.is_ack() {
                        return Ok(());
                    }
                    return Err(err.into_error(payload));
                }

                if header.is_done() {
                    return Ok(());
                }
            }
        }
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
    /// ```ignore
    /// use nlink::netlink::{Connection, Nftables};
    /// use nlink::netlink::nftables::{NftablesEvent, NftablesGroup};
    /// use tokio_stream::StreamExt;
    ///
    /// let mut nft = Connection::<Nftables>::new()?;
    /// nft.subscribe(&[NftablesGroup::All])?;
    /// let mut events = nft.events();
    /// while let Some(evt) = events.next().await {
    ///     match evt? {
    ///         NftablesEvent::NewTable(t) => println!("+ table {}", t.name),
    ///         NftablesEvent::DelTable(t) => println!("- table {}", t.name),
    ///         _ => {}
    ///     }
    /// }
    /// ```
    #[tracing::instrument(level = "info", skip(self), fields(groups = ?groups))]
    pub fn subscribe(&mut self, groups: &[super::events::NftablesGroup]) -> Result<()> {
        for g in groups {
            self.socket_mut().add_membership(g.to_kernel_group())?;
        }
        Ok(())
    }

    /// Subscribe to every nftables multicast group.
    ///
    /// Convenience for the typical "watch any ruleset mutation"
    /// pattern. Today equivalent to `subscribe(&[NftablesGroup::All])`;
    /// future kernel additions are picked up automatically.
    pub fn subscribe_all(&mut self) -> Result<()> {
        self.subscribe(&[super::events::NftablesGroup::All])
    }

    /// Send a dump request and collect responses.
    ///
    /// Returns (nfgen_family, payload_after_nfgenmsg) tuples.
    async fn nft_dump(&self, mut builder: MessageBuilder) -> Result<Vec<(u8, Vec<u8>)>> {
        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        let mut results = Vec::new();

        loop {
            let data: Vec<u8> = self.socket().recv_msg().await?;
            let mut done = false;

            for msg_result in MessageIter::new(&data) {
                let (header, payload) = msg_result?;

                if header.nlmsg_seq != seq {
                    continue;
                }

                if header.is_error() {
                    let err = NlMsgError::from_bytes(payload)?;
                    if !err.is_ack() {
                        return Err(err.into_error(payload));
                    }
                    continue;
                }

                if header.is_done() {
                    done = true;
                    break;
                }

                // Extract nfgenmsg family from the payload
                if payload.len() >= NFGENMSG_HDRLEN {
                    let family = payload[0];
                    results.push((family, payload[NFGENMSG_HDRLEN..].to_vec()));
                }
            }

            if done {
                break;
            }
        }

        Ok(results)
    }
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
                        _ => {}
                    }
                }
            }
            NFTA_CHAIN_POLICY if payload.len() >= 4 => {
                chain.policy = Some(u32::from_be_bytes(payload[..4].try_into().unwrap()));
            }
            NFTA_CHAIN_TYPE => {
                chain.chain_type = attr_str(payload);
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
            _ => {}
        }
    }

    if rule.table.is_empty() {
        None
    } else {
        Some(rule)
    }
}

fn parse_set(data: &[u8], family: Family) -> Option<SetInfo> {
    let mut set = SetInfo {
        table: String::new(),
        name: String::new(),
        family,
        flags: 0,
        key_type: 0,
        key_len: 0,
        handle: 0,
    };

    for (attr_type, payload) in AttrIter::new(data) {
        match attr_type & 0x7FFF {
            NFTA_SET_TABLE => {
                set.table = attr_str(payload).unwrap_or_default();
            }
            NFTA_SET_NAME => {
                set.name = attr_str(payload).unwrap_or_default();
            }
            NFTA_SET_FLAGS if payload.len() >= 4 => {
                set.flags = u32::from_be_bytes(payload[..4].try_into().unwrap());
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
    seq_counter: u32,
}

impl Transaction {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
            seq_counter: 1,
        }
    }

    fn next_seq(&mut self) -> u32 {
        let seq = self.seq_counter;
        self.seq_counter += 1;
        seq
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
        builder.set_seq(self.next_seq());
        self.messages.push(builder.finish());
        self
    }

    /// Add a chain creation to the batch.
    pub fn add_chain(mut self, chain: Chain) -> Self {
        let mut builder = MessageBuilder::new(
            nft_msg_type(NFT_MSG_NEWCHAIN),
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
        );
        let nfgenmsg = NfGenMsg::new(chain.family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_CHAIN_TABLE, &chain.table);
        builder.append_attr_str(NFTA_CHAIN_NAME, &chain.name);

        if let Some(chain_type) = chain.chain_type {
            builder.append_attr_str(NFTA_CHAIN_TYPE, chain_type.as_str());
        }

        if let Some(hook) = chain.hook {
            let hook_nest = builder.nest_start(NFTA_CHAIN_HOOK | 0x8000);
            builder.append_attr_u32_be(NFTA_HOOK_HOOKNUM, hook.to_u32());
            let priority = chain.priority.unwrap_or(Priority::Filter).to_i32();
            builder.append_attr_u32_be(NFTA_HOOK_PRIORITY, priority as u32);
            builder.nest_end(hook_nest);
        }

        if let Some(policy) = chain.policy {
            builder.append_attr_u32_be(NFTA_CHAIN_POLICY, policy.to_u32());
        }

        builder.set_seq(self.next_seq());
        self.messages.push(builder.finish());
        self
    }

    /// Add a rule to the batch.
    pub fn add_rule(mut self, rule: Rule) -> Self {
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_NEWRULE), NLM_F_REQUEST | NLM_F_CREATE);
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

        builder.set_seq(self.next_seq());
        self.messages.push(builder.finish());
        self
    }

    /// Add a table deletion to the batch.
    pub fn del_table(mut self, name: &str, family: Family) -> Self {
        let mut builder = MessageBuilder::new(nft_msg_type(NFT_MSG_DELTABLE), NLM_F_REQUEST);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_TABLE_NAME, name);
        builder.set_seq(self.next_seq());
        self.messages.push(builder.finish());
        self
    }

    /// Commit the transaction atomically.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "commit"))]
    pub async fn commit(self, conn: &Connection<Nftables>) -> Result<()> {
        conn.send_batch(self.messages).await
    }
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
