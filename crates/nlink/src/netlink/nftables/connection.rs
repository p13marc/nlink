//! nftables connection implementation for `Connection<Nftables>`.

use super::expr::write_expressions;
use super::types::*;
use super::*;
use crate::netlink::attr::AttrIter;
use crate::netlink::builder::MessageBuilder;
use crate::netlink::connection::Connection;
use crate::netlink::error::{Error, Result};
use crate::netlink::message::{MessageIter, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST, NlMsgError};
use crate::netlink::protocol::Nftables;

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
    pub async fn add_table(&self, name: &str, family: Family) -> Result<()> {
        if name.is_empty() || name.len() > 256 {
            return Err(Error::InvalidMessage(
                "table name must be 1-256 characters".into(),
            ));
        }

        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_NEWTABLE), NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_TABLE_NAME, name);

        self.nft_request_ack(builder).await
    }

    /// List all nftables tables.
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

    /// Delete an nftables table.
    pub async fn del_table(&self, name: &str, family: Family) -> Result<()> {
        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_DELTABLE), NLM_F_REQUEST | NLM_F_ACK);
        let nfgenmsg = NfGenMsg::new(family);
        builder.append(&nfgenmsg);
        builder.append_attr_str(NFTA_TABLE_NAME, name);

        self.nft_request_ack(builder).await
    }

    /// Flush all rules from a table (keeps chains).
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
    pub async fn add_chain(&self, chain: Chain) -> Result<()> {
        // Validate: base chains require type
        if chain.hook.is_some() && chain.chain_type.is_none() {
            return Err(Error::InvalidMessage(
                "base chains with a hook require chain_type".into(),
            ));
        }

        let mut builder =
            MessageBuilder::new(nft_msg_type(NFT_MSG_NEWCHAIN), NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
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
    pub async fn list_rules(
        &self,
        table: &str,
        family: Family,
    ) -> Result<Vec<RuleInfo>> {
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
    // Internal helpers
    // =========================================================================

    /// Send a request and wait for ACK.
    async fn nft_request_ack(&self, mut builder: MessageBuilder) -> Result<()> {
        let seq = self.socket().next_seq();
        builder.set_seq(seq);
        builder.set_pid(self.socket().pid());

        let msg = builder.finish();
        self.socket().send(&msg).await?;

        // Wait for ACK
        loop {
            let data: Vec<u8> = self.socket().recv_msg().await?;

            for msg_result in MessageIter::new(&data) {
                let (header, payload) = msg_result?;

                if header.nlmsg_seq != seq {
                    continue;
                }

                if header.is_error() {
                    let err = NlMsgError::from_bytes(payload)?;
                    if err.is_ack() {
                        return Ok(());
                    }
                    return Err(Error::from_errno(err.error));
                }

                if header.is_done() {
                    return Ok(());
                }
            }
        }
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
                        return Err(Error::from_errno(err.error));
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

fn parse_table(data: &[u8], family: Family) -> Option<Table> {
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
            NFTA_TABLE_FLAGS => {
                if payload.len() >= 4 {
                    table.flags = u32::from_be_bytes(payload[..4].try_into().unwrap());
                }
            }
            NFTA_TABLE_USE => {
                if payload.len() >= 4 {
                    table.use_count = u32::from_be_bytes(payload[..4].try_into().unwrap());
                }
            }
            NFTA_TABLE_HANDLE => {
                if payload.len() >= 8 {
                    table.handle = u64::from_be_bytes(payload[..8].try_into().unwrap());
                }
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

fn parse_chain(data: &[u8], family: Family) -> Option<ChainInfo> {
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
            NFTA_CHAIN_HANDLE => {
                if payload.len() >= 8 {
                    chain.handle = u64::from_be_bytes(payload[..8].try_into().unwrap());
                }
            }
            NFTA_CHAIN_HOOK => {
                for (hook_attr, hook_payload) in AttrIter::new(payload) {
                    match hook_attr & 0x7FFF {
                        NFTA_HOOK_HOOKNUM => {
                            if hook_payload.len() >= 4 {
                                chain.hook = Some(u32::from_be_bytes(
                                    hook_payload[..4].try_into().unwrap(),
                                ));
                            }
                        }
                        NFTA_HOOK_PRIORITY => {
                            if hook_payload.len() >= 4 {
                                chain.priority = Some(i32::from_be_bytes(
                                    hook_payload[..4].try_into().unwrap(),
                                ));
                            }
                        }
                        _ => {}
                    }
                }
            }
            NFTA_CHAIN_POLICY => {
                if payload.len() >= 4 {
                    chain.policy = Some(u32::from_be_bytes(payload[..4].try_into().unwrap()));
                }
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

fn parse_rule(data: &[u8], family: Family) -> Option<RuleInfo> {
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
            NFTA_RULE_HANDLE => {
                if payload.len() >= 8 {
                    rule.handle = u64::from_be_bytes(payload[..8].try_into().unwrap());
                }
            }
            NFTA_RULE_POSITION => {
                if payload.len() >= 8 {
                    rule.position = Some(u64::from_be_bytes(payload[..8].try_into().unwrap()));
                }
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
