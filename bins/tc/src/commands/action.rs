//! tc action command implementation.
//!
//! Actions are operations attached to filters that control packet fate.
//! Common actions include:
//! - gact: Generic action (pass, drop, etc.)
//! - mirred: Mirror or redirect to another interface
//! - police: Rate limiting with token bucket

use clap::{Args, Subcommand};
use rip_lib::ifname::name_to_index;
use rip_lib::parse::get_rate;
use rip_netlink::attr::AttrIter;
use rip_netlink::connection::dump_request;
use rip_netlink::message::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_REQUEST, NLMSG_HDRLEN, NlMsgHdr, NlMsgType,
};
use rip_netlink::types::tc::action::{
    self, TC_ACT_PIPE, TC_ACT_STOLEN, TCA_ACT_KIND, TCA_ACT_OPTIONS,
    gact::{PGACT_DETERM, PGACT_NETRAND, TCA_GACT_PARMS, TCA_GACT_PROB, TcGact, TcGactP},
    mirred::{
        self, TCA_EGRESS_MIRROR, TCA_EGRESS_REDIR, TCA_INGRESS_MIRROR, TCA_INGRESS_REDIR,
        TCA_MIRRED_PARMS, TcMirred,
    },
    police::{TCA_POLICE_AVRATE, TCA_POLICE_RATE64, TCA_POLICE_RESULT, TCA_POLICE_TBF, TcPolice},
};
use rip_netlink::types::tc::{TCA_ACT_TAB, TcMsg};
use rip_netlink::{Connection, MessageBuilder, Result};
use rip_output::{OutputFormat, OutputOptions};
use std::io::{self, Write};

#[derive(Args)]
pub struct ActionCmd {
    #[command(subcommand)]
    action: Option<ActionAction>,
}

#[derive(Subcommand)]
enum ActionAction {
    /// Show actions.
    Show {
        /// Action type (gact, mirred, police).
        kind: String,
    },

    /// List actions (alias for show).
    #[command(visible_alias = "ls")]
    List {
        /// Action type.
        kind: String,
    },

    /// Add an action.
    Add {
        /// Action type (gact, mirred, police).
        kind: String,

        /// Action-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Delete an action.
    Del {
        /// Action type.
        kind: String,

        /// Action index.
        #[arg(long)]
        index: Option<u32>,
    },

    /// Get a specific action.
    Get {
        /// Action type.
        kind: String,

        /// Action index.
        index: u32,
    },
}

impl ActionCmd {
    pub async fn run(
        &self,
        conn: &Connection,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match &self.action {
            Some(ActionAction::Show { kind }) | Some(ActionAction::List { kind }) => {
                self.show_actions(conn, kind, format, opts).await
            }
            Some(ActionAction::Add { kind, params }) => self.add_action(conn, kind, params).await,
            Some(ActionAction::Del { kind, index }) => self.del_action(conn, kind, *index).await,
            Some(ActionAction::Get { kind, index }) => {
                self.get_action(conn, kind, *index, format, opts).await
            }
            None => {
                println!("Usage: tc action <show|add|del|get> <type> [options]");
                println!("Action types: gact, mirred, police");
                Ok(())
            }
        }
    }

    async fn show_actions(
        &self,
        conn: &Connection,
        kind: &str,
        format: OutputFormat,
        _opts: &OutputOptions,
    ) -> Result<()> {
        let mut builder = dump_request(NlMsgType::RTM_GETACTION);

        // Add tcmsg header (zeroed for action dump)
        let tcmsg = TcMsg::default();
        builder.append(&tcmsg);

        // Add TCA_ACT_TAB with action kind
        let tab_token = builder.nest_start(TCA_ACT_TAB);
        let act_token = builder.nest_start(1); // First action slot
        builder.append_attr(TCA_ACT_KIND, kind.as_bytes());
        builder.nest_end(act_token);
        builder.nest_end(tab_token);

        let responses = conn.dump(builder).await?;

        let stdout = io::stdout();
        let mut handle = stdout.lock();

        for response in responses {
            if response.len() < NLMSG_HDRLEN + std::mem::size_of::<TcMsg>() {
                continue;
            }

            let payload = &response[NLMSG_HDRLEN..];
            if payload.len() < std::mem::size_of::<TcMsg>() {
                continue;
            }

            let attrs_data = &payload[std::mem::size_of::<TcMsg>()..];
            print_action_response(&mut handle, attrs_data, format)?;
        }

        Ok(())
    }

    async fn add_action(&self, conn: &Connection, kind: &str, params: &[String]) -> Result<()> {
        let mut builder = MessageBuilder::new(
            NlMsgType::RTM_NEWACTION,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        );

        // Add tcmsg header
        let tcmsg = TcMsg::default();
        builder.append(&tcmsg);

        // Add TCA_ACT_TAB with action
        let tab_token = builder.nest_start(TCA_ACT_TAB);
        let act_token = builder.nest_start(1); // First action slot

        // Add action kind
        builder.append_attr(TCA_ACT_KIND, kind.as_bytes());

        // Add action-specific options
        let opts_token = builder.nest_start(TCA_ACT_OPTIONS);
        match kind {
            "gact" => add_gact_options(&mut builder, params)?,
            "mirred" => add_mirred_options(&mut builder, params)?,
            "police" => add_police_options(&mut builder, params)?,
            _ => {
                return Err(rip_netlink::Error::InvalidMessage(format!(
                    "unknown action type '{}', supported: gact, mirred, police",
                    kind
                )));
            }
        }
        builder.nest_end(opts_token);

        builder.nest_end(act_token);
        builder.nest_end(tab_token);

        conn.request(builder).await?;

        println!("Action added");
        Ok(())
    }

    async fn del_action(&self, conn: &Connection, kind: &str, index: Option<u32>) -> Result<()> {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELACTION, NLM_F_REQUEST | NLM_F_ACK);

        let tcmsg = TcMsg::default();
        builder.append(&tcmsg);

        let tab_token = builder.nest_start(TCA_ACT_TAB);
        let act_token = builder.nest_start(1);

        builder.append_attr(TCA_ACT_KIND, kind.as_bytes());

        if let Some(idx) = index {
            // Add options with index
            let opts_token = builder.nest_start(TCA_ACT_OPTIONS);
            match kind {
                "gact" => {
                    let mut gact = TcGact::default();
                    gact.index = idx;
                    builder.append_attr(TCA_GACT_PARMS, gact.as_bytes());
                }
                "mirred" => {
                    let mut mirred = TcMirred::default();
                    mirred.index = idx;
                    builder.append_attr(TCA_MIRRED_PARMS, mirred.as_bytes());
                }
                "police" => {
                    let mut police = TcPolice::default();
                    police.index = idx;
                    builder.append_attr(TCA_POLICE_TBF, police.as_bytes());
                }
                _ => {}
            }
            builder.nest_end(opts_token);
        }

        builder.nest_end(act_token);
        builder.nest_end(tab_token);

        conn.request(builder).await?;

        println!("Action deleted");
        Ok(())
    }

    async fn get_action(
        &self,
        conn: &Connection,
        kind: &str,
        index: u32,
        format: OutputFormat,
        _opts: &OutputOptions,
    ) -> Result<()> {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETACTION, NLM_F_REQUEST);

        let tcmsg = TcMsg::default();
        builder.append(&tcmsg);

        let tab_token = builder.nest_start(TCA_ACT_TAB);
        let act_token = builder.nest_start(1);

        builder.append_attr(TCA_ACT_KIND, kind.as_bytes());

        // Add options with index to get specific action
        let opts_token = builder.nest_start(TCA_ACT_OPTIONS);
        match kind {
            "gact" => {
                let mut gact = TcGact::default();
                gact.index = index;
                builder.append_attr(TCA_GACT_PARMS, gact.as_bytes());
            }
            "mirred" => {
                let mut mirred = TcMirred::default();
                mirred.index = index;
                builder.append_attr(TCA_MIRRED_PARMS, mirred.as_bytes());
            }
            "police" => {
                let mut police = TcPolice::default();
                police.index = index;
                builder.append_attr(TCA_POLICE_TBF, police.as_bytes());
            }
            _ => {}
        }
        builder.nest_end(opts_token);

        builder.nest_end(act_token);
        builder.nest_end(tab_token);

        let response = conn.request(builder).await?;

        let stdout = io::stdout();
        let mut handle = stdout.lock();

        if response.len() >= NLMSG_HDRLEN + std::mem::size_of::<TcMsg>() {
            let payload = &response[NLMSG_HDRLEN..];
            let attrs_data = &payload[std::mem::size_of::<TcMsg>()..];
            print_action_response(&mut handle, attrs_data, format)?;
        }

        Ok(())
    }
}

/// Add gact (generic action) options.
fn add_gact_options(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
    let mut action_result = action::TC_ACT_OK;
    let mut index = 0u32;
    let mut random_type: Option<u16> = None;
    let mut random_val: u16 = 0;
    let mut random_action = action::TC_ACT_OK;

    let mut i = 0;
    while i < params.len() {
        let param = params[i].to_lowercase();
        match param.as_str() {
            "pass" | "ok" => action_result = action::TC_ACT_OK,
            "drop" | "shot" => action_result = action::TC_ACT_SHOT,
            "reclassify" => action_result = action::TC_ACT_RECLASSIFY,
            "pipe" | "continue" => action_result = action::TC_ACT_PIPE,
            "stolen" => action_result = action::TC_ACT_STOLEN,
            "trap" => action_result = action::TC_ACT_TRAP,
            "index" => {
                i += 1;
                if i < params.len() {
                    index = params[i].parse().map_err(|_| {
                        rip_netlink::Error::InvalidMessage(format!("invalid index: {}", params[i]))
                    })?;
                }
            }
            "random" => {
                // random <netrand|determ> <action> <val>
                i += 1;
                if i < params.len() {
                    match params[i].to_lowercase().as_str() {
                        "netrand" => random_type = Some(PGACT_NETRAND),
                        "determ" => random_type = Some(PGACT_DETERM),
                        _ => {
                            return Err(rip_netlink::Error::InvalidMessage(format!(
                                "expected 'netrand' or 'determ', got: {}",
                                params[i]
                            )));
                        }
                    }
                    i += 1;
                    if i < params.len() {
                        random_action =
                            action::parse_action_result(&params[i]).unwrap_or(action::TC_ACT_OK);
                        i += 1;
                        if i < params.len() {
                            random_val = params[i].parse().map_err(|_| {
                                rip_netlink::Error::InvalidMessage(format!(
                                    "invalid probability value (0-10000): {}",
                                    params[i]
                                ))
                            })?;
                            if random_val > 10000 {
                                return Err(rip_netlink::Error::InvalidMessage(
                                    "probability must be 0-10000".to_string(),
                                ));
                            }
                        }
                    }
                }
            }
            _ => {
                // Try to parse as action control
                if let Some(act) = action::parse_action_result(&param) {
                    action_result = act;
                }
            }
        }
        i += 1;
    }

    let mut gact = TcGact::new(action_result);
    gact.index = index;
    builder.append_attr(TCA_GACT_PARMS, gact.as_bytes());

    // Add probability if specified
    if let Some(ptype) = random_type {
        let prob = TcGactP::new(ptype, random_val, random_action);
        builder.append_attr(TCA_GACT_PROB, prob.as_bytes());
    }

    Ok(())
}

/// Add mirred (mirror/redirect) options.
fn add_mirred_options(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
    let mut eaction = TCA_EGRESS_REDIR;
    let mut ifindex = 0u32;
    let mut action_result = TC_ACT_STOLEN; // Default for redirect
    let mut index = 0u32;

    let mut i = 0;
    let mut direction_set = false;
    let mut action_type_set = false;

    while i < params.len() {
        let param = params[i].to_lowercase();
        match param.as_str() {
            "egress" => {
                direction_set = true;
                if action_type_set {
                    // Update eaction based on current action type
                    eaction = if eaction == TCA_INGRESS_MIRROR || eaction == TCA_EGRESS_MIRROR {
                        TCA_EGRESS_MIRROR
                    } else {
                        TCA_EGRESS_REDIR
                    };
                }
            }
            "ingress" => {
                direction_set = true;
                if action_type_set {
                    eaction = if eaction == TCA_INGRESS_MIRROR || eaction == TCA_EGRESS_MIRROR {
                        TCA_INGRESS_MIRROR
                    } else {
                        TCA_INGRESS_REDIR
                    };
                } else {
                    eaction = TCA_INGRESS_REDIR;
                }
            }
            "mirror" => {
                action_type_set = true;
                eaction = if direction_set && eaction == TCA_INGRESS_REDIR {
                    TCA_INGRESS_MIRROR
                } else {
                    TCA_EGRESS_MIRROR
                };
                action_result = TC_ACT_PIPE; // Mirror uses pipe
            }
            "redirect" => {
                action_type_set = true;
                eaction = if direction_set
                    && (eaction == TCA_INGRESS_MIRROR || eaction == TCA_INGRESS_REDIR)
                {
                    TCA_INGRESS_REDIR
                } else {
                    TCA_EGRESS_REDIR
                };
                action_result = TC_ACT_STOLEN; // Redirect uses stolen
            }
            "dev" => {
                i += 1;
                if i < params.len() {
                    ifindex = name_to_index(&params[i]).map_err(|_| {
                        rip_netlink::Error::InvalidMessage(format!(
                            "device not found: {}",
                            params[i]
                        ))
                    })?;
                }
            }
            "index" => {
                i += 1;
                if i < params.len() {
                    index = params[i].parse().map_err(|_| {
                        rip_netlink::Error::InvalidMessage(format!("invalid index: {}", params[i]))
                    })?;
                }
            }
            // Allow action control override
            "pass" | "ok" => action_result = action::TC_ACT_OK,
            "pipe" | "continue" => action_result = TC_ACT_PIPE,
            "drop" | "shot" => action_result = action::TC_ACT_SHOT,
            _ => {
                // Try to parse as device name if no dev keyword
                if ifindex == 0 {
                    if let Ok(idx) = name_to_index(&params[i]) {
                        ifindex = idx;
                    }
                }
            }
        }
        i += 1;
    }

    if ifindex == 0 {
        return Err(rip_netlink::Error::InvalidMessage(
            "dev <device> is required for mirred action".to_string(),
        ));
    }

    let mut mirred = TcMirred::new(eaction, ifindex, action_result);
    mirred.index = index;
    builder.append_attr(TCA_MIRRED_PARMS, mirred.as_bytes());

    Ok(())
}

/// Add police (rate limiting) options.
fn add_police_options(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
    let mut police = TcPolice::default();
    let mut rate: u64 = 0;
    let mut burst: u64 = 0;
    let mut avrate: u32 = 0;
    let mut conform_action = action::TC_ACT_OK;
    let mut exceed_action = action::TC_ACT_RECLASSIFY;

    let mut i = 0;
    while i < params.len() {
        let param = params[i].to_lowercase();
        match param.as_str() {
            "rate" => {
                i += 1;
                if i < params.len() {
                    rate = get_rate(&params[i]).map_err(|_| {
                        rip_netlink::Error::InvalidMessage(format!("invalid rate: {}", params[i]))
                    })?;
                }
            }
            "burst" | "buffer" | "maxburst" => {
                i += 1;
                if i < params.len() {
                    burst = parse_size(&params[i])?;
                }
            }
            "mtu" | "minburst" => {
                i += 1;
                if i < params.len() {
                    police.mtu = parse_size(&params[i])? as u32;
                }
            }
            "avrate" => {
                i += 1;
                if i < params.len() {
                    avrate = get_rate(&params[i]).map_err(|_| {
                        rip_netlink::Error::InvalidMessage(format!("invalid avrate: {}", params[i]))
                    })? as u32;
                }
            }
            "conform-exceed" => {
                i += 1;
                if i < params.len() {
                    // Parse conform/exceed actions like "pass/drop"
                    let actions: Vec<&str> = params[i].split('/').collect();
                    if !actions.is_empty() {
                        exceed_action = action::parse_action_result(actions[0])
                            .unwrap_or(action::TC_ACT_RECLASSIFY);
                    }
                    if actions.len() > 1 {
                        conform_action =
                            action::parse_action_result(actions[1]).unwrap_or(action::TC_ACT_OK);
                    }
                }
            }
            "index" => {
                i += 1;
                if i < params.len() {
                    police.index = params[i].parse().map_err(|_| {
                        rip_netlink::Error::InvalidMessage(format!("invalid index: {}", params[i]))
                    })?;
                }
            }
            // Direct action keywords
            "drop" | "shot" => exceed_action = action::TC_ACT_SHOT,
            "pass" | "ok" => exceed_action = action::TC_ACT_OK,
            "reclassify" => exceed_action = action::TC_ACT_RECLASSIFY,
            "pipe" | "continue" => exceed_action = TC_ACT_PIPE,
            _ => {}
        }
        i += 1;
    }

    // Set rate in the police structure
    if rate > 0 {
        police.rate.rate = if rate >= (1u64 << 32) {
            u32::MAX
        } else {
            rate as u32
        };
        // Calculate burst time (simplified - real implementation needs tc_calc_xmittime)
        if burst > 0 {
            police.burst = ((burst * 8 * 1000000) / rate.max(1)) as u32;
        }
    }

    police.action = exceed_action;

    builder.append_attr(TCA_POLICE_TBF, police.as_bytes());

    // Add rate64 if rate exceeds 32-bit
    if rate >= (1u64 << 32) {
        builder.append_attr(TCA_POLICE_RATE64, &rate.to_ne_bytes());
    }

    // Add avrate if specified
    if avrate > 0 {
        builder.append_attr(TCA_POLICE_AVRATE, &avrate.to_ne_bytes());
    }

    // Add conform action if different from default
    if conform_action != action::TC_ACT_OK {
        builder.append_attr(TCA_POLICE_RESULT, &(conform_action as u32).to_ne_bytes());
    }

    Ok(())
}

/// Parse size string (e.g., "1kb", "1mb").
fn parse_size(s: &str) -> Result<u64> {
    let s_lower = s.to_lowercase();
    let (num_str, multiplier) = if s_lower.ends_with("kb") || s_lower.ends_with("k") {
        (s_lower.trim_end_matches(|c| c == 'k' || c == 'b'), 1024u64)
    } else if s_lower.ends_with("mb") || s_lower.ends_with("m") {
        (
            s_lower.trim_end_matches(|c| c == 'm' || c == 'b'),
            1024u64 * 1024,
        )
    } else if s_lower.ends_with("gb") || s_lower.ends_with("g") {
        (
            s_lower.trim_end_matches(|c| c == 'g' || c == 'b'),
            1024u64 * 1024 * 1024,
        )
    } else if s_lower.ends_with('b') {
        (s_lower.trim_end_matches('b'), 1u64)
    } else {
        (s_lower.as_str(), 1u64)
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| rip_netlink::Error::InvalidMessage(format!("invalid size: {}", s)))?;

    Ok(num * multiplier)
}

/// Print action response.
fn print_action_response(
    w: &mut impl Write,
    attrs_data: &[u8],
    format: OutputFormat,
) -> Result<()> {
    // Parse TCA_ACT_TAB
    for (attr_type, attr_data) in AttrIter::new(attrs_data) {
        if attr_type == TCA_ACT_TAB {
            // Iterate over actions in the tab
            for (act_idx, act_data) in AttrIter::new(attr_data) {
                if act_idx == 0 {
                    continue;
                }
                print_single_action(w, act_data, format)?;
            }
        }
    }

    Ok(())
}

/// Print a single action.
fn print_single_action(w: &mut impl Write, act_data: &[u8], format: OutputFormat) -> Result<()> {
    let mut kind: Option<&str> = None;
    let mut options_data: Option<&[u8]> = None;

    for (attr_type, attr_data) in AttrIter::new(act_data) {
        match attr_type {
            TCA_ACT_KIND => {
                if let Ok(k) = std::str::from_utf8(attr_data) {
                    kind = Some(k.trim_end_matches('\0'));
                }
            }
            TCA_ACT_OPTIONS => {
                options_data = Some(attr_data);
            }
            _ => {}
        }
    }

    let kind = kind.unwrap_or("unknown");

    match format {
        OutputFormat::Json => {
            write!(w, "{{\"kind\":\"{}\",", kind)?;
            if let Some(opts) = options_data {
                print_action_options_json(w, kind, opts)?;
            }
            writeln!(w, "}}")?;
        }
        OutputFormat::Text => {
            write!(w, "action {} ", kind)?;
            if let Some(opts) = options_data {
                print_action_options_text(w, kind, opts)?;
            }
            writeln!(w)?;
        }
    }

    Ok(())
}

/// Print action options in JSON format.
fn print_action_options_json(w: &mut impl Write, kind: &str, opts_data: &[u8]) -> Result<()> {
    match kind {
        "gact" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                if attr_type == TCA_GACT_PARMS && attr_data.len() >= std::mem::size_of::<TcGact>() {
                    let gact = unsafe { &*(attr_data.as_ptr() as *const TcGact) };
                    write!(
                        w,
                        "\"action\":\"{}\",\"index\":{},\"ref\":{},\"bind\":{}",
                        action::format_action_result(gact.action),
                        gact.index,
                        gact.refcnt,
                        gact.bindcnt
                    )?;
                }
            }
        }
        "mirred" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                if attr_type == TCA_MIRRED_PARMS
                    && attr_data.len() >= std::mem::size_of::<TcMirred>()
                {
                    let m = unsafe { &*(attr_data.as_ptr() as *const TcMirred) };
                    write!(
                        w,
                        "\"mirred_action\":\"{}\",\"ifindex\":{},\"action\":\"{}\",\"index\":{},\"ref\":{},\"bind\":{}",
                        mirred::format_mirred_action(m.eaction),
                        m.ifindex,
                        action::format_action_result(m.action),
                        m.index,
                        m.refcnt,
                        m.bindcnt
                    )?;
                }
            }
        }
        "police" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                if attr_type == TCA_POLICE_TBF && attr_data.len() >= std::mem::size_of::<TcPolice>()
                {
                    let p = unsafe { &*(attr_data.as_ptr() as *const TcPolice) };
                    write!(
                        w,
                        "\"rate\":{},\"burst\":{},\"mtu\":{},\"action\":\"{}\",\"index\":{},\"ref\":{},\"bind\":{}",
                        p.rate.rate,
                        p.burst,
                        p.mtu,
                        action::format_action_result(p.action),
                        p.index,
                        p.refcnt,
                        p.bindcnt
                    )?;
                }
            }
        }
        _ => {}
    }

    Ok(())
}

/// Print action options in text format.
fn print_action_options_text(w: &mut impl Write, kind: &str, opts_data: &[u8]) -> Result<()> {
    match kind {
        "gact" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                if attr_type == TCA_GACT_PARMS && attr_data.len() >= std::mem::size_of::<TcGact>() {
                    let gact = unsafe { &*(attr_data.as_ptr() as *const TcGact) };
                    write!(w, "{}", action::format_action_result(gact.action))?;
                    writeln!(w)?;
                    write!(
                        w,
                        "\tindex {} ref {} bind {}",
                        gact.index, gact.refcnt, gact.bindcnt
                    )?;
                }
            }
        }
        "mirred" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                if attr_type == TCA_MIRRED_PARMS
                    && attr_data.len() >= std::mem::size_of::<TcMirred>()
                {
                    let m = unsafe { &*(attr_data.as_ptr() as *const TcMirred) };
                    write!(
                        w,
                        "({} to device ifindex {}) {}",
                        mirred::format_mirred_action(m.eaction),
                        m.ifindex,
                        action::format_action_result(m.action)
                    )?;
                    writeln!(w)?;
                    write!(w, "\tindex {} ref {} bind {}", m.index, m.refcnt, m.bindcnt)?;
                }
            }
        }
        "police" => {
            for (attr_type, attr_data) in AttrIter::new(opts_data) {
                if attr_type == TCA_POLICE_TBF && attr_data.len() >= std::mem::size_of::<TcPolice>()
                {
                    let p = unsafe { &*(attr_data.as_ptr() as *const TcPolice) };
                    write!(
                        w,
                        "rate {} burst {} mtu {} action {}",
                        format_rate(p.rate.rate as u64),
                        p.burst,
                        p.mtu,
                        action::format_action_result(p.action)
                    )?;
                    writeln!(w)?;
                    write!(w, "\tindex {} ref {} bind {}", p.index, p.refcnt, p.bindcnt)?;
                }
            }
        }
        _ => {}
    }

    Ok(())
}

/// Format rate for display.
fn format_rate(rate: u64) -> String {
    if rate >= 1_000_000_000 {
        format!("{}Gbit", rate / 1_000_000_000)
    } else if rate >= 1_000_000 {
        format!("{}Mbit", rate / 1_000_000)
    } else if rate >= 1000 {
        format!("{}Kbit", rate / 1000)
    } else {
        format!("{}bit", rate)
    }
}
