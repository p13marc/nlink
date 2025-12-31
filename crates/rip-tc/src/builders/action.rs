//! Action message builders.
//!
//! This module provides high-level builders for creating action netlink messages.
//! Actions are operations attached to filters that control packet fate.
//!
//! Common actions include:
//! - gact: Generic action (pass, drop, etc.)
//! - mirred: Mirror or redirect to another interface
//! - police: Rate limiting with token bucket

use rip_netlink::message::{NLM_F_ACK, NLM_F_CREATE, NLM_F_REQUEST, NlMsgType};
use rip_netlink::types::tc::TCA_ACT_TAB;
use rip_netlink::types::tc::TcMsg;
use rip_netlink::types::tc::action::{
    self, TC_ACT_PIPE, TC_ACT_STOLEN, TCA_ACT_KIND, TCA_ACT_OPTIONS,
    gact::{PGACT_DETERM, PGACT_NETRAND, TCA_GACT_PARMS, TCA_GACT_PROB, TcGact, TcGactP},
    mirred::{
        TCA_EGRESS_MIRROR, TCA_EGRESS_REDIR, TCA_INGRESS_MIRROR, TCA_INGRESS_REDIR,
        TCA_MIRRED_PARMS, TcMirred,
    },
    police::{TCA_POLICE_AVRATE, TCA_POLICE_RATE64, TCA_POLICE_RESULT, TCA_POLICE_TBF, TcPolice},
};
use rip_netlink::{Connection, MessageBuilder, Result};

/// Add a new action.
///
/// # Arguments
/// * `conn` - The netlink connection
/// * `kind` - Action type (gact, mirred, police)
/// * `params` - Type-specific parameters
pub async fn add(conn: &Connection, kind: &str, params: &[String]) -> Result<()> {
    let mut builder = MessageBuilder::new(
        NlMsgType::RTM_NEWACTION,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
    );

    let tcmsg = TcMsg::default();
    builder.append(&tcmsg);

    let tab_token = builder.nest_start(TCA_ACT_TAB);
    let act_token = builder.nest_start(1); // First action slot

    builder.append_attr(TCA_ACT_KIND, kind.as_bytes());

    let opts_token = builder.nest_start(TCA_ACT_OPTIONS);
    add_options(&mut builder, kind, params)?;
    builder.nest_end(opts_token);

    builder.nest_end(act_token);
    builder.nest_end(tab_token);

    conn.request(builder).await?;
    Ok(())
}

/// Delete an action.
///
/// # Arguments
/// * `conn` - The netlink connection
/// * `kind` - Action type
/// * `index` - Optional action index
pub async fn del(conn: &Connection, kind: &str, index: Option<u32>) -> Result<()> {
    let mut builder = MessageBuilder::new(NlMsgType::RTM_DELACTION, NLM_F_REQUEST | NLM_F_ACK);

    let tcmsg = TcMsg::default();
    builder.append(&tcmsg);

    let tab_token = builder.nest_start(TCA_ACT_TAB);
    let act_token = builder.nest_start(1);

    builder.append_attr(TCA_ACT_KIND, kind.as_bytes());

    if let Some(idx) = index {
        let opts_token = builder.nest_start(TCA_ACT_OPTIONS);
        add_index_option(&mut builder, kind, idx);
        builder.nest_end(opts_token);
    }

    builder.nest_end(act_token);
    builder.nest_end(tab_token);

    conn.request(builder).await?;
    Ok(())
}

/// Get a specific action.
///
/// # Arguments
/// * `conn` - The netlink connection
/// * `kind` - Action type
/// * `index` - Action index
pub async fn get(conn: &Connection, kind: &str, index: u32) -> Result<Vec<u8>> {
    let mut builder = MessageBuilder::new(NlMsgType::RTM_GETACTION, NLM_F_REQUEST);

    let tcmsg = TcMsg::default();
    builder.append(&tcmsg);

    let tab_token = builder.nest_start(TCA_ACT_TAB);
    let act_token = builder.nest_start(1);

    builder.append_attr(TCA_ACT_KIND, kind.as_bytes());

    let opts_token = builder.nest_start(TCA_ACT_OPTIONS);
    add_index_option(&mut builder, kind, index);
    builder.nest_end(opts_token);

    builder.nest_end(act_token);
    builder.nest_end(tab_token);

    conn.request(builder).await
}

/// Add action-specific options to the message.
pub fn add_options(builder: &mut MessageBuilder, kind: &str, params: &[String]) -> Result<()> {
    match kind {
        "gact" => add_gact_options(builder, params)?,
        "mirred" => add_mirred_options(builder, params)?,
        "police" => add_police_options(builder, params)?,
        _ => {
            return Err(rip_netlink::Error::InvalidMessage(format!(
                "unknown action type '{}', supported: gact, mirred, police",
                kind
            )));
        }
    }
    Ok(())
}

/// Add index option for action lookup/delete.
fn add_index_option(builder: &mut MessageBuilder, kind: &str, index: u32) {
    match kind {
        "gact" => {
            let gact = TcGact {
                index,
                ..Default::default()
            };
            builder.append_attr(TCA_GACT_PARMS, gact.as_bytes());
        }
        "mirred" => {
            let mirred = TcMirred {
                index,
                ..Default::default()
            };
            builder.append_attr(TCA_MIRRED_PARMS, mirred.as_bytes());
        }
        "police" => {
            let police = TcPolice {
                index,
                ..Default::default()
            };
            builder.append_attr(TCA_POLICE_TBF, police.as_bytes());
        }
        _ => {}
    }
}

// ============================================================================
// Gact (Generic Action) Options
// ============================================================================

/// Add gact options.
///
/// Supported parameters:
/// - pass/ok: Allow packet
/// - drop/shot: Drop packet
/// - reclassify: Reclassify packet
/// - pipe/continue: Continue to next action
/// - stolen: Packet consumed by action
/// - trap: Send to userspace
/// - index N: Specify action index
/// - random netrand|determ ACTION VAL: Probabilistic action
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

    if let Some(ptype) = random_type {
        let prob = TcGactP::new(ptype, random_val, random_action);
        builder.append_attr(TCA_GACT_PROB, prob.as_bytes());
    }

    Ok(())
}

// ============================================================================
// Mirred (Mirror/Redirect) Options
// ============================================================================

/// Add mirred options.
///
/// Supported parameters:
/// - egress/ingress: Direction
/// - mirror/redirect: Action type
/// - dev DEVICE: Target device
/// - index N: Specify action index
fn add_mirred_options(builder: &mut MessageBuilder, params: &[String]) -> Result<()> {
    let mut eaction = TCA_EGRESS_REDIR;
    let mut ifindex = 0u32;
    let mut action_result = TC_ACT_STOLEN;
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
                action_result = TC_ACT_PIPE;
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
                action_result = TC_ACT_STOLEN;
            }
            "dev" => {
                i += 1;
                if i < params.len() {
                    ifindex = rip_lib::get_ifindex(&params[i])
                        .map(|idx| idx as u32)
                        .map_err(rip_netlink::Error::InvalidMessage)?;
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
            "pass" | "ok" => action_result = action::TC_ACT_OK,
            "pipe" | "continue" => action_result = TC_ACT_PIPE,
            "drop" | "shot" => action_result = action::TC_ACT_SHOT,
            _ => {
                // Try to parse as device name if no dev keyword
                if ifindex == 0
                    && let Ok(idx) = rip_lib::get_ifindex(&params[i])
                {
                    ifindex = idx as u32;
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

// ============================================================================
// Police (Rate Limiting) Options
// ============================================================================

/// Add police options.
///
/// Supported parameters:
/// - rate RATE: Rate limit (e.g., "1mbit")
/// - burst SIZE: Burst size (e.g., "10kb")
/// - mtu SIZE: MTU for burst calculation
/// - avrate RATE: Average rate
/// - conform-exceed ACTION/ACTION: Actions for conform/exceed
/// - index N: Specify action index
/// - drop/pass/reclassify/pipe: Exceed action
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
                    rate = rip_lib::parse::get_rate(&params[i]).map_err(|_| {
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
                    avrate = rip_lib::parse::get_rate(&params[i]).map_err(|_| {
                        rip_netlink::Error::InvalidMessage(format!("invalid avrate: {}", params[i]))
                    })? as u32;
                }
            }
            "conform-exceed" => {
                i += 1;
                if i < params.len() {
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
            "drop" | "shot" => exceed_action = action::TC_ACT_SHOT,
            "pass" | "ok" => exceed_action = action::TC_ACT_OK,
            "reclassify" => exceed_action = action::TC_ACT_RECLASSIFY,
            "pipe" | "continue" => exceed_action = TC_ACT_PIPE,
            _ => {}
        }
        i += 1;
    }

    if rate > 0 {
        police.rate.rate = if rate >= (1u64 << 32) {
            u32::MAX
        } else {
            rate as u32
        };
        if burst > 0 {
            police.burst = ((burst * 8 * 1000000) / rate.max(1)) as u32;
        }
    }

    police.action = exceed_action;

    builder.append_attr(TCA_POLICE_TBF, police.as_bytes());

    if rate >= (1u64 << 32) {
        builder.append_attr(TCA_POLICE_RATE64, &rate.to_ne_bytes());
    }

    if avrate > 0 {
        builder.append_attr(TCA_POLICE_AVRATE, &avrate.to_ne_bytes());
    }

    if conform_action != action::TC_ACT_OK {
        builder.append_attr(TCA_POLICE_RESULT, &(conform_action as u32).to_ne_bytes());
    }

    Ok(())
}

/// Parse size string (e.g., "1kb", "1mb").
fn parse_size(s: &str) -> Result<u64> {
    let s_lower = s.to_lowercase();
    let (num_str, multiplier) = if s_lower.ends_with("kb") || s_lower.ends_with("k") {
        (s_lower.trim_end_matches(['k', 'b']), 1024u64)
    } else if s_lower.ends_with("mb") || s_lower.ends_with("m") {
        (s_lower.trim_end_matches(['m', 'b']), 1024u64 * 1024)
    } else if s_lower.ends_with("gb") || s_lower.ends_with("g") {
        (s_lower.trim_end_matches(['g', 'b']), 1024u64 * 1024 * 1024)
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
