---
name: nlink-lab feedback response
description: Consolidated improvement plans for nlink based on nlink-lab feedback report (2026-03-28). Tracks what's already done, what's misconceived, and what remains.
type: project
---

nlink-lab submitted a feedback report (NLINK_FEEDBACK_REPORT.md) on 2026-03-28.

Key corrections to send back:
- batch() already supports Route operations (add_route, add_link, add_address) - report section 2.3 is wrong
- replace_qdisc already exists with NLM_F_CREATE | NLM_F_REPLACE - report section 1.4 partially addressed
- match_saddr_v4, match_daddr_v4, match_iif, match_oif, log, limit, snat, dnat, masquerade all exist in nftables Rule builder - report section 4.4 is mostly wrong
- namespace::connection_for is already generic over P: ProtocolState + Default - report section 1.3 issue is specifically about async GENL family resolution

**Why:** nlink-lab is the heaviest known consumer (~125 API calls, ~2500 lines). Their feedback drives priorities.
**How to apply:** Reference this when planning nlink releases. Send corrections to nlink-lab team.
