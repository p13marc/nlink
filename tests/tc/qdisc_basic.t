#!/bin/bash
# Test basic tc qdisc operations

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/helpers.sh"

init_tests
require_root

echo "=== tc qdisc basic tests ==="

# Test: Show qdiscs on loopback
rip_tc qdisc show dev lo
test_ok "tc qdisc show dev lo"

# Test: Show all qdiscs
rip_tc qdisc show
test_ok "tc qdisc show"

# Test: JSON output
rip_tc -j qdisc show
test_ok "tc -j qdisc show"
test_json_valid "JSON output is valid"

# Create dummy interface for testing
DEV="$(rand_dev)"

rip_ip link add "$DEV" type dummy
test_ok "create dummy interface"

rip_ip link set "$DEV" up
test_ok "bring interface up"

# Test: Add fq_codel qdisc
rip_tc qdisc add dev "$DEV" root fq_codel
test_ok "tc qdisc add dev $DEV root fq_codel"

rip_tc qdisc show dev "$DEV"
test_ok "tc qdisc show dev $DEV"
test_output_contains "fq_codel" "fq_codel qdisc in output"

# Test: Delete qdisc
rip_tc qdisc del dev "$DEV" root
test_ok "tc qdisc del dev $DEV root"

# Test: Add prio qdisc
rip_tc qdisc add dev "$DEV" root prio
test_ok "tc qdisc add dev $DEV root prio"

rip_tc qdisc show dev "$DEV"
test_output_contains "prio" "prio qdisc in output"

rip_tc qdisc del dev "$DEV" root
test_ok "delete prio qdisc"

# Cleanup
rip_ip link del "$DEV"
test_ok "cleanup"

print_summary
