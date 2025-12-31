#!/bin/bash
# Test netem qdisc operations

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/helpers.sh"

init_tests
require_root

echo "=== tc netem tests ==="

# Create dummy interface for testing
DEV="$(rand_dev)"

rip_ip link add "$DEV" type dummy
test_ok "create dummy interface"

rip_ip link set "$DEV" up
test_ok "bring interface up"

# Test: Add netem with delay
rip_tc qdisc add dev "$DEV" root netem delay 100ms
test_ok "tc qdisc add netem delay 100ms"

rip_tc qdisc show dev "$DEV"
test_ok "tc qdisc show"
test_output_contains "netem" "netem qdisc in output"
test_output_contains "delay" "delay in output"

# Test: Replace netem with different config
rip_tc qdisc replace dev "$DEV" root netem delay 50ms loss 1%
test_ok "tc qdisc replace netem delay 50ms loss 1%"

rip_tc qdisc show dev "$DEV"
test_output_contains "netem" "netem still in output after replace"

# Test: Delete netem
rip_tc qdisc del dev "$DEV" root
test_ok "tc qdisc del"

rip_tc qdisc show dev "$DEV"
test_output_not_contains "netem" "netem removed"

# Test: Add netem with jitter
rip_tc qdisc add dev "$DEV" root netem delay 100ms 20ms
test_ok "tc qdisc add netem delay 100ms 20ms (with jitter)"

rip_tc qdisc show dev "$DEV"
test_output_contains "netem" "netem with jitter in output"

rip_tc qdisc del dev "$DEV" root
test_ok "cleanup qdisc"

# Test: Add netem with loss
rip_tc qdisc add dev "$DEV" root netem loss 5%
test_ok "tc qdisc add netem loss 5%"

rip_tc qdisc show dev "$DEV"
test_output_contains "netem" "netem with loss in output"

rip_tc qdisc del dev "$DEV" root
test_ok "cleanup qdisc"

# Cleanup
rip_ip link del "$DEV"
test_ok "cleanup interface"

print_summary
