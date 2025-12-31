#!/bin/bash
# Test basic ip link operations

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/helpers.sh"

init_tests
require_root

echo "=== ip link basic tests ==="

# Test: Show loopback interface
rip_ip link show lo
test_ok "ip link show lo"
test_output_contains "lo" "output contains 'lo'"
test_output_contains "LOOPBACK" "output contains 'LOOPBACK'"

# Test: Show all links
rip_ip link show
test_ok "ip link show"
test_output_contains "lo" "loopback in link list"

# Test: Show with JSON output
rip_ip -j link show lo
test_ok "ip -j link show lo"
test_json_valid "JSON output is valid"

# Test: Create and delete dummy interface
DEV="$(rand_dev)"

rip_ip link add "$DEV" type dummy
test_ok "ip link add $DEV type dummy"

rip_ip link show "$DEV"
test_ok "ip link show $DEV"
test_output_contains "$DEV" "device name in output"

rip_ip link set "$DEV" up
test_ok "ip link set $DEV up"

rip_ip link show "$DEV"
test_output_contains "UP" "interface is UP"

rip_ip link set "$DEV" down
test_ok "ip link set $DEV down"

rip_ip link set "$DEV" mtu 9000
test_ok "ip link set $DEV mtu 9000"

rip_ip link show "$DEV"
test_output_contains "mtu 9000" "MTU is 9000"

rip_ip link del "$DEV"
test_ok "ip link del $DEV"

rip_ip link show "$DEV" 2>/dev/null
test_fail "deleted interface should not exist"

print_summary
