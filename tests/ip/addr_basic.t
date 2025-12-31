#!/bin/bash
# Test basic ip address operations

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/helpers.sh"

init_tests
require_root

echo "=== ip address basic tests ==="

# Test: Show loopback addresses
rip_ip addr show lo
test_ok "ip addr show lo"
test_output_contains "127.0.0.1" "loopback has 127.0.0.1"
test_output_contains "::1" "loopback has ::1"

# Test: Show all addresses
rip_ip addr show
test_ok "ip addr show"
test_output_contains "lo" "loopback in address list"

# Test: JSON output
rip_ip -j addr show lo
test_ok "ip -j addr show lo"
test_json_valid "JSON output is valid"

# Test: Add and delete address on dummy interface
DEV="$(rand_dev)"

rip_ip link add "$DEV" type dummy
test_ok "create dummy interface"

rip_ip link set "$DEV" up
test_ok "bring interface up"

# Add IPv4 address
rip_ip addr add 192.168.100.1/24 dev "$DEV"
test_ok "ip addr add 192.168.100.1/24 dev $DEV"

rip_ip addr show "$DEV"
test_ok "ip addr show $DEV"
test_output_contains "192.168.100.1" "address in output"
test_output_contains "/24" "prefix length in output"

# Add IPv6 address
rip_ip addr add 2001:db8::1/64 dev "$DEV"
test_ok "ip addr add 2001:db8::1/64 dev $DEV"

rip_ip addr show "$DEV"
test_output_contains "2001:db8::1" "IPv6 address in output"

# Delete address
rip_ip addr del 192.168.100.1/24 dev "$DEV"
test_ok "ip addr del 192.168.100.1/24 dev $DEV"

rip_ip addr show "$DEV"
test_output_not_contains "192.168.100.1" "address removed"

# Cleanup
rip_ip link del "$DEV"
test_ok "cleanup"

print_summary
