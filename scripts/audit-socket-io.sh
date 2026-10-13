#!/bin/bash
# Every netlink datagram goes through NetlinkSocket (#168).
#
# `nlink::replay` records and replays a connection by hooking
# NetlinkSocket's send and receive methods in crates/nlink/src/netlink/
# socket.rs. A send or receive syscall anywhere else in the library would
# bypass the hook: a recording would miss it, and a replay would let it reach
# the kernel. This fails the build on one.
set -euo pipefail
cd "$(dirname "$0")/.."

pattern='libc::(recv|recvfrom|recvmsg|recvmmsg|send|sendto|sendmsg|sendmmsg)\b'
hits=$(grep -rnE "$pattern" crates/nlink/src --include='*.rs' \
  | grep -v '^crates/nlink/src/netlink/socket.rs:' \
  | grep -vE '^[^:]+:[0-9]+:\s*//' || true)
if [ -n "$hits" ]; then
  echo "FAIL: socket I/O outside NetlinkSocket (crates/nlink/src/netlink/socket.rs):"
  echo "$hits"
  echo "Route it through NetlinkSocket, so nlink::replay sees it (#168)."
  exit 1
fi
echo "OK: every netlink send and receive goes through NetlinkSocket."
