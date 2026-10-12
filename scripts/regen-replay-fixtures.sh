#!/bin/bash
# Record the replay fixtures under crates/nlink/tests/fixtures/ again, against
# this machine's kernel (#168). Needs root (sudo) for the recording namespace;
# the replays of them need nothing.
set -euo pipefail
cd "$(dirname "$0")/.."
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E' NLINK_REPLAY_REGEN=1 \
  cargo test -q -p nlink --test integration \
  --features lab,sockdiag,namespace_watcher,process,serde,replay \
  -- --test-threads=1 a_route_session_replays_as_it_was_recorded
sudo chown "$(id -u):$(id -g)" crates/nlink/tests/fixtures/*.nlreplay
ls -l crates/nlink/tests/fixtures/
