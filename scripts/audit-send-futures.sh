#!/bin/bash
# Every public async fn is checked for a Send future (#884): see
# scripts/audit_send_futures.py. Runs the audit's self-test first, so a
# checker that cannot fail does not pass the tree.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/audit_send_futures.py --self-test
python3 scripts/audit_send_futures.py crates/nlink/src
