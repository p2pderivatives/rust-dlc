#!/bin/bash
set -e
while true
do
./scripts/start_node.sh
sleep 3
cargo test -- --ignored integration_tests_multi --nocapture
./scripts/stop_node.sh
sleep 5
done
