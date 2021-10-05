#!/bin/bash

set -e

for i in {0..100}
do
  echo "Start"
  ./scripts/start_node.sh
  RUST_LOG=info cargo test -- --ignored three_of_three_oracle_numerical_with_diff_test
  ./scripts/stop_node.sh
done
