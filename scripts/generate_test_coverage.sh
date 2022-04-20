#!/bin/bash

set -e

export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="rust-dlc-%p-%m.profraw"

cargo build

cargo test

grcov . --binary-path ./target/debug/deps/ -s . -t html --branch --ignore-not-existing -o ./coverage/
rm **/rust-dlc-*
