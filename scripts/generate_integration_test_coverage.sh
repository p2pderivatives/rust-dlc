#!/bin/bash

set -e

export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="rust-dlc-%p-%m.profraw"

if command -v docker &> /dev/null
then
   CMD=docker
else
   CMD=podman
fi

export TEST_BIN=$1
LIST=$(bash ${PWD}/scripts/generate_test_list.sh $TEST_BIN)

echo $LIST

for TEST_NAME in $LIST
do
    if [ ! -z $TEST_NAME ]
    then
        export TEST_NAME=${TEST_NAME}
        bash ${PWD}/scripts/start_node.sh
        cargo test -- $TEST_NAME --ignored --exact --nocapture
        bash ${PWD}/scripts/stop_node.sh
    fi
done

grcov . --binary-path ./target/debug/deps/ -s . -t html --branch --ignore-not-existing -o ./integration_coverage/
rm **/rust-dlc-*