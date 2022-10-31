#!/bin/bash

set -e

if command -v docker &> /dev/null
then
   CMD=docker
else
   CMD=podman
fi

export TEST_BIN=$1
LIST=$(bash ${PWD}/scripts/generate_test_list.sh $TEST_BIN)

for TEST_NAME in $LIST
do
    if [ ! -z $TEST_NAME ]
    then
        bash ${PWD}/scripts/start_node.sh
        cargo test -- $TEST_NAME --ignored --exact --nocapture
        bash ${PWD}/scripts/stop_node.sh
    fi
done