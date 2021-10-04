#!/bin/bash

set -e

export TEST_BIN=manager_execution_tests
LIST=$(docker run -v "${PWD}:/tmp/workspace/rust-dlc" -it rust-dlc-test /app/scripts/generate_test_list.sh $TEST_BIN)

for TEST_NAME in $LIST
do
    if [ ! -z $TEST_NAME ]
    then
        export TEST_NAME=${TEST_NAME}
        docker-compose -p ${TEST_NAME} up -d bitcoind
        docker-compose -p ${TEST_NAME} run -w /app tester ./scripts/kcov_exec.sh --abort-on-container-exit
        docker-compose -p ${TEST_NAME} down -v
    fi
done