#!/bin/bash

set -e

TEST_BIN="daemon_execution_tests"
LIST=$(docker run -e TEST_BIN=${TEST_BIN}  -v "${PWD}:/tmp/workspace/rust-dlc" -it rust-dlc-test /app/scripts/get_test_list.sh)

for test in $LIST
do
    TEST_NAME=$(echo $test | grep "test:" | sed 's/://')
    if [ ! -z $TEST_NAME ]
    then
        TEST_BIN=${TEST_BIN} TEST_NAME=${TEST_NAME} docker-compose -p ${TEST_NAME} up --abort-on-container-exit
        docker-compose -p ${TEST_NAME} down -v
    fi
done