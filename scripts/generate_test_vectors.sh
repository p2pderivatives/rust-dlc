#!/bin/bash

set -e

SCRIPT_PATH=$(cd "$(dirname ${BASH_SOURCE[0]})"; pwd -P)
echo $SCRIPT_PATH
LIST=$(${SCRIPT_PATH}/generate_test_list.sh manager)
echo $LIST
OUTPUT="$(pwd)/test_vectors"
mkdir -p $OUTPUT

for TEST_NAME in $LIST
do
    if [[ ! -z ${TEST_NAME} && ! ${TEST_NAME} =~ bad|refund ]]
    then
        ./scripts/start_node.sh
        GENERATE_TEST_VECTOR=1 TEST_VECTOR_OUTPUT_NAME="$OUTPUT/${TEST_NAME}.json" cargo test -- --ignored ${TEST_NAME}
        ./scripts/stop_node.sh
    fi
done