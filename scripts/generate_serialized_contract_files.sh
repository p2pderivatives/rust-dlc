#!/bin/bash

set -e

TEST_FILES=("Offered" "Accepted" "Confirmed" "Confirmed1" "Signed" "Signed1" "Closed")
DEST=${PWD}/dlc-sled-storage-provider/test_files/

for FILE in ${TEST_FILES[@]}
do
    bash ${PWD}/scripts/start_node.sh
    GENERATE_SERIALIZED_CONTRACT=1 cargo test -- single_oracle_numerical_test --ignored --exact
    bash ${PWD}/scripts/stop_node.sh
    cp ${PWD}/dlc-manager/${FILE//1/} ${DEST}${FILE}
done

for FILE in ${TEST_FILES[@]}
do
    rm ${PWD}/dlc-manager/${FILE}
done