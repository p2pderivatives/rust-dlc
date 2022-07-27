#!/bin/bash

set -e

CONTRACT_TEST_FILES=("Offered" "Accepted" "Confirmed" "Confirmed1" "Signed" "Signed1" "PreClosed" "Closed")
DEST=${PWD}/dlc-sled-storage-provider/test_files/

for FILE in ${CONTRACT_TEST_FILES[@]}
do
    # bash ${PWD}/scripts/start_node.sh
    GENERATE_SERIALIZED_CONTRACT=1 cargo test -- single_oracle_numerical_test --ignored --exact
    # bash ${PWD}/scripts/stop_node.sh
    cp ${PWD}/dlc-manager/${FILE//1/} ${DEST}${FILE}
done

CHANNEL_TEST_FILES=("OfferedChannel" "AcceptedChannel" "SignedChannelEstablished" "SignedChannelSettled")

for FILE in ${CHANNEL_TEST_FILES[@]}
do
    # bash ${PWD}/scripts/start_node.sh
    GENERATE_SERIALIZED_CHANNEL=1 cargo test -- channel_settled_close_test --ignored --exact
    # bash ${PWD}/scripts/stop_node.sh
    cp ${PWD}/dlc-manager/${FILE//1/} ${DEST}${FILE}
done

TEST_FILES=( "${CONTRACT_TEST_FILES[@]}" "${CHANNEL_TEST_FILES[@]}" )

for FILE in ${TEST_FILES[@]}
do
    rm ${PWD}/dlc-manager/${FILE}
done

rm ${PWD}/dlc-manager/Signed*
