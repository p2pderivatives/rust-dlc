#!/bin/bash

set -e

CONTRACT_TEST_FILES=("Offered" "Accepted" "Confirmed" "Confirmed1" "Signed" "Signed1" "PreClosed" "Closed")

DEST=${PWD}/dlc-sled-storage-provider/test_files/

docker-compose up -d
./scripts/wait_for_electrs.sh

for FILE in ${CONTRACT_TEST_FILES[@]}
do
    GENERATE_SERIALIZED_CONTRACT=1 cargo test -- single_oracle_numerical_test --ignored --exact
    cp ${PWD}/dlc-manager/${FILE//1/} ${DEST}${FILE}
done

CHANNEL_TEST_FILES=("OfferedChannel" "AcceptedChannel" "SignedChannelEstablished" "SignedChannelSettled")

for FILE in ${CHANNEL_TEST_FILES[@]}
do
    GENERATE_SERIALIZED_CHANNEL=1 cargo test -- channel_settled_close_test --ignored --exact
    cp ${PWD}/dlc-manager/${FILE//1/} ${DEST}${FILE}
done

TEST_FILES=( "${CONTRACT_TEST_FILES[@]}" "${CHANNEL_TEST_FILES[@]}" )

for FILE in ${TEST_FILES[@]}
do
    rm -f ${PWD}/dlc-manager/${FILE}
done

rm ${PWD}/dlc-manager/Signed*

docker-compose down -v
