#!/bin/bash

# Calculate the Unix timestamp one hour from now
DIR=$(git rev-parse --show-toplevel)

current_timestamp=$(date +%s)
future_timestamp=$((current_timestamp + 3600))
# Read the JSON file and update the eventId field
updated_json=$(jq --arg new_timestamp "$future_timestamp" '.contractInfos[0].oracles.eventId |= sub("\\d+$"; $new_timestamp)' ${DIR}/sample/examples/contracts/numerical_contract_input.json)

# Output the updated JSON
rm -f ${DIR}/sample/examples/contracts/sample_contract.json
echo "$updated_json" > ${DIR}/sample/examples/contracts/sample_contract.json

echo "Updated numerical contract has been saved"