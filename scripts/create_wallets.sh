#!/bin/bash

bitcoincli=$(command -v bitcoin-cli)
opts=( -rpcuser="testuser" -rpcpassword="lq6zequb-gYTdF2_ZEUtr8ywTXzLYtknzWU4nV8uVoo=" -regtest )

$bitcoincli "${opts[@]}" createwallet "alice" "false" "false"
$bitcoincli "${opts[@]}" createwallet "bob" "false" "false"

aliceAddress=$($bitcoincli "${opts[@]}" -rpcwallet=alice getnewaddress bec32)
$bitcoincli "${opts[@]}" generatetoaddress 101 ${aliceAddress} &> /dev/null
bobAddress=$($bitcoincli "${opts[@]}" -rpcwallet=bob getnewaddress bec32)
$bitcoincli "${opts[@]}" generatetoaddress 201 ${bobAddress} &> /dev/null
