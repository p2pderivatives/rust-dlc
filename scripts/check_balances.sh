#!/bin/bash

# Locate bitcoin-cli
bitcoincli=$(command -v bitcoin-cli)

# Define RPC options
opts=( -rpcuser="testuser" -rpcpassword="lq6zequb-gYTdF2_ZEUtr8ywTXzLYtknzWU4nV8uVoo=" -regtest -named)

# Check and print balance of alice wallet
aliceBalance=$($bitcoincli "${opts[@]}" -rpcwallet=alice getbalance)
echo "Alice's balance: ${aliceBalance} BTC"

# Check and print balance of bob wallet
bobBalance=$($bitcoincli "${opts[@]}" -rpcwallet=bob getbalance)
echo "Bob's balance: ${bobBalance} BTC"