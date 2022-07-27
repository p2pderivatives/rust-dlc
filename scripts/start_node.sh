#!/bin/bash

if command -v docker &> /dev/null
then
   CMD=docker
else
   CMD=podman
fi

: "${BITCOINVERSION:=0.20.0}"
$CMD run --rm -d -p 18443:18443 --name bitcoin-node ruimarinho/bitcoin-core:$BITCOINVERSION \
  -regtest=1 \
  -rpcallowip=0.0.0/0 \
  -rpcbind=0.0.0.0 \
  -rpcauth='testuser:ea8070e0acccb49670309dd6c7812e16$2a3487173f9f6b603d43a70e6ccb0aa671a16dbee1cf86b098e77532d2515370' \
  -addresstype=bech32\
  -fallbackfee=0.0002
