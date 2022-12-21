#!/bin/bash

until $(curl --output /dev/null --silent --fail http://localhost:3004/blocks/tip/height); do
    printf 'waiting for electrs to start'
    curl  --user testuser:lq6zequb-gYTdF2_ZEUtr8ywTXzLYtknzWU4nV8uVoo= --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "generatetoaddress", "params": [1, "bcrt1qzqaernqlwetvahu59fwt3p38ezww7w95jqlxkg"]}' -H 'content-type: text/plain;' http://127.0.0.1:18443/
    sleep 5
done