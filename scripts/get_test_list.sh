#!/bin/bash

for TEST_PREFIX in "$@"; do
  TEST_BIN=$(ls ./target/debug/deps/${TEST_PREFIX}* | grep -v '\.d\|Contents')
  LIST=$(${TEST_BIN} --list --format=terse | sed 's/\: test$/,/' | sed 's@[^[:space:],]\+@"'${TEST_BIN}' &"@g')
  RES+=(${LIST})
done

echo $(echo [${RES[@]}] | sed 's/,]/]/')

