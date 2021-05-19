#!/bin/bash

mkdir -p ./target/cov/cov-${TEST_BIN}-${TEST_NAME}
kcov ./target/cov/cov-${TEST_BIN}-${TEST_NAME} --exclude-pattern=/.cargo,/usr $(ls ./target/debug/deps/${TEST_BIN}-* | grep -v '\.d\|Contents') ${TEST_NAME}