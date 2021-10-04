#!/bin/bash

if [ ! -z $TEST_NAME ]
then
  IGNORED="--ignored ${TEST_NAME}"
  SUFFIX=${TEST_BIN}-${TEST_NAME}
else
  SUFFIX=${TEST_BIN}
  INCLUDE="--include-pattern=${TEST_BIN}"
fi
OUTPUT=./target/cov/cov-${SUFFIX}
mkdir -p ${OUTPUT}
TEST_BIN=$(echo ${TEST_BIN} | sed 's/-/_/g')
BIN=$(ls ./target/debug/deps/${TEST_BIN}-* | grep -v '\.d\|\.o')

HAS_TESTS=$(${BIN} --list --format=terse)

if [ ! -z "${HAS_TESTS}" ]
then
  kcov ${OUTPUT} --exclude-pattern=/.cargo,/usr ${INCLUDE} $BIN ${IGNORED}
fi