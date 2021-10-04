#!/bin/bash

set -e

LIST=$(ls -d */ | sed 's/\///g' | grep -v 'scripts\|target')

for TEST_BIN in $LIST
do
    
    if [ ! -z $TEST_BIN ]
    then
        export TEST_BIN=${TEST_BIN}
        docker-compose run -e TEST_BIN=$TEST_BIN tester ./scripts/kcov_exec.sh --abort-on-container-exit
    fi
done