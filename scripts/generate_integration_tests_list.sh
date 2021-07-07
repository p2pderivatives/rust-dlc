#!/bin/bash

echo [$(echo $($(ls ./target/debug/deps/execution* | grep -v '\.d\|Contents') --list --format=terse | sed 's/\: test$/,/') | sed 's/[^[:space:],]\+/"&"/g') ] | sed 's/, ]/]/'
