#!/bin/bash

echo $(echo $($(ls ./target/debug/deps/$1* | grep -v '\.d\|\.o') --list --format=terse | sed 's/\: test$//'))