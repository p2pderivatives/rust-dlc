#!/bin/bash

BIN=$(ls ./target/debug/deps/${TEST_BIN}-* | grep -v '\.d\|Contents')
$BIN --list