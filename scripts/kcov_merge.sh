#!/bin/bash

mkdir -p ./target/cov/merged
LIST=$(ls -d ./target/cov/${1}*)
kcov --merge ./target/cov/merged ${LIST[@]}
rm -r ${LIST[@]}