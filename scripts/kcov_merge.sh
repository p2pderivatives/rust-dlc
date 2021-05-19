#!/bin/bash

mkdir -p ./target/cov/merged
kcov --merge ./target/cov/merged ./target/cov/${1}