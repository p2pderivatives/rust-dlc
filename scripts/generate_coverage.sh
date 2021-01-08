#!/bin/bash

rustup toolchain install nightly
cargo +nightly tarpaulin --verbose --all-features --workspace --timeout 120 --out Html --exclude-files dlc/tests/*
