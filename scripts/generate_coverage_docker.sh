#!/bin/bash

docker run --security-opt seccomp=unconfined  -v "${PWD}:/volume"  xd009642/tarpaulin ./scripts/generate_coverage.sh
