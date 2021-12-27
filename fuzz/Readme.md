# Fuzz testing

This folder contains utilities to carry out fuzz testing.
Currently only Honggfuzz is supported.
Heavily inspired by [the fuzz testing setup of rust-lightning](https://github.com/lightningdevkit/rust-lightning/tree/main/fuzz).

## Running 

Generate the fuzzing code:
```bash
pushd src/bin
./gen_msgs_fuzz.sh
popd
HFUZZ_RUN_ARGS="--exit_upon_crash" cargo hfuzz run offerdlc_fuzz
```
(replace with whichever target you want to fuzz)

## Running through docker

A docker image is provided to run honggfuzz on it.
To build it, from the repository root directory run:
```bash
docker build . -f fuzz/Dockerfile -t dlcfuzz
```

You can then use it to fuzz as follow:
```bash
docker run --rm -it dlcfuzz offerdlc_fuzz
```
(replacing with whichever target you want to fuzz)

You can alter the hongfuzz arguments using the `HFUZZ_RUN_ARGS` environment variable, e.g.:
```bash
docker run --rm -it -e HFUZZ_RUN_ARGS='--exit_upon_crash -t 10' dlcfuzz offerdlc_fuzz
```