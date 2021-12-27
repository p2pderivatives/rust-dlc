from rust as fuzzbase

RUN apt-get update
RUN apt-get update && apt-get -y install build-essential\
    binutils-dev libunwind-dev libblocksruntime-dev liblzma-dev
ENV WORKSPACE /fuzzing
WORKDIR ${WORKSPACE}
ADD . ${WORKSPACE}/
RUN cargo update
RUN cargo install --force honggfuzz
WORKDIR ${WORKSPACE}/fuzz
RUN cargo hfuzz build
ENV HFUZZ_RUN_ARGS='--exit_upon_crash'
ENTRYPOINT ["cargo", "hfuzz", "run"]

