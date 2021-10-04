FROM rust as kcov-base

ENV WORKSPACE /app
WORKDIR ${WORKSPACE}
COPY "./scripts/install_kcov.sh" ./
ENV DEBIAN_FRONTEND=noninteractive

# install dependencies
RUN apt-get update && apt-get -y install wget binutils-dev libcurl4-openssl-dev\
	libssl-dev libelf-dev zlib1g-dev libdw-dev libiberty-dev\
	build-essential python3 cmake

# install kcov
RUN ./install_kcov.sh

FROM rust as planner
ENV WORKSPACE /app
WORKDIR ${WORKSPACE}
RUN cargo install cargo-chef 
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM rust as cacher
ENV WORKSPACE /app
WORKDIR ${WORKSPACE}
RUN cargo install cargo-chef
COPY --from=planner ${WORKSPACE}/recipe.json recipe.json
RUN cargo chef cook --recipe-path recipe.json

FROM kcov-base as tester
ENV WORKSPACE /app
WORKDIR ${WORKSPACE}
COPY . .
# Copy over the cached dependencies
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo

RUN cargo test --no-run

RUN cp -r ./sled-storage-provider/test_files ./target/debug/deps/

CMD [ "cargo test" ]
