FROM rust as planner

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

RUN cargo install cargo-chef 
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

FROM rust as cacher
ENV WORKSPACE /app
WORKDIR ${WORKSPACE}
RUN cargo install cargo-chef
COPY --from=planner ${WORKSPACE}/recipe.json recipe.json
RUN cargo chef cook --recipe-path recipe.json

FROM planner as builder
ENV WORKSPACE /app
WORKDIR ${WORKSPACE}
COPY . .
# Copy over the cached dependencies
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo

COPY --from=planner /usr/local/bin/kcov /usr/local/bin/kcov

RUN cargo test --no-run

CMD [ "./scripts/kcov_exec.sh" ]
