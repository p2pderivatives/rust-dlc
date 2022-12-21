# Development

Developing the library requires only a working rust environment.
Integration testing and code coverage report generation require `docker` and `docker-compose`.

## Running tests

In the main directory, you can run `cargo test --all-features` to run all the unit tests.

## Running integration tests (requires docker-compose)

In the root directory, run `docker-compose up -d` to run a bitcoin node and electrs instance.

Then in the `dlc` or `dlc-manager` directory run
```
cargo test -- --ignored test_name
```
replacing `test_name` with the test you want to run.
For example within the `dlc-manager` folder:
```
cargo test -- --ignored two_of_five_oracle_numerical_test
```

## Running fuzz tests

Some fuzz testing are implemented, check [the documentation](../fuzz/Readme.md) for details.

## Generating code coverage report

### Code coverage for unit tests

From the main folder run:
```
./scripts/generate_test_coverage.sh
```

This will generate a coverage report in `coverage/index.html`.

### Code coverage for dlc-manager integration tests

From the main folder run:
```
./scripts/generate_integration_test_coverage.sh
```
The coverage report will be available at `integration_coverage/index.html`.

## Benchmarking and profiling

At the moment the bottlenecks are mainly the adaptor signature verification and signing for numerical outcome DLC with a relatively large number of CETs.
However it can sometimes be useful to have a look at benchmarks and do some profiling.

### Benchmarking (requires rust nightly)

Some benchmarks are [available for the dlc manager](../dlc-manager/benches/benchmarks.rs).
To run them:
```
cargo +nightly bench  --features=unstable
```

### Profiling (requires docker-compose)

Profiling is currently not working.
