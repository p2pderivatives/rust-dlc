# Development

Developing the library requires only a working rust environment.
Integration testing and code coverage report generation require `docker` and `docker-compose`.

## Running tests

In the main directory, you can run `cargo test --all-features` to run all the unit tests.

## Running integration tests (requires docker)

In the `dlc` or `dlc-manager` directory, run `../script/start_node.sh` to start a bitcoind instance.

Then run
```
cargo test --ignored test_name
```
replacing `test_name` with the test you want to run.
For example within the `dlc-manager` folder:
```
cargo test --ignored two_of_five_oracle_numerical_test
```

## Running fuzz tests

Some fuzz testing are implemented, check [the documentation](../fuzz/Readme.md) for details.

## Generating code coverage report

Start by building the docker image using:
```
docker build . -t rust-dlc-test
```

### Code coverage for unit tests

From the main folder run:
```
./scripts/run_test_coverage.sh
```

This will generate coverage reports for each projects in `target/cov/cov-project-name`.

To generate a consolidated report run:
```
docker-compose run tester ./scripts/kcov_merge.sh cov-
```

The consolidated report will be available at `target/cov/merged`.

### Code coverage for dlc-manager integration tests

From the main folder run:
```
./scripts/run_manager_test_coverage.sh
```

This will generate coverage reports for each integration test.

To generate a consolidated report run (note that this will override the report in the `target/cov/merged` folder if it previously existed):
```
docker-compose run tester ./scripts/kcov_merge.sh cov-manager_execution_tests
```

The consolidated report will be available at `target/cov/merged`.

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

To profile integration tests using [perf](https://perf.wiki.kernel.org/index.php/Main_Page), run the following commands from the project's root folder:
```bash
# build the docker image
docker build . -t rust-dlc-test
# start a bitcoind instance
docker-compose run -d bitcoind
# get into the tester container
docker-compose run tester bash
# profile an integration test (change the name of the test with the one you want)
perf record -g ./target/debug/deps/manager_execution_tests-2a19999c47ed3cfb --ignored three_of_three_oracle_numerical_test
# get FlameGraph and generate a flame graph
git clone https://github.com/brendangregg/FlameGraph
perf script | ./FlameGraph/stackcollapse-perf.pl > out.perf-folded
./FlameGraph/flamegraph.pl out.perf-folded > rust-perf.svg

# from another terminal recover the generated svg
docker exec containerid cat /app/rust-perf.svg > ./rust-perf.svg
```