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
