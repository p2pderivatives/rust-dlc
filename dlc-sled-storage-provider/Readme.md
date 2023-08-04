# Sled storage provider

Implementation of the storage trait required by the [dlc-manager](../dlc-manager) using the [Sled](https://github.com/spacejam/sled) embedded database.

## Tests

We have roundtrip tests to check the behavior of all the methods defined by the `dlc_manager::Storage` trait.
For all types which can be saved and loaded via the `Storage` trait, after their serialization format changes we must run the [generate_serialized_contract_files.sh](../scripts/generate_serialized_contract_files.sh) script to update the static files used in these roundtrip tests.
