# Dlc-manager Benchmarks

This folder contains benchmarks to measure the signing and verification of adaptor signatures for numerical outcome contracts.
The `const` parameters at the beginning of the file can be changed to try out different settings.
See code comments for details on the parameters.

## Running

To run the benchmarks: `cargo bench`.
To run the benchmarks using parallelization of anticipation points computation: `cargo bench --features=parallel`.
