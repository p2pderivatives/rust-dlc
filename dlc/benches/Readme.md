# DLC Benchmarks

This folder contains benchmarks to evaluate the impact of optimizations on computation of adaptor signatures and aggregated anticipation points.
The `const` parameters at the beginning of the file can be changed to try out different settings (note that the computation of all aggregated points without optimization can take a very long time for large number of digits and/or oracles).
See code comments for details on each benchmark.

## Running

To run the benchmarks: `cargo +nightly bench --features=unstable`
