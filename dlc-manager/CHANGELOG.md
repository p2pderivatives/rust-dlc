# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2023-02-06

### Added
- support for DLC channels

### Changed
- remove event maturity from `ContractInput`. The maturity is now computed from the oracle event information.
- closed contract data is now pruned geatly reducing storage usage.

### Fixed
- better validation of rounding intervals
- better validation of `ContractInput` and contract offers.

## [0.3.0] - 2022-10-28

### Changed
- `Contract` enum now has a `Pre-Closed` state.
- `dlc` crate version update.

## [0.2.0] - 2022-06-06

### Added
- `parallel` feature for computing anticipation points in parallel.
- signing of transaction inputs was added to the `Wallet` trait.
- support for contracts with multi oracle with varying number of digits.

### Changed
- serialization format was changed according to update of the DLC specifications.
- improved validation of payout curves.
- validation of node id on manager callbacks.
- validation of received contract offers.

### Fixed
- computation of contract id according to the DLC specifications.
- conversion of hyperbola curves.
