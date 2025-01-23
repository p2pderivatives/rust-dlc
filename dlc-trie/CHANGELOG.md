# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## Changed
- validate that `RangePayout` do not contain a `count` of zero
- `group_by_ignoring_digits` panics when `start` is greater than `end`

## [0.5.0] - 2024-07-11

### Changed
- update bitcoin and secp256k1_zkp dependencies

### Added
- support for `no-std`

## [0.4.0] - 2022-10-28

### Changed
- `dlc` crate version update

## [0.3.0] - 2022-10-28

### Changed
- `dlc` crate version update

## [0.2.0]

### Added
- `parallel` feature for computing anticipation points in parallel.
- support for multi oracles with varying number of digits.

### Fixed
- iteration of DigitTrie sometimes omitting values.
