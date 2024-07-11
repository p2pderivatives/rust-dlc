# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2024-07-11

### Fixed
- serialization of `f64`
- `use-serde` feature
- `Reject` message

### Changed
- updated bitcoin, lightning and secp256k1_zkp dependencies
- `read_dlc_message` is no public
- implement `std::error::Error` for `Error` struct

### Added
- support for `no-std`
- `nonces` method for `OracleAttestation`

## [0.3.0] - 2022-10-28

### Changed
- `dlc` crate version update

## [0.2.0] - 2022-06-06

### Changed
- contract id computation function removed from crate.
- serialization format according to the DLC specifications.

### Fixed
- vulnerability on deserialization of vectors.
