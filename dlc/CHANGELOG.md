# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2022-06-06

### Fixed
- Fix build issue caused by breaking minor update of `rust-secp256k1-sys` crate.

### Changed
- Discard dust outputs on the refund transaction.
