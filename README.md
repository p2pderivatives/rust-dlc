# Rust-Dlc

A Rust library for working with [Discreet Log Contracts](https://adiabat.github.io/dlc.pdf).

A [sample](./sample) is provided as an example usage of this library.

Contributions are welcome.
Check the [contributing](./docs/Contributing.md) and [development](./docs/Development.md) documents for more information.

## Status

The implementation is mainly based on the [DLC specifications](https://github.com/discreetlogcontracts/dlcspecs) but is not yet fully compliant with it.


## Organization

The library provides several crates to let users chose which functionality they want to utilize within their applications.

### dlc

The [dlc](./dlc) crate provides basic functionalities for creating, signing and verifying DLC transactions.

### dlc-trie

The [dlc-trie](./dlc-trie) crate provides data structures for facilitating the storage and retrieval of information related to DLC based on numerical events.

### dlc-manager

The [dlc-manager](./dlc-manager) crate provides functionalities for handling the creation and processing of DLC, as well as the generation of messages to be exchanged between two parties of a DLC.

### dlc-messages

The [dlc-messages](./dlc-messages) crate provides data structures and serialization functionalities for messages to be exchanged between DLC peers.

### bitcoin-rpc-provider

The [bitcoin-rpc-provider](./bitcoin-rpc-provider) crate implements interfaces required by the [dlc-manager](#dlc-manager) for interacting with the Bitcoin blockchain and proving wallet functionalities through the bitcoin-core RPC.

### cg-oracle-client

The [cg-oracle-client](./cg-oracle-client) crate implements the oracle interface required by the [dlc-manager](#dlc-manager) to interact with an instance of the [P2PDerivatives oracle](https://github.com/p2pderivatives/p2pderivatives-oracle).

### sled-storage-provider

The [sled-storage-provider](./sled-storage-provider) crate implements the storage interface required by the [dlc-manager](#dlc-manager) to provide persistent storage of data.

### Testing related crates

The [bitcoin-test-utils](./bitcoin-test-utils) and [mocks](./mocks) crates are used for testing purpose and are not intended to be used externally.
