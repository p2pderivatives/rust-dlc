# Ordinal Support

This library now supports the locking of an ordinal as part of the collateral of a DLC.

Notes:
* An ordinal is inscribed into a single satoshi. However, that satoshi is often part of a larger UTXO. DLCs lock UTXOs, so please keep that context in mind.

* In all cases, the gas fee to lock and later unlock the DLC is split between both parties.

* For more information about DLCs, please see the main folder of this repo, the [`DLC-Link docs page`](https://docs.dlc.link), https://github.com/dlc-link, and the main https://github.com/discreetlogcontracts/dlcspecs specifications page.

> Resizing UTXOs
>
> Please note, this package does not currently support the re-sizing of the UTXO containing the ordinal within the DLC. See [this section](#changing-postage) for more details


## Supported types of DLCs

### DLC with only the ordinal
This package supports the use case when the offering party of the DLC locks the ordinal-containing UTXO into the DLC, and the counter-party (the acceptor) does not lock any collateral.

In this case, the outcome is essentially binary, either the ordinal containing UTXO goes to the offeror, or the acceptor.

### Ordinal with additional collateral
This package also supports the case when the offering party of the DLC locks the ordinal-contianing UTXO into the dlc, AND any amount of addition collateral is locked into the DLC by either party.

1. In this case, the outcome of the UTXO containing the ordinal will go to either party A or B, without resizing (as described earlier)
2. The remaining collateral locked by either, or both, parties can be split between the parties based on the standard DLC enumerated or numerical outcome guidelines.

### Locking an ordinal in the DLC

To lock an ordinal, an [`OrdDescriptor`](../dlc-manager/src/contract/ord_descriptor.rs) must be used. This descriptor contains information about the ordinal being included in the DLC (location in the blockchain and the transaction that includes is), as well as information about the event upon which the DLC is based.

Event outcomes can be, as for regular contracts, enumerated or numerical.

## Enumerated events

Ordinal DLCs based on enumerated events include, in addition to the regular enumerated event information, an array of boolean indicating for each possible outcome whether the ordinal should be given to the offer party (note this means that this array *must* be have the same number of elements as there are possible outcomes).

## Numerical events

Ordinal DLCs based on numerical events include, in addition to the regular numerical event information, an array or intervals.
These intervals indicate the ranges of outcomes for which the ordinal should be given to the offer party.

# Limitations

## Changing postage

It is currently not possible to change the postage of the ordinal.

This means that if an ordinal is contained in a 1BTC UTXO, the entire 1BTC will be included in the DLC, and given to the ordinal winner without changing the sats in the UTXO.

Changing the postage should thus be done prior to including the ordinal in a DLC by the wallet.

In addition, the postage of the ordinal will be merged with the payout of the winner.

This means that if a party is given an ordinal with a postage of 1BTC in addition to a payout of 1BTC, the output of the CET including the ordinal will have a value of 2BTC.

## Offering party provides the ordinal
Currently only the offering party can lock/put the ordinal into the DLC. We are currently exploring having either party perform this function.

# How it works

In order to ensure that the ordinal does not get lost to fee, the DLC transactions for DLCs including an ordinal are created in the following way:
* The ordinal input is always set as the first one in the funding transaction,
* The funding output is always set as the first one in the funding transaction,
* The party getting the ordinal will always have its CET output in the first position.
