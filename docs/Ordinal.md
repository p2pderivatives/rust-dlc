# Ordinal Support

It is possible to use an ordinal as part of the collateral of a DLC.
To do so, an [`OrdDescriptor`](../dlc-manager/src/contract/ord_descriptor.rs) must be used.
This descriptor contains information about the ordinal being included in the DLC (location in the blockchain and the transaction that includes is), as well as information about the event upon which the DLC is based.
Event outcomes can be, as for regular contracts, enumerated or numerical.

## Enumerated events

Ordinal DLCs based on enumerated events include, in addition to the regular enumerated event information, an array of boolean indicating for each possible outcome whether the ordinal should be given to the offer party (note this means that this array *must* be have the same number of elements as there are possible outcomes).

## Numerical events

Ordinal DLCs based on numerical events include, in addition to the regular numerical event information, an array or intervals.
These intervals indicate the ranges of outcomes for which the ordinal should be given to the offer party.

# Limitations

## Changing postage

It is currently not possible to change the postage of the ordinal.
This means that if an ordinal is contained in a 1BTC UTXO, the entire 1BTC will be included in the DLC and given to the ordinal winner.
Changing the postage should thus be done prior to including the ordinal in a DLC.

In addition, the postage of the ordinal will be merged with the payout of the winner.
This means that if a party is given an ordinal with a postage of 1BTC in addition to a payout of 1BTC, the output of the CET including the ordinal will have a value of 2BTC.

# How it works

In order to ensure that the ordinal does not get lost to fee, the DLC transactions for DLCs including an ordinal are created in the following way:
* The ordinal input is always set as the first one in the funding transaction,
* The funding output is always set as the first one in the funding transaction,
* The party getting the ordinal will always have its CET output in the first position.
