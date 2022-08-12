
export type OutPoint = {
  txid: string,
  vout: number,
}// Contains the parameters required for creating DLC transactions for a single
// party. Specifically these are the common fields between Offer and Accept
// messages.
export type PartyParams = {     fundPubkey: string; changeScriptPubkey: string; changeSerialId:     number; payoutScriptPubkey: string; payoutSerialId: number; inputs:     TxInputInfo []; inputAmount: number; collateral: number };
// Represents the payouts for a unique contract outcome. Offer party represents
// the initiator of the contract while accept party represents the party
// accepting the contract.
export type Payout = { offer: number; accept: number };
// Contains info about a utxo used for funding a DLC contract
export type TxInputInfo = {     outpoint: OutPoint; maxWitnessLen: number; redeemScript: string;     serialId: number };
// Structure containing oracle information for a single event.
export type OracleInfo = { publicKey: string; nonces: string [] };
