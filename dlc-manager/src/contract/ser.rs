//! Serialization trait implementations for various data structures enabling them
//! to be converted to byte arrays.

use crate::contract::accepted_contract::AcceptedContract;
use crate::contract::contract_info::ContractInfo;
use crate::contract::enum_descriptor::EnumDescriptor;
use crate::contract::numerical_descriptor::{
    DifferenceParams, NumericalDescriptor, NumericalEventInfo,
};
use crate::contract::offered_contract::OfferedContract;
use crate::contract::signed_contract::SignedContract;
use crate::contract::AdaptorInfo;
use crate::contract::{
    ClosedContract, ContractDescriptor, FailedAcceptContract, FailedSignContract, FundingInputInfo,
};
use crate::payout_curve::{
    HyperbolaPayoutCurvePiece, PayoutFunction, PayoutFunctionPiece, PayoutPoint,
    PolynomialPayoutCurvePiece, RoundingInterval, RoundingIntervals,
};
use bitcoin::network::constants::Network;
use bitcoin::Address;
use dlc::{DlcTransactions, EnumerationPayout, PartyParams, Payout, TxInputInfo};
use dlc_messages::utils::{
    read_f64, read_string, read_vec, read_vec_cb, write_f64, write_string, write_vec, write_vec_cb,
};
use dlc_trie::digit_trie::{DigitNodeData, DigitTrieDump};
use dlc_trie::multi_oracle_trie::{MultiOracleTrie, MultiOracleTrieDump};
use dlc_trie::multi_oracle_trie_with_diff::{MultiOracleTrieWithDiff, MultiOracleTrieWithDiffDump};
use dlc_trie::multi_trie::{MultiTrieDump, MultiTrieNodeData, TrieNodeInfo};
use dlc_trie::RangeInfo;
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::ffi::ECDSA_ADAPTOR_SIGNATURE_LENGTH;
use secp256k1_zkp::EcdsaAdaptorSignature;
use std::io::Read;

/// Trait used to de/serialize an object to/from a vector of bytes.
pub trait Serializable
where
    Self: Sized,
{
    /// Serialize the object.
    fn serialize(&self) -> Result<Vec<u8>, ::std::io::Error>;
    /// Deserialize the object.
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DecodeError>;
}

impl<T> Serializable for T
where
    T: Writeable + Readable,
{
    fn serialize(&self) -> Result<Vec<u8>, ::std::io::Error> {
        let mut buffer = Vec::new();
        self.write(&mut buffer)?;
        Ok(buffer)
    }

    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
        Readable::read(reader)
    }
}

fn write_usize<W: Writer>(i: &usize, writer: &mut W) -> Result<(), ::std::io::Error> {
    <u64 as Writeable>::write(&(*i as u64), writer)
}

fn read_usize<R: ::std::io::Read>(reader: &mut R) -> Result<usize, DecodeError> {
    let i: u64 = Readable::read(reader)?;
    Ok(i as usize)
}

fn write_option<W: Writer, T>(t: &Option<T>, writer: &mut W) -> Result<(), ::std::io::Error>
where
    T: Writeable,
{
    write_option_cb(t, writer, &<T as Writeable>::write)
}

fn read_option<R: ::std::io::Read, T>(reader: &mut R) -> Result<Option<T>, DecodeError>
where
    T: Readable,
{
    read_option_cb(reader, &<T as Readable>::read)
}

fn write_option_cb<W: Writer, T, F>(
    t: &Option<T>,
    writer: &mut W,
    cb: &F,
) -> Result<(), ::std::io::Error>
where
    F: Fn(&T, &mut W) -> Result<(), ::std::io::Error>,
{
    match t {
        Some(t) => {
            1_u8.write(writer)?;
            cb(&t, writer)
        }
        None => 0_u8.write(writer),
    }
}

fn read_option_cb<R: ::std::io::Read, T, F>(
    reader: &mut R,
    cb: &F,
) -> Result<Option<T>, DecodeError>
where
    F: Fn(&mut R) -> Result<T, DecodeError>,
{
    let prefix: u8 = Readable::read(reader)?;
    let res = match prefix {
        0 => None,
        1 => Some(cb(reader)?),
        _ => return Err(DecodeError::InvalidValue),
    };
    Ok(res)
}

fn write_address<W: Writer>(address: &Address, writer: &mut W) -> Result<(), ::std::io::Error> {
    address.script_pubkey().write(writer)?;
    let net: u8 = match address.network {
        Network::Bitcoin => 0,
        Network::Testnet => 1,
        Network::Signet => 2,
        Network::Regtest => 3,
    };

    net.write(writer)
}

fn read_address<R: Read>(reader: &mut R) -> Result<Address, DecodeError> {
    let script: bitcoin::Script = Readable::read(reader)?;
    let net: u8 = Readable::read(reader)?;
    let network = match net {
        0 => Network::Bitcoin,
        1 => Network::Testnet,
        2 => Network::Signet,
        3 => Network::Regtest,
        _ => return Err(DecodeError::InvalidValue),
    };
    Ok(bitcoin::Address::from_script(&script, network).unwrap())
}

fn write_ecdsa_adaptor_signature<W: Writer>(
    sig: &EcdsaAdaptorSignature,
    writer: &mut W,
) -> Result<(), ::std::io::Error> {
    let mut ser_sig = [0; ECDSA_ADAPTOR_SIGNATURE_LENGTH];
    ser_sig.copy_from_slice(&sig.as_ref());
    ser_sig.write(writer)
}

fn read_ecdsa_adaptor_signature<R: ::std::io::Read>(
    reader: &mut R,
) -> Result<EcdsaAdaptorSignature, DecodeError> {
    let sig_buf: [u8; ECDSA_ADAPTOR_SIGNATURE_LENGTH] = Readable::read(reader)?;
    let signature = match EcdsaAdaptorSignature::from_slice(&sig_buf) {
        Ok(sig) => sig,
        Err(_) => return Err(DecodeError::InvalidValue),
    };

    Ok(signature)
}

fn write_ecdsa_adaptor_signatures<W: Writer>(
    sig: &Vec<EcdsaAdaptorSignature>,
    writer: &mut W,
) -> Result<(), ::std::io::Error> {
    write_vec_cb(&sig, writer, &write_ecdsa_adaptor_signature)
}

fn read_ecdsa_adaptor_signatures<R: ::std::io::Read>(
    reader: &mut R,
) -> Result<Vec<EcdsaAdaptorSignature>, DecodeError> {
    read_vec_cb(reader, &read_ecdsa_adaptor_signature)
}

macro_rules! field_write {
    ($stream: expr, $field: expr, writeable) => {
        $field.write($stream)?;
    };
    ($stream: expr, $field: expr, {cb_writeable, $w_cb: expr, $r_cb: expr}) => {
        $w_cb(&$field, $stream)?;
    };
    ($stream: expr, $field: expr, string) => {
        write_string(&$field, $stream)?;
    };
    ($stream: expr, $field: expr, vec) => {
        write_vec(&$field, $stream)?;
    };
    ($stream: expr, $field: expr, {vec_cb, $w_cb: expr, $r_cb: expr}) => {
        write_vec_cb(&$field, $stream, &$w_cb)?;
    };
    ($stream: expr, $field: expr, float) => {
        write_f64($field, $stream)?;
    };
    ($stream: expr, $field: expr, usize) => {
        write_usize(&$field, $stream)?;
    };
    ($stream: expr, $field: expr, {option_cb, $w_cb: expr, $r_cb: expr}) => {
        write_option_cb(&$field, $stream, &$w_cb)?;
    };
    ($stream: expr, $field: expr, option) => {
        write_option(&$field, $stream)?;
    };
}

macro_rules! field_read {
    ($stream: expr, writeable) => {
        Readable::read($stream)?
    };
    ($stream: expr, {cb_writeable, $w_cb: expr, $r_cb: expr}) => {
        $r_cb($stream)?
    };
    ($stream: expr, string) => {
        read_string($stream)?
    };
    ($stream: expr, vec) => {
        read_vec($stream)?
    };
    ($stream: expr, {vec_cb, $w_cb: expr, $r_cb: expr}) => {
        read_vec_cb($stream, &$r_cb)?
    };
    ($stream: expr, float) => {
        read_f64($stream)?
    };
    ($stream: expr, usize) => {
        read_usize($stream)?
    };
    ($stream: expr, {option_cb, $w_cb: expr, $r_cb: expr}) => {
        read_option_cb($stream, &$r_cb)?
    };
    ($stream: expr, option) => {
        read_option($stream)?
    };
}

macro_rules! impl_writeable_custom {
    ($st:ident, {$(($field: ident, $fieldty: tt)), *} ) => {
        impl Writeable for $st {
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
				$(
                    field_write!(w, self.$field, $fieldty);
                )*
				Ok(())
            }
        }

        impl Readable for $st {
			fn read<R: std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
                Ok(Self {
                    $(
                        $field: field_read!(r, $fieldty),
                    )*
                })
            }
        }
    };
}

macro_rules! impl_writeable_external {
    ($st: ident $(< $gen: ident $(< $gen2: ident >)?> )? , $name: ident, {$(($field: ident, $fieldty: tt)), *} ) => {
        mod $name {
            use super::*;
            use lightning::ln::msgs::DecodeError;
            use lightning::util::ser::Writer;
            pub fn write<W: Writer>($name: &$st<$($gen$(<$gen2>)?)?>, w: &mut W) -> Result<(), ::std::io::Error> {
                $(
                    field_write!(w, $name.$field, $fieldty);
                )*
                Ok(())
            }

            pub fn read<R: std::io::Read>(r: &mut R) -> Result<$st<$($gen$(<$gen2>)?)?>, DecodeError> {
                Ok($st {
                    $(
                        $field: field_read!(r, $fieldty),
                    )*
                })
            }
        }
    };
}

macro_rules! impl_writeable_external_enum {
    ($st:ident $(<$gen: ident>)?, $name: ident, $(($variant_id: expr, $variant_name: ident, $variant_mod: ident)), * ) => {
        mod $name {
            use super::*;

			pub fn write<W: Writer>($name: &$st$(<$gen>)?, w: &mut W) -> Result<(), ::std::io::Error> {
                match $name {
                    $($st::$variant_name(ref field) => {
                        let id : u8 = $variant_id;
                        id.write(w)?;
                        $variant_mod::write(field, w)?;
                    }),*
                };
				Ok(())
            }

			pub fn read<R: std::io::Read>(r: &mut R) -> Result<$st$(<$gen>)?, DecodeError> {
                let id: u8 = Readable::read(r)?;
                match id {
                    $($variant_id => {
						Ok($st::$variant_name($variant_mod::read(r)?))
					}),*
					_ => {
						Err(DecodeError::UnknownRequiredFeature)
					},
                }
            }
        }
    };
}

macro_rules! impl_writeable_custom_enum {
    ($st:ident, $(($variant_id: expr, $variant_name: ident)), *; $(($external_variant_id: expr, $external_variant_name: ident, $write_cb: expr, $read_cb: expr)), *; $(($simple_variant_id: expr, $simple_variant_name: ident)), *) => {
        impl Writeable for $st {
			fn write<W: Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
                match self {
                    $($st::$variant_name(ref field) => {
                        let id : u8 = $variant_id;
                        id.write(w)?;
                        field.write(w)?;
                    }),*
                    $($st::$external_variant_name(ref field) => {
                        let id : u8 = $external_variant_id;
                        id.write(w)?;
                        $write_cb(field, w)?;
                    }),*
                    $($st::$simple_variant_name => {
                        let id : u8 = $simple_variant_id;
                        id.write(w)?;
                    }),*
                };
				Ok(())
            }
        }

        impl Readable for $st {
			fn read<R: std::io::Read>(r: &mut R) -> Result<Self, DecodeError> {
                let id: u8 = Readable::read(r)?;
                match id {
                    $($variant_id => {
						Ok($st::$variant_name(Readable::read(r)?))
					}),*
                    $($external_variant_id => {
						Ok($st::$external_variant_name($read_cb(r)?))
					}),*
                    $($simple_variant_id => {
						Ok($st::$simple_variant_name)
					}),*
					_ => {
						Err(DecodeError::UnknownRequiredFeature)
					},
                }
            }
        }
    };
}

impl_writeable_external!(Payout, payout, { (offer, writeable), (accept, writeable) });
impl_writeable_external!(EnumerationPayout, enum_payout, { (outcome, string), (payout, { cb_writeable, payout::write, payout::read} )});
impl_writeable_external!(TxInputInfo, tx_input_info, { (outpoint, writeable), (max_witness_len, usize), (redeem_script, writeable), (serial_id, writeable)});
impl_writeable_external!(PartyParams, party_params, {
    (fund_pubkey, writeable),
    (change_script_pubkey, writeable),
    (change_serial_id, writeable),
    (payout_script_pubkey, writeable),
    (payout_serial_id, writeable),
    (inputs, { vec_cb, tx_input_info::write, tx_input_info::read }),
    (input_amount, writeable),
    (collateral, writeable)
});

impl_writeable_custom!(PayoutPoint, { (event_outcome, writeable), (outcome_payout, writeable), (extra_precision, writeable) });
impl_writeable_custom_enum!(
    PayoutFunctionPiece,
    (0, PolynomialPayoutCurvePiece),
    (1, HyperbolaPayoutCurvePiece);;
);
impl_writeable_custom!(RoundingInterval, { (begin_interval, writeable), (rounding_mod, writeable) });
impl_writeable_custom!(PayoutFunction, { (payout_function_pieces, vec) });
impl_writeable_custom!(NumericalDescriptor, { (payout_function, writeable), (rounding_intervals, writeable), (info, writeable), (difference_params, option) });
impl_writeable_custom!(PolynomialPayoutCurvePiece, { (payout_points, vec) });
impl_writeable_custom!(RoundingIntervals, { (intervals, vec) });
impl_writeable_custom!(NumericalEventInfo, { (base, usize), (nb_digits, usize), (unit, string) });
impl_writeable_custom!(DifferenceParams, { (max_error_exp, usize), (min_support_exp, usize), (maximize_coverage, writeable) });
impl_writeable_custom!(HyperbolaPayoutCurvePiece, {
    (left_end_point, writeable),
    (right_end_point, writeable),
    (use_positive_piece, writeable),
    (translate_outcome, float),
    (translate_payout, float),
    (a, float),
    (b, float),
    (c, float),
    (d, float)
});
impl_writeable_custom_enum!(ContractDescriptor, (0, Enum), (1, Numerical);;);
impl_writeable_custom!(ContractInfo, { (contract_descriptor, writeable), (oracle_announcements, vec), (threshold, usize)});
impl_writeable_custom!(FundingInputInfo, { (funding_input, writeable), (address, {option_cb, write_address, read_address}) });
impl_writeable_custom!(EnumDescriptor, {
    (
        outcome_payouts,
        {vec_cb, enum_payout::write, enum_payout::read}
    )
});
impl_writeable_custom!(OfferedContract, {
    (id, writeable),
    (is_offer_party, writeable),
    (contract_info, vec),
    (offer_params, { cb_writeable, party_params::write, party_params::read }),
    (total_collateral, writeable),
    (funding_inputs_info, vec),
    (fund_output_serial_id, writeable),
    (fee_rate_per_vb, writeable),
    (contract_maturity_bound, writeable),
    (contract_timeout, writeable)
});
impl_writeable_external!(RangeInfo, range_info, { (cet_index, usize), (adaptor_index, usize)});
impl_writeable_custom_enum!(AdaptorInfo,; (0, Numerical, write_multi_oracle_trie, read_multi_oracle_trie), (1, NumericalWithDifference, write_multi_oracle_trie_with_diff, read_multi_oracle_trie_with_diff); (2, Enum));
impl_writeable_external!(
    DlcTransactions, dlc_transactions,
    { (fund, writeable),
    (cets, vec),
    (refund, writeable),
    (funding_script_pubkey, writeable) }
);
impl_writeable_custom!(AcceptedContract, {
    (offered_contract, writeable),
    (accept_params, { cb_writeable, party_params::write, party_params::read }),
    (funding_inputs, vec),
    (adaptor_infos, vec),
    (adaptor_signatures, {option_cb, write_ecdsa_adaptor_signatures, read_ecdsa_adaptor_signatures }),
    (accept_refund_signature, writeable),
    (dlc_transactions, {cb_writeable, dlc_transactions::write, dlc_transactions::read })
});
impl_writeable_custom!(SignedContract, {
    (accepted_contract, writeable),
    (adaptor_signatures, {option_cb, write_ecdsa_adaptor_signatures, read_ecdsa_adaptor_signatures }),
    (offer_refund_signature, writeable),
    (funding_signatures, writeable)
});
impl_writeable_custom!(ClosedContract, {
    (signed_contract, writeable),
    (attestations, vec),
    (cet_index, usize)
});
impl_writeable_custom!(FailedAcceptContract, {(offered_contract, writeable), (accept_message, writeable), (error_message, string)});
impl_writeable_custom!(FailedSignContract, {(accepted_contract, writeable), (sign_message, writeable), (error_message, string)});

impl_writeable_external!(DigitTrieDump<Vec<RangeInfo> >, digit_trie_dump_vec_range, { (node_data, {vec_cb, write_digit_node_data_vec_range, read_digit_node_data_vec_range}), (root, {option_cb, write_usize, read_usize}), (base, usize)});
impl_writeable_external!(DigitTrieDump<RangeInfo>, digit_trie_dump_range, { (node_data, {vec_cb, write_digit_node_data_range, read_digit_node_data_range}), (root, {option_cb, write_usize, read_usize}), (base, usize)});
impl_writeable_external!(DigitTrieDump<Vec<TrieNodeInfo> >, digit_trie_dump_trie, { (node_data, {vec_cb, write_digit_node_data_trie, read_digit_node_data_trie}), (root, {option_cb, write_usize, read_usize}), (base, usize)});
impl_writeable_external!(MultiOracleTrieDump, multi_oracle_trie_dump, { (digit_trie_dump, {cb_writeable, digit_trie_dump_vec_range::write, digit_trie_dump_vec_range::read}), (nb_oracles, usize), (threshold, usize), (nb_digits, usize) });
impl_writeable_external_enum!(
    MultiTrieNodeData<RangeInfo>,
    multi_trie_node_data,
    (0, Leaf, digit_trie_dump_range),
    (1, Node, digit_trie_dump_trie)
);
impl_writeable_external!(MultiTrieDump<RangeInfo>, multi_trie_dump, { (node_data, {vec_cb, multi_trie_node_data::write, multi_trie_node_data::read}), (base, usize), (nb_tries, usize), (nb_required, usize), (min_support_exp, usize), (max_error_exp, usize), (nb_digits, usize), (maximize_coverage, writeable) });
impl_writeable_external!(MultiOracleTrieWithDiffDump, multi_oracle_trie_with_diff_dump, { (multi_trie_dump, {cb_writeable, multi_trie_dump::write, multi_trie_dump::read}), (base, usize), (nb_digits, usize) });
impl_writeable_external!(TrieNodeInfo, trie_node_info, { (trie_index, usize), (store_index, usize) });

fn write_digit_node_data_trie<W: Writer>(
    input: &DigitNodeData<Vec<TrieNodeInfo>>,
    writer: &mut W,
) -> Result<(), ::std::io::Error> {
    let cb = |x: &Vec<TrieNodeInfo>, writer: &mut W| -> Result<(), ::std::io::Error> {
        write_vec_cb(x, writer, &trie_node_info::write)
    };
    write_digit_node_data(input, writer, &cb)
}

fn read_digit_node_data_trie<R: Read>(
    reader: &mut R,
) -> Result<DigitNodeData<Vec<TrieNodeInfo>>, DecodeError> {
    let cb = |reader: &mut R| -> Result<Vec<TrieNodeInfo>, DecodeError> {
        read_vec_cb(reader, &trie_node_info::read)
    };
    read_digit_node_data(reader, &cb)
}

fn write_digit_node_data_range<W: Writer>(
    input: &DigitNodeData<RangeInfo>,
    writer: &mut W,
) -> Result<(), ::std::io::Error> {
    write_digit_node_data(input, writer, &range_info::write)
}

fn read_digit_node_data_range<R: Read>(
    reader: &mut R,
) -> Result<DigitNodeData<RangeInfo>, DecodeError> {
    read_digit_node_data(reader, &range_info::read)
}

fn write_digit_node_data_vec_range<W: Writer>(
    input: &DigitNodeData<Vec<RangeInfo>>,
    writer: &mut W,
) -> Result<(), ::std::io::Error> {
    let cb = |x: &Vec<RangeInfo>, writer: &mut W| -> Result<(), ::std::io::Error> {
        write_vec_cb(x, writer, &range_info::write)
    };
    write_digit_node_data(input, writer, &cb)
}

fn read_digit_node_data_vec_range<R: Read>(
    reader: &mut R,
) -> Result<DigitNodeData<Vec<RangeInfo>>, DecodeError> {
    let cb = |reader: &mut R| -> Result<Vec<RangeInfo>, DecodeError> {
        read_vec_cb(reader, &range_info::read)
    };
    read_digit_node_data(reader, &cb)
}

fn write_digit_node_data<W: Writer, T, F>(
    input: &DigitNodeData<T>,
    writer: &mut W,
    cb: &F,
) -> Result<(), ::std::io::Error>
where
    F: Fn(&T, &mut W) -> Result<(), ::std::io::Error>,
{
    write_option_cb(&input.data, writer, &cb)?;
    write_vec_cb(&input.prefix, writer, &write_usize)?;
    let cb = |x: &Vec<Option<usize>>, writer: &mut W| -> Result<(), ::std::io::Error> {
        let cb = |y: &Option<usize>, writer: &mut W| -> Result<(), ::std::io::Error> {
            write_option_cb(&y, writer, &write_usize)
        };
        write_vec_cb(&x, writer, &cb)
    };
    write_option_cb(&input.children, writer, &cb)
}

fn read_digit_node_data<R: Read, T, F>(
    reader: &mut R,
    cb: &F,
) -> Result<DigitNodeData<T>, DecodeError>
where
    F: Fn(&mut R) -> Result<T, DecodeError>,
{
    let cb1 = |reader: &mut R| -> Result<T, DecodeError> { cb(reader) };
    let cb = |reader: &mut R| -> Result<Vec<Option<usize>>, DecodeError> {
        let cb = |reader: &mut R| -> Result<Option<usize>, DecodeError> {
            read_option_cb(reader, &read_usize)
        };
        read_vec_cb(reader, &cb)
    };

    Ok(DigitNodeData {
        data: read_option_cb(reader, &cb1)?,
        prefix: read_vec_cb(reader, &read_usize)?,
        children: read_option_cb(reader, &cb)?,
    })
}

fn write_multi_oracle_trie<W: Writer>(
    trie: &MultiOracleTrie,
    w: &mut W,
) -> Result<(), ::std::io::Error> {
    multi_oracle_trie_dump::write(&trie.dump(), w)
}

fn read_multi_oracle_trie<R: Read>(reader: &mut R) -> Result<MultiOracleTrie, DecodeError> {
    let dump = multi_oracle_trie_dump::read(reader)?;
    Ok(MultiOracleTrie::from_dump(dump))
}

fn write_multi_oracle_trie_with_diff<W: Writer>(
    trie: &MultiOracleTrieWithDiff,
    w: &mut W,
) -> Result<(), ::std::io::Error> {
    multi_oracle_trie_with_diff_dump::write(&trie.dump(), w)
}

fn read_multi_oracle_trie_with_diff<R: Read>(
    reader: &mut R,
) -> Result<MultiOracleTrieWithDiff, DecodeError> {
    let dump = multi_oracle_trie_with_diff_dump::read(reader)?;
    Ok(MultiOracleTrieWithDiff::from_dump(dump))
}
