//! Serialization trait implementations for various data structures enabling them
//! to be converted to byte arrays.

use crate::contract::accepted_contract::AcceptedContract;
use crate::contract::contract_info::ContractInfo;
use crate::contract::enum_descriptor::EnumDescriptor;
use crate::contract::numerical_descriptor::{DifferenceParams, NumericalDescriptor};
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
use dlc::DlcTransactions;
use dlc_messages::ser_impls::{
    read_ecdsa_adaptor_signatures, read_option_cb, read_usize, read_vec_cb,
    write_ecdsa_adaptor_signatures, write_option_cb, write_usize, write_vec_cb,
};
use dlc_trie::digit_trie::{DigitNodeData, DigitTrieDump};
use dlc_trie::multi_oracle_trie::{MultiOracleTrie, MultiOracleTrieDump};
use dlc_trie::multi_oracle_trie_with_diff::{MultiOracleTrieWithDiff, MultiOracleTrieWithDiffDump};
use dlc_trie::multi_trie::{MultiTrieDump, MultiTrieNodeData, TrieNodeInfo};
use dlc_trie::{OracleNumericInfo, RangeInfo};
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{Readable, Writeable, Writer};
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

impl_dlc_writeable!(PayoutPoint, { (event_outcome, writeable), (outcome_payout, writeable), (extra_precision, writeable) });
impl_dlc_writeable_enum!(
    PayoutFunctionPiece,
    (0, PolynomialPayoutCurvePiece),
    (1, HyperbolaPayoutCurvePiece);;
);
impl_dlc_writeable!(RoundingInterval, { (begin_interval, writeable), (rounding_mod, writeable) });
impl_dlc_writeable!(PayoutFunction, { (payout_function_pieces, vec) });
impl_dlc_writeable!(NumericalDescriptor, { (payout_function, writeable), (rounding_intervals, writeable), (difference_params, option), (oracle_numeric_infos, {cb_writeable, oracle_params::write, oracle_params::read}) });
impl_dlc_writeable!(PolynomialPayoutCurvePiece, { (payout_points, vec) });
impl_dlc_writeable!(RoundingIntervals, { (intervals, vec) });
impl_dlc_writeable!(DifferenceParams, { (max_error_exp, usize), (min_support_exp, usize), (maximize_coverage, writeable) });
impl_dlc_writeable!(HyperbolaPayoutCurvePiece, {
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
impl_dlc_writeable_enum!(ContractDescriptor, (0, Enum), (1, Numerical);;);
impl_dlc_writeable!(ContractInfo, { (contract_descriptor, writeable), (oracle_announcements, vec), (threshold, usize)});
impl_dlc_writeable!(FundingInputInfo, { (funding_input, writeable), (address, {option_cb, dlc_messages::ser_impls::write_address, dlc_messages::ser_impls::read_address}) });
impl_dlc_writeable!(EnumDescriptor, {
    (
        outcome_payouts,
        {vec_cb, dlc_messages::ser_impls::enum_payout::write, dlc_messages::ser_impls::enum_payout::read}
    )
});
impl_dlc_writeable!(OfferedContract, {
    (id, writeable),
    (is_offer_party, writeable),
    (contract_info, vec),
    (offer_params, { cb_writeable, dlc_messages::ser_impls::party_params::write, dlc_messages::ser_impls::party_params::read }),
    (total_collateral, writeable),
    (funding_inputs_info, vec),
    (fund_output_serial_id, writeable),
    (fee_rate_per_vb, writeable),
    (contract_maturity_bound, writeable),
    (contract_timeout, writeable),
    (counter_party, writeable)
});
impl_dlc_writeable_external!(RangeInfo, range_info, { (cet_index, usize), (adaptor_index, usize)});
impl_dlc_writeable_enum!(AdaptorInfo,; (0, Numerical, write_multi_oracle_trie, read_multi_oracle_trie), (1, NumericalWithDifference, write_multi_oracle_trie_with_diff, read_multi_oracle_trie_with_diff); (2, Enum));
impl_dlc_writeable_external!(
    DlcTransactions, dlc_transactions,
    { (fund, writeable),
    (cets, vec),
    (refund, writeable),
    (funding_script_pubkey, writeable) }
);
impl_dlc_writeable!(AcceptedContract, {
    (offered_contract, writeable),
    (accept_params, { cb_writeable, dlc_messages::ser_impls::party_params::write, dlc_messages::ser_impls::party_params::read }),
    (funding_inputs, vec),
    (adaptor_infos, vec),
    (adaptor_signatures, {option_cb, write_ecdsa_adaptor_signatures, read_ecdsa_adaptor_signatures }),
    (accept_refund_signature, writeable),
    (dlc_transactions, {cb_writeable, dlc_transactions::write, dlc_transactions::read })
});
impl_dlc_writeable!(SignedContract, {
    (accepted_contract, writeable),
    (adaptor_signatures, {option_cb, write_ecdsa_adaptor_signatures, read_ecdsa_adaptor_signatures }),
    (offer_refund_signature, writeable),
    (funding_signatures, writeable)
});
impl_dlc_writeable!(ClosedContract, {
    (signed_contract, writeable),
    (attestations, vec),
    (signed_cet, writeable)
});
impl_dlc_writeable!(FailedAcceptContract, {(offered_contract, writeable), (accept_message, writeable), (error_message, string)});
impl_dlc_writeable!(FailedSignContract, {(accepted_contract, writeable), (sign_message, writeable), (error_message, string)});

impl_dlc_writeable_external!(DigitTrieDump<Vec<RangeInfo> >, digit_trie_dump_vec_range, { (node_data, {vec_cb, write_digit_node_data_vec_range, read_digit_node_data_vec_range}), (root, {option_cb, write_usize, read_usize}), (base, usize)});
impl_dlc_writeable_external!(DigitTrieDump<RangeInfo>, digit_trie_dump_range, { (node_data, {vec_cb, write_digit_node_data_range, read_digit_node_data_range}), (root, {option_cb, write_usize, read_usize}), (base, usize)});
impl_dlc_writeable_external!(DigitTrieDump<Vec<TrieNodeInfo> >, digit_trie_dump_trie, { (node_data, {vec_cb, write_digit_node_data_trie, read_digit_node_data_trie}), (root, {option_cb, write_usize, read_usize}), (base, usize)});
impl_dlc_writeable_external!(MultiOracleTrieDump, multi_oracle_trie_dump, { (digit_trie_dump, {cb_writeable, digit_trie_dump_vec_range::write, digit_trie_dump_vec_range::read}), (threshold, usize), (oracle_numeric_infos, {cb_writeable, oracle_params::write, oracle_params::read}), (extra_cover_trie_dump, {option_cb, multi_trie_dump::write, multi_trie_dump::read}) });
impl_dlc_writeable_external!(OracleNumericInfo, oracle_params, { (base, usize), (nb_digits, {vec_cb, write_usize, read_usize}) });
impl_dlc_writeable_external_enum!(
    MultiTrieNodeData<RangeInfo>,
    multi_trie_node_data,
    (0, Leaf, digit_trie_dump_range),
    (1, Node, digit_trie_dump_trie)
);
impl_dlc_writeable_external!(MultiTrieDump<RangeInfo>, multi_trie_dump, { (node_data, {vec_cb, multi_trie_node_data::write, multi_trie_node_data::read}), (nb_tries, usize), (nb_required, usize), (min_support_exp, usize), (max_error_exp, usize), (maximize_coverage, writeable), (oracle_numeric_infos, {cb_writeable, oracle_params::write, oracle_params::read}) });
impl_dlc_writeable_external!(MultiOracleTrieWithDiffDump, multi_oracle_trie_with_diff_dump, { (multi_trie_dump, {cb_writeable, multi_trie_dump::write, multi_trie_dump::read}), (oracle_numeric_infos, {cb_writeable, oracle_params::write, oracle_params::read}) });
impl_dlc_writeable_external!(TrieNodeInfo, trie_node_info, { (trie_index, usize), (store_index, usize) });

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
            write_option_cb(y, writer, &write_usize)
        };
        write_vec_cb(x, writer, &cb)
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
