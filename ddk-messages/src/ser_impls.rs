//! Set of utility functions to help with serialization.

use bitcoin::Address;
use bitcoin::Network;
use ddk_dlc::{EnumerationPayout, PartyParams, Payout, TxInputInfo};
use lightning::io::Read;
use lightning::ln::msgs::DecodeError;
use lightning::ln::wire::Type;
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::{ffi::ECDSA_ADAPTOR_SIGNATURE_LENGTH, EcdsaAdaptorSignature};
use std::collections::HashMap;
use std::hash::Hash;

const MAX_VEC_SIZE: u64 = 1000000;

/// Taken from rust-lightning: <https://github.com/rust-bitcoin/rust-lightning/blob/v0.0.101/lightning/src/util/ser.rs#L295>
///
/// Lightning TLV uses a custom variable-length integer called BigSize. It is similar to Bitcoin's
/// variable-length integers except that it is serialized in big-endian instead of little-endian.
///
/// Like Bitcoin's variable-length integer, it exhibits ambiguity in that certain values can be
/// encoded in several different ways, which we must check for at deserialization-time. Thus, if
/// you're looking for an example of a variable-length integer to use for your own project, move
/// along, this is a rather poor design.
pub struct BigSize(pub u64);
impl Writeable for BigSize {
    #[inline]
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        match self.0 {
            0..=0xFC => (self.0 as u8).write(writer),
            0xFD..=0xFFFF => {
                0xFDu8.write(writer)?;
                (self.0 as u16).write(writer)
            }
            0x10000..=0xFFFFFFFF => {
                0xFEu8.write(writer)?;
                (self.0 as u32).write(writer)
            }
            _ => {
                0xFFu8.write(writer)?;
                self.0.write(writer)
            }
        }
    }
}
impl Readable for BigSize {
    #[inline]
    fn read<R: Read>(reader: &mut R) -> Result<BigSize, DecodeError> {
        let n: u8 = Readable::read(reader)?;
        match n {
            0xFF => {
                let x: u64 = Readable::read(reader)?;
                if x < 0x100000000 {
                    Err(DecodeError::InvalidValue)
                } else {
                    Ok(BigSize(x))
                }
            }
            0xFE => {
                let x: u32 = Readable::read(reader)?;
                if x < 0x10000 {
                    Err(DecodeError::InvalidValue)
                } else {
                    Ok(BigSize(x as u64))
                }
            }
            0xFD => {
                let x: u16 = Readable::read(reader)?;
                if x < 0xFD {
                    Err(DecodeError::InvalidValue)
                } else {
                    Ok(BigSize(x as u64))
                }
            }
            n => Ok(BigSize(n as u64)),
        }
    }
}

/// Writes a given string to the given writer, prefixing the string length as
/// a BigSize value.
pub fn write_string<W: Writer>(input: &str, writer: &mut W) -> Result<(), lightning::io::Error> {
    let len = BigSize(input.len() as u64);
    len.write(writer)?;
    let bytes = input.as_bytes();

    for b in bytes {
        b.write(writer)?;
    }

    Ok(())
}

/// Reads a string from the given reader.
pub fn read_string<R: Read>(reader: &mut R) -> Result<String, DecodeError> {
    let len: BigSize = Readable::read(reader)?;

    if len.0 > MAX_VEC_SIZE {
        return Err(DecodeError::InvalidValue);
    }

    let mut buf = Vec::with_capacity(len.0 as usize);

    for _ in 0..len.0 {
        let b: u8 = Readable::read(reader)?;
        buf.push(b);
    }

    let res = match String::from_utf8(buf) {
        Ok(s) => s,
        Err(_) => return Err(DecodeError::InvalidValue),
    };

    Ok(res)
}

/// Writes a set of strings to the given writer.
pub fn write_strings<W: Writer>(
    inputs: &[String],
    writer: &mut W,
) -> Result<(), lightning::io::Error> {
    BigSize(inputs.len() as u64).write(writer)?;
    for s in inputs {
        write_string(s, writer)?;
    }

    Ok(())
}

/// Reads a set of strings from the given reader.
pub fn read_strings<R: Read>(reader: &mut R) -> Result<Vec<String>, DecodeError> {
    let len: BigSize = lightning::util::ser::Readable::read(reader)?;
    if len.0 > MAX_VEC_SIZE {
        return Err(DecodeError::InvalidValue);
    }
    let mut res = Vec::<String>::new();
    for _ in 0..len.0 {
        res.push(read_string(reader)?);
    }

    Ok(res)
}

/// Writes a set of strings to the given writer, using `u16` prefixes, compared
/// to [`write_strings`] which uses `BigSize` prefixes.
pub fn write_strings_u16<W: Writer>(
    inputs: &[String],
    writer: &mut W,
) -> Result<(), lightning::io::Error> {
    (inputs.len() as u16).write(writer)?;
    for s in inputs {
        write_string(s, writer)?;
    }

    Ok(())
}

/// Reads a set of string from the given reader, assuming `u16` prefixes, compared
/// to [`read_strings`] which assumes `BigSize` prefixes.
pub fn read_strings_u16<R: Read>(
    reader: &mut R,
) -> Result<Vec<String>, lightning::ln::msgs::DecodeError> {
    let len: u16 = lightning::util::ser::Readable::read(reader)?;
    let mut res = Vec::<String>::new();
    for _ in 0..len {
        res.push(read_string(reader)?);
    }

    Ok(res)
}

/// Writes an `f64` value to the given writer.
pub fn write_f64<W: lightning::util::ser::Writer>(
    input: f64,
    writer: &mut W,
) -> Result<(), ::lightning::io::Error> {
    for b in input.to_be_bytes() {
        b.write(writer)?;
    }

    Ok(())
}

/// Reads an `f64` value from the given reader.
pub fn read_f64<R: ::lightning::io::Read>(
    reader: &mut R,
) -> Result<f64, lightning::ln::msgs::DecodeError> {
    let mut buf = [0u8; 8];
    for b in &mut buf {
        *b = Readable::read(reader)?;
    }
    Ok(f64::from_be_bytes(buf))
}

/// Writes a [`secp256k1_zkp::schnorrsig::Signature`] value to the given writer.
pub fn write_schnorrsig<W: lightning::util::ser::Writer>(
    signature: &secp256k1_zkp::schnorr::Signature,
    writer: &mut W,
) -> Result<(), ::lightning::io::Error> {
    signature.as_ref().write(writer)
}

/// Reads a [`secp256k1_zkp::schnorrsig::Signature`] value from the given reader.
pub fn read_schnorrsig<R: ::lightning::io::Read>(
    reader: &mut R,
) -> Result<secp256k1_zkp::schnorr::Signature, lightning::ln::msgs::DecodeError> {
    let buf: [u8; 64] = Readable::read(reader)?;
    match secp256k1_zkp::schnorr::Signature::from_slice(&buf) {
        Ok(sig) => Ok(sig),
        Err(_) => Err(lightning::ln::msgs::DecodeError::InvalidValue),
    }
}

/// Writes a set of [`secp256k1_zkp::schnorrsig::Signature`] to the given writer.
pub fn write_schnorr_signatures<W: lightning::util::ser::Writer>(
    signatures: &[secp256k1_zkp::schnorr::Signature],
    writer: &mut W,
) -> Result<(), ::lightning::io::Error> {
    (signatures.len() as u16).write(writer)?;
    for signature in signatures {
        write_schnorrsig(signature, writer)?;
    }
    Ok(())
}

/// Reads a set of [`secp256k1_zkp::schnorrsig::Signature`] from the given reader.
pub fn read_schnorr_signatures<R: Read>(
    reader: &mut R,
) -> Result<Vec<secp256k1_zkp::schnorr::Signature>, lightning::ln::msgs::DecodeError> {
    let len: u16 = Readable::read(reader)?;
    let byte_size = (len as usize)
        .checked_mul(secp256k1_zkp::constants::SCHNORR_SIGNATURE_SIZE)
        .ok_or(lightning::ln::msgs::DecodeError::BadLengthDescriptor)?;
    if byte_size > lightning::util::ser::MAX_BUF_SIZE {
        return Err(lightning::ln::msgs::DecodeError::BadLengthDescriptor);
    }
    let mut ret = Vec::with_capacity(len as usize);
    for _ in 0..len {
        ret.push(read_schnorrsig(reader)?);
    }
    Ok(ret)
}

/// Writes a schnorr public key to the given writer.
pub fn write_schnorr_pubkey<W: lightning::util::ser::Writer>(
    pubkey: &secp256k1_zkp::XOnlyPublicKey,
    writer: &mut W,
) -> Result<(), ::lightning::io::Error> {
    pubkey.serialize().write(writer)
}

/// Reads a schnorr public key from the given reader.
pub fn read_schnorr_pubkey<R: ::lightning::io::Read>(
    reader: &mut R,
) -> Result<secp256k1_zkp::XOnlyPublicKey, lightning::ln::msgs::DecodeError> {
    let buf: [u8; 32] = Readable::read(reader)?;
    match secp256k1_zkp::XOnlyPublicKey::from_slice(&buf) {
        Ok(sig) => Ok(sig),
        Err(_) => Err(lightning::ln::msgs::DecodeError::InvalidValue),
    }
}

/// Writes a set of schnorr public keys to the given writer.
pub fn write_schnorr_pubkeys<W: Writer>(
    pubkeys: &[secp256k1_zkp::XOnlyPublicKey],
    writer: &mut W,
) -> Result<(), ::lightning::io::Error> {
    (pubkeys.len() as u16).write(writer)?;
    for pubkey in pubkeys {
        write_schnorr_pubkey(pubkey, writer)?;
    }
    Ok(())
}

/// Reads a set of schnorr public keys from the given reader.
pub fn read_schnorr_pubkeys<R: ::lightning::io::Read>(
    reader: &mut R,
) -> Result<Vec<secp256k1_zkp::XOnlyPublicKey>, DecodeError> {
    let len: u16 = Readable::read(reader)?;
    let byte_size = (len as usize)
        .checked_mul(secp256k1_zkp::constants::SCHNORR_PUBLIC_KEY_SIZE)
        .ok_or(DecodeError::BadLengthDescriptor)?;
    if byte_size > lightning::util::ser::MAX_BUF_SIZE {
        return Err(DecodeError::BadLengthDescriptor);
    }
    let mut ret = Vec::with_capacity(len as usize);
    for _ in 0..len {
        ret.push(read_schnorr_pubkey(reader)?);
    }
    Ok(ret)
}

/// Writes a vector of writeable to the given writer.
pub fn write_vec<W: Writer, T>(input: &Vec<T>, writer: &mut W) -> Result<(), ::lightning::io::Error>
where
    T: Writeable,
{
    write_vec_cb(input, writer, &<T as Writeable>::write)
}

/// Reads a vector of writeable from the given reader.
pub fn read_vec<R: ::lightning::io::Read, T>(reader: &mut R) -> Result<Vec<T>, DecodeError>
where
    T: Readable,
{
    read_vec_cb(reader, &Readable::read)
}

/// Writes a vector of values to the given writer using the provided callback to
/// serialize each value.
pub fn write_vec_cb<W: Writer, T, F>(
    input: &Vec<T>,
    writer: &mut W,
    cb: &F,
) -> Result<(), ::lightning::io::Error>
where
    F: Fn(&T, &mut W) -> Result<(), ::lightning::io::Error>,
{
    BigSize(input.len() as u64).write(writer)?;
    for s in input {
        cb(s, writer)?;
    }
    Ok(())
}

/// Reads a vector of values from the given reader using the provided callback to
/// deserialize each value.
pub fn read_vec_cb<R: ::lightning::io::Read, T, F>(
    reader: &mut R,
    cb: &F,
) -> Result<Vec<T>, DecodeError>
where
    F: Fn(&mut R) -> Result<T, DecodeError>,
{
    let len: BigSize = Readable::read(reader)?;
    if len.0 > MAX_VEC_SIZE {
        return Err(DecodeError::InvalidValue);
    }
    let mut res = Vec::<T>::new();
    for _ in 0..len.0 {
        res.push(cb(reader)?);
    }

    Ok(res)
}

/// Writes a vector of values to the given writer. This function differs from
/// [`write_vec`] in that it uses `u16` prefixes to give the length of the vector
/// instead of a `BigSize`.
pub fn write_vec_u16<W: Writer, T>(
    input: &[T],
    writer: &mut W,
) -> Result<(), ::lightning::io::Error>
where
    T: Writeable,
{
    write_vec_u16_cb(input, writer, &<T as Writeable>::write)
}

/// Reads a vector of values from the given reader. This function differs from
/// [`read_vec`] in that it uses `u16` prefixes to read the length of the vector
/// instead of a `BigSize`.
pub fn read_vec_u16<R: ::lightning::io::Read, T>(reader: &mut R) -> Result<Vec<T>, DecodeError>
where
    T: Readable,
{
    read_vec_u16_cb(reader, &Readable::read)
}

/// Writes a vector of values to the given writer using the provided callback to
/// serialize each value. This function differs from [`write_vec_cb`] in that it
/// uses `u16` prefixes to give the length of the vector instead of a `BigSize`.
pub fn write_vec_u16_cb<W: Writer, T, F>(
    input: &[T],
    writer: &mut W,
    cb: &F,
) -> Result<(), ::lightning::io::Error>
where
    F: Fn(&T, &mut W) -> Result<(), ::lightning::io::Error>,
{
    (input.len() as u16).write(writer)?;
    for s in input {
        cb(s, writer)?;
    }
    Ok(())
}

/// Reads a vector of values from the given reader using the provided callback to
/// deserialize each value. This function differs from [`read_vec_cb`] in that it
/// uses `u16` prefixes to read the length of the vector instead of a `BigSize`.
pub fn read_vec_u16_cb<R: ::lightning::io::Read, T, F>(
    reader: &mut R,
    cb: &F,
) -> Result<Vec<T>, DecodeError>
where
    F: Fn(&mut R) -> Result<T, DecodeError>,
{
    let len: u16 = Readable::read(reader)?;
    let mut res = Vec::<T>::new();
    for _ in 0..len {
        res.push(cb(reader)?);
    }

    Ok(res)
}

/// Writes a usize value as a u64 to the given writer.
pub fn write_usize<W: Writer>(i: &usize, writer: &mut W) -> Result<(), ::lightning::io::Error> {
    <u64 as Writeable>::write(&(*i as u64), writer)
}

/// Reads a usize value as a u64 from the given reader.
pub fn read_usize<R: ::lightning::io::Read>(reader: &mut R) -> Result<usize, DecodeError> {
    let i: u64 = Readable::read(reader)?;
    Ok(i as usize)
}

/// Writes an option of a [`lightning::util::ser::Writeable`] value to the given writer.
pub fn write_option<W: Writer, T>(
    t: &Option<T>,
    writer: &mut W,
) -> Result<(), ::lightning::io::Error>
where
    T: Writeable,
{
    write_option_cb(t, writer, &<T as Writeable>::write)
}

/// Reads an option of a [`lightning::util::ser::Writeable`] value from the given reader.
pub fn read_option<R: ::lightning::io::Read, T>(reader: &mut R) -> Result<Option<T>, DecodeError>
where
    T: Readable,
{
    read_option_cb(reader, &<T as Readable>::read)
}

/// Writes an option using the provided callback to serialize the inner value (if any).
pub fn write_option_cb<W: Writer, T, F>(
    t: &Option<T>,
    writer: &mut W,
    cb: &F,
) -> Result<(), ::lightning::io::Error>
where
    F: Fn(&T, &mut W) -> Result<(), ::lightning::io::Error>,
{
    match t {
        Some(t) => {
            1_u8.write(writer)?;
            cb(t, writer)
        }
        None => 0_u8.write(writer),
    }
}

/// Reads an option using the provided callback to deserialize the inner value (if any).
pub fn read_option_cb<R: ::lightning::io::Read, T, F>(
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

/// Writes a [`bitcoin::util::address::Address`] value to the given writer.
///
/// https://docs.rs/bitcoin/0.30.2/bitcoin/address/struct.Address.html
///
/// Parsed addresses do not always have one network. The problem is that legacy testnet, regtest and
/// signet addresse use the same prefix instead of multiple different ones. When parsing,
/// such addresses are always assumed to be testnet addresses (the same is true for bech32 signet addresses).
///
/// Only checks if the address is Mainnet.
pub fn write_address<W: Writer>(
    address: &Address,
    writer: &mut W,
) -> Result<(), ::lightning::io::Error> {
    address.script_pubkey().write(writer)?;
    let unchecked_address = address.as_unchecked();

    const NETWORKS: [Network; 4] = [
        Network::Bitcoin,
        Network::Testnet,
        Network::Signet,
        Network::Regtest,
    ];

    let mut net: u8 = 0;

    for (i, n) in NETWORKS.iter().enumerate() {
        if unchecked_address.is_valid_for_network(*n) {
            net = i as u8;
            break;
        }
    }

    net.write(writer)
}

/// Reads a [`bitcoin::util::address::Address`] value from the given reader.
pub fn read_address<R: Read>(reader: &mut R) -> Result<Address, DecodeError> {
    let script: bitcoin::ScriptBuf = Readable::read(reader)?;
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

/// Writes an [`secp256k1_zkp::EcdsaAdaptorSignature`] to the given writer.
pub fn write_ecdsa_adaptor_signature<W: Writer>(
    sig: &EcdsaAdaptorSignature,
    writer: &mut W,
) -> Result<(), ::lightning::io::Error> {
    for x in sig.as_ref() {
        x.write(writer)?;
    }
    Ok(())
}

/// Reads an [`secp256k1_zkp::EcdsaAdaptorSignature`] from the given reader.
pub fn read_ecdsa_adaptor_signature<R: ::lightning::io::Read>(
    reader: &mut R,
) -> Result<EcdsaAdaptorSignature, DecodeError> {
    let mut buf: Vec<u8> = Vec::with_capacity(ECDSA_ADAPTOR_SIGNATURE_LENGTH);

    for _ in 0..ECDSA_ADAPTOR_SIGNATURE_LENGTH {
        buf.push(Readable::read(reader)?);
    }
    EcdsaAdaptorSignature::from_slice(&buf).map_err(|_| DecodeError::InvalidValue)
}

/// Writes a set of [`secp256k1_zkp::EcdsaAdaptorSignature`] to the given writer.
#[allow(clippy::ptr_arg)] // Need to have Vec to work with callbacks.
pub fn write_ecdsa_adaptor_signatures<W: Writer>(
    sig: &Vec<EcdsaAdaptorSignature>,
    writer: &mut W,
) -> Result<(), ::lightning::io::Error> {
    write_vec_cb(sig, writer, &write_ecdsa_adaptor_signature)
}

/// Reads a set of [`secp256k1_zkp::EcdsaAdaptorSignature`] from the given reader.
pub fn read_ecdsa_adaptor_signatures<R: ::lightning::io::Read>(
    reader: &mut R,
) -> Result<Vec<EcdsaAdaptorSignature>, DecodeError> {
    read_vec_cb(reader, &read_ecdsa_adaptor_signature)
}

/// Writes an `i32` value to the given writer.
pub fn write_i32<W: Writer>(i: &i32, writer: &mut W) -> Result<(), ::lightning::io::Error> {
    i.to_be_bytes().write(writer)
}

/// Reads an `i32` value from the given reader.
pub fn read_i32<R: Read>(reader: &mut R) -> Result<i32, DecodeError> {
    let v: [u8; 4] = Readable::read(reader)?;
    Ok(i32::from_be_bytes(v))
}
/// Writes an `i64` value to the given writer.
pub fn write_i64<W: Writer>(i: &i64, writer: &mut W) -> Result<(), ::lightning::io::Error> {
    let i = i.to_be_bytes();
    for b in i {
        b.write(writer)?;
    }
    Ok(())
}

/// Reads an `i64` value from the given reader.
pub fn read_i64<R: ::lightning::io::Read>(reader: &mut R) -> Result<i64, DecodeError> {
    let mut v = [0u8; 8];
    for x in &mut v {
        *x = Readable::read(reader)?;
    }
    Ok(i64::from_be_bytes(v))
}

/// Writes a [`lightning::util::ser::Writeable`] value to the given writer as a TLV.
pub fn write_as_tlv<T: Type + Writeable, W: Writer>(
    e: &T,
    writer: &mut W,
) -> Result<(), ::lightning::io::Error> {
    BigSize(e.type_id() as u64).write(writer)?;
    BigSize(e.serialized_length() as u64).write(writer)?;
    e.write(writer)
}

/// Read a [`lightning::util::ser::Writeable`] value from the given reader as a TLV.
pub fn read_as_tlv<T: Type + Readable, R: Read>(reader: &mut R) -> Result<T, DecodeError> {
    // TODO(tibo): consider checking type here.
    // This retrieves type as BigSize. Will be u16 once specs are updated.
    let _: BigSize = Readable::read(reader)?;
    // This retrieves the length, will be removed once oracle specs are updated.
    let _: BigSize = Readable::read(reader)?;
    Readable::read(reader)
}

/// Writes a [`HashMap`].
pub fn write_hash_map<W: Writer, T, V>(
    input: &HashMap<T, V>,
    writer: &mut W,
) -> Result<(), lightning::io::Error>
where
    T: Writeable,
    V: Writeable,
{
    (input.len() as u64).write(writer)?;

    for (key, value) in input.iter() {
        key.write(writer)?;
        value.write(writer)?;
    }

    Ok(())
}

/// Reads a [`HashMap`].
pub fn read_hash_map<R: Read, T, V>(reader: &mut R) -> Result<HashMap<T, V>, DecodeError>
where
    T: Readable + Hash + Eq,
    V: Readable,
{
    let len: u64 = Readable::read(reader)?;
    let mut map = HashMap::new();
    for _ in 0..len {
        let key: T = Readable::read(reader)?;
        let value: V = Readable::read(reader)?;
        map.insert(key, value);
    }

    Ok(map)
}

impl_dlc_writeable_external!(Payout, payout, { (offer, writeable), (accept, writeable) });
impl_dlc_writeable_external!(EnumerationPayout, enum_payout, { (outcome, string), (payout, { cb_writeable, payout::write, payout::read} )});
impl_dlc_writeable_external!(TxInputInfo, tx_input_info, { (outpoint, writeable), (max_witness_len, usize), (redeem_script, writeable), (serial_id, writeable)});
impl_dlc_writeable_external!(PartyParams, party_params, {
    (fund_pubkey, writeable),
    (change_script_pubkey, writeable),
    (change_serial_id, writeable),
    (payout_script_pubkey, writeable),
    (payout_serial_id, writeable),
    (inputs, { vec_cb, tx_input_info::write, tx_input_info::read }),
    (input_amount, writeable),
    (collateral, writeable)
});

#[cfg(test)]
mod tests {
    use lightning::io::Cursor;

    use super::{read_f64, write_f64};

    #[test]
    fn f64_serialize_round_trip() {
        let original = 2.3;
        let mut ser = Vec::new();
        write_f64(original, &mut ser).unwrap();
        let deser = read_f64(&mut Cursor::new(&ser)).unwrap();

        assert_eq!(original, deser);
    }
}
