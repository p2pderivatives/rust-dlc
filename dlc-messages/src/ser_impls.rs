use bitcoin::network::constants::Network;
use bitcoin::Address;
use dlc::{EnumerationPayout, PartyParams, Payout, TxInputInfo};
use lightning::ln::msgs::DecodeError;
use lightning::ln::wire::Type;
use lightning::util::ser::{Readable, Writeable, Writer};
use secp256k1_zkp::{ffi::ECDSA_ADAPTOR_SIGNATURE_LENGTH, EcdsaAdaptorSignature};
use std::convert::TryInto;
use std::io::Read;

const MAX_VEC_SIZE: u64 = 1000000;

/// Taken from rust-lightning: https://github.com/rust-bitcoin/rust-lightning/blob/v0.0.101/lightning/src/util/ser.rs#L295
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
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ::std::io::Error> {
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
                (self.0 as u64).write(writer)
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

pub fn write_string<W: Writer>(input: &str, writer: &mut W) -> Result<(), ::std::io::Error> {
    let len = BigSize(input.len() as u64);
    len.write(writer)?;
    let bytes = input.as_bytes();

    for b in bytes {
        b.write(writer)?;
    }

    Ok(())
}

pub fn read_string<R: ::std::io::Read>(reader: &mut R) -> Result<String, DecodeError> {
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

pub fn write_strings<W: Writer>(inputs: &[String], writer: &mut W) -> Result<(), ::std::io::Error> {
    BigSize(inputs.len() as u64).write(writer)?;
    for s in inputs {
        write_string(s, writer)?;
    }

    Ok(())
}

pub fn read_strings<R: ::std::io::Read>(
    reader: &mut R,
) -> Result<Vec<String>, lightning::ln::msgs::DecodeError> {
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

pub fn write_strings_u16<W: Writer>(
    inputs: &[String],
    writer: &mut W,
) -> Result<(), ::std::io::Error> {
    (inputs.len() as u16).write(writer)?;
    for s in inputs {
        write_string(s, writer)?;
    }

    Ok(())
}

pub fn read_strings_u16<R: ::std::io::Read>(
    reader: &mut R,
) -> Result<Vec<String>, lightning::ln::msgs::DecodeError> {
    let len: u16 = lightning::util::ser::Readable::read(reader)?;
    let mut res = Vec::<String>::new();
    for _ in 0..len {
        res.push(read_string(reader)?);
    }

    Ok(res)
}

pub fn write_f64<W: lightning::util::ser::Writer>(
    input: f64,
    writer: &mut W,
) -> Result<(), ::std::io::Error> {
    let sign = input >= 0.0;
    sign.write(writer)?;
    let input_abs = f64::abs(input);
    let no_precision = f64::floor(input_abs);
    BigSize(no_precision as u64).write(writer)?;
    let extra_precision = f64::floor((input_abs - no_precision) * ((1 << 16) as f64)) as u16;
    extra_precision.write(writer)
}

pub fn read_f64<R: ::std::io::Read>(
    reader: &mut R,
) -> Result<f64, lightning::ln::msgs::DecodeError> {
    let sign: bool = Readable::read(reader)?;
    let no_precision_bs: BigSize = Readable::read(reader)?;
    let no_precision = no_precision_bs.0 as f64;
    let extra_precision: u16 = Readable::read(reader)?;
    let mul_sign: f64 = if sign { 1.0 } else { -1.0 };

    Ok(((no_precision) + ((extra_precision as f64) / ((1 << 16) as f64))) * mul_sign)
}

pub fn write_schnorrsig<W: lightning::util::ser::Writer>(
    signature: &secp256k1_zkp::schnorrsig::Signature,
    writer: &mut W,
) -> Result<(), ::std::io::Error> {
    signature.as_ref().write(writer)
}

pub fn read_schnorrsig<R: ::std::io::Read>(
    reader: &mut R,
) -> Result<secp256k1_zkp::schnorrsig::Signature, lightning::ln::msgs::DecodeError> {
    let buf: [u8; 64] = Readable::read(reader)?;
    match secp256k1_zkp::schnorrsig::Signature::from_slice(&buf) {
        Ok(sig) => Ok(sig),
        Err(_) => Err(lightning::ln::msgs::DecodeError::InvalidValue),
    }
}

pub fn write_schnorr_signatures<W: lightning::util::ser::Writer>(
    signatures: &[secp256k1_zkp::schnorrsig::Signature],
    writer: &mut W,
) -> Result<(), ::std::io::Error> {
    (signatures.len() as u16).write(writer)?;
    for signature in signatures {
        write_schnorrsig(signature, writer)?;
    }
    Ok(())
}

pub fn read_schnorr_signatures<R: ::std::io::Read>(
    reader: &mut R,
) -> Result<Vec<secp256k1_zkp::schnorrsig::Signature>, lightning::ln::msgs::DecodeError> {
    let len: u16 = Readable::read(reader)?;
    let byte_size = (len as usize)
        .checked_mul(secp256k1_zkp::constants::SCHNORRSIG_SIGNATURE_SIZE)
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

pub fn write_schnorr_pubkey<W: lightning::util::ser::Writer>(
    pubkey: &secp256k1_zkp::schnorrsig::PublicKey,
    writer: &mut W,
) -> Result<(), ::std::io::Error> {
    pubkey.serialize().write(writer)
}

pub fn read_schnorr_pubkey<R: ::std::io::Read>(
    reader: &mut R,
) -> Result<secp256k1_zkp::schnorrsig::PublicKey, lightning::ln::msgs::DecodeError> {
    let buf: [u8; 32] = Readable::read(reader)?;
    match secp256k1_zkp::schnorrsig::PublicKey::from_slice(&buf) {
        Ok(sig) => Ok(sig),
        Err(_) => Err(lightning::ln::msgs::DecodeError::InvalidValue),
    }
}

pub fn write_schnorr_pubkeys<W: Writer>(
    pubkeys: &[secp256k1_zkp::schnorrsig::PublicKey],
    writer: &mut W,
) -> Result<(), ::std::io::Error> {
    (pubkeys.len() as u16).write(writer)?;
    for pubkey in pubkeys {
        write_schnorr_pubkey(pubkey, writer)?;
    }
    Ok(())
}

pub fn read_schnorr_pubkeys<R: ::std::io::Read>(
    reader: &mut R,
) -> Result<Vec<secp256k1_zkp::schnorrsig::PublicKey>, DecodeError> {
    let len: u16 = Readable::read(reader)?;
    let byte_size = (len as usize)
        .checked_mul(secp256k1_zkp::constants::SCHNORRSIG_PUBLIC_KEY_SIZE)
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

pub fn write_vec<W: Writer, T>(input: &[T], writer: &mut W) -> Result<(), ::std::io::Error>
where
    T: Writeable,
{
    write_vec_cb(input, writer, &<T as Writeable>::write)
}

pub fn read_vec<R: ::std::io::Read, T>(reader: &mut R) -> Result<Vec<T>, DecodeError>
where
    T: Readable,
{
    read_vec_cb(reader, &Readable::read)
}

pub fn write_vec_cb<W: Writer, T, F>(
    input: &[T],
    writer: &mut W,
    cb: &F,
) -> Result<(), ::std::io::Error>
where
    F: Fn(&T, &mut W) -> Result<(), ::std::io::Error>,
{
    BigSize(input.len() as u64).write(writer)?;
    for s in input {
        cb(s, writer)?;
    }
    Ok(())
}

pub fn read_vec_cb<R: ::std::io::Read, T, F>(reader: &mut R, cb: &F) -> Result<Vec<T>, DecodeError>
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

pub fn write_vec_u16<W: Writer, T>(input: &[T], writer: &mut W) -> Result<(), ::std::io::Error>
where
    T: Writeable,
{
    write_vec_u16_cb(input, writer, &<T as Writeable>::write)
}

pub fn read_vec_u16<R: ::std::io::Read, T>(reader: &mut R) -> Result<Vec<T>, DecodeError>
where
    T: Readable,
{
    read_vec_u16_cb(reader, &Readable::read)
}

pub fn write_vec_u16_cb<W: Writer, T, F>(
    input: &[T],
    writer: &mut W,
    cb: &F,
) -> Result<(), ::std::io::Error>
where
    F: Fn(&T, &mut W) -> Result<(), ::std::io::Error>,
{
    (input.len() as u16).write(writer)?;
    for s in input {
        cb(s, writer)?;
    }
    Ok(())
}

pub fn read_vec_u16_cb<R: ::std::io::Read, T, F>(
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

pub fn write_usize<W: Writer>(i: &usize, writer: &mut W) -> Result<(), ::std::io::Error> {
    <u64 as Writeable>::write(&(*i as u64), writer)
}

pub fn read_usize<R: ::std::io::Read>(reader: &mut R) -> Result<usize, DecodeError> {
    let i: u64 = Readable::read(reader)?;
    Ok(i as usize)
}

pub fn write_option<W: Writer, T>(t: &Option<T>, writer: &mut W) -> Result<(), ::std::io::Error>
where
    T: Writeable,
{
    write_option_cb(t, writer, &<T as Writeable>::write)
}

pub fn read_option<R: ::std::io::Read, T>(reader: &mut R) -> Result<Option<T>, DecodeError>
where
    T: Readable,
{
    read_option_cb(reader, &<T as Readable>::read)
}

pub fn write_option_cb<W: Writer, T, F>(
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
            cb(t, writer)
        }
        None => 0_u8.write(writer),
    }
}

pub fn read_option_cb<R: ::std::io::Read, T, F>(
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

pub fn write_address<W: Writer>(address: &Address, writer: &mut W) -> Result<(), ::std::io::Error> {
    address.script_pubkey().write(writer)?;
    let net: u8 = match address.network {
        Network::Bitcoin => 0,
        Network::Testnet => 1,
        Network::Signet => 2,
        Network::Regtest => 3,
    };

    net.write(writer)
}

pub fn read_address<R: Read>(reader: &mut R) -> Result<Address, DecodeError> {
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

pub fn write_ecdsa_adaptor_signature<W: Writer>(
    sig: &EcdsaAdaptorSignature,
    writer: &mut W,
) -> Result<(), ::std::io::Error> {
    for x in sig.as_ref() {
        x.write(writer)?;
    }
    Ok(())
}

pub fn read_ecdsa_adaptor_signature<R: ::std::io::Read>(
    reader: &mut R,
) -> Result<EcdsaAdaptorSignature, DecodeError> {
    let mut buf: Vec<u8> = Vec::with_capacity(ECDSA_ADAPTOR_SIGNATURE_LENGTH);

    for _ in 0..ECDSA_ADAPTOR_SIGNATURE_LENGTH {
        buf.push(Readable::read(reader)?);
    }
    EcdsaAdaptorSignature::from_slice(&buf).map_err(|_| DecodeError::InvalidValue)
}

#[allow(clippy::ptr_arg)] // Need to have Vec to work with callbacks.
pub fn write_ecdsa_adaptor_signatures<W: Writer>(
    sig: &Vec<EcdsaAdaptorSignature>,
    writer: &mut W,
) -> Result<(), ::std::io::Error> {
    write_vec_cb(sig, writer, &write_ecdsa_adaptor_signature)
}

pub fn read_ecdsa_adaptor_signatures<R: ::std::io::Read>(
    reader: &mut R,
) -> Result<Vec<EcdsaAdaptorSignature>, DecodeError> {
    read_vec_cb(reader, &read_ecdsa_adaptor_signature)
}

pub fn write_i32<W: Writer>(i: &i32, writer: &mut W) -> Result<(), ::std::io::Error> {
    write_vec(&i.to_be_bytes().to_vec(), writer)
}

pub fn read_i32<R: ::std::io::Read>(reader: &mut R) -> Result<i32, DecodeError> {
    let v = read_vec(reader)?;
    Ok(i32::from_be_bytes(
        v.try_into().map_err(|_| DecodeError::InvalidValue)?,
    ))
}

pub fn write_as_tlv<T: Type + Writeable, W: Writer>(
    e: &T,
    writer: &mut W,
) -> Result<(), ::std::io::Error> {
    BigSize(e.type_id() as u64).write(writer)?;
    BigSize(e.serialized_length() as u64).write(writer)?;
    e.write(writer)
}

pub fn read_as_tlv<T: Type + Readable, R: ::std::io::Read>(
    reader: &mut R,
) -> Result<T, DecodeError> {
    // TODO(tibo): consider checking type here.
    // This retrieves type as BigSize. Will be u16 once specs are updated.
    let _: BigSize = Readable::read(reader)?;
    // This retrieves the length, will be removed once oracle specs are updated.
    let _: BigSize = Readable::read(reader)?;
    Readable::read(reader)
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
