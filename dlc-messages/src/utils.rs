use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{BigSize, Readable, Writeable, Writer};

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

pub fn write_strings<W: Writer>(
    inputs: &Vec<String>,
    writer: &mut W,
) -> Result<(), ::std::io::Error> {
    (inputs.len() as u16).write(writer)?;
    for s in inputs {
        write_string(&s, writer)?;
    }

    Ok(())
}

pub fn read_strings<R: ::std::io::Read>(
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
        Err(_) => return Err(lightning::ln::msgs::DecodeError::InvalidValue),
    }
}

pub fn write_schnorr_signatures<W: lightning::util::ser::Writer>(
    signatures: &Vec<secp256k1_zkp::schnorrsig::Signature>,
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
        Err(_) => return Err(lightning::ln::msgs::DecodeError::InvalidValue),
    }
}

pub fn write_schnorr_pubkeys<W: Writer>(
    pubkeys: &Vec<secp256k1_zkp::schnorrsig::PublicKey>,
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

pub fn write_vec<W: Writer, T>(input: &Vec<T>, writer: &mut W) -> Result<(), ::std::io::Error>
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
    input: &Vec<T>,
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

pub fn read_vec_cb<R: ::std::io::Read, T, F>(reader: &mut R, cb: &F) -> Result<Vec<T>, DecodeError>
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
