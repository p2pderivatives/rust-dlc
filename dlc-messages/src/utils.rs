use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{BigSize, Readable, Writeable, Writer};

pub(crate) fn write_string<W: Writer>(input: &str, writer: &mut W) -> Result<(), ::std::io::Error> {
    let len = BigSize(input.len() as u64);
    len.write(writer)?;
    let bytes = input.as_bytes();

    for b in bytes {
        b.write(writer)?;
    }

    Ok(())
}

pub(crate) fn read_string<R: ::std::io::Read>(reader: &mut R) -> Result<String, DecodeError> {
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

pub(crate) fn write_vec<W: Writer, T>(
    input: &Vec<T>,
    writer: &mut W,
) -> Result<(), ::std::io::Error>
where
    T: Writeable,
{
    (input.len() as u16).write(writer)?;
    for s in input {
        s.write(writer)?;
    }
    Ok(())
}

pub(crate) fn read_vec<R: ::std::io::Read, T>(reader: &mut R) -> Result<Vec<T>, DecodeError>
where
    T: Readable,
{
    let len: u16 = Readable::read(reader)?;
    let mut res = Vec::<T>::new();
    for _ in 0..len {
        res.push(Readable::read(reader)?);
    }

    Ok(res)
}
