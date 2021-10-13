use super::{
    read::{BorrowReader, Reader},
    BorrowDecode, Decode,
};
use crate::error::DecodeError;

pub struct Decoder<R> {
    reader: R,
}

impl<'de, R: Reader<'de>> Decoder<R> {
    pub fn new(reader: R) -> Decoder<R> {
        Decoder { reader }
    }

    pub fn into_reader(self) -> R {
        self.reader
    }

    fn read_bigsize(&mut self) -> Result<u64, DecodeError> {
        let mut s = self;
        let n: u8 = s.decode_u8()?;
        match n {
            0xFF => {
                let x: u64 = s.decode_u64()?;
                if x < 0x100000000 {
                    Err(DecodeError::InvalidBigSize)
                } else {
                    Ok(x)
                }
            }
            0xFE => {
                let x: u32 = s.decode_u32()?;
                if x < 0x10000 {
                    Err(DecodeError::InvalidBigSize)
                } else {
                    Ok(x as u64)
                }
            }
            0xFD => {
                let x: u16 = s.decode_u16()?;
                if x < 0xFD {
                    Err(DecodeError::InvalidBigSize)
                } else {
                    Ok(x as u64)
                }
            }
            n => Ok(n as u64),
        }
    }
}

impl<'a, 'de, R: BorrowReader<'de>> BorrowDecode<'de> for &'a mut Decoder<R> {
    fn decode_slice(&mut self, len: usize) -> Result<&'de [u8], DecodeError> {
        self.reader.take_bytes(len)
    }
}

impl<'a, 'de, R: Reader<'de>> Decode for &'a mut Decoder<R> {
    fn decode_u8(&mut self) -> Result<u8, DecodeError> {
        let mut bytes = [0u8; 1];
        self.reader.read(&mut bytes)?;
        Ok(bytes[0])
    }

    fn decode_u16(&mut self) -> Result<u16, DecodeError> {
        let mut bytes = [0u8; 2];
        self.reader.read(&mut bytes)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn decode_u32(&mut self) -> Result<u32, DecodeError> {
        let mut bytes = [0u8; 4];
        self.reader.read(&mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn decode_u64(&mut self) -> Result<u64, DecodeError> {
        let mut bytes = [0u8; 8];
        self.reader.read(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn decode_u128(&mut self) -> Result<u128, DecodeError> {
        let mut bytes = [0u8; 16];
        self.reader.read(&mut bytes)?;
        Ok(u128::from_be_bytes(bytes))
    }

    fn decode_usize(&mut self) -> Result<usize, DecodeError> {
        let mut bytes = [0u8; 8];
        self.reader.read(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes) as usize)
    }

    fn decode_i8(&mut self) -> Result<i8, DecodeError> {
        let mut bytes = [0u8; 1];
        self.reader.read(&mut bytes)?;
        Ok(bytes[0] as i8)
    }

    fn decode_i16(&mut self) -> Result<i16, DecodeError> {
        let mut bytes = [0u8; 2];
        self.reader.read(&mut bytes)?;
        Ok(i16::from_be_bytes(bytes))
    }

    fn decode_i32(&mut self) -> Result<i32, DecodeError> {
        let mut bytes = [0u8; 4];
        self.reader.read(&mut bytes)?;
        Ok(i32::from_be_bytes(bytes))
    }

    fn decode_i64(&mut self) -> Result<i64, DecodeError> {
        let mut bytes = [0u8; 8];
        self.reader.read(&mut bytes)?;
        Ok(i64::from_be_bytes(bytes))
    }

    fn decode_i128(&mut self) -> Result<i128, DecodeError> {
        let mut bytes = [0u8; 16];
        self.reader.read(&mut bytes)?;
        Ok(i128::from_be_bytes(bytes))
    }

    fn decode_isize(&mut self) -> Result<isize, DecodeError> {
        let mut bytes = [0u8; 8];
        self.reader.read(&mut bytes)?;
        Ok(i64::from_be_bytes(bytes) as isize)
    }

    fn decode_f32(&mut self) -> Result<f32, DecodeError> {
        let mut bytes = [0u8; 4];
        self.reader.read(&mut bytes)?;
        Ok(f32::from_be_bytes(bytes))
    }

    fn decode_f64(&mut self) -> Result<f64, DecodeError> {
        let mut bytes = [0u8; 8];
        self.reader.read(&mut bytes)?;
        Ok(f64::from_be_bytes(bytes))
    }

    fn decode_array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut array = [0u8; N];
        self.reader.read(&mut array)?;
        Ok(array)
    }

    fn decode_vec(&mut self) -> Result<::std::vec::Vec<u8>, DecodeError> {
        let size = self.read_bigsize()?;
        let mut v = ::std::vec::Vec::<u8>::with_capacity(size as usize);
        self.reader.read(&mut v)?;
        Ok(v)
    }
}
