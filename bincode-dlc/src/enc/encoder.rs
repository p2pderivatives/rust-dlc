use super::{write::Writer, Encode};
use crate::error::EncodeError;

pub struct Encoder<W: Writer> {
    writer: W,
}

impl<W: Writer> Encoder<W> {
    pub fn new(writer: W) -> Encoder<W> {
        Encoder { writer }
    }

    pub fn into_writer(self) -> W {
        self.writer
    }

    fn write_bigsize(&mut self, b: u64) -> Result<(), EncodeError> {
        let mut s = self;
        match b {
            0..=0xFC => s.encode_u8(b as u8),
            0xFD..=0xFFFF => {
                s.encode_u8(0xFDu8)?;
                s.encode_u16(b as u16)
            }
            0x10000..=0xFFFFFFFF => {
                s.encode_u8(0xFEu8)?;
                s.encode_u32(b as u32)
            }
            _ => {
                s.encode_u8(0xFFu8)?;
                s.encode_u64(b as u64)
            }
        }
    }
}

macro_rules! encode_primitive {
    ($name: ident, $ty:ty) => {
        fn $name(&mut self, val: $ty) -> Result<(), EncodeError> {
            self.writer.write(&val.to_be_bytes())
        }
    };
}

impl<'a, W: Writer> Encode for &'a mut Encoder<W> {
    fn encode_u8(&mut self, val: u8) -> Result<(), EncodeError> {
        self.writer.write(&[val])
    }

    encode_primitive!(encode_u16, u16);
    encode_primitive!(encode_u32, u32);
    encode_primitive!(encode_u64, u64);
    encode_primitive!(encode_usize, usize);
    encode_primitive!(encode_u128, u128);
    encode_primitive!(encode_i16, i16);
    encode_primitive!(encode_i32, i32);
    encode_primitive!(encode_i64, i64);
    encode_primitive!(encode_i128, i128);
    encode_primitive!(encode_isize, isize);
    encode_primitive!(encode_f32, f32);
    encode_primitive!(encode_f64, f64);

    fn encode_i8(&mut self, val: i8) -> Result<(), EncodeError> {
        self.writer.write(&[val as u8])
    }

    fn encode_slice(&mut self, val: &[u8]) -> Result<(), EncodeError> {
        self.write_bigsize(val.len() as u64)?;
        self.writer.write(val)
    }

    fn encode_array<const N: usize>(&mut self, val: [u8; N]) -> Result<(), EncodeError> {
        self.writer.write(&val)
    }

    // fn encode_bigsize(&mut self, b: u64) -> Result<(), EncodeError> {
    //     #[allow(ellipsis_inclusive_range_patterns)]
    //     match b {
    //         0...0xFC => self.encode_u8(b as u8),
    //         0xFD...0xFFFF => {
    //             self.encode_u8(0xFDu8)?;
    //             self.encode_u16(b as u16)
    //         }
    //         0x10000...0xFFFFFFFF => {
    //             self.encode_u8(0xFEu8)?;
    //             self.encode_u32(b as u32)
    //         }
    //         _ => {
    //             self.encode_u8(0xFFu8)?;
    //             self.encode_u64(b as u64)
    //         }
    //     }
    // }
}
