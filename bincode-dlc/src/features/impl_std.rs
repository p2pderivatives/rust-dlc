use crate::{
    de::{read::Reader, Decodable, Decoder},
    error::DecodeError,
};

pub fn decode_from<D: Decodable, R: std::io::Read>(src: &mut R) -> Result<D, DecodeError> {
    let mut decoder = Decoder::<_>::new(src);
    D::decode(&mut decoder)
}

impl<'storage, R: std::io::Read> Reader<'storage> for R {
    #[inline(always)]
    fn read(&mut self, bytes: &mut [u8]) -> Result<(), DecodeError> {
        match self.read_exact(bytes) {
            Ok(_) => Ok(()),
            Err(_) => Err(DecodeError::UnexpectedEnd),
        }
    }
}
