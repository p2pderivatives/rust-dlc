//! Module used when working with message segmentation.

use lightning::ln::msgs::DecodeError;
use lightning::ln::wire::Type;
use lightning::util::ser::{Readable, Writeable, Writer};

/// The type of the [`SegmentStart`] message.
pub const SEGMENT_START_TYPE: u16 = 42900;

/// The type of the [`SegmentChunk`] message.
pub const SEGMENT_CHUNK_TYPE: u16 = 42902;

/// Maximum allowed size by noise protocol: <http://www.noiseprotocol.org/noise.html#message-format>
pub const MAX_DATA_SIZE: usize = 65535;

// Max data size - 2 for wrapper type - 5 for bigsize length prefix - 2 for nb segments
const MAX_START_DATA_SIZE: usize = 65526;

// Max data size - 2 for wrapper type - 5 for bigsize length prefix
const MAX_CHUNK_SIZE: usize = 65528;

const MAX_SEGMENTS: usize = 1000;

pub mod segment_reader;

#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[derive(Clone, Debug, PartialEq)]
/// Message indicating that an incoming message has been split and needs to be
/// reconstructed.
pub struct SegmentStart {
    /// The number of segments into which the large message has been split.
    pub nb_segments: u16,
    /// The data for the first segment.
    pub data: Vec<u8>,
}

impl_dlc_writeable!(SegmentStart, {
    (nb_segments, writeable),
    (data, writeable)
});

impl Type for SegmentStart {
    fn type_id(&self) -> u16 {
        SEGMENT_START_TYPE
    }
}

#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[derive(Clone, Debug, PartialEq)]
/// Message providing a chunk of a split message.
pub struct SegmentChunk {
    /// The data to be appended to previously received chunks.
    pub data: Vec<u8>,
}

impl_dlc_writeable!(SegmentChunk, { (data, writeable) });

impl Type for SegmentChunk {
    fn type_id(&self) -> u16 {
        SEGMENT_CHUNK_TYPE
    }
}

/// Split the given data into multiple segments, pre-pending the message type
/// to enable decoding on the receiving side.
pub fn get_segments(mut data: Vec<u8>, msg_type: u16) -> (SegmentStart, Vec<SegmentChunk>) {
    debug_assert!(data.len() > MAX_DATA_SIZE);

    let len_minus_start = data.len() - MAX_START_DATA_SIZE + 2;
    let mut nb_segments = (len_minus_start / MAX_CHUNK_SIZE + 1) as u16;

    if len_minus_start % MAX_CHUNK_SIZE != 0 {
        nb_segments += 1;
    }

    debug_assert!(nb_segments > 1);

    let mut start_data = Vec::with_capacity(MAX_START_DATA_SIZE);
    msg_type
        .write(&mut start_data)
        .expect("to be able to write the type prefix");
    start_data.append(&mut data.drain(..MAX_START_DATA_SIZE - 2).collect());

    debug_assert_eq!(MAX_START_DATA_SIZE, start_data.len());

    let segment_start = SegmentStart {
        nb_segments,
        data: start_data,
    };

    let mut segments = Vec::with_capacity((nb_segments as usize) - 1);

    for _ in 1..(nb_segments as usize) {
        let to_take = usize::min(data.len(), MAX_CHUNK_SIZE);
        segments.push(SegmentChunk {
            data: data.drain(..to_take).collect(),
        });
    }

    (segment_start, segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_segments() {
        let data_size = MAX_START_DATA_SIZE + 2 * MAX_CHUNK_SIZE + 1234;
        let mut data = Vec::new();
        data.resize(data_size, 1);

        let (segment_start, segment_chunks) = get_segments(data, 2);

        assert_eq!(4, segment_start.nb_segments);
        assert_eq!(MAX_START_DATA_SIZE, segment_start.data.len());
        assert_eq!(3, segment_chunks.len());
        assert_eq!(MAX_CHUNK_SIZE, segment_chunks[0].data.len());
        assert_eq!(MAX_CHUNK_SIZE, segment_chunks[1].data.len());
        assert_eq!(1236, segment_chunks[2].data.len());
    }
}
