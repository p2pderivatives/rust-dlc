//! Module helping with processing message segmentation related messages.

use super::{SegmentChunk, SegmentStart, MAX_CHUNK_SIZE, MAX_SEGMENTS, MAX_START_DATA_SIZE};

/// Struct helping with processing message segmentation related messages.
pub struct SegmentReader {
    cur_data: Vec<u8>,
    remaining_segments: u16,
}

#[derive(Debug)]
/// An error that occured while processing message segmentation related messages.
pub enum Error {
    /// The reader is in a state that is invalid.
    InvalidState(String),
    /// A parameter received by the reader was not in accordance with its state.
    InvalidParameter(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::InvalidState(ref s) => write!(f, "Invalid state {}", s),
            Error::InvalidParameter(ref s) => write!(f, "Invalid parameters were provided: {}", s),
        }
    }
}

impl Default for SegmentReader {
    fn default() -> Self {
        Self::new()
    }
}

impl SegmentReader {
    /// Returns a new instance of [`Self`].
    pub fn new() -> Self {
        SegmentReader {
            cur_data: Vec::new(),
            remaining_segments: 0,
        }
    }

    /// Reset the state of the reader
    pub fn reset(&mut self) {
        self.cur_data = Vec::new();
        self.remaining_segments = 0;
    }

    /// Whether the reader is waiting for an incoming chunk.
    pub fn expecting_chunk(&self) -> bool {
        self.remaining_segments != 0
    }

    /// Process a [`super::SegmentStart`] message.
    pub fn process_segment_start(&mut self, segment_start: SegmentStart) -> Result<(), Error> {
        if !self.cur_data.is_empty() {
            return Err(Error::InvalidState(
                "Received segment start while cur data buffer is not empty.".to_string(),
            ));
        }

        if segment_start.nb_segments < 2 || segment_start.nb_segments > (MAX_SEGMENTS as u16) {
            return Err(Error::InvalidParameter(
                "Segment start must specify at least two chunks and maximum a thousand."
                    .to_string(),
            ));
        }

        if segment_start.data.len() < MAX_START_DATA_SIZE {
            return Err(Error::InvalidParameter(
                "Segment start data should be filled to its maximum capacity.".to_string(),
            ));
        }

        let SegmentStart { nb_segments, data } = segment_start;

        self.remaining_segments = nb_segments - 1;

        self.cur_data = data;

        Ok(())
    }

    /// Process a [`super::SegmentChunk`] message.
    pub fn process_segment_chunk(
        &mut self,
        mut segment_chunk: SegmentChunk,
    ) -> Result<Option<Vec<u8>>, Error> {
        if self.cur_data.is_empty() {
            return Err(Error::InvalidState(
                "Received segment chunk while cur data buffer is empty.".to_string(),
            ));
        }

        if self.remaining_segments > 1 && segment_chunk.data.len() != MAX_CHUNK_SIZE {
            return Err(Error::InvalidParameter(
                "Receive non final segment chunk that was not not filled.".to_string(),
            ));
        }

        self.cur_data.append(&mut segment_chunk.data);
        self.remaining_segments -= 1;

        if self.remaining_segments == 0 {
            let mut res = Vec::new();
            std::mem::swap(&mut self.cur_data, &mut res);
            Ok(Some(res))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::segmentation::MAX_DATA_SIZE;

    use super::*;

    fn segments() -> (SegmentStart, Vec<SegmentChunk>) {
        let mut buf = Vec::new();
        buf.resize(MAX_DATA_SIZE * 4, 1);
        super::super::get_segments(buf, 2)
    }

    #[test]
    fn read_segments_test() {
        let mut segment_reader = SegmentReader::new();
        let (segment_start, segment_chunks) = segments();

        assert!(!segment_reader.expecting_chunk());

        segment_reader
            .process_segment_start(segment_start)
            .expect("to be able to process the segment start");

        assert!(segment_reader.expecting_chunk());

        for chunk in segment_chunks {
            assert!(segment_reader.expecting_chunk());
            segment_reader
                .process_segment_chunk(chunk)
                .expect("to be able to process the segment chunk");
        }

        assert!(!segment_reader.expecting_chunk());
    }

    #[test]
    fn chunk_no_start_fails_test() {
        let mut segment_reader = SegmentReader::new();
        let (_, mut segment_chunks) = segments();
        segment_reader
            .process_segment_chunk(segment_chunks.pop().unwrap())
            .expect_err("Should not process a chunk without having had a start first.");
    }

    #[test]
    fn start_not_finished_previous_fails_test() {
        let mut segment_reader = SegmentReader::new();
        let (segment_start, segment_chunks) = segments();
        let (segment_start2, _) = segments();
        segment_reader
            .process_segment_start(segment_start)
            .expect("to be able to process the first segment start");
        segment_reader
            .process_segment_chunk(segment_chunks[0].clone())
            .expect("to be able to process the segment chunk");
        segment_reader
            .process_segment_start(segment_start2)
            .expect_err("should not process new start before finishing previous segment");
    }

    #[test]
    fn start_reset_start_accepted_test() {
        let mut segment_reader = SegmentReader::new();
        let (segment_start, _) = segments();
        let (segment_start2, _) = segments();
        segment_reader
            .process_segment_start(segment_start)
            .expect("to be able to process the first segment start");
        segment_reader.reset();
        segment_reader
            .process_segment_start(segment_start2)
            .expect("to be able to process the same segment start after reset");
    }

    #[test]
    fn too_few_chunk_in_start_fails_test() {
        let mut segment_reader = SegmentReader::new();
        let (mut segment_start, _) = segments();
        segment_start.nb_segments = 1;
        segment_reader
            .process_segment_start(segment_start)
            .expect_err("should not accept segment with less than 2 elements");
    }

    #[test]
    fn too_many_chunks_in_start_fails_test() {
        let mut segment_reader = SegmentReader::new();
        let (mut segment_start, _) = segments();
        segment_start.nb_segments = 1001;
        segment_reader
            .process_segment_start(segment_start)
            .expect_err("should not accept segments with more than 1000 elements");
    }

    #[test]
    fn segment_start_not_full_fails_test() {
        let mut segment_reader = SegmentReader::new();
        let (mut segment_start, _) = segments();
        segment_start.data.pop();

        segment_reader
            .process_segment_start(segment_start)
            .expect_err("Should error on non full segment start message.");
    }

    #[test]
    fn non_final_chunk_not_full_fails_test() {
        let mut segment_reader = SegmentReader::new();
        let (segment_start, mut segment_chunks) = segments();
        segment_reader
            .process_segment_start(segment_start)
            .expect("to be able to process the segment start");

        segment_chunks[0].data.pop();

        segment_reader
            .process_segment_chunk(segment_chunks[0].clone())
            .expect_err("should not accept not full segment that is not the last one");
    }
}
