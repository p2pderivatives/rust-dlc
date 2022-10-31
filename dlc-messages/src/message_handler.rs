//! Struct used to help send and receive DLC related messages.

use std::{
    collections::{HashMap, VecDeque},
    fmt::Display,
    io::Cursor,
    sync::Mutex,
};

use lightning::{
    ln::{
        msgs::{DecodeError, LightningError},
        peer_handler::CustomMessageHandler,
        wire::{CustomMessageReader, Type},
    },
    util::ser::{Readable, Writeable, MAX_BUF_SIZE},
};
use secp256k1_zkp::PublicKey;

use crate::{
    segmentation::{get_segments, segment_reader::SegmentReader},
    Message, WireMessage,
};

/// MessageHandler is used to send and receive messages through the custom
/// message handling mechanism of the LDK. It also handles message segmentation
/// by splitting large messages when sending and re-constructing them when
/// receiving.
pub struct MessageHandler {
    msg_events: Mutex<VecDeque<(PublicKey, WireMessage)>>,
    msg_received: Mutex<Vec<(PublicKey, Message)>>,
    segment_readers: Mutex<HashMap<PublicKey, SegmentReader>>,
}

impl Default for MessageHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageHandler {
    /// Creates a new instance of a [`MessageHandler`]
    pub fn new() -> Self {
        MessageHandler {
            msg_events: Mutex::new(VecDeque::new()),
            msg_received: Mutex::new(Vec::new()),
            segment_readers: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the messages received by the message handler and empty the
    /// receiving buffer.
    pub fn get_and_clear_received_messages(&self) -> Vec<(PublicKey, Message)> {
        let mut ret = Vec::new();
        std::mem::swap(&mut *self.msg_received.lock().unwrap(), &mut ret);
        ret
    }

    /// Send a message to the peer with given node id. Not that the message is not
    /// sent right away, but only when the LDK
    /// [`lightning::ln::peer_handler::PeerManager::process_events`] is next called.
    pub fn send_message(&self, node_id: PublicKey, msg: Message) {
        if msg.serialized_length() > MAX_BUF_SIZE {
            let (seg_start, seg_chunks) = get_segments(msg.encode(), msg.type_id());
            let mut msg_events = self.msg_events.lock().unwrap();
            msg_events.push_back((node_id, WireMessage::SegmentStart(seg_start)));
            for chunk in seg_chunks {
                msg_events.push_back((node_id, WireMessage::SegmentChunk(chunk)));
            }
        } else {
            self.msg_events
                .lock()
                .unwrap()
                .push_back((node_id, WireMessage::Message(msg)));
        }
    }

    /// Returns whether the message handler has any message to be sent.
    pub fn has_pending_messages(&self) -> bool {
        !self.msg_events.lock().unwrap().is_empty()
    }
}

macro_rules! handle_read_dlc_messages {
    ($msg_type:ident, $buffer:ident, $(($type_id:ident, $variant:ident)),*) => {{
        let decoded = match $msg_type {
            $(
                $crate::$type_id => Message::$variant(Readable::read(&mut $buffer)?),
            )*
            _ => return Ok(None),
        };
        Ok(Some(WireMessage::Message(decoded)))
    }};
}

fn read_dlc_message<R: ::std::io::Read>(
    msg_type: u16,
    mut buffer: &mut R,
) -> Result<Option<WireMessage>, DecodeError> {
    handle_read_dlc_messages!(
        msg_type,
        buffer,
        (OFFER_TYPE, Offer),
        (ACCEPT_TYPE, Accept),
        (SIGN_TYPE, Sign),
        (OFFER_CHANNEL_TYPE, OfferChannel),
        (ACCEPT_CHANNEL_TYPE, AcceptChannel),
        (SIGN_CHANNEL_TYPE, SignChannel),
        (SETTLE_CHANNEL_OFFER_TYPE, SettleOffer),
        (SETTLE_CHANNEL_ACCEPT_TYPE, SettleAccept),
        (SETTLE_CHANNEL_CONFIRM_TYPE, SettleConfirm),
        (SETTLE_CHANNEL_FINALIZE_TYPE, SettleFinalize),
        (RENEW_CHANNEL_OFFER_TYPE, RenewOffer),
        (RENEW_CHANNEL_ACCEPT_TYPE, RenewAccept),
        (RENEW_CHANNEL_CONFIRM_TYPE, RenewConfirm),
        (RENEW_CHANNEL_FINALIZE_TYPE, RenewFinalize),
        (COLLABORATIVE_CLOSE_OFFER_TYPE, CollaborativeCloseOffer)
    )
}

/// Implementation of the `CustomMessageReader` trait is required to decode
/// custom messages in the LDK.
impl CustomMessageReader for MessageHandler {
    type CustomMessage = WireMessage;
    fn read<R: ::std::io::Read>(
        &self,
        msg_type: u16,
        mut buffer: &mut R,
    ) -> Result<Option<WireMessage>, DecodeError> {
        let decoded = match msg_type {
            crate::segmentation::SEGMENT_START_TYPE => {
                WireMessage::SegmentStart(Readable::read(&mut buffer)?)
            }
            crate::segmentation::SEGMENT_CHUNK_TYPE => {
                WireMessage::SegmentChunk(Readable::read(&mut buffer)?)
            }
            _ => return read_dlc_message(msg_type, buffer),
        };

        Ok(Some(decoded))
    }
}

/// Implementation of the `CustomMessageHandler` trait is required to handle
/// custom messages in the LDK.
impl CustomMessageHandler for MessageHandler {
    fn handle_custom_message(
        &self,
        msg: WireMessage,
        org: &PublicKey,
    ) -> Result<(), LightningError> {
        let mut segment_readers = self.segment_readers.lock().unwrap();
        let segment_reader = segment_readers
            .entry(*org)
            .or_insert_with(SegmentReader::new);

        if segment_reader.expecting_chunk() {
            match msg {
                WireMessage::SegmentChunk(s) => {
                    if let Some(msg) = segment_reader
                        .process_segment_chunk(s)
                        .map_err(|e| to_ln_error(e, "Error processing segment chunk"))?
                    {
                        let mut buf = Cursor::new(msg);
                        let message_type = <u16 as Readable>::read(&mut buf).map_err(|e| {
                            to_ln_error(e, "Could not reconstruct message from segments")
                        })?;
                        if let WireMessage::Message(m) = self
                            .read(message_type, &mut buf)
                            .map_err(|e| {
                                to_ln_error(e, "Could not reconstruct message from segments")
                            })?
                            .expect("to have a message")
                        {
                            self.msg_received.lock().unwrap().push((*org, m));
                        } else {
                            return Err(to_ln_error(
                                "Unexpected message type",
                                &message_type.to_string(),
                            ));
                        }
                    }
                    return Ok(());
                }
                _ => {
                    // We were expecting a segment chunk but received something
                    // else, we reset the state.
                    segment_reader.reset();
                }
            }
        }

        match msg {
            WireMessage::Message(m) => self.msg_received.lock().unwrap().push((*org, m)),
            WireMessage::SegmentStart(s) => segment_reader
                .process_segment_start(s)
                .map_err(|e| to_ln_error(e, "Error processing segment start"))?,
            WireMessage::SegmentChunk(_) => {
                return Err(LightningError {
                    err: "Received a SegmentChunk while not expecting one.".to_string(),
                    action: lightning::ln::msgs::ErrorAction::DisconnectPeer { msg: None },
                });
            }
        };
        Ok(())
    }

    fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
        self.msg_events.lock().unwrap().drain(..).collect()
    }
}

#[inline]
fn to_ln_error<T: Display>(e: T, msg: &str) -> LightningError {
    LightningError {
        err: format!("{} :{}", msg, e),
        action: lightning::ln::msgs::ErrorAction::DisconnectPeer { msg: None },
    }
}

#[cfg(test)]
mod tests {
    use secp256k1_zkp::SECP256K1;

    use crate::{
        segmentation::{SegmentChunk, SegmentStart},
        AcceptDlc, OfferDlc, SignDlc,
    };

    use super::*;

    fn some_pk() -> PublicKey {
        PublicKey::from_secret_key(SECP256K1, &secp256k1_zkp::key::ONE_KEY)
    }

    macro_rules! read_test {
        ($type: ty, $input: ident) => {
            let msg: $type = serde_json::from_str(&$input).unwrap();
            handler_read_test(msg);
        };
    }

    fn handler_read_test<T: Writeable + Readable + PartialEq + Type + std::fmt::Debug>(msg: T) {
        let mut buf = Vec::new();
        msg.type_id()
            .write(&mut buf)
            .expect("Error writing type id");
        msg.write(&mut buf).expect("Error writing message");
        let handler = MessageHandler::new();
        let mut reader = Cursor::new(&mut buf);
        let message_type =
            <u16 as Readable>::read(&mut reader).expect("to be able to read the type prefix.");
        handler
            .read(message_type, &mut reader)
            .expect("to be able to read the message")
            .expect("to have a message");
    }

    #[test]
    fn read_offer_test() {
        let input = include_str!("./test_inputs/offer_msg.json");
        read_test!(OfferDlc, input);
    }

    #[test]
    fn read_accept_test() {
        let input = include_str!("./test_inputs/accept_msg.json");
        read_test!(AcceptDlc, input);
    }

    #[test]
    fn read_sign_test() {
        let input = include_str!("./test_inputs/sign_msg.json");
        read_test!(SignDlc, input);
    }

    #[test]
    fn read_segment_start_test() {
        let input = include_str!("./test_inputs/segment_start_msg.json");
        read_test!(SegmentStart, input);
    }

    #[test]
    fn read_segment_chunk_test() {
        let input = include_str!("./test_inputs/segment_chunk_msg.json");
        read_test!(SegmentChunk, input);
    }

    #[test]
    fn read_unknown_message_returns_none() {
        let handler = MessageHandler::new();
        let mut buf = &[0u8; 10];
        let mut reader = Cursor::new(&mut buf);
        let message_type = 0;

        assert!(handler
            .read(message_type, &mut reader)
            .expect("should not error on unknown messages")
            .is_none());
    }

    #[test]
    fn send_regular_message_test() {
        let input = include_str!("./test_inputs/offer_msg.json");
        let msg: OfferDlc = serde_json::from_str(input).unwrap();
        let handler = MessageHandler::new();
        handler.send_message(some_pk(), Message::Offer(msg));
        assert_eq!(handler.msg_events.lock().unwrap().len(), 1);
    }

    #[test]
    fn send_large_message_segmented_test() {
        let input = include_str!("./test_inputs/accept_msg.json");
        let msg: AcceptDlc = serde_json::from_str(input).unwrap();
        let handler = MessageHandler::new();
        handler.send_message(some_pk(), Message::Accept(msg));
        assert!(handler.msg_events.lock().unwrap().len() > 1);
    }

    #[test]
    fn is_empty_after_clearing_msg_events_test() {
        let input = include_str!("./test_inputs/accept_msg.json");
        let msg: AcceptDlc = serde_json::from_str(input).unwrap();
        let handler = MessageHandler::new();
        handler.send_message(some_pk(), Message::Accept(msg));
        handler.get_and_clear_pending_msg();
        assert!(!handler.has_pending_messages());
    }

    #[test]
    fn rebuilds_segments_properly_test() {
        let input1 = include_str!("./test_inputs/segment_start_msg.json");
        let input2 = include_str!("./test_inputs/segment_chunk_msg.json");
        let segment_start: SegmentStart = serde_json::from_str(input1).unwrap();
        let segment_chunk: SegmentChunk = serde_json::from_str(input2).unwrap();

        let handler = MessageHandler::new();
        handler
            .handle_custom_message(WireMessage::SegmentStart(segment_start), &some_pk())
            .expect("to be able to process segment start");
        handler
            .handle_custom_message(WireMessage::SegmentChunk(segment_chunk), &some_pk())
            .expect("to be able to process segment start");
        let msg = handler.get_and_clear_received_messages();
        assert_eq!(1, msg.len());
        if let (_, Message::Accept(_)) = msg[0] {
        } else {
            panic!("Expected an accept message");
        }
    }
}
