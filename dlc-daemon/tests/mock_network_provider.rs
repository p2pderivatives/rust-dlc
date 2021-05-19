extern crate dlc_daemon;
extern crate dlc_messages;

use dlc_daemon::daemon::{Error as DaemonError, Network};
use dlc_messages::Message as DlcMessage;
use std::sync::mpsc::{Receiver, Sender};

pub struct MockNetwork {
    sender: Sender<DlcMessage>,
}

impl MockNetwork {
    pub fn new(sender: Sender<DlcMessage>) -> Self {
        MockNetwork { sender }
    }
}

impl Network for MockNetwork {
    fn send_message(&self, message: DlcMessage) -> Result<(), DaemonError> {
        self.sender.send(message).or(Err(DaemonError::NetworkError))
    }
}
