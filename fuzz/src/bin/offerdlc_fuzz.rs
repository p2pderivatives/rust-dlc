use dlc_messages::*;
use honggfuzz::fuzz;

fn main() {
    fuzz!(|data| {
        use lightning::util::ser::{Readable, Writeable};
        let mut buf = ::std::io::Cursor::new(data);
        if let Ok(msg) = <OfferDlc as Readable>::read(&mut buf) {
            let p = buf.position() as usize;
            let mut writer = Vec::new();
            msg.write(&mut writer).unwrap();
            assert_eq!(&buf.into_inner()[..p], &writer[..p]);
        }
    });
}
