extern crate ddk_manager;

use ddk_manager::Time;
use std::cell::RefCell;

thread_local! {
  static MOCK_TIME: RefCell<u64> = RefCell::new(0);
}

pub struct MockTime {}

impl Time for MockTime {
    fn unix_time_now(&self) -> u64 {
        MOCK_TIME.with(|f| *f.borrow())
    }
}

pub fn set_time(time: u64) {
    MOCK_TIME.with(|f| {
        *f.borrow_mut() = time;
    });
}
