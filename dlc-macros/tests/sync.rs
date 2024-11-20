use dlc_macros::maybe_async;

/// Documentation
#[maybe_async]
pub trait Example {
    /// Documentation
    #[maybe_async]
    fn example_fn(&self);
}

struct Test;

impl Example for Test {
    fn example_fn(&self) {}
}

fn main() {
    let test = Test;
    test.example_fn();
}
