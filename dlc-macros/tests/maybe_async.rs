use dlc_macros::*;

#[maybe_async]
trait TestTrait {
    fn test_method(&self) -> Result<(), std::io::Error>;
}

struct TestStruct;

#[maybe_async]
impl TestTrait for TestStruct {
    fn test_method(&self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_implementation() {
        let test_struct = TestStruct;
        let test = maybe_await!(test_struct.test_method());
        assert!(test.is_ok());
    }
}
