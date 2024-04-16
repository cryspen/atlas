#[derive(Debug)]
pub enum Error {
    InsufficientRandomness,
}

pub struct Randomness {
    bytes: Vec<u8>,
    pointer: usize,
}

impl Randomness {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, pointer: 0 }
    }

    pub fn bytes(&mut self, len: usize) -> Result<&[u8], Error> {
        if self.pointer + len > self.bytes.len() {
            return Err(Error::InsufficientRandomness);
        }

        let out = &self.bytes[self.pointer..self.pointer + len];
        self.pointer += len;
        Ok(out)
    }
}
