pub trait FunctionalVec {
    fn concat(&self, other: &[u8]) -> Vec<u8>;
    fn concat_byte(&self, other: u8) -> Vec<u8>;
}

impl FunctionalVec for Vec<u8> {
    fn concat(&self, other: &[u8]) -> Vec<u8> {
        let mut out = self.clone();
        out.extend_from_slice(other);
        out
    }

    fn concat_byte(&self, other: u8) -> Vec<u8> {
        let mut out = self.clone();
        Vec::<u8>::push(&mut out, other);
        out
    }
}

impl FunctionalVec for &[u8] {
    fn concat(&self, other: &[u8]) -> Vec<u8> {
        let mut out = self.to_vec();
        out.extend_from_slice(other);
        out
    }

    fn concat_byte(&self, other: u8) -> Vec<u8> {
        let mut out = self.to_vec();
        Vec::<u8>::push(&mut out, other);
        out
    }
}
