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

pub trait Conversions {
    fn to_le_bytes(&self) -> Vec<u8>;
}

impl<const LEN: usize> Conversions for [u64; LEN] {
    fn to_le_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LEN * 8);
        for item in self {
            out.extend_from_slice(&item.to_le_bytes());
        }
        out
    }
}

impl<const LEN: usize> Conversions for [u32; LEN] {
    fn to_le_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LEN * 4);
        for item in self {
            out.extend_from_slice(&item.to_le_bytes());
        }
        out
    }
}

pub fn bytes_to_le_u32s(input: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    for block in input.chunks(4) {
        out.push(u32::from_le_bytes(block.try_into().unwrap()));
    }
    out
}
