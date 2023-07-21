use p256::NatMod;

pub trait PrimeField<T: NatMod<LEN>, const LEN: usize> {
    fn is_sqare(&self) -> bool;
    fn sqrt(self) -> Self;
    fn sgn0(self) -> bool;
}

pub fn hash_to_field_prime_order<T: NatMod<LEN>, const LEN: usize>(
        msg: &[u8],
        dst: &[u8],
        count: usize,
        l: usize,
        expand_message: fn(&[u8], &[u8], usize) -> Vec<u8>,
    ) -> Vec<T> {
        let len_in_bytes = count * l;
        let uniform_bytes = expand_message(msg, dst, len_in_bytes);
        let mut u = Vec::with_capacity(count);
        for i in 0..count {
            // m = 1
            let elm_offset = l * i;
            let tv = &uniform_bytes[elm_offset..l * (i + 1)];
            let tv = T::from_be_bytes(tv);
            u.push(tv);
        }
        u
    }
