pub trait PrimeField {
    fn is_square(&self) -> bool;
    fn sqrt(self) -> Self;
    fn sgn0(self) -> bool;
    fn hash_to_field_prime_order(count: usize, l: usize, uniform_bytes: Vec<u8>) -> Vec<Self>
    where
        Self: Sized;
}
