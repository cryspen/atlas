#[allow(non_camel_case_types)]
pub struct CURVE448_XOF_SHAKE256_ELL2_RO {}

#[allow(non_camel_case_types)]
pub struct CURVE448_XOF_SHAKE256_ELL2_NU {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    #[should_panic]
    fn curve448_xof_shake256_ell2_hash_to_field() {
        todo!()
    }

    #[test]
    #[should_panic]
    fn curve448_xof_shake256_ell2_map_to_curve() {
        todo!()
    }

    #[test]
    #[should_panic]
    fn curve448_xof_shake256_ell2_ro_hash_to_curve() {
        todo!()
    }

    #[test]
    #[should_panic]
    fn curve448_xof_shake256_ell2_nu_encode_to_curve() {
        todo!()
    }
}
