pub trait HashToCurveSuite {
    /// The SuiteID
    const ID: &'static str;

    /// The target security level of the suite in bits.
    const K: usize;

    /// The length parameter for [hash_to_field].
    const L: usize;

    /// An point in an elliptic curve over the [BaseField].
    type OutputCurve;

    /// A field of prime characteristic p ≠ 2.
    type BaseField;

    type Hash;

    fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8>;
    fn hash_to_field(msg: &[u8], dst: &[u8], count: usize) -> Vec<Self::BaseField>;
    fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Self::OutputCurve;
}
