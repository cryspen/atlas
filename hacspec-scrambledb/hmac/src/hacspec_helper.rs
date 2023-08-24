pub(super) fn xor_slice(mut this: Vec<u8>, other: &[u8]) -> Vec<u8> {
    assert!(this.len() == other.len());

    // error[CE0008]: (Diagnostics.Context.Phase (Reject ArbitraryLhs)): ExplicitRejection { reason: "unknown reason" }
    //  --> hmac-rust/src/hacspec_helper.rs:5:9
    //   |
    // 5 |         *x = *x ^ *o;
    //   |
    // for (x, o) in this.iter_mut().zip(other.iter()) {
    //     *x = *x ^ *o;
    // }
    for i in 0..this.len() {
        this[i] = this[i] ^ other[i];
    }
    this
}