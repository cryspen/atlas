//! # 8.8. Suites for BLS12-381
//! This section defines ciphersuites for groups G1 and G2 of the BLS12-381
//! elliptic curve [BLS12-381]. The curve parameters in this section match the
//! ones listed in [I-D.irtf-cfrg-pairing-friendly-curves], Appendix C.

use crate::bls12_381::{self, *};
use crate::expand_message::expand_message_xmd;
use crate::hash_suite::{Ciphersuite, EncodeToCurve, HashToCurve, HashToField};
use crate::hasher::SHA256;
use crate::prime_curve::{Constructor, MapToCurve, PrimeCurve, PrimeField};
use crate::Error;
use p256::NatMod; // XXX: move to hacspec lib

/// # 8.8.1. BLS12-381 G1
///
/// `BLS12381G1_XMD:SHA-256_SSWU_RO_`
///
/// BLS12381G1_XMD:SHA-256_SSWU_NU_ is identical to BLS12381G1_XMD:SHA-256_SSWU_RO_,
/// except that the encoding type is encode_to_curve (Section 3).
///
/// Note that the h_eff values for these suites are chosen for compatibility with
/// the fast cofactor clearing method described by Scott ([WB19] Section 5).
///
/// An optimized example implementation of the Simplified SWU mapping to the
/// curve E' isogenous to BLS12-381 G1 is given in Appendix F.2.
#[allow(non_camel_case_types)]
pub struct BLS12381G1_XMD_SHA_256_SSWU_RO {}

impl Ciphersuite for BLS12381G1_XMD_SHA_256_SSWU_RO {
    const ID: &'static str = "BLS12381G1_XMD:SHA-256_SSWU_RO_";
    const K: usize = 128;
    const L: usize = 64;
    const M: usize = 1;

    type BaseField = BLS12FieldElement;
    type OutputCurve = BLS12_G1;

    fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>, Error> {
        expand_message_xmd::<SHA256>(msg, dst, len_in_bytes)
    }
}

impl Constructor<48, BLS12FieldElement> for BLS12FieldElement {
    fn from_coeffs(v: Vec<BLS12FieldElement>) -> Self {
        assert_eq!(v.len(), 1);
        v[0]
    }
}

impl HashToField for BLS12381G1_XMD_SHA_256_SSWU_RO {
    fn hash_to_field(
        msg: &[u8],
        dst: &[u8],
        count: usize,
    ) -> Result<Vec<Self::BaseField>, crate::Error> {
        crate::hash_suite::hash_to_field::<48, BLS12FieldElement, BLS12FieldElement>(
            msg,
            dst,
            count,
            Self::L,
            Self::M,
            Self::expand_message,
        )
    }
}

impl HashToCurve for BLS12381G1_XMD_SHA_256_SSWU_RO {
    fn hash_to_curve(
        msg: &[u8],
        dst: &[u8],
    ) -> Result<(Self::BaseField, Self::BaseField), crate::Error> {
        let u = Self::hash_to_field(msg, dst, 2)?;
        let (x0, y0) = u[0].map_to_curve();
        let (x1, y1) = u[1].map_to_curve();
        let r = g1add((x0, y0, false), (x1, y1, false));
        Ok(BLS12_G1::clear_cofactor(r))
    }
}

#[allow(non_camel_case_types)]
pub struct BLS12381G1_XMD_SHA_256_SSWU_NU {}

impl Ciphersuite for BLS12381G1_XMD_SHA_256_SSWU_NU {
    const ID: &'static str = "BLS12381G1_XMD:SHA-256_SSWU_NU_";
    const K: usize = 128;
    const L: usize = 64;
    const M: usize = 1;

    type BaseField = BLS12FieldElement;
    type OutputCurve = BLS12_G1;

    fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>, Error> {
        expand_message_xmd::<SHA256>(msg, dst, len_in_bytes)
    }
}

impl HashToField for BLS12381G1_XMD_SHA_256_SSWU_NU {
    fn hash_to_field(
        msg: &[u8],
        dst: &[u8],
        count: usize,
    ) -> Result<Vec<Self::BaseField>, crate::Error> {
        crate::hash_suite::hash_to_field::<48, BLS12FieldElement, BLS12FieldElement>(
            msg,
            dst,
            count,
            Self::L,
            Self::M,
            Self::expand_message,
        )
    }
}

impl EncodeToCurve for BLS12381G1_XMD_SHA_256_SSWU_NU {
    fn encode_to_curve(
        msg: &[u8],
        dst: &[u8],
    ) -> Result<(Self::BaseField, Self::BaseField), crate::Error> {
        let u = Self::hash_to_field(msg, dst, 1)?;
        let (x, y) = u[0].map_to_curve();
        let q = (x, y, false);
        Ok(BLS12_G1::clear_cofactor(q))
    }
}

impl PrimeField<48> for BLS12FieldElement {
    fn is_square(&self) -> bool {
        crate::prime_curve::is_square_m_eq_1(self)
    }

    fn sqrt(self) -> BLS12FieldElement {
        crate::prime_curve::sqrt_3mod4_m_eq_1(&self)
    }

    fn sgn0(self) -> bool {
        crate::prime_curve::sgn0_m_eq_1(self)
    }
}

impl PrimeCurve for BLS12_G1 {
    type BaseField = BLS12FieldElement;

    fn clear_cofactor(self) -> (Self::BaseField, Self::BaseField) {
        let (x, y, _) = g1mul(Scalar::from_hex("d201000000010001"), self);
        (x, y)
    }

    fn point_add(lhs: Self, rhs: Self) -> Result<(Self::BaseField, Self::BaseField), Error> {
        let (x, y, _) = bls12_381::g1add(lhs, rhs);
        Ok((x, y))
    }
}

/// ## E.2.  11-isogeny map for BLS12-381 G1
///
/// The 11-isogeny map from (x', y') on E' to (x, y) on E is given by the
/// following rational functions:
///
/// *  x = x_num / x_den, where
///
///    -  x_num = k_(1,11) * x'^11 + k_(1,10) * x'^10 + k_(1,9) * x'^9 +
///       ... + k_(1,0)
///
///    -  x_den = x'^10 + k_(2,9) * x'^9 + k_(2,8) * x'^8 + ... + k_(2,0)
///
/// *  y = y' * y_num / y_den, where
///
///    -  y_num = k_(3,15) * x'^15 + k_(3,14) * x'^14 + k_(3,13) * x'^13
///       + ... + k_(3,0)
///
///    -  y_den = x'^15 + k_(4,14) * x'^14 + k_(4,13) * x'^13 + ... +
///       k_(4,0)
fn bls12_381_g1_isogeny_map(
    x_prime: BLS12FieldElement,
    y_prime: BLS12FieldElement,
) -> (BLS12FieldElement, BLS12FieldElement) {
    fn k1_eval(x: BLS12FieldElement) -> BLS12FieldElement {
        let k1 = [
    BLS12FieldElement::from_hex("11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7"),
    BLS12FieldElement::from_hex("17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb"),
    BLS12FieldElement::from_hex("0d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0"),
    BLS12FieldElement::from_hex("1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861"),
    BLS12FieldElement::from_hex("0e99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9"),
    BLS12FieldElement::from_hex("1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983"),
    BLS12FieldElement::from_hex("0d6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84"),
    BLS12FieldElement::from_hex("17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e"),
    BLS12FieldElement::from_hex("080d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317"),
    BLS12FieldElement::from_hex("169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e"),
    BLS12FieldElement::from_hex("10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b"),
    BLS12FieldElement::from_hex("06e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229"),
    ];
        k1[11] * x.pow(11)
            + k1[10] * x.pow(10)
            + k1[9] * x.pow(9)
            + k1[8] * x.pow(8)
            + k1[7] * x.pow(7)
            + k1[6] * x.pow(6)
            + k1[5] * x.pow(5)
            + k1[4] * x.pow(4)
            + k1[3] * x.pow(3)
            + k1[2] * x.pow(2)
            + k1[1] * x.pow(1)
            + k1[0]
    }
    let x_num = k1_eval(x_prime);

    fn k2_eval(x: BLS12FieldElement) -> BLS12FieldElement {
        let k2 = [
    BLS12FieldElement::from_hex("08ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c"),
    BLS12FieldElement::from_hex("12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff"),
    BLS12FieldElement::from_hex("0b2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19"),
    BLS12FieldElement::from_hex("03425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8"),
    BLS12FieldElement::from_hex("13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e"),
    BLS12FieldElement::from_hex("0e7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5"),
    BLS12FieldElement::from_hex("0772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a"),
    BLS12FieldElement::from_hex("14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e"),
    BLS12FieldElement::from_hex("0a10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641"),
    BLS12FieldElement::from_hex("095fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a"),
	    ];
        x.pow(10)
            + k2[9] * x.pow(9)
            + k2[8] * x.pow(8)
            + k2[7] * x.pow(7)
            + k2[6] * x.pow(6)
            + k2[5] * x.pow(5)
            + k2[4] * x.pow(4)
            + k2[3] * x.pow(3)
            + k2[2] * x.pow(2)
            + k2[1] * x.pow(1)
            + k2[0]
    }
    let x_den = k2_eval(x_prime);

    fn k3_eval(x: BLS12FieldElement) -> BLS12FieldElement {
        let k3 = [
    BLS12FieldElement::from_hex("090d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33"),
    BLS12FieldElement::from_hex("134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696"),
    BLS12FieldElement::from_hex("00cc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6"),
    BLS12FieldElement::from_hex("01f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb"),
    BLS12FieldElement::from_hex("08cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb"),
    BLS12FieldElement::from_hex("16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0"),
    BLS12FieldElement::from_hex("04ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2"),
    BLS12FieldElement::from_hex("0987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29"),
    BLS12FieldElement::from_hex("09fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587"),
    BLS12FieldElement::from_hex("0e1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30"),
    BLS12FieldElement::from_hex("19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132"),
    BLS12FieldElement::from_hex("18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e"),
    BLS12FieldElement::from_hex("0b182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8"),
    BLS12FieldElement::from_hex("0245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133"),
    BLS12FieldElement::from_hex("05c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b"),
    BLS12FieldElement::from_hex("15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604"),
	    ];
        k3[15] * x.pow(15)
            + k3[14] * x.pow(14)
            + k3[13] * x.pow(13)
            + k3[12] * x.pow(12)
            + k3[11] * x.pow(11)
            + k3[10] * x.pow(10)
            + k3[9] * x.pow(9)
            + k3[8] * x.pow(8)
            + k3[7] * x.pow(7)
            + k3[6] * x.pow(6)
            + k3[5] * x.pow(5)
            + k3[4] * x.pow(4)
            + k3[3] * x.pow(3)
            + k3[2] * x.pow(2)
            + k3[1] * x.pow(1)
            + k3[0]
    }
    let y_num = k3_eval(x_prime);

    fn k4_eval(x: BLS12FieldElement) -> BLS12FieldElement {
        let k4 = [
    BLS12FieldElement::from_hex("16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1"),
    BLS12FieldElement::from_hex("1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d"),
    BLS12FieldElement::from_hex("058df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2"),
    BLS12FieldElement::from_hex("16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416"),
    BLS12FieldElement::from_hex("0be0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d"),
    BLS12FieldElement::from_hex("08d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac"),
    BLS12FieldElement::from_hex("166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c"),
    BLS12FieldElement::from_hex("16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9"),
    BLS12FieldElement::from_hex("1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a"),
    BLS12FieldElement::from_hex("167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55"),
    BLS12FieldElement::from_hex("04d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8"),
    BLS12FieldElement::from_hex("0accbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092"),
    BLS12FieldElement::from_hex("0ad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc"),
    BLS12FieldElement::from_hex("02660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7"),
    BLS12FieldElement::from_hex("0e0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f"),
	    ];
        x.pow(15)
            + k4[14] * x.pow(14)
            + k4[13] * x.pow(13)
            + k4[12] * x.pow(12)
            + k4[11] * x.pow(11)
            + k4[10] * x.pow(10)
            + k4[9] * x.pow(9)
            + k4[8] * x.pow(8)
            + k4[7] * x.pow(7)
            + k4[6] * x.pow(6)
            + k4[5] * x.pow(5)
            + k4[4] * x.pow(4)
            + k4[3] * x.pow(3)
            + k4[2] * x.pow(2)
            + k4[1] * x.pow(1)
            + k4[0]
    }
    let y_den = k4_eval(x_prime);

    let x = x_num * x_den.inv();
    let y = y_prime * y_num * y_den.inv();
    (x, y)
}

impl MapToCurve for BLS12FieldElement {
    type TargetCurve = (BLS12FieldElement, BLS12FieldElement);

    fn map_to_curve(self) -> Self::TargetCurve {
        let (x, y) = 	crate::mappings::sswu_ainvb_eq_1(&self,
							 &Self::from_hex("00144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d"),
							 &Self::from_hex("12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0"),
							 Self::from_u128(11),
							 bls12_381_g1_isogeny_map);
        (x, y)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn bls12381g1_xmd_sha256_sswu_ro_hash_to_field() {
        test_hash_to_field::<48, BLS12381G1_XMD_SHA_256_SSWU_RO>();
    }

    #[test]
    fn bls12381g1_xmd_sha256_sswu_ro_map_to_curve() {
        test_map_to_curve::<48, BLS12381G1_XMD_SHA_256_SSWU_RO>();
    }

    #[test]
    fn bls12381g1_xmd_sha256_sswu_ro_hash_to_curve() {
        test_hash_to_curve::<48, BLS12381G1_XMD_SHA_256_SSWU_RO>();
    }

    #[test]
    fn bls12381g1_xmd_sha256_sswu_nu_encode_to_curve() {
        test_encode_to_curve::<48, BLS12381G1_XMD_SHA_256_SSWU_NU>();
    }
}
